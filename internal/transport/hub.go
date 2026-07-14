package transport

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"m31labs.dev/gosx/crdt"
	"m31labs.dev/gosx/hub"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/review"
	"m31labs.dev/mercutio/internal/secrets"
)

// CellHub carries presence, steering, and buffer updates. The server also
// registers each cell's GoSX CRDT document so the binary sync protocol is
// available to the browser editor as it grows beyond the v1 snapshot path.
type CellHub struct {
	*hub.Hub
	agentHub     *hub.Hub
	store        *cell.Store
	mu           sync.RWMutex
	agents       map[string]agentSession
	agentByCell  map[string]string
	commitMu     sync.Mutex
	commits      map[string]pendingCommit
	reviewMu     sync.Mutex
	reviewTimers map[string]*time.Timer
}

type agentSession struct {
	CellID      string
	AgentID     string
	ExpiresAt   int64
	Permissions map[string]bool
}

type pendingCommit struct {
	clientID string
	result   chan commitResult
}

type commitResult struct {
	receipt string
	err     string
}

func NewCellHub(store *cell.Store) *CellHub {
	h := &CellHub{Hub: hub.New("mercutio-cells"), agentHub: hub.New("mercutio-agents"), store: store, agents: make(map[string]agentSession), agentByCell: make(map[string]string), commits: make(map[string]pendingCommit), reviewTimers: make(map[string]*time.Timer)}
	h.configureBinaryAuthorization(h.Hub)
	h.configureBinaryAuthorization(h.agentHub)
	h.Hub.SetBinaryMessageHandler(func(client *hub.Client, data []byte) bool {
		if len(data) < 4 || string(data[:4]) != "MXSP" {
			return false
		}
		h.handleBrowserSplice(client, data)
		return true
	})
	for _, snapshot := range store.State(0).Cells {
		h.registerCell(snapshot.ID)
	}
	h.On("join", func(ctx *hub.Context) {
		cellID, _ := ctx.Client.Metadata("cellID")
		if snapshot, err := store.Snapshot(cellID); err == nil {
			h.Send(ctx.Client.ID, "state", model.State{Cells: []model.CellSnapshot{snapshot}, ActiveCellID: cellID, Connected: h.ClientCount()})
		}
		docActor, _ := ctx.Client.Metadata("docActor")
		role, _ := ctx.Client.Metadata("role")
		permissions, _ := ctx.Client.Metadata("permissions")
		h.Send(ctx.Client.ID, "attach:welcome", map[string]any{"clientId": ctx.Client.ID, "actorId": docActor, "role": role, "granted": strings.Split(permissions, ","), "heartbeatIntervalMs": 15000})
		h.broadcastCellEvent(cellID, "presence:count", map[string]int{"count": h.Presence().Count()})
	})
	h.On("leave", func(ctx *hub.Context) {
		cellID, _ := ctx.Client.Metadata("cellID")
		h.broadcastCellEvent(cellID, "presence:leave", map[string]string{"clientID": ctx.Client.ID})
		h.broadcastCellEvent(cellID, "cursor:leave", map[string]string{"clientID": ctx.Client.ID})
		h.broadcastCellEvent(cellID, "presence:count", map[string]int{"count": h.Presence().Count()})
	})
	h.agentHub.On("join", func(ctx *hub.Context) {
		h.agentHub.Send(ctx.Client.ID, "agent:ready", map[string]string{"status": "attach-required"})
	})
	h.agentHub.On("leave", func(ctx *hub.Context) {
		h.failCommitsForClient(ctx.Client.ID)
		if session, ok := h.removeAgent(ctx.Client.ID); ok {
			if snapshot, err := store.Detach(session.CellID, session.AgentID); err == nil {
				h.BroadcastCell(snapshot)
			}
		}
	})
	h.agentHub.On("agent:commit-result", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "agent:commit") {
			return
		}
		if _, ok := h.agent(ctx.Client.ID); !ok {
			return
		}
		var payload struct {
			RequestID string `json:"requestID"`
			Receipt   string `json:"receipt"`
			Error     string `json:"error"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil || payload.RequestID == "" {
			return
		}
		h.commitMu.Lock()
		pending, ok := h.commits[payload.RequestID]
		if ok && pending.clientID == ctx.Client.ID {
			delete(h.commits, payload.RequestID)
		}
		h.commitMu.Unlock()
		if ok && pending.clientID == ctx.Client.ID {
			pending.result <- commitResult{receipt: payload.Receipt, err: payload.Error}
		}
	})
	h.agentHub.On("agent:attach", func(ctx *hub.Context) {
		var payload struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		cellID, _ := ctx.Client.Metadata("cellID")
		agentID, _ := ctx.Client.Metadata("actor")
		token, _ := ctx.Client.Metadata("capability")
		if !metadataPermission(ctx.Client, "hub:attach") {
			h.agentHub.Send(ctx.Client.ID, "attach:reject", map[string]string{"reason": "capability_expired"})
			h.agentHub.Disconnect(ctx.Client.ID, "capability expired")
			return
		}
		h.mu.RLock()
		previousID := h.agentByCell[cellID]
		h.mu.RUnlock()
		if previousID != "" && previousID != ctx.Client.ID {
			h.agentHub.Send(ctx.Client.ID, "attach:reject", map[string]string{"reason": "role_not_permitted"})
			h.agentHub.Disconnect(ctx.Client.ID, "agent already attached")
			return
		}
		snapshot, err := store.Attach(cellID, token, agentID, payload.Name)
		if err != nil {
			h.agentHub.Send(ctx.Client.ID, "attach:reject", map[string]string{"reason": "capability_expired"})
			return
		}
		h.mu.Lock()
		expiresAt, _ := strconv.ParseInt(metadataValue(ctx.Client, "expiresAt"), 10, 64)
		h.agents[ctx.Client.ID] = agentSession{CellID: cellID, AgentID: snapshot.Agent.ID, ExpiresAt: expiresAt, Permissions: permissionSet(metadataValue(ctx.Client, "permissions"))}
		h.agentByCell[cellID] = ctx.Client.ID
		h.mu.Unlock()
		docActor, _ := ctx.Client.Metadata("docActor")
		permissions, _ := ctx.Client.Metadata("permissions")
		h.agentHub.Send(ctx.Client.ID, "attach:welcome", map[string]any{"clientId": ctx.Client.ID, "actorId": docActor, "granted": strings.Split(permissions, ","), "cellState": snapshot.Status, "heartbeatIntervalMs": 15000})
		h.BroadcastCell(snapshot)
	})
	h.agentHub.On("agent:status", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "agent:status") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.UpdateAgent(session.CellID, session.AgentID, payload.Status); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	h.agentHub.On("agent:heartbeat", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "agent:status") {
			h.agentHub.Disconnect(ctx.Client.ID, "capability expired")
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		if snapshot, err := store.Heartbeat(session.CellID, session.AgentID); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	h.agentHub.On("agent:refresh", func(ctx *hub.Context) {
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		current, _ := ctx.Client.Metadata("capability")
		token, err := store.RefreshAttachToken(session.CellID, current)
		if err != nil {
			h.agentHub.Send(ctx.Client.ID, "agent:error", map[string]string{"error": err.Error()})
			return
		}
		h.agentHub.Send(ctx.Client.ID, "agent:capability", map[string]string{"token": token})
	})
	h.agentHub.On("agent:trace", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "telemetry:write") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var event model.Event
		if json.Unmarshal(ctx.Data, &event) != nil {
			return
		}
		event.Kind = model.EventIntent
		event.Source = session.AgentID
		event.Actor = session.AgentID
		event.Authenticated = false
		event.Summary = secrets.RedactText(event.Summary)
		event.Detail = secrets.RedactText(event.Detail)
		event.Path = secrets.RedactText(event.Path)
		event.Argv = secrets.RedactText(event.Argv)
		event.Destination = secrets.RedactText(event.Destination)
		event.ProgramDanger = model.DangerAxes{}
		event.NodeID = ""
		event.CPU = 0
		event.CgroupID = 0
		event.KernelSeq = 0
		event.BatchSeq = 0
		event.Drops = 0
		event.Evidence = "agent-reported"
		if snapshot, err := store.RecordEvent(session.CellID, event); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	h.agentHub.On("agent:output", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "telemetry:write") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct {
			Stream string `json:"stream"`
			Text   string `json:"text"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil || strings.TrimSpace(payload.Text) == "" {
			return
		}
		stream := "stdout"
		if payload.Stream == "stderr" {
			stream = "stderr"
		}
		event := model.Event{Kind: model.EventIntent, Source: session.AgentID, Action: "agent.output", Summary: "Agent " + stream + " output", Detail: secrets.RedactText(payload.Text), Timestamp: time.Now().UTC()}
		if snapshot, err := store.RecordEvent(session.CellID, event); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	h.agentHub.On("agent:secret-request", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "secret:request") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct {
			Credential string   `json:"credential"`
			Purpose    string   `json:"purpose"`
			TTLSeconds int64    `json:"ttlSeconds"`
			EnvName    string   `json:"envName"`
			Command    []string `json:"command"`
			WorkingDir string   `json:"workingDir"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		snapshot, request, err := store.RequestSecretGrant(session.CellID, payload.Credential, payload.Purpose, session.AgentID, payload.EnvName, payload.Command, payload.WorkingDir, time.Duration(payload.TTLSeconds)*time.Second)
		if err != nil {
			h.agentHub.Send(ctx.Client.ID, "agent:error", map[string]string{"error": err.Error()})
			return
		}
		h.broadcastCellEvent(session.CellID, "control:ask-human", map[string]any{"cellID": session.CellID, "request": request})
		h.BroadcastCell(snapshot)
	})
	h.agentHub.On("agent:edit", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:write") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.ApplyEdit(session.CellID, payload.Path, payload.Content, session.AgentID); err == nil {
			h.BroadcastCell(snapshot)
		} else {
			h.agentHub.Send(ctx.Client.ID, "agent:error", map[string]string{"error": err.Error()})
		}
	})
	h.agentHub.On("agent:disk-edit", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:write") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct{ Path, Content, Base string }
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.ApplyDiskEdit(session.CellID, payload.Path, payload.Base, payload.Content, session.AgentID); err == nil {
			h.BroadcastCell(snapshot)
		} else {
			h.agentHub.Send(ctx.Client.ID, "agent:error", map[string]string{"error": err.Error()})
		}
	})
	h.agentHub.On("agent:disk-delete", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:write") {
			return
		}
		session, ok := h.agent(ctx.Client.ID)
		if !ok {
			return
		}
		var payload struct{ Path, Base string }
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.ApplyDiskDelete(session.CellID, payload.Path, payload.Base, session.AgentID); err == nil {
			h.BroadcastCell(snapshot)
		} else {
			h.agentHub.Send(ctx.Client.ID, "agent:error", map[string]string{"error": err.Error()})
		}
	})
	h.On("cell:select", func(ctx *hub.Context) {
		var payload struct {
			CellID string `json:"cellID"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		cellID, _ := ctx.Client.Metadata("cellID")
		if payload.CellID != cellID || !metadataPermission(ctx.Client, "doc:read") {
			return
		}
		if snapshot, err := store.Snapshot(cellID); err == nil {
			h.Send(ctx.Client.ID, "cell:update", snapshot)
		}
	})
	h.On("presence:cursor", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:read") {
			return
		}
		var payload map[string]any
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		payload["clientID"] = ctx.Client.ID
		cellID, _ := ctx.Client.Metadata("cellID")
		payload["cellID"] = cellID
		h.broadcastCellEvent(cellID, "presence:cursor", payload)
	})
	h.On("presence:focus", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:read") {
			return
		}
		var payload struct {
			CellID  string `json:"cellID"`
			Path    string `json:"path"`
			Focused bool   `json:"focused"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		cellID, _ := ctx.Client.Metadata("cellID")
		actor, _ := ctx.Client.Metadata("actor")
		if payload.CellID != cellID {
			return
		}
		if snapshot, err := store.SetWriterActive(cellID, payload.Path, actor, payload.Focused); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	h.On("prompt", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "prompt:write") {
			return
		}
		var payload struct {
			CellID string `json:"cellID"`
			Prompt string `json:"prompt"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		cellID, _ := ctx.Client.Metadata("cellID")
		if payload.CellID != cellID {
			return
		}
		if snapshot, err := store.Prompt(cellID, payload.Prompt); err == nil {
			h.BroadcastCell(snapshot)
			if clientID := h.AgentClient(cellID); clientID != "" {
				h.agentHub.Send(clientID, "prompt:deliver", map[string]string{"cellID": cellID, "prompt": payload.Prompt})
			}
		}
	})
	h.On("edit", func(ctx *hub.Context) {
		if !metadataPermission(ctx.Client, "doc:write") {
			return
		}
		var payload struct {
			CellID  string `json:"cellID"`
			Path    string `json:"path"`
			Content string `json:"content"`
			Actor   string `json:"actor"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		cellID, _ := ctx.Client.Metadata("cellID")
		actor, _ := ctx.Client.Metadata("actor")
		if payload.CellID != cellID {
			return
		}
		if snapshot, err := store.ApplyEdit(cellID, payload.Path, payload.Content, actor); err == nil {
			h.BroadcastCell(snapshot)
		}
	})
	return h
}

type browserSplice struct {
	Path        string
	BaseHash    uint32
	Index       uint32
	DeleteCount uint32
	Insert      string
}

func decodeBrowserSplice(data []byte) (browserSplice, error) {
	if len(data) < 22 || string(data[:4]) != "MXSP" {
		return browserSplice{}, fmt.Errorf("invalid browser splice frame")
	}
	pathLength := int(binary.BigEndian.Uint16(data[4:6]))
	insertLength := int(binary.BigEndian.Uint32(data[18:22]))
	if pathLength == 0 || pathLength > 4096 || insertLength > 1<<20 || len(data) != 22+pathLength+insertLength {
		return browserSplice{}, fmt.Errorf("invalid browser splice lengths")
	}
	path := data[22 : 22+pathLength]
	insert := data[22+pathLength:]
	if !utf8.Valid(path) || !utf8.Valid(insert) {
		return browserSplice{}, fmt.Errorf("browser splice text is not UTF-8")
	}
	return browserSplice{
		Path: string(path), BaseHash: binary.BigEndian.Uint32(data[6:10]),
		Index: binary.BigEndian.Uint32(data[10:14]), DeleteCount: binary.BigEndian.Uint32(data[14:18]), Insert: string(insert),
	}, nil
}

func (h *CellHub) handleBrowserSplice(client *hub.Client, data []byte) {
	if !metadataPermission(client, "doc:write") {
		return
	}
	cellID, _ := client.Metadata("cellID")
	actor, _ := client.Metadata("actor")
	operation, err := decodeBrowserSplice(data)
	if err == nil {
		var snapshot model.CellSnapshot
		snapshot, err = h.store.ApplySplice(cellID, operation.Path, operation.BaseHash, operation.Index, operation.DeleteCount, operation.Insert, actor)
		if err == nil {
			h.BroadcastCell(snapshot)
			h.scheduleReviewRefresh(cellID, snapshot.Revision)
			return
		}
	}
	h.Hub.Send(client.ID, "edit:reject", map[string]string{"reason": "stale_or_invalid_splice"})
	if snapshot, snapshotErr := h.store.Snapshot(cellID); snapshotErr == nil {
		h.Hub.Send(client.ID, "cell:update", snapshot)
	}
}

func (h *CellHub) scheduleReviewRefresh(cellID string, revision uint64) {
	h.reviewMu.Lock()
	if existing := h.reviewTimers[cellID]; existing != nil {
		existing.Stop()
	}
	var timer *time.Timer
	timer = time.AfterFunc(150*time.Millisecond, func() {
		snapshot, changed, err := h.store.RefreshReviews(cellID, revision)
		if err == nil && changed {
			h.BroadcastCell(snapshot)
		}
		h.reviewMu.Lock()
		if h.reviewTimers[cellID] == timer {
			delete(h.reviewTimers, cellID)
		}
		h.reviewMu.Unlock()
	})
	h.reviewTimers[cellID] = timer
	h.reviewMu.Unlock()
}

func (h *CellHub) configureBinaryAuthorization(target *hub.Hub) {
	target.SetBinaryReadAuthorizer(func(client *hub.Client, docName string) bool {
		cellID, _ := client.Metadata("cellID")
		return metadataPermission(client, "doc:read") && strings.HasPrefix(docName, cellID+":")
	})
	target.SetBinaryAuthorizer(func(client *hub.Client, docName string) bool {
		cellID, _ := client.Metadata("cellID")
		return metadataPermission(client, "doc:write") && strings.HasPrefix(docName, cellID+":")
	})
	target.SetBinaryChangeAuthorizer(func(client *hub.Client, _ string, changes []crdt.Change) error {
		actor, _ := client.Metadata("docActor")
		for _, change := range changes {
			if actor == "" || change.ActorID != actor {
				return fmt.Errorf("CRDT actor substitution rejected")
			}
		}
		return nil
	})
}

func metadataPermission(client *hub.Client, permission string) bool {
	expires, _ := client.Metadata("expiresAt")
	if unix, err := strconv.ParseInt(expires, 10, 64); err != nil || unix <= time.Now().UTC().Unix() {
		return false
	}
	permissions, _ := client.Metadata("permissions")
	for _, value := range strings.Split(permissions, ",") {
		if value == permission {
			return true
		}
	}
	return false
}

func metadataValue(client *hub.Client, key string) string {
	value, _ := client.Metadata(key)
	return value
}

func permissionSet(encoded string) map[string]bool {
	result := make(map[string]bool)
	for _, permission := range strings.Split(encoded, ",") {
		if permission = strings.TrimSpace(permission); permission != "" {
			result[permission] = true
		}
	}
	return result
}

func (h *CellHub) authorizedAgent(clientID, cellID, permission string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	session, ok := h.agents[clientID]
	return ok && session.CellID == cellID && session.ExpiresAt > time.Now().UTC().Unix() && session.Permissions[permission]
}

func (h *CellHub) DeliverTier2Grant(cellID string, request model.SecretGrantRequest, token string) error {
	clientID := h.AgentClient(cellID)
	if clientID == "" {
		return fmt.Errorf("no attach sidecar for cell %q", cellID)
	}
	if !h.authorizedAgent(clientID, cellID, "secret:request") {
		return fmt.Errorf("attach sidecar capability expired or lacks secret delivery permission")
	}
	h.agentHub.Send(clientID, "agent:tier2-grant", map[string]any{"cellID": cellID, "requestID": request.ID, "grant": token, "envName": request.EnvName, "command": request.Command, "workingDir": request.WorkingDir, "expiresAt": request.ExpiresAt})
	return nil
}

func (h *CellHub) DeliverProxyRoute(cellID, routeID, proxyURL string) error {
	clientID := h.AgentClient(cellID)
	if clientID == "" {
		return fmt.Errorf("no attach sidecar for cell %q", cellID)
	}
	if !h.authorizedAgent(clientID, cellID, "secret:request") {
		return fmt.Errorf("attach sidecar capability expired or lacks proxy delivery permission")
	}
	h.agentHub.Send(clientID, "agent:proxy-route", map[string]string{"cellID": cellID, "routeID": routeID, "proxyURL": proxyURL})
	return nil
}

func (h *CellHub) SendAgent(clientID, event string, value any) bool {
	h.mu.RLock()
	session, ok := h.agents[clientID]
	h.mu.RUnlock()
	if !ok || session.ExpiresAt <= time.Now().UTC().Unix() || !session.Permissions["prompt:read"] {
		return false
	}
	h.agentHub.Send(clientID, event, value)
	return true
}

func (h *CellHub) RegisterCell(id string) {
	h.registerCell(id)
	if snapshot, err := h.store.Snapshot(id); err == nil {
		h.BroadcastCell(snapshot)
	}
}

func (h *CellHub) registerCell(id string) {
	for path, doc := range h.store.Documents(id) {
		h.SyncDoc(id+":"+path, doc)
		h.agentHub.SyncDoc(id+":"+path, doc)
	}
}

func (h *CellHub) BroadcastCell(snapshot model.CellSnapshot) {
	h.broadcastCellEvent(snapshot.ID, "cell:update", snapshot)
}

// AskHuman delivers a blocking governance request only to operator
// connections already bound to this cell by server-side capability metadata.
func (h *CellHub) AskHuman(cellID string, request model.ActionApproval) {
	h.Hub.BroadcastWhere("control:ask-human", map[string]any{"cellID": cellID, "request": request}, func(client *hub.Client) bool {
		bound, _ := client.Metadata("cellID")
		return bound == cellID && metadataPermission(client, "cell:control")
	})
}

func (h *CellHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := h.store.VerifyCapability(r.URL.Query().Get("capability"), r.URL.Query().Get("cellID"), "doc:read")
	if err != nil || claims.Role != "operator" {
		http.Error(w, "cell capability required", http.StatusUnauthorized)
		return
	}
	h.Hub.ServeHTTPWithMetadata(w, r, capabilityMetadata(claims.CellID, claims.ActorID, claims.Role, claims.Permissions, claims.ExpiresAt, ""))
}

func (h *CellHub) ServeAgentHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	claims, err := h.store.VerifyCapability(token, r.URL.Query().Get("cellID"), "hub:attach")
	if err != nil || claims.Role != "agent" {
		http.Error(w, "agent capability required", http.StatusUnauthorized)
		return
	}
	h.agentHub.ServeHTTPWithMetadata(w, r, capabilityMetadata(claims.CellID, claims.ActorID, claims.Role, claims.Permissions, claims.ExpiresAt, token))
}

func capabilityMetadata(cellID, actor, role string, permissions []string, expiresAt int64, token string) hub.ConnectionMetadata {
	docActor, _ := crdt.NewActorID()
	return hub.ConnectionMetadata{"cellID": cellID, "actor": actor, "docActor": docActor.String(), "role": role, "permissions": strings.Join(permissions, ","), "expiresAt": strconv.FormatInt(expiresAt, 10), "capability": token}
}

func (h *CellHub) broadcastCellEvent(cellID, event string, value any) {
	h.Hub.BroadcastWhere(event, value, func(client *hub.Client) bool {
		bound, _ := client.Metadata("cellID")
		return bound == cellID && metadataPermission(client, "doc:read")
	})
}

func (h *CellHub) AgentClient(cellID string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	clientID := h.agentByCell[cellID]
	session, ok := h.agents[clientID]
	if !ok || session.CellID != cellID || session.ExpiresAt <= time.Now().UTC().Unix() {
		return ""
	}
	return clientID
}

// DisconnectCell revokes the live attach transport for a cell immediately.
// Store teardown owns the durable lifecycle state; this method owns the
// realtime connection and prevents a stopped agent from sending more work.
func (h *CellHub) DisconnectCell(cellID, reason string) bool {
	if snapshot, err := h.store.Snapshot(cellID); err == nil {
		for _, file := range snapshot.Files {
			name := cellID + ":" + file.Path
			h.Hub.UnsyncDoc(name)
			h.agentHub.UnsyncDoc(name)
		}
	}
	clientID := h.AgentClient(cellID)
	if clientID == "" {
		return false
	}
	h.removeAgent(clientID)
	h.failCommitsForClient(clientID)
	return h.agentHub.Disconnect(clientID, reason)
}

func (h *CellHub) RequestAgentCommit(ctx context.Context, request review.CommitRequest) (string, error) {
	clientID := h.AgentClient(request.CellID)
	if clientID == "" {
		return "", fmt.Errorf("no agent is attached to cell %q", request.CellID)
	}
	if !h.authorizedAgent(clientID, request.CellID, "agent:commit") {
		return "", fmt.Errorf("agent capability expired or lacks commit permission")
	}
	requestID := fmt.Sprintf("commit-%d", time.Now().UnixNano())
	result := make(chan commitResult, 1)
	h.commitMu.Lock()
	h.commits[requestID] = pendingCommit{clientID: clientID, result: result}
	h.commitMu.Unlock()
	payload := struct {
		RequestID string       `json:"requestID"`
		CellID    string       `json:"cellID"`
		Branch    string       `json:"branch"`
		Review    model.Review `json:"review"`
	}{RequestID: requestID, CellID: request.CellID, Branch: request.Branch, Review: request.Review}
	h.agentHub.Send(clientID, "agent:commit", payload)
	select {
	case outcome := <-result:
		if outcome.err != "" {
			return "", fmt.Errorf("agent commit: %s", outcome.err)
		}
		if outcome.receipt == "" {
			return "", fmt.Errorf("agent commit returned no receipt")
		}
		return outcome.receipt, nil
	case <-ctx.Done():
		h.commitMu.Lock()
		delete(h.commits, requestID)
		h.commitMu.Unlock()
		return "", ctx.Err()
	}
}

func (h *CellHub) failCommitsForClient(clientID string) {
	h.commitMu.Lock()
	deferred := make([]pendingCommit, 0)
	for requestID, pending := range h.commits {
		if pending.clientID == clientID {
			delete(h.commits, requestID)
			deferred = append(deferred, pending)
		}
	}
	h.commitMu.Unlock()
	for _, pending := range deferred {
		pending.result <- commitResult{err: "agent disconnected"}
	}
}

func (h *CellHub) agent(clientID string) (agentSession, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	session, ok := h.agents[clientID]
	return session, ok
}

func (h *CellHub) removeAgent(clientID string) (agentSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	session, ok := h.agents[clientID]
	if !ok {
		return agentSession{}, false
	}
	delete(h.agents, clientID)
	if h.agentByCell[session.CellID] == clientID {
		delete(h.agentByCell, session.CellID)
	}
	return session, true
}
