package transport

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"m31labs.dev/gosx/hub"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/divergence"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/review"
)

func TestDecodeBrowserSpliceRejectsMalformedAndPreservesUnicode(t *testing.T) {
	path := []byte("src/π.go")
	insert := []byte("🙂")
	frame := make([]byte, 22+len(path)+len(insert))
	copy(frame[:4], "MXSP")
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(path)))
	binary.BigEndian.PutUint32(frame[6:10], 42)
	binary.BigEndian.PutUint32(frame[10:14], 3)
	binary.BigEndian.PutUint32(frame[14:18], 2)
	binary.BigEndian.PutUint32(frame[18:22], uint32(len(insert)))
	copy(frame[22:], path)
	copy(frame[22+len(path):], insert)
	operation, err := decodeBrowserSplice(frame)
	if err != nil || operation.Path != string(path) || operation.Insert != string(insert) || operation.BaseHash != 42 || operation.Index != 3 || operation.DeleteCount != 2 {
		t.Fatalf("operation=%+v err=%v", operation, err)
	}
	if _, err := decodeBrowserSplice(frame[:len(frame)-1]); err == nil {
		t.Fatal("truncated browser splice was accepted")
	}
}

func TestAgentCommitRoundTrip(t *testing.T) {
	store := cell.NewStore()
	cellHub := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(cellHub.ServeAgentHTTP))
	defer server.Close()

	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatalf("attach token: %v", err)
	}
	connection := dialAgentHub(t, server.URL, "cell-demo", token)
	defer connection.Close()
	if err := connection.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{
		"name": "test-agent",
	})}); err != nil {
		t.Fatalf("send attach: %v", err)
	}
	for {
		message, err := readTextMessage(connection)
		if err != nil {
			t.Fatalf("read attach response: %v", err)
		}
		if message.Event == "attach:welcome" {
			break
		}
		if message.Event == "state" || message.Event == "cell:update" || message.Event == "presence:count" {
			t.Fatalf("agent received operator telemetry: %s", message.Event)
		}
		if message.Event == "agent:error" {
			t.Fatalf("agent attach rejected: %s", message.Data)
		}
	}

	type outcome struct {
		receipt string
		err     error
	}
	result := make(chan outcome, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		receipt, err := cellHub.RequestAgentCommit(ctx, review.CommitRequest{
			CellID: "cell-demo", Branch: "main", Review: model.Review{ID: "review-1", Files: []string{"README.md"}},
		})
		result <- outcome{receipt: receipt, err: err}
	}()

	var request struct {
		RequestID string `json:"requestID"`
	}
	for {
		message, err := readTextMessage(connection)
		if err != nil {
			t.Fatalf("read commit request: %v", err)
		}
		if message.Event != "agent:commit" {
			continue
		}
		if err := json.Unmarshal(message.Data, &request); err != nil {
			t.Fatalf("decode commit request: %v", err)
		}
		break
	}
	if err := connection.WriteJSON(hub.Message{Event: "agent:commit-result", Data: rawJSON(map[string]string{
		"requestID": request.RequestID, "receipt": "agent-commit-receipt",
	})}); err != nil {
		t.Fatalf("send commit result: %v", err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.receipt != "agent-commit-receipt" {
			t.Fatalf("commit result = %q, %v", got.receipt, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for commit result")
	}
}

func TestAgentHeartbeatAndCapabilityRefresh(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	defer conn.Close()
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	if err := conn.WriteJSON(hub.Message{Event: "agent:heartbeat", Data: rawJSON(map[string]string{})}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(hub.Message{Event: "agent:refresh", Data: rawJSON(map[string]string{})}); err != nil {
		t.Fatal(err)
	}
	message := readEvent(t, conn, "agent:capability")
	var payload map[string]string
	if json.Unmarshal(message.Data, &payload) != nil || payload["token"] == "" || payload["token"] == token {
		t.Fatalf("refresh payload %#v", payload)
	}
}

func TestPromptDeliveryUsesAgentUnicastProtocol(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	agentServer := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer agentServer.Close()
	browserServer := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer browserServer.Close()

	attachToken, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	agent := dialAgentHub(t, agentServer.URL, "cell-demo", attachToken)
	defer agent.Close()
	if err = agent.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, agent, "attach:welcome")

	operatorToken, err := store.MintOperatorCapability("cell-demo", "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	operator, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(browserServer.URL, "http")+"?cellID=cell-demo&capability="+operatorToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	if err = operator.WriteJSON(hub.Message{Event: "prompt", Data: rawJSON(map[string]string{"cellID": "cell-demo", "prompt": "please retry"})}); err != nil {
		t.Fatal(err)
	}
	message := readEvent(t, agent, "prompt:deliver")
	var payload map[string]string
	if json.Unmarshal(message.Data, &payload) != nil || payload["cellID"] != "cell-demo" || payload["prompt"] != "please retry" {
		t.Fatalf("prompt payload=%#v", payload)
	}
}

func TestAgentOutputIsRedactedAndRecordedAsIntent(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	defer conn.Close()
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	secret := "ghp_abcdefghijklmnopqrstuvwxyz"
	if err := conn.WriteJSON(hub.Message{Event: "agent:output", Data: rawJSON(map[string]string{"stream": "stderr", "text": "failed with " + secret})}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := store.Snapshot("cell-demo")
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range snapshot.Events {
			if event.Action != "agent.output" {
				continue
			}
			if event.Kind != model.EventIntent || event.Summary != "Agent stderr output" || strings.Contains(event.Detail, secret) || !strings.Contains(event.Detail, "<redacted>") {
				t.Fatalf("output event=%+v", event)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("agent output was not recorded")
}

func TestAgentTraceCannotSpoofOperatorEvidence(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	defer conn.Close()
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	secret := "ghp_abcdefghijklmnopqrstuvwxyz"
	spoof := model.Event{TraceID: "trace-spoof", Kind: model.EventKernel, Source: "operator", Actor: "operator", Action: "file.write", Summary: "claimed", Detail: secret, NodeID: "forged-node", CgroupID: 99, Authenticated: true, Evidence: "kernel"}
	if err := conn.WriteJSON(hub.Message{Event: "agent:trace", Data: rawJSON(spoof)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, snapshotErr := store.Snapshot("cell-demo")
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		for _, event := range snapshot.Events {
			if event.TraceID != spoof.TraceID {
				continue
			}
			if event.Kind != model.EventIntent || event.Source != "agent-cell-demo" || event.Actor != "agent-cell-demo" || event.Authenticated || event.NodeID != "" || event.CgroupID != 0 || event.Evidence != "agent-reported" || strings.Contains(event.Detail, secret) {
				t.Fatalf("agent spoof survived sanitization: %+v", event)
			}
			kernel := model.Event{TraceID: spoof.TraceID, Kind: model.EventKernel, Source: "kernel", Actor: "operator", Action: "file.write", Timestamp: event.Timestamp.Add(time.Millisecond)}
			divergences := divergence.Evaluate([]model.Event{event, kernel}, divergence.Options{CellID: "cell-demo", EvidenceHealthy: true})
			for _, record := range divergences {
				if record.RuleID == "D9" {
					return
				}
			}
			t.Fatal("spoofed agent trace suppressed operator-attribution mismatch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("sanitized agent trace was not recorded")
}

func TestAgentIdleStatusLeavesCellIdleNotFailed(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	defer conn.Close()
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	if err := conn.WriteJSON(hub.Message{Event: "agent:status", Data: rawJSON(map[string]string{"status": "idle"})}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := store.Snapshot("cell-demo")
		if err == nil && snapshot.Status == model.CellIdle && snapshot.Agent.Status == "idle" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("agent exit did not transition cell to idle")
}

func TestBrowserBinarySpliceIsActorBoundAndAppliedToCRDT(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer server.Close()
	token, err := store.MintOperatorCapability("cell-demo", "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"?cellID=cell-demo&capability="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot("cell-demo")
	if err != nil || len(before.Files) == 0 {
		t.Fatalf("snapshot=%+v err=%v", before, err)
	}
	file := before.Files[0]
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(file.Content))
	insert := "binary-splice\n"
	frame := make([]byte, 22+len(file.Path)+len(insert))
	copy(frame[:4], "MXSP")
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(file.Path)))
	binary.BigEndian.PutUint32(frame[6:10], hash.Sum32())
	binary.BigEndian.PutUint32(frame[10:14], 0)
	binary.BigEndian.PutUint32(frame[14:18], 0)
	binary.BigEndian.PutUint32(frame[18:22], uint32(len(insert)))
	copy(frame[22:], file.Path)
	copy(frame[22+len(file.Path):], insert)
	if err := connection.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	for {
		message, err := readTextMessage(connection)
		if err != nil {
			t.Fatal(err)
		}
		if message.Event != "cell:update" {
			continue
		}
		var snapshot model.CellSnapshot
		if json.Unmarshal(message.Data, &snapshot) != nil {
			continue
		}
		for _, candidate := range snapshot.Files {
			if candidate.Path == file.Path && candidate.Content == insert+file.Content {
				if len(snapshot.Events) == 0 || snapshot.Events[len(snapshot.Events)-1].Actor != "operator-browser" {
					t.Fatalf("splice actor was not connection-bound: %+v", snapshot.Events)
				}
				return
			}
		}
	}
}

func TestBrowserCursorPresenceIsRelayedAsElementAnchors(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer server.Close()
	token, err := store.MintOperatorCapability("cell-demo", "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"?cellID=cell-demo&capability="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil || len(snapshot.Files) == 0 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if err := connection.WriteJSON(hub.Message{Event: "presence:cursor", Data: rawJSON(map[string]any{
		"path": snapshot.Files[0].Path, "start": 0, "end": 1, "coordinateSpace": "utf16",
	})}); err != nil {
		t.Fatal(err)
	}
	message := readEvent(t, connection, "presence:cursor")
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(message.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["start"]; ok {
		t.Fatalf("raw start offset leaked in anchored cursor: %s", message.Data)
	}
	if _, ok := payload["end"]; ok {
		t.Fatalf("raw end offset leaked in anchored cursor: %s", message.Data)
	}
	for _, key := range []string{"startAnchor", "endAnchor", "actorID", "clientID"} {
		if len(payload[key]) == 0 {
			t.Fatalf("anchored cursor missing %q: %s", key, message.Data)
		}
	}
}

func TestBrowserReceivesOnlyItsCellCRDTDocuments(t *testing.T) {
	store := cell.NewStore()
	other, err := store.Create("https://github.com/example/other", "main", "standard")
	if err != nil {
		t.Fatal(err)
	}
	h := NewCellHub(store)
	h.RegisterCell(other.ID)
	server := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer server.Close()
	token, err := store.MintOperatorCapability("cell-demo", "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"?cellID=cell-demo&capability="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	demo, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	binaryFrames := 0
	for {
		_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		messageType, _, err := connection.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.BinaryMessage {
			binaryFrames++
		}
	}
	if binaryFrames != len(demo.Files) {
		t.Fatalf("binary bootstrap frames=%d, want exactly %d authorized documents", binaryFrames, len(demo.Files))
	}
}

func TestExpiredOperatorConnectionReceivesNoCellBroadcasts(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Hub.ServeHTTPWithMetadata(w, r, hub.ConnectionMetadata{
			"cellID": "cell-demo", "actor": "operator", "role": "operator",
			"permissions": "doc:read,cell:control", "expiresAt": "1",
		})
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	readEvent(t, connection, "state")
	snapshot, _ := store.Snapshot("cell-demo")
	h.BroadcastCell(snapshot)
	h.AskHuman("cell-demo", model.ActionApproval{ID: "ask-expired", CellID: "cell-demo"})
	_ = connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		var message hub.Message
		if err := connection.ReadJSON(&message); err != nil {
			break
		}
		if message.Event == "cell:update" || message.Event == "control:ask-human" {
			t.Fatalf("expired connection received %s", message.Event)
		}
	}
}

func TestExpiredAgentSessionCannotReceivePrivilegedOutboundWork(t *testing.T) {
	h := NewCellHub(cell.NewStore())
	h.agents["expired"] = agentSession{CellID: "cell-demo", AgentID: "agent-cell-demo", ExpiresAt: 1, Permissions: map[string]bool{"prompt:read": true, "secret:request": true, "agent:commit": true}}
	h.agentByCell["cell-demo"] = "expired"
	if h.AgentClient("cell-demo") != "" {
		t.Fatal("expired agent remained discoverable")
	}
	if h.SendAgent("expired", "prompt:deliver", map[string]string{"prompt": "unsafe"}) {
		t.Fatal("prompt delivered to expired agent")
	}
	if err := h.DeliverTier2Grant("cell-demo", model.SecretGrantRequest{ID: "grant"}, "token"); err == nil {
		t.Fatal("Tier-2 grant delivered to expired agent")
	}
	if _, err := h.RequestAgentCommit(context.Background(), review.CommitRequest{CellID: "cell-demo"}); err == nil {
		t.Fatal("commit request delivered to expired agent")
	}
}

func TestDestroyedCellReleasesHubDocuments(t *testing.T) {
	store := cell.NewStore()
	created, err := store.Create("https://github.com/example/temporary", "main", "standard")
	if err != nil {
		t.Fatal(err)
	}
	h := NewCellHub(store)
	token, err := store.MintOperatorCapability(created.ID, "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Destroy(created.ID); err != nil {
		t.Fatal(err)
	}
	h.DisconnectCell(created.ID, "destroyed")
	server := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"?cellID="+created.ID+"&capability="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	binaryFrames := 0
	for {
		_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		messageType, _, err := connection.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.BinaryMessage {
			binaryFrames++
		}
	}
	if binaryFrames != 0 {
		t.Fatalf("destroyed cell retained %d CRDT sync documents", binaryFrames)
	}
}

func TestDisconnectCellRevokesAttachTransport(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	defer conn.Close()
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	if !h.DisconnectCell("cell-demo", "cell destroyed") {
		t.Fatal("expected attached agent to disconnect")
	}
	if h.AgentClient("cell-demo") != "" {
		t.Fatal("agent mapping survived disconnect")
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func TestAgentWebSocketDisconnectReturnsSteeringCellToReady(t *testing.T) {
	store := cell.NewStore()
	h := NewCellHub(store)
	server := httptest.NewServer(http.HandlerFunc(h.ServeAgentHTTP))
	defer server.Close()
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialAgentHub(t, server.URL, "cell-demo", token)
	if err := conn.WriteJSON(hub.Message{Event: "agent:attach", Data: rawJSON(map[string]string{"name": "agent"})}); err != nil {
		t.Fatal(err)
	}
	readEvent(t, conn, "attach:welcome")
	if _, err := store.Prompt("cell-demo", "perform a task"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, snapshotErr := store.Snapshot("cell-demo")
		if snapshotErr == nil && snapshot.Status == model.CellReady && !snapshot.Agent.Connected && snapshot.Agent.Status == "detached" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshot, _ := store.Snapshot("cell-demo")
	t.Fatalf("disconnect did not restore ready state: %+v", snapshot.Cell)
}

func dialAgentHub(t *testing.T, serverURL, cellID, token string) *websocket.Conn {
	t.Helper()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(serverURL, "http")+"?cellID="+cellID, headers)
	if err != nil {
		t.Fatalf("dial hub: %v", err)
	}
	return connection
}

func readEvent(t *testing.T, connection *websocket.Conn, event string) hub.Message {
	t.Helper()
	for {
		message, err := readTextMessage(connection)
		if err != nil {
			t.Fatal(err)
		}
		if message.Event == event {
			return message
		}
	}
}

func rawJSON(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}

func readTextMessage(connection *websocket.Conn) (hub.Message, error) {
	for {
		messageType, payload, err := connection.ReadMessage()
		if err != nil {
			return hub.Message{}, err
		}
		if messageType != websocket.TextMessage {
			continue
		}
		var message hub.Message
		if err := json.Unmarshal(payload, &message); err != nil {
			return hub.Message{}, err
		}
		return message, nil
	}
}
