package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/intelligence"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/sandbox"
	"m31labs.dev/mercutio/internal/shadow"
	"m31labs.dev/mercutio/internal/transport"
)

type Handler struct {
	store        *cell.Store
	hub          *transport.CellHub
	intelligence *intelligence.Service
	proxyClient  *http.Client
	kernelMu     sync.Mutex
}

func New(store *cell.Store, hub *transport.CellHub) *Handler {
	return &Handler{store: store, hub: hub, intelligence: intelligence.New(), proxyClient: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

type kernelBatch struct {
	NodeID   string            `json:"nodeID"`
	BatchSeq uint64            `json:"batchSeq"`
	Clock    kernelClock       `json:"clockSync"`
	Events   []kernelEvent     `json:"events"`
	Drops    map[string]uint64 `json:"drops"`
	SentAt   time.Time         `json:"sentAt"`
}

type kernelClock struct {
	MonotonicNS int64  `json:"monotonicNs"`
	RealtimeNS  int64  `json:"realtimeNs"`
	SkewBoundMS int64  `json:"skewBoundMs"`
	NodeID      string `json:"nodeID"`
}

type kernelEvent struct {
	CellID           string            `json:"cellID"`
	NodeID           string            `json:"nodeID"`
	CPU              uint32            `json:"cpu"`
	Seq              uint64            `json:"seq"`
	TimestampNS      uint64            `json:"tsNs"`
	Kind             string            `json:"kind"`
	Verdict          string            `json:"verdict"`
	PID              uint32            `json:"pid"`
	CgroupID         uint64            `json:"cgroupID"`
	PPID             uint32            `json:"ppid"`
	TGID             uint32            `json:"tgid"`
	UID              uint32            `json:"uid"`
	Comm             string            `json:"comm"`
	Path             string            `json:"path"`
	PathTruncated    bool              `json:"pathTruncated"`
	Argv             string            `json:"argv"`
	ArgvTruncated    bool              `json:"argvTruncated"`
	Destination      string            `json:"destination"`
	Flags            uint32            `json:"flags"`
	Mode             uint32            `json:"mode"`
	Operation        uint32            `json:"operation"`
	Program          string            `json:"program"`
	Evidence         string            `json:"evidence"`
	ClockSkewBoundMS int64             `json:"clockSkewBoundMs"`
	ActionDanger     map[string]string `json:"actionDanger"`
	ProgramDanger    map[string]string `json:"programDanger"`
}

func (h *Handler) KernelTelemetry(w http.ResponseWriter, r *http.Request) {
	// Keep validation, durable event writes, and cursor advancement ordered for
	// each process. The cursor itself lives in Store and survives restarts.
	h.kernelMu.Lock()
	defer h.kernelMu.Unlock()
	defer r.Body.Close()
	reader := io.Reader(http.MaxBytesReader(w, r.Body, 4<<20))
	if r.Header.Get("Content-Encoding") == "gzip" {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid gzip telemetry: %w", err))
			return
		}
		defer compressed.Close()
		reader = io.LimitReader(compressed, 16<<20)
	} else if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && encoding != "identity" {
		errorJSON(w, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content encoding %q", encoding))
		return
	}
	var batch kernelBatch
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if batch.NodeID == "" || batch.BatchSeq == 0 || batch.Clock.NodeID != batch.NodeID || batch.Clock.MonotonicNS <= 0 || batch.Clock.RealtimeNS <= 0 || batch.Clock.SkewBoundMS <= 0 || len(batch.Events) > 512 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("valid node, sequence, clock sync, and at most 512 events are required"))
		return
	}
	for _, event := range batch.Events {
		if event.CellID == "" || (event.NodeID != "" && event.NodeID != batch.NodeID) {
			errorJSON(w, http.StatusBadRequest, fmt.Errorf("kernel event cell and matching node are required"))
			return
		}
		if _, err := h.store.Snapshot(event.CellID); err != nil {
			errorJSON(w, http.StatusBadRequest, err)
			return
		}
		delta := int64(event.TimestampNS) - batch.Clock.MonotonicNS
		if delta > int64(5*time.Second) || delta < -int64(24*time.Hour) {
			errorJSON(w, http.StatusBadRequest, fmt.Errorf("kernel event timestamp is outside the accepted clock window"))
			return
		}
	}
	previous := h.store.KernelBatchCursor(batch.NodeID)
	if batch.BatchSeq <= previous {
		errorJSON(w, http.StatusConflict, fmt.Errorf("kernel batch sequence %d is not newer than %d", batch.BatchSeq, previous))
		return
	}
	gap := previous != 0 && batch.BatchSeq != previous+1
	var drops uint64
	for _, count := range batch.Drops {
		drops += count
	}
	now := time.Now().UTC()
	for index, raw := range batch.Events {
		delta := int64(raw.TimestampNS) - batch.Clock.MonotonicNS
		at := time.Unix(0, batch.Clock.RealtimeNS+delta).UTC()
		action := "kernel." + defaultEventText(raw.Kind, "event")
		summary := "Kernel observed " + defaultEventText(raw.Kind, "sandbox activity")
		eventDrops := uint64(0)
		if index == 0 {
			eventDrops = drops
		}
		skewBound := raw.ClockSkewBoundMS
		if skewBound <= 0 || skewBound < batch.Clock.SkewBoundMS {
			skewBound = batch.Clock.SkewBoundMS
		}
		event := model.Event{
			ID: fmt.Sprintf("kernel:%s:%d:%d", batch.NodeID, batch.BatchSeq, index), Kind: model.EventKernel,
			Source: "horizon-node-agent", Action: action, Summary: summary,
			Detail:     fmt.Sprintf("program=%s pid=%d ppid=%d tgid=%d uid=%d comm=%s argv=%q flags=%d mode=%d operation=%d", raw.Program, raw.PID, raw.PPID, raw.TGID, raw.UID, raw.Comm, raw.Argv, raw.Flags, raw.Mode, raw.Operation),
			DangerAxes: dangerAxes(raw.ActionDanger), ProgramDanger: dangerAxes(raw.ProgramDanger), Danger: dangerLabel(raw.ActionDanger), Verdict: raw.Verdict,
			Path: raw.Path, PathTruncated: raw.PathTruncated, Argv: raw.Argv, ArgvTruncated: raw.ArgvTruncated, Destination: raw.Destination, CPU: raw.CPU, KernelSeq: raw.Seq, BatchSeq: batch.BatchSeq, Drops: eventDrops,
			PID: raw.PID, CgroupID: raw.CgroupID, NodeID: batch.NodeID,
			ClockSkewBoundMS: skewBound, Evidence: defaultEventText(raw.Evidence, "clean"),
			Authenticated: true, Timestamp: at,
		}
		if gap && index == 0 {
			event.Detail += "; batch-gap=true"
		}
		snapshot, err := h.store.RecordEvent(raw.CellID, event)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, err)
			return
		}
		h.hub.BroadcastCell(snapshot)
		if raw.Verdict == "ask" {
			resource := raw.Path
			if resource == "" {
				resource = raw.Destination
			}
			approvalSnapshot, approval, approvalErr := h.store.RequestActionApproval(raw.CellID, event.ID+":approval", batch.NodeID, raw.CgroupID, raw.PID, raw.Kind, resource)
			if approvalErr != nil {
				errorJSON(w, http.StatusBadRequest, approvalErr)
				return
			}
			h.hub.BroadcastCell(approvalSnapshot)
			h.hub.AskHuman(raw.CellID, approval)
		}
	}
	// A drop-only batch still enters the durable evidence stream.
	if len(batch.Events) == 0 && drops > 0 {
		for _, cellID := range h.store.CellIDs() {
			detail := "node=" + batch.NodeID
			if gap {
				detail += "; batch-gap=true"
			}
			snapshot, err := h.store.RecordEvent(cellID, model.Event{ID: fmt.Sprintf("kernel:%s:%d:drops", batch.NodeID, batch.BatchSeq), Kind: model.EventKernel, Source: "horizon-node-agent", Action: "kernel.telemetry.drop", Summary: "Kernel telemetry reported dropped evidence", Detail: detail, Danger: "high", BatchSeq: batch.BatchSeq, Drops: drops, Authenticated: true, Timestamp: now})
			if err == nil {
				h.hub.BroadcastCell(snapshot)
			}
		}
	}
	if err := h.store.CommitKernelBatch(batch.NodeID, batch.BatchSeq); err != nil {
		errorJSON(w, http.StatusServiceUnavailable, fmt.Errorf("durable telemetry cursor: %w", err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(batch.Events), "batchSeq": batch.BatchSeq, "drops": drops, "batchGap": gap})
}

func (h *Handler) NodeTelemetryCursor(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "internal" || parts[2] != "nodes" || parts[4] != "telemetry-cursor" || strings.TrimSpace(parts[3]) == "" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid node telemetry cursor path"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"nodeID": parts[3], "lastBatchSeq": h.store.KernelBatchCursor(parts[3])})
}

func (h *Handler) NodeActionDecisions(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "internal" || parts[2] != "nodes" || parts[4] != "action-decisions" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid node decision path"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"decisions": h.store.TakeNodeActionDecisions(parts[3])})
}

func (h *Handler) NodeCells(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "internal" || parts[2] != "nodes" || parts[4] != "cells" || strings.TrimSpace(parts[3]) == "" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid node cells path"))
		return
	}
	cells, err := h.store.NodeCells(r.Context(), parts[3])
	if err != nil {
		errorJSON(w, http.StatusServiceUnavailable, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"cells": cells})
}

func dangerAxes(values map[string]string) model.DangerAxes {
	return model.DangerAxes{Mode: values["mode"], Scope: values["scope"], Reversibility: values["reversibility"]}
}

func dangerLabel(values map[string]string) string {
	switch values["mode"] {
	case "control":
		return "critical"
	case "mutate":
		return "high"
	default:
		return "low"
	}
}

func (h *Handler) State(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.store.State(h.hub.ClientCount()))
}

func (h *Handler) CreateCell(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RepoURL string `json:"repoURL"`
		Branch  string `json:"branch"`
		Profile string `json:"profile"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Create(input.RepoURL, input.Branch, input.Profile)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.RegisterCell(snapshot.ID)
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusCreated, snapshot)
}

func (h *Handler) Cell(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Snapshot(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Snapshot(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	kind := model.EventKind(r.URL.Query().Get("kind"))
	if kind == "" {
		writeJSON(w, http.StatusOK, snapshot.Events)
		return
	}
	filtered := make([]model.Event, 0)
	for _, event := range snapshot.Events {
		if event.Kind == kind {
			filtered = append(filtered, event)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (h *Handler) Evidence(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, h.store.Evidence(id))
}

func (h *Handler) RecordEvent(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var event model.Event
	if err := decodeJSON(r, &event); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.RecordEvent(id, event)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusAccepted, snapshot)
}

func (h *Handler) Armed(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		NodeID         string   `json:"nodeID"`
		Programs       []string `json:"programs"`
		ManifestDigest string   `json:"manifestDigest"`
		ObjectDigest   string   `json:"objectDigest"`
		ProfileDigest  string   `json:"profileDigest"`
		CgroupID       uint64   `json:"cgroupID"`
		Enforcement    string   `json:"enforcement"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.MarkArmedContext(r.Context(), id, cell.ArmReceipt{NodeID: input.NodeID, Programs: input.Programs, ManifestDigest: input.ManifestDigest, ObjectDigest: input.ObjectDigest, ProfileDigest: input.ProfileDigest, CgroupID: input.CgroupID, Enforcement: input.Enforcement})
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusAccepted, snapshot.Sandbox)
}

func (h *Handler) ArmState(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	token := r.Header.Get("X-Mercutio-Arm-Token")
	if token == "" {
		token = r.URL.Query().Get("attachToken")
	}
	if !h.store.VerifyArmToken(id, token) {
		errorJSON(w, http.StatusUnauthorized, fmt.Errorf("cell arm capability required"))
		return
	}
	state, err := h.store.ArmState(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *Handler) WorkspaceDevice(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	defer r.Body.Close()
	var input sandbox.MountDevices
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := h.store.RecordMountDevices(r.Context(), id, r.Header.Get("X-Mercutio-Arm-Token"), input); err != nil {
		errorJSON(w, http.StatusForbidden, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) InternalEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var input struct {
		CellID     string          `json:"cellID"`
		CellIDAlt  string          `json:"cell_id"`
		Event      *model.Event    `json:"event"`
		Kind       model.EventKind `json:"kind"`
		Source     string          `json:"source"`
		Action     string          `json:"action"`
		Summary    string          `json:"summary"`
		Detail     string          `json:"detail"`
		Danger     string          `json:"danger"`
		ID         string          `json:"id"`
		TraceID    string          `json:"traceID"`
		Time       time.Time       `json:"time"`
		Capability string          `json:"capability"`
		Output     string          `json:"output"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if input.CellID == "" {
		input.CellID = input.CellIDAlt
	}
	event := model.Event{Kind: input.Kind, Source: input.Source, Action: input.Action, Summary: input.Summary, Detail: input.Detail, Danger: input.Danger}
	if input.Event != nil {
		event = *input.Event
	}
	if event.Kind == "" {
		event.Kind = model.EventKernel
	}
	if event.Source == "" {
		event.Source = "horizon"
	}
	if input.Capability != "" {
		event.Source = "horizon"
		if input.Output != "" {
			event.Action = "horizon." + input.Output
		} else {
			event.Action = "horizon.event"
		}
		event.Summary = "Horizon observed " + defaultEventText(input.Output, "a sandbox event")
		event.Detail = "capability=" + input.Capability
	}
	if event.ID == "" {
		event.ID = input.ID
	}
	if event.TraceID == "" {
		event.TraceID = input.TraceID
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = input.Time
	}
	if event.Action == "" {
		event.Action = "kernel.event"
	}
	if event.Summary == "" {
		event.Summary = "Horizon observed a sandbox event"
	}
	if input.CellID == "" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("cellID is required"))
		return
	}
	snapshot, err := h.store.RecordEvent(input.CellID, event)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusAccepted, snapshot)
}

func defaultEventText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (h *Handler) AttachToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	token, err := h.store.AttachToken(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cellID": id, "token": token})
}

func (h *Handler) OperatorCapability(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	token, err := h.store.MintOperatorCapability(id, "operator")
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	claims, err := h.store.VerifyCapability(token, id, "doc:read")
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"cellID": id, "token": token, "expiresAt": claims.ExpiresAt})
}

func (h *Handler) PutSecret(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Name       string `json:"name"`
		Value      string `json:"value"`
		Actor      string `json:"actor"`
		Capability string `json:"capability"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if input.Capability == "" {
		input.Capability = r.Header.Get("X-Mercutio-Capability")
	}
	snapshot, receipt, err := h.store.PutSecret(id, input.Name, input.Value, input.Actor, input.Capability)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusAccepted, map[string]any{"receipt": receipt, "snapshot": snapshot})
}

func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "cells" || parts[3] != "secrets" || parts[2] == "" || parts[4] == "" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid secret path"))
		return
	}
	token := r.Header.Get("X-Mercutio-Capability")
	if token == "" {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(authorization, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		}
	}
	actor := defaultEventText(r.URL.Query().Get("actor"), "operator")
	value, receipt, err := h.store.SecretValue(parts[2], parts[4], actor, token)
	if err != nil {
		errorJSON(w, http.StatusForbidden, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"name": parts[4], "value": value, "receipt": receipt})
}

func (h *Handler) SecretCapability(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Actor      string `json:"actor"`
		Permission string `json:"permission"`
	}
	if err = decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if input.Actor == "" {
		input.Actor = "operator"
	}
	token, err := h.store.MintSecretCapability(id, input.Actor, input.Permission)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresIn": 60})
}

func (h *Handler) SecretDescriptors(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	values, err := h.store.SecretDescriptors(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (h *Handler) ApproveSecretGrant(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid grant path"))
		return
	}
	id, requestID := parts[2], parts[4]
	var input struct {
		Actor      string `json:"actor"`
		Capability string `json:"capability"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	input.Actor = defaultEventText(input.Actor, "operator")
	if input.Capability == "" {
		input.Capability = r.Header.Get("X-Mercutio-Capability")
	}
	snapshot, grant, err := h.store.ApproveSecretGrant(id, requestID, input.Actor, input.Capability)
	if err != nil {
		errorJSON(w, http.StatusForbidden, err)
		return
	}
	request, ok := secretRequest(snapshot.SecretRequests, requestID)
	if !ok {
		errorJSON(w, http.StatusInternalServerError, fmt.Errorf("approved secret request disappeared"))
		return
	}
	if err = h.hub.DeliverTier2Grant(id, request, grant); err != nil {
		_, _ = h.store.FailSecretGrantDelivery(id, requestID, err.Error())
		errorJSON(w, http.StatusConflict, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, map[string]any{"requestID": requestID, "deliveredTo": "attach-sidecar"})
}

func secretRequest(requests []model.SecretGrantRequest, id string) (model.SecretGrantRequest, bool) {
	for _, request := range requests {
		if request.ID == id {
			return request, true
		}
	}
	return model.SecretGrantRequest{}, false
}

func (h *Handler) ConsumeSecretGrant(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CellID    string `json:"cellID"`
		RequestID string `json:"requestID"`
		Grant     string `json:"grant"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	value, receipt, err := h.store.ConsumeSecretGrant(input.CellID, input.RequestID, input.Grant)
	if err != nil {
		errorJSON(w, http.StatusForbidden, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"value": value, "receipt": receipt})
}

func (h *Handler) ConfigureSecretProxy(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Credential  string `json:"credential"`
		Destination string `json:"destination"`
		Header      string `json:"header"`
		Actor       string `json:"actor"`
		Capability  string `json:"capability"`
	}
	if err = decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	input.Actor = defaultEventText(input.Actor, "operator")
	snapshot, route, token, err := h.store.ConfigureSecretProxy(id, input.Credential, input.Destination, input.Header, input.Actor, input.Capability)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	proxyURL := scheme + "://" + r.Host + "/api/proxy/" + id + "/" + route.ID + "?cap=" + url.QueryEscape(token)
	h.hub.DeliverProxyRoute(id, route.ID, proxyURL)
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusCreated, map[string]any{"route": route, "proxyURL": proxyURL})
}

func (h *Handler) SecretProxy(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid proxy path"))
		return
	}
	cellID, routeID := parts[2], parts[3]
	route, credential, _, err := h.store.ResolveSecretProxy(cellID, routeID, r.URL.Query().Get("cap"))
	if err != nil {
		errorJSON(w, http.StatusForbidden, err)
		return
	}
	base, err := url.Parse(route.Destination)
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, err)
		return
	}
	suffix := "/" + strings.Join(parts[4:], "/")
	target := base.ResolveReference(&url.URL{Path: strings.TrimRight(base.Path, "/") + suffix, RawQuery: r.URL.RawQuery})
	query := target.Query()
	query.Del("cap")
	target.RawQuery = query.Encode()
	body := http.MaxBytesReader(w, r.Body, 8<<20)
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	for key, values := range r.Header {
		canonical := http.CanonicalHeaderKey(key)
		if canonical == "Authorization" || canonical == "Cookie" || canonical == "Proxy-Authorization" || strings.HasPrefix(canonical, "X-Mercutio-") {
			continue
		}
		for _, value := range values {
			request.Header.Add(canonical, value)
		}
	}
	injected := credential
	if http.CanonicalHeaderKey(route.Header) == "Authorization" {
		injected = "Bearer " + credential
	}
	request.Header.Set(route.Header, injected)
	response, err := h.proxyClient.Do(request)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, err)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		canonical := http.CanonicalHeaderKey(key)
		if canonical == "Set-Cookie" || canonical == "Location" {
			continue
		}
		for _, value := range values {
			w.Header().Add(canonical, value)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 16<<20))
}

func (h *Handler) Analyze(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Path    string  `json:"path"`
		Content *string `json:"content"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	file, err := h.store.File(id, input.Path)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	content := file.Content
	if input.Content != nil {
		content = *input.Content
	}
	result := h.intelligence.AnalyzeIncremental(id+":"+file.Path, file.Path, file.Language, content)
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Path  string `json:"path"`
		Actor string `json:"actor"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.DeleteFile(id, input.Path, input.Actor)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) PolicyPreview(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Content *string `json:"content"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	content := ""
	if input.Content != nil {
		content = *input.Content
	} else if file, fileErr := h.store.File(id, "policy/sandbox.yaml"); fileErr == nil {
		content = file.Content
	}
	preview, err := h.store.PolicyPreview(id, content)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *Handler) PolicyApply(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Content    string `json:"content"`
		Actor      string `json:"actor"`
		Capability string `json:"capability"`
	}
	if err = decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if input.Capability == "" {
		input.Capability = r.Header.Get("X-Mercutio-Capability")
	}
	snapshot, preview, err := h.store.ApplyPolicyAuthorized(r.Context(), id, input.Content, input.Actor, input.Capability)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, map[string]any{"cell": snapshot, "preview": preview})
}

func (h *Handler) Edit(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Path    string `json:"path"`
		Content string `json:"content"`
		Actor   string `json:"actor"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.ApplyEdit(id, input.Path, input.Content, input.Actor)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) UndoEdit(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Path      string `json:"path"`
		Actor     string `json:"actor"`
		AgentOnly bool   `json:"agentOnly"`
	}
	if err = decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var snapshot model.CellSnapshot
	if input.AgentOnly {
		snapshot, err = h.store.RevertAgentEdit(id, input.Path, input.Actor)
	} else {
		snapshot, err = h.store.UndoEdit(id, input.Path, input.Actor)
	}
	if err != nil {
		errorJSON(w, http.StatusConflict, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Prompt(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Prompt string `json:"prompt"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Prompt(id, input.Prompt)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Destroy(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Destroy(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	h.hub.DisconnectCell(id, "cell destroyed")
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "cells" || parts[3] != "reviews" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid review path"))
		return
	}
	snapshot, err := h.store.ApproveReview(parts[2], parts[4])
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) AcknowledgeReview(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid review path"))
		return
	}
	var input struct {
		Actor            string `json:"actor"`
		Reason           string `json:"reason"`
		SecretFinding    bool   `json:"secretFinding"`
		EvidenceDegraded bool   `json:"evidenceDegraded"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.AcknowledgeReview(parts[2], parts[4], input.Actor, input.Reason, input.SecretFinding, input.EvidenceDegraded)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) RejectReview(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid review path"))
		return
	}
	var input struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, prompt, err := h.store.RejectReview(parts[2], parts[4], input.Actor, input.Reason)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	if clientID := h.hub.AgentClient(parts[2]); clientID != "" {
		h.hub.SendAgent(clientID, "prompt:deliver", map[string]string{"cellID": parts[2], "prompt": prompt})
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) ShadowDecision(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid shadow path"))
		return
	}
	cellID, shadowID, operation := parts[2], parts[4], parts[5]
	var input struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var snapshot model.CellSnapshot
	var result any
	var err error
	switch operation {
	case "adopt":
		snapshot, err = h.store.AdoptShadow(cellID, shadowID, input.Actor)
	case "merge":
		var mergeResult shadow.Result
		snapshot, mergeResult, err = h.store.MergeShadow(cellID, shadowID, input.Actor)
		result = mergeResult
	case "discard":
		snapshot, err = h.store.DiscardShadow(cellID, shadowID, input.Actor, input.Reason)
	default:
		err = fmt.Errorf("unknown shadow operation")
	}
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, map[string]any{"cell": snapshot, "result": result})
}

func pathParam(path, segment string, offset int) (string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) <= offset || parts[0] != "api" || parts[1] != segment || parts[offset] == "" {
		return "", fmt.Errorf("invalid %s path", segment)
	}
	return parts[offset], nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorJSON(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
