package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type BatchPoster interface {
	PostBatch(context.Context, Batch) error
}

type telemetryCursorSource interface {
	TelemetryCursor(context.Context, string) (uint64, error)
}

type TelemetryQueue struct {
	mu       sync.Mutex
	flushMu  sync.Mutex
	capacity int
	nodeID   string
	events   []KernelEvent
	drops    map[string]uint64
	wake     chan struct{}
	sequence uint64
	poster   BatchPoster
}

func NewTelemetryQueue(nodeID string, capacity int, poster BatchPoster) *TelemetryQueue {
	if capacity <= 0 {
		capacity = 8192
	}
	return &TelemetryQueue{capacity: capacity, nodeID: nodeID, drops: map[string]uint64{}, wake: make(chan struct{}, 1), poster: poster}
}

func (q *TelemetryQueue) Enqueue(event KernelEvent) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) >= q.capacity {
		if !priorityEvent(event) {
			q.drops["queue-allow"]++
			return false
		}
		replace := -1
		for index, queued := range q.events {
			if !priorityEvent(queued) {
				replace = index
				break
			}
		}
		if replace < 0 {
			q.drops["queue-priority"]++
			return false
		}
		q.events = append(q.events[:replace], q.events[replace+1:]...)
		q.drops["queue-allow"]++
	}
	q.events = append(q.events, event)
	if len(q.events) >= 512 {
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
	return true
}

func priorityEvent(event KernelEvent) bool {
	if event.Verdict != "" && !strings.EqualFold(event.Verdict, "allow") {
		return true
	}
	switch strings.ToLower(event.ActionDanger["mode"]) {
	case "mutate", "write", "execute", "control", "admin":
		return true
	default:
		return false
	}
}

func (q *TelemetryQueue) AddKernelDrops(source string, count uint64) {
	if count == 0 {
		return
	}
	q.mu.Lock()
	q.drops[source] += count
	q.mu.Unlock()
}

func (q *TelemetryQueue) Run(ctx context.Context) error {
	if q.poster == nil {
		return fmt.Errorf("telemetry batch poster is required")
	}
	if err := q.reconcileCursor(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = q.flush(context.Background())
			return ctx.Err()
		case <-ticker.C:
			if err := q.flush(ctx); err != nil {
				q.AddKernelDrops("ingest", 1)
			}
		case <-q.wake:
			if err := q.flush(ctx); err != nil {
				q.AddKernelDrops("ingest", 1)
			}
		}
	}
}

func (q *TelemetryQueue) reconcileCursor(ctx context.Context) error {
	if source, ok := q.poster.(telemetryCursorSource); ok {
		sequence, err := source.TelemetryCursor(ctx, q.nodeID)
		if err != nil {
			return fmt.Errorf("reconcile telemetry cursor: %w", err)
		}
		q.mu.Lock()
		q.sequence = sequence
		q.mu.Unlock()
	}
	return nil
}

func (q *TelemetryQueue) flush(ctx context.Context) error {
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	q.mu.Lock()
	if len(q.events) == 0 && len(q.drops) == 0 {
		q.mu.Unlock()
		return nil
	}
	count := len(q.events)
	if count > 512 {
		count = 512
	}
	events := append([]KernelEvent(nil), q.events[:count]...)
	q.events = append([]KernelEvent(nil), q.events[count:]...)
	drops := make(map[string]uint64, len(q.drops))
	for source, value := range q.drops {
		drops[source] = value
	}
	q.drops = map[string]uint64{}
	batchSeq := q.sequence + 1
	q.mu.Unlock()
	clock := clockSync(q.nodeID)
	for i := range events {
		events[i].ClockSkewBoundM = clock.SkewBoundMS
	}
	batch := Batch{NodeID: q.nodeID, BatchSeq: batchSeq, Clock: clock, Events: events, Drops: drops, SentAt: time.Now().UTC()}
	if err := q.poster.PostBatch(ctx, batch); err != nil {
		q.mu.Lock()
		q.events = append(events, q.events...)
		for source, value := range drops {
			q.drops[source] += value
		}
		q.mu.Unlock()
		return err
	}
	q.mu.Lock()
	q.sequence = batchSeq
	q.mu.Unlock()
	return nil
}

func (q *TelemetryQueue) Flush(ctx context.Context) (uint64, error) {
	if err := q.flush(ctx); err != nil {
		return 0, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sequence, nil
}

type NodeDrainReporter struct {
	NodeID  string
	Queue   *TelemetryQueue
	Control HTTPControl
}

func (r NodeDrainReporter) FinalizeDisarm(ctx context.Context, cellID string) error {
	if r.Queue == nil {
		return fmt.Errorf("telemetry queue is required")
	}
	sequence, err := r.Queue.Flush(ctx)
	if err != nil {
		return fmt.Errorf("flush final telemetry: %w", err)
	}
	return r.Control.Disarmed(ctx, cellID, r.NodeID, sequence)
}

func clockSync(nodeID string) ClockSync {
	before := time.Now().UnixNano()
	var monotonic unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic)
	after := time.Now().UnixNano()
	bound := (after - before + int64(time.Millisecond) - 1) / int64(time.Millisecond)
	if bound < 1 {
		bound = 1
	}
	return ClockSync{MonotonicNS: monotonic.Nano(), RealtimeNS: before + (after-before)/2, SkewBoundMS: bound, NodeID: nodeID}
}

type HTTPControl struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (h HTTPControl) Cells(ctx context.Context, nodeID string) ([]Cell, error) {
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/nodes/" + nodeID + "/cells"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Mercutio-Event-Token", h.Token)
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %s", response.Status)
	}
	var payload struct {
		Cells []Cell `json:"cells"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Cells, nil
}

func (h HTTPControl) TelemetryCursor(ctx context.Context, nodeID string) (uint64, error) {
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/nodes/" + nodeID + "/telemetry-cursor"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("X-Mercutio-Event-Token", h.Token)
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("control plane returned %s", response.Status)
	}
	var payload struct {
		NodeID       string `json:"nodeID"`
		LastBatchSeq uint64 `json:"lastBatchSeq"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return 0, err
	}
	if payload.NodeID != nodeID {
		return 0, fmt.Errorf("control plane returned telemetry cursor for %q", payload.NodeID)
	}
	return payload.LastBatchSeq, nil
}

func (h HTTPControl) Armed(ctx context.Context, cell Cell, result ArmResult) error {
	payload, _ := json.Marshal(map[string]any{
		"nodeID": cell.NodeID, "programs": result.Programs, "manifestDigest": result.ManifestDigest,
		"objectDigest": result.ObjectDigest, "profileDigest": cell.ProfileDigest, "cgroupID": cell.CgroupID, "enforcement": result.Enforcement,
	})
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/cells/" + cell.ID + "/armed"
	return h.do(ctx, http.MethodPost, endpoint, payload)
}

func (h HTTPControl) Disarmed(ctx context.Context, cellID, nodeID string, finalBatchSeq uint64) error {
	payload, _ := json.Marshal(map[string]any{"nodeID": nodeID, "finalBatchSeq": finalBatchSeq})
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/cells/" + cellID + "/disarmed"
	return h.do(ctx, http.MethodPost, endpoint, payload)
}

func (h HTTPControl) PostBatch(ctx context.Context, batch Batch) error {
	var payload bytes.Buffer
	writer := gzip.NewWriter(&payload)
	if err := json.NewEncoder(writer).Encode(batch); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/telemetry/kernel"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &payload)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	return h.send(request)
}

func (h HTTPControl) ActionDecisions(ctx context.Context, nodeID string) ([]ActionDecision, error) {
	endpoint := strings.TrimRight(h.BaseURL, "/") + "/api/internal/nodes/" + nodeID + "/action-decisions"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Mercutio-Event-Token", h.Token)
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %s", response.Status)
	}
	var payload struct {
		Decisions []ActionDecision `json:"decisions"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Decisions, nil
}

func (h HTTPControl) do(ctx context.Context, method, endpoint string, payload []byte) error {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return h.send(request)
}

func (h HTTPControl) send(request *http.Request) error {
	request.Header.Set("X-Mercutio-Event-Token", h.Token)
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("control plane returned %s", response.Status)
	}
	return nil
}
