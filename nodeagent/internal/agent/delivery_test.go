package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recordingPoster struct{ batches []Batch }

func (p *recordingPoster) PostBatch(_ context.Context, batch Batch) error {
	p.batches = append(p.batches, batch)
	return nil
}

func TestNodeDrainReporterFlushesTelemetryBeforeReceipt(t *testing.T) {
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/internal/telemetry/kernel":
			order = append(order, "telemetry")
		case "/api/internal/cells/cell-a/disarmed":
			var body struct {
				NodeID        string `json:"nodeID"`
				FinalBatchSeq uint64 `json:"finalBatchSeq"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.NodeID != "node-a" || body.FinalBatchSeq != 1 {
				t.Fatalf("drain body=%+v", body)
			}
			order = append(order, "disarmed")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	control := HTTPControl{BaseURL: server.URL, Token: "node-token", Client: server.Client()}
	queue := NewTelemetryQueue("node-a", 8, control)
	queue.Enqueue(KernelEvent{CellID: "cell-a", Kind: "exec"})
	if err := (NodeDrainReporter{NodeID: "node-a", Queue: queue, Control: control}).FinalizeDisarm(context.Background(), "cell-a"); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "telemetry" || order[1] != "disarmed" {
		t.Fatalf("order=%v", order)
	}
}

type reconnectingPoster struct {
	batches   []Batch
	cursor    uint64
	failFirst bool
}

func (p *reconnectingPoster) TelemetryCursor(_ context.Context, _ string) (uint64, error) {
	return p.cursor, nil
}

func (p *reconnectingPoster) PostBatch(_ context.Context, batch Batch) error {
	p.batches = append(p.batches, batch)
	if p.failFirst {
		p.failFirst = false
		return errors.New("control plane unavailable")
	}
	return nil
}

func TestTelemetryQueueShedsAllowBeforeDeny(t *testing.T) {
	poster := &recordingPoster{}
	queue := NewTelemetryQueue("node-1", 2, poster)
	queue.Enqueue(KernelEvent{CellID: "a", Verdict: "allow"})
	queue.Enqueue(KernelEvent{CellID: "b", Verdict: "deny"})
	if !queue.Enqueue(KernelEvent{CellID: "c", Verdict: "deny"}) {
		t.Fatal("priority event was shed while allow event was queued")
	}
	if err := queue.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.batches) != 1 || len(poster.batches[0].Events) != 2 {
		t.Fatalf("batches = %+v", poster.batches)
	}
	for _, event := range poster.batches[0].Events {
		if event.Verdict == "allow" {
			t.Fatal("allow event survived priority shedding")
		}
	}
	if poster.batches[0].Drops["queue-allow"] != 1 {
		t.Fatalf("drops = %+v", poster.batches[0].Drops)
	}
	if poster.batches[0].Clock.SkewBoundMS <= 0 || poster.batches[0].Events[0].ClockSkewBoundM != poster.batches[0].Clock.SkewBoundMS {
		t.Fatalf("batch omitted clock skew bound: %+v", poster.batches[0])
	}
}

func TestTelemetryQueuePreservesAllowedHighDangerEffects(t *testing.T) {
	poster := &recordingPoster{}
	queue := NewTelemetryQueue("node-1", 2, poster)
	queue.Enqueue(KernelEvent{CellID: "observe-a", Verdict: "allow", ActionDanger: map[string]string{"mode": "observe"}})
	queue.Enqueue(KernelEvent{CellID: "observe-b", Verdict: "allow", ActionDanger: map[string]string{"mode": "read"}})
	if !queue.Enqueue(KernelEvent{CellID: "mutation", Verdict: "allow", ActionDanger: map[string]string{"mode": "mutate", "scope": "filesystem", "reversibility": "restart"}}) {
		t.Fatal("allowed high-danger mutation was shed while benign observations were queued")
	}
	if err := queue.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range poster.batches[0].Events {
		found = found || event.CellID == "mutation"
	}
	if !found {
		t.Fatal("allowed high-danger mutation did not survive priority shedding")
	}
}

func TestTelemetryQueueReconcilesCursorAndRetriesSameSequence(t *testing.T) {
	poster := &reconnectingPoster{cursor: 41, failFirst: true}
	queue := NewTelemetryQueue("node-1", 2, poster)
	if err := queue.reconcileCursor(context.Background()); err != nil {
		t.Fatal(err)
	}
	queue.Enqueue(KernelEvent{CellID: "a", Verdict: "deny"})
	if err := queue.flush(context.Background()); err == nil {
		t.Fatal("first upload unexpectedly succeeded")
	}
	if err := queue.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.batches) != 2 || poster.batches[0].BatchSeq != 42 || poster.batches[1].BatchSeq != 42 {
		t.Fatalf("retry sequences = %+v", poster.batches)
	}
	if queue.sequence != 42 {
		t.Fatalf("committed sequence = %d", queue.sequence)
	}
}
