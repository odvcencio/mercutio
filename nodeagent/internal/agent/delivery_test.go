package agent

import (
	"context"
	"errors"
	"testing"
)

type recordingPoster struct{ batches []Batch }

func (p *recordingPoster) PostBatch(_ context.Context, batch Batch) error {
	p.batches = append(p.batches, batch)
	return nil
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
