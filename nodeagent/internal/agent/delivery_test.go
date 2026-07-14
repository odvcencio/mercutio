package agent

import (
	"context"
	"testing"
)

type recordingPoster struct{ batches []Batch }

func (p *recordingPoster) PostBatch(_ context.Context, batch Batch) error {
	p.batches = append(p.batches, batch)
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
}
