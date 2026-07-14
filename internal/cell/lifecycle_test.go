package cell

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/sandbox"
)

type receiptRuntime struct{ *sandbox.MemoryRuntime }

func (*receiptRuntime) RequiresDrainReceipt() bool { return true }

func TestPauseResumeUsesNormativeLifecycle(t *testing.T) {
	store := NewStore()
	attached, err := store.Attach("cell-demo", store.cells["cell-demo"].attachToken, "agent-cell-demo", "agent")
	if err != nil || !attached.Agent.Connected {
		t.Fatalf("attach=%+v err=%v", attached.Agent, err)
	}
	paused, err := store.Pause("cell-demo", "operator")
	if err != nil || paused.Status != model.CellPaused || paused.Agent.Status != "paused" {
		t.Fatalf("pause=%s agent=%s err=%v", paused.Status, paused.Agent.Status, err)
	}
	resumed, err := store.Resume("cell-demo", "operator")
	if err != nil || resumed.Status != model.CellActive || resumed.Agent.Status != "working" {
		t.Fatalf("resume=%s agent=%s err=%v", resumed.Status, resumed.Agent.Status, err)
	}
}

func TestLoadStateNormalizesLegacyLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := persistedState{Version: 1, NextID: 2, ActiveID: "legacy", Cells: []persistedRecord{{Cell: model.Cell{ID: "legacy", RepoURL: "https://example.test/repo", Branch: "main", SandboxProfile: "standard", Status: "steering"}}}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithOptions(Options{StatePath: path, CapabilityKey: []byte("test-capability-key")})
	snapshot, err := store.Snapshot("legacy")
	if err != nil || snapshot.Status != model.CellActive {
		t.Fatalf("status=%s err=%v", snapshot.Status, err)
	}
}

func TestDestroyWaitsForDurableNodeDrainReceipt(t *testing.T) {
	store := NewStoreWithRuntime(&receiptRuntime{MemoryRuntime: sandbox.NewMemoryRuntime()})
	draining, err := store.Destroy("cell-demo")
	if err != nil || draining.Status != model.CellDraining {
		t.Fatalf("destroy status=%s err=%v", draining.Status, err)
	}
	if _, err = store.MarkDisarmed("cell-demo", "node-a", 1); err == nil {
		t.Fatal("accepted disarm receipt ahead of durable telemetry")
	}
	terminated, err := store.MarkDisarmed("cell-demo", "node-a", 0)
	if err != nil || terminated.Status != model.CellTerminated {
		t.Fatalf("terminated status=%s err=%v", terminated.Status, err)
	}
	receipts := store.Evidence("cell-demo")
	foundReceipt := false
	for _, receipt := range receipts {
		foundReceipt = foundReceipt || receipt.Kind == "cell-drain-receipt"
	}
	if !foundReceipt {
		t.Fatal("drain receipt missing")
	}
	if _, _, err = store.Reconcile(context.Background(), "cell-demo"); err != nil {
		t.Fatal(err)
	}
}
