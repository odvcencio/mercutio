package cell

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

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
