package cell

import (
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

func TestStoreLifecycleAndSharedDocuments(t *testing.T) {
	store := NewStore()
	created, err := store.Create("https://github.com/example/project", "main", "strict")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Status != model.CellReady || created.SandboxProfile != "strict" {
		t.Fatalf("created cell = %+v", created.Cell)
	}

	updated, err := store.ApplyEdit(created.ID, "README.md", "# changed\n\nA human edit.\n", "operator")
	if err != nil {
		t.Fatalf("ApplyEdit: %v", err)
	}
	if got := updated.Files[0].Content; got != "# changed\n\nA human edit.\n" {
		t.Fatalf("updated content = %q", got)
	}
	if updated.Revision <= created.Revision {
		t.Fatalf("revision did not advance: %d -> %d", created.Revision, updated.Revision)
	}

	steered, err := store.Prompt(created.ID, "Please tighten the policy review.")
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if steered.Status != model.CellSteering || steered.Agent.Status != "steering" {
		t.Fatalf("steered cell = %+v", steered.Cell)
	}

	approved, err := store.ApproveReview(created.ID, created.Reviews[0].ID)
	if err != nil {
		t.Fatalf("ApproveReview: %v", err)
	}
	if approved.Reviews[0].Status != "approved" {
		t.Fatalf("review status = %q", approved.Reviews[0].Status)
	}

	stopped, err := store.Destroy(created.ID)
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if stopped.Status != model.CellStopped || stopped.Agent.Connected {
		t.Fatalf("stopped cell = %+v", stopped.Cell)
	}
}

func TestStoreRejectsBlankCommands(t *testing.T) {
	store := NewStore()
	if _, err := store.Create("", "main", "standard"); err == nil {
		t.Fatal("Create accepted a blank repo")
	}
	if _, err := store.Prompt("cell-demo", " "); err == nil {
		t.Fatal("Prompt accepted a blank prompt")
	}
	if _, err := store.ApplyEdit("cell-demo", "", "x", "operator"); err == nil {
		t.Fatal("ApplyEdit accepted a blank path")
	}
}
