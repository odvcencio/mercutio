package cell

import (
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestMinimalSpliceDoesNotScaleWithWholeFile(t *testing.T) {
	doc := NewStore().cells["cell-demo"].docs["cmd/hello/main.go"]
	before, err := doc.doc.TextToString(doc.text)
	if err != nil {
		t.Fatal(err)
	}
	after := before + "// x\n"
	inserted, deleted, err := spliceTextMinimal(doc, after)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 5 || deleted != 0 {
		t.Fatalf("ops inserted=%d deleted=%d for %d-byte file", inserted, deleted, len(before))
	}
}

func TestAgentWriteShadowsWhileHumanActiveAndAdoptsWithReceipt(t *testing.T) {
	store := NewStore()
	human, err := store.ApplyEdit("cell-demo", "cmd/hello/main.go", "package main\n\n// human\n", "operator")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := store.ApplyEdit("cell-demo", "cmd/hello/main.go", "package main\n\n// agent\n", "agent-cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.Shadows) != 1 || agent.Files[1].Content != human.Files[1].Content {
		t.Fatalf("shadow routing=%+v file=%q", agent.Shadows, agent.Files[1].Content)
	}
	shadowID := agent.Shadows[0].ID
	adopted, err := store.AdoptShadow("cell-demo", shadowID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(adopted.Shadows) != 2 || adopted.Shadows[0].Status != "adopted" || adopted.Shadows[1].Status != "open" {
		t.Fatalf("adoption must retain the resolved agent shadow and preserve human live work: %+v", adopted.Shadows)
	}
	file, err := store.File("cell-demo", "cmd/hello/main.go")
	if err != nil || file.Content != "package main\n\n// agent\n" {
		t.Fatalf("file=%q %v", file.Content, err)
	}
	found := false
	for _, record := range store.Evidence("cell-demo") {
		if record.Kind == "shadow-resolution" {
			found = true
		}
	}
	if !found {
		t.Fatal("shadow adoption lacked resolution receipt")
	}
	if removed := store.CollectShadowGarbage(time.Now().UTC()); removed != 1 {
		t.Fatalf("resolved shadow GC removed=%d, want 1", removed)
	}
}

func TestActorScopedUndoAndAgentRevertPreserveOtherWriter(t *testing.T) {
	store := NewStore()
	path := "cmd/hello/main.go"
	base, _ := store.File("cell-demo", path)
	human := base.Content + "// human\n"
	if _, err := store.ApplyEdit("cell-demo", path, human, "operator"); err != nil {
		t.Fatal(err)
	}
	_, _ = store.SetWriterActive("cell-demo", path, "operator", false)
	withAgent := human + "// agent\n"
	if _, err := store.ApplyEdit("cell-demo", path, withAgent, "agent-cell-demo"); err != nil {
		t.Fatal(err)
	}
	undone, err := store.UndoEdit("cell-demo", path, "operator")
	if err != nil {
		t.Fatal(err)
	}
	file := fileContent(undone, path)
	if strings.Contains(file, "// human") || !strings.Contains(file, "// agent") {
		t.Fatalf("actor undo rewrote another writer: %q", file)
	}
	reverted, err := store.RevertAgentEdit("cell-demo", path, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if file = fileContent(reverted, path); strings.Contains(file, "// agent") {
		t.Fatalf("agent revert left agent operation: %q", file)
	}
}

func fileContent(snapshot model.CellSnapshot, path string) string {
	for _, file := range snapshot.Files {
		if file.Path == path {
			return file.Content
		}
	}
	return ""
}
