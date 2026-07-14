package cell

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"m31labs.dev/gosx/crdt"
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
	if _, err := store.SetWriterActive("cell-demo", "cmd/hello/main.go", "operator", true); err != nil {
		t.Fatal(err)
	}
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
	gcReason := ""
	for _, record := range store.Evidence("cell-demo") {
		if record.Kind != "shadow-gc-receipt" {
			continue
		}
		var fields map[string]string
		if json.Unmarshal(record.Payload, &fields) == nil {
			gcReason = fields["reason"]
		}
	}
	if gcReason != "adopted" {
		t.Fatalf("shadow GC receipt reason = %q, want adopted", gcReason)
	}
}

func TestSnapshotRedactsSecretShapedShadowContent(t *testing.T) {
	store := NewStore()
	path := "cmd/hello/main.go"
	if _, err := store.SetWriterActive("cell-demo", path, "operator", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyEdit("cell-demo", path, "package main\n// human\n", "operator"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ApplyEdit("cell-demo", path, "package main\n// ghp_abcdefghijklmnopqrstuvwxyz1234567890\n", "agent-cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Shadows) != 1 || strings.Contains(snapshot.Shadows[0].After, "ghp_") || !strings.Contains(strings.ToLower(snapshot.Shadows[0].After), "<redacted>") {
		t.Fatalf("snapshot exposed secret-shaped shadow content: %+v", snapshot.Shadows)
	}
}

func TestOpenBufferWithoutRecentHumanEditDoesNotRouteAgentToShadow(t *testing.T) {
	store := NewStore()
	path := "cmd/hello/main.go"
	if _, err := store.SetWriterActive("cell-demo", path, "operator", true); err != nil {
		t.Fatal(err)
	}
	agentContent := "package main\n\n// agent live\n"
	snapshot, err := store.ApplyEdit("cell-demo", path, agentContent, "agent-cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Shadows) != 0 || fileContent(snapshot, path) != agentContent {
		t.Fatalf("focus-only buffer was treated as active writer: shadows=%+v file=%q", snapshot.Shadows, fileContent(snapshot, path))
	}
}

func TestHumanEnteringDuringAgentWriteCreatesShadowAndTakesLiveBuffer(t *testing.T) {
	store := NewStore()
	path := "cmd/hello/main.go"
	base, err := store.File("cell-demo", path)
	if err != nil {
		t.Fatal(err)
	}
	agentContent := base.Content + "// agent in flight\n"
	if _, err = store.ApplyEdit("cell-demo", path, agentContent, "agent-cell-demo"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.SetWriterActive("cell-demo", path, "operator", true)
	if err != nil {
		t.Fatal(err)
	}
	if fileContent(snapshot, path) != base.Content {
		t.Fatalf("human did not take pre-agent live buffer: %q", fileContent(snapshot, path))
	}
	if len(snapshot.Shadows) != 1 || snapshot.Shadows[0].After != agentContent || snapshot.Shadows[0].Before != base.Content {
		t.Fatalf("agent in-flight set was not preserved as a shadow: %+v", snapshot.Shadows)
	}
	if _, err = store.RevertAgentEdit("cell-demo", path, "operator"); err == nil {
		t.Fatal("taken-over agent change remained independently revertible")
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

func TestActorScopedUndoMissingElementsIsNoOpWithNotice(t *testing.T) {
	store := NewStore()
	path := "cmd/hello/main.go"
	before, err := store.File("cell-demo", path)
	if err != nil {
		t.Fatal(err)
	}
	store.cells["cell-demo"].history = append(store.cells["cell-demo"].history, editOperation{
		Actor: "operator", Path: path, Inserted: []crdt.OpID{{Actor: "missing-actor", Counter: 999}}, CreatedAt: time.Now().UTC(),
	})
	snapshot, err := store.UndoEdit("cell-demo", path, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if got := fileContent(snapshot, path); got != before.Content {
		t.Fatalf("no-op undo changed content: %q", got)
	}
	found := false
	for _, event := range snapshot.Events {
		if event.Action == "buffer.undo.noop" {
			found = true
		}
	}
	if !found {
		t.Fatal("no-op undo did not emit an operator-visible notice")
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
