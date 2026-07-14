package cell

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"m31labs.dev/gosx/crdt"
	crdtsync "m31labs.dev/gosx/crdt/sync"
	"m31labs.dev/mercutio/internal/model"
)

func TestInitialDocumentUsesRunEncodedSyncFrame(t *testing.T) {
	content := strings.Repeat("func generated() { return }\n", 700)
	doc := crdt.NewDoc()
	textID, err := docWithText(doc, content)
	if err != nil {
		t.Fatal(err)
	}
	message, ok := doc.GenerateSyncMessage(crdtsync.NewState())
	if !ok || len(message) >= 64*1024 {
		t.Fatalf("initial document sync frame=%d ok=%v", len(message), ok)
	}
	replica := crdt.NewDoc()
	if err := replica.ReceiveSyncMessage(crdtsync.NewState(), message); err != nil {
		t.Fatal(err)
	}
	if got, err := replica.TextToString(textID); err != nil || got != content {
		t.Fatalf("replica length=%d err=%v", len(got), err)
	}
}

func FuzzMinimalSpliceMatchesTarget(f *testing.F) {
	f.Add("hello world", "hello brave world")
	f.Add("αβγ", "α界γ")
	f.Fuzz(func(t *testing.T, before, after string) {
		if len(before) > 4096 || len(after) > 4096 {
			return
		}
		doc := crdt.NewDoc()
		text, err := docWithText(doc, before)
		if err != nil {
			t.Skip()
		}
		if _, _, err = spliceTextMinimal(textDocument{doc: doc, text: text}, after); err != nil {
			t.Fatal(err)
		}
		got, err := doc.TextToString(text)
		if err != nil || got != after {
			t.Fatalf("got=%q want=%q err=%v", got, after, err)
		}
	})
}

func TestRandomWriterInterleavingsConvergeDiskCRDTAndSnapshot(t *testing.T) {
	root := t.TempDir()
	store := NewStoreWithOptions(Options{WorktreeRoot: root})
	path := "cmd/hello/main.go"
	random := rand.New(rand.NewSource(42))
	for i := 0; i < 120; i++ {
		actor := "agent-cell-demo"
		if random.Intn(2) == 0 {
			actor = "operator"
		}
		if random.Intn(4) == 0 {
			_, _ = store.SetWriterActive("cell-demo", path, "operator", false)
		}
		content := "package main\n\n// revision " + strconv.Itoa(i) + " by " + actor + "\n"
		snapshot, err := store.ApplyEdit("cell-demo", path, content, actor)
		if err != nil {
			t.Fatal(err)
		}
		if shadow, ok := firstOpenShadow(snapshot); ok && random.Intn(3) == 0 {
			if random.Intn(2) == 0 {
				snapshot, err = store.AdoptShadow("cell-demo", shadow.ID, "operator")
			} else {
				snapshot, err = store.DiscardShadow("cell-demo", shadow.ID, "operator", "randomized convergence test")
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		assertConverged(t, store, root, path)
	}
	snapshot, _ := store.Snapshot("cell-demo")
	for {
		shadow, ok := firstOpenShadow(snapshot)
		if !ok {
			break
		}
		snapshot, _ = store.DiscardShadow("cell-demo", shadow.ID, "operator", "test cleanup")
	}
	assertConverged(t, store, root, path)
}

func firstOpenShadow(snapshot model.CellSnapshot) (model.ShadowRevision, bool) {
	for _, shadow := range snapshot.Shadows {
		if shadow.Status == "open" {
			return shadow, true
		}
	}
	return model.ShadowRevision{}, false
}

func assertConverged(t *testing.T, store *Store, root, path string) {
	t.Helper()
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	var file string
	for _, candidate := range snapshot.Files {
		if candidate.Path == path {
			file = candidate.Content
		}
	}
	doc := store.cells["cell-demo"].docs[path]
	text, err := doc.doc.TextToString(doc.text)
	if err != nil || text != file {
		t.Fatalf("CRDT=%q snapshot=%q err=%v", text, file, err)
	}
	disk, err := os.ReadFile(filepath.Join(root, "cell-demo", path))
	if err != nil || string(disk) != file {
		t.Fatalf("disk=%q snapshot=%q err=%v", disk, file, err)
	}
}
