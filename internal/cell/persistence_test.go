package cell

import (
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

func TestCellStateSurvivesRestartWithoutSecretMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first := NewStoreWithOptions(Options{StatePath: path, CapabilityKey: []byte("test-key")})
	created, err := first.Create("https://example.test/repo", "feature", "strict")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := first.ApplyEdit(created.ID, "main.go", "package main\n", "operator-test")
	if err != nil {
		t.Fatal(err)
	}
	writeCap, _ := first.MintSecretCapability(created.ID, "operator", "secret:write")
	if _, _, err = first.PutSecret(created.ID, "TOKEN", "do-not-persist", "operator", writeCap); err != nil {
		t.Fatal(err)
	}
	second := NewStoreWithOptions(Options{StatePath: path, CapabilityKey: []byte("test-key")})
	restored, err := second.Snapshot(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision != updated.Revision+1 {
		t.Fatalf("revision=%d want=%d", restored.Revision, updated.Revision+1)
	}
	file, err := second.File(created.ID, "main.go")
	if err != nil || file.Content != "package main\n" {
		t.Fatalf("restored file %#v, %v", file, err)
	}
	readCap, _ := second.MintSecretCapability(created.ID, "operator", "secret:read")
	if _, _, err = second.SecretValue(created.ID, "TOKEN", "operator", readCap); err == nil {
		t.Fatal("secret plaintext survived restart")
	}
	found := false
	for _, event := range restored.Events {
		if event.Kind == model.EventEdit && event.Action == "secret.write" {
			found = true
		}
	}
	if !found {
		t.Fatal("secret receipt event was not durable")
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("corrupt state did not fail closed")
		}
	}()
	_ = NewStoreWithOptions(Options{StatePath: path, CapabilityKey: []byte("test-key")})
}
