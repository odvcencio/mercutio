package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestDiskReconcilerPreservesUnknownBytesAndIngestsAgainstKnownBase(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.go")
	if err := os.WriteFile(path, []byte("disk-before-connect"), 0o644); err != nil {
		t.Fatal(err)
	}
	type edit struct {
		path, base, content string
		deleted             bool
	}
	edits := make(chan edit, 4)
	r, err := newDiskReconciler(root, func(path, base, content string, deleted bool) {
		edits <- edit{path: path, base: base, content: content, deleted: deleted}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.ApplySnapshot([]model.File{{Path: "main.go", Content: "server"}})
	select {
	case got := <-edits:
		if got.path != "main.go" || got.base != "" || got.content != "disk-before-connect" {
			t.Fatalf("unknown edit=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("unknown disk bytes were not preserved")
	}
	waitForDiskContent(t, path, "server")
	if err := os.WriteFile(path, []byte("agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-edits:
		if got.base != "server" || got.content != "agent" {
			t.Fatalf("disk edit=%+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disk edit was not ingested")
	}
}

func TestDiskReconcilerDebouncesLatestSnapshotAndMaterializesDeletion(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.go")
	if err := os.WriteFile(path, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}
	edits := make(chan string, 4)
	r, err := newDiskReconciler(root, func(_ string, _ string, content string, _ bool) { edits <- content })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.ApplySnapshot([]model.File{{Path: "main.go", Content: "initial"}})
	r.ApplySnapshot([]model.File{{Path: "main.go", Content: "first"}})
	r.ApplySnapshot([]model.File{{Path: "main.go", Content: "latest"}})
	if got, _ := os.ReadFile(path); string(got) != "initial" {
		t.Fatalf("write was not debounced: %q", got)
	}
	waitForDiskContent(t, path, "latest")
	select {
	case edit := <-edits:
		t.Fatalf("materialization looped back as disk edit: %q", edit)
	case <-time.After(200 * time.Millisecond):
	}
	r.ApplySnapshot(nil)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("removed CRDT file remained in worktree")
}

func TestDiskReconcilerReportsDeletion(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.go")
	if err := os.WriteFile(path, []byte("known"), 0o644); err != nil {
		t.Fatal(err)
	}
	type edit struct {
		base    string
		deleted bool
	}
	edits := make(chan edit, 1)
	r, err := newDiskReconciler(root, func(_ string, base string, _ string, deleted bool) {
		edits <- edit{base: base, deleted: deleted}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.ApplySnapshot([]model.File{{Path: "main.go", Content: "known"}})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-edits:
		if got.base != "known" || !got.deleted {
			t.Fatalf("delete=%+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disk deletion was not ingested")
	}
}

func TestDiskReconcilerRejectsSymlinkEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	r, err := newDiskReconciler(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.resolve("escape/file.txt"); err == nil {
		t.Fatal("symlink escape was accepted")
	}
}

func TestAtomicWriteUsesRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "file.txt")
	if err := atomicWrite(path, []byte("value")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "value" {
		t.Fatalf("content=%q", got)
	}
}

func waitForDiskContent(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := os.ReadFile(path); err == nil && string(got) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, err := os.ReadFile(path)
	t.Fatalf("materialized=%q err=%v, want %q", got, err, want)
}
