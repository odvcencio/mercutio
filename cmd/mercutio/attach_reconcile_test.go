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
	if got, _ := os.ReadFile(path); string(got) != "server" {
		t.Fatalf("materialized=%q", got)
	}
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
