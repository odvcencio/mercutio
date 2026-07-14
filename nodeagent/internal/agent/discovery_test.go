package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestControlSourceDiscoversThroughControlPlaneAndResolvesLocalCgroups(t *testing.T) {
	root := t.TempDir()
	podUID := "12345678-abcd-ef01-2345-6789abcdef01"
	podRoot := filepath.Join(root, "kubepods.slice", "pod12345678_abcd_ef01_2345_6789abcdef01")
	if err := os.MkdirAll(filepath.Join(podRoot, "agent.scope"), 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/nodes/node-a/cells" || r.Header.Get("X-Mercutio-Event-Token") != "event-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"cells": []Cell{{
			ID: "cell-a", Namespace: "cells", PodName: "cell-a", PodUID: podUID, NodeID: "node-a",
			WorktreeDev: 11, ScratchDev: 12, RuntimeDev: 13, Programs: []string{"GateExec"}, ProfileDigest: "sha256:profile",
		}}})
	}))
	defer server.Close()

	cells, err := (ControlSource{Control: HTTPControl{BaseURL: server.URL, Token: "event-token"}, NodeID: "node-a", CgroupRoot: root}).ListCells(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].ID != "cell-a" || cells[0].Profile != "standard" || cells[0].CgroupPath != podRoot || len(cells[0].CgroupIDs) != 2 || cells[0].CgroupID == 0 {
		t.Fatalf("cells=%+v", cells)
	}
}

func TestResolveCgroupRequiresPodAndContainerIdentity(t *testing.T) {
	root := t.TempDir()
	podUID := "12345678-abcd-ef01-2345-6789abcdef01"
	containerID := "abcdef0123456789"
	want := filepath.Join(root, "kubepods.slice", "pod12345678_abcd_ef01_2345_6789abcdef01", "cri-containerd-"+containerID+".scope")
	if err := os.MkdirAll(want, 0o700); err != nil {
		t.Fatal(err)
	}
	path, id, err := ResolveCgroup(root, podUID, containerID)
	if err != nil {
		t.Fatalf("ResolveCgroup: %v", err)
	}
	if path != want || id == 0 {
		t.Fatalf("path=%q id=%d", path, id)
	}
	if _, _, err := ResolveCgroup(root, "different-pod", containerID); err == nil {
		t.Fatal("expected pod identity mismatch")
	}
}

func TestResolvePodCgroupsIncludesRootAndDescendantsBeforeAgentStarts(t *testing.T) {
	root := t.TempDir()
	podUID := "12345678-abcd-ef01-2345-6789abcdef01"
	podRoot := filepath.Join(root, "kubepods.slice", "pod12345678_abcd_ef01_2345_6789abcdef01")
	if err := os.MkdirAll(filepath.Join(podRoot, "init.scope", "nested.scope"), 0o700); err != nil {
		t.Fatal(err)
	}
	path, ids, err := ResolvePodCgroups(root, podUID)
	if err != nil {
		t.Fatal(err)
	}
	if path != podRoot || len(ids) != 3 || ids[0] == 0 {
		t.Fatalf("path=%q ids=%v", path, ids)
	}
}
