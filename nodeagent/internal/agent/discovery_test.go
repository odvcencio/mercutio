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
	procRoot := t.TempDir()
	podUID := "12345678-abcd-ef01-2345-6789abcdef01"
	podRoot := filepath.Join(root, "kubepods.slice", "pod12345678_abcd_ef01_2345_6789abcdef01")
	if err := os.MkdirAll(filepath.Join(podRoot, "agent.scope"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(podRoot, "agent.scope", "cgroup.procs"), []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "42"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "42", "mountinfo"), []byte("1 0 8:1 / / rw - ext4 root rw\n2 1 0:41 / /workspace rw - tmpfs workspace rw\n3 1 0:42 / /tmp rw - tmpfs scratch rw\n4 1 0:43 / /run/mercutio rw - tmpfs runtime rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/nodes/node-a/cells" || r.Header.Get("X-Mercutio-Event-Token") != "event-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"cells": []Cell{{
			ID: "cell-a", Namespace: "cells", PodName: "cell-a", PodUID: podUID, NodeID: "node-a",
			Programs: []string{"GateExec"}, ProfileDigest: "sha256:profile",
		}}})
	}))
	defer server.Close()

	cells, err := (ControlSource{Control: HTTPControl{BaseURL: server.URL, Token: "event-token"}, NodeID: "node-a", CgroupRoot: root, ProcRoot: procRoot}).ListCells(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].ID != "cell-a" || cells[0].Profile != "standard" || cells[0].CgroupPath != podRoot || len(cells[0].CgroupIDs) != 2 || cells[0].CgroupID == 0 || cells[0].WorktreeDev == 0 || cells[0].ScratchDev == 0 || cells[0].RuntimeDev == 0 {
		t.Fatalf("cells=%+v", cells)
	}
}

func TestResolvePodMountDevicesRejectsWorkspaceOnContainerRootDevice(t *testing.T) {
	cgroupRoot := t.TempDir()
	procRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(cgroupRoot, "cgroup.procs"), []byte("77\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "77"), 0o700); err != nil {
		t.Fatal(err)
	}
	mounts := "1 0 8:1 / / rw - ext4 root rw\n2 1 8:1 / /workspace rw - ext4 root rw\n3 1 0:42 / /tmp rw - tmpfs scratch rw\n4 1 0:43 / /run/mercutio rw - tmpfs runtime rw\n"
	if err := os.WriteFile(filepath.Join(procRoot, "77", "mountinfo"), []byte(mounts), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePodMountDevices(cgroupRoot, procRoot); err == nil {
		t.Fatal("workspace sharing the root filesystem device was accepted")
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
