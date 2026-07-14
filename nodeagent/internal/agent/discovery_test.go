package agent

import (
	"os"
	"path/filepath"
	"testing"
)

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
