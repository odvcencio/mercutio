package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

func TestCollectFileRulesScopesSensitiveAndGovernedInodes(t *testing.T) {
	procRoot := t.TempDir()
	root := filepath.Join(procRoot, "101", "root")
	mustMkdirAll(t, filepath.Join(root, "root", ".ssh"))
	mustMkdirAll(t, filepath.Join(root, "workspace", "repo", ".github"))
	mustMkdirAll(t, filepath.Join(root, "proc", "1"))
	mustWriteFile(t, filepath.Join(procRoot, "101", "cgroup"), "0::/kubepods/cell\n")
	secret := filepath.Join(root, "root", ".ssh", "id_ed25519")
	workflow := filepath.Join(root, "workspace", "repo", ".github", "ci.yml")
	makefile := filepath.Join(root, "workspace", "repo", "Makefile")
	environ := filepath.Join(root, "proc", "1", "environ")
	for _, path := range []string{secret, workflow, makefile, environ} {
		mustWriteFile(t, path, "x")
	}

	manager := &ProgramManager{options: ProgramOptions{ProcRoot: procRoot}}
	cell := Cell{ID: "cell", CgroupPath: "/sys/fs/cgroup/kubepods/cell", CgroupIDs: []uint64{22, 11}}
	rules, err := manager.collectFileRules(cell, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, cgroupID := range []uint64{11, 22} {
		assertFileRule(t, rules, cgroupID, secret, fileDeny)
		assertFileRule(t, rules, cgroupID, environ, fileDeny)
		assertFileRule(t, rules, cgroupID, workflow, fileAsk)
		assertFileRule(t, rules, cgroupID, makefile, fileAsk)
	}
	openRules, err := manager.collectFileRules(cell, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertFileRule(t, openRules, 11, secret, fileDeny)
	assertFileRule(t, openRules, 11, workflow, 0)
}

func assertFileRule(t *testing.T, rules map[bindings.FileKey]uint32, cgroupID uint64, path string, want uint32) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	got := rules[bindings.FileKey{CgroupId: cgroupID, Dev: uint64(stat.Dev), Ino: stat.Ino}]
	if got != want {
		t.Fatalf("rule for %s in cgroup %d = %d, want %d", path, cgroupID, got, want)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
