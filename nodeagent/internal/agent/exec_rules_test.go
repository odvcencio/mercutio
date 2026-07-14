package agent

import (
	"os"
	"path/filepath"
	"testing"

	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

func TestCgroupFileContainsExactScopeOrDescendant(t *testing.T) {
	scope := "/sys/fs/cgroup/kubepods.slice/pod-a"
	for _, input := range []string{"0::/kubepods.slice/pod-a\n", "0::/kubepods.slice/pod-a/agent\n"} {
		if !cgroupFileContains(input, scope) {
			t.Fatalf("scope not found in %q", input)
		}
	}
	for _, input := range []string{"0::/kubepods.slice/pod-ab\n", "0::/other/pod-a\n"} {
		if cgroupFileContains(input, scope) {
			t.Fatalf("foreign scope matched %q", input)
		}
	}
}

func TestCellProcessRootsAndExecInodesUseContainerRoot(t *testing.T) {
	procRoot := t.TempDir()
	root := filepath.Join(procRoot, "42", "root")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "42", "cgroup"), []byte("0::/kubepods.slice/pod-a/agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "echo")
	if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	roots, err := cellProcessRoots(procRoot, "/sys/fs/cgroup/kubepods.slice/pod-a")
	if err != nil || len(roots) != 1 || roots[0] != root {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	rules := map[bindings.ExecKey]uint32{}
	addExecPath(rules, root, "/bin/echo", execAllow)
	if len(rules) != 1 {
		t.Fatalf("resolved rules=%v", rules)
	}
	for _, verdict := range rules {
		if verdict != execAllow {
			t.Fatalf("verdict=%d", verdict)
		}
	}
}

func TestStrictAgentScriptsReceiveSingleUseInterpreterGrant(t *testing.T) {
	root := t.TempDir()
	for path, content := range map[string]string{
		"/usr/local/bin/claude": "#!/usr/bin/env node\n",
		"/usr/local/bin/tiller": "native-binary",
		"/usr/bin/node":         "node-binary",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rules := map[bindings.ExecKey]uint32{}
	addStrictAgentPath(rules, root, "/usr/local/bin/claude")
	addStrictAgentPath(rules, root, "/usr/local/bin/tiller")
	addExecPath(rules, root, "/usr/bin/node", execInterpreter)
	counts := map[uint32]int{}
	for _, verdict := range rules {
		counts[verdict]++
	}
	if counts[execAllowInterpreter] != 1 || counts[execAllow] != 1 || counts[execInterpreter] != 1 {
		t.Fatalf("strict executable verdicts = %v", counts)
	}
}
