//go:build kernelintegration

package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	continuumhorizon "m31labs.dev/continuum/horizon"
	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

func TestKernelLoadsAttachesAndEnforcesStrictExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("kernel integration requires root")
	}
	dist := os.Getenv("MERCUTIO_KERNEL_ARTIFACT_DIR")
	events := &integrationEventQueue{events: make(chan KernelEvent, 64)}
	manager, err := NewProgramManager(ProgramOptions{
		ManifestPath: filepath.Join(dist, "mercutio.cap.json"), ObjectPath: filepath.Join(dist, "mercutio.bpf.o"),
		DigestPins: readIntegrationPins(t, filepath.Join(dist, "pins.json")), PublicKeys: readIntegrationKeys(t, filepath.Join(dist, "public-keys.json")), Queue: events,
	})
	if err != nil {
		t.Fatalf("load signed BPF collection: %v", err)
	}
	defer manager.Close()
	cgroup := filepath.Join("/sys/fs/cgroup", "mercutio-kernel-integration-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroup)
	info, _ := os.Stat(cgroup)
	cgroupID := info.Sys().(*syscall.Stat_t).Ino
	workspace := t.TempDir()
	workspaceInfo, _ := os.Stat(workspace)
	device := uint64(workspaceInfo.Sys().(*syscall.Stat_t).Dev)
	copyPath := filepath.Join(workspace, "copied-true")
	data, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	sentinel := exec.Command("/bin/sleep", "30")
	sentinel.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err := sentinel.Start(); err != nil {
		t.Fatalf("start cgroup sentinel: %v", err)
	}
	defer func() {
		_ = sentinel.Process.Kill()
		_ = sentinel.Wait()
	}()
	baselineOpen := medianOpenLatency(t, fd)
	baselineCPU := medianCPULatency(t, fd)
	if _, err := manager.Arm(context.Background(), Cell{ID: "kernel-open-performance", Profile: "open", CgroupPath: cgroup, CgroupID: cgroupID, CgroupIDs: []uint64{cgroupID}, WorktreeDev: device, ScratchDev: device, RuntimeDev: device}); err != nil {
		t.Fatalf("arm open performance cell: %v", err)
	}
	enforcedOpen := medianOpenLatency(t, fd)
	enforcedCPU := medianCPULatency(t, fd)
	if err := manager.Disarm(context.Background(), "kernel-open-performance"); err != nil {
		t.Fatal(err)
	}
	if enforcedOpen > baselineOpen+baselineOpen/50 {
		t.Fatalf("LSM open-heavy latency baseline=%dns enforced=%dns overhead=%.2f%%, budget 2%%", baselineOpen, enforcedOpen, float64(enforcedOpen-baselineOpen)*100/float64(baselineOpen))
	}
	if enforcedCPU > baselineCPU+baselineCPU/20 {
		t.Fatalf("NodeAgent workload latency baseline=%dns enforced=%dns overhead=%.2f%%, budget 5%%", baselineCPU, enforcedCPU, float64(enforcedCPU-baselineCPU)*100/float64(baselineCPU))
	}
	if _, err := manager.Arm(context.Background(), Cell{ID: "kernel-test", Profile: "strict", CgroupPath: cgroup, CgroupID: cgroupID, CgroupIDs: []uint64{cgroupID}, WorktreeDev: device, ScratchDev: device, RuntimeDev: device}); err != nil {
		t.Fatalf("arm strict cgroup: %v", err)
	}
	assertStrictGoBuildAndTest(t, fd, workspace)
	assertStrictCargoBuildAndTest(t, fd, workspace)
	assertDeniedExecVisible(t, exec.Command(copyPath), fd, events, "kernel-test")
	assertDeniedExecVisible(t, exec.Command("/usr/bin/python3", "-c", "pass"), fd, events, "kernel-test")
	if err := manager.Disarm(context.Background(), "kernel-test"); err != nil {
		t.Fatal(err)
	}
	assertKernelMapsEmpty(t, manager)
	globalLinks := countGlobalLinks(manager)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range 50 {
		id := fmt.Sprintf("kernel-churn-%02d", i)
		if _, err := manager.Arm(context.Background(), Cell{ID: id, Profile: "strict", CgroupPath: cgroup, CgroupID: cgroupID, CgroupIDs: []uint64{cgroupID}, WorktreeDev: device, ScratchDev: device, RuntimeDev: device}); err != nil {
			t.Fatalf("arm churn cell %d: %v", i, err)
		}
		if err := manager.Disarm(context.Background(), id); err != nil {
			t.Fatalf("disarm churn cell %d: %v", i, err)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	assertKernelMapsEmpty(t, manager)
	if len(manager.cells) != 0 || len(manager.identities) != 0 {
		t.Fatalf("manager retained cells=%d identities=%d", len(manager.cells), len(manager.identities))
	}
	if links := countGlobalLinks(manager); links != globalLinks {
		t.Fatalf("global BPF links grew from %d to %d", globalLinks, links)
	}
	if after.HeapAlloc > before.HeapAlloc+2*1024*1024 {
		t.Fatalf("NodeAgent heap grew from %d to %d bytes after churn", before.HeapAlloc, after.HeapAlloc)
	}
}

func assertStrictCargoBuildAndTest(t *testing.T, cgroup *os.File, workspace string) {
	t.Helper()
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Log("cargo is not installed on this kernel runner; Rust toolchain proof skipped")
		return
	}
	project := filepath.Join(workspace, "strict-rust-project")
	target := filepath.Join(workspace, "cargo-target")
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"Cargo.toml": "[package]\nname = \"strictproof\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
		"src/lib.rs": `pub fn add(a: i32, b: i32) -> i32 { a + b }

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn generated_runner_executes_but_cannot_spawn_shell() {
        assert_eq!(add(2, 3), 5);
        assert!(Command::new("/bin/sh").arg("-c").arg("true").status().is_err());
    }
}
`,
	}
	for name, content := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	environment := append(os.Environ(), "CARGO_TARGET_DIR="+target, "CARGO_NET_OFFLINE=true")
	for _, arguments := range [][]string{{"build", "--offline"}, {"test", "--offline"}} {
		command := exec.Command(cargo, arguments...)
		command.Dir = project
		command.Env = environment
		command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("strict cargo %s: %v\n%s", arguments[0], err, output)
		}
	}
}

func assertStrictGoBuildAndTest(t *testing.T, cgroup *os.File, workspace string) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(workspace, "strict-go-project")
	cache := filepath.Join(workspace, "go-cache")
	tmp := filepath.Join(workspace, "tmp")
	for _, path := range []string{project, cache, tmp} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"go.mod":   "module example.invalid/strictproof\n\ngo 1.24\n",
		"proof.go": "package strictproof\n\nfunc Add(a, b int) int { return a + b }\n",
		"proof_test.go": `package strictproof

import (
	"os/exec"
	"testing"
)

func TestGeneratedRunnerExecutesButCannotSpawnShell(t *testing.T) {
	if Add(2, 3) != 5 {
		t.Fatal("generated test runner did not execute")
	}
	if err := exec.Command("/bin/sh", "-c", "true").Run(); err == nil {
		t.Fatal("generated test runner inherited toolchain execution authority")
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	environment := append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOCACHE="+cache, "GOTMPDIR="+tmp, "TMPDIR="+tmp, "HOME="+workspace)
	for _, arguments := range [][]string{{"build", "./..."}, {"test", "-count=1", "./..."}} {
		command := exec.Command(goBinary, arguments...)
		command.Dir = project
		command.Env = environment
		command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("strict go %s: %v\n%s", arguments[0], err, output)
		}
	}
}

func medianOpenLatency(t *testing.T, cgroup *os.File) int64 {
	t.Helper()
	const script = `import os,time
n=300000
started=time.perf_counter_ns()
for _ in range(n):
    fd=os.open('/etc/hosts',os.O_RDONLY)
    os.close(fd)
print((time.perf_counter_ns()-started)//n)
`
	values := make([]int64, 5)
	for i := range values {
		command := exec.Command("/usr/bin/python3", "-c", script)
		command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		output, err := command.Output()
		if err != nil {
			t.Fatalf("open-heavy probe: %v", err)
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
		if err != nil || value <= 0 {
			t.Fatalf("open-heavy probe output %q: %v", output, err)
		}
		values[i] = value
	}
	slices.Sort(values)
	return values[len(values)/2]
}

func medianCPULatency(t *testing.T, cgroup *os.File) int64 {
	t.Helper()
	const script = `import time
n=8000000
started=time.perf_counter_ns()
value=0
for i in range(n):
    value=(value+i)&0xffffffff
print(time.perf_counter_ns()-started)
`
	values := make([]int64, 5)
	for i := range values {
		command := exec.Command("/usr/bin/python3", "-c", script)
		command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		output, err := command.Output()
		if err != nil {
			t.Fatalf("CPU workload probe: %v", err)
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
		if err != nil || value <= 0 {
			t.Fatalf("CPU workload probe output %q: %v", output, err)
		}
		values[i] = value
	}
	slices.Sort(values)
	return values[len(values)/2]
}

func assertDeniedExecVisible(t *testing.T, command *exec.Cmd, cgroup *os.File, events *integrationEventQueue, cellID string) {
	t.Helper()
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	err := command.Run()
	var exitErr *exec.ExitError
	denied := errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.As(err, &exitErr) && exitErr.ExitCode() == 126
	if !denied {
		t.Fatalf("strict cgroup executed %s; err=%v", command.Path, err)
	}
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case event := <-events.events:
			if event.CellID == cellID && event.Program == "GateExec" && event.Verdict == "deny" && event.Path == command.Path {
				return
			}
		case <-deadline:
			t.Fatalf("strict denial for %s was not visible in the kernel event queue", command.Path)
		}
	}
}

func countGlobalLinks(manager *ProgramManager) int {
	total := 0
	for _, programs := range manager.classes {
		total += len(programs.globalLinks)
	}
	return total
}

func assertKernelMapsEmpty(t *testing.T, manager *ProgramManager) {
	t.Helper()
	for class, programs := range manager.classes {
		counts := map[string]int{}
		if err := programs.objects.ForEachCellScope(func(uint64, bindings.CellScopeVal) error { counts["cell"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := programs.objects.ForEachNetAllow(func(bindings.NetKey, uint8) error { counts["net4"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := programs.objects.ForEachNet6Allow(func(bindings.Net6Key, uint8) error { counts["net6"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := programs.objects.ForEachFileRules(func(bindings.FileKey, bindings.FileRule) error { counts["file"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := programs.objects.ForEachInterpreterGrant(func(bindings.InterpreterKey, bindings.InterpreterGrantVal) error { counts["interpreter"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := programs.objects.ForEachToolchainGrant(func(bindings.InterpreterKey, bindings.InterpreterGrantVal) error { counts["toolchain"]++; return nil }); err != nil {
			t.Fatal(err)
		}
		for name, count := range counts {
			if count != 0 {
				t.Fatalf("class %d retained %d %s map entries", class, count, name)
			}
		}
	}
}

type integrationEventQueue struct {
	events chan KernelEvent
}

func (q *integrationEventQueue) Enqueue(event KernelEvent) bool {
	select {
	case q.events <- event:
		return true
	default:
		return false
	}
}

func (q *integrationEventQueue) AddKernelDrops(string, uint64) {}

func readIntegrationPins(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func readIntegrationKeys(t *testing.T, path string) []continuumhorizon.TrustedPublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var encoded []struct{ ID, Key string }
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatal(err)
	}
	result := make([]continuumhorizon.TrustedPublicKey, 0, len(encoded))
	for _, item := range encoded {
		key, err := base64.StdEncoding.DecodeString(item.Key)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, continuumhorizon.TrustedPublicKey{ID: item.ID, Key: ed25519.PublicKey(key)})
	}
	return result
}
