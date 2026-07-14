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
			if event.CellID == cellID && event.Program == "GateExec" && event.Verdict == "deny" {
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
