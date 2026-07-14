//go:build kernelintegration

package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	continuumhorizon "m31labs.dev/continuum/horizon"
)

func TestKernelLoadsAttachesAndEnforcesStrictExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("kernel integration requires root")
	}
	dist := os.Getenv("MERCUTIO_KERNEL_ARTIFACT_DIR")
	manager, err := NewProgramManager(ProgramOptions{
		ManifestPath: filepath.Join(dist, "mercutio.cap.json"), ObjectPath: filepath.Join(dist, "mercutio.bpf.o"),
		DigestPins: readIntegrationPins(t, filepath.Join(dist, "pins.json")), PublicKeys: readIntegrationKeys(t, filepath.Join(dist, "public-keys.json")),
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
	if _, err := manager.Arm(context.Background(), Cell{ID: "kernel-test", Profile: "strict", CgroupPath: cgroup, CgroupID: cgroupID, CgroupIDs: []uint64{cgroupID}, WorktreeDev: device, ScratchDev: device, RuntimeDev: device}); err != nil {
		t.Fatalf("arm strict cgroup: %v", err)
	}
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
	command := exec.Command(copyPath)
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	err = command.Run()
	var exitErr *exec.ExitError
	denied := errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.As(err, &exitErr) && exitErr.ExitCode() == 126
	if !denied {
		t.Fatalf("strict cgroup executed copied binary; err=%v", err)
	}
}

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
