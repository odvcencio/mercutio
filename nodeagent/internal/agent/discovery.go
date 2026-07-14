package agent

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type ControlSource struct {
	Control    HTTPControl
	NodeID     string
	CgroupRoot string
	ProcRoot   string
}

func (s ControlSource) ListCells(ctx context.Context) ([]Cell, error) {
	if strings.TrimSpace(s.Control.BaseURL) == "" || strings.TrimSpace(s.NodeID) == "" {
		return nil, fmt.Errorf("control plane and node ID are required")
	}
	cells, err := s.Control.Cells(ctx, s.NodeID)
	if err != nil {
		return nil, fmt.Errorf("list node cells: %w", err)
	}
	root := s.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	result := make([]Cell, 0, len(cells))
	for _, cell := range cells {
		if strings.TrimSpace(cell.ID) == "" || strings.TrimSpace(cell.PodUID) == "" || cell.NodeID != s.NodeID {
			continue
		}
		cgroupPath, cgroupIDs, err := ResolvePodCgroups(root, cell.PodUID)
		if err != nil {
			continue
		}
		devices, err := ResolvePodMountDevices(cgroupPath, defaultString(s.ProcRoot, "/proc"))
		if err != nil {
			continue
		}
		cell.CgroupPath = cgroupPath
		cell.CgroupID = cgroupIDs[0]
		cell.CgroupIDs = cgroupIDs
		cell.WorktreeDev = devices.Workspace
		cell.ScratchDev = devices.Scratch
		cell.RuntimeDev = devices.Runtime
		cell.Profile = defaultString(cell.Profile, "standard")
		result = append(result, cell)
	}
	return result, nil
}

type MountDevices struct {
	Workspace uint64
	Scratch   uint64
	Runtime   uint64
}

// ResolvePodMountDevices derives writable mount identities from host procfs.
// mountinfo is kernel-owned metadata; no path in the cell volume is opened or
// trusted, and no assertion from a sandbox process participates in arming.
func ResolvePodMountDevices(cgroupRoot, procRoot string) (MountDevices, error) {
	pids, err := cgroupPIDs(cgroupRoot)
	if err != nil {
		return MountDevices{}, err
	}
	for _, pid := range pids {
		devices, rootDevice, readErr := readMountDevices(filepath.Join(procRoot, strconv.Itoa(pid), "mountinfo"))
		if readErr == nil && devices.Workspace != 0 && devices.Scratch != 0 && devices.Runtime != 0 && rootDevice != 0 && devices.Workspace != rootDevice {
			return devices, nil
		}
	}
	return MountDevices{}, fmt.Errorf("no pod process exposes distinct workspace, scratch, and runtime mounts")
}

func cgroupPIDs(root string) ([]int, error) {
	seen := make(map[int]struct{})
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if readErr != nil {
			if os.IsNotExist(readErr) || os.IsPermission(readErr) {
				return nil
			}
			return readErr
		}
		for _, field := range strings.Fields(string(data)) {
			pid, parseErr := strconv.Atoi(field)
			if parseErr == nil && pid > 0 {
				seen[pid] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan pod processes: %w", err)
	}
	pids := make([]int, 0, len(seen))
	for pid := range seen {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	if len(pids) == 0 {
		return nil, fmt.Errorf("pod cgroup has no visible host processes")
	}
	return pids, nil
}

func readMountDevices(path string) (MountDevices, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return MountDevices{}, 0, err
	}
	defer file.Close()
	devices := MountDevices{}
	var root uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		parts := strings.Split(fields[2], ":")
		if len(parts) != 2 {
			continue
		}
		major, majorErr := strconv.ParseUint(parts[0], 10, 32)
		minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
		if majorErr != nil || minorErr != nil {
			continue
		}
		device := unix.Mkdev(uint32(major), uint32(minor))
		switch unescapeMountInfo(fields[4]) {
		case "/":
			root = device
		case "/workspace":
			devices.Workspace = device
		case "/tmp":
			devices.Scratch = device
		case "/run/mercutio":
			devices.Runtime = device
		}
	}
	if err := scanner.Err(); err != nil {
		return MountDevices{}, 0, err
	}
	return devices, root, nil
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

// ResolvePodCgroups resolves the pod-level cgroup before application containers
// start, then returns every current descendant inode. Repeated discovery makes
// descendant registration converge within the reconcile interval.
func ResolvePodCgroups(root, podUID string) (string, []uint64, error) {
	root = filepath.Clean(root)
	token := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(podUID)), "-", "_")
	if token == "" {
		return "", nil, fmt.Errorf("pod UID is required")
	}
	var podRoot string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		name := strings.ReplaceAll(strings.ToLower(entry.Name()), "-", "_")
		if strings.Contains(name, token) && (podRoot == "" || len(path) < len(podRoot)) {
			podRoot = path
		}
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("scan pod cgroup: %w", err)
	}
	if podRoot == "" {
		return "", nil, fmt.Errorf("cgroup for pod %s not found", podUID)
	}
	ids := make([]uint64, 0, 8)
	err = filepath.WalkDir(podRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && stat.Ino != 0 {
			ids = append(ids, stat.Ino)
		}
		return nil
	})
	if err != nil || len(ids) == 0 {
		return "", nil, fmt.Errorf("resolve pod cgroup subtree: %w", err)
	}
	return podRoot, ids, nil
}

func trimContainerID(value string) string {
	if index := strings.Index(value, "://"); index >= 0 {
		value = value[index+3:]
	}
	return strings.TrimSpace(value)
}

// ResolveCgroup finds the unified cgroup directory for a container without
// depending on a kubelet path format. The container ID and Pod UID must both
// occur in the path, preventing a prefix collision with another workload.
func ResolveCgroup(root, podUID, containerID string) (string, uint64, error) {
	root = filepath.Clean(root)
	podToken := strings.ReplaceAll(strings.ToLower(podUID), "-", "_")
	containerID = strings.ToLower(strings.TrimSpace(containerID))
	if containerID == "" {
		return "", 0, fmt.Errorf("container ID is required")
	}
	var found string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		podMatch := podToken == "" || strings.Contains(strings.ReplaceAll(lower, "-", "_"), podToken)
		if podMatch && strings.Contains(lower, containerID) {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", 0, fmt.Errorf("scan cgroup v2 tree: %w", err)
	}
	if found == "" {
		return "", 0, fmt.Errorf("cgroup for pod %s container %s not found", podUID, containerID)
	}
	info, err := os.Stat(found)
	if err != nil {
		return "", 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return "", 0, fmt.Errorf("cgroup %s has no kernel inode ID", found)
	}
	return found, stat.Ino, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
