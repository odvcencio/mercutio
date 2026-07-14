package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

type KubernetesSource struct {
	Client     kubernetes.Interface
	NodeID     string
	CgroupRoot string
}

func (s KubernetesSource) ListCells(ctx context.Context) ([]Cell, error) {
	if s.Client == nil || strings.TrimSpace(s.NodeID) == "" {
		return nil, fmt.Errorf("Kubernetes client and node ID are required")
	}
	pods, err := s.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.nodeName", s.NodeID).String()})
	if err != nil {
		return nil, fmt.Errorf("list node sandbox pods: %w", err)
	}
	root := s.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	result := make([]Cell, 0)
	for _, pod := range pods.Items {
		if pod.Labels["mercutio.m31labs.dev/component"] != "cell" && pod.Labels["mercutio.dev/managed"] != "true" {
			continue
		}
		cellID := pod.Labels["mercutio.dev/cell-id"]
		if cellID == "" || pod.DeletionTimestamp != nil {
			continue
		}
		cgroupPath, cgroupIDs, err := ResolvePodCgroups(root, string(pod.UID))
		if err != nil {
			continue
		}
		worktreeDev, err := strconv.ParseUint(pod.Annotations["mercutio.dev/workspace-device"], 10, 64)
		if err != nil || worktreeDev == 0 {
			continue
		}
		var policy struct {
			Egress        []string `json:"egress"`
			Programs      []string `json:"programs"`
			ProfileDigest string   `json:"profileDigest"`
		}
		_ = json.Unmarshal([]byte(pod.Annotations["mercutio.dev/capability-manifest"]), &policy)
		result = append(result, Cell{
			ID: cellID, Namespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID),
			Profile: defaultString(pod.Labels["mercutio.dev/profile"], "standard"), NodeID: s.NodeID,
			CgroupPath: cgroupPath, CgroupID: cgroupIDs[0], CgroupIDs: cgroupIDs, WorktreeDev: worktreeDev, AllowedEgress: append([]string(nil), policy.Egress...), Programs: append([]string(nil), policy.Programs...), ProfileDigest: policy.ProfileDigest,
		})
	}
	return result, nil
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
