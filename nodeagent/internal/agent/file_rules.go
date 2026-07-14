package agent

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

const (
	fileDeny = uint32(1)
	fileAsk  = uint32(2)
)

var sensitiveFileTrees = []string{
	"/root/.ssh", "/root/.aws", "/root/.kube", "/root/.docker",
	"/home/agent/.ssh", "/home/agent/.aws", "/home/agent/.kube", "/home/agent/.docker",
	"/home/nonroot/.ssh", "/home/nonroot/.aws", "/home/nonroot/.kube", "/home/nonroot/.docker",
	"/var/run/secrets",
}

var governedFileTrees = []string{
	"/workspace/repo/.github", "/workspace/repo/.git", "/workspace/repo/.graft",
}

func (m *ProgramManager) collectFileRules(cell Cell, class uint32) (map[bindings.FileKey]uint32, error) {
	procRoot := m.options.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	roots, err := cellProcessRoots(procRoot, cell.CgroupPath)
	if err != nil {
		return nil, fmt.Errorf("resolve cell file roots: %w", err)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("resolve cell file roots: no process found in %s", cell.CgroupPath)
	}
	rules := map[bindings.FileKey]uint32{}
	cgroupIDs := cellCgroupIDs(cell)
	for _, root := range roots {
		for _, path := range sensitiveFileTrees {
			addFileTree(rules, cgroupIDs, root, path, fileDeny)
		}
		addProcEnvironRules(rules, cgroupIDs, root)
		if class < 2 {
			for _, path := range governedFileTrees {
				addFileTree(rules, cgroupIDs, root, path, fileAsk)
			}
			addFilePath(rules, cgroupIDs, root, "/workspace/repo/Makefile", fileAsk)
		}
	}
	return rules, nil
}

func (m *ProgramManager) RefreshRules(ctx context.Context, cellID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	loaded := m.cells[cellID]
	if loaded == nil || !hasProgram(loaded.cell.Programs, "GateFileOpen") {
		return nil
	}
	class, err := profileClass(loaded.cell.Profile)
	if err != nil {
		return err
	}
	rules, err := m.collectFileRules(loaded.cell, class)
	if err != nil {
		return err
	}
	newKeys := make([]bindings.FileKey, 0, len(rules))
	installed := make([]bindings.FileKey, 0, len(rules))
	for key, verdict := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := loaded.programs.objects.UpdateFileRules(key, bindings.FileRule{Verdict: verdict}); err != nil {
			for _, added := range installed {
				if !containsFileKey(loaded.fileKeys, added) {
					_ = loaded.programs.objects.DeleteFileRules(added)
				}
			}
			return fmt.Errorf("refresh FileRules: %w", err)
		}
		newKeys = append(newKeys, key)
		installed = append(installed, key)
	}
	for _, key := range loaded.fileKeys {
		if !containsFileKey(newKeys, key) {
			_ = loaded.programs.objects.DeleteFileRules(key)
		}
	}
	loaded.fileKeys = newKeys
	return nil
}

func containsFileKey(keys []bindings.FileKey, want bindings.FileKey) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

func addFileTree(rules map[bindings.FileKey]uint32, cgroupIDs []uint64, root, path string, verdict uint32) {
	base := filepath.Join(root, strings.TrimPrefix(path, "/"))
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return
	}
	_ = filepath.WalkDir(resolved, func(item string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		addFileIdentity(rules, cgroupIDs, item, verdict)
		return nil
	})
}

func addFilePath(rules map[bindings.FileKey]uint32, cgroupIDs []uint64, root, path string, verdict uint32) {
	addFileIdentity(rules, cgroupIDs, filepath.Join(root, strings.TrimPrefix(path, "/")), verdict)
}

func addProcEnvironRules(rules map[bindings.FileKey]uint32, cgroupIDs []uint64, root string) {
	proc := filepath.Join(root, "proc")
	entries, err := os.ReadDir(proc)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		addFileIdentity(rules, cgroupIDs, filepath.Join(proc, entry.Name(), "environ"), fileDeny)
	}
}

func addFileIdentity(rules map[bindings.FileKey]uint32, cgroupIDs []uint64, path string, verdict uint32) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 || stat.Dev == 0 {
		return
	}
	for _, cgroupID := range cgroupIDs {
		key := bindings.FileKey{CgroupId: cgroupID, Dev: uint64(stat.Dev), Ino: stat.Ino}
		if current := rules[key]; current == 0 || verdict == fileDeny {
			rules[key] = verdict
		}
	}
}
