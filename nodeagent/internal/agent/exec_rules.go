package agent

import (
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
	execAllow            = uint32(1)
	execDeny             = uint32(2)
	execAllowInterpreter = uint32(3)
	execInterpreter      = uint32(4)
)

var strictExecPaths = []string{
	"/usr/local/go/bin/go", "/usr/bin/go", "/usr/bin/cargo",
	"/usr/bin/git", "/usr/bin/graft", "/usr/bin/buckley", "/usr/local/bin/graft", "/usr/local/bin/buckley",
	"/bin/cat", "/bin/cp", "/bin/cut", "/bin/date", "/bin/echo", "/bin/env", "/bin/find", "/bin/grep",
	"/bin/head", "/bin/ls", "/bin/mkdir", "/bin/mv", "/bin/pwd", "/bin/rm", "/bin/sed", "/bin/sort",
	"/bin/tail", "/bin/tar", "/bin/touch", "/bin/tr", "/bin/uniq", "/bin/wc",
	"/usr/bin/cat", "/usr/bin/cp", "/usr/bin/cut", "/usr/bin/date", "/usr/bin/echo", "/usr/bin/env",
	"/usr/bin/find", "/usr/bin/grep", "/usr/bin/head", "/usr/bin/ls", "/usr/bin/mkdir", "/usr/bin/mv",
	"/usr/bin/pwd", "/usr/bin/rm", "/usr/bin/sed", "/usr/bin/sort", "/usr/bin/tail", "/usr/bin/tar",
	"/usr/bin/touch", "/usr/bin/tr", "/usr/bin/uniq", "/usr/bin/wc",
}

var strictAgentPaths = []string{
	"/usr/local/bin/claude", "/usr/bin/claude", "/usr/local/bin/tiller", "/usr/bin/tiller",
}

var strictInterpreterPaths = []string{
	"/usr/bin/node", "/usr/local/bin/node", "/usr/bin/python3", "/usr/local/bin/python3",
}

var standardExecPrefixes = []string{"/bin", "/usr/bin", "/usr/local/bin", "/usr/local/go/bin"}

var privilegeExecPaths = []string{
	"/usr/bin/sudo", "/usr/bin/su", "/bin/su", "/usr/bin/mount", "/bin/mount",
	"/usr/bin/insmod", "/usr/sbin/insmod", "/usr/bin/setcap", "/usr/sbin/setcap",
}

var supervisorExecPaths = []string{"/run/mercutio/mercutio"}

func (m *ProgramManager) installExecRules(cell Cell, programs *classPrograms, class uint32) error {
	procRoot := m.options.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	roots, err := cellProcessRoots(procRoot, cell.CgroupPath)
	if err != nil {
		return fmt.Errorf("resolve cell executable roots: %w", err)
	}
	if len(roots) == 0 {
		return fmt.Errorf("resolve cell executable roots: no process found in %s", cell.CgroupPath)
	}
	rules := map[bindings.ExecKey]uint32{}
	for _, root := range roots {
		if class < 2 {
			for _, path := range supervisorExecPaths {
				addExecPath(rules, root, path, execAllow)
			}
		}
		if class == 0 {
			for _, path := range strictExecPaths {
				addExecPath(rules, root, path, execAllow)
			}
			for _, path := range strictAgentPaths {
				addStrictAgentPath(rules, root, path)
			}
			for _, path := range strictInterpreterPaths {
				addExecPath(rules, root, path, execInterpreter)
			}
		} else if class == 1 {
			for _, prefix := range standardExecPrefixes {
				addExecTree(rules, root, prefix, execAllow)
			}
		}
		for _, path := range privilegeExecPaths {
			addExecPath(rules, root, path, execDeny)
		}
	}
	for key, verdict := range rules {
		if err := programs.objects.UpdateExecRules(key, bindings.ExecRule{Verdict: verdict}); err != nil {
			return fmt.Errorf("populate ExecRules: %w", err)
		}
	}
	return nil
}

func addStrictAgentPath(rules map[bindings.ExecKey]uint32, root, path string) {
	resolved := filepath.Join(root, strings.TrimPrefix(path, "/"))
	verdict := execAllow
	if file, err := os.Open(resolved); err == nil {
		defer file.Close()
		magic := make([]byte, 2)
		if count, _ := file.Read(magic); count == 2 && string(magic) == "#!" {
			verdict = execAllowInterpreter
		}
	}
	addExecFile(rules, resolved, verdict)
}

func cellProcessRoots(procRoot, cgroupPath string) ([]string, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	seen := map[[2]uint64]bool{}
	var roots []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cgroup"))
		if err != nil || !cgroupFileContains(string(data), cgroupPath) {
			continue
		}
		root := filepath.Join(procRoot, entry.Name(), "root")
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if !seen[identity] {
			seen[identity] = true
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func cgroupFileContains(data, cgroupPath string) bool {
	want := strings.TrimPrefix(filepath.Clean(cgroupPath), "/sys/fs/cgroup")
	want = "/" + strings.TrimPrefix(want, "/")
	for _, line := range strings.Split(data, "\n") {
		index := strings.LastIndexByte(line, ':')
		if index < 0 {
			continue
		}
		got := filepath.Clean(line[index+1:])
		if got == want || strings.HasPrefix(got, want+"/") {
			return true
		}
	}
	return false
}

func addExecTree(rules map[bindings.ExecKey]uint32, root, path string, verdict uint32) {
	base := filepath.Join(root, strings.TrimPrefix(path, "/"))
	_ = filepath.WalkDir(base, func(item string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && item != base {
			return filepath.SkipDir
		}
		if !entry.IsDir() {
			addExecFile(rules, item, verdict)
		}
		return nil
	})
}

func addExecPath(rules map[bindings.ExecKey]uint32, root, path string, verdict uint32) {
	addExecFile(rules, filepath.Join(root, strings.TrimPrefix(path, "/")), verdict)
}

func addExecFile(rules map[bindings.ExecKey]uint32, path string, verdict uint32) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return
	}
	rules[bindings.ExecKey{Dev: uint64(stat.Dev), Ino: stat.Ino}] = verdict
}
