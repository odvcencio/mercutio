package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"m31labs.dev/arbiter/authz"
)

const EPSSchema = "m31labs.dev/mercutio/eps/v1"

type Permission struct {
	Domain  string   `json:"domain"`
	Targets []string `json:"targets"`
	Ops     []string `json:"ops,omitempty"`
	Verdict string   `json:"verdict"`
	Rule    string   `json:"rule"`
}

type EffectivePermissionSet struct {
	Schema         string       `json:"schema"`
	Profile        string       `json:"profile"`
	SourceDigest   string       `json:"sourceDigest"`
	HorizonDigest  string       `json:"horizonDigest"`
	ProfileDigest  string       `json:"profileDigest"`
	Filesystem     []Permission `json:"filesystem"`
	Exec           []Permission `json:"exec"`
	Network        []Permission `json:"network"`
	Programs       []string     `json:"programs"`
	ActionCeiling  DangerAxes   `json:"actionDangerCeiling"`
	ProgramCeiling DangerAxes   `json:"programDangerCeiling"`
	RecordedOnly   bool         `json:"recordedOnly"`
}

type DangerAxes struct {
	Mode          string `json:"mode"`
	Scope         string `json:"scope"`
	Reversibility string `json:"reversibility"`
}

type horizonEnvelope struct {
	Programs []struct {
		Name string `json:"name"`
	} `json:"programs"`
}

var fileDomain = map[string][]string{
	"worktree": {"/workspace/repo/"}, "tmp": {"/tmp/", "/ipc/"}, "cache": {"/home/agent/.cache/", "/home/agent/go/pkg/mod/", "/workspace/repo/node_modules/"},
	"system": {"/usr/", "/lib/", "/etc/"}, "other": {"*"}, "ci": {"/workspace/repo/.github/", "/workspace/repo/.git", "/workspace/repo/.graft/", "/workspace/repo/Makefile"},
	"sensitive": {"/home/agent/.ssh/", "/home/agent/.aws/", "/home/agent/.kube/", "/home/agent/.docker/", "/var/run/secrets/"}, "proc-other": {"/proc/<other-pid>/**", "/proc/*/environ"},
}

var execDomain = map[string][]string{
	"toolchain": {"go", "cargo", "test-runners"}, "interpreter": {"node", "python3"}, "vcs": {"graft", "buckley", "git"}, "coreutils": {"coreutils"},
	"shell": {"sh", "bash", "zsh"}, "network-tool": {"curl", "wget", "nc", "ssh", "scp"}, "package-manager": {"npm", "pip", "cargo", "go"},
	"inline": {"python3 -c", "node -e", "sh -c"}, "worktree-binary": {"/workspace/repo/*"}, "privilege": {"sudo", "su", "mount", "insmod", "setcap"},
}

var networkDomain = map[string][]string{
	"control-plane": {"mercutio-control-plane"}, "dns": {"cluster-dns:53"}, "registry-mirror": {"registry-mirror"},
	"dependency": {"github.com:443", "proxy.golang.org:443", "registry.npmjs.org:443", "pypi.org:443", "crates.io:443"}, "public": {"public:*"},
	"private": {"rfc1918:*"}, "metadata": {"169.254.169.254:*"}, "kubernetes": {"kubernetes.default.svc:443"}, "cell": {"cell-network:*"},
}

func Compile(profile string, source, horizonManifest []byte) (EffectivePermissionSet, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile != "strict" && profile != "standard" && profile != "open" {
		return EffectivePermissionSet{}, fmt.Errorf("unknown profile %q", profile)
	}
	var horizon horizonEnvelope
	if err := json.Unmarshal(horizonManifest, &horizon); err != nil {
		return EffectivePermissionSet{}, fmt.Errorf("decode Horizon program manifest: %w", err)
	}
	if len(horizon.Programs) == 0 {
		return EffectivePermissionSet{}, fmt.Errorf("Horizon program manifest has no programs")
	}
	eps := EffectivePermissionSet{Schema: EPSSchema, Profile: profile}
	eps.SourceDigest = digest(source)
	eps.HorizonDigest = digest(horizonManifest)
	eps.ProfileDigest = digest(append(append(append([]byte(nil), source...), 0), horizonManifest...))
	for _, domain := range sortedKeys(fileDomain) {
		for _, op := range []string{"read", "write"} {
			verdict, rule, err := evaluate(source, "file", domain, op)
			if err != nil {
				return EffectivePermissionSet{}, err
			}
			eps.Filesystem = append(eps.Filesystem, Permission{Domain: domain, Targets: append([]string(nil), fileDomain[domain]...), Ops: []string{op}, Verdict: verdict, Rule: rule})
		}
	}
	for _, domain := range sortedKeys(execDomain) {
		verdict, rule, err := evaluate(source, "exec", domain, "execute")
		if err != nil {
			return EffectivePermissionSet{}, err
		}
		eps.Exec = append(eps.Exec, Permission{Domain: domain, Targets: append([]string(nil), execDomain[domain]...), Verdict: verdict, Rule: rule})
	}
	for _, domain := range sortedKeys(networkDomain) {
		verdict, rule, err := evaluate(source, "net", domain, "connect")
		if err != nil {
			return EffectivePermissionSet{}, err
		}
		eps.Network = append(eps.Network, Permission{Domain: domain, Targets: append([]string(nil), networkDomain[domain]...), Verdict: verdict, Rule: rule})
	}
	available := make(map[string]bool, len(horizon.Programs))
	for _, program := range horizon.Programs {
		available[program.Name] = true
	}
	wanted := []string{"OnExec", "GateExec", "GateFileOpen", "GateConnect4", "GateConnect6"}
	if profile == "open" {
		wanted = []string{"OnExec", "ObserveFileOpen", "ObserveConnect4", "ObserveConnect6"}
		eps.RecordedOnly = true
		eps.ActionCeiling = DangerAxes{Mode: "mutate", Scope: "system", Reversibility: "persistent"}
		eps.ProgramCeiling = DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
	} else {
		eps.ActionCeiling = DangerAxes{Mode: "mutate", Scope: "filesystem", Reversibility: map[string]string{"strict": "restart", "standard": "persistent"}[profile]}
		eps.ProgramCeiling = DangerAxes{Mode: "control", Scope: "system", Reversibility: "restart"}
	}
	for _, name := range wanted {
		if !available[name] {
			return EffectivePermissionSet{}, fmt.Errorf("profile %s requires missing Horizon program %s", profile, name)
		}
		eps.Programs = append(eps.Programs, name)
	}
	return eps, nil
}

func evaluate(source []byte, action, domain, op string) (string, string, error) {
	decision, err := authz.EvaluateSource(source, authz.Request{Action: action, Resource: map[string]any{"domain": domain, "op": op}})
	if err != nil {
		return "", "", fmt.Errorf("compile %s/%s/%s: %w", action, domain, op, err)
	}
	if len(decision.Matched) != 1 {
		return "", "", fmt.Errorf("compile %s/%s/%s: expected exactly one policy outcome, got %d", action, domain, op, len(decision.Matched))
	}
	match := decision.Matched[0]
	switch strings.ToLower(match.Action) {
	case "allow":
		return "allow", match.Name, nil
	case "deny":
		return "deny", match.Name, nil
	case "askhuman":
		return "ask", match.Name, nil
	default:
		return "", "", fmt.Errorf("rule %s emitted unsupported outcome %s", match.Name, match.Action)
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
