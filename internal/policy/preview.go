package policy

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type PreviewResult struct {
	Before  Manifest      `json:"before"`
	After   Manifest      `json:"after"`
	Changes []string      `json:"changes,omitempty"`
	Affects []string      `json:"affects,omitempty"`
	Classes []ClassImpact `json:"classes,omitempty"`
	Cells   []CellImpact  `json:"cells,omitempty"`
}

type RuleImpact struct {
	Action        string `json:"action"`
	Domain        string `json:"domain"`
	Operation     string `json:"operation"`
	BeforeVerdict string `json:"beforeVerdict"`
	AfterVerdict  string `json:"afterVerdict"`
	BeforeRule    string `json:"beforeRule"`
	AfterRule     string `json:"afterRule"`
	Direction     string `json:"direction"`
}

type ReplayImpact struct {
	EventID       string `json:"eventID"`
	Action        string `json:"action"`
	Resource      string `json:"resource,omitempty"`
	BeforeVerdict string `json:"beforeVerdict"`
	AfterVerdict  string `json:"afterVerdict"`
	BeforeRule    string `json:"beforeRule"`
	AfterRule     string `json:"afterRule"`
	Direction     string `json:"direction"`
}

type ClassImpact struct {
	Class          string       `json:"class"`
	BeforeDigest   string       `json:"beforeDigest"`
	AfterDigest    string       `json:"afterDigest"`
	ProgramChanges bool         `json:"programChanges"`
	MapChanges     bool         `json:"mapChanges"`
	Widens         int          `json:"widens"`
	Narrows        int          `json:"narrows"`
	Rules          []RuleImpact `json:"rules,omitempty"`
}

type CellImpact struct {
	CellID        string         `json:"cellID"`
	BeforeClass   string         `json:"beforeClass"`
	AfterClass    string         `json:"afterClass"`
	RequiresRearm bool           `json:"requiresRearm"`
	Widens        int            `json:"widens"`
	Narrows       int            `json:"narrows"`
	Replay        []ReplayImpact `json:"replay,omitempty"`
}

// ReplayEvent is the policy-relevant projection of a recorded kernel event.
// It deliberately excludes event detail that is not needed to compare policy
// verdicts, so impact preview cannot become a second telemetry store.
type ReplayEvent struct {
	ID          string
	Action      string
	Path        string
	Argv        string
	Destination string
}

type ReplayCell struct {
	CellID   string
	Profile  string
	Worktree string
	Events   []ReplayEvent
}

// Preview evaluates a policy buffer without mutating the active sandbox.
func Preview(before Manifest, content string) (PreviewResult, error) {
	return PreviewForCells(before, content, nil)
}

// PreviewForCells combines a rule-by-rule EPS diff with replay of recorded
// kernel events through the baseline and candidate policy. Only cells supplied
// by the caller are in the blast radius; callers should pass every running cell
// affected by the edit.
func PreviewForCells(before Manifest, content string, cells []ReplayCell) (PreviewResult, error) {
	var input struct {
		Profile string `yaml:"profile"`
	}
	if err := yaml.Unmarshal([]byte(content), &input); err != nil {
		return PreviewResult{}, fmt.Errorf("parse policy: %w", err)
	}
	profile := strings.TrimSpace(input.Profile)
	if profile == "" {
		return PreviewResult{}, fmt.Errorf("policy profile is required")
	}
	after, err := Resolve(profile)
	if err != nil {
		return PreviewResult{}, err
	}
	preview := PreviewResult{Before: before, After: after}
	if before.Filesystem != after.Filesystem {
		preview.Changes = append(preview.Changes, "filesystem: "+before.Filesystem+" -> "+after.Filesystem)
	}
	if strings.Join(before.Exec, "\x00") != strings.Join(after.Exec, "\x00") {
		preview.Changes = append(preview.Changes, "exec allowlist changes")
	}
	if strings.Join(before.Egress, "\x00") != strings.Join(after.Egress, "\x00") {
		preview.Changes = append(preview.Changes, "egress destinations change")
	}
	if before.Danger != after.Danger {
		preview.Changes = append(preview.Changes, "danger: "+before.Danger+" -> "+after.Danger)
	}
	if before.ProfileDigest != after.ProfileDigest {
		preview.Changes = append(preview.Changes, "effective permission set digest changes")
	}
	programChanges := strings.Join(before.Programs, "\x00") != strings.Join(after.Programs, "\x00")
	if programChanges {
		preview.Changes = append(preview.Changes, "Horizon program attachment set changes")
	}
	if len(preview.Changes) == 0 {
		return preview, nil
	}
	preview.Affects = []string{"sandbox capability manifest", "Horizon enforcement", "cell network policy"}
	beforeEPS, err := EPS(before.Profile)
	if err != nil {
		return PreviewResult{}, fmt.Errorf("load baseline EPS: %w", err)
	}
	afterEPS, err := EPS(after.Profile)
	if err != nil {
		return PreviewResult{}, fmt.Errorf("load candidate EPS: %w", err)
	}
	rules := staticRuleDiff(beforeEPS, afterEPS)
	class := ClassImpact{Class: before.Profile, BeforeDigest: before.ProfileDigest, AfterDigest: after.ProfileDigest, ProgramChanges: programChanges, MapChanges: true, Rules: rules}
	for _, rule := range rules {
		if rule.Direction == "widens" {
			class.Widens++
		} else {
			class.Narrows++
		}
	}
	preview.Classes = []ClassImpact{class}
	for _, cell := range cells {
		impact := CellImpact{CellID: cell.CellID, BeforeClass: defaultProfile(cell.Profile, before.Profile), AfterClass: after.Profile, RequiresRearm: true}
		for _, event := range cell.Events {
			request, resource, ok := replayRequest(event, cell.Worktree)
			if !ok {
				continue
			}
			baseline, baselineErr := DecideEnforcement(beforeEPS, RungKernel, request)
			candidate, candidateErr := DecideEnforcement(afterEPS, RungKernel, request)
			if baselineErr != nil || candidateErr != nil || baseline.Verdict == candidate.Verdict {
				continue
			}
			direction := changeDirection(baseline.Verdict, candidate.Verdict)
			flip := ReplayImpact{EventID: event.ID, Action: request.Action + "/" + request.Domain + "/" + request.Op, Resource: resource, BeforeVerdict: baseline.Verdict, AfterVerdict: candidate.Verdict, BeforeRule: baseline.Rule, AfterRule: candidate.Rule, Direction: direction}
			impact.Replay = append(impact.Replay, flip)
			if direction == "widens" {
				impact.Widens++
			} else {
				impact.Narrows++
			}
		}
		sort.Slice(impact.Replay, func(i, j int) bool { return impact.Replay[i].EventID < impact.Replay[j].EventID })
		preview.Cells = append(preview.Cells, impact)
	}
	sort.Slice(preview.Cells, func(i, j int) bool { return preview.Cells[i].CellID < preview.Cells[j].CellID })
	return preview, nil
}

func staticRuleDiff(before, after EffectivePermissionSet) []RuleImpact {
	type keyed struct {
		action string
		item   Permission
	}
	beforeRules := map[string]keyed{}
	afterRules := map[string]keyed{}
	collect := func(target map[string]keyed, action string, permissions []Permission) {
		for _, permission := range permissions {
			op := ""
			if len(permission.Ops) > 0 {
				op = permission.Ops[0]
			}
			target[action+"\x00"+permission.Domain+"\x00"+op] = keyed{action: action, item: permission}
		}
	}
	collect(beforeRules, "file", before.Filesystem)
	collect(beforeRules, "exec", before.Exec)
	collect(beforeRules, "net", before.Network)
	collect(afterRules, "file", after.Filesystem)
	collect(afterRules, "exec", after.Exec)
	collect(afterRules, "net", after.Network)
	keys := make([]string, 0, len(beforeRules))
	for key := range beforeRules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result []RuleImpact
	for _, key := range keys {
		left, right := beforeRules[key], afterRules[key]
		if left.item.Verdict == right.item.Verdict {
			continue
		}
		op := ""
		if len(left.item.Ops) > 0 {
			op = left.item.Ops[0]
		}
		result = append(result, RuleImpact{Action: left.action, Domain: left.item.Domain, Operation: op, BeforeVerdict: left.item.Verdict, AfterVerdict: right.item.Verdict, BeforeRule: left.item.Rule, AfterRule: right.item.Rule, Direction: changeDirection(left.item.Verdict, right.item.Verdict)})
	}
	return result
}

func changeDirection(before, after string) string {
	if verdictRank(after) < verdictRank(before) {
		return "widens"
	}
	return "narrows"
}

func replayRequest(event ReplayEvent, worktree string) (AccessRequest, string, bool) {
	action := strings.ToLower(event.Action)
	if strings.Contains(action, "connect") || event.Destination != "" {
		return AccessRequest{Action: "net", Domain: networkReplayDomain(event.Destination), Op: "connect"}, event.Destination, true
	}
	if strings.Contains(action, "exec") || event.Argv != "" {
		value := strings.TrimSpace(event.Argv)
		if value == "" {
			value = event.Path
		}
		return AccessRequest{Action: "exec", Domain: execReplayDomain(value), Op: "execute"}, value, true
	}
	if strings.Contains(action, "file") || strings.Contains(action, "write") || strings.Contains(action, "open") {
		op := "read"
		if strings.Contains(action, "write") || strings.Contains(action, "delete") || strings.Contains(action, "create") || strings.Contains(action, "rename") {
			op = "write"
		}
		return AccessRequest{Action: "file", Domain: fileReplayDomain(event.Path, worktree), Op: op}, event.Path, true
	}
	return AccessRequest{}, "", false
}

func fileReplayDomain(path, worktree string) string {
	clean := filepath.Clean(path)
	if worktree != "" && (clean == filepath.Clean(worktree) || strings.HasPrefix(clean, filepath.Clean(worktree)+string(filepath.Separator))) {
		if strings.Contains(clean, string(filepath.Separator)+".github"+string(filepath.Separator)) || strings.HasSuffix(clean, string(filepath.Separator)+"Makefile") {
			return "ci"
		}
		return "worktree"
	}
	lower := strings.ToLower(clean)
	for _, marker := range []string{"/.ssh/", "/.aws/", "/.kube/", "/.docker/", "/var/run/secrets/"} {
		if strings.Contains(lower, marker) {
			return "sensitive"
		}
	}
	if strings.HasPrefix(lower, "/proc/") {
		return "proc-other"
	}
	if strings.HasPrefix(lower, "/tmp/") || strings.HasPrefix(lower, "/ipc/") {
		return "tmp"
	}
	if strings.Contains(lower, "/.cache/") || strings.Contains(lower, "/go/pkg/mod/") || strings.Contains(lower, "/node_modules/") {
		return "cache"
	}
	if strings.HasPrefix(lower, "/usr/") || strings.HasPrefix(lower, "/lib/") || strings.HasPrefix(lower, "/etc/") {
		return "system"
	}
	return "other"
}

func execReplayDomain(command string) string {
	fields := strings.Fields(strings.ToLower(command))
	if len(fields) == 0 {
		return "worktree-binary"
	}
	name := filepath.Base(fields[0])
	switch name {
	case "sudo", "su", "mount", "insmod", "setcap":
		return "privilege"
	case "curl", "wget", "nc", "ssh", "scp":
		return "network-tool"
	case "graft", "buckley", "git":
		return "vcs"
	case "sh", "bash", "zsh":
		if len(fields) > 1 && fields[1] == "-c" {
			return "inline"
		}
		return "shell"
	case "python", "python3", "node":
		if len(fields) > 1 && (fields[1] == "-c" || fields[1] == "-e") {
			return "inline"
		}
		return "interpreter"
	case "npm", "pip", "pip3":
		return "package-manager"
	case "go", "cargo":
		if len(fields) > 1 && (fields[1] == "get" || fields[1] == "install" || fields[1] == "add") {
			return "package-manager"
		}
		return "toolchain"
	case "make", "gcc", "clang", "rustc", "pytest", "go.test":
		return "toolchain"
	}
	if strings.HasPrefix(fields[0], "/workspace/repo/") || strings.HasPrefix(fields[0], "./") {
		return "worktree-binary"
	}
	return "coreutils"
}

func networkReplayDomain(destination string) string {
	host := strings.TrimSpace(destination)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Count(host, ":") == 1 {
		host = strings.SplitN(host, ":", 2)[0]
	}
	host = strings.Trim(host, "[]")
	if host == "169.254.169.254" {
		return "metadata"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return "private"
		}
		return "public"
	}
	lower := strings.ToLower(host)
	if lower == "kubernetes.default.svc" || strings.HasSuffix(lower, ".svc") {
		return "kubernetes"
	}
	if strings.Contains(lower, "mercutio-control-plane") {
		return "control-plane"
	}
	if strings.Contains(lower, "dns") {
		return "dns"
	}
	if lower == "registry-mirror" {
		return "registry-mirror"
	}
	for _, dependency := range []string{"github.com", "proxy.golang.org", "registry.npmjs.org", "pypi.org", "crates.io"} {
		if lower == dependency || strings.HasSuffix(lower, "."+dependency) {
			return "dependency"
		}
	}
	if strings.Contains(lower, "cell") {
		return "cell"
	}
	return "public"
}

func defaultProfile(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
