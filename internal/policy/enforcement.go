package policy

import "fmt"

type EnforcementRung string

const (
	RungBaseline EnforcementRung = "r0"
	RungKernel   EnforcementRung = "r1"
)

type AccessRequest struct {
	Action string
	Domain string
	Op     string
}

type EnforcementDecision struct {
	Verdict string
	Rule    string
}

func (d EnforcementDecision) Blocks() bool { return d.Verdict != "allow" }

// Decide projects the effective outcome at a concrete enforcement rung. R0
// represents the immutable pod, mount, and network boundary. R1 may tighten
// that result with the compiled profile, but can never relax it.
func DecideEnforcement(eps EffectivePermissionSet, rung EnforcementRung, request AccessRequest) (EnforcementDecision, error) {
	baseline, err := baselineDecision(eps.Profile, request)
	if err != nil {
		return EnforcementDecision{}, err
	}
	if rung == RungBaseline {
		return baseline, nil
	}
	if rung != RungKernel {
		return EnforcementDecision{}, fmt.Errorf("unknown enforcement rung %q", rung)
	}
	profile, err := profileDecision(eps, request)
	if err != nil {
		return EnforcementDecision{}, err
	}
	if verdictRank(profile.Verdict) > verdictRank(baseline.Verdict) {
		return profile, nil
	}
	return baseline, nil
}

func baselineDecision(profile string, request AccessRequest) (EnforcementDecision, error) {
	switch request.Action {
	case "file":
		if request.Domain == "sensitive" || request.Domain == "proc-other" {
			return EnforcementDecision{Verdict: "deny", Rule: "baseline-sensitive-file-wall"}, nil
		}
		if request.Op == "write" && (request.Domain == "cache" || request.Domain == "system" || request.Domain == "other") {
			return EnforcementDecision{Verdict: "deny", Rule: "baseline-readonly-root"}, nil
		}
		return EnforcementDecision{Verdict: "allow", Rule: "baseline-mounted-scope"}, nil
	case "exec":
		if request.Domain == "privilege" {
			return EnforcementDecision{Verdict: "deny", Rule: "baseline-no-privilege-escalation"}, nil
		}
		return EnforcementDecision{Verdict: "allow", Rule: "baseline-process-scope"}, nil
	case "net":
		switch request.Domain {
		case "private", "metadata", "kubernetes", "cell":
			return EnforcementDecision{Verdict: "deny", Rule: "baseline-protected-network"}, nil
		case "control-plane", "dns":
			return EnforcementDecision{Verdict: "allow", Rule: "baseline-control-network"}, nil
		case "registry-mirror":
			return EnforcementDecision{Verdict: "deny", Rule: "baseline-default-deny"}, nil
		case "dependency", "public":
			if profile == "strict" {
				return EnforcementDecision{Verdict: "deny", Rule: "baseline-strict-egress"}, nil
			}
			return EnforcementDecision{Verdict: "allow", Rule: "baseline-profile-egress"}, nil
		}
	}
	return EnforcementDecision{}, fmt.Errorf("unsupported access request %s/%s/%s", request.Action, request.Domain, request.Op)
}

func profileDecision(eps EffectivePermissionSet, request AccessRequest) (EnforcementDecision, error) {
	permissions := eps.Network
	switch request.Action {
	case "file":
		permissions = eps.Filesystem
	case "exec":
		permissions = eps.Exec
	case "net":
	default:
		return EnforcementDecision{}, fmt.Errorf("unsupported access action %q", request.Action)
	}
	for _, permission := range permissions {
		if permission.Domain != request.Domain || !matchesOp(permission.Ops, request.Op) {
			continue
		}
		return EnforcementDecision{Verdict: permission.Verdict, Rule: permission.Rule}, nil
	}
	return EnforcementDecision{}, fmt.Errorf("compiled profile %s has no decision for %s/%s/%s", eps.Profile, request.Action, request.Domain, request.Op)
}

func matchesOp(ops []string, want string) bool {
	if len(ops) == 0 {
		return true
	}
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}

func verdictRank(verdict string) int {
	switch verdict {
	case "allow":
		return 0
	case "ask":
		return 1
	case "deny":
		return 2
	default:
		return 3
	}
}
