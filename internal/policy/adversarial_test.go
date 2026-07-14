package policy_test

import (
	"testing"

	"m31labs.dev/mercutio/internal/adversary"
	"m31labs.dev/mercutio/internal/policy"
)

func TestAdversarialCorpusRungParity(t *testing.T) {
	techniques := adversary.Catalog()
	if len(techniques) != 30 {
		t.Fatalf("adversarial corpus has %d techniques, want 30", len(techniques))
	}
	seen := map[string]bool{}
	for _, technique := range techniques {
		if seen[technique.Name] {
			t.Fatalf("duplicate adversarial technique %q", technique.Name)
		}
		seen[technique.Name] = true
	}
	for _, profile := range policy.Names() {
		eps, err := policy.EPS(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, technique := range techniques {
			t.Run(profile+"/"+technique.Name, func(t *testing.T) {
				r0, err := policy.DecideEnforcement(eps, policy.RungBaseline, technique.Request)
				if err != nil {
					t.Fatal(err)
				}
				r1, err := policy.DecideEnforcement(eps, policy.RungKernel, technique.Request)
				if err != nil {
					t.Fatal(err)
				}
				if verdictRank(r1.Verdict) < verdictRank(r0.Verdict) {
					t.Fatalf("R1 relaxed R0: R0=%+v R1=%+v", r0, r1)
				}
			})
		}
	}
}

func TestUniversalEscapeBoundariesBlockAtBothRungs(t *testing.T) {
	requests := []policy.AccessRequest{
		{Action: "file", Domain: "system", Op: "write"},
		{Action: "file", Domain: "other", Op: "write"},
		{Action: "file", Domain: "sensitive", Op: "read"},
		{Action: "file", Domain: "proc-other", Op: "read"},
		{Action: "exec", Domain: "privilege", Op: "execute"},
		{Action: "net", Domain: "metadata", Op: "connect"},
		{Action: "net", Domain: "kubernetes", Op: "connect"},
		{Action: "net", Domain: "private", Op: "connect"},
		{Action: "net", Domain: "cell", Op: "connect"},
	}
	for _, profile := range policy.Names() {
		eps, err := policy.EPS(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, request := range requests {
			for _, rung := range []policy.EnforcementRung{policy.RungBaseline, policy.RungKernel} {
				decision, err := policy.DecideEnforcement(eps, rung, request)
				if err != nil {
					t.Fatal(err)
				}
				if !decision.Blocks() {
					t.Errorf("%s %s allowed universal escape boundary %+v", profile, rung, request)
				}
			}
		}
	}
}

func TestProfileSwitchHasExactKernelDifferences(t *testing.T) {
	tests := []struct {
		request                policy.AccessRequest
		strict, standard, open string
	}{
		{policy.AccessRequest{Action: "exec", Domain: "shell", Op: "execute"}, "deny", "allow", "allow"},
		{policy.AccessRequest{Action: "exec", Domain: "inline", Op: "execute"}, "deny", "allow", "allow"},
		{policy.AccessRequest{Action: "exec", Domain: "network-tool", Op: "execute"}, "deny", "allow", "allow"},
		{policy.AccessRequest{Action: "exec", Domain: "worktree-binary", Op: "execute"}, "deny", "ask", "allow"},
		{policy.AccessRequest{Action: "file", Domain: "ci", Op: "write"}, "ask", "ask", "allow"},
		{policy.AccessRequest{Action: "net", Domain: "dependency", Op: "connect"}, "deny", "allow", "allow"},
		{policy.AccessRequest{Action: "net", Domain: "public", Op: "connect"}, "deny", "ask", "allow"},
	}
	for _, test := range tests {
		want := map[string]string{"strict": test.strict, "standard": test.standard, "open": test.open}
		for _, profile := range policy.Names() {
			eps, err := policy.EPS(profile)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.DecideEnforcement(eps, policy.RungKernel, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != want[profile] {
				t.Errorf("%s %+v: got %s (%s), want %s", profile, test.request, decision.Verdict, decision.Rule, want[profile])
			}
		}
	}
}

func verdictRank(verdict string) int {
	return map[string]int{"allow": 0, "ask": 1, "deny": 2}[verdict]
}
