package policy

import "testing"

type adversarialTechnique struct {
	name    string
	request AccessRequest
}

var adversarialTechniques = []adversarialTechnique{
	{"write-etc", AccessRequest{"file", "system", "write"}},
	{"replace-system-binary", AccessRequest{"file", "system", "write"}},
	{"write-outside-mounted-scope", AccessRequest{"file", "other", "write"}},
	{"poison-runtime-cache", AccessRequest{"file", "cache", "write"}},
	{"read-service-account-token", AccessRequest{"file", "sensitive", "read"}},
	{"read-ssh-credentials", AccessRequest{"file", "sensitive", "read"}},
	{"read-cloud-credentials", AccessRequest{"file", "sensitive", "read"}},
	{"read-kube-credentials", AccessRequest{"file", "sensitive", "read"}},
	{"read-container-credentials", AccessRequest{"file", "sensitive", "read"}},
	{"read-other-process-environ", AccessRequest{"file", "proc-other", "read"}},
	{"overwrite-ci-workflow", AccessRequest{"file", "ci", "write"}},
	{"overwrite-vcs-metadata", AccessRequest{"file", "ci", "write"}},
	{"execute-sh", AccessRequest{"exec", "shell", "execute"}},
	{"execute-bash", AccessRequest{"exec", "shell", "execute"}},
	{"execute-zsh", AccessRequest{"exec", "shell", "execute"}},
	{"python-inline", AccessRequest{"exec", "inline", "execute"}},
	{"node-inline", AccessRequest{"exec", "inline", "execute"}},
	{"shell-inline", AccessRequest{"exec", "inline", "execute"}},
	{"execute-copied-binary", AccessRequest{"exec", "worktree-binary", "execute"}},
	{"execute-downloaded-binary", AccessRequest{"exec", "worktree-binary", "execute"}},
	{"execute-network-tool", AccessRequest{"exec", "network-tool", "execute"}},
	{"execute-sudo", AccessRequest{"exec", "privilege", "execute"}},
	{"execute-su", AccessRequest{"exec", "privilege", "execute"}},
	{"execute-mount", AccessRequest{"exec", "privilege", "execute"}},
	{"connect-instance-metadata", AccessRequest{"net", "metadata", "connect"}},
	{"connect-kubernetes-api", AccessRequest{"net", "kubernetes", "connect"}},
	{"connect-rfc1918", AccessRequest{"net", "private", "connect"}},
	{"connect-sibling-cell", AccessRequest{"net", "cell", "connect"}},
	{"connect-unlisted-public-host", AccessRequest{"net", "public", "connect"}},
	{"connect-dependency-host", AccessRequest{"net", "dependency", "connect"}},
}

func TestAdversarialCorpusRungParity(t *testing.T) {
	if len(adversarialTechniques) != 30 {
		t.Fatalf("adversarial corpus has %d techniques, want 30", len(adversarialTechniques))
	}
	for _, profile := range Names() {
		eps, err := EPS(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, technique := range adversarialTechniques {
			t.Run(profile+"/"+technique.name, func(t *testing.T) {
				r0, err := DecideEnforcement(eps, RungBaseline, technique.request)
				if err != nil {
					t.Fatal(err)
				}
				r1, err := DecideEnforcement(eps, RungKernel, technique.request)
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
	requests := []AccessRequest{
		{"file", "system", "write"},
		{"file", "other", "write"},
		{"file", "sensitive", "read"},
		{"file", "proc-other", "read"},
		{"exec", "privilege", "execute"},
		{"net", "metadata", "connect"},
		{"net", "kubernetes", "connect"},
		{"net", "private", "connect"},
		{"net", "cell", "connect"},
	}
	for _, profile := range Names() {
		eps, err := EPS(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, request := range requests {
			for _, rung := range []EnforcementRung{RungBaseline, RungKernel} {
				decision, err := DecideEnforcement(eps, rung, request)
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
		request                AccessRequest
		strict, standard, open string
	}{
		{AccessRequest{"exec", "shell", "execute"}, "deny", "allow", "allow"},
		{AccessRequest{"exec", "inline", "execute"}, "deny", "allow", "allow"},
		{AccessRequest{"exec", "network-tool", "execute"}, "deny", "allow", "allow"},
		{AccessRequest{"exec", "worktree-binary", "execute"}, "deny", "ask", "allow"},
		{AccessRequest{"file", "ci", "write"}, "ask", "ask", "allow"},
		{AccessRequest{"net", "dependency", "connect"}, "deny", "allow", "allow"},
		{AccessRequest{"net", "public", "connect"}, "deny", "ask", "allow"},
	}
	for _, test := range tests {
		want := map[string]string{"strict": test.strict, "standard": test.standard, "open": test.open}
		for _, profile := range Names() {
			eps, err := EPS(profile)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := DecideEnforcement(eps, RungKernel, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != want[profile] {
				t.Errorf("%s %+v: got %s (%s), want %s", profile, test.request, decision.Verdict, decision.Rule, want[profile])
			}
		}
	}
}
