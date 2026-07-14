package policy

import (
	"fmt"
	"strings"

	"m31labs.dev/arbiter/authz"
)

type Decision struct {
	Allowed   bool
	Rule      string
	TraceSize int
}

// Decide runs the profile gate through Arbiter so the policy boundary has a
// governed decision and an explainable trace before a capability manifest is
// handed to a runtime.
func Decide(profile, repoURL string) (Decision, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return Decision{}, fmt.Errorf("sandbox profile is required")
	}
	if !validProfile(profile) {
		return Decision{}, fmt.Errorf("sandbox profile %q is not governed", profile)
	}
	source := []byte(fmt.Sprintf(`
segment requested_profile {
	resource.profile == %q
}

rule AllowSandboxProfile {
	when segment requested_profile
	then Allow {
		reason: "profile-approved",
	}
}
`, profile))
	decision, err := authz.EvaluateSource(source, authz.Request{
		Action: "sandbox.create",
		Resource: map[string]any{
			"profile": profile,
			"repo":    repoURL,
		},
	})
	if err != nil {
		return Decision{}, fmt.Errorf("evaluate sandbox profile: %w", err)
	}
	result := Decision{Allowed: decision.Allowed, Rule: "AllowSandboxProfile", TraceSize: len(decision.Arbitrace)}
	if !result.Allowed {
		return result, fmt.Errorf("sandbox profile %q was denied", profile)
	}
	return result, nil
}

func validProfile(profile string) bool {
	for _, name := range Names() {
		if profile == name {
			return true
		}
	}
	return false
}
