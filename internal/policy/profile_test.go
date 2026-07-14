package policy

import "testing"

func TestResolveCannedProfiles(t *testing.T) {
	for _, name := range Names() {
		manifest, err := Resolve(name)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", name, err)
		}
		if manifest.Profile != name || manifest.ProfileDigest == "" || manifest.Filesystem == "" || len(manifest.Programs) == 0 {
			t.Fatalf("manifest(%q) = %+v", name, manifest)
		}
		if name == "strict" && len(manifest.Egress) != 0 {
			t.Fatalf("strict profile unexpectedly permits dependency egress: %+v", manifest.Egress)
		}
	}
	if _, err := Resolve("unsafe"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestDecideRunsGovernedProfileGate(t *testing.T) {
	decision, err := Decide("strict", "https://github.com/example/project")
	if err != nil || !decision.Allowed || decision.Rule == "" || decision.TraceSize == 0 {
		t.Fatalf("decision = %+v, %v", decision, err)
	}
	if _, err := Decide("unknown", "https://github.com/example/project"); err == nil {
		t.Fatal("unknown profile was allowed")
	}
}
