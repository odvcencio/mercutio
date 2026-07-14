package policy

import (
	"encoding/json"
	"slices"
	"testing"

	profilefiles "m31labs.dev/mercutio/profiles"
)

func TestCompileProfilesIsDeterministicAndArbiterDriven(t *testing.T) {
	horizon := []byte(`{"programs":[{"name":"OnExec"},{"name":"GateExec"},{"name":"GateFileOpen"},{"name":"GateConnect4"},{"name":"GateConnect6"},{"name":"ObserveFileOpen"},{"name":"ObserveConnect4"},{"name":"ObserveConnect6"}]}`)
	for _, name := range []string{"strict", "standard", "open"} {
		source, err := profilefiles.Files.ReadFile(name + "/" + name + ".arb")
		if err != nil {
			t.Fatal(err)
		}
		first, err := Compile(name, source, horizon)
		if err != nil {
			t.Fatalf("Compile(%s): %v", name, err)
		}
		second, err := Compile(name, source, horizon)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(second)
		if string(a) != string(b) || first.ProfileDigest == "" || len(first.Filesystem) == 0 || len(first.Exec) == 0 || len(first.Network) == 0 {
			t.Fatalf("non-deterministic or incomplete EPS for %s", name)
		}
		wantPrograms := []string{"OnExec", "GateExec", "GateFileOpen", "GateConnect4", "GateConnect6"}
		if name == "open" {
			wantPrograms = []string{"OnExec", "ObserveFileOpen", "ObserveConnect4", "ObserveConnect6"}
			if !first.RecordedOnly || first.ProgramCeiling != (DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}) {
				t.Fatalf("open profile is not observe-only: %+v", first)
			}
		}
		if !slices.Equal(first.Programs, wantPrograms) {
			t.Fatalf("programs for %s = %v, want %v", name, first.Programs, wantPrograms)
		}
	}
}
