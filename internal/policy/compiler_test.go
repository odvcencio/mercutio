package policy

import (
	"encoding/json"
	"testing"

	profilefiles "m31labs.dev/mercutio/profiles"
)

func TestCompileProfilesIsDeterministicAndArbiterDriven(t *testing.T) {
	horizon := []byte(`{"programs":[{"name":"OnExec"},{"name":"GateExec"},{"name":"GateFileOpen"},{"name":"GateConnect4"},{"name":"GateConnect6"}]}`)
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
	}
}
