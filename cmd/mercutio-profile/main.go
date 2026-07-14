package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"m31labs.dev/mercutio/internal/policy"
)

func main() {
	manifestPath := flag.String("horizon-manifest", "nodeagent/generated/mercutio.cap.json", "Horizon capability manifest")
	profilesRoot := flag.String("profiles", "profiles", "profile source root")
	check := flag.Bool("check", false, "verify committed EPS output without writing")
	flag.Parse()
	manifest, err := os.ReadFile(*manifestPath)
	if err != nil {
		fatal(err)
	}
	for _, name := range []string{"strict", "standard", "open"} {
		dir := filepath.Join(*profilesRoot, name)
		source, err := os.ReadFile(filepath.Join(dir, name+".arb"))
		if err != nil {
			fatal(err)
		}
		eps, err := policy.Compile(name, source, manifest)
		if err != nil {
			fatal(err)
		}
		encoded, err := json.MarshalIndent(eps, "", "  ")
		if err != nil {
			fatal(err)
		}
		encoded = append(encoded, '\n')
		path := filepath.Join(dir, "eps.json")
		if *check {
			current, err := os.ReadFile(path)
			if err != nil || string(current) != string(encoded) {
				fatal(fmt.Errorf("%s is stale; run mercutio-profile", path))
			}
			continue
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mercutio-profile:", err)
	os.Exit(1)
}
