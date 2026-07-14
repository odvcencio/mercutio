package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	profilefiles "m31labs.dev/mercutio/profiles"
)

// Manifest is the runtime projection of the deterministic EPS. The complete
// EPS remains the review/impact surface; this smaller shape is safe to place on
// a Pod annotation for the node agent.
type Manifest struct {
	Profile       string   `json:"profile"`
	ProfileDigest string   `json:"profileDigest"`
	Filesystem    string   `json:"filesystem"`
	Exec          []string `json:"exec"`
	Egress        []string `json:"egress"`
	Programs      []string `json:"programs"`
	Danger        string   `json:"danger"`
	RecordedOnly  bool     `json:"recordedOnly"`
}

func Resolve(name string) (Manifest, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "standard"
	}
	if !validProfile(name) {
		return Manifest{}, fmt.Errorf("unknown sandbox profile %q (want strict, standard, or open)", name)
	}
	encoded, err := profilefiles.Files.ReadFile(name + "/eps.json")
	if err != nil {
		return Manifest{}, fmt.Errorf("load compiled profile %s: %w", name, err)
	}
	var eps EffectivePermissionSet
	if err := json.Unmarshal(encoded, &eps); err != nil || eps.Schema != EPSSchema || eps.Profile != name {
		return Manifest{}, fmt.Errorf("compiled profile %s is invalid: %w", name, err)
	}
	manifest := Manifest{Profile: name, ProfileDigest: eps.ProfileDigest, Programs: append([]string(nil), eps.Programs...), RecordedOnly: eps.RecordedOnly}
	manifest.Filesystem = map[string]string{"strict": "scoped-rw-readonly-cache", "standard": "scoped-rw", "open": "recorded-rw"}[name]
	manifest.Danger = map[string]string{"strict": "low", "standard": "medium", "open": "high"}[name]
	for _, permission := range eps.Exec {
		if permission.Verdict == "allow" {
			manifest.Exec = append(manifest.Exec, permission.Targets...)
		}
	}
	for _, permission := range eps.Network {
		if permission.Verdict != "allow" || permission.Domain == "control-plane" || permission.Domain == "dns" || permission.Domain == "registry-mirror" {
			continue
		}
		manifest.Egress = append(manifest.Egress, permission.Targets...)
	}
	if name == "open" {
		manifest.Egress = []string{"*"}
	}
	return manifest, nil
}

func EPS(name string) (EffectivePermissionSet, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	encoded, err := profilefiles.Files.ReadFile(name + "/eps.json")
	if err != nil {
		return EffectivePermissionSet{}, err
	}
	var eps EffectivePermissionSet
	err = json.Unmarshal(encoded, &eps)
	return eps, err
}

func Names() []string { return []string{"strict", "standard", "open"} }
