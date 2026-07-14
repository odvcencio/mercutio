package policy

import (
	"fmt"
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

type ClassImpact struct {
	Class          string `json:"class"`
	BeforeDigest   string `json:"beforeDigest"`
	AfterDigest    string `json:"afterDigest"`
	ProgramChanges bool   `json:"programChanges"`
	MapChanges     bool   `json:"mapChanges"`
}

type CellImpact struct {
	CellID        string `json:"cellID"`
	BeforeClass   string `json:"beforeClass"`
	AfterClass    string `json:"afterClass"`
	RequiresRearm bool   `json:"requiresRearm"`
}

// Preview evaluates a policy buffer without mutating the active sandbox. The
// operator can see the effect before an edit is approved or applied to a
// running cell.
func Preview(before Manifest, content string) (PreviewResult, error) {
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
	if strings.Join(before.Programs, "\x00") != strings.Join(after.Programs, "\x00") {
		preview.Changes = append(preview.Changes, "Horizon program attachment set changes")
	}
	if len(preview.Changes) > 0 {
		preview.Affects = []string{"sandbox capability manifest", "Horizon enforcement", "cell network policy"}
		preview.Classes = []ClassImpact{{Class: after.Profile, BeforeDigest: before.ProfileDigest, AfterDigest: after.ProfileDigest, ProgramChanges: strings.Join(before.Programs, "\x00") != strings.Join(after.Programs, "\x00"), MapChanges: true}}
	}
	return preview, nil
}
