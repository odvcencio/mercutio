package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAdversaryRequiresExplicitContainedConfirmation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runAdversary(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAdversaryEmitsThirtyBlockedAttemptsAndSummary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	probe := func(name, _ string, _ time.Duration) (string, error) {
		return "target:" + name, errors.New("operation blocked")
	}
	code := runAdversaryWithProbe([]string{"--confirm-contained-probes", "--worktree", t.TempDir()}, &stdout, &stderr, probe)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	seen := map[string]bool{}
	for range 30 {
		var report adversaryReport
		if err := decoder.Decode(&report); err != nil {
			t.Fatal(err)
		}
		if !report.Blocked || !report.ExpectedBlock || report.Rule == "" || report.Danger.Mode == "" {
			t.Fatalf("incomplete report: %+v", report)
		}
		seen[report.Name] = true
	}
	var summary struct {
		Attempts int `json:"attempts"`
		Escapes  int `json:"escapes"`
	}
	if err := decoder.Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 30 || summary.Attempts != 30 || summary.Escapes != 0 {
		t.Fatalf("seen=%d summary=%+v", len(seen), summary)
	}
}
