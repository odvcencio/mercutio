package divergence

import (
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestEvaluateNormativeRulesAndStableIDs(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	events := []model.Event{
		{ID: "i1", TraceID: "t1", Kind: model.EventIntent, Source: "agent-1", Action: "test.run", Timestamp: now},
		{ID: "k1", TraceID: "t2", Kind: model.EventKernel, Source: "horizon", Action: "process.exec", Danger: "high", DangerAxes: model.DangerAxes{Mode: "execute", Scope: "external", Reversibility: "persistent"}, Timestamp: now.Add(time.Second)},
		{ID: "k2", Kind: model.EventKernel, Source: "horizon", Action: "file.write", Path: "/etc/passwd", BatchSeq: 3, Timestamp: now.Add(2 * time.Second)},
		{ID: "k3", Kind: model.EventKernel, Source: "horizon", Action: "network.connect", Destination: "evil.example:443", Verdict: "deny", BatchSeq: 5, Drops: 2, Timestamp: now.Add(50 * time.Second)},
	}
	got := Evaluate(events, Options{CellID: "cell-1", Worktree: "/work/cell-1", NetAllow: []string{"github.com"}, EvidenceHealthy: true})
	want := map[string]bool{"D1": false, "D2": false, "D3": false, "D4": false, "D6": false, "D7": false}
	for _, r := range got {
		if _, ok := want[r.RuleID]; ok {
			want[r.RuleID] = true
		}
		if r.ID == "" || r.Evidence.Healthy {
			t.Fatalf("incomplete record: %#v", r)
		}
	}
	for rule, seen := range want {
		if !seen {
			t.Errorf("missing %s in %#v", rule, got)
		}
	}
	again := Evaluate(events, Options{CellID: "cell-1", Worktree: "/work/cell-1", NetAllow: []string{"github.com"}, EvidenceHealthy: true})
	if len(got) != len(again) {
		t.Fatalf("unstable record count")
	}
	for i := range got {
		if got[i].ID != again[i].ID {
			t.Fatalf("unstable ID: %q != %q", got[i].ID, again[i].ID)
		}
	}
}

func TestEvaluateAttributionAndStructuralSecret(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	events := []model.Event{
		{ID: "k", Kind: model.EventKernel, Source: "operator-alice", Action: "file.write", Path: "/work/c/a.go", Timestamp: now},
		{ID: "s", Kind: model.EventReview, Source: "agent-c", Action: "structural.secret.finding", Timestamp: now},
	}
	got := Evaluate(events, Options{CellID: "c", Worktree: "/work/c", EvidenceHealthy: true})
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.RuleID] = true
	}
	if !seen["D8"] || !seen["D9"] {
		t.Fatalf("got rules %#v", seen)
	}
}

func TestAuthenticatedOperatorEditPreventsD9(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	events := []model.Event{
		{TraceID: "edit", Kind: model.EventEdit, Source: "operator-alice", Actor: "operator-alice", Action: "buffer.update", Authenticated: true, Timestamp: now},
		{TraceID: "edit", Kind: model.EventKernel, Source: "operator-alice", Actor: "operator-alice", Action: "file.write", Path: "/work/c/a.go", Timestamp: now.Add(time.Second)},
	}
	for _, r := range Evaluate(events, Options{CellID: "c", Worktree: "/work/c", EvidenceHealthy: true}) {
		if r.RuleID == "D9" {
			t.Fatal("unexpected D9")
		}
	}
}
