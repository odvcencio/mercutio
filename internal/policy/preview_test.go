package policy

import "testing"

func TestPreviewShowsImpactWithoutMutatingProfile(t *testing.T) {
	before, err := Resolve("standard")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Preview(before, "profile: strict\n")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Before.Profile != "standard" || preview.After.Profile != "strict" || len(preview.Changes) == 0 || len(preview.Affects) == 0 {
		t.Fatalf("preview = %+v", preview)
	}
	if before.Profile != "standard" {
		t.Fatalf("before manifest mutated: %+v", before)
	}
	if len(preview.Classes) != 1 || preview.Classes[0].Narrows == 0 || preview.Classes[0].Widens != 0 {
		t.Fatalf("expected strict policy to report static narrows: %+v", preview.Classes)
	}
}

func TestPreviewReplaysRecordedEventsPerRunningCell(t *testing.T) {
	before, err := Resolve("standard")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewForCells(before, "profile: strict\n", []ReplayCell{{
		CellID: "cell-b", Profile: "standard", Worktree: "/workspace/repo",
		Events: []ReplayEvent{
			{ID: "k2", Action: "network.connect", Destination: "github.com:443"},
			{ID: "k1", Action: "file.write", Path: "/workspace/repo/main.go"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Cells) != 1 || preview.Cells[0].CellID != "cell-b" || !preview.Cells[0].RequiresRearm {
		t.Fatalf("missing per-cell impact: %+v", preview.Cells)
	}
	if preview.Cells[0].Narrows == 0 || preview.Cells[0].Widens != 0 {
		t.Fatalf("expected replayed standard-to-strict event narrows: %+v", preview.Cells[0])
	}
	for _, flip := range preview.Cells[0].Replay {
		if flip.Direction != "narrows" || flip.BeforeVerdict == flip.AfterVerdict {
			t.Fatalf("invalid replay flip: %+v", flip)
		}
	}
}

func TestPreviewReportsWidens(t *testing.T) {
	before, err := Resolve("strict")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewForCells(before, "profile: open\n", []ReplayCell{{CellID: "cell-a", Profile: "strict", Events: []ReplayEvent{{ID: "k", Action: "process.exec", Argv: "curl https://example.com"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classes[0].Widens == 0 || preview.Cells[0].Widens == 0 {
		t.Fatalf("expected static and replay widens: classes=%+v cells=%+v", preview.Classes, preview.Cells)
	}
}
