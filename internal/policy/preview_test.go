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
}
