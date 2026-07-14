package shadow

import (
	"strings"
	"testing"

	"m31labs.dev/mercutio/internal/intelligence"
)

func TestMergeNonOverlappingEntitiesAndNameSameEntityConflict(t *testing.T) {
	service := intelligence.New()
	base := "package p\n\nfunc A() int { return 1 }\nfunc B() int { return 2 }\n"
	human := "package p\n\nfunc A() int { return 10 }\nfunc B() int { return 2 }\n"
	agent := "package p\n\nfunc A() int { return 1 }\nfunc B() int { return 20 }\n"
	merged := Merge(service, "x.go", "go", base, human, agent)
	if !merged.Clean || len(merged.Conflicts) != 0 || !strings.Contains(merged.Content, "return 10") || !strings.Contains(merged.Content, "return 20") {
		t.Fatalf("merged=%+v", merged)
	}
	conflict := Merge(service, "x.go", "go", base, human, "package p\n\nfunc A() int { return 11 }\nfunc B() int { return 2 }\n")
	if len(conflict.Conflicts) != 1 || !strings.HasSuffix(conflict.Conflicts[0], "::A") {
		t.Fatalf("conflict=%+v", conflict)
	}
}

func TestMergeFallsBackToLineDiff3AndKeepsConflictOutOfLiveContent(t *testing.T) {
	service := intelligence.New()
	base := "alpha\nbravo\ncharlie\n"
	human := "alpha human\nbravo\ncharlie\n"
	agent := "alpha\nbravo\ncharlie agent\n"
	merged := Merge(service, "notes.txt", "text", base, human, agent)
	if !merged.Clean || merged.Intelligence != "line-diff3" || !strings.Contains(merged.Content, "alpha human") || !strings.Contains(merged.Content, "charlie agent") {
		t.Fatalf("fallback merge=%+v", merged)
	}

	conflict := Merge(service, "notes.txt", "text", base, human, "alpha agent\nbravo\ncharlie\n")
	if conflict.Clean || conflict.Content != human || conflict.Intelligence != "line-diff3" || len(conflict.Conflicts) == 0 {
		t.Fatalf("fallback conflict=%+v", conflict)
	}
}
