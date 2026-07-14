package intelligence

import "testing"

func TestAnalyzeIncrementalMatchesFreshAnalysis(t *testing.T) {
	service := New()
	first := service.AnalyzeIncremental("cell-1:main.go", "main.go", "go", "package main\n\nfunc hello() {}\n")
	if first.Language != "go" || len(first.Symbols) == 0 || len(first.Highlights) == 0 {
		t.Fatalf("initial analysis = %+v", first)
	}
	updatedSource := "package main\n\nfunc goodbye() {}\n"
	updated := service.AnalyzeIncremental("cell-1:main.go", "main.go", "go", updatedSource)
	fresh := service.Analyze("main.go", "go", updatedSource)
	if updated.HasErrors != fresh.HasErrors || len(updated.Symbols) != len(fresh.Symbols) || len(updated.Highlights) != len(fresh.Highlights) {
		t.Fatalf("incremental=%+v fresh=%+v", updated, fresh)
	}
	if updated.Symbols[0].Name != "goodbye" {
		t.Fatalf("incremental symbol = %+v", updated.Symbols[0])
	}
}
