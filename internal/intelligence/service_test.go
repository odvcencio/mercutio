package intelligence

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyzeFailsClosedWhenAuthoritativeParseTimesOut(t *testing.T) {
	service := newWithParseTimeoutMicros(1)
	source := "package main\n" + strings.Repeat("func generated() { println(1) }\n", 100_000)
	started := time.Now()
	analysis := service.Analyze("main.go", "go", source)

	if !strings.Contains(analysis.Error, "intelligence unavailable") || !strings.Contains(analysis.Error, "timeout") {
		t.Fatalf("analysis error = %q, want unavailable timeout", analysis.Error)
	}
	if len(analysis.Highlights) != 0 || len(analysis.Symbols) != 0 {
		t.Fatalf("timed-out analysis exposed decisions: %+v", analysis)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timed-out analysis took %s", elapsed)
	}
}

func TestAnalyzeIncrementalFailsClosedWhenParseTimesOut(t *testing.T) {
	service := newWithParseTimeoutMicros(1)
	source := "package main\n" + strings.Repeat("func generated() { println(1) }\n", 100_000)
	analysis := service.AnalyzeIncremental("cell-1:main.go", "main.go", "go", source)

	if !strings.Contains(analysis.Error, "parse stopped before accepting input: timeout") {
		t.Fatalf("analysis error = %q, want parse timeout", analysis.Error)
	}
	if len(analysis.Highlights) != 0 || len(analysis.Symbols) != 0 {
		t.Fatalf("timed-out incremental analysis exposed decisions: %+v", analysis)
	}
}

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

func TestAnalyzeSupportsMercutioConfigAndDSLLanes(t *testing.T) {
	tests := []struct {
		path, language, source string
	}{
		{"config.yaml", "yaml", "enabled: true\nname: mercutio\n"},
		{"config.toml", "toml", "enabled = true\nname = \"mercutio\"\n"},
		{"config.json", "json", "{\"enabled\": true, \"name\": \"mercutio\"}\n"},
		{"policy.hcl", "hcl", "profile \"strict\" { enabled = true }\n"},
		{"guide.mdpp", "markdown", "# Mercutio\n\n**ready**\n"},
		{"policy.arb", "arbiter", "rule Allow priority 1 { when { action == \"read\" } then Allow { reason: \"safe\" } }\n"},
		{"program.hzn", "horizon", "package demo\n\nfunc allow(value u32) bool { return value > 0 }\n"},
	}
	service := New()
	for _, test := range tests {
		t.Run(test.language, func(t *testing.T) {
			analysis := service.AnalyzeIncremental("cell-1:"+test.path, test.path, test.language, test.source)
			if analysis.Path != test.path || analysis.Error != "" || len(analysis.Highlights) == 0 {
				t.Fatalf("analysis = %+v", analysis)
			}
		})
	}
}
