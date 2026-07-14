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
