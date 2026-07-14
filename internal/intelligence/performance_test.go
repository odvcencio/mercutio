package intelligence

import (
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	gosxintelligence "m31labs.dev/gosx/editor/intelligenceassets"
)

func TestIncrementalServerHighlightP95Budget(t *testing.T) {
	service := New()
	source := "package main\n\n" + strings.Repeat("func helper() int { return 42 }\n", 500)
	initial := service.AnalyzeIncremental("perf:main.go", "main.go", "go", source)
	if initial.Error != "" || len(initial.Highlights) == 0 {
		t.Fatalf("initial analysis failed: %+v", initial)
	}
	durations := make([]time.Duration, 25)
	for i := range durations {
		updated := source + strings.Repeat(" ", i) + "\n"
		started := time.Now()
		analysis := service.AnalyzeIncremental("perf:main.go", "main.go", "go", updated)
		durations[i] = time.Since(started)
		if analysis.Error != "" {
			t.Fatal(analysis.Error)
		}
	}
	slices.Sort(durations)
	if p95 := durations[23]; p95 > 150*time.Millisecond {
		t.Fatalf("incremental server highlight p95 = %s, budget 150ms", p95)
	}
}

func TestWASMRuntimeCompressedSizeBudget(t *testing.T) {
	request := httptest.NewRequest("GET", "/gotreesitter.wasm", nil)
	recorder := httptest.NewRecorder()
	gosxintelligence.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("runtime status = %d", recorder.Code)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(recorder.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	const budget = 3600 * 1024
	if compressed.Len() > budget {
		t.Fatalf("compressed WASM runtime = %d bytes, budget %d", compressed.Len(), budget)
	}
}
