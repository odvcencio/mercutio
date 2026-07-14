package intelligence

import (
	"strings"
	"testing"
)

func TestSecretScanStructuralAndFallbackAreExplicit(t *testing.T) {
	service := New()
	structural := service.ScanSecrets("config.yaml", "token: ghp_abcdefghijklmnopqrstuvwxyz\n")
	if structural.Status != "structural" || len(structural.Findings) == 0 {
		t.Fatalf("structural=%+v", structural)
	}
	broken := service.ScanSecrets("main.go", "package main\nfunc {")
	if broken.Status != "unavailable" {
		t.Fatalf("broken=%+v", broken)
	}
	minified := service.ScanSecrets("app.js", "const token='ghp_abcdefghijklmnopqrstuvwxyz';"+strings.Repeat("a", 5000))
	if minified.Status != "unavailable" || len(minified.Findings) == 0 {
		t.Fatalf("minified=%+v", minified)
	}
}

func TestSecretScanTimeoutFallsBackWithoutTrustingPartialTree(t *testing.T) {
	source := "package main\n" + strings.Repeat("func generated() { println(1) }\n", 100_000)
	scan := scanSecretsWithTimeout("main.go", source, 1)
	if scan.Status != "unavailable" || !strings.Contains(scan.Reason, "timed out") {
		t.Fatalf("timed-out scan=%+v", scan)
	}
}
