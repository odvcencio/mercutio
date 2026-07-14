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
