package cell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/evidence"
)

func unavailableEvidenceLog(t *testing.T) *evidence.Log {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence-target")
	log, err := evidence.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Open succeeds while the path is absent; replacing the target with a
	// directory makes every subsequent durable append fail deterministically.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return log
}

func TestSecretPlaintextIsNotReleasedWhenReceiptAppendFails(t *testing.T) {
	store := NewStore()
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, _, err := store.PutSecret("cell-demo", "TOKEN", "credential-value", "operator", writeCap); err != nil {
		t.Fatal(err)
	}
	store.evidence = unavailableEvidenceLog(t)

	readCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:read")
	value, receipt, err := store.SecretValue("cell-demo", "TOKEN", "operator", readCap)
	if err == nil || value != "" || receipt.ID != "" || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("unreceipted read released secret: value=%q receipt=%+v err=%v", value, receipt, err)
	}
	snapshot, _ := store.Snapshot("cell-demo")
	if snapshot.EvidenceHealth != "degraded" {
		t.Fatalf("receipt failure did not degrade evidence: %+v", snapshot.Cell)
	}
}

func TestSecretWriteReportsReceiptFailure(t *testing.T) {
	store := NewStore()
	store.evidence = unavailableEvidenceLog(t)
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, receipt, err := store.PutSecret("cell-demo", "TOKEN", "credential-value", "operator", writeCap); err == nil || receipt.ID != "" || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("unreceipted write reported success: receipt=%+v err=%v", receipt, err)
	}
}

func TestShadowGarbageCollectionRetainsRevisionWhenReceiptFails(t *testing.T) {
	store := NewStore()
	if _, err := store.SetWriterActive("cell-demo", "cmd/hello/main.go", "operator", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyEdit("cell-demo", "cmd/hello/main.go", "package main\n// human\n", "operator"); err != nil {
		t.Fatal(err)
	}
	shadowed, err := store.ApplyEdit("cell-demo", "cmd/hello/main.go", "package main\n// agent\n", "agent-cell-demo")
	if err != nil || len(shadowed.Shadows) == 0 {
		t.Fatalf("create shadow: %+v %v", shadowed.Shadows, err)
	}
	if _, err := store.AdoptShadow("cell-demo", shadowed.Shadows[0].ID, "operator"); err != nil {
		t.Fatal(err)
	}
	store.evidence = unavailableEvidenceLog(t)
	if removed := store.CollectShadowGarbage(time.Now().UTC()); removed != 0 {
		t.Fatalf("removed %d shadows without durable receipts", removed)
	}
	after, _ := store.Snapshot("cell-demo")
	found := false
	for _, shadow := range after.Shadows {
		found = found || shadow.ID == shadowed.Shadows[0].ID
	}
	if !found {
		t.Fatal("resolved shadow disappeared after receipt failure")
	}
}
