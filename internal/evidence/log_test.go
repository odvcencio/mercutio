package evidence

import (
	"path/filepath"
	"testing"
)

func TestEvidenceSurvivesReopenAndVerifiesHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append("cell-1", "event", map[string]string{"summary": "created"}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append("cell-1", "receipt", map[string]string{"id": "receipt-1"}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatal(err)
	}
	if records := reopened.Records("cell-1"); len(records) != 2 || records[1].Previous != records[0].Hash {
		t.Fatalf("records = %#v", records)
	}
}
