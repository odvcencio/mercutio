package secrets

import "testing"

func TestBrokerStoresByReceiptWithoutExposingValue(t *testing.T) {
	broker := NewBroker()
	receipt, err := broker.Put("cell-1", "github-token", "ghp_abcdefghijklmnopqrstuvwxyz", "capability")
	if err != nil || receipt.ID == "" || receipt.Version != 1 {
		t.Fatalf("Put = %+v, %v", receipt, err)
	}
	if !ContainsSecretShape("token: ghp_abcdefghijklmnopqrstuvwxyz") {
		t.Fatal("secret-shaped value was not detected")
	}
	if got := RedactText("token: ghp_abcdefghijklmnopqrstuvwxyz"); got == "token: ghp_abcdefghijklmnopqrstuvwxyz" || got == "" {
		t.Fatalf("redaction = %q", got)
	}
	if _, _, err := broker.Get("cell-1", "github-token", ""); err == nil {
		t.Fatal("broker allowed access without capability")
	}
}

func TestFindSecretSpansReturnsExactNonOverlappingRanges(t *testing.T) {
	value := "before ghp_abcdefghijklmnopqrstuvwxyz after AKIAABCDEFGHIJKLMNOP end"
	spans := FindSecretSpans(value)
	if len(spans) != 2 {
		t.Fatalf("spans=%+v", spans)
	}
	for _, span := range spans {
		if span.Start < 0 || span.End <= span.Start || span.End > len(value) || !ContainsSecretShape(value[span.Start:span.End]) {
			t.Fatalf("invalid secret span %+v", span)
		}
	}
}
