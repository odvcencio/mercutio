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
