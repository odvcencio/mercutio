package cell

import (
	"testing"
	"time"
)

func TestTier2GrantIsAskHumanBoundedAndSingleUse(t *testing.T) {
	store := NewStore()
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, _, err := store.PutSecret("cell-demo", "SANDBOX_KEY", "credential-value", "operator", writeCap); err != nil {
		t.Fatal(err)
	}
	_, request, err := store.RequestSecretGrant("cell-demo", "SANDBOX_KEY", "run integration test", "agent-cell-demo", "SANDBOX_KEY", []string{"go", "test", "./..."}, ".", 5*time.Minute)
	if err != nil || request.Status != "pending" {
		t.Fatalf("request=%+v %v", request, err)
	}
	grantCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:grant")
	snapshot, grant, err := store.ApproveSecretGrant("cell-demo", request.ID, "operator", grantCap)
	if err != nil || grant == "" || snapshot.SecretRequests[0].Status != "approved" {
		t.Fatalf("approve=%+v %v", snapshot.SecretRequests, err)
	}
	value, receipt, err := store.ConsumeSecretGrant("cell-demo", request.ID, grant)
	if err != nil || value != "credential-value" || receipt.Action != "secret:tier2-inject" {
		t.Fatalf("consume=%q %+v %v", value, receipt, err)
	}
	if _, _, err = store.ConsumeSecretGrant("cell-demo", request.ID, grant); err == nil {
		t.Fatal("single-use grant consumed twice")
	}
	if _, _, err = store.RequestSecretGrant("cell-demo", "SANDBOX_KEY", "too long", "agent-cell-demo", "SANDBOX_KEY", []string{"go", "test"}, ".", 21*time.Minute); err == nil {
		t.Fatal("grant over 20 minutes accepted")
	}
	if _, _, err = store.RequestSecretGrant("cell-demo", "SANDBOX_KEY", "escape", "agent-cell-demo", "SANDBOX_KEY", []string{"go", "test"}, "../outside", time.Minute); err == nil {
		t.Fatal("worktree escape accepted")
	}
}
