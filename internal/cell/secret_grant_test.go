package cell

import (
	"strings"
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

func TestFailedTier2DeliveryRollsApprovalBackAndInvalidatesGrant(t *testing.T) {
	store := NewStore()
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, _, err := store.PutSecret("cell-demo", "SANDBOX_KEY", "credential-value", "operator", writeCap); err != nil {
		t.Fatal(err)
	}
	_, request, err := store.RequestSecretGrant("cell-demo", "SANDBOX_KEY", "run test", "agent-cell-demo", "SANDBOX_KEY", []string{"go", "test", "./..."}, ".", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grantCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:grant")
	_, grant, err := store.ApproveSecretGrant("cell-demo", request.ID, "operator", grantCap)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.FailSecretGrantDelivery("cell-demo", request.ID, "connection failed with ghp_sensitive")
	if err != nil || snapshot.SecretRequests[0].Status != "pending" || !snapshot.SecretRequests[0].ExpiresAt.IsZero() {
		t.Fatalf("rollback=%+v err=%v", snapshot.SecretRequests, err)
	}
	if _, _, err := store.ConsumeSecretGrant("cell-demo", request.ID, grant); err == nil {
		t.Fatal("undelivered grant remained consumable")
	}
	latest := snapshot.Events[len(snapshot.Events)-1]
	if latest.Action != "secret.grant.delivery-failed" || strings.Contains(latest.Detail, "ghp_sensitive") {
		t.Fatalf("delivery failure receipt=%+v", latest)
	}
}
