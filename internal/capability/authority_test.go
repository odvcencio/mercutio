package capability

import (
	"testing"
	"time"
)

func TestCapabilityIsCellPermissionAndTTLScoped(t *testing.T) {
	authority := New([]byte("01234567890123456789012345678901"))
	now := time.Unix(1000, 0).UTC()
	authority.now = func() time.Time { return now }
	token, err := authority.Mint(Claims{CellID: "cell-1", ActorID: "agent-1", Role: "agent", Permissions: []string{"hub:attach", "buffer:write"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := authority.Verify(token, "cell-1", "buffer:write")
	if err != nil || claims.ActorID != "agent-1" {
		t.Fatalf("verify = %#v, %v", claims, err)
	}
	if _, err := authority.Verify(token, "cell-2", "buffer:write"); err == nil {
		t.Fatal("cross-cell capability was accepted")
	}
	if _, err := authority.Verify(token, "cell-1", "telemetry:read"); err == nil {
		t.Fatal("ungranted telemetry permission was accepted")
	}
	authority.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := authority.Verify(token, "cell-1", "hub:attach"); err == nil {
		t.Fatal("expired capability was accepted")
	}
}
