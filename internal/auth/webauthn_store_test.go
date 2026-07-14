package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gosxauth "m31labs.dev/gosx/auth"
)

func TestFileWebAuthnStoreSurvivesRestartAndUpdatesCounter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	store, err := newFileWebAuthnStore(path)
	if err != nil {
		t.Fatal(err)
	}
	credential := gosxauth.WebAuthnCredential{ID: "credential-a", User: gosxauth.User{ID: "operator@example.test", Email: "operator@example.test"}, PublicKey: []byte{1, 2, 3}, Algorithm: -7, SignCount: 1, Transports: []string{"internal"}}
	if err := store.SaveCredential(credential); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions=%v", info.Mode().Perm())
	}

	restarted, err := newFileWebAuthnStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Credential(credential.ID)
	if err != nil || loaded.User.ID != credential.User.ID || loaded.SignCount != 1 || len(loaded.PublicKey) != 3 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	usedAt := time.Now().UTC().Truncate(time.Second)
	if err := restarted.UpdateCounter(credential.ID, 2, usedAt); err != nil {
		t.Fatal(err)
	}
	again, err := newFileWebAuthnStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = again.Credential(credential.ID)
	if err != nil || loaded.SignCount != 2 || !loaded.LastUsedAt.Equal(usedAt) {
		t.Fatalf("updated=%+v err=%v", loaded, err)
	}
	credentials, err := again.Credentials(credential.User.ID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
}

func TestFileWebAuthnStoreFailsClosedOnCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileWebAuthnStore(path); err == nil {
		t.Fatal("corrupt passkey state was accepted")
	}
}
