package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestReadKeysAndPinsFailClosed(t *testing.T) {
	dir := t.TempDir()
	_, public, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keysPath, []byte(`[{"id":"release","key":"`+base64.StdEncoding.EncodeToString(public.Public().(ed25519.PublicKey))+`"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if keys, err := readKeys(keysPath); err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	pinsPath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(pinsPath, []byte(`{"mercutio.cap.json":"aa","mercutio.bpf.o":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if pins, err := readPins(pinsPath); err != nil || len(pins) != 2 {
		t.Fatalf("pins=%v err=%v", pins, err)
	}
	if err := os.WriteFile(keysPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeys(keysPath); err == nil {
		t.Fatal("empty trust roots accepted")
	}
}
