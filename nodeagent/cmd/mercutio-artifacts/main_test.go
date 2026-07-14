package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	continuumhorizon "m31labs.dev/continuum/horizon"
)

func TestRunCreatesVerifiablePinnedRelease(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "mercutio.cap.json")
	objectPath := filepath.Join(dir, "mercutio.bpf.o")
	keyPath := filepath.Join(dir, "key")
	manifest, object := []byte(`{"schema":"m31labs.dev/horizon/capability/v1","package":"test"}`), []byte("object")
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	for path, data := range map[string][]byte{manifestPath: manifest, objectPath: object, keyPath: []byte(base64.StdEncoding.EncodeToString(seed))} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "release")
	if err := run([]string{"--manifest", manifestPath, "--object", objectPath, "--private-key", keyPath, "--key-id", "test", "--out", out}); err != nil {
		t.Fatal(err)
	}
	pins, err := readPinsForTest(filepath.Join(out, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	if _, err := continuumhorizon.Preflight(continuumhorizon.PreflightOptions{
		ManifestPath: filepath.Join(out, "mercutio.cap.json"), ObjectPath: filepath.Join(out, "mercutio.bpf.o"), DigestPins: pins,
		PublicKeys: []continuumhorizon.TrustedPublicKey{{ID: "test", Key: private.Public().(ed25519.PublicKey)}},
	}); err != nil {
		t.Fatal(err)
	}
}

func readPinsForTest(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pins map[string]string
	err = json.Unmarshal(data, &pins)
	return pins, err
}
