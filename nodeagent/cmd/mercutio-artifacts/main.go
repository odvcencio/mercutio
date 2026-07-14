package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	continuumhorizon "m31labs.dev/continuum/horizon"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mercutio-artifacts:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("mercutio-artifacts", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "generated/mercutio.cap.json", "Horizon capability manifest")
	objectPath := flags.String("object", "generated/mercutio.bpf.o", "compiled BPF object")
	keyPath := flags.String("private-key", "", "Ed25519 private key or seed file")
	keyID := flags.String("key-id", "", "release signing key ID")
	outDir := flags.String("out", "dist", "release artifact directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*keyID) == "" {
		return fmt.Errorf("--private-key and --key-id are required")
	}
	manifest, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	object, err := os.ReadFile(*objectPath)
	if err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signature, err := continuumhorizon.SignPayload(manifest, *keyID, privateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	manifestName, objectName := filepath.Base(*manifestPath), filepath.Base(*objectPath)
	pins := map[string]string{manifestName: continuumhorizon.SHA256Hex(manifest), objectName: continuumhorizon.SHA256Hex(object)}
	pinsJSON, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	publicJSON, err := json.MarshalIndent([]map[string]string{{"id": *keyID, "key": base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))}}, "", "  ")
	if err != nil {
		return err
	}
	for path, data := range map[string][]byte{
		filepath.Join(*outDir, manifestName):        manifest,
		filepath.Join(*outDir, manifestName+".sig"): signature,
		filepath.Join(*outDir, objectName):          object,
		filepath.Join(*outDir, "pins.json"):         append(pinsJSON, '\n'),
		filepath.Join(*outDir, "public-keys.json"):  append(publicJSON, '\n'),
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	decoded, decodeErr := base64.StdEncoding.DecodeString(trimmed)
	if decodeErr != nil {
		decoded, decodeErr = hex.DecodeString(trimmed)
	}
	if decodeErr != nil {
		decoded = data
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), decoded...)), nil
	default:
		return nil, fmt.Errorf("Ed25519 key must contain a %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}
