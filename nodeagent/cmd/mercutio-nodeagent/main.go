package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	continuumhorizon "m31labs.dev/continuum/horizon"
	"m31labs.dev/mercutio/nodeagent/internal/agent"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("mercutio-nodeagent: %v", err)
		os.Exit(1)
	}
}

func run() error {
	nodeID := requiredEnv("NODE_NAME")
	controlURL := requiredEnv("MERCUTIO_CONTROL_URL")
	token := requiredEnv("MERCUTIO_EVENT_TOKEN")
	if nodeID == "" || controlURL == "" || token == "" {
		return fmt.Errorf("NODE_NAME, MERCUTIO_CONTROL_URL, and MERCUTIO_EVENT_TOKEN are required")
	}
	manifest := envOr("MERCUTIO_HORIZON_MANIFEST", "/etc/mercutio/programs/mercutio.cap.json")
	object := envOr("MERCUTIO_HORIZON_OBJECT", "/etc/mercutio/programs/mercutio.bpf.o")
	pins, err := readPins(envOr("MERCUTIO_HORIZON_PINS", "/etc/mercutio/trust/pins.json"))
	if err != nil {
		return err
	}
	keys, err := readKeys(envOr("MERCUTIO_HORIZON_PUBLIC_KEYS", "/etc/mercutio/trust/public-keys.json"))
	if err != nil {
		return err
	}
	control := agent.HTTPControl{BaseURL: controlURL, Token: token}
	mtlsClient, err := newMTLSClient(
		requiredEnv("MERCUTIO_MTLS_CERT"),
		requiredEnv("MERCUTIO_MTLS_KEY"),
		requiredEnv("MERCUTIO_MTLS_CA"),
	)
	if err != nil {
		return err
	}
	control.Client = mtlsClient
	queue := agent.NewTelemetryQueue(nodeID, envInt("MERCUTIO_TELEMETRY_CAPACITY", 8192), control)
	manager, err := agent.NewProgramManager(agent.ProgramOptions{
		ManifestPath: manifest, ObjectPath: object, DigestPins: pins, PublicKeys: keys,
		BaseAllow: splitList(os.Getenv("MERCUTIO_BASE_EGRESS")), Queue: queue,
	})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	server := healthServer(envOr("MERCUTIO_HEALTH_ADDR", ":9090"))
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	errorsCh := make(chan error, 3)
	go func() { errorsCh <- server.ListenAndServe() }()
	go func() { errorsCh <- queue.Run(ctx) }()
	go pollActionDecisions(ctx, nodeID, control, manager)
	runner := &agent.Agent{
		Source: agent.ControlSource{Control: control, NodeID: nodeID, CgroupRoot: envOr("MERCUTIO_CGROUP_ROOT", "/sys/fs/cgroup")},
		Loader: manager, Control: control, Drain: agent.NodeDrainReporter{NodeID: nodeID, Queue: queue, Control: control}, Interval: time.Duration(envInt("MERCUTIO_RECONCILE_MS", 2000)) * time.Millisecond,
	}
	go func() { errorsCh <- runner.Run(ctx) }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errorsCh:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
				cancel()
				return err
			}
		}
	}
}

func pollActionDecisions(ctx context.Context, nodeID string, control agent.HTTPControl, manager *agent.ProgramManager) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			decisions, err := control.ActionDecisions(ctx, nodeID)
			if err != nil {
				continue
			}
			for _, decision := range decisions {
				if err := manager.ApplyDecision(decision); err != nil {
					log.Printf("action decision %s: %v", decision.ID, err)
				}
			}
		}
	}
}

func newMTLSClient(certPath, keyPath, caPath string) (*http.Client, error) {
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, fmt.Errorf("MERCUTIO_MTLS_CERT, MERCUTIO_MTLS_KEY, and MERCUTIO_MTLS_CA are required")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load node mTLS identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read control-plane CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("control-plane CA contains no certificates")
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
		}},
	}, nil
}

func healthServer(address string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
}

func readPins(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read digest pins: %w", err)
	}
	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("decode digest pins: %w", err)
	}
	if len(pins) < 2 {
		return nil, fmt.Errorf("digest pins must include the manifest and object")
	}
	return pins, nil
}

func readKeys(path string) ([]continuumhorizon.TrustedPublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted public keys: %w", err)
	}
	var encoded []struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &encoded); err != nil {
		return nil, fmt.Errorf("decode trusted public keys: %w", err)
	}
	keys := make([]continuumhorizon.TrustedPublicKey, 0, len(encoded))
	for _, item := range encoded {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(item.Key))
		if err != nil {
			decoded, err = hex.DecodeString(strings.TrimSpace(item.Key))
		}
		if err != nil || len(decoded) != ed25519.PublicKeySize || strings.TrimSpace(item.ID) == "" {
			return nil, fmt.Errorf("trusted key %q is not a named Ed25519 public key", item.ID)
		}
		keys = append(keys, continuumhorizon.TrustedPublicKey{ID: item.ID, Key: ed25519.PublicKey(decoded)})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one trusted Horizon signing key is required")
	}
	return keys, nil
}

func requiredEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func envOr(name, fallback string) string {
	if value := requiredEnv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(requiredEnv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == '\n' })
	result := make([]string, 0, len(fields))
	for _, item := range fields {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
