package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"m31labs.dev/gosx"
	gosxeditor "m31labs.dev/gosx/editor"
	gosxintelligence "m31labs.dev/gosx/editor/intelligenceassets"
	"m31labs.dev/gosx/server"
	"m31labs.dev/mercutio/internal/actions"
	"m31labs.dev/mercutio/internal/api"
	"m31labs.dev/mercutio/internal/auth"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/evidence"
	"m31labs.dev/mercutio/internal/policy"
	"m31labs.dev/mercutio/internal/review"
	"m31labs.dev/mercutio/internal/sandbox"
	secretstore "m31labs.dev/mercutio/internal/secrets"
	"m31labs.dev/mercutio/internal/transport"
	"m31labs.dev/mercutio/internal/view"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "attach" {
		runAttach(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		os.Exit(runAgent(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "armgate" {
		runArmgate(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "workspace-probe" {
		runWorkspaceProbe(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(runDoctor(os.Args[2:], os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "adversary" {
		os.Exit(runAdversary(os.Args[2:], os.Stdout, os.Stderr))
	}
	port := flag.String("port", envOr("MERCUTIO_PORT", "9011"), "HTTP port")
	flag.Parse()

	sandboxRuntime := sandbox.Runtime(sandbox.NewMemoryRuntime())
	secretBroker := secretstore.NewBroker()
	if envOr("MERCUTIO_SANDBOX_RUNTIME", "memory") == "kubernetes" {
		kubernetesRuntime, err := sandbox.NewKubernetesRuntimeFromEnv()
		if err != nil {
			log.Fatal(err)
		}
		sandboxRuntime = kubernetesRuntime
		secretBroker, err = secretstore.NewKubernetesBrokerFromEnv(envOr("MERCUTIO_NAMESPACE", "default"))
		if err != nil {
			log.Fatal(err)
		}
	}
	committer := review.Committer(review.LocalCommitter{})
	if envOr("MERCUTIO_COMMITTER", "local") == "buckley" {
		committer = review.NewBuckleyCommitter(envOr("BUCKLEY_BINARY", "buckley"))
	}
	store := cell.NewStoreWithOptions(cell.Options{
		Runtime:       sandboxRuntime,
		Committer:     committer,
		WorktreeRoot:  os.Getenv("MERCUTIO_WORKTREE_ROOT"),
		HubURL:        envOr("MERCUTIO_HUB_URL", "http://mercutio:9011/gosx/hub/agent"),
		Evidence:      mustEvidence(envOr("MERCUTIO_EVIDENCE_PATH", "./data/evidence.jsonl")),
		CapabilityKey: []byte(os.Getenv("MERCUTIO_CAPABILITY_SECRET")),
		StatePath:     envOr("MERCUTIO_STATE_PATH", "./data/state.json"),
		SecretBroker:  secretBroker,
	})
	cellHub := transport.NewCellHub(store)
	if envOr("MERCUTIO_COMMITTER", "local") == "agent" {
		store.SetCommitter(review.NewAgentCommitter(cellHub.RequestAgentCommit))
	}
	apiHandler := api.New(store, cellHub)
	browserActions := actions.New(store, cellHub)
	authn := auth.FromEnv()

	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	publicDir, err := filepath.Abs(filepath.Join(root, "public"))
	if err != nil {
		log.Fatal(err)
	}

	app := server.New()
	app.Use(authn.SessionMiddleware)
	app.SetPublicDir(publicDir)
	app.Mount("/editor/", http.StripPrefix("/editor/", gosxeditor.AssetHandler()))
	app.Mount("/intelligence/", authn.Require(http.StripPrefix("/intelligence/", gosxintelligence.Handler())))
	app.SetLayout(view.Layout)
	app.Page("GET /login", func(ctx *server.Context) gosx.Node { return view.LoginPage(authn.CSRFToken(ctx.Request)) })
	app.HandlePage(server.PageRoute{Pattern: "GET /", Middleware: []server.Middleware{server.Middleware(authn.Require)}, Handler: func(ctx *server.Context) gosx.Node {
		cellID := ctx.Request.URL.Query().Get("cell")
		path := ctx.Request.URL.Query().Get("file")
		if mobileShellRequest(ctx.Request) {
			return view.MobilePage(store.State(cellHub.ClientCount()), cellID, authn.CSRFToken(ctx.Request))
		}
		var preview *policy.PreviewResult
		if path == "policy/sandbox.yaml" && ctx.Request.URL.Query().Get("policyPreview") == "1" {
			if file, fileErr := store.File(cellID, path); fileErr == nil {
				if result, previewErr := store.PolicyPreview(cellID, file.Content); previewErr == nil {
					preview = &result
				}
			}
		}
		return view.PageWithPolicyPreview(store.State(cellHub.ClientCount()), cellID, path, authn.CSRFToken(ctx.Request), preview)
	}})
	app.Mount("POST /gosx/action/{name}", authn.Require(authn.ProtectBrowser(browserActions)))

	// API mutations and the collaboration hub share the same operator boundary.
	app.Mount("GET /api/state", authn.Require(http.HandlerFunc(apiHandler.State)))
	app.Mount("GET /api/session", http.HandlerFunc(authn.Session))
	app.Mount("POST /api/cells", authn.Require(http.HandlerFunc(apiHandler.CreateCell)))
	app.Mount("GET /api/cells/{cellID}", authn.Require(http.HandlerFunc(apiHandler.Cell)))
	app.Mount("GET /api/cells/{cellID}/events", authn.Require(http.HandlerFunc(apiHandler.Events)))
	app.Mount("GET /api/cells/{cellID}/evidence", authn.Require(http.HandlerFunc(apiHandler.Evidence)))
	app.Mount("POST /api/cells/{cellID}/events", authn.Require(http.HandlerFunc(apiHandler.RecordEvent)))
	app.Mount("POST /api/cells/{cellID}/attach-token", authn.Require(http.HandlerFunc(apiHandler.AttachToken)))
	app.Mount("GET /api/cells/{cellID}/capability", authn.Require(http.HandlerFunc(apiHandler.OperatorCapability)))
	app.Mount("POST /api/cells/{cellID}/secrets", authn.Require(http.HandlerFunc(apiHandler.PutSecret)))
	app.Mount("GET /api/cells/{cellID}/secrets", authn.Require(http.HandlerFunc(apiHandler.SecretDescriptors)))
	app.Mount("POST /api/cells/{cellID}/secret-capability", authn.Require(authn.ProtectBrowser(http.HandlerFunc(apiHandler.SecretCapability))))
	app.Mount("POST /api/cells/{cellID}/secret-grants/{requestID}/approve", authn.Require(http.HandlerFunc(apiHandler.ApproveSecretGrant)))
	app.Mount("POST /api/internal/tier2/consume", http.HandlerFunc(apiHandler.ConsumeSecretGrant))
	app.Mount("POST /api/internal/cells/{cellID}/armed", authn.RequireInternal(http.HandlerFunc(apiHandler.Armed)))
	app.Mount("GET /api/internal/cells/{cellID}/arm-state", http.HandlerFunc(apiHandler.ArmState))
	app.Mount("POST /api/internal/cells/{cellID}/workspace-device", http.HandlerFunc(apiHandler.WorkspaceDevice))
	app.Mount("POST /api/internal/telemetry/kernel", authn.RequireInternal(http.HandlerFunc(apiHandler.KernelTelemetry)))
	app.Mount("GET /api/internal/nodes/{nodeID}/action-decisions", authn.RequireInternal(http.HandlerFunc(apiHandler.NodeActionDecisions)))
	app.Mount("GET /api/internal/nodes/{nodeID}/cells", authn.RequireInternal(http.HandlerFunc(apiHandler.NodeCells)))
	app.Mount("POST /api/cells/{cellID}/secret-proxies", authn.Require(http.HandlerFunc(apiHandler.ConfigureSecretProxy)))
	app.Mount("/api/proxy/", http.HandlerFunc(apiHandler.SecretProxy))
	app.Mount("GET /api/cells/{cellID}/secrets/{name}", authn.RequireSecret(http.HandlerFunc(apiHandler.GetSecret)))
	app.Mount("POST /api/cells/{cellID}/analyze", authn.Require(http.HandlerFunc(apiHandler.Analyze)))
	app.Mount("POST /api/cells/{cellID}/edit", authn.Require(http.HandlerFunc(apiHandler.Edit)))
	app.Mount("POST /api/cells/{cellID}/undo", authn.Require(http.HandlerFunc(apiHandler.UndoEdit)))
	app.Mount("POST /api/cells/{cellID}/files/delete", authn.Require(http.HandlerFunc(apiHandler.DeleteFile)))
	app.Mount("POST /api/cells/{cellID}/policy/preview", authn.Require(http.HandlerFunc(apiHandler.PolicyPreview)))
	app.Mount("POST /api/cells/{cellID}/policy/apply", authn.Require(http.HandlerFunc(apiHandler.PolicyApply)))
	app.Mount("POST /api/cells/{cellID}/prompt", authn.Require(http.HandlerFunc(apiHandler.Prompt)))
	app.Mount("POST /api/cells/{cellID}/destroy", authn.Require(http.HandlerFunc(apiHandler.Destroy)))
	app.Mount("POST /api/cells/{cellID}/reviews/{reviewID}/approve", authn.Require(http.HandlerFunc(apiHandler.Approve)))
	app.Mount("POST /api/cells/{cellID}/reviews/{reviewID}/acknowledge", authn.Require(http.HandlerFunc(apiHandler.AcknowledgeReview)))
	app.Mount("POST /api/cells/{cellID}/reviews/{reviewID}/reject", authn.Require(http.HandlerFunc(apiHandler.RejectReview)))
	app.Mount("POST /api/cells/{cellID}/shadows/{shadowID}/{operation}", authn.Require(http.HandlerFunc(apiHandler.ShadowDecision)))
	app.Mount("/api/internal/events", authn.RequireInternal(http.HandlerFunc(apiHandler.InternalEvent)))
	app.Mount("POST /auth/magic-link", authn.ProtectBrowser(authn.MagicLinkRequest()))
	app.Mount("GET /auth/magic-link", authn.MagicLinkCallback())
	app.Mount("POST /auth/passkey/register/options", authn.ProtectBrowser(authn.WebAuthnRegisterOptions()))
	app.Mount("POST /auth/passkey/register", authn.ProtectBrowser(authn.WebAuthnRegister()))
	app.Mount("POST /auth/passkey/login/options", authn.ProtectBrowser(authn.WebAuthnLoginOptions()))
	app.Mount("POST /auth/passkey/login", authn.ProtectBrowser(authn.WebAuthnLogin()))
	app.Mount("/gosx/hub/cells", authn.Require(cellHub))
	app.Mount("/gosx/hub/agent", http.HandlerFunc(cellHub.ServeAgentHTTP))
	app.Mount("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok","service":"mercutio"}`))
	}))
	internalServer, err := internalMTLSServer(app.Build())
	if err != nil {
		log.Fatal(err)
	}
	if internalServer != nil {
		go func() {
			log.Printf("mercutio internal mTLS listener at %s", internalServer.Addr)
			if err := internalServer.ListenAndServeTLS(os.Getenv("MERCUTIO_INTERNAL_TLS_CERT"), os.Getenv("MERCUTIO_INTERNAL_TLS_KEY")); err != nil && err != http.ErrServerClosed {
				log.Fatalf("internal mTLS listener: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reconcileCells(ctx, store, cellHub)

	addr := ":" + *port
	log.Printf("mercutio listening at http://127.0.0.1%s", addr)
	if err := app.ListenAndServe(addr); err != nil {
		log.Fatal(err)
	}
}

func mobileShellRequest(request *http.Request) bool {
	if strings.EqualFold(request.URL.Query().Get("shell"), "mobile") || request.Header.Get("Sec-CH-UA-Mobile") == "?1" {
		return true
	}
	agent := strings.ToLower(request.UserAgent())
	return strings.Contains(agent, "iphone") || strings.Contains(agent, "ipad") || strings.Contains(agent, "android") || strings.Contains(agent, "mobile")
}

func internalMTLSServer(handler http.Handler) (*http.Server, error) {
	certPath := strings.TrimSpace(os.Getenv("MERCUTIO_INTERNAL_TLS_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("MERCUTIO_INTERNAL_TLS_KEY"))
	caPath := strings.TrimSpace(os.Getenv("MERCUTIO_INTERNAL_TLS_CLIENT_CA"))
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, fmt.Errorf("internal mTLS requires certificate, key, and client CA")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read internal client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("internal client CA contains no certificates")
	}
	return &http.Server{
		Addr:              envOr("MERCUTIO_INTERNAL_TLS_ADDR", ":9443"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
		},
	}, nil
}

func mustEvidence(path string) *evidence.Log {
	log, err := evidence.Open(path)
	if err != nil {
		panic(err)
	}
	return log
}

func reconcileCells(ctx context.Context, store *cell.Store, hub *transport.CellHub) {
	ticker := time.NewTicker(2 * time.Second)
	gcTicker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer gcTicker.Stop()
	if removed, err := store.GarbageCollect(ctx); err != nil {
		log.Printf("sandbox garbage collection: %v", err)
	} else if len(removed) > 0 {
		log.Printf("sandbox garbage collection removed %d orphan(s)", len(removed))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, id := range store.CellIDs() {
				if snapshot, changed, err := store.Reconcile(ctx, id); err == nil && changed {
					hub.BroadcastCell(snapshot)
				}
			}
		case <-gcTicker.C:
			if removed, err := store.GarbageCollect(ctx); err != nil {
				log.Printf("sandbox garbage collection: %v", err)
			} else if len(removed) > 0 {
				log.Printf("sandbox garbage collection removed %d orphan(s)", len(removed))
			}
		}
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
