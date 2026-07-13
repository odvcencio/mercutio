package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"m31labs.dev/gosx"
	"m31labs.dev/gosx/server"
	"m31labs.dev/mercutio/internal/api"
	"m31labs.dev/mercutio/internal/auth"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/transport"
	"m31labs.dev/mercutio/internal/view"
)

func main() {
	port := flag.String("port", envOr("MERCUTIO_PORT", "9011"), "HTTP port")
	flag.Parse()

	store := cell.NewStore()
	cellHub := transport.NewCellHub(store)
	apiHandler := api.New(store, cellHub)
	authn := auth.FromEnv()

	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	publicDir, err := filepath.Abs(filepath.Join(root, "public"))
	if err != nil {
		log.Fatal(err)
	}

	app := server.New()
	app.SetPublicDir(publicDir)
	app.SetLayout(view.Layout)
	app.Page("GET /", func(_ *server.Context) gosx.Node {
		raw, _ := json.Marshal(store.State(cellHub.ClientCount()))
		return view.Page(string(raw))
	})

	// API mutations and the collaboration hub share the same operator boundary.
	app.Mount("GET /api/state", authn.Require(http.HandlerFunc(apiHandler.State)))
	app.Mount("GET /api/session", http.HandlerFunc(authn.Session))
	app.Mount("POST /api/cells", authn.Require(http.HandlerFunc(apiHandler.CreateCell)))
	app.Mount("GET /api/cells/{cellID}", authn.Require(http.HandlerFunc(apiHandler.Cell)))
	app.Mount("GET /api/cells/{cellID}/events", authn.Require(http.HandlerFunc(apiHandler.Events)))
	app.Mount("POST /api/cells/{cellID}/edit", authn.Require(http.HandlerFunc(apiHandler.Edit)))
	app.Mount("POST /api/cells/{cellID}/prompt", authn.Require(http.HandlerFunc(apiHandler.Prompt)))
	app.Mount("POST /api/cells/{cellID}/destroy", authn.Require(http.HandlerFunc(apiHandler.Destroy)))
	app.Mount("POST /api/cells/{cellID}/reviews/{reviewID}/approve", authn.Require(http.HandlerFunc(apiHandler.Approve)))
	app.Mount("/gosx/hub/cells", authn.Require(cellHub))
	app.Mount("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok","service":"mercutio"}`))
	}))

	addr := ":" + *port
	log.Printf("mercutio listening at http://127.0.0.1%s", addr)
	if err := app.ListenAndServe(addr); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
