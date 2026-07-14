package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestCellCLIExercisesLifecycleAPIWithBearerAuth(t *testing.T) {
	t.Setenv("MERCUTIO_OPERATOR_TOKEN", "operator-token")
	created := model.CellSnapshot{Cell: model.Cell{ID: "cell-001", RepoURL: "https://example.test/repo", SandboxProfile: "strict", Status: model.CellReady, Sandbox: model.Sandbox{Phase: model.SandboxRunning}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /api/cells":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["repoURL"] != created.RepoURL || input["profile"] != "strict" {
				t.Fatalf("create input=%v", input)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		case "GET /api/state":
			_ = json.NewEncoder(w).Encode(model.State{Cells: []model.CellSnapshot{created}})
		case "POST /api/cells/cell-001/destroy":
			stopped := created
			stopped.Status = model.CellStopped
			_ = json.NewEncoder(w).Encode(stopped)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("MERCUTIO_URL", server.URL)

	for _, test := range []struct {
		args []string
		want string
	}{{[]string{"create", "--repo", created.RepoURL, "--profile", "strict"}, "cell-001\tready\tstrict"}, {[]string{"list"}, "CELL"}, {[]string{"destroy", "cell-001"}, "cell-001\tstopped"}} {
		var output, errors bytes.Buffer
		if code := runCell(test.args, &output, &errors, server.Client()); code != 0 || !strings.Contains(output.String(), test.want) {
			t.Fatalf("args=%v code=%d output=%q errors=%q", test.args, code, output.String(), errors.String())
		}
	}
}

func TestCellLogsFiltersAndPrintsDurableEvents(t *testing.T) {
	timestamp := time.Date(2026, 7, 13, 1, 2, 3, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cells/cell-a/events" || r.URL.Query().Get("kind") != "kernel" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]model.Event{{ID: "event-1", Timestamp: timestamp, Kind: model.EventKernel, Source: "horizon", Action: "kernel.exec", Summary: "observed exec"}})
	}))
	defer server.Close()
	var output, errors bytes.Buffer
	code := runCell([]string{"logs", "--server", server.URL, "--kind", "kernel", "cell-a"}, &output, &errors, server.Client())
	if code != 0 || !strings.Contains(output.String(), "kernel.exec\tobserved exec") {
		t.Fatalf("code=%d output=%q errors=%q", code, output.String(), errors.String())
	}
}

func TestCellCLIRejectsMissingRepoWithoutCallingAPI(t *testing.T) {
	var output, errors bytes.Buffer
	if code := runCell([]string{"create"}, &output, &errors, nil); code != 2 || !strings.Contains(errors.String(), "--repo is required") {
		t.Fatalf("code=%d errors=%q", code, errors.String())
	}
}
