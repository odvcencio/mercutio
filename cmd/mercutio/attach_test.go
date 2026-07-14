package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestExecuteTier2ProcessInjectsOnlyChildAndRedactsOutput(t *testing.T) {
	const secret = "tier2-child-only-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&payload) != nil || payload["grant"] != "single-use-grant" {
			http.Error(w, "invalid", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": secret, "receipt": map[string]string{"id": "receipt-1"}})
	}))
	defer server.Close()

	t.Setenv("MERCUTIO_TEST_TIER2", "parent-value")
	result := executeTier2Process(server.URL, t.TempDir(), tier2Grant{
		CellID: "cell-1", RequestID: "request-1", Grant: "single-use-grant",
		EnvName: "MERCUTIO_TEST_TIER2", Command: []string{"sh", "-c", `printf '%s' "$MERCUTIO_TEST_TIER2"`}, WorkingDir: ".", ExpiresAt: time.Now().Add(time.Minute),
	})
	if result["exitCode"] != 0 || result["receipt"] != "receipt-1" || result["stdout"] != "<redacted>" {
		t.Fatalf("result = %#v", result)
	}
	if os.Getenv("MERCUTIO_TEST_TIER2") != "parent-value" {
		t.Fatal("Tier-2 credential mutated the attach process environment")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("Tier-2 credential leaked into process result")
	}
}

func TestExecuteCellCommitRunsBuckleyInWorktreeAndReturnsRevision(t *testing.T) {
	worktree := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		command := exec.Command(args[0], args[1:]...)
		command.Dir = worktree
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, output)
		}
	}
	run("git", "init", "-q")
	if err := os.WriteFile(filepath.Join(worktree, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBuckley := filepath.Join(t.TempDir(), "buckley")
	script := "#!/bin/sh\nset -eu\ngit add -A\ngit -c user.name=Mercutio -c user.email=mercutio@example.invalid commit -q -m 'approved entity review'\n"
	if err := os.WriteFile(fakeBuckley, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUCKLEY_BINARY", fakeBuckley)
	receipt, err := executeCellCommit(worktree, attachCommitRequest{
		RequestID: "review-1",
		Review:    model.Review{Files: []string{"main.go"}},
	})
	if err != nil || !strings.HasPrefix(receipt, "commit:") || len(strings.TrimPrefix(receipt, "commit:")) != 40 {
		t.Fatalf("receipt=%q err=%v", receipt, err)
	}
}

func TestConfinedWorkdirRejectsEscape(t *testing.T) {
	if _, err := confinedWorkdir(t.TempDir(), "../escape"); err == nil {
		t.Fatal("worktree escape accepted")
	}
}

func TestScrubAttachTokenArgsRemovesCapabilityFromRestartArgv(t *testing.T) {
	got := scrubAttachTokenArgs([]string{"mercutio", "attach", "--cell", "cell-1", "--token", "secret-one", "--token=secret-two", "--name", "agent"})
	want := []string{"mercutio", "attach", "--cell", "cell-1", "--name", "agent"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%q want=%q", got, want)
	}
}
