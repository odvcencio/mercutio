package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func TestWaitForArmBlocksUntilVerifiedReceipt(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mercutio-Arm-Token") != "cell-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		state := model.Sandbox{Phase: model.SandboxRunning}
		if calls.Add(1) >= 2 {
			state.Armed = true
			state.ManifestDigest = "sha256:manifest"
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := waitForArm(ctx, server.Client(), server.URL, "cell-1", "cell-token", time.Millisecond)
	if err != nil {
		t.Fatalf("waitForArm: %v", err)
	}
	if !state.Armed || calls.Load() < 2 {
		t.Fatalf("state=%+v calls=%d", state, calls.Load())
	}
}

func TestWaitForArmRejectsBadCapability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := waitForArm(ctx, server.Client(), server.URL, "cell-1", "bad", time.Millisecond); err == nil {
		t.Fatal("expected capability rejection")
	}
}
