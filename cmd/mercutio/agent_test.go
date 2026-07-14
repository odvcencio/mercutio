package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentAdapterParity(t *testing.T) {
	for _, name := range []string{"stdio", "claude-code", "tiller"} {
		t.Run(name, func(t *testing.T) {
			worktree := t.TempDir()
			result := filepath.Join(worktree, "result.txt")
			adapter, err := newAgentAdapter(context.Background(), name, []string{"sh", "-c", `IFS= read -r line; printf '%s' "$line" > result.txt`}, worktree)
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.SendPrompt(context.Background(), "same steering prompt"); err != nil {
				t.Fatal(err)
			}
			if err := adapter.Wait(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(result)
			if err != nil || string(body) != "same steering prompt" {
				t.Fatalf("result=%q err=%v", body, err)
			}
		})
	}
}

func TestHookAdaptersEmitAdditiveTrace(t *testing.T) {
	line := `{"hook_event_name":"PostToolUse","tool_name":"Write"}`
	for _, name := range []string{"claude-code", "tiller"} {
		trace, ok := adapterTrace(name, line)
		if !ok || trace.Action != "PostToolUse" || trace.Summary != "Write" {
			t.Fatalf("%s trace=%+v ok=%v", name, trace, ok)
		}
	}
	if _, ok := adapterTrace("stdio", line); ok {
		t.Fatal("stdio treated hook output as required protocol")
	}
}

func TestRunAgentRoutesPromptOutputAndIdleExit(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "attach.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan int, 1)
	go func() {
		done <- runAgent([]string{"--adapter", "stdio", "--socket", socket, "--worktree", dir, "--", "sh", "-c", `IFS= read -r line; printf 'ack:%s\n' "$line"`}, nil, nil, &strings.Builder{})
	}()
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	decoder := json.NewDecoder(connection)
	var attached map[string]any
	if err := decoder.Decode(&attached); err != nil || attached["status"] != "attached" {
		t.Fatalf("attached=%v err=%v", attached, err)
	}
	if err := json.NewEncoder(connection).Encode(map[string]string{"event": "prompt", "prompt": "tighten policy"}); err != nil {
		t.Fatal(err)
	}
	connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	seenOutput, seenExit, seenIdle := false, false, false
	for !seenIdle {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		seenOutput = seenOutput || event["event"] == "output" && event["text"] == "ack:tighten policy"
		seenExit = seenExit || event["event"] == "trace" && event["action"] == "agent.exited"
		seenIdle = event["event"] == "status" && event["status"] == "idle"
	}
	if !seenOutput || !seenExit {
		t.Fatalf("output=%v exit=%v", seenOutput, seenExit)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code=%d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent supervisor did not exit")
	}
}
