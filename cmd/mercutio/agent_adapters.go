package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

type agentOutput struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

type agentTrace struct {
	Action  string `json:"action"`
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

type agentAdapter interface {
	SendPrompt(context.Context, string) error
	Pause() error
	Resume() error
	Output() <-chan agentOutput
	Traces() <-chan agentTrace
	Wait() error
}

type processAdapter struct {
	name    string
	command *exec.Cmd
	stdin   io.WriteCloser
	output  chan agentOutput
	traces  chan agentTrace
	wg      sync.WaitGroup
}

func newAgentAdapter(ctx context.Context, name string, command []string, worktree string) (agentAdapter, error) {
	name = strings.TrimSpace(name)
	if name != "stdio" && name != "claude-code" && name != "tiller" {
		return nil, fmt.Errorf("unsupported adapter %q (want stdio, claude-code, or tiller)", name)
	}
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return nil, fmt.Errorf("agent command is required after --")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = worktree
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	adapter := &processAdapter{name: name, command: cmd, stdin: stdin, output: make(chan agentOutput, 128), traces: make(chan agentTrace, 128)}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	adapter.wg.Add(2)
	go adapter.scan("stdout", stdout)
	go adapter.scan("stderr", stderr)
	return adapter, nil
}

func (a *processAdapter) SendPrompt(ctx context.Context, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("prompt is empty")
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(a.stdin, text+"\n")
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (a *processAdapter) Output() <-chan agentOutput { return a.output }
func (a *processAdapter) Traces() <-chan agentTrace  { return a.traces }

func (a *processAdapter) Pause() error {
	return a.command.Process.Signal(syscall.SIGSTOP)
}

func (a *processAdapter) Resume() error {
	return a.command.Process.Signal(syscall.SIGCONT)
}

func (a *processAdapter) Wait() error {
	err := a.command.Wait()
	_ = a.stdin.Close()
	a.wg.Wait()
	close(a.output)
	close(a.traces)
	return err
}

func (a *processAdapter) scan(stream string, reader io.Reader) {
	defer a.wg.Done()
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 1<<20)
	for scanner.Scan() {
		text := scanner.Text()
		a.output <- agentOutput{Stream: stream, Text: text}
		if trace, ok := adapterTrace(a.name, text); ok {
			a.traces <- trace
		}
	}
}

func adapterTrace(adapter, line string) (agentTrace, bool) {
	if adapter == "stdio" {
		return agentTrace{}, false
	}
	var payload map[string]any
	if json.Unmarshal([]byte(line), &payload) != nil {
		return agentTrace{}, false
	}
	action := firstString(payload, "action", "event", "type", "hook_event_name")
	summary := firstString(payload, "summary", "message", "status", "tool_name")
	if action == "" && summary == "" {
		return agentTrace{}, false
	}
	if action == "" {
		action = adapter + ".hook"
	}
	if summary == "" {
		summary = action
	}
	return agentTrace{Action: action, Summary: summary, Detail: adapter + " hook"}, true
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
