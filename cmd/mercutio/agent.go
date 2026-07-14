package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func runAgent(args []string, _ io.Reader, _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	adapterName := flags.String("adapter", envOr("MERCUTIO_AGENT_ADAPTER", "stdio"), "stdio, claude-code, or tiller")
	socket := flags.String("socket", envOr("MERCUTIO_ATTACH_SOCKET", "/run/mercutio/attach.sock"), "attach sidecar Unix socket")
	worktree := flags.String("worktree", envOr("MERCUTIO_WORKTREE", "/workspace/repo"), "cell worktree")
	connectTimeout := flags.Duration("connect-timeout", 30*time.Second, "attach socket deadline")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	command := flags.Args()
	if len(command) == 0 {
		command = agentCommandFromEnv()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection, err := dialAttach(ctx, *socket, *connectTimeout)
	if err != nil {
		fmt.Fprintln(stderr, "connect attach:", err)
		return 1
	}
	defer connection.Close()
	adapter, err := newAgentAdapter(ctx, *adapterName, command, *worktree)
	if err != nil {
		fmt.Fprintln(stderr, "start agent:", err)
		return 2
	}
	var writeMu sync.Mutex
	encoder := json.NewEncoder(connection)
	emit := func(value any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = encoder.Encode(value)
	}
	emit(map[string]any{"event": "status", "status": "attached", "adapter": *adapterName})
	wait := make(chan error, 1)
	go func() { wait <- adapter.Wait() }()
	commands := make(chan agentCommand)
	go readAgentCommands(connection, commands)
	for {
		select {
		case command, ok := <-commands:
			if !ok {
				cancel()
				return 1
			}
			var commandErr error
			switch command.Event {
			case "prompt":
				commandErr = adapter.SendPrompt(ctx, command.Prompt)
			case "control:pause":
				commandErr = adapter.Pause()
				if commandErr == nil {
					emit(map[string]any{"event": "status", "status": "paused"})
				}
			case "control:resume":
				commandErr = adapter.Resume()
				if commandErr == nil {
					emit(map[string]any{"event": "status", "status": "working"})
				}
			}
			if commandErr != nil {
				emit(map[string]any{"event": "trace", "action": "agent.command.failed", "summary": "Agent command failed"})
			}
		case output, ok := <-adapter.Output():
			if ok {
				emit(map[string]any{"event": "output", "stream": output.Stream, "text": output.Text})
			}
		case trace, ok := <-adapter.Traces():
			if ok {
				emit(map[string]any{"event": "trace", "action": trace.Action, "summary": trace.Summary, "detail": trace.Detail})
			}
		case processErr := <-wait:
			for output := range adapter.Output() {
				emit(map[string]any{"event": "output", "stream": output.Stream, "text": output.Text})
			}
			for trace := range adapter.Traces() {
				emit(map[string]any{"event": "trace", "action": trace.Action, "summary": trace.Summary, "detail": trace.Detail})
			}
			emit(map[string]any{"event": "trace", "action": "agent.exited", "summary": "Agent process exited", "detail": processError(processErr)})
			emit(map[string]any{"event": "status", "status": "idle"})
			return 0
		}
	}
}

type agentCommand struct {
	Event  string `json:"event"`
	Prompt string `json:"prompt"`
}

func readAgentCommands(reader io.Reader, commands chan<- agentCommand) {
	defer close(commands)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var message agentCommand
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			continue
		}
		if message.Event == "prompt" && strings.TrimSpace(message.Prompt) != "" || message.Event == "control:pause" || message.Event == "control:resume" {
			commands <- message
		}
	}
}

func dialAttach(ctx context.Context, socket string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Timeout: time.Second}
	for {
		connection, err := dialer.DialContext(ctx, "unix", socket)
		if err == nil {
			return connection, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func processError(err error) string {
	if err == nil {
		return "exit=0"
	}
	return err.Error()
}

func agentCommandFromEnv() []string {
	return strings.Fields(os.Getenv("MERCUTIO_AGENT_COMMAND"))
}
