package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"m31labs.dev/gosx/hub"
	"m31labs.dev/mercutio/internal/model"
)

// attach is a small JSONL bridge for agent runtimes. Prompts arrive on
// stdout as JSON objects; stdin accepts {"event":"trace|edit|status",...}
// objects or treats plain lines as intent trace summaries.
func runAttach(args []string) {
	flags := flag.NewFlagSet("attach", flag.ExitOnError)
	cellID := flags.String("cell", os.Getenv("MERCUTIO_CELL_ID"), "cell ID")
	token := flags.String("token", os.Getenv("MERCUTIO_ATTACH_TOKEN"), "cell attach token")
	name := flags.String("name", envOr("MERCUTIO_AGENT_NAME", "coding-agent"), "agent display name")
	hubURL := flags.String("hub", envOr("MERCUTIO_HUB_URL", "http://127.0.0.1:9011/gosx/hub/agent"), "Mercutio agent hub URL")
	socketPath := flags.String("socket", os.Getenv("MERCUTIO_ATTACH_SOCKET"), "optional Unix socket exposed only to the agent container")
	controlURL := flags.String("control", os.Getenv("MERCUTIO_CONTROL_URL"), "control-plane HTTP base URL")
	worktree := flags.String("worktree", envOr("MERCUTIO_WORKTREE", "/workspace"), "shared cell worktree")
	flags.Parse(args)
	if strings.TrimSpace(*cellID) == "" || strings.TrimSpace(*token) == "" {
		fmt.Fprintln(os.Stderr, "attach requires --cell and --token")
		os.Exit(2)
	}
	parsed, err := url.Parse(*hubURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if strings.TrimSpace(*controlURL) == "" {
		controlScheme := parsed.Scheme
		if controlScheme == "ws" {
			controlScheme = "http"
		} else if controlScheme == "wss" {
			controlScheme = "https"
		}
		*controlURL = (&url.URL{Scheme: controlScheme, Host: parsed.Host}).String()
	}
	if parsed.Scheme == "http" {
		parsed.Scheme = "ws"
	} else if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	}
	query := parsed.Query()
	query.Set("cellID", *cellID)
	parsed.RawQuery = query.Encode()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+*token)
	connection, _, err := websocket.DefaultDialer.Dial(parsed.String(), headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer connection.Close()
	input, output, closeIO, err := attachIO(*socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach transport:", err)
		os.Exit(1)
	}
	defer closeIO()

	var writeMu sync.Mutex
	write := func(message hub.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return connection.WriteJSON(message)
	}
	reconciler, err := newDiskReconciler(*worktree, func(path, base, content string, deleted bool) {
		event := "agent:disk-edit"
		if deleted {
			event = "agent:disk-delete"
		}
		_ = write(hub.Message{Event: event, Data: mustJSON(map[string]string{"path": path, "base": base, "content": content})})
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "worktree reconciliation:", err)
		os.Exit(1)
	}
	defer reconciler.Close()
	if err := write(hub.Message{Event: "agent:attach", Data: mustJSON(map[string]string{"name": *name})}); err != nil {
		fmt.Fprintln(os.Stderr, "attach:", err)
		os.Exit(1)
	}

	done := make(chan struct{})
	stopLiveness := make(chan struct{})
	defer close(stopLiveness)
	go func() {
		heartbeat := time.NewTicker(15 * time.Second)
		refresh := time.NewTicker(10 * time.Minute)
		defer heartbeat.Stop()
		defer refresh.Stop()
		for {
			select {
			case <-heartbeat.C:
				_ = write(hub.Message{Event: "agent:heartbeat", Data: mustJSON(map[string]string{"status": "attached"})})
			case <-refresh.C:
				_ = write(hub.Message{Event: "agent:refresh", Data: mustJSON(map[string]string{})})
			case <-stopLiveness:
				return
			case <-done:
				return
			}
		}
	}()
	go func() {
		defer close(done)
		encoder := json.NewEncoder(output)
		var outputMu sync.Mutex
		emit := func(value any) {
			outputMu.Lock()
			defer outputMu.Unlock()
			_ = encoder.Encode(value)
		}
		for {
			var message hub.Message
			if err := connection.ReadJSON(&message); err != nil {
				if !strings.Contains(err.Error(), "close") {
					fmt.Fprintln(os.Stderr, "hub:", err)
				}
				return
			}
			switch message.Event {
			case "agent:prompt":
				var payload map[string]any
				if json.Unmarshal(message.Data, &payload) == nil {
					emit(map[string]any{"event": "prompt", "cellID": payload["cellID"], "prompt": payload["prompt"]})
				}
			case "agent:commit":
				var payload attachCommitRequest
				if json.Unmarshal(message.Data, &payload) != nil || payload.RequestID == "" {
					continue
				}
				go func() {
					receipt, commitErr := executeCellCommit(*worktree, payload)
					result := map[string]string{"requestID": payload.RequestID, "receipt": receipt}
					if commitErr != nil {
						result["error"] = "in-cell Buckley commit failed"
					}
					_ = write(hub.Message{Event: "agent:commit-result", Data: mustJSON(result)})
				}()
			case "agent:error":
				fmt.Fprintln(os.Stderr, string(message.Data))
			case "agent:capability":
				var payload struct {
					Token string `json:"token"`
				}
				if json.Unmarshal(message.Data, &payload) == nil && payload.Token != "" {
					if err := restartAttachWithToken(payload.Token); err != nil {
						fmt.Fprintln(os.Stderr, "capability rotation:", err)
					}
				}
			case "agent:proxy-route":
				var payload map[string]any
				if json.Unmarshal(message.Data, &payload) == nil {
					payload["event"] = "proxy-route"
					emit(payload)
				}
			case "agent:tier2-grant":
				var grant tier2Grant
				if json.Unmarshal(message.Data, &grant) != nil {
					continue
				}
				go func() {
					result := executeTier2Process(*controlURL, *worktree, grant)
					result["event"] = "tier2-result"
					emit(result)
				}()
			case "cell:update":
				var snapshot model.CellSnapshot
				if json.Unmarshal(message.Data, &snapshot) == nil {
					reconciler.ApplySnapshot(snapshot.Files)
				}
			case "__welcome", "agent:attached":
				// Lifecycle snapshots are available to clients that need them; the
				// bridge keeps stdout reserved for prompt and command traffic.
			}
		}
	}()

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var input map[string]any
		if json.Unmarshal([]byte(line), &input) != nil {
			input = map[string]any{"event": "trace", "summary": line}
		}
		event := fmt.Sprint(input["event"])
		if event == "" {
			event = "trace"
		}
		wireEvent := map[string]any{}
		for key, value := range input {
			if key != "event" {
				wireEvent[key] = value
			}
		}
		if event == "prompt" {
			continue
		}
		if err := write(hub.Message{Event: "agent:" + event, Data: mustJSON(wireEvent)}); err != nil {
			fmt.Fprintln(os.Stderr, "hub:", err)
			break
		}
	}
	<-done
}

func restartAttachWithToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("empty refreshed capability")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := scrubAttachTokenArgs(os.Args)
	environment := childEnvironment(os.Environ(), "MERCUTIO_ATTACH_TOKEN", token)
	return syscall.Exec(executable, args, environment)
}

func scrubAttachTokenArgs(args []string) []string {
	clean := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		if args[index] == "--token" || args[index] == "-token" {
			index++
			continue
		}
		if strings.HasPrefix(args[index], "--token=") || strings.HasPrefix(args[index], "-token=") {
			continue
		}
		clean = append(clean, args[index])
	}
	return clean
}

type attachCommitRequest struct {
	RequestID string       `json:"requestID"`
	CellID    string       `json:"cellID"`
	Branch    string       `json:"branch"`
	Review    model.Review `json:"review"`
}

func executeCellCommit(worktree string, request attachCommitRequest) (string, error) {
	if request.RequestID == "" || len(request.Review.Files) == 0 {
		return "", fmt.Errorf("commit request is incomplete")
	}
	dir, err := confinedWorkdir(worktree, ".")
	if err != nil {
		return "", err
	}
	args := []string{"commit", "-yes", "-min", "-push=false", "-exclusive"}
	for _, path := range request.Review.Files {
		clean := filepath.Clean(path)
		if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("invalid commit path")
		}
		args = append(args, "-paths", clean)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, envOr("BUCKLEY_BINARY", "buckley"), args...)
	command.Dir = dir
	if output, runErr := command.CombinedOutput(); runErr != nil {
		_ = output // Command output may contain repository secrets; never relay it.
		return "", runErr
	}
	revision := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	revision.Dir = dir
	output, err := revision.Output()
	if err != nil {
		return "", err
	}
	hash := strings.TrimSpace(string(output))
	if hash == "" {
		return "", fmt.Errorf("commit produced no revision")
	}
	return "commit:" + hash, nil
}

type tier2Grant struct {
	CellID     string    `json:"cellID"`
	RequestID  string    `json:"requestID"`
	Grant      string    `json:"grant"`
	EnvName    string    `json:"envName"`
	Command    []string  `json:"command"`
	WorkingDir string    `json:"workingDir"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func executeTier2Process(controlURL, worktree string, grant tier2Grant) map[string]any {
	result := map[string]any{"requestID": grant.RequestID, "exitCode": -1}
	if grant.CellID == "" || grant.RequestID == "" || grant.Grant == "" || !validAttachEnvName(grant.EnvName) || len(grant.Command) == 0 || strings.TrimSpace(grant.Command[0]) == "" {
		result["error"] = "invalid Tier-2 execution grant"
		return result
	}
	dir, err := confinedWorkdir(worktree, grant.WorkingDir)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	deadline := grant.ExpiresAt
	if deadline.IsZero() || deadline.After(time.Now().Add(20*time.Minute)) {
		deadline = time.Now().Add(20 * time.Minute)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	payload, _ := json.Marshal(map[string]string{"cellID": grant.CellID, "requestID": grant.RequestID, "grant": grant.Grant})
	endpoint := strings.TrimRight(controlURL, "/") + "/api/internal/tier2/consume"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		result["error"] = "prepare credential consumption: " + err.Error()
		return result
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		result["error"] = "consume credential grant: " + err.Error()
		return result
	}
	defer response.Body.Close()
	var consumed struct {
		Value   string `json:"value"`
		Receipt struct {
			ID string `json:"id"`
		} `json:"receipt"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK || decoder.Decode(&consumed) != nil || consumed.Value == "" {
		result["error"] = "credential grant was rejected"
		return result
	}

	command := exec.CommandContext(ctx, grant.Command[0], grant.Command[1:]...)
	command.Dir = dir
	command.Env = childEnvironment(os.Environ(), grant.EnvName, consumed.Value)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	secret := consumed.Value
	consumed.Value = ""
	result["receipt"] = consumed.Receipt.ID
	result["stdout"] = strings.ReplaceAll(stdout.String(), secret, "<redacted>")
	result["stderr"] = strings.ReplaceAll(stderr.String(), secret, "<redacted>")
	result["exitCode"] = processExitCode(err)
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func childEnvironment(parent []string, name, value string) []string {
	prefix := name + "="
	environment := make([]string, 0, len(parent)+1)
	for _, item := range parent {
		if !strings.HasPrefix(item, prefix) {
			environment = append(environment, item)
		}
	}
	return append(environment, prefix+value)
}

func confinedWorkdir(root, relative string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve worktree: %w", err)
	}
	relative = filepath.Clean(strings.TrimSpace(relative))
	if relative == "" {
		relative = "."
	}
	if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("Tier-2 working directory escapes the worktree")
	}
	return filepath.Join(root, relative), nil
}

func validAttachEnvName(value string) bool {
	if value == "" || !(value[0] == '_' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for i := 1; i < len(value); i++ {
		char := value[i]
		if char != '_' && !(char >= 'A' && char <= 'Z') && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func processExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return -1
}

func attachIO(socketPath string) (io.Reader, io.Writer, func(), error) {
	if strings.TrimSpace(socketPath) == "" {
		return os.Stdin, os.Stdout, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, nil, func() {}, err
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, nil, func() {}, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, func() {}, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		return nil, nil, func() {}, err
	}
	connection, err := listener.Accept()
	if err != nil {
		listener.Close()
		return nil, nil, func() {}, err
	}
	closeAll := func() {
		connection.Close()
		listener.Close()
		_ = os.Remove(socketPath)
	}
	return connection, connection, closeAll, nil
}

func mustJSON(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
