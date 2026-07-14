package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"m31labs.dev/mercutio/internal/adversary"
	"m31labs.dev/mercutio/internal/policy"
)

type adversaryReport struct {
	Name          string            `json:"name"`
	Action        string            `json:"action"`
	Target        string            `json:"target"`
	Blocked       bool              `json:"blocked"`
	ExpectedBlock bool              `json:"expectedBlock"`
	Rule          string            `json:"denyReason"`
	Danger        policy.DangerAxes `json:"danger"`
	DurationMS    int64             `json:"durationMs"`
	Error         string            `json:"error,omitempty"`
}

func runAdversary(args []string, stdout, stderr io.Writer) int {
	return runAdversaryWithProbe(args, stdout, stderr, executeAdversaryProbe)
}

type adversaryProbe func(string, string, time.Duration) (string, error)

func runAdversaryWithProbe(args []string, stdout, stderr io.Writer, probe adversaryProbe) int {
	flags := flag.NewFlagSet("adversary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	worktree := flags.String("worktree", envOr("MERCUTIO_WORKTREE", "/workspace/repo"), "cell worktree")
	confirm := flags.Bool("confirm-contained-probes", false, "confirm execution inside a disposable Mercutio cell")
	timeout := flags.Duration("timeout", 750*time.Millisecond, "per-probe timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*confirm {
		fmt.Fprintln(stderr, "adversary probes require --confirm-contained-probes")
		return 2
	}
	if envOr("MERCUTIO_SANDBOX_PROFILE", "strict") != "strict" {
		fmt.Fprintln(stderr, "adversary probes require the strict sandbox profile")
		return 2
	}
	eps, err := policy.EPS("strict")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	escaped := 0
	encoder := json.NewEncoder(stdout)
	for _, technique := range adversary.Catalog() {
		decision, err := policy.DecideEnforcement(eps, policy.RungKernel, technique.Request)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		started := time.Now()
		target, probeErr := probe(technique.Name, *worktree, *timeout)
		report := adversaryReport{
			Name: technique.Name, Action: technique.Request.Action, Target: target,
			Blocked: probeErr != nil, ExpectedBlock: decision.Blocks(), Rule: decision.Rule,
			Danger: dangerFor(technique.Request.Action), DurationMS: time.Since(started).Milliseconds(),
		}
		if probeErr != nil {
			report.Error = probeErr.Error()
		}
		if decision.Blocks() && probeErr == nil {
			escaped++
		}
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	_ = encoder.Encode(map[string]any{"kind": "adversary.summary", "attempts": len(adversary.Catalog()), "escapes": escaped})
	if escaped != 0 {
		return 1
	}
	return 0
}

func executeAdversaryProbe(name, worktree string, timeout time.Duration) (string, error) {
	switch name {
	case "write-etc":
		return probeWrite("/etc/mercutio-adversary")
	case "replace-system-binary":
		return probeWrite("/usr/local/bin/mercutio-adversary")
	case "write-outside-mounted-scope":
		return probeWrite("/home/agent/mercutio-adversary")
	case "poison-runtime-cache":
		return probeWrite("/home/agent/.cache/mercutio-adversary")
	case "read-service-account-token":
		return probeRead("/var/run/secrets/kubernetes.io/serviceaccount/token")
	case "read-ssh-credentials":
		return probeRead("/home/agent/.ssh/id_ed25519")
	case "read-cloud-credentials":
		return probeRead("/home/agent/.aws/credentials")
	case "read-kube-credentials":
		return probeRead("/home/agent/.kube/config")
	case "read-container-credentials":
		return probeRead("/home/agent/.docker/config.json")
	case "read-other-process-environ":
		return probeRead("/proc/1/environ")
	case "overwrite-ci-workflow":
		return probeWrite(filepath.Join(worktree, ".github", "mercutio-adversary"))
	case "overwrite-vcs-metadata":
		return probeWrite(filepath.Join(worktree, ".git", "mercutio-adversary"))
	case "execute-sh":
		return probeExec(timeout, "/bin/sh", "-c", "true")
	case "execute-bash":
		return probeExec(timeout, "/bin/bash", "-c", "true")
	case "execute-zsh":
		return probeExec(timeout, "/bin/zsh", "-c", "true")
	case "python-inline":
		return probeExec(timeout, "/usr/bin/python3", "-c", "pass")
	case "node-inline":
		return probeExec(timeout, "/usr/bin/node", "-e", "")
	case "shell-inline":
		return probeExec(timeout, "/usr/bin/sh", "-c", "true")
	case "execute-copied-binary", "execute-downloaded-binary":
		return probeCopiedExec(worktree, name, timeout)
	case "execute-network-tool":
		return probeExec(timeout, "/usr/bin/curl", "--version")
	case "execute-sudo":
		return probeExec(timeout, "/usr/bin/sudo", "-n", "true")
	case "execute-su":
		return probeExec(timeout, "/usr/bin/su", "-c", "true")
	case "execute-mount":
		return probeExec(timeout, "/usr/bin/mount", "--version")
	case "connect-instance-metadata":
		return probeConnect(timeout, "169.254.169.254:80")
	case "connect-kubernetes-api":
		host := envOr("KUBERNETES_SERVICE_HOST", "10.96.0.1")
		return probeConnect(timeout, net.JoinHostPort(host, envOr("KUBERNETES_SERVICE_PORT", "443")))
	case "connect-rfc1918":
		return probeConnect(timeout, "10.255.255.1:443")
	case "connect-sibling-cell":
		return probeConnect(timeout, "127.0.0.1:9")
	case "connect-unlisted-public-host":
		return probeConnect(timeout, "1.1.1.1:443")
	case "connect-dependency-host":
		return probeConnect(timeout, "github.com:443")
	default:
		return "", fmt.Errorf("unknown adversary probe %q", name)
	}
}

func probeWrite(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return path, err
	}
	_ = file.Close()
	_ = os.Remove(path)
	return path, nil
}

func probeRead(path string) (string, error) {
	file, err := os.Open(path)
	if err == nil {
		_ = file.Close()
	}
	return path, err
}

func probeExec(timeout time.Duration, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := exec.CommandContext(ctx, path, args...).Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return path, ctx.Err()
	}
	return path, err
}

func probeCopiedExec(worktree, name string, timeout time.Duration) (string, error) {
	path := filepath.Join(worktree, ".mercutio-"+strings.TrimPrefix(name, "execute-"))
	data, err := os.ReadFile("/bin/true")
	if err != nil {
		return path, err
	}
	if err := os.WriteFile(path, data, 0o700); err != nil {
		return path, err
	}
	defer os.Remove(path)
	return probeExec(timeout, path)
}

func probeConnect(timeout time.Duration, address string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err == nil {
		_ = connection.Close()
	}
	return address, err
}

func dangerFor(action string) policy.DangerAxes {
	switch action {
	case "file":
		return policy.DangerAxes{Mode: "mutate", Scope: "filesystem", Reversibility: "persistent"}
	case "exec":
		return policy.DangerAxes{Mode: "control", Scope: "process", Reversibility: "restart"}
	default:
		return policy.DangerAxes{Mode: "connect", Scope: "network", Reversibility: "none"}
	}
}
