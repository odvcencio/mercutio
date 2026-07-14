package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

func runArmgate(args []string) {
	flags := flag.NewFlagSet("armgate", flag.ExitOnError)
	cellID := flags.String("cell", os.Getenv("MERCUTIO_CELL_ID"), "cell ID")
	token := flags.String("token", os.Getenv("MERCUTIO_ARM_TOKEN"), "cell arm capability")
	control := flags.String("control", envOr("MERCUTIO_CONTROL_URL", "http://mercutio:9011"), "control-plane base URL")
	output := flags.String("output", "/run/mercutio/armed", "verified arm receipt path")
	timeout := flags.Duration("timeout", 2*time.Minute, "maximum time to wait for kernel arm")
	flags.Parse(args)
	if strings.TrimSpace(*cellID) == "" || strings.TrimSpace(*token) == "" {
		fmt.Fprintln(os.Stderr, "armgate requires --cell and --token")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := waitForArm(ctx, http.DefaultClient, *control, *cellID, *token, 250*time.Millisecond)
	if err != nil {
		fmt.Fprintln(os.Stderr, "armgate:", err)
		os.Exit(1)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "armgate:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "armgate:", err)
		os.Exit(1)
	}
}

func waitForArm(ctx context.Context, client *http.Client, control, cellID, token string, interval time.Duration) (model.Sandbox, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	endpoint := strings.TrimRight(control, "/") + "/api/internal/cells/" + cellID + "/arm-state"
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return model.Sandbox{}, err
		}
		request.Header.Set("X-Mercutio-Arm-Token", token)
		response, err := client.Do(request)
		if err == nil {
			var state model.Sandbox
			decodeErr := json.NewDecoder(response.Body).Decode(&state)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && state.Armed {
				return state, nil
			}
			if response.StatusCode == http.StatusUnauthorized {
				return model.Sandbox{}, fmt.Errorf("arm-state capability rejected")
			}
		}
		select {
		case <-ctx.Done():
			return model.Sandbox{}, fmt.Errorf("arm timeout: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
