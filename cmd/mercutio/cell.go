package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

type cellAPIClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func runCell(args []string, output, errors io.Writer, client *http.Client) int {
	if len(args) == 0 {
		cellUsage(errors)
		return 2
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	api := cellAPIClient{baseURL: strings.TrimRight(envOr("MERCUTIO_URL", "http://127.0.0.1:9011"), "/"), token: os.Getenv("MERCUTIO_OPERATOR_TOKEN"), client: client}
	switch args[0] {
	case "create":
		return runCellCreate(api, args[1:], output, errors)
	case "list":
		return runCellList(api, args[1:], output, errors)
	case "destroy":
		return runCellDestroy(api, args[1:], output, errors)
	case "logs":
		return runCellLogs(api, args[1:], output, errors)
	default:
		fmt.Fprintf(errors, "unknown cell command %q\n", args[0])
		cellUsage(errors)
		return 2
	}
}

func cellUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: mercutio cell {create|list|destroy|logs} [options]")
}

func addCellConnectionFlags(flags *flag.FlagSet, api *cellAPIClient) (*string, *string, *bool) {
	server := flags.String("server", api.baseURL, "Mercutio control-plane URL")
	token := flags.String("token", api.token, "operator bearer token")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	return server, token, jsonOutput
}

func configureCellClient(api *cellAPIClient, server, token string) error {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(server), "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("valid --server URL is required")
	}
	api.baseURL = parsed.String()
	api.token = strings.TrimSpace(token)
	return nil
}

func runCellCreate(api cellAPIClient, args []string, output, errors io.Writer) int {
	flags := flag.NewFlagSet("cell create", flag.ContinueOnError)
	flags.SetOutput(errors)
	server, token, jsonOutput := addCellConnectionFlags(flags, &api)
	repo := flags.String("repo", "", "repository URL")
	branch := flags.String("branch", "main", "repository branch or ref")
	profile := flags.String("profile", "standard", "sandbox profile: strict, standard, or open")
	if flags.Parse(args) != nil {
		return 2
	}
	if err := configureCellClient(&api, *server, *token); err != nil {
		fmt.Fprintln(errors, err)
		return 2
	}
	if strings.TrimSpace(*repo) == "" {
		fmt.Fprintln(errors, "--repo is required")
		return 2
	}
	var snapshot model.CellSnapshot
	if err := api.request(context.Background(), http.MethodPost, "/api/cells", map[string]string{"repoURL": *repo, "branch": *branch, "profile": *profile}, &snapshot); err != nil {
		fmt.Fprintln(errors, err)
		return 1
	}
	if *jsonOutput {
		return writeCellJSON(output, snapshot)
	}
	fmt.Fprintf(output, "%s\t%s\t%s\t%s\n", snapshot.ID, snapshot.Status, snapshot.SandboxProfile, snapshot.RepoURL)
	return 0
}

func runCellList(api cellAPIClient, args []string, output, errors io.Writer) int {
	flags := flag.NewFlagSet("cell list", flag.ContinueOnError)
	flags.SetOutput(errors)
	server, token, jsonOutput := addCellConnectionFlags(flags, &api)
	if flags.Parse(args) != nil {
		return 2
	}
	if err := configureCellClient(&api, *server, *token); err != nil {
		fmt.Fprintln(errors, err)
		return 2
	}
	var state model.State
	if err := api.request(context.Background(), http.MethodGet, "/api/state", nil, &state); err != nil {
		fmt.Fprintln(errors, err)
		return 1
	}
	sort.Slice(state.Cells, func(i, j int) bool { return state.Cells[i].ID < state.Cells[j].ID })
	if *jsonOutput {
		return writeCellJSON(output, state.Cells)
	}
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "CELL\tSTATUS\tSANDBOX\tPROFILE\tREPOSITORY")
	for _, snapshot := range state.Cells {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", snapshot.ID, snapshot.Status, snapshot.Sandbox.Phase, snapshot.SandboxProfile, snapshot.RepoURL)
	}
	_ = writer.Flush()
	return 0
}

func runCellDestroy(api cellAPIClient, args []string, output, errors io.Writer) int {
	flags := flag.NewFlagSet("cell destroy", flag.ContinueOnError)
	flags.SetOutput(errors)
	server, token, jsonOutput := addCellConnectionFlags(flags, &api)
	if flags.Parse(args) != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errors, "usage: mercutio cell destroy [options] <cell-id>")
		return 2
	}
	if err := configureCellClient(&api, *server, *token); err != nil {
		fmt.Fprintln(errors, err)
		return 2
	}
	var snapshot model.CellSnapshot
	path := "/api/cells/" + url.PathEscape(flags.Arg(0)) + "/destroy"
	if err := api.request(context.Background(), http.MethodPost, path, struct{}{}, &snapshot); err != nil {
		fmt.Fprintln(errors, err)
		return 1
	}
	if *jsonOutput {
		return writeCellJSON(output, snapshot)
	}
	fmt.Fprintf(output, "%s\t%s\n", snapshot.ID, snapshot.Status)
	return 0
}

func runCellLogs(api cellAPIClient, args []string, output, errors io.Writer) int {
	flags := flag.NewFlagSet("cell logs", flag.ContinueOnError)
	flags.SetOutput(errors)
	server, token, jsonOutput := addCellConnectionFlags(flags, &api)
	kind := flags.String("kind", "", "event kind filter")
	follow := flags.Bool("follow", false, "follow new durable events")
	interval := flags.Duration("interval", time.Second, "follow poll interval")
	if flags.Parse(args) != nil {
		return 2
	}
	if flags.NArg() != 1 || *interval <= 0 {
		fmt.Fprintln(errors, "usage: mercutio cell logs [options] <cell-id>")
		return 2
	}
	if err := configureCellClient(&api, *server, *token); err != nil {
		fmt.Fprintln(errors, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	path := "/api/cells/" + url.PathEscape(flags.Arg(0)) + "/events"
	if strings.TrimSpace(*kind) != "" {
		path += "?kind=" + url.QueryEscape(*kind)
	}
	seen := make(map[string]struct{})
	for {
		var events []model.Event
		if err := api.request(ctx, http.MethodGet, path, nil, &events); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			fmt.Fprintln(errors, err)
			return 1
		}
		for _, event := range events {
			key := eventKey(event)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if *jsonOutput {
				encoded, _ := json.Marshal(event)
				fmt.Fprintln(output, string(encoded))
			} else {
				fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\n", event.Timestamp.UTC().Format(time.RFC3339Nano), event.Kind, event.Source, event.Action, strings.ReplaceAll(event.Summary, "\n", " "))
			}
		}
		if !*follow {
			return 0
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}

func eventKey(event model.Event) string {
	if event.ID != "" {
		return event.ID
	}
	return fmt.Sprintf("%d|%s|%s|%s|%s", event.Timestamp.UnixNano(), event.Kind, event.Source, event.Action, event.Summary)
}

func (c cellAPIClient) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("Mercutio API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("Mercutio API returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(output); err != nil {
		return fmt.Errorf("decode Mercutio response: %w", err)
	}
	return nil
}

func writeCellJSON(output io.Writer, value any) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}
