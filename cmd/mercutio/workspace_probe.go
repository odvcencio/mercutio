package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
)

func runWorkspaceProbe(args []string) {
	flags := flag.NewFlagSet("workspace-probe", flag.ExitOnError)
	cellID := flags.String("cell", os.Getenv("MERCUTIO_CELL_ID"), "cell ID")
	control := flags.String("control", os.Getenv("MERCUTIO_CONTROL_URL"), "control-plane URL")
	workspace := flags.String("workspace", "/workspace/repo", "worktree path")
	flags.Parse(args)
	info, err := os.Stat(*workspace)
	if err != nil {
		fatalProbe(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 {
		fatalProbe(fmt.Errorf("workspace device unavailable"))
	}
	body, _ := json.Marshal(map[string]uint64{"device": uint64(stat.Dev)})
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(*control, "/")+"/api/internal/cells/"+*cellID+"/workspace-device", bytes.NewReader(body))
	if err != nil {
		fatalProbe(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Mercutio-Arm-Token", os.Getenv("MERCUTIO_ARM_TOKEN"))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		fatalProbe(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		fatalProbe(fmt.Errorf("workspace report returned %s", response.Status))
	}
}

func fatalProbe(err error) {
	fmt.Fprintln(os.Stderr, "workspace-probe:", err)
	os.Exit(1)
}
