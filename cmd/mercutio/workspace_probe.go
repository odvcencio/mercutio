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
	scratch := flags.String("scratch", "/tmp", "scratch path")
	runtime := flags.String("runtime", "/run/mercutio", "runtime IPC path")
	flags.Parse(args)
	devices := map[string]uint64{}
	for name, path := range map[string]string{"workspace": *workspace, "scratch": *scratch, "runtime": *runtime} {
		device, err := mountDevice(path)
		if err != nil {
			fatalProbe(fmt.Errorf("%s device: %w", name, err))
		}
		devices[name] = device
	}
	body, _ := json.Marshal(devices)
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

func mountDevice(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 {
		return 0, fmt.Errorf("device unavailable")
	}
	return uint64(stat.Dev), nil
}

func fatalProbe(err error) {
	fmt.Fprintln(os.Stderr, "workspace-probe:", err)
	os.Exit(1)
}
