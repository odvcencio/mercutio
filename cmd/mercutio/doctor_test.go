package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorStatesActualEnforcementRung(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"sys/kernel/btf/vmlinux": "btf", "sys/fs/cgroup/cgroup.controllers": "cpu", "sys/kernel/security/lsm": "capability,bpf", "boot/config-6.12.0": "CONFIG_BPF_LSM=y\n",
	} {
		name := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if code := runDoctor([]string{"--root", root, "--kernel-release", "6.12.0", "--require-r1"}, &output); code != 0 {
		t.Fatalf("doctor code=%d output=%s", code, output.String())
	}
	if !strings.Contains(output.String(), "R1-bpf-lsm") {
		t.Fatalf("doctor hid enforcement rung: %s", output.String())
	}
}
