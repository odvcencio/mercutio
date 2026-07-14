package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"m31labs.dev/horizon/preflight"
)

func runDoctor(args []string, output io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(output)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	requireR1 := flags.Bool("require-r1", false, "exit non-zero unless BPF-LSM enforcement is available")
	root := flags.String("root", "", "optional root containing host proc/sys trees")
	release := flags.String("kernel-release", "", "override kernel release (testing)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := preflight.Check(preflight.Options{Root: *root, KernelRelease: *release})
	if *jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(report)
	} else {
		fmt.Fprintf(output, "Mercutio enforcement rung: %s\n", report.EnforcementRung)
		fmt.Fprintf(output, "Kernel: %s (>=5.10: %t)\nBTF: %t\ncgroup v2: %t\nBPF-LSM compiled: %t\nBPF-LSM active: %t\n", report.KernelRelease, report.KernelAtLeast510, report.BTF, report.CgroupV2, report.BPFLSMCompiled, report.BPFLSMEnabled)
		for _, issue := range report.Issues {
			fmt.Fprintln(output, "- "+issue)
		}
	}
	if *requireR1 && !report.Ready() {
		return 1
	}
	return 0
}
