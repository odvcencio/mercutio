#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "kernel integration requires root" >&2
  exit 1
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "BPF LSM is not enabled" >&2
  exit 1
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
openssl rand -hex 32 >"$tmp/release.key"
cd "$root/nodeagent"
"${GO:-go}" run ./cmd/mercutio-artifacts -manifest generated/mercutio.cap.json -object generated/mercutio.bpf.o -private-key "$tmp/release.key" -key-id kernel-integration -out "$tmp/dist"
MERCUTIO_KERNEL_ARTIFACT_DIR="$tmp/dist" "${GO:-go}" test -tags=kernelintegration -run TestKernelLoadsAttachesAndEnforcesStrictExec -v ./internal/agent
