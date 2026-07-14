#!/usr/bin/env bash
set -euo pipefail

port="${MERCUTIO_E2E_PORT:-$((20000 + RANDOM % 20000))}"
tmp="$(mktemp -d)"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

operator_token="browser-e2e-operator-token"
MERCUTIO_PORT="$port" MERCUTIO_DEV_MODE=1 MERCUTIO_OPERATOR_TOKEN="$operator_token" MERCUTIO_STATE_PATH="$tmp/state.json" MERCUTIO_EVIDENCE_PATH="$tmp/evidence.jsonl" ./bin/mercutio >"$tmp/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
  kill -0 "$server_pid" 2>/dev/null || { cat "$tmp/server.log"; exit 1; }
  curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null
api_headers=(-H "Authorization: Bearer $operator_token" -H 'Content-Type: application/json')
created="$(curl -fsS "${api_headers[@]}" -d '{"repoURL":"https://github.com/example/e2e","branch":"main","profile":"standard"}' "http://127.0.0.1:$port/api/cells")"
cell_id="$(printf '%s' "$created" | sed -n 's/^{"id":"\([^"]*\)".*/\1/p')"
test -n "$cell_id"
fallback_created="$(curl -fsS "${api_headers[@]}" -d '{"repoURL":"https://github.com/example/e2e-fallback","branch":"main","profile":"standard"}' "http://127.0.0.1:$port/api/cells")"
fallback_cell_id="$(printf '%s' "$fallback_created" | sed -n 's/^{"id":"\([^"]*\)".*/\1/p')"
test -n "$fallback_cell_id"
for index in $(seq 3 49); do
  curl -fsS "${api_headers[@]}" -d "{\"repoURL\":\"https://github.com/example/e2e-$index\",\"branch\":\"main\",\"profile\":\"standard\"}" "http://127.0.0.1:$port/api/cells" >/dev/null
done
curl -fsS "${api_headers[@]}" -d '{"path":"cmd/hello/main.go","content":"package main\n\nfunc main() {}\n"}' "http://127.0.0.1:$port/api/cells/$cell_id/edit" >/dev/null
curl -fsS "${api_headers[@]}" -d '{"path":"cmd/fallback/main.go","content":"package main\n\nfunc main() {}\n"}' "http://127.0.0.1:$port/api/cells/$fallback_cell_id/edit" >/dev/null
MERCUTIO_E2E_URL="http://127.0.0.1:$port/?cell=$cell_id&file=cmd%2Fhello%2Fmain.go" \
  MERCUTIO_E2E_FALLBACK_URL="http://127.0.0.1:$port/?cell=$fallback_cell_id&file=cmd%2Ffallback%2Fmain.go" \
  MERCUTIO_E2E_PEER_URL="http://127.0.0.1:$port/?cell=cell-demo&file=main.go" \
  MERCUTIO_E2E_CELL_ID="$cell_id" \
  MERCUTIO_E2E_CELL_COUNT=50 \
  MERCUTIO_CHROME="${MERCUTIO_CHROME:-/usr/bin/google-chrome}" \
  "${GO:-go}" test ./internal/e2e -run 'TestGoSXEditorIntelligence|TestGoSXEditorFallsBackToServerWithoutWASM|TestOrreryScaleAndPerformance|TestPeerEditLatencyBudget' -count=1
