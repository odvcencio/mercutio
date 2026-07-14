package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/sandbox"
	"m31labs.dev/mercutio/internal/transport"
)

type nodeCellRuntime struct {
	*sandbox.MemoryRuntime
	cells []sandbox.NodeCell
}

func (r *nodeCellRuntime) NodeCells(_ context.Context, nodeID string) ([]sandbox.NodeCell, error) {
	var result []sandbox.NodeCell
	for _, candidate := range r.cells {
		if candidate.NodeID == nodeID {
			result = append(result, candidate)
		}
	}
	return result, nil
}

func TestNodeCellsExposesOnlyNodeScopedEnforcementMetadata(t *testing.T) {
	runtime := &nodeCellRuntime{MemoryRuntime: sandbox.NewMemoryRuntime(), cells: []sandbox.NodeCell{{ID: "cell-a", PodUID: "pod-a", NodeID: "node-a"}, {ID: "cell-b", PodUID: "pod-b", NodeID: "node-b"}}}
	handler := New(cell.NewStoreWithRuntime(runtime), nil)
	request := httptest.NewRequest(http.MethodGet, "/api/internal/nodes/node-a/cells", nil)
	response := httptest.NewRecorder()
	handler.NodeCells(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"cell-a"`) || strings.Contains(response.Body.String(), "cell-b") || strings.Contains(response.Body.String(), "worktreeDev") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestKernelTelemetryPersistsGzipBatchAndEvidenceGaps(t *testing.T) {
	store := cell.NewStore()
	handler := New(store, transport.NewCellHub(store))
	now := time.Now().UTC()
	post := func(sequence uint64, drops uint64) *httptest.ResponseRecorder {
		payload := map[string]any{
			"nodeID": "node-a", "batchSeq": sequence,
			"clockSync": map[string]any{"nodeID": "node-a", "monotonicNs": int64(10_000), "realtimeNs": now.UnixNano(), "skewBoundMs": 7},
			"events": []map[string]any{{
				"cellID": "cell-demo", "nodeID": "node-a", "seq": sequence, "tsNs": uint64(10_000),
				"kind": "exec", "verdict": "deny", "pid": 9, "program": "GateExec",
				"path": "/usr/bin/curl", "actionDanger": map[string]string{"mode": "control", "scope": "process", "reversibility": "restart"},
			}},
			"drops": map[string]uint64{"ring": drops}, "sentAt": now,
		}
		var body bytes.Buffer
		zw := gzip.NewWriter(&body)
		if err := json.NewEncoder(zw).Encode(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/api/internal/telemetry/kernel", &body)
		request.Header.Set("Content-Encoding", "gzip")
		response := httptest.NewRecorder()
		handler.KernelTelemetry(response, request)
		return response
	}
	if response := post(1, 0); response.Code != http.StatusAccepted {
		t.Fatalf("first batch=%d %s", response.Code, response.Body.String())
	}
	if response := post(3, 4); response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"batchGap":true`) {
		t.Fatalf("gap batch=%d %s", response.Code, response.Body.String())
	}
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	latest := snapshot.Events[len(snapshot.Events)-1]
	if latest.Kind != "kernel" || latest.BatchSeq != 3 || latest.Drops != 4 || latest.Verdict != "deny" || latest.Path != "/usr/bin/curl" || !latest.Authenticated || latest.ClockSkewBoundMS != 7 {
		t.Fatalf("kernel event not preserved: %+v", latest)
	}
	if !strings.Contains(latest.Detail, "batch-gap=true") {
		t.Fatalf("batch gap not durable: %s", latest.Detail)
	}
	if replay := post(3, 0); replay.Code != http.StatusConflict {
		t.Fatalf("replay status=%d %s", replay.Code, replay.Body.String())
	}
}

func TestKernelTelemetryCursorSurvivesControlPlaneRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	newStore := func() *cell.Store {
		return cell.NewStoreWithOptions(cell.Options{StatePath: statePath, CapabilityKey: []byte("test-capability-key")})
	}
	now := time.Now().UTC()
	post := func(handler *Handler, sequence uint64) *httptest.ResponseRecorder {
		payload := map[string]any{
			"nodeID": "node-reconnect", "batchSeq": sequence,
			"clockSync": map[string]any{"nodeID": "node-reconnect", "monotonicNs": int64(100), "realtimeNs": now.UnixNano(), "skewBoundMs": 2},
			"events":    []map[string]any{{"cellID": "cell-demo", "nodeID": "node-reconnect", "seq": sequence, "tsNs": uint64(100), "kind": "exec", "verdict": "allow", "pid": 7}},
			"drops":     map[string]uint64{}, "sentAt": now,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.KernelTelemetry(response, httptest.NewRequest(http.MethodPost, "/api/internal/telemetry/kernel", bytes.NewReader(data)))
		return response
	}

	firstStore := newStore()
	first := New(firstStore, transport.NewCellHub(firstStore))
	if response := post(first, 1); response.Code != http.StatusAccepted {
		t.Fatalf("first batch=%d %s", response.Code, response.Body.String())
	}

	secondStore := newStore()
	second := New(secondStore, transport.NewCellHub(secondStore))
	if response := post(second, 1); response.Code != http.StatusConflict {
		t.Fatalf("replay after restart=%d %s", response.Code, response.Body.String())
	}
	cursorResponse := httptest.NewRecorder()
	second.NodeTelemetryCursor(cursorResponse, httptest.NewRequest(http.MethodGet, "/api/internal/nodes/node-reconnect/telemetry-cursor", nil))
	if cursorResponse.Code != http.StatusOK || !strings.Contains(cursorResponse.Body.String(), `"lastBatchSeq":1`) || cursorResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cursor=%d headers=%v body=%s", cursorResponse.Code, cursorResponse.Header(), cursorResponse.Body.String())
	}
	if response := post(second, 2); response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), `"batchGap":true`) {
		t.Fatalf("resumed batch=%d %s", response.Code, response.Body.String())
	}
}

func TestKernelAskCreatesOperatorApprovalAndNodeDecision(t *testing.T) {
	store := cell.NewStore()
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkArmed("cell-demo", cell.ArmReceipt{NodeID: "node-a", Programs: []string{"GateExec"}, ManifestDigest: "sha256:manifest", ObjectDigest: "sha256:object", ProfileDigest: snapshot.Capabilities.ProfileDigest, CgroupID: 77, Enforcement: "r1-bpf-lsm"}); err != nil {
		t.Fatal(err)
	}
	handler := New(store, transport.NewCellHub(store))
	now := time.Now().UTC()
	payload := map[string]any{
		"nodeID": "node-a", "batchSeq": 1,
		"clockSync": map[string]any{"nodeID": "node-a", "monotonicNs": int64(100), "realtimeNs": now.UnixNano(), "skewBoundMs": 4},
		"events":    []map[string]any{{"cellID": "cell-demo", "nodeID": "node-a", "cgroupID": uint64(77), "seq": 1, "tsNs": uint64(100), "kind": "exec", "verdict": "ask", "pid": 42, "program": "GateExec", "path": "/workspace/repo/tool"}},
		"drops":     map[string]uint64{}, "sentAt": now,
	}
	var body bytes.Buffer
	zipper := gzip.NewWriter(&body)
	if err := json.NewEncoder(zipper).Encode(payload); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/internal/telemetry/kernel", &body)
	request.Header.Set("Content-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.KernelTelemetry(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("telemetry=%d %s", response.Code, response.Body.String())
	}
	snapshot, _ = store.Snapshot("cell-demo")
	if len(snapshot.ActionApprovals) != 1 || snapshot.ActionApprovals[0].Status != "pending" {
		t.Fatalf("approvals=%+v", snapshot.ActionApprovals)
	}
	if _, err := store.DecideActionApproval("cell-demo", snapshot.ActionApprovals[0].ID, "operator", false); err != nil {
		t.Fatal(err)
	}
	decisionRequest := httptest.NewRequest(http.MethodGet, "/api/internal/nodes/node-a/action-decisions", nil)
	decisionResponse := httptest.NewRecorder()
	handler.NodeActionDecisions(decisionResponse, decisionRequest)
	if decisionResponse.Code != http.StatusOK || !strings.Contains(decisionResponse.Body.String(), `"status":"rejected"`) || !strings.Contains(decisionResponse.Body.String(), `"cgroupID":77`) {
		t.Fatalf("decisions=%d %s", decisionResponse.Code, decisionResponse.Body.String())
	}
}

func TestCreateAndEditAPI(t *testing.T) {
	store := cell.NewStore()
	hub := transport.NewCellHub(store)
	handler := New(store, hub)

	createRequest := httptest.NewRequest("POST", "/api/cells", strings.NewReader(`{"repoURL":"https://github.com/example/repo","branch":"main","profile":"standard"}`))
	createResponse := httptest.NewRecorder()
	handler.CreateCell(createResponse, createRequest)
	if createResponse.Code != 201 {
		t.Fatalf("create status = %d, body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	editRequest := httptest.NewRequest("POST", "/api/cells/"+created.ID+"/edit", strings.NewReader(`{"path":"README.md","content":"updated"}`))
	editResponse := httptest.NewRecorder()
	handler.Edit(editResponse, editRequest)
	if editResponse.Code != 200 || !strings.Contains(editResponse.Body.String(), "updated") {
		t.Fatalf("edit response = %d, body=%s", editResponse.Code, editResponse.Body.String())
	}
}

func TestPolicyApplyAPIRequiresCellScopedCapability(t *testing.T) {
	store := cell.NewStore()
	handler := New(store, transport.NewCellHub(store))
	request := httptest.NewRequest(http.MethodPost, "/api/cells/cell-demo/policy/apply", strings.NewReader(`{"content":"profile: strict\n","actor":"operator"}`))
	response := httptest.NewRecorder()
	handler.PolicyApply(response, request)
	if response.Code == http.StatusOK || !strings.Contains(response.Body.String(), "policy:apply capability required") {
		t.Fatalf("uncapable apply=%d %s", response.Code, response.Body.String())
	}
	token, err := store.MintOperatorCapability("cell-demo", "operator")
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/cells/cell-demo/policy/apply", strings.NewReader(`{"content":"profile: strict\n","actor":"operator"}`))
	request.Header.Set("X-Mercutio-Capability", token)
	response = httptest.NewRecorder()
	handler.PolicyApply(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("capable apply=%d %s", response.Code, response.Body.String())
	}
}

func TestTier1ProxyInjectsCredentialOnlyAtExactHTTPSDestination(t *testing.T) {
	var gotAuthorization, gotCookie string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Set-Cookie", "session=upstream")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	store := cell.NewStore()
	handler := New(store, transport.NewCellHub(store))
	handler.proxyClient = upstream.Client()
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, _, err := store.PutSecret("cell-demo", "GITHUB_TOKEN", "network-secret", "operator", writeCap); err != nil {
		t.Fatal(err)
	}
	grantCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:grant")
	configure := httptest.NewRequest("POST", "https://mercutio.test/api/cells/cell-demo/secret-proxies", strings.NewReader(`{"credential":"GITHUB_TOKEN","destination":"`+upstream.URL+`","actor":"operator","capability":"`+grantCap+`"}`))
	configured := httptest.NewRecorder()
	handler.ConfigureSecretProxy(configured, configure)
	if configured.Code != 201 {
		t.Fatalf("configure=%d %s", configured.Code, configured.Body.String())
	}
	var payload struct {
		ProxyURL string `json:"proxyURL"`
	}
	if err := json.Unmarshal(configured.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	proxyURL, err := url.Parse(payload.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.Path += "/v1/resource"
	request := httptest.NewRequest("GET", proxyURL.RequestURI(), nil)
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("Cookie", "session=attacker")
	response := httptest.NewRecorder()
	handler.SecretProxy(response, request)
	if response.Code != 200 || gotAuthorization != "Bearer network-secret" || gotCookie != "" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("response=%d auth=%q cookie=%q headers=%v", response.Code, gotAuthorization, gotCookie, response.Header())
	}
}

func TestInternalEventAcceptsHorizonShape(t *testing.T) {
	store := cell.NewStore()
	hub := transport.NewCellHub(store)
	handler := New(store, hub)
	request := httptest.NewRequest("POST", "/api/internal/events", strings.NewReader(`{"cell_id":"cell-demo","capability":"file-events","output":"FileAccessEvent","id":"kernel-1","traceID":"trace-1"}`))
	response := httptest.NewRecorder()
	handler.InternalEvent(response, request)
	if response.Code != 202 || !strings.Contains(response.Body.String(), "horizon.FileAccessEvent") || !strings.Contains(response.Body.String(), "trace-1") {
		t.Fatalf("internal event response = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestSecretBrokerNeverRevealsValueToAgentCapability(t *testing.T) {
	store := cell.NewStore()
	hub := transport.NewCellHub(store)
	handler := New(store, hub)
	writeCap, err := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if err != nil {
		t.Fatal(err)
	}
	put := httptest.NewRequest("POST", "/api/cells/cell-demo/secrets", strings.NewReader(`{"name":"api-token","value":"secret-value","actor":"operator","capability":"`+writeCap+`"}`))
	putResponse := httptest.NewRecorder()
	handler.PutSecret(putResponse, put)
	if putResponse.Code != 202 {
		t.Fatalf("put secret status = %d, body=%s", putResponse.Code, putResponse.Body.String())
	}
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatalf("AttachToken: %v", err)
	}
	read := httptest.NewRequest("GET", "/api/cells/cell-demo/secrets/api-token", nil)
	read.Header.Set("X-Mercutio-Capability", token)
	readResponse := httptest.NewRecorder()
	handler.GetSecret(readResponse, read)
	if readResponse.Code != 403 || strings.Contains(readResponse.Body.String(), "secret-value") {
		t.Fatalf("agent secret reveal response = %d, body=%s", readResponse.Code, readResponse.Body.String())
	}
	denied := httptest.NewRequest("GET", "/api/cells/cell-demo/secrets/api-token", nil)
	deniedResponse := httptest.NewRecorder()
	handler.GetSecret(deniedResponse, denied)
	if deniedResponse.Code != 403 {
		t.Fatalf("unauthorized secret status = %d", deniedResponse.Code)
	}
}

func TestSecretRevealRequiresFreshOperatorCapabilityAndReceipts(t *testing.T) {
	store := cell.NewStore()
	handler := New(store, transport.NewCellHub(store))
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	put := httptest.NewRequest("POST", "/api/cells/cell-demo/secrets", strings.NewReader(`{"name":"API_TOKEN","value":"token-value-1234","actor":"operator","capability":"`+writeCap+`"}`))
	putResponse := httptest.NewRecorder()
	handler.PutSecret(putResponse, put)
	if putResponse.Code != 202 {
		t.Fatalf("put=%d %s", putResponse.Code, putResponse.Body.String())
	}
	readCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:read")
	read := httptest.NewRequest("GET", "/api/cells/cell-demo/secrets/API_TOKEN?actor=operator", nil)
	read.Header.Set("X-Mercutio-Capability", readCap)
	response := httptest.NewRecorder()
	handler.GetSecret(response, read)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "token-value-1234") || !strings.Contains(response.Body.String(), "secret:reveal") {
		t.Fatalf("reveal=%d %s", response.Code, response.Body.String())
	}
	descriptors, _ := store.SecretDescriptors("cell-demo")
	if len(descriptors) != 1 || strings.Contains(descriptors[0].Redacted, "token-value") {
		t.Fatalf("descriptors=%+v", descriptors)
	}
}
