package cell

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"m31labs.dev/mercutio/internal/evidence"

	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/sandbox"
)

func TestSyncWorktreeFileAtomicallyReplacesDestination(t *testing.T) {
	root := t.TempDir()
	path := "cmd/main.go"
	if err := syncWorktreeFile(root, "cell-1", path, "old content"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "cell-1", path)
	before, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = syncWorktreeFile(root, "cell-1", path, "new content"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("materialization rewrote the destination inode instead of replacing it atomically")
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "new content" {
		t.Fatalf("content=%q err=%v", content, err)
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".mercutio-write-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary files=%v err=%v", temps, err)
	}
}

func TestGarbageCollectRemovesOrphansAndRetainsLiveCells(t *testing.T) {
	runtime := sandbox.NewMemoryRuntime()
	store := NewStoreWithOptions(Options{Runtime: runtime})
	if _, err := runtime.Ensure(context.Background(), sandbox.Spec{CellID: "orphan", RepoURL: "https://github.com/example/orphan", Profile: "standard"}); err != nil {
		t.Fatal(err)
	}
	removed, err := store.GarbageCollect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "orphan" {
		t.Fatalf("removed = %v", removed)
	}
	if _, err := runtime.Observe(context.Background(), "orphan"); err != sandbox.ErrNotFound {
		t.Fatalf("orphan remained after garbage collection: %v", err)
	}
	live, err := runtime.Observe(context.Background(), "cell-demo")
	if err != nil || live.Phase != sandbox.PhaseRunning {
		t.Fatalf("live = %+v, %v", live, err)
	}
}

func TestReconcileRecreatesMissingLiveSandboxFromDurableState(t *testing.T) {
	runtime := sandbox.NewMemoryRuntime()
	store := NewStoreWithOptions(Options{Runtime: runtime})
	before, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Delete(context.Background(), "cell-demo"); err != nil {
		t.Fatal(err)
	}
	after, changed, err := store.Reconcile(context.Background(), "cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if !changed || after.Revision != before.Revision+1 || after.Sandbox.Phase != model.SandboxRunning {
		t.Fatalf("reconciled snapshot=%+v changed=%v", after.Cell, changed)
	}
	if _, err := runtime.Observe(context.Background(), "cell-demo"); err != nil {
		t.Fatalf("sandbox was not recreated: %v", err)
	}
	latest := after.Events[len(after.Events)-1]
	if latest.Action != "sandbox.recreated" || !latest.Authenticated {
		t.Fatalf("missing recreation receipt: %+v", latest)
	}
}

func TestReconcileDoesNotRecreateStoppedSandbox(t *testing.T) {
	runtime := sandbox.NewMemoryRuntime()
	store := NewStoreWithOptions(Options{Runtime: runtime})
	stopped, err := store.Destroy("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := store.Reconcile(context.Background(), "cell-demo")
	if err != nil || changed || after.Status != model.CellStopped || after.Revision != stopped.Revision {
		t.Fatalf("stopped reconcile=%+v changed=%v err=%v", after.Cell, changed, err)
	}
	if _, err := runtime.Observe(context.Background(), "cell-demo"); err != sandbox.ErrNotFound {
		t.Fatalf("stopped sandbox was recreated: %v", err)
	}
}

func TestBrowserSplicePublishesBeforeRevisionedReviewRefresh(t *testing.T) {
	store := NewStore()
	before, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	var file model.File
	for _, candidate := range before.Files {
		if candidate.Path == "cmd/hello/main.go" {
			file = candidate
			break
		}
	}
	if file.Path == "" {
		t.Fatal("demo Go file is missing")
	}
	mainOffset := strings.Index(file.Content, "main")
	if mainOffset < 0 {
		t.Fatal("demo main function is missing")
	}
	immediate, err := store.ApplySplice("cell-demo", file.Path, browserContentHash(file.Content), uint32(mainOffset), uint32(len([]rune("main"))), "launch", "operator-browser")
	if err != nil {
		t.Fatal(err)
	}
	if immediate.Revision != before.Revision+1 || !reflect.DeepEqual(immediate.Reviews, before.Reviews) {
		t.Fatalf("hot path recomputed reviews: before=%d immediate=%d", before.Revision, immediate.Revision)
	}
	refreshed, changed, err := store.RefreshReviews("cell-demo", immediate.Revision)
	if err != nil || !changed || refreshed.Revision != immediate.Revision+1 || reflect.DeepEqual(refreshed.Reviews, immediate.Reviews) {
		t.Fatalf("review refresh changed=%v err=%v immediate=%d refreshed=%d", changed, err, immediate.Revision, refreshed.Revision)
	}
}

func TestTwentyCreateDestroyCyclesReleaseLiveState(t *testing.T) {
	runtime := sandbox.NewMemoryRuntime()
	store := NewStoreWithOptions(Options{Runtime: runtime})
	for cycle := 0; cycle < 20; cycle++ {
		created, err := store.Create("https://github.com/example/churn", "main", "standard")
		if err != nil {
			t.Fatalf("cycle %d create: %v", cycle, err)
		}
		if _, err := store.Destroy(created.ID); err != nil {
			t.Fatalf("cycle %d destroy: %v", cycle, err)
		}
		store.mu.RLock()
		record := store.cells[created.ID]
		liveDocs, history, writers := len(record.docs), len(record.history), len(record.writers)
		store.mu.RUnlock()
		if liveDocs != 0 || history != 0 || writers != 0 {
			t.Fatalf("cycle %d retained docs=%d history=%d writers=%d", cycle, liveDocs, history, writers)
		}
	}
	pods, err := runtime.Managed(context.Background())
	if err != nil || len(pods) != 1 || pods[0].CellID != "cell-demo" {
		t.Fatalf("managed pods after churn=%d err=%v", len(pods), err)
	}
}

func TestEvidenceSurvivesCellDestructionAndStoreLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	ledger, err := evidence.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithOptions(Options{Evidence: ledger})
	created, err := store.Create("https://github.com/example/durable", "main", "standard")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Destroy(created.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err := evidence.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	records := reopened.Records(created.ID)
	if len(records) < 3 {
		t.Fatalf("durable records = %d, want lifecycle and policy evidence", len(records))
	}
	if records[len(records)-1].Kind != "event" {
		t.Fatalf("last durable record = %#v", records[len(records)-1])
	}
}

func TestStoreLifecycleAndSharedDocuments(t *testing.T) {
	store := NewStore()
	created, err := store.Create("https://github.com/example/project", "main", "strict")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Status != model.CellReady || created.SandboxProfile != "strict" {
		t.Fatalf("created cell = %+v", created.Cell)
	}

	updated, err := store.ApplyEdit(created.ID, "README.md", "# changed\n\nA human edit.\n", "operator")
	if err != nil {
		t.Fatalf("ApplyEdit: %v", err)
	}
	if got := updated.Files[0].Content; got != "# changed\n\nA human edit.\n" {
		t.Fatalf("updated content = %q", got)
	}
	if updated.Revision <= created.Revision {
		t.Fatalf("revision did not advance: %d -> %d", created.Revision, updated.Revision)
	}

	steered, err := store.Prompt(created.ID, "Please tighten the policy review.")
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if steered.Status != model.CellSteering || steered.Agent.Status != "steering" {
		t.Fatalf("steered cell = %+v", steered.Cell)
	}
	ready, err := store.Detach(created.ID, steered.Agent.ID)
	if err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if ready.Status != model.CellReady || ready.Agent.Connected || ready.Agent.Status != "detached" {
		t.Fatalf("detached cell = %+v", ready.Cell)
	}

	if len(updated.Reviews) == 0 {
		t.Fatal("edit did not produce an entity review")
	}
	approved, err := store.ApproveReview(created.ID, updated.Reviews[0].ID)
	if err != nil {
		t.Fatalf("ApproveReview: %v", err)
	}
	if approved.Reviews[0].Status != "approved" {
		t.Fatalf("review status = %q", approved.Reviews[0].Status)
	}

	stopped, err := store.Destroy(created.ID)
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if stopped.Status != model.CellStopped || stopped.Agent.Connected {
		t.Fatalf("stopped cell = %+v", stopped.Cell)
	}
}

func TestApplySpliceUsesExactUnicodeBaseAndRejectsStaleWriter(t *testing.T) {
	store := NewStore()
	initial := "a🙂c"
	if _, err := store.ApplyEdit("cell-demo", "unicode.txt", initial, "operator"); err != nil {
		t.Fatal(err)
	}
	updated, err := store.ApplySplice("cell-demo", "unicode.txt", browserContentHash(initial), 1, 1, "β", "operator")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, file := range updated.Files {
		if file.Path == "unicode.txt" {
			got = file.Content
		}
	}
	if got != "aβc" {
		t.Fatalf("content=%q", got)
	}
	if _, err := store.ApplySplice("cell-demo", "unicode.txt", browserContentHash(initial), 0, 0, "stale", "operator"); err == nil {
		t.Fatal("stale browser splice was accepted")
	}
}

func TestActionApprovalIsDeliveredExactlyOnce(t *testing.T) {
	store := NewStore()
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkArmed("cell-demo", ArmReceipt{NodeID: "node-a", Programs: []string{"GateExec"}, ManifestDigest: "sha256:manifest", ObjectDigest: "sha256:object", ProfileDigest: snapshot.Capabilities.ProfileDigest, CgroupID: 99, Enforcement: "r1-bpf-lsm"}); err != nil {
		t.Fatal(err)
	}
	snapshot, request, err := store.RequestActionApproval("cell-demo", "ask-1", "node-a", 77, 42, "exec", "/workspace/repo/tool")
	if err != nil || request.Status != "pending" || len(snapshot.ActionApprovals) != 1 {
		t.Fatalf("request=%+v snapshot=%+v err=%v", request, snapshot.ActionApprovals, err)
	}
	if _, err := store.DecideActionApproval("cell-demo", request.ID, "operator", true); err != nil {
		t.Fatal(err)
	}
	decisions := store.TakeNodeActionDecisions("node-a")
	if len(decisions) != 1 || decisions[0].Status != "approved" || decisions[0].CgroupID != 77 || decisions[0].PID != 42 {
		t.Fatalf("decisions=%+v", decisions)
	}
	if repeated := store.TakeNodeActionDecisions("node-a"); len(repeated) != 0 {
		t.Fatalf("decision delivered more than once: %+v", repeated)
	}
}

func TestMarkArmedRejectsStaleProfileDigest(t *testing.T) {
	store := NewStore()
	_, err := store.MarkArmed("cell-demo", ArmReceipt{
		NodeID: "node-a", Programs: []string{"GateExec"}, ManifestDigest: "sha256:manifest",
		ObjectDigest: "sha256:object", ProfileDigest: "sha256:stale", CgroupID: 99,
	})
	if err == nil {
		t.Fatal("stale profile arm receipt was accepted")
	}
}

func TestDiskEditWithStaleBaseBecomesShadow(t *testing.T) {
	store := NewStore()
	before, _ := store.Snapshot("cell-demo")
	current := before.Files[1].Content
	snapshot, err := store.ApplyDiskEdit("cell-demo", before.Files[1].Path, "stale", "agent disk", "agent-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Shadows) == 0 || snapshot.Shadows[len(snapshot.Shadows)-1].After != "agent disk" || snapshot.Files[1].Content != current {
		t.Fatalf("stale disk edit was not preserved: shadows=%+v file=%q", snapshot.Shadows, snapshot.Files[1].Content)
	}
	snapshot, err = store.ApplyDiskEdit("cell-demo", before.Files[1].Path, current, "agent applied", "agent-demo")
	if err != nil || snapshot.Files[1].Content != "agent applied" {
		t.Fatalf("matching disk edit=%q err=%v", snapshot.Files[1].Content, err)
	}
}

func TestDiskDeleteRequiresExactBase(t *testing.T) {
	store := NewStore()
	before, _ := store.Snapshot("cell-demo")
	path, current := before.Files[1].Path, before.Files[1].Content
	snapshot, err := store.ApplyDiskDelete("cell-demo", path, "stale", "agent-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Files) != len(before.Files) || len(snapshot.Shadows) == 0 || snapshot.Shadows[len(snapshot.Shadows)-1].After != "" {
		t.Fatalf("uncertain deletion was not shadowed: files=%d shadows=%+v", len(snapshot.Files), snapshot.Shadows)
	}
	snapshot, err = store.ApplyDiskDelete("cell-demo", path, current, "agent-demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range snapshot.Files {
		if file.Path == path {
			t.Fatalf("exact-base disk deletion retained %q", path)
		}
	}
}

func TestStoreRejectsBlankCommands(t *testing.T) {
	store := NewStore()
	if _, err := store.Create("", "main", "standard"); err == nil {
		t.Fatal("Create accepted a blank repo")
	}
	if _, err := store.Prompt("cell-demo", " "); err == nil {
		t.Fatal("Prompt accepted a blank prompt")
	}
	if _, err := store.ApplyEdit("cell-demo", "", "x", "operator"); err == nil {
		t.Fatal("ApplyEdit accepted a blank path")
	}
	if _, err := store.Create("https://github.com/example/project", "main", "custom"); err == nil {
		t.Fatal("Create accepted an unknown capability profile")
	}
	writeCap, _ := store.MintSecretCapability("cell-demo", "operator", "secret:write")
	if _, _, err := store.PutSecret("cell-demo", "api-token", "secret-value", "operator", writeCap); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	token, err := store.AttachToken("cell-demo")
	if err != nil {
		t.Fatalf("AttachToken: %v", err)
	}
	if _, _, err := store.SecretValue("cell-demo", "api-token", "agent-cell-demo", token); err == nil {
		t.Fatal("agent attach capability revealed a brokered secret")
	}
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil || len(snapshot.Events) == 0 {
		t.Fatalf("Snapshot after secret = %+v, %v", snapshot, err)
	}
	for _, event := range snapshot.Events {
		if strings.Contains(event.Detail, "secret-value") {
			t.Fatalf("secret leaked in event: %+v", event)
		}
	}
	if _, err := store.Destroy("cell-demo"); err != nil {
		t.Fatalf("Destroy after secret: %v", err)
	}
}

func TestStoreTracksIntentKernelDivergence(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	intent, err := store.RecordEvent("cell-demo", model.Event{Kind: model.EventIntent, Source: "agent", Action: "test.run", TraceID: "trace-1", Timestamp: now})
	if err != nil || !intent.Divergence {
		t.Fatalf("intent divergence = %+v, %v", intent.Cell, err)
	}
	observed, err := store.RecordEvent("cell-demo", model.Event{Kind: model.EventKernel, Source: "horizon", Action: "process.exec", TraceID: "trace-1", Timestamp: now.Add(time.Second)})
	if err != nil || observed.Divergence {
		t.Fatalf("kernel divergence = %+v, %v", observed.Cell, err)
	}
}
