package cell

import (
	"context"
	"testing"

	"m31labs.dev/mercutio/internal/sandbox"
)

type policyRuntimeRecorder struct {
	inner                    *sandbox.MemoryRuntime
	ensures, rearms, deletes int
}

func (r *policyRuntimeRecorder) Ensure(ctx context.Context, spec sandbox.Spec) (sandbox.Pod, error) {
	r.ensures++
	return r.inner.Ensure(ctx, spec)
}

func (r *policyRuntimeRecorder) Observe(ctx context.Context, cellID string) (sandbox.Pod, error) {
	return r.inner.Observe(ctx, cellID)
}

func (r *policyRuntimeRecorder) Managed(ctx context.Context) ([]sandbox.Pod, error) {
	return r.inner.Managed(ctx)
}

func (r *policyRuntimeRecorder) Rearm(ctx context.Context, spec sandbox.Spec) (sandbox.Pod, error) {
	r.rearms++
	return r.inner.Rearm(ctx, spec)
}

func (r *policyRuntimeRecorder) Delete(ctx context.Context, cellID string) error {
	r.deletes++
	return r.inner.Delete(ctx, cellID)
}

func TestApplyPolicyRearmsBeforePublishingManifest(t *testing.T) {
	runtime := &policyRuntimeRecorder{inner: sandbox.NewMemoryRuntime()}
	store := NewStoreWithOptions(Options{Runtime: runtime})
	runtime.ensures, runtime.rearms, runtime.deletes = 0, 0, 0
	snapshot, preview, err := store.ApplyPolicy(context.Background(), "cell-demo", "profile: strict\n", "operator-test")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Before.Profile != "standard" || preview.After.Profile != "strict" {
		t.Fatalf("preview=%+v", preview)
	}
	if snapshot.SandboxProfile != "strict" || snapshot.Capabilities.Profile != "strict" || snapshot.Sandbox.Phase != "running" {
		t.Fatalf("snapshot=%+v", snapshot.Cell)
	}
	foundReplay, foundArm := false, false
	for _, e := range snapshot.Events {
		foundReplay = foundReplay || e.Action == "policy.replay"
		foundArm = foundArm || e.Action == "policy.rearm"
	}
	if !foundReplay || !foundArm {
		t.Fatalf("missing replay/rearm events")
	}
	if runtime.rearms != 1 || runtime.ensures != 0 || runtime.deletes != 0 {
		t.Fatalf("policy apply restarted sandbox: ensure=%d rearm=%d delete=%d", runtime.ensures, runtime.rearms, runtime.deletes)
	}
	for _, event := range snapshot.Events {
		if event.Action == "policy.rearm" && event.Summary != "Live enforcement profile armed without sandbox restart" {
			t.Fatalf("unexpected rearm semantics: %+v", event)
		}
	}
}
