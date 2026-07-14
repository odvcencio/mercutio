package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeSource struct{ cells []Cell }

func (f *fakeSource) ListCells(context.Context) ([]Cell, error) { return f.cells, nil }

type fakeLoader struct {
	calls []string
	err   error
}

func (f *fakeLoader) Arm(_ context.Context, cell Cell) (ArmResult, error) {
	f.calls = append(f.calls, "arm:"+cell.ID)
	return ArmResult{Programs: []string{"GateExec"}, ManifestDigest: "sha256:m", ObjectDigest: "sha256:o", Enforcement: "r1-kernel"}, f.err
}
func (f *fakeLoader) Disarm(_ context.Context, id string) error {
	f.calls = append(f.calls, "disarm:"+id)
	return nil
}
func (f *fakeLoader) Close() error { return nil }

type fakeControl struct {
	calls *[]string
	err   error
}

func (f fakeControl) Armed(_ context.Context, cell Cell, _ ArmResult) error {
	*f.calls = append(*f.calls, "receipt:"+cell.ID)
	return f.err
}

func TestReconcileReportsOnlyAfterArmAndDisarmsMissingCells(t *testing.T) {
	source := &fakeSource{cells: []Cell{{ID: "cell-1", CgroupID: 7, Profile: "standard"}}}
	loader := &fakeLoader{}
	controlCalls := []string{}
	agent := &Agent{Source: source, Loader: loader, Control: fakeControl{calls: &controlCalls}}
	if err := agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := append(append([]string(nil), loader.calls...), controlCalls...)
	if !reflect.DeepEqual(all, []string{"arm:cell-1", "receipt:cell-1"}) {
		t.Fatalf("unexpected ordering: %v", all)
	}
	loader.calls = nil
	controlCalls = nil
	if err := agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(loader.calls)+len(controlCalls) != 0 {
		t.Fatal("unchanged cell was armed twice")
	}
	source.cells = nil
	if err := agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"disarm:cell-1"}) {
		t.Fatalf("missing disarm: %v", loader.calls)
	}
}

func TestReconcileRetriesReceiptWithoutClaimingSuccess(t *testing.T) {
	source := &fakeSource{cells: []Cell{{ID: "cell-1", CgroupID: 7}}}
	loader := &fakeLoader{}
	controlCalls := []string{}
	control := &fakeControl{calls: &controlCalls, err: errors.New("offline")}
	agent := &Agent{Source: source, Loader: loader, Control: control}
	if err := agent.Reconcile(context.Background()); err == nil {
		t.Fatal("expected receipt error")
	}
	control.err = nil
	if err := agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(loader.calls); got != 2 {
		t.Fatalf("arm attempts = %d, want 2", got)
	}
}
