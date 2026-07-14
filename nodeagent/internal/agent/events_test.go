package agent

import (
	"testing"

	"golang.org/x/sys/unix"
	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

func TestAskEventStopsBoundProcessBeforeQueueing(t *testing.T) {
	var pid int
	var signal unix.Signal
	programs := &classPrograms{class: 1}
	manager := &ProgramManager{
		options:    ProgramOptions{Signal: func(gotPID int, gotSignal unix.Signal) error { pid, signal = gotPID, gotSignal; return nil }},
		cells:      map[string]*loadedCell{"cell-1": {cell: Cell{ID: "cell-1", NodeID: "node-a"}, programs: programs}},
		identities: map[[2]uint64]string{{1, 2}: "cell-1"},
	}
	event, ok := manager.baseEvent(programs, bindings.EventHeader{CellLo: 1, CellHi: 2, Pid: 42, Verdict: 2})
	if !ok || event.Verdict != "ask" || pid != 42 || signal != unix.SIGSTOP || event.Evidence != "clean" {
		t.Fatalf("event=%+v pid=%d signal=%v ok=%t", event, pid, signal, ok)
	}
}

func TestApprovedEventIsReportedDistinctly(t *testing.T) {
	programs := &classPrograms{class: 1}
	manager := &ProgramManager{
		options:    ProgramOptions{Signal: func(int, unix.Signal) error { return nil }},
		cells:      map[string]*loadedCell{"cell-1": {cell: Cell{ID: "cell-1", NodeID: "node-a"}, programs: programs}},
		identities: map[[2]uint64]string{{1, 2}: "cell-1"},
	}
	event, ok := manager.baseEvent(programs, bindings.EventHeader{CellLo: 1, CellHi: 2, Pid: 42, Verdict: 3})
	if !ok || event.Verdict != "approved" {
		t.Fatalf("event=%+v ok=%t", event, ok)
	}
}

func TestEventRejectsIdentityFromAnotherProfileClass(t *testing.T) {
	standard := &classPrograms{class: 1}
	manager := &ProgramManager{
		cells:      map[string]*loadedCell{"cell-1": {cell: Cell{ID: "cell-1"}, programs: standard}},
		identities: map[[2]uint64]string{{1, 2}: "cell-1"},
	}
	if _, ok := manager.baseEvent(&classPrograms{class: 0}, bindings.EventHeader{CellLo: 1, CellHi: 2}); ok {
		t.Fatal("event from a different profile-class collection was accepted")
	}
}
