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

func TestOpenEventMetadataNamesObserveProgramsWithoutControlDanger(t *testing.T) {
	fileName, fileDanger := fileProgramMetadata(2)
	if fileName != "ObserveFileOpen" || fileDanger["mode"] != "observe" || fileDanger["scope"] != "event" || fileDanger["reversibility"] != "none" {
		t.Fatalf("open file metadata = %s %+v", fileName, fileDanger)
	}
	for family, want := range map[uint16]string{2: "ObserveConnect4", 10: "ObserveConnect6"} {
		name, programDanger := connectProgramMetadata(2, family)
		if name != want || programDanger["mode"] != "observe" || programDanger["scope"] != "event" || programDanger["reversibility"] != "none" {
			t.Fatalf("open connect family %d metadata = %s %+v", family, name, programDanger)
		}
	}
}

func TestContainedEventMetadataNamesControlPrograms(t *testing.T) {
	execName, execDanger := execProgramMetadata(1)
	if execName != "GateExec" || execDanger["mode"] != "control" || execDanger["scope"] != "process" || execDanger["reversibility"] != "restart" {
		t.Fatalf("gate exec metadata = %s %+v", execName, execDanger)
	}
	fileName, fileDanger := fileProgramMetadata(1)
	if fileName != "GateFileOpen" || fileDanger["mode"] != "control" || fileDanger["scope"] != "filesystem" || fileDanger["reversibility"] != "restart" {
		t.Fatalf("standard file metadata = %s %+v", fileName, fileDanger)
	}
	for family, want := range map[uint16]string{2: "GateConnect4", 10: "GateConnect6"} {
		name, programDanger := connectProgramMetadata(1, family)
		if name != want || programDanger["mode"] != "control" || programDanger["scope"] != "network" || programDanger["reversibility"] != "restart" {
			t.Fatalf("standard connect family %d metadata = %s %+v", family, name, programDanger)
		}
	}
}

func TestExecMetadataDoesNotDependOnRecordedPath(t *testing.T) {
	name, programDanger := execProgramMetadata(1)
	if name != "GateExec" || programDanger["mode"] != "control" {
		t.Fatalf("gate event with an unreadable path would be mislabeled: %s %+v", name, programDanger)
	}
	name, programDanger = execProgramMetadata(0)
	if name != "OnExec" || programDanger["mode"] != "observe" {
		t.Fatalf("tracepoint event metadata = %s %+v", name, programDanger)
	}
}

func TestExecPayloadIgnoresFieldsNotWrittenByItsProducer(t *testing.T) {
	gate := bindings.ExecEvent{Pad: 1, ArgvTrunc: 3}
	copy(gate.Filename[:], "/usr/bin/go")
	copy(gate.ArgvHead[:], "stale argv")
	path, argv, pathTruncated, argvTruncated := execPayload(gate)
	if path != "" || argv != "" || !pathTruncated || argvTruncated {
		t.Fatalf("gate payload = path %q argv %q pathTruncated=%t argvTruncated=%t", path, argv, pathTruncated, argvTruncated)
	}

	trace := bindings.ExecEvent{Pad: 0, ArgvTrunc: 3}
	copy(trace.Filename[:], "stale path")
	copy(trace.ArgvHead[:], "go\x00test")
	path, argv, pathTruncated, argvTruncated = execPayload(trace)
	if path != "" || argv != "go test" || pathTruncated || !argvTruncated {
		t.Fatalf("trace payload = path %q argv %q pathTruncated=%t argvTruncated=%t", path, argv, pathTruncated, argvTruncated)
	}
}

func TestFilePayloadIgnoresPathWhenHelperFailed(t *testing.T) {
	raw := bindings.FileEvent{PathTrunc: 1}
	copy(raw.Path[:], "/stale/secret")
	path, truncated := filePayload(raw)
	if path != "" || !truncated {
		t.Fatalf("file payload = path %q truncated=%t", path, truncated)
	}

	raw.PathTrunc = 0
	path, truncated = filePayload(raw)
	if path != "/stale/secret" || truncated {
		t.Fatalf("file payload = path %q truncated=%t", path, truncated)
	}
}
