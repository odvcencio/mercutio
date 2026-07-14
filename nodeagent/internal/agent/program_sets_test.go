package agent

import "testing"

func TestExpectedProgramsSeparateOpenObservationFromControl(t *testing.T) {
	control := expectedPrograms("strict")
	if !programSetEqual(control, expectedPrograms("standard")) {
		t.Fatal("strict and standard must share the verified control program set")
	}
	open := expectedPrograms("open")
	for _, blocked := range []string{"GateExec", "GateFileOpen", "GateConnect4", "GateConnect6"} {
		if hasProgram(open, blocked) {
			t.Fatalf("open profile unexpectedly loads control program %s", blocked)
		}
	}
	for _, observed := range []string{"OnExec", "ObserveFileOpen", "ObserveConnect4", "ObserveConnect6"} {
		if !hasProgram(open, observed) {
			t.Fatalf("open profile is missing observation program %s", observed)
		}
	}
}
