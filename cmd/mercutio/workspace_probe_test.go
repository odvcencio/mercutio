package main

import "testing"

func TestMountDeviceReportsStableNonzeroIdentity(t *testing.T) {
	first, err := mountDevice(t.TempDir())
	if err != nil || first == 0 {
		t.Fatalf("device=%d err=%v", first, err)
	}
	second, err := mountDevice("/tmp")
	if err != nil || second == 0 {
		t.Fatalf("tmp device=%d err=%v", second, err)
	}
}
