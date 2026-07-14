package secrets

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesPersistenceVersionsAndDeletesPerCell(t *testing.T) {
	backend := NewKubernetesPersistence(fake.NewSimpleClientset(), "tests")
	broker := NewBrokerWithPersistence(backend)
	first, err := broker.Put("cell-1", "TOKEN", "first-value", "operator")
	if err != nil || first.Version != 1 {
		t.Fatalf("first=%+v %v", first, err)
	}
	second, err := broker.Put("cell-1", "TOKEN", "second-value", "operator")
	if err != nil || second.Version != 2 {
		t.Fatalf("second=%+v %v", second, err)
	}
	value, receipt, err := broker.Get("cell-1", "TOKEN", "operator")
	if err != nil || value != "second-value" || receipt.Version != 2 {
		t.Fatalf("get=%q %+v %v", value, receipt, err)
	}
	list, err := broker.List("cell-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Redacted == "second-value" {
		t.Fatalf("list=%+v", list)
	}
	broker.DeleteCell("cell-1")
	if _, _, err = broker.Get("cell-1", "TOKEN", "operator"); err == nil {
		t.Fatal("deleted cell secret remained")
	}
}
