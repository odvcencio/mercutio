package deploycheck

import (
	"encoding/json"
	"os"
	"testing"
)

func TestChartEnforcesSingleDurableControlPlaneWriter(t *testing.T) {
	data, err := os.ReadFile("../../deploy/helm/mercutio/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Type  string `json:"type"`
			Const int    `json:"const"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	replica := schema.Properties["replicaCount"]
	if replica.Type != "integer" || replica.Const != 1 {
		t.Fatalf("replicaCount schema=%+v", replica)
	}
	found := false
	for _, name := range schema.Required {
		found = found || name == "replicaCount"
	}
	if !found {
		t.Fatal("replicaCount is not required by the chart schema")
	}
}
