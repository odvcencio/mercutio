package deploycheck

import (
	"io"
	"os"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestCellEgressPoliciesExcludeProtectedNetworks(t *testing.T) {
	file, err := os.Open("../../deploy/manifests/mercutio.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
	checked := 0
	for {
		var policy networkingv1.NetworkPolicy
		if err := decoder.Decode(&policy); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if policy.Kind != "NetworkPolicy" || !strings.HasSuffix(policy.Name, "-standard-egress") && !strings.HasSuffix(policy.Name, "-open-egress") {
			continue
		}
		checked++
		if len(policy.Spec.Egress) != 1 || len(policy.Spec.Egress[0].To) != 2 {
			t.Fatalf("%s/%s must have one IPv4/IPv6 constrained egress rule: %+v", policy.Namespace, policy.Name, policy.Spec.Egress)
		}
		families := map[string]bool{}
		for _, peer := range policy.Spec.Egress[0].To {
			if peer.IPBlock == nil || len(peer.IPBlock.Except) == 0 {
				t.Fatalf("%s/%s has unconstrained egress peer %+v", policy.Namespace, policy.Name, peer)
			}
			families[peer.IPBlock.CIDR] = true
		}
		if !families["0.0.0.0/0"] || !families["::/0"] {
			t.Fatalf("%s/%s does not constrain both address families: %+v", policy.Namespace, policy.Name, families)
		}
	}
	if checked != 6 {
		t.Fatalf("checked %d profile egress policies, want 6", checked)
	}
}
