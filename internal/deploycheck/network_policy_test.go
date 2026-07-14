package deploycheck

import (
	"io"
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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

func TestNodeAgentUsesHostProcessMetadataWithoutCellVolumeMounts(t *testing.T) {
	file, err := os.Open("../../deploy/manifests/mercutio.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
	checked := 0
	for {
		var daemonSet appsv1.DaemonSet
		if err := decoder.Decode(&daemonSet); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if daemonSet.Kind != "DaemonSet" || daemonSet.Spec.Template.Labels["app.kubernetes.io/component"] != "nodeagent" {
			continue
		}
		checked++
		if !daemonSet.Spec.Template.Spec.HostPID {
			t.Fatal("nodeagent cannot resolve host cgroup processes without hostPID")
		}
		for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
			if volume.HostPath != nil && strings.HasPrefix(volume.HostPath.Path, "/var/lib/kubelet") {
				t.Fatalf("nodeagent mounts a cell-volume path: %s", volume.HostPath.Path)
			}
		}
	}
	if checked != 1 {
		t.Fatalf("checked %d nodeagent daemonsets, want 1", checked)
	}
}

func TestNodeAgentHasNoKubernetesCredentialsOrAPIServerEgress(t *testing.T) {
	data, err := os.ReadFile("../../deploy/manifests/mercutio.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	if strings.Contains(manifest, "name: kube-api-access") || strings.Contains(manifest, "kind: ClusterRole\nmetadata:\n  name: mercutio-nodeagent") || strings.Contains(manifest, "kind: ClusterRoleBinding\nmetadata:\n  name: mercutio-nodeagent") {
		t.Fatal("nodeagent manifest grants Kubernetes API credentials or RBAC")
	}

	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096)
	checked := 0
	for {
		var policy networkingv1.NetworkPolicy
		if err := decoder.Decode(&policy); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if policy.Kind != "NetworkPolicy" || !strings.HasSuffix(policy.Name, "-nodeagent-egress") {
			continue
		}
		checked++
		if len(policy.Spec.Egress) != 2 {
			t.Fatalf("nodeagent must egress only to control plane and DNS: %+v", policy.Spec.Egress)
		}
		for _, rule := range policy.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					t.Fatalf("nodeagent has direct IP egress: %+v", peer.IPBlock)
				}
			}
		}
	}
	if checked != 1 {
		t.Fatalf("checked %d nodeagent egress policies, want 1", checked)
	}
}
