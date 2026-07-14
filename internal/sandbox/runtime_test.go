package sandbox

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestMemoryRuntimeLifecycle(t *testing.T) {
	runtime := NewMemoryRuntime()
	spec := Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Branch: "main", Profile: "strict"}
	pod, err := runtime.Ensure(context.Background(), spec)
	if err != nil || pod.Phase != PhaseRunning {
		t.Fatalf("Ensure = %+v, %v", pod, err)
	}
	if err := runtime.Delete(context.Background(), spec.CellID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err = runtime.Observe(context.Background(), spec.CellID); err != ErrNotFound {
		t.Fatalf("deleted pod remained observable: %v", err)
	}
}

func TestMemoryRuntimeRearmsWithoutRestart(t *testing.T) {
	runtime := NewMemoryRuntime()
	spec := Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Branch: "main", Profile: "standard"}
	before, err := runtime.Ensure(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Profile = "strict"
	after, err := runtime.Rearm(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != before.Name || !after.StartedAt.Equal(before.StartedAt) || after.Profile != "strict" || after.Phase != PhaseRunning {
		t.Fatalf("rearm replaced or stopped pod: before=%+v after=%+v", before, after)
	}
}

func TestKubernetesRuntimeRearmsPodMetadataInPlace(t *testing.T) {
	started := metav1.Now()
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "mercutio-cell-1", Namespace: "cells", UID: "stable-uid", CreationTimestamp: started, Labels: map[string]string{"mercutio.dev/cell-id": "cell-1", "mercutio.dev/profile": "standard"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells"})
	pod, err := runtime.Rearm(context.Background(), Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Profile: "strict", AttachToken: "attach", ArmToken: "arm"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Pods("cells").Get(context.Background(), "mercutio-cell-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if updated.UID != "stable-uid" || updated.Labels["mercutio.dev/profile"] != "strict" || updated.Annotations["mercutio.dev/policy-rearmed-at"] == "" || updated.Annotations["mercutio.dev/armed"] != "false" || pod.Phase != PhaseRunning {
		t.Fatalf("pod was not rearmed in place: runtime=%+v kubernetes=%+v", pod, updated)
	}
}

func TestKubernetesRuntimeRearmsAcrossProfileClassesInCurrentNamespace(t *testing.T) {
	started := metav1.Now()
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "mercutio-cell-1", Namespace: "cells-standard", UID: "stable-uid", CreationTimestamp: started, Labels: map[string]string{"mercutio.dev/cell-id": "cell-1", "mercutio.dev/profile": "standard", "mercutio.dev/network-profile": "standard"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{
		Namespace: "control",
		ClassNamespaces: map[string]string{
			"strict": "cells-strict", "standard": "cells-standard", "open": "cells-open",
		},
	})
	pod, err := runtime.Rearm(context.Background(), Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Profile: "strict", AttachToken: "attach", ArmToken: "arm"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Pods("cells-standard").Get(context.Background(), "mercutio-cell-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if updated.UID != "stable-uid" || updated.Labels["mercutio.dev/profile"] != "strict" || updated.Labels["mercutio.dev/network-profile"] != "standard" || pod.Profile != "strict" {
		t.Fatalf("class-changing re-arm did not preserve the live pod: runtime=%+v kubernetes=%+v", pod, updated)
	}
	if err := runtime.FinalizePolicy(context.Background(), "cell-1", "strict", updated.Annotations["mercutio.dev/profile-digest"]); err != nil {
		t.Fatal(err)
	}
	updated, err = client.CoreV1().Pods("cells-standard").Get(context.Background(), "mercutio-cell-1", metav1.GetOptions{})
	if err != nil || updated.Labels["mercutio.dev/network-profile"] != "strict" || updated.Annotations["mercutio.dev/armed"] != "true" {
		t.Fatalf("network profile was not finalized after kernel arm: profile=%q err=%v", updated.Labels["mercutio.dev/network-profile"], err)
	}
	pods, err := client.CoreV1().Pods("cells-strict").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(pods.Items) != 0 {
		t.Fatalf("class-changing re-arm created a replacement pod: pods=%+v err=%v", pods.Items, err)
	}
}

func TestKubernetesRuntimeListsOnlyManagedPods(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "cells", Labels: map[string]string{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": "cell-orphan"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "cells", Labels: map[string]string{"app": "other"}}},
	)
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells"})
	pods, err := runtime.Managed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 || pods[0].CellID != "cell-orphan" {
		t.Fatalf("managed pods = %+v", pods)
	}
}

func TestKubernetesRuntimeRejectsAmbiguousDuplicateCellPods(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "duplicate-a", Namespace: "cells", Labels: map[string]string{"mercutio.dev/cell-id": "cell-a"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "duplicate-b", Namespace: "cells", Labels: map[string]string{"mercutio.dev/cell-id": "cell-a"}}},
	)
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells"})
	if _, err := runtime.Observe(context.Background(), "cell-a"); err == nil {
		t.Fatal("duplicate Pods were accepted during observation")
	}
	if _, err := runtime.Ensure(context.Background(), Spec{CellID: "cell-a", RepoURL: "https://example.test/repo", Profile: "standard", AttachToken: "attach", ArmToken: "arm"}); err == nil {
		t.Fatal("duplicate Pods were accepted during ensure")
	}
}

func TestKubernetesRuntimeNodeCellsReturnsMinimalEnforcementMetadata(t *testing.T) {
	manifest := `{"profile":"strict","profileDigest":"sha256:profile","egress":["control:8443"],"programs":["GateExec"]}`
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "cells", UID: "pod-uid", Labels: map[string]string{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": "cell-a", "mercutio.dev/profile": "strict"}, Annotations: map[string]string{"mercutio.dev/capability-manifest": manifest}}, Spec: corev1.PodSpec{NodeName: "node-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-node", Namespace: "cells", Labels: map[string]string{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": "cell-b"}}, Spec: corev1.PodSpec{NodeName: "node-b"}},
	)
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells"})
	cells, err := runtime.NodeCells(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].ID != "cell-a" || cells[0].NodeID != "node-a" || cells[0].PodUID != "pod-uid" || cells[0].ProfileDigest != "sha256:profile" || len(cells[0].Programs) != 1 {
		t.Fatalf("cells=%+v", cells)
	}
}

func TestKubernetesRuntimeDeletesEveryCellObjectBySharedSelector(t *testing.T) {
	labels := func(cellID string) map[string]string {
		return map[string]string{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": cellID}
	}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "renamed-pod", Namespace: "cells", Labels: labels("cell-a")}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-pod", Namespace: "cells", Labels: labels("cell-b")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "nonstandard-secret-name", Namespace: "cells", Labels: labels("cell-a")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "other-secret", Namespace: "cells", Labels: labels("cell-b")}},
	)
	cellObject := func(name, cellID string) *unstructured.Unstructured {
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "mercutio.dev/v1alpha1", "kind": "Cell", "metadata": map[string]any{"name": name, "namespace": "cells"}}}
		object.SetLabels(labels(cellID))
		return object
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(k8sruntime.NewScheme(), map[schema.GroupVersionResource]string{cellResource: "CellList"}, cellObject("renamed-cell-resource", "cell-a"), cellObject("other-cell-resource", "cell-b"))
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells", DynamicClient: dynamicClient})
	for i := 0; i < 2; i++ {
		if err := runtime.Delete(t.Context(), "cell-a"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	wantSelector := "mercutio.dev/cell-id=cell-a,mercutio.dev/managed=true"
	assertSelectorDeletes := func(actions []k8stesting.Action, resources map[string]int) {
		t.Helper()
		for _, action := range actions {
			if action.GetVerb() != "delete-collection" {
				continue
			}
			deletion, ok := action.(k8stesting.DeleteCollectionAction)
			if !ok || deletion.GetListRestrictions().Labels.String() != wantSelector {
				t.Fatalf("delete action lacks shared selector: %#v", action)
			}
			resources[action.GetResource().Resource]++
		}
	}
	resources := map[string]int{}
	assertSelectorDeletes(client.Actions(), resources)
	assertSelectorDeletes(dynamicClient.Actions(), resources)
	if resources["pods"] != 2 || resources["secrets"] != 2 || resources["cells"] != 2 {
		t.Fatalf("selector deletion counts=%v", resources)
	}
}

func TestKubernetesRuntimeRendersTemplate(t *testing.T) {
	dynamicClient := dynamicfake.NewSimpleDynamicClient(k8sruntime.NewScheme())
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "template", Namespace: "cells"},
		Data: map[string]string{"pod-template.yaml": `apiVersion: v1
kind: Pod
metadata:
  labels:
    mercutio.dev/cell-id: "{{CELL_ID}}"
spec:
  automountServiceAccountToken: false
  activeDeadlineSeconds: 3600
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  initContainers:
    - name: armgate
      image: armgate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext: &restricted
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities: {drop: ["ALL"]}
      env:
        - name: MERCUTIO_ARM_TOKEN
          valueFrom:
            secretKeyRef:
              name: "{{ARM_SECRET_REF}}"
              key: token
      volumeMounts:
        - name: workspace
          mountPath: /workspace
          readOnly: true
  containers:
    - name: agent
      image: agent@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      securityContext: *restricted
      env:
        - name: MERCUTIO_ATTACH_SOCKET
          value: /run/mercutio/attach.sock
    - name: attach
      image: attach@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      securityContext: *restricted
      env:
        - name: MERCUTIO_ATTACH_TOKEN
          valueFrom:
            secretKeyRef:
              name: "{{ATTACH_SECRET_REF}}"
              key: token
  volumes:
    - name: workspace
      emptyDir: {}
`},
	})
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells", TemplateName: "template", DynamicClient: dynamicClient})
	pod, err := runtime.Ensure(context.Background(), Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Profile: "standard", AttachToken: "secret-token", ArmToken: "arm-token"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if pod.Name != "mercutio-cell-1" || pod.Phase != PhasePending {
		t.Fatalf("pod = %+v", pod)
	}
	created, err := client.CoreV1().Pods("cells").Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil || created.Spec.Containers[0].Env[0].Value != "/run/mercutio/attach.sock" {
		t.Fatalf("created pod = %+v, err=%v", created, err)
	}
	if len(created.Spec.Containers[0].EnvFrom) != 0 || len(created.Spec.Containers) != 2 {
		t.Fatalf("agent secret exposure or missing attach sidecar: %+v", created.Spec.Containers)
	}
	if created.Annotations["mercutio.dev/profile-digest"] == "" {
		t.Fatal("sandbox pod has no profile digest annotation")
	}
	secret, err := client.CoreV1().Secrets("cells").Get(context.Background(), "mercutio-cell-1-attach", metav1.GetOptions{})
	if err != nil || string(secret.Data["token"]) != "secret-token" && secret.StringData["token"] != "secret-token" {
		t.Fatalf("secret = %+v, err=%v", secret, err)
	}
	if secret.Annotations["mercutio.dev/profile-digest"] == "" {
		t.Fatal("attach Secret has no profile digest annotation")
	}
	armSecret, err := client.CoreV1().Secrets("cells").Get(context.Background(), "mercutio-cell-1-arm", metav1.GetOptions{})
	if err != nil || string(armSecret.Data["token"]) != "arm-token" && armSecret.StringData["token"] != "arm-token" {
		t.Fatalf("arm secret = %+v, err=%v", armSecret, err)
	}
	if created.Spec.AutomountServiceAccountToken == nil || *created.Spec.AutomountServiceAccountToken {
		t.Fatal("service-account token was not disabled")
	}
	cell, err := dynamicClient.Resource(cellResource).Namespace("cells").Get(context.Background(), "cell-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if profile, _, _ := unstructured.NestedString(cell.Object, "spec", "profile"); profile != "standard" {
		t.Fatalf("Cell resource profile=%q object=%+v", profile, cell.Object)
	}
	if phase, _, _ := unstructured.NestedString(cell.Object, "status", "phase"); phase != "pending" {
		t.Fatalf("Cell resource phase=%q object=%+v", phase, cell.Object)
	}
	if cell.GetAnnotations()["mercutio.dev/profile-digest"] == "" {
		t.Fatal("Cell resource has no profile digest annotation")
	}
	if err := runtime.FinalizePolicy(context.Background(), "cell-1", "standard", created.Annotations["mercutio.dev/profile-digest"]); err != nil {
		t.Fatalf("finalize policy: %v", err)
	}
	cell, err = dynamicClient.Resource(cellResource).Namespace("cells").Get(context.Background(), "cell-1", metav1.GetOptions{})
	if armed, _, _ := unstructured.NestedBool(cell.Object, "status", "armed"); err != nil || !armed {
		t.Fatalf("Cell resource did not record armed status: armed=%v err=%v object=%+v", armed, err, cell.Object)
	}
	if _, err := runtime.Ensure(context.Background(), Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", Profile: "standard", AttachToken: "rotated-attach", ArmToken: "rotated-arm"}); err != nil {
		t.Fatalf("reconcile existing sandbox: %v", err)
	}
	secret, _ = client.CoreV1().Secrets("cells").Get(context.Background(), "mercutio-cell-1-attach", metav1.GetOptions{})
	armSecret, _ = client.CoreV1().Secrets("cells").Get(context.Background(), "mercutio-cell-1-arm", metav1.GetOptions{})
	if string(secret.Data["token"]) != "rotated-attach" || string(armSecret.Data["token"]) != "rotated-arm" {
		t.Fatalf("existing sandbox credentials were not reconciled: attach=%q arm=%q", secret.Data["token"], armSecret.Data["token"])
	}
}

func TestKubernetesRuntimeRejectsAgentTokenInjection(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "template", Namespace: "cells"},
		Data: map[string]string{"pod-template.yaml": `apiVersion: v1
kind: Pod
spec:
  automountServiceAccountToken: false
  activeDeadlineSeconds: 60
  initContainers:
    - name: armgate
      image: armgate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  containers:
    - name: agent
      image: agent@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      env:
        - name: MERCUTIO_ATTACH_TOKEN
          value: exposed
    - name: attach
      image: attach@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`},
	})
	runtime := NewKubernetesRuntime(client, KubernetesRuntimeOptions{Namespace: "cells", TemplateName: "template"})
	if _, err := runtime.Ensure(context.Background(), Spec{CellID: "cell-1", RepoURL: "https://github.com/example/project", AttachToken: "token", ArmToken: "arm-token"}); err == nil {
		t.Fatal("insecure sandbox template was accepted")
	}
}
