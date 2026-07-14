package sandbox

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
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
	pod, err = runtime.Observe(context.Background(), spec.CellID)
	if err != nil || pod.Phase != PhaseStopped {
		t.Fatalf("Observe = %+v, %v", pod, err)
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
	if updated.UID != "stable-uid" || updated.Labels["mercutio.dev/profile"] != "strict" || updated.Annotations["mercutio.dev/policy-rearmed-at"] == "" || pod.Phase != PhaseRunning {
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
	if err != nil || updated.Labels["mercutio.dev/network-profile"] != "strict" {
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
