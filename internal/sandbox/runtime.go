package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"m31labs.dev/mercutio/internal/policy"
)

var ErrNotFound = errors.New("sandbox not found")

type Spec struct {
	CellID      string
	RepoURL     string
	Branch      string
	Profile     string
	HubURL      string
	AttachToken string
	ArmToken    string
}

type PodPhase string

const (
	PhasePending PodPhase = "pending"
	PhaseRunning PodPhase = "running"
	PhaseStopped PodPhase = "stopped"
	PhaseFailed  PodPhase = "failed"
)

type Pod struct {
	Name           string    `json:"name"`
	CellID         string    `json:"cellID"`
	Phase          PodPhase  `json:"phase"`
	RepoURL        string    `json:"repoURL"`
	Branch         string    `json:"branch"`
	Profile        string    `json:"profile"`
	StartedAt      time.Time `json:"startedAt,omitempty"`
	LastTransition time.Time `json:"lastTransition,omitempty"`
	Failure        string    `json:"failure,omitempty"`
	Armed          bool      `json:"armed"`
}

// Runtime is the only boundary the control plane needs to reconcile a cell.
// The memory implementation keeps local development deterministic; the
// Kubernetes implementation consumes the pod template installed by the Helm
// chart and reports the same lifecycle shape.
type Runtime interface {
	Ensure(context.Context, Spec) (Pod, error)
	Observe(context.Context, string) (Pod, error)
	Managed(context.Context) ([]Pod, error)
	Rearm(context.Context, Spec) (Pod, error)
	Delete(context.Context, string) error
}

type MountDevices struct {
	Workspace uint64 `json:"workspace"`
	Scratch   uint64 `json:"scratch"`
	Runtime   uint64 `json:"runtime"`
}

type MountDeviceRecorder interface {
	RecordMountDevices(context.Context, string, MountDevices) error
}

// PolicyFinalizer promotes network enforcement only after the Node Agent has
// confirmed that the matching kernel profile is live.
type PolicyFinalizer interface {
	FinalizePolicy(context.Context, string, string, string) error
}

type MemoryRuntime struct {
	mu   sync.RWMutex
	pods map[string]Pod
}

func NewMemoryRuntime() *MemoryRuntime {
	return &MemoryRuntime{pods: make(map[string]Pod)}
}

func (r *MemoryRuntime) Ensure(_ context.Context, spec Spec) (Pod, error) {
	if err := validateSpec(spec); err != nil {
		return Pod{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if pod, ok := r.pods[spec.CellID]; ok {
		pod.Phase = PhaseRunning
		pod.LastTransition = time.Now().UTC()
		pod.Failure = ""
		r.pods[spec.CellID] = pod
		return pod, nil
	}
	now := time.Now().UTC()
	pod := Pod{
		Name:           "mercutio-" + dnsName(spec.CellID),
		CellID:         spec.CellID,
		Phase:          PhaseRunning,
		RepoURL:        spec.RepoURL,
		Branch:         defaultValue(spec.Branch, "main"),
		Profile:        defaultValue(spec.Profile, "standard"),
		StartedAt:      now,
		LastTransition: now,
		Armed:          true,
	}
	r.pods[spec.CellID] = pod
	return pod, nil
}

func (r *MemoryRuntime) Observe(_ context.Context, cellID string) (Pod, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pod, ok := r.pods[cellID]
	if !ok {
		return Pod{}, ErrNotFound
	}
	return pod, nil
}

func (r *MemoryRuntime) Managed(_ context.Context) ([]Pod, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pods := make([]Pod, 0, len(r.pods))
	for _, pod := range r.pods {
		pods = append(pods, pod)
	}
	return pods, nil
}

func (r *MemoryRuntime) Rearm(_ context.Context, spec Spec) (Pod, error) {
	if err := validateSpec(spec); err != nil {
		return Pod{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pod, ok := r.pods[spec.CellID]
	if !ok {
		return Pod{}, ErrNotFound
	}
	pod.Profile = defaultValue(spec.Profile, "standard")
	pod.LastTransition = time.Now().UTC()
	r.pods[spec.CellID] = pod
	return pod, nil
}

func (r *MemoryRuntime) Delete(_ context.Context, cellID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pod, ok := r.pods[cellID]; ok {
		pod.Phase = PhaseStopped
		pod.LastTransition = time.Now().UTC()
		r.pods[cellID] = pod
	}
	return nil
}

func (r *MemoryRuntime) RecordMountDevices(_ context.Context, _ string, _ MountDevices) error {
	return nil
}

func (r *MemoryRuntime) FinalizePolicy(_ context.Context, cellID, profile, _ string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pod, ok := r.pods[cellID]
	if !ok {
		return ErrNotFound
	}
	if pod.Profile != defaultValue(profile, "standard") {
		return fmt.Errorf("sandbox desired profile changed before finalization")
	}
	return nil
}

type KubernetesRuntimeOptions struct {
	Namespace       string
	ClassNamespaces map[string]string
	TemplateName    string
	ServiceAccount  string
	Client          kubernetes.Interface
	DynamicClient   dynamic.Interface
}

type KubernetesRuntime struct {
	client          kubernetes.Interface
	dynamic         dynamic.Interface
	namespace       string
	templateName    string
	serviceAccount  string
	classNamespaces map[string]string
}

func NewKubernetesRuntime(client kubernetes.Interface, opts KubernetesRuntimeOptions) *KubernetesRuntime {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.TemplateName == "" {
		opts.TemplateName = "mercutio-sandbox-template"
	}
	return &KubernetesRuntime{client: client, dynamic: opts.DynamicClient, namespace: opts.Namespace, templateName: opts.TemplateName, serviceAccount: opts.ServiceAccount, classNamespaces: opts.ClassNamespaces}
}

func (r *KubernetesRuntime) namespaceFor(profile string) string {
	profile = defaultValue(profile, "standard")
	if namespace := strings.TrimSpace(r.classNamespaces[profile]); namespace != "" {
		return namespace
	}
	return r.namespace
}

func (r *KubernetesRuntime) cellNamespaces() []string {
	seen := map[string]bool{}
	result := make([]string, 0, 3)
	for _, profile := range []string{"strict", "standard", "open"} {
		namespace := r.namespaceFor(profile)
		if !seen[namespace] {
			seen[namespace] = true
			result = append(result, namespace)
		}
	}
	return result
}

func NewKubernetesRuntimeFromEnv() (*KubernetesRuntime, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return nil, fmt.Errorf("resolve kubeconfig: %w", err)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		loading := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{},
		)
		config, err = loading.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("load Kubernetes config: %w", err)
		}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes dynamic client: %w", err)
	}
	return NewKubernetesRuntime(client, KubernetesRuntimeOptions{
		Namespace:       defaultValue(os.Getenv("MERCUTIO_NAMESPACE"), "default"),
		ClassNamespaces: map[string]string{"strict": os.Getenv("MERCUTIO_STRICT_NAMESPACE"), "standard": os.Getenv("MERCUTIO_STANDARD_NAMESPACE"), "open": os.Getenv("MERCUTIO_OPEN_NAMESPACE")},
		TemplateName:    defaultValue(os.Getenv("MERCUTIO_SANDBOX_TEMPLATE"), "mercutio-sandbox-template"),
		ServiceAccount:  os.Getenv("MERCUTIO_SANDBOX_SERVICE_ACCOUNT"),
		DynamicClient:   dynamicClient,
	}), nil
}

var cellResource = schema.GroupVersionResource{Group: "mercutio.dev", Version: "v1alpha1", Resource: "cells"}

func (r *KubernetesRuntime) Ensure(ctx context.Context, spec Spec) (Pod, error) {
	if r == nil || r.client == nil {
		return Pod{}, fmt.Errorf("Kubernetes sandbox runtime is not configured")
	}
	if err := validateSpec(spec); err != nil {
		return Pod{}, err
	}
	namespace := r.namespaceFor(spec.Profile)
	manifest, err := policy.Resolve(spec.Profile)
	if err != nil {
		return Pod{}, err
	}
	if err := r.ensureAttachCredential(ctx, namespace, spec.CellID, spec.AttachToken, manifest.ProfileDigest); err != nil {
		return Pod{}, err
	}
	if err := r.ensureArmCredential(ctx, namespace, spec.CellID, spec.ArmToken, manifest.ProfileDigest); err != nil {
		return Pod{}, err
	}
	if err := r.ensureCellResource(ctx, namespace, spec); err != nil {
		return Pod{}, err
	}
	pods, err := r.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "mercutio.dev/cell-id=" + spec.CellID})
	if err != nil {
		return Pod{}, fmt.Errorf("list sandbox pods: %w", err)
	}
	if len(pods.Items) > 0 {
		result := podFromKubernetes(pods.Items[0], spec)
		_ = r.updateCellStatus(ctx, namespace, result, pods.Items[0].Spec.NodeName)
		return result, nil
	}
	pod, err := r.renderTemplate(ctx, namespace, spec)
	if err != nil {
		return Pod{}, err
	}
	created, err := r.client.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return Pod{}, fmt.Errorf("create sandbox pod: %w", err)
	}
	result := podFromKubernetes(*created, spec)
	_ = r.updateCellStatus(ctx, namespace, result, created.Spec.NodeName)
	return result, nil
}

func (r *KubernetesRuntime) Observe(ctx context.Context, cellID string) (Pod, error) {
	if r == nil || r.client == nil {
		return Pod{}, fmt.Errorf("Kubernetes sandbox runtime is not configured")
	}
	for _, namespace := range r.cellNamespaces() {
		pods, err := r.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "mercutio.dev/cell-id=" + cellID})
		if err != nil {
			return Pod{}, fmt.Errorf("observe sandbox pods: %w", err)
		}
		if len(pods.Items) > 0 {
			return podFromKubernetes(pods.Items[0], Spec{CellID: cellID}), nil
		}
	}
	return Pod{}, ErrNotFound
}

func (r *KubernetesRuntime) Managed(ctx context.Context) ([]Pod, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("Kubernetes sandbox runtime is not configured")
	}
	var pods []Pod
	for _, namespace := range r.cellNamespaces() {
		items, err := r.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "mercutio.dev/managed=true"})
		if err != nil {
			return nil, fmt.Errorf("list managed sandbox pods: %w", err)
		}
		for _, item := range items.Items {
			pods = append(pods, podFromKubernetes(item, Spec{CellID: item.Labels["mercutio.dev/cell-id"]}))
		}
	}
	return pods, nil
}

// Rearm publishes the desired kernel profile on the live pod without replacing
// it. Network policy remains on the previously armed profile until the matching
// Node Agent receipt calls FinalizePolicy.
func (r *KubernetesRuntime) Rearm(ctx context.Context, spec Spec) (Pod, error) {
	if r == nil || r.client == nil {
		return Pod{}, fmt.Errorf("Kubernetes sandbox runtime is not configured")
	}
	if err := validateSpec(spec); err != nil {
		return Pod{}, err
	}
	namespace, live, err := r.findCellPod(ctx, spec.CellID)
	if err != nil {
		return Pod{}, fmt.Errorf("find sandbox pod for re-arm: %w", err)
	}
	manifest, err := policy.Resolve(spec.Profile)
	if err != nil {
		return Pod{}, fmt.Errorf("resolve re-arm policy: %w", err)
	}
	if err := r.ensureAttachCredential(ctx, namespace, spec.CellID, spec.AttachToken, manifest.ProfileDigest); err != nil {
		return Pod{}, err
	}
	if err := r.ensureArmCredential(ctx, namespace, spec.CellID, spec.ArmToken, manifest.ProfileDigest); err != nil {
		return Pod{}, err
	}
	if err := r.ensureCellResource(ctx, namespace, spec); err != nil {
		return Pod{}, err
	}
	pod := live
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Labels["mercutio.dev/profile"] = defaultValue(spec.Profile, "standard")
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return Pod{}, fmt.Errorf("encode re-arm policy: %w", err)
	}
	pod.Annotations["mercutio.dev/capability-manifest"] = string(encoded)
	pod.Annotations["mercutio.dev/profile-digest"] = manifest.ProfileDigest
	pod.Annotations["mercutio.dev/policy-rearmed-at"] = time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := r.client.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		return Pod{}, fmt.Errorf("re-arm sandbox pod %q: %w", pod.Name, err)
	}
	result := podFromKubernetes(*updated, spec)
	_ = r.updateCellStatus(ctx, namespace, result, updated.Spec.NodeName)
	return result, nil
}

func (r *KubernetesRuntime) FinalizePolicy(ctx context.Context, cellID, profile, profileDigest string) error {
	namespace, pod, err := r.findCellPod(ctx, cellID)
	if err != nil {
		return err
	}
	profile = defaultValue(profile, "standard")
	if pod.Labels["mercutio.dev/profile"] != profile || pod.Annotations["mercutio.dev/profile-digest"] != profileDigest {
		return fmt.Errorf("sandbox desired policy changed before network finalization")
	}
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels["mercutio.dev/network-profile"] = profile
	if _, err := r.client.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("finalize sandbox network profile: %w", err)
	}
	return nil
}

func (r *KubernetesRuntime) findCellPod(ctx context.Context, cellID string) (string, *corev1.Pod, error) {
	var namespace string
	var live *corev1.Pod
	for _, candidate := range r.cellNamespaces() {
		pods, err := r.client.CoreV1().Pods(candidate).List(ctx, metav1.ListOptions{LabelSelector: "mercutio.dev/cell-id=" + cellID})
		if err != nil {
			return "", nil, fmt.Errorf("list sandbox pods in %s: %w", candidate, err)
		}
		for i := range pods.Items {
			if live != nil {
				return "", nil, fmt.Errorf("multiple live sandbox pods found for cell %q", cellID)
			}
			namespace = candidate
			live = pods.Items[i].DeepCopy()
		}
	}
	if live == nil {
		return "", nil, ErrNotFound
	}
	return namespace, live, nil
}

func (r *KubernetesRuntime) Delete(ctx context.Context, cellID string) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("Kubernetes sandbox runtime is not configured")
	}
	selector := "mercutio.dev/managed=true,mercutio.dev/cell-id=" + cellID
	for _, namespace := range r.cellNamespaces() {
		if err := r.client.CoreV1().Pods(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: selector}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete sandbox pod collection: %w", err)
		}
		for _, purpose := range []string{"attach", "arm"} {
			if err := r.client.CoreV1().Secrets(namespace).Delete(ctx, credentialSecretRefName(cellID, purpose), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete sandbox %s credential: %w", purpose, err)
			}
		}
		if r.dynamic != nil {
			if err := r.dynamic.Resource(cellResource).Namespace(namespace).Delete(ctx, dnsName(cellID), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete Cell resource: %w", err)
			}
		}
	}
	return nil
}

func (r *KubernetesRuntime) RecordMountDevices(ctx context.Context, cellID string, devices MountDevices) error {
	for _, namespace := range r.cellNamespaces() {
		pods, err := r.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "mercutio.dev/cell-id=" + cellID})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			continue
		}
		pod := pods.Items[0].DeepCopy()
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations["mercutio.dev/workspace-device"] = fmt.Sprint(devices.Workspace)
		pod.Annotations["mercutio.dev/scratch-device"] = fmt.Sprint(devices.Scratch)
		pod.Annotations["mercutio.dev/runtime-device"] = fmt.Sprint(devices.Runtime)
		_, err = r.client.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{})
		return err
	}
	return ErrNotFound
}

func (r *KubernetesRuntime) ensureCellResource(ctx context.Context, namespace string, spec Spec) error {
	if r.dynamic == nil {
		return nil
	}
	manifest, err := policy.Resolve(spec.Profile)
	if err != nil {
		return err
	}
	resources := r.dynamic.Resource(cellResource).Namespace(namespace)
	name := dnsName(spec.CellID)
	current, err := resources.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = resources.Create(ctx, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "mercutio.dev/v1alpha1",
			"kind":       "Cell",
			"metadata":   map[string]any{"name": name, "labels": map[string]any{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": spec.CellID}, "annotations": map[string]any{"mercutio.dev/profile-digest": manifest.ProfileDigest}},
			"spec":       map[string]any{"cellID": spec.CellID, "repoURL": spec.RepoURL, "branch": defaultValue(spec.Branch, "main"), "profile": defaultValue(spec.Profile, "standard"), "profileDigest": manifest.ProfileDigest, "podTemplateRef": r.templateName},
		}}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create Cell resource: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Cell resource: %w", err)
	}
	if err := unstructured.SetNestedField(current.Object, spec.RepoURL, "spec", "repoURL"); err != nil {
		return err
	}
	_ = unstructured.SetNestedField(current.Object, defaultValue(spec.Branch, "main"), "spec", "branch")
	_ = unstructured.SetNestedField(current.Object, defaultValue(spec.Profile, "standard"), "spec", "profile")
	_ = unstructured.SetNestedField(current.Object, manifest.ProfileDigest, "spec", "profileDigest")
	_ = unstructured.SetNestedField(current.Object, r.templateName, "spec", "podTemplateRef")
	if current.GetAnnotations() == nil {
		current.SetAnnotations(map[string]string{})
	}
	annotations := current.GetAnnotations()
	annotations["mercutio.dev/profile-digest"] = manifest.ProfileDigest
	current.SetAnnotations(annotations)
	if _, err := resources.Update(ctx, current, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update Cell resource: %w", err)
	}
	return nil
}

func (r *KubernetesRuntime) updateCellStatus(ctx context.Context, namespace string, pod Pod, nodeName string) error {
	if r.dynamic == nil {
		return nil
	}
	resources := r.dynamic.Resource(cellResource).Namespace(namespace)
	current, err := resources.Get(ctx, dnsName(pod.CellID), metav1.GetOptions{})
	if err != nil {
		return err
	}
	status := map[string]any{
		"phase": string(pod.Phase), "podName": pod.Name, "nodeName": nodeName, "armed": pod.Armed,
		"observedGeneration": current.GetGeneration(), "lastTransitionTime": pod.LastTransition.UTC().Format(time.RFC3339Nano),
	}
	if err := unstructured.SetNestedMap(current.Object, status, "status"); err != nil {
		return err
	}
	_, err = resources.UpdateStatus(ctx, current, metav1.UpdateOptions{})
	return err
}

func (r *KubernetesRuntime) ensureAttachCredential(ctx context.Context, namespace, cellID, token, profileDigest string) error {
	return r.ensureCredential(ctx, namespace, cellID, token, "attach", profileDigest)
}

func (r *KubernetesRuntime) ensureArmCredential(ctx context.Context, namespace, cellID, token, profileDigest string) error {
	return r.ensureCredential(ctx, namespace, cellID, token, "arm", profileDigest)
}

func (r *KubernetesRuntime) ensureCredential(ctx context.Context, namespace, cellID, token, purpose, profileDigest string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("sandbox %s credential is required", purpose)
	}
	name := credentialSecretRefName(cellID, purpose)
	secret, err := r.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = r.client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"mercutio.dev/managed": "true", "mercutio.dev/cell-id": cellID, "mercutio.dev/purpose": purpose}, Annotations: map[string]string{"mercutio.dev/profile-digest": profileDigest}},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"token": token},
		}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create sandbox %s credential: %w", purpose, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get sandbox %s credential: %w", purpose, err)
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data["token"] = []byte(token)
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations["mercutio.dev/profile-digest"] = profileDigest
	if _, err := r.client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update sandbox %s credential: %w", purpose, err)
	}
	return nil
}

func (r *KubernetesRuntime) renderTemplate(ctx context.Context, namespace string, spec Spec) (*corev1.Pod, error) {
	manifest, _ := policy.Resolve(spec.Profile)
	template, err := r.client.CoreV1().ConfigMaps(r.namespace).Get(ctx, r.templateName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get sandbox template %q: %w", r.templateName, err)
	}
	raw := template.Data["pod-template.yaml"]
	if raw == "" {
		return nil, fmt.Errorf("sandbox template %q has no pod-template.yaml", r.templateName)
	}
	raw = strings.NewReplacer(
		"{{CELL_ID}}", spec.CellID,
		"{{REPO_URL}}", spec.RepoURL,
		"{{BRANCH}}", defaultValue(spec.Branch, "main"),
		"{{HUB_URL}}", spec.HubURL,
		"{{ATTACH_SECRET_REF}}", attachSecretRefName(spec.CellID),
		"{{ARM_SECRET_REF}}", credentialSecretRefName(spec.CellID, "arm"),
		"{{PROFILE}}", defaultValue(spec.Profile, "standard"),
	).Replace(raw)
	var pod corev1.Pod
	if err := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(raw), 4096).Decode(&pod); err != nil {
		return nil, fmt.Errorf("decode sandbox template: %w", err)
	}
	now := time.Now().UTC()
	pod.Namespace = namespace
	pod.Name = "mercutio-" + dnsName(spec.CellID)
	pod.GenerateName = ""
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels["mercutio.dev/managed"] = "true"
	pod.Labels["mercutio.dev/cell-id"] = spec.CellID
	pod.Labels["mercutio.dev/profile"] = defaultValue(spec.Profile, "standard")
	pod.Labels["mercutio.dev/network-profile"] = defaultValue(spec.Profile, "standard")
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	if encoded, err := json.Marshal(manifest); err == nil {
		pod.Annotations["mercutio.dev/capability-manifest"] = string(encoded)
	}
	pod.Annotations["mercutio.dev/profile-digest"] = manifest.ProfileDigest
	pod.Annotations["mercutio.dev/repo-url"] = spec.RepoURL
	pod.Annotations["mercutio.dev/branch"] = defaultValue(spec.Branch, "main")
	if r.serviceAccount != "" {
		pod.Spec.ServiceAccountName = r.serviceAccount
	}
	if err := validateRenderedPod(&pod); err != nil {
		return nil, err
	}
	if pod.CreationTimestamp.IsZero() {
		pod.CreationTimestamp = metav1.NewTime(now)
	}
	return &pod, nil
}

func validateRenderedPod(pod *corev1.Pod) error {
	if pod == nil {
		return fmt.Errorf("sandbox pod is required")
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return fmt.Errorf("sandbox pod must disable service-account token mounting")
	}
	if pod.Spec.ActiveDeadlineSeconds == nil || *pod.Spec.ActiveDeadlineSeconds <= 0 {
		return fmt.Errorf("sandbox pod requires a positive active deadline")
	}
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		return fmt.Errorf("sandbox pod may not use host namespaces")
	}
	armgate := false
	for _, container := range pod.Spec.InitContainers {
		if container.Name == "armgate" {
			armgate = true
		}
		if err := validateContainer(container, container.Name == "armgate"); err != nil {
			return fmt.Errorf("init container %s: %w", container.Name, err)
		}
		if container.Name == "armgate" && !hasExactSecretEnv(container, "MERCUTIO_ARM_TOKEN", credentialSecretRefName(pod.Labels["mercutio.dev/cell-id"], "arm"), "token") {
			return fmt.Errorf("armgate requires only the cell arm capability")
		}
		if container.Name == "armgate" && mountsVolume(container, "workspace") {
			return fmt.Errorf("armgate may not mount the cell workspace")
		}
	}
	if !armgate {
		return fmt.Errorf("sandbox pod requires armgate before agent start")
	}
	agent, attach := false, false
	for _, container := range pod.Spec.Containers {
		if container.Name == "agent" {
			agent = true
		}
		if container.Name == "attach" {
			attach = true
		}
		if err := validateContainer(container, container.Name == "attach"); err != nil {
			return fmt.Errorf("container %s: %w", container.Name, err)
		}
		if container.Name == "agent" {
			if len(container.EnvFrom) > 0 {
				return fmt.Errorf("agent may not consume envFrom secrets")
			}
			for _, env := range container.Env {
				if strings.Contains(strings.ToUpper(env.Name), "TOKEN") || env.ValueFrom != nil {
					return fmt.Errorf("agent may not receive token or secret environment values")
				}
			}
		}
	}
	if !agent || !attach {
		return fmt.Errorf("sandbox pod requires separate agent and attach containers")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil || volume.Projected != nil {
			return fmt.Errorf("sandbox pod may not mount secret or projected volumes")
		}
	}
	return nil
}

func mountsVolume(container corev1.Container, name string) bool {
	for _, mount := range container.VolumeMounts {
		if mount.Name == name {
			return true
		}
	}
	return false
}

func validateContainer(container corev1.Container, allowSecretEnv bool) error {
	if !digestPinned(container.Image) {
		return fmt.Errorf("image must be pinned by sha256 digest")
	}
	security := container.SecurityContext
	if security == nil || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.Privileged != nil && *security.Privileged || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.RunAsNonRoot == nil || !*security.RunAsNonRoot {
		return fmt.Errorf("restricted security context is required")
	}
	if security.Capabilities == nil || !containsCapability(security.Capabilities.Drop, corev1.Capability("ALL")) {
		return fmt.Errorf("all Linux capabilities must be dropped")
	}
	if !allowSecretEnv {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				return fmt.Errorf("secret environment is not allowed")
			}
		}
	}
	return nil
}

func hasExactSecretEnv(container corev1.Container, name, secret, key string) bool {
	found := false
	for _, env := range container.Env {
		if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
			continue
		}
		if env.Name != name || env.ValueFrom.SecretKeyRef.Name != secret || env.ValueFrom.SecretKeyRef.Key != key {
			return false
		}
		found = true
	}
	return found
}

func digestPinned(image string) bool {
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || len(parts[1]) != 64 {
		return false
	}
	for _, char := range parts[1] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}

func containsCapability(values []corev1.Capability, want corev1.Capability) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func attachSecretRefName(cellID string) string {
	return credentialSecretRefName(cellID, "attach")
}

func credentialSecretRefName(cellID, purpose string) string {
	return "mercutio-" + dnsName(cellID) + "-" + dnsName(purpose)
}

func podFromKubernetes(pod corev1.Pod, spec Spec) Pod {
	phase := PhasePending
	var failure string
	switch pod.Status.Phase {
	case corev1.PodRunning:
		phase = PhaseRunning
	case corev1.PodSucceeded:
		phase = PhaseStopped
	case corev1.PodFailed:
		phase = PhaseFailed
		failure = pod.Status.Reason
		if failure == "" {
			failure = pod.Status.Message
		}
	}
	transition := pod.CreationTimestamp.Time
	if transition.IsZero() {
		transition = time.Now().UTC()
	}
	profile := defaultValue(pod.Labels["mercutio.dev/profile"], defaultValue(spec.Profile, "standard"))
	repoURL := pod.Annotations["mercutio.dev/repo-url"]
	if repoURL == "" {
		repoURL = spec.RepoURL
	}
	branch := pod.Annotations["mercutio.dev/branch"]
	if branch == "" {
		branch = defaultValue(spec.Branch, "main")
	}
	return Pod{
		Name:           pod.Name,
		CellID:         defaultValue(pod.Labels["mercutio.dev/cell-id"], spec.CellID),
		Phase:          phase,
		RepoURL:        repoURL,
		Branch:         branch,
		Profile:        profile,
		StartedAt:      transition,
		LastTransition: transition,
		Failure:        failure,
		Armed:          pod.Annotations["mercutio.dev/armed"] == "true",
	}
}

func validateSpec(spec Spec) error {
	if strings.TrimSpace(spec.CellID) == "" {
		return fmt.Errorf("sandbox cell ID is required")
	}
	if strings.TrimSpace(spec.RepoURL) == "" {
		return fmt.Errorf("sandbox repository URL is required")
	}
	if _, err := policy.Resolve(spec.Profile); err != nil {
		return err
	}
	return nil
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func dnsName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "cell"
	}
	if len(name) > 50 {
		name = name[:50]
	}
	return strings.Trim(name, "-")
}
