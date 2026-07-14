package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const versionsAnnotation = "mercutio.dev/secret-versions"

type KubernetesPersistence struct {
	client    kubernetes.Interface
	namespace string
}

func NewKubernetesPersistence(client kubernetes.Interface, namespace string) *KubernetesPersistence {
	if namespace == "" {
		namespace = "default"
	}
	return &KubernetesPersistence{client: client, namespace: namespace}
}

func NewKubernetesBrokerFromEnv(namespace string) (*Broker, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return NewBrokerWithPersistence(NewKubernetesPersistence(client, namespace)), nil
}

func (k *KubernetesPersistence) Put(cellID, name, value string) (uint64, error) {
	if k == nil || k.client == nil {
		return 0, fmt.Errorf("kubernetes secret backend unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api := k.client.CoreV1().Secrets(k.namespace)
	objectName := secretObjectName(cellID)
	for attempt := 0; attempt < 5; attempt++ {
		current, err := api.Get(ctx, objectName, metav1.GetOptions{})
		exists := err == nil
		if apierrors.IsNotFound(err) {
			current = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: objectName, Labels: map[string]string{"app.kubernetes.io/managed-by": "mercutio", "mercutio.dev/cell-id": cellID}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
		} else if err != nil {
			return 0, err
		}
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		versions := decodeVersions(current.Annotations)
		versions[name]++
		current.Data[name] = []byte(value)
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		encoded, _ := json.Marshal(versions)
		current.Annotations[versionsAnnotation] = string(encoded)
		if !exists {
			_, err = api.Create(ctx, current, metav1.CreateOptions{})
		} else {
			_, err = api.Update(ctx, current, metav1.UpdateOptions{})
		}
		if err == nil {
			return versions[name], nil
		}
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("secret update conflict did not converge")
}

func (k *KubernetesPersistence) Get(cellID, name string) (string, uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secret, err := k.client.CoreV1().Secrets(k.namespace).Get(ctx, secretObjectName(cellID), metav1.GetOptions{})
	if err != nil {
		return "", 0, err
	}
	value, ok := secret.Data[name]
	if !ok {
		return "", 0, fmt.Errorf("secret not found")
	}
	return string(value), decodeVersions(secret.Annotations)[name], nil
}
func (k *KubernetesPersistence) List(cellID string) ([]Descriptor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secret, err := k.client.CoreV1().Secrets(k.namespace).Get(ctx, secretObjectName(cellID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	versions := decodeVersions(secret.Annotations)
	out := make([]Descriptor, 0, len(secret.Data))
	for name, value := range secret.Data {
		out = append(out, Descriptor{Name: name, Version: versions[name], Redacted: RedactedValue(string(value))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (k *KubernetesPersistence) DeleteCell(cellID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := k.client.CoreV1().Secrets(k.namespace).Delete(ctx, secretObjectName(cellID), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
func decodeVersions(annotations map[string]string) map[string]uint64 {
	out := map[string]uint64{}
	if annotations != nil {
		_ = json.Unmarshal([]byte(annotations[versionsAnnotation]), &out)
	}
	return out
}
func secretObjectName(cellID string) string {
	value := strings.ToLower(cellID)
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	value = strings.Trim(b.String(), "-")
	if len(value) > 48 {
		value = value[:48]
	}
	return "mercutio-secret-" + value
}
