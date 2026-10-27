package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/example/tetragon-firewall/internal/config"
)

func TestSelectedContainers(t *testing.T) {
	client := fake.NewClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "demo", Labels: map[string]string{"restricted": "true"}},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", Ready: true, ContainerID: "containerd://abc",
		}}},
	})
	r := NewResolver(client, "node-a")
	ids, err := r.SelectedContainers(context.Background(), config.Selector{Namespace: "demo", MatchLabels: map[string]string{"restricted": "true"}})
	if err != nil || len(ids) != 1 || ids[0] != "abc" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestSelectedContainersFiltersIneligibleStatuses(t *testing.T) {
	client := fake.NewClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "demo", Labels: map[string]string{"restricted": "true"}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mixed", Namespace: "demo", Labels: map[string]string{"restricted": "true"}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: "waiting", ContainerID: "containerd://waiting"},
			{Name: "docker", Ready: true, ContainerID: "docker://ignored"},
		}}},
	)
	ids, err := NewResolver(client, "node-a").SelectedContainers(context.Background(), config.Selector{Namespace: "demo", MatchLabels: map[string]string{"restricted": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("unexpected IDs: %v", ids)
	}
	if containerID("") != "" || containerID("docker://id") != "" {
		t.Fatal("non-containerd IDs must be ignored")
	}
}

func TestSelectedContainersListError(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, kruntime.Object, error) {
		return true, nil, errors.New("API unavailable")
	})
	_, err := NewResolver(client, "node-a").SelectedContainers(context.Background(), config.Selector{Namespace: "demo", MatchLabels: map[string]string{"restricted": "true"}})
	if err == nil {
		t.Fatal("expected list error")
	}
}

func TestServiceAddresses(t *testing.T) {
	ready := true
	client := fake.NewClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "demo"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "backend-1", Namespace: "demo", Labels: map[string]string{discoveryv1.LabelServiceName: "backend"}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.244.0.4"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}}},
	)
	r := NewResolver(client, "node-a")
	addresses, err := r.ServiceAddresses(context.Background(), "demo", "backend")
	if err != nil || len(addresses) != 2 {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
}

func TestServiceAddressesIgnoresInvalidAndUnreadyEndpoints(t *testing.T) {
	ready, notReady := true, false
	client := fake.NewClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "demo"}, Spec: corev1.ServiceSpec{ClusterIP: "None"}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "backend-1", Namespace: "demo", Labels: map[string]string{discoveryv1.LabelServiceName: "backend"}}, Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.0.4", "invalid"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.244.0.5"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		}},
	)
	addresses, err := NewResolver(client, "node-a").ServiceAddresses(context.Background(), "demo", "backend")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "10.244.0.4" {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
}

func TestServiceAddressErrors(t *testing.T) {
	t.Run("missing service", func(t *testing.T) {
		_, err := NewResolver(fake.NewClientset(), "node-a").ServiceAddresses(context.Background(), "demo", "missing")
		if err == nil {
			t.Fatal("expected service error")
		}
	})
	t.Run("endpoint list", func(t *testing.T) {
		client := fake.NewClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "demo"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}})
		client.PrependReactor("list", "endpointslices", func(ktesting.Action) (bool, kruntime.Object, error) {
			return true, nil, errors.New("API unavailable")
		})
		_, err := NewResolver(client, "node-a").ServiceAddresses(context.Background(), "demo", "backend")
		if err == nil {
			t.Fatal("expected EndpointSlice error")
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		client := fake.NewClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "demo"}, Spec: corev1.ServiceSpec{ClusterIP: "None"}})
		_, err := NewResolver(client, "node-a").ServiceAddresses(context.Background(), "demo", "backend")
		if err == nil {
			t.Fatal("expected empty address error")
		}
	})
}
