package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/example/tetragon-firewall/internal/config"
)

// Resolver reads selected Pods, Services, and EndpointSlices from Kubernetes.
type Resolver struct {
	client   kubernetes.Interface
	nodeName string
}

// NewResolver constructs a Kubernetes resolver for a single node.
func NewResolver(client kubernetes.Interface, nodeName string) *Resolver {
	return &Resolver{client: client, nodeName: nodeName}
}

// SelectedContainers returns sorted containerd IDs for matching running Pods on this node.
func (r *Resolver) SelectedContainers(ctx context.Context, selector config.Selector) ([]string, error) {
	labelSelector := labels.SelectorFromSet(selector.MatchLabels).String()
	pods, err := r.client.CoreV1().Pods(selector.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
		FieldSelector: "spec.nodeName=" + r.nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("list selected pods: %w", err)
	}
	ids := make([]string, 0)
	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, status := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
			if !status.Ready && status.State.Running == nil {
				continue
			}
			if id := containerID(status.ContainerID); id != "" {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// containerID extracts a containerd identifier and ignores unsupported runtimes.
func containerID(value string) string {
	const prefix = "containerd://"
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	return strings.TrimPrefix(value, prefix)
}

// ServiceAddresses returns unique IPv4 ClusterIP and ready endpoint addresses.
func (r *Resolver) ServiceAddresses(ctx context.Context, namespace, name string) ([]netip.Addr, error) {
	svc, err := r.client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get service %s/%s: %w", namespace, name, err)
	}
	set := map[netip.Addr]struct{}{}
	if addr, err := netip.ParseAddr(svc.Spec.ClusterIP); err == nil && addr.Is4() {
		set[addr] = struct{}{}
	}
	slices, err := r.client.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + name,
	})
	if err != nil {
		return nil, fmt.Errorf("list endpoints for %s/%s: %w", namespace, name, err)
	}
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, raw := range endpoint.Addresses {
				if addr, err := netip.ParseAddr(raw); err == nil && addr.Is4() {
					set[addr] = struct{}{}
				}
			}
		}
	}
	result := make([]netip.Addr, 0, len(set))
	for addr := range set {
		result = append(result, addr)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	if len(result) == 0 {
		return nil, fmt.Errorf("service %s/%s has no IPv4 ClusterIP or ready endpoint", namespace, name)
	}
	return result, nil
}
