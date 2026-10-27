package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/tetragon-firewall/internal/bpf"
	"github.com/example/tetragon-firewall/internal/config"
)

type fakeKubernetes struct {
	containers []string
	addresses  map[string][]netip.Addr
	err        error
}

// SelectedContainers returns the fake Kubernetes container selection.
func (f *fakeKubernetes) SelectedContainers(context.Context, config.Selector) ([]string, error) {
	return f.containers, f.err
}

// ServiceAddresses returns deterministic application and DNS service addresses.
func (f *fakeKubernetes) ServiceAddresses(_ context.Context, namespace, name string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.addresses[namespace+"/"+name], nil
}

type fakeRuntime struct {
	paths map[string]string
	err   error
}

// CgroupPath returns a fake cgroup path or the configured runtime error.
func (f *fakeRuntime) CgroupPath(_ context.Context, id string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.paths[id], nil
}

type fakeFirewall struct {
	rules      []bpf.Rule
	mode       uint32
	attached   map[string]string
	desired    map[string]struct{}
	counters   [4]uint64
	applyError error
}

// Apply records the rules and mode supplied by the agent.
func (f *fakeFirewall) Apply(rules []bpf.Rule, mode uint32) error {
	f.rules, f.mode = rules, mode
	return f.applyError
}

// Attach records one requested container attachment.
func (f *fakeFirewall) Attach(id, path string) error {
	if f.attached == nil {
		f.attached = map[string]string{}
	}
	f.attached[id] = path
	return nil
}

// ReconcileLinks records the final desired pinned-link set.
func (f *fakeFirewall) ReconcileLinks(desired map[string]struct{}) error {
	f.desired = desired
	return nil
}

// LinkKey returns the deterministic fake link key for an identity.
func (f *fakeFirewall) LinkKey(id string) string { return "key-" + id }

// Counters returns the configured fake kernel counters.
func (f *fakeFirewall) Counters() ([4]uint64, error) { return f.counters, nil }

// TestAgentReconcileEnforcement verifies rule compilation and link attachment.
func TestAgentReconcileEnforcement(t *testing.T) {
	path := writeConfig(t, "enforce")
	kube := &fakeKubernetes{
		containers: []string{"container-a"},
		addresses: map[string][]netip.Addr{
			"demo/allowed-backend": {netip.MustParseAddr("10.96.0.10"), netip.MustParseAddr("10.244.0.4")},
			"kube-system/kube-dns": {netip.MustParseAddr("10.96.0.53")},
		},
	}
	runtime := &fakeRuntime{paths: map[string]string{"container-a": "/sys/fs/cgroup/container-a"}}
	firewall := &fakeFirewall{}
	agent := NewAgent(path, kube, runtime, firewall, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if firewall.mode != bpf.ModeEnforce {
		t.Fatalf("mode=%d, want enforce", firewall.mode)
	}
	if firewall.attached["container-a"] != "/sys/fs/cgroup/container-a" {
		t.Fatalf("unexpected attachments: %#v", firewall.attached)
	}
	if _, ok := firewall.desired["key-container-a"]; !ok {
		t.Fatalf("desired links=%v", firewall.desired)
	}
	assertRule(t, firewall.rules, "127.0.0.0/8", 6, 0)
	assertRule(t, firewall.rules, "10.96.0.10/32", 6, 8080)
	assertRule(t, firewall.rules, "10.96.0.53/32", 17, 53)
	assertRule(t, firewall.rules, "203.0.113.10/32", 6, 443)
}

// TestAgentKeepsDesiredLinkWhenRuntimeIsTemporarilyUnavailable verifies link retention during transient failures.
func TestAgentKeepsDesiredLinkWhenRuntimeIsTemporarilyUnavailable(t *testing.T) {
	path := writeConfig(t, "audit")
	kube := &fakeKubernetes{containers: []string{"container-a"}, addresses: map[string][]netip.Addr{
		"demo/allowed-backend": {netip.MustParseAddr("10.96.0.10")},
		"kube-system/kube-dns": {netip.MustParseAddr("10.96.0.53")},
	}}
	firewall := &fakeFirewall{}
	agent := NewAgent(path, kube, &fakeRuntime{err: errors.New("task restarting")}, firewall, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := firewall.desired["key-container-a"]; !ok {
		t.Fatal("existing persistent link would have been removed")
	}
	if len(firewall.attached) != 0 {
		t.Fatalf("unexpected attachment: %v", firewall.attached)
	}
}

// TestAgentRejectsInvalidConfigBeforeChangingPolicy verifies fail-safe reconciliation.
func TestAgentRejectsInvalidConfigBeforeChangingPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	firewall := &fakeFirewall{}
	agent := NewAgent(path, &fakeKubernetes{}, &fakeRuntime{}, firewall, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := agent.reconcile(context.Background()); err == nil {
		t.Fatal("expected invalid configuration error")
	}
	if firewall.rules != nil {
		t.Fatal("policy changed after invalid configuration")
	}
}

// TestMetrics verifies Prometheus metrics derived from agent and kernel state.
func TestMetrics(t *testing.T) {
	firewall := &fakeFirewall{counters: [4]uint64{1, 2, 3, 4}}
	agent := NewAgent("unused", &fakeKubernetes{}, &fakeRuntime{}, firewall, slog.Default())
	agent.attached.Store(2)
	agent.rules.Store(7)
	agent.errors.Store(1)
	metrics := agent.Metrics()
	for _, want := range []string{
		"firewall_attachments_active 2", "firewall_rules_loaded 7",
		"firewall_reconcile_errors_total 1",
		`firewall_decisions_total{protocol="tcp",decision="allow"} 1`,
		`firewall_decisions_total{protocol="udp",decision="deny"} 4`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %q:\n%s", want, metrics)
		}
	}
}

// writeConfig writes a complete test policy and returns its path.
func writeConfig(t *testing.T, mode string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `apiVersion: firewall.example.io/v1alpha1
mode: ` + mode + `
selector:
  namespace: demo
  matchLabels:
    firewall.example.io/restricted: "true"
allowLoopback: true
external:
  - cidr: 203.0.113.10/32
    protocols:
      tcp: [443]
service:
  namespace: demo
  name: allowed-backend
  protocol: tcp
  port: 8080
dns:
  namespace: kube-system
  serviceName: kube-dns
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertRule verifies that a compiled rule contains an expected destination tuple.
func assertRule(t *testing.T, rules []bpf.Rule, prefix string, protocol uint8, port uint16) {
	t.Helper()
	for _, rule := range rules {
		if rule.Prefix.String() != prefix || rule.Protocol != protocol {
			continue
		}
		for _, candidate := range rule.Ports {
			if candidate == port {
				return
			}
		}
	}
	t.Fatalf("rule %s protocol=%d port=%d not found in %#v", prefix, protocol, port, rules)
}
