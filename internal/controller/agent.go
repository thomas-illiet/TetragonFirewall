package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/example/tetragon-firewall/internal/bpf"
	"github.com/example/tetragon-firewall/internal/config"
)

// CgroupResolver maps a runtime container identifier to its cgroup v2 path.
type CgroupResolver interface {
	CgroupPath(context.Context, string) (string, error)
}

// KubernetesResolver provides the Kubernetes state required by reconciliation.
type KubernetesResolver interface {
	SelectedContainers(context.Context, config.Selector) ([]string, error)
	ServiceAddresses(context.Context, string, string) ([]netip.Addr, error)
}

// Firewall describes the eBPF policy and attachment operations used by the agent.
type Firewall interface {
	Apply([]bpf.Rule, uint32) error
	Attach(string, string) error
	ReconcileLinks(map[string]struct{}) error
	LinkKey(string) string
	Counters() ([4]uint64, error)
}

// Agent periodically reconciles configuration, Kubernetes state, and eBPF state.
type Agent struct {
	configPath string
	resolver   KubernetesResolver
	runtime    CgroupResolver
	bpf        Firewall
	logger     *slog.Logger
	interval   time.Duration
	attached   atomic.Int64
	rules      atomic.Int64
	errors     atomic.Uint64
}

// NewAgent constructs a reconciliation agent with its external dependencies.
func NewAgent(configPath string, resolver KubernetesResolver, runtime CgroupResolver, manager Firewall, logger *slog.Logger) *Agent {
	return &Agent{configPath: configPath, resolver: resolver, runtime: runtime, bpf: manager, logger: logger, interval: 5 * time.Second}
}

// Run reconciles immediately and then every five seconds until the context ends.
func (a *Agent) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		if err := a.reconcile(ctx); err != nil {
			a.errors.Add(1)
			a.logger.Error("reconciliation failed; keeping the last valid policy", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// reconcile applies one validated policy snapshot and updates cgroup attachments.
func (a *Agent) reconcile(ctx context.Context) error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	rules, err := a.compileRules(ctx, cfg)
	if err != nil {
		return err
	}
	mode := bpf.ModeAudit
	if cfg.Mode == "enforce" {
		mode = bpf.ModeEnforce
	}
	if err := a.bpf.Apply(rules, mode); err != nil {
		return err
	}
	containers, err := a.resolver.SelectedContainers(ctx, cfg.Selector)
	if err != nil {
		return err
	}
	desired := make(map[string]struct{}, len(containers))
	attached := int64(0)
	for _, id := range containers {
		desired[a.bpf.LinkKey(id)] = struct{}{}
		path, err := a.runtime.CgroupPath(ctx, id)
		if err != nil {
			a.logger.Warn("container cgroup not ready", "container", short(id), "error", err)
			continue
		}
		if err := a.bpf.Attach(id, path); err != nil {
			return err
		}
		attached++
	}
	if err := a.bpf.ReconcileLinks(desired); err != nil {
		return err
	}
	a.attached.Store(attached)
	a.rules.Store(int64(len(rules)))
	a.logger.Debug("reconciled", "mode", cfg.Mode, "containers", attached, "rules", len(rules))
	return nil
}

// compileRules combines external, loopback, application Service, and DNS rules.
func (a *Agent) compileRules(ctx context.Context, cfg config.Config) ([]bpf.Rule, error) {
	external, err := cfg.ExternalRules()
	if err != nil {
		return nil, err
	}
	rules := make([]bpf.Rule, 0, len(external)+8)
	for _, rule := range external {
		rules = append(rules, bpf.Rule{Prefix: rule.Prefix, Protocol: rule.Protocol, Ports: rule.Ports})
	}
	if cfg.AllowLoopback {
		loopback := netip.MustParsePrefix("127.0.0.0/8")
		rules = append(rules,
			bpf.Rule{Prefix: loopback, Protocol: 6, Ports: []uint16{0}},
			bpf.Rule{Prefix: loopback, Protocol: 17, Ports: []uint16{0}},
		)
	}
	serviceAddresses, err := a.resolver.ServiceAddresses(ctx, cfg.Service.Namespace, cfg.Service.Name)
	if err != nil {
		return nil, err
	}
	for _, addr := range serviceAddresses {
		rules = append(rules, bpf.Rule{Prefix: netip.PrefixFrom(addr, 32), Protocol: 6, Ports: []uint16{cfg.Service.Port}})
	}
	dnsAddresses, err := a.resolver.ServiceAddresses(ctx, cfg.DNS.Namespace, cfg.DNS.ServiceName)
	if err != nil {
		return nil, err
	}
	for _, addr := range dnsAddresses {
		prefix := netip.PrefixFrom(addr, 32)
		rules = append(rules,
			bpf.Rule{Prefix: prefix, Protocol: 6, Ports: []uint16{53}},
			bpf.Rule{Prefix: prefix, Protocol: 17, Ports: []uint16{53}},
		)
	}
	return rules, nil
}

// Metrics renders current agent and kernel counters in Prometheus text format.
func (a *Agent) Metrics() string {
	counters, err := a.bpf.Counters()
	if err != nil {
		a.errors.Add(1)
	}
	return fmt.Sprintf(`# HELP firewall_attachments_active Number of container cgroups with firewall links.
# TYPE firewall_attachments_active gauge
firewall_attachments_active %d
# HELP firewall_rules_loaded Number of compiled allow rules.
# TYPE firewall_rules_loaded gauge
firewall_rules_loaded %d
# HELP firewall_reconcile_errors_total Reconciliation and metrics errors.
# TYPE firewall_reconcile_errors_total counter
firewall_reconcile_errors_total %d
# HELP firewall_decisions_total eBPF decisions by protocol and result.
# TYPE firewall_decisions_total counter
firewall_decisions_total{protocol="tcp",decision="allow"} %d
firewall_decisions_total{protocol="udp",decision="allow"} %d
firewall_decisions_total{protocol="tcp",decision="deny"} %d
firewall_decisions_total{protocol="udp",decision="deny"} %d
`, a.attached.Load(), a.rules.Load(), a.errors.Load(), counters[0], counters[1], counters[2], counters[3])
}

// short returns a log-safe abbreviated container identifier.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
