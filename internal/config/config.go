package config

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// APIVersion is the only configuration schema version supported by the agent.
const APIVersion = "firewall.example.io/v1alpha1"

// Config is the complete user-facing firewall configuration.
type Config struct {
	APIVersion    string         `yaml:"apiVersion"`
	Mode          string         `yaml:"mode"`
	Selector      Selector       `yaml:"selector"`
	AllowLoopback bool           `yaml:"allowLoopback"`
	External      []ExternalRule `yaml:"external"`
	Service       ServiceRule    `yaml:"service"`
	DNS           DNSRule        `yaml:"dns"`
}

// Selector identifies Kubernetes Pods to which the firewall is attached.
type Selector struct {
	Namespace   string            `yaml:"namespace"`
	MatchLabels map[string]string `yaml:"matchLabels"`
}

// ExternalRule allows selected ports and protocols for an IPv4 CIDR.
type ExternalRule struct {
	CIDR      string    `yaml:"cidr"`
	Protocols Protocols `yaml:"protocols"`
}

// Protocols lists allowed TCP and UDP destination ports.
type Protocols struct {
	TCP []uint16 `yaml:"tcp"`
	UDP []uint16 `yaml:"udp"`
}

// ServiceRule identifies the application Service and port that remain reachable.
type ServiceRule struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
	Protocol  string `yaml:"protocol"`
	Port      uint16 `yaml:"port"`
}

// DNSRule identifies the Kubernetes DNS Service that selected Pods may use.
type DNSRule struct {
	Namespace   string `yaml:"namespace"`
	ServiceName string `yaml:"serviceName"`
}

// Rule is a validated, protocol-specific rule ready for policy compilation.
type Rule struct {
	Prefix   netip.Prefix
	Protocol uint8
	Ports    []uint16
	Source   string
}

// Load reads, strictly decodes, and validates a configuration file.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return cfg, cfg.Validate()
}

// Validate checks schema invariants and rejects ambiguous external CIDRs.
func (c Config) Validate() error {
	if c.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if c.Mode != "audit" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be audit or enforce")
	}
	if c.Selector.Namespace == "" || len(c.Selector.MatchLabels) == 0 {
		return fmt.Errorf("selector namespace and matchLabels are required")
	}
	if c.Service.Namespace == "" || c.Service.Name == "" || c.Service.Port == 0 {
		return fmt.Errorf("service namespace, name and port are required")
	}
	if strings.ToLower(c.Service.Protocol) != "tcp" {
		return fmt.Errorf("service protocol must be tcp")
	}
	if c.DNS.Namespace == "" || c.DNS.ServiceName == "" {
		return fmt.Errorf("dns namespace and serviceName are required")
	}
	prefixes := make([]netip.Prefix, 0, len(c.External))
	for i, ext := range c.External {
		p, err := netip.ParsePrefix(ext.CIDR)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("external[%d].cidr must be an IPv4 CIDR", i)
		}
		p = p.Masked()
		if len(ext.Protocols.TCP) == 0 && len(ext.Protocols.UDP) == 0 {
			return fmt.Errorf("external[%d] has no ports", i)
		}
		for _, port := range append(append([]uint16(nil), ext.Protocols.TCP...), ext.Protocols.UDP...) {
			if port == 0 {
				return fmt.Errorf("external[%d] contains reserved port 0", i)
			}
		}
		prefixes = append(prefixes, p)
	}
	for i := range prefixes {
		for j := i + 1; j < len(prefixes); j++ {
			if prefixes[i] == prefixes[j] {
				continue
			}
			if prefixes[i].Contains(prefixes[j].Addr()) || prefixes[j].Contains(prefixes[i].Addr()) {
				return fmt.Errorf("overlapping external CIDRs %s and %s are ambiguous", prefixes[i], prefixes[j])
			}
		}
	}
	return nil
}

// ExternalRules normalizes, merges, sorts, and de-duplicates external rules.
func (c Config) ExternalRules() ([]Rule, error) {
	merged := map[string]*Rule{}
	for _, ext := range c.External {
		prefix := netip.MustParsePrefix(ext.CIDR).Masked()
		for _, tuple := range []struct {
			proto uint8
			ports []uint16
		}{{6, ext.Protocols.TCP}, {17, ext.Protocols.UDP}} {
			if len(tuple.ports) == 0 {
				continue
			}
			key := fmt.Sprintf("%s/%d", prefix, tuple.proto)
			if merged[key] == nil {
				merged[key] = &Rule{Prefix: prefix, Protocol: tuple.proto, Source: "external"}
			}
			merged[key].Ports = append(merged[key].Ports, tuple.ports...)
		}
	}
	result := make([]Rule, 0, len(merged))
	for _, rule := range merged {
		rule.Ports = uniquePorts(rule.Ports)
		result = append(result, *rule)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Prefix.String() == result[j].Prefix.String() {
			return result[i].Protocol < result[j].Protocol
		}
		return result[i].Prefix.String() < result[j].Prefix.String()
	})
	return result, nil
}

// uniquePorts removes port zero and returns unique ports in ascending order.
func uniquePorts(in []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(in))
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if p == 0 {
			continue
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
