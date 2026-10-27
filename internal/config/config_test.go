package config

import (
	"os"
	"path/filepath"
	"testing"
)

func validConfig() Config {
	return Config{
		APIVersion: APIVersion,
		Mode:       "audit",
		Selector:   Selector{Namespace: "demo", MatchLabels: map[string]string{"restricted": "true"}},
		External:   []ExternalRule{{CIDR: "203.0.113.10/32", Protocols: Protocols{TCP: []uint16{443}}}},
		Service:    ServiceRule{Namespace: "demo", Name: "backend", Protocol: "tcp", Port: 8080},
		DNS:        DNSRule{Namespace: "kube-system", ServiceName: "kube-dns"},
	}
}

func TestValidate(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectOverlappingCIDRs(t *testing.T) {
	cfg := validConfig()
	cfg.External = append(cfg.External, ExternalRule{CIDR: "203.0.113.0/24", Protocols: Protocols{UDP: []uint16{53}}})
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected overlapping CIDRs to be rejected")
	}
}

func TestMergeDuplicateCIDR(t *testing.T) {
	cfg := validConfig()
	cfg.External = append(cfg.External, ExternalRule{CIDR: "203.0.113.10/32", Protocols: Protocols{TCP: []uint16{8443, 443}}})
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	rules, err := cfg.ExternalRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(rules[0].Ports) != 2 {
		t.Fatalf("unexpected merged rules: %#v", rules)
	}
}

func TestValidationFailures(t *testing.T) {
	tests := map[string]func(*Config){
		"api version":       func(c *Config) { c.APIVersion = "v1" },
		"mode":              func(c *Config) { c.Mode = "block" },
		"namespace":         func(c *Config) { c.Selector.Namespace = "" },
		"labels":            func(c *Config) { c.Selector.MatchLabels = nil },
		"service namespace": func(c *Config) { c.Service.Namespace = "" },
		"service protocol":  func(c *Config) { c.Service.Protocol = "udp" },
		"dns":               func(c *Config) { c.DNS.ServiceName = "" },
		"invalid cidr":      func(c *Config) { c.External[0].CIDR = "invalid" },
		"ipv6 cidr":         func(c *Config) { c.External[0].CIDR = "2001:db8::/32" },
		"no ports": func(c *Config) {
			c.External[0].Protocols = Protocols{}
		},
		"port zero": func(c *Config) {
			c.External[0].Protocols.TCP = []uint16{0}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadStrictYAML(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(unknown, []byte("apiVersion: firewall.example.io/v1alpha1\nunknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(unknown); err == nil {
		t.Fatal("expected unknown field error")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestExternalRulesProtocolsAndOrdering(t *testing.T) {
	cfg := validConfig()
	cfg.External = []ExternalRule{
		{CIDR: "203.0.113.20/32", Protocols: Protocols{UDP: []uint16{53, 53}}},
		{CIDR: "198.51.100.0/24", Protocols: Protocols{TCP: []uint16{8443}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	rules, err := cfg.ExternalRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Prefix.String() != "198.51.100.0/24" || rules[1].Protocol != 17 || len(rules[1].Ports) != 1 {
		t.Fatalf("unexpected rules: %#v", rules)
	}
	if got := uniquePorts([]uint16{0, 2, 1, 2}); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("unexpected ports: %v", got)
	}
}
