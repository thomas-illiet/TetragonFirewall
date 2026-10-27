package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestCommandResolvesDefaultsEnvironmentAndFlags verifies configuration precedence.
func TestCommandResolvesDefaultsEnvironmentAndFlags(t *testing.T) {
	t.Setenv("NODE_NAME", "node-from-env")
	t.Setenv("FIREWALL_METRICS_ADDRESS", ":9000")

	var got Options
	cmd := NewCommand(func(opts Options, _ *slog.Logger) error {
		got = opts
		return nil
	})
	cmd.SetArgs([]string{"--metrics-address=:9100", "--log-format=text"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got.NodeName != "node-from-env" {
		t.Fatalf("node name = %q, want environment value", got.NodeName)
	}
	if got.MetricsAddress != ":9100" {
		t.Fatalf("metrics address = %q, want flag to override environment", got.MetricsAddress)
	}
	if got.ConfigPath != "/etc/firewall/config.yaml" || got.LogFormat != "text" || got.LogLevel != "info" {
		t.Fatalf("unexpected resolved options: %#v", got)
	}
}

// TestCommandSupportsPrefixedNodeName verifies the Viper-prefixed node variable.
func TestCommandSupportsPrefixedNodeName(t *testing.T) {
	t.Setenv("NODE_NAME", "")
	t.Setenv("FIREWALL_NODE_NAME", "prefixed-node")

	var got Options
	cmd := NewCommand(func(opts Options, _ *slog.Logger) error {
		got = opts
		return nil
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got.NodeName != "prefixed-node" {
		t.Fatalf("node name = %q, want prefixed environment value", got.NodeName)
	}
}

// TestNewLogger verifies structured output and rejects unsupported settings.
func TestNewLogger(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(&output, "debug", "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("ready", "component", "test")
	if got := output.String(); !strings.Contains(got, `"level":"DEBUG"`) || !strings.Contains(got, `"component":"test"`) {
		t.Fatalf("unexpected JSON log: %s", got)
	}

	if _, err := NewLogger(&output, "verbose", "json"); err == nil {
		t.Fatal("expected invalid level error")
	}
	if _, err := NewLogger(&output, "info", "xml"); err == nil {
		t.Fatal("expected invalid format error")
	}
}
