// Package cli defines the firewall agent command-line interface.
package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const envPrefix = "FIREWALL"

// Options contains the effective runtime settings after Cobra flags and Viper
// environment variables have been resolved.
type Options struct {
	ConfigPath       string
	NodeName         string
	ContainerdSocket string
	HostProc         string
	CgroupRoot       string
	PinRoot          string
	CheckPinRoot     string
	CheckCgroup      string
	MetricsAddress   string
	CheckOnly        bool
	LogLevel         string
	LogFormat        string
}

// Runner starts the agent using fully resolved options.
type Runner func(Options, *slog.Logger) error

// NewCommand creates an isolated Cobra command and Viper instance. The
// isolation keeps tests and repeated in-process executions deterministic.
func NewCommand(run Runner) *cobra.Command {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	cmd := &cobra.Command{
		Use:           "firewall-agent",
		Short:         "Run the Kubernetes eBPF egress firewall agent",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := optionsFrom(v)
			logger, err := NewLogger(os.Stdout, opts.LogLevel, opts.LogFormat)
			if err != nil {
				return err
			}
			slog.SetDefault(logger)
			return run(opts, logger)
		},
	}

	flags := cmd.Flags()
	flags.String("config", "/etc/firewall/config.yaml", "firewall policy configuration file")
	flags.String("node-name", "", "Kubernetes node name")
	flags.String("containerd-socket", "/run/containerd/containerd.sock", "containerd socket")
	flags.String("host-proc", "/host/proc", "host procfs mount")
	flags.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount")
	flags.String("pin-root", "/sys/fs/bpf/tetragon-firewall", "bpffs pin directory")
	flags.String("check-pin-root", "/sys/fs/bpf/tetragon-firewall-preflight", "temporary bpffs directory used by --check-only")
	flags.String("check-cgroup", "/sys/fs/cgroup", "cgroup used for temporary attachment by --check-only")
	flags.String("metrics-address", ":2112", "metrics listen address")
	flags.Bool("check-only", false, "load and verify eBPF objects, then exit")
	flags.String("log-level", "info", "log level: debug, info, warn, or error")
	flags.String("log-format", "json", "log format: json or text")

	for _, key := range []string{
		"config", "node-name", "containerd-socket", "host-proc", "cgroup-root",
		"pin-root", "check-pin-root", "check-cgroup", "metrics-address", "check-only",
		"log-level", "log-format",
	} {
		if err := v.BindPFlag(key, flags.Lookup(key)); err != nil {
			panic(fmt.Sprintf("bind flag %q: %v", key, err))
		}
	}
	// Preserve the Kubernetes Downward API convention used by the manifest.
	if err := v.BindEnv("node-name", "NODE_NAME", "FIREWALL_NODE_NAME"); err != nil {
		panic(fmt.Sprintf("bind node name environment variable: %v", err))
	}

	return cmd
}

// optionsFrom materializes the effective runtime options from Viper.
func optionsFrom(v *viper.Viper) Options {
	return Options{
		ConfigPath:       v.GetString("config"),
		NodeName:         v.GetString("node-name"),
		ContainerdSocket: v.GetString("containerd-socket"),
		HostProc:         v.GetString("host-proc"),
		CgroupRoot:       v.GetString("cgroup-root"),
		PinRoot:          v.GetString("pin-root"),
		CheckPinRoot:     v.GetString("check-pin-root"),
		CheckCgroup:      v.GetString("check-cgroup"),
		MetricsAddress:   v.GetString("metrics-address"),
		CheckOnly:        v.GetBool("check-only"),
		LogLevel:         v.GetString("log-level"),
		LogFormat:        v.GetString("log-format"),
	}
}

// NewLogger builds the structured slog logger selected by the CLI settings.
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var slogLevel slog.Level
	if err := slogLevel.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		return nil, fmt.Errorf("invalid log level %q: use debug, info, warn, or error", level)
	}

	opts := &slog.HandlerOptions{Level: slogLevel}
	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q: use json or text", format)
	}
	return slog.New(handler), nil
}
