//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/example/tetragon-firewall/internal/bpf"
	"github.com/example/tetragon-firewall/internal/cli"
	"github.com/example/tetragon-firewall/internal/controller"
	runtimeclient "github.com/example/tetragon-firewall/internal/runtime"
)

// main initializes the node agent, metrics endpoint, and reconciliation loop.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := cli.NewCommand(run).Execute(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

// run initializes the agent dependencies and serves until shutdown or failure.
func run(opts cli.Options, logger *slog.Logger) error {
	effectivePinRoot := opts.PinRoot
	if opts.CheckOnly {
		effectivePinRoot = opts.CheckPinRoot
	}
	manager, err := bpf.NewManager(effectivePinRoot)
	if err != nil {
		return err
	}
	defer manager.Close()
	if opts.CheckOnly {
		if err := manager.Attach("preflight", opts.CheckCgroup); err != nil {
			return fmt.Errorf("attach preflight programs: %w", err)
		}
		if err := manager.CleanupPins(); err != nil {
			return fmt.Errorf("clean up preflight pins: %w", err)
		}
		logger.Info("eBPF preflight succeeded")
		return nil
	}
	if opts.NodeName == "" {
		return fmt.Errorf("node-name, NODE_NAME, or FIREWALL_NODE_NAME is required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("cannot remove memlock limit", "error", err)
	}
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	kube, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}
	runtime, err := runtimeclient.NewContainerd(opts.ContainerdSocket, opts.HostProc, opts.CgroupRoot)
	if err != nil {
		return err
	}
	defer runtime.Close()
	agent := controller.NewAgent(opts.ConfigPath, controller.NewResolver(kube, opts.NodeName), runtime, manager, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go consumeEvents(ctx, manager, logger)
	server := &http.Server{Addr: opts.MetricsAddress, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(agent.Metrics()))
	})}
	go func() {
		logger.Info("metrics server listening", "address", opts.MetricsAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
			stop()
		}
	}()
	if err := agent.Run(ctx); err != nil {
		return err
	}
	return server.Shutdown(context.Background())
}

// consumeEvents logs firewall decisions until the process context is cancelled.
func consumeEvents(ctx context.Context, manager *bpf.Manager, logger *slog.Logger) {
	for {
		event, err := manager.ReadEvent()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("read eBPF event", "error", err)
			continue
		}
		logger.Info("firewall decision", "denied", event.Denied, "cgroup_id", event.CgroupID,
			"destination", event.Address.String(), "port", event.Port, "protocol", event.Protocol, "hook", event.Hook)
	}
}
