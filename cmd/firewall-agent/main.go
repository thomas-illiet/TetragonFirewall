//go:build linux

package main

import (
	"context"
	"flag"
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
	"github.com/example/tetragon-firewall/internal/controller"
	runtimeclient "github.com/example/tetragon-firewall/internal/runtime"
)

// main initializes the node agent, metrics endpoint, and reconciliation loop.
func main() {
	var configPath, nodeName, containerdSocket, hostProc, cgroupRoot, pinRoot, checkPinRoot, checkCgroup, metricsAddress string
	var checkOnly bool
	flag.StringVar(&configPath, "config", "/etc/firewall/config.yaml", "configuration file")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name")
	flag.StringVar(&containerdSocket, "containerd-socket", "/run/containerd/containerd.sock", "containerd socket")
	flag.StringVar(&hostProc, "host-proc", "/host/proc", "host procfs mount")
	flag.StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount")
	flag.StringVar(&pinRoot, "pin-root", "/sys/fs/bpf/tetragon-firewall", "bpffs pin directory")
	flag.StringVar(&checkPinRoot, "check-pin-root", "/sys/fs/bpf/tetragon-firewall-preflight", "temporary bpffs directory used by --check-only")
	flag.StringVar(&checkCgroup, "check-cgroup", "/sys/fs/cgroup", "cgroup used for temporary attachment by --check-only")
	flag.StringVar(&metricsAddress, "metrics-address", ":2112", "metrics listen address")
	flag.BoolVar(&checkOnly, "check-only", false, "load and verify eBPF objects, then exit")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	effectivePinRoot := pinRoot
	if checkOnly {
		effectivePinRoot = checkPinRoot
	}
	manager, err := bpf.NewManager(effectivePinRoot)
	if err != nil {
		fatal(logger, err)
	}
	defer manager.Close()
	if checkOnly {
		if err := manager.Attach("preflight", checkCgroup); err != nil {
			fatal(logger, fmt.Errorf("attach preflight programs: %w", err))
		}
		if err := manager.CleanupPins(); err != nil {
			fatal(logger, fmt.Errorf("clean up preflight pins: %w", err))
		}
		logger.Info("eBPF preflight succeeded")
		return
	}
	if nodeName == "" {
		fatal(logger, fmt.Errorf("node-name or NODE_NAME is required"))
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("cannot remove memlock limit", "error", err)
	}
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		fatal(logger, err)
	}
	kube, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		fatal(logger, err)
	}
	runtime, err := runtimeclient.NewContainerd(containerdSocket, hostProc, cgroupRoot)
	if err != nil {
		fatal(logger, err)
	}
	defer runtime.Close()
	agent := controller.NewAgent(configPath, controller.NewResolver(kube, nodeName), runtime, manager, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go consumeEvents(ctx, manager, logger)
	server := &http.Server{Addr: metricsAddress, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(agent.Metrics()))
	})}
	go func() {
		logger.Info("metrics server listening", "address", metricsAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
			stop()
		}
	}()
	if err := agent.Run(ctx); err != nil {
		fatal(logger, err)
	}
	_ = server.Shutdown(context.Background())
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

// fatal logs an unrecoverable error and terminates the process.
func fatal(logger *slog.Logger, err error) {
	logger.Error("fatal error", "error", err)
	os.Exit(1)
}
