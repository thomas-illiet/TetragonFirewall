package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// Containerd resolves Kubernetes container tasks through the containerd API.
type Containerd struct {
	tasks    taskPIDResolver
	close    func() error
	hostProc string
	cgroup   string
}

// taskPIDResolver abstracts containerd task lookup for deterministic tests.
type taskPIDResolver interface {
	TaskPID(context.Context, string) (uint32, error)
}

// containerdTasks implements task PID lookup with the native containerd client.
type containerdTasks struct{ client *containerd.Client }

// NewContainerd connects to containerd and configures host filesystem roots.
func NewContainerd(socket, hostProc, cgroupRoot string) (*Containerd, error) {
	client, err := containerd.New(socket)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	return &Containerd{tasks: &containerdTasks{client: client}, close: client.Close, hostProc: hostProc, cgroup: cgroupRoot}, nil
}

// Close releases the containerd client connection.
func (c *Containerd) Close() error {
	if c.close == nil {
		return nil
	}
	return c.close()
}

// CgroupPath returns the verified host cgroup v2 directory for a container.
func (c *Containerd) CgroupPath(ctx context.Context, containerID string) (string, error) {
	pid, err := c.tasks.TaskPID(ctx, containerID)
	if err != nil {
		return "", err
	}
	path, err := readUnifiedCgroup(filepath.Join(c.hostProc, fmt.Sprintf("%d/cgroup", pid)))
	if err != nil {
		return "", fmt.Errorf("resolve task %s cgroup: %w", shortID(containerID), err)
	}
	full := filepath.Join(c.cgroup, strings.TrimPrefix(path, "/"))
	info, err := os.Stat(full)
	if err != nil {
		return "", fmt.Errorf("stat cgroup %s: %w", full, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cgroup path %s is not a directory", full)
	}
	return full, nil
}

// TaskPID returns the host PID of a running containerd task.
func (c *containerdTasks) TaskPID(ctx context.Context, containerID string) (uint32, error) {
	ctx = namespaces.WithNamespace(ctx, "k8s.io")
	container, err := c.client.LoadContainer(ctx, containerID)
	if err != nil {
		return 0, fmt.Errorf("load container %s: %w", shortID(containerID), err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("load task %s: %w", shortID(containerID), err)
	}
	return task.Pid(), nil
}

// readUnifiedCgroup extracts the unified hierarchy path from a procfs cgroup file.
func readUnifiedCgroup(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("unified cgroup entry not found")
}

// shortID abbreviates a container identifier for error messages.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
