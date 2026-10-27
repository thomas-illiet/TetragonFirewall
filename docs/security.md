# Security and privilege model

## Trust boundary

The firewall agent is a trusted node component. It can load networking eBPF programs, access the container runtime socket, inspect host process metadata, and write persistent kernel objects to bpffs. Compromise of this Pod should be treated as node compromise.

## Minimum container privileges

The provided DaemonSet uses:

- UID and GID `0` for the root-owned containerd socket and bpffs;
- `privileged: false`;
- all Linux capabilities dropped;
- only `CAP_BPF` and `CAP_NET_ADMIN` added;
- `allowPrivilegeEscalation: false`;
- a read-only root filesystem;
- an unconfined seccomp profile because the agent must call `bpf(2)`.

Linux before 5.11 may additionally require `CAP_SYS_RESOURCE` for `RLIMIT_MEMLOCK`. Older kernels or runtimes without fine-grained BPF capability support may require `CAP_SYS_ADMIN`; that fallback is intentionally not present in the default manifest.

The agent does not use host networking, host PID sharing, host IPC, or a writable container root filesystem.

## Host mounts

| Host path | Container path | Mode | Purpose |
| --- | --- | --- | --- |
| `/proc` | `/host/proc` | Read-only | Read task cgroup membership by host PID |
| `/sys/fs/cgroup` | `/sys/fs/cgroup` | Read-only | Open target cgroup directories for BPF link attachment |
| `/sys/fs/bpf` | `/sys/fs/bpf` | Read-write | Pin programs, maps, and links across restarts |
| `/run/containerd/containerd.sock` | Same | Socket mount | Resolve container tasks to host PIDs |

The containerd socket is the most sensitive dependency and is effectively a node-administration interface. Admission policies must restrict this DaemonSet definition and its ServiceAccount to trusted administrators.

## Kubernetes permissions

RBAC is namespace scoped:

- application namespace: list Pods, get Services, and list EndpointSlices;
- `kube-system`: get the DNS Service and list its EndpointSlices.

The agent cannot create, update, patch, or delete Kubernetes resources. It does not read Secrets, ConfigMaps through the API, Nodes, workloads outside the configured namespace, or Tetragon resources.

The required hostPath mounts and capabilities are incompatible with the Kubernetes Restricted Pod Security Standard. Use an admission exception scoped to the firewall namespace, ServiceAccount, image digest, and exact DaemonSet fields rather than exempting application namespaces.

## Failure behavior

- Invalid configuration: retain the last valid active generation.
- Kubernetes API or Service resolution failure: retain policy and existing links; retry after five seconds.
- Temporary containerd task failure: keep the corresponding persistent link desired.
- Agent restart: pinned links continue enforcement; the new agent reopens and reconciles them.
- Node reboot: behavior depends on bpffs lifecycle; deploy and start the DaemonSet before restricted workloads.
- Ring-buffer overflow: enforcement continues, but some audit events may be lost.

## Operational recommendations

1. Deploy in audit mode and review events before enabling enforcement.
2. Pin the container image by digest.
3. Restrict updates to the ConfigMap and DaemonSet through admission policy and RBAC.
4. Alert on reconciliation errors, missing attachments, and unexpected agent restarts.
5. Run `--check-only` on every node pool before rollout.
6. Validate DNS, the allowed Service, every external destination, UDP `sendmsg()`, and denied traffic after each kernel or runtime upgrade.
