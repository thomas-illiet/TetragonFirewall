# Tetragon Firewall PoC

This repository contains an IPv4 egress firewall for Kubernetes Pods selected by namespace and labels. The agent is written in Go with [`cilium/ebpf`](https://github.com/cilium/ebpf), runs as a DaemonSet, and targets the cgroup v2 hierarchy of containers managed by containerd.

> **Security PoC:** always validate a policy in `audit` mode before enabling enforcement. This implementation is intentionally limited to Linux, IPv4, cgroup v2, and containerd. It is not a replacement for a production-supported CNI network policy.

## Architecture

The agent attaches three programs to every container belonging to a selected Pod:

- `cgroup/connect4` rejects TCP connections and connected UDP sockets;
- `cgroup/sendmsg4` covers UDP datagrams sent without calling `connect()`;
- `cgroup_skb/egress` checks every outbound packet, including packets from existing connections.

Allowed destinations are compiled into an IPv4 LPM trie and a `{group, protocol, port}` hash map. Two map generations allow a complete policy to be loaded before the active generation is switched atomically. Maps, programs, and links are pinned under `/sys/fs/bpf/tetragon-firewall`, so enforcement remains active while the userspace agent restarts.

The controller automatically adds these destinations to the allowlist:

- the application Service ClusterIP and ready endpoints, restricted to the configured port;
- the DNS Service ClusterIP and ready endpoints, restricted to TCP/UDP port 53;
- `127.0.0.0/8` when `allowLoopback` is enabled.

Service endpoints are required because `cgroup_skb` may observe traffic before or after DNAT, depending on the cluster datapath.

## Requirements and minimum privileges

- Linux nodes using containerd and cgroup v2;
- bpffs mounted at `/sys/fs/bpf`;
- permission to deploy a trusted node-level DaemonSet with narrowly scoped eBPF capabilities and hostPath mounts;
- Kubernetes EndpointSlice support (`discovery.k8s.io/v1`);
- Tetragon only when the complementary audit policy is required.

The manifest is not privileged: it drops every capability and adds only `BPF` and `NET_ADMIN`. Kernels older than 5.11 may also require `SYS_RESOURCE`; older environments may require `SYS_ADMIN`. The process still runs as UID 0 because it must access the containerd socket and the root-owned bpffs mount. Kubernetes `restricted` Pod Security does not permit the required capabilities or hostPath mounts, so grant a narrowly scoped admission exception only to this namespace and ServiceAccount. `hostPID` and `hostNetwork` are not used.

RBAC is namespace-scoped. The example grants Pod and application Service reads only in `demo`, plus DNS Service reads in `kube-system`. If the configured namespaces change, move or duplicate those Roles and RoleBindings rather than replacing them with a cluster-wide role.

Initial cluster check:

```bash
./scripts/preflight.sh
```

Loading the programs is the authoritative kernel feature test. The image can perform that test without contacting Kubernetes:

```bash
docker run --rm --cap-drop=ALL --cap-add=BPF --cap-add=NET_ADMIN \
  --security-opt seccomp=unconfined \
  -v /sys/fs/bpf:/sys/fs/bpf tetragon-firewall:dev --check-only
```

The check uses and removes only `/sys/fs/bpf/tetragon-firewall-preflight`; it never modifies the persistent production objects.

## Build and test

Generated eBPF bindings and objects are committed so the runtime image does not require clang or kernel headers.

```bash
make test
make build
docker build -t tetragon-firewall:dev .
```

Run the complete portable verification suite:

```bash
make test-all
```

Run the privileged Linux eBPF verifier after building the image:

```bash
IMAGE=tetragon-firewall:dev ./scripts/test-ebpf.sh
```

After changing `internal/bpf/firewall.c`, regenerate the embedded objects:

```bash
make generate
```

On macOS, generation requires a clang build with the BPF backend. A reproducible alternative is:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.24-bookworm \
  bash -c 'apt-get update && apt-get install -y --no-install-recommends clang llvm && go generate ./internal/bpf'
```

## Deploy the PoC

1. Build the image and make it available on every node or in a registry.
2. Replace `ghcr.io/example/tetragon-firewall:dev` in `deploy/firewall.yaml`.
3. Deploy the demonstration workloads and the agent:

```bash
kubectl apply -f deploy/demo.yaml
kubectl apply -f deploy/firewall.yaml
kubectl -n tetragon-firewall rollout status daemonset/firewall-agent
```

4. Generate traffic in audit mode and inspect the events:

```bash
./scripts/validate.sh
kubectl -n tetragon-firewall logs daemonset/firewall-agent -f
```

5. After reviewing the allowlist, change `mode: audit` to `mode: enforce` in the ConfigMap and reapply it. The projected ConfigMap is reread every five seconds.
6. Run `./scripts/validate.sh` again. `allowed-backend:8080` must remain reachable and `denied-backend:8080` must fail.

## Configuration

The schema is strict. Unknown keys or invalid values leave the last valid policy active. Nested external CIDRs are rejected to avoid implicit precedence; repeated entries with exactly the same CIDR are merged.

```yaml
apiVersion: firewall.example.io/v1alpha1
mode: audit
selector:
  namespace: demo
  matchLabels:
    firewall.example.io/restricted: "true"
allowLoopback: true
external:
  - cidr: 203.0.113.10/32
    protocols:
      tcp: [443]
      udp: [123]
service:
  namespace: demo
  name: allowed-backend
  protocol: tcp
  port: 8080
dns:
  namespace: kube-system
  serviceName: kube-dns
```

Every external destination must be an IPv4 CIDR. Ports are explicit and range from 1 to 65535. Port `0` is reserved internally for the loopback "all ports" rule.

## Audit and metrics

`deploy/tetragon-audit.yaml` adds an observation-only `TracingPolicyNamespaced` for restricted Pods:

```bash
kubectl apply -f deploy/tetragon-audit.yaml
```

The agent ring buffer is the authoritative source for firewall denials, including UDP `sendmsg`. Prometheus metrics are exposed on `:2112/metrics`: active attachments, loaded rules, reconciliation errors, and decisions by protocol and result. IP addresses are intentionally excluded from metric labels.

## Test matrix

The repository contains automated checks for:

- strict configuration parsing, validation, CIDR overlap detection, and rule merging;
- Kubernetes Pod selection and Service/EndpointSlice resolution;
- Service, DNS, loopback, and external rule compilation;
- audit/enforcement mode selection and persistent-link reconciliation;
- containerd cgroup v2 path parsing;
- Linux and cross-compiled agent builds, `go vet`, shell syntax, and YAML decoding;
- real eBPF object verification against a Linux kernel through `--check-only`;
- demonstration-cluster behavior through `scripts/validate.sh`.

Portable tests cannot prove compatibility with every kernel, container runtime build, admission controller, CNI datapath, or managed Kubernetes distribution. Run the privileged verifier and the cluster validation script on every target node pool before enabling enforcement.

## Known limitations

- IPv6, CRI-O, ingress filtering, and external DNS-name rules are not supported.
- Allowing Service endpoints also permits direct access to those endpoint IPs on the Service port. This is required to support both pre-DNAT and post-DNAT observation.
- Non-TCP/UDP and IPv6 packets pass in audit mode and are dropped in enforcement mode.
- Metrics count hook decisions; one connection attempt may traverse both a socket hook and the packet hook.
- Forcefully deleting the bpffs directory detaches persistent links and must only be done during an explicit maintenance or uninstall procedure.
