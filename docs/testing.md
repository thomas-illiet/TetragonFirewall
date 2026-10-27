# Testing strategy

## Test layers

### Portable unit tests

`make test` generates the eBPF bindings and runs Go tests covering:

- strict YAML decoding and policy validation;
- IPv4 CIDR overlap detection and rule merging;
- Kubernetes Pod filtering and EndpointSlice resolution;
- external, loopback, application Service, and DNS rule compilation;
- audit/enforcement mode selection;
- persistent-link desired-state behavior during task restarts;
- containerd PID-to-cgroup path resolution;
- Prometheus metric rendering.

### Static and build checks

`make test-all` additionally runs:

- the race detector;
- `go vet`;
- a Linux static build;
- Kubernetes multi-document YAML validation;
- shell syntax checks;
- SVG structure and accessibility validation.

Use `make test-container` when the host does not provide a BPF-capable clang toolchain. It installs clang/LLVM only in the Linux builder and leaves generated files untracked.

### Kernel verification

`make test-ebpf` builds the image and starts it with only `CAP_BPF` and `CAP_NET_ADMIN`. The `--check-only` command loads all maps and programs, temporarily attaches all three programs to a cgroup, cleans the temporary bpffs directory, and exits.

This verifies the actual kernel verifier, attach types, bpf-link support, bpffs pinning, and minimum capabilities. It does not replace a Kubernetes datapath test.

### Kubernetes acceptance

After deploying `deploy/demo.yaml` and `deploy/firewall.yaml`, run `scripts/validate.sh` in audit mode and again in enforcement mode. Acceptance requires:

| Scenario | Expected result |
| --- | --- |
| Restricted client to `allowed-backend:8080` | Allowed |
| Restricted client to another Service | Denied in enforcement |
| Kubernetes DNS TCP/UDP 53 | Allowed |
| External CIDR on configured protocol and port | Allowed |
| Same external CIDR on another port | Denied in enforcement |
| UDP with and without `connect()` outside the allowlist | Denied in enforcement |
| Unselected Pod | Unaffected |
| Agent restart | Existing pinned links continue enforcing |
| Invalid ConfigMap update | Previous policy remains active |

## CI

The GitHub Actions workflow installs clang/LLVM, runs unit and race tests, regenerates ignored eBPF artifacts from source, validates that generated outputs remain ignored, builds the Linux binary, validates documentation assets, and builds the final scratch image.

## Compatibility statement

Passing the repository tests proves behavior for the tested source, compiler, and kernel. It does not prove compatibility with every kernel backport, containerd packaging, CNI, admission controller, or managed Kubernetes distribution. Run kernel verification and Kubernetes acceptance on each target node pool.
