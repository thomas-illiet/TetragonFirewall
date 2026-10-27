#!/usr/bin/env bash
set -euo pipefail

image=${IMAGE:-tetragon-firewall:dev}
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

docker run --rm --cap-drop=ALL --cap-add=BPF --cap-add=NET_ADMIN \
  --security-opt seccomp=unconfined \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${image}" --check-only
