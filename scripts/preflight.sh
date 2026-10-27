#!/usr/bin/env bash
set -euo pipefail

command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }
kubectl version --client >/dev/null
kubectl auth can-i list pods --all-namespaces >/dev/null

bad_nodes=$(kubectl get nodes -o jsonpath='{range .items[?(@.status.nodeInfo.operatingSystem!="linux")]}{.metadata.name}{"\n"}{end}')
if [[ -n "${bad_nodes}" ]]; then
  echo "non-Linux nodes are unsupported: ${bad_nodes}" >&2
  exit 1
fi

bad_runtimes=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}' | awk '$2 !~ /^containerd:/ {print}')
if [[ -n "${bad_runtimes}" ]]; then
  echo "all nodes must use containerd:" >&2
  echo "${bad_runtimes}" >&2
  exit 1
fi

echo "Kubernetes nodes are Linux/containerd. The agent will perform the authoritative eBPF and cgroup-v2 feature probe when it starts."
