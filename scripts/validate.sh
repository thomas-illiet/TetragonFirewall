#!/usr/bin/env bash
set -euo pipefail

namespace=demo
client=restricted-client

kubectl -n "${namespace}" wait --for=condition=Ready pod/${client} --timeout=120s
kubectl -n "${namespace}" wait --for=condition=Available deployment/allowed-backend deployment/denied-backend --timeout=120s

mode=$(kubectl -n tetragon-firewall get configmap firewall-policy -o jsonpath='{.data.config\.yaml}' | awk '/^mode:/ {print $2}')
echo "Policy mode: ${mode}"

kubectl -n "${namespace}" exec "${client}" -- curl -fsS --max-time 3 http://allowed-backend:8080
kubectl -n "${namespace}" exec "${client}" -- getent hosts allowed-backend

if [[ "${mode}" == "enforce" ]]; then
  if kubectl -n "${namespace}" exec "${client}" -- curl -fsS --max-time 3 http://denied-backend:8080; then
    echo "ERROR: denied-backend was reachable" >&2
    exit 1
  fi
  echo "Denied backend correctly blocked."
else
  echo "Audit mode leaves denied traffic reachable; inspect firewall-agent logs before enabling enforcement."
fi
