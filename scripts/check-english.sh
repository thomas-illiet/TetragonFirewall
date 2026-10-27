#!/usr/bin/env bash
set -euo pipefail

if LC_ALL=C grep -RIn \
  --exclude='go.sum' \
  --exclude='firewall_bpfel.go' \
  --exclude='firewall_bpfeb.go' \
  --exclude='*.o' \
  --exclude-dir='.git' \
  '[^[:print:][:space:]]' README.md Makefile Dockerfile cmd deploy internal scripts tools .github; then
  echo "Non-ASCII text found. Keep project-facing text in English ASCII." >&2
  exit 1
fi
