.DEFAULT_GOAL := help

BPF_SOURCE := internal/bpf/firewall.c
BPF_GENERATED := \
	internal/bpf/firewall_bpfel.go \
	internal/bpf/firewall_bpfel.o \
	internal/bpf/firewall_bpfeb.go \
	internal/bpf/firewall_bpfeb.o

.PHONY: help tools generate clean-generated build test test-race coverage vet manifests test-all test-container image test-ebpf clean

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tools: ## Verify that the eBPF compilation tools are installed.
	@command -v clang >/dev/null || { echo "clang is required" >&2; exit 1; }
	@command -v llvm-strip >/dev/null || { echo "llvm-strip is required" >&2; exit 1; }
	@go tool bpf2go -h >/dev/null 2>&1 || { echo "bpf2go is unavailable; run 'go mod download'" >&2; exit 1; }

generate: tools ## Generate untracked eBPF objects and Go bindings.
	go generate ./internal/bpf

clean-generated: ## Remove generated eBPF objects and Go bindings.
	rm -f $(BPF_GENERATED)

build: generate ## Build the Linux firewall agent.
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/firewall-agent ./cmd/firewall-agent

test: generate ## Run the unit test suite.
	go test ./...

test-race: generate ## Run unit tests with the Go race detector.
	go test -race ./...

coverage: generate ## Write a Go coverage profile to coverage.out.
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-all: test test-race vet build manifests ## Run every portable validation.
	bash -n scripts/*.sh

test-container: ## Run the complete test suite in the Linux builder image.
	docker build --target test -t "$${IMAGE:-tetragon-firewall:test}" .

vet: generate ## Run Go static analysis.
	go vet ./...

manifests: generate ## Validate all Kubernetes YAML documents.
	go run ./tools/validate-yaml deploy/firewall.yaml deploy/demo.yaml deploy/tetragon-audit.yaml

image: ## Build the container image, including eBPF generation in the builder.
	docker build -t "$${IMAGE:-tetragon-firewall:dev}" .

test-ebpf: image ## Load and attach generated programs on the local Linux kernel.
	IMAGE="$${IMAGE:-tetragon-firewall:dev}" ./scripts/test-ebpf.sh

clean: clean-generated ## Remove all local build and coverage outputs.
	rm -rf bin coverage.out
