.PHONY: generate build test vet manifests test-all test-ebpf

generate:
	go generate ./internal/bpf

build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/firewall-agent ./cmd/firewall-agent

test:
	go test ./...

test-all: test vet build manifests
	bash -n scripts/*.sh
	./scripts/check-english.sh

vet:
	go vet ./...

manifests:
	go run ./tools/validate-yaml deploy/firewall.yaml deploy/demo.yaml deploy/tetragon-audit.yaml

test-ebpf:
	./scripts/test-ebpf.sh
