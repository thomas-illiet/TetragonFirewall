# syntax=docker/dockerfile:1
FROM golang:1.24-bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm \
    && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./internal/bpf \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/firewall-agent ./cmd/firewall-agent

FROM build AS test
RUN make test-all

FROM scratch AS runtime
COPY --from=build /out/firewall-agent /firewall-agent
USER 0:0
ENTRYPOINT ["/firewall-agent"]
