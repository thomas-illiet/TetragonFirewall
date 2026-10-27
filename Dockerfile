# syntax=docker/dockerfile:1
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/firewall-agent ./cmd/firewall-agent

FROM scratch
COPY --from=build /out/firewall-agent /firewall-agent
USER 0:0
ENTRYPOINT ["/firewall-agent"]
