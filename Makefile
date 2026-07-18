BINARY_NAME=mibee-steward
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-s -w -X mibee-steward/internal/version.Version=$(VERSION)
BUILD_DIR=bin

.PHONY: all build build-all build-frontend build-server build-agent build-with-ebpf build-with-lldp clean test dev migrate-up sync-fingerprints fpimport docker-build docker-build-priv docker-up docker-up-bridge docker-up-macvlan docker-down docker-logs

all: build

build-frontend:
	cd web && npm run build

build-server:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/

# Discovery agent (distributed mode): lightweight scan + report binary. No
# frontend, no SPA — just the scannerv2 engine + upstream reporter.
build-agent:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/mibee-agent ./cmd/agent/

build: build-frontend build-server

build-all: build-frontend
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server/

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server/

# Build with the eBPF passive observer enabled. Requires clang/llvm/bpftool
# and kernel BTF on the build host; produces a binary that, at runtime, needs
# Linux >=5.8 + CAP_BPF/CAP_NET_ADMIN when scanner.ebpf.enabled is true.
# Without those runtime privileges the observer degrades to active-only.
build-with-ebpf: build-frontend
	cd bpf && $(MAKE) tc_ingress.o
	CGO_ENABLED=0 go build -tags WITH_EBPF -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/

# Build with the raw-frame LLDPDU listener enabled (needs CAP_NET_RAW at runtime;
# default build ships a no-op stub so it stays unprivileged).
build-with-lldp: build-frontend
	CGO_ENABLED=0 go build -tags WITH_LLDP -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/

clean:
	rm -rf $(BUILD_DIR) web/dist web/.svelte-kit
	cd bpf && $(MAKE) clean || true

test:
	go test ./...

dev:
	cd web && npm run dev &
	CGO_ENABLED=0 go run ./cmd/server/

migrate-up:
	@echo "Migrations run automatically on server startup via the embedded db/schema.sql (see db/embed.go). No manual step required."

# sync-fingerprints copies configs/fingerprints/*.yaml into the classify
# package's embed directory so they ship in the binary (//go:embed). Run this
# before building whenever fingerprint rules change. The configs/ dir is the
# source of truth; this target keeps the embed copy in sync.
sync-fingerprints:
	@mkdir -p internal/service/scannerv2/classify/fingerprint-assets
	@cp -v configs/fingerprints/*.yaml internal/service/scannerv2/classify/fingerprint-assets/
	@echo "fingerprints synced to embed dir"

# fpimport converts third-party fingerprint databases into the MiBee rule format.
# See cmd/fpimport/ and docs/fingerprint-spec.md for supported sources.
fpimport:
	@go run ./cmd/fpimport/ $(ARGS)

# ---- Docker targets -------------------------------------------------------
# Pick the network profile that matches your deployment intent. The scanner's
# ICMP/ARP/MAC discovery is network-namespace-sensitive — see docker-compose.yml
# header comment and docs/zh/deployment.md "Docker 网络模式选型".
#
# Recommended for real scanning: host profile (shares host netns, sees the LAN).
#   make docker-up            # = docker-up-host (builds + starts --profile host)
#
# Demo / UI-only: bridge profile (NAT'd, ICMP/ARP/MAC degraded).
#   make docker-up-bridge
#
# Container-as-LAN-device: macvlan profile (own LAN IP; set MIBEE_MACVLAN_*).
#   make docker-up-macvlan

# Default image = unprivileged (LLDP/CDP/eBPF compiled as stubs).
docker-build:
	docker compose --profile host build

# Privileged image variant — bakes in the raw-frame LLDP/CDP listeners and the
# eBPF TC observer. Still needs runtime caps (cap_add NET_RAW/NET_ADMIN/BPF).
docker-build-priv:
	BUILD_TAGS=WITH_LLDP,WITH_CDP,WITH_EBPF docker compose --profile host build

# Default: host profile (recommended). Builds first if needed.
docker-up: docker-build
	docker compose --profile host up -d

docker-up-host: docker-up

docker-up-bridge:
	docker compose --profile bridge up -d --build

docker-up-macvlan:
	docker compose --profile macvlan up -d --build

docker-down:
	docker compose --profile host down
	docker compose --profile bridge down
	docker compose --profile macvlan down

docker-logs:
	docker compose --profile host logs -f
