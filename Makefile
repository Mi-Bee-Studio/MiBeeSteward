BINARY_NAME=mibee-steward
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-s -w -X mibee-steward/internal/version.Version=$(VERSION)
BUILD_DIR=bin

.PHONY: all build build-all build-frontend build-server build-agent build-with-ebpf build-with-lldp build-with-arpscan build-linux-amd64 build-linux-arm64 build-linux-arm build-agent-linux-amd64 build-agent-linux-arm64 build-agent-linux-arm package-openwrt package-openwrt-ipk package-openwrt-apk openwrt-stage check-openwrt clean test dev migrate-up sync-fingerprints sync-device-types sync-oui-curated docs-changelog-sync fpimport docker-build docker-build-priv docker-up docker-up-bridge docker-up-macvlan docker-down docker-logs

all: build

build-frontend:
	cd web && npm run build

build-server: sync-device-types sync-oui-curated
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/

# Discovery agent (distributed mode): lightweight scan + report binary. No
# frontend, no SPA — just the scannerv2 engine + upstream reporter.
build-agent: sync-device-types sync-oui-curated
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/mibee-agent ./cmd/agent/

build: build-frontend build-server

build-all: build-frontend sync-device-types sync-oui-curated
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server/
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm ./cmd/server/

build-linux-amd64: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server/

build-linux-arm64: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server/

# ARM 32-bit (ARMv7) — targets older ARM routers/boards (GL.iNet AR300, etc.).
# GOARM=7 is the modern soft-float baseline; the README's cross-compile section
# documents this arch for OpenWrt form B/C. MIPS is NOT supported (modernc/libc).
build-linux-arm: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm ./cmd/server/

# Agent (form B) cross-compile — same three archs as the center above. The
# agent has no frontend/embed-dist step, but it DOES embed the fingerprint
# corpus + curated OUI, so the two sync targets remain prerequisites. Without
# these targets a form-B deploy reflexively runs `make build-agent` and ships
# a HOST-arch binary to the router (observed on the MT2500: an x86-64 ELF
# flashed to aarch64 fails with a confusing "syntax error" from ash).
build-agent-linux-amd64: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/mibee-agent-linux-amd64 ./cmd/agent/

build-agent-linux-arm64: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/mibee-agent-linux-arm64 ./cmd/agent/

build-agent-linux-arm: sync-device-types sync-oui-curated
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/mibee-agent-linux-arm ./cmd/agent/

# Bundle the center for OpenWrt / iStoreOS routers (form C, no Docker): arm64
# binary + procd init script + example config + on-router installer, packed as
# one self-contained tar.gz. GOARCH=arm64 covers aarch64 routers (NanoPi R5S,
# GL.iNet mt798x, ipq807x); override GOARCH=arm for ARMv7. On the router:
#   tar -xzf mibee-steward-openwrt-arm64-*.tar.gz && ./install.sh
# (install.sh lays down binary + init, generates /etc/mibee/config.yaml on
# first install — random jwt_secret + admin password, LAN cidr from uci —
# fixes ping_group_range, then enables + starts + health-checks the service.)
# build-frontend is required because the server embeds web/dist (go:embed
# all:dist). Scripts are piped through `tr -d '\r'` so a CRLF working tree
# (Windows autocrlf) can never ship scripts busybox ash can't parse.
package-openwrt: GOARCH?=arm64
package-openwrt: build-frontend sync-device-types sync-oui-curated
	GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-$(GOARCH) ./cmd/server/
	@rm -rf $(BUILD_DIR)/openwrt-pkg && mkdir -p $(BUILD_DIR)/openwrt-pkg
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-$(GOARCH) $(BUILD_DIR)/openwrt-pkg/mibee-steward
	tr -d '\r' < deploy/openwrt/mibee-steward.init > $(BUILD_DIR)/openwrt-pkg/mibee-steward.init
	tr -d '\r' < deploy/openwrt/install.sh > $(BUILD_DIR)/openwrt-pkg/install.sh
	tr -d '\r' < configs/config.example.yaml > $(BUILD_DIR)/openwrt-pkg/config.example.yaml
	chmod +x $(BUILD_DIR)/openwrt-pkg/install.sh
	tar -czf $(BUILD_DIR)/mibee-steward-openwrt-$(GOARCH)-$(VERSION).tar.gz -C $(BUILD_DIR)/openwrt-pkg mibee-steward mibee-steward.init install.sh config.example.yaml
	@rm -rf $(BUILD_DIR)/openwrt-pkg
	@echo "-> $(BUILD_DIR)/mibee-steward-openwrt-$(GOARCH)-$(VERSION).tar.gz  (scp to router, extract, ./install.sh)"

# Shared staging root for the router package formats (.ipk / .apk): the
# binary + procd init + example config + installer laid out exactly as they
# land on the router. GOARCH is inherited from the package target that pulls
# this in (package-openwrt-ipk / package-openwrt-apk).
openwrt-stage: build-frontend sync-device-types sync-oui-curated
	@rm -rf $(BUILD_DIR)/openwrt-stage
	@mkdir -p $(BUILD_DIR)/openwrt-stage/usr/bin $(BUILD_DIR)/openwrt-stage/etc/init.d $(BUILD_DIR)/openwrt-stage/etc/mibee $(BUILD_DIR)/openwrt-stage/usr/lib/mibee \
	        $(BUILD_DIR)/openwrt-stage/usr/lib/lua/luci/controller $(BUILD_DIR)/openwrt-stage/usr/lib/lua/luci/view/mibee
	GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/openwrt-stage/usr/bin/mibee-steward ./cmd/server/
	tr -d '\r' < deploy/openwrt/mibee-steward.init > $(BUILD_DIR)/openwrt-stage/etc/init.d/mibee-steward
	tr -d '\r' < configs/config.example.yaml     > $(BUILD_DIR)/openwrt-stage/etc/mibee/config.example.yaml
	tr -d '\r' < deploy/openwrt/install.sh       > $(BUILD_DIR)/openwrt-stage/usr/lib/mibee/install.sh
	tr -d '\r' < deploy/openwrt/luci/luci-helper.sh > $(BUILD_DIR)/openwrt-stage/usr/lib/mibee/luci-helper.sh
# LuCI integration (inert files on builds without LuCI — no hard Depends):
# classic Lua controller + plain templates; no luci-compat/CBI dependency.
	tr -d '\r' < deploy/openwrt/luci/controller/mibee.lua > $(BUILD_DIR)/openwrt-stage/usr/lib/lua/luci/controller/mibee.lua
	tr -d '\r' < deploy/openwrt/luci/view/mibee/status.htm   > $(BUILD_DIR)/openwrt-stage/usr/lib/lua/luci/view/mibee/status.htm
	tr -d '\r' < deploy/openwrt/luci/view/mibee/settings.htm > $(BUILD_DIR)/openwrt-stage/usr/lib/lua/luci/view/mibee/settings.htm
	chmod 755 $(BUILD_DIR)/openwrt-stage/etc/init.d/mibee-steward $(BUILD_DIR)/openwrt-stage/usr/lib/mibee/install.sh $(BUILD_DIR)/openwrt-stage/usr/lib/mibee/luci-helper.sh
# Guard: none of the staged router files may carry a CR byte. busybox ash
# happens to tolerate CRLF scripts and Go's YAML reader tolerates CRLF
# configs, but LuCI's template parser does NOT (a raw \r inside a write("...")
# literal = "unfinished string" — field-found on iStoreOS 24.10 / R68S when
# a Makefile edit silently corrupted the tr -d patterns above). usr/bin is
# excluded: the ELF binary legitimately contains \r bytes.
	@if grep -rlq $$(printf '\r') $(BUILD_DIR)/openwrt-stage/etc $(BUILD_DIR)/openwrt-stage/usr/lib; then \
		echo "ERROR: CR bytes found in staged router files (a tr -d step above is broken?):"; \
		grep -rl $$(printf '\r') $(BUILD_DIR)/openwrt-stage/etc $(BUILD_DIR)/openwrt-stage/usr/lib; \
		exit 1; \
	fi

# Hand-rolled .ipk for opkg (OpenWrt 22.03/23.05-based iStoreOS and older):
# install/upgrade/remove via opkg with lifecycle scripts (preinst arch gate,
# postinst = install.sh --from-ipk, prerm stop+disable, postrm keeps data).
# Architecture is "all" — the binary is CGO-free/static, so the arch gate is
# the preinst uname check + postinst -version smoke run, not a toolchain
# match. Format mirrors modern feed ipks byte-for-byte: gzip(tar(./debian-
# binary, ./data.tar.gz, ./control.tar.gz)) — NOT the legacy ar container
# (field-rejected by iStoreOS opkg as "Malformed package file").
package-openwrt-ipk: GOARCH?=arm64
package-openwrt-ipk: openwrt-stage
	PKG_VER=$$(echo "$(VERSION)" | sed 's/^v//'); \
	sh ./deploy/openwrt/mkipk.sh $(BUILD_DIR)/openwrt-stage $$PKG_VER $(GOARCH) $(BUILD_DIR)/mibee-steward_$${PKG_VER}_$(GOARCH).ipk

# Hand-rolled .apk for apk-tools (OpenWrt 24.10+ / iStoreOS builds that
# replaced opkg): same content and lifecycle as the .ipk in the apk v2
# package format (gzip tar: .PKGINFO + dot-prefixed scripts first, payload
# after). Install with: apk add --allow-untrusted <file>.apk
package-openwrt-apk: GOARCH?=arm64
package-openwrt-apk: openwrt-stage
	PKG_VER=$$(echo "$(VERSION)" | sed 's/^v//'); \
	sh ./deploy/openwrt/mkapk.sh $(BUILD_DIR)/openwrt-stage $$PKG_VER $(GOARCH) $(BUILD_DIR)/mibee-steward_$${PKG_VER}_$(GOARCH).apk

# Static assertions on the OpenWrt packaging sources (#358). The R68S field
# session (iStoreOS 24.10, #355) proved this class of bug goes "local-green,
# on-router-dead": a LuCI template with a raw CR byte white-screens with
# "unfinished string", a Lua syntax slip kills the whole controller, and none
# of it is caught by go test. Fast (no build): luac -p on the controller,
# CR-byte scan + sh -n on the committed router sources. The full packaging
# smoke is `make package-openwrt-ipk` (openwrt-stage CR guard + mkipk.sh),
# exercised by the CI `openwrt` job. CR/sh checks read the GIT INDEX (`git
# show :file`) — a CRLF Windows working tree must not false-positive on files
# the committed tree stores as LF.
check-openwrt:
	@LUAC="" && for c in luac5.1 luac5.4 luac; do \
		command -v $$c >/dev/null 2>&1 && { LUAC=$$(command -v $$c); break; }; \
	done; \
	if [ -z "$$LUAC" ]; then \
		echo "ERROR: no luac found (apt install lua5.1) - LuCI controller syntax check cannot run"; exit 1; \
	fi; \
	echo "-> $$LUAC -p deploy/openwrt/luci/controller/mibee.lua"; \
	$$LUAC -p deploy/openwrt/luci/controller/mibee.lua
	@for f in deploy/openwrt/luci/view/mibee/status.htm deploy/openwrt/luci/view/mibee/settings.htm \
	          deploy/openwrt/install.sh deploy/openwrt/mkipk.sh deploy/openwrt/mkapk.sh \
	          deploy/openwrt/luci/luci-helper.sh deploy/openwrt/mibee-steward.init configs/config.example.yaml; do \
		if git show :$$f 2>/dev/null | grep -q $$(printf '\r'); then \
			echo "ERROR: CR byte in committed $$f — LuCI tparser yields 'unfinished string' (R68S #355)"; exit 1; \
		fi; \
	done; echo "-> no CR bytes in committed router sources"
	@for f in deploy/openwrt/install.sh deploy/openwrt/mkipk.sh deploy/openwrt/mkapk.sh \
	          deploy/openwrt/luci/luci-helper.sh deploy/openwrt/mibee-steward.init; do \
		if ! git show :$$f 2>/dev/null | sh -n; then \
			echo "ERROR: sh -n failed on committed $$f"; exit 1; \
		fi; \
	done; echo "-> sh -n OK on committed router scripts"

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

# Build with the active ARP-sweep discovery source enabled (needs CAP_NET_RAW at
# runtime; default build ships a no-op stub so it stays unprivileged). Combine
# with LLDP/CDP via -tags WITH_ARPSCAN,WITH_LLDP,WITH_CDP.
build-with-arpscan: build-frontend
	CGO_ENABLED=0 go build -tags WITH_ARPSCAN -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/

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

# sync-device-types copies the device-type inference table (the DATA half of
# heuristicDeviceType) from its source-of-truth location under
# configs/fingerprints/device-types/ into the runner package dir, where it is
# picked up by //go:embed (Go embed cannot reference files outside the package
# dir, so a build-time copy is required). The source lives in a SUBDIRECTORY of
# configs/fingerprints/ so the fingerprint RuleClassifier's LoadFromDir (which
# scans top-level *.yaml and would reject this different schema) ignores it.
# All build-* targets depend on this. Run `make build` (not raw `go build`) so
# the sync happens; a stale copy under runner/ will silently use old keywords.
sync-device-types:
	@cp -v configs/fingerprints/device-types/device_types.yaml internal/service/scannerv2/runner/device_types.yaml
	@echo "device_types.yaml synced to runner embed dir"

# docs-changelog-sync regenerates the docs/{zh,en}/changelog.md mirrors from
# the root CHANGELOG.md (#322). Run whenever CHANGELOG.md changes; the CI
# `docs` job runs the same script and fails on drift.
docs-changelog-sync:
	@./scripts/gen_changelog_mirror.sh

# sync-oui-curated copies the hand-maintained CC-BY-SA OUI table from configs/
# into the vendor package dir so //go:embed picks it up (Go embed cannot reach
# outside the package dir). The embedded table gives out-of-box vendor inference
# for common devices when scanner.oui_path is empty; the full IEEE set is an
# optional runtime download (scripts/fetch-oui.sh). All build-* targets depend
# on this. Run `make build` (not raw `go build`) so the sync happens; a stale
# copy under vendor/ will silently use old vendor mappings.
sync-oui-curated:
	@cp -v configs/oui-curated.txt internal/service/scannerv2/vendor/oui_curated.txt
	@echo "oui_curated.txt synced to vendor embed dir"

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
