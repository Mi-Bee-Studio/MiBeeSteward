# Changelog

All notable changes to MiBee Steward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-18

**Full L2 topology + TLS certificate inventory + container images** — v0.3.0
completes the topology story started in v0.2.0 (CDP/Q-BRIDGE/STP probes, radial
visualization, neighbor identity inference), adds a TLS certificate inventory
that collects the full cert chain from every TLS-wrapped service on each device,
and introduces official multi-arch container images on GHCR.

### TLS certificate inventory
- **TLS cert collection** (`probe/cert_collector.go`): single source of truth —
  `CollectCertChain(ctx, ip, port, timeout)` performs a TLS handshake
  (InsecureSkipVerify for inventory) and extracts the full peer chain. Per-cert:
  Subject/Issuer/SAN (DNS/IP/email)/serial/validity/sig algorithm/key algorithm
  + bits (RSA/ECDSA/Ed25519)/is_ca/self_signed/SHA-256 fingerprint/PEM;
  per-handshake: TLS version, cipher suite, best-effort trust verdict. Failure
  path returns an error record (still persisted) so the UI can show "we tried
  this port".
- **TLS-wrapped service handlers** (`handler/tls_collect.go`): 8 handlers
  (`https`, `ldaps`, `smtps`, `imaps`, `pop3s`, `ftps`, `ircs`, `telnets`)
  sharing one `tlsCollectHandler` core — each `Collect()` calls
  `probe.CollectCertChain` and returns a `TLSCertCollected` payload. Handler
  count 21 → 29.
- **Extended MiscClassifier**: TLS-wrapped service ports (465/989/990/992/993/994/995)
  now asserted as service identities so the cert-collect handler runs for them.
- **Extended TLSProbe**: default port set expanded from 4 to 12 (+ 465/636/989/
  990/992/993/994/995). Refactored to emit richer evidence fields (`not_before`/
  `not_after`/`sig_algorithm`/`key_algorithm`/`fingerprint_sha256`/`san_email`).
- **`host_tls_certs` table**: one row per cert in each port's chain (cert_index
  0 = leaf, 1..N = issuers); PEM + typed columns; indexed on `(ip, port)` and
  `not_after` (for expiry sweeps).
- **Read API** `GET /api/v1/devices/{id}/certificates`: per-port grouping with
  leaf + chain; status-coloring metadata (TLS version, cipher suite, trust
  verdict, error).
- **Frontend TLS sub-panel**: new "TLS 证书" panel under Scan Discovery — one
  clickable row per port with status-colored left border (green=valid / amber=
  expiring <15d / red=expired), day-count badge, self-signed/trusted tags.
- **`CertificateModal.svelte`**: full-chain viewer — status header, summary field
  grid (Subject/Issuer/Validity/SAN/algorithms/fingerprint), collapsible chain
  entries, PEM block with copy-to-clipboard.
- **Retention** `retention.host_tls_certs_days` (default 30).
- **i18n**: new `certificates` section (34 keys, EN + ZH).

### Topology probe breadth
- **CDP-MIB probe** (`active:cdp_mib`): walks CISCO-CDP-MIB `cdpCacheTable`
  on Cisco/CDP-speaking switches. Uses device id as the neighbor merge key.
  Emits `protocol:"CDP"` neighbor edges.
- **Q-BRIDGE-MIB probe** (`active:q_bridge_mib`): walks IEEE 802.1Q
  `dot1qTpFdbPort` for VLAN-aware MAC→port forwarding entries. Recovers L2
  adjacency on tagged/inter-VLAN topologies. Emits `protocol:"Q-BRIDGE"` edges
  with ifName-resolved port names.
- **STP-MIB probe** (`active:stp_mib`): walks BRIDGE-MIB `dot1dStp` for
  Spanning Tree facts (root bridge, designated port, port role/state). Emits
  `protocol:"STP"` evidence.
- **IF-MIB ifName resolution** (`probe.ResolvePortNames`): shared helper that
  turns numeric ifIndex/port values into human-readable interface names (e.g.
  `GigabitEthernet0/1`). Used by CDP/Q-BRIDGE probes.

### Topology visualization
- **Network topology page** (`/topology`): a full-network radial tree view
  (ECharts `tree` series, newly tree-shaken in) of devices as nodes and
  `device_neighbors` as edges. Node color by device type; edge color by protocol
  (LLDP blue / Bridge-MIB green); dashed edges point at unidentified neighbors.
  Network filter + 60s auto-refresh; click a node to open its detail page.
- **Device-detail Neighbors panel**: a table of a device's L2 neighbors with the
  neighbor's name/IP/type (via a device JOIN — `neighbor_device_id` was always
  NULL in v0.2.0; now resolved at query time) and a link to its detail page.

### LLDP discovery (two paths)
- **SNMP LLDP-MIB probe** (`active:lldp_mib`, default ON): walks `lldpRemTable`
  on SNMP-speaking switches/APs that run LLDP — the cross-vendor standard.
  Emits `protocol:"LLDP"` neighbor edges through the existing neighbor pipeline
  (zero new wiring). Unprivileged (UDP/161); no new dependencies.
- **Raw-frame LLDPDU listener** (`WITH_LLDP` build-tag, default OFF): captures
  ethertype 0x88cc frames via AF_PACKET (needs CAP_NET_RAW) to see
  LLDP-broadcasting endpoints (IP phones, APs, NAS) that don't run SNMP LLDP-MIB.
  Mirrors the eBPF observer's build-tag pattern — the default build ships a
  no-op stub so it stays unprivileged (`make build-with-lldp` to enable).

### Neighbor identity inference
- Orchestrator gains pluggable `NeighborIdentityInfer` callback wired to the
  RuleClassifier — CDP/LLDP neighbors get vendor/model/type inferred from their
  platform string.
- **`EnrichDeviceByMAC`**: enriches a device's vendor/model/type/hostname by MAC
  (the neighbor merge key), preserving existing non-empty values.

### Container images & deployment profiles
- **GHCR publishing**: every `v*` tag now builds a multi-arch (linux/amd64 +
  linux/arm64) image at `ghcr.io/mi-bee-studio/mibeesteward`, tagged
  `:latest` / `:<version>` / `:<major>.<minor>` / `:sha-<short>`. The release
  workflow's `publish` job waits on `[release, docker]` so a GitHub Release is
  only created when both binaries and image succeed. Image is the unprivileged
  variant (LLDP/CDP/eBPF compiled as stubs).
- **Docker network-mode profiles**: three compose profiles so the deployment
  shape matches the intent — `bridge` (default, NAT'd, MAC/ARP degraded),
  `host` (recommended, ≈ bare-metal probe fidelity), `macvlan` (own LAN IP).
  Measured on the test LAN: the default docker bridge found 0/26 device MACs vs
  30/31 with host networking (the container's `/proc/net/arp` only sees the
  bridge gateway). See `docs/{en,zh}/deployment.md` § "Docker network mode".
- **Dockerfile**: `BUILD_TAGS` arg (WITH_LLDP/CDP/EBPF opt-in), opt-in `SETCAP`
  (file caps break exec() when the cap isn't in the bounding set, so default
  off), `NPM_REGISTRY`/`GOPROXY` args for restricted-network builds,
  `NODE_OPTIONS` for the vite heap, `/data` pre-owned by the non-root user.
- **Makefile**: `docker-build` / `-priv` / `-up` / `-up-bridge` /
  `-up-macvlan` / `-down` / `-logs` targets.
- **`configs/config.docker.yaml`**: container template (network.cidr, /data
  paths, bridge-mode router_arp guidance).

### CI
- **`docker-build` smoke-test job** (ci.yml): on every PR, builds the image
  (amd64 only, no push) and boots it with a minimal config, waiting up to 30s
  for `/health` — catches Dockerfile/compose regressions before a tag.
- **Node.js 20 deprecation**: actions still target Node 20; GitHub is forcing
  Node 24 (warning, not failure). Upgrade pending.

### Retention hardening
- `device_neighbors` and `host_services` now have retention sweepers (they grew
  unbounded in v0.2.0 — a latent bloat bug). Defaults: 90d neighbors (topology
  history value), 30d host_services. Per-table `retention.*` config keys +
  `days<=0` safety guard.
- Also fixes a latent sqlc v1.27.0 bug: a non-ASCII char in a query comment
  corrupted sibling-query codegen (silently emitted broken SQL — runtime query
  failure, not a build error).

### Test coverage
- **taskservice** (scan-task state machine): was zero-tested. Now covers
  CRUD, validation, pagination clamping, not-found mapping, and nil-scheduler
  behavior.
- **Fingerprint golden test**: a quality regression guard (real-world evidence
  samples → expected service/metadata), distinct from the existing count test —
  so a rule edit that breaks identification fails even if the count is unchanged.

### Fingerprint library
- Extended `snmp-data.yaml` with consumer/SMB networking sysObjectID prefixes
  underrepresented vs the enterprise-heavy table (ASUS, D-Link, Zyxel, Tenda,
  DrayTek, alternate TP-Link/Mikrotik subtypes). Each is one YAML entry.
- New `lldp-cdp.yaml` rules for CDP/LLDP device identification.

### Fixes
- Removed deprecated `tls.VersionSSL30` (staticcheck SA1019).
- gofmt + golangci-lint cleanup (QF1008, unused params, embedded selectors).

## [0.2.0] - 2026-07-13

Distributed multi-network discovery, topology-aware probing, a change-detection
engine, and a data-driven fingerprint rule library. The release ships **two
binaries**: the center (`mibee-steward`, the existing SPA-embedded server) and
the new discovery **agent** (`mibee-agent`) for remote LANs.

### Distributed discovery (center + agent)
- **Agent binary** (`cmd/agent`): runs the scannerv2 engine against the LAN it
  sits on and reports results to the center via `POST /api/v1/agents/report`.
  Pull model — the agent initiates all connections (report + poll commands), so
  it works behind NAT. CGO-free, runs as a regular user.
- **Center ingestion**: agent reports are converted to local device portraits via
  the device bridge; agent-managed networks are excluded from the center's own
  cross-subnet probing (the agent's reports ARE the liveness signal).
- **Anti-entropy fast path**: agents send an `X-Network-State-Hash` header
  (SHA-256 of the alive set's identity+classification fields); on a match the
  center skips the per-host device bridge and only refreshes leases — the
  steady-state path for stable networks.
- **Lease model**: agent reports refresh per-device leases; lost detection for
  agent networks is TTL-based (`LeaseSweeper`, default 5m TTL), distinct from
  the center's own consecutive-scan `DetectLost`.
- **Command channel**: center enqueues scan commands; the agent polls, acks, and
  completes them (~60s cycle).
- **Agent token auth**: machine-to-machine bearer tokens bound to a
  `network_id` + `agent_id` (admin CRUD at `/api/v1/agents/tokens`).
- **Watch SSE + agent disconnect backfill**: `GET /changes/watch` foundation;
  agents reconnect by re-sending their last hash.

### Topology & probing
- **Bridge-MIB neighbor probe**: walks `BRIDGE-MIB` to discover L2 neighbors and
  persists `device_neighbors` (Phase 4 topology layer).
- **SMB2 Negotiate probe + FTP banner reliability**: richer service evidence.
- **TLS cert CN brand override**: recognizes OpenWrt / GL.iNet / iStoreOS from
  certificate subject/issuer fields.
- **Router ARP** walk for cross-subnet MAC resolution.

### Change-detection engine
- Records `device_added` / `device_changed` / `device_lost` to `change_log` +
  an in-process `Watcher` (center only). `device_lost` has two paths:
  consecutive-scan `miss_count` (center's own network) and TTL-based lease
  expiry (agent networks). Query via `GET /api/v1/changes`; history page in the UI.

### Fingerprint rule library (data-driven)
- Identification rules are now **data** (YAML), not hand-written Go. A
  `RuleClassifier` loads rules at startup from a configured path or the rules
  embedded in the binary. Adding a device signature = one YAML entry.
- **Imported corpora** (license-clean): Rapid7 Recog (~1174 rules, Apache-2.0)
  and SNMP/Recog data tables (~2554 rules total after scoping). nmap's NPSL is
  excluded (never imported). See `cmd/fpimport/` for the converter.
- The standalone engine lives at
  [github.com/Mi-Bee-Studio/mibee-fingerprints-go](https://github.com/Mi-Bee-Studio/mibee-fingerprints-go).
- Logic that can't be a single declarative rule (SNMP bitmask heuristic, camera
  cross-evidence fusion) stays as Go code.

### Management UI
- **Networks admin page**: create / edit / delete logical networks
  (POST/PUT/DELETE `/api/v1/networks`) — the network registry the agents bind to.
- **Discovery status page**: passive host-discovery runtime counters + recent
  discoveries (`GET /api/v1/discovery/status`).
- **Devices page**: user-toggleable optional columns (persisted to localStorage);
  device name links to the detail page; the type union now mirrors all device
  categories.
- **Change history page** with structured before/after diffs.
- **CSRF-safe exports**: CSV/JSON downloads now route through the API client
  (previously bypassed it via raw `fetch`, dropping the CSRF header).

### Operational
- Server bind-retry prevents restart storms from lingering sockets.
- Agent HTTP-transport keep-alive deadlock fix + scan deadline enforcement.
- Anti-entropy + lease model + heartbeat scope governance.

### Known limitations
- The center is single-instance (SQLite). Multi-center clustering is not in scope.
- No built-in alerting — integrate with Alertmanager / Uptime Kuma.
- eBPF passive observer requires a special build (`make build-with-ebpf`) and
  runtime privileges.

## [0.1.0] - 2026-07-07

First public release. MiBee Steward is a device management & network-layer
auto-discovery system with an embedded SvelteKit SPA, packaged as a single
binary.

### Core capabilities
- **Network discovery**: plugin-based scanner v2 (ICMP, TCP portscan, SNMP,
  RTSP, ONVIF, HTTP, ARP, UDP-discovery) with 5-layer pipeline
  (probe → classify → handler → persist).
- **Identity inference**: device type/vendor/OS/hostname inferred from scan
  evidence (cameras, servers, switches, routers, NAS, etc.).
- **Device registry**: full CRUD, batch operations, CSV export, custom
  attributes, document linking, device-systems grouping.
- **Heartbeat monitoring**: asset-freshness probing (ICMP/TCP/HTTP/SNMP) with
  dedicated time-series store, in-memory status cache, WAL-isolation-safe sync.
- **Authentication**: JWT (cookie + Bearer), 2FA (TOTP), login lockout, token
  blacklist, RBAC (admin/user).
- **Dashboard**: configurable widgets, Prometheus-backed time-series charts.
- **Audit logging**: all admin actions recorded.
- **Prometheus integration**: `/metrics` + `/sd` (HTTP service discovery).
- **Notification channels**: webhook/email channel management with test dispatch.
- **i18n**: Chinese and English, fully translated.

### Deployment
- Single binary (CGO-free, SQLite via modernc.org/sqlite), embedded SPA.
- Docker (multi-stage, non-root), systemd unit, nginx reverse-proxy config.
- Configurable data retention sweeper for all high-volume tables.
- CLI: `mibee-steward -version`, `mibee-steward reset-admin-password`.

### Known limitations
- Single-instance (SQLite). Distributed/multi-network mode is future work.
- No built-in alerting engine — alerting is intentionally out of scope
  (integrate with Alertmanager/Uptime Kuma).
- eBPF passive observer requires a special build (`make build-with-ebpf`) and
  runtime privileges.
