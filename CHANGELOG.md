# Changelog

All notable changes to MiBee Steward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
