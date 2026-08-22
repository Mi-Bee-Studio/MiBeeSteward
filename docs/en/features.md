# MiBee Steward Feature Overview

This page is the complete capability inventory of MiBee Steward, baselined on **v0.5.0** (released 2026-08-19). MiBee Steward is a **device/network-layer asset discovery, identification, and registry** tool — it answers three questions: *What devices are on the network? What are they? Are they still alive?* Every feature serves those questions; work outside the deliberate [product scope](product-scope.md) is left to mature tools.

![Dashboard](images/dashboard.webp)

## Capability map

| Layer | Modules | In one line |
|---|---|---|
| Discovery | Multi-protocol scanning / passive discovery / router-side sources / eBPF | Find what's on the network |
| Identification | Fingerprint rule library / OUI vendor / device-type inference | Recognize what it is (brand, model, type) |
| Registry | Asset inventory / heartbeat liveness / device systems | Keep a living ledger |
| Understanding | L2 topology / change detection / TLS certificate inventory | Understand relationships and changes |
| Operations | Config backup / synthetic probing / notifications / distributed agents | Day-to-day asset ops |
| Platform | REST API / Prometheus endpoints / Web UI / RBAC | Integration & governance |

## Discovery

**Scanner engine v2**: a plugin-based five-layer pipeline (probe → classify → handle → persist → orchestrate). Adding a protocol means one Classifier + one Handler — the orchestration and persistence layers never change.

- **Active probes**: ICMP, TCP port scan, SNMP (v1/v2c/v3 USM), HTTP, RTSP, ONVIF, ARP, mDNS/SSDP/NetBIOS (UDP), rDNS (configurable DNS servers), SMB2 negotiate, FTP banner; exponential-backoff retry (1s → 2s → 4s, network errors only).
- **Cascading deep collection**: find HTTP → probe `/metrics` → identify Prometheus → cascade to node_exporter → auto-backfill hardware info. One scan progressively refines the device portrait.
- **Passive discovery service** (opt-in): ARP-diff plus passive mDNS/SSDP listening between scheduled scans shrinks the discovery-to-registry gap to about a minute.
- **Router-resident sources** (when running on the router): DHCP leases (dnsmasq), conntrack table, hostapd WiFi stations (signal/association time), dnsmasq DNS query logs (passive DNS fingerprinting).
- **Router ARP tables**: SNMP walks of routers' ARP tables resolve MACs for cross-subnet devices.
- **eBPF passive observer** (optional build): a TC-ingress program sniffing WS-Discovery multicast and TCP magic bytes as supplementary evidence.
- **Raw-frame LLDP listener** (optional build): AF_PACKET capture of ethertype 0x88cc for endpoints that don't expose SNMP.
- **Discovery funnel status**: received → suppressed → known-skip → identify → alive-confirm → registered, with full counters and recent discoveries.

![Scanner](images/pb-scanner-form.webp)

## Identification

- **Data-driven fingerprint rule library**: identification rules are YAML data, not hardcoded Go — loaded at startup from a local path or embedded assets. Adding a vendor/model signature is one YAML entry; community contributions welcome.
- **Imported corpora**: Rapid7 Recog (Apache-2.0, ~1,100+ rules) + SNMP tables (~2,500+ rules total), converted via `cmd/fpimport`; nmap corpora are clean-room reference only (license incompatibility).
- **Protocol fingerprint classification**: banner, HTTP (Server header/HTML body), RTSP, ONVIF device info, SNMP sysObjectID/sysDesc, Prometheus/node_exporter, TLS certificates, SSH/Telnet banners.
- **Camera cross-evidence fusion**: RTSP + ONVIF + HTTP three-stage classifiers tuned for IP cameras (SNMP bitmask heuristics remain Go code).
- **OUI vendor inference**: longest-prefix match across IEEE MA-S(/36)/MA-M(/28)/MA-L(/24) registries, distinguishing NIC silicon vendor from the device's self-declared brand; an embedded curated CC-BY-SA table works out of the box, configurable full IEEE data overrides it.
- **Device-type inference table**: the hostname/brand/port → type keyword table is data too (YAML), with `heuristic` (hostname guess, `?` badge in UI) vs `protocol` (protocol evidence) source markers.
- **MAC observation flags**: locally-administered (U/L) and multicast bits recorded as neutral observability fields — they never change asset identity.

![Fingerprint coverage](images/pb-fingerprints.webp)

## Registry & Liveness

- **Multi-network inventory**: `networks` + composite-unique `(ip, network_id)` — the same private IP can exist on different LANs; MAC is the primary upsert key so roaming devices stay one asset; `device_uuid` keys all satellite tables, so IP changes don't fork history.
- **Heartbeat probing**: per-device ICMP/TCP/HTTP/SNMP probes and intervals (default 30s); 5 consecutive failures mark offline; known-offline devices are probed with backoff (default every 10 ticks); a reviving scan clears the failure count.
- **Liveness time series**: `device_liveness` records one online/offline verdict per device per tick; online ratio, offline duration, and history are queryable — status flips no longer flood the change log.
- **Silent-asset retention**: scanner-discovered devices without heartbeats are pruned after 7d (MAC-bearing) / 24h (MAC-less); manually entered devices are never auto-deleted.
- **Device systems**: multiple installed systems per device with entry URLs, card-grid UI with category badges.
- **Attachments**: manuals/photos/receipts uploaded to `data/uploads` and attached to devices.

## Topology

- **Switch-side L2 adjacency**: LLDP-MIB (cross-vendor standard), CISCO-CDP-MIB (`cdpCacheTable`), Bridge-MIB forwarding DBs, Q-BRIDGE-MIB (`dot1qTpFdbPort`, VLAN-aware MAC→port), STP-MIB (root bridge / designated port / port roles), IF-MIB (ifIndex → human port names).
- **Materialized topology edges**: `device_neighbors` → `topology_edges` (device↔device edges with local/remote port, VLAN tag, STP role); subnets and VLAN tables (802.1Q) update per scan.
- **Visualization**: layered force-directed layout (core/distribution/access colored; the legend doubles as a per-layer filter), search-and-focus dimming, neighbor highlight + node detail card, port drill-down; incremental rebuilds keep large graphs interactive.

![Network topology](images/pb-topology.webp)

## Change Detection

- **Event types**: `device_added` / `device_changed` / `device_lost` (plus `device_config_changed`), written to `change_log` and pushed to an in-process Watcher.
- **Anti-jitter**: consecutive-scan miss-count threshold (default 2) prevents single-miss flaps; agent networks detect loss via lease TTL with decaying flap counts.
- **Device replacement detection**: on same-IP replacement the IP holder wins, identity is force-overwritten, the old row goes offline, and the old→new relation lands in the change log.
- **Consumption**: `GET /api/v1/changes` history; `GET /changes/watch` SSE stream; UI timeline with structured before/after diffs.

![Change history](images/pb-changes.webp)

## Device Config Backup (v0.5.0, opt-in)

Oxidized/RANCID-style config pull and versioning for network gear:

- **Scheduled pulls**: SSH `running-config` fetches for routers/switches/firewalls; versioned storage (`device_configs`); a new version is cut only on change.
- **Vendor command matrix**: JunOS `show configuration | display set`; HP/Aruba/H3C/Comware `display current-configuration`; Cisco IOS/NX-OS, Arista, Huawei VRP, MikroTik and unknowns fall back to `show running-config`.
- **SSH host-key TOFU**: trust-on-first-use recording.
- **Diffing**: unified diff between any two versions; a Config History tab on device detail with hand-colored rendering; config changes feed change detection and notifications.
- **Encrypted credential vault**: SSH credentials AES-256-GCM encrypted at rest; encrypted on write, redacted on read.

## Synthetic Probing (v0.5.0)

Blackbox-style periodic probing of external assets — public sites, hosted TLS ports, anything "outside" the network:

- **Four modules**: `http` (status <400 = success; https collects the cert chain), `tls` (full chain), `tcp`, `icmp`; per-target interval (10s–86400s) and timeout (1–60s).
- **Engine**: 10s tick re-reads targets (CRUD effective without restart), 8-way concurrency, resume from last run, manual trigger.
- **Certificate inventory**: reuses the scanner's cert-chain collector; SNI auto-derived; last-known-good chain kept on transient failure.
- **Metrics & alerts**: `mibee_probe_up` / `mibee_probe_duration_seconds` / `mibee_probe_cert_expiry_timestamp_seconds`, with example alert rules (target down, cert expiring).

![Probes](images/pb-probes.webp)

## Notifications

- **Channels**: webhook (Feishu/WeCom/Telegram/Discord all work over webhook) and email (SMTP), with test dispatch.
- **Built-in rules** (v0.5.0): event type (device lost/recovered/added/changed/config-changed) × scope (all/network/device) → target channel; per-(rule×device) cooldown (default 30 minutes) against flapping — deliberately a thin rule→channel hop, not an alerting engine.
- **Per-user unread tracking**: header bell with unread count, cleared on open.

## Distributed Agents

- **Cross-subnet model**: center + agent (`mibee-agent`, a separate CGO-free binary running as a regular user); agents scan the local LAN and report to the center over HTTPS.
- **NAT-friendly pull model**: the agent initiates every connection (report + ~60s command poll) — no inbound exposure of the center.
- **Anti-entropy fast path**: `X-Network-State-Hash` (SHA-256 over the alive set's identity fields); on match the center skips per-host processing and refreshes leases only — near-zero overhead on stable networks.
- **Lease model**: agent reports refresh per-device leases; TTL expiry (default 5 min) plus a background sweeper detect loss.
- **Command channel**: the center enqueues scan and optional remote-ops commands (restart/config-reload/log-tail — gated on both sides, audit-logged); agents poll → ack → complete.
- **Machine tokens**: agent bearer tokens bound to `agent_id` + `network_id`, admin CRUD, one-time display.

![Agents](images/agents.webp)

## Security & RBAC

- **Authentication**: JWT (cookie-first + Bearer fallback), login lockout, token blacklist; optional TOTP 2FA.
- **Multi-role capability model** (v0.5.0): `admin` / `operator` / `viewer` map to fine-grained capability sets (`CapDeviceRead`, `CapScanTrigger`, …); every route is gated by capability; unknown roles grant nothing.
- **Object-level network scoping**: per-user network grants; in `closed` mode non-admins see only granted networks across the whole read surface (devices, scans, changes, topology, exports), unauthorized details return 404; admin always bypasses.
- **SNMPv3 credential vault**: USM credentials (auth/priv passphrases + protocols, security level) AES-256-GCM encrypted at rest, never echoed back; all OID paths work under v3 (identity + every topology walk).
- **Hardening**: CSRF, rate limiting (login 10/min, global 600/min, scan 10/min), security headers, trusted-proxy-aware RealIP, full audit logging of sensitive actions, `reset-admin-password` CLI subcommand.

## API & Integrations

- **REST API** (`/api/v1`, snake_case): devices, scan tasks/runs/results, changes, networks, agents & tokens, users & grants, audit, documents, notification channels & rules, credentials, probe targets, topology, discovery status.
- **Prometheus endpoints**: `/metrics` (device-status gauges, heartbeat counters/latency histograms, scanner run/duration/tasks, probe metrics, network-drift gauge); `/sd` HTTP service discovery auto-registers discovered assets into Prometheus.
- **Import/export**: CSV import (with per-row errors), CSRF-safe CSV/JSON export.
- **Ecosystem**: example Grafana dashboards, 7 example alert rules (down, 5xx, heartbeat failures, DB-lock bursts, memory, probe target down, cert expiring), n8n and Home Assistant guides.

## Web UI

A SvelteKit 5 SPA embedded in the binary: Chinese/English i18n (auto-detect + locale formatting), light/dark themes, responsive layout, keyboard accessibility.

| Page | Capabilities |
|---|---|
| Dashboard | Configurable widget cards (status distribution, heartbeat success, type distribution, location), scan activity, needs-attention banner + one-click scan |
| Devices | Cross-network aggregation, filters (status/type/network), optional columns (persisted), server-side search/sort/pagination (numeric IP ordering), topology view toggle |
| Device detail | Health banner + tabs: overview / scan discovery (services/ports/banners) / network & certificates (TLS chains, neighbors, subnets) / systems / heartbeat / config history |
| Scan center | Quick scan (sync), scan tasks (async, cancellable), scan results, passive-discovery funnel |
| Topology | Layered layout, layer filters, search focus, neighbor highlight, port drill-down |
| Changes | Timeline + event filters + structured diffs |
| Probes | Target management, status/latency/cert-days badges, history and cert-chain modals |
| Agents/Networks/Users/Audit | Distributed ops and governance surfaces |
| Settings | Profile/password/TOTP/theme/language; notification channels & rules; SNMP credentials |

![Device detail](images/pb-camera-overview.webp)

## Deployment & Operations

- **Single binary, zero dependencies**: CGO-free (modernc.org/sqlite, pure Go), frontend embedded via `go:embed`, embedded SQLite (WAL); `make build-all` cross-compiles linux amd64 + arm64.
- **Deployment shapes**: systemd + Nginx, Docker (multi-stage non-root, multi-arch GHCR images, bridge/host/macvlan profiles), OpenWrt procd (center + agent, UCI config, ARMv7).
- **Retention**: per-table batched sweeps (heartbeat 7d, scans 30d, audit 90d, … — all configurable); silent-device pruning.
- **Data safety**: automatic startup migrations (with pre-migration `VACUUM INTO` backup), schema-version gating, `scripts/backup.sh` (`.backup` + integrity check, 7-day retention).
- **Configuration**: koanf (YAML + `MIBEE_*` env overrides); the example config covers every module.
- **Observability**: slog structured logging, request/scanner/heartbeat/probe metrics, bind-retry against restart storms, graceful shutdown.

## Product scope (what it deliberately doesn't do)

Consistent with the [product scope](product-scope.md), the following are intentionally out of scope and left to better tools, glued via `/metrics` and `/sd`:

| Not built | Use instead |
|---|---|
| Alerting engine (thresholds/silences/routing trees) | Prometheus + Alertmanager |
| Free-form dashboards | Grafana |
| Status pages | Uptime Kuma / gatus |
| Host deep monitoring (CPU/memory/disk) | node_exporter / Netdata |
| L7 service discovery | Consul / etcd |
| Config push/management | Ansible / Oxidized |

The built-in notification rules are a thin device-event → channel forward — when you need real alerting semantics, put Alertmanager in front.
