> 本页是仓库根目录 [CHANGELOG.md](../../CHANGELOG.md) 的镜像副本（保留英文原文，便于与仓库逐字对照）。上游 CHANGELOG 更新后需同步刷新本文件。

# Changelog

All notable changes to MiBee Steward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Synthetic probing / 拨测 (Phase 1)

**Blackbox-style probing of EXPLICIT external endpoints (PR #235)** — user-configured
probe targets (typically internet resources: a public HTTPS site, a hosted mail
TLS port) probed on fixed intervals, managed via DB/API/UI. The scanner's
internal-network TLS certificate collection (`CollectCertChain`) is reused
directly against external hostnames (SNI auto-derived), extending cert-chain
inventory beyond the LAN.

- **Three tables**: `probe_targets` (name UNIQUE, module CHECK
  http/tls/tcp/icmp, interval 10–86400s, timeout 1–60s, denormalized last_*
  outcome), `probe_results` (append-only history with per-run cert summary;
  RFC3339 string timestamps), `probe_tls_certs` (each target's CURRENT chain,
  delete-then-insert; a transient handshake failure keeps the last known-good
  chain — unlike the scanner's current-state semantics).
- **Engine** (`internal/service/probetarget/`): 10s tick re-reads enabled
  targets so CRUD applies without restart; next-due times resume from
  `last_run_at` on restart (no startup storm); 8-probe concurrency bound;
  in-flight guard makes scheduled and manual runs of one target mutually
  exclusive; `POST /{id}/trigger` probes synchronously and returns the recorded
  result.
- **Modules**: http/tcp/icmp reuse the shared heartbeat probers
  (`probe.Result` gains `StatusCode`); tls — and https-flavored http — call
  `CollectCertChain` for the full chain (leaf + issuers + trust verdict +
  TLS version/cipher).
- **API** `/api/v1/probe-targets`: CRUD + trigger + `/{id}/results` +
  `/{id}/certificates` (the cert response reuses the device endpoint's
  `tlsPortCerts` shape, so the frontend `CertificateModal` works unmodified).
  RBAC: `probe:read` (viewer+), `probe:manage` (operator+).
- **Prometheus**: `mibee_probe_up` (mirrors `probe_success`),
  `mibee_probe_duration_seconds`, `mibee_probe_cert_expiry_timestamp_seconds`
  (mirrors `probe_ssl_earliest_cert_expiry`), `mibee_probe_checks_total`; two
  example alert rules (`ProbeTargetDown`, `ProbeCertExpiringSoon`) in
  `deploy/prometheus/alert_rules.yml`.
- **Retention**: `retention.probe_results_days` (default 30d) swept by the
  existing cleanup service.
- **Frontend**: `/probes` management page (status/latency/cert-days badges,
  enable toggle, history modal, certificate chain modal), zh/en i18n, nav entry.
- **sqlc note**: query-file comments must NOT contain apostrophes — sqlc's
  SQLite lexer swallows them and silently truncates the generated statement
  (documented in `db/AGENTS.md`).


### MAC bit flags: locally-administered / multicast (neutralized from Phase 1)
**Correction of #118 Phase 1 (PR #121)** — Phase 1 treated the
locally-administered (U/L) bit as a "randomized MAC" verdict and downgraded such
devices to `(ip, network_id)` identity. That was a semantic overreach: per IEEE
802 / RFC 7042 the U/L bit only means "locally administered", and it **cannot**
distinguish privacy randomization (iOS/Android, unstable) from a locally fixed
setting (soft-router / hypervisor / manual, stable). On the test network this
mislabelled 7 stable soft-routers/NASes and split one (R68s) across networks
because of the identity downgrade. This change reverts the wrong behavior while
keeping the bit as a neutral observability flag.

- **Identity downgrade reverted** (`resolveDeviceIdentity` in `device_bridge.go`):
  the LAA-bit gate that forced `(ip, network_id)` identity is removed; device
  identity is pure MAC-primary again (with the existing `(ip, network_id)`
  fallback only when no MAC is known).
- **Neutral naming**: the U/L bit is reported as **"locally administered"**, not
  "randomized". Renamed: `scan_attributes.mac_is_randomized` →
  `mac_is_locally_administered`; helper `store.IsLocalMAC` →
  `IsLocallyAdministeredMAC`; UI badge label "Randomized" → "Locally Admin." with
  a neutral tooltip stating the bit cannot tell random from fixed. `mac_is_multicast` / `IsMulticastMAC` unchanged (multicast bit is unambiguous).
- The flag is observability-only — it does NOT change device identity. See
  issue #118 research comment for the full rationale (RFC 7042, license boundary
  for IEEE data, etc.).

### OUI vendor inference: MA-S / MA-M / MA-L longest-prefix match
**Deterministic MAC enrichment** — the OUI lookup now resolves a MAC to its
IEEE-registered vendor via **longest-prefix-match** across the three registries:
MA-S (/36, 9 hex, formerly IAB) → MA-M (/28, 7 hex) → MA-L (/24, 6 hex). This is
mandatory because MA-S/MA-M sub-blocks are carved out of /24 OUIs owned by IEEE
or another vendor — without longest-prefix, a MAC starting `8C1F64B14..` would
be mislabelled "IEEE Registration Authority" instead of "Murata" (the MA-S
sub-assignee).

- **`vendor/oui.go`**: `Lookup` now does longest-prefix match; new `LookupFull`
  returns `(vendor, prefix)` so callers can record which block matched. The
  loader indexes prefixes of all three lengths (the 6-hex cap in
  `NormalizeMACPrefix` is lifted via a new `normalizeHexPrefix`).
- **New `scan_attributes` fields**: `oui_prefix` (the matched 6/7/9-hex block)
  and `oui_vendor` (the IEEE organization name — the NIC silicon vendor). Kept
  SEPARATE from the existing `vendor` (the device's self-declared brand via
  SNMP/HTTP/TLS); the two differ in OEM/rebrand/virtualization cases.
- **Out-of-box coverage**: the engine now auto-seeds from an EMBEDDED curated
  CC-BY-SA table (`vendor/oui_curated.txt`, via `//go:embed`) when
  `scanner.oui_path` is empty — a fresh install gets vendor inference for common
  devices without any setup. A user-configured full IEEE file still overrides it.
- **`scripts/fetch-oui.sh` rewritten**: fetches all three IEEE CSVs (MA-L/MA-M/
  MA-S), merges into one `<prefix>\t<vendor>` file with Python CSV parsing
  (vendor names contain commas/quotes). Also fixes a pre-existing typo in the
  download URL (`standardeee.org` → `standards-oui.ieee.org`) — the old script
  downloaded from a non-canonical mirror and would have failed.
- **License boundary preserved**: the IEEE registries are "All rights reserved"
  factual data — they are NOT folded into the CC-BY-SA fingerprint corpus (see
  `docs/fingerprint-spec.md` §8 "Data vs code distinction"). The embedded
  curated table is a hand-authored CC-BY-SA subset, not an IEEE reproduction;
  the full IEEE set stays an optional runtime download.

### UI: OUI vendor (NIC silicon) surfaced in device views
**Follow-up to the OUI vendor inference above** — the new `oui_vendor` /
`oui_prefix` fields (Phase 2) are now visible in the UI, kept distinct from the
device's self-declared `vendor` brand.

- **Device detail Discovery panel**: a new "OUI Vendor (NIC)" row after Vendor,
  showing `oui_vendor` with the matched IEEE block (`oui_prefix`) as a tooltip.
- **Expand-row device summary**: the same field after Vendor.
- **Extras-leak fix**: the store's `RecordDevice`/`buildStoreScanAttributes`
  path was letting `oui_prefix`/`oui_vendor` (and `mac`) fall through into
  `scan_attributes.extras` (visible as raw `OUI_PREFIX`/`OUI_VENDOR` keys in the
  Extras panel). They're now mapped to the typed fields and kept out of Extras.

## [0.4.0] - 2026-07-29

**Router-resident discovery + OpenWrt deployment + device-persistence rewrite.**
v0.4.0's headline is a new **router form factor**: when the center or agent runs
ON the gateway, it gains four Tier-1 passive discovery sources (DHCP leases,
conntrack, hostapd, dnsmasq query log) that see hosts active probing can't —
sleeping IoT, firewalled hosts, WiFi-only clients. This ships with first-class
**OpenWrt** deployment (procd init scripts for both binaries) and a
**single-writer device-persistence rewrite** that eliminates a long-standing
dual-write fissure. Rounded out by a frontend IA restructure, server-side
search/sort that survives pagination, per-user notification read state, Zod form
validation, and a DataTable XSS hardening pass.

### Router-resident discovery sources (Phase A/B)
The discovery engine (`internal/service/scannerv2/discovery/`) gains four
Tier-1 sources that only work when the host IS the LAN's gateway/AP — the NAT
choke point that sees every flow. All are opt-in (default off) and no-op where
their backing file/socket is absent, so a host-based deployment degrades
gracefully.

- **`dhcp_leases`**: reads the local DHCP server's lease table (dnsmasq
  `/tmp/dhcp.leases` on OpenWrt, `/var/lib/misc/dnsmasq.leases` on Debian) — the
  authoritative hostname↔MAC↔IP map, covering devices that never answer
  SNMP/ICMP/rDNS.
- **`conntrack`**: reads `/proc/net/nf_conntrack` and emits the LAN-side
  endpoint of every ESTABLISHED/ASSURED flow — the "who is talking RIGHT NOW"
  view. Liveness + discovery for hosts that don't answer active probes but
  maintain outbound flows. Filters to `network.cidr`.
- **`hostapd`**: enumerates WiFi STAs via the hostapd control socket
  (`/var/run/hostapd/<phy>`), falling back to `iw station dump`. Captures signal
  dBm / connect time / SSID — unavailable to a wired host. `interfaces` lists
  wlan names; empty = autodetect.
- **`dns_log`**: tails the dnsmasq query log (`--log-queries` output) and emits
  each querying host + the domain — a powerful passive fingerprint (devices that
  block inbound probes still do outbound DNS). Operator must enable query
  logging (UCI: `uci set dhcp.@dnsmasq[0].logqueries=1`).
- **`arp_scan` active source** (`discovery/arp_scan_*`): active ARP-sweep source
  (CAP_NET_RAW, build-tag stub when unavailable) — complements the existing
  passive `arp_cache`/`multicast`/`router_arp` sources.
- **Passive-source wiring on the agent** (Phase A): the agent binary now runs
  the discovery engine, so a router-form agent reports its LAN's passive
  discoveries into the center alongside scan results.
- **Multicast / `router_arp` silent-failure fix**: these sources no longer fail
  silently — they disable themselves with a logged reason when their socket /
  SNMP walk is unavailable, instead of appearing healthy while emitting nothing.
  A new warning fires when `router_arp` is redundant to a router-resident
  source already covering the same hosts.

### OpenWrt deployment (Form C router-center)
First-class support for running the center or agent directly on an OpenWrt
router — the natural home for the router-resident sources above.

- **procd init scripts**: `deploy/openwrt/mibee-steward.init` and
  `mibee-agent.init` — UCI-configured services that start on boot, restart on
  crash, and run as an unprivileged user. README documents install, config, and
  the CAP_NET_RAW story.
- **ARMv7 build target** + init-script dedup: the release matrix and OpenWrt
  packaging were polished for the common low-power-router target (ARMv7), and
  the two init scripts were de-duplicated.

### Device persistence: single-writer funnel + device replacement
**Architecture fix** — eliminates the dual-write fissure where the `devices` row
was written by two independent paths (`store.RecordDevice` and
`runner.applyDeviceBridge`) with inconsistent field semantics. The most visible
symptom was that a synchronous `POST /scanner/scan` left the row `status=
'unknown'` (only the store wrote it), while a scheduled scan flipped it to
`online` (the runner's write). A device-replacement case (router swap) exposed a
worse failure: the new device's data landed on a stale IP while the live gateway
row kept showing the dead old device, because the two writers disagreed on
identity + which fields to overwrite.

- **Single device writer**: `runner.applyDeviceBridge` is now the sole authority
  for the `devices` row lifecycle (identity creation, display name, `status`,
  heartbeat seeding, change-detection, device-replacement detection). The sync
  scan API (`scanner.go` `Scan`) now persists alive hosts through
  `runner.ApplyReport` — the SAME path async scan tasks use — so a sync scan and
  a scheduled scan leave identical rows.
- **`store.RecordDevice` reduced to enrichment-only**: it no longer INSERTs
  identities, sets `name`/`status`, or detects replacement. It only enriches an
  already-existing matched row (mac/type/brand/scan_attributes) as a best-effort
  pre-write inside the orchestrator; it cannot conflict with the runner.
- **Device replacement detection** (`resolveDeviceIdentity` in
  `device_bridge.go`): when a scan's MAC matches a device on a different IP and
  that IP is held by a different-MAC device (router/asset swap), the IP-holder
  wins, its identity fields are force-overwritten with the new device's, and the
  prior MAC-matched row is marked offline. The before/after change-detection
  diff records the old→new identity in `change_log`.

### Network reconciliation (drift detection)
- **`internal/service/scannerv2/reconcile/`**: a background job that finds
  devices whose IP has drifted outside their stamped `networks.cidr` (e.g. a
  roaming laptop that picked up a new subnet's DHCP) and surfaces them for
  operator correction. **Detect-and-surface, not auto-fix** — automatically
  re-homing a device is destructive (changes identity, breaks historical
  linkage, can flap on overlapping IP space), so correction stays a human
  decision. Findings are exposed via structured `slog` warnings (rate-limited),
  a `mibee_network_mismatches` Prometheus gauge per network, and the
  `Reconcile()` return value (a future admin endpoint). Backed by the new
  `internal/cidrutil` package.

### Configurability
- **Detection thresholds + heartbeat cadence now configurable** (were
  hard-coded): `scanner.lost_threshold` (consecutive-scan absence count before
  "lost", default 2), `heartbeat.tick_interval_seconds` (probe-loop cadence,
  default 30), `heartbeat.offline_threshold` (probe failures before offline,
  default 5), `heartbeat.offline_backoff_ticks` (probe an already-offline host
  once every N ticks, default 10 → ~5min on a 30s ticker). All carry `MIBEE_*`
  env overrides; `0` means "use default". See `internal/config/defaults.go`.
- **Rate limit raised** `rate_limit.global_per_minute` 100 → 600, with SPA
  static assets (`/_app/*`) exempted and `data:` fonts allowed in CSP — the old
  100/min starved multi-tab + background-polling sessions.
- **Shared constants extracted** (`config.SysUpTimeOID`,
  `config.DefaultScanPortSpec`): the sysUpTime OID (copied across 6 sites) and
  the curated scan port set are now single-source constants, killing the
  duplication that invited drift.

### Domain: device types
- **`phone` and `printer` device types** added to the type union
  (`internal/domain/device.go`) and the `devices.type` CHECK constraint — both
  the schema and the Go enum are the single source of truth, guarded by a
  schema-sync drift test. The hostname/brand/port → type inference table
  (`configs/fingerprints/device-types/device_types.yaml`) is fully data-driven
  (adding a signature = one YAML entry, not a Go `case`).

### Management UI restructure
- **Information architecture overhaul**: sidebar regrouped, scan entry points
  consolidated, **topology merged into the Devices page as a view toggle**
  (radial graph ↔ table), and a dashboard **attention banner** with a primary
  action surfacing what needs an operator's eye.
- **Device-detail restructure**: health banner + 5-tab navigation (overview /
  services / TLS certs / neighbors / changes).
- **Device edit/delete** via a shared `DeviceEditModal.svelte` reachable from
  both the list and detail pages.
- **Shared primitives**: `PageHeader` / `PageShell` / `LoadingButton` extracted
  and adopted across pages for consistent loading + layout.

### Server-side search, sort, and pagination
A batch of correctness fixes where client-side filtering silently lost results
once a list grew past one page — search/sort now runs on the server so it spans
the full dataset:
- **Server-side search** on users / audit / changes / documents / scan-tasks /
  scan-results (`fix(web,api)` #54, #55, #64, #86).
- **Scan-results sort** server-side so ordering holds across pages (#55).
- **Dedicated `PATCH /channels/{id}`** for the channel enabled-toggle (#53) —
  writes only `enabled`, avoiding a GET-then-write race.
- **CSV import** reads the backend `{added, errors}` result instead of the
  preview count, so the post-import tally matches reality (#58).

### Notifications
- **Per-user unread tracking** (`notification_read_states` table): the header
  bell now shows a per-user unread count and clears on dropdown open. Previously
  the bell was system-wide (no recipient concept).
- **NotificationBell** pauses polling in background tabs and backs off on
  failure — stops hammering the API from idle tabs (#67).

### Frontend hardening
- **DataTable XSS fix** (`lib/utils/html.ts`): a tagged-template `html()`
  helper that escapes interpolated values, with all rich-text callers migrated
  off string concatenation (#50, #87).
- **Zod schema validation** added to 7 forms (login, register, device edit,
  network, channel, scan, CSV import) — client-side validation now mirrors the
  backend rules (#66, #106).
- **Error-state honesty**: pages no longer disguise server errors as empty
  states — a failed fetch shows an error + retry UI instead of a blank "no data"
  panel (#65); device-detail shows error + skeleton states instead of blank
  (#56).
- **API client hardening**: GET retry on transient 5xx, env-based base URL, and
  a unified 401 handler that routes session-expiry to re-login (#73, #109).
- **i18n completeness**: localized scattered hardcoded English across 9+ pages,
  the discovery funnel, topology tooltips, ChangeDiff labels, and layout/a11y
  labels; API error messages + form-validation messages now go through the i18n
  boundary (#40–#63, #101–#105).
- **a11y + component cleanup**: ARIA ids, focus management, Escape-to-close on
  click-toggle menus, chart resize handling, scanner alive-hosts table
  **pagination for large (/22+) ranges** with the bar hidden when results fit
  one page (#74, #100, #108, #110, #112).
- **Misc P2/P3 batches**: lib/components, agents/settings/networks/documents,
  and devices subtrees got consolidated correctness / type-safety / a11y passes.

### Operations
- **`change_log` noise reduction**: service-evidence dedup + offline-backoff cut
  the steady write of timeout rows for dead hosts.
- **`agent` race fixes**: `TestCommandPoller_ScanPayload_StringQuoted` and
  `TestReporter_SendsStateHashHeader` data/logic races fixed (CI runs `-race`).
- **Fingerprint corpus sync** from `mibee-fingerprints-go` (http-tls + ports
  rules), with golden tests covering the synced http-server-* + smb-version
  rules.

### License
- **AGPLv3 + commercial dual-licensing** applied project-wide (supersedes the
  earlier PolyForm NC): full AGPL-3.0 `LICENSE`, `LICENSE-COMMERCIAL.md`,
  `NOTICE` third-party attributions, `CLA.md` + `.github/DCO.md` + DCO CI check,
  and `SPDX-License-Identifier: AGPL-3.0-or-later` headers on all `.go`/`.ts`/
  `.svelte`/`.c`/`.sql` source; fingerprint YAMLs carry CC-BY-SA 4.0 headers.

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
