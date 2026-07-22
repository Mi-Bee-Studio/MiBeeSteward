# Architecture

## System Overview

MiBee Steward is a device management and monitoring system built as a single binary deployment with an embedded web interface. The system consists of a Go backend using the Chi web framework with SQLite database, and a SvelteKit 5 frontend embedded via Go's `go:embed` functionality. The system provides SNMP/ICMP/TCP/HTTP probing capabilities, Prometheus metrics integration, comprehensive heartbeat monitoring, and device systems management.

## Layered Architecture

The system follows a Domain-Driven Design (DDD) inspired layered architecture with optional repository pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Layer                          │
│                 SvelteKit SPA (embedded)                  │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Handler Layer                           │
│              HTTP Request/Response Processing              │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Service Layer                          │
│              Business Logic & Orchestration               │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│              Repository Layer (Optional)                  │
│             Data Access Abstraction Layer                  │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Domain Layer                          │
│               DTOs, Constants, Context Keys                │
└─────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

**Domain Layer**: Contains business models, data transfer objects (DTOs), and application constants. Includes context keys for request tracing and typed error definitions, and device systems models.

**Repository Layer**: Optional data access layer that wraps sqlc-generated code. Used by DeviceService and DeviceSystemService, while other services use sqlc directly for simpler data access patterns.

**Service Layer**: Implements business logic, error handling, and the probe subsystem. Services use constructor-based dependency injection and return typed errors. Includes device systems management and Prometheus service discovery.

**Handler Layer**: HTTP request/response processing, input validation, audit logging, and error translation to HTTP status codes. Routes include device systems CRUD operations.

## Text-Based Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    External Requests                       │
│                    /                                     │
│                   ↓                                       │
│        ┌─────────────────────────────────────┐           │
│        │           Chi Router                │           │
│        │  Routes → Middleware Chain → Handlers│           │
│        └─────────────────────────────────────┘           │
│                   │                                       │
│            ┌──────┴──────┐                               │
│            │ Middleware  │                               │
│            │  Pipeline   │                               │
│            └──────┬──────┘                               │
│                   ↓                                       │
│        ┌─────────────────────────────────────┐           │
│        │           Handlers                  │           │
│        │  Validation → Audit Logging → Business Logic    │
│        └─────────────────────────────────────┘           │
│                   │                                       │
│            ┌──────┴──────┐                               │
│            │    Services │                               │
│            │  Device, User, Probe, Audit               │
│            └──────┬──────┘                               │
│                   ↓                                       │
│        ┌─────────────────────────────────────┐           │
│        │        Data Access Layer              │           │
│        │     Repository OR sqlc Direct         │           │
│        └─────────────────────────────────────┘           │
│                   │                                       │
│            ┌──────┴──────┐                               │
│            │    SQLite   │                               │
│            │    Database │                               │
│            └─────────────┘                               │
│                                                         │
│    ┌─────────────────────────────────────┐               │
│    │           Background Services      │               │
│    │        HeartbeatService → Probes   │               │
│    └─────────────────────────────────────┘               │
```

## Request Lifecycle

HTTP requests flow through the system in the following sequence:

1. **HTTP Request** → External client sends request to the server
2. **Chi Router** → Route matching and middleware chain initiation
3. **Middleware Pipeline** → Each middleware processes the request in order
4. **Handler** → Request validation, audit logging, business logic invocation
5. **Service** → Business logic processing and error handling
6. **Repository/SQLc** → Data access to SQLite database
7. **Database Response** → Query results returned to service
8. **Service Response** → Business logic results returned to handler
9. **HTTP Response** → Final response formatted and sent to client

## Middleware Chain

The system processes requests through a carefully ordered middleware chain:

```
Request → RequestID → RealIP → Logging → Metrics → Recoverer → 
SecurityHeaders → CORS → CSRF → RateLimit → Auth/RBAC → Handler
```

Each middleware serves a specific purpose:
- **RequestID**: Assigns unique request IDs for tracing
- **RealIP**: Extracts real client IP from proxies
- **Logging**: Request/response logging with structured data
- **Metrics**: Prometheus metrics collection
- **Recoverer**: Panic recovery and error handling
- **SecurityHeaders**: Security-related HTTP headers
- **CORS**: Cross-origin resource sharing configuration
- **CSRF**: Cross-site request forgery protection
- **RateLimit**: Request rate limiting
- **Auth/RBAC**: Authentication and role-based access control

## Database Design

The system uses SQLite with Write-Ahead Logging (WAL) mode for optimal performance:

- **Connection Pool**: Single connection (`MaxOpenConns=1`) for SQLite compatibility
- **Code Generation**: sqlc generates type-safe Go code from SQL queries
- **Migration System**: Single schema.sql applied on startup
- **Data Directory**: Default path `./data/mibee.db` with automatic directory creation
- **Schema Evolution**: Migrations handle database schema changes

Database code generation follows the pattern:
```
db/queries/*.sql → sqlc generate → internal/db/*.go
```

Never edit `internal/db/*.go` files directly - modify SQL queries and regenerate.

## Frontend Architecture

The frontend is a SvelteKit 5 single-page application with specific configuration:

- **Routing**: File-based routing in `web/src/routes/`
- **Build Output**: Frontend builds to `web/dist/` for embedding
- **Embedding**: Go embeds frontend via `web/embed.go` (`//go:embed all:dist`)
- **Styling**: Tailwind 4 for responsive design
- **Charts**: ECharts integration for data visualization
- **Internationalization**: @inlang/paraglide-js with English and Chinese support
- **State Management**: SvelteKit's `$app/stores` for client-side state

Key frontend patterns:
- Translation function: `t('section', 'key')`
- Chart components with ECharts integration
- File-based routing with `+page.svelte` files
- Shared components in `web/src/lib/components/`

## Background Services

The system runs background services in separate goroutines:

**HeartbeatService**:
- 30-second ticker interval
- Configurable `isDue()` checks based on monitoring intervals
- 5-failure threshold for device detection (`offlineThreshold=5`)
- Offline-device backoff: known-dead hosts are probed once every `offline_backoff_ticks` ticks (default 10, ~5min on a 30s ticker) instead of every tick, to stop the steady write of timeout rows for devices that won't answer
- Orchestrates probe execution across all devices
- Graceful shutdown coordination via returned service reference

**Service Lifecycle**:
```
NewRouter() → HeartbeatService.Start() → goroutine launch → signal wait → graceful shutdown
```

## Probe Subsystem

The probe system uses an interface-based design with decorator pattern:

```
Prober Interface → ICMP/TCP/HTTP/SNMP Implementations → RetryProber Decorator
```

**Probe Features**:
- Exponential backoff retry (1s → 2s → 4s)
- Network error retries only (immediate return on probe failures)
- Configurable timeout and retry parameters
- Comprehensive probe result tracking

**Probe Implementations**:
- **ICMP**: Ping-based connectivity checks
- **TCP**: Port connectivity and banner grabbing
- **HTTP**: Web server health checks and response validation
- **SNMP**: Network device monitoring via SNMP protocol

## Network Scanner (v2)

The scanner is a **plugin-based, 5-layer architecture** that decouples detection from persistence and makes adding new protocols a matter of registering one classifier + one handler. It replaces the legacy hardcoded 6-stage pipeline.

```
┌─────────────────────────────────────────────────────────────────────┐
│  ① Probe         — active (TCP/SNMP/RTSP/ONVIF/HTTP-metrics) +      │
│                     passive (eBPF TC observer, build-tag gated)      │
│     → emits Evidence (port_open / banner / snmp / wsdiscovery / ...) │
├─────────────────────────────────────────────────────────────────────┤
│  ② Classifier    — per-protocol, pure functions over Evidence        │
│     → fuses into ServiceIdentity (ssh/http/rtsp/onvif/prometheus/    │
│       node_exporter/snmp/camera) with confidence                    │
├─────────────────────────────────────────────────────────────────────┤
│  ③ ServiceHandler — per-service customization                        │
│     ├─ GenerateHeartbeat()  → adapted heartbeat spec                │
│     ├─ Collect()            → deep gather, may Trigger other handlers│
│     └─ EnrichDevice()       → fill device fields from collected data │
│     canonical cascade: http → probe /metrics → prometheus →          │
│     detect node_ → node_exporter → parse CPU/mem/kernel → enrich     │
├─────────────────────────────────────────────────────────────────────┤
│  ④ Persistence   — Repository interface (SQLite impl in store/)      │
│     → records evidence / services / device updates / heartbeats      │
├─────────────────────────────────────────────────────────────────────┤
│  ⑤ Orchestrator  — declarative driver: gather → classify → dispatch │
│     with cycle-guarded cascade triggers (max depth 5)                │
└─────────────────────────────────────────────────────────────────────┘
```

**Extending detection**: to add a new protocol, implement a `ServiceClassifier` and a `ServiceHandler`, then register them in `classify.DefaultClassifiers()` / `handler.DefaultHandlers()`. No orchestrator or persistence changes are required.

**Detected services** (out of the box): SSH, HTTP/HTTPS, RTSP, ONVIF, SNMP, Prometheus, node_exporter, mail (SMTP/POP3/IMAP), remote-access (VNC/RDP/Telnet), directory & file-share (LDAP/SMB), DNS, the TLS-wrapped service family (LDAPS, SMTPS, IMAPS, POP3S, FTPS, IRCS, TelnetS), and a host-level **camera** meta-identity (fused from RTSP + ONVIF evidence, with brand inference from Server headers / SNMP sysDescr / enterprise OID / TLS cert CN).

**TLS certificate inventory**: any port classified as TLS-speaking (default ports 443/8443/9443/4443 + the well-known TLS-wrapped service ports 465/636/989/990/992/993/994/995, plus any port a classifier flags) has its full certificate chain collected via `probe.CollectCertChain` and persisted to `host_tls_certs` — Subject/Issuer/SAN/validity/signature/key/fingerprint + PEM, one row per cert in the chain (leaf + issuers). Surfaced per-device via `GET /api/v1/devices/{id}/certificates` and the device-detail TLS sub-panel.

**eBPF passive observer**: an optional TC ingress program (`bpf/tc_ingress.c`) sniffs ONVIF WS-Discovery multicast (239.255.255.250:3702) and TCP magic bytes (SSH-/RTSP/HTTP/). It emits corroborating Evidence at confidence 0.6, fused with active-probe results. Built only with `make build-with-ebpf` (needs clang/llvm/bpftool + kernel BTF ≥5.8); the default build uses a no-op stub so the binary stays dependency-free.

**Persistence tables** (added by v2): `service_evidence` (raw probe observations, sampling-controlled), `host_services` (classified service identities per host), and `host_tls_certs` (TLS certificate chains per `(ip, port)`, one row per cert; PEM + typed columns for queryability; `not_after` indexed for expiry sweeps). Device upserts go to the existing `devices` table; heartbeat configs to `heartbeat_configs`.

## Prometheus Integration

The system provides comprehensive monitoring capabilities:

**Metrics Endpoint**: `/metrics` - Standard Prometheus metrics export
**Dashboard Proxy**: `/api/v1/dashboard/query` - Read-only proxy to Prometheus
**Service Discovery**: HTTP SD endpoint at `/sd` for service discovery and device systems auto-discovery
**Metric Types**: Counter, Gauge, and Histogram for various system metrics

The dashboard service integrates with Prometheus for monitoring data collection.

### Device Systems Architecture
- **Database**: New `device_systems` table with relationship to devices
- **API**: REST endpoints under `/api/v1/devices/{id}/systems` for CRUD operations
- **Service Discovery**: Extended `/sd` endpoint to auto-discover systems with `metrics_enabled=true`
- **Frontend**: Card grid UI in device detail pages with category badges (web_app, database, middleware, custom)
- **Labels**: Systems appear in service discovery with labels (device_name, system_name, category, device_type, location)

## Distributed Architecture

MiBee Steward supports a distributed deployment model: a **center** (the main
binary, `cmd/server`) aggregates device data from multiple **agents**
(lightweight binaries, `cmd/agent`), each deployed on a different LAN segment.
This enables cross-network device discovery without requiring the center to have
direct L3 reachability to every subnet.

```
[Network A: 192.168.63.0/24]           [Network B: 192.168.62.0/24]
  ┌──────────────────────┐               ┌──────────────────────┐
  │ Center (cmd/server)  │               │ Agent (cmd/agent)     │
  │  - API + SPA         │   HTTPS       │  - scannerv2 engine   │
  │  - Device registry   │◄─────────────│  - Reporter (POST)    │
  │  - Change detection  │   Bearer tok  │  - Command poller     │
  │  - Scanner (local)   │──────────────►│  - Scheduler (cron)   │
  │  - Heartbeat service │   Commands    │  - Mini SQLite        │
  └──────────────────────┘               └──────────────────────┘
```

### Roles

| Role | Binary | Responsibilities |
|---|---|---|
| **Center** | `cmd/server` | Aggregation hub: API, SPA, device registry, change detection, heartbeat, ingestion, agent management |
| **Agent** | `cmd/agent` | Lightweight scanner: runs scannerv2 locally, reports results upstream, polls for commands |

### Agent ↔ Center Protocol

**Pull model** — the agent initiates all connections (works behind NAT):

1. **Report** (`POST /api/v1/agents/report`): Agent batches alive HostReports and
   POSTs them to the center. The center authenticates via the agent's bearer
   token and merges devices through the MAC-primary identity model.
2. **Command poll** (`GET /api/v1/agents/commands`): Agent polls for ad-hoc
   commands (e.g. "scan these targets now") every 60s.
3. **Disconnect recovery**: Failed report batches are held in an in-memory
   pending queue (bounded at 100 batches). The flush loop drains pending
   oldest-first once the center recovers.

### Identity Model (MAC-Primary)

Devices are identified by **MAC address first** (a roaming device stays one
asset across networks), falling back to `(ip_address, network_id)` when no MAC
is known. This means:

- The same private IP (e.g. `192.168.1.10`) on two different LANs is **two
  distinct devices** (partitioned by `network_id`).
- A device that moves between subnets (same MAC, different IP) stays **one asset**.
- The `(ip_address, network_id)` composite unique index backs this partitioning.

### Agent Authentication

Agent tokens are SHA-256-hashed opaque bearer tokens stored in `agent_tokens`.
The plaintext is returned **once** at creation; only the hash is persisted.
Tokens are bound to a `network_id` — every device the agent reports is tagged
with that network. Revocation is a soft delete (`revoked_at`); revoked tokens
immediately fail authentication.

Two auth regimes, never mixed:
- **Admin JWT** (cookie/Bearer): human users via the SPA.
- **Agent token** (`RequireAgentToken` middleware): machine-to-machine ingestion.

### Change Detection Engine

The center runs a change-detection engine that diffs each scan against the
known device state and emits events to `change_log`:

- **device_added**: A new device appears in a scan.
- **device_changed**: A tracked field (type, brand, MAC, ports, services,
  scan_attributes) differs from the prior state. The old `wasUpdated` always-true
  heuristic is replaced with a real field-by-field comparison. `scan_attributes`
  is normalized before diffing — volatile keys (`last_scanned_at`,
  `last_scan_rtt_ms`) are stripped and key order is canonicalized, so a pure
  timestamp refresh no longer fires a spurious `device_changed`. The
  `after_data` payload is the full post-change device snapshot (not a field-level
  diff map), so consumers can render the new state without a follow-up fetch.
- **device_lost**: A device absent from `lostThreshold` (2) consecutive scans is
  declared lost and marked offline. The grace period prevents single-scan jitter
  (ICMP drop, brief downtime) from flapping.

Events are queryable via `GET /api/v1/changes` and streamable via SSE at
`GET /api/v1/changes/watch`. A Prometheus counter (`mibee_changes_total{type}`)
tracks the change rate.

### Topology Discovery (L2 + Derived)

The Bridge-MIB probe walks `dot1dTpFdbTable` (1.3.6.1.2.1.17.4.3) on
SNMP-capable switches to learn L2 adjacency (which MACs are behind which port).
Discovered neighbors are persisted to `device_neighbors` via
`Repository.RecordNeighbors`. LLDP/CDP probes follow the same path. When no
device speaks SNMP, the kernel ARP cache is walked post-scan to write
gateway-centric `device_neighbors` edges (protocol `"ARP"`) as a fallback.

**Derived topology tables**: after each scan the runner derives three
higher-level tables from `device_neighbors` — `topology_edges` (materialized
device↔device edges via `deriveTopologyEdges`, where both endpoints must be known
devices; LLDP/CDP/Bridge-MIB → `l2` with high confidence, ARP → `l3` lower),
`subnets` (per-network CIDR + gateway via `recordSubnets`), and `vlans` (802.1Q
tags via `recordVLANs`). VLAN tags are extracted from Q-BRIDGE-MIB OID indices
by `extractVLANFromIndex` and carried on `NeighborSpec.VLANTag`.
(`vlans.name`/`description` and `subnets.vlan_id` linkage are still TODO.)

### Distributed Schema

| Table | Purpose |
|---|---|
| `networks` | Logical network registry (one row per LAN an agent discovers) |
| `agent_tokens` | Agent bearer tokens (SHA-256 hash + network binding) |
| `agent_commands` | Center→agent command queue (pull model) |
| `scan_snapshots` | Per-network miss counter for device_lost grace period |
| `change_log` | device_added/changed/lost event stream |
| `device_neighbors` | L2 adjacency edges (LLDP/CDP/Bridge-MIB/Q-BRIDGE-MIB/ARP) |
| `topology_edges` | Materialized device↔device edges (derived from device_neighbors) |
| `subnets` | Per-network CIDR + gateway observed during scans |
| `vlans` | 802.1Q VLAN tags extracted from Q-BRIDGE-MIB |