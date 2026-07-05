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
- 10-second ticker interval
- Configurable `isDue()` checks based on monitoring intervals
- 3-failure threshold for device detection
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

**Detected services** (out of the box): SSH, HTTP/HTTPS, RTSP, ONVIF, SNMP, Prometheus, node_exporter, and a host-level **camera** meta-identity (fused from RTSP + ONVIF evidence, with brand inference from Server headers / SNMP sysDescr / enterprise OID).

**eBPF passive observer**: an optional TC ingress program (`bpf/tc_ingress.c`) sniffs ONVIF WS-Discovery multicast (239.255.255.250:3702) and TCP magic bytes (SSH-/RTSP/HTTP/). It emits corroborating Evidence at confidence 0.6, fused with active-probe results. Built only with `make build-with-ebpf` (needs clang/llvm/bpftool + kernel BTF ≥5.8); the default build uses a no-op stub so the binary stays dependency-free.

**Persistence tables** (added by v2): `service_evidence` (raw probe observations, sampling-controlled) and `host_services` (classified service identities per host). Device upserts go to the existing `devices` table; heartbeat configs to `heartbeat_configs`.

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