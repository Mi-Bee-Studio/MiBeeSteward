# Introduction to MiBee Steward

## What is MiBee Steward

MiBee Steward is a **device/network-layer asset discovery, identification, and registry** tool — CMDB-lite for network and IoT assets. It automatically discovers what devices are on a network (via ICMP, TCP portscan, SNMP, HTTP, RTSP, ONVIF, mDNS, WS-Discovery probing, plus an optional eBPF passive observer), infers what they are (device type, brand, model via protocol fingerprints), and registers/tracks them over time with heartbeat-based freshness. Built with a Go backend (Chi + SQLite, CGO-free) and an embedded SvelteKit single-page application, it deploys as a single zero-dependency binary.

Heartbeat probing keeps the asset registry fresh: devices are probed at configurable intervals, and after three consecutive failures the device status is automatically marked offline (recovery is auto-detected when the device responds again). This produces the online/offline history, latency, and availability stats that make the registry a living record rather than a one-time snapshot. Asset state is also exposed to the Prometheus ecosystem via `/metrics` and `/sd` — **alerting and visualization are intentionally left to Alertmanager and Grafana**, which consume those endpoints natively. See [Product Scope & Boundary](product-scope.md) for what MiBee Steward does and does not build.

## Key Features

### Device Management
- Complete CRUD operations for network devices including creation, editing, deletion, and viewing
- Device grouping and categorization for organized management
- Device systems management with entry URLs and category badges
- Detailed device configuration with custom parameters and probe settings
- Bulk operations for efficient management of large device inventories
### Multi-Protocol Probing
- SNMP v2c support for monitoring network devices with community string authentication
- ICMP ping functionality for basic network connectivity testing
- TCP connect checks for specific port availability and service monitoring
- HTTP GET requests with customizable headers and timeout settings
- Exponential backoff retry mechanism (1s → 2s → 4s) for network errors only

### Heartbeat Monitoring
- Configurable monitoring intervals per device or device groups
- Three-strike failure detection with automatic status updates
- Automatic recovery detection when failed devices respond again
- Real-time status changes reflected in the web interface and metrics

### Prometheus Integration
- Comprehensive metrics endpoint at `/metrics` following Prometheus exposition format
- Device status gauges showing online/offline states
- Device systems auto-discovery at `/sd` endpoint with metrics_enabled=true
- Heartbeat counters for total and failed probe attempts
- Response time histograms for performance monitoring
- HTTP service discovery endpoint at `/sd` for auto-discovery
### Embedded Web Interface
- SvelteKit 5 single-page application embedded via go:embed
- Real-time dashboards using ECharts for data visualization
- Dark and light theme support with automatic system preference detection
- Responsive design optimized for desktop and mobile devices
- File upload functionality for device certificates and configuration files

### Authentication & Security
- JWT-based authentication with cookie-first approach
- Bearer token fallback for API clients and automation tools
- Role-based access control with admin (full access) and user (read-only) roles
- Comprehensive audit logging for all user actions including login attempts, device changes, and file uploads
- CSRF protection and security headers middleware

### Internationalization
- Full i18n support with English and Chinese language packs
- @inlang/paraglide-js for efficient message compilation
- Automatic language detection based on browser preferences
- Localized date/time formatting and error messages

## Use Cases

### Network Asset Inventory
Automatically discover and catalog what's on your network — routers, switches, access points, servers, IoT — with brand/model identification via protocol fingerprints. Replaces manual spreadsheet-based asset tracking with a continuously-fresh registry.

### IoT / Camera Fleet Discovery
Identify IP cameras, sensors, controllers, and other IoT devices by brand and model. Camera detection (RTSP + ONVIF + camera classifiers) is a current priority scenario because the fingerprints are crisp and demand is concrete — not because MiBee Steward is camera-specific. The same identification pipeline applies to any device type.

### Branch / SOHO Network Mapping
Lightweight enough for small/branch networks where LibreNMS or Zabbix is overkill. Deploy a single binary, scan the subnet, get a structured asset portrait without standing up a database, message broker, or container stack.

### Lab / Edge Asset Tracking
Track research lab equipment, test rigs, measurement devices, and edge nodes with flexible per-device probe configurations. Heartbeat-based freshness ensures the asset registry reflects reality, not a stale snapshot.

## System Requirements

### Backend Requirements
- Go 1.26 or later for compilation and runtime
- SQLite via modernc.org/sqlite (CGO_ENABLED=0 build flag)
- Minimum 50MB disk space for the application and database
- Network access for device probing and metrics collection
- Optional: 100MB+ for file uploads and document storage

### Frontend Requirements
- Node.js 20+ for development and building
- Modern web browser with JavaScript support
- Optional: ECharts for dashboard visualization features

### Infrastructure Requirements
- Linux x86_64 (primary deployment platform)
- Optional: ARM64 support via cross-compilation
- Systemd for production service management
- Nginx for reverse proxy and TLS termination
- Docker for containerized deployment

### Performance Considerations
- Single SQLite database with WAL mode for concurrent access
- Memory usage typically under 100MB for most deployments
- CPU usage scales with number of active device probes
- Network bandwidth depends on probe frequency and response sizes

## Architecture

```
Browser → Nginx → Go Server (Chi)
                         ↓
               SQLite + Heartbeat Service (10s ticker)
                         ↓
               Prometheus Metrics / HTTP Service Discovery
```