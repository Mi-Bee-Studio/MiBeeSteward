# Configuration Reference

MiBee Steward uses YAML configuration files with environment variable overrides. This document covers all available configuration options.

## Configuration Structure

The configuration is organized into 15 main sections:

- **Server** (`server`): HTTP server settings and trusted proxies
- **Database** (`database`): Database configuration (SQLite)
- **Authentication** (`auth`): JWT and cookie settings
- **CORS** (`cors`): Cross-origin resource sharing
- **Heartbeat** (`heartbeat`): Device monitoring settings
- **Scanner** (`scanner`): Network scanner engine (v2)
- **Retention** (`retention`): Data lifecycle and cleanup
- **Rate Limit** (`rate_limit`): Global request throttling
- **Prometheus** (`prometheus`): Metrics collection
- **Dashboard** (`dashboard`): Dashboard data source configuration
- **Storage** (`storage`): File upload settings
- **Logging** (`log`): Log output configuration
- **Network** (`network`): This instance's network identity and CIDR
- **Center** (`center`): Distributed agent mode (upstream center reporting)
- **Security** (`security`): Master key and credential encryption

## Configuration Loading Priority

Configuration values are loaded in the following order (with later values overriding earlier ones):

1. **YAML Configuration File**: Base configuration loaded from whatever the `-config` flag points at (defaults to `configs/config.example.yaml`; production deployments typically copy it to `config.yaml` and pass that)
2. **Environment Variables**: `MIBEE_*` prefixed variables override YAML values

Any key set to `0` (or the zero value for its type) is treated as "use default" — it does **not** mean "no limit" or "keep forever".

## Environment Variable Override Pattern

Environment variables override configuration values using the following pattern:

- Prefix: `MIBEE_`
- Section and key: Convert to uppercase, replace dots with underscores
- Example: `server.port` → `MIBEE_SERVER_PORT`

## 1. Server Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.port` | int | 8080 | HTTP port to listen on |
| `server.host` | string | "0.0.0.0" | Bind address (0.0.0.0 = all interfaces) |
| `server.read_timeout` | duration | "15s" | Max time to read the full request (headers + body) |
| `server.write_timeout` | duration | "5m" | Max response lifetime. **Must exceed the slowest synchronous endpoint** (POST `/scanner/scan`). Auto-raised to `scanner.default_timeout×2+30s` if configured lower, so synchronous scans are never truncated. |
| `server.idle_timeout` | duration | "120s" | Keep-alive idle timeout |
| `server.trusted_proxies` | []string | [] | List of trusted proxy CIDRs. `X-Forwarded-For` is only honored when the TCP peer is in this list — otherwise the TCP peer address is used as the client IP. Empty list = trust no proxy (safe for direct exposure). Set to the proxy's source range when deploying behind nginx. |

**Environment Variables:**
- `MIBEE_SERVER_PORT`
- `MIBEE_SERVER_HOST`
- `MIBEE_SERVER_READ_TIMEOUT`, `MIBEE_SERVER_WRITE_TIMEOUT`, `MIBEE_SERVER_IDLE_TIMEOUT`
- `MIBEE_SERVER_TRUSTED_PROXIES` (comma-separated trusted proxy list)

**Example:**
```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "15s"
  write_timeout: "5m"     # auto-raised if too low for synchronous scans
  idle_timeout: "120s"
  trusted_proxies:
    - "172.16.0.0/12"

# Environment override
export MIBEE_SERVER_PORT=3000
export MIBEE_SERVER_HOST="192.168.1.100"
```

## 2. Database Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `database.sqlite.path` | string | "./data/mibee.db" | SQLite database file path |

**Environment Variables:**
- `MIBEE_DATABASE_SQLITE_PATH`

**Example:**
```yaml
database:
  sqlite:
    path: "./data/mibee.db"
```

## 3. Authentication Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auth.jwt_secret` | string | none (required) | JWT signing key. **Required**: startup fails when empty, shorter than 32 characters, or equal to the placeholder `"change-me-in-production"` (25 chars — it fails both checks). |
| `auth.token_expiry` | string | "24h" | JWT token lifetime |
| `auth.initial_admin_password` | string | *(required)* | Initial admin password. **Required** — the server exits at startup when it is empty (set it via config or `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`). |
| `auth.cookie_domain` | string | "" | Cookie domain (empty = current domain) |
| `auth.cookie_secure` | bool | false | Set true for HTTPS-only cookies |
| `auth.cookie_same_site` | string | "strict" | Cookie same-site policy: "strict" or "lax" |
| `auth.cookie_max_age` | duration | *(falls back to `auth.token_expiry`, then 86400)* | Auth cookie lifetime. Falls back to `auth.token_expiry` when unset, then 86400 seconds (24h). |

**Environment Variables:**
- `MIBEE_AUTH_JWT_SECRET`
- `MIBEE_AUTH_TOKEN_EXPIRY`
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`
- `MIBEE_AUTH_COOKIE_DOMAIN`
- `MIBEE_AUTH_COOKIE_SECURE`
- `MIBEE_AUTH_COOKIE_SAME_SITE`
- `MIBEE_AUTH_COOKIE_MAX_AGE`

**Example:**
```yaml
auth:
  jwt_secret: "your-strong-jwt-secret-here"
  token_expiry: "24h"
  initial_admin_password: "secure_admin_password"
  cookie_domain: "example.com"
  cookie_secure: true
  cookie_same_site: "strict"

# Environment overrides
export MIBEE_AUTH_JWT_SECRET="super-secret-key"
export MIBEE_AUTH_COOKIE_SECURE=true
```

### RBAC Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rbac.scope_default` | string | "open" | Network scope mode. `open` = all users can access all networks; `closed` = users can only access explicitly granted networks (managed via the network-grant endpoints in the [API Reference](api.md)). Admins can access all networks in either mode. |

## 4. CORS Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cors.allowed_origins` | []string | no default | Allowed origins for cross-origin requests. Unset/empty = no cross-origin allowed (same-origin only). Startup logs a warning for origins containing localhost/127.0.0.1. |

**Environment Variables:**
- `MIBEE_CORS_ALLOWED_ORIGINS`

**Example:**
```yaml
cors:
  allowed_origins:
    - "http://localhost:5173"
    - "http://localhost:8080"
    - "https://yourdomain.com"

# Environment override
export MIBEE_CORS_ALLOWED_ORIGINS="https://example.com,https://app.example.com"
```

## 5. Heartbeat Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `heartbeat.default_interval` | int | 30 | Default device check interval (seconds) |
| `heartbeat.tick_interval_seconds` | int | 30 | Interval (seconds) between heartbeat scheduler ticks. Drives how often the probe loop fires. Decoupled from `default_interval` so the scheduler rate can be tuned independently of the per-device default. |
| `heartbeat.timeout` | int | 5 | Device probe timeout (seconds) |
| `heartbeat.retention_days` | int | *(no in-code default)* | Legacy passthrough: only takes effect when `retention.heartbeat_results_days` is unset (effective default 7 days; `configs/config.example.yaml` ships 30). |
| `heartbeat.offline_threshold` | int | 5 | Number of consecutive probe failures before the device flips to `offline` (5 × the default 30s interval ≈ 2.5 minutes). |
| `heartbeat.offline_backoff_ticks` | int | 10 | Probe offline devices once every N ticks instead of every tick (on a 30s ticker, N=10 ≈ 5min between probes for known-dead hosts). Stops the steady write of timeout rows for devices that won't answer. A scan that revives a host clears its failure count immediately, so backoff never delays recovery. 0 disables backoff. |

**Environment Variables:**
- `MIBEE_HEARTBEAT_DEFAULT_INTERVAL`
- `MIBEE_HEARTBEAT_TICK_INTERVAL_SECONDS`
- `MIBEE_HEARTBEAT_TIMEOUT`
- `MIBEE_HEARTBEAT_RETENTION_DAYS`
- `MIBEE_HEARTBEAT_OFFLINE_THRESHOLD`
- `MIBEE_HEARTBEAT_OFFLINE_BACKOFF_TICKS`

**Example:**
```yaml
heartbeat:
  default_interval: 30
  tick_interval_seconds: 30
  timeout: 5
  retention_days: 30
  offline_threshold: 5
  offline_backoff_ticks: 10

# Environment overrides
export MIBEE_HEARTBEAT_DEFAULT_INTERVAL=60
export MIBEE_HEARTBEAT_TIMEOUT=10
```

## 6. Prometheus Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `prometheus.enabled` | bool | — | **Currently unused**: the `/metrics` endpoint is always mounted regardless of this switch. |
| `prometheus.metrics_path` | string | — | **Currently unused**: the metrics path is hardcoded to `/metrics`; this key has no effect. |

**Environment Variables:**
- `MIBEE_PROMETHEUS_ENABLED` (no effect — see table above)
- `MIBEE_PROMETHEUS_METRICS_PATH` (no effect — see table above)

**Example:**
```yaml
prometheus:
  enabled: true
  metrics_path: "/metrics"

# Environment override
# (MIBEE_PROMETHEUS_METRICS_PATH has no effect: the metrics path is hardcoded to /metrics)
```

## 7. Dashboard Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dashboard.data_source_type` | string | "prometheus" | Data source: "prometheus" |
| `dashboard.prometheus_url` | string | "http://localhost:9090" | Prometheus server URL |

**Environment Variables:**
- `MIBEE_DASHBOARD_DATA_SOURCE_TYPE`
- `MIBEE_DASHBOARD_PROMETHEUS_URL`

**Example:**
```yaml
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"
```

## 8. Storage Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `storage.upload_path` | string | "./data/uploads" | File upload directory |
| `storage.max_file_size` | int64 | 104857600 | Maximum upload size in bytes (default: 100MB) |

**Environment Variables:**
- `MIBEE_STORAGE_UPLOAD_PATH`
- `MIBEE_STORAGE_MAX_FILE_SIZE`

**Example:**
```yaml
storage:
  upload_path: "./data/uploads"
  max_file_size: 104857600

# Environment overrides
export MIBEE_STORAGE_UPLOAD_PATH="/var/lib/mibee/uploads"
export MIBEE_STORAGE_MAX_FILE_SIZE=209715200  # 200MB
```

## 9. Logging Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log.level` | string | "info" | Log level: "debug", "info", "warn", "error" |
| `log.format` | string | "text" | Log format: "text" or "json" |

**Environment Variables:**
- `MIBEE_LOG_LEVEL`
- `MIBEE_LOG_FORMAT`

**Example:**
```yaml
log:
  level: "info"
  format: "text"

# Production configuration
log:
  level: "info"
  format: "json"

# Environment overrides
export MIBEE_LOG_LEVEL=debug
export MIBEE_LOG_FORMAT=json
```

## 10. Scanner Configuration (v2 engine)

The network scanner uses a plugin-based 5-layer architecture (probe → classify → handler → persist → orchestrate). See [Architecture](architecture.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.enabled` | bool | — | **Currently unused** (exists in the struct, consumed nowhere): scanner routes and the background scheduler start unconditionally. |
| `scanner.max_concurrent_scans` | int | 3 | Cap on top-level scans running at once (the engine's concurrent-scan semaphore — live and enforced). |
| `scanner.default_timeout` | int (s) | 300 | Per-host pipeline timeout for cron-driven scans. Also drives the `write_timeout` auto-raise. |
| `scanner.max_concurrent_hosts` | int | 50 | Parallelism cap for per-host scanning |
| `scanner.retention_days` | int | — | Legacy fallback: only takes effect when `retention.scan_results_days` is unset (then 30). The sweep runs every `retention.sweep_interval_hours` (default 6h), not daily. |
| `scanner.default_cron_expr` | string | "0 */6 * * *" | Default cron for newly-created scan tasks |
| `scanner.engine` | string | "v2" | Engine selection (only "v2" is supported; v1 was removed) |
| `scanner.persist_raw_evidence` | bool | false | Write every probe observation to `service_evidence` (voluminous — enable for debugging only) |
| `scanner.lost_threshold` | int | 2 | Consecutive scans absent from the alive set before a device is declared lost. Its heartbeat-side counterpart is `heartbeat.offline_threshold` (probe-failure count). |
| `scanner.per_probe_timeout` | int (s) | 3 | Timeout for a SINGLE probe attempt (one SNMP Get / TCP dial / HTTP fetch). Distinct from `default_timeout` (the whole per-host pipeline). |
| `scanner.snmp_community` | string | "public" | Global SNMP community string (used by v1/v2c scans). |
| `scanner.oui_path` | string | "" | Path to an IEEE OUI vendor file (MA-L+MA-M+MA-S, produced by `scripts/fetch-oui.sh`). Empty = use the embedded curated CC-BY-SA table (out-of-box coverage of common vendors). Override: `MIBEE_SCANNER_OUI_PATH`. |
| `scanner.fingerprint_path` | string | "" | Directory of fingerprint YAML rules (see `docs/fingerprint-spec.md`). Empty = rules embedded in the binary. |
| `scanner.ebpf.enabled` | bool | false | Enable the eBPF passive observer (no-op unless built with `make build-with-ebpf`) |
| `scanner.ebpf.interfaces` | []string | [] | Interfaces to attach the TC program to (empty = all non-loopback) |
| `scanner.pipeline_defaults.*` | various | — | Per-stage enable flags + `default_ports` (expanded to include camera + prometheus ports) |
| `scanner.agent_lease_ttl` | duration | "5m" | Lease expiry for agent-managed devices. After an agent stops reporting, the device is marked lost within this time. |
| `scanner.lease_sweep_interval` | duration | "60s" | How often the lease sweeper runs. |
| `scanner.reconcile_interval` | duration | "1h" | Network attribution reconciliation interval. Detects devices whose IP has drifted outside their network's CIDR. |

### Config Backup (config_backup)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.config_backup.enabled` | bool | false | Enable SSH config backup (requires `security.master_key` + bound SSH credentials) |
| `scanner.config_backup.interval_seconds` | int (s) | 21600 | Config backup polling interval (seconds). <=0 → 6 hours (21600s). |
| `scanner.config_backup.timeout_seconds` | int (s) | 30 | Per-device SSH timeout (seconds). <=0 → 30s. |

### Router ARP Scan

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.router_arp.routers` | []string | [] | Router IPs for cross-subnet ARP walks. |
| `scanner.router_arp.community` | string | *(fallback)* | Router SNMP community. Falls back to `scanner.snmp_community` when empty (then "public"). |
| `scanner.router_arp.timeout` | int (s) | 4 | Per-router ARP walk timeout. |

### Reverse DNS

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.rdns.dns_servers` | []string | [] | DNS servers for reverse DNS lookups. |
| `scanner.rdns.timeout` | int (s) | 2 | Reverse DNS query timeout. |

### mDNS

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.mdns.unicast_queries` | bool | false | Enable mDNS unicast queries (for devices that don't respond to multicast). |

### ARP Scan

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.arp_scan.interface` | string | "" | Network interface name for ARP scan. |

**Synchronous scan limit**: `POST /scanner/scan` rejects targets >1024 IPs with HTTP 413. Use the async task API (`POST /scanner/tasks` + `/trigger`) for larger ranges.

**Example:**
```yaml
scanner:
  enabled: true
  default_timeout: 300
  max_concurrent_hosts: 50
  retention_days: 30
  default_cron_expr: "0 */6 * * *"
  engine: "v2"
  persist_raw_evidence: false
  lost_threshold: 2
  per_probe_timeout: 3
  snmp_community: "public"
  pipeline_defaults:
    icmp_enabled: true
    snmp_enabled: true
    port_scan_enabled: true
    default_ports: "22,80,443,8080,8443,8000,554,8554,9090,9100,9104,9113,9121,9187,161"
    service_detection_enabled: true
    prometheus_check_enabled: true
    node_exporter_enabled: true
  ebpf:
    enabled: false       # requires make build-with-ebpf + kernel ≥5.8 + CAP_BPF
    interfaces: []       # empty = all non-loopback
  config_backup:
    enabled: false
    interval_seconds: 21600   # <=0 → 6h
    timeout_seconds: 30
  router_arp:
    routers: []
    community: "public"
    timeout: 4
  rdns:
    dns_servers: []
    timeout: 2
  mdns:
    unicast_queries: false
```

## Router-Resident Discovery Sources

The scanner can ingest device data from router-resident sources in addition to active probing. The whole service is gated by the master switch `scanner.discovery.enabled` (disabled by default). Note: `trigger_identify` and the `router_arp`/`arp_cache`/`multicast` sub-source toggles ship **enabled: true** in `configs/config.example.yaml` (the recommended values) — they are off out of the box because of the master switch, not because each source individually defaults off. Each source is a no-op when the backing file or socket is absent on the host.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.discovery.enabled` | bool | false | Enable the passive discovery service |
| `scanner.discovery.interval` | int (s) | 60 | Discovery scan interval (seconds) |
| `scanner.discovery.trigger_identify` | bool | false* | Whether to trigger an identification scan when a new host is discovered. Zero-value is false, but the shipped/recommended default in `configs/config.example.yaml` is true. |
| `scanner.discovery.router_arp.enabled` | bool | false* | Enable router SNMP ARP walk source (cross-subnet coverage) |
| `scanner.discovery.arp_cache.enabled` | bool | false* | Enable local ARP cache source (reads `/proc/net/arp`) |
| `scanner.discovery.multicast.enabled` | bool | false* | Enable mDNS/SSDP passive listener source |
| `scanner.discovery.dhcp_leases.enabled` | bool | false | Read the local dnsmasq DHCP lease file (`/tmp/dhcp.leases` on OpenWrt, `/var/lib/misc/dnsmasq.leases` on Debian) to discover devices that recently obtained an IP. dnsmasq only — dhcpd.leases is not supported. |
| `scanner.discovery.conntrack.enabled` | bool | false | Parse the kernel conntrack table (`/proc/net/nf_conntrack` only — no `conntrack -L` CLI) to discover active NAT connections and their internal hosts. |
| `scanner.discovery.hostapd.enabled` | bool | false | Read the hostapd control interface to discover Wi-Fi clients associated with the router's access point. |
| `scanner.discovery.hostapd.interfaces` | []string | [] | Network interface names to monitor for hostapd. |
| `scanner.discovery.dns_log.enabled` | bool | false | Parse the dnsmasq query log (`--log-queries` output; dnsmasq only, not pihole) to discover hosts by their DNS activity. |
| `scanner.discovery.dns_log.path` | string | "" | Path to the DNS query log file. |
| `scanner.discovery.arp_scan.enabled` | bool | false | Enable active ARP who-has sweep (requires `WITH_ARPSCAN` build tag + `CAP_NET_RAW`). |
| `scanner.discovery.lldp_interfaces` | []string | [] | Network interface names for LLDP/CDP passive frame listening (requires `WITH_LLDP`/`WITH_CDP` build tags). |

> \* Sub-source toggles default to the Go zero value (false), but `router_arp`/`arp_cache`/`multicast` ship **enabled: true** in `configs/config.example.yaml` (recommended) — they are off out of the box only because of the master `scanner.discovery.enabled: false`.

**Environment Variables:**
- `MIBEE_SCANNER_DISCOVERY_DHCP_LEASES_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_CONNTRACK_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_HOSTAPD_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_DNS_LOG_ENABLED`

**Example:**
```yaml
scanner:
  discovery:
    enabled: true
    interval: 60
    trigger_identify: true    # recommended: new hosts get identified immediately
    router_arp:
      enabled: true      # recommended in the example config
    arp_cache:
      enabled: true      # recommended in the example config
    multicast:
      enabled: true      # recommended in the example config
    dhcp_leases:
      enabled: true     # read dnsmasq leases (/tmp/dhcp.leases or /var/lib/misc/dnsmasq.leases)
    conntrack:
      enabled: false    # parse /proc/net/nf_conntrack
    hostapd:
      enabled: false    # read hostapd control socket
      interfaces: []
    dns_log:
      enabled: false    # parse dnsmasq query log
      path: ""
    arp_scan:
      enabled: false
    lldp_interfaces: []
```

> **Note**: When the backing file or socket does not exist on the host, the source silently becomes a no-op — no error is logged and no discovery data is produced.

## Network Configuration

Identifies this instance's network identity. In multi-instance deployments, each instance configures a different `network.name` so devices are tagged with the corresponding `network_id` to avoid IP collisions.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network.name` | string | "default" | This instance's network name. Empty resolves to "default". |
| `network.cidr` | string | "" | CIDR representation of this network (e.g. "192.168.1.0/24"). Used for conntrack source filtering and network attribution reconciliation. |
| `network.site` | string | "" | Site/location description for this network (free text). |

## Center (Upstream Reporting) Configuration

The distributed-mode switch: with `center.url` set, this instance runs as an **agent** and reports scan results to the center; empty means center/standalone mode.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `center.url` | string | "" | The center's base URL (e.g. "http://192.168.63.101:8080"). Empty = center/standalone mode (no upstream reporting). |
| `center.auth_token` | string | "" | The agent's bearer token (minted on the center via `POST /api/v1/agents/tokens`). Required in agent mode. |
| `center.report_interval` | duration | "30s" | How often buffered scan results are flushed upstream when the buffer isn't full. Errors retry with exponential backoff. |

**Environment Variables:**
- `MIBEE_CENTER_URL`
- `MIBEE_CENTER_AUTH_TOKEN`
- `MIBEE_CENTER_REPORT_INTERVAL`

## Security Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `security.master_key` | string | "" | AES-GCM master key (must be exactly 32 bytes). Used for encrypted storage of SNMPv3 and SSH credentials. Empty = credential encryption disabled (falls back to v1/v2c community strings). |

**Example:**
```yaml
security:
  master_key: "<exactly 32 bytes>"   # the key must be exactly 32 bytes (AES-256-GCM)
```

Generate a master key (take 32 raw bytes and encode them):
```bash
head -c 32 /dev/urandom | base64
```

> Note: `openssl rand -hex 32` produces 64 hex characters (64 bytes) and FAILS the exactly-32-byte requirement — do not use it for the master key.

## Heartbeat Thresholds

The heartbeat subsystem uses several configurable thresholds to control when devices are marked offline and when probe frequency is reduced:

| Threshold | Key | Default | Effect |
|-----------|-----|---------|--------|
| **Offline flip** | `heartbeat.offline_threshold` | 5 | Consecutive probe failures before the device status transitions to `offline`. |
| **Backoff** | `heartbeat.offline_backoff_ticks` | 10 | For devices already offline, probe once every N ticks instead of every tick. On the default 30s ticker, N=10 ≈ 5 minutes between probes. |
| **Tick** | `heartbeat.tick_interval_seconds` | 30 | Interval between scheduler ticks (the heartbeat loop's heartbeat). |

**Recovery**: A successful scan always clears the failure count immediately — backoff never delays recovery of a host that comes back online.

## Sync Scan Limit

The synchronous scan endpoint (`POST /api/v1/scanner/scan`) imposes a hard target limit:

- **Max targets**: 1024 IPs (individual, CIDR, or range — total count after expansion)
- **Exceeds limit**: HTTP 413 with `target range too large for synchronous scan (N IPs; max 1024). Use POST /api/v1/scanner/tasks to run asynchronously.`
- **Workaround**: Use the async task API — `POST /api/v1/scanner/tasks` to create a task, then `POST /api/v1/scanner/tasks/{id}/trigger` to fire it. The async path has no target count limit.

## Rate Limit Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rate_limit.global_per_minute` | int | 100 (code default; example config ships 600) | Global maximum requests per minute per client IP. Applies to all endpoints. |
| `rate_limit.login_per_minute` | int | 10 | Stricter per-minute limit for login/auth endpoints (`/auth/login`, `/auth/register`). |
| `rate_limit.scan_per_minute` | int | 10 | Per-minute limit for scan trigger endpoints (`/scanner/scan`, `/scanner/tasks/{id}/trigger`). |

**Environment Variables:**
- `MIBEE_RATE_LIMIT_GLOBAL_PER_MINUTE`
- `MIBEE_RATE_LIMIT_LOGIN_PER_MINUTE`
- `MIBEE_RATE_LIMIT_SCAN_PER_MINUTE`

## Retention Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `retention.heartbeat_results_days` | int | 7 | Heartbeat results retention (days) |
| `retention.device_liveness_days` | int | 7 (mirrors the heartbeat window) | Device liveness series retention (days). Defaults to the `heartbeat_results_days` value when unset. |
| `retention.silent_device_days_mac` | int | 7 | Physical deletion of silent scanner-discovered devices with a MAC: deleted after this many days without observation |
| `retention.silent_device_hours_no_mac` | int | 24 | Physical deletion of silent devices without a MAC: deleted after this many hours without observation |
| `retention.scan_results_days` | int | 30 | Scan results retention (days) |
| `retention.scan_task_runs_days` | int | 30 | Scan task run records retention (days) |
| `retention.audit_logs_days` | int | 90 | Audit logs retention (days) |
| `retention.notification_log_days` | int | 30 | Notification logs retention (days) |
| `retention.service_evidence_days` | int | 14 | Service evidence retention (days) |
| `retention.change_log_days` | int | 30 | Change log retention (days) |
| `retention.device_neighbors_days` | int | 90 | Device neighbor records retention (days) |
| `retention.host_services_days` | int | 30 | Host service records retention (days) |
| `retention.host_tls_certs_days` | int | 30 | TLS certificate records retention (days) |
| `retention.probe_results_days` | int | 30 | Synthetic-probe (拨测) result history retention (days). `probe_tls_certs` is not swept — it holds only each target's current chain |
| `retention.sweep_interval_hours` | int | 6 | Cleanup sweep interval (hours) |
| `retention.batch_size` | int | 5000 | Max rows per cleanup batch |

## Docker Configuration Template

The repository ships a ready-to-use Docker Compose config template at [`configs/config.docker.yaml`](../../configs/config.docker.yaml). It pre-configures paths and network settings appropriate for containerized deployment — copy it as your starting `config.yaml` and adjust `auth.jwt_secret` and `auth.initial_admin_password` for production.

## Complete Configuration Example

```yaml
# Server configuration
server:
  port: 8080
  host: "0.0.0.0"
  trusted_proxies: []

# Database configuration
database:
  sqlite:
    path: "./data/mibee.db"

# Authentication
auth:
  jwt_secret: "your-strong-jwt-secret-key"
  token_expiry: "24h"
  initial_admin_password: "secure_admin_password"
  cookie_domain: ""
  cookie_secure: false
  cookie_same_site: "strict"

# RBAC
rbac:
  scope_default: "open"

# CORS
cors:
  allowed_origins:
    - "http://localhost:5173"
    - "http://localhost:8080"

# Heartbeat monitoring
heartbeat:
  default_interval: 30
  tick_interval_seconds: 30
  timeout: 5
  retention_days: 30
  offline_threshold: 5
  offline_backoff_ticks: 10

# Prometheus metrics
prometheus:
  enabled: true
  metrics_path: "/metrics"

# Dashboard
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"

# Storage
storage:
  upload_path: "./data/uploads"
  max_file_size: 104857600

# Logging
log:
  level: "info"
  format: "text"

# Scanner (v2)
scanner:
  enabled: true
  default_timeout: 300
  max_concurrent_hosts: 50
  retention_days: 30
  default_cron_expr: "0 */6 * * *"
  engine: "v2"
  persist_raw_evidence: false
  lost_threshold: 2
  snmp_community: "public"
  discovery:
    enabled: false
    interval: 60
    trigger_identify: true    # recommended: new hosts get identified immediately
    dhcp_leases:
      enabled: false
    conntrack:
      enabled: false
    hostapd:
      enabled: false
      interfaces: []
    dns_log:
      enabled: false
      path: ""
    arp_scan:
      enabled: false
    lldp_interfaces: []
  pipeline_defaults:
    icmp_enabled: true
    snmp_enabled: true
    port_scan_enabled: true
    default_ports: "22,80,443,8080,8443,8000,554,8554,9090,9100,9104,9113,9121,9187,161"
    service_detection_enabled: true
    prometheus_check_enabled: true
    node_exporter_enabled: true
  ebpf:
    enabled: false
    interfaces: []
  config_backup:
    enabled: false
    interval_seconds: 21600   # <=0 → 6h
    timeout_seconds: 30
  router_arp:
    routers: []
    community: "public"
    timeout: 4
  rdns:
    dns_servers: []
    timeout: 2
  mdns:
    unicast_queries: false

# Network
network:
  name: "default"
  cidr: ""
  site: ""

# Security
security:
  master_key: ""

# Retention
retention:
  heartbeat_results_days: 7
  scan_results_days: 30
  scan_task_runs_days: 30
  audit_logs_days: 90
  notification_log_days: 30
  service_evidence_days: 14
  change_log_days: 30
  device_neighbors_days: 90
  host_services_days: 30
  host_tls_certs_days: 30
  probe_results_days: 30
  sweep_interval_hours: 6
  batch_size: 5000

# Rate limiting
rate_limit:
  global_per_minute: 600
  login_per_minute: 10
  scan_per_minute: 10
```

## Production Security Checklist

When deploying to production, ensure these security settings are properly configured:

### 🔑 Critical Security Settings

1. **JWT Secret**: Generate a strong, random secret:
   ```bash
   openssl rand -base64 32
   ```
   Set `auth.jwt_secret` to this value

2. **Admin Password**: Change the default admin password immediately

3. **HTTPS Configuration**: Set `auth.cookie_secure: true` when using HTTPS

4. **CORS Origins**: Limit `cors.allowed_origins` to trusted domains only

5. **Master Key**: If using SNMPv3/SSH credential encryption, generate and configure `security.master_key`

### 🔒 Additional Security Considerations

- **File Uploads**: Monitor `storage.upload_path` for unauthorized files
- **Metrics Endpoint**: Restrict access to `/metrics` to monitoring systems only
- **Database Access**: Ensure database files have proper file permissions
- **Log Security**: Use JSON format in production for structured logging
- **Network Security**: Use firewall rules to restrict access to non-HTTP ports
- **Trusted Proxies**: When deploying behind a reverse proxy, configure `server.trusted_proxies`

### 📝 Environment Template

Create `/etc/default/mibee-steward` for production deployment:

```bash
# Server settings
MIBEE_SERVER_PORT=8080
MIBEE_SERVER_HOST=0.0.0.0
MIBEE_SERVER_TRUSTED_PROXIES=172.16.0.0/12,192.168.0.0/16   # comma-separated trusted proxy list

# Database
MIBEE_DATABASE_SQLITE_PATH=/opt/mibee-steward/data/mibee.db

# Security (MUST change these)
MIBEE_AUTH_JWT_SECRET=your-strong-secret-here
MIBEE_AUTH_INITIAL_ADMIN_PASSWORD=your-secure-password
MIBEE_AUTH_COOKIE_SECURE=true

# Logging
MIBEE_LOG_LEVEL=info
MIBEE_LOG_FORMAT=json

# CORS
MIBEE_CORS_ALLOWED_ORIGINS=https://yourdomain.com
```

### 🔒 Device Systems Configuration

Device systems management is enabled by default with these key settings:

- **Categories**: web_app, database, middleware, custom
- **Auto-discovery**: Systems with `metrics_enabled=true` appear in `/sd` endpoint
- **Labels**: Automatic labels include device_name, system_name, category, device_type, location

## Configuration Validation

The application validates configuration on startup (`internal/config/config.go`):

**Agent mode** (`center.url` set):
- `center.auth_token` is required (mint one on the center via `POST /api/v1/agents/tokens`)
- `network.name` is required (must match the network the token is bound to)

**Center / standalone mode**:
- `auth.jwt_secret` is required and must be at least 32 characters long
- `auth.jwt_secret` must not equal the placeholder `"change-me-in-production"`
- an empty `auth.initial_admin_password` makes the server exit at startup (see `cmd/server/main.go`)

The following produce **warnings only** and do not block startup:
- `auth.cookie_secure=false` (cookies will be sent over HTTP)
- `cors.allowed_origins` contains localhost/127.0.0.1 origins
- `security.master_key` is set but is not exactly 32 bytes long

Invalid configuration will prevent the application from starting with detailed error messages.
