# Configuration Reference

MiBee Steward uses YAML configuration files with environment variable overrides. This document covers all available configuration options.

## Configuration Structure

The configuration is organized into 10 main sections:

- **Server**: HTTP server settings
- **Database**: Database configuration (SQLite)
- **Authentication**: JWT and cookie settings
- **CORS**: Cross-origin resource sharing
- **Heartbeat**: Device monitoring settings
- **Device Systems**: Systems management configuration
- **Prometheus**: Metrics collection
- **Dashboard**: Dashboard data source configuration
- **Storage**: File upload settings
- **Logging**: Log output configuration
## Configuration Loading Priority

Configuration values are loaded in the following order (with later values overriding earlier ones):

1. **YAML Configuration File**: Base configuration loaded from `config.yaml`
2. **Environment Variables**: `MIBEE_*` prefixed variables override YAML values

## Environment Variable Override Pattern

Environment variables override configuration values using the pattern:
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

**Environment Variables:**
- `MIBEE_SERVER_PORT`
- `MIBEE_SERVER_HOST`
- `MIBEE_SERVER_READ_TIMEOUT`, `MIBEE_SERVER_WRITE_TIMEOUT`, `MIBEE_SERVER_IDLE_TIMEOUT`

**Example:**
```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "15s"
  write_timeout: "5m"     # auto-raised if too low for synchronous scans
  idle_timeout: "120s"

# Environment override
export MIBEE_SERVER_PORT=3000
export MIBEE_SERVER_HOST="192.168.1.100"
```

## 2. Database Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
|| `database.type` | string | "sqlite" | Database type: "sqlite" |
| `database.sqlite.path` | string | "./data/mibee.db" | SQLite database file path |

**Environment Variables:**
- `MIBEE_DATABASE_TYPE`
- `MIBEE_DATABASE_SQLITE_PATH`

**Example:**
```yaml
database:
  type: "sqlite"
  sqlite:
    path: "./data/mibee.db"


## 3. Authentication Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auth.jwt_secret` | string | "change-me-in-production" | JWT signing key **(MUST change in production)** |
| `auth.token_expiry` | string | "24h" | JWT token lifetime |
| `auth.initial_admin_password` | string | *(unset → random)* | Initial admin password. **Must be set for production** — the server refuses to start with an empty value in production mode. |
| `auth.cookie_domain` | string | "" | Cookie domain (empty = current domain) |
| `auth.cookie_secure` | bool | false | Set true for HTTPS-only cookies |
| `auth.cookie_same_site` | string | "strict" | Cookie same-site policy: "strict" or "lax" |

**Environment Variables:**
- `MIBEE_AUTH_JWT_SECRET`
- `MIBEE_AUTH_TOKEN_EXPIRY`
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`
- `MIBEE_AUTH_COOKIE_DOMAIN`
- `MIBEE_AUTH_COOKIE_SECURE`
- `MIBEE_AUTH_COOKIE_SAME_SITE`

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

## 4. CORS Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cors.allowed_origins` | []string | ["localhost:5173", "localhost:8080"] | Allowed origins for cross-origin requests |

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
| `heartbeat.timeout` | int | 5 | Device probe timeout (seconds) |
| `heartbeat.retention_days` | int | 30 | Result retention period (days) |

**Environment Variables:**
- `MIBEE_HEARTBEAT_DEFAULT_INTERVAL`
- `MIBEE_HEARTBEAT_TIMEOUT`
- `MIBEE_HEARTBEAT_RETENTION_DAYS`

**Example:**
```yaml
heartbeat:
  default_interval: 30
  timeout: 5
  retention_days: 30

# Environment overrides
export MIBEE_HEARTBEAT_DEFAULT_INTERVAL=60
export MIBEE_HEARTBEAT_TIMEOUT=10
```

## 6. Prometheus Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `prometheus.enabled` | bool | true | Enable Prometheus metrics collection |
| `prometheus.metrics_path` | string | "/metrics" | Metrics endpoint path |

**Environment Variables:**
- `MIBEE_PROMETHEUS_ENABLED`
- `MIBEE_PROMETHEUS_METRICS_PATH`

**Example:**
```yaml
prometheus:
  enabled: true
  metrics_path: "/metrics"

# Environment override
export MIBEE_PROMETHEUS_METRICS_PATH="/monitoring/metrics"
```

## 7. Dashboard Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
|| `dashboard.data_source_type` | string | "prometheus" | Data source: "prometheus" |
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

The network scanner uses a plugin-based 5-layer architecture (probe → classify → handler → persist → orchestrate). See [Architecture → Network Scanner](architecture.md#network-scanner-v2).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner.enabled` | bool | true | Master switch for scanner endpoints + background scheduler |
| `scanner.max_concurrent_scans` | int | 3 | (legacy field, retained for compatibility) |
| `scanner.default_timeout` | int (s) | 300 | Per-host pipeline timeout for cron-driven scans. Also drives the `write_timeout` auto-raise. |
| `scanner.max_concurrent_hosts` | int | 50 | Parallelism cap for per-host scanning |
| `scanner.retention_days` | int | 30 | `scan_results` rows older than this are pruned daily |
| `scanner.default_cron_expr` | string | "0 */6 * * *" | Default cron for newly-created scan tasks |
| `scanner.engine` | string | "v2" | Engine selection (only "v2" is supported; v1 was removed) |
| `scanner.persist_raw_evidence` | bool | false | Write every probe observation to `service_evidence` (voluminous — enable for debugging only) |
| `scanner.ebpf.enabled` | bool | false | Enable the eBPF passive observer (no-op unless built with `make build-with-ebpf`) |
| `scanner.ebpf.interfaces` | []string | [] | Interfaces to attach the TC program to (empty = all non-loopback) |
| `scanner.pipeline_defaults.*` | various | — | Per-stage enable flags + `default_ports` (expanded to include camera + prometheus ports) |

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
```

## Complete Configuration Example

```yaml
# Server configuration
server:
  port: 8080
  host: "0.0.0.0"

# Database configuration
database:
  type: "sqlite"
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

# CORS
cors:
  allowed_origins:
    - "http://localhost:5173"
    - "http://localhost:8080"

# Heartbeat monitoring
heartbeat:
  default_interval: 30
  timeout: 5
  retention_days: 30

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

### 🔒 Additional Security Considerations

- **File Uploads**: Monitor `storage.upload_path` for unauthorized files
- **Metrics Endpoint**: Restrict access to `/metrics` to monitoring systems only
- **Database Access**: Ensure database files have proper file permissions
- **Log Security**: Use JSON format in production for structured logging
- **Network Security**: Use firewall rules to restrict access to non-HTTP ports

### 📝 Environment Template

Create `/etc/default/mibee-steward` for production deployment:

```bash
# Server settings
MIBEE_SERVER_PORT=8080
MIBEE_SERVER_HOST=0.0.0.0

# Database
MIBEE_DATABASE_TYPE=sqlite
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

The application validates configuration on startup:

- Database type must be "sqlite"
- Required fields are checked (jwt_secret, initial_admin_password)
- Port numbers must be valid (1-65535)
- File paths must be accessible
- SSL mode must be a valid option

Invalid configuration will prevent the application from starting with detailed error messages.