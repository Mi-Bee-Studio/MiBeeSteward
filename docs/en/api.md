# MiBee Steward API Reference

Complete REST API documentation for the MiBee Steward device management and monitoring system with device systems management.

## Table of Contents

- [Authentication](#authentication)
- [Health](#health)
- [Users](#users)
- [Devices](#devices)
- [Device Systems](#device-systems)
- [Documents](#documents)
- [Heartbeat](#heartbeat)
- [Dashboard](#dashboard)
- [Links](#links)
- [Metrics & Discovery](#metrics--discovery)

## Authentication

Authentication uses JWT tokens with a cookie-first approach, falling back to Bearer header tokens.

### JWT Flow

1. **Login**: Submit credentials to receive JWT token (set as HTTP-only cookie)
2. **Usage**: Token sent automatically via cookie on subsequent requests
3. **Fallback**: Use `Authorization: Bearer <token>` header if cookie unavailable
4. **Expiry**: Configurable (default 24 hours)
5. **Logout**: Clear cookie (token automatically expires)

### Roles

- **Admin**: Full access to all resources
- **User**: Read-only access on most resources, limited admin operations

### Authentication Levels

- **Public**: No authentication required
- **RequireAuth**: Valid JWT token (any role)
- **RequireAdmin**: Valid JWT token with admin role

### Endpoints

#### POST /api/v1/auth/login
Authenticate user and return JWT token.

**Public** • **10 req/min rate limit**

**Request**:
```json
{
  "username": "string",  // accepts username or email
  "password": "string"
}
```

**Response**:
```json
{
  "token": "string",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
  }
}
```

#### POST /api/v1/auth/register
Register new user (admin only).

**Public** • **10 req/min rate limit**

**Request**:
```json
{
  "username": "string",
  "email": "string", 
  "password": "string",
  "role": "string"  // optional, defaults to "user"
}
```

**Response**:
```json
{
  "id": 1,
  "username": "user",
  "email": "user@example.com",
  "role": "user",
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

#### POST /api/v1/auth/logout
Logout user (clear cookie).

**Public** • **10 req/min rate limit**

**Response**: `204 No Content`

## Health

### GET /api/v1/health
System health check with database status.

**Public**

**Response**:
```json
{
  "status": "ok",
  "db": "ok",
  "version": "v0.1.0"
}
```

`status` is `ok` or `degraded` (when the database ping fails). `db` is `ok` or `error`. `version` is the build version injected via ldflags (`dev` for untagged builds).

## Users

Admin-only user management endpoints.

### GET /api/v1/users
List all users.

**RequireAdmin**

**Query Parameters**:
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Offset for pagination

**Response**:
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### Reset User Password

**Admin only**

`POST /api/v1/users/{id}/reset-password`

Resets a user's password. The target user is forced to change the password on next login. Any login lockout is cleared.

**Request**:
```json
{
  "new_password": "new-secure-password"
}
```

**Response**: `200 OK`
```json
{
  "message": "password reset successfully"
}
```

## Devices

Device management with multi-protocol monitoring capabilities.

### GET /api/v1/devices
List devices with filtering and pagination.

**RequireAuth**

**Query Parameters**:
- `status`: Filter by status (`online`, `offline`, `unknown`)
- `type`: Filter by type (`pc`, `embedded`, `iot`, `other`)
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Offset for pagination

**Response**:
```json
{
  "devices": [
    {
      "id": 1,
      "name": "Server-01",
      "type": "pc",
      "brand": "Dell",
      "model": "PowerEdge R740",
      "location": "Data Center A",
      "purpose": "Web Server",
      "description": "Primary web hosting server",
      "status": "online",
      "ip_address": "192.168.1.100",
      "mac_address": "00:1A:2B:3C:4D:5E",
      "serial_number": "DELL123456",
      "purchase_date": "2022-01-15",
      "warranty_expiry": "2025-01-15",
      "tags": "web,primary",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### GET /api/v1/devices/stats
Get device statistics (counts by status and type).

**RequireAuth**

**Response**:
```json
{
  "by_status": {
    "online": 5,
    "offline": 2,
    "unknown": 1
  },
  "by_type": {
    "pc": 4,
    "embedded": 2,
    "iot": 1,
    "other": 1
  }
}
```

### GET /api/v1/devices/{id}
Get device details by ID.

**RequireAuth**

**Response**: Same as GET /api/v1/devices but single device object

### POST /api/v1/devices
Create new device.

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "type": "string",     // pc, embedded, iot, other
  "brand": "string",
  "model": "string",
  "location": "string",
  "purpose": "string",
  "description": "string",
  "ip_address": "string",
  "mac_address": "string",
  "serial_number": "string",
  "purchase_date": "string",
  "warranty_expiry": "string",
  "tags": "string"
}
```

**Response**: `201 Created` with DeviceResponse

### PUT /api/v1/devices/{id}
Update device (partial update with pointer fields).

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "type": "string",
  "brand": "string",
  "model": "string",
  "location": "string",
  "purpose": "string",
  "description": "string",
  "ip_address": "string",
  "mac_address": "string",
  "serial_number": "string",
  "purchase_date": "string",
  "warranty_expiry": "string",
  "tags": "string"
}
```

**Response**: `200 OK` with updated DeviceResponse

### DELETE /api/v1/devices/{id}
Delete device.

**RequireAdmin**

**Response**: `204 No Content`

## Documents

Document management with URL ingestion and file upload capabilities.

### GET /api/v1/documents
List documents.

**RequireAuth**

**Query Parameters**:
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Offset for pagination

**Response**:
```json
{
  "documents": [
    {
      "id": 1,
      "title": "Server Manual",
      "type": "file",
      "url": "",
      "file_path": "./data/uploads/server-manual.pdf",
      "file_size": 2048000,
      "mime_type": "application/pdf",
      "description": "Server administration manual",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### GET /api/v1/documents/{id}
Get document details.

**RequireAuth**

**Response**: Same as GET /api/v1/documents but single document object

### GET /api/v1/documents/{id}/download
Download document file.

**RequireAuth**

**Response**: File download with appropriate content-type headers

### POST /api/v1/documents
Create URL document.

**RequireAdmin**

**Request**:
```json
{
  "title": "string",
  "type": "url",
  "url": "https://example.com/document",
  "description": "string"
}
```

**Response**: `201 Created` with DocumentResponse

### POST /api/v1/documents/upload
Upload file document (multipart form).

**RequireAdmin**

**Form Parameters**:
- `file`: File to upload (max 100MB)
- `title`: Document title
- `description`: Document description

**Response**: `201 Created` with DocumentResponse

### PUT /api/v1/documents/{id}
Update document.

**RequireAdmin**

**Request**:
```json
{
  "title": "string",
  "url": "string",
  "description": "string"
}
```

**Response**: `200 OK` with updated DocumentResponse

### DELETE /api/v1/documents/{id}
Delete document.

**RequireAdmin**

**Response**: `204 No Content`

## Heartbeat

Configurable heartbeat monitoring with automatic failure detection.

### GET /api/v1/devices/{id}/heartbeat-configs
List heartbeat configs for device.

**RequireAuth**

**Response**:
```json
{
  "configs": [
    {
      "id": 1,
      "device_id": 1,
      "interval_seconds": 30,
      "timeout_seconds": 10,
      "threshold": 3,
      "enabled": true
    }
  ],
  "total": 1
}
```

### POST /api/v1/devices/{id}/heartbeat-configs
Create heartbeat config for device.

**RequireAdmin**

**Request**:
```json
{
  "interval_seconds": 30,
  "timeout_seconds": 10,
  "threshold": 3,
  "enabled": true
}
```

**Response**: `201 Created` with heartbeat config

### PUT /api/v1/heartbeat-configs/{id}
Update heartbeat config.

**RequireAdmin**

**Request**:
```json
{
  "interval_seconds": 60,
  "timeout_seconds": 15,
  "threshold": 5,
  "enabled": true
}
```

**Response**: `200 OK` with updated heartbeat config

### DELETE /api/v1/heartbeat-configs/{id}
Delete heartbeat config.

**RequireAdmin**

**Response**: `204 No Content`

### GET /api/v1/devices/{id}/heartbeat-results
List heartbeat results for device.

**RequireAuth**

**Response**:
```json
{
  "results": [
    {
      "id": 1,
      "device_id": 1,
      "status": "success",
      "response_time_ms": 45,
      "error_message": "",
      "timestamp": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

## Dashboard

Prometheus query proxy for dashboard visualization.

### GET /api/v1/dashboard/configs
List dashboard configs.

**RequireAuth**

**Response**:
```json
{
  "configs": [
    {
      "id": 1,
      "name": "CPU Usage",
      "query": "cpu_usage",
      "description": "CPU usage monitoring"
    }
  ],
  "total": 1
}
```

### GET /api/v1/dashboard/query
**Request**:
```json
{
  "query": "cpu_usage",
  "time": "2023-01-01T00:00:00Z"
}
```

**RequireAuth**

**Request**:
```json
{
  "query": "cpu_usage",
  "time": "2023-01-01T00:00:00Z"
}
```

**Response**:
```json
{
  "data": [
    {
      "metric": "cpu_usage",
      "value": 0.45,
      "timestamp": "2023-01-01T00:00:00Z"
    }
  ]
}
```

### GET /api/v1/dashboard/query_range
Execute range query against metrics backend.

**RequireAuth**

**Request**:
```json
{
  "query": "cpu_usage",
  "start": "2023-01-01T00:00:00Z",
  "end": "2023-01-01T01:00:00Z",
  "step": "1m"
}
```

**Response**:
```json
{
  "data": [
    {
      "metric": "cpu_usage",
      "values": [
        [0.45, 1672574400],
        [0.52, 1672574460],
        [0.48, 1672574520]
      ]
    }
  ]
}
```

### POST /api/v1/dashboard/configs
Create dashboard config.

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "query": "string",
  "description": "string"
}
```

**Response**: `201 Created` with dashboard config

### PUT /api/v1/dashboard/configs/{id}
Update dashboard config.

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "query": "string",
  "description": "string"
}
```

**Response**: `200 OK` with updated dashboard config

### DELETE /api/v1/dashboard/configs/{id}
Delete dashboard config.

**RequireAdmin**

**Response**: `204 No Content`

## Links

Device-document relationship management.

### GET /api/v1/devices/{id}/documents
Get documents linked to device.

**RequireAuth**

**Response**:
```json
{
  "documents": [
    {
      "id": 1,
      "title": "Server Manual",
      "type": "file",
      "url": "",
      "file_path": "./data/uploads/server-manual.pdf",
      "file_size": 2048000,
      "mime_type": "application/pdf",
      "description": "Server administration manual",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v1/devices/{id}/documents
Link document to device.

**RequireAdmin**

**Request**:
```json
{
  "document_id": 1
}
```

**Response**: `201 Created`

### DELETE /api/v1/devices/{id}/documents/{docId}
Unlink document from device.

**RequireAdmin**

**Response**: `204 No Content`

### GET /api/v1/documents/{id}/devices
Get devices linked to document.

**RequireAuth**

**Response**:
```json
{
  "devices": [
    {
      "id": 1,
      "name": "Server-01",
      "type": "pc",
      "brand": "Dell",
      "model": "PowerEdge R740",
      "location": "Data Center A",
      "purpose": "Web Server",
      "description": "Primary web hosting server",
      "status": "online",
      "ip_address": "192.168.1.100",
      "mac_address": "00:1A:2B:3C:4D:5E",
      "serial_number": "DELL123456",
      "purchase_date": "2022-01-15",
      "warranty_expiry": "2025-01-15",
      "tags": "web,primary",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

## Device Systems

Device systems management for each installed system on devices with entry URLs and monitoring capabilities.

### GET /api/v1/devices/{id}/systems
List all systems for a device.

**RequireAuth**

**Response**:
```json
{
  "systems": [
    {
      "id": 1,
      "device_id": 1,
      "name": "Web Server",
      "entry_url": "https://app.example.com",
      "description": "Main web application",
      "category": "web_app",
      "metrics_url": "https://app.example.com/metrics",
      "metrics_enabled": true,
      "tags": "primary,web",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v1/devices/{id}/systems
Create a new system for a device.

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "entry_url": "string",
  "description": "string",
  "category": "string",  // web_app, database, middleware, custom
  "metrics_url": "string",
  "metrics_enabled": true,
  "tags": "string"
}
```

**Response**: `201 Created` with SystemResponse

### GET /api/v1/devices/{id}/systems/{systemId}
Get system details by ID.

**RequireAuth**

**Response**: Same as GET /api/v1/devices/{id}/systems but single system object

### PUT /api/v1/devices/{id}/systems/{systemId}
Update system (partial update with pointer fields).

**RequireAdmin**

**Request**:
```json
{
  "name": "string",
  "entry_url": "string",
  "description": "string",
  "category": "string",
  "metrics_url": "string",
  "metrics_enabled": true,
  "tags": "string"
}
```

**Response**: `200 OK` with updated SystemResponse

### DELETE /api/v1/devices/{id}/systems/{systemId}
Delete system.

**RequireAdmin**

**Response**: `204 No Content`


## Metrics & Discovery
Prometheus metrics endpoint.

**Public**

**Response**: Prometheus text format metrics

### GET /sd
Prometheus HTTP Service Discovery endpoint.

**Public**

**Response**: JSON service discovery data

---

## Network Scanner

All scanner endpoints are **admin-only** and versioned under `/api/v1/scanner`. The scanner uses the v2 plugin engine (probe → classify → handler → persist). See [Architecture → Network Scanner](architecture.md#network-scanner-v2).

### POST /api/v1/scanner/scan
Run a synchronous scan over a target spec (single IP, CIDR, range, or comma-separated list).

**Admin** · Rate-limited (10/min per IP by default)

**Request body**:
```json
{ "targets": "192.168.1.0/24", "community": "public", "timeout": 2 }
```
- `targets` (required): IP / CIDR / `a.b.c.d-e` range / comma list
- `community` (default "public"): SNMP community string
- `timeout` (default 2): per-host ICMP timeout in seconds

**Response**: `ScanResponse { hosts: [ScanHost], total, alive, duration_ms }` where each `ScanHost` carries `ip`, `alive`, `rtt_ms`, `snmp_*` varbinds, and `inferred_type` / `inferred_brand` (e.g. `camera`, `server`, `pc`).

**Limits**: rejects targets >1024 IPs with **413** (use the async task API below). Returns **504** if the server `write_timeout` fires mid-scan (config drift defense). The synchronous scan does **not** persist results — use AddDevices or the task scheduler for that.

### POST /api/v1/scanner/add-devices
Manually add devices from scan output. Each item is upserted via the device bridge (creates `devices` row + seeds heartbeat configs for new devices).

**Admin**

**Request body**:
```json
{ "devices": [ { "ip": "192.168.1.1", "name": "Gateway", "type": "other", "brand": "...", "ports": [...], "services": [...] } ] }
```

**Response**: `{ added: int, errors: [string] }`

### Scanner Task API (async, for large ranges)
- `POST /api/v1/scanner/tasks` — create a scheduled scan task (cron-driven)
- `GET /api/v1/scanner/tasks` — list tasks (paginated)
- `GET/PUT/DELETE /api/v1/scanner/tasks/{id}` — task CRUD
- `POST /api/v1/scanner/tasks/{id}/trigger` — fire a task asynchronously (returns `202` with a synthetic "triggered" status; the real run row is created when the scan starts)
- `POST /api/v1/scanner/tasks/{id}/cancel` — cancel an in-flight run (`409` if not running)
- `GET /api/v1/scanner/tasks/{id}/runs` — run history
- `GET /api/v1/scanner/tasks/{id}/results` — per-host results for a task

### Scanner Result API
- `GET /api/v1/scanner/results?task_id=&ip=&limit=&offset=` — browse results
- `GET /api/v1/scanner/results/{id}` — single result
- `GET /api/v1/scanner/runs?task_id=` — browse runs
- `GET /api/v1/scanner/runs/{id}` — single run
- `GET /api/v1/scanner/results/export?task_id=X` — CSV export
- `DELETE /api/v1/scanner/results?before_date=RFC3339` — bulk delete by date

---

## Response Format

### General Guidelines

- All responses use JSON format
- Field names use snake_case convention
- Timestamps use ISO 8601 format (UTC)
- Error responses use `{"error": "message"}` format

### Pagination

Endpoints that return lists support pagination:
- `limit`: Number of results per page (default: 20, max: 100)
- `offset`: Number of items to skip (default: 0)

Paginated responses include:
- Array of items
- `total` count of all items

### Rate Limiting

Global rate limits apply:
- **Global**: 100 requests per minute per IP
- **Login endpoints**: 10 requests per minute per IP

Rate limit headers:
- `X-RateLimit-Limit`: Request limit
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Unix timestamp when limit resets

### Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Missing or invalid JWT |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource does not exist |
| 409 | Conflict - Resource already exists |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 502 | Bad Gateway - Upstream service error |

### Authentication

Tokens can be provided in two ways:
1. **Cookie**: Automatically sent by browser (HTTP-only)
2. **Header**: `Authorization: Bearer <token>`

Login response sets an HTTP-only cookie with the JWT token for subsequent requests.