# MiBee Steward API 参考文档
# 
# MiBee Steward 设备/网络层资产发现与登记系统的完整 REST API 文档。

## 目录
- [认证](#认证)
- [健康检查](#健康检查)
- [用户](#用户)
- [设备](#设备)
- [设备证书](#设备证书)
- [文档](#文档)
- [心跳监控](#心跳监控)
- [仪表板](#仪表板)
- [关联](#关联)
- [指标与服务发现](#指标与服务发现)

## 认证

认证使用 JWT 令牌，采用优先 cookie 的方式，回退到 Bearer 头令牌。

### JWT 流程

1. **登录**：提交凭据获取 JWT 令牌（设置为 HTTP-only cookie）
2. **使用**：后续请求自动通过 cookie 发送令牌
3. **回退**：如果 cookie 不可用，使用 `Authorization: Bearer <token>` 头
4. **过期**：可配置（默认 24 小时）
5. **登出**：清除 cookie（令牌自动过期）

### 角色

- **管理员**：对所有资源的完全访问权限
- **用户**：对大多数资源的只读权限，有限的操作权限

### 认证级别

- **公开**：无需认证
- **需要认证**：有效的 JWT 令牌（任意角色）
- **需要管理员**：具有管理员角色的有效 JWT 令牌

### 端点

#### POST /api/v1/auth/login
验证用户并返回 JWT 令牌。

**公开** • **每分钟 10 次请求速率限制**

**请求**：
```json
{
  "username": "string",  // 接受用户名或邮箱
  "password": "string"
}
```

**响应**：
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
注册新用户（仅管理员）。

**公开** • **每分钟 10 次请求速率限制**

**请求**：
```json
{
  "username": "string",
  "email": "string", 
  "password": "string",
  "role": "string"  // 可选，默认为 "user"
}
```

**响应**：
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
用户登出（清除 cookie）。

**公开** • **每分钟 10 次请求速率限制**

**响应**：`204 No Content`

## 健康检查

### GET /api/v1/health
系统健康检查，包含数据库状态。

**公开**

**响应**：
```json
{
  "status": "ok",
  "db": "ok",
  "version": "v0.1.0"
}
```

`status` 为 `ok` 或 `degraded`（数据库 ping 失败时）。`db` 为 `ok` 或 `error`。`version` 为通过 ldflags 注入的构建版本（未打 tag 的构建为 `dev`）。

## 用户

仅管理员可用的用户管理端点。

### GET /api/v1/users
列出所有用户。

**需要管理员**

**查询参数**：
- `limit`：结果数量（默认：20，最大：100）
- `offset`：分页偏移量

**响应**：
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

### 重置用户密码

**仅管理员**

`POST /api/v1/users/{id}/reset-password`

重置指定用户的密码。目标用户下次登录时需要修改密码，同时清除登录锁定状态。

**请求**：
```json
{
  "new_password": "new-secure-password"
}
```

**响应**：`200 OK`
```json
{
  "message": "password reset successfully"
}
```

## 设备

具有多协议自动发现与身份识别能力的设备登记与管理。

### GET /api/v1/devices
列出设备，支持过滤和分页。

**需要认证**

**查询参数**：
- `status`：按状态过滤（`online`，`offline`，`unknown`）
- `type`：按类型过滤（`pc`，`embedded`，`iot`，`other`）
- `limit`：结果数量（默认：20，最大：100）
- `offset`：分页偏移量

**响应**：
```json
{
  "devices": [
    {
      "id": 1,
      "name": "Server-01",
      "type": "pc",
      "brand": "Dell",
      "model": "PowerEdge R740",
      "location": "数据中心 A",
      "purpose": "Web 服务器",
      "description": "主要 Web 托管服务器",
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
获取设备统计信息（按状态和类型的计数）。

**需要认证**

**响应**：
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
根据 ID 获取设备详情。

**需要认证**

**响应**：与 GET /api/v1/devices 相同，但为单个设备对象

## 设备证书

由 v2 扫描器从设备上 TLS 包装的服务（HTTPS、LDAPS、SMTPS、IMAPS、POP3S、FTPS、IRCS、TelnetS）采集的 TLS/SSL 证书链。每个端口的证书链中每张证书一行（`cert_index` 0 = 叶/服务器证书，1..N = 上级颁发者）。由 `probe.CollectCertChain` 采集并写入 `host_tls_certs` 表；每次扫描时该端口的链被整体替换。按 `retention.host_tls_certs_days`（默认 30 天）保留。

### GET /api/v1/devices/{id}/certificates
列出从设备上每个 TLS 端口采集的证书链，按端口分组。

**需要认证**（任意登录用户；只读）

**响应**：
```json
{
  "certificates": [
    {
      "port": 990,
      "tls_version": "TLS 1.2",
      "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "trusted": false,
      "error": "",
      "updated_at": "2026-07-17T23:38:33Z",
      "leaf": {
        "cert_index": 0,
        "subject_cn": "device.example.com",
        "subject_org": "Example Org",
        "subject": "CN=device.example.com,O=Example Org",
        "issuer_cn": "Example CA",
        "issuer_org": "Example CA Ltd",
        "issuer": "CN=Example CA,O=Example CA Ltd,C=US",
        "san_dns": "device.example.com, alt.example.com",
        "san_ip": "192.168.63.112",
        "san_email": "",
        "serial": "665071982890971409216315924781532514095376553279",
        "not_before": "2023-10-29T02:38:14Z",
        "not_after": "2033-10-26T02:38:14Z",
        "sig_algorithm": "SHA256-RSA",
        "key_algorithm": "RSA",
        "key_bits": 2048,
        "is_ca": false,
        "self_signed": false,
        "fingerprint_sha256": "B8A72EE7DF38217D2C037C8927E687921FD8D31B9A0AF2E4E22779B60671F278",
        "pem": "-----BEGIN CERTIFICATE-----\nMIIC4zCCAcsCFHR+...\n-----END CERTIFICATE-----\n"
      },
      "chain": [
        { "cert_index": 0, "subject_cn": "device.example.com", "...": "..." },
        { "cert_index": 1, "subject_cn": "Example CA", "is_ca": true, "...": "..." }
      ]
    }
  ],
  "total": 1
}
```

**字段说明**：
- `tls_version` / `cipher_suite` / `trusted` 是握手元数据，在同一端口链中的每个条目上都相同（描述的是同一次握手）。
- `leaf` 即 `chain[0]`，单独暴露以便一览式渲染；当 `error` 非空时省略。
- `error` 在 TLS 握手失败时非空（如 `not TLS`、`handshake failure`）。这类行仍然返回，便于 UI 显示"已尝试过此端口"而非默默省略。此时 `leaf` 与 `chain` 为空。
- `trusted` 是最佳努力的判定（对系统根证书池做一次验证握手得出），仅用于 UI 徽章，**不影响采集**（自签名证书总会被采集）。
- 设备未记录任何 TLS 端口时返回空 `certificates` 数组，HTTP 仍为 200 —— 应渲染空状态，而非 404。

### POST /api/v1/devices
创建新设备。

**需要管理员**

**请求**：
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

**响应**：`201 Created` 带 DeviceResponse

### PUT /api/v1/devices/{id}
更新设备（使用指针字段进行部分更新）。

**需要管理员**

**请求**：
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

**响应**：`200 OK` 带 updated DeviceResponse

### DELETE /api/v1/devices/{id}
删除设备。

**需要管理员**

**响应**：`204 No Content`

## 文档

具有 URL 获取和文件上传功能的文档管理。

### GET /api/v1/documents
列出文档。

**需要认证**

**查询参数**：
- `limit`：结果数量（默认：20，最大：100）
- `offset`：分页偏移量

**响应**：
```json
{
  "documents": [
    {
      "id": 1,
      "title": "服务器手册",
      "type": "file",
      "url": "",
      "file_path": "./data/uploads/server-manual.pdf",
      "file_size": 2048000,
      "mime_type": "application/pdf",
      "description": "服务器管理手册",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### GET /api/v1/documents/{id}
获取文档详情。

**需要认证**

**响应**：与 GET /api/v1/documents 相同，但为单个文档对象

### GET /api/v1/documents/{id}/download
下载文档文件。

**需要认证**

**响应**：带有适当 content-type 头的文件下载

### POST /api/v1/documents
创建 URL 文档。

**需要管理员**

**请求**：
```json
{
  "title": "string",
  "type": "url",
  "url": "https://example.com/document",
  "description": "string"
}
```

**响应**：`201 Created` 带 DocumentResponse

### POST /api/v1/documents/upload
上传文件文档（multipart 表单）。

**需要管理员**

**表单参数**：
- `file`：要上传的文件（最大 100MB）
- `title`：文档标题
- `description`：文档描述

**响应**：`201 Created` 带 DocumentResponse

### PUT /api/v1/documents/{id}
更新文档。

**需要管理员**

**请求**：
```json
{
  "title": "string",
  "url": "string",
  "description": "string"
}
```

**响应**：`200 OK` 带 updated DocumentResponse

### DELETE /api/v1/documents/{id}
删除文档。

**需要管理员**

**响应**：`204 No Content`

## 心跳监控

具有自动故障检测的可配置心跳监控。

### GET /api/v1/devices/{id}/heartbeat-configs
列出设备的心跳配置。

**需要认证**

**响应**：
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
为设备创建心跳配置。

**需要管理员**

**请求**：
```json
{
  "interval_seconds": 30,
  "timeout_seconds": 10,
  "threshold": 3,
  "enabled": true
}
```

**响应**：`201 Created` 带 heartbeat config

### PUT /api/v1/heartbeat-configs/{id}
更新心跳配置。

**需要管理员**

**请求**：
```json
{
  "interval_seconds": 60,
  "timeout_seconds": 15,
  "threshold": 5,
  "enabled": true
}
```

**响应**：`200 OK` 带 updated heartbeat config

### DELETE /api/v1/heartbeat-configs/{id}
删除心跳配置。

**需要管理员**

**响应**：`204 No Content`

### GET /api/v1/devices/{id}/heartbeat-results
列出设备的心跳结果。

**需要认证**

**响应**：
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

## 仪表板

用于仪表板可视化的 Prometheus 查询代理。

### GET /api/v1/dashboard/configs
列出仪表板配置。

**需要认证**

**响应**：
```json
{
  "configs": [
    {
      "id": 1,
      "name": "CPU 使用率",
      "query": "cpu_usage",
      "description": "CPU 使用率监控"
    }
  ],
  "total": 1
}
```

### GET /api/v1/dashboard/query
对指标后端执行即时查询。

**需要认证**

**请求**：
```json
{
  "query": "cpu_usage",
  "time": "2023-01-01T00:00:00Z"
}
```

**响应**：
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
对指标后端执行范围查询。

**需要认证**

**请求**：
```json
{
  "query": "cpu_usage",
  "start": "2023-01-01T00:00:00Z",
  "end": "2023-01-01T01:00:00Z",
  "step": "1m"
}
```

**响应**：
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
创建仪表板配置。

**需要管理员**

**请求**：
```json
{
  "name": "string",
  "query": "string",
  "description": "string"
}
```

**响应**：`201 Created` 带 dashboard config

### PUT /api/v1/dashboard/configs/{id}
更新仪表板配置。

**需要管理员**

**请求**：
```json
{
  "name": "string",
  "query": "string",
  "description": "string"
}
```

**响应**：`200 OK` 带 updated dashboard config

### DELETE /api/v1/dashboard/configs/{id}
删除仪表板配置。

**需要管理员**

**响应**：`204 No Content`

## 关联

设备文档关系管理。

### GET /api/v1/devices/{id}/documents
获取与设备关联的文档。

**需要认证**

**响应**：
```json
{
  "documents": [
    {
      "id": 1,
      "title": "服务器手册",
      "type": "file",
      "url": "",
      "file_path": "./data/uploads/server-manual.pdf",
      "file_size": 2048000,
      "mime_type": "application/pdf",
      "description": "服务器管理手册",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v1/devices/{id}/documents
将文档关联到设备。

**需要管理员**

**请求**：
```json
{
  "document_id": 1
}
```

**响应**：`201 Created`

### DELETE /api/v1/devices/{id}/documents/{docId}
解除设备与文档的关联。

**需要管理员**

**响应**：`204 No Content`

### GET /api/v1/documents/{id}/devices
获取与文档关联的设备。

**需要认证**

**响应**：
```json
{
  "devices": [
    {
      "id": 1,
      "name": "Server-01",
      "type": "pc",
      "brand": "Dell",
      "model": "PowerEdge R740",
      "location": "数据中心 A",
      "purpose": "Web 服务器",
      "description": "主要 Web 托管服务器",
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

## 指标与服务发现

### GET /metrics
Prometheus 指标端点。

**公开**

**响应**：Prometheus 文本格式指标

### GET /sd
Prometheus HTTP 服务发现端点。

**公开**

**响应**：JSON 服务发现数据

---

## 网络扫描器

所有扫描器端点均为**仅管理员**，位于 `/api/v1/scanner` 下。扫描器使用 v2 插件引擎（探测 → 分类 → 处理器 → 持久化）。详见 [架构 → 网络扫描器](architecture.md#网络扫描器v2)。

### POST /api/v1/scanner/scan
对目标（单 IP、CIDR、范围、逗号列表）执行同步扫描。

**仅管理员** · 限流（默认每 IP 10/分钟）

**请求体**：
```json
{ "targets": "192.168.1.0/24", "community": "public", "timeout": 2 }
```
- `targets`（必填）：IP / CIDR / `a.b.c.d-e` 范围 / 逗号列表
- `community`（默认 "public"）：SNMP community
- `timeout`（默认 2）：每主机 ICMP 超时（秒）

**响应**：`ScanResponse { hosts: [ScanHost], total, alive, duration_ms }`，每个 `ScanHost` 含 `ip`、`alive`、`rtt_ms`、`snmp_*` 变量，以及 `inferred_type` / `inferred_brand`（如 `camera`、`server`、`pc`）。

**限制**：对 >1024 IP 的目标返回 **413**（请用下方异步任务 API）。若服务器 `write_timeout` 在扫描途中触发则返回 **504**（配置漂移兜底）。**同步扫描不持久化结果**——请用 AddDevices 或任务调度器。

### POST /api/v1/scanner/add-devices
从扫描结果手动添加设备。每个条目经设备桥接 upsert（新建 `devices` 行 + 为新设备种子心跳配置）。

**仅管理员**

**请求体**：
```json
{ "devices": [ { "ip": "192.168.1.1", "name": "Gateway", "type": "other", "brand": "...", "ports": [...], "services": [...] } ] }
```

**响应**：`{ added: int, errors: [string] }`

### 扫描任务 API（异步，用于大范围）
- `POST /api/v1/scanner/tasks` — 创建定时扫描任务（cron 驱动）
- `GET /api/v1/scanner/tasks` — 列出任务（分页）
- `GET/PUT/DELETE /api/v1/scanner/tasks/{id}` — 任务 CRUD
- `POST /api/v1/scanner/tasks/{id}/trigger` — 异步触发任务（返回 `202` 合成 "triggered" 状态；真实 run 行在扫描启动时创建）
- `POST /api/v1/scanner/tasks/{id}/cancel` — 取消运行中的扫描（未运行则 `409`）
- `GET /api/v1/scanner/tasks/{id}/runs` — 运行历史
- `GET /api/v1/scanner/tasks/{id}/results` — 任务每主机结果

### 扫描结果 API
- `GET /api/v1/scanner/results?task_id=&ip=&limit=&offset=` — 浏览结果
- `GET /api/v1/scanner/results/{id}` — 单条结果
- `GET /api/v1/scanner/runs?task_id=` — 浏览运行
- `GET /api/v1/scanner/runs/{id}` — 单次运行
- `GET /api/v1/scanner/results/export?task_id=X` — CSV 导出
- `DELETE /api/v1/scanner/results?before_date=RFC3339` — 按日期批量删除

---

## 响应格式

### 通用指南

- 所有响应使用 JSON 格式
- 字段名使用 snake_case 约定
- 时间戳使用 ISO 8601 格式（UTC）
- 错误响应使用 `{"error": "message"}` 格式

### 分页

返回列表的端点支持分页：
- `limit`：每页结果数量（默认：20，最大：100）
- `offset`：要跳过的项目数（默认：0）

分页响应包括：
- 项目数组
- 所有项目的 `total` 计数

### 速率限制

全局速率限制适用：
- **全局**：每 IP 每分钟 100 次请求
- **登录端点**：每 IP 每分钟 10 次请求

速率限制头：
- `X-RateLimit-Limit`：请求限制
- `X-RateLimit-Remaining`：剩余请求数
- `X-RateLimit-Reset`：限制重置的 Unix 时间戳

### 错误码

| 代码 | 含义 |
|------|------|
| 400 | 错误的请求 - 无效的输入数据 |
| 401 | 未授权 - 缺少或无效的 JWT |
| 403 | 禁止 - 权限不足 |
| 404 | 未找到 - 资源不存在 |
| 409 | 冲突 - 资源已存在 |
| 429 | 请求过多 - 超过速率限制 |
| 500 | 内部服务器错误 |
| 502 | 网关错误 - 上游服务错误 |

### 认证

令牌可以通过两种方式提供：
1. **Cookie**：由浏览器自动发送（HTTP-only）
2. **Header**：`Authorization: Bearer <token>`

登录响应设置一个包含 JWT 令牌的 HTTP-only cookie，用于后续请求。