# 配置参考

MiBee Steward 使用 YAML 配置文件，支持环境变量覆盖。本文档涵盖所有可用的配置选项。

## 配置结构

配置分为 9 个主要部分：

- **服务器**：HTTP 服务器设置
- **数据库**：数据库配置（SQLite）
- **认证**：JWT 和 cookie 设置
- **CORS**：跨域资源共享
- **心跳**：设备监控设置
- **Prometheus**：指标收集
- **仪表板**：仪表板数据源配置
- **存储**：文件上传设置
- **日志**：日志输出配置

## 配置加载优先级

配置值按以下顺序加载（后面的值会覆盖前面的值）：

1. **YAML 配置文件**：从 `config.yaml` 加载基础配置
2. **环境变量**：`MIBEE_*` 前缀的变量覆盖 YAML 值

## 环境变量覆盖模式

环境变量使用以下模式覆盖配置值：
- 前缀：`MIBEE_`
- 部分和键：转换为大写，用下划线替换点号
- 示例：`server.port` → `MIBEE_SERVER_PORT`

## 1. 服务器配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `server.port` | int | 8080 | HTTP 监听端口 |
| `server.host` | string | "0.0.0.0" | 绑定地址（0.0.0.0 = 所有接口） |
| `server.read_timeout` | duration | "15s" | 读取完整请求（头+体）的最长时间 |
| `server.write_timeout` | duration | "5m" | 响应生命周期上限。**必须超过最慢的同步端点**（POST `/scanner/scan`）。若配置过低会自动上调至 `scanner.default_timeout×2+30s`，确保同步扫描永不被截断。 |
| `server.idle_timeout` | duration | "120s" | keep-alive 空闲超时 |

**环境变量：**
- `MIBEE_SERVER_PORT`、`MIBEE_SERVER_HOST`
- `MIBEE_SERVER_READ_TIMEOUT`、`MIBEE_SERVER_WRITE_TIMEOUT`、`MIBEE_SERVER_IDLE_TIMEOUT`

**示例：**
```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "15s"
  write_timeout: "5m"     # 若对同步扫描过低会自动上调
  idle_timeout: "120s"

# 环境变量覆盖
export MIBEE_SERVER_PORT=3000
export MIBEE_SERVER_HOST="192.168.1.100"
```

## 2. 数据库配置

|| 键 | 类型 | 默认值 | 描述 |
||-----|------|---------|-------------|
|| `database.sqlite.path` | string | "./data/mibee.db" | SQLite 数据库文件路径 |

**环境变量：**
- `MIBEE_DATABASE_TYPE`
- `MIBEE_DATABASE_SQLITE_PATH`
- `MIBEE_DATABASE_POSTGRESQL_HOST`
- `MIBEE_DATABASE_POSTGRESQL_PORT`
- `MIBEE_DATABASE_POSTGRESQL_USER`
- `MIBEE_DATABASE_POSTGRESQL_PASSWORD`
**环境变量：：
- `MIBEE_DATABASE_SQLITE_PATH`

**示例：：
```yaml
database:
  sqlite:
    path: "./data/mibee.db"
```
```

## 3. 认证配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `auth.jwt_secret` | string | "change-me-in-production" | JWT 签名密钥 **（生产环境必须更改）** |
| `auth.token_expiry` | string | "24h" | JWT 令牌有效期 |
| `auth.initial_admin_password` | string | *(未设置 → 随机)* | 初始管理员密码。**生产环境必须设置** — 生产模式下服务器拒绝空值启动。 |
| `auth.cookie_domain` | string | "" | Cookie 域名（空表示当前域名） |
| `auth.cookie_secure` | bool | false | HTTPS 专用 cookie 时设置为 true |
| `auth.cookie_same_site` | string | "strict" | Cookie 同站策略："strict" 或 "lax" |

**环境变量：**
- `MIBEE_AUTH_JWT_SECRET`
- `MIBEE_AUTH_TOKEN_EXPIRY`
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`
- `MIBEE_AUTH_COOKIE_DOMAIN`
- `MIBEE_AUTH_COOKIE_SECURE`
- `MIBEE_AUTH_COOKIE_SAME_SITE`

**示例：**
```yaml
auth:
  jwt_secret: "your-strong-jwt-secret-here"
  token_expiry: "24h"
  initial_admin_password: "secure_admin_password"
  cookie_domain: "example.com"
  cookie_secure: true
  cookie_same_site: "strict"

# 环境变量覆盖
export MIBEE_AUTH_JWT_SECRET="super-secret-key"
export MIBEE_AUTH_COOKIE_SECURE=true
```

## 4. CORS 配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `cors.allowed_origins` | []string | ["localhost:5173", "localhost:8080"] | 允许跨域请求的源列表 |

**环境变量：**
- `MIBEE_CORS_ALLOWED_ORIGINS`

**示例：**
```yaml
cors:
  allowed_origins:
    - "http://localhost:5173"
    - "http://localhost:8080"
    - "https://yourdomain.com"

# 环境变量覆盖
export MIBEE_CORS_ALLOWED_ORIGINS="https://example.com,https://app.example.com"
```

## 5. 心跳配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `heartbeat.default_interval` | int | 30 | 默认设备检查间隔（秒） |
| `heartbeat.timeout` | int | 5 | 设备探测超时（秒） |
| `heartbeat.retention_days` | int | 30 | 结果保留期（天） |
| `heartbeat.offline_backoff_ticks` | int | 10 | 离线设备每 N 个 tick 探测一次而非每 tick（30s ticker 下 N=10 约 5 分钟一次）。避免对不会响应的设备持续写入超时记录。扫描恢复设备时会立即清除失败计数，因此退避不会延迟恢复检测。0 禁用退避。 |

**环境变量：**
- `MIBEE_HEARTBEAT_DEFAULT_INTERVAL`
- `MIBEE_HEARTBEAT_TIMEOUT`
- `MIBEE_HEARTBEAT_RETENTION_DAYS`
- `MIBEE_HEARTBEAT_OFFLINE_BACKOFF_TICKS`

**示例：**
```yaml
heartbeat:
  default_interval: 30
  timeout: 5
  retention_days: 30
  offline_backoff_ticks: 10

# 环境变量覆盖
export MIBEE_HEARTBEAT_DEFAULT_INTERVAL=60
export MIBEE_HEARTBEAT_TIMEOUT=10
```

## 6. Prometheus 配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `prometheus.enabled` | bool | true | 启用 Prometheus 指标收集 |
| `prometheus.metrics_path` | string | "/metrics" | 指标端点路径 |

**环境变量：**
- `MIBEE_PROMETHEUS_ENABLED`
- `MIBEE_PROMETHEUS_METRICS_PATH`

**示例：**
```yaml
prometheus:
  enabled: true
  metrics_path: "/metrics"

# 环境变量覆盖
export MIBEE_PROMETHEUS_METRICS_PATH="/monitoring/metrics"
```

## 7. 仪表板配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
|| `dashboard.data_source_type` | string | "prometheus" | 数据源："prometheus" |
|| `dashboard.prometheus_url` | string | "http://localhost:9090" | Prometheus 服务器 URL |

**环境变量：**
- `MIBEE_DASHBOARD_DATA_SOURCE_TYPE`
- `MIBEE_DASHBOARD_PROMETHEUS_URL`

**示例：**
```yaml
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"


## 8. 存储配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `storage.upload_path` | string | "./data/uploads" | 文件上传目录 |
| `storage.max_file_size` | int64 | 104857600 | 最大上传大小（字节，默认：100MB） |

**环境变量：**
- `MIBEE_STORAGE_UPLOAD_PATH`
- `MIBEE_STORAGE_MAX_FILE_SIZE`

**示例：**
```yaml
storage:
  upload_path: "./data/uploads"
  max_file_size: 104857600

# 环境变量覆盖
export MIBEE_STORAGE_UPLOAD_PATH="/var/lib/mibee/uploads"
export MIBEE_STORAGE_MAX_FILE_SIZE=209715200  # 200MB
```

## 9. 日志配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `log.level` | string | "info" | 日志级别："debug"、"info"、"warn"、"error" |
| `log.format` | string | "text" | 日志格式："text" 或 "json" |

**环境变量：**
- `MIBEE_LOG_LEVEL`
- `MIBEE_LOG_FORMAT`

**示例：**
```yaml
log:
  level: "info"
  format: "text"

# 生产环境配置
log:
  level: "info"
  format: "json"

# 环境变量覆盖
export MIBEE_LOG_LEVEL=debug
export MIBEE_LOG_FORMAT=json
```

## 10. 扫描器配置（v2 引擎）

网络扫描器采用插件式五层架构（探测 → 分类 → 处理器 → 持久化 → 编排）。详见 [架构 → 网络扫描器](architecture.md#网络扫描器v2)。

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.enabled` | bool | true | 扫描端点 + 后台调度器的总开关 |
| `scanner.default_timeout` | int (秒) | 300 | 定时扫描的每主机流水线超时。同时驱动 `write_timeout` 的自动上调。 |
| `scanner.max_concurrent_hosts` | int | 50 | 每主机并行扫描上限 |
| `scanner.retention_days` | int | 30 | 早于此天数的 `scan_results` 行每日清理 |
| `scanner.default_cron_expr` | string | "0 */6 * * *" | 新建扫描任务的默认 cron |
| `scanner.engine` | string | "v2" | 引擎选择（仅支持 "v2"；v1 已移除） |
| `scanner.persist_raw_evidence` | bool | false | 将每次探测观测写入 `service_evidence`（数据量大——仅调试时开启） |
| `scanner.ebpf.enabled` | bool | false | 启用 eBPF 被动观测器（除非用 `make build-with-ebpf` 构建否则为 no-op） |
| `scanner.ebpf.interfaces` | []string | [] | 挂载 TC 程序的网卡（空 = 所有非环回口） |
| `scanner.pipeline_defaults.*` | various | — | 各阶段开关 + `default_ports`（已扩展含摄像头 + prometheus 端口） |

**同步扫描限制**：`POST /scanner/scan` 对 >1024 IP 的目标返回 HTTP 413。更大范围请用异步任务 API（`POST /scanner/tasks` + `/trigger`）。

**示例：**
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
    enabled: false       # 需 make build-with-ebpf + 内核 ≥5.8 + CAP_BPF
    interfaces: []       # 空 = 所有非环回口
```

## 11. 保留期配置

保留期清理器（`internal/service/scannerv2/cleanup/`）周期性地修剪高流量明细表，防止无限增长。单个 ticker 驱动所有表的修剪；每张表的窗口独立配置。删除按批（`batch_size`，默认 5000）进行，避免在大表上长时间持有 SQLite 写锁。

```yaml
retention:
  heartbeat_results_days: 7       # heartbeat_results（心跳库）
  scan_results_days: 30           # scan_results（v1 每次扫描主机行）
  scan_task_runs_days: 30         # scan_task_runs
  audit_logs_days: 90             # audit_logs
  notification_log_days: 30       # notification_log
  service_evidence_days: 14       # service_evidence（v2 原始探测证据，受采样控制）
  change_log_days: 30             # change_log（设备新增/变更/离线）
  device_neighbors_days: 90       # device_neighbors（L2 拓扑边）
  host_services_days: 30          # host_services（v2 已分类服务身份）
  host_tls_certs_days: 30         # host_tls_certs（v2 TLS 证书链；PEM 单行 KB 级）
  sweep_interval_hours: 6         # 清理器跨所有表运行的频率
  batch_size: 5000                # 单条 DELETE 语句最大删除行数
```

| 键 | 默认值 | 说明 |
|----|--------|------|
| 各表 `*_days` | 见上 | 字段为 0 表示**使用默认值**，**不是**"永久保留"。这些明细表从不意图永久保留。 |
| `sweep_interval_hours` | `6` | 频繁到没有表会显著滞后于其窗口；稀疏到开销可忽略。清理器在启动时立即运行一次，以便长时间停机的服务器能立刻追上进度。 |
| `batch_size` | `5000` | 限制单次 DELETE 的行数，使 WAL 能在大表的批次之间执行 checkpoint。 |

**注意**：旧字段 `heartbeat.retention_days`（位于 `heartbeat.*`）和 `scanner.retention_days`（位于 `scanner.*`）是各自子系统独立的旧字段，**不是**上述统一的 `retention.*` 块。

## 完整配置示例

```yaml
# 服务器配置
server:
  port: 8080
  host: "0.0.0.0"

# 数据库配置
database:
  type: "sqlite"
  sqlite:
    path: "./data/mibee.db"

# 认证
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

# 心跳监控
heartbeat:
  default_interval: 30
  timeout: 5
  retention_days: 30

# Prometheus 指标
prometheus:
  enabled: true
  metrics_path: "/metrics"

# 仪表板
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"

# 存储
storage:
  upload_path: "./data/uploads"
  max_file_size: 104857600

# 日志
log:
  level: "info"
  format: "text"
```

## 生产环境安全检查清单

在生产环境部署时，请确保正确配置以下安全设置：

### 🔑 关键安全设置

1. **JWT 密钥**：生成强随机密钥：
   ```bash
   openssl rand -base64 32
   ```
   将 `auth.jwt_secret` 设置为此值

2. **管理员密码**：立即更改默认管理员密码

3. **HTTPS 配置**：使用 HTTPS 时设置 `auth.cookie_secure: true`

4. **CORS 源**：仅将 `cors.allowed_origins` 限制为受信任的域名

### 🔒 其他安全考虑

- **文件上传**：监控 `storage.upload_path` 中的未授权文件
- **指标端点**：仅对监控系统限制 `/metrics` 访问权限
- **数据库访问**：确保数据库文件具有适当的文件权限
- **日志安全**：在生产环境中使用 JSON 格式进行结构化日志记录
- **网络安全**：使用防火墙规则限制对非 HTTP 端口的访问

### 📝 环境变量模板

为生产部署创建 `/etc/default/mibee-steward`：

```bash
# 服务器设置
MIBEE_SERVER_PORT=8080
MIBEE_SERVER_HOST=0.0.0.0

# 数据库
MIBEE_DATABASE_TYPE=sqlite
MIBEE_DATABASE_SQLITE_PATH=/opt/mibee-steward/data/mibee.db

# 安全（必须更改这些）
MIBEE_AUTH_JWT_SECRET=your-strong-secret-here
MIBEE_AUTH_INITIAL_ADMIN_PASSWORD=your-secure-password
MIBEE_AUTH_COOKIE_SECURE=true

# 日志
MIBEE_LOG_LEVEL=info
MIBEE_LOG_FORMAT=json

# CORS
MIBEE_CORS_ALLOWED_ORIGINS=https://yourdomain.com
```

## 配置验证

应用程序在启动时会验证配置：

- 数据库类型必须是 "sqlite" 或 "postgresql"
- 检查必需字段（jwt_secret、initial_admin_password）
- 端口号必须有效（1-65535）
- 文件路径必须可访问

无效的配置将阻止应用程序启动，并提供详细的错误消息。