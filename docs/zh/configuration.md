# 配置参考

MiBee Steward 使用 YAML 配置文件，支持环境变量覆盖。本文档涵盖所有可用的配置选项。

## 配置结构

配置分为 15 个主要部分：

- **服务器**（`server`）：HTTP 服务器设置与可信代理
- **数据库**（`database`）：数据库配置（SQLite）
- **认证**（`auth`）：JWT 和 cookie 设置
- **CORS**（`cors`）：跨域资源共享
- **心跳**（`heartbeat`）：设备监控设置
- **扫描器**（`scanner`）：网络扫描器引擎（v2）
- **保留期**（`retention`）：数据生命周期与清理
- **速率限制**（`rate_limit`）：全局请求节流
- **Prometheus**（`prometheus`）：指标收集
- **仪表板**（`dashboard`）：仪表板数据源配置
- **存储**（`storage`）：文件上传设置
- **日志**（`log`）：日志输出配置
- **网络**（`network`）：本实例的网络身份与 CIDR
- **中心**（`center`）：分布式代理模式（上报目标中心）
- **安全**（`security`）：主密钥与凭证加密

## 配置加载优先级

配置值按以下顺序加载（后面的值会覆盖前面的值）：

1. **YAML 配置文件**：基础配置从 `-config` 标志指向的文件加载（未指定时默认 `configs/config.example.yaml`；生产部署通常将其复制为 `config.yaml` 后传入）
2. **环境变量**：`MIBEE_*` 前缀的变量覆盖 YAML 值

任何设置为 `0`（或对应类型的零值）的键表示**使用默认值**，而**不是**"无限制"或"永久保留"。

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
| `server.trusted_proxies` | []string | [] | 可信代理 CIDR 列表。仅当 TCP 对端在此列表中时，`X-Forwarded-For` 头才会被信任——否则使用 TCP 对端地址作为客户端 IP。空列表 = 信任无代理（直接暴露时安全）。部署在 nginx 后方时，设为代理的源地址范围。 |

**环境变量：**
- `MIBEE_SERVER_PORT`
- `MIBEE_SERVER_HOST`
- `MIBEE_SERVER_READ_TIMEOUT`、`MIBEE_SERVER_WRITE_TIMEOUT`、`MIBEE_SERVER_IDLE_TIMEOUT`
- `MIBEE_SERVER_TRUSTED_PROXIES`（逗号分隔的可信代理列表）

**示例：**
```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "15s"
  write_timeout: "5m"     # 若对同步扫描过低会自动上调
  idle_timeout: "120s"
  trusted_proxies:
    - "172.16.0.0/12"

# 环境变量覆盖
export MIBEE_SERVER_PORT=3000
export MIBEE_SERVER_HOST="192.168.1.100"
```

## 2. 数据库配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `database.sqlite.path` | string | "./data/mibee.db" | SQLite 数据库文件路径 |

**环境变量：**
- `MIBEE_DATABASE_SQLITE_PATH`

**示例：**
```yaml
database:
  sqlite:
    path: "./data/mibee.db"
```

## 3. 认证配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `auth.jwt_secret` | string | 无（必填） | JWT 签名密钥。**必填**：空值、长度不足 32 字符或等于占位符 `"change-me-in-production"`（仅 25 字符，两条校验都无法通过）都会导致启动失败。 |
| `auth.token_expiry` | string | "24h" | JWT 令牌有效期 |
| `auth.initial_admin_password` | string | *(必填)* | 初始管理员密码。**必填** — 为空时服务器在启动时直接退出（需通过配置或 `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD` 设置）。 |
| `auth.cookie_domain` | string | "" | Cookie 域名（空表示当前域名） |
| `auth.cookie_secure` | bool | false | HTTPS 专用 cookie 时设置为 true |
| `auth.cookie_same_site` | string | "strict" | Cookie 同站策略："strict" 或 "lax" |
| `auth.cookie_max_age` | duration | *(回退 `auth.token_expiry`，再 86400)* | 认证 cookie 有效期。未设置时沿用 `auth.token_expiry`，仍未设置则为 86400 秒（24h）。 |

**环境变量：**
- `MIBEE_AUTH_JWT_SECRET`
- `MIBEE_AUTH_TOKEN_EXPIRY`
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`
- `MIBEE_AUTH_COOKIE_DOMAIN`
- `MIBEE_AUTH_COOKIE_SECURE`
- `MIBEE_AUTH_COOKIE_SAME_SITE`
- `MIBEE_AUTH_COOKIE_MAX_AGE`

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

### RBAC 配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `rbac.scope_default` | string | "open" | 网络范围模式。`open` = 所有用户可访问所有网络；`closed` = 用户只能访问被明确授权的网络（通过 [API 参考](api.md) 中的网络授权端点管理）。管理员在两种模式下均可访问全部网络。 |

## 4. CORS 配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `cors.allowed_origins` | []string | 无默认 | 允许跨域请求的源列表。未设置/为空 = 不放行任何跨域请求（仅同源可访问）。启动时对包含 localhost/127.0.0.1 的源打印警告。 |

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
| `heartbeat.tick_interval_seconds` | int | 30 | 心跳调度器 tick 之间的间隔（秒）。控制探测循环的触发频率。与 `default_interval` 解耦，可独立调节调度器速率。 |
| `heartbeat.timeout` | int | 5 | 设备探测超时（秒） |
| `heartbeat.retention_days` | int | *(无内建默认)* | 旧版直通键：仅当 `retention.heartbeat_results_days` 未设置时生效（有效默认 7 天；`configs/config.example.yaml` 出厂为 30）。 |
| `heartbeat.offline_threshold` | int | 5 | 连续探测失败多少次后将设备状态置为 `offline`（默认 30s 间隔下 5 次 ≈ 2.5 分钟）。 |
| `heartbeat.offline_backoff_ticks` | int | 10 | 离线设备每 N 个 tick 探测一次而非每 tick（30s ticker 下 N=10 约 5 分钟一次）。避免对不会响应的设备持续写入超时记录。扫描恢复设备时会立即清除失败计数，因此退避不会延迟恢复检测。0 禁用退避。 |

**环境变量：**
- `MIBEE_HEARTBEAT_DEFAULT_INTERVAL`
- `MIBEE_HEARTBEAT_TICK_INTERVAL_SECONDS`
- `MIBEE_HEARTBEAT_TIMEOUT`
- `MIBEE_HEARTBEAT_RETENTION_DAYS`
- `MIBEE_HEARTBEAT_OFFLINE_THRESHOLD`
- `MIBEE_HEARTBEAT_OFFLINE_BACKOFF_TICKS`

**示例：**
```yaml
heartbeat:
  default_interval: 30
  tick_interval_seconds: 30
  timeout: 5
  retention_days: 30
  offline_threshold: 5
  offline_backoff_ticks: 10

# 环境变量覆盖
export MIBEE_HEARTBEAT_DEFAULT_INTERVAL=60
export MIBEE_HEARTBEAT_TIMEOUT=10
```

## 6. Prometheus 配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `prometheus.enabled` | bool | — | **当前未使用**：`/metrics` 端点始终挂载，与此开关无关。 |
| `prometheus.metrics_path` | string | — | **当前未使用**：指标路径硬编码为 `/metrics`，此键无效。 |

**环境变量：**
- `MIBEE_PROMETHEUS_ENABLED`（无效——见上表）
- `MIBEE_PROMETHEUS_METRICS_PATH`（无效——见上表）

**示例：**
```yaml
prometheus:
  enabled: true
  metrics_path: "/metrics"

# 环境变量覆盖
# （MIBEE_PROMETHEUS_METRICS_PATH 无效：指标路径硬编码为 /metrics）
```

## 7. 仪表板配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `dashboard.data_source_type` | string | "prometheus" | 数据源："prometheus" |
| `dashboard.prometheus_url` | string | "http://localhost:9090" | Prometheus 服务器 URL |

**环境变量：**
- `MIBEE_DASHBOARD_DATA_SOURCE_TYPE`
- `MIBEE_DASHBOARD_PROMETHEUS_URL`

**示例：**
```yaml
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"
```

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

网络扫描器采用插件式五层架构（探测 → 分类 → 处理器 → 持久化 → 编排）。详见 [架构](architecture.md)。

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.enabled` | bool | — | **当前未使用**（结构体中存在但无处消费）：扫描路由与后台调度器无条件启动。 |
| `scanner.max_concurrent_scans` | int | 3 | 同时运行的顶层扫描数上限（引擎的并发扫描信号量，实际生效）。 |
| `scanner.default_timeout` | int (秒) | 300 | 定时扫描的每主机流水线超时。同时驱动 `write_timeout` 的自动上调。 |
| `scanner.max_concurrent_hosts` | int | 50 | 每主机并行扫描上限 |
| `scanner.retention_days` | int | — | 旧版回退：仅当 `retention.scan_results_days` 未设置时生效（再回退 30）。清理由 `retention.sweep_interval_hours`（默认 6h）驱动，并非每日一次。 |
| `scanner.default_cron_expr` | string | "0 */6 * * *" | 新建扫描任务的默认 cron |
| `scanner.engine` | string | "v2" | 引擎选择（仅支持 "v2"；v1 已移除） |
| `scanner.persist_raw_evidence` | bool | false | 将每次探测观测写入 `service_evidence`（数据量大——仅调试时开启） |
| `scanner.lost_threshold` | int | 2 | 连续多少次扫描未在存活集中出现后设备被判定为 lost。心跳侧的对应阈值是 `heartbeat.offline_threshold`（探测失败计数）。 |
| `scanner.per_probe_timeout` | int (秒) | 3 | 单次探测尝试（一次 SNMP Get / TCP 拨号 / HTTP 抓取）的超时（秒）。与 `default_timeout`（整条主机流水线）不同。 |
| `scanner.snmp_community` | string | "public" | 全局 SNMP community 字符串（v1/v2c 扫描使用）。 |
| `scanner.oui_path` | string | "" | IEEE OUI 厂商映射文件路径（MA-L+MA-M+MA-S，由 `scripts/fetch-oui.sh` 生成）。空 = 用内嵌精简 CC-BY-SA 表（开箱即用，覆盖常见厂商）。环境变量覆盖：`MIBEE_SCANNER_OUI_PATH`。 |
| `scanner.fingerprint_path` | string | "" | 指纹 YAML 规则目录（见 `docs/fingerprint-spec.md`）。空 = 用二进制内嵌规则。 |
| `scanner.ebpf.enabled` | bool | false | 启用 eBPF 被动观测器（除非用 `make build-with-ebpf` 构建否则为 no-op） |
| `scanner.ebpf.interfaces` | []string | [] | 挂载 TC 程序的网卡（空 = 所有非环回口） |
| `scanner.pipeline_defaults.*` | various | — | 各阶段开关 + `default_ports`（已扩展含摄像头 + prometheus 端口） |
| `scanner.agent_lease_ttl` | duration | "5m" | 代理管理设备的租约过期时间。代理停止上报后，设备在此时间内被标记为 lost。 |
| `scanner.lease_sweep_interval` | duration | "60s" | 租约清扫器运行间隔。 |
| `scanner.reconcile_interval` | duration | "1h" | 网络归属对账间隔。检测设备 IP 是否漂移到其网络 CIDR 之外。 |

### 配置备份（config_backup）

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.config_backup.enabled` | bool | false | 启用 SSH 配置备份（需 `security.master_key` + 绑定 SSH 凭证） |
| `scanner.config_backup.interval_seconds` | int (秒) | 21600 | 配置备份轮询间隔（秒）。<=0 → 6 小时（21600 秒）。 |
| `scanner.config_backup.timeout_seconds` | int (秒) | 30 | 每台设备的 SSH 超时（秒）。<=0 → 30 秒。 |

### 路由器 ARP 扫描

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.router_arp.routers` | []string | [] | 用于跨子网 ARP 走查的路由器 IP 列表。 |
| `scanner.router_arp.community` | string | *(回退)* | 路由器 SNMP community。为空时回退到 `scanner.snmp_community`（再回退 "public"）。 |
| `scanner.router_arp.timeout` | int (秒) | 4 | 每台路由器的 ARP 走查超时。 |

### 反向 DNS

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.rdns.dns_servers` | []string | [] | 反向 DNS 查询使用的 DNS 服务器。 |
| `scanner.rdns.timeout` | int (秒) | 2 | 反向 DNS 查询超时。 |

### mDNS

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.mdns.unicast_queries` | bool | false | 启用 mDNS 单播查询（用于不响应多播的设备）。 |

### ARP 扫描

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.arp_scan.interface` | string | "" | ARP 扫描使用的网卡接口名。 |

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
    enabled: false       # 需 make build-with-ebpf + 内核 ≥5.8 + CAP_BPF
    interfaces: []       # 空 = 所有非环回口
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

## 路由器驻留发现源

扫描器除了主动探测外，还可以从路由器驻留源获取设备数据。整个服务由总开关 `scanner.discovery.enabled` 控制（默认关闭）。注意：`trigger_identify` 与 `router_arp`/`arp_cache`/`multicast` 子源在 `configs/config.example.yaml` 中出厂为 true（推荐值）——开箱关闭靠的是总开关，而非各子源自身默认关闭。当宿主机上不存在对应的文件或 socket 时，每个源都是空操作（no-op）。

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `scanner.discovery.enabled` | bool | false | 启用被动发现服务 |
| `scanner.discovery.interval` | int (秒) | 60 | 发现扫描间隔（秒） |
| `scanner.discovery.trigger_identify` | bool | false* | 发现新主机时是否自动触发识别扫描。未设置时零值为 false，但 `configs/config.example.yaml` 出厂/推荐为 true。 |
| `scanner.discovery.router_arp.enabled` | bool | false* | 启用路由器 SNMP ARP 走查源（跨子网覆盖） |
| `scanner.discovery.arp_cache.enabled` | bool | false* | 启用本地 ARP 缓存源（读取 `/proc/net/arp`） |
| `scanner.discovery.multicast.enabled` | bool | false* | 启用 mDNS/SSDP 被动监听源 |
| `scanner.discovery.dhcp_leases.enabled` | bool | false | 读取本机 dnsmasq 的 DHCP 租约文件（`/tmp/dhcp.leases`（OpenWrt）或 `/var/lib/misc/dnsmasq.leases`（Debian）），发现最近获取 IP 的设备。仅支持 dnsmasq，不支持 dhcpd.leases。 |
| `scanner.discovery.conntrack.enabled` | bool | false | 解析内核 conntrack 表（仅 `/proc/net/nf_conntrack`，不调用 `conntrack -L` CLI），发现活跃的 NAT 连接及其内部主机。 |
| `scanner.discovery.hostapd.enabled` | bool | false | 读取 hostapd 控制接口，发现关联到路由器访问点的 Wi-Fi 客户端。 |
| `scanner.discovery.hostapd.interfaces` | []string | [] | hostapd 监听的网卡接口名列表。 |
| `scanner.discovery.dns_log.enabled` | bool | false | 解析 dnsmasq 查询日志（`--log-queries` 输出；仅 dnsmasq，不支持 pihole），按 DNS 活动发现主机。 |
| `scanner.discovery.dns_log.path` | string | "" | DNS 查询日志文件路径。 |
| `scanner.discovery.arp_scan.enabled` | bool | false | 启用主动 ARP who-has 扫描（需 `WITH_ARPSCAN` 构建标签 + `CAP_NET_RAW`）。 |
| `scanner.discovery.lldp_interfaces` | []string | [] | LLDP/CDP 被动帧监听的网卡接口名列表（需 `WITH_LLDP`/`WITH_CDP` 构建标签）。 |

> \* 各子源的 Go 零值为 false，但 `router_arp`/`arp_cache`/`multicast` 在 `configs/config.example.yaml` 中出厂为 true（推荐值）——开箱关闭由总开关 `scanner.discovery.enabled: false` 实现。

**环境变量：**
- `MIBEE_SCANNER_DISCOVERY_DHCP_LEASES_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_CONNTRACK_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_HOSTAPD_ENABLED`
- `MIBEE_SCANNER_DISCOVERY_DNS_LOG_ENABLED`

**示例：**
```yaml
scanner:
  discovery:
    enabled: true
    interval: 60
    trigger_identify: true    # 推荐值：新主机立即获得类型与服务识别
    router_arp:
      enabled: true      # 示例配置推荐值
    arp_cache:
      enabled: true      # 示例配置推荐值
    multicast:
      enabled: true      # 示例配置推荐值
    dhcp_leases:
      enabled: true     # 读取 dnsmasq 租约（/tmp/dhcp.leases 或 /var/lib/misc/dnsmasq.leases）
    conntrack:
      enabled: false    # 解析 /proc/net/nf_conntrack
    hostapd:
      enabled: false    # 读取 hostapd 控制 socket
      interfaces: []
    dns_log:
      enabled: false    # 解析 dnsmasq 查询日志
      path: ""
    arp_scan:
      enabled: false
    lldp_interfaces: []
```

> **注意**：当宿主机上不存在对应的文件或 socket 时，该源静默变为空操作——不记录错误日志，也不产生发现数据。

## 网络配置

标识本实例的网络身份。多实例部署时，每个实例配置不同的 `network.name`，设备会被标记对应的 `network_id` 以避免 IP 冲突。

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `network.name` | string | "default" | 本实例的网络名称。空值自动解析为 "default"。 |
| `network.cidr` | string | "" | 本网络的 CIDR 表示（如 "192.168.1.0/24"）。用于 conntrack 源过滤和网络归属对账。 |
| `network.site` | string | "" | 网络的站点/位置描述（自由文本）。 |

## Center（中心上报）配置

分布式模式的开关：设置 `center.url` 后，本实例作为**代理（agent）**运行并向中心上报扫描结果；留空则为中心/独立模式。

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `center.url` | string | "" | 中心实例的基础 URL（如 "http://192.168.63.101:8080"）。空 = 中心/独立模式（不上报）。 |
| `center.auth_token` | string | "" | 代理的 bearer 令牌（在中心端通过 `POST /api/v1/agents/tokens` 铸造）。代理模式下必填。 |
| `center.report_interval` | duration | "30s" | 缓冲未满时向上游刷新扫描结果的间隔。出错按指数退避重试。 |

**环境变量：**
- `MIBEE_CENTER_URL`
- `MIBEE_CENTER_AUTH_TOKEN`
- `MIBEE_CENTER_REPORT_INTERVAL`

## 安全配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `security.master_key` | string | "" | AES-GCM 主密钥（必须恰好 32 字节）。用于 SNMPv3 和 SSH 凭证的加密存储。空 = 凭证加密禁用（回退到 v1/v2c community 字符串）。 |

**示例：**
```yaml
security:
  master_key: "<恰好 32 字节的密钥>"   # 取值后必须恰好 32 字节（AES-256-GCM 密钥）
```

生成主密钥（取 32 个原始字节再编码）：
```bash
head -c 32 /dev/urandom | base64
```

> 注意：`openssl rand -hex 32` 生成的是 64 个十六进制字符（64 字节），**无法**通过恰好 32 字节的校验——不要用它生成主密钥。

## 心跳阈值

心跳子系统使用多个可配置阈值来控制设备何时标记为离线以及何时降低探测频率：

| 阈值 | 键 | 默认值 | 效果 |
|-----------|-----|---------|--------|
| **离线翻转** | `heartbeat.offline_threshold` | 5 | 连续探测失败多少次后设备状态变为 `offline`。 |
| **退避** | `heartbeat.offline_backoff_ticks` | 10 | 设备已离线后，每 N 个 tick 探测一次而非每个 tick。默认 30s ticker 下 N=10 ≈ 每 5 分钟一次。 |
| **Tick** | `heartbeat.tick_interval_seconds` | 30 | 调度器 tick 之间的间隔（心跳循环的心跳）。 |

**恢复机制**：成功的扫描始终会立即清除失败计数——退避永远不会延迟上线主机的恢复检测。

## 同步扫描限制

同步扫描端点（`POST /api/v1/scanner/scan`）有硬性目标限制：

- **最大目标数**：1024 个 IP（展开后的总数，包括单 IP、CIDR 或范围）
- **超出限制**：返回 HTTP 413，错误信息为 `target range too large for synchronous scan (N IPs; max 1024). Use POST /api/v1/scanner/tasks to run asynchronously.`
- **替代方案**：使用异步任务 API——`POST /api/v1/scanner/tasks` 创建任务，然后 `POST /api/v1/scanner/tasks/{id}/trigger` 触发。异步路径无目标数量限制。

## 速率限制配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `rate_limit.global_per_minute` | int | 100（代码默认；示例配置出厂 600） | 每个客户端 IP 每分钟全局最大请求数。适用于所有端点。 |
| `rate_limit.login_per_minute` | int | 10 | 登录/认证端点（`/auth/login`、`/auth/register`）的更严格每分钟限制。 |
| `rate_limit.scan_per_minute` | int | 10 | 扫描触发端点（`/scanner/scan`、`/scanner/tasks/{id}/trigger`）的每分钟限制。 |

**环境变量：**
- `MIBEE_RATE_LIMIT_GLOBAL_PER_MINUTE`
- `MIBEE_RATE_LIMIT_LOGIN_PER_MINUTE`
- `MIBEE_RATE_LIMIT_SCAN_PER_MINUTE`

## 保留期配置

| 键 | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `retention.heartbeat_results_days` | int | 7 | 心跳结果保留天数 |
| `retention.device_liveness_days` | int | 7（随心跳窗口） | 设备活跃度序列保留天数。未设置时取 `heartbeat_results_days` 的值。 |
| `retention.silent_device_days_mac` | int | 7 | 静默扫描发现设备（有 MAC）的物理删除阈值：超过此天数无观测即删除 |
| `retention.silent_device_hours_no_mac` | int | 24 | 静默设备（无 MAC）的物理删除阈值：超过此小时数无观测即删除 |
| `retention.scan_results_days` | int | 30 | 扫描结果保留天数 |
| `retention.scan_task_runs_days` | int | 30 | 扫描任务运行记录保留天数 |
| `retention.audit_logs_days` | int | 90 | 审计日志保留天数 |
| `retention.notification_log_days` | int | 30 | 通知日志保留天数 |
| `retention.service_evidence_days` | int | 14 | 服务证据保留天数 |
| `retention.change_log_days` | int | 30 | 变更日志保留天数 |
| `retention.device_neighbors_days` | int | 90 | 设备邻居记录保留天数 |
| `retention.host_services_days` | int | 30 | 主机服务记录保留天数 |
| `retention.host_tls_certs_days` | int | 30 | TLS 证书记录保留天数 |
| `retention.probe_results_days` | int | 30 | 拨测历史结果保留天数（`probe_tls_certs` 不清扫——每目标只存当前证书链） |
| `retention.sweep_interval_hours` | int | 6 | 清理扫描间隔（小时） |
| `retention.batch_size` | int | 5000 | 每批清理的最大行数 |

## Docker 配置模板

仓库提供了现成的 Docker Compose 配置模板 [`configs/config.docker.yaml`](../../configs/config.docker.yaml)，预配置了适合容器化部署的路径和网络设置——将其复制为你的起始 `config.yaml`，并为生产环境调整 `auth.jwt_secret` 和 `auth.initial_admin_password`。

## 完整配置示例

```yaml
# 服务器配置
server:
  port: 8080
  host: "0.0.0.0"
  trusted_proxies: []

# 数据库配置
database:
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

# RBAC
rbac:
  scope_default: "open"

# CORS
cors:
  allowed_origins:
    - "http://localhost:5173"
    - "http://localhost:8080"

# 心跳监控
heartbeat:
  default_interval: 30
  tick_interval_seconds: 30
  timeout: 5
  retention_days: 30
  offline_threshold: 5
  offline_backoff_ticks: 10

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

# 扫描器（v2）
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
    trigger_identify: true    # 推荐值：新主机立即获得类型与服务识别
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

# 网络
network:
  name: "default"
  cidr: ""
  site: ""

# 安全
security:
  master_key: ""

# 保留期
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

# 速率限制
rate_limit:
  global_per_minute: 600
  login_per_minute: 10
  scan_per_minute: 10
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

5. **主密钥**：如需使用 SNMPv3/SSH 凭证加密，生成并配置 `security.master_key`

### 🔒 其他安全考虑

- **文件上传**：监控 `storage.upload_path` 中的未授权文件
- **指标端点**：仅对监控系统限制 `/metrics` 访问权限
- **数据库访问**：确保数据库文件具有适当的文件权限
- **日志安全**：在生产环境中使用 JSON 格式进行结构化日志记录
- **网络安全**：使用防火墙规则限制对非 HTTP 端口的访问
- **可信代理**：部署在反向代理后方时，配置 `server.trusted_proxies`

### 📝 环境变量模板

为生产部署创建 `/etc/default/mibee-steward`：

```bash
# 服务器设置
MIBEE_SERVER_PORT=8080
MIBEE_SERVER_HOST=0.0.0.0
MIBEE_SERVER_TRUSTED_PROXIES=172.16.0.0/12,192.168.0.0/16   # 逗号分隔的可信代理列表

# 数据库
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

### 🔒 设备系统配置

设备系统管理默认启用，关键设置如下：

- **分类**：web_app、database、middleware、custom
- **自动发现**：`metrics_enabled=true` 的系统出现在 `/sd` 端点
- **标签**：自动标签包括 device_name、system_name、category、device_type、location

## 配置验证

应用程序在启动时会验证配置（`internal/config/config.go`）：

**代理模式**（`center.url` 非空）：
- `center.auth_token` 必填（在中心端通过 `POST /api/v1/agents/tokens` 铸造）
- `network.name` 必填（必须与令牌绑定的网络一致）

**中心/独立模式**：
- `auth.jwt_secret` 必填，且长度至少 32 字符
- `auth.jwt_secret` 不得等于占位符 `"change-me-in-production"`
- `auth.initial_admin_password` 为空时服务器在启动时退出（见 `cmd/server/main.go`）

以下情况仅输出**警告**、不阻止启动：
- `auth.cookie_secure=false`（cookie 会经 HTTP 传输）
- `cors.allowed_origins` 含 localhost/127.0.0.1 源
- `security.master_key` 已设置但长度不是恰好 32 字节

校验失败的配置将阻止应用程序启动，并提供详细的错误消息。
