# 用户手册

MiBee Steward Web 界面完整导览：每个页面展示什么、能做什么。安装见[快速开始](quick-start.md)/[部署](deployment.md)；截图见 [Web 界面](web-ui.md)；REST API 见 [API](api.md)。

## 首次登录

1. 打开 `http://<中心地址>:8080`。
2. 全新安装且配置未设置 `auth.initial_admin_password` 时，首次访问会进入**首启向导**创建管理员账号。若配置播了初始密码，用其登录后界面会**强制改密**，改完才能进入其他页面（强制改密门对每个会话生效，直到密码被轮换）。
3. 会话基于 Cookie；生产环境应为 `cookie_secure: true` + `cookie_same_site: strict`，请通过反向代理的 HTTPS 访问。

## 仪表盘（`/dashboard`）

落地总览：在线/离线设备数、各网段设备趋势、最近变更事件、agent 健康度、心跳失败摘要。各组件直接链到对应页面，数据同源。

## 网段（`/networks`）

每个受管 LAN 一行：**名称、CIDR、归属 agent**（`agent_id`）。

- **新增网段**：名称 + CIDR（如 `lan-1` / `192.168.1.0/24`）。CIDR 驱动扫描目标圈定与设备→网段归属。
- **agent 绑定即派发开关**：网段带 `agent_id` 时，其扫描任务派发给该 agent（分布式模式）；**为空 = 中心本地扫描**。当某 agent 网段的设备停止更新时先查这里——`agent_id` 被意外清空会把网段静默切回中心本地扫描。
- 删除网段不删设备，设备在下次扫描时重新归属。

## 设备

### 资产清单（`/devices`）

资产注册表。列：状态（在线/离线 + 最近在线时间）、名称、类型、品牌/型号、IP/MAC、网段、扫描属性徽章（本地管理位 MAC、推断来源）。行内操作：

- **重扫** — 对该主机发起一次性扫描。
- **编辑** — 设置名称/位置/描述/用途；用户设置字段是**粘性**的：扫描桥只回填空值或 "unknown"，绝不覆盖你的编辑（只有设备**替换**才强制覆写身份字段）。
- **删除** — 连同心跳配置与拓扑边一并移除。

身份规则一段话：**一个 MAC 一行**（MAC 优先身份）。设备换 IP 保留原行（漫游）；设备同时持有两个活 IP（双网卡绑定、双 DHCP 租约）仍是一行，孪生 IP 记入 `scan_attributes.extras.ip_aliases`；从未见过的 MAC 出现在已占用槽位按替换处理（旧行下线，`mac_aliases` 记录历史）；**随机化（本地管理位）MAC 绝不强制替换真实设备**——真实设备的行被"泊车"（清 IP、保身份），再次出现时经漫游路径回归。

### 设备详情（`/devices/detail/{id}`）

单资产的全部已知信息：身份卡、开放端口 + 识别到的服务、扫描属性（SNMP sysDescr、OS/内核、带置信度的推断来源）、心跳状态历史、L2 拓扑边（`device_neighbors`——来自 LLDP/CDP/Bridge-MIB 探针）、该设备的变更历史。

### 发现与扫描（`/devices/discovery`、`/devices/scan-results`、`/devices/scan-tasks`、`/devices/scanner`）

- **扫描任务**：按网段配置的周期扫描（cron 表达式，如 `*/10 * * * *`）。每次运行都有记录；运行列表展示存活主机数与时长。分布式模式下任务在网段归属的 agent 上执行。
- **扫描结果**：按主机的扫描结果历史。
- **扫描器设置**：并发、超时、端口表、保留段守卫（`scanner.allow_reserved_targets`——保持**关闭**；环回/链路本地目标默认在所有入口被拒）。

## 采集器（`/agents`）

分布式部署的舰队视图：每个 agent 的版本（如 `mibee-agent-rs/0.1.5`）、运行时长、最近上报时间、扫描计数、采纳的指纹库版本。

- **铸发令牌**（Agents 页 → 创建）：绑定 `agent_id + network_id`，明文**仅展示一次**——粘贴进 agent 的 `agent.yaml`（`center.auth_token`）。令牌可吊销，吊销立即生效。
- **远程运维**：中心侧 `agent_fleet.remote_ops_enabled` + agent 侧 `center.remote_ops_enabled: true` 时，中心可下发按需扫描与日志获取。
- "最近上报"变陈旧是 agent 故障的第一信号 → 上 agent 主机查（`systemctl status mibee-agent`、`journalctl -u mibee-agent`）。

## 指纹库（`/fingerprints`）

识别语料管理页（能力位 `fingerprint:manage`，全程审计）：

- **状态**：现行语料版本 + 规则数（引擎视图 vs 受管目录）。
- **上传**：tar.gz/zip 包或单个 `.yaml`（只替换该文件）。每次上传先过规则引擎自带的加载器校验——坏语料会带引擎原始报错被拒，现网语料继续运行。
- **回滚**：一键回到上一版语料（首传前的语料自动留存）。
- **上游检查**：对 `scanner.fingerprint_upstream.url` 的 manifest——展示版本 + 增删规则 diff，一键应用。
- **舰队采纳**：每个 agent 跑哪个版本（开启 `center.fingerprint_sync.enabled` 的 agent 自动收敛）。

## 拓扑（`/topology`）

由 `device_neighbors` 构建的二层邻接视图（agent 上报的 LLDP/CDP/Bridge-MIB/Q-BRIDGE/STP 证据 + 中心本地扫描）。边携带端口名与观测协议。

## 拨测（`/probes`）

心跳（存活）监控：每设备探针配置（HTTP/TCP/ICMP/SNMP）、近期结果、失败状态。探针失败噪声按连败抑制（首败 WARN，重复采样）——ERROR 持续刷屏通常意味着指向已死 IP 的孤儿配置，保留清理会回收它们。

## 变更与审计（`/changes`、`/audit`）

- **变更**：变更检测流（设备新增/变更/恢复/失联，逐字段 diff）。单设备 IP 变更只在其真实漫游时才是预期的；两 IP 间反复翻转是 bug 特征——先查该设备的 `ip_aliases`。
- **审计**：谁在何时对哪些变更类 API 做了操作（能力位动作、指纹变更、用户管理）。

## 设置（`/settings`）

手风琴式分区（原地展开）：

- **指纹库** — 即上述语料管理。
- **安全** — JWT 密钥轮换、Cookie 标志、密码策略。
- **扫描器** — 引擎调参、发现信号源、SNMP 凭据（SNMPv3 口令落库即 AES 加密，任何 API 都**不会**回显）。
- **通知** — 心跳与变更事件的 webhook/通知渠道。
- **用户** — 账号管理（管理员能力位）。

## 用户（`/users`）

账号列表与能力位/RBAC。删除或降级最后一名管理员会被阻止。管理员重置的密码在下次登录时强制修改。

## 文档（`/documents`）

按设备挂附件/文档（说明书、发票）——上传走 API，在设备详情页展示。

## 演示模式

以 `server.demo_mode: true`（或 `-demo`）启动中心：自动播种虚构资产（仅 RFC 5737 文档段）、回放模拟事件、界面提供一键清空。演示数据绝不触碰真实网络。适合截图与评估——[web-ui.md](web-ui.md) 的截图即由此产生。

## 故障速查

| 症状 | 先查 |
|---|---|
| agent 网段的设备冻结 / 陈旧 | `/networks` 里该网段的 `agent_id`；`/agents` 里 agent 服务状态与最近上报时间 |
| 中心日志出现 agent 401 | 令牌被吊销或轮换——重新铸发，更新 `center.auth_token` |
| 同一台盒子两行（有线 + 无线） | 那是 `mac_aliases` 在生效；UI 侧别名聚合在路线图中，合并意图已记录 |
| 设备"变成"一个随机样子的 MAC | 本地管理位（随机化）MAC；真实持有者被泊车后会回归——见 [agent-rs.md](agent-rs.md) / CHANGELOG |
| 播种密码登录失败 | 安装后密码已被轮换；用管理员重置 CLI（`mibee-steward reset-admin-password`）或重建库后的首启向导 |
| 扫描拒绝我的目标网段 | 保留段守卫——见 [configuration.md](configuration.md)；生产环境不要关闭 |
| 忘记管理员密码被锁 | `mibee-steward reset-admin-password`（密码经 stdin/参数/环境变量） |
