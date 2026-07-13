# 分布式部署指南

本指南介绍如何将 MiBee Steward 部署为分布式（多局域网）配置：一个**中心**
汇聚来自多个**采集器**的设备数据，每个采集器部署在不同的网络段。

## 何时使用分布式模式

- 你的设备分布在**多个 LAN/VLAN** 上，中心无法直接扫描（无 L3 路由、NAT、防火墙）。
- 你需要一个跨所有网络的**统一设备注册表**，可从一个界面查询。
- 你需要**按网络的变化检测**（每个 LAN 的设备新增/变更/离线）。

如果只有一个网络，中心内置的扫描器就足够了，无需采集器。

## 架构概览

```
[网络 A]                       [网络 B]
  中心 (cmd/server)              采集器 (cmd/agent)
  - Web 界面 + API              - 扫描本地局域网
  - 设备注册表                   - 上报到中心
  - 变化检测                     - 轮询命令
  - 本地扫描器                   - 按 cron + 临时触发运行
```

采集器使用**拉取模型**：它发起所有到中心的连接（上报结果、轮询命令）。
中心不需要到采集器的入站连接，因此采集器可以在 NAT 后运行。

## 前提条件

- **中心**：一台运行 `cmd/server` 的机器，所有采集器可通过 HTTP 访问。
- **采集器**：每个远程 LAN 一台机器，有目标子网的网络访问权限。
  不需要 sudo — 采集器以普通用户运行。
- 两个二进制都是 CGO-free（纯 Go + modernc.org/sqlite），目标机器无需 C 工具链。

## 步骤 1：在中心设置网络

每个采集器绑定到一个**网络**（`networks` 表中的一行）。中心在启动时从
`config.yaml` 解析自己的网络：

```yaml
network:
  name: "lan-63"          # 中心自己的网络
  cidr: "192.168.63.0/24"
  site: "总部"
```

对于每个**远程**网络（采集器将覆盖的），需要在中心创建 `networks` 行。
在 **网络**（Networks，左侧导航，仅管理员可见）页面创建，或通过 API：

```bash
curl -X POST http://localhost:8080/api/v1/networks \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"lan-62","cidr":"192.168.62.0/24","site":"分支机构"}'
```

也可直接写入 SQLite（高级用法）：

```bash
sqlite3 /opt/mibee-steward/data/mibee.db \
  "INSERT INTO networks (name, cidr, site) VALUES ('lan-62', '192.168.62.0/24', '分支机构');"
```

## 步骤 2：创建采集器令牌

在中心的 Web 界面中：

1. 以管理员登录。
2. 进入左侧导航的 **采集器**（Agents，仅管理员可见）。
3. 点击 **"+ 创建令牌"**。
4. 填写：
   - **采集器 ID**：唯一标识，如 `agent-lan-62`。
   - **网络**：选择该采集器负责的网络（如 `lan-62`）。
   - **名称**：可选的人类可读标签，如"分支机构 LAN-62"。
5. 点击 **创建**。
6. ⚠️ **立即复制明文令牌** — 仅显示一次，之后无法再次获取。

也可通过 API 创建：

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"你的密码"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://localhost:8080/api/v1/agents/tokens/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-lan-62","network_id":2,"name":"分支机构"}'
# 响应包含 "token" — 复制它！
```

## 步骤 3：编译采集器二进制

在你的构建机器上：

```bash
make build-agent
# 输出: bin/mibee-agent (CGO-free, ~12MB)
```

或交叉编译：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/mibee-agent ./cmd/agent/
```

## 步骤 4：部署采集器

在远程机器上（如 `192.168.62.174`）：

```bash
# 上传二进制
scp bin/mibee-agent user@192.168.62.174:~/mibee-agent/
ssh user@192.168.62.174 'chmod +x ~/mibee-agent/mibee-agent'
```

创建采集器配置（`~/mibee-agent/configs/agent.yaml`）：

```yaml
center:
  url: "http://192.168.63.101:8080"     # 中心的地址
  auth_token: "粘贴令牌"                   # 步骤 2 获取的令牌
  report_interval: "30s"                 # 上报刷新间隔

network:
  name: "lan-62"                         # 必须与中心上的网络名称匹配
  cidr: "192.168.62.0/24"

scanner:
  default_timeout: 300
  max_concurrent_hosts: 50
  per_probe_timeout: 3

log:
  level: "info"
  format: "text"
```

启动采集器：

```bash
cd ~/mibee-agent
setsid ./mibee-agent -config configs/agent.yaml > agent.log 2>&1 &

# 验证
tail -f agent.log
# 期望看到: "mibee-agent running" + "scannerv2 engine ready"
```

## 步骤 5：设置定时扫描任务（可选）

采集器的调度器从本地 `scan_tasks` 表读取任务。设置定期扫描：

```bash
# 采集器首次运行时会在配置旁边创建 agent.db。
# 启动一次后停止，然后插入任务：
sqlite3 ~/mibee-agent/configs/agent.db \
  "INSERT INTO scan_tasks (name, targets, cron_expr, timeout, concurrent_hosts, enabled)
   VALUES ('lan-62-full', '192.168.62.0/24', '0 */6 * * *', 300, 50, 1);"
```

重启采集器。它将每 6 小时扫描一次并上报结果。

## 步骤 6：从中心触发临时扫描

在中心的 Web 界面 → **采集器** 页面 → 点击该采集器行的 **"触发扫描"**。
输入扫描目标（如 `192.168.62.0/24`）和超时时间。采集器在 60 秒内获取命令、
执行并上报结果。

通过 API：

```bash
curl -X POST http://localhost:8080/api/v1/agents/agent-lan-62/commands/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"command":"scan","payload":{"targets":"192.168.62.0/24","timeout":120}}'
```

## 步骤 7：查看结果

- **设备页面**：使用 **网络** 下拉框按网络筛选，查看每个 LAN 的设备。
- **变更页面**：查看 device_added / device_changed / device_lost 事件，
  可按网络和事件类型筛选。
- **采集器页面**：监控采集器状态（在线/空闲/已吊销）和最后使用时间。

## 管理采集器

### 吊销令牌

在采集器页面，点击令牌的 **"吊销"**。采集器立即失去访问权限。
这是软删除 — 令牌记录保留以供审计。

### 采集器状态

中心从 `last_used_at`（每次采集器请求时更新）推断采集器存活状态：

- 🟢 **在线**：5 分钟内有请求。
- ⚪ **空闲**：令牌存在但近期无活动。
- 🔴 **已吊销**：令牌已被吊销。

### 断线恢复

如果中心不可达，采集器将失败的 report 批次保存在内存队列中（最多 100 批）。
中心恢复后按序补报。短暂中断期间不会丢失数据。

## API 参考

| 方法 | 端点 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/v1/agents/tokens/` | 管理员 | 创建采集器令牌 |
| GET | `/api/v1/agents/tokens/` | 管理员 | 列出所有令牌 |
| POST | `/api/v1/agents/tokens/{id}/revoke` | 管理员 | 吊销令牌 |
| DELETE | `/api/v1/agents/tokens/{id}` | 管理员 | 删除令牌 |
| POST | `/api/v1/agents/{agentId}/commands/` | 管理员 | 下发命令 |
| GET | `/api/v1/agents/commands/all` | 管理员 | 查看所有命令 |
| POST | `/api/v1/agents/report` | 采集器 | 上报扫描结果 |
| GET | `/api/v1/agents/commands` | 采集器 | 轮询待处理命令 |
| GET | `/api/v1/networks` | 登录用户 | 列出所有网络 |
| GET | `/api/v1/changes` | 登录用户 | 查询变更历史 |
| GET | `/api/v1/changes/watch` | 登录用户 | SSE 实时变更推送 |
