# 生态集成

MiBee Steward 专注于设备发现与资产管理，同时为周边可观测生态提供官方桥梁：面向其导出指标的 Grafana 面板、面向团队常用聊天平台的通知渠道，以及面向自动化工具的 webhook 示例。

## Grafana

MiBee 在 `/metrics` 暴露 Prometheus 指标（Prometheus 抓取配置与内置告警规则见[部署指南](deployment.md)）。仓库在 [`deploy/grafana/`](https://github.com/Mi-Bee-Studio/MiBeeSteward/tree/main/deploy/grafana) 下附带五张开箱即用的面板：

| 面板 | 内容 |
|---|---|
| `mibee-overview` | 总览：设备状态分布、扫描运行、心跳结果、API 请求率、数据库大小 |
| `mibee-devices` | 设备面：在线/离线数量、在线率、类型分布、各 agent 上报时延 |
| `mibee-heartbeat` | 心跳健康：结果速率、失败占比、按探测方式的 p50/p95 时延 |
| `mibee-probes` | 拨测：按目标的 up/down 状态、成功率、探测耗时、证书剩余天数 |
| `mibee-scanner` | 扫描活动：运行速率、耗时分位数、发现主机数、扫描表增长 |

### 通过 provisioning 导入（推荐）

将整个 `deploy/grafana/` 目录挂载进 Grafana：

```yaml
# docker-compose.yml 片段
volumes:
  - ./deploy/grafana/provisioning/datasources:/etc/grafana/provisioning/datasources:ro
  - ./deploy/grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro
  - ./deploy/grafana/dashboards:/var/lib/grafana/dashboards:ro
```

内置的 datasource provisioning 假定 Prometheus 位于 `http://prometheus:9090`，若不同请编辑 `deploy/grafana/provisioning/datasources/prometheus.yml`。启动后面板出现在 `MiBee` 目录。

### 手动导入

Grafana → Dashboards → Import → 粘贴 JSON 文件内容 → 选择 Prometheus 数据源。

## 通知渠道

通知规则（事件 → 渠道，见 [Web UI](web-ui.md) → 设置 → 通知）支持六种渠道类型：

| 类型 | 配置字段 | 鉴权 |
|---|---|---|
| `webhook` | `url`、可选 `headers` | 自定义请求头（如接收方 token） |
| `email` | SMTP `host`/`port`/`username`/`password`、`from`、`to` | SMTP 认证 |
| `feishu` | `url`、可选 `secret` | 飞书自定义机器人 HMAC 签名（在机器人上开启"签名校验"并粘贴密钥） |
| `wecom` | `url` | 无（webhook URL 即凭证，请按密钥对待） |
| `telegram` | `bot_token`、`chat_id` | Bot API token |
| `discord` | `url`、可选 `username` | 无（webhook URL 即凭证） |

四个聊天平台渠道是"格式化 webhook"：MiBee 会把事件转换成平台的消息格式（标题 + 详情的文本消息）。若需要原始 JSON 载荷，请使用通用 `webhook` 类型 —— 它 POST 完整事件结构：

```json
{
  "subject": "Device Lost: cam-01",
  "body": "Device: cam-01\nIP: 192.168.63.133\n...",
  "metadata": {
    "event_type": "device_lost",
    "device_name": "cam-01",
    "ip_address": "192.168.63.133",
    "mac_address": "...",
    "device_type": "camera",
    "detected_at": "2026-08-22T00:02:43Z"
  }
}
```

每个渠道在 UI（设置 → 通知 → 渠道行）都有**测试发送**按钮 —— 绑定规则前先用它验证连通性。

## 自动化示例

现成示例位于 [`deploy/integrations/`](https://github.com/Mi-Bee-Studio/MiBeeSteward/tree/main/deploy/integrations)：

- **n8n** — `n8n/mibee-device-alerts.json`：可导入的工作流，接收通用 webhook 载荷、过滤 `device_lost`，交给任意目标节点（聊天、工单……）。
- **Home Assistant** — `homeassistant/mibee-device-webhook.yaml`：`webhook` 触发器自动化，设备离线时推送持久通知；另含从 HA 触发 MiBee 扫描的 `rest_command`。

模式都一样：创建一个指向你工具入站 URL 的 `webhook` 渠道，绑定通知规则，然后按 `metadata.event_type` 做路由。
