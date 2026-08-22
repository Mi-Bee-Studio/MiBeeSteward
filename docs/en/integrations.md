# Integrations

MiBee Steward stays focused on device discovery and inventory — but it ships official bridges to the surrounding observability ecosystem: Grafana dashboards for the metrics it exports, notification channels for the chat platforms your team already uses, and webhook examples for automation tools.

## Grafana

MiBee exposes Prometheus metrics at `/metrics` (see the [deployment guide](deployment.md) for the Prometheus scrape config and bundled alert rules). The repo also ships five ready-to-import dashboards under [`deploy/grafana/`](https://github.com/Mi-Bee-Studio/MiBeeSteward/tree/main/deploy/grafana):

| Dashboard | Contents |
|---|---|
| `mibee-overview` | General health: devices by status, scan runs, heartbeat outcomes, API request rate, DB size |
| `mibee-devices` | Device fleet: online/offline counts, online ratio, type distribution, per-agent report age |
| `mibee-heartbeat` | Heartbeat health: outcome rates, failure share, p50/p95 probe latency by method |
| `mibee-probes` | Synthetic probes: up/down state by target, success ratio, probe duration, certificate expiry days |
| `mibee-scanner` | Scanner activity: run rates, duration quantiles, hosts discovered, scanner table growth |

### Import via provisioning (recommended)

Mount the whole `deploy/grafana/` directory into your Grafana container/host:

```yaml
# docker-compose.yml fragment
volumes:
  - ./deploy/grafana/provisioning/datasources:/etc/grafana/provisioning/datasources:ro
  - ./deploy/grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro
  - ./deploy/grafana/dashboards:/var/lib/grafana/dashboards:ro
```

The bundled datasource provisioning expects Prometheus at `http://prometheus:9090` — edit `deploy/grafana/provisioning/datasources/prometheus.yml` if yours lives elsewhere. Dashboards appear in the `MiBee` folder on startup.

### Manual import

Grafana → Dashboards → Import → paste the JSON file contents → select your Prometheus datasource.

## Notification Channels

Notification rules (event → channel, see [Web UI](web-ui.md) → Settings → Notifications) can deliver to six channel types:

| Type | Config fields | Auth |
|---|---|---|
| `webhook` | `url`, optional `headers` map | Custom headers (e.g. your receiver's token) |
| `email` | SMTP `host`/`port`/`username`/`password`, `from`, `to` | SMTP AUTH |
| `feishu` | `url`, optional `secret` | 飞书 custom-bot HMAC signature (enable "签名校验" on the bot and paste the secret) |
| `wecom` | `url` | none (the webhook URL is the credential — treat it as secret) |
| `telegram` | `bot_token`, `chat_id` | Bot API token |
| `discord` | `url`, optional `username` | none (webhook URL is the credential) |

The four chat-platform channels are "formatted webhooks": MiBee translates each event into the platform's message format (a text message combining the subject and details). Use the generic `webhook` type when you want the raw JSON payload instead — it posts the full event structure:

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

Every channel has a **Test send** button in the UI (Settings → Notifications → channel row) — use it to verify delivery before wiring rules.

## Automation Examples

Ready-made examples live under [`deploy/integrations/`](https://github.com/Mi-Bee-Studio/MiBeeSteward/tree/main/deploy/integrations):

- **n8n** — `n8n/mibee-device-alerts.json`: an importable workflow that receives the generic-webhook payload, filters `device_lost`, and hands off to your choice of destination node (chat, ticketing, …).
- **Home Assistant** — `homeassistant/mibee-device-webhook.yaml`: a `webhook` trigger automation that pushes a persistent notification when a device is lost, plus a `rest_command` for triggering MiBee scans from HA.

The pattern is the same everywhere: create a `webhook` channel pointing at your tool's inbound URL, bind a notification rule to it, and consume `metadata.event_type` for routing.
