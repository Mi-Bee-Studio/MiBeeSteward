# Quick Start

This guide shows how to get MiBee Steward running in minutes and complete your first network asset discovery. It assumes you use a prebuilt binary or container image; to build from source, see the [Development Guide](development.md).

## Prerequisites

- A Linux x86_64 or ARM64 host (CGO-free single binary, no runtime dependencies)
- ~50MB of disk space (application + SQLite database)
- Network access to the target subnets (for ICMP / SNMP / TCP probing)
- For the container path: Docker Engine (optional)

## Get the Binary

### Option 1: GitHub Releases

Download the binary for your architecture from the [Mi-Bee-Studio/MiBeeSteward Releases](https://github.com/Mi-Bee-Studio/MiBeeSteward/releases) page (current version: v0.9.0):

```bash
chmod +x mibee-steward
./mibee-steward --config config.yaml
```

### Option 2: Docker

```bash
docker pull ghcr.io/mi-bee-studio/mibeesteward:0.9.0
```

Scanning operates at the network-namespace level, so run the container with host networking and declare `NET_RAW` / `NET_ADMIN`:

```bash
docker run -d --name mibee \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/configs:/app/configs:ro" \
  ghcr.io/mi-bee-studio/mibeesteward:0.9.0
```

> Docker's default bridge mode sits behind NAT, which breaks ICMP, ARP/MAC, and multicast probing, it cannot be used for real asset inventory. See [Deployment](deployment.md).

## Minimal Configuration

**Zero-config path (#682)**: if the config file does not exist, the very first `./mibee-steward` run generates a minimal one at the `-config` path (default `config.yaml`) — a random `jwt_secret`, an empty admin password so the browser first-run setup creates it — and starts right away. Write a config yourself only when you want to tune something.

Create `config.yaml`. The smallest useful config is the listen address, your local network CIDR, and the JWT secret (`auth.jwt_secret` must be at least 32 characters). `initial_admin_password` may stay empty — the first visit to the UI then opens the first-run setup that creates the admin password in the browser:

```yaml
server:
  host: "0.0.0.0"
  port: 8080

network:
  name: "lan-1"
  cidr: "192.168.1.0/24"

auth:
  jwt_secret: "change-me-to-a-random-string-32-chars-min"   # ≥32 chars, required
  initial_admin_password: ""                                # empty = browser first-run setup; or set a temp password (first login forces a change)
```

Every config key can be overridden by an environment variable with the `MIBEE_` prefix (dots become underscores, e.g. `network.cidr` → `MIBEE_NETWORK_CIDR`):

```bash
export MIBEE_SERVER_PORT=8080
export MIBEE_AUTH_JWT_SECRET="$(openssl rand -base64 32)"
export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD="your-strong-password"
```

For production, always set a unique `auth.jwt_secret`; for the admin password either set `initial_admin_password` to a one-time value (the first login forces a change) or leave it empty and create the password through the browser first-run setup. See the [Configuration Reference](configuration.md) for all options.

## Start and Log In

```bash
./mibee-steward --config config.yaml
```

Open http://localhost:8080. If `initial_admin_password` is empty, the login page switches to a first-run form: create the admin password there and you are logged straight in. Otherwise log in with `admin` and the configured password, and the first login forces you to replace it. Health check:

![Login page](images/login.webp)

```bash
curl http://localhost:8080/api/v1/health
```

## 60-Second Demo (no network needed)

Curious what the inventory looks like before wiring a real subnet? Start in demo mode, a fictional fleet (two networks, ~20 devices with portraits, change history, probe results) is seeded on first boot and kept active with simulated events:

```bash
./mibee-steward -demo
```

(No config file yet? One is generated on first start — see [zero-config first run](#minimal-configuration) above; or pass `-config configs/config.example.yaml` to try the checked-in example.)

Open the UI and explore; an amber banner marks demo mode and offers a one-click **Clear demo data** to switch to real inventorying.

## First Scan

```mermaid
sequenceDiagram
    participant U as User
    participant W as Steward Web UI
    participant S as Scanner
    participant T as Target network
    participant D as SQLite
    U->>W: Initiate scan 192.168.1.0/24
    W->>S: POST /api/v1/scanner/scan
    S->>T: ICMP + TCP + SNMP probing
    T-->>S: Device responses (IP/MAC/RTT)
    S->>D: Device bridge (devices + heartbeat seeds)
    S-->>W: Return scan results
    W-->>U: Display device list
```

**Web UI**: after logging in, open the scanner page and launch a scan against your target CIDR.

![Scanner](images/scanner.webp)

**Synchronous API** (for targets up to 1024 IPs):

```bash
# Obtain an admin token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-strong-password"}' | jq -r .token)

curl -X POST http://localhost:8080/api/v1/scanner/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":"192.168.1.0/24"}'
```

The response is `{ hosts, total, alive, duration_ms }`; each host carries `ip`, `alive`, `rtt_ms`, `inferred_type`, `inferred_brand`, and more. Alive hosts are immediately registered through the **device bridge** (upserting `devices`, seeding heartbeat configs, and emitting change events); scan history rows (`scan_results` / `scan_task_runs`) are only persisted by async tasks.

**Async tasks** (the sync endpoint returns 413 for targets larger than 1024 IPs): create a task with `POST /api/v1/scanner/tasks` and trigger it with `POST /api/v1/scanner/tasks/{id}/trigger`; results are persisted to `scan_results`. See the [API Reference](api.md).

## What You Should See

![Device list after the first scan](images/devices.webp)

- Device list: IP, MAC, OUI vendor, brand/model, type
- Identification results: `inferred_type` / `inferred_brand` (e.g. camera, server, pc, iot)
- Heartbeat status: online/offline and response latency
- Topology and neighbor relationships if the network has SNMP-capable switches

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Port 8080 already in use | Change `server.port` or set `MIBEE_SERVER_PORT` |
| No devices found | Verify `network.cidr` and `targets`; check that the firewall allows ICMP and SNMP (UDP 161) |
| Devices online but unidentified | Check the SNMP community (default `public`), or pass `community` explicitly in the scan request |
| Scanning misbehaves in Docker | Switch to host networking (see above) |
| Service fails to start | Read the startup log: a missing `auth.jwt_secret` (<32 chars) exits immediately (an empty `initial_admin_password` is fine — that is the browser first-run path); then check write permissions on the `data/` directory |
| Want a self-check | `./mibee-steward doctor -config config.yaml` — validates the config and checks the database, port conflicts, backups, and (agent mode) center reachability |
| Forgot the admin password | `./mibee-steward reset-admin-password -config config.yaml` (interactive prompt, or `-password 'new-pass'` / env `MIBEE_RESET_PASSWORD`) |

## Next Steps

- [Scenario playbooks](playbooks.md), six guided scenarios from first scan to multi-subnet
- [Feature overview](features.md), the full capability inventory
- [Architecture](architecture.md), scanner pipeline and background services
- [Deployment](deployment.md), systemd, Docker, Nginx, backups
- [Distributed](distributed.md), center + agents for multi-network discovery
- [Configuration Reference](configuration.md), all config options
- [API Reference](api.md), scan, device, and heartbeat endpoints
