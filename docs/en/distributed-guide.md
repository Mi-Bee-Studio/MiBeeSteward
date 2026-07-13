# Distributed Deployment Guide

This guide covers deploying MiBee Steward in a distributed (multi-LAN) configuration:
a **center** that aggregates device data from one or more **agents**, each deployed
on a different network segment.

## When to Use Distributed Mode

- You have devices on **multiple LANs/VLANs** that the center cannot directly scan
  (no L3 route, NAT, firewall).
- You want a **unified device registry** spanning all networks, queryable from one UI.
- You need **per-network change detection** (device added/changed/lost per LAN).

If you only have one network, the center's built-in scanner is sufficient — no
agent needed.

## Architecture Overview

```
[Network A]                    [Network B]
  Center (cmd/server)           Agent (cmd/agent)
  - Web UI + API                - Scans local LAN
  - Device registry             - Reports to center
  - Change detection            - Polls for commands
  - Local scanner               - Runs on cron + ad-hoc
```

The agent uses a **pull model**: it initiates all connections to the center
(report results, poll commands). No inbound connection from the center is needed,
so the agent works behind NAT.

## Prerequisites

- **Center**: one machine running `cmd/server` (the standard binary), reachable
  from all agents via HTTP.
- **Agent**: one machine per remote LAN, with network access to the target subnet.
  No sudo required — the agent runs as a regular user.
- Both binaries are CGO-free (pure Go + modernc.org/sqlite), so no C toolchain
  needed on the target.

## Step 1: Set Up Networks on the Center

Each agent is bound to a **network** (a row in the `networks` table). The center
resolves its own network at startup from `config.yaml`:

```yaml
network:
  name: "lan-63"          # this center's own network
  cidr: "192.168.63.0/24"
  site: "hq"
```

For each **remote** network an agent will cover, you need a `networks` row on the
center. Create it from the **Networks** admin page (left sidebar, admin-only) or
via the API:

```bash
curl -X POST http://localhost:8080/api/v1/networks \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"lan-62","cidr":"192.168.62.0/24","site":"branch-office"}'
```

You can also insert it directly into SQLite (advanced):

```bash
sqlite3 /opt/mibee-steward/data/mibee.db \
  "INSERT INTO networks (name, cidr, site) VALUES ('lan-62', '192.168.62.0/24', 'branch-office');"
```

## Step 2: Create an Agent Token

In the center's web UI:

1. Log in as admin.
2. Go to **Agents** (left sidebar, admin-only).
3. Click **"+ Create Token"**.
4. Fill in:
   - **Agent ID**: a unique identifier, e.g. `agent-lan-62`.
   - **Network**: select the network this agent discovers for (e.g. `lan-62`).
   - **Name**: optional human label, e.g. "Branch Office LAN-62".
5. Click **Create**.
6. ⚠️ **Copy the plaintext token immediately** — it is shown only once and cannot
   be retrieved later.

Alternatively, via API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://localhost:8080/api/v1/agents/tokens/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-lan-62","network_id":2,"name":"Branch Office"}'
# Response includes "token" — copy it!
```

## Step 3: Build the Agent Binary

On your build machine:

```bash
make build-agent
# Output: bin/mibee-agent (CGO-free, ~12MB)
```

Or cross-compile:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/mibee-agent ./cmd/agent/
```

## Step 4: Deploy the Agent

On the remote machine (e.g. `192.168.62.174`):

```bash
# Upload the binary
scp bin/mibee-agent user@192.168.62.174:~/mibee-agent/
ssh user@192.168.62.174 'chmod +x ~/mibee-agent/mibee-agent'
```

Create the agent config (`~/mibee-agent/configs/agent.yaml`):

```yaml
center:
  url: "http://192.168.63.101:8080"     # center's address
  auth_token: "PASTE_TOKEN_HERE"          # the token from Step 2
  report_interval: "30s"                 # how often to flush reports

network:
  name: "lan-62"                         # must match the network name on the center
  cidr: "192.168.62.0/24"

scanner:
  default_timeout: 300
  max_concurrent_hosts: 50
  per_probe_timeout: 3

log:
  level: "info"
  format: "text"
```

Start the agent:

```bash
cd ~/mibee-agent
setsid ./mibee-agent -config configs/agent.yaml > agent.log 2>&1 &

# Verify
tail -f agent.log
# Expect: "mibee-agent running" + "scannerv2 engine ready"
```

## Step 5: Seed a Scan Task (Optional)

The agent's scheduler reads from a local `scan_tasks` table. To set up a periodic
scan, insert a task row into the agent's local SQLite:

```bash
# The agent creates agent.db next to the config on first run.
# After starting the agent once, stop it and seed a task:
sqlite3 ~/mibee-agent/configs/agent.db \
  "INSERT INTO scan_tasks (name, targets, cron_expr, timeout, concurrent_hosts, enabled)
   VALUES ('lan-62-full', '192.168.62.0/24', '0 */6 * * *', 300, 50, 1);"
```

Restart the agent. It will scan every 6 hours and report results upstream.

## Step 6: Trigger an Ad-Hoc Scan from the Center

In the center's web UI → **Agents** page → click **"Trigger Scan"** on the agent's
row. Enter the scan targets (e.g. `192.168.62.0/24`) and timeout. The agent picks
up the command within 60 seconds, executes it, and reports results.

Via API:

```bash
curl -X POST http://localhost:8080/api/v1/agents/agent-lan-62/commands/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"command":"scan","payload":{"targets":"192.168.62.0/24","timeout":120}}'
```

## Step 7: View Results

- **Devices page**: filter by network using the **Network** dropdown to see devices
  per LAN.
- **Changes page**: view device_added / device_changed / device_lost events, filterable
  by network and event type.
- **Agents page**: monitor agent status (Active/Idle/Revoked) and last-used time.

## Managing Agents

### Revoke a Token

In the Agents page, click **"Revoke"** on a token. The agent immediately loses
access. This is a soft delete — the token record remains for audit.

### Agent Status

The center infers agent liveness from `last_used_at` (updated on every agent
request):

- 🟢 **Active**: last request within 5 minutes.
- ⚪ **Idle**: token exists but no recent activity.
- 🔴 **Revoked**: token has been revoked.

### Disconnect Recovery

If the center is unreachable, the agent holds failed report batches in an
in-memory queue (up to 100 batches). Once the center recovers, the backlog is
delivered in order. No data is lost during transient outages.

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/agents/tokens/` | Admin | Create agent token |
| GET | `/api/v1/agents/tokens/` | Admin | List all tokens |
| POST | `/api/v1/agents/tokens/{id}/revoke` | Admin | Revoke a token |
| DELETE | `/api/v1/agents/tokens/{id}` | Admin | Delete a token |
| POST | `/api/v1/agents/{agentId}/commands/` | Admin | Enqueue a command |
| GET | `/api/v1/agents/commands/all` | Admin | View all commands |
| POST | `/api/v1/agents/report` | Agent | Agent reports scan results |
| GET | `/api/v1/agents/commands` | Agent | Agent polls pending commands |
| GET | `/api/v1/networks` | Auth | List all networks |
| GET | `/api/v1/changes` | Auth | Query change history |
| GET | `/api/v1/changes/watch` | Auth | SSE stream of change events |
