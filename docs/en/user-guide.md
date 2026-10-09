# User Guide

The complete walkthrough of the MiBee Steward web UI: every page, what it shows, and the actions it offers. For installation see [Quick Start](quick-start.md) / [Deployment](deployment.md); for screenshots see [Web UI](web-ui.md); for the REST API see [API](api.md).

## First login

1. Open `http://<center-host>:8080`.
2. On a fresh install with `auth.initial_admin_password` **unset**, the first visit lands on a first-run setup wizard — set the admin account there. If the config seeds an initial password, log in with it; the UI then **forces a password change** before any other page works (the forced-change gate applies to every session until the password is rotated).
3. Sessions are cookie-based; in production `cookie_secure: true` + `cookie_same_site: strict` are expected, so access the UI over HTTPS behind your reverse proxy.

## Dashboard (`/dashboard`)

The landing overview: online/offline device counts, per-network device trends, recent change-log events, agent health, and heartbeat failure summaries. Widgets link into their respective pages — it reads entirely from the same API the individual pages use.

## Networks (`/networks`)

Each managed LAN is one network row: **name, CIDR, and which agent owns it** (`agent_id`).

- **Add a network**: name + CIDR (e.g. `lan-1` / `192.168.1.0/24`). The CIDR drives scan targeting and device→network attribution.
- **Agent binding** is the dispatch switch: an `agent_id` on the network means its scan tasks are dispatched to that agent (distributed mode); **empty = the center scans it locally**. When devices from an agent-covered LAN stop updating, check this field first — an accidentally emptied `agent_id` silently flips the network back to center-local scans.
- Deleting a network does not delete devices; they are re-attributed on the next scan.

## Devices

### Inventory (`/devices`)

The asset registry. Columns: status (online/offline with last-seen), name, type, brand/model, IP/MAC, network, and the scan-attribute badges (locally-administered MAC, inference source). Actions per row:

- **Rescan** — queue a one-off scan of that host.
- **Edit** — set name/location/description/purpose; user-set fields are sticky: the scan bridge only fills empty or "unknown" fields and never overwrites your edits (only a device **replacement** force-overwrites identity).
- **Delete** — removes the device and its heartbeat configs and topology edges.

Identity rules, in one paragraph: **one row per MAC** (MAC-primary identity). A device that moves IPs keeps its row (roam); a device holding two live IPs simultaneously (dual-NIC, dual DHCP lease) keeps one row with the twin IP recorded in `scan_attributes.extras.ip_aliases`; a never-seen MAC appearing at an occupied slot is treated as a replacement (the old row goes offline, `mac_aliases` records the history); a **randomized (locally-administered) MAC never force-replaces a real device** — the real device's row is parked (IP cleared, identity kept) and it returns via the roam path when seen again.

### Device detail (`/devices/detail/{id}`)

Everything known about one asset: identity card, open ports + detected services, scan attributes (SNMP sysDescr, OS/kernel, inference sources with their confidence), heartbeat status history, L2 topology edges (`device_neighbors` — learned from LLDP/CDP/Bridge-MIB probes), and the device's change history.

### Discovery & scans (`/devices/discovery`, `/devices/scan-results`, `/devices/scan-tasks`, `/devices/scanner`)

- **Scan tasks**: recurring scans per network (cron expressions, e.g. `*/10 * * * *`). Each run is recorded; the runs list shows alive hosts and duration. In distributed mode a task runs on the network's owning agent.
- **Scan results**: per-host scan outcome history.
- **Scanner settings**: concurrency, timeouts, port spec, reserved-range guard (`scanner.allow_reserved_targets` — leave **off**; loopback/link-local targets are rejected at every entry point by default).

## Agents (`/agents`)

The fleet view for distributed deployments: each agent's version (e.g. `mibee-agent-rs/0.1.5`), uptime, last report age, scan counter, and its adopted fingerprint-corpus revision.

- **Mint a token** (Agents page → create): binds `agent_id + network_id`, plaintext shown **exactly once** — paste it into the agent's `agent.yaml` (`center.auth_token`). Tokens are revocable; revoked agents fail auth immediately.
- **Remote ops**: with `agent_fleet.remote_ops_enabled` on the center side and the agent's `center.remote_ops_enabled: true`, the center can request on-demand scans and log retrieval.
- A stale "last report" is the first symptom of a broken agent → check the agent host (`systemctl status mibee-agent`, `journalctl -u mibee-agent`).

## Fingerprints (`/fingerprints`)

The identification corpus management page (capability `fingerprint:manage`, audit-logged):

- **Status**: active corpus revision + rule count (engine view vs managed dir).
- **Upload**: a tar.gz/zip envelope or a single `.yaml` replacing just that file. Every upload validates through the rule engine's own loader first — a broken corpus is rejected with the engine's error and the live one keeps running.
- **Rollback**: one click back to the predecessor corpus (the pre-first-upload corpus is parked automatically).
- **Upstream check**: against a configured `scanner.fingerprint_upstream.url` manifest — shows version + added/removed rule diff, one-click apply.
- **Fleet adoption**: which agent runs which revision (agents on `center.fingerprint_sync.enabled` converge automatically).

## Topology (`/topology`)

Layer-2 adjacency view built from `device_neighbors` (LLDP/CDP/Bridge-MIB/Q-BRIDGE/STP evidence reported by agents, plus center-local scans). Edges carry port names and the observing protocol.

## Probes (`/probes`)

Heartbeat (liveness) monitoring: per-device probe configs (HTTP/TCP/ICMP/SNMP), their recent results, and failure state. Probe failure noise is streak-suppressed (first failures WARN, repeats sampled) — a steady stream of probe ERRORs usually means orphaned configs pointing at a dead IP, which the retention cleanup reaps.

## Change log & audit (`/changes`, `/audit`)

- **Changes**: the change-detection stream (device added/changed/recovered/lost, per-field diffs). IP churn on one device is expected only when it genuinely roams; repeated flips between two IPs are a bug signature — check `ip_aliases` on the device first.
- **Audit**: who did what on mutating APIs (capability-gated actions, fingerprint changes, user management).

## Settings (`/settings`)

Accordion sections (expand in place):

- **Fingerprints** — the corpus management above.
- **Security** — JWT secret rotation, cookie flags, password policy.
- **Scanner** — engine tuning, discovery sources, SNMP credentials (SNMPv3 passphrases are vault-encrypted at rest and **never** echo back from any API).
- **Notifications** — webhook/notification channels for heartbeat and change events.
- **Users** — account management (admin capability).

## Users (`/users`)

Account list with capabilities/RBAC. Deleting or demoting the last admin is prevented. Password resets by an admin force a change on next login.

## Documents (`/documents`)

Attachment/document storage per device (manuals, invoices) — uploads are API-backed and exposed on the device detail page.

## Demo mode

Start the center with `server.demo_mode: true` (or `-demo`): it seeds a fictional inventory on documentation-only IP ranges (RFC 5737), replays simulated events, and the UI offers a one-click reset. Demo data never touches a real network. Ideal for screenshots and evaluations — [web-ui.md](web-ui.md) screenshots are captured through it.

## Troubleshooting quick answers

| Symptom | First check |
|---|---|
| Devices from an agent LAN frozen / stale | The network's `agent_id` on `/networks`; the agent's service status + last report age on `/agents` |
| Agent 401s in the center log | Token revoked or rotated — mint a new one, update `center.auth_token` |
| Two device rows for one box (Ethernet + WiFi) | That's `mac_aliases` at work; UI-side alias aggregation is roadmap — merge intent is recorded |
| A device "moved" to a random-looking MAC | Locally-administered (randomized) MAC; the real holder is parked and returns — see [agent-rs.md](agent-rs.md) / CHANGELOG |
| Login fails with the seeded password | Password was rotated post-install; use the admin reset CLI (`mibee-steward reset-admin-password`) or the first-run wizard after a DB rebuild |
| Scan rejects my target range | Reserved-range guard — see [configuration.md](configuration.md); do not disable in production |
| Forgot admin password, locked out | `mibee-steward reset-admin-password` (password via stdin/flag/env) |
