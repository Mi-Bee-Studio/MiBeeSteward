# MiBee Steward on OpenWrt (router deployment)

MiBee Steward can run **on an OpenWrt router** in two forms:

| Form | Binary | Role | When to use |
|---|---|---|---|
| **B — router-agent → remote center** | `cmd/agent` | Pure sensor: scans the router's LAN, reports upstream over HTTPS to a center elsewhere | Multi-site / multi-LAN: one remote center + one agent per router. The agent is light (18MB binary, ~100MB RAM). |
| **C — router-center** | `cmd/server` | The full center (API + SPA + asset registry + discovery) running ON the router | Single-network (home / small office): one router does everything — gets the choke-point discovery signals (DHCP leases / conntrack / hostapd / dns_log) AND serves the portrait UI. No separate agent process needed. |

Both forms unlock the **4 Tier-1 router-only discovery signals** that a host-based deployment can't get (the router is the network choke point: it sees DHCP, NAT flows, WiFi associations, and DNS queries a random LAN host can't). See `scanner.discovery.*` in `configs/config.example.yaml`.

## ⚠️ Hardware requirements (read first)

| Resource | Minimum | Comfortable | Notes |
|---|---|---|---|
| **Architecture** | **ARM or ARM64** | ARM64 (GL.iNet MT3000, ipq807x, mt798x) | **MIPS is NOT supported** — `modernc.org/libc` (the pure-Go SQLite backend's transitive dep) has no working `mips`/`mipsle` port and a broken `mips64le` one. This excludes older ath79/ramips routers (TP-Link Archer C7, Netgear R7000, etc.). |
| **RAM** | 128 MB | 256 MB+ | modernc SQLite is memory-heavier than C-SQLite; the center is heavier than the agent. |
| **Flash** | 32 MB | 128 MB+ | Binary 16-18MB + OUI (~5MB full / 1.2KB curated) + fingerprint corpus (~1.2MB) + DB. The DB should live on `/tmp` (tmpfs) — see [Flash-wear mitigation](#flash-wear-mitigation-db-on-tmpfs). |

## Cross-compile

Both binaries build CGO-free (`modernc.org/sqlite`), so a plain `GOOS`/`GOARCH` cross-compile works — no OpenWrt SDK needed.

```bash
# Form B: agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags="-s -w" -o mibee-agent ./cmd/agent/
#   → ~18MB

# Form C: center
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags="-s -w" -o mibee-steward ./cmd/server/
#   → ~24MB (includes the embedded SvelteKit SPA)
```

`GOARCH=arm` (32-bit, GOARM=7) also works for older ARM boards. `GOARCH=mips*` does **not** (see above).

The repo's Makefile has cross-compile targets for all three supported archs —
prefer these over the raw `go build` above (they run the device-type sync the
embed step needs):

```bash
make build-linux-amd64   # x86_64 (generic Linux host)
make build-linux-arm64   # ARMv8 (GL.iNet MT3000, ipq807x, mt798x)
make build-linux-arm     # ARMv7 32-bit (older ARM boards)
make build-all           # all three at once (server binary each)
```

## Install (form B — agent → remote center)

```bash
# On your build host:
scp mibee-agent root@router:/usr/bin/mibee-agent
scp deploy/openwrt/mibee-agent.init root@router:/etc/init.d/mibee-agent
ssh root@router 'mkdir -p /etc/mibee'
scp configs/agent.yaml root@router:/etc/mibee/agent.yaml   # then edit on the router

# On the router, edit /etc/mibee/agent.yaml:
#   center.url:         http://<your-center-ip>:<port>
#   center.auth_token:  <minted on the center via POST /api/v1/agents/tokens>
#   network.name/cidr:  this router's LAN (e.g. lan-62 / 192.168.62.0/24)
#   scanner.discovery.*: enable the router-only sources you want
#     (dhcp_leases, conntrack, hostapd, dns_log — all default false)

ssh root@router '/etc/init.d/mibee-agent enable && /etc/init.d/mibee-agent start'
ssh root@router 'logread -e mibee-agent | tail -20'   # expect "mibee-agent running"
```

## Install (form C — center on the router)

```bash
scp mibee-steward root@router:/usr/bin/mibee-steward
scp deploy/openwrt/mibee-steward.init root@router:/etc/init.d/mibee-steward
ssh root@router 'mkdir -p /etc/mibee'
scp configs/config.yaml root@router:/etc/mibee/config.yaml   # then edit on the router

# On the router, edit /etc/mibee/config.yaml:
#   server.port:                   e.g. 8080
#   auth.initial_admin_password:   REQUIRED (no hardcoded default) — change from default!
#   network.name/cidr:             this router's LAN
#   database.path:                 /tmp/mibee/mibee.db  (tmpfs — see below)
#   scanner.discovery.*:           enable the router-only sources

ssh root@router '/etc/init.d/mibee-steward enable && /etc/init.d/mibee-steward start'
# Browse to http://<router-ip>:8080, log in with admin / <initial_admin_password>
```

## Flash-wear mitigation (db on tmpfs)

Both binaries write a SQLite DB (WAL mode). On a router's NAND flash under overlayfs this causes write-wear. **Point the DB at `/tmp` (tmpfs, RAM-backed):**

- **Agent (form B):** the local DB is explicitly a *shadow* (the center is the writer of record), so cold-start loss is fine. **Always use `/tmp/mibee-agent/agent.db`.** The agent's in-memory pending-queue (100 batches) handles disconnection during a reboot.
- **Center (form C):** the DB is the authoritative portrait. `/tmp` means cold-start loss (rebuilt on the next scan; acceptable for a single-router deployment). For deployments that need persistence across reboots, leave `database.path` on flash and accept the wear — consumer routers live 5-10 years and scan write volume is modest.

## Router-only discovery sources (enable in `scanner.discovery.*`)

| Source | What it gives | Router daemon it reads | No-op when absent |
|---|---|---|---|
| `dhcp_leases` | Authoritative hostname↔MAC↔IP map | dnsmasq `/tmp/dhcp.leases` | ✅ non-DHCP host |
| `conntrack` | "Who is talking RIGHT NOW" (liveness + discovery) | `/proc/net/nf_conntrack` | ✅ module not loaded |
| `hostapd` | WiFi STA associations (signal dBm / SSID / connect time) | hostapd ctrl socket → `iw station dump` fallback | ✅ no WiFi / no hostapd |
| `dns_log` | Passive DNS fingerprint (devices that block probes still do DNS) | dnsmasq `--log-queries` log file | ✅ no query logging configured |

All four are **shared across forms B and C** (and form A — center on a generic host), so the same config block works in `agent.yaml` and `config.yaml`. All four degrade to a clean no-op (debug log + skip) on a host that doesn't have the file/socket — no errors, no crashes.

**Operator setup for `dns_log`:** enable dnsmasq query logging —
`uci set dhcp.@dnsmasq[0].logqueries=1 && uci commit && /etc/init.d/dnsmasq restart`. Point `scanner.discovery.dns_log.path` at the resulting log (or leave empty to probe the conventional paths).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `bind: address already in use` on start | Another process holds the port (often the center's SPA + the router's own LuCI on 80/443). Set `server.port` to a free port (e.g. 8080). |
| `database is locked (SQLITE_BUSY)` | WAL-mode write contention under heavy concurrent probing. Raise `database.max_open_conns` (default 16) or reduce `scanner.max_concurrent_hosts`. |
| `mmap: access denied` at startup | Kernel disallows the mmap SQLite wants — run as root (the procd script does) or check the router's seccomp/apparmor. |
| Discovery sources all no-op | Expected on a non-router host. On a router, check each source's prereq (dnsmasq running, `nf_conntrack` loaded, hostapd ctrl_interface enabled). |
| `unsupported GOARCH mips` at build | MIPS isn't supported (modernc/libc limitation). Use an ARM/ARM64 router. |

## What's NOT covered here

- **Official .ipk packaging** (OpenWrt build feed): this repo ships init scripts + binaries that work via plain `scp` + `/etc/init.d/`. A proper `.ipk` via the OpenWrt buildroot's `golang-package` macros is a follow-up (lower friction for end users; not required for correctness).
- **MIPS support**: structural limitation of `modernc/libc`; would require swapping the SQLite backend to bbolt/goleveldb (a real refactor — deferred until a MIPS customer need exists).
