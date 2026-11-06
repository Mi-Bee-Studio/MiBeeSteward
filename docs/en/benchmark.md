# Benchmarks

Scale and accuracy evidence for MiBee Steward, the synthetic-load harness (`cmd/loadgen`), the nmap comparison script, and the methodology behind both.

## Synthetic scale harness

`loadgen` emulates a device LAN on the loopback network without any virtual machines: every synthetic device lives on its own `127.x.y.z` address, so ICMP works for free (the kernel answers), and per-template TCP/UDP responders emulate SNMP v2c agents, HTTP servers, SSH-style banners, and RTSP servers with realistic payload shapes. The scanner's probes, classifiers, and write paths run unmodified, this measures the real pipeline, not a mock.

Device classes are a deterministic weighted mix (cameras / routers / servers / NAS / IoT / printers) so identification pressure and per-class port layouts are realistic.

### Running a benchmark

On the machine running the center (needs `CAP_NET_BIND_SERVICE` for the well-known ports 22/80/161/554, i.e. run as root, same as the scanner's ICMP needs):

```bash
# 1. Build both binaries
go build -o bin/loadgen ./cmd/loadgen

# 2. Start the plane (e.g. 1000 devices from 127.8.0.0)
sudo bin/loadgen serve --devices 1000 --base 127.8.0.0

# 3. From a second shell, drive one scan through the real center
bin/loadgen drive --center http://127.0.0.1:8080 \
  --user admin --pass '…' \
  --targets 127.8.0.0/22 --out bench-1k
```

`drive` logs in through the HTTP API, creates a disabled async scan task, triggers it, waits for completion, and samples `/metrics` deltas around the run. It writes `bench-1k.json` (machine-readable) and `bench-1k.md` (summary) covering:

- scan duration and alive-host counts
- SQLite main-DB growth (deltas of `mibee_db_size_bytes`)
- `mibee_sqlite_busy_total` delta (single-writer contention under the synthetic load, the #267 observability line)
- center process CPU seconds and end-of-run resident memory
- API latency p50/p95/max from a burst of `GET /api/v1/devices`

Scale up by widening the CIDR: `--devices 10000 --base 127.8.0.0` + `--targets 127.8.0.0/19`. Watch the listener count (file descriptors) on very large planes.

## Accuracy vs nmap

`scripts/bench-accuracy.sh <CIDR> [center_url]` runs MiBee and `nmap -sn` against the same subnet and diffs the alive sets into a confusion matrix:

- **recall**, share of nmap-found hosts MiBee also found (the "no silent misses" dimension)
- **precision**, share of MiBee-found hosts nmap confirms
- **MiBee-only hosts** are reported separately: MiBee's TCP-probe fan-out deliberately counts hosts that only answer a TCP connect (which `nmap -sn` without root/ARP can miss), a surplus here is a feature, not an error, but is worth eyeballing.

Requires `nmap`, `curl`, `jq`-less (python3), and credentials via `MIBEE_USER` / `MIBEE_PASS`.

## Low-resource field test (pre-v0.9.0, 2026-11-07)

Can the center carry a real home/SMB LAN on hardware class people actually
run routers and Pi-class boxes on? The whole binary — scanner, SQLite,
embedded SPA — was run under a cgroup v2 `systemd-run` scope with
**CPUQuota 30%** (three tenths of one core) and **MemoryMax 256 MB**, then
driven through the 1000-device synthetic plane:

| Metric | Value | Notes |
|---|---|---|
| Idle RSS after boot | **43 MB** | zero-config first boot, fresh DB |
| 1000-device scan (ICMP+SNMP+port_scan, /22 = 1022 hosts) | **446 s, 1022/1022 discovered** | ≈2.3 hosts/s at 0.3 core |
| Peak RSS during + after the scan | **168 MB** | headroom to the 256 MB cap |
| Center CPU for the whole scan | 88.2 s | ≈20% of the quota budget |
| SQLite DB growth | **0.6 MB** | 1000 devices + evidence |
| `mibee_sqlite_busy_total` delta | **0** | no single-writer contention |
| Device list API p50 / p95 / max (n=100) | 90.7 / 201 / 502 ms | paginated list under quota |
| Dashboard overview aggregate | **7–10 ms** | 1000 devices, all cards |
| `/devices/stats` | ~10 ms | |

Reading: on a third of one core and a 256 MB ceiling, a fresh center
discovers a full /22, serves the dashboard in single-digit milliseconds, and
keeps the list page interactive (p95 ≈0.2 s). The write path never
contended (`sqlite_busy` stayed 0). That is Raspberry-Pi-Zero-2W / budget
router territory — a single-board Linux box comfortably runs the center for
a thousand-device LAN; for anything bigger, agents fan out and the center
only aggregates.

Reproduce: `sudo systemd-run --unit=mibee-bench --property=CPUQuota=30%
--property=MemoryMax=256M ./mibee-steward -config …` then the loadgen
procedure above; the transient unit pins the limits while everything else
stays stock.

## Methodology caveats

- The loopback plane has no packet loss, no latency, and no ARP, wall-clock scan duration underestimates a real LAN; DB write load, identification work, and API latency are representative.
- **Every address in 127/8 answers ICMP** (kernel behavior), so the alive count equals the scanned address count, not the synthetic device count, liveness numbers on the plane measure pipeline throughput, not discovery precision. Identification counts (cameras via RTSP/HTTP, etc.) are the meaningful accuracy signal.
- `loadgen serve` answers SNMP with a single sysDescr for the whole plane (UDP has no per-connection state); identification pressure comes from the TCP side (banners / HTTP titles / RTSP).
- For sustained-load runs (write-path contention), trigger several scans back-to-back while `mibee_sqlite_busy_total` is scraped.

> **Note (reserved-target guard):** scan targets in reserved address space
> (loopback, etc.) are rejected by default since #317. The loadgen synthetic
> plane on `127/8` requires `scanner.allow_reserved_targets: true` in the
> CENTER's config (env `MIBEE_SCANNER_ALLOW_RESERVED_TARGETS=true`). Leave it
> off in production, a scheduled loopback task otherwise invents phantom
> devices that the silent-device retention can't clear.
