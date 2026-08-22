# Benchmarks

Scale and accuracy evidence for MiBee Steward — the synthetic-load harness (`cmd/loadgen`), the nmap comparison script, and the methodology behind both.

## Synthetic scale harness

`loadgen` emulates a device LAN on the loopback network without any virtual machines: every synthetic device lives on its own `127.x.y.z` address, so ICMP works for free (the kernel answers), and per-template TCP/UDP responders emulate SNMP v2c agents, HTTP servers, SSH-style banners, and RTSP servers with realistic payload shapes. The scanner's probes, classifiers, and write paths run unmodified — this measures the real pipeline, not a mock.

Device classes are a deterministic weighted mix (cameras / routers / servers / NAS / IoT / printers) so identification pressure and per-class port layouts are realistic.

### Running a benchmark

On the machine running the center (needs `CAP_NET_BIND_SERVICE` for the well-known ports 22/80/161/554 — i.e. run as root, same as the scanner's ICMP needs):

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
- `mibee_sqlite_busy_total` delta (single-writer contention under the synthetic load — the #267 observability line)
- center process CPU seconds and end-of-run resident memory
- API latency p50/p95/max from a burst of `GET /api/v1/devices`

Scale up by widening the CIDR: `--devices 10000 --base 127.8.0.0` + `--targets 127.8.0.0/19`. Watch the listener count (file descriptors) on very large planes.

## Accuracy vs nmap

`scripts/bench-accuracy.sh <CIDR> [center_url]` runs MiBee and `nmap -sn` against the same subnet and diffs the alive sets into a confusion matrix:

- **recall** — share of nmap-found hosts MiBee also found (the "no silent misses" dimension)
- **precision** — share of MiBee-found hosts nmap confirms
- **MiBee-only hosts** are reported separately: MiBee's TCP-probe fan-out deliberately counts hosts that only answer a TCP connect (which `nmap -sn` without root/ARP can miss) — a surplus here is a feature, not an error, but is worth eyeballing.

Requires `nmap`, `curl`, `jq`-less (python3), and credentials via `MIBEE_USER` / `MIBEE_PASS`.

## Methodology caveats

- The loopback plane has no packet loss, no latency, and no ARP — wall-clock scan duration underestimates a real LAN; DB write load, identification work, and API latency are representative.
- **Every address in 127/8 answers ICMP** (kernel behavior), so the alive count equals the scanned address count, not the synthetic device count — liveness numbers on the plane measure pipeline throughput, not discovery precision. Identification counts (cameras via RTSP/HTTP, etc.) are the meaningful accuracy signal.
- `loadgen serve` answers SNMP with a single sysDescr for the whole plane (UDP has no per-connection state); identification pressure comes from the TCP side (banners / HTTP titles / RTSP).
- For sustained-load runs (write-path contention), trigger several scans back-to-back while `mibee_sqlite_busy_total` is scraped.
