# Build Variants & Capability Matrix

MiBee Steward ships as one binary in several build variants. The **default build is unprivileged and kernel-free**: it runs anywhere Go compiles, needs no capabilities, and degrades nothing because everything privileged is compiled out. Optional capabilities come in via build tags, each with a documented privilege price.

## Variants at a glance

| Variant | Tags | Artifacts | Runtime privileges |
|---|---|---|---|
| **default** | — | `mibee-steward-linux-<arch>`, Docker image, OpenWrt packages | none |
| **full** | `WITH_LLDP,WITH_CDP,WITH_ARPSCAN` | `mibee-steward-linux-<arch>-full` (release attachments, #502) | `CAP_NET_RAW` |
| **eBPF** | `WITH_EBPF` | local build only (`make build-with-ebpf`) — needs clang ≥14 at build time | root, or ambient `CAP_BPF` + `CAP_NET_ADMIN` (kernel-dependent, see [ebpf.md](ebpf.md)) |
| single-capability | `WITH_LLDP` / `WITH_CDP` / `WITH_ARPSCAN` alone | local builds (`make build-with-lldp` …) | `CAP_NET_RAW` |

Every variant is CGO-free and cross-compiles cleanly; the optional sources are pure Go (raw sockets via `syscall`), which is also why they are Linux-only at build time.

Checksums: the release attaches `SHA256SUMS.center` covering all center binaries of both variants, flat filenames throughout — `sha256sum -c SHA256SUMS.center` works in any download directory (same rule as the agent's `SHA256SUMS.agent-rs`).

## What each tag buys

| Tag | Capability | Needs | Kernel | Data produced | Config |
|---|---|---|---|---|---|
| `WITH_LLDP` | Passive LLDPDU listener (ethertype 0x88cc) | `CAP_NET_RAW` (AF_PACKET) | Linux | `lldp_frame` source: neighbor edges → `device_neighbors`, topology edges on the next scan; system name/description evidence. Known gap: neighbor rows need the local host's device row to carry its MAC (#522) | `scanner.discovery.lldp_interfaces` (empty = all UP interfaces) |
| `WITH_CDP` | Passive Cisco CDP listener (ethertype 0x2000) | `CAP_NET_RAW` (AF_PACKET) | Linux | `cdp_frame` source: neighbor edges + Device ID / Platform / Software Version evidence (same local-anchor gap as LLDP, #522) | same list as LLDP |
| `WITH_ARPSCAN` | Active ARP sweep: who-has for every IP in the network CIDR, emitted hosts from replies | `CAP_NET_RAW` (raw sockets) | Linux | `NewHostEvent` per replying host — the only source covering the whole broadcast domain with no router access | `scanner.discovery.arp_scan.enabled` + `scanner.arp_scan.interface` |
| `WITH_EBPF` | TC passive observer: 8 protocol signatures (banners, WS-Discovery, DHCP, TLS SNI, mDNS, SSDP) | root or ambient caps | Linux ≥ 6.6 (TCX) | `passive:ebpf:tc` evidence rows feeding fingerprint classification | `scanner.ebpf.enabled` + `scanner.ebpf.interfaces` — full story in [ebpf.md](ebpf.md) |

**ARP sweep semantics** (worth knowing before enabling): the sweep broadcasts ARP who-has requests for every address in `network.cidr`, riding the discovery service's cadence — it fires per discovery round, it is not a constant flood. Every host with a network stack answers ARP, including firewalled ones that drop all inbound probes, which is exactly its value. Traffic visibility is one broadcast frame per address per round.

## Granting CAP_NET_RAW

For systemd deployments, add a drop-in (`systemctl edit mibee-steward`):

```ini
[Service]
AmbientCapabilities=CAP_NET_RAW
```

For Docker: `docker run --cap-add=NET_RAW …` (the `host` compose profile is the one that can use it).

Without the capability, a `full` binary simply skips the privileged sources at registration (they log why); the server itself and all default sources keep working. `mibee-steward doctor` reports each source's state: `ok` (built + capability present), `warn` (built but capability missing, or configured but not built), `skip` (not built / not enabled / not Linux).

## Why eBPF is not in the release matrix

The eBPF observer's BPF object is compiled from `bpf/tc_ingress.c` by bpf2go at build time — that step needs clang ≥ 14, which the release runners don't install. `make build-with-ebpf` does it locally on any OS and embeds the object; the resulting binary is as portable as the default one (CO-RE free, loads even without kernel BTF). See [ebpf.md](ebpf.md).
