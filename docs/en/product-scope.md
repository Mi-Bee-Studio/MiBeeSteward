# Product Scope & Boundary

> This document defines what MiBee Steward **is**, what it **is not**, and where it fits in the landscape. For feature lists and getting started, see [Introduction](introduction.md).

## What MiBee Steward IS

MiBee Steward is a **device/network-layer asset discovery, identification, and registry** tool. It answers three questions:

1. **What devices are on this network?** — auto-discovery via ICMP / TCP portscan / SNMP / HTTP / RTSP / ONVIF / mDNS / WS-Discovery probing, plus an optional eBPF passive observer
2. **What are they?** — identity inference (device type, brand, model) via banner / HTTP / RTSP / ONVIF / SNMP / Prometheus fingerprint classification
3. **Track them over time** — registry/management with heartbeat-based freshness (online/offline + latency + history)

It is **CMDB-lite for network and IoT assets**, built as a single zero-dependency binary (Go + SQLite + embedded SvelteKit SPA).

## What MiBee Steward is NOT (intentional boundaries)

MiBee Steward deliberately does NOT build capabilities that mature tools already do better. These are **product boundaries, not gaps**:

| Capability | Use instead | Why we don't build it |
|---|---|---|
| Alerting | Prometheus Alertmanager | We expose data via `/metrics`; Alertmanager decides what/when to alert |
| Dashboards / visualization | Grafana | Built-in ECharts is for asset overview only, not a Grafana replacement |
| Status pages | Uptime Kuma | Different problem space; that's its core competency |
| Host-deep monitoring (CPU/RAM/disk) | Netdata / node_exporter | We discover node_exporter; we are not node_exporter |
| Service-layer discovery | Consul / eureka | We discover devices (L2-L4), not service instances (L7) |

If you need any of the above, deploy the listed tool alongside MiBee Steward — they consume our `/metrics` and `/sd` endpoints natively.

## Core capability

**Auto-discovery + identity inference + registry** for network and IoT devices.

The differentiation is **identity inference accuracy and breadth**: recognizing "this IP is a Hikvision camera, that one is a Huawei switch, that one is an APC UPS, that's a Raspberry Pi" via protocol fingerprints. This is built over time via a community-contributable fingerprint/rule library.

## Derived capabilities (byproducts of accurate asset data)

- **Heartbeat** — keeps the asset registry fresh (online/offline + latency + history). **Not** for alerting — for asset freshness. Heartbeat data flows to Prometheus via `/metrics`; Alertmanager handles alerting.
- **Prometheus outlet** — `/metrics` (asset state gauges + heartbeat counters) + `/sd` (HTTP service discovery for auto-registering assets in Prometheus)
- **Single-binary deploy** — zero runtime deps, CGO-free, cross-compiles to linux/amd64 + arm64

## Where MiBee Steward fits

MiBee Steward sits at the intersection of established categories, none of which is its body:

| Category | Examples | What they miss |
|---|---|---|
| Asset registry (CMDB) | NetBox, Snipe-IT | Manual entry — no auto-discovery |
| Service discovery | Consul, eureka | L7 services, not L2-L4 devices |
| Scanner | nmap | No management UI, no continuous registry, no identity inference |
| Network monitoring | LibreNMS, Zabbix | SNMP-heavy, monitoring-oriented, no identity inference |

**MiBee Steward's unique cell**: auto-discovery (nmap-grade) + identity inference (fingerprint-based) + registry/management (CMDB-lite) + single-binary. None of the categories above occupy this combination.

> **Common misconception**: MiBee Steward is sometimes compared to lightweight monitoring tools like Beszel / Uptime Kuma / Netdata. That's a category error — those tools monitor hosts/services you already know about; MiBee Steward discovers what's there in the first place.

## Use cases

- **Network asset inventory** — automatically discover and catalog what's on your network, with brand/model identification
- **IoT / camera fleet discovery** — identify IP cameras, sensors, controllers by brand/model. (Camera is a current priority scenario because RTSP+ONVIF fingerprints are crisp and demand is concrete — not because MiBee Steward is camera-specific.)
- **Branch / SOHO network mapping** — lightweight enough for small networks where LibreNMS is overkill
- **Lab / edge asset tracking** — track research or edge devices with flexible probe configs and continuous freshness

## Design principles

1. **Single binary, zero runtime deps** — `scp` and run. No Docker/DB/Node required.
2. **CGO-free** — cross-compiles to linux/amd64 + arm64.
3. **Prometheus-native outlet** — asset data flows into the Prometheus ecosystem; we don't compete with it.
4. **Plugin-based discovery** — add a protocol by registering one classifier + one handler (see `scannerv2/` architecture).
5. **Identity inference is the differentiator** — investment priority is fingerprint/rule library breadth and accuracy.
6. **Boundaries are features** — what we don't build is as deliberate as what we build. Don't reinvent Alertmanager/Grafana/Kuma inside MiBee Steward.
