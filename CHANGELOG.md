# Changelog

All notable changes to MiBee Steward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-07

First public release. MiBee Steward is a device management & network-layer
auto-discovery system with an embedded SvelteKit SPA, packaged as a single
binary.

### Core capabilities
- **Network discovery**: plugin-based scanner v2 (ICMP, TCP portscan, SNMP,
  RTSP, ONVIF, HTTP, ARP, UDP-discovery) with 5-layer pipeline
  (probe → classify → handler → persist).
- **Identity inference**: device type/vendor/OS/hostname inferred from scan
  evidence (cameras, servers, switches, routers, NAS, etc.).
- **Device registry**: full CRUD, batch operations, CSV export, custom
  attributes, document linking, device-systems grouping.
- **Heartbeat monitoring**: asset-freshness probing (ICMP/TCP/HTTP/SNMP) with
  dedicated time-series store, in-memory status cache, WAL-isolation-safe sync.
- **Authentication**: JWT (cookie + Bearer), 2FA (TOTP), login lockout, token
  blacklist, RBAC (admin/user).
- **Dashboard**: configurable widgets, Prometheus-backed time-series charts.
- **Audit logging**: all admin actions recorded.
- **Prometheus integration**: `/metrics` + `/sd` (HTTP service discovery).
- **Notification channels**: webhook/email channel management with test dispatch.
- **i18n**: Chinese and English, fully translated.

### Deployment
- Single binary (CGO-free, SQLite via modernc.org/sqlite), embedded SPA.
- Docker (multi-stage, non-root), systemd unit, nginx reverse-proxy config.
- Configurable data retention sweeper for all high-volume tables.
- CLI: `mibee-steward -version`, `mibee-steward reset-admin-password`.

### Known limitations
- Single-instance (SQLite). Distributed/multi-network mode is future work.
- No built-in alerting engine — alerting is intentionally out of scope
  (integrate with Alertmanager/Uptime Kuma).
- eBPF passive observer requires a special build (`make build-with-ebpf`) and
  runtime privileges.
