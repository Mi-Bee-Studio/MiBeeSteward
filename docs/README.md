# MiBee Steward Documentation

Comprehensive documentation for MiBee Steward — device/network-layer asset discovery, identification, and registry (CMDB-lite for network and IoT assets).

MiBee Steward automatically discovers what devices are on a network, infers what they are (type/brand/model via protocol fingerprints), and registers/tracks them over time. Asset state flows to the Prometheus ecosystem via `/metrics` and `/sd`; alerting and visualization are intentionally left to Alertmanager and Grafana. See [Product Scope & Boundary](en/product-scope.md) for what MiBee Steward does and does not build.

Documentation is maintained bilingually: `zh/` (中文) and `en/` (English) are structurally aligned, page for page.

## Manual (13 pages per language)

### 入门 / Getting Started

- [产品介绍 / Introduction](zh/introduction.md) · [EN](en/introduction.md) — project overview, capabilities, scope & boundaries
- [快速开始 / Quick Start](zh/quick-start.md) · [EN](en/quick-start.md) — first deployment and scan within minutes
- [设备发现与识别 / Discovery](zh/discovery.md) · [EN](en/discovery.md) — probe sources, fingerprint rules, OUI, identity model
- [架构总览 / Architecture](zh/architecture.md) · [EN](en/architecture.md) — layering, scannerv2 engine, background tasks

### 部署与配置 / Deployment & Configuration

- [单机部署 / Standalone Deployment](zh/deployment.md) · [EN](en/deployment.md) — binary, systemd, Docker, Nginx, backups
- [OpenWrt 部署 / OpenWrt Deployment](zh/openwrt.md) · [EN](en/openwrt.md) — router-center and router-agent forms
- [分布式部署 / Distributed](zh/distributed.md) · [EN](en/distributed.md) — center + agents, lease & anti-entropy model
- [配置参考 / Configuration](zh/configuration.md) · [EN](en/configuration.md) — every config key and `MIBEE_*` env override

### 参考与进阶 / Reference & Advanced

- [API 参考 / API Reference](zh/api.md) · [EN](en/api.md) — REST endpoints, auth regimes, examples
- [eBPF 被动观测 / eBPF Observer](zh/ebpf.md) · [EN](en/ebpf.md) — passive TC-based observation
- [指纹库适配器规范 / Fingerprint Spec](zh/fingerprint-spec.md) · [EN](en/fingerprint-spec.md) — normative rule-format specification
- [开发与贡献 / Development](zh/development.md) · [EN](en/development.md) — environment, conventions, CLA/DCO
- [更新日志 / Changelog](zh/changelog.md) · [EN](en/changelog.md) — mirror of the root `CHANGELOG.md` (update together)

### 其他 / Extras

- [产品范围与边界 / Product Scope](zh/product-scope.md) · [EN](en/product-scope.md) — what it is, is not, and where it fits

## Conventions

- **Website sync**: the MiBee Studio website (www.mlsbs.top) mirrors this manual from `docs/{zh,en}/` into `public/docs/mibeesteward/{zh-CN,en-US}/` via its `sync-docs.ps1` script (slug = filename, 1:1). Keep filenames stable — renaming a page breaks the site's `manifest.json`.
- **Changelog mirror**: `en/changelog.md` is a verbatim copy of the root [CHANGELOG.md](../CHANGELOG.md); `zh/changelog.md` is the same content behind a Chinese note. Refresh both when `CHANGELOG.md` changes.
- **Diagrams**: use Mermaid fenced blocks; do not use ASCII-art diagrams.
- **Public docs only**: content here is published — never include private infrastructure details, credentials, or unreleased strategy.

[← Back to root README.md](../README.md)
