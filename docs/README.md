# MiBee Steward Documentation

Comprehensive documentation for MiBee Steward — device/network-layer asset discovery, identification, and registry (CMDB-lite for network and IoT assets).

MiBee Steward automatically discovers what devices are on a network, infers what they are (type/brand/model via protocol fingerprints), and registers/tracks them over time. Asset state flows to the Prometheus ecosystem via `/metrics` and `/sd`; alerting and visualization are intentionally left to Alertmanager and Grafana. See [Product Scope & Boundary](en/product-scope.md) for what MiBee Steward does and does not build.

Documentation is maintained bilingually: `zh/` (中文) and `en/` (English) are structurally aligned, page for page.

## Manual (14 pages per language)

### 入门 / Getting Started

- [产品介绍 / Introduction](zh/introduction.md) · [EN](en/introduction.md) — project overview, capabilities, scope & boundaries
- [快速开始 / Quick Start](zh/quick-start.md) · [EN](en/quick-start.md) — first deployment and scan within minutes
- [Web 界面巡礼 / Web UI Tour](zh/web-ui.md) · [EN](en/web-ui.md) — every UI area with screenshots
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
- [更新日志 / Changelog](zh/changelog.md) · [EN](en/changelog.md) — the root `CHANGELOG.md` (EN) plus its hand-maintained Chinese translation (update together)

### 其他 / Extras

- [产品范围与边界 / Product Scope](zh/product-scope.md) · [EN](en/product-scope.md) — what it is, is not, and where it fits

## Conventions

- **Single source of truth**: this directory IS the manual. The MiBee Studio website docs center (www.mlsbs.top/#/docs/mibeesteward/) syncs from `docs/{zh,en}/` automatically — the website mirrors the repo, never the other way around.
- **Website sync mechanics**: the site pulls `docs/{zh,en}/` into `public/docs/mibeesteward/{zh-CN,en-US}/` via its `sync-docs.ps1` script (slug = filename, 1:1). Keep filenames stable; **renaming/moving/deleting a page requires an issue** so the website's `ArticleMap` and `manifest.json` can be updated in lockstep — a silent rename becomes a 404 on the site. In-manual cross-links use bare `slug.md`; targets outside the collection use absolute links.
- **Changelog docs**: `en/changelog.md` is a **generated** verbatim copy of the root [CHANGELOG.md](../CHANGELOG.md) — never hand-edit it; run `make docs-changelog-sync` after editing `CHANGELOG.md`. `zh/changelog.md` is a **hand-maintained Chinese translation** of the same content (the website publishes it verbatim as the zh manual's changelog page, so it must be actual Chinese, not an English mirror). After changing `CHANGELOG.md`, update the translation in the same PR — the sync script's coverage check (identical version-header sets on both sides) and the CI `docs` job fail on drift. Keep code identifiers, config keys, API paths, and issue numbers verbatim.
- **Fence languages**: every code fence carries a language annotation (`go`, `bash`, `yaml`, `mermaid`, …; plain output as `text`) — enforced by markdownlint MD040 in the CI `docs` job, because the website's highlight.js rendering degrades to monochrome without it.
- **Diagrams**: use Mermaid fenced blocks; do not use ASCII-art diagrams.
- **Screenshots**: WebP, 1440×900 viewport, light theme, stored under `{zh,en}/images/` and referenced with relative paths (`images/foo.webp`) — the website sync script downloads relative image srcs into the site automatically. Every screenshot must be **sanitized**: demo-safe IPs (`192.168.1.x` / `192.168.2.x`), generic device names, no real MACs/hostnames/credentials. Capture via `scripts/docs_sanitize_proxy.py` (reverse proxy that rewrites API responses) and audit before publishing.
- **Public docs only**: content here is published — never include private infrastructure details, credentials, or unreleased strategy.

[← Back to root README.md](../README.md)
