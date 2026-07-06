# MiBee Steward Documentation

Comprehensive documentation for MiBee Steward — device/network-layer asset discovery, identification, and registry (CMDB-lite for network and IoT assets).

MiBee Steward automatically discovers what devices are on a network, infers what they are (type/brand/model via protocol fingerprints), and registers/tracks them over time. Asset state flows to the Prometheus ecosystem via `/metrics` and `/sd`; alerting and visualization are intentionally left to Alertmanager and Grafana. See [Product Scope & Boundary](en/product-scope.md) for what MiBee Steward does and does not build.

## Navigation
Documentation is available in both English (English) and Chinese (中文). Each section provides comprehensive coverage of its topic with practical examples and best practices.

## English Documentation

- [Product Scope & Boundary](en/product-scope.md) — What MiBee Steward is, is NOT, and where it fits
- [Introduction](en/introduction.md) — Project overview and features
- [Quick Start](en/quick-start.md) — Get running in 5 minutes
- [Architecture](en/architecture.md) — System design and data flow
- [API Reference](en/api.md) — REST API documentation
- [Deployment](en/deployment.md) — Production deployment guide
- [Development Guide](en/development-guide.md) — Contributing and coding conventions
- [Configuration](en/configuration.md) — Configuration reference

## 中文文档

- [产品范围与边界](zh/product-scope.md) — MiBee Steward 是什么、不是什么、它的位置
- [项目概述](zh/introduction.md) — 项目概述与功能
- [快速开始](zh/quick-start.md) — 五分钟快速开始
- [系统架构](zh/architecture.md) — 系统架构与设计
- [API 参考](zh/api.md) — REST API 参考文档
- [部署指南](zh/deployment.md) — 生产环境部署指南
- [开发指南](zh/development-guide.md) — 开发指南与贡献规范
- [配置参考](zh/configuration.md) — 配置参考文档

[← Back to root README.md](../README.md)