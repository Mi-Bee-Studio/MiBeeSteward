# MiBee Steward

[![CI](https://github.com/Mi-Bee-Studio/MiBeeSteward/actions/workflows/ci.yml/badge.svg)](https://github.com/Mi-Bee-Studio/MiBeeSteward/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/mibee-steward.svg)](https://pkg.go.dev/mibee-steward)
[![Go Report Card](https://goreportcard.com/badge/github.com/Mi-Bee-Studio/MiBeeSteward)](https://goreportcard.com/report/github.com/Mi-Bee-Studio/MiBeeSteward)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue)](https://polyformproject.org/licenses/noncommercial/1.0.0)
[![Frontend: SvelteKit 5](https://img.shields.io/badge/Frontend-SvelteKit%205-FF3E00?logo=svelte&logoColor=white)](https://svelte.dev)

[English](README.md) | **中文**

**设备/网络层的资产发现、识别与登记** —— 面向网络与 IoT 资产的轻量 CMDB。自动发现网络上的设备，通过协议指纹识别品牌/型号，并持续跟踪。单个零依赖二进制；资产状态通过 `/metrics` + `/sd` 流向 Prometheus 生态。告警/可视化有意留给 Alertmanager/Grafana。Go 后端 + SvelteKit 前端。

## 功能特性

- **设备管理**：添加、配置并监控网络设备
- **多协议探测**：SNMP、ICMP、TCP、HTTP 监控
- **设备系统管理**：每台设备可挂载多个已安装系统（含入口 URL），以带分类徽章的卡片网格展示
- **网络扫描器（v2）**：基于插件的 5 层架构（探测 → 分类 → 处理 → 持久化 → 编排），支持级联深度采集。可识别 SSH/HTTP/RTSP/ONVIF/SNMP/Prometheus/node_exporter，并推断设备类型与品牌（例如根据 RTSP+ONVIF 识别为摄像头）。扩展方式：注册一个 Classifier + 一个 Handler 即可接入新协议
- **eBPF 被动观测器**：可选的 TC ingress 程序，嗅探 ONVIF WS-Discovery 组播与 TCP 特征字节，作为旁证数据源（构建标签门控；默认构建无此依赖）
- **心跳监控**：可配置探测间隔，自动失败检测
- **Prometheus 集成**：`/metrics` 指标端点用于监控，`/sd` HTTP 服务发现用于自动发现
- **内嵌 Web 界面**：SvelteKit SPA，实时仪表盘
- **JWT 认证**：基于角色的访问控制（admin / user）
- **多语言支持**：中英双语，基于 @inlang/paraglide-js
- **审计日志**：完整的操作追踪
- **单二进制部署**：前端通过 go:embed 嵌入

## 技术栈

### 后端
- **Go 1.26+**，使用 Chi v5 Web 框架
- **SQLite**，通过 modernc.org/sqlite 实现（CGO_ENABLED=0，纯 Go）
- **sqlc** 生成类型安全的数据库查询代码
- **koanf/v2** 配置管理
- **JWT 认证**，使用 go-chi/jwtauth

### 前端
- **SvelteKit 5**，基于文件的路由
- **Tailwind 4** 样式
- **ECharts** 数据可视化
- **@inlang/paraglide-js** 国际化

### 基础设施
- **Prometheus 指标**集成
- **Systemd** 服务部署
- **Nginx** 反向代理 + TLS
- **Docker** 容器化支持

## 快速开始

### 开发
```bash
# 克隆仓库
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward

# 安装前端依赖
cd web && npm install
cd ..

# 启动开发服务器
make dev
```

### 生产构建
```bash
# 生产构建
make build

# 跨平台编译
make build-all
```

### 首次运行
1. 应用会在 `./data/mibee.db` 创建 SQLite 数据库
2. 通过配置中的 `auth.initial_admin_password` 设置强管理员密码（生产环境必需）
3. **重要**：生产环境切勿使用默认或弱密码

## 文档

- [项目概述](docs/zh/introduction.md) — 项目概览与功能
- [快速开始](docs/zh/quick-start.md) — 五分钟上手
- [系统架构](docs/zh/architecture.md) — 系统设计与数据流
- [API 参考](docs/zh/api.md) — REST API 文档
- [部署指南](docs/zh/deployment.md) — 生产环境部署指南
- [开发指南](docs/zh/development-guide.md) — 贡献与编码规范
- [配置参考](docs/zh/configuration.md) — 配置参考

## 配置

应用使用 YAML 配置文件，并支持环境变量覆盖。可用选项见 `configs/config.example.yaml`：

```yaml
server:
  port: 8080
  host: 0.0.0.0

database:
  path: ./data/mibee.db

metrics:
  enabled: true
  path: /metrics
```

以 `MIBEE_` 为前缀的环境变量会覆盖配置项。

## 架构

```
├── cmd/server/           # 入口
├── internal/
│   ├── api/             # HTTP 处理器与中间件
│   ├── config/          # 配置加载
│   ├── db/              # 单一 schema.sql + sqlc 生成的数据库代码
│   ├── domain/          # 业务模型
│   ├── repository/      # 数据访问层
│   └── service/         # 业务逻辑
├── web/                 # SvelteKit 前端
└── deploy/              # 部署配置
```

## 测试

```bash
# 运行所有测试
go test ./...

# 运行集成测试
make test
```

## 安全须知

- 切勿编辑 `internal/db/*.go` 文件 —— 它们由 sqlc 生成
- 使用 `.env` 文件存放密钥，切勿提交
- SQLite 启用 WAL 模式以提升性能
- 所有功能测试必须在测试服务器上进行

## 贡献

1. Fork 本仓库
2. 创建功能分支
3. 进行修改
4. 为新功能添加测试
5. 运行 `make test` 确保一切正常
6. 提交 Pull Request

## 许可证

本项目基于 [PolyForm Noncommercial License v1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) 授权 —— 不允许商业使用。详见 [LICENSE](LICENSE)。

## 支持

如需支持，请在 GitHub 仓库中提交 issue，或联系开发团队。
