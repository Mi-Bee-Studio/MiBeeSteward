# 产品范围与边界

> 本文档定义 MiBee Steward **是什么**、**不是什么**、以及它在行业中的位置。功能列表与快速上手见[项目概述](introduction.md)。

## MiBee Steward 是什么

MiBee Steward 是一个**设备/网络层的资产发现、识别与登记**工具。它回答三个问题：

1. **网络上有哪些设备？** —— 通过 ICMP / TCP 端口扫描 / SNMP / HTTP / RTSP / ONVIF / mDNS / WS-Discovery 探测自动发现，外加可选的 eBPF 被动观测
2. **它们是什么？** —— 通过 banner / HTTP / RTSP / ONVIF / SNMP / Prometheus 指纹分类，推断设备类型、品牌、型号
3. **持续跟踪** —— 登记/管理 + 基于心跳的资产鲜活度（在线/离线 + 延迟 + 历史）

它是**面向网络与 IoT 资产的轻量 CMDB**，以单个零依赖二进制交付（Go + SQLite + 内嵌 SvelteKit SPA）。

## MiBee Steward 不是什么（有意的产品边界）

MiBee Steward **有意不构建**成熟工具已经做得更好的能力。这些是**产品边界，不是缺口**：

| 能力 | 请使用 | 我们不做的原因 |
|---|---|---|
| 告警 | Prometheus Alertmanager | 我们通过 `/metrics` 暴露数据；告警什么、何时告警由 Alertmanager 决定 |
| 仪表盘 / 可视化 | Grafana | 内置 ECharts 仅用于资产概览，不替代 Grafana |
| 状态页 | Uptime Kuma | 不同的赛道，那是它的核心能力 |
| 主机深度监控（CPU/内存/磁盘） | Netdata / node_exporter | 我们发现 node_exporter；我们不是 node_exporter |
| 服务层发现 | Consul / eureka | 我们发现的是设备（L2-L4），不是服务实例（L7） |

如果你需要上述任何能力，把对应工具与 MiBee Steward 一起部署即可——它们原生消费我们的 `/metrics` 和 `/sd` 端点。

## 核心能力

**自动发现 + 身份识别 + 登记**，面向网络与 IoT 设备。

差异化在于**身份识别的准确度与广度**：通过协议指纹认出"这台 IP 是海康摄像头、那是华为交换机、那是 APC UPS、那是树莓派"。这通过社区可贡献的指纹/规则库随时间积累构建。

## 衍生能力（准确资产数据的副产品）

- **心跳** —— 保持资产登记鲜活（在线/离线 + 延迟 + 历史）。**不是**为了告警，是为了资产鲜活度。心跳数据通过 `/metrics` 流向 Prometheus；告警由 Alertmanager 处理。
- **Prometheus 出口** —— `/metrics`（资产状态指标 + 心跳计数器）+ `/sd`（HTTP 服务发现，自动把资产注册到 Prometheus）
- **单二进制部署** —— 零运行时依赖，CGO-free，可交叉编译到 linux/amd64 + arm64

## MiBee Steward 的位置

MiBee Steward 站在已有类别的交叉点，**这些类别都不是它的本体**：

| 类别 | 例子 | 它们缺失的 |
|---|---|---|
| 资产登记（CMDB） | NetBox、Snipe-IT | 手动录入 —— 无自动发现 |
| 服务发现 | Consul、eureka | L7 服务，不是 L2-L4 设备 |
| 扫描器 | nmap | 无管理界面、无持续登记、无身份识别 |
| 网络监控 | LibreNMS、Zabbix | SNMP 重、监控导向、无身份识别 |

**MiBee Steward 的独特格子**：自动发现（nmap 级）+ 身份识别（基于指纹）+ 登记/管理（CMDB-lite）+ 单二进制。上述类别都没有占据这个组合。

> **常见误解**：MiBee Steward 有时被拿来与轻量监控工具（Beszel / Uptime Kuma / Netdata）比较。这是类别错误 —— 那些工具监控你已经知道的主机/服务；MiBee Steward 是去发现"那里到底有什么"。

## 使用场景

- **网络资产清单** —— 自动发现并登记网络上的设备，识别品牌/型号
- **IoT / 摄像头舰队发现** —— 按品牌/型号识别 IP 摄像头、传感器、控制器（摄像头是当前的优先场景，因为 RTSP+ONVIF 指纹清晰、需求明确 —— 不代表 MiBee Steward 是摄像头专属工具）
- **分支机构 / SOHO 网络画像** —— 在 LibreNMS 显得过重的小型网络中足够轻量
- **实验室 / 边缘资产跟踪** —— 用灵活的探测配置和持续鲜活度跟踪研究或边缘设备

## 设计原则

1. **单二进制，零运行时依赖** —— `scp` 后运行。无需 Docker/数据库/Node。
2. **CGO-free** —— 可交叉编译到 linux/amd64 + arm64。
3. **Prometheus 原生出口** —— 资产数据流入 Prometheus 生态；我们不与它竞争。
4. **插件化发现** —— 添加协议只需注册一个分类器 + 一个处理器（见 `scannerv2/` 架构）。
5. **身份识别是差异化点** —— 投入优先级是指纹/规则库的广度与准确度。
6. **边界即特性** —— 我们不做什么和我们做什么一样经过深思熟虑。不要在 MiBee Steward 内部重造 Alertmanager/Grafana/Kuma。
