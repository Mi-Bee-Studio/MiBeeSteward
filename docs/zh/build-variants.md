# 构建变体与能力矩阵

MiBee Steward 以单一二进制、多种构建变体发布。**默认构建零特权、零内核依赖**：Go 能编译的平台就能跑，不需要任何 capability；所有特权能力都被编译为 no-op stub，因此没有"降级失败"一说。可选能力通过构建标签引入，每个标签都有明确的特权代价。

## 变体总览

| 变体 | 标签 | 产物 | 运行时特权 |
|---|---|---|---|
| **default** | — | `mibee-steward-linux-<arch>`、Docker 镜像、OpenWrt 软件包 | 无 |
| **full** | `WITH_LLDP,WITH_CDP,WITH_ARPSCAN` | `mibee-steward-linux-<arch>-full`（发布附件，#502） | `CAP_NET_RAW` |
| **eBPF** | `WITH_EBPF` | 仅本地构建（`make build-with-ebpf`）——构建期需要 clang ≥14 | root，或 ambient `CAP_BPF` + `CAP_NET_ADMIN`（因内核而异，见 [ebpf.md](ebpf.md)） |
| 单能力 | 单独 `WITH_LLDP` / `WITH_CDP` / `WITH_ARPSCAN` | 本地构建（`make build-with-lldp` 等） | `CAP_NET_RAW` |

所有变体均 CGO-free、可干净交叉编译；可选源全部为纯 Go 实现（经 `syscall` 的原始套接字），这也是它们构建期仅限 Linux 的原因。

校验和：发布附件中的 `SHA256SUMS.center` 覆盖两个变体的全部 center 二进制，文件名全部平铺——`sha256sum -c SHA256SUMS.center` 在任意下载目录可用（与 agent 的 `SHA256SUMS.agent-rs` 同一规则）。

## 每个标签换到什么

| 标签 | 能力 | 需要 | 内核 | 产出的数据 | 配置 |
|---|---|---|---|---|---|
| `WITH_LLDP` | 被动 LLDPDU 监听（ethertype 0x88cc） | `CAP_NET_RAW`（AF_PACKET） | Linux | `lldp_frame` 源：邻居边 → `device_neighbors`，下次扫描物化为拓扑边；系统名/描述证据。已知缺口：邻居行要求本机设备行带 MAC（#522） | `scanner.discovery.lldp_interfaces`（空 = 所有 UP 接口） |
| `WITH_CDP` | 被动 Cisco CDP 监听（ethertype 0x2000） | `CAP_NET_RAW`（AF_PACKET） | Linux | `cdp_frame` 源：邻居边 + Device ID / Platform / 软件版本证据（与 LLDP 同一本地锚点缺口，#522） | 与 LLDP 同一接口列表 |
| `WITH_ARPSCAN` | 主动 ARP 扫描：对网络 CIDR 内每个 IP 发 who-has，以应答发现主机 | `CAP_NET_RAW`（原始套接字） | Linux | 每个应答主机一个 `NewHostEvent`——唯一无需路由器访问就能覆盖整个广播域的源 | `scanner.discovery.arp_scan.enabled` + `scanner.arp_scan.interface` |
| `WITH_EBPF` | TC 被动观测器：8 种协议签名（banner、WS-Discovery、DHCP、TLS SNI、mDNS、SSDP） | root 或 ambient caps | Linux ≥ 6.6（TCX） | `passive:ebpf:tc` 证据行，驱动指纹分类 | `scanner.ebpf.enabled` + `scanner.ebpf.interfaces`——详见 [ebpf.md](ebpf.md) |

**ARP 扫描语义**（启用前值得了解）：扫描对 `network.cidr` 内每个地址广播 ARP who-has 请求，跟随 discovery 服务的节奏——每个 discovery 轮次触发一次，并非常驻泛洪。任何有网络栈的主机都会应答 ARP，包括丢弃一切入站探测的被防火墙保护的主机，这正是它的价值。流量可见性为每轮每地址一个广播帧。

## 授予 CAP_NET_RAW

systemd 部署加一个 drop-in（`systemctl edit mibee-steward`）：

```ini
[Service]
AmbientCapabilities=CAP_NET_RAW
```

Docker：`docker run --cap-add=NET_RAW …`（`host` compose profile 才用得上）。

缺少该 capability 时，`full` 二进制只是在源注册时跳过特权源（日志说明原因）；服务本体与全部默认源照常工作。`mibee-steward doctor` 逐源报告状态：`ok`（已构建且 capability 在位）、`warn`（已构建但缺 capability，或已配置但未构建）、`skip`（未构建 / 未启用 / 非 Linux）。

## 为什么 eBPF 不在发布矩阵里

eBPF 观测器的 BPF 对象在构建期由 bpf2go 从 `bpf/tc_ingress.c` 编译——该步骤需要 clang ≥ 14，发布 runner 未安装。`make build-with-ebpf` 可在任意 OS 本地完成并内嵌对象；产物与默认构建同样可移植（CO-RE free，无内核 BTF 也能加载）。见 [ebpf.md](ebpf.md)。
