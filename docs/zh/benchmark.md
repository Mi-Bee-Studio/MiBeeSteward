# 基准测试

MiBee Steward 的规模与准确率证据，合成负载 harness（`cmd/loadgen`）、nmap 对比脚本，及其方法学。

## 合成规模 harness

`loadgen` 在回环网络上模拟一整个设备局域网，无需任何虚拟机：每台合成设备占一个独立的 `127.x.y.z` 地址，ICMP 由内核免费应答，各模板的 TCP/UDP responder 以真实载荷形态模拟 SNMP v2c agent、HTTP 服务器、SSH 式 banner 与 RTSP 服务器。扫描器的探测、分类与写路径**原样运行**，测的是真实管线，不是 mock。

设备类别为确定性加权混合（摄像头/路由器/服务器/NAS/IoT/打印机），识别压力与各类别端口布局贴近真实。

### 运行一次基准

在运行 center 的机器上（知名端口 22/80/161/554 需要 `CAP_NET_BIND_SERVICE`，即以 root 运行，与扫描器 ICMP 的要求相同）：

```bash
# 1. 构建两个二进制
go build -o bin/loadgen ./cmd/loadgen

# 2. 起设备面（例如从 127.8.0.0 起 1000 台）
sudo bin/loadgen serve --devices 1000 --base 127.8.0.0

# 3. 另一个 shell，驱动真实 center 跑一轮扫描
bin/loadgen drive --center http://127.0.0.1:8080 \
  --user admin --pass '…' \
  --targets 127.8.0.0/22 --out bench-1k
```

`drive` 经 HTTP API 登录 → 创建禁用的异步扫描任务 → 触发 → 等待完成，并在运行前后采样 `/metrics` 差值。输出 `bench-1k.json`（机器可读）与 `bench-1k.md`（摘要），覆盖：

- 扫描耗时与存活主机数
- SQLite 主库增长（`mibee_db_size_bytes` 差值）
- `mibee_sqlite_busy_total` 差值（合成负载下的单写者竞争，#267 可观测线）
- center 进程 CPU 秒与运行结束时常驻内存
- `GET /api/v1/devices` 突发的 p50/p95/max 延迟

扩大规模：`--devices 10000 --base 127.8.0.0` + `--targets 127.8.0.0/19`。超大规模注意监听 socket 数量（文件描述符）。

## 与 nmap 的准确率对比

`scripts/bench-accuracy.sh <CIDR> [center_url]` 对同一子网分别跑 MiBee 与 `nmap -sn`，将存活集差分为混淆矩阵：

- **recall**，nmap 找到的主机中 MiBee 也找到的比例（"不漏报"维度）
- **precision**，MiBee 找到的主机中 nmap 确认的比例
- **MiBee-only 主机** 单独列出：MiBee 的 TCP 探测扇出刻意计入只应答 TCP connect 的主机（无 root/ARP 的 `nmap -sn` 会漏）-- 这里的盈余是特性而非误差，但值得人工过目。

依赖 `nmap`、`curl`、python3；凭据经 `MIBEE_USER` / `MIBEE_PASS` 传入。

## 极低资源实测（v0.9.0 发版前，2026-11-07）

center 能不能跑在人们真正用来跑路由器/派级硬件的资源档上？整个二进制——扫描器、SQLite、内嵌 SPA——在 cgroup v2 `systemd-run` 作用域下运行：**CPUQuota 30%**（单核的三成）+ **MemoryMax 256 MB**，再驱动千设备合成平面：

| 指标 | 数值 | 说明 |
|---|---|---|
| 启动后空载 RSS | **43 MB** | 零配置首启、全新库 |
| 千机扫描（ICMP+SNMP+port_scan，/22=1022 地址） | **446 秒，1022/1022 全发现** | 0.3 核下 ≈2.3 台/秒 |
| 扫描期间及之后 RSS 峰值 | **168 MB** | 距 256 MB 上限有余量 |
| 全程 center CPU | 88.2 秒 | ≈配额预算的 20% |
| SQLite 库增长 | **0.6 MB** | 千设备+证据 |
| `mibee_sqlite_busy_total` 增量 | **0** | 无单写者争抢 |
| 设备列表 API p50 / p95 / max（n=100） | 90.7 / 201 / 502 ms | 限配额下的分页列表 |
| 仪表盘 overview 聚合 | **7–10 ms** | 千设备全卡片 |
| `/devices/stats` | ~10 ms | |

解读：单核三成 + 256 MB 上限下，全新 center 扫完一整个 /22、仪表盘毫秒级响应、列表页保持可交互（p95 ≈0.2 秒），写路径零争抢。这是树莓派 Zero 2 W / 入门路由器的资源档——一块单板 Linux 稳跑千机 LAN 的 center；再往上，agent 扇出、center 只做聚合。

复现：`sudo systemd-run --unit=mibee-bench --property=CPUQuota=30% --property=MemoryMax=256M ./mibee-steward -config …` 后接上文 loadgen 流程；临时单元钉住限额，其余一切原样。

## 方法学注意事项

- 回环面没有丢包、延迟与 ARP，墙钟扫描时长会低估真实局域网；DB 写入负载、识别工作量与 API 延迟具有代表性。
- **127/8 内所有地址都应答 ICMP**（内核行为），存活数 = 扫描地址数而非合成设备数，面上的存活数字衡量管线吞吐而非发现精度；识别计数（经 RTSP/HTTP 判定的摄像头等）才是有意义的准确率信号。
- `loadgen serve` 的 SNMP 对整个面返回同一 sysDescr（UDP 无每连接状态）；识别压力来自 TCP 侧（banner / HTTP title / RTSP）。
- 持续负载实验（写路径竞争）：连续触发多轮扫描并抓取 `mibee_sqlite_busy_total`。

> **注意(保留网段防护):** 自 #317 起,保留地址空间(环回等)的扫描目标默认被拒绝。
> loadgen 的 `127/8` 合成设备面需要在**中心**配置 `scanner.allow_reserved_targets: true`
> (或环境变量 `MIBEE_SCANNER_ALLOW_RESERVED_TARGETS=true`)。生产环境请保持关闭 --
> 否则计划任务扫环回会造出静默清理也清不掉的幻影设备。
