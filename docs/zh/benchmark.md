# 基准测试

MiBee Steward 的规模与准确率证据 —— 合成负载 harness（`cmd/loadgen`）、nmap 对比脚本，及其方法学。

## 合成规模 harness

`loadgen` 在回环网络上模拟一整个设备局域网，无需任何虚拟机：每台合成设备占一个独立的 `127.x.y.z` 地址 —— ICMP 由内核免费应答，各模板的 TCP/UDP responder 以真实载荷形态模拟 SNMP v2c agent、HTTP 服务器、SSH 式 banner 与 RTSP 服务器。扫描器的探测、分类与写路径**原样运行** —— 测的是真实管线，不是 mock。

设备类别为确定性加权混合（摄像头/路由器/服务器/NAS/IoT/打印机），识别压力与各类别端口布局贴近真实。

### 运行一次基准

在运行 center 的机器上（知名端口 22/80/161/554 需要 `CAP_NET_BIND_SERVICE`，即以 root 运行 —— 与扫描器 ICMP 的要求相同）：

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
- `mibee_sqlite_busy_total` 差值（合成负载下的单写者竞争 —— #267 可观测线）
- center 进程 CPU 秒与运行结束时常驻内存
- `GET /api/v1/devices` 突发的 p50/p95/max 延迟

扩大规模：`--devices 10000 --base 127.8.0.0` + `--targets 127.8.0.0/19`。超大规模注意监听 socket 数量（文件描述符）。

## 与 nmap 的准确率对比

`scripts/bench-accuracy.sh <CIDR> [center_url]` 对同一子网分别跑 MiBee 与 `nmap -sn`，将存活集差分为混淆矩阵：

- **recall** —— nmap 找到的主机中 MiBee 也找到的比例（"不漏报"维度）
- **precision** —— MiBee 找到的主机中 nmap 确认的比例
- **MiBee-only 主机** 单独列出：MiBee 的 TCP 探测扇出刻意计入只应答 TCP connect 的主机（无 root/ARP 的 `nmap -sn` 会漏）—— 这里的盈余是特性而非误差，但值得人工过目。

依赖 `nmap`、`curl`、python3；凭据经 `MIBEE_USER` / `MIBEE_PASS` 传入。

## 方法学注意事项

- 回环面没有丢包、延迟与 ARP —— 墙钟扫描时长会低估真实局域网；DB 写入负载、识别工作量与 API 延迟具有代表性。
- **127/8 内所有地址都应答 ICMP**（内核行为），存活数 = 扫描地址数而非合成设备数 —— 面上的存活数字衡量管线吞吐而非发现精度；识别计数（经 RTSP/HTTP 判定的摄像头等）才是有意义的准确率信号。
- `loadgen serve` 的 SNMP 对整个面返回同一 sysDescr（UDP 无每连接状态）；识别压力来自 TCP 侧（banner / HTTP title / RTSP）。
- 持续负载实验（写路径竞争）：连续触发多轮扫描并抓取 `mibee_sqlite_busy_total`。
