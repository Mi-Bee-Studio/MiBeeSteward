# 分布式 Agent：Rust（`agent-rs`）与已下线的 Go Agent 完整对比

> **状态（2026-10-09）**：Rust agent（`agent-rs/`，cargo workspace）是**唯一的**分布式 agent。原 Go agent（`cmd/agent`）已**退役并从仓库移除**——其最后的发行版为 v0.6.0-95；两个实测节点自 2026-10-06 起已全程运行 Rust agent。本页是支撑该决策的完整工程对比，所有数据均标注测量来源。

## 为什么重写

Go agent 功能完好，但在产品真正面向的边缘硬件（ARMv7 单板机、256 MB–1 GB 内存的路由器、flash 存储）上，有几项成本始终无法消除：

- **内存下限**：Go runtime + 指纹语料编译使 agent 常驻内存停留在 40–110 MB 区间（取决于语料编译策略）——比一块 ARMv7 板子愿意分给单个守护进程的内存高出一个数量级。
- **GC 尾部抖动**：扫描 worker + GC 循环造成 RSS 锯齿波动（38–63 MB 摆幅），小机型的容量规划只能靠猜。
- **分发**：Go agent 从未以带对等测试覆盖的正式制品发布过，历次部署都是临时构建。

GitHub issue **#471** 把替换工程框定为严格 TDD，并设置了硬性验收门槛：**分类器与 Go 实现逐字节一致**（全量语料对拍）+ 与现有 center 的线上协议兼容。不搞"重写了事"——每个里程碑都挂在差分测试后面落地。

## 实测对比

### 测量方法

- **Go 基线**：来自 Go agent 在同一硬件上的生产期记录（NanoPi NEO，ARMv7，512 MB，systemd；center 的 `lan-63` 网段）。内存区间来自 2 天 96 轮观察器（2026-10-04 → 10-06）；扫描时长出自同一台账。语料急切→惰性编译的优化（指纹库 v0.1.1）**先受益的是 Go agent**——下表 Go 数字是优化后的。
- **Rust 数字**：同一块板上 `mibee-agent-rs/0.1.5` 的生产实测（2026-10-09），加上同一提交下两个 agent 的全新构建做二进制体积对齐。
- 两者均为 `-s -w`/release 构建、静态链接（无运行时依赖）、相同扫描目标与节奏。

### 二进制体积

| | Go agent | Rust agent | 倍率 |
|---|---|---|---|
| linux/armv7（部署架构） | 19,988,640 B | 4,795,716 B | **4.2×** |
| linux/arm64 | 19,464,352 B | ~4.8 MB | ~4.1× |

### 内存（同一块板、同一网段、生产流量）

| | Go agent | Rust agent | 倍率 |
|---|---|---|---|
| RSS 区间（2 天观察器 96 轮） | 38.5 – 62.8 MB | 10.9 – 12.4 MB | — |
| RSS 中位数 | 54.1 MB | 11.9 MB | **4.5×** |
| 2026-10-09 实时采样（连续运行 2 天 8 小时） | — | 12.6 MiB RSS / 11.8 MiB（systemd MemoryCurrent） | — |
| 优化前稳态（急切语料编译期） | ~110 MB | — | — |

Rust agent 的内存不光更低，而且**平**：没有 GC 锯齿——这正是小机型容量规划要的确定性。

### 扫描性能（/24，主动扫描，相同目标）

| | Go agent | Rust agent |
|---|---|---|
| 时长区间 | 142 – 165 s | 84.8 – 88.6 s（6 次新鲜采样，alive=45） |
| 相对吞吐 | 1× | **~1.7×** |

收益主要来自 Rust 引擎的探针调度与 **SNMP 门控**：L2/MIB 探针只对第一段已证明讲 SNMP 的主机运行（Go 引擎对每台非 SNMP 主机都白付数轮 walk 超时）。实测：0.1.4 加入五个 L2 探针后 /24 仍为 85 s（加之前 86 s）。

### 本地数据库足迹

| | Go agent | Rust agent |
|---|---|---|
| `agent.db` 稳态 | 40 – 47 MB（保留清扫 + VACUUM 后） | 2.58 MB（同一保留策略） |

如实说明：两个 agent 写入本地影子表的行数并不完全一致，此行是指示性的而非严格同口径。但方向没有歧义——Go agent 即便带着清扫，文件也会爬向 flash 不友好的几十 MB；Rust agent 稳在个位数 MB。

### 测试与验证深度

| | Go agent | Rust agent |
|---|---|---|
| 单元/集成测试 | 105 个测试函数（`cmd/agent` + `internal/agent`） | 172 个测试（workspace，`cargo test`） |
| 分类器对等 | 参照实现本体 | **逐字节对拍**：全量语料（约 2,600 条规则）双种子对照 Go 分类器，oracle 在库（`agent-rs/difftest/`） |
| SNMP 线上验证 | 信任库（gosnmp） | **对真实 net-snmp 差分**：v2c walk 5/5、RFC 4293 回退 5/5、v3 authPriv（SHA/AES）5/5——全部逐字节一致；与 gosnmp 跨语言互操作 11/11 |

差分测试立刻回了本：它揪出了我们自己 v3 编码器的一个潜伏 BER bug（`msgMaxSize 65535` 被编成 `FF FF` = 有符号 −1；真实 agent 会静默丢弃**我们发过的每一个** v3 报文——自测用的宽容版 echo server 永远发现不了）。已修复并加回归测试；这类 bug 正是验收门槛要设成字节级的原因。

### 代码规模（如实的成本）

| | Go agent | Rust agent |
|---|---|---|
| 代码行数 | 5,152 行（Go，借力 gosnmp/yaml.v3/Go crypto） | 15,937 行（Rust，自包含：自研 BER、SNMPv3 USM + 密钥本地化、AES-GCM vault、cron 解析器） |

3 倍的代码增长是重写两个初始动机的刻意代价：运行期内存无意外、不依赖分配行为不受我们控制的库。Go agent 把线上格式交给库，Rust agent 自己拥有它们——也拥有它们的差分测试。

## 功能对等矩阵（终态 0.1.5）

| 能力 | Go agent | Rust agent | 备注 |
|---|---|---|---|
| 六端点 center 协议（上报/轮询/命令/指纹/…） | ✔ | ✔ | 与同一套 wire 类型做契约测试 |
| 分类器（指纹语料） | 参照本体 | ✔ 逐字节一致 | 全语料对拍，语料 rev 全 fleet 共享（退役时 `86e1ff8a`） |
| SNMPv1/v2c + v3 USM（authPriv、SHA/AES、密钥本地化） | ✔（经 gosnmp） | ✔（自研实现） | 差分测试见上 |
| 凭据 vault（AES-256-GCM，密文不出机） | ✔ | ✔ | blob 格式已文档化供迁移 |
| 指纹语料同步（fpsync，rev 协商、校验后换装） | ✔ | ✔ | 同一 center 端点 |
| 本地 cron 扫描任务（robfig 5 字段语义） | ✔ | ✔ | 区间/列表/步进/日-周 OR |
| 路由器 ARP walk（legacy + RFC 4293，单飞缓存） | ✔ | ✔ | 跨网段 MAC 解析 |
| L2 拓扑探针（Bridge/Q-BRIDGE/LLDP/CDP/STP） | ✔ | ✔ | 挂 SNMP 门控（Go 对非 SNMP 主机白付超时，Rust 不付） |
| `neighbors` wire 数组 → center `device_neighbors` | ✔ | ✔ | 同一发布列车双侧落地 |
| 主机名证据通道（NBNS、TLS 证书 CN → hostname 规则） | ✔ | ✔ | 0.1.4/0.1.5 |
| hostapd/iw WiFi 站点遥测 | ✔ | ✔ | 等待带 AP 的实测环境做活体验证 |
| 上报携带心跳探针规格 | ✔ | ✔ | |
| 保留清扫 + VACUUM | ✔ | ✔ | |
| 配置（`agent.yaml` 键 + `MIBEE_` 环境变量） | ✔ | ✔ | 同构——存量 agent.yaml 无需改动即可使用 |

## 实战记录

- **2026-10-06**：两个实测节点的 agent（NanoPi NEO armv7 走 systemd，FastRhino R68S arm64 走 iStoreOS 网页包通道）切换为 Rust agent。自该时刻起，节点的识别管线就是 Rust-only。
- **0.1.0 → 0.1.5**，两节点共五次生产升级：零失败升级、零服务重启（整个窗口 `NRestarts=0`）、零扫描节奏缺失。随机 MAC 守卫、多宿主稳定性修复、TLS-CN 主机名通道都在这个窗口内发布并实测验证。
- Go agent 的最后一次生产值班是 2026-10-06 01:27 UTC（NEO）。2026-10-09 从仓库移除。

## 运维者退役须知

- **安装/升级路径**：见[分布式部署](distributed.md)。Go agent 的 OpenWrt `.ipk`/`.apk`/tarball 包形态随 `cmd/agent` 一并移除；Rust agent 目前以静态 musl 二进制交付（`make build-agent-rs`，aarch64 + armv7），路由器安装按形态分别文档化。Rust 原生 `.ipk`/`.apk` 打包是已登记的后续项。
- **配置**：存量 `agent.yaml` 无需修改即可用于 Rust agent（同键；未知键会记日志警告并忽略）。
- **本地数据**：Rust agent 的 `agent.db` 是自有 schema（v1）。Go agent 的 `agent.db` **不做迁移**——它只承载设备影子与扫描历史，center 的资产台账才是权威数据源，首次扫描即回填。
- **版本串**：Rust agent 在 center 的 fleet 视图上报 `mibee-agent-rs/x.y.z`；混合舰队过渡期内 center 同时接受旧 Go 格式。

## 发布与验证门禁

- **CI**：cargo workspace 在每个 PR 上跑独立测试任务（`agent-rs`）——全量测试套件加全语料加载，规则数断言为下限（语料只增不减）。2026-10-09 之前这套测试只在开发机上跑；该任务上线的当天就抓到一个在语料批次中静默断裂的计数 pin。
- **发版**：`v*` tag 构建静态 musl 二进制，覆盖 amd64、arm64 与 armv7，版本串在构建期由 tag 注入（`MIBEE_AGENT_VERSION`；日常构建报 Cargo.toml 版本）。制品以 `mibee-agent-linux-amd64` / `-arm64` / `-armv7` 挂上 GitHub Release，流水线还会在 runner 上执行 amd64 二进制核验版本戳。
- **实测覆盖率**：两 crate 合计 74.3% 行 / 74.6% 函数（`cargo llvm-cov`，2026-10-09，19,244 行被统计）。这个数字低估了验证强度：对等关键的分类器与 SNMP 层由全语料字节对拍和上文的真实 net-snmp 差分把门，行覆盖率看不见它们。Rust 侧的覆盖率棘轮是候选后续项，当前不是门禁。

## 已知缺口 / 后续项

- **MIPS**：Rust agent 可构建 `mipsel`（QEMU 下的对拍 oracle 在用），但 MIPS 实机未验证；center 本身也不支持 MIPS（modernc/libc）。
- **hostapd 活体验证**：WiFi STA 源在测试中解析真实 `hostapd_cli`/`iw` 抓取；仍欠一台带 AP 的实测环境。
- **Rust agent 路由器包**（`.ipk`/`.apk` + LuCI 集成）：Go 打包脚手架随下线一并移除而非半吊子转换；原生包落地前，tarball + init 脚本是文档化的安装路径。
