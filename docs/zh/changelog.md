# 更新日志

本页是仓库根目录 [CHANGELOG.md](../../CHANGELOG.md) 的**中文版**，与英文原文逐版本对应维护（技术名词、配置键、API 路径、议题编号保留原文）。新增或修改英文条目后请在同一 PR 内更新本页 —— `make docs-changelog-sync` 会校验两侧版本清单一致，CI `docs` 任务据此拦截漂移。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]（未发布）

### 新增

- **多视角拨测的 UI 落地（#277，补齐中心侧剩余部分）**：agent 侧执行通道此前已合入（#344 —— 拨测计划经命令通道下发到 agent，结果经 `/agents/probe-report` 回流，按视角分轨存储并带 `mibee_probe_*{vantage=…}` 标签），但 SPA 对此一无所知。拨测页现在端到端支持视角：目标表单新增**视角选择器**（中心 / 中心+全部 agent / 指定已注册 agent —— 选项由 `networks.agent_id` 构建；未注册的 `agent:{id}` 值仍会带标记回显，编辑不会静默改写计划；选 `all` 且无已注册 agent 时给出提示）；目标列表把计划显示为徽标（`all` / `agent:{id}` 原样显示；中心默认保持安静的纯文本）；仅 agent 的目标禁用手动**立即拨测**按钮（引擎对 `ErrProbeVantageNotLocal` 返回 409 —— 按钮状态如今与实际一致）；历史弹窗新增**各视角最新结果面板** —— 并排展示每个执行者的最新结果与延迟、采样数，各轨判定不一致时整个面板高亮（这正是多视角存在的意义："从 A 可达、从 B 不可达"）。结果表新增视角列。套件中首批开弹窗的测试还顺手修了一个潜伏的 jsdom 缺口（共享 setup 里的 `Element.animate` 桩 —— svelte/transition 委托给 WAAPI）。
- **Agent mini-schema 漂移防护（#171 安全网批次）**：agent 的本地 SQLite schema 是**手工**镜像 `db/schema.sql` 的（`CREATE TABLE IF NOT EXISTS` 从不更新已有表），而 agent 复用按中心 schema 生成的 sqlc 查询 —— 单侧加列过去只会在远程 agent 运行时以 "no such column" 暴露（#337 正是这样发生的）。现在一个一致性测试逐一比对共享表（`networks`/`vlans`/`scan_tasks`/`scan_task_runs`/`scan_results`/`heartbeat_configs`/`devices`）在 `agentSchema` 与内嵌中心 schema 之间的列集，另有一个冒烟测试对新初始化的 mini-DB 实跑调度器/runner 的真实查询链（`ListEnabledScanTasks` → `CreateScanTaskRun` → `UpdateScanTaskRun` → `BatchInsertScanResults` → `ListScanResults`）。cmd/agent 覆盖率 5.2% → 11.7%（其余是 `main()` 接线）。前端：scan-results 页的首批渲染测试 —— 种子行渲染、行展开显示解析出的 SNMP 明细、运行历史页签切换（断言全部数据驱动，不断言本地化字符串）。
- **被动发现观察现在会喂给指纹分类器（#377）**：发现服务为每个 IP 维护一份"旁听到的事实"缓存 —— DHCP 租约主机名（每轮清扫刷新）、以及用与主动探测**相同**的解析器（新导出的 `probe.ParseMDNSResponse`/`ParseSSDPResponse`）解析的 mDNS/SSDP 公告 —— 每次扫描经编排器新的种子钩子把它们前插到主机的采集输出。真实网络上被动通道往往是这些信号的唯一来源（R68S 实地会话测得主动 mDNS 查询 100% 无应答，而监听器旁听到丰富的公告），因此 iot-identity 与 mdns-ssdp 规则语料如今能在实地数据上命中：一条 `viomi-waterheater-…` 租约主机名产出米家品牌/家电身份，一段旁听到的 `_smb`+`_adisk` 公告把主机判型为 nas —— 一个探测包都没发。
- **mDNS/SSDP 自公告现在可被指纹识别（#365）**：主动 mDNS 与 SSDP 探测早已产出丰富的证据（服务列表、TXT 记录、SSDP SERVER/USN/LOCATION 头），却没有任何分类器消费 —— 线接好了，最后一公里缺失。新的 `mdns-ssdp.yaml` 语料规则匹配这些字段并产出携带 type/brand/description/model 元数据的 `mdns`/`ssdp` 身份，由新的 Mdns/Ssdp handler 折入设备记录（按设备桥接契约属协议级 —— 不带 `?` 徽标 —— 但绝不覆盖更强的协议内证据）。来自 R68S PoC 的实地验证规则样本：NAS 的 avahi 服务集（`_smb`+`_adisk` → nas）、路由器的 SSDP SERVER 自报家门（`lunzn,fastrhino-r68s` → router + FastRhino）、MiniDLNA（`→ nas`），以及数据驱动的映射表：`_onvif`→camera、`_ipp`→printer、`_googlecast`/`_airplay`/`_hap`/`_esphomelib`（TXT model 透传）/`_miio`→iot，外加 Hikvision/Dahua/Synology 厂商签名。（范围说明：米家设备这些一概不公告 —— 它们的天花板仍是 #361 的主机名规则。）
- **路由器上一键开启 Tier-1 被动发现（#360）**：`install.sh` 首装生成的配置现在默认启用三个零成本的路由器常驻源（`dhcp_leases` —— 权威的主机名/MAC/IP 映射、`conntrack` —— "谁正在说话"视图、`hostapd` —— WiFi STA 列表），生成配置的健全性检查断言这些翻转；LuCI 设置页新增"被动发现"区块，四个源全部做成复选框（保存 = 重写配置 + 重启 + 健康检查，经新的 `luci-helper.sh set-passive` 完成）。`dns_log` 保持关闭 —— 它需要 dnsmasq 查询日志，页面与安装器都改为打印那一行 UCI 配置而不是静默改动 DHCP 日志。升级保留既有设置并打印提示。
- **发布产物现包含 OpenWrt 路由器包（#359）**：`release.yml` 新增 `openwrt` 作业，在 `v*` 标签上构建全部三种安装形态 —— tarball（scp + `./install.sh`）、`.ipk`（opkg）与 `.apk`（OpenWrt 24.10+ apk-tools），arm64 —— 走与 CI 冒烟（#358）完全相同的流水线，并附 `SHA256SUMS.openwrt`；只有二进制、容器镜像与路由器包全部成功才发布 Release。32 位 ARM 路由器可经 `make build-linux-arm` 本地构建。
- **OpenWrt/LuCI 打包源的 CI 闸门（#358）**：新的 `openwrt` CI 作业运行 `make check-openwrt` —— 对 LuCI 控制器做 `luac -p`（OpenWrt 24.10 的 Lua 运行时是 5.1）、对**已提交**的路由器源做 CR 字节扫描与 `sh -n`（基于 git 索引，CRLF 的 Windows 检出不会误报）—— 外加经 `make package-openwrt-ipk` 的完整打包冒烟（arm64 构建 → openwrt-stage CR 暂存防护 → mkipk.sh 组装）。R68S 实地会话（#355）证明了这类缺陷"本地绿、上路由器就死"：模板里的一个 CR 字节让 LuCI 白屏报 "unfinished string"，而 go test 永远看不到它。
- **米家生态主机名指纹 —— 为除此之外一问三不知的 IoT 提供品牌与家电识别（#361）**：新的 `iot-identity.yaml` 指纹语料文件匹配小米生态 WiFi 模块公告的 DHCP/rDNS 主机名（`viomi-waterheater-e13_miap5E55`、`yeelink-light-lamp22_mibt63AA`、`chuangmi_camera_039a01`、…），产出携带 `inferred_brand`（Viomi/Yeelight/Chuangmi/Chunmi/Smartmi/Aqara/Roborock/Xiaomi）、`appliance`（热水器 / 油烟机 / 空调 / IP 摄像头 / …）与 `ecosystem` 元数据的 `miot` 服务身份 —— `exclusive_group` 保证每个主机名恰好一条身份（厂商专属规则优先于通用的 `_miap`/`_mibt` 后缀回退）。新的 `MiotHandler` 把这些元数据折入设备字段（厂商、人类可读描述）但**不**认领设备类型 —— 主机名推断类型上的 `?` 徽标诚实地保留。在一台 iStoreOS R68S 上对 12 台真实米家设备实地验证（该环境下主机名可证明是唯一的身份通道：12/12 的 mDNS/miIO/TCP 均无响应）。`device_types.yaml` 补齐了缺失的生态关键词（yeelink/lumi/aqara/roborock/dreame/smartmi/…）。
- **扫描任务的周期预设（无需 cron 知识）**：扫描任务表单的裸 cron 输入框改为友好预设下拉（每 30 分钟 / 每小时 / 每 6 小时 / 每 12 小时 / 每天 02:00 与 04:00 / 每周一 / 每月 1 号），旁边显示生成的表达式；自定义保留裸表达式输入（供进阶用户），任意既有表达式无损往返。任务列表显示预设标签并以小字显示原始表达式。后端不变（仍是 5 字段 cron 字符串）。
- **OpenWrt/iStoreOS 上的 LuCI 集成（路由器原生入口）**：ipk/apk/tarball 现在随包附带经典 Lua 控制器 + 模板（不依赖 luci-compat/CBI，无 LuCI 时为惰性）—— LuCI 的 服务 → MiBee Steward 新增状态页（服务/健康/自启/版本/端口/DB 体积 + 打开 UI 按钮）与设置页（修改 Web 端口并自动重启 + 健康检查 —— 拒绝 80/443；按生效策略设置管理员密码；自启开关；重启）。所有特权操作都汇入单一可审计的 `/usr/lib/mibee/luci-helper.sh`，可独立调用；密码经 0600 tmpfs 文件 + `MIBEE_RESET_PASSWORD` 传递，绝不上命令行。
- **无临时密码的首启设置（空凭据引导）**：`auth.initial_admin_password` 现在可以为**空**（OpenWrt/iStoreOS 安装器默认）—— 管理员以无密码状态播种，登录页自行检测该状态（公共 `GET /auth/setup-status`）并渲染**创建管理员密码**表单以替代登录表单；`POST /auth/setup`（公共、走严格登录限流、按策略校验、一次性 —— 一旦存在任何密码就永远 409）设置凭据并直接返回完整会话（token + cookie，无需二次登录）。对引导中账户的登录尝试返回明确的 409 `setup_required`，且**不**累计失败次数。安装器不再生成/打印任何临时密码。
- **首启网页设置密码 + 设置中心（免 SSH 配置，第 1 步）**：管理员引导凭据（`auth.initial_admin_password`，含安装器随机生成的）现在以**临时**密码播种 —— 刻意绕过密码策略，首次登录强制在浏览器内（SPA 弹窗）完成修改，并由服务端闸门兜底：标志置位期间签发的 token 携带 `mcp` claim，`Authenticator` 对除变更白名单（force-password / profile GET / 2FA）外的所有已认证调用返回 403。此前违反策略的 `initial_admin_password` 只以一条 warn 失败播种 —— 全新安装可能根本没有管理员，只能靠 CLI 恢复。`PUT /auth/force-password` 现在返回未受限的新 token + 轮换 cookie。新增设置中心覆盖层（`system_settings` 表、`SettingsService`：DB 覆盖 > YAML > 默认值，内存快照 + 变更订阅者），提供 `GET/PUT /api/v1/settings/auth`（管理员、审计留痕）与 `GET /api/v1/system`（只读实例信息），以及 设置 → 安全 的 SPA 页面（带实时规则预览的密码策略表单、锁定参数调节、系统信息）。密码策略与锁定的修改在下一次校验/登录时生效 —— 无需重启。默认密码策略放宽：不再要求特殊字符（最小 8 位 + 大写 + 小写 + 数字）；可经 UI 或 YAML 重新收紧。
- **OpenWrt/iStoreOS 免 Docker 安装器**：`make package-openwrt`（tarball + 路由器上 `install.sh` —— 生成带随机 `jwt_secret` + `cookie_secure: false` 与无密码引导管理员的配置、修 `ping_group_range`、enable + start + 健康检查）、`make package-openwrt-ipk`（现代 gzip-tar feed 格式的手工 opkg 包 —— 旧式 ar 容器会被当代 opkg 拒绝 "Malformed package file"；preinst 架构闸门、postinst 复用同一套配置逻辑、卸载保留 `/etc/mibee`）、`make package-openwrt-apk`（面向 OpenWrt 24.10+ 的 apk-tools v2 格式）。`.gitattributes` 保证 shell/unit 文件在 Windows 检出下为 LF；发布打包同样归一化。
- **OpenWrt 形态 C 实机验证 + IPv6 绑定修复（#288 / #37）**：路由器中心形态在真实硬件上端到端验证（GL.iNet MT2500 / Brume 2，mt7981，aarch64）：完整引擎注册表 + 内嵌指纹语料、全部 4 个 Tier-1 路由器源产出实时数据（一条 DHCP 租约变为一台携带租约主机名的设备；conntrack + dns_log 事件流入；hostapd 干净空转）、/24 扫描 74 秒且路由器自识别为 GL.iNet、SPA 浏览器验证、RSS 约 113MB。`server.host: "::"`（文档记载的 GL 固件 v4 变通）现在真正可用 —— 旧地址拼接会产出无法解析的 `:::8090` 并导致启动崩溃循环；绑定地址现在统一走 `net.JoinHostPort`。
- **Agent 网络扫描任务（#336）**：目标地址落在 agent 托管网段内的 `scan_tasks`，现在每个 cron tick 都会向该 agent 下发一条扫描命令 —— 不再需要外部定时器或内嵌密码的脚本。下发结果落入任务的运行历史（被拒绝的下发，例如目标超出网段，会作为一条带原因的失败运行记录）。本地网络任务不受影响。
- **可配置密码策略（#332）**：`auth.password_policy`（min_length + 四类字符开关）。默认值与此前硬编码规则完全一致；部分块只覆盖其显式写出的键。
- **可配置登录锁定（#338）**：`auth.lockout`（max_failed_attempts / lock_minutes）。锁定期满后现在会重置失败计数 —— 过期后的一次误试不会再立即重新锁定（此前，持有过期密码的周期客户端可能让账户无限期处于锁定态）。账户锁定响应从 429 改为 **423** 并附带 retry-after 提示，UI 也能区分"账户已锁定"与"尝试过于频繁"。
- **设备文档 Markdown 上传与预览（#324）**：`.md` 上传（MIME 归一化 + 拒绝二进制内容）、经净化（DOMPurify）的弹窗内 GFM 预览、软删除与可用的撤销（恢复端点）、按设备列出文档的修复、`?inline=1` PDF 预览、类型化上传错误（413/415/400）。
- **合成负载压测工具（#313）**：`cmd/loadgen` 提供一个 127/8 合成设备面（内核 ICMP + SNMP/HTTP/SSH/RTSP 应答器），通过真实 API 驱动全栈基准测试；`scanner.allow_reserved_targets` 是该设备面的逃生开关。
- **演示模式（#315 / #285）**：`server.demo_mode`（或 `-demo`）在空数据库上灌入虚构的 TEST-NET 资产清单。
- **多视角拨测数据模型（#328，#277 第 1 步）**：`probe_targets.vantage` 执行计划 + 按视角分离的结果轨道。
- **多视角拨测执行通道（#344，#277 第 2 步）**：agent 本地拨测执行端到端落地 —— AgentDispatcher 每 10 秒对比各 agent 的计划指纹（规范形式的 sha256），仅在变化时下发拨测命令（稳态零命令流量；清空目标会下发一条空计划以停止 agent 侧扫描）；agent 完全本地调度拨测（首次见到的目标立即拨，之后按目标各自周期；10 秒 tick 重读计划使 CRUD 一个 tick 内生效，且中心宕机期间拨测继续）；结果经 `POST /api/v1/agents/probe-report` 回流（agent-token 认证，10 秒/32 行批量；上报者身份覆盖载荷声称的视角 —— 一个 agent 只能写自己的轨；丢弃的批量丢的是样本而非无限缓存 —— 拨测是观测不是账本）；`mibee_probe_*` 指标新增 `vantage` 标签（旧的无标签选择器仍然匹配）。
- 官网内容：功能总览 / 场景玩法指引 / 同类工具对比三篇文章，中英双语（#320）。

### 安全

- **修改密码即吊销全部既有会话（#357）**：users 表新增 `token_version` 纪元列；每个签发的 JWT 把它记为 `tv` claim，Authenticator 拒绝任何 claim 落后于当前值的 token —— 自助改密、管理员重置、首登强制改密或 CLI `reset-admin-password` 都会推进纪元，因此可能泄露的 token 在下一次请求即失效，而不是活满 24 小时过期（实地观察到：LuCI 重置密码后，旧浏览器会话仍保有完整 API 权限）。被删除用户的 token 随行消亡；纪元持久化，与内存版 JTI 黑名单不同，重启不再复活已吊销的会话。每请求开销为一次主键查询。

### 修复

- **`viomi-dishwasher-*` 主机名被误判为洗衣机**：家电关键词表先命中了 `dishwasher` 里的 `washer` 子串；现在具体条目排在通用条目之前（R68S 上 #377 全网验证时发现 —— 一轮扫描内 19 台米家设备补齐了品牌 + 家电标注）。
- **零配置部署静默缺失新指纹语料（验证 #377 时实地发现）**：引擎在无 `fingerprint_path` 时的回退加载的是独立指纹库自带的内嵌规则（v0.1.0 —— 没有 `iot-identity.yaml`、没有 `mdns-ssdp.yaml`），于是所有默认部署都在用过期语料分类，米家/mDNS/SSDP 规则从未命中 —— R68S 上实地观察到：种子的租约主机名产出了类型却没有品牌。回退现在加载 `classify` 包内嵌的语料（`make sync-fingerprints` 的副本 —— 库规则的严格超集），经 `LoadFromDir` 外的临时目录物化完成。引擎级回归测试把种子租约主机名跑过 gather/classify/dispatch 并断言带 Viomi 品牌的 `miot` 身份落到报告上。
- **ucode 桥上 LuCI 应用操作全部失灵 —— helper_call 经命令文件包装器重接（R68S 验证 #360 时实地发现）**：在 LuCI 24.10 的 luci-lua-runtime 桥上，经典 Lua 控制器可用的 exec 家族**不**做 POSIX 命令串拆分 —— luci-helper.sh 把整条命令行当成单个参数收下并落进用法回退，于是设置页的每个操作（restart/port/password/passive）都报 *_fail（桥外的独立 `lua` 对同一字符串拆分正常；模板侧 `luci.sys.exec` 也正常 —— 只有控制器上下文会弄坏）。helper_call 现在把校验过的参数行写入 cmd 文件并调用新的单词命令 `/usr/lib/mibee/luci-apply.sh` 包装器，由它重新拆分并执行 helper；退出码经 rc 文件回传。同时修复了 passive 分支把 helper 路径传两次的问题。在 iStoreOS 24.10.8/R68S 上端到端验证：passive_ok、四个源全部落进配置、服务健康重启。
- **`go test ./internal/service/scannerv2/probe` 不再拨真实网络（#364）**：超时语义测试拨打一个 TEST-NET 地址期待静默 —— 在 TUN 代理（Clash Verge 等）后面的开发机上，代理会对不可路由目标伪造 SYN 应答，把"超时"变成幻影"开放"并让套件本地失败（CI 不受影响）。端口探测背后的 TCP 拨号改为可注入函数；测试桩定 deadline-exceeded 语义并额外钉死恰好一次重试的契约。
- **LuCI 设置页不再硬编码默认密码策略（#356）**：管理员经设置中心（DB 覆盖层）放宽策略后，LuCI 页面仍在描述出厂默认（最小 8 位 + 大写 + 小写 + 数字）—— 误导了实际密码已可通过的路由器管理员。表单提示与 `pw_fail` 横幅现在都指向 管理 → 设置 → 安全 这一唯一事实源，不再复述规则。
- **SPA 从不发送 `Authorization: Bearer` —— `cookie_secure: true` + 纯 HTTP 部署整体不可用**：api client 文档记载的"cookie 优先、Bearer 回退"契约此前根本没有实现回退 —— 请求完全依赖 auth cookie。浏览器在纯 HTTP 上会静默**丢弃** Secure cookie，于是在全新路由器安装（生成的配置带 `cookie_secure: true`）上登录"成功"但后续所有已认证调用 401：强制改密弹窗永远完不成（表现为一个泛泛的会话过期错误），仪表盘直接弹回 /login。`request`/`download`/`upload` 现在都会从存储的会话附带 Bearer 头；OpenWrt 安装器额外在生成配置里强制 `cookie_secure: false`（路由器形态 = 局域网纯 HTTP）。
- **心跳 Start/Stop 生命周期竞态（关机挂死）**：`NewRouter` 以 `go heartbeatSvc.Start(...)` 启动，紧随其后的 `Stop()`（测试或快速关机）可能先于延迟的 Start 执行 —— `HeartbeatStore.Close()` 随即读到 nil cancel、跳过、并永远阻塞在 `<-done`，而迟到的 Start 又启动了无人能取消的刷新循环（实地表现为 `internal/api/routes` 全套件挂死 15 分钟；刷新 + 同步循环双双 goroutine 泄漏）。store 与 service 现在都实现了 started/stopped 生命周期状态机：未启动即 Close 直接返回不等待，Close 后/Stop 后再 Start 是空操作，双重 Start 不会孵化重复循环。回归测试钉死全部三种顺序。
- **管理员播种健壮性（首启体验）**：`seedAdminUser` 用 `==` 比较包装过的 `ErrUserExists`，"已存在则跳过"分支从未命中 —— 已初始化实例的每次重启都记一条播种失败；启动播种失败过去只是 warn（现在升为 ERROR 并附 `reset-admin-password` 补救提示）；两步播种（Register + SetMustChangePassword 硬编码 id 1）合并为一条带标志的原子 CreateUser；自助改密现在会盖 `password_changed_at`（此前只有强制/管理员路径会盖）；声明过却从未实现的 `ErrSamePassword` 校验（新密码必须异于当前密码）现在在修改/强制修改路径上真正生效；2FA 验证 cookie 不再硬编码 24 小时，与登录 cookie 一样跟随 `auth.cookie_max_age`/`token_expiry`。
- **拒绝保留网段扫描目标（#318 / #317）**：环回 / 未指定 / 链路本地 / 多播 / 广播 / 240- 开头目标在每个扫描入口（任务创建/更新、同步扫描、agent 命令下发）一律拒绝；CIDR 展开剔除网络地址与广播地址（nmap 语义，同时关掉 #254 的 .255 幽灵设备一类问题）。目标展开逻辑收敛进 `internal/cidrutil`。
- **下划线键的 `MIBEE_*` 环境变量覆盖（#334 / #331）**：从 Config 结构体推导出精确的环境变量名 → 配置键映射；此前含下划线的键（`initial_admin_password`、`allow_reserved_targets` 等）在环境变量侧静默不可达。
- **设备量表周期性刷新（#335 / #333）**：`mibee_devices_total` 不再冻结在进程启动时的快照。
- **`-demo` 携带损坏配置时不再段错误（#330 / #327）**。
- **Agent 本地库启动迁移（#339 / #337）**：agent 本地 schema 现在带全量列集（offline_since / device_uuid / ssh_credential_id / scan_tasks.network_id+credential_id）并原地升级旧库 —— 此前每次设备身份漫游/替换都会因 "no such column" 静默劣化。
- Windows 构建/测试一致性恢复（#325 / #321）；sqlite BUSY 写路径治理 + 重试指标（#311 / #267）；schema 版本门控 + 备份保留（#312 / #268）；scannerv2 store 迁移到 sqlc（#314 / #269）；仪表盘布局冻结修复（#302）；agent 舰队管理（#309 / #278）；指纹覆盖率报告（#308 / #282）；生态通知渠道 + Grafana 仪表盘（#307 / #284）；UI 内 SSE 变更流（#306 / #272）；拨测 UX 批次（#305 / #276）；VLAN 名称采集（#304 / #273）；`doctor` 子命令（#303 / #281）；OpenWrt 运维文档（#329 / #316）；文档治理批（#326）。
## [0.5.0] - 2026-08-19

**SNMPv3 + 多角色 RBAC + 设备配置备份 + 内置通知器 + 拨测 + 鲜活度时间序列。** v0.5.0 清掉了企业落地的硬门槛：**SNMPv3**（USM authNoPriv/authPriv + 加密凭据保险库）、**角色/能力 RBAC 模型与对象级网络作用域**（admin / operator / viewer + 按用户的网络授权）、**设备配置备份**（Oxidized/RANCID 风格：SSH 定时拉取 `show running-config`、版本化存储、双版本 diff、接入变更检测）、一个**极简内置通知器**（设备事件 → webhook/邮件，无需跑 Alertmanager），以及外部端点的**拨测**。底层方面，设备鲜活度改为**时间序列**（根治变更日志噪声风暴），设备身份以 `device_uuid` 贯穿各卫星表；版本收尾还包含 OUI 最长前缀厂商推断、拓扑可视化打磨、可观测性接线修复，以及一大批前端 UX/无障碍/正确性改进。

### RBAC：多角色能力模型 + 对象级网络作用域（议题 #138）

双角色模型（admin / user 一刀切的 `RequireAdmin`）被替换为**能力图 + 按网络的对象作用域** —— 解锁团队与 MSP 场景：

- **角色与能力**：`users.role` CHECK 扩为 `admin` / `operator` / `viewer`（`user` 保留为 viewer 的遗留别名）。每条路由都由一个**能力**（`CapDeviceRead`、`CapScanTrigger`、`CapDeviceWrite` 等）经新的 `RequireCapability` 中间件把关；角色映射到能力集，admin 继承一切。所有 `RequireAdmin` 调用点完成重映射，共享只读面统一要求对应的 `CapXxxRead` 能力。
- **网络授权**：新 `user_network_grants` 表 + 管理端 API（`/api/v1/users/{id}/network-grants` + `/api/v1/networks/{id}/grants`）+ 用户页 UI，用于指定非 admin 用户可见哪些网络。
- **作用域模式**（`rbac.scope_default`，默认 `open`）：`open` 模式下非 admin 可见全部网络（保留单团队行为）；`closed` 模式下非 admin **只**可见被授权的网络 —— 在整个读面上强制（设备列表/详情、扫描任务/运行/结果、变更、拓扑），未授权详情返回 `404`。admin 始终绕过作用域；未知配置值回落 `open`（防锁死的失效安全）。
- **扫描器对象作用域**：`scan_tasks.network_id` 为每个任务盖所属网络章；closed 模式下非 admin 只能查看/触发其授权网络内的任务，扫描目标的网络边界检查同样生效。
- 存量安装零波澜迁移：admin 仍是 admin，`user` 行继续按 viewer 工作，`open` 模式完整保留既有可见性。

### SNMPv3（authNoPriv / authPriv）— 议题 #135

最后一个企业硬门槛：加固环境日益禁用 v2c 社区串，而所有像样的竞品都支持 v3。

- **凭据保险库**：新 `snmp_credentials` 表存储 USM 凭据（用户名、auth 口令 + 协议、priv 口令 + 协议、安全级别），**落盘 AES-256-GCM 加密**，密钥来自 `security.master_key`（恰好 32 字节，可用 `MIBEE_SECURITY_MASTER_KEY` 覆盖）。在第一个 v3 凭据出现之前密钥是可选的 —— 既有 v1/v2c 部署完全不受影响。
- **探测支持**：SNMP 探测器的版本循环加入 `Version3`；authNoPriv（MD5/SHA/SHA-2）与 authPriv（+ AES/DES）凭据按目标尝试，所有 OID 路径在 v3 下可用 —— 8-OID 身份采集以及 LLDP-MIB / CDP-MIB / Bridge-MIB / Q-BRIDGE-MIB / STP-MIB / IF-MIB 拓扑遍历。
- **API + UI**：凭据 CRUD，写入加密、读取脱敏（口令永不回显）；扫描表单与设备页带 v3 选项和安全级别下拉。
- agent 侧 v3 有意延后（议题 #241 —— 需要分布式凭据设计）；agent 维持 v1/v2c。

### 设备配置备份 — Oxidized/RANCID 风格（议题 #137）

网络运维的标配：周期性拉取每台路由器/交换机/防火墙的 running-config，版本化、做 diff、并把配置变更接入变更检测。端到端交付（浏览器实测）；经 `scanner.config_backup.enabled` **选择开启**（默认关 —— 需要 `security.master_key` + 绑定到设备的 SSH 凭据）。

- **存储**：`device_configs`（按 `device_uuid` 版本化：fetched_at、config_hash、config_text、protocol、与前版 diff）和 `ssh_credentials`（与 SNMPv3 同一套 AES-256-GCM 主密钥加密；CRUD API 写加密读脱敏）。
- **SSH 探测引擎**（`scannerv2/configbackup`）：`golang.org/x/crypto/ssh` + 厂商命令矩阵（Juniper JunOS `show configuration | display set`；HP / Aruba / H3C / Comware `display current-configuration`；Cisco IOS/NX-OS、Arista、华为 VRP、Mikrotik 及未知设备回落 `show running-config`）与主机密钥 **TOFU**（首次使用即信任）记录。
- **服务**：定时清扫选取绑定了凭据的路由器/交换机/防火墙设备，抓取、比对，仅在变更时记录新版本 —— 变更会向 `change_log` + 进程内 Watcher 发出 **`device_config_changed`** 事件（进而喂给变更页、SSE watch 与通知规则）。
- **读取 API + UI**：`GET /devices/{id}/configs`（列表）、`/{configId}`（详情）、`/diff?a=&b=`（双版本对比）；设备详情新增 **Config History** 标签页（英文界面；中文界面为"配置历史"），带版本列表、详情弹窗与手工着色的 unified-diff 渲染。
- 真机端到端冒烟（GL-MT3000）延后到下一版 —— 代码路径完整，且已针对 API 完成浏览器验证。

### 内置通知器：设备事件 → webhook/邮件（议题 #139）

SOHO/分支用户不再需要为了收到"设备失联"邮件而搭一套 Prometheus+Alertmanager。**规则引擎**订阅变更检测 Watcher，把命中事件经既有通知分发器（webhook/邮件通道、3 个 worker、按用户的已读状态）路由出去 —— 一层薄薄的规则→通道跳转，刻意**不做**告警引擎：

- 新 `notification_rules` 表：事件类型（`device_lost` / `device_recovered` / `device_added` / `device_changed`）、作用域（全部 / 网络 / 按 UUID 的设备）、目标通道、按（规则 × 设备）防抖的 `cooldown_minutes`（默认 30）、启用开关。
- 引擎在变更检测器既有鲜活度冷却之上叠加按（规则, 设备）的冷却 —— 抖动设备不会刷屏通道。

### 设备鲜活度时间序列 + 身份加固（议题 #114 / #115 / #116 / #117 / #120 / #129）

从根上修复变更检测噪声风暴：鲜活度（在线/离线）此前被建模为离散 `device_changed` 事件，每次状态翻转都写一行（测试网络上 7 万+ 行淹没了真实变更）。

- **`device_liveness` 时间序列**（心跳库内）：每设备每 tick 一条在线/离线判定样本，走既有的缓冲写/WAL 设施。查询：`OnlineRatio`（窗口内抖动 vs 翻转信号）、`OfflineDuration`、`LivenessHistory`。可丢弃 —— `devices.status` 仍是事实源。
- **分层变更事件**：状态翻转被鲜活度层消化，不再刷 `device_changed`；真实的新增/变更/失联保持清晰。
- **`device_uuid` 作为卫星表键**：心跳目标与卫星表按键稳定的设备 UUID（而非 IP）关联，地址变化不再分叉历史。修复设备第二次扫描显示陈旧哨兵数据的回归（#129）。
- **租约清扫器抖动衰减**：agent 网络的抖动计数改为衰减而非硬清零，抖动设备会趋向失联而不是来回横跳。
- **静默设备保留**：无心跳的扫描发现设备自动清退 —— 带 MAC 的设备 `retention.silent_device_days_mac`（默认 7 天）后、无 MAC 身份 `retention.silent_device_hours_no_mac`（默认 24 小时）后。手动登记的设备永不自动删除；重新上线重置计时。
- **UI 中的鲜活度**：设备详情暴露最近发现 / 离线始于 / 最近在线。

### 拓扑可视化打磨（议题 #136）

L2 数据（LLDP/CDP/Bridge/Q-BRIDGE/STP 边）本就已是 OSS 同类中最全 —— 这次让渲染跟上：

- **分层力导向布局**：核心/汇聚/接入三层节点异色；图例兼作按层可见性过滤器。
- **搜索 + 聚焦**：输入即压暗不匹配节点；点击节点高亮其邻居并打开详情卡（IP/MAC/类型/度数）。
- **端口下钻**：边暴露来自 `topology_edges` 的本地/对端端口、VLAN 标签与 STP 角色。
- **性能**：选项重建改为增量；大图保持可交互。

### Handler/Service 章程债务清偿：4 个豁免 handler 迁移完毕（议题 #240）

最后四个直写数据库的变更类 handler（自 #166 起记录为章程债务）全部改走 service 层 —— 章程不再有存量债务行：

- **`service.NetworkService`**：网络 CRUD；raw-SQL UPDATE 的权宜方案（sqlc 截断问题）从 handler 移入 service。
- **`service.AgentTokenService`**：agent 令牌的创建/吊销/删除，含 `networks.agent_id` 的创建时盖章 / 吊销时条件清空接线。令牌**铸造**留在 HTTP 层（一次性凭据展示），以 `TokenMinter` 函数注入 —— service 层保持不依赖 api 层。
- **`service.AgentCommandService`**：入队（含扫描目标网络边界检查，现返回携带违规 IP 原文的类型化 `BoundaryError`）、确认、完成。
- **`service.ScannerResultService`**：`BulkDeleteResults`（前日期校验 + 删除）。

只读透传（List/Poll/ListAll/export）按章程许可的例外继续使用 `*db.Queries`。HTTP 表面行为不变（一处消息差异：吊销一个已吊销令牌现在返回 "agent token not found" 而非 "...or already revoked"）。`internal/api/AGENTS.md` 债务表清空。

### 指标：死采集器接线 + metrics_path 生效（议题 #238 / #239）

**HeartbeatFailures 此前是个死告警** —— `mibee_heartbeat_checks_total`（及五个兄弟指标）在 `/metrics` 注册了却从未在生产代码中递增，告警表达式恒为 0。修复方式是把采集器搬到中立包并接上生产方：

- **`internal/metrics`**（新包）：7 个 `mibee_*` 采集器搬出 `internal/api/handler`，service 层得以递增它们而不引发 handler→service→handler 导入环。`handler.MetricsHandler` / `UpdateDeviceMetrics` 行为不变。
- **心跳**：`probeAndRecord` 现在按记录结果递增 `mibee_heartbeat_checks_total{status}` 并观测 `mibee_heartbeat_latency_seconds{method}` —— `HeartbeatFailures` 告警规则终于对着真实数据求值。
- **扫描器**：运行完成/失败递增 `mibee_scanner_runs_total{status}`、观测 `mibee_scanner_duration_seconds`、向 `mibee_scanner_hosts_discovered` 累加存活主机；`mibee_scanner_tasks_total{status}` 在调度器启动与任务 CRUD 后刷新（`metrics.RefreshScannerTaskGauges`）。
- **`prometheus.metrics_path`** 现在真正生效于挂载点（此前配置里定义了却硬编码 `/metrics`；空值或非绝对路径回落 `/metrics`）。

### sqlc：生成代码与 schema.sql 重新对齐 + CI 漂移守卫（议题 #237）

仓库里的 `internal/db` 自 #233 起就处于陈旧状态（`scan_tasks.network_id` 进了 schema + 迁移却没跑 `sqlc generate`），任何一次全量再生成都会产出破坏约 10 个调用点的逐查询 Row 结构 —— PR #235 只能绕着做外科手术式合并。根因修复：

- `db/queries/devices.sql` 的全行列表现在选出 `ssh_credential_id`（6 处），`db/queries/scan_tasks.sql` 选出 `network_id`（7 处）—— 列集与表重新吻合，sqlc 恢复模型复用，且**零**调用点需要改动。`CreateScanTask` 的 INSERT 仍不设置 `network_id`（照旧由 raw SQL 在插入后盖章）。
- 全量 `sqlc generate` 对当前树幂等（全新生成产出空 diff）。
- **CI 漂移守卫**：`sqlc-verify` 任务安装 sqlc **v1.31.1**（与仓库内生成器版本一致），`sqlc generate` 在 `internal/db/` 产生 diff 即失败 —— schema/查询变更必须随附再生成后的代码。
- 手写内联 `devices` schema 的测试补上了 `ssh_credential_id` 列。

### 拨测（Synthetic Probing，第 1 期）

**对显式配置的外部端点做 blackbox 风格探测（PR #235）** —— 用户配置拨测目标（典型为互联网资源：公开 HTTPS 站点、托管邮件的 TLS 端口），按固定间隔探测，经数据库/API/UI 管理。扫描器的内网 TLS 证书采集（`CollectCertChain`）被直接复用于外部主机名（SNI 自动推导），把证书链清点能力延伸到局域网之外。

- **三张表**：`probe_targets`（name 唯一，module CHECK http/tls/tcp/icmp，interval 10–86400s、timeout 1–60s，反规范化的 last_* 结果）、`probe_results`（只追加的历史，带每次运行的证书摘要；RFC3339 字符串时间戳）、`probe_tls_certs`（每个目标**当前**的证书链，先删后插；瞬时握手失败保留上一条已知良好链 —— 区别于扫描器的当前态语义）。
- **引擎**（`internal/service/probetarget/`）：10s tick 重读启用目标，CRUD 免重启生效；下次到期时间从 `last_run_at` 恢复（无启动风暴）；8 并发探测上限；在途守卫使同一目标的定时与手动运行互斥；`POST /{id}/trigger` 同步探测并返回记录的结果。
- **模块**：http/tcp/icmp 复用共享心跳探测器（`probe.Result` 增加 `StatusCode`）；tls —— 以及 https 形态的 http —— 调 `CollectCertChain` 拿完整链（叶 + 签发者 + 信任判定 + TLS 版本/密码套件）。
- **API** `/api/v1/probe-targets`：CRUD + trigger + `/{id}/results` + `/{id}/certificates`（证书响应复用设备端点的 `tlsPortCerts` 形状，前端 `CertificateModal` 零改动可用）。RBAC：`probe:read`（viewer 起）、`probe:manage`（operator 起）。
- **Prometheus**：`mibee_probe_up`（对应 `probe_success`）、`mibee_probe_duration_seconds`、`mibee_probe_cert_expiry_timestamp_seconds`（对应 `probe_ssl_earliest_cert_expiry`）、`mibee_probe_checks_total`；`deploy/prometheus/alert_rules.yml` 内含两条示例告警规则（`ProbeTargetDown`、`ProbeCertExpiringSoon`）。
- **保留**：`retention.probe_results_days`（默认 30 天），由既有清理服务清扫。
- **前端**：`/probes` 管理页（状态/延迟/证书剩余天数徽章、启用开关、历史弹窗、证书链弹窗），中英 i18n，导航入口。
- **sqlc 注记**：查询文件注释不得含撇号 —— sqlc 的 SQLite 词法器会吞掉它并静默截断生成语句（已记入 `db/AGENTS.md`）。

### MAC 位标志：本地管理 / 多播（自第 1 期起中性化）
**对 #118 第 1 期的修正（PR #121）** —— 第 1 期把本地管理（U/L）位当作"随机化 MAC"判定，并把此类设备降级为 `(ip, network_id)` 身份。这是语义越界：按 IEEE 802 / RFC 7042，U/L 位只表示"本地管理"，**无法**区分隐私随机化（iOS/Android，不稳定）与本地固定设置（软路由 / 虚拟化 / 手工，稳定）。在测试网络上，这误标了 7 台稳定的软路由/NAS，并因身份降级把其中一台（R68s）拆到了两个网络。本次变更回退错误行为，同时保留该位作为中性观测标志。

- **身份降级回退**（`device_bridge.go` 的 `resolveDeviceIdentity`）：强制 `(ip, network_id)` 身份的 LAA 位闸门移除；设备身份回归纯 MAC 优先（仅在无 MAC 时走既有的 `(ip, network_id)` 回落）。
- **中性命名**：U/L 位报告为**"本地管理（locally administered）"**，而非"随机化"。重命名：`scan_attributes.mac_is_randomized` → `mac_is_locally_administered`；辅助函数 `store.IsLocalMAC` → `IsLocallyAdministeredMAC`；UI 徽章文案 "Randomized" → "Locally Admin."，配中性 tooltip 说明该位无法区分随机与固定。`mac_is_multicast` / `IsMulticastMAC` 不变（多播位无歧义）。
- 该标志仅作观测 —— **不**改变设备身份。完整论证（RFC 7042、IEEE 数据的许可边界等）见议题 #118 的调研评论。

### OUI 厂商推断：MA-S / MA-M / MA-L 最长前缀匹配
**确定性的 MAC 富化** —— OUI 查询现在通过三注册库的**最长前缀匹配**把 MAC 解析到 IEEE 注册厂商：MA-S（/36，9 位十六进制，前身 IAB）→ MA-M（/28，7 位）→ MA-L（/24，6 位）。这是必须的：MA-S/MA-M 子块是从 IEEE 或其他厂商持有的 /24 OUI 中划出的 —— 没有最长前缀，以 `8C1F64B14..` 开头的 MAC 会被误标为 "IEEE Registration Authority" 而非 "Murata"（MA-S 子受让方）。

- **`vendor/oui.go`**：`Lookup` 改为最长前缀匹配；新 `LookupFull` 返回 `(vendor, prefix)`，调用方可记录命中了哪个块。加载器索引全部三种长度的前缀（`NormalizeMACPrefix` 的 6 位十六进制上限经由新的 `normalizeHexPrefix` 解除）。
- **新 `scan_attributes` 字段**：`oui_prefix`（命中的 6/7/9 位块）与 `oui_vendor`（IEEE 组织名 —— NIC 芯片厂商）。与既有 `vendor`（设备经 SNMP/HTTP/TLS 自报的品牌）**分开**；两者在 OEM/贴牌/虚拟化场景下会不一致。
- **开箱覆盖**：`scanner.oui_path` 为空时，引擎自动从**内嵌**的 CC-BY-SA 精编表（`vendor/oui_curated.txt`，`//go:embed`）播种 —— 全新安装对常见设备即刻可用厂商推断。用户配置的完整 IEEE 文件仍可覆盖。
- **`scripts/fetch-oui.sh` 重写**：抓取三份 IEEE CSV（MA-L/MA-M/MA-S），用 Python CSV 解析合并为单一 `<prefix>\t<vendor>` 文件（厂商名含逗号/引号）。同时修复下载 URL 的既有笔误（`standardeee.org` → `standards-oui.ieee.org`）—— 旧脚本从非规范镜像下载，本会失败。
- **许可边界保持**：IEEE 注册库是 "All rights reserved" 的事实数据 —— **不**并入 CC-BY-SA 指纹语料（见 `docs/fingerprint-spec.md` §8"数据与代码之别"）。内嵌精编表是手工撰写的 CC-BY-SA 子集，不是 IEEE 复制品；完整 IEEE 数据集保持为可选的运行时下载。

### UI：OUI 厂商（NIC 芯片）进入设备视图
**上条 OUI 厂商推断的跟进** —— 新的 `oui_vendor` / `oui_prefix` 字段（第 2 期）现已在 UI 可见，并与设备自报 `vendor` 品牌区分展示。

- **设备详情发现面板**：Vendor 之后新增 "OUI Vendor (NIC)" 行，显示 `oui_vendor`，tooltip 展示命中的 IEEE 块（`oui_prefix`）。
- **展开行设备摘要**：同样位置追加该字段。
- **Extras 泄漏修复**：store 的 `RecordDevice`/`buildStoreScanAttributes` 路径此前会让 `oui_prefix`/`oui_vendor`（及 `mac`）漏进 `scan_attributes.extras`（在 Extras 面板显示为原始 `OUI_PREFIX`/`OUI_VENDOR` 键）。现在它们映射到类型化字段并排除在 Extras 之外。

### HTTP 面加固（议题 #133 / #164 / #165 / #177）
- **感知可信代理的 RealIP**：弃用的 `chimw.RealIP`（无条件信任 `X-Forwarded-For`）被替换为只在来源属于配置的 `server.trusted_proxies` 时才采信转发头的中间件 —— 客户端 IP 无法再经该头伪造。
- **哨兵错误 → 正确的 400**：service 层校验错误类型化为哨兵；handler 用 `errors.Is` 映射，不再对用户失误返回 500。
- **credential.go 错误泄漏**：内部错误细节不再漏给 API 客户端；裸 `http.Error` 响应改为 JSON；补上哨兵映射。

### 前端 UX / 无障碍 / 正确性批次（议题 #150–#176）
SPA 的一次整固 pass：
- **破坏性操作门**：批量设备状态翻转需要确认；五个创建/编辑弹窗增加"有未保存修改时放弃需确认"守卫。
- **DataTable 无障碍重构**：事件委托行变为真正可交互（键盘可达、可聚焦）—— 不再只有点击。
- **扫描取消**：长扫描可在扫描页中止（AbortController），同一校验模式应用到扫描任务与 agent 目标；登录密码获得 Zod schema。
- **2FA 类型安全**：登录 2FA 路径去掉 `as any` 断言；2FA 后强制改密复用同一弹窗。
- **变更反馈一致性**：用户页 toast、文档页静默成功、扫描页合并错误处理。
- **本地化格式化**：`toLocaleString` 跟随 paraglide UI 语言（日期/数字与所选语言一致）。
- **空态诚实**：搜索无结果不再显示误导性的创建 CTA；错误态与空态分离。
- **修复**：`/changes/watch` SSE 不再永远显示"已断开"（#195）；变更页以结构化摘要显示显示名/IP 而非原始 JSON（#196）；仪表盘离线设备回落路径在名称退化为当前 IP 时正确解析（#197）；设备列表按 IP/网络/厂商/主机名排序带数字 IP 排序为服务端实现（#122）。

### 性能与并发（议题 #162 / #163）
- **扫描器性能**：UUID 查询缓存、`PRAGMA temp_store=MEMORY`、DetectLost 路径批量 miss-count 递增。
- **并发卫生**：调度器在锁外做 IO，`LeaseSweeper` 拥有 WaitGroup，限流器与 eBPF 观测器在关机时干净停止。

### 代码健康（议题 #132 / #141 / #157 / #158 / #160 / #161）
- **`internal/repository/` 解散** —— repository 类型移入 `internal/service/` 靠近消费者（少跳一层）。
- **Handler 存根塌缩**：server/TLS handler 家族数据化注册 —— 删除约 68 个手写存根。
- **巨型文件拆分**：`main.go` 迁移逻辑 → `migrations.go`；扫描器配置类型 → `scanner_config.go`。
- 死代码清理：v1 扫描器存根、错放的测试辅助、`var _` 占位。

### 测试覆盖网（议题 #134 / #171）
对先前无测试核心的一轮特征化 + 回归测试：`runMigrations` 幂等 + 全新库、device-bridge 身份合并、router-ARP 配置解析、保留期清扫、与调度器耦合的扫描任务触发/取消、auth/CSRF/RBAC 中间件、网络 CRUD、2FA-TOTP（含一个绕过守卫）、用户管理安全路径、SNMP 凭据 handler（含口令泄漏守卫）、扫描任务 + 审计 handler，以及首批 `.svelte` 页面渲染测试（登录 / 设备 / 扫描 / 拨测）。

### 文档
- **官网手册迁入仓库**（`docs/{zh,en}/`，14 个双语文件）：介绍、快速开始、架构、API、配置、部署、开发、发现、分布式、eBPF、OpenWrt、指纹规范、产品范围、更新日志 —— 仓库成为官网同步的唯一事实源（议题 #234）。
- 拨测/合成探测文档 + 配置样例补齐（议题 #236）；`config.example.yaml` 找回代码在用而样例缺失的 9 个配置块（agent/rdns/mdns/arp_scan/reconcile/retention，议题 #131）。

### 暂缓
- agent 侧 SNMPv3 凭据（议题 #241 —— 需要分布式凭据/密钥分发设计；agent 维持 v1/v2c）。
- 配置备份真机端到端冒烟（GL-MT3000）—— 代码完整，验证受硬件门控。

## [0.4.0] - 2026-07-29

**路由器驻留发现 + OpenWrt 部署 + 设备持久化重写。** v0.4.0 的头牌是新的**路由器形态**：当中心或 agent 运行在网关上时，获得四个一阶被动发现源（DHCP 租约、conntrack、hostapd、dnsmasq 查询日志），看得见主动探测看不见的主机 —— 沉睡的 IoT、被防火墙拦的主机、纯 WiFi 客户端。随附一等公民的 **OpenWrt** 部署（两个二进制都有 procd init 脚本）和消除长期双写裂缝的**单写者设备持久化重写**。收尾还包括前端信息架构重组、跨页存活的服务端搜索/排序、按用户的通知已读态、Zod 表单校验与 DataTable XSS 加固批次。

### 路由器驻留发现源（Phase A/B）
发现引擎（`internal/service/scannerv2/discovery/`）新增四个只有当宿主**就是**局域网网关/AP 时才能工作的一阶源 —— NAT 咽喉点看得见每一条流。全部选择开启（默认关），且在底层文件/socket 缺失时无操作，宿主型部署优雅降级。

- **`dhcp_leases`**：读取本机 DHCP 服务器的租约表（OpenWrt 上 dnsmasq 的 `/tmp/dhcp.leases`，Debian 上 `/var/lib/misc/dnsmasq.leases`）—— 权威的 主机名↔MAC↔IP 映射，覆盖从不响应 SNMP/ICMP/rDNS 的设备。
- **`conntrack`**：读取 `/proc/net/nf_conntrack`，对每条 ESTABLISHED/ASSURED 流发出其局域网侧端点 —— "谁**正在**通信"视图。为不响应主动探测但维持出站流的主机提供鲜活度 + 发现。按 `network.cidr` 过滤。
- **`hostapd`**：经 hostapd 控制套接字（`/var/run/hostapd/<phy>`）枚举 WiFi STA，回落 `iw station dump`。采集信号 dBm / 接入时间 / SSID —— 有线宿主拿不到。`interfaces` 列 wlan 名；留空 = 自动探测。
- **`dns_log`**：tail dnsmasq 查询日志（`--log-queries` 输出），发出每个发起查询的主机 + 域名 —— 强力被动指纹（拦入站探测的设备照样做出站 DNS）。运维需开启查询日志（UCI：`uci set dhcp.@dnsmasq[0].logqueries=1`）。
- **`arp_scan` 主动源**（`discovery/arp_scan_*`）：主动 ARP 扫掠源（CAP_NET_RAW，不可用时构建标签存根）—— 补齐既有的被动 `arp_cache`/`multicast`/`router_arp` 源。
- **agent 侧被动源接线**（Phase A）：agent 二进制现在运行发现引擎，路由器形态的 agent 会把其局域网的被动发现连同扫描结果一起报给中心。
- **多播 / `router_arp` 静默失败修复**：这些源不再静默失败 —— socket / SNMP 遍历不可用时自行停用并记录原因，而不是"看起来健康却什么都不发"。新增一条告警：当 `router_arp` 与某个已覆盖相同主机的路由器驻留源重复时触发。

### OpenWrt 部署（Form C 路由器中心）
把中心或 agent 直接跑在 OpenWrt 路由器上的一等支持 —— 上述路由器驻留源的天然归宿。

- **procd init 脚本**：`deploy/openwrt/mibee-steward.init` 与 `mibee-agent.init` —— UCI 配置的服务，开机自启、崩溃重启、以非特权用户运行。README 记录安装、配置与 CAP_NET_RAW 事项。
- **ARMv7 构建目标** + init 脚本去重：发布矩阵与 OpenWrt 打包面向常见低功耗路由目标（ARMv7）打磨，两个 init 脚本完成去重。

### 设备持久化：单写者漏斗 + 设备替换
**架构修复** —— 消除 `devices` 行由两条独立路径（`store.RecordDevice` 与 `runner.applyDeviceBridge`）写入、字段语义不一致的双写裂缝。最直观的症状：同步 `POST /scanner/scan` 留下的行 `status='unknown'`（只有 store 写它），而计划扫描翻成 `online`（runner 写的）。一次设备替换案例（换路由器）暴露了更糟的失败：新设备的数据落在了陈旧 IP 上，而活网关行继续显示死掉的旧设备 —— 因为两个写者对身份 + 覆盖哪些字段意见不合。

- **单一设备写者**：`runner.applyDeviceBridge` 成为 `devices` 行生命周期的唯一权威（身份创建、显示名、`status`、心跳播种、变更检测、设备替换检测）。同步扫描 API（`scanner.go` 的 `Scan`）现在经 `runner.ApplyReport` 持久化存活主机 —— 与异步扫描任务**同一条**路径 —— 同步扫描与计划扫描留下的行完全一致。
- **`store.RecordDevice` 缩减为仅富化**：不再 INSERT 身份、设置 `name`/`status`、检测替换。只作为编排器内的尽力前置写，富化已匹配的行（mac/type/brand/scan_attributes）；与 runner 不再有冲突面。
- **设备替换检测**（`device_bridge.go` 的 `resolveDeviceIdentity`）：当扫描的 MAC 命中另一个 IP 上的设备、而该 IP 又由另一个 MAC 的设备持有时（路由器/资产换新），IP 持有者胜出，其身份字段被新设备的强制覆盖，先前 MAC 命中的行标记离线。变更检测的前后 diff 把旧→新身份记入 `change_log`。

### 网络对账（漂移检测）
- **`internal/service/scannerv2/reconcile/`**：后台任务查找 IP 漂移出其盖章 `networks.cidr` 的设备（如漫游笔记本拿到了新网段的 DHCP），浮出给运维纠正。**检测并浮出，不自动改** —— 自动重挂设备是破坏性的（改身份、断历史关联、在重叠 IP 空间上会抖动），纠正保留为人工决策。发现经结构化 `slog` 告警（限速）、按网络的 `mibee_network_mismatches` Prometheus 量表、以及 `Reconcile()` 返回值（未来的管理端点）暴露。由新 `internal/cidrutil` 包支撑。

### 可配置性
- **检测阈值 + 心跳节奏可配置**（此前硬编码）：`scanner.lost_threshold`（判"失联"的连续缺席扫描数，默认 2）、`heartbeat.tick_interval_seconds`（探测循环节奏，默认 30）、`heartbeat.offline_threshold`（判离线的探测失败数，默认 5）、`heartbeat.offline_backoff_ticks`（已离线主机每 N tick 探测一次，默认 10 → 30s ticker 下约 5 分钟）。全部带 `MIBEE_*` 环境覆盖；`0` 表示"用默认"。见 `internal/config/defaults.go`。
- **限流放宽** `rate_limit.global_per_minute` 100 → 600，SPA 静态资源（`/_app/*`）豁免、CSP 放行 `data:` 字体 —— 旧的 100/min 会饿死多标签页 + 后台轮询会话。
- **共享常量抽取**（`config.SysUpTimeOID`、`config.DefaultScanPortSpec`）：sysUpTime OID（曾在 6 处复制）与精编扫描端口集收敛为单一来源常量，消除诱发漂移的重复。

### 领域：设备类型
- **新增 `phone` 与 `printer` 设备类型**，进入类型联合（`internal/domain/device.go`）与 `devices.type` CHECK 约束 —— schema 与 Go 枚举互为事实源，由 schema 同步漂移测试守卫。主机名/品牌/端口 → 类型推断表（`configs/fingerprints/device-types/device_types.yaml`）完全数据驱动（加签名 = 一条 YAML，不是 Go `case`）。

### 管理 UI 重组
- **信息架构大修**：侧栏重新分组、扫描入口收敛、**拓扑作为视图开关并入设备页**（辐射图 ↔ 表格切换）、仪表盘新增**待办横幅**带主操作，浮出需要运维目光的事项。
- **设备详情重组**：健康横幅 + 5 标签导航（概览 / 服务 / TLS 证书 / 邻居 / 变更）。
- **设备编辑/删除**经共享 `DeviceEditModal.svelte`，列表页与详情页皆可达。
- **共享基元**：抽出 `PageHeader` / `PageShell` / `LoadingButton` 并全站采用，统一加载态与布局。

### 服务端搜索、排序与分页
一批"客户端过滤在列表超过一页后静默丢结果"的正确性修复 —— 搜索/排序改在服务端跑，覆盖全量数据：
- **服务端搜索**覆盖 users / audit / changes / documents / scan-tasks / scan-results（`fix(web,api)` #54、#55、#64、#86）。
- **扫描结果排序**移到服务端，排序跨页保持（#55）。
- **专用 `PATCH /channels/{id}`** 承接通道启用开关（#53）—— 只写 `enabled`，避免 GET 后再写的竞态。
- **CSV 导入**读取后端 `{added, errors}` 结果而非预览计数，导入后的账面与现实一致（#58）。

### 通知
- **按用户未读跟踪**（`notification_read_states` 表）：顶栏铃铛显示按用户的未读数，下拉打开即清。此前铃铛是系统级的（没有接收者概念）。
- **NotificationBell** 在后台标签页暂停轮询、失败退避 —— 阻止空闲标签页敲打 API（#67）。

### 前端加固
- **DataTable XSS 修复**（`lib/utils/html.ts`）：标签模板 `html()` 辅助函数对插值转义，全部富文本调用方从字符串拼接迁出（#50、#87）。
- **Zod schema 校验**加入 7 个表单（登录、注册、设备编辑、网络、通道、扫描、CSV 导入）—— 客户端校验镜像后端规则（#66、#106）。
- **错误态诚实**：页面不再把服务端错误伪装成空态 —— 拉取失败显示错误 + 重试 UI 而非空白"无数据"面板（#65）；设备详情显示错误 + 骨架屏而非空白（#56）。
- **API 客户端加固**：瞬时 5xx GET 重试、环境变量基础 URL、统一 401 处理把会话过期导向重新登录（#73、#109）。
- **i18n 补全**：9+ 页面散落的硬编码英文本地化，含发现漏斗、拓扑 tooltip、ChangeDiff 标签、布局/无障碍标签；API 错误消息 + 表单校验消息走 i18n 边界（#40–#63、#101–#105）。
- **无障碍 + 组件清理**：ARIA id、焦点管理、点击切换菜单的 Escape 关闭、图表 resize 处理、扫描存活主机表**大网段（/22+）分页**（结果一页装得下时隐藏分页条）（#74、#100、#108、#110、#112）。
- **杂项 P2/P3 批次**：lib/components、agents/settings/networks/documents、devices 子树做了整固的正确性 / 类型安全 / 无障碍 pass。

### 运维
- **`change_log` 降噪**：服务证据去重 + 离线退避，砍掉了死主机超时行的持续写入。
- **`agent` 竞态修复**：`TestCommandPoller_ScanPayload_StringQuoted` 与 `TestReporter_SendsStateHashHeader` 的数据/逻辑竞态修复（CI 跑 `-race`）。
- 从 `mibee-fingerprints-go` 同步**指纹语料**（http-tls + ports 规则），同步的 http-server-* + smb-version 规则有 golden 测试覆盖。

### 许可证
- **AGPLv3 + 商业双授权**全仓落地（取代早期的 PolyForm NC）：完整 AGPL-3.0 `LICENSE`、`LICENSE-COMMERCIAL.md`、`NOTICE` 三方署名、`CLA.md` + `.github/DCO.md` + DCO CI 检查，全部 `.go`/`.ts`/`.svelte`/`.c`/`.sql` 源码带 `SPDX-License-Identifier: AGPL-3.0-or-later` 头；指纹 YAML 带 CC-BY-SA 4.0 头。

## [0.3.0] - 2026-07-18

**完整 L2 拓扑 + TLS 证书清点 + 容器镜像** —— v0.3.0 补完 v0.2.0 起步的拓扑故事（CDP/Q-BRIDGE/STP 探测、辐射可视化、邻居身份推断），新增从每台设备所有 TLS 包装服务采集完整证书链的 TLS 证书清点，并引入 GHCR 官方多架构容器镜像。

### TLS 证书清点
- **TLS 证书采集**（`probe/cert_collector.go`）：单一事实源 —— `CollectCertChain(ctx, ip, port, timeout)` 完成 TLS 握手（清点用途 InsecureSkipVerify）并提取完整对端链。每证书：Subject/Issuer/SAN（DNS/IP/email）/序列号/有效期/签名算法/密钥算法 + 位数（RSA/ECDSA/Ed25519）/is_ca/self_signed/SHA-256 指纹/PEM；每握手：TLS 版本、密码套件、尽力信任判定。失败路径返回错误记录（仍持久化），UI 能显示"这个端口我们试过了"。
- **TLS 包装服务 handler**（`handler/tls_collect.go`）：8 个 handler（`https`、`ldaps`、`smtps`、`imaps`、`pop3s`、`ftps`、`ircs`、`telnets`）共享一个 `tlsCollectHandler` 核心 —— 每个的 `Collect()` 调 `probe.CollectCertChain` 并返回 `TLSCertCollected` 载荷。handler 数 21 → 29。
- **MiscClassifier 扩展**：TLS 包装服务端口（465/989/990/992/993/994/995）现被断言为服务身份，证书采集 handler 得以为其运行。
- **TLSProbe 扩展**：默认端口集从 4 扩到 12（+ 465/636/989/990/992/993/994/995）。重构为发出更丰富的证据字段（`not_before`/`not_after`/`sig_algorithm`/`key_algorithm`/`fingerprint_sha256`/`san_email`）。
- **`host_tls_certs` 表**：每端口链中每证书一行（cert_index 0 = 叶，1..N = 签发者）；PEM + 类型化列；`(ip, port)` 与 `not_after` 建索引（供到期清扫）。
- **读取 API** `GET /api/v1/devices/{id}/certificates`：按端口分组带叶 + 链；状态着色元数据（TLS 版本、密码套件、信任判定、错误）。
- **前端 TLS 子面板**：扫描发现下新增 "TLS Certificates" 面板（中文界面为"TLS 证书"）—— 每端口一行可点击，左侧状态着色边条（绿=有效 / 琥珀=15 天内到期 / 红=已过期）、剩余天数徽章、自签/受信标签。
- **`CertificateModal.svelte`**：全链查看器 —— 状态头、摘要字段网格（Subject/Issuer/有效期/SAN/算法/指纹）、可折叠链条目、带复制按钮的 PEM 块。
- **保留** `retention.host_tls_certs_days`（默认 30）。
- **i18n**：新 `certificates` 节（34 键，EN + ZH）。

### 拓扑探测广度
- **CDP-MIB 探测器**（`active:cdp_mib`）：在 Cisco/说 CDP 的交换机上遍历 CISCO-CDP-MIB `cdpCacheTable`。以 device id 作为邻居合并键。发出 `protocol:"CDP"` 邻居边。
- **Q-BRIDGE-MIB 探测器**（`active:q_bridge_mib`）：遍历 IEEE 802.1Q `dot1qTpFdbPort` 拿 VLAN 感知的 MAC→端口转发表项。在打标签/跨 VLAN 拓扑上恢复 L2 邻接。发出带 ifName 解析端口名的 `protocol:"Q-BRIDGE"` 边。
- **STP-MIB 探测器**（`active:stp_mib`）：遍历 BRIDGE-MIB `dot1dStp` 拿生成树事实（根桥、指定端口、端口角色/状态）。发出 `protocol:"STP"` 证据。
- **IF-MIB ifName 解析**（`probe.ResolvePortNames`）：共享辅助函数把数字 ifIndex/端口值转成人类可读接口名（如 `GigabitEthernet0/1`）。CDP/Q-BRIDGE 探测器使用。

### 拓扑可视化
- **网络拓扑页**（`/topology`）：全网辐射树视图（ECharts `tree` 系列，新 tree-shake 进来），设备为节点、`device_neighbors` 为边。节点色按设备类型；边色按协议（LLDP 蓝 / Bridge-MIB 绿）；虚线边指向未识别邻居。网络过滤 + 60s 自动刷新；点节点开其详情页。
- **设备详情邻居面板**：设备 L2 邻居表，带邻居的名称/IP/类型（经设备 JOIN —— v0.2.0 里 `neighbor_device_id` 恒为 NULL，现查询时解析）及详情页链接。

### LLDP 发现（双路径）
- **SNMP LLDP-MIB 探测器**（`active:lldp_mib`，默认开）：在说 SNMP 且跑 LLDP 的交换机/AP 上遍历 `lldpRemTable` —— 跨厂商标准。经既有邻居管线发出 `protocol:"LLDP"` 邻居边（零新增接线）。非特权（UDP/161）；无新依赖。
- **原始帧 LLDPDU 监听器**（`WITH_LLDP` 构建标签，默认关）：经 AF_PACKET 捕获 ethertype 0x88cc 帧（需 CAP_NET_RAW），看见不发 SNMP LLDP-MIB 但广播 LLDP 的端点（IP 话机、AP、NAS）。镜像 eBPF 观测器的构建标签模式 —— 默认构建带无操作存根保持非特权（`make build-with-lldp` 启用）。

### 邻居身份推断
- 编排器新增可插拔 `NeighborIdentityInfer` 回调接到 RuleClassifier —— CDP/LLDP 邻居从其平台串推断厂商/型号/类型。
- **`EnrichDeviceByMAC`**：按 MAC（邻居合并键）富化设备的厂商/型号/类型/主机名，保留既有非空值。

### 容器镜像与部署形态
- **GHCR 发布**：每个 `v*` 标签构建多架构镜像（linux/amd64 + linux/arm64）发布到 `ghcr.io/mi-bee-studio/mibeesteward`，打 `:latest` / `:<version>` / `:<major>.<minor>` / `:sha-<short>` 标签。发布工作流的 `publish` 任务等待 `[release, docker]` —— 只有二进制与镜像都成功才创建 GitHub Release。镜像为非特权变体（LLDP/CDP/eBPF 编译为存根）。
- **Docker 网络模式形态**：三个 compose profile 让部署形状匹配意图 —— `bridge`（默认，NAT，MAC/ARP 劣化）、`host`（推荐，≈ 裸机探测保真）、`macvlan`（独立局域网 IP）。测试局域网实测：默认 docker bridge 找到 0/26 设备 MAC，host 网络为 30/31（容器的 `/proc/net/arp` 只看得见网桥网关）。见 `docs/{en,zh}/deployment.md` § "Docker 网络模式"。
- **Dockerfile**：`BUILD_TAGS` 参数（WITH_LLDP/CDP/EBPF 选择启用）、可选 `SETCAP`（能力不在 bounding set 时 file caps 会破坏 exec()，故默认关）、受限网络构建的 `NPM_REGISTRY`/`GOPROXY` 参数、vite 堆的 `NODE_OPTIONS`、`/data` 预归属非 root 用户。
- **Makefile**：`docker-build` / `-priv` / `-up` / `-up-bridge` / `-up-macvlan` / `-down` / `-logs` 目标。
- **`configs/config.docker.yaml`**：容器模板（network.cidr、/data 路径、bridge 模式 router_arp 指引）。

### CI
- **`docker-build` 冒烟任务**（ci.yml）：每个 PR 构建镜像（仅 amd64，不推送）并以最小配置启动，最长等 30s 探活 `/health` —— 在打标签前抓住 Dockerfile/compose 回归。
- **Node.js 20 弃用**：actions 仍目标 Node 20；GitHub 正在强制 Node 24（告警，未失败）。升级待办。

### 保留期加固
- `device_neighbors` 与 `host_services` 有了保留清扫器（v0.2.0 起无限增长 —— 潜在膨胀 bug）。默认：neighbors 90 天（拓扑历史价值）、host_services 30 天。每表 `retention.*` 配置键 + `days<=0` 安全守卫。
- 同时修复一个潜伏的 sqlc v1.27.0 bug：查询注释里的非 ASCII 字符会破坏兄弟查询的代码生成（静默产出坏 SQL —— 运行时查询失败，不是构建错误）。

### 测试覆盖
- **taskservice**（扫描任务状态机）：此前零测试。现覆盖 CRUD、校验、分页钳制、not-found 映射、nil 调度器行为。
- **指纹 golden 测试**：质量回归守卫（真实世界证据样本 → 期望的服务/元数据），区别于既有计数测试 —— 破坏识别的规则编辑即使计数不变也会失败。

### 指纹库
- 扩充 `snmp-data.yaml`：补上相比企业向表格偏少用的消费级/ SMB 网络设备 sysObjectID 前缀（ASUS、D-Link、Zyxel、Tenda、DrayTek、TP-Link/Mikrotik 备选子型）。每条一个 YAML 条目。
- 新 `lldp-cdp.yaml` 规则用于 CDP/LLDP 设备识别。

### 修复
- 移除弃用的 `tls.VersionSSL30`（staticcheck SA1019）。
- gofmt + golangci-lint 清理（QF1008、未用参数、内嵌选择器）。

## [0.2.0] - 2026-07-13

分布式多网络发现、拓扑感知探测、变更检测引擎与数据驱动的指纹规则库。本版发布**两个二进制**：中心（`mibee-steward`，既有内嵌 SPA 的服务器）与新发现的 **agent**（`mibee-agent`），面向远程局域网。

### 分布式发现（中心 + agent）
- **Agent 二进制**（`cmd/agent`）：在其所在的局域网运行 scannerv2 引擎，经 `POST /api/v1/agents/report` 向中心上报结果。拉模型 —— agent 主动发起所有连接（上报 + 轮询命令），因此在 NAT 后可用。CGO-free，普通用户即可运行。
- **中心侧摄取**：agent 报告经 device bridge 转成本地设备画像；agent 托管网络排除在中心自己的跨网段探测之外（agent 的报告**就是**鲜活度信号）。
- **反熵快速路径**：agent 发送 `X-Network-State-Hash` 头（存活集合的身份+分类字段的 SHA-256）；命中时中心跳过逐主机 device bridge，只刷新租约 —— 稳定网络的稳态路径。
- **租约模型**：agent 报告刷新按设备租约；agent 网络的失联检测基于 TTL（`LeaseSweeper`，默认 5 分钟 TTL），区别于中心自身网络的连续扫描 `DetectLost`。
- **命令通道**：中心入队扫描命令；agent 轮询、确认、完成（约 60s 周期）。
- **Agent 令牌认证**：绑定 `network_id` + `agent_id` 的机对机 bearer 令牌（管理端 CRUD 在 `/api/v1/agents/tokens`）。
- **Watch SSE + agent 断线回填**：`GET /changes/watch` 奠基；agent 重连时重发其最后的哈希。

### 拓扑与探测
- **Bridge-MIB 邻居探测器**：遍历 `BRIDGE-MIB` 发现 L2 邻居并持久化 `device_neighbors`（拓扑层 Phase 4）。
- **SMB2 Negotiate 探测器 + FTP banner 可靠性**：更丰富的服务证据。
- **TLS 证书 CN 品牌覆盖**：从证书 subject/issuer 字段识别 OpenWrt / GL.iNet / iStoreOS。
- **Router ARP** 遍历解决跨网段 MAC。

### 变更检测引擎
- 向 `change_log` + 进程内 `Watcher`（仅中心）记录 `device_added` / `device_changed` / `device_lost`。`device_lost` 有两条路径：连续扫描 `miss_count`（中心自身网络）与基于 TTL 的租约到期（agent 网络）。经 `GET /api/v1/changes` 查询；UI 有历史页。

### 指纹规则库（数据驱动）
- 识别规则从手写 Go 变为**数据**（YAML）。`RuleClassifier` 启动时从配置路径或二进制内嵌规则加载。加设备签名 = 一条 YAML 条目。
- **导入语料**（许可干净）：Rapid3 Recog（约 1174 条规则，Apache-2.0）与 SNMP/Recog 数据表（划定范围后共约 2554 条）。nmap 的 NPSL 排除（永不导入）。转换器见 `cmd/fpimport/`。
- 独立引擎位于 [github.com/Mi-Bee-Studio/mibee-fingerprints-go](https://github.com/Mi-Bee-Studio/mibee-fingerprints-go)。
- 无法成为单条声明式规则的逻辑（SNMP 位掩码启发、相机跨证据融合）保留为 Go 代码。

### 管理 UI
- **网络管理页**：逻辑网络的创建 / 编辑 / 删除（POST/PUT/DELETE `/api/v1/networks`）—— agent 绑定的网络注册表。
- **发现状态页**：被动主机发现运行时计数 + 近期发现（`GET /api/v1/discovery/status`）。
- **设备页**：用户可切换的可选列（持久化到 localStorage）；设备名链到详情页；类型联合镜像全部设备类别。
- **变更历史页**带结构化前后 diff。
- **CSRF 安全导出**：CSV/JSON 下载改走 API 客户端（此前经裸 `fetch` 绕过它，丢 CSRF 头）。

### 运维
- 服务器绑定重试防止残留 socket 引发的重启风暴。
- Agent HTTP 传输 keep-alive 死锁修复 + 扫描截止期强制。
- 反熵 + 租约模型 + 心跳作用域治理。

### 已知限制
- 中心为单实例（SQLite）。多中心集群不在范围内。
- 无内置告警 —— 与 Alertmanager / Uptime Kuma 集成。
- eBPF 被动观测器需要特殊构建（`make build-with-ebpf`）与运行时特权。

## [0.1.0] - 2026-07-07

首次公开发布。MiBee Steward 是一个设备管理与网络层自动发现系统，内嵌 SvelteKit SPA，打包为单一二进制。

### 核心能力
- **网络发现**：插件化扫描器 v2（ICMP、TCP 端口扫描、SNMP、RTSP、ONVIF、HTTP、ARP、UDP 发现），5 层管线（探测 → 分类 → handler → 持久化）。
- **身份推断**：从扫描证据推断设备类型/厂商/系统/主机名（相机、服务器、交换机、路由器、NAS 等）。
- **设备登记**：完整 CRUD、批量操作、CSV 导出、自定义属性、文档关联、设备系统分组。
- **心跳监控**：资产鲜活度探测（ICMP/TCP/HTTP/SNMP），专用时序存储、内存状态缓存、WAL 隔离安全的同步。
- **认证**：JWT（cookie + Bearer）、2FA（TOTP）、登录锁定、令牌黑名单、RBAC（admin/user）。
- **仪表盘**：可配置小组件、Prometheus 支撑的时序图表。
- **审计日志**：全部管理操作留痕。
- **Prometheus 集成**：`/metrics` + `/sd`（HTTP 服务发现）。
- **通知通道**：webhook/邮件通道管理带测试发送。
- **i18n**：中英双语完整翻译。

### 部署
- 单一二进制（CGO-free，SQLite 走 modernc.org/sqlite），内嵌 SPA。
- Docker（多阶段、非 root）、systemd 单元、nginx 反向代理配置。
- 全部高量表可配置的数据保留清扫器。
- CLI：`mibee-steward -version`、`mibee-steward reset-admin-password`。

### 已知限制
- 单实例（SQLite）。分布式/多网络模式是未来工作。
- 无内置告警引擎 —— 告警有意排除在范围外（与 Alertmanager/Uptime Kuma 集成）。
- eBPF 被动观测器需要特殊构建（`make build-with-ebpf`）与运行时特权。
