# TCP/UDP 转发特性审计报告 —— 性能问题、逻辑问题与 SOCKS5 TCP/UDP ECHO 影响

**审计对象**：`41031b4 feat(client): add config-driven TCP/UDP forward listeners`（parent `1135076`，HEAD `7232088` / v0.2.2）
**审计日期**：2026-10-23
**方法**：静态源码审计（三路并行：TCP 转发 / UDP 转发 / SOCKS 热路径差分）+ 真实二进制 A/B 基准（release，macOS arm64 loopback，父版本客户端 vs HEAD 客户端，同一 HEAD 服务端）。
**详细证据**：`analysis/forwarding-audit/{tcp,udp,socks}.md`（英文，逐条 file:line 证据）+ `bench.md`（实测数据与方法）。

> 结论均基于当前 HEAD 源码与真实二进制实测；每一条静态结论在详细报告里标注了 verified / inferred，未在本机复现的 Linux 内核行为单独标注。

> **修复状态（2026-10-23，fix round）**：§7 中 P0/P1 建议已实现并验证（P2 完成一部分），实现与逐项映射见 [FIXES.md](FIXES.md)；`cargo fmt/check/clippy` 全绿、566 tests 全绿（基线 555），证据见 [fix-verification.md](fix-verification.md)；修复后基准与外部准入行为验证见 [fix-bench.md](fix-bench.md)。本报告正文保留审计时的原始结论与数值（审计基线），未按修复结果改写。

---

## 0. 结论（TL;DR）

| 问题 | 结论 |
|---|---|
| **未配置转发时，SOCKS5 TCP ECHO 性能是否受影响？** | **不受影响（0 代码差异）**。`socks.rs`、`src/tcp/pump.rs`、`pool.rs`、`server/*` 等 CONNECT 数据面文件相对父版本**逐字节相同**；未配置 `[[tcp_forward]]` 时新增代码只有两个空 `Vec` 解析，每连接零开销。实测在噪声内（见 §6）。 |
| **未配置转发时，SOCKS5 UDP ECHO 性能是否受影响？** | **稳态/节流/延迟均无差异；仅“未节流突发”路径实测到小幅余量下降**。每回复代码增量 2 次 bool 读、2 次 bool 写、2–3 个必然命中的分支 ≈ **0.6–0.9 ns @3.5GHz**；每上行数据报 0 新增（`send_payload_uplink` 是逐语句等价搬移，release `lto=true, codegen-units=1` 下大概率内联）。无新增分配/锁/原子/系统调用。实测：paced/全双工/多关联丢包 0%，串行 p50/p99 相同；但**未节流 UDP blast 的 clean pps 中位 33,088→30,571（−7.6%，p≈5e-4）**、丢包 run 比例 9/55→19/55（p=0.048）。该量级无法用 ~1ns/回复的代码增量解释，**归因未定**（疑为新增代码导致的编译布局/内联扰动，需 Linux+PGO 复核），不是语义性热路径变更。`AssocEntry` 仍为 48B，`StagedReply` 104→112B（每连接一次 +256B 工作区，非每包）。详见 §6.2。 |
| **配置转发后，是否影响 SOCKS5 TCP/UDP ECHO？** | **空闲监听器：无热路径影响**（仅启动时每个监听器一次 bind/一个任务/一个定时器）。**转发有实际流量时：会，通过共享预算竞争**——不是 SOCKS 代码变慢，而是 SOCKS 可能拿不到资源：UDP 会话池（4032，默认单监听器可占满）、TCP relay 许可（8192，无 per-listener cap）、interactive UDP egress 单连接（与 SOCKS 小包 ECHO 同类共享 cwnd/队列）、服务端 session 池（8192 / 公平份额 1024..4096）。见 §5。 |
| **转发特性自身有没有“大的性能问题”？** | **稳态数据面没有**：实测 UDP 转发单 peer 32k pps（1000B、0 丢包）、50 peer 聚合 50.8k pps（0 丢包）、p50 113µs，与 SOCKS UDP ECHO 同量级；TCP 转发 p50 95µs、8MiB 批量 ~90MB/s、SHA-256 校验全对。**条件性性能问题有 4 个**：共享 hub 饥饿（S1）、单个 UDP 监听器单核上限（S3）、Linux ICMP 异步错误导致 20ms 全监听器停顿（S2）、单 socket 的 wildcard 回复源地址问题（S2，正确性）。 |
| **有没有逻辑问题？** | **没有发现 S0（数据损坏/越权/远程内存放大）**；raw 回程帧格式、双栈地址映射、会话生命周期（alloc/publish/release 恰好一次，含 panic/abort 路径）、关机 SESS_CLOSE 均验证正确。**1×S1 + 4×S2 + 若干 S3** 逻辑/资源问题，核心是“共享预算没有为 SOCKS 预留 + 默认 per-listener 上限等于全局上限 + 180s 空闲回收”，见 §4。 |

---

## 1. 范围与基线

### 1.1 本次提交真正改了什么

`git diff --stat 1135076 41031b4`：

| 区域 | 文件 | 运行时性 |
|---|---|---|
| 客户端共享代码 | `client/{assoc,dispatcher,hub,main}.rs`（+289/−83） | 是，逐 hunk 审计 |
| 新特性 | `client/forward.rs`（+242）、`client/forward_udp.rs`（+445） | 仅配置非空时可达 |
| 配置 | `config/client_conf.rs`（+472） | 启动一次解析/校验 |
| 导出/测试/文档 | `lib.rs`（re-export）、`tests.rs`、`tests/forward_e2e.rs`、`udp_stats.rs`（测试块）、README/样例/plan、`Cargo.*`（仅 dev-dep `tempfile`） | 无运行时影响 |

**服务端、MQP-3 rev2 线格式、TCP pump、UDP send/retry/batch、DNS、transport 全部零改动**（路径过滤 diff 为空）。因此 A/B 基准只需比较两个版本的 **client** 二进制（同一 server 二进制）。

### 1.2 关键共享预算（默认值）

| 资源 | 常量 | 转发与 SOCKS 是否共享 |
|---|---|---|
| TCP relay 并发 | `MAX_SOCKS_CONNS = 8192`（`socks.rs:11`） | **是**，同一 `socks_conn_limiter()`；转发持有许可到流结束（300s idle） |
| 客户端 UDP 会话 | `MAX_UDP_ASSOCS = 4032`（`tuning.rs:187`） | **是**，同一 `UdpHub` |
| 服务端 UDP session | `MAX_SESSIONS_GLOBAL = 8192`，每连接公平份额 `clamp(8192/holders,1024,4096)`（server `table.rs:461-511`） | **是**，且**每个转发 peer 各占一个完整服务端 session** |
| UDP egress 连接 | interactive 固定 1 条 + 默认 2 条 bulk 分片（`pool.rs`） | **是**，按 egress class 共享 |
| TCP pool slot / 流信用 | 默认 4 个 TCP slot、每连接 8192 bidi streams | **是** |
| QUIC per-conn rev2 重组预算 | 256 KiB / 连接 | **是** |
| 空闲回收 | UDP 180s（30s tick）、TCP 300s | 同 SOCKS 语义 |

---

## 2. 三个问题的直接回答

### 2.1 是否有大的性能问题？

- **未启用转发：没有。** 代码级 0 差异（TCP）/ ≤1ns 每回复（UDP），实测在噪声内。
- **启用转发：稳态数据面没有“大问题”，但存在 4 个条件性缺陷**：
  1. **S1（最重要）**：共享 UDP 会话池没有为 SOCKS 预留份额，且默认 `max_sessions` = 全局 4032、只能靠 180s 空闲回收。对端源端口变化型负载（glibc resolver 风格 DNS、TFTP、一次性客户端）在 **>~20 个新 peer/s** 时即可让 hub 永久满：转发新 peer 被 `SESSION_FULL` 丢弃，**同时**新的 SOCKS `UDP ASSOCIATE` 被拒绝（`REP=0x01`），且在 churn 停止后仍持续最多 ~180s。
  2. **S2**：TCP 转发**没有** per-listener 上限（UDP 有 `max_sessions`）。单条对外暴露的 `[[tcp_forward]]` 可以占满 8192 个共享 relay 许可（空连接也能占 300s），使 **SOCKS5 TCP 拒绝新连接**。
  3. **S2**：Linux 上共享监听 socket 的**异步 ICMP 错误**会干扰其他 peer：一次 `send_to` 可能被上一个已关闭 peer 的 ICMP 错误打断（该回复被丢弃，无重试），或 `recv_from` 返回 `ECONNREFUSED` 后代码 **sleep 20ms**，期间**所有 peer** 停摆；恶意/高频 churn 可放大为监听器级 DoS。
  4. **S2**：通配地址监听器用普通 `send_to` 回复，**回复源地址由路由选择**而非 peer 发送时用的本地地址；多宿主/别名地址场景下，严格或 connected UDP 客户端会丢弃回复（SOCKS 通过绑定通告地址避开了这个问题）。
- **单监听器单任务**：所有 peer 串行在一个任务上，单核 pps 上限与 SOCKS 单关联任务同量级（plan 已声明，未实现 `SO_REUSEPORT` 分片）——这是容量上限而非回归，S3。
- **内存放大**：每个 UDP peer = 一个完整服务端 session（fd + reader task + Linux ~288KiB 计费口径，64KiB/dir socket cap 被内核翻倍），最坏可达服务端公平份额 4096（约半个全局池）；客户端侧每 peer 反而比 SOCKS 关联便宜（无 per-peer socket/task）。另外每个 UDP 监听器 socket 用端点级 4MiB×2 缓冲（Linux 内核翻倍 ≈ 16MiB cap/监听器，plan §6.2 有意为之），路由器部署需注意。S2/S3。

### 2.2 是否有逻辑问题？

**没有发现 S0**。已逐项验证正确的关键逻辑：raw 回程在所有生产路径（n==1、分组 sendmmsg n>1、legacy slow path）字节正确；双栈 `reply_v6` 映射正确且 SOCKS 行为不变；`alloc_sess/publish/release` 恰好一次（`PeerSession::Drop` 覆盖 sweep/shutdown/panic）；会话 id 单调递增不复用，迟到的回复不会串到新 peer；SESS_CLOSE best-effort + 服务端 180s sweep 兜底。

**S1/S2 逻辑-资源问题**见 §4（U1–U4、T1）。**S3 级**包括：`[::ffff:0.0.0.0]:p` 目标绕过“拒绝 unspecified”校验；overlap 校验误拒合法的 `0.0.0.0:P` + `[::1]:P` 组合；转发 abort 与 SOCKS 共用 1s 日志窗口（可能吞掉 SOCKS 的 warn+连接统计）；O(n²) 启动校验且无监听器数量上限；监听器在 QUIC 池已开始拨号后才 bind（失败仍 fail-fast，但时机偏晚）；mapped-loopback `[::ffff:127.0.0.1]:p` 触发误报“not loopback”；UDP 监听器 fatal 错误日志可能被共享窗口吞掉且任务不重启；ENOBUFS 等被当 fatal；`flush_staged` 分组 key 未包含 `raw`（当前不变量成立但未断言）；缺少 grouped/batch/双栈/churn 测试。

### 2.3 是否影响 SOCKS5 TCP/UDP ECHO 性能？

| 姿态 | SOCKS5 TCP ECHO | SOCKS5 UDP ECHO |
|---|---|---|
| 未配置转发 | **0 影响**（代码逐字节相同；实测 TCP 延迟/吞吐无差异） | **≤1ns/回复**（2–3 个预测命中分支），无新分配/锁/系统调用；实测 paced/延迟无差异。**未节流突发 pps −7.6%（归因未定）** |
| 配置转发但空闲 | 0 热路径影响 | 0 热路径影响；仅启动多 N 个 task/socket/30s timer |
| 配置转发且活跃 | 竞争 8192 relay 许可、TCP pool slot/cwnd、流信用 → 可能拒绝新连接 / 抬高延迟 | 竞争 4032 hub 会话、interactive egress 单连接（cwnd/quinn DATAGRAM 队列/stager 互斥/dispatcher 32/唤醒预算）、服务端 session 池、主 runtime CPU → 可拒绝新 ASSOCIATE / 丢包率上升 |

**结论**：本次提交**没有**改变 SOCKS5 TCP/UDP ECHO 的单包路径；对 ECHO 的影响只会在“转发被配置且产生流量”时以**容量竞争**形式出现。保持监听器 loopback-only、给 `max_sessions` 设小值（如 ≤1024）、并避免把延迟敏感 UDP 目标放进 interactive class，即可把影响控制在可接受范围。

---

## 3. SOCKS5 热路径逐包增量（代码级证据）

### 3.1 TCP ECHO（CONNECT + copy pump）

- `socks.rs`、`src/tcp/pump.rs`、`pool.rs`、`auth.rs`、`egress.rs`、`rev2.rs`、`linux.rs`、`server/{tcp,reader,forward}.rs` 相对 `1135076` **零 hunk（逐字节相同）**。
- `main.rs` 差异只有新增：两个空表校验 + 空 spawn 循环 + `timeout` 变量提前一行定义。未配置转发时每连接增量为 **0**；无新增 syscall/task/alloc。

### 3.2 UDP ECHO（UDP ASSOCIATE，上行 + 回程）

| 时机 | 增量 | 说明 |
|---|---|---|
| 每 app 数据报（上行） | **0** | `send_payload_uplink` 为等价搬移（归一化 token diff 仅 3 处：debug label 参数、闭包重排、`return` vs `return Continue`；SOCKS 的 label 仍渲染为 `"udp assoc"`，日志逐字节不变） |
| 每回复（下行） | 2×bool load（`entry.raw_reply/reply_v6`）+ 2×bool store（写入 `StagedReply`）+ 2–3 个必然分支（raw/run_v6/run 边界比较），约 **0.6–0.9 ns** | 无新分配（`Vec` 容量不变、每连接一次 +8B/元素 ×32 工作区）、无新锁/原子/syscall |
| 每 UDP ASSOCIATE | +1 次 `getsockname`（`relay.local_addr()` 求 `reply_v6`） | 关联建立路径，几十 µs 量级下的 0.2–0.5µs |
| 结构体 | `AssocEntry` 48B 不变（两个 bool 落入既有 padding）；`StagedReply` 104→112B | 无需重新分配；每连接 staged `Vec` 一次 +256B |

**行为不变性**：SOCKS relay socket 恒为 AF_INET6 双栈（`bind_relay` → `map_for_dual`），故 `reply_v6=true`、`raw=false`，`map_for_dual` 调用与父版本完全一致；分组 flush 的 run 边界在 SOCKS 下等价；错误计数/日志文本/发送顺序均不变（14 项怀疑点逐条排除，见 `socks.md` §5）。

---

## 4. 转发特性的逻辑/性能问题清单（合并去重，按严重度）

> 完整证据、代码引用、复现条件见 `tcp.md` / `udp.md` 对应编号；此处给结论与建议。

### S1

**U1. 共享 UDP 会话池无 SOCKS 预留 + 默认 per-listener 上限=全局 + 仅空闲回收（churn 饥饿）**
- 位置：`forward_udp.rs:163-187,223-246`；`client_conf.rs:319-323,225-229`；`hub.rs:359-386`；`assoc.rs:12-19`。
- 机制：未配置 `max_sessions` 时取全局 `max_udp_assocs`（默认 4032）；会话按源地址创建、按 180–210s 双向空闲回收（30s tick），**没有** oldest-evict / LRU / SOCKS 保留。稳态会话数 ≈ `新peer速率 × 180..210s`；>~20 个新源/s 即长期占满。
- 影响：转发新 peer 与 **SOCKS 新 `UDP ASSOCIATE`** 同时被拒（后者 SOCKS `REP=0x01`），denial 最长延续 ~180s；非 loopback 监听器可被 spoofed 源低成本触发。
- 建议（P0）：给转发聚合预算设上限（默认取 `max_udp_assocs` 的一个分数，如 1/4~1/2）；支持“满时驱逐最老空闲 peer 再重试”；文档写明 `new_sources/s ≈ budget/idle` 规则；对暴露监听器建议更短 idle。

### S2

**U2. 每个 UDP peer = 一个完整服务端 session，且创建在共享 connection reader 内联执行**
- 位置：server `reader.rs:1711-1807`、`table.rs:461-511`、`tuning.rs:448-465`；client `forward_udp.rs:190-209`。
- 机制/影响：每 peer 在服务端消耗 semaphore 许可 + 一个双栈 socket（64KiB/dir cap，内核翻倍）+ 一个 reply-reader task + ~288KiB Linux 计费口径；单客户端最多可占公平份额 4096（约半个 8192 池）。session 创建（socket/bind/spawn）在**共享连接 DATAGRAM reader 内联**执行，peer churn 期间会阻塞同一连接上 SOCKS 数据报的处理（HOL）。
- 建议（P1）：明确“转发 peer 是否允许以原始 churn 速率占用完整服务端 session”的产品决策；若要限制：服务端按连接增加 forward-peer 配额，或客户端限制 session 建立速率；至少把该成本写进配置指南。

**T1. TCP 转发没有 per-listener 准入上限**
- 位置：`forward.rs:51,79-94`；`socks.rs:11,24-27`；`main.rs:470-482`。
- 机制/影响：与 SOCKS 共用进程级 8192 许可，连接期间一直持有（零字节空闲连接也可占 300s）；单条对外监听器即可让 **SOCKS5 TCP 拒绝新连接**（fail-closed，速率限制告警）。UDP 有 `max_sessions`，TCP 没有对应旋钮。
- 建议（P1）：增加 `max_conns`（或每监听器份额）+ 类似 UDP 的聚合预算；或至少文档化“不要把 TCP 转发暴露到不可信网络”。

**U3. 通配地址监听器的回复源地址由路由选择（无 IP_PKTINFO）**
- 位置：`forward_udp.rs:33-35`；`assoc.rs:1097-1126`；`dispatcher.rs:713-808`；全仓库无 `IP_PKTINFO`。
- 机制/影响：`send_to(peer)` 的源 IP 由出口路由决定，可能不是 peer 发包时用的本地地址（多宿主/别名 IP）。严格或 connected UDP 客户端会丢弃回复。SOCKS 通过把 relay 绑定到通告地址规避；转发单 socket 无法天然做到。
- 建议（P1/P2）：文档明确“多宿主场景请绑定具体地址而非 wildcard”；或实现 `IP_PKTINFO`/`IPV6_PKTINFO` 回填源地址。

**U4. 共享监听 socket 的异步 ICMP 错误干扰（20ms 全 peer 停顿 / 误丢无关回复）**
- 位置：`forward_udp.rs:291-303,419-429`；`udp/retry.rs`（send 无重试）；`udp/batch.rs`。
- 机制/影响：Linux `udp(7)` 会把已发送数据触发的异步 ICMP 错误返回给该 socket 的**下一次**系统调用。后果：(a) 给已关闭 peer 的回复导致下一次 `recv_from` 返回 `ECONNREFUSED` → 代码 `sleep(20ms)`，期间**所有 peer** 停摆；(b) 该 ICMP 错误也可能被另一个 peer 的 `send_to` 消费，使一条**无关回复**被丢弃（无重试）。churn 越频繁越严重，可被用于监听器级 DoS。SOCKS 每关联独立 socket，不受此共享干扰。
- 建议（P1）：不要对已消费的 ICMP 错误无条件 sleep——排空 socket 错误队列（`IP_RECVERR`/`MSG_ERRQUEUE`）或连续错误才退避；对 send 侧异步错误计数/重试一次。

**X1. interactive UDP egress 单连接共享（跨特性，条件性）**
- 转发目标端口落在 `interactive_ports`（默认含 53）或首包 ≤512B 时，与 SOCKS 小包 ECHO 走**同一条** QUIC egress 连接：共享 cwnd、quinn DATAGRAM 队列、连接级 stager 互斥、per-slot dispatcher 的 32/唤醒 drain 预算。转发放量时会抬高 SOCKS ECHO 延迟/丢包。bulk class 默认有 2 分片，隔离较好。
- 建议（P2）：文档建议把延迟敏感的转发目标与 SOCKS 小包负载错开 class（或调大 `udp_egress_conns`）；如规模大，考虑 per-listener/feature 的 class 归属。

### S3（摘要）

| 编号 | 问题 | 位置 |
|---|---|---|
| U5 | 单个 UDP 监听器=单任务，单核 pps 上限，burst 内不让出；多核无法扩展（plan 已知，未实现 SO_REUSEPORT 分片） | `forward_udp.rs:268-372` |
| U6 | 每数据报 2 次 HashMap 查找（`contains_key` + `get_mut`）+ `touched` 线性扫描（≤9）+ 1 次 relaxed load；plan 声称“一次查找”，估计 +10–30ns/包 | `forward_udp.rs:138-145,400-404` |
| U7 | 观测/监管缺口：无当前会话 gauge、转发/SOCKS 共用 drop 计数器、生命周期仅 debug、fatal 告警可能被共享 1s 窗口吞掉、任务 detached 不重启、shutdown 不 join（SESS_CLOSE best-effort） | `forward_udp.rs:309-316,435-445`；`reporter.rs` |
| U8 | 错误分类：仅 6 种 ErrorKind 视为 transient；ENOBUFS/ENOMEM 等会被当 fatal 永久停监听器且无计数；EINTR 也睡 20ms | `forward_udp.rs:305-316,419-429` |
| U9 | 配置/文档不一致：`[::ffff:127.0.0.1]` 误报非 loopback；一个监听器的 peer 可跨最多 9 个 egress binding（非“每监听器一个 class”）；`max_sessions` 只能保护 SOCKS、不能解决转发自身 churn 失败 | `client_conf.rs:334-344`；`pool.rs:695-746` |
| U10 | 潜在不变量：`flush_staged` 分组 key 含 `(app, reply_v6, sock)` 但**不含 raw**（当前成立未断言）；缺 grouped raw / batch / 双栈 / oversize / churn 测试 | `dispatcher.rs:755-786`；`tests.rs`；`tests/forward_e2e.rs` |
| U11 | 无 per-peer / per-listener 公平性：一个 flooding peer 占用监听任务与该 class 的 stager/cwnd，同监听器其他 peer 与同类 SOCKS 流 FIFO 排队 | `forward_udp.rs:132-159,268-372` |
| T2 | 目标 `[::ffff:0.0.0.0]:p` 通过客户端校验与共享 wire 的“拒绝 unspecified”检查（`is_unspecified()` 对 mapped 形式为 false）；server `allow_private=true` 时可能拨到服务端自身 loopback | `client_conf.rs:394-401`；`mqp/addr.rs:165-178,205-227` |
| T3 | overlap 校验过度拒绝合法的 `0.0.0.0:P` + `[::1]:P` 组合（v4 wildcard 不覆盖 v6）；启动失败报“overlaps” | `client_conf.rs:336-363` |
| T4 | 转发 abort 与 SOCKS 共用 `tcp_abort_log_due()` 1s 窗口，但只打 `debug!`（默认不可见），可能吞掉 SOCKS 的 warn+连接统计；转发失败行缺 plan 要求的 conn stats | `forward.rs:137-140,236-242`；`stats/warn.rs:159-172` |
| T5 | overlap 校验 O(n²) 且无监听器数量上限；上万条生成配置会拖慢启动并为每条监听器预置 1024 backlog | `client_conf.rs:271-318`；`lib.rs:633` |
| T6 | 监听器 bind 发生在 QUIC shard/endpoint 已 spawn、开始拨号之后（校验顺序正确，fail-fast 仍成立，但时机偏晚） | `main.rs:135-136,278-390` |
| T7 | mapped-loopback listen 误报；link-local listen 通过校验只在 bind 时失败 | `forward.rs:44`；`client_conf.rs:336-344`；`lib.rs:633` |
| T8 | 测试缺口：未断言 pre-pump “RST 而非 FIN”；dead-slot self-heal、多监听器启动、SOCKS/转发准入交互未覆盖 | `tests.rs:7339-7357`；`tests/forward_e2e.rs:377-436` |

---

## 5. 共享资源与跨特性干扰矩阵（配置转发并活跃时）

| # | 共享资源 | SOCKS 侧 | 转发侧 | 触发条件 | 后果 |
|---|---|---|---|---|---|
| R1 | TCP relay 许可 8192（`socks_conn_limiter`） | 每个 CONNECT 一条 | 每个转发连接一条，**无 per-listener cap** | ~8192 并发转发 TCP 流 | SOCKS 新连接被 fail-closed 丢弃 |
| R2 | UDP 会话池 4032（`UdpHub`） | 每个 UDP ASSOCIATE 一个 | **每个 peer 源地址一个**，默认可占满 | 稳态 peer 数 ≥ 预算，或 >~20 新源/s | SOCKS `UDP ASSOCIATE` 被拒 `REP=0x01`；转发 peer `SESSION_FULL`；最长 180s |
| R3 | interactive UDP egress 单连接 | 小包 ECHO（≤512B） | 目标端口在 interactive_ports 或首包 ≤512B | 转发进入 interactive class | 共享 cwnd/队列/dispatcher，延迟与 pps 相互影响 |
| R4 | bulk UDP egress 分片（默认 2） | >512B 流 | 同类 peer | 大规模 bulk 转发 | 分片级带宽/驱动时间共享；rr 游标受转发首包影响（仅分布） |
| R5 | 服务端 session 池 8192 / 公平份额 1024..4096 | 每客户端关联 | **每 peer 一个完整 session**（fd+task+~288KiB 计费） | 大规模转发 peer | 服务端池/份额耗尽；创建内联阻塞同连接 reader（HOL） |
| R6 | TCP pool slot（默认 4）/ per-conn 8192 stream 信用 | 按目标选 slot | 同池同 slot | 转发 bulk 与 SOCKS 落同一 slot | 共享 cwnd/单线程 driver，延迟上升；极端情况 open_bi 5s 超时 |
| R7 | per-conn rev2 重组预算 256KiB | 分片回复 | 分片回复 | 分片转发流量 | 后到分片被拒（既有共享预算形状） |
| R8 | 主 runtime CPU + 日志/计数器 | SOCKS accept/assoc 任务 | 每监听器 1 任务（串行处理全部 peer） | 转发 pps 高 | 同核竞争；单监听器上限 1 核 |
| R9 | 启动耦合 | SOCKS 可用性 | 转发校验/绑定失败即退出 | 配置错误/端口占用 | SOCKS 一并不可用（有意的 fail-loud） |

---

## 6. 实测 A/B 基准（release 二进制，macOS arm64 loopback）

> 数据与原始日志见 `bench.md` / `bench-raw/`。方法：父版本 client（`1135076`）与 HEAD client（`7232088`）对同一 HEAD server；A/B 交替重复取中位数；另测“HEAD + 空闲转发监听器”与“转发路径绝对性能”。本机 loopback 噪声较大，绝对值仅供同机对比。

### 6.1 方法

- 双 worktree release 构建：父版本客户端（`1135076`）与 HEAD 客户端（`7232088`）对**同一个 HEAD 服务端二进制**（server 无改动，sha256 `95cbe0cf…`）；`hotpath_bench` 作为负载与 echo 目标；每次运行新起 server+client，交替 A/B，丢弃 warmup；macOS loopback，`load average 4–6`（无关进程），所以绝对值只适合同机对比，不用于 Linux/生产推断。
- 原始数据、每个 run 的日志（含 lossy run 与 load 行）、配置与脚本：`bench-raw/`；完整方法与复现命令：`bench.md`。

### 6.2 A：SOCKS5 ECHO，父客户端 vs HEAD 客户端（均未配置转发）

| 指标 | parent `1135076` | HEAD `7232088` | 结论 |
|---|---|---|---|
| UDP 未节流 blast（10,000×64B，clean 运行）pps 中位 | **33,088**（34/40 clean） | **30,571**（28/40 clean） | **−7.6%**，Mann-Whitney z=3.49（p≈5e-4）；第二组 15 run/arm 复现 −5.3% |
| UDP blast 中出现 1–2 包丢失的运行比例 | 9/55 | 19/55 | Fisher 精确检验 **p=0.048** |
| UDP paced 30k pps 丢包（中位） | 0% | 0% | 无差异 |
| UDP 全双工 20k pps（udpbidir） | 0.000% | 0.000% | 无差异 |
| 多关联 paced 4×4k（udpmultipaced） | 0.000%，recv 14,538–14,541 | 0.000%，recv 14,538–14,541 | 无差异 |
| UDP 串行 RTT p50/p99（独立测量） | 116 / 320 µs | 116 / 327 µs | 无差异 |
| UDP 未节流 knee @44k offered（n=2） | 0.000 / 0.015% | 0.774 / 1.701% | 方向性：HEAD 更早失去余量 |
| TCP `lattcp` echo p50 | 131–136 µs | 131–137 µs | 无差异 |
| TCP 8MiB `tcpecho`（warm 后，clean A/B） | 89.1 MB/s | 89.5 MB/s | 无差异（双峰现象两版等频出现，属既有 loopback 调度特性） |

**解读**：稳态/节流 UDP、串行延迟、TCP 全部无回归。唯一可检测的差异在**未节流突发路径**（−5~8% 吞吐余量、丢包概率约 2 倍，绝对丢包率仍只有 ~0.01–0.02%）。代码级分析显示每回复增量只有 ~1ns 量级，**无法解释 5–8%**，因此归因**未定**：最可能是新增 ~700 行链接代码 + `send_payload_uplink` 抽取导致的编译布局/内联扰动（`socks.md` 预判的残余风险 R1），而不是语义性热路径变更；必须在 Linux 目标环境用正式 release/PGO 复核后才能作为发布门禁。对应用的实际影响面很窄：只有“无节流突发且贴着吞吐上限”的 UDP 负载会看到；RTP 类 paced、多关联 paced、普通 UDP ECHO 不受影响。此外 campaign 中“blast 之后的 p99”HEAD 偏高，但独立复测不复现，列为**未解释项**。

### 6.3 B：HEAD + 1 个空闲 `tcp_forward` + 1 个空闲 `udp_forward` vs 不配置

| 指标 | headA（无转发配置） | headB（转发监听器空闲） |
|---|---|---|
| UDP blast clean pps 中位 | 29,512（8/15 clean） | 30,700（10/15 clean） |
| UDP `lat` p50 / p99 | 117 / 397 µs | 117 / 360 µs |
| `udppaced` 30k 丢包 | 0, 0.029, 0, 0, 0, 0.184% | 0, 0.030, 0, 0.067, 0, 0% |
| `udpbidir` 20k / `udpmultipaced` 4×4k | 0.000% / 0.000% | 0.000% / 0.000% |

**结论：仅配置空闲转发监听器没有可测干扰**（3 rep/arm 下“无信号”，不是等价性证明）。符合静态分析：空闲监听器只是各多一个 parked task + 一个 30s timer，不进入 SOCKS 热路径。

### 6.4 C：转发路径本身的绝对性能（HEAD + 活跃转发）

| 指标 | 转发路径 | SOCKS 基线（同二进制，数分钟内） |
|---|---|---|
| UDP forward 吞吐（1000B，10k，batch 64） | 中位 **32,267 pps**，5/5 clean，**0.000% 丢包** | clean 中位 30,700 pps |
| UDP forward 串行 RTT p50 | **113 µs** | 117 µs |
| UDP forward 50 并发 peer ×2000 包 | **50,886 / 50,805 pps（100,000/100,000），0.000% 丢包** | 形状不同，未测 |
| TCP forward 8MiB 批量（SHA-256 校验） | 中位 **86.3 MB/s**（稳态 83–91.5） | `tcpecho` 中位 ≈92.5 MB/s |
| TCP forward 流 RTT p50 | **96 µs** | `lattcp` echo p50 131–137 µs（含每轮新 CONNECT，不完全可比） |

**结论：转发数据面本身没有明显的性能问题**，UDP 侧甚至略优于 SOCKS（省掉每包 SOCKS5 头与关联握手），50 个 per-peer session 聚合 50.8k pps 且零丢包；TCP 批量与 SOCKS 同量级。

### 6.5 S0 复核：TCP 转发是否损坏数据？

基准脚本早期在 2/4 次 `tcp-bulk` 上报 `mismatched=1..4`。已定位为**校验脚本 bug**（期望字节切片 `reps[start:start+k]` 在 `reps` 只有 2×65536B 时会截断，误计 mismatch），与 relay 无关。修正后的校验：**SHA-256 全流校验**——直连目标 5/5、经 `tcp_forward` 10/10、经 SOCKS `tcpecho` 10/10 全部匹配；**逐块比较**——直连 10/10、转发 20/20，0 坏块。**结论：无数据损坏/乱序，不构成 S0。**

### 6.6 噪声与局限

- macOS loopback + 10 核机器上 `load average 4–6`；所有数字为中位数，原始 run 全部归档，可重算分布。绝对值不能与空闲机/Linux 对比。
- loopback RTT≈0，测的是 framing/CPU/调度效应（正是本次提交触碰的部分），不是 WAN 拥塞行为。
- 未节流 UDP pps 用 clean-run 中位（存在 outcome 选择偏差），因此同时报告了无偏的“lossy run 比例”；knee sweep 与 B 场景样本量小（n=2 / 3 reps），只能发现大效应。
- 转发路径 C 用单线程 python driver，其自身上限 >50k pps，但调度噪声大于 Rust harness，数字较粗。
- **A 场景的 −5~8% 未节流突发差异归因未定**（见 6.2），Linux + PGO 正式构建复核前不应下“确定性回归”结论。

---

## 7. 修复建议（按优先级）

**P0（建议本迭代修）**
1. **U1**：给 UDP 转发聚合预算设上限并默认取全局的一小部分（例如 `max_udp_assocs/4`）；支持满时驱逐本监听器最老空闲 peer；文档写明 churn 规则；对非 loopback 监听器建议更短 idle 或显式 `max_sessions`。
2. **T1**：为 TCP 转发增加 per-listener/聚合连接上限（与 UDP 对齐），避免单监听器占满 8192 共享许可。

**P1（强烈建议）**
3. **U4**：去掉 transient recv 错误的 20ms 无条件 sleep；改为排空错误队列/仅在连续错误时退避；send 侧异步错误计数并可重试一次；补 Linux 回归测试。
4. **U2**：明确并限制“每 peer 一个服务端 session”的成本（服务端 per-connection forward 配额或客户端建速率限制），至少写入文档/配置指南。
5. **U3**：文档化 wildcard 监听器的回复源地址限制，或实现 `IP_PKTINFO` 回填。

**P2（清理项）**
6. U5/U6/U11：单任务上限与公平性（必要时按 plan §11 做 SO_REUSEPORT 分片）、`peers.entry()` 单次查找。
7. U7/U8：转发会话 gauge、独立 drop 计数、listener 启停 info 日志、任务监管/重启、错误分类与计数。
8. U9/U10/T2–T8：配置/文档一致性（mapped 地址归一化、overlap 规则、mapped-unspecified 拒绝）、`raw` 加入 flush 分组 key、补齐 grouped/batch/双栈/oversize/churn/RST 测试。

---

## 8. 残余风险与未验证项

- **A 场景未节流 UDP 突发 −5~8% 的归因未定**：代码级每回复 ~1ns 无法解释该量级；最可能是新增代码引起的编译布局/内联扰动（`socks.md` R1），也可能是 loopback 测量偏差。**在 Linux 目标环境用正式 release/PGO 构建复核 A/B 之前，不应把它当作确定性回归，也不应忽视它**（若 ECHO 突发吞吐是发布门禁，建议把该 A/B 加入 Linux bench matrix）。
- **Linux 专属行为**未在本机（macOS）复现：ICMP 异步错误语义（U4）、`SO_*BUFFFORCE` 与 4MiB 缓冲的实际内存、`[::ffff:0.0.0.0]` dial 行为（T2）。结论基于内核文档 + 代码路径，标注为 inferred。
- **基准是 macOS loopback**，绝对值不代表生产；Linux + `tc netem` 矩阵（`scripts/linux-bench-matrix.sh`）未跑。A/B 结论只要求同机同轮次可比。
- 转发路径基准使用自定义脚本（UDP echo / TCP echo，SHA-256 校验），不是产品基准；TCP bulk 早期 `mismatched=1/4` 已定位为**校验脚本 slice 越界 bug**（见 bench.md §4.3 / `bench-raw/BUG-tcp-verifier.md`），修正后 SHA-256 全对，**不是数据损坏**。
- 转发路径 C 为单线程 python driver（自身上限 >50k pps），数字较粗；50 peer 场景只测到 50.8k 聚合 pps，更高规模未压测。
- churn/DoS 场景（U1）是数学推演 + 代码证据，未做攻击复现；多宿主/别名 IP 环境下的 U3 丢弃行为未实测。
- 空闲监听器 B 场景只有 3 reps/arm，能排除大干扰，不能证明 <5% 无影响。

---

## 附录：证据索引

| 文件 | 内容 |
|---|---|
| `analysis/forwarding-audit/socks.md` | SOCKS 热路径逐 hunk 表、逐包增量、行为不变性 14 项检查、共享预算 R2a–R2j |
| `analysis/forwarding-audit/tcp.md` | TCP 转发 T-01..T-08 详情、plan 保证逐条核对、“checked sound”清单 |
| `analysis/forwarding-audit/udp.md` | UDP 转发 UDPF-01..11 详情、生命周期/raw/双栈验证、预算表、逐包/每 peer 成本核算、修复优先级 |
| `analysis/forwarding-audit/bench.md` | A/B 命令、配置、原始结果、噪声评估、转发路径绝对性能与完整性验证 |
| 基线 | 父提交 `1135076`；特性提交 `41031b4`；HEAD `7232088` |
| 设计文档 | `docs/superpowers/plans/2026-10-23-client-tcp-udp-forwarding.md`（§4.3/§5/§6/§9/§11） |
