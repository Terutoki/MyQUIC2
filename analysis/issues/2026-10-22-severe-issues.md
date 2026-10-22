# MyQUIC2 严重问题清单（性能 / 内存 / 逻辑）

> 基线：`main` @ `8f0d685`（工作区干净）· 日期：2026-10-22
> 方法：5 个只读域审计并行（UDP 数据面 / MQP 线协议 / server / client / shared core），Lead 做跨域复核、去重与定级；
> `cargo check --workspace --all-targets` 通过，`cargo test --lib --bins` 全绿（macOS），**源码/测试/配置零改动**。
> 各域证据原文见 [udp-dataplane.md](udp-dataplane.md)、[mqp-wire.md](mqp-wire.md)、[server-bin.md](server-bin.md)、
> [client-bin.md](client-bin.md)、[core-dns.md](core-dns.md)；本文只保留去重后的结论与 Lead 复核结论。
>
> 结论先说：**未发现"无条件 S0"**（没有远程必现崩溃/任意读写/协议解析越界），但发现 **10 个 S1 级问题**，
> 集中在三类：(1) 三个"内存上界"在真实触发路径上被绕过（admission 记账与 RSS 不符）；
> (2) 三个可用性/拒绝服务面（CTL 帧 CPU 放大、预认证槽位耗尽、会话池泄漏）；
> (3) 两个静默丢包/永久黑洞（丢一条 `OPEN|SRC` 或一个 `SESS_CLOSE` 就永久失聪）＋ 一个编码器/解码器自相矛盾的 S1。
> 另有 16 个 P1（材料级）与一批 P2/文档/可观测性小项。

---

## 0. 定级与验证

- **S1（P0，本轮最严重）**：正常生产负载/常规攻击流量下即可触发的内存上界绕过、跨客户端 DoS、永久静默丢包或 CPU 放大。
  "代码机制"均已由 Lead 或审计人按行复核；个别影响量级需要基准/抓包实测（文中标注）。
- **S2（P1）**：条件触发或影响面较窄的材料级问题。 **P2**：局部/低频，附在末尾清单。
- 验证标记：**[复核]** = Lead 独立重读了代码/依赖源码确认；**[审计]** = 域审计人按行取证，Lead 未逐行重读；
  **[推断]** = 机制成立但影响量级是分析估算，缺实测。

---

## 1. P0 —— S1 严重问题（建议优先处理）

| # | 类别 | 位置 | 一句话 | 置信/验证 |
|---|------|------|--------|-----------|
| MEM-1 | 内存上界 | `src/udp/r2_reasm.rs:79-92, 386-398, 486-492` | 乱序分片以 `Bytes` 视图挂起，一个 49 B 记账项可钉住 quinn 整批 GRO 接收缓冲（≤~92 KiB）；256 KiB 单连接上界被放大 100–1900× | 高 / **[复核]** |
| MEM-2 | 内存上界 | `src/dns/store.rs:67-68, 83-92` + `src/dns/resolve.rs:459-479` | 正 DNS 缓存只按"条目数"限容，单条地址集合由对端权威 DNS 决定（TCP 应答最大 64 KiB），缓存可驻留数百 MiB–~1 GiB，而 admission 只计 9.17 MiB | 高/中 / **[复核]** |
| MEM-3 | 内存上界 | `src/config/tuning.rs:496-505` + `src/bin/myquic2-server/main.rs:222, 235-241` | `stream_pump_memory_bytes` 只计 2×16 KiB 用户态泵缓冲，未计 TCP relay 套接字内核 `SO_SNDBUF/SO_RCVBUF`；16,384 流池实际可钉 1.2–2.3 GiB+，启动日志却称"worst case 512 MiB" | 高 / **[复核]** |
| LOGIC-1 | 逻辑/生命周期 | `src/bin/myquic2-server/forward.rs:516-536, 585-593` + `reader.rs:1421-1437` | 8f0d685 的"SESS_CLOSE × domain DNS"修复只覆盖 rev2 `DATA OPEN` 路径；通用 DNS 慢路径在 DNS 返回后用**无守卫** `get_or_create_sess`，会确定性复活刚关闭的 session（socket+task+全局许可泄漏至 180 s 清扫） | 高 / **[复核]** |
| LOGIC-2 | 逻辑/热路径 | `src/bin/myquic2-client/rev2.rs:55, 272-311, 518-535` | `closed_sessions` 只增不减：任一条过期 SESS_CLOSE 残留后，**每个上行数据报**都要拿排他锁线性扫描；累计 64 条后新 SESS_CLOSE 被静默丢弃 → 服务端已回收 session、客户端仍发 steady 帧，**永久静默黑洞** | 高 / **[复核]** |
| LOGIC-3 | 逻辑/协议 | `src/bin/myquic2-server/reader.rs:521-553` + `src/mqp/r2_flow.rs:269-300` + `src/bin/myquic2-client/dispatcher.rs:756-758, 960-978` | 服务端在 quinn "Sent"（不可靠）时即 `set_reply_src`，`match_source` 此后永远 Exact、不再补 `OPEN|SRC`；客户端只有收到 `OPEN|SRC` 才知道 reply_src。丢一帧 ⇒ 该 flow 下行永久失效（domain/source-change/full-cone），且客户端根本不发 FLOW_ACK/REJECT，无恢复机制 | 高 / **[复核]** |
| LOGIC-4 | 逻辑/线格式 | `src/mqp/r2.rs:634` vs `:428-456`；`src/udp/r2_stage.rs:584-585`；`src/bin/myquic2-client/assoc.rs:243-247` | TRAIN 的 `len==0` item：本端编码器会生成（空 UDP 载荷合法），本端解码器却整帧拒绝。一条空载荷混进多 item TRAIN（≤64 条，可跨 session）⇒ **整帧、其它 session 的报文一起静默丢失**，双向可触发 | 高 / **[复核]** |
| PERF-1 | 性能/DoS | `src/bin/myquic2-server/accept.rs:1275-1280, 1366-1384` + `src/mqp/r2_flow.rs:500-508`；客户端同型 `dispatcher.rs:888-896` | 重复/伪造 `CTL SESS_CLOSE`（7 B body）在"session 是否存在"早退**之前**就对 4096 项 registry 做 `HashMap::retain` + 写锁；无 CTL 速率/去重上限（spec §3.4 要求）。~30 B 帧换 10⁴–10⁵× CPU，同连接/同 shard 的 steady 转发被写锁阻塞 | 高 / **[复核]** |
| PERF-2 | 可用性/DoS | `src/bin/myquic2-server/main.rs:625-656, 732-749` + `auth.rs:12-24` | 预认证槽位（256）在握手前获取、token 校验后才释放，5 s+5 s 预算内可被"只连不说话"的对端占满；~26–51 个停滞握手/秒即可让**所有新连接**（含合法 token 持有者）被拒；无 per-source 限速/驱逐。tokenless 模式同样经 `conn_limit`+10 s 超时成立 | 高 / **[复核]** |
| PERF-3 | 性能 | `src/bin/myquic2-client/main.rs:87-97` + `src/bin/myquic2-client/pool.rs:878` | 默认 7 个 slot runtime 时主 runtime worker = `cores-7`（下限 1）⇒ ≤8 核机器上**全部 SOCKS accept/TCP relay/UDP assoc 任务挤在 1 个 worker**；非 Linux 的 `pin_to_core` 是空操作，减扣依据不成立。疑似吞吐回归，需基准确认 | 高/需实测 / **[复核]** |

> 说明：MEM-1 在"每连接 256 KiB"口径下是**确定性越界**；要打满数百 MiB 需要较高入向带宽
>（钉住量 ≈ 入向速率 × 2.5 s 分片超时），故定为 S1 而非无条件 S0。另：LOGIC-4 的触发需要该空载荷与
> 至少另一个 steady item 同批打包（`run_len==1` 时走 standalone `DATA`，解码器接受空 payload）。

---

## 2. P1 —— 材料级问题（S2）

| # | 类别 | 位置 | 问题 | 置信 |
|---|------|------|------|------|
| PERF-4 | 性能/公平 | `src/bin/myquic2-server/accept.rs:288, 2290-2330`；`forward.rs:463, 478` | 快速会话表只有 16 槽，而协议设计按"单连接承载数百 association"；>16 个活跃 session 时几乎每个报文都走慢路径（2–3 把 shard 读锁 + 255 B pin 拷贝 + **绕过 sendmmsg 的逐包 `udp_try_send`**） | 高 |
| PERF-5 | 性能/锁 | `src/udp/retry.rs:125-155` | 最后一次发送 `WouldBlock` 时，每个数据报 spawn 一个 `JoinSet` task + 一个 `timeout` 定时器 + 一次 payload copy；这正是拥塞时的稳态，和文件内"no task is spawned per packet"的承诺相反 | 高 |
| PERF-6 | 性能/分配 | `server/reader.rs:1052-1094`；`client/rev2.rs:598-627` | 下行每个小回复：owned `Bytes::copy_from_slice` + stager 节点 + 新帧 `Bytes`（2–3 次分配+1 次全量拷贝）；上行每个小载荷：一次 heap copy + 连接级 stager 互斥锁；多 association 时是主要分配器流量 | 高/中 |
| PERF-7 | 性能/停顿 | `server/accept.rs:2201-2216`；`reader.rs:1558-1567, 1673-1682` | 回收（60 s 清扫/fair-share/session-pool）在 packet/shard runtime 上同步执行：每个被回收 session 一次 registry 写锁 + 3 个 `CTL SESS_CLOSE` datagram；4096 session 连接 = 数千次 `try_send_datagram` + registry 写锁，毫秒级阻塞该 shard 的全部连接 | 中 |
| PERF-8 | 性能/扫描 | `src/mqp/r2_flow.rs:472-493` + `client/rev2.rs:923-939` | 新目标上行路径在**读锁**下全表扫描 4096 项 registry（`find_server_flow`）找可复用 server-owned flow；大量唯一目标时 O(flows)/新目标并阻塞 writer。另：8f0d685 把 `has_capacity()` 探针移到该扫描**之前**，registry 满时连已存在的 server-owned flow 也不再复用（退回 INLINE） | 高 |
| PERF-9 | 性能/锁 | `client/dispatcher.rs:1033-1051` | 客户端 TRAIN 入口逐 id 取读锁 + Arc clone；`FlowRegistry::get_batch` 已存在（server 在用）却未用，一个 64-item 帧 = 64 次锁往返 | 高 |
| LOGIC-5 | 逻辑/时延 | `server/reader.rs:1314-1325, 1186-1202` | 连接级 stager 只在 session reader 的 burst 边界 drain；`Blocked` 后没有重试定时器，也没有 teardown 时的 drain——静默尾包可能一直排队到下一次"别的 session 有回复"或连接关闭。**更正**：连接对象析构时 `R2Stager::drop` 会按 `EGRESS_DEAD` 记账，故不是"完全无计数"，但"无限期延迟"成立 | 高 / **[复核]** |
| LOGIC-6 | 逻辑/TTL | `server/forward.rs:590`；`accept.rs:1582` + `pin.rs:433-453` | 慢路径 DNS 完成后用固定 `DNS_CACHE_TTL_MS` 装载 pin/session dest memo，而 `resolve_all_cached` 可能命中的是"即将过期"的缓存项 ⇒ 实际可用比 120 s 上界多 30 s，`pin_life_ms` 的 clamp 契约在这两处失效 | 高 |
| LOGIC-7 | 逻辑/竞态 | `src/dns/resolve.rs:454-458` + `src/dns/memo.rs:123-138` | negative-memo 的 epoch 在负面缓存探测**之后**采样：并发的成功解析 bump epoch 后，失败线程可能把自己过期的负 memo 打上新 epoch 标签，导致该线程最多 10 s 错误拒绝一个已可解析的域名 | 中 |
| LOGIC-8 | 逻辑/泄漏 | `client/rev2.rs:432-466` | association 退出清理（registry.remove_session + stager.drop_session）以 `rev2.is_ready()` 且能拿到 egress handle 为前提；握手窗口内退出/刷新失败时 binding 与暂存 payload 泄漏到连接结束，服务端 session 要等 180 s 清扫（其回收又喂给 LOGIC-2） | 高 |
| LOGIC-9 | 逻辑/回归 | `server/reader.rs:1379-1400` | 8f0d685 新增的 `no_live_entry` 守卫：reader 退出后若同 id session 被重建，则死条目的 ≤64 个 binding 永不标 Closed/移除，泄漏到连接结束（该守卫并不必要——清理本来就只按死条目自己的快照遍历） | 中 |
| LOGIC-10 | 逻辑/资源 | `src/dns/resolve.rs:168-198` | hickory 初始化失败时回退 `getaddrinfo`：`timeout` 丢弃 future 并归还 DNS permit，但 `spawn_blocking` 线程仍在 libc 解析（10–40 s）⇒ 1,024 permit 不再约束真实解析工作，阻塞池最多 512 线程 | 中 |
| LOGIC-11 | 逻辑/静默 | `client/assoc.rs:235`；`:214-219, 426` | SOCKS5 UDP `FRAG!=0`（合法但本实现不支持）直接丢弃、零计数/零日志；`expected_app_ip` pin 对地址族敏感（控制连接 v4 + UDP 从 `::1` 来，或反之）⇒ 所有报文被静默忽略，association 装死到 180 s | 中 |
| OBS-1 | 计数/静默丢包 | `udp/r2_frag.rs:194-205, 232-249`；`udp/r2_reasm.rs`（0 个计数）；`server/reader.rs:1106-1109`；`udp/r2_stage.rs:848-857` | rev2 FRAG/大包在 `Blocked`/`TooLarge`/budget 拒绝/过期/驱逐时全都没有 `dgram_drops` 计数（旧 MQP-2 路径每种都有）；stager 还把 `TooLarge` 记成 `EGRESS_DEAD`（连接明明活着）。下行饱和时丢包对运维完全不可见 | 高 |
| OBS-2 | 计数/争用 | `stats/udp_stats.rs:46-55, 88-118, 202-222`；`stats/udp_write.rs:39-56`；`server/accept.rs:830-878` | 线程本地计数只按数量（256）flush、无时间 flush，`snapshot()` 只能 flush 调用线程 ⇒ 低速率 worker 的 relay/sent 计数可无限期为 0（与"cannot dwell at zero"注释矛盾）；server 侧 `r2_stats::bump` 又是每帧全局 `fetch_add`（热路径共享 cache line） | 高 |
| SEC-1 | 安全 | `src/tls/cert.rs:8-17` | 自动生成的服务器私钥用 `fs::write` 落盘（umask 022 ⇒ 0644），本机任意用户可读；客户端又把该证书当唯一 pinned root ⇒ 多用户主机上可完整中间人解密隧道（未来会话，非历史会话） | 高 |
| DOC-1 | 文档/配置 | `config-server.toml:34-47`；`README.md:26, 133`；`MQP3_REV2_SPEC.md:5` | 示例配置的 admission 注释仍是旧数字（"4 KiB 流表 / ~1.09–2.09 GiB 池 / 14.5 MiB 每连接 / ~512 MiB 泵"），实际已是 22 KiB / 2.25 GiB / 19.625 MiB + 384 MiB assembler + 34 MiB retry + 8.75 MiB DNS（≈3.1 GiB 固定项），按示例设 `max_peer_memory_mb` 会严重低估；另 README/分析文档仍出现 spec 明令禁止的字面 "MQP-4" | 高 |

---

## 3. P2 / 小项（记录在案，暂不展开）

| # | 位置 | 问题 |
|---|------|------|
| P2-1 | `mqp/r2.rs:857-861` | `CAPS.max_conn_flows / max_flows_sess / max_reassembly` 解码后从未被消费（仅 `max_frame_bytes`/`max_train_items` 生效），与 spec §2.3/§5.7 的"协商上限"契约不符；当前两个自带二进制恰好同值故无运行时影响 |
| P2-2 | `mqp/v3.rs:140-155` | 旧 v3 解码器的 varint 用 wrapping 移位，接受溢出编码（rev2 已正确拒绝）；仅旧线兼容入向，非 S0/S1 |
| P2-3 | `udp/r2_stage.rs:620-647, 705-714, 918-975` | 每个 DATAGRAM 打包新建 `Vec` + O(flows×items) `position` + 每个 train 首项的 O(sessions) `rotate_steady_past`，且都在连接级 stager 锁内（成本小） |
| P2-4 | `udp/r2_reasm.rs:169-181, 205-212` | 顺序分片 `resize(end,0)` + `copy_from_slice`，每个 chunk 写两遍 |
| P2-5 | `server/reporter.rs:6-35` vs lib `warn.rs:6-18` | 三个 `warn_*` 用 0 初始化而非 `NEVER_WARNED`，首秒的握手/fd 风暴告警被吞 |
| P2-6 | `server/accept.rs:1717` | `PendingOpen::Full`（每连接 16 槽上限）被计入全局 `DNS_BUDGET`，60 s 报表会误报解析预算耗尽 |
| P2-7 | `server/accept.rs:681, 732`；`reader.rs` 多处 | `udp_stats::payload` 在 forward/send 结果之前计数，被拒绝/丢弃的载荷仍算作已转发 |
| P2-8 | `client/dispatcher.rs:179-185` | hub 中"存在但已死"的 entry 返回 NoEntry 却不计 `UNKNOWN_SESS`（与枚举注释不符） |
| P2-9 | `client/dispatcher.rs:1248-1263` + `egress.rs:393-405` | conn handle 与 slot.rev2() 分两次读，死亡+重拨窗口内可能"旧连接 + 新 generation 表"配对；需 >200 ms 抢占才可达，低概率 |
| P2-10 | `client/dispatcher.rs:1369-1373`；`server/accept.rs:2355` | 客户端 500 ms 重组过期 tick 未按需臂定（server 有 `held_bytes()>0` 守卫）；连接数少，≈2 wake/s/conn |
| P2-11 | `server/auth.rs:24` vs lib `mqp/ack.rs:54` | `AUTH_MAX_BYTES` 在 server 重复声明（当前同为 256），库常量变更会静默漂移 |
| P2-12 | `config/tuning.rs:371-377` | `RECENT_ADDRS_BYTES` 硬编码"16 槽"，未与 binary-private `RECENT_DST_CAP` 建立编译期约束 |

---

## 4. 跨域去重与复核记录

| 合并后编号 | 来源报告中的重复项 |
|---|---|
| LOGIC-1 | server-bin #1 |
| LOGIC-2 | client-bin C1 |
| LOGIC-3 | mqp-wire PW-2 |
| LOGIC-4 | mqp-wire PW-1 |
| PERF-1 | server-bin #2 + mqp-wire PW-3 + client-bin C3 |
| PERF-4 | server-bin #5 |
| PERF-6 | server-bin #9 + client-bin C6 |
| PERF-7 | server-bin #10 |
| PERF-8 | mqp-wire PW-6 + client-bin C7（`has_capacity` 顺序回归） |
| PERF-9 | client-bin C5 |
| OBS-1 | server-bin #8 + udp-dataplane UDP-03 + UDP-04 |

Lead 独立复验（重读代码/依赖源码，非只看报告）的项：MEM-1（`PendingChunk` 视图 + quinn
`endpoint.rs:790-800` 的每 `recvmsg` `BytesMut` 分配与 `frame.rs:711-716` 的 `Bytes` 切片）、MEM-2
（`resolve_ips` 无条数上限、moka 仅条目数限容）、MEM-3（`tune_relay_tcp` 只设 NODELAY/NOTSENT_LOWAT，全树无 relay
TCP `SO_*BUF`）、LOGIC-1/2/3/4、PERF-1/2/3、PERF-4/8、LOGIC-5（并修正了"teardown 无计数"的说法）、
LOGIC-6/9、OBS-1、DOC-1 的实际数字。**未实测**：所有吞吐/内存量级、丢包触发器、DoS 速率，均需基准或
netem 复现（见 §6）。

---

## 5. 检查后确认"没有问题"的面（避免把已知优化当缺陷）

- **解析器抗敌对输入**：rev2 `DATA/TRAIN/FRAG/CTL`/地址解码全部先验长度后切片，无按长度字段驱动的分配，
  LEB128 溢出/截断/尾随字节均拒绝；TRAIN count ≤64；无对端可控 panic 路径（release 为 `panic=abort`，这点重要）。
- **首字节分派**：rev2 `0x0X` 与旧 `0x02/0x05/0x06`、旧 v3 `0x1X–0x4X` 两两不相交，拆包顺序两端一致。
- **所有权/ID 规则**：wire_id 单调不复用、owner 半区校验、`insert_new` 先查容量再分配（8f0d685 的 id 泄漏修复确实生效）、
  INLINE 失败兜底、按 session 作用域的 stager/reassembler 清理。
- **SSRF 策略**：完整 CIDR 表 + IPv4-mapped/translated/NAT64/compatible 递归，`::ffff:127.0.0.1`、元数据地址等均拒绝；
  domain 路径全量过滤后才装 binding，steady 帧只用已授权地址。
- **TCP 泵**：字节计数、部分写、vectored 写、idle AND-gate、RST-vs-FIN、`BytesMut::try_reclaim` 精确 reserve 均正确。
- **热路径基线**：steady fast path 无分配、无 shard 锁、无 DNS 查询、`slice_ref` 零拷贝；stager 锁不跨 send/await。
- **admission 其余公式**：session pool/endpoint/retry/DNS waiter/worker scratch 与结构体一致；quinn assembler 按 96 B/span
  记账偏保守；窗口/超时/MTU/token 长度等配置 clamp 正确。

---

## 6. 建议修复顺序（若只做 5 件事）

1. **LOGIC-3 + LOGIC-2 + LOGIC-1**：先补控制面确认语义（客户端发送 FLOW_ACK/REJECT；`OPEN|SRC` 未确认前不置
   `reply_src` 且可重发）+ 客户端 `closed_sessions` 改为"按 session 消费 + TTL/墓碑" + 通用 DNS 慢路径接入取消令牌。
   这三项决定"丢一帧就永久黑洞/泄漏"的可用性画像。
2. **MEM-1**：`PendingChunk` 改为拥有字节（或限制 pending 视图 pin 的批大小），并让 `held_bytes()` 反映真实驻留。
3. **MEM-2/MEM-3**：DNS 缓存加 per-entry 地址条数上限/字节 weigher；relay TCP 显式设小 `SO_SNDBUF/SO_RCVBUF` 并计入
   `stream_pump_memory_bytes`（或把真实内核上界写进 admission）。
4. **PERF-1 + LOGIC-4**：SESS_CLOSE 先判存在再扫（或按被回收 entry 自己的快照清理）+ CTL 速率/去重上限；
   `decode_train` 接受 `len==0`（或两个 stage 站点过滤空载荷 + 解码器保持兼容）。
5. **PERF-2 + PERF-4 + PERF-3**：预认证槽位按源限速/缩短、快速表按"数百 session"重新定容并实测、客户端主
   runtime worker 数在非 Linux/≤8 核上重新评估（附基准）。

其余 P1 可与上述并行排期；P2 建议随手清理（尤其 OBS-1/OBS-2，否则以上问题的线上证据不可观测）。

---

## 7. 残余风险与未覆盖

- 所有涉及"吞吐/内存量级/DoS 速率"的数字都是源码推导；未在 Linux 目标机跑 `examples/hotpath_bench.rs`、未用
  `tc netem` 复现 LOGIC-3/LOGIC-4。
- 未覆盖：`src/bin/*/tests.rs` 之外的集成行为、真实 quinn 版本升级后的内部契约、macOS/OpenWrt 内核 socket 默认值差异、
  `max_peer_memory_mb` 未配置时（默认）的整机 worst-case 实测。
- 依赖侧假设已核对到锁定版本（quinn 0.11.12 / quinn-proto 0.11.19 / quinn-udp 0.5.16 / hickory-resolver 0.26.3 / bytes 1.12.1），
  升级时需重验 MEM-1 的 GRO 批分配与 pw 的 `try_reclaim` 语义。

---

## 8. 修复状态（2026-10-22，同日落地）

**全部 P0（10 项）与 P1（16 项）已修复；P2 中可代码修复的项已修复，其余按设计文档化。**
逐项修复位置、测试证据、有意的行为/配置变化与残余取舍见 [2026-10-22-fixes.md](2026-10-22-fixes.md)。

验证：`cargo fmt --check` 干净、`cargo clippy --workspace --all-targets -- -D warnings` 0 告警、
`cargo test --workspace --all-targets` **530 passed / 0 failed**（原 476）；真实 client+server 端到端冒烟
（TCP domain/IP + 20 并发、UDP domain flow 含空载荷 TRAIN、UDP IP flow）在 tokenless ×3 与 auth ×2 下全部通过。
