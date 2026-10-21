# MyQUIC2 数据面性能分析报告（代码逻辑层面）

> 分析日期：2026-10-19 · 基线提交：`d73809f` · 只读分析，未修改任何源码。
> 范围约束：**只分析代码逻辑**，不分析配置参数取值（窗口/MTU/buffer size/timeout/核数等），
> 所有修复建议均为代码逻辑、数据结构、批处理或调度结构层面的改动。

---

## 0. 分析范围与方法

- 四路并行深读 + Lead 逐条复核：
  - `src/udp/**` + `src/mqp/**`（~4.7k 行）
  - `src/bin/myquic2-server/**`（~3.6k 行）
  - `src/bin/myquic2-client/**`（~3.2k 行）
  - `src/lib.rs` 生产段、`src/dns/**`、`src/stats/**`、`src/transport/**`、`src/linux.rs`
- 关键结论均有代码行号证据；量化数字来自各分析者的 `/tmp` 微基准（Apple M4/macOS，**只用于量级**），
  以及代码/README 内已有的测量记录（如 `accept.rs` 的 +8.8% CPU、`frame_bench` 的池化否决数据）。
  端到端收益仍需在 Linux 目标机用 `examples/hotpath_bench.rs` 复测。

### 总体判断

主数据路径（UDP 编码 → quinn DATAGRAM → sendmmsg / recvmmsg；TCP 双缓冲 pump）**已经高度优化**：
稳态每数据报 = 1 次精确容量分配 + 1 次 payload 拷贝 + quinn 内部 1 次状态锁，
没有逐包 Mutex / 通道 / 任务 / 格式化日志，统计已 thread-local 批处理，BATCH 解码零分配。
因此本次报告没有 P0；剩余问题集中在 **4 个 P1（其中 2 个是逻辑缺陷型放大）+ 9 个 P2 + 若干 P3**。

| 编号 | 优先级 | 位置 | 问题一句话 |
|---|---|---|---|
| F1 | **P1** | `server/forward.rs:55-143` | 域目标被 SSRF 过滤时**每包 spawn 一个 resolver 任务**，且永不 arm 连接 fast table |
| F2 | **P1** | `server/accept.rs:258-438` | 16 槽直接映射 fast table 与客户端**稀疏单调 session id** 冲突，冲突会话每包退化慢路径 |
| F3 | **P1（系统级）** | `client/main.rs:49,210-244,473-543` | 分片 slot runtime 叠加主 runtime 默认 worker 数，Linux 默认路径**确定性核心过度订阅** |
| F4 | **P1** | `udp/reassembler.rs:336-361,603-632` | 分片重组器淘汰用 **O(256) `min_by_key` 全表扫描**，完成率 >~128/s 后每个完成载荷付一次 |
| F5 | P2 | `server/reader.rs:138-248` + `client/dispatcher.rs:549-563,retry.rs:328-332,391-408` | 下行"单条回复"路径多一次全 payload 拷贝（GROUP_SCRATCH）且被 BATCH-of-1 包装 |
| F6 | P2 | `udp/batch.rs:553-572` + `assoc.rs:245,255` / `server/reader.rs:345,362` | Linux `recvmmsg` 排空后对每个数据报**再 memcpy 一次**到调用方 buf |
| F7 | P2 | `server/pin.rs:467-492` + `reader.rs:453-466` | `remember_dst` **无条件** bump allowlist epoch，令 reply reader 的 epoch 门控失效 |
| F8 | P2 | `client/assoc.rs:195-208,373-449` | 上行小包只做 **2-pack**，同 burst 同目的地本可 8~13 个/帧（server 侧已有 N-pack 参照） |
| F9 | P2（条件性） | `udp/fragmenter.rs:237-264` | 分片发送遇 quinn 发送缓冲"够 1 片不够 N 片"时**先发前缀丢尾部**，产生孤儿分片浪费隧道带宽 |
| F10 | P2（结构） | `client/main.rs:379-388` + `assoc.rs:5-10` + `main.rs:508-543` | relay 任务在主 runtime、egress driver 钉在 slot runtime，每出站 DATAGRAM 跨核 state 锁 + driver wake |
| F11 | P2 | `lib.rs:318-394` + `server/reader.rs:769` + `table.rs:148-158` | 每 UDP session socket 多 4~5 次诊断 `getsockopt`（clamp 时 +2 次注定 EPERM 的 BUFFFORCE）；每次 insert/remove 扫 8 个 shard 读锁 |
| F12 | P2 | `stats/udp_stats.rs:92-115` | `fragmented()`/`unsolicited()` 未做同类 256 批处理，分片态每载荷一次**全局原子 RMW** |
| F13 | P2/P3 | `udp/reassembler.rs:288,384,446-448,497,319-329` | 每分片 3 次、完成时 5~6 次重复 hash 探测；完成时对 payload 二次遍历 + 两次额外分配 |
| F14 | P3 | `stats/drops.rs:239`、`accept.rs:530`、`pin.rs:389`、`fragmenter.rs:213`、`dns/resolve.rs:386-450`、`socks.rs:133-259`、`assoc.rs:45-46` | 一系列逐包/逐流可消除的小开销（见 §4） |

### 0.5 修复落地状态（2026-10-19 实施）

本报告 §1/§2/§3 的 file:line 是**分析时基线**（`d73809f`）的行号；修复后的对应代码以
`git diff` 为准。实施结果：

| 编号 | 状态 | 落地要点 |
|---|---|---|
| F1 | ✅ 已修复 | `server/forward.rs` 新增 per-connection `DnsGate`（in-flight 合并 + Unusable 5s 负缓存）+ `resolve_forward_target`（thread memo 被 SSRF 过滤时回退 session DestMemo，命中即 inline 并返回 `Some` 让 `arm_fast` 生效）；全过滤不再逐包 spawn |
| F2 | ✅ 已修复 | `server/accept.rs` 16 槽改有界线性探测（`fast_probe` / `fast_arm_index`），resolve/try_stage/arm 共用；>16 活会话才按 `last` 淘汰最不活跃 |
| F3 | ⏸ 待测量 | 线程拓扑改动需 Linux 2~4 核 benchmark 确认后再做（报告 §5 第二批） |
| F4 | ✅ 已修复 | `udp/reassembler.rs` 两个 map 各加插入序 `VecDeque` + 惰性失效 + `expire` 时 prune/超额重建；淘汰均摊 O(1)，`held` 记账不变 |
| F5 | ✅ 已修复 | `udp/retry.rs` Linux n==1+header 改两 iovec `sendmmsg`（零拷贝）；`server/reader.rs` 单条 staged 回复改发单个 0x02 帧，不再 BATCH-of-1 |
| F6 | ✅ 已修复 | `src/udp/batch.rs` 新增 `with_burst_msg`（借用式）；client `assoc.rs` 与 server `reader.rs` 的 recvmmsg 排空路径就地处理，非 Linux 保持 `burst_msg_copy` 回退 |
| F7 | ✅ 已修复 | `server/pin.rs` `remember_dst` 仅在 rcu 真正 publish 时 bump epoch（Cell 标记），稳态零 epoch RMW |
| F8 | ⏸ deferred | 量化收益 ~0.25~1% 单核，与 4 条回归测试钉住的丢包/记账/延迟不变量冲突；设计已存档（client 报告） |
| F9 | ✅ 已修复 | `udp/fragmenter.rs` 记录 `last_blocked`，分片发送在背压下先 `datagram_send_buffer_space()` 聚合预检，装不下整包丢弃（不再发孤儿前缀帧） |
| F10 | ⏸ 待测量 | 跨 runtime relay 迁移需 `MYQUIC2_SHARD_RUNTIME=0` A/B 实测后再决定 |
| F11 | ✅ 已修复 | `src/lib.rs` 进程级 socket buffer 探测缓存（后续 socket 跳过 4~6 次 getsockopt/失败 BUFFFORCE）+ `udp_socket_dual_small_addr`；`server/table.rs` 表级 `live` 计数使 `note_empty_state` O(1) |
| F12 | ✅ 已修复 | `stats/udp_stats.rs` `fragmented()`/`unsolicited()` 并入 thread-local 256 批处理 |
| F13 | ⏸ deferred | 需重写 `push_with_chunk` 借用/记账结构，收益 ~4ns/分片 + 完成时 30~45ns，风险不划算；留待独立改动 |
| F14 | ◐ 部分 | 已修：P3-2 重组 tick guard、P3-3 pin 命中免 SSRF 复检、P3-4 fragmenter 时钟惰性化、P3-5 DNS warm-hit 先正后负 + 单次分配、P3-6 SocketAddr 直传；未做：P3-1 丢包计数 padded shard、P3-7 CONNECT 定时器合并、P3-8 dispatcher slice_ref、P3-9 interactive 单连接分片（均低收益/冷路径/设计取舍） |

> 约束遵守：未改任何配置参数/默认值（`src/config/**`、`Cargo.toml` 零改动），未加依赖；
> 全部为代码逻辑、数据结构、批处理与调度结构改动。行为变化见 §7。

### 0.6 第二批修复落地状态（rev2/R2 路径，2026-10-21 实施）

第二批（T0–T9，rev2/R2 表格化、重组、stager 与统计路径）按
`T3→T4→T9→T1→T7→T5+T0→T2→T8→T6` 顺序实施；约束同 0.5（零配置/零依赖改动，
arc-swap 复用既有依赖），为既有行为钉住的测试同步更新以保持断言意图。落地要点
以 `git diff` 为准：

| 编号 | 状态 | 落地要点 |
|---|---|---|
| T3 | ✅ 已修复 | `server/accept.rs` r2_stats 新增 `TRAIN_ITEMS` 独立计数 + `bump_train_item()`：逐 **item**（一个 TRAIN 帧最多 64 项）thread-local 256 批回写，唯一一条落在包路径上的 r2_stats 线；其余 r2_stats 保持每帧一次 RMW（由测试直读） |
| T4/T4b | ✅ 已修复 | `client/rev2.rs` counters 拆 `rev2_counter_fns_tls`（thread-local `Cell` 累计、`FLUSH_EVERY` 周期回写共享）与 direct fn 两类；`Rev2Snapshot::now()` 读前先 `flush_locals()` 当前线程，快照/测试读与批处理互见。可观测计数语义不变 |
| T9 | ✅ 已修复 | `client/rev2.rs` `UplinkFlows` 单槽 memo（`last: Option<(TargetAddr, Arc<FlowBinding>)>`）服务 steady 目标：命中省 `SessionFlows::find` 线性扫描与 binding 的 Arc clone/drop；memo 槽位与 `mark_closed` 互斥语义由回归测试钉住（闭环后必须用新 id 重开，绝不复用死绑定） |
| T1 | ✅ 已修复 | `server/accept.rs` TRAIN 两遍解析：pass1 构 `item_slot: Vec<u16>` + ≤64 去重 slot（编码器上限的线性去重），新增 `FlowRegistry::get_batch` **单次读锁**填充全部 slot；pass2 逐 item 走新拆出的 `r2_forward_flow_resolved(state, binding, payload)`（binding 已 `Closed` 不转发）；原逐项入口 `r2_forward_flow_item` 变薄包装 |
| T7 | ✅ 已修复 | `client/dispatcher.rs` `dispatch_r2_train` 三层 hoist：per-distinct-id memo（跳 registry.get + reply-dst 推导）、per-session-run memo（跳 `r2_lookup` 的 Weak 升级 + is_alive + app 读）、`stage_reply_follow` 令 run 跟随项 `sock: None` 继承 flush 的 relay Arc（每 run 一次 clone）。miss 全部回落逐项路径，计数/拒绝/staging 顺序等可观测面逐项保持 |
| T5+T0 | ✅ 已修复 | `udp/r2_stage.rs` drain 两段式：`pack(limit, &mut PackedFrames)` 只在锁内编码帧，`send_packed_frames`（自由函数）在**锁外**发 QUIC，`requeue_unsent` 失败帧之后的 items 回插恢复 per-session FIFO（溢出由调用方按满队策略记账：client `BUFFER_FULL`，server 另加 `STAGE_FULL_DROPS`）；`push` 返回排队长度免二次锁定；热路径 reader/drainer 全部走三段组合。**旧的整体 `drain()` 保留但仅剩 `stage_open_src` 一个调用方**（其不变式"本次排空的队列里就是这条 OPEN SRC 且已上线"要求 push→send 单持锁），其内部亦已改为 pack+send+requeue 并断言回插零溢出。**不做 push_batch**：下行回复来自不同 session 无共享可批实体，锁跨 send 已被两段式本身消除 |
| T2 | ✅ 已修复 | `FlowBinding.resolved` RwLock→`ArcSwap<Vec<SocketAddr>>`：DNS install/rebind `store` 整组原子换、读取方 `load()` 快照永不阻塞写（REP `SourceMatch` 每候选一次快照读） |
| T8 | ✅ 已修复 | `server/forward.rs` DnsGate 新增单槽 fast hint（hot_key/hot_state/hot_deadline 三个 AtomicU64；publish 序 deadline→state→key，Release 存 key）：同 key 热路径无锁直接返回 InFlight/Unusable；finish 按裁决失效——delivered 清 entry+hint、被淘汰且权威表无此 key 才清 hint、stale finish 不扰动 newer claim 的 hint、过期按 deadline 穿透。行为测试 `dns_gate_fast_hint_is_invalidated_by_a_delivered_finish_and_expires` |
| T6 | ✅ 已修复 | `udp/r2_reasm.rs` 重组改**单 assembly buf**：total==1 零拷贝返回 `d.slice(chunk_off..)`（payload 与帧共享分配，测试断言指针相等）；多片按 `pos(i)=len(0)+(i-1)*unit`（发端分割契约：middle 等宽、末段短或等宽）**一次**拷入最终位置，位置不可定的分片持"帧视图"（Bytes refcount clone + chunk_off/len）等待 determinator，解锁时恰好一次落位；完成即 `Bytes::from(mem::take(buf))` 零二次拷贝（各 chunk end 单调 ≤ 末段 end，无需 truncate）；middle 宽度与已锁 `unit` 不符**整片拒绝**（任何 mutation 之前返回）；写入终点 > 8 KiB 一律拒绝（防恶意加宽 unit 的 resize 爆炸）。retained 记账改 capacity 基准：`buf.capacity() + pending Σ(len+48)`（`PENDING_CHUNK_COST`），每次 mutation 后重算并对 `held` 饱和增减；首次写 reserve 上限 8 KiB。`mqp/r2.rs` `FragRef` 增信息性 `chunk_off` 字段（decode 时填，wire 不变） |

> **行为变化（仅两处）**：① middle 分片宽度与同 payload 已锁 unit 不符时该分片被拒
> （旧实现容忍中段异宽并按到达序拼接——发射方契约本就等宽中段）；② `FragRef` 新增
> `chunk_off` 字段（纯信息，wire/编码不变）。held 记账从"slot 表 + chunk 长度"改为
> "assembly buf 容量 + pending 视图"，256 KiB/连接上限与满队/淘汰语义不变。
>
> **验证（macOS 本机）**：`cargo fmt --all --check` ✅ clean ｜
> `cargo clippy --all-targets -- -D warnings` ✅ clean ｜
> `cargo test --all-targets` ✅ **433 passed / 0 failed**
> （lib 206 / client 125 / server 102；含 T6 新增 5 个、T8 fast-hint 1 个、
> T9 回归 1 个、T5 requeue 2 个测试）。审查修复：`total == 64` 的完成掩码改用
> `checked_shl`（原 `1u64 << 64` 在 debug 下 panic、release 下掩码归零永不完组），
> 并由 `a_full_width_64_fragment_payload_completes` 钉住。

---

## 1. P1 问题（预期影响最大）

### F1【P1】域目标解析结果被 SSRF 过滤时，每个 UDP 包 spawn 一个 resolver 任务，fast table 永不 arm

**位置**
- `src/bin/myquic2-server/forward.rs:55-70`（解析来源选择）、`:71-87`（spawn 分支）、`:89-107`（任务内解析/过滤）、`:108-137`（任务内发送）、`:138-143`（返回 `None`）
- `src/dns/resolve.rs:431-450`（线程 DNS memo 只存"排序后首条地址"）
- `src/bin/myquic2-server/accept.rs:681-692,723-737,752-770,814-816`（只有 `forward_server_dgram` 返回 `Some` 才 `arm_fast`）

**机制（已逐行验证）**

```rust
// forward.rs:55-70 —— 只有 Unknown 分支才查 session DestMemo
let resolved = match lookup_cached_fast_with_ttl(h, p) {
    (CachedLookup::Negative, _) => { bump(REFUSED); return None; }
    (CachedLookup::Addr(dst), life) => Some((dst, life)),          // ← 被过滤地址也走这里
    (CachedLookup::Unknown, _) => sess_dest_lookup_ttl(ss, coarse_millis(), s, h, p),
};
if let Some((dst, life)) = resolved
    && (allow_private || is_global_ip_cached(dst.ip())) {
    ... send ...; return Some((dst, life));                        // 只有这条能 arm_fast
}
// forward.rs:77-87 —— 过滤失败 / 未缓存 → 每包 permit + clone + spawn
let permit = dns_slow_path_limiter().clone().try_acquire_owned()?;
let host = h.to_owned();
tokio::spawn(async move { ... resolve_all_cached(&host, p).await ... });
// forward.rs:143 —— 返回 None ⇒ accept.rs 永远不 arm_fast
```

三种持久形态：
1. **解析结果首条被过滤**（`CachedLookup::Addr(filtered)`）：线程 memo 由 `resolve.rs:431-448`
   在共享缓存命中时写入"排序后首条地址"，因此下一次同步查询**永远**返回同一条被过滤地址；
   该分支不再查 session `DestMemo`，直接落 spawn。
2. **整组记录全被过滤**：spawn 任务 `find(...)` 无可用地址时只 `bump(REFUSED)` 就返回
   （`forward.rs:98-101`），**不写任何负缓存** ⇒ 下一包完全重来。
3. **spawn 分支只能返回 `None`** ⇒ 连接级 fast table 永不 arm；后续每个包都重新走
   `resolve_fast` 未命中 → 全慢路径 → 再 spawn。

`allow_private` 默认 `false`（`config/server_conf.rs:35-37`），因此这是默认配置下的行为。

**触发条件**：目标域名解析出私网/回环地址（localtest.me、nip.io、自控域名、split-horizon、
NAT 内网服务），或混合记录中首条是私网（后续有公网地址）。**可被对端驱动**：
默认空 `auth_token` 时任何能连上 server 的 peer 都可以用域目标数据报驱动该路径；
1024 permit 的 `dns_slow_path_limiter` 还与 server 的 TCP 拨号共用（`server/tcp.rs:91`），
占满后合法域目标首解析会按 `DNS_BUDGET` 丢包/复位。

**成本**：每包 ≈ `tokio::spawn` + `host.to_owned()` + 2×Arc clone + permit `try_acquire_owned`
+ 任务内 moka 两次 await 探测 + 成功臂两次分配 + `get_or_create_sess` + `remember_dst`
+ 一次 `sendto` ≈ **1~3µs/包**；对比正常 fast path 数十~百 ns，放大 **10~30 倍**。

**修复方向**（逻辑修复，不改任何参数）
1. `CachedLookup::Addr(filtered)` 分支先查 session `DestMemo`（两次来源合并），命中可用地址就
   `send + return Some((dst, life))`，让 `arm_fast` 生效；
2. 给"整组记录都不可用"加短期负缓存（可复用 `DNS_NEG_TTL` 或 `DestMemo` 的 filtered 变体），
   后续包 inline 计 `REFUSED`，不再 spawn；
3. 每 `(conn, sess, host, port)` 加 in-flight 去重：解析在飞时后续包直接按 UDP 语义丢弃
   （或共享同一 waiter），杜绝"每包一个任务"。

**验证**：用 `dns_cache_seed_set` 构造"首条 filtered、后一条 global"和"全 filtered"两种目标，
断言连续 N 包 spawn 次数为 1/0（加 test-only 计数）。

---

### F2【P1】16 槽直接映射 fast table 与稀疏单调 session id 冲突，冲突会话永久慢路径

**位置**
- `src/bin/myquic2-server/accept.rs:258`（`FAST_SESS_SLOTS = 16`）
- `:318-320`（`fast_slot(s) = (s as usize) & 15`）
- `:364-409`（`try_stage` 要求槽内 `sess == s`，否则返回 `Err`）
- `:411-438`（`arm_fast` 无条件覆盖该槽）
- `:574-575`（注释断言："Session ids come from the client's monotonic counter, so N <= 16 live ids land on N distinct slots"）
- 客户端事实：`src/bin/myquic2-client/hub.rs:295-322`（进程级单调 `fetch_add`，不回退、不复用）

**机制**：注释的前提不成立。客户端 id 是**进程级单调、从不复用**的计数器，
活跃会话集合是 `[1, next)` 的**稀疏子集**（会话释放留空洞；interactive/bulk 两个 egress class
的 id 在同一个计数器上交错）。因此 `s & 15` 冲突概率按生日问题估计（活跃数 A）：
A=5 约 **50%**、A=8 约 **88%**、A=10 约 **97%**。注释里的"17 个才冲突"只在 id 连续时成立。

冲突对会互相覆盖对方的槽，于是两个会话**每个包**都 miss：
`resolve_fast`（`accept.rs:333-362`）→ `try_stage` 返回 `Err` → 慢路径
`forward_server_dgram` → `udp_try_send`（**每包一次 `sendto`，绕过 burst 的 sendmmsg 每 32 包一次**）
+ `remember_dst` 的 shard 读锁 + epoch bump + 两次 memo 探测 + 4×Arc clone → `arm_fast` 又覆盖回去。

**影响**：客户端把某一 egress class 的全部 UDP 关联复用到一个 QUIC 连接是文档化主形态
（interactive class 固定 index 0，`pool.rs:592-598`）；常见的 5~20 个并发 UDP 流大概率命中冲突。
代码自己测量过同类慢路径 +8.8% CPU（`accept.rs:564-568`），Linux 上的 `sendto` 放大更大。
与 F7 叠加后回复方向还要多付 ArcSwap load。

**修复方向**：16 槽 direct-map 改**有界线性探测**（从 `s & 15` 起最多探测 16 个槽，遇到
`sess == s` 命中 / 空槽停止；arm 取第一个空槽，满表再淘汰），或 4-way set-associative。
探测只可能 miss、不会 mis-route。不要只靠增大槽数（每槽 ~420B，4096 连接已 ~27MiB）。

**验证**：扩展 `tests.rs` 现有 fast-table 用例，用同余稀疏 id（如 1001/1009/1025）断言两者都能命中。

---

### F3【P1，系统级】分片 slot runtime + 主 runtime 默认 worker 数 ⇒ Linux 默认路径核心过度订阅

**位置**
- `src/bin/myquic2-client/main.rs:49`（`#[tokio::main]` = 默认多线程 runtime，worker 数 = `available_parallelism()`）
- `:210-244`（sharded 拓扑：**每个 pool slot 一条 OS 线程**）
- `:473-490`（`priority_pin_cores`：前 `cores` 个 slot 钉核）
- `:508-543`（每条 slot 线程内建 `new_current_thread` runtime，承载该连接的 quinn driver + dispatcher + 重连）
- `src/bin/myquic2-client/pool.rs:575-598`（默认 pool = 4 TCP + 3 UDP = **7 slot**）
- `src/linux.rs`（`pin_to_core` 仅 Linux 生效）

**机制**：默认配置下 7 条 slot 线程（前 `min(cores,7)` 条钉核）+ 主 runtime 的 `cores` 条
抢占式 worker。4 核 Linux/OpenWrt 上 = 4 pinned + 3 floating slot 线程 + 4 main worker，
**11 个可运行线程抢 4 核**；主 runtime 承载全部 SOCKS/TCP pump 与 UDP association relay 任务，
pinned slot 线程承载收包/回包热路径 ⇒ 每个 pinned 核上同时有两个常驻竞争者。
macOS 上 `pin_to_core` 是 no-op，所以现有 macOS soak 看不到这个问题；而 Linux 是发布目标。

**影响**：CPU 饱和时 pinned shard 的 driver/dispatcher 可用 CPU 近似按 CFS 均分下降，
收/发延迟与 pps 上限下降；核越少越重。需 Linux 2~4 核实测确认幅度。

**修复方向**（调度逻辑）：
- 显式构建主 runtime：`worker_threads((cores - pinned_slot_count).max(1))`，并用
  `on_thread_start` + 原子游标把 worker 钉到未被 shard 占用的核；或
- 当 `slots_total >= cores` 时限制 pin 数（给 ingress 至少留 1 核）/ 缩小默认 pool 宽度。
原则：`pinned shard 数 + 抢占式 worker 数` 不应超过核数。

---

### F4【P1】分片重组器淘汰用 O(n) `min_by_key` 全表扫描，分片完成率 >~128/s 后每载荷付一次

**位置**
- `src/udp/reassembler.rs:336-361`（`remember`：每个**完成**的分片载荷插一个 tombstone，然后
  `while recent.len() > FRAG_MAX_PARTIALS && evict_oldest_tombstone()`、
  `while held > FRAG_MAX_HELD_BYTES && evict_oldest_tombstone()`）
- `:603-616`（`evict_oldest_tombstone`：`recent.iter().min_by_key(at_ms)`，最多 256 项）
- `:618-632`（`evict_oldest`：对 `parts` 同样 `min_by_key`）
- `:496-517`（完成分支调用 `remember`）
- `:527-534`（丢包/乱序导致 byte-cap 持续超限时，**每个存储分片**都先逐个淘汰 tombstone，再扫 parts）

**机制**：每个完成的分片载荷都记一个 tombstone（活 `FRAG_TIMEOUT_MS = 2s`，上限 256）。
只要单个重组器（每条 QUIC 连接一个）的分片载荷完成率 >~128/s，`recent` 就长期饱和，
**之后每个完成的分片载荷都做一次 256 项 `min_by_key` 全表扫描**（实测 256 项 ~181ns）。
默认 `initial_mtu = 1200`（`config/tuning.rs:192`）⇒ QUIC DATAGRAM 预算 1162B ⇒ 约 >1150B 的
UDP payload 就会分片，任何 bulk UDP / VPN 流量都会进入该路径，不是冷路径。
byte-cap 路径在丢包下还会对 `parts` 每片再扫一次。

**影响**：20k 完成载荷/s ≈ 3.6~4.2ms/s（~0.4% 核）；100k/s ≈ 2%；
与 F13 的完成路径 hash/assemble 叠加后约占重组器单载荷用户态成本的一半。

**修复方向**（改数据结构，不改上限参数）：淘汰顺序与插入顺序一致（`at_ms`/`first_ms` 单调），
可在两个 map 旁各维护一个插入序 `VecDeque<key>`：淘汰时从队头 pop，不在 map 或时间戳不匹配则
惰性跳过，均摊 O(1)；或用单调 seq + `BTreeMap<seq,key>`（O(log n)）。
对已有 key 的覆盖只需把旧队列项惰性作废。

---

## 2. P2 问题

### F5【P2】下行"单条回复"路径多一次全 payload 拷贝，且被 BATCH-of-1 包装

**位置**
- `src/bin/myquic2-client/dispatcher.rs:549-563`（run 长度 1 时走 `[SendFrame;1]`）
- `src/udp/retry.rs:328-332`（n==1 直接 per-frame）→ `:391-408`
  （`GROUP_SCRATCH` 拼接 header + **整包 payload**）
- `src/bin/myquic2-server/reader.rs:184-248`（`flush_reply_batch` 即使 n==1 也 `encode_batch`）
- `src/bin/myquic2-client/hub.rs:28-31` / `dispatcher.rs:500-508` 的注释均宣称下行"零 payload 拷贝"

**机制**：server 对 ≤512B 回复做 BATCH（n==1 也包成 0x06 帧），>512B 和重组后的回复走单帧。
client 收到后按 `(sock,app)` 分组 flush；**run 长度 1 是常见形状**（一条回复一个 drain burst）。
n==1 时 `udp_try_send_grouped` 走 per-frame 路径：header 非空 ⇒ 把 header+payload 拼进
`GROUP_SCRATCH` 再 `try_send_to`。即**每个单帧回复付一次整包 memcpy**，与文档"zero-copy"矛盾
（`retry.rs:387-390` 注释"Linux 不会走到带 header 的分支"也是错的——该分支在 Linux 同样命中）。
server 侧 n==1 还多付一次 arena 暂存拷贝 + BATCH 头/计数 + client batch 解码。

**影响**：1.4KB 回复 ~17.5ns/条（实测），20k~100k 回复/s ⇒ 0.04~0.4% 核 + 与 quinn driver 争 L1/L2；
量不大，但是热路径上白付的全 payload 拷贝，修复约 10 行。

**修复方向**
- `retry.rs` n==1 且 header 非空时，改用已支持 n==1 的 `sendmmsg_frames(fd,&dst,&frames[..1])`
  （2 个 iovec、零拷贝；n==1 跳过 `record_send_group` 保持 histogram 语义）；
- server `flush_reply_batch` 在 `staged.len() == 1` 时直接用 `DgramFragmenter::send` 发 0x02
  单帧（前缀缓存已在 `frag` 里），不再包 BATCH。

---

### F6【P2】`recvmmsg` 排空后每个数据报再 memcpy 一次到调用方 buffer

**位置**
- `src/udp/batch.rs:553-572`（`burst_msg_copy`：`dst[..n].copy_from_slice(&b.data[off..off+n])`）
- `src/udp/batch.rs:425-455`（每线程 32×`BURST_SLOT` ≈270KiB 的 recvmmsg scratch）
- 调用点：`client/assoc.rs:245,255`（app→QUIC 上行）、`server/reader.rs:345,362`（target→client 下行）

**机制**：awaited head 用 `recv_from(&mut buf)`（内核→buf 一次）；drain 余下用 `recv_burst`
一次 `recvmmsg` 写进线程本地 BURST arena（内核→arena），随后 `burst_msg_copy` 再 arena→buf，
最后才解码/编码。drain 循环体内**没有 await**，BURST arena 直到下一次 refill 前都有效，
payload 在同一同步段内被消费 ⇒ 这次 arena→buf 拷贝可删。

**影响**：Linux 上每个被 drain 的数据报少一次全 payload memcpy；40~100k pps × ~1KB ≈ 0.5~1% 一核；
8KB 载荷线性放大。

**修复方向**：在 `udp::batch` 增加借用式访问器（`burst_msg(i) -> Option<(&[u8], SocketAddr)>`
或闭包作用域 API），caller 直接就地解析/编码；server accept 的慢路径若需 `.await` 再拷贝那一条。

---

### F7【P2】`remember_dst` 无条件 bump allowlist epoch，reply reader 的 epoch 门控失效

**位置**：`src/bin/myquic2-server/pin.rs:467-492`（`fetch_add` 在 `:489-490`，rcu 在 `:476-488`）、
`src/bin/myquic2-server/reader.rs:453-466`（epoch 变化 ⇒ `recent.load_full()` 每个回复一次）

**机制**：epoch 的设计目的是让 reply reader 稳态只付一次 relaxed load（`table.rs:41-50` 注释），
但 `remember_dst` 在 ring 无变化（稳态同目标）时仍无条件 `fetch_add`。走慢路径的会话
（F2 冲突会话、多目标会话、域目标未 arm 阶段）每包调用 `remember_dst` ⇒ 其 reply reader
**每个回复**执行 `ArcSwap::load_full()`（hazard pointer + Arc 引用计数 RMW），
并和发送侧 epoch RMW 争同一条 cache line。

**修复方向**：只在 ring 真正变化时 bump（放进 `!contains` 分支；rcu 闭包里用本地 flag 记录
是否实际 push 过，rcu 重试多 bump 一次无害——epoch 只需单调宁多勿少）。

---

### F8【P2】客户端上行小包只做 2-pack，N-pack 能力缺口

**位置**：`src/bin/myquic2-client/assoc.rs:195-208`（`pending_buf`/`pending_pack` 状态与注释）、
`:373-449`（配对逻辑，只把相邻两条拼成 `[&[u8];2]`）、`:511-521`（burst 末尾 flush）；
参照实现 `src/bin/myquic2-server/reader.rs:138-248`（预算感知 arena + `reply_stage`/`flush_reply_batch`，最多 16 条/帧）

**机制**：`send_udp_batch` 支持最多 `MAX_BATCH_ITEMS = 16`，但 assoc 只配 2 条就立即发送。
同目的地 32 包 burst ⇒ 16 次 quinn send，每次 = connection-state mutex + driver wake +
一帧精确分配 + quinn packet 拷贝。100~200B payload 按 path budget 可装 ~8~13 个/帧。
interactive class 全部 association 共享同一 egress 连接，减少 send 次数同时降低该 mutex 跨核竞争。

**影响**：send 次数/payload 从 0.5 → ~1/8~1/13；按 40k pps、单次 send 200~300ns 估 ≈ 0.3~0.6% 核，
并与 README 的 100k pps N=1 小包目标直接相关。**不增加延迟**（仍在 burst 末尾 flush）。

**修复方向**：把 `pending_buf` 扩为 arena + `Vec<(off,len)>`，照搬 server 的
`reply_stage`/`flush_reply_batch` 模式；编码失败回退逐条 `frag.send`，保留现有
TooLarge/Blocked 语义与记账。

---

### F9【P2，条件性】分片发送在发送缓冲饱和窗口"先发前缀、丢尾部"，产生无法重组的孤儿分片

**位置**：`src/udp/fragmenter.rs:237-264`（逐片 `send_encoded`，首个非 `Sent` 立即返回）、
`src/udp/send.rs:243-252`（`PayloadSend` 文档：partial send 不回滚）、
`src/udp/send.rs:84-95`（quinn `send_datagram_wait` 按**单条** datagram 检查空间）

**机制**：quinn 0.11.12 的 `send_datagram_wait` 只检查"这一条 datagram"是否能入队
（`quinn-proto-0.11.19/src/connection/datagrams.rs:49`）。当发送缓冲处于"够 1 片、不够 N 片"
（饱和时 driver 每次只排空一个包 ≈ 一片大小，属常态窗口），2 片载荷会成功入队第 1 片、
第 2 片 `Blocked` 返回——第 1 片照样上网，对端永远等不到第 2 片，2s 后丢弃 partial，
**额外浪费 (F−1) 片的隧道带宽**（F=2 时最多 50% 该载荷字节）。

**修复方向**：`DgramFragmenter` 记录"上次分片发送是否 Blocked"；需分片（F>1）且上次 Blocked 时，
先调用 quinn 0.11.12 公开的 `Connection::datagram_send_buffer_space()`
（`quinn-0.11.12/src/connection.rs:508`）预检，空间 < 各帧总长 + bookkeeping 余量就整体丢弃
（记 `Blocked`，等价于第一片就 Blocked 的情形），否则照常逐片发。健康路径只多一个 bool 判断。

---

### F10【P2，结构】客户端 relay 任务与 egress driver 跨 runtime ⇒ 每出站 DATAGRAM 跨核 state 锁 + driver wake

**位置**：`src/bin/myquic2-client/socks.rs:139` → `assoc.rs:5-10`（relay 循环在 SOCKS 任务里，
由 `main.rs:379-388` spawn 在 `#[tokio::main]` 主 runtime）；
egress driver/dispatcher 在 `main.rs:508-543` 的 slot runtime。

**机制**：`try_send_datagram` → quinn `SendDatagram::poll` 每次取 `ConnectionInner.state` 互斥锁并
`state.wake()`（quinn-0.11.12 `connection.rs:856-876`）；该锁的 partner 是每收一个包都持有的
driver，而 driver 在 pinned slot 线程、relay 任务在 main worker ⇒ 每个 UDP send 一次跨核
cache-line 交接 + 一次跨 runtime driver wake（TCP 每 16KiB 分摊，UDP 每包）。

**影响**：每个出站 UDP 数据报；每次跨核交接+wake 约 0.1~0.3µs（估算）⇒ 40k pps ≈ 0.5~1.3% 核 +
延迟抖动。**修复收益不确定、重构成本高，必须先 A/B 实测**（`MYQUIC2_SHARD_RUNTIME=0` 对照
`hotpath_bench udpmulti/lat`）。方向：首包确定 `UdpBind` 后把 relay 循环挪到对应 slot runtime；
不建议用跨 runtime channel（会引入同量级 hop）。

---

### F11【P2】每个 UDP session socket 创建多做 4~5 次诊断 `getsockopt`；每次 insert/remove 扫 8 个 shard 读锁

**位置**
- `src/lib.rs:318-394`（`udp_socket_dual_impl`）：Linux 分支 `:367-373` 先 getsockopt 判 force，
  `:374-387` 为告警再读回 2 次；`warn_buf_clamped` 每次 2 个 atomic swap；`:414-425` force 失败不缓存
- 调用点：`server/reader.rs:769`（每个新 UDP session 一次）、`client/assoc.rs:45-46,50`（每个 association）
- `src/bin/myquic2-server/table.rs:148-158`（`note_empty_state`：`shards.iter().any(|sh| !sh.read().is_empty())`，
  每个 insert/remove 都调：`reader.rs:894` 与 `:607`）

**机制**：SO_SNDBUF/SO_RCVBUF 的 clamp 判定是 netns/进程级常量，但为了"是否被 clamp"的告警在
**每个 socket** 上读回；被 clamp 且无 CAP_NET_ADMIN 时每 socket 还发 2 次注定 EPERM 的
`SO_*BUFFFORCE`。实测（macOS A/B）：4 次读回额外 +1.5~1.7µs/socket；Linux 按 0.3~0.5µs/syscall
估 ~1.2~3µs/新流。`note_empty_state` 每次 insert/remove 取 8 个 shard 读锁（~百 ns 级）。

**修复方向**：`static PROBE: OnceLock<ClampVerdict>` 进程级缓存一次判定（首个 socket 探测 + 尝试一次
force 并记录 capability），之后跳过读回/force；`note_empty_state` 改为表级 `AtomicUsize live_count`
（insert +1、remove -1，0↔1 迁移时更新全局 holders），去掉每次 8 锁扫描。

---

### F12【P2】`udp_stats::fragmented()` / `unsolicited()` 未批处理，分片态每载荷一次全局原子 RMW

**位置**：`src/stats/udp_stats.rs:92-99`（fragmented）、`:111-115`（unsolicited）；
对照 `:60-89` 的 `payload()` TLS 批处理；调用点 `udp/fragmenter.rs:273`（每个分片载荷发送成功后）、
`server/reader.rs:471`（full-cone 每个非白名单入站包）

**机制**：`FRAGMENTED.fetch_add(1, Relaxed)` 直接打全局 cache line，所有 shard/线程争同一条线。
默认 `initial_mtu=1200` 使 >1150B payload 常态化分片，这是**常态路径**而非异常路径。
实测共享 `fetch_add` 22.6/24.6ns/op vs 批处理 0.21ns；每分片载荷多 ~5~25ns 且是跨 shard 串行点。

**修复方向**：在现有 TLS 结构里加 `fragmented` 计数（与 datagrams/bytes 同一 Cell），或新增
`payload_fragmented(len, frames)` 合并一次 TLS 访问，随 256 阈值一起 flush；`unsolicited` 同法。

---

### F13【P2/P3】重组器每分片重复 hash 探测；完成时二次遍历 + 两次额外分配

**位置**：`src/udp/reassembler.rs:288`→`:297-311`（`recent.get`）、`:384`（`parts.get`）、
`:446-448`（`parts.entry`，同 key 二次探测）、`:497`（完成 `parts.remove` 第三次）、
`:319-329`（`prints_of` 对每个 chunk 做 hash 并分配 `Box<[Option<ChunkFp>]>`）、
`:85-91`（`assemble` 分配 BytesMut 再拷贝全部 chunk）

**机制**：普通分片 3 次 hash map 探测；完成分片 5~6 次。完成时先对 payload 全量算指纹
（实测 2800B ~45ns）再全量 assemble 拷贝（~60ns），同一份数据被独立遍历两次、两次分配
（另有 Domain 目标 `p.address.clone()` 一次 String 分配）。

**修复方向**：单个 `parts.entry(key)` 服务"存在/超限/重启/完成"四个判断；更彻底可把 tombstone
并入同一 map（`enum Slot { Partial, Tombstone }`），每分片 1 次探测、完成时原地转换；指纹在
`push` 存 chunk 的同一 cache-hot 访问里顺手计算，完成时直接移动，省掉二次遍历与 `Box` 分配。

---

## 3. P3 清单（小开销，修复零/低风险）

| # | 位置 | 问题 |
|---|---|---|
| P3-1 | `stats/drops.rs:239`、`stats/udp_write.rs` 的直接计数、`stats/warn.rs:26-38` | 每个丢包一次全局 `fetch_add` + `coarse_millis`；饱和/REFUSED 洪泛时按包发生。可改 padded per-thread shard 数组（snapshot 求和仍精确），告警闸门保留 |
| P3-2 | `server/accept.rs:530,607` + `client/dispatcher.rs:602-604,692` | 每连接 500ms 重组 tick 无条件唤醒（即使 reassembler 为空，TCP-only 连接也一样）；4096 连接 ≈ 8k wakeup/s。select 分支加 guard `if reasm.held_bytes() > 0` |
| P3-3 | `server/pin.rs:389` | pin 命中每个域目标包重复一次 `is_global_ip_cached`（纯函数、arm 时已过滤）；可信任 arm 结论直接返回，省 ~10ns/包 |
| P3-4 | `udp/fragmenter.rs:213` | 每个分片载荷读一次精确 `mono_millis()`，但它只在 2^32 个 id 回绕后才被使用；把时钟求值移进 `last_wrap_ms != 0` 分支 |
| P3-5 | `dns/resolve.rs:386-450` | warm-hit 每次先 negative 再 positive 两次 moka probe；Ok 分支 `Vec<SocketAddr>` + `Arc::from` 两次分配。positive 先查、端口由调用方 attach |
| P3-6 | `client/assoc.rs:45-46` + `lib.rs:319` | 每个 association 把 `SocketAddr` 格式化为 String 再 parse 回来；lib 增加收 `SocketAddr` 的构造入口 |
| P3-7 | `client/socks.rs:133,150,166,218,246-252,377` + `pool.rs:763-771,252-257` | 每 TCP CONNECT ~7 个独立 timeout 定时器；`holds_dead_handle` 与 `wait_conn` 对同一 quinn state 锁探活两次；非 interactive 流多一次 `set_priority(0)`（quinn-proto 0.11 只存 i32 不发帧） |
| P3-8 | `client/dispatcher.rs:220-243` | BATCH 每 payload 一次 `d.slice_ref` + 每帧一次 `entry.relay.clone()`；可改 `StagedReply{frame,off,len}` 只持 1 个 frame + 1 个 socket Arc/帧 |
| P3-9 | `client/pool.rs:592-598`、`egress.rs:259-290` | interactive UDP class 硬绑单连接（一个 driver + 一把 state 锁承载所有小包 association）；bulk 已有 shard 轮转，可泛化（设计上限，非缺陷） |

---

## 4. 已确认优化到位、**不建议动**的点

以下经逐行核对 + 代码内已有测量，属于"再动是负收益或重复劳动"：

- **每数据报 encode**：`Vec::with_capacity` 精确容量 + `Bytes::from` 走 in-place `into_boxed_slice`
  （`mqp/datagram.rs:97-135`），1 次分配 + 1 次拷贝；帧池化已被 `examples/frame_bench.rs` 实测否决
  （+39~52% / +128~324%）。
- **`DgramPrefixCache`**：稳态同 (sess,dst) 零校验、零 re-encode（`mqp/datagram.rs:168-217`）。
- **BATCH 编解码**：`decode_batch` 零分配、先整帧校验再惰性迭代（`mqp/batch.rs:141-181`）。
- **quinn 每帧 state 锁**：`send_datagram_wait` 内部锁，API 内在，本仓库无法绕过。
- **重组器 chunk 拷贝**：`Bytes::copy_from_slice` 是为让 `FRAG_MAX_HELD_BYTES` 记账精确
  （否则 20B 分片会钉住 ~92KiB 的 GRO batch，见 `udp/reassembler.rs:266-279` 与对应测试）。
- **TCP pump**：`read_chunks(8)` + `write_vectored`、≥8KiB `write_chunk` 零拷贝、双缓冲池、
  固定 5s idle tick（`tcp/pump.rs:229-535`）；无逐 chunk 分配。
- **thread-local 统计**：`udp_stats::payload`、`udp_write::sent`、`record_drain_batch` 均 256 批处理
  （F12 只是把漏掉的两个字段补齐）。
- **egress memo / hub / dispatcher**：`with_fresh` 1×TLS + 1×Acquire load、无 Arc RMW、无 quinn 锁
  （`egress.rs:139-165`）；hub 256 shard `ArcSwap<HashMap>` 读路径无锁（`hub.rs:210-233`）；
  dispatcher 每唤醒 drain ≤32 包、无逐包 spawn/通道（`dispatcher.rs:615-693`）。
- **正常发送路径不付 retry 代价**：`udp_try_send_*` 成功时只有 `try_send_to` + TLS 计数。
- **正则/日志/format**：所有热路径 warn 都限频且 detail 闭包只在 due 时执行；无逐包格式化。
- **coarse/mono 时钟**：coarse 1.44ns、mono 3.26ns（实测），逐包路径已用 coarse；不要再改。
- **transport/TLS/DNS memo**：启动构建一次；DNS memo hit 零分配零锁；`is_global_ip` 只在 cache-miss。
- **sendmmsg/recvmmsg batching**：last-hop 已按 (sock,dst) run 分组、Linux 一次最多 32 帧；
  `sendmmsg_frames` 已用 `MaybeUninit` 消除 2.7KB 死存储；F5 只是 n==1+header 的残留。

---

## 5. 建议修复顺序与验证方式

**第一批（小改动、大收益、含安全放大）**
1. **F1**：slow path 合并 session memo + filtered 负缓存 + in-flight 去重（+ seeded DNS 单测）。
2. **F2**：fast table 有界线性探测（+ 稀疏 id 单测）。
3. **F5**：client n==1 走 `sendmmsg_frames`；server n==1 直接单帧（+ batch 用例断言）。
4. **F6**：`udp::batch` 借用式 burst 访问器，client/server 两处就地处理。
5. **F7**：epoch 只在真正写入时 bump（+ 单测）。
6. **F12**：fragmented/unsolicited 并入 TLS 批次。

**第二批（需先测量）**
7. **F3**：Linux 2~4 核 `hotpath_bench udpmulti/lat/lattcp` 复核过度订阅；再限定主 runtime worker 数/钉核。
8. **F4**：重组器插入序队列 + 惰性淘汰；`udpps` + 分片流量压测对比。
9. **F8**：client 上行 N-pack（照 server `reply_stage` 模式）。
10. **F9**：fragmenter blocked 状态 + `datagram_send_buffer_space()` 预检；饱和态带宽对比。
11. **F10**：先 `MYQUIC2_SHARD_RUNTIME=0` A/B，再决定是否迁移 relay 任务。

**第三批**：F11、F13、P3 清单（低风险清理）。

**共性验证手段**
- 单元测试：seeded DNS、稀疏 session id、epoch 计数、n==1 单帧、burst 借用访问器。
- 端到端：`examples/hotpath_bench.rs` 的 `udpps`/`udppaced`/`udpmulti`/`udpdomain`/`bulk`/`lat`，
  在 Linux 目标机（含 2~4 核小机器）对比修复前后 CPU/pps/延迟。
- 系统观测：`perf stat`（context-switch、cycles/instruction）、`strace -c`（session 创建的 syscall 数）、
  `perf record`（确认热点迁移）。

---

## 6. 局限

- 未执行端到端 benchmark；本文百分比/µs 均为"单事件成本 × 频率假设"的估算或代码内既有测量，
  以量级和相对排序为目的，最终收益需在 Linux 目标机复测。
- 微基准在 Apple M4/macOS 上运行；Linux 的 syscall 单价通常更低、quanta 精度不同，但
  syscall 次数、原子争用、拷贝字节数的机制一致，问题方向不变。
- F3/F9/F10 的触发频率依赖部署形态（核数、饱和程度、跨核拓扑），列为 P1/P2 时已标注条件。

---

## 7. 实施记录与验证（2026-10-19）

### 7.1 改动范围

17 个源文件（+3298/−874），未改 `src/config/**`、`Cargo.toml`/`Cargo.lock`：

| 文件组 | 修复 |
|---|---|
| `src/bin/myquic2-server/{accept,forward,pin,reader,table,tests}.rs` | F1/F2/F5-server/F6-server/F7/F11b/P3-2/P3-3 |
| `src/bin/myquic2-client/assoc.rs` | F6-client、P3-6 |
| `src/udp/{batch,retry,fragmenter,reassembler,send}.rs`、`src/udp.rs` | F4/F5/F6-API/F9/P3-4 + `note_send_buffer_full` 记账入口 |
| `src/lib.rs`、`src/stats/udp_stats.rs`、`src/dns/resolve.rs` | F11a/F12/P3-5 + `udp_socket_dual_small_addr` |
| `src/mqp/fragment.rs` | 淘汰策略注释同步（唯一文档改动） |

### 7.2 验证结果（macOS aarch64 本机 + Podman Linux 容器，rustc 1.99.0）

| 命令 | 结果 |
|---|---|
| `cargo fmt --all --check` | ✅ clean（已在集成时统一 fmt） |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test --all-targets`（macOS 本机） | ✅ **279 passed / 0 failed**（lib 134 / client 76 / server 69；基线约 240，新增 39 个回归测试） |
| **`cargo test --all-targets`（Podman / Debian 12 aarch64 Linux 容器）** | ✅ **283 passed / 0 failed**（lib 138 / client 76 / server 69；多出的 4 个是 `#[cfg(target_os = "linux")]` 测试） |
| **`cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings`（同一 Linux 容器）** | ✅ clean（CI parity） |
| `cargo zigbuild --target x86_64-unknown-linux-gnu --all-targets` | ✅ exit 0（含 Linux-only cfg 分支：F5 sendmmsg、F6 with_burst_msg、F9 gate、F11a probe） |
| `cargo zigbuild --target x86_64-unknown-linux-musl --bins` | ✅ exit 0（CI 静态 musl 目标） |
| `git diff --check` | ✅ clean |

> Linux 容器运行说明：镜像基于 `localhost/myquic2-ci:1.99`（Rust 1.99.0）加装 `cmake`/`ninja`，
> 挂载工作区与宿主 cargo registry，`CARGO_TARGET_DIR` 指向 Podman volume。这样
> `recvmmsg`/`sendmmsg`、`with_burst_msg` 就地分支、F9 backpressure gate、F11a Linux 探测等
> 运行时路径都真正被执行并通过。剩余未验证项只有**吞吐/延迟收益**本身：建议在 Linux 目标机用
> `examples/hotpath_bench.rs`（`udpps`/`udppaced`/`udpdomain`/`udpmulti`）做修复前后对比。

### 7.3 行为变化（需要 review 关注）

1. **F1**：解析在飞期间，同一 `(session, name, port)` 的后续数据报现在直接丢弃（UDP 语义，
   计 `REFUSED`），而不是各自 spawn 一个 resolver；全过滤/失败结论缓存 5s，期间 inline 拒绝。
   原有 `l2_dns_singleflight_burst_delivers_server` 相应改名为
   `l2_dns_burst_coalesces_to_one_waiter_per_session`（断言 spawn==1）。
2. **F5-server**：单条 staged 回复现在发单个 `0x02` DATAGRAM，不再包 1-item BATCH 帧
   （客户端两种都接受；wire 上每回复少 3 字节包装）。
3. **F6**：Linux 上 recvmmsg 排空的数据报不再拷贝到调用方 buf（非 Linux/无 recvmmsg 保持原路径）。
4. **F11a**：socket buffer clamp 判定改为进程级缓存（首个 socket 探测后不再观察运行期
   `net.core.*mem_max` 变化，重启生效；与 `MYQUIC2_SESS_SOCKET_BUF` 的进程级模型一致）。
5. **P3-3**：pin 命中不再每包重做 SSRF 判定（arm 前已过滤、pin 地址生命周期内不变、谓词纯函数）；
   安全语义不变。
6. **P3-5**：DNS warm-hit 改为先 positive 后 negative（正/负 store 互斥不变式有测试钉住），
   负缓存命中路径多一次 positive probe，warm 路径少一次。

### 7.4 后续（deferred，按 §0.5）

F3（线程拓扑）、F8（client N-pack）、F10（跨 runtime）、F13（重组器探测融合）、
P3-1/P3-7/P3-8/P3-9 —— 均需 Linux benchmark 或收益/风险比不适合本批，已在报告中保留设计方案。

