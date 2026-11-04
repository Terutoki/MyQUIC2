# TCP / UDP ECHO 全链路性能与锁竞争审计

> 基线：`2f8b841`（2026-11-03）· 分析日期：2026-11-04 · 修复日期：2026-11-04 · 全部工作在本机完成
> 范围：SOCKS5 `CONNECT` / `UDP ASSOCIATE` 与 `[[tcp_forward]]` / `[[udp_forward]]` 两种入口，
> 从 app socket 到 echo target 再回到 app 的完整数据面；重点是**锁竞争**，其次是每包分配、拷贝、
> syscall 次数与任务/运行时拓扑。配置参数值本身不作为结论依据（沿用仓库现有预设）。

---

## 0. 结论

**稳态 TCP / UDP ECHO 路径上没有 P0 / P1 级锁竞争，也没有发现会在 100k pps 量级把 worker
park 住的共享锁。** 实测 20k pps 全双工 UDP ECHO（40k datagram/s 通过隧道）：

- 服务端 ingress 线程 5413 个采样点中，栈顶落在 `pthread_mutex_lock` 的只有 **9 个（0.17%）**；
- 客户端整个进程只有 **8 个** mutex 采样点（约 6 个在该 slot 线程，且是 `pthread_mutex_lock`
  而非真正阻塞的 `__psynch_mutexwait`）；
- 往返 p50 = 111 µs，p99 = 269 µs，p999 = 350 µs，无锁抖动尾巴（修复后同口径 112/271/347）。

这不是"运气好"，而是拓扑决定的：**服务端每个 ingress endpoint 一个 current-thread runtime
（Linux 上再按 endpoint 绑核），连接任务、session reader、QUIC driver 全部在同一 OS 线程；
客户端每个 pool slot 也是 current-thread runtime，UDP association 稳态被迁移到承载它的
slot 上**。锁在同一线程里不会竞争，只剩"锁税"（lock/unlock 的几十 ns），不构成瓶颈。
真正的上限是**单线程每包 CPU**（syscall、QUIC 加解密、拷贝）。

> **修复状态（2026-11-04）**：E1 / E2 已实现并验证（见 §5），E3 的"每包未 batch 的 sendto"
> 一句经复核对 rev2/rev3 稳态不成立（已更正），E4/E5/E6 保留为有意不修的低优先级项。

问题清单与修复状态：

| # | 级别 | 位置 | 问题 | 状态 |
|---|---|---|---|---|
| E1 | **P2**（形状相关） | `forward_udp.rs` | `[[udp_forward]]` 监听器每 payload 一次 stager push，且任务留在 main 多线程 runtime，未像 SOCKS association 那样迁移到 slot runtime | ✅ 已修：burst 批处理 + 由连接的 retry task 在 slot runtime drain |
| E2 | **P2** | `socks.rs`、`forward.rs`、`main.rs` | 客户端 TCP pump 仍在 main runtime，而 slot 的 QUIC driver 在自己线程：每 16 KiB chunk 跨核抢 quinn 连接锁 | ✅ 已修：pump 迁移到 slot runtime（`run_tcp_pump`），实测 mutex wait 归零 |
| E3 | **P2** | `accept.rs:356-372`、`memo.rs:61` | 服务端 fast table 568 槽 + 线程 memo 256 槽，而文档给出的 shipped 客户端可把 ~2000 个 session 压到一个连接 | ◐ 保留：容量是内存/admission 的取舍；慢路径本身仍走 burst staging（原报告此处措辞已更正） |
| E4 | **P3** | `assoc.rs:652`、`reader.rs:1912` | macOS 无 `recvmmsg`，便携收包路径每个 burst 多做一次 `try_recv_from`（EAGAIN） | ◐ 不修：平台限制，Linux 无此开销 |
| E5 | **P3** | `r2_stage.rs:1524-1601` | 每条连接一把 drain gate，覆盖 encode+send，单次 drain 最多处理 1024 个 item | ◐ 不修：单线程 shard 上不竞争，改小反而增加重试延迟 |
| E6 | **P3** | `rev2.rs:1833`、`rev2.rs:408-425` | 每 payload 一次分配 + 两次锁税 | ◐ 不修：约 0.1-0.2% CPU，属既定设计 |

> **条件性 P1**：以上"无锁竞争"的前提是 sharded topology（默认）。若设置
> `MYQUIC2_SHARD_RUNTIME=0`，服务端连接任务回到多线程 runtime，per-connection stager mutex +
> drain gate 变成真正跨线程，而 `drain_stage` 用的是**阻塞锁**且 gate 覆盖 encode+send，
> 此时应按 P1 处理：要么保留 sharded topology，要么先把 drain 改成非阻塞/有界 + 重试任务。

---

## 1. 审计方法与证据来源

1. **逐路径代码走读**：把 UDP / TCP 两个方向拆成 hop，逐跳列出"每包做什么、碰哪些共享状态、
   锁的持有者与竞争域"，而不是只看锁的类型。
2. **实测**（macOS 27.0.1 / Apple M4 / 10 core / 16 GiB，release + LTO，单机 loopback）：
   - `hotpath_bench`（仓库自带）做 echo 目标、延迟、paced 全双工、bulk；
   - `sample <pid> 1ms` 采样服务端 / 客户端调用栈（为拿到符号，本次用
     `CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_PROFILE_RELEASE_STRIP=none` 重新构建；只改 profile
     选项，不改源码）；
   - `ps -o cputime` 取进程 CPU 时间。
3. **与仓库既有测量对齐**：Linux 侧数字引用 `PERF_ANALYSIS.md` §13（120k pps、server 0.42 core）
   与 README §性能；本次只补 macOS 的锁行为与运行时拓扑证据。
4. **修复与验证**（2026-11-04）：E1/E2 的改动见 §5；验证为
   `cargo fmt --all --check`、`cargo clippy --all-targets -- -D warnings`、
   `cargo test --all-targets`（lib 384 + client 210 + server 163 + forward_e2e 7 + rev3_e2e 9
   全过，server 1 个微基准 ignored），以及 §4.3-§4.5 的同口径复测。

**实测的边界**：loopback 没有 RTT/拥塞信号；macOS 只有 1 个 ingress endpoint（`SO_REUSEPORT`
组在同一时刻只投递一个成员），因此服务端数据面本来就是 1 个线程；采样以 1 ms 为间隔，
百分比是"该线程采样点占比"，不是进程总 CPU。结论中的锁竞争判断不依赖绝对值，而依赖
`mutex-wait` 是否出现在热点栈上。

---

## 2. 路径与每跳成本

### 2.1 UDP ECHO — SOCKS5 `UDP ASSOCIATE`（`hotpath_bench udp/lat/udpbidir`）

```
app --UDP--> relay socket --(assoc task, slot runtime)--> rev2 编码 --> quinn DATAGRAM
    --> server ingress shard: decode -> fast table -> 目标 socket(sendmmsg/try_send)
    --> echo target --> session reader (per session) --> 连接 stager --> quinn DATAGRAM
    --> client dispatcher (slot runtime) --> 直接 sendmmsg 到 app 的 relay 地址
```

| Hop | 每包工作 | 共享状态 / 锁 | 竞争域（默认拓扑） |
|---|---|---|---|
| app → relay | 一次 `recv_from`（+ 每 burst 一次 `try_recv_from`） | 无（task-local buffer） | 单 assoc task |
| assoc 上行 | 解析 SOCKS 头、`ensure_binding`（memo 命中）、`admit_uplink`（interactive 预设；bulk 预设 window=0，直接短路）、`Bytes::copy_from_slice`、push 到 burst batch | `Mutex<R2Stager>`（admission 读 `queued_bytes`；burst 末 `push_batch`）；quinn 连接状态锁（`datagram_send_buffer_space`） | **同一 slot 线程**（PERF_ANALYSIS §22.8 迁移后）→ 不竞争 |
| burst 末 drain | gate → claim(≤4 frame/64 item) → encode → `send_datagram` | stager mutex、drain gate、quinn 状态锁 | 同一 slot 线程 |
| quinn → server | 每 DATAGRAM 一次连接状态锁（driver 侧 `MAX_TRANSMIT_DATAGRAMS` 打包） | quinn 内部 mutex | driver 与 assoc 同线程 |
| server ingress | `read_datagram`、`wire::kind`、decode（零拷贝 slice）、fast table probe、`mirror_record`（稳态只比较 memo）、`staged.push` | fast table 是 task-local；`SessTable` 8 个 shard 的 `RwLock` 只在 fast-table **且**线程 memo 都 miss 时读；allowlist 的 `ArcSwap` 只在目标变化时 publish | **单 shard 线程** |
| server → target | burst 末按 `(sock,dst)` 分组，Linux 一次 `sendmmsg` ≤32，macOS 每帧 `try_send_to` | 目标 socket 每 session 一个（无共享） | 单 shard 线程 |
| target → server | 每 session 一个 reader task，`recv_from` + burst | session 的 `ArcSwap` allowlist；`StageBatch` 是 task-local | 单 shard 线程（多 task 协作调度） |
| server 回程 | `handle_session_reply` → `StageBatch` → 连接 stager → `drain_staged` → `send_datagram` | **一条连接一把 stager mutex + 一把 drain gate**，被该连接所有 session reader 共享 | 单 shard 线程 → 不竞争；但 gate 串行化所有 session 的发送，且覆盖 encode+send |
| client 回程 | dispatcher `read_datagram` → decode → registry `get`（read lock）→ hub shard `ArcSwap::load` → `Weak::upgrade` → 直接 `sendmmsg` | `FlowRegistry` 每连接两把 `RwLock`（map/by_session）；hub 256 shard `ArcSwap` | dispatcher 与 assoc 同 slot 线程；hub 只读、无锁 |

### 2.2 UDP ECHO — `[[udp_forward]]`（固定目的转发）

与 2.1 的差异在客户端入口，以及**发送线程**：

- `forward_udp.rs:72` 在 **main 多线程 runtime** 上 `tokio::spawn` 监听器（一个监听器服务多个
  peer、可跨多个 binding，因此不能整体搬到一个 slot）；
- 每个 peer 的 `UplinkFlows` 在 burst 内只攒本地 batch，burst 边界由 `flush_peer` →
  `rev2::flush_assoc_stage` **一次 `push_batch`** 推进连接 stager（不是每 payload 一次 push）；
- `flush_assoc_stage` 随即 `ConnRev2::request_drain()`，唤醒该连接在 slot runtime 上的
  stager-retry task；**encode + `send_datagram` + quinn 连接状态锁都发生在 driver 线程**，
  监听器只做一次 push 和一次 notify；
- `UplinkFlows` 的 `Drop` 给"从未进入 stager 的 batch"记账；peer 被 admission 淘汰时先
  **同步** `drain_assoc_stage` 再 `SESS_CLOSE`（close 走可靠流，不能让它抢在数据帧之前）。

stager 仍会把同一 session 已排队的多个 item 在 claim 时组成 `TRAIN`，所以**帧数不会退化**；
与修复前相比，stager push 从每 payload 一次降到每 burst 每 peer 一次，跨核的 send 次数从
每 burst 每 binding 一次降到 0（由 retry task 在 slot 线程完成）。

### 2.3 TCP ECHO — SOCKS5 `CONNECT`（`hotpath_bench lattcp` / `bulk`）

```
app TCP --CONNECT--> socks.rs: open_bi + write header + optimistic reply
    --> pump (copy_tcp_quic_acked): c2s read_buf 16 KiB -> write_chunk
                                    s2c read_chunks(8) -> write_vectored
    --> server shard: handle_tcp_stream -> dial -> ACK -> copy_tcp_quic_idle (同一对 pump)
    --> echo target
```

| 资源 | 事实 |
|---|---|
| 应用层锁 | **没有**。每条 TCP flow 一个 task，缓冲区是 task-local + 线程池（`COPY_BUF_POOL`），计数是 atomic/线程本地 |
| 唯一共享锁 | quinn 每连接状态锁：`write_chunk` 每 16 KiB 一次、`read_chunks` 每批一次；同连接上所有 stream 共享 |
| 竞争域（服务端） | `handle_tcp_stream` 由 `handle_conn_inner` 在 shard runtime 上 spawn（`accept.rs:4782`），pump 与 driver **同线程** → 无竞争，代价是单连接单核 |
| 竞争域（客户端） | pump 由 `handle_socks` 在 **main runtime** 跑（`socks.rs:255`），driver 在 slot 线程 → **每 chunk 跨核**，这是 TCP 方向唯一实测到 mutex wait 的地方 |
| 拷贝 | c2s ≥`ZEROCOPY_MIN_WRITE` 用 `split_to().freeze()` 交给 quinn（无额外拷贝）；s2c `read_chunks` 返回 quinn 缓冲切片 + `write_vectored`（无拷贝） |

---

## 3. 锁与共享状态清单（数据面）

| 结构 | 定义位置 | 粒度 | 每包？ | 竞争者 | 默认拓扑下的判定 |
|---|---|---|---|---|---|
| quinn connection state (`std::sync::Mutex`) | quinn 内部 | 每连接 | 每 DATAGRAM / 每 stream chunk | driver + 所有生产者 | UDP 同线程；**客户端 TCP pump 跨线程**（E2）；服务端同线程 |
| `Mutex<R2Stager>` | `accept.rs:1667` / `rev2.rs:222` | 每连接 | 每 burst（server/SOCKS）或每 payload（forward） | 所有 session reader / association / retry task | 同线程（E1 例外） |
| drain gate `Mutex<()>` | `r2_stage.rs:281` | 每连接 | 每 batch | 所有 drainer | 同线程；覆盖 encode+send（E5） |
| `FlowRegistry` 两把 `RwLock` | `mqp/r2_flow.rs:546-547` | 每连接 | 每 DATA frame / 每 TRAIN（`get_batch`） | ingress reader、installer、session 退出 | 同线程；写锁只在 open/close |
| `SessTable` 8 × `RwLock` | `table.rs:85,156` | 每连接 | 仅 fast-table **且**线程 memo 都 miss | datagram reader、session reader、sweeper | 同线程；只读锁也是 RMW，但只在 miss 路径 |
| `SessMemo` 256 槽 | `memo.rs:61` | thread-local | 仅 fast-table 慢路径 | 无 | 无锁 |
| `UdpHub` 256 shard `ArcSwap` | `hub.rs:337` | 进程 | 每回程包 lookup | dispatcher / publish | 无锁 |
| `FlowBinding` 的 `state`/`context` 原子 | `r2_flow.rs` | 每 flow | 每帧一次 load / rev3 每 payload 一次 RMW | 归属单个 assoc；server 只读 | 无竞争 |
| drop / rev2 计数 | `stats/*` | 进程 | 每次**丢弃**一次 RMW；rev2 事件 256 批 | 所有线程 | 稳态不触发 |
| UDP retry shard `mpsc` | `udp/retry.rs:66` | 每 shard | 仅 `WouldBlock` | 生产者 / 一个 worker | 异常路径 |
| 各类 semaphore | `accept.rs` / `socks.rs` | 进程 | 仅建连/建 session | 所有连接 | 非稳态 |

**关键事实**：默认拓扑里，上表所有"每包级"的可变结构（stager、gate、registry、session
shard、fast table、memo）都只被**同一个 OS 线程**访问。这是 sharded runtime 的直接结果
（`server/main.rs:584-640`；`client/main.rs:842-880`），也是本审计认为"不存在锁竞争"的
结构性依据，而不是采样没抓到。

---

## 4. 实测证据

### 4.1 UDP ECHO 延迟（SOCKS，单 assoc，128 B，loopback）

```
lat    n=2000  p50=111  p90=132  p99=269  p999=350  max=683  mean=119 µs   lost=0
```

### 4.2 UDP ECHO 全双工 paced（1 assoc，20k pps × 10 s，128 B）

```
sent=200000  recv=200000  loss=0.000%
server CPU 7.20 s / 10.6 s = 0.68 core（单 shard 线程）
client CPU 8.11 s / 10.6 s = 0.77 core（interactive slot 线程 ≈ 74% 采样点 busy）
```

`sample` 在该 slot 线程上的分布（4727 个采样点）：dispatcher 1403（29.7%）、
quinn driver 1196（25.3%，其中 `sendmsg` 588、`recvmsg` 421）、association 914（19.3%，
其中 `try_recv_from` 509）、其余 park/timer。**整个进程的 mutex 采样点只有 8 个（该线程约 6 个，
且均为 `pthread_mutex_lock`，没有 `__psynch_mutexwait`）**。

服务端 shard 线程（5413 个采样点）：quinn driver 1713（31.6%，`recvmsg` 835、
`try_send→sendmsg` 678）、连接 datagram reader 1484（27.4%）、session readers 1072（19.8%，
其中 `try_recv_from` 564、`handle_session_reply` 约 20）、其余 accept/timer/park。
**栈顶 `pthread_mutex_lock` 9 个（0.17%）**。

> 平台对照：macOS 上 40k datagram/s 约 0.68 core（≈17 µs/datagram，无 `sendmmsg`/`recvmmsg`、
> 无 GSO）；仓库在 Linux 上测得 120k pps 时 server 0.42 core（≈3.5 µs/RTT，PERF_ANALYSIS §13）。
> 5 倍差距来自 syscall 批处理能力，不是锁。

> `handle_session_reply` 只占约 20 个采样点，说明 stager push/encode 本身已经很薄；
> session reader 的 20% 主要是"每个 burst 多一次 EAGAIN"（E4）和 select 轮询，不是锁。

### 4.3 TCP ECHO 延迟（SOCKS，每次新建 CONNECT，1 KiB echo）

```
修复前  connect p50=106 p90=146 p99=222 p999=300  | echo p50=135 p90=188 p99=338 p999=465 µs
修复后  connect p50=100 p90=117 p99=143 p999=171  | echo p50=130 p90=146 p99=178 p999=411 µs
```

### 4.4 TCP bulk（4 flows，512 MiB/flow，总 2 GiB，loopback）

```
修复前  throughput = 135 MB/s，wall 15.93 s；客户端 5 个 main worker 上约 170 个
        __psynch_mutexwait，其中约 160 个的栈是 copy_tcp_quic_acked
修复后  throughput = 137 MB/s，wall 15.65 s；客户端采样中 __psynch_mutexwait = 0
```

修复前的服务端 shard 线程 4316 个采样点中，4204 在 driver，3333 在 `try_send`，
**3324 在 `__sendmsg`（77%）**——TCP 侧的上限是"每包一次 sendmsg"的 syscall/加密成本
（macOS 无 GSO）加上单 shard 线程，不是应用层锁。修复只消除了客户端的跨核 mutex 等待，
不改变这一服务端上限。

### 4.5 修复后回归（其他形状）

| 场景 | 结果 |
|---|---|
| UDP echo `lat`（2000 次） | p50 112 / p99 271 / p999 347 µs，0 丢包（修复前 111/269/350） |
| UDP 全双工 20k pps × 10 s | 0 丢包；server 0.64 core，client 0.71 core（修复前 0.68 / 0.77） |
| `[[udp_forward]]` 5k pps × 8 s（单 peer，128 B） | 40 001/40 001 回复，0 丢包；client 0.18 core |
| `[[udp_forward]]` 串行往返（2000 次，Python 驱动，含驱动开销） | p50 119 / p90 212 / p99 357 / p999 534 µs，0 丢包；无 2 ms retry 尾巴 |
| `forward_e2e` + `rev3_e2e` | 7 + 9 个用例全部通过（含两 peer 分离、8 KiB 载荷、peer churn、服务端重启恢复） |


### 4.6 复现命令

```bash
# 目标
target/release/examples/hotpath_bench echo 9000          # UDP echo
target/release/examples/hotpath_bench techo 9001         # TCP echo
target/release/examples/hotpath_bench server 9002 65536 20000
# 代理
target/release/myquic2-server --config config-server.toml
target/release/myquic2-client --config config-client.toml
# 负载
target/release/examples/hotpath_bench lat      127.0.0.1:1080 127.0.0.1:9000 2000 128
target/release/examples/hotpath_bench udpbidir 127.0.0.1:1080 127.0.0.1:9000 10 128 20000
target/release/examples/hotpath_bench lattcp   127.0.0.1:1080 127.0.0.1:9001 300 1024
target/release/examples/hotpath_bench bulk     127.0.0.1:1080 127.0.0.1:9002 512 4
# 采样（需带符号构建）
sample "$(pgrep -x myquic2-server)" 8 -file /tmp/server.sample.txt
```

> 构建口径：4.1/4.2/4.3 的延迟与 CPU 用默认 `strip = "symbols"` 的 release 构建；4.2/4.4 的
> 栈采样用同一源码、`CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_PROFILE_RELEASE_STRIP=none` 的 LTO
> release 构建（否则栈上没有符号）。采样窗口 6-8 s，叠在 20 s paced / bulk 负载内。
> `udpbidir` 的 `recv_pps` 包含停止后的 2 s 排空宽限，长跑时读数会低于 `sent_pps`，不等于隧道丢包。

---

## 5. 问题与修复（按优先级）

### E1 [P2，形状相关] `[[udp_forward]]`：每包一次 push + 主运行时跨核 — ✅ 已修

**机制（修复前）**：`spawn_udp_forward` 在 main runtime 上 spawn（`forward_udp.rs:72`），peer 的
uplink 用 `new_unbatched`（旧 `:308`），于是 `stage_or_count` 对每个 payload 都走到
`flush_stage`（`rev2.rs:1921-1922`）——一次 stager mutex；而 admission 还要
`Mutex<R2Stager>::queued_bytes()` + `conn.datagram_send_buffer_space()`（`rev2.rs:408-425`），
这两个锁的持有者分别在 slot 线程（driver/retry）和 main worker 上。drain 也在监听器线程上
执行，encode + `send_datagram`（以及 quinn 连接状态锁）每 burst 跨核一次。

**修复**：
1. `UplinkFlows` 不再有 unbatched 模式：每个 peer 的小包先留在自己的 burst batch 里，
   `forward_udp::run` 在 burst 边界按 peer 调 `flush_peer`，通过新增的
   `rev2::flush_assoc_stage` **一次 `push_batch`** 把整批交给连接 stager；
2. `flush_assoc_stage` 随后调用新增的 `ConnRev2::request_drain`，唤醒该连接在 slot runtime 上
   的 stager-retry task；**实际 encode 和 `send_datagram` 由 retry task 在 driver 线程执行**，
   监听器不再自己 drain（`forward_udp.rs` 删掉了 per-binding 的 `drain_assoc_stage`）；
3. retry task 的 `Busy` 处理从"直接睡 2 ms"改为先 `yield` 重试最多
   `STAGE_BUSY_SPINS = 4` 次，避免监听器短暂持锁把 notify 路径变成 2 ms 延迟；
4. `impl Drop for UplinkFlows` 给"从未进入 stager 的 burst batch"记账
   （`EGRESS_DEAD`），并在 peer 被 admission 淘汰时先同步 `drain_assoc_stage` 再发
   `SESS_CLOSE`（close 走可靠流，不能让它抢在数据帧之前），
   所以批处理没有引入静默丢包；
5. stager 在 claim 时仍会把同一 session 已排队的多个 item 组成 `TRAIN`，**帧数不退化**。

**验证**：`forward_e2e` 的 7 个用例（含 `udp_forward_e2e_two_peers_get_their_own_replies`、
`udp_forward_e2e_roundtrips_an_8k_payload`、`udp_forward_listener_survives_peer_churn`、
`forwards_detect_server_loss_and_recover_after_restart`）全部通过；`rev3_e2e` 的
`rev3_forward_listeners_roundtrip` 通过。单元测试改为在 `handle_datagram` 之后显式
`flush_peer`，钉住"批处理 + burst 边界 flush"这一契约。

### E2 [P2] 客户端 TCP pump 跨运行时 → 抢 quinn 连接锁 — ✅ 已修

**机制（修复前）**：SOCKS 的 `handle_socks` 在 main 多线程 runtime 上跑，`copy_tcp_quic_acked`
（旧 `socks.rs:255`）也就在 main worker 上；而该连接所属 slot 的 endpoint/driver 在
current-thread slot 线程上。每次 `write_chunk`（16 KiB，`pump.rs:66`）和 `read_chunks` 都要拿
quinn 的连接状态锁，driver 在 `poll` 期间持有同一把锁并做最多 20 次 socket send。

**修复**：新增 `crate::run_tcp_pump`（`main.rs`）。它在 `slot.runtime()` 存在时把 pump spawn
到该 slot 的 current-thread runtime，调用方只 await `JoinHandle`；无 slot runtime（共享拓扑和
单测）时原样 inline。两个调用点都改用它：
- SOCKS：`socks.rs` 的 `copy_tcp_quic_acked`；
- TCP forward：`forward.rs` 的 `relay_tcp_forward`（`open_forward_stream` 现在把选中的
  `slot_idx` 一起返回）。

配套语义：
- `PumpAbort` 守卫在调用方 future 被 drop 时 abort pump（等价于迁移前"drop 调用方即关流"），
  pump 自己的 drop 会关 socket、reset/stop 流；
- `JoinError`：`is_cancelled` 只在 `SHUTTING_DOWN` 时视为正常退出，否则报"slot runtime 没了"；
  panic 用 `resume_unwind` 保留原始 panic site；
- app socket 仍由 main runtime 注册，token 的 readiness 可以唤醒任意 live runtime 上的任务，
  与 UDP relay socket 的既有契约一致。

**验证**：新增单元测试 `tcp_pump_runs_on_the_slot_runtime`：把一个 current-thread runtime
放在另一线程并在它进入 `block_on` 之前park 住，断言 pump 不会在调用方 runtime 上运行；
释放后 pump 完成并返回。重跑 4 流 TCP bulk 采样，`copy_tcp_quic_acked` 栈上的
`__psynch_mutexwait` 从约 160 个采样点降到 **0**（见 §4.4）。

### E3 [P2] 服务端 fast table / memo 容量 vs 高扇出 — ◐ 保留

**机制（更正）**：`FAST_SESS_SLOTS` 约 568（`accept.rs:356-372`），`SessMemo` 256
（`memo.rs:61`），而 README 明确说 shipped 客户端可把 ~2000 个 session 压到一个连接。超过
工作集后，每个 datagram 都要走 `forward_server_dgram` 慢路径：shard 读锁（8 个 shard 的
`RwLock` 读也是 RMW）、`Arc` 克隆。

**更正**：rev2/rev3 的稳态 DATA/TRAIN 调用点传的是 `staged: Some(&mut Vec<StagedSend>)`
（`accept.rs:3025-3035` 的 `r2_forward_flow_resolved`、`forward_v3_item`），所以慢路径的目标
发送**仍然进入 burst staging**，由 burst 末的 `flush_staged_sends` 分组发送；`staged: None`
只出现在 legacy MQP-2 分支（`forward.rs:744/768`）。因此 E3 的成本是"每 miss 一次 shard
读锁 + 若干 Arc 克隆 + 一次 fast-table 重装"，不是每包一次未 batch 的 syscall。

**评估**：这是容量/内存的取舍，不是锁 bug；8 session 的 echo benchmark 完全不触发。判定依据是
60 s 行的 `fast_table hits=/misses=`；若 miss 率 >50%，再考虑扩容（4096 槽约 ~360 KiB/连接）
或二级 memo。本次不改，避免把 admission 的内存预算与一个未观测到的形状绑定。

### E4 [P3] macOS 便携收包：每 burst 一次 EAGAIN

`assoc.rs:652` / `reader.rs:1912` 的 `try_recv_from` 在 macOS 上必定 `WouldBlock`（无
`recvmmsg`），每次 burst 多一次 syscall。实测占服务端 shard 线程 10.4%、客户端 slot 线程 10.8%
的采样点。Linux 走 `recvmmsg`，没有这项。可做的只有"把多个 session 的收包合并到一个
`recvmsg` 循环"之类的结构性改动，代价高、收益平台相关，暂不建议。

### E5 [P3] drain gate 的长持有

`drain_staged_inner` 在 gate 内完成 claim、encode、`send_packed_frames`，单次调用最多处理
`R2_STAGE_MAX_ITEMS = 1024` 个 item（每批 4 frame/64 item，循环）。单线程 shard 上它不会
"竞争"，但会占住该线程：期间同一 endpoint 的所有连接都不能收包/发 driver。正常情况下
队列很浅（每 burst 几十个 item），影响在数十 µs 内；一旦 stager 积压到上限，就是一次可感知的
队头阻塞。若要收敛，可把 gate 内的批数限制在 4 批并在批间 `yield`/交给 retry task。

### E6 [P3] 每 payload 的一次分配 + 两次锁税

小包上行 `Bytes::copy_from_slice`（`rev2.rs:1833`）是一次分配+拷贝；interactive 连接每 payload
的 admission 是 2 次锁（stager + quinn 状态）。同线程下合计 ~50-100 ns/包，20k pps 约 0.1-0.2%
CPU，属于已知且可接受的设计点（PERF_ANALYSIS §0 的"1 alloc + 1 copy"）。不要为此改成
借用/池化而破坏 `R2StageItem` 的所有权模型。

---

## 6. 已核对、确认不是问题的部分

- **下行不经过 stager**：客户端 dispatcher 自己 `sendmmsg` 写 relay socket，没有 per-assoc
  队列、没有 256 深度 mpsc、没有 `Full` 丢包分支（`hub.rs:20-40`）。
- **没有每包 channel / task / spawn**：唯一的数据面 channel 是 `udp/retry.rs` 的 shard 队列，
  只在 `WouldBlock` 时使用。
- **统计**：`udp_stats::payload` 等 256 条线程本地批；drop 计数只在**丢弃**时一次 RMW。
- **日志**：所有丢包/拒绝日志都过 rate limit；`debug!` 先判级别，稳态不格式化。
- **下行零拷贝**：服务端 `Bytes` slice 直接进 `R2StageItem`；客户端 dispatcher `slice_ref` +
  直接发送；`try_send_direct` 的单回复快路径避免两次分配两次拷贝。
- **TCP pump**：c2s 大块 `write_chunk` 零拷贝；s2c `read_chunks` + `write_vectored` 零拷贝；
  缓冲区 thread-local 池化；无 per-chunk 分配。
- **会话创建**（socket/task/表项）只发生在 association 建立，不在每包路径。
- **60 s sweep** 的写锁只影响本连接，且不在稳态。

---

## 7. 建议顺序

1. **E1 / E2 已落地**（本轮）：burst 批处理 + retry-task drain；TCP pump 迁移到 slot runtime。
   两者的回归见 §4.3-§4.5，测试见 §5。
2. **E3**：只在 `fast_table hits/misses` 显示高扇出时做；否则不要动内存预算。若要做，先决定
   "4096 槽 × ~88 B ≈ 360 KiB/连接" 由谁付费（`R2_INGRESS_FIXED_BYTES` / `max_peer_memory_mb`）。
3. **E4/E5/E6**：不建议现在改；E5 若将来关闭 sharded topology，必须与"drain 改非阻塞"一起做。
4. **后续可选**：给 `[[udp_forward]]` 增加与 `lat` 等价的延迟模式，把 forward 形状的
   p99 纳入常规回归；目前只有 e2e 与 CPU 粗略对照。

---

## 8. 行号索引

| 主题 | 位置 |
|---|---|
| 服务端 shard = 单线程 | `src/bin/myquic2-server/main.rs:584-640` |
| 服务端 datagram reader / TCP stream spawn | `src/bin/myquic2-server/accept.rs:4194`、`:4782` |
| 服务端 fast table 容量 / probe | `src/bin/myquic2-server/accept.rs:356-372`、`:768` |
| 服务端 session memo 256 | `src/bin/myquic2-server/memo.rs:61` |
| 服务端 session table 8 shard | `src/bin/myquic2-server/table.rs:85,156` |
| 服务端 stager flush / drain | `src/bin/myquic2-server/reader.rs:640-683`、`:1938-1948` |
| drain gate / 1024 上限 / 状态锁探测 | `src/udp/r2_stage.rs:1524-1601`、`:1547`、`:1564-1597` |
| 客户端 UDP assoc 迁移 | `src/bin/myquic2-client/assoc.rs:1091-1137` |
| 客户端 admission（2 锁） | `src/bin/myquic2-client/rev2.rs:408-425` |
| 客户端 TCP pump 迁移 | `src/bin/myquic2-client/main.rs`（`run_tcp_pump`/`PumpAbort`）、`socks.rs`、`forward.rs`（`open_forward_stream` 返回 slot idx） |
| 客户端 burst push / drain | `src/bin/myquic2-client/rev2.rs`（`push_stage_batch`/`drain_stage`）、`flush_assoc_stage`、`request_drain` |
| retry task 的 Busy 重试 | `src/bin/myquic2-client/rev2.rs`（`STAGE_BUSY_SPINS`） |
| forward 监听器 batch / flush | `src/bin/myquic2-client/forward_udp.rs`（`flush_peer`、burst 边界）、`rev2.rs`（`UplinkFlows`/`Drop`） |
| TCP pump / 16 KiB chunk | `src/tcp/pump.rs:66`、`:363-368`、`:431-472` |
| 客户端 dispatcher spawn 在 slot runtime | `src/bin/myquic2-client/dispatcher.rs:1822`、`main.rs:842-880` |
