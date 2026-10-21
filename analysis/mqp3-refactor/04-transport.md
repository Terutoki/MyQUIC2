# MQP-3 传输层事实、连接拓扑与「全双工」差距分析（task-4）

> 基线：`/Users/eric/WorkSpace/MyQUIC2`，HEAD `d2f9658` / v0.2.0（2026-10-20）。
> 方法：**只读**读源码 + quinn 依赖源码（`~/.cargo/registry/src/*/`）+ `python3` 算术建模。
> **未执行 `cargo build/test`，未启动任何进程做压测**；本文所有实测数字均标注来源，其余是模型/估算。
> 引用约定：仓库内文件用 `src/...:行号`；quinn 内部源码用 `quinn-<ver>/src/...:行号`，根目录为
> `~/.cargo/registry/src/index.crates.io-*/`。
> 置信度标注：**[实测]** 已有仓库内测量；**[模型]** 由源码常量+公式推导；**[估算]** 量级估计，
> 需要在 Linux 目标机用 microbench 校准。

---

## 0. TL;DR（先给结论）

1. **传输层本身已经是全双工的**：quinn/QUIC 两个方向有独立的包号空间、拥塞控制、丢包检测、
   RTT/PTO 和流控；一个方向的数据不以另一个方向的数据为前提。用户要求的「实现全双工」
   在 QUIC 层已成立，**缺的是 MQP-3 协议状态面的对称性和控制面**，不是 QUIC 能力。
2. **真正把两方向耦合在一起的只有四件事**：① 同一连接 driver 任务/状态锁/CPU 核（发送与接收
   在同一任务里）② 反向 ACK 流量与生成 CPU ③ 同一 server ingress shard 的核 ④
   同一方向内所有 session/flow 共享 cwnd/pacing/DATAGRAM FIFO（这是同方向问题，不是双向问题）。
3. **传输配置里最大的两个「白送」杠杆是配置而非协议**：`initial_mtu` 默认 1200（QUIC 下限），
   而 PMTU 发现只在发送队列排空时才探测，饱和连接可能长期停在 1200；把已知路径设成
   1360/1400/1472 可让 >1157 B（flow0 单帧上限）的 UDP payload 不再分片（1200 B 时包数
   −50%、wire −6.6%）。
   另一个是 4/8/4 MB 窗口（单 TCP 流 ~240 Mb/s @140 ms 的上限就是它算出来的，不是 BBR）。
4. **`send_datagram` 的真实成本结构**：一次 `std::sync::Mutex` 加锁 + 一次 `VecDeque` 入队 +
   一次 driver `wake`（同线程 ~50–150 ns）；但 driver 在**整轮 poll 期间一直持有该锁**（事件、
   发送、加密、syscall 都在锁内完成），跨线程发送方可能阻塞数微秒到数十微秒——这是 pps
   场景尾延迟的主要来源，也是「把生产者放到 driver 同线程」比任何协议改动都便宜的原因。
5. **quinn 已经会自动合包**：同一次 `poll_transmit` 内排队的多个 DATAGRAM 帧会被塞进同一个
   QUIC packet（`populate_packet` 的 DATAGRAM while 循环），所以「跨 session 聚合能省大量带宽」
   是**被高估的**：相比已合包的单帧，跨 session 超级帧只剩每帧 ~1–3 B 的 MQP 头去重
   （~1–3% wire）+ 更少的 send 调用（CPU）；TRAIN 相对「每 payload 一次 send」的小包 wire
   −8%（vs 已被 quinn 合包的单帧）、send −18×，这部分已实现（其中大部分 MQP-2 BATCH 已给）。
6. **bulk 的「1 payload = 1 send_datagram」不是协议浪费**：MTU 决定一个 packet 只能装一个
   接近 MTU 的 payload；除非抬 MTU 或做多连接/多路径，否则任何「超级帧」都减少不了包数。
7. **全双工的协议级缺口清单**（按收益排序）：(a) flow 表只由 client 拥有、server 不能开 flow、
   下行压缩依赖上行 install → 纯上行 flow 永不压缩（小包 4–18% wire，payload 越小/v6 越甚）；
   (b) 无控制面（CTL 仅保留、无 opcode）→ 无显式 flow ACK/close/能力协商/优先级/接收反馈；
   (c) server 不能主动 push； (d) 一个 TRAIN = 一个方向 + 一个 session；
   (e) 512 B 以上 payload 走 MQP-2 分片，没有 flow/地址压缩。
8. **推荐定义「MQP-3 全双工」= D1–D6**（见 §3.4）：数据面/状态面/控制面三对称 + 无方向依赖 +
   独立调度 + 可 benchmark 验证。它**不是**「两方向各得 100% 带宽」，也**不改变**每方向共享一个
   cwnd 的物理事实。
9. **杠杆排序（收益/风险比）**：配置（MTU、窗口）> 架构（生产者与 driver 同线程 + 每连接聚合
   发送）> 协议控制面 + per-direction flow 表（能力 + 小包 4–18%）> server 按 class 选 transport
   （~1–3% CPU，需分端口/ALPN 架构）> 单 flow 多连接 striping（仅单大流场景 30–80%，
   复杂度高）> FEC/NACK（条件性，默认不做）> 跨 session wire 聚合（1–3%）。
10. **对「大收益」的诚实判断**：对 bulk 吞吐，协议 wire 重写本身 ≤1–3%；真正的 10–30% 来自
    MTU/窗口/同线程化/分片消除；只有「单 flow 上限」才需要多连接/多路径这种结构性改动。
    「全双工」是**能力/公平性/延迟隔离**项，不是吞吐倍增器。
11. **测量计划**：macOS 本版 quinn-udp **无 GSO/GRO**（`fast-apple-datapath` 未启用），每包
    1 次 sendmsg/recvmsg，且 server 默认只有 1 个 shard 线程 → macOS 数字无法外推；必须在
    Linux 2–4 核 + `tc netem`（70/140 ms，0/0.5/2% loss）上跑 §5.4 的矩阵，并补 §5.3 的计数器
    （quinn `stats()` 已给出 cwnd/RTT/current_mtu/ios，可直接抓取）。
12. **开放问题 6 个**（§6），其中最关键：目标场景是「单大流」还是「多小流扇出」？这决定了
    bonding/拓扑是否在 scope 内。

---

## 1. 传输层事实基线（HEAD d2f9658）

### 1.1 依赖版本（Cargo.toml / Cargo.lock）

| 组件 | 版本 | 位置 |
|---|---|---|
| quinn | 0.11.12 | `Cargo.lock:1294`；`Cargo.toml:42-47`（`default-features=false`，features: log/runtime-tokio/bloom/rustls-aws-lc-rs） |
| quinn-proto | 0.11.19 | `Cargo.lock:1314` |
| quinn-udp | 0.5.16 | `Cargo.lock:1338` |
| rustls | 0.23.46（aws-lc-rs） | `Cargo.lock:1508` |
| tokio | 1.53.3 | `Cargo.lock` |

`Cargo.toml:20-41` 的注释明确：0.11 线浮动，`Blocked`-vs-`try_send_datagram` 语义被回归测试钉住；
**没有** fork、没有 `MAX_CHUNKS` 补丁。quinn-udp 以 `default-features=false, features=["tracing"]`
被 quinn 引入 → **`fast-apple-datapath` 未启用**（这是后文 macOS 结论的根据）。

### 1.2 生效的传输配置（逐项，标注生效端）

代码位置：`src/transport/build.rs:144-281`（`build_transport_tuned_class`），默认值
`src/config/tuning.rs:207-236`、`src/transport/limits.rs`。

| 参数 | 生效值 | 代码 | 生效端/说明 |
|---|---|---|---|
| 拥塞控制 | **BBR**（`BbrConfig::default()`：初始 cwnd = 200×1200 B = 234 KiB，min cwnd = 4×MTU） | `build.rs:167-174`；quinn-proto `congestion/bbr/mod.rs:517-537,638-650` | 两端；`congestion="cubic"` 只是逃生口 |
| DATAGRAM → 发送缓冲 | interactive **1 MiB** / bulk **2 MiB** | `build.rs:159-163,179-180`；`limits.rs:84,88` | 仅本端发送队列；**server 永远用 interactive 预设**（下条） |
| DATAGRAM → 接收缓冲 | interactive 1 MiB / bulk 2 MiB | `build.rs:179` | 本端接收队列（对端可发上限）；server 1 MiB |
| ACK 频率（请求**对端**） | interactive: threshold 2 / max_delay 5 ms；bulk: 8 / 10 ms；reordering_threshold 2 | `build.rs:224-229`；`build.rs:150-158` | **客户端按 slot 分预设；server 对所有连接只有 interactive 预设**（`src/bin/myquic2-server/main.rs:126` 用 `build_transport_tuned`→`is_bulk=false`）→ 双向不对称 |
| initial_rtt | 190 ms | `build.rs:238`；`tuning.rs:163-170` | 只影响首个 PTO/初始 pacing |
| initial_mtu | **1200**（QUIC 下限） | `build.rs:263`；`tuning.rs:193`；`config-server.toml:74` 注释 | 两端各自配置；clamp 1200..=1472 |
| PMTU 发现 | 开启，upper_bound 1472，min_mtu 1200，interval 600 s，black-hole cooldown 60 s | `build.rs:243-245`；quinn-proto `config/transport.rs:698-755` | **机会式**：探针只在 `poll_transmit` 的 `buf.is_empty() && established` 才发出（quinn-proto `connection/mod.rs:950`）→ 饱和连接可能长期停在 1200 |
| 流控窗口 | 4 / 8 / 4 MiB（stream_rwnd / conn_rwnd / send_window） | `build.rs:206-212`；`tuning.rs:229-232` | 每连接、每方向（send_window 是本端发送预算）；opt-in 8/16/8 |
| 并发流 | bidi 8192 / uni 100 | `build.rs:197-198`；`tuning.rs:96` | 覆盖 8192 SOCKS 连接落一连接的最坏情况 |
| keepalive / idle | 5 s / 15 s（=3×keepalive，floor 15） | `build.rs:264-275` | 每连接心跳；7 连接 = ~1.4 pkt/s/客户端 |
| GSO/GRO | **quinn-udp 自动探测，无 API 开关**：Linux GSO=64 段（quinn 再 clamp 到 10 段/sendmsg），GRO=64 段；macOS 无 `fast-apple-datapath` → GSO=1、GRO=1、每包一次 recvmsg | quinn-udp `unix.rs:189,237-252,806-855,978-996`；quinn `connection.rs:1020-1023,1334-1341`；`build.rs:175-178,276-279` | **`gso` 配置是惰性的**：server 只打印（`myquic2-server/main.rs:163-170`），client 解析后从未读取（`config/client_conf.rs:20`） |
| ECN | **默认开**：quinn-proto `PathData::sending_ecn = true`，发 ECT0，ACK 不含 ECN 计数/校验失败即关 | quinn-proto `connection/paths.rs:73,122`、`connection/mod.rs:1006,1563-1600`；quinn-udp `unix.rs:119-140,614-632,719-799` | Linux 生效；macOS 双栈套接字的 `IP_RECVTOS` 不被支持（quinn-udp 注释 `unix.rs:119-121`）→ IPv4 收包无 TOS → ECN 大概率被自动关闭。**不是可调杠杆** |
| 端点 socket 缓冲 | 每 endpoint 请求 4 MiB SO_SNDBUF/SO_RCVBUF（Linux 内核记 2×）；`SO_*BUFFORCE` best-effort | `src/lib.rs:137-144,336-402,592-603` | 每 client slot / server endpoint |

**README 声称 vs 实际**（`README.md:755-790`）：

- 「BBR + GSO/GRO + ECN + PMTU」——BBR/ECN（Linux）为真；GSO/GRO 仅 Linux（本 quinn-udp 版本
  macOS 完全关闭）；PMTU「opportunistic」的描述与源码一致，但 README 未强调饱和连接可能永不升级。
- 「4 TCP + 2 class-split UDP 连接」——默认是 **7 条 QUIC 连接**（4 TCP + 1 interactive UDP +
  2 bulk UDP；`config-client.toml` 注释、`README.md:147-190`、`src/bin/myquic2-client/pool.rs:429-460`）。
- 「connection count scales linearly」——按连接数线性，但**单连接单 shard 是单线程**，见 §1.3。
- `gso = true` 配置项：**纯装饰**（只影响日志），改它不会有任何传输行为变化。
- 一处小的内存记账偏差：`endpoint_recv_buffer_bytes()`（`src/config/tuning.rs:343-351`）在非
  Linux 上只记 1472 B，实际 quinn 的 `recv_buf = max_udp_payload(1472) × max_receive_segments(1)
  × BATCH_SIZE(32) = 46 KiB`（quinn `endpoint.rs:751-760`，quinn-udp `unix.rs:806-809`）→
  非 Linux 每 endpoint 少算 ~46 KiB（7 endpoint ≈ 0.3 MiB，量级无关紧要，但可用于校正文档）。

### 1.3 连接/端点/线程拓扑（这决定全双工的 CPU 耦合）

**客户端**（`src/bin/myquic2-client/main.rs`、`pool.rs`）：

- 默认 7 个池 slot = 4 TCP（slot 0 交互 + slot 1-3 bulk RR）+ 1 interactive UDP + 2 bulk UDP
  shard（`pool.rs:429-460`；`udp_split=true`、`udp_egress_conns=2`）。
- **每个 slot 一个独立 `quinn::Endpoint` + 独立 UDP socket + 独立 current-thread tokio runtime**
  （`main.rs:199-232` 默认分片拓扑；`MYQUIC2_SHARD_RUNTIME=0` 回退到共享多线程 runtime）。
  Linux 上按优先级 pin 核（interactive 优先）；**macOS 的 `pin_to_core` 是空操作**
  （`src/linux.rs:184-198`）。
- UDP association 的 relay 任务（上行生产者）**跑在主 multi-thread runtime** 上，而 egress
  driver 在 slot runtime 上 → 每个上行 DATAGRAM 一次跨核 state 锁 + driver wake
  （`PERF_ANALYSIS.md:326-343` 的 F10，至今仍是 deferred）。这是**当前上行 pps 成本的
  结构性大头**，比任何 wire 格式优化都值钱。

**服务端**（`src/bin/myquic2-server/main.rs`）：

- `quic_endpoints` 个 `SO_REUSEPORT` endpoint，Linux 默认 = 可用核数（clamp 1..=8），非 Linux
  默认 1（`src/config/tuning.rs:151-161`）。
- 默认分片：**每个 endpoint 一个独立 OS 线程 + current-thread runtime，accept loop、该 endpoint
  上所有 connection driver、所有 TCP stream pump、所有 UDP session reader 全部跑在这一个线程上**
  （`main.rs:485-556` `spawn_ingress_shard`；`main.rs:566+` `accept_loop`）。
  ⇒ **单 shard 上一条连接的双向流量共享一个核**；全双工吞吐上限 = 单核处理能力，
  与该连接的 quinn 无关。2–4 核路由器形态下 server 只有 2–4 个 shard。
- 所有连接共用**一个** `ServerConfig` transport 预设 → 第 1.2 节所述 bulk 预设不对称
  （server 侧 bulk 连接仍是 1 MiB DATAGRAM 缓冲 + ACK threshold 2）。quinn 0.11 没有按
  ALPN/SNI 在握手前选 transport config 的钩子；要做到 per-class 只能分端口/分 endpoint。

### 1.4 对 README「性能设计」段的核对结论

| README 声称 | 核对结果 |
|---|---|
| 「每 UDP payload 一次精确容量分配 + 一次拷贝」 | 成立（`src/mqp/datagram.rs:93-135`），quinn 内部还会再拷一次进 packet buffer（`frame.rs:905-913` `extend_from_slice`）→ **发送路径实际 2 次拷贝** |
| 「zero-copy TCP↔QUIC pump」 | 成立（`src/tcp/pump.rs`） |
| 「GSO/GRO batched I/O」 | 仅 Linux；macOS 本依赖配置下为 0 |
| 「ECN + PMTU」 | ECN 默认开（Linux 有效）；PMTU 机会式，饱和时可能不生效 |
| 「A TRAIN amortizes the frame over every payload that fits」 | 成立，但仅 ≤512 B payload（`BATCH_SMALL_MAX`）；>512 B 走 MQP-2 分片路径（每片一帧） |

---

## 2. `send_datagram` 每包成本模型（quinn 0.11.12 / quinn-proto 0.11.19）

### 2.1 调用链（逐跳引用）

应用调用 `try_send_datagram`（`src/udp/send.rs:84-95`）→ `conn.send_datagram_wait(d).now_or_never()`：

1. `SendDatagram::poll`：`state.lock("SendDatagram::poll")`（`quinn-0.11.12/src/connection.rs:846-890`）；
2. `Datagrams::send(data, drop=false)`（quinn-proto `connection/datagrams.rs:31-65`）：
   - 校验 DATAGRAM 是否启用（`datagram_receive_buffer_size.is_none()` → `Disabled`）、
     对端是否支持（`peer_params.max_datagram_frame_size` → `UnsupportedByPeer`）、
     大小上限 `min(max_datagram_size(), send_buffer_size - size_of::<Datagram>())`（`TooLarge`）；
   - 发送缓冲空间检查（`Blocked`）后 `outgoing.push_back(Datagram { data })`；
3. `state.wake()`：取走 driver waker 调 `Waker::wake`（`connection.rs:1221-1225`）；
4. 失败语义：`Blocked` 把 Bytes 放回 future，挂在 `datagrams_unblocked.notified()` 上
   （本项目 `now_or_never` 立即 drop → 新包被丢弃并计数，不排队等）。

### 2.2 发送侧成本分解

| 阶段 | 成本（估算/实测） | 说明 |
|---|---|---|
| MQP 编码（帧分配 + 拷贝） | **15–30 ns/帧 [实测]** | `examples/frame_bench.rs:17-25`：128 B 同线程 15–19 ns、1200 B 25 ns |
| `send_datagram_wait` 无竞争 | **~50–150 ns [估算]** | std Mutex lock/unlock ~10–20 ns + VecDeque push + `Waker::wake` + future 构造/drop |
| **state 锁竞争（关键）** | **0 或 数 µs–数十 µs [估算]** | driver 在**整轮 `ConnectionDriver::poll` 期间持锁**：处理事件→`drive_transmit`（最多 20 个 datagram / 每 `poll_transmit` 最多 10 个 GSO 段，含 AEAD 加密与 `try_send` syscall）→timer→事件转发（`quinn-0.11.12/src/connection.rs:256-287`）。跨线程发送方会在 `std::sync::Mutex` 上**阻塞**（无 try_lock）。Linux GSO 满载一轮约 5–25 µs；macOS 无 GSO（20 次 sendmsg）约 30–80 µs |
| driver 侧每 DATAGRAM | Linux **~0.5–1.1 µs**；macOS **~1.5–3.5 µs [估算]** | AEAD 加解密 1.2–1.4 KB ≈ 0.3–0.9 µs（AES-GCM/AES-NI，aws-lc-rs）+ 组包 0.05–0.15 µs + syscall 摊销（Linux GSO 10 段一次 sendmsg → 0.02–0.05 µs/包；macOS 1–3 µs/次） |
| GSO 批内 padding | ≤6–8 B/包 [模型] | DATAGRAM 的最大 body = MTU−38，实际包 = MTU−8（2 字节 PN）→ 批内每包补 8 B 到 segment_size（quinn-proto `connection/mod.rs:645-700`） |

### 2.3 接收侧成本分解

quinn 的接收是两段式：**endpoint driver** 做 syscall + `PartialDecode` + CID 查表 + 投递事件；
**每个 connection driver** 在锁内做完整解密/帧解析/入队（`quinn-proto/src/endpoint.rs:148-260`；
`quinn-0.11.12/src/endpoint.rs:742-850`；`connection.rs:256-287`）。

| 阶段 | 成本（估算） | 说明 |
|---|---|---|
| recv syscall | Linux ~0.02–0.1 µs/包（recvmmsg 32 条 + GRO 64 段摊薄）；macOS **1–2 µs/包（每包一次 recvmsg）** | quinn-udp `unix.rs:433-581,806-809`；macOS 走 `recv_single` |
| endpoint partial decode + CID 路由 + 事件通道 | ~0.1–0.3 µs/包 | 每包一次 `mpsc::UnboundedSender::send`（含节点分配 + 目标任务 wake） |
| 解密 + 帧解析 | ~0.3–0.9 µs/包 | connection driver 锁内 |
| DATAGRAM 入队 + `DatagramReceived` notify | ~0.05–0.2 µs/包 | `split_to` 零拷贝切片（`frame.rs:567-573`），`read_datagram` 每个 DATAGRAM 一次锁 |
| 应用消费（relay 转发 / dispatcher） | Linux ~0.1–0.5 µs（sendmmsg 分组摊薄）；macOS ~1–3 µs | 客户端 dispatcher 每次唤醒 drain ≤32 包（`client/dispatcher.rs:733-860`）；server 每 session 一个 reader task（`server/reader.rs:1132`） |

> 以上除 frame_bench 外都是**估算**；§5.3 的计数器 + 一个 `examples/sendcost_bench.rs` 微基准
> 可以在目标机把这张表校准成实测值。**结论只需要相对量级**：每包成本由「加密 + syscall +
> 任务唤醒」主导，`send_datagram` API 本身在无竞争时很便宜，真正贵的是**跨线程竞争**。

### 2.4 合包行为：quinn 已经做了什么、没做什么

**已经做**：同一次 `poll_transmit` 内，`populate_packet` 用 while 循环把已排队的多个 DATAGRAM
帧写入同一个 QUIC packet（quinn-proto `connection/mod.rs:3351-3368`），条件是
`buf.len() + Datagram::SIZE_BOUND < max_size`。GSO 又把最多 10 个 packet 塞进一个 sendmsg
（`quinn-0.11.12/src/connection.rs:1020-1023,1341`）。实测含义：

| 场景 | 每 packet 帧数 [模型] | 每 sendmsg 包数 |
|---|---:|---:|
| 60 B payload，每帧一次 send 且同 poll 排队 | 17 | 1（只占 1 段） |
| 60 B payload 用现有 MQP-3 TRAIN | **18** | 1 |
| 1200–1400 B payload（接近 MTU） | 1 | Linux 10 / macOS 1 |
| 28 B payload（同 poll 排队） | 32 | 1 |

**没做（两个真实边界）**：

1. **FIFO 队头阻塞**：`DatagramState::write` 取队首，若放不进当前包就 `push_front` 并返回 false，
   循环 break（quinn-proto `connection/datagrams.rs:212-227`，注释原文：*"Future work: we could be
   more clever about cramming small datagrams into mostly-full packets when a larger one is queued
   first"*）。⇒ 一个接近 MTU 的队头 DATAGRAM 会让后面一堆小包开启新 packet，packet 尾部的
   ~1 KB 空间浪费。小包/大包混跑的同连接会因此多出少量包。
2. **DATAGRAM 先于 STREAM 写入**：`populate_packet` 的顺序是 ACK/控制 → DATAGRAM → STREAM
   （quinn-proto `connection/mod.rs:3350` vs `:3408`），所以同一连接上 UDP 洪泛会先占满
   packet，TCP STREAM 只能吃剩余空间/下一包 → **TCP 与 UDP 绝不能共享连接**（现有拓扑正确）。

### 2.5 `Blocked` / `TooLarge` / `max_datagram_size` 的确切语义

- `max_datagram_size() = current_mtu − predict_1rtt_overhead(None) − Datagram::SIZE_BOUND`
  = MTU − 29 − 9 = **MTU − 38**（quinn-proto `connection/datagrams.rs:86-100`；
  `connection/mod.rs:3763-3787`），再与对端 `max_datagram_frame_size` 取 min（quinn 广播值 =
  `min(接收缓冲, u16::MAX)`，即 ≥64 KiB 缓冲时是 65535，实际总是路径预算更小，
  `transport_parameters.rs:170-172`；两侧都广播 `min_ack_delay` 所以 ACK_FREQUENCY 扩展双向生效，
  `transport_parameters.rs:176-179`）。MTU 是「最大 UDP payload」：1200 → 1162，
  1360 → 1322，1400 → 1362，1472 → 1434。
- `TooLarge` 两个来源：路径 MTU 缩小（`drop_oversized` 在每次 MTU 变化时丢弃队列中超限的
  DATAGRAM，`datagrams.rs:67-83`）和编码器预算过期（本项目 100 ms 内不重读，两端的 `TooLarge` 节流见
  `udp/send.rs:190-212`、`server/reader.rs:86-100`）。
- `Blocked`：发送缓冲满。本项目的 `try_send_datagram` 选择「drop 新包并计数」，
  而 quinn 的 `send_datagram` 会「丢最老的」且返回 Ok（`udp/send.rs:43-95` 有详细理由）。
- 单帧最大应用 payload（flow 0、无 inline 地址）= `MTU − 38 − 5`：1200→**1157**、
  1360→1317、1400→1357、1472→**1429**。⇒ **1420 B 的 WireGuard 内层 payload 只有
  `initial_mtu=1472` 才能单帧**（1420+5+38=1463 ≤1472）；1360/1400 下必然 2 分片。

### 2.6 量化表（IPv4；公式见附录 A）

**表 A：单个 MQP SINGLE（flow 0，5 B 头）独占一包**

| payload | wire | 总开销占比 | 其中 MQP 头 |
|---:|---:|---:|---:|
| 28 B (STUN) | 91 B | 69.2% | 5.5% |
| 60 B (DNS) | 123 B | 51.2% | 4.1% |
| 128 B | 191 B | 33.0% | 2.6% |
| 200 B (game) | 263 B | 24.0% | 1.9% |
| 512 B | 575 B | 11.0% | 0.9% |
| 1000 B | 1063 B | 5.9% | 0.5% |
| 1157 B (1200 MTU 上限) | 1220 B | 5.2% | 0.4% |

> 固定开销 = 20 IP + 8 UDP + 27 QUIC 头(1+8 DCID+2 PN+16 tag) + 3 DATAGRAM 帧头 = 58 B。
> 「总开销」一列的结论：**小包的 45–60% 是 QUIC/IP 固定开销，不是 MQP 头**；MQP-3 的重写
> 空间在 60 B payload 上上限 ~4–8%，这正是 PROTOCOL_ANALYSIS 的结论，本文复核成立。

**表 B：现有 MQP-3 TRAIN 的打包效率（MTU 1200，flow 0，item=1B flags+1–2B len）**

| payload | item | 每包 items | wire/payload | 同 payload 单帧独占一包 |
|---:|---:|---:|---:|---:|
| 28 B | 30 B | 38 | **1.13** | 3.25 |
| 60 B | 62 B | 18 | **1.09** | 2.05 |
| 128 B | 131 B | 8 | **1.09** | 1.49 |
| 200 B | 203 B | 5 | **1.08** | 1.32 |
| 512 B | 515 B | 2 | **1.07** | 1.12 |

**表 C：同样 payload 用「多次 send_datagram」但被 quinn 合进同一 packet**

| payload | 每包帧数 | wire/payload | TRAIN 相对它 |
|---:|---:|---:|---:|
| 28 B | 32 | 1.35 | −16% |
| 60 B | 17 | 1.19 | **−8.0%** |
| 128 B | 8 | 1.12 | −2.7% |
| 200 B | 5 | 1.10 | −1.5% |
| 512 B | 2 | 1.07 | −0.1% |

⇒ TRAIN 的真实收益 = 小包 2–8% wire + （最多 64 项）1 次 send 代替 N 次；**bulk 无收益**。

**表 D：反向 ACK 开销（下行 300 Mb/s、ACK 帧 ~12 B、v4 包 70 B）**

| ACK threshold | 每 N 包 1 ACK | 反向带宽 | 占下行字节 | ACK 率 @MTU1200 |
|---:|---:|---:|---:|---:|
| 1（quinn 无扩展时默认） | 2 | 8.98 Mbps | 2.87% | 16.0k/s |
| 2（交互预设） | 3 | 5.99 Mbps | 1.91% | 10.7k/s |
| 8（bulk 预设） | 9 | 2.00 Mbps | 0.64% | 3.6k/s |
| 16 | 17 | 1.06 Mbps | 0.34% | 1.9k/s |

> 表中按「计数**超过** threshold 才 ACK」计算（quinn 语义，`build.rs:222-223` 注释）；
> 反向还有 ACK 生成 CPU（每条 ~1–3 µs [估算]），10.7k ACK/s ≈ 单核 1–3%。

**表 E：MTU 对 bulk / 分片的影响（MQP 单帧上限 & 分片消除）**

| 场景 | MTU 1200 | MTU 1360 | MTU 1400 | MTU 1472 |
|---|---|---|---|---|
| 1200 B payload | 2 片（1144+56），wire 1352，2 send | **1 帧**，1263，1 send | 1 帧，1263 | 1 帧，1263 |
| 1420 B payload | 2 片，1572，2 send | 2 片，1572 | 2 片，1572 | **1 帧，1483，1 send** |
| 1200→1360 收益 | — | wire **−6.6%**，send/包数 **−50%** | 同 1360 | 同 1360（对 1200B） |
| 单帧上限 | 1157 | 1317 | 1357 | 1429 |
| TCP（每包应用字节） | 1168 | 1328 | 1368 | 1440 |
| TCP 每 MiB 包数 | 898 | 790（−12%） | 767（−15%） | 728（−19%） |

PLPMTUD 从 1200 升到 1472 的搜索序列是 1336→1404→1438→1472（quinn-proto `mtud.rs:315-350`），
每个探针要等一个 ACK（~1 RTT）：**140 ms 链路 ≈ 560 ms 才能到顶，且只在发送队列排空的 poll
才发探针**（`connection/mod.rs:950`）。⇒ 对持续饱和的 bulk 连接，**不要指望 PMTU 自动升**。

### 2.7 结论：「1 frame = 1 send_datagram」值得改吗？

- **bulk（≥512 B）**：不值得。一个 packet 只能装一个接近 MTU 的 payload；减少 send 调用只能靠
  「抬 MTU」（把 2 分片变 1 帧，调用/包数 −50%）或「改走 QUIC STREAM」（不适用：UDP 要不可靠）。
  任何「超级帧」都不能把 1200 B payload 塞进 1162 B 预算。
- **小包**：已经通过 TRAIN 把每包 17–18 个 payload 压到 1 次 send；剩余空间是跨 session：
  当每个 session 每 burst 只有 1 个 60 B 包时，当前是 N 次 send + quinn 尽力合包
  （N 个单帧合进 1 包，wire/payload 1.19），跨 session 超级帧可到 1 次 send + 1.16
  （**wire −2.4%，send −N+1**）。**CPU 收益真实但不巨大（5–15% of send path），wire 收益 <3%。**
- 因此设计文档里不应把「跨 session 聚合」写成带宽项；它是 **CPU/pps 项**，且用架构手段
  （每连接聚合发送）即可拿到大部分，不必改 wire。

---

## 3. 「全双工」：精确定义与差距

### 3.1 传输层：哪些是真耦合

先说清楚：**QUIC 的数据面是天然全双工**。每条连接两个方向各有独立的包号空间、拥塞控制实例
（每个 endpoint 各自一份）、丢包检测/PTO/RTT 估计；一个方向的数据不以另一个方向的数据为前提。
真正跨方向的耦合只有：

| 耦合项 | 机制/证据 | 量级 | 能否消除 |
|---|---|---|---|
| 同连接 driver 任务与 state 锁 | 收包解密、发包加密、ACK 生成、发送队列都在同一个 connection driver 的锁内（`quinn-0.11.12/src/connection.rs:256-287`） | 满载时单任务 CPU 100%，双向共享；跨线程发送方阻塞尾延迟 5–50 µs [估算] | 不能消除；只能**同核/同 runtime** 降低调度成本，或每方向独立连接（当前 class 隔离） |
| 反向 ACK 流量 + 生成 CPU | 表 D：下行 300 Mb/s 时反向 0.6–2.9% 带宽 + 3.6–10.7k ACK/s 生成 | 带宽 <2%；CPU 1–3% [估算] | 调 `ack_threshold`/`max_ack_delay`（客户端 bulk 已有 8/10ms；server 侧没有 bulk 预设） |
| 同一 server ingress shard 的核 | 默认分片拓扑下一个 endpoint 的所有连接/流/session 全在一个核（§1.3） | 单 shard 单向 ~数百 Mbps 级；双向合计受单核 | 只能加 endpoint/多进程，不能靠协议 |
| 同方向内多 session/flow 共享 cwnd/pacing/DATAGRAM FIFO | quinn 无 per-flow 调度（见 §4.2） | 同方向内 bulk 流可饿死延迟流 | 需要协议级调度或连接隔离 |
| MTU / PMTU / ECN 状态 | 每 path 一份，双向共用 | — | 无需消除（本就该共用） |

**不存在**的耦合（不要虚构）：两个方向的 cwnd、丢包恢复、流控（STREAM 的 MAX_DATA 是单向的）、
PTO 定时器、0-RTT/密钥空间都各自独立。**「全双工」不会让上行跑得快或下行跑得慢——**
链路上行/下行带宽本来就是共享的，协议只能决定**如何调度**。

### 3.2 协议层：MQP-3 的非对称清单（真正的 gap）

证据：`src/mqp/v3.rs`（codec）、`src/bin/myquic2-client/assoc.rs`（上行）、
`src/bin/myquic2-server/reader.rs`（下行）、README `MQP-3` 段（`README.md:590-745`）。

| # | 现象 | 证据 | 影响 | 量化 |
|---|---|---|---|---|
| P1 | **flow 表由 client 拥有**：client 分配 id、server 只按 inline open 安装；server 不能开 flow | `v3.rs:640-780`（FlowTable）；`assoc.rs:350-430`；`reader.rs:79-190` | 下行压缩依赖上行 install；server 主动 push 只能 `NO_FLOW` inline | — |
| P2 | **纯上行 flow 永不压缩**：client 要等一次「压缩下行的下行帧」作为隐式 ACK 才从 inline 切压缩（`assoc.rs:340-400`） | 同左；README「Flow lifecycle」 | 只上行的小包流每帧多带 7/19 B 地址（v4/v6） | 60 B 包 +5.7%（v4）/+13%（v6）；128 B +3.7%/+9% |
| P3 | **无控制面**：`MQP3_CTL` 只有常量，无 codec/opcode；无 FLOW_ACK/CLOSE/CAPS/优先级/接收反馈 | `v3.rs:25`；README「CTL reserved」 | 无法显式确认/关闭/协商；无法做优先级、FEC、接收端信用；协议演进只能「匹配部署」 | 能力项 |
| P4 | **server 不能主动开 flow/push**（full-cone 未请求来源只能 inline） | `reader.rs:102-190`（`MQP3_NO_FLOW`） | WebRTC/P2P 入站等场景每帧多 7–19 B，且无法压缩 | 28–60 B 入站：v4 +5.7~7.7%，v6 +13~17% |
| P5 | **一个 TRAIN = 一个方向 + 一个 session**：跨 session 无法合帧/调度 | `v3.rs:286-360`（TRAIN 头带 sess） | 跨 session 小包只能靠 quinn 合包；无法按 session 调度 | §2.7 |
| P6 | **无 in-band ACK/接收信用**：quinn 接收缓冲满时丢最老 DATAGRAM，发送方无感知 | quinn-proto `datagrams.rs:125-155`（`while ... self.recv()`） | 慢消费者造成「静默丢包」（不影响 CC，因为包已被 ACK） | 洪泛场景（README `udpps` 基线 96.9% loss 可能包含此链） |
| P7 | >512 B payload 走 MQP-2 分片：每片带完整地址、无 flow、无 v3 紧凑头 | README「FRAG not wired」；`src/udp/fragmenter.rs` | 每片 18 B（v4）/30 B（v6）头；无跨片复用 | 1200 B 2 片时头占 payload 3%，wire 比单帧 +6.6%（MTU 允许时） |
| P8 | 一个 session 固定在一条连接一个 shard 上（`udp_bind` 首包定生死） | `pool.rs:429-460` | 单 assoc 吞吐 ≤ 单 shard 单 cwnd；无法跨连接聚合 | §4.4 |

### 3.3 架构层：7 连接 vs 单连接

| 维度 | 当前：4 TCP + 3 UDP 独立连接 | 若合并为 1 连接 + 协议 class |
|---|---|---|
| 每方向拥塞隔离 | **有**（每连接独立 cwnd/pacing/loss domain） | 失去；所有 flow 共享一个 cwnd（quinn 无 stream 优先级） |
| 接收/端点并行 | **有**（每 slot 独立 endpoint/driver/核；server endpoint 数 = 核数） | 单 endpoint 单 recv 循环 → 单核收包瓶颈 |
| 延迟隔离（bulk vs interactive） | **有**（独立队列与核） | 需协议级 priority + 应用层调度器，且 cwnd 仍共享 |
| 内存/准入 | 传输 7 × 14.25 ≈ 100 MiB，另加端点 userspace ~20 MiB + kernel caps 112 MiB；4096 连接上限 / 7 ≈ **585 客户端** | 传输 3 × 14.25 ≈ 43 MiB + 端点 ~9 MiB + kernel caps 48 MiB；≈ 1365 客户端/4096 连接 |
| 握手/keepalive | 7 次 TLS/心跳 | 3 次 |
| 适用 | 当前没有 stream 优先级/多路径，**这是 quinn 0.11 下唯一真实的隔离手段** | 只有协议层做出调度器之后才成立 |

**结论**：不要为了「全双工」把 class 合并成一条连接。应保留 **transport 级隔离**（interactive /
bulk，TCP / UDP），在**每条连接内部**做协议级的多 session 复用与优先级。可以合并的是：
同 class 内多条连接（例如 4 条 TCP bulk 连接）**在协议具备 session 级调度之后**，但收益是
内存/准入/握手，风险是丢隔离；不建议在本次 refactor 里做。

### 3.4 推荐定义：「MQP-3 全双工」（可直接写进设计文档）

> **定义**：MQP-3 是「全双工隧道协议」当且仅当满足以下 6 条（每条有可验收测试）：
>
> **D1 数据面对称**：任何帧类型（SINGLE/TRAIN/FRAG）可在两个方向发送；编解码不区分方向；
> 每个方向有独立的发送队列与调度器，一个方向的背压（该方向 cwnd/send buffer 满）不得阻塞
> 另一个方向的控制/数据路径。
>
> **D2 状态面对称**：每条 session 在每个端点为「本端发送方向」和「本端接收方向」各维护一张
> flow 表；flow id 由**发送方**分配、接收方安装；flow 的 open/confirm/close 由控制通道显式完成，
> **不依赖对向数据帧**。纯上行与纯下行 flow 达到相同的压缩率。
>
> **D3 控制面双向**：控制通道（建议用一条 QUIC 流，而不是 DATAGRAM；见 §4.9）双向可用，
> 承载 HELLO/CAPS、FLOW_OPEN/FLOW_ACK(可位图化)/FLOW_CLOSE、可选 PRIORITY/rate 提示与
> 接收信用；**两端都可以主动开 flow/关 flow**，包括 server 主动 push。
>
> **D4 无方向依赖**：任一方在对方尚未在本方向发送任何 payload 时即可发送（只受握手与 flow
> open 约束）；不要求「先收到反向数据」才能压缩/确认。
>
> **D5 独立调度**：每方向独立做 TRAIN 打包、MTU 预算、优先级/加权调度；跨方向的耦合只允许
> 共享 CPU/ACK 反向流量，并且这些耦合必须可度量（§5.3 计数器）。
>
> **D6 可测**：新增 `udpbidir` 基准：双向同时跑（每方向 20k/50k pps 或各 100 Mb/s），
> 验证 (a) 双向合计 ≥ 单方向 goodput 的 1.6×；(b) 交互方向 p99 相对单方向劣化 ≤10%；
> (c) 两方向都不出现 >1% 的静默丢包（P6）。
>
> **非目标**（写清楚，避免过度承诺）：
> - 不等于「两方向各得 100% 带宽」：链路/拥塞控制物理共享；
> - 不等于可靠传输：DATAGRAM 语义保持不可靠、无序、不重传；
> - 不消除同方向内 flow 竞争：需要 §4.2 的调度或连接隔离；
> - 不是 QUIC 的新特性：quinn/QUIC 已双向，本定义约束的是 MQP-3 的协议状态机。

### 3.5 差距 → 动作对照

| gap | 对应定义条款 | 最小动作 | 依赖 wire 变更？ |
|---|---|---|---|
| P1/P2/P4/P8 | D2、D4 | per-direction flow 表 + 发送方分配 id + 位图式 FLOW_ACK（或控制流可靠 ACK） | 是 |
| P3/P6 | D3 | 控制通道（QUIC 流）+ CAPS/FLOW/CLOSE/priority/credit | 是（新帧语义），控制流行本身复用流 |
| P5 | D5 | 跨 session 的帧复用（可选，收益小）+ 发送端每连接调度器 | 是（若做跨 session 合帧） |
| 传输耦合 | D1、D5 | 生产者与 driver 同 runtime/核；server 每 class 独立 endpoint/端口 | 否 |
| 可测性 | D6 | `udpbidir` + quinn stats 计数器 | 否 |

---

## 4. 传输/协议杠杆评估

> 每项给：机制 / quinn 能否 / 预期收益（按 §4.10 的 workload 编号）/ 风险 / 结论。
> 收益标注 **[实测][模型][估算]**，并区分「带宽」与「CPU/pps」。

### 4.1 连接级跨 session / 跨 flow 聚合

- **机制**：每个连接一个发送聚合器，把多个 session 的 pending payload 装进一个 DATAGRAM
  （需要新的跨 session 帧，item 里带 sess）或至少合成一次批量 send。
- **quinn 能否**：合包已经自动做（§2.4）；但「一次 send 发多个 DATAGRAM」**没有 API**，
  每个 DATAGRAM 仍是一次 `send_datagram`。跨 session 合帧只能在 MQP 层做。
- **预期收益**：wire **−1–3%**（对比 quinn 已合包的单帧，60 B：1.19→1.16）；send 调用
  **−N+1**（N=每包 session 数）；CPU 5–15% of send path [模型]；只对「大量 session 稀疏小包」
  有效；bulk/单 session 为 0。
- **风险**：跨 session 帧放大 fate-sharing（一个 packet 丢 → 多个 session 同时丢）；
  需要每连接共享队列（引入一次跨任务 hop，抵消一部分收益）；公平性要从任务调度改成显式轮转。
- **结论**：**不是带宽杠杆，是 pps/CPU 杠杆**；优先级低于「生产者同线程化」。若做，
  做成可选帧型（`TRAIN_MULTI`），作为控制面/调度器落地后的第二步。

### 4.2 每 flow 优先级 / 加权调度

- **机制**：wire 上给 item/flow 带 1–2 bit class/priority；两端各维护 per-class 队列；
  发送端每连接一个加权调度器（DRR/WFQ）按预算取包。
- **quinn 能否**：**不能**。quinn 0.11 没有 datagram 优先级/加权调度；`send_fairness`
  只作用于 STREAM（`config/transport.rs:157-158,380`）；DATAGRAM 是严格 FIFO
  （`datagrams.rs:31-65`），且同连接内跨 session 无任何隔离。
- **要做什么**：必须**绕过 quinn 的 FIFO**：应用层每连接一个调度任务，按优先级从 per-flow
  队列取 payload → 自行编码 → 一次 send（仍受 quinn FIFO 约束，但入队顺序即优先级顺序）。
  接收端若要保优先级，也需要 per-priority 的接收队列（quinn 只有一个 incoming FIFO）。
- **预期收益**：仅在「同方向同类连接内多 flow 竞争」时有效：交互 p99 在 bulk 竞争下
  **−30–80% [估算]**（取决于队列深度/BDP）；带宽 0。当前架构已用连接隔离处理了
  bulk-vs-interactive，剩下来的是 class 内部竞争（如一个 interactive 连接上多个 WebRTC flow）。
- **风险**：调度器本身 CPU；与 quinn 的 pacing/CC 交互复杂；优先级饥饿需审计；
  接收端 DATAGRAM FIFO 会打乱发送端优先级（除非协议保证按优先级发送且网络不重排——UDP 会重排，
  所以接收端必须自己分队列，这要求 dispatcher 在解码后按 class 分流，现有 hub/dispatcher 可以扩展）。
- **结论**：**D3/D5 的一部分，建议做**；但明确它改善的是延迟公平性而非吞吐。

### 4.3 每 class 独立连接（现状）vs 单连接 + 协议 class

见 §3.3 表。补充量化：

- 现状 7 连接：client 侧端点内存 Linux ≈ 20 MiB 常驻 receive scratch + 112 MiB 内核 caps
  + 7×14.25 MiB 传输预算 ≈ 100 MiB；server 对每客户端按 7 条连接计准入（4096 上限 → 585 客户端）。
- 合并到 3 条（TCP 池 1 + UDP interactive 1 + UDP bulk 1）：端点内存 ≈ 9 MiB + 48 MiB +
  43 MiB 传输；准入 → 1365 客户端/4096。
- **但**：quinn 无 stream 优先级 → 4 条 TCP 连接是「多 cwnd + 多核收包」的唯一来源；
  合并 TCP 池会让单 bulk 流仍限一个 cwnd，且所有 TCP 流共享一个 cwnd（互相排队）。
- **结论**：**保留 class 隔离**。可选的中间态：同 class 内连接数按核数配置（已有 `quic_conns`
  1..16、`udp_egress_conns` 1..8）；「全双工协议」不应该假设单连接，而应该假设
  「每连接 = 一个调度域（一个 cwnd、一个核、一个优先级域）」。

### 4.4 单 flow 多连接（bonding / multipath）——真收益还是炒作？

- **机制**：把一个 session 的 DATAGRAM 轮转/加权分发到 N 条连接（UDP 无序，天然可 striping），
  接收端按 session 归并；或做 MPTCP/MP-QUIC 式的可靠多路径（本场景不需要，UDP 不可靠）。
- **quinn 能否**：quinn 0.11 无 multipath、无跨连接 session；需要 MQP 层把 `sess → [conn]`
  映射，且**接收端 session 表目前是 per-connection 的**（每连接独立 `SessionTable`），
  跨连接必须让 serv 端按全局 session 路由 → 协议/架构改动大。
- **预期收益** [估算]：对**单条大流**（WireGuard 隧道、单 QUIC 透传、大文件 TCP 上传/下载）：
  在「单 cwnd/BDP 受限」或「单流丢包导致 BBR 吞吐受限」时，N 条连接可拿 **+30–80%**
  （2–3 条；上限是物理带宽/对端收包能力）。对多流场景 **0**（总容量已由多流分摊）。
  TCP 单流 striping 会引入重排 → 需要可靠重排序，**不建议**；UDP 单 assoc striping 可行。
- **风险**：重排（对 RTP 可接受，对隧道内 TCP 是灾难——但隧道内是 UDP，交回给内层应用）；
  不同连接 PMTU/丢包不同；接收端归并/去重；准入/内存 ×N；debug 复杂度。
- **结论**：**只有确认目标场景是「单大流」时才值得**。当前 `udp_bind` 把每个 assoc 固定到
  一个 shard，单 assoc 确实用不到 2 个 bulk shard 的总容量；但先测「单 assoc 在 Linux 上的
  实际上限」再决定（§5.4 矩阵 W3/W7）。**不要把它写成默认优化项。**

### 4.5 FEC 与 NACK/ARQ（对不可靠 DATAGRAM）

- **机制**：per-flow XOR/RS 奇偶校验包；接收端 NACK + 发送端重传或从 FEC 组恢复；
  需要 in-band 反馈（P3 控制面）。
- **quinn 能否**：DATAGRAM 不重传、不流控；quinn 的 CC 只看到「丢包」并按损失降速
  （BBR loss 处理），**应用层修复的包对 CC 不可见** → FEC/ARQ 的额外流量会加剧拥塞，
  除非协议自己限速。
- **收益**：只在有损链路（0.5–5% loss，移动/Wi-Fi/跨国）：
  - FEC（10+1 组）在 1% 丢包下把单包到达率从 99% 提到 ~99.9%（块内恢复），代价 +10% 带宽
    与编码 CPU；对 bulk 吞吐 **0 或负**（BBR 已经处理丢包；10% 冗余反而降有效带宽）；
  - NACK/ARQ 增加 ≥1 RTT（140 ms 链路上对实时流量不可接受），只适合非实时可靠业务——
    而可靠业务已经该走 QUIC STREAM（quinn 已有）。
- **风险**：与 quinn CC 的冲突、反馈通道成本、CPU、复杂度；错误配置会在干净链路上净亏。
- **结论**：**默认不做**。控制面设计时预留 per-flow policy + 反馈字段即可；作为 Phase 3
  可选项，用 A/B 在真实丢包网络上验证。不要相信「FEC 能大幅提升吞吐」——它换的是时延/到达率，
  不是带宽。

### 4.6 MTU 1200→1360/1400/1472 与 GSO

- **机制**：`initial_mtu`（配置/两端）决定每包可载字节与 DATAGRAM 单帧上限；
  GSO/GRO 由 quinn-udp 自动探测（Linux），无配置项。
- **quinn 能否**：能（`TransportConfig::initial_mtu`，clamp 1200..=1472）；但 PMTU 发现不可靠
  （§2.6），所以**必须显式配置**。`gso` 配置项无效。
- **预期收益**（表 E）：bulk UDP 1200 B payload：wire −6.6%、包数/send 调用 −50%；
  1420 B payload：只有 1472 能单帧（wire −5.7%、调用 −50%）；TCP：包数 −12–15%，
  wire −0.7%，CPU/pps 受限时 +5–15% [模型]；小包（60–200 B）：packing 密度 +5–11%，
  wire 改善 <2%。**GSO 收益仅 Linux**（macOS 0）。
- **风险**：路径实际 MTU 小于配置 → quinn black-hole 检测回退 1200（一次丢包风暴）；
  中间设备/VPN 封装。需要部署侧确认，建议默认 1360（WireGuard-1400 场景安全）或按部署配置。
- **结论**：**最高性价比的单项**（不改 wire、不改协议），应作为 P0。注意 1430+ B 内层
  payload 需要 1472，且 1472 只在确认 1500 路径上用。

### 4.7 0-RTT / 连接复用

- **机制**：quinn/rustls 的 session ticket；本项目已实现 resumption + `into_0rtt()`
  （`src/bin/myquic2-client/auth.rs:277-320`），但 **auth token 强制 1-RTT**（安全考虑，
  README 安全模型），且 0-RTT 期间没有应用 DATAGRAM 被发送（等 auth 后才 publish 连接）。
- **收益**：重连/重拨时省一个握手 RTT（140 ms 链路上 CONNECT/ASSOCIATE 首包延迟 −~1 RTT）；
  稳态吞吐 0。对「路径切换/移动网络」的体验有值，对性能目标几乎无值。
- **结论**：**保持现状**；如果未来做「会话跨连接恢复」（full-duplex 的 mobility 扩展），
  才需要把 session/flow 状态放进 ticket/控制通道。

### 4.8 ECN

- **机制**：quinn 默认 ECT0（§1.2），Linux 上生效；`process_ecn` 把 CE 当拥塞事件处理。
- **收益**：现代路径浅缓冲下 0–1%；对 BBR 意义有限；**已开，无可调项**。
- **结论**：不是杠杆。唯一可考虑的是「内层 ECN 透传」（隧道场景把内层 CE 映射到外层）——
  但 SOCKS5 UDP 不携带 ECN，MQP 没有字段，收益/复杂度不成立，**不做**。

### 4.9 附加：控制面 / 接收信用 / server push（全双工的核心增量）

- **机制**：MQP-3 CTL 已有 kind 保留位（`v3.rs:25`）；建议**控制消息走一条 QUIC 流**
  （可靠、有序、天然双向），而不是用 DATAGRAM 承载控制（要自己实现重传）。
  可选两条路线：
  - A. **每 session 一条 bidi 控制流**：生命周期最干净，但每条 session 占一个 stream 槽
    （server `MAX_STREAM_TASKS` 16384 / session 上限 8192；还需流控 credit）；
  - B. **每连接一条控制流 + session-id 复用**：更省，推荐；控制帧 ~6-20 B。
- **内容**：HELLO/CAPS、FLOW_OPEN（发送方分配 id + 目标地址）、FLOW_ACK（位图，8 B/64 flow，
  或直接依赖流的可靠有序性做「开流即开 flow」）、FLOW_CLOSE、PRIORITY/CLASS、可选接收信用。
- **收益**：纯上行 flow 压缩（P2：小包 4–18% wire，v6 更甚）；server push/入站压缩
  （P4：入站小包 6–18% wire）；显式 close 回收资源（session 180 s idle → 提前释放）；
  能力协商让 wire 可以演进；接收信用/优先级是 §4.2/§4.5 的前置。
- **成本**：控制流自身的带宽（每 flow 一次 open/ack，~20-40 B；对 DNS 这种 1 请求 1 回复的
  短 flow，**显式 open+ack 比省下的 7 B 更贵**）→ 必须设计成可摊销：
  **短 flow 继续 inline + 隐式确认；只有「会话内发送 ≥N 帧的 flow」才升级压缩**（N≈3），
  或把 FLOW_ACK 位图捎带在任意反向 TRAIN 头里（1 flag + 8 B）。
- **结论**：这是「全双工」的实体，**建议做**，但按 amortization 设计，不要无脑 per-flow ACK。

### 4.10 预期收益总表（按 workload × 杠杆）

workload 定义：**W1** bulk TCP 下行（300 Mb/s）；**W2** bulk TCP 上行；**W3** bulk UDP 单 assoc
（1200–1420 B payload）；**W4** bulk UDP 多 assoc/多 shard；**W5** 小包同 session（60–200 B，
20–100k pps）；**W6** 多 session 小包扇出（60 B）；**W7** 实时低延迟（p99 优先）；
**W8** 丢包移动网络（0.5–5%）。收益是相对当前 HEAD 的**方向性模型值**（非实测）。

| 杠杆 | W1 | W2 | W3 | W4 | W5 | W6 | W7 | W8 | 风险 |
|---|---|---|---|---|---|---|---|---|---|
| MTU 1200→1360/1400（配置） | 包数 −12–15%，吞吐 +0–5%（CPU 受限 +5–15%） | 同 W1 | **wire −6.6%，调用/包数 −50%** | 同 W3 | 打包密度 +5–11%，wire <2% | 同 W5 | ~0 | 同 W3；路径未确认时有回退风险 | 低 |
| 窗口 4/8/4→8/16/8（配置，仅 TCP） | **单流上限 240→300 Mb/s（+25%）** | 同 W1 | 0（DATAGRAM 无流控） | 0 | 0 | 0 | 无（但负载排队变差） | 0 | 低（内存 ×1.8/连接） |
| 生产者与 driver 同线程 + 每连接聚合发送 | CPU −3–10% | 同 W1 | CPU −3–10% | 同 W4 | **CPU −5–15%，尾延迟改善** | 同 W5 | p99 改善 | p99/尾延迟改善 | 低 |
| 协议控制面 + per-dir flow（D1–D5） | 0 | 0 | 0 | 0 | wire −4–8%（纯上行 flow） | wire −4–13%（60 B，v6 更甚；入站 6–18%） | 支持优先级/信用 | 有损链路上作为 FEC/反馈前置 | 中（wire 变更+摊销设计） |
| 跨 session 聚合（wire 层） | 0 | 0 | 0 | 0 | ~0 | **wire −1–3%，send −N+1** | ~0 | ~0 | 中（fate-sharing） |
| 每 flow 优先级/加权调度 | 0 | 0 | 0 | 0 | 0 | 0 | **p99 −30–80%（同类竞争时）** | p99 −20–50%（有损+竞争） | 中（调度器与 CC 交互） |
| 单 flow 多连接 striping | 不建议（TCP 重排） | 同 W1 | **+30–80%（单大流、受限时）** | **0**（多流已分摊） | +0–20%（单 flow 受限时） | ~0 | 0 | +20–50%（多路径冗余） | 高（归并/重排/准入） |
| FEC / NACK | −5–10%（若开） | 同 W1 | 0/负 | 0 | 0 | 0 | 到达率 + | **残损率 −10–100×，+5–30% 带宽** | 高（与 CC 冲突） |
| server per-class transport | 0–1% | 0–1% | ACK CPU −1–2% | 同 W3 | ~0 | ~0 | ~0 | 同 W3 | 中（需分端口/ALPN） |
| 0-RTT / 连接复用 | 重连 −1 RTT | 同 W1 | 同 W1 | 同 | 同 | 同 | 同 | 同（已实现） | 低（auth 强制 1-RTT） |
| ECN | 已开 | 已开 | 已开（Linux） | 同 | 同 | 同 | 同 | 同 | 无杠杆 |

**排序建议（收益/风险/工作量）**：

- **P0（不改 wire，先做）**：① `initial_mtu` 部署值 1360/1400（1420 B 业务用 1472）；② 窗口按
  部署设 8/16/8（或至少 8 MB stream 窗口）；③ F10：UDP relay 任务与 egress driver 同
  runtime（消跨核锁/wake）；④ server 侧统一 bulk 预设（当前不对称：1 MiB dgram + ACK thr 2）；
  ⑤ 加 §5.3 计数器。
- **P1（wire 变更，全双工本体）**：控制面（QUIC 流）+ per-direction flow 表 + 位图/可靠确认
  + server push + item 级 priority bit；`udpbidir` 基准。
- **P2（看测量结果）**：跨 session 帧复用；每连接加权调度器；单 assoc striping（若 W3 确认
  是目标场景）；FEC 可选协商。
- **不做**：payload 压缩（加密/随机数据无效，CPU 与延迟不划算）；用 QUIC STREAM 承载 UDP
  （改变语义）；跨 session 聚合作为「带宽」卖点；多连接 striping 作为默认行为。

### 4.11 负面清单（明确不要做的）

1. 不要为了「全双工」把 7 连接合并成 1 条——quinn 0.11 没有 stream 优先级，丢隔离的代价
   远大于省下的内存/握手。
2. 不要把 `gso` 配置当开关——它无效；GSO/GRO 由平台+quinn-udp 决定。
3. 不要指望 PMTU 自动升级——饱和连接可能永远停在 `initial_mtu`。
4. 不要用 `send_datagram`（drop-oldest）替换 `send_datagram_wait`（drop-newest）——丢包计数
   语义会静默改变（`udp/send.rs:43-95`）。
5. 不要给短 flow（DNS 1 请求 1 回复）做 per-flow 显式 ACK——控制开销大于压缩收益。
6. 不要在 QUIC DATAGRAM 上默认开 FEC——它在干净链路上是净亏，且与 quinn CC 冲突。
7. 不要假设 macOS 数字能代表 Linux：本 quinn-udp 版本 macOS 无 GSO/GRO，server 默认单 shard。

---

## 5. 测量计划与 benchmark 矩阵

### 5.1 现有证据（可直接引用，但都不足以支撑结论）

| 证据 | 内容 | 局限 |
|---|---|---|
| `README.md:859-866` | 301 tests 通过；真实二进制 TCP 1 MiB 校验、UDP 8–8000 B sweep 0 丢、sharded ingress/`SHARD_RUNTIME=0` 都验证；MQP-3 release smoke（macOS loopback）：`udp`/`udpdomain` 1000/1000、`udpmulti` 4×500、`udppaced` 1k–5k pps 0 loss、`udpps` 2 s 10803/10803、`lat` p50≈0.98 ms | **全部 macOS loopback**；README 自己标注 Linux 2–4 核数字仍是 deployment gate |
| `examples/hotpath_bench.rs:1228-1241` | macOS 基线（2026-09-30）：`udpraw` 73k pps、`udp` batch=64 26.8k pps、`udpps` 5 s/128 B offered 96.5k→goodput 2.6k pps（96.9% loss）、60 s → 370 pps | macOS 无 GSO + 单 shard，不代表 Linux；且是「blasting」而非稳态 |
| `examples/frame_bench.rs:17-25` | 每帧分配成本：128 B 15–19 ns / 1200 B 25 ns（同线程）；池化更差（+39–324%） | 只测 MQP 编码，不含 quinn |
| `PROTOCOL_ANALYSIS.md` | MQP-2→MQP-3 的字节/调用模型（与本文 §2 一致量级） | 模型，未在 Linux 上验证 |
| `PERF_ANALYSIS.md` | F1–F14 代码逻辑热点（多数已修）；F10 跨 runtime 未测 | 基线 `d73809f`，早于 v0.2.0 |

**没有任何 Linux 2–4 核的 pps/CPU/RTT 数据** → 本次 refactor 的收益论证必须先补这一层。

### 5.2 macOS loopback 能测什么、不能测什么

| 能力 | macOS 本机 | Linux 2–4 核（必须） |
|---|---|---|
| 功能/正确性（帧解码、fanout、重连、碎片重组） | ✅ 可测 | ✅ |
| 每帧 MQP 编码成本、分配成本 | ✅（frame_bench） | ✅ |
| 单连接 p50 延迟（无 netem） | ✅ 但 RTT≈0，只能看软件路径 | ✅ |
| GSO/GRO 摊销、每次 sendmsg 多包 | ❌ **本 quinn-udp 版本 macOS 无 GSO/GRO，每包 1 syscall** | ✅（GSO 64→quinn 10 段、GRO 64） |
| 多核扩展（server shard × N） | ❌ 默认 1 endpoint/1 shard | ✅（`quic_endpoints` 1/2/4） |
| 跨 runtime/跨核 send 竞争 | ❌ `pin_to_core` 空操作、核多但无隔离意义 | ✅（`MYQUIC2_SHARD_RUNTIME=0/1` A/B） |
| ECN 生效 | ❌ 双栈 `IP_RECVTOS` 不支持 → 自动关 | ✅（tcpdump 看 TOS） |
| BDP/CC/窗口效应 | ❌ loopback RTT≈0 | ✅ netem delay 70/140 ms |
| 丢包/乱序 | ⚠️ 可用 dummynet/pfctl，但与 Linux tc 不可比 | ✅ `tc qdisc netem` |
| 真实网卡/中断/softirq | ❌ | ✅ |

### 5.3 要加的计数器（分层，采样开销可控）

**A. 从 quinn `Connection::stats()` 直接拿（`connection.rs:554`，注意取 stats 要拿 state 锁 →
低频采样，建议 1–10 s 一次，或只在本项目 60 s reporter 里取）：**

| 计数器 | 公式/用途 |
|---|---|
| `udp_tx.datagrams` / `udp_tx.bytes` / `udp_tx.ios` | `bytes/payload` = wire 效率；`ios/datagrams` = GSO 摊销（Linux 应 ≪1） |
| `udp_rx.*` 同理 | 接收侧 |
| `frame_tx.datagram` / `frame_tx.acks` / `frame_tx.stream` | `datagram/udp_tx.datagrams` = 每包 DATAGRAM 帧数（合包率）；`acks/datagram` = ACK 比例 |
| `path.rtt` / `path.min_rtt` / `path.cwnd` | CC/队列健康度 |
| `path.current_mtu` / `sent_plpmtud_probes` / `black_holes_detected` | **验证 PMTU 是否真的升级**（关键！） |
| `path.lost_packets` / `lost_bytes` / `congestion_events` | 区分「网络丢包」与「接收端缓冲丢包」 |

**B. 应用层新计数器（thread-local 批处理，延续现有风格）：**

| 计数器 | 位置 | 用途 |
|---|---|---|
| `send_calls`、`send_blocked`、`send_too_large`（按连接/class/方向） | `src/udp/send.rs::try_send_datagram` 三个返回点 | 每次调用的真实成本 × 调用数；验证 TRAIN/聚合收益 |
| `payloads_per_frame`（TRAIN items 分布）+ `train_bytes` | 编码处（client `assoc.rs`、server `reader.rs`） | 打包效率（当前无观测） |
| `staging_copies` / `frame_alloc` | 编码入口 | 验证「每 payload 拷贝次数」假设 |
| `datagram_send_buffer_space` 高水位 | 采样 `conn.datagram_send_buffer_space()`（`connection.rs:512-519`） | 发送队列是否被打满（drop 前兆） |
| `recv_queue_drops`（quinn 接收缓冲溢出） | 现有 `dgram_drops` + 新增 | **P6 静默丢包的可观测化**：quinn 丢最老时不通知应用，只能靠 `frame_rx.datagram` 与应用计数差 |
| `relay_send_wouldblock` / `sendmmsg` 批大小 | 已有 metrics histograms（`udp/batch.rs`） | 最后一跳瓶颈 |
| `direction_payload_bytes`（up/down 分开统计） | 现有 `udp_stats::payload` 加方向维度 | **全双工 D6 验证** |

**C. 系统层：**

- `perf stat -p <pid>`：cycles/instruction、context-switches、syscalls、page-faults（Linux）；
  macOS `sample`/`spindump` 只能粗看。
- `strace -c -f`：sendmsg/recvmsg 次数（验证 GSO/GRO 是否真的生效）。
- `tcpdump -i <if> -v udp port 8443`：包数/字节/TOS（ECN）/burst；pcap 后处理算 wire/payload。
- `/proc/<pid>/stat` + `/proc/<pid>/status`：CPU、RSS；qdisc `tc -s qdisc show dev lo` 看队列。

### 5.4 benchmark 矩阵（Linux 2–4 核目标机；每个 cell 3 次取中位）

前置：`build --release`；server/client 同机（loopback 或 veth）；先 `tc qdisc del` 清空；
需要 RTT 的用 `tc qdisc add dev lo root netem delay 70ms`（或 140 ms）；丢包用
`loss 0.5%`/`2%`；记录 `taskset`、`quic_endpoints`、`MYQUIC2_SHARD_RUNTIME`、
`initial_mtu`、窗口配置。

| # | 命令（`examples/hotpath_bench`） | 配置 | 指标 | 验收/止损 |
|---|---|---|---|---|
| M0 | `frame_bench` | — | ns/帧 | 校准基线；改动不得劣化 >5% |
| M1 | `udp <socks> <echo> 20000 64` | 默认 | recv_pps、loss | 功能回归；loss=0 |
| M2 | `udpmulti <socks> <echo> 1/4/16/64 5000 64` | 1–4 核 | recv_pps、每流公平性 | 多 assoc 扩展线性度 |
| M3 | `udppaced <socks> <echo> 30 128 <pps>`，pps=1k/5k/10k/20k/50k | MTU 1200 vs 1400；ACK thr 2 vs 8 | goodput、loss、CPU/pps | 找到 0-loss knee；新协议 knee 提升 ≥15% |
| M4 | `udpps <socks> <echo> 10 128` | 同上 | offered/goodput/loss | 记录崩溃点，不作为验收（flood 本身非目标） |
| M5 | `udp <socks> <echo> 20000 1` payload 1000/1200/1420 | MTU 1200/1360/1400/1472（两端） | recv_pps、wire bytes（tcpdump） | 验证表 E：1200→1360 wire −6.6%、调用 −50%；`stats().path.current_mtu` 必须 == 配置值 |
| M6 | `udpdomain <socks> <echo> 1000 64`；`udpdomainmulti 8 domains 4 assocs` | 默认 | recv_pps、loss | 域目标路径不劣化 |
| M7 | `udpmulti` 200 assocs × 500，60 B | 1/2/4 bulk shard | 总 pps、wire/payload | 跨 session 聚合 A/B（聚合前 vs 后） |
| M8 | `lat <socks> <echo> 500 60` | netem 70ms；0/0.5/2% loss | p50/p90/p99/p999 | 全双工/优先级改动的延迟验收 |
| M9 | **新增 `udpbidir`**：同时下行生成 + 上行 echo（或双 echo 对称） | 2–4 核；20k/50k pps；netem | 每方向 goodput、p99、loss | D6：双向合计 ≥1.6× 单向；p99 劣化 ≤10%；无静默丢包 |
| M10 | `bulk <socks> <server> 256 1`（下行）；上行版（`server` 变体或加 `bulku`） | 窗口 4/8/4 vs 8/16/8 | MB/s、wire bytes、CPU | 验证 240→300 Mb/s |
| M11 | `lattcp <socks> <techo> 200 1024` | netem 0/70/140 ms | CONNECT p50、首字节 p50 | TCP 路径回归 |
| M12 | A/B：`MYQUIC2_SHARD_RUNTIME=0` vs 1；`quic_endpoints` 1/2/4 | 2 核/4 核 | pps、CPU、延迟 | 验证同线程化/分片收益；若 0 更好则回退拓扑 |
| M13 | 长稳：`udppaced` 20k pps × 300 s；`udpmulti` 64 assocs × 10 min | 默认 | RSS、drop counters、`cwnd/rtt/current_mtu` 漂移 | 无内存增长、无 counter 异常 |
| M14 | 抓包：`tcpdump -w` 同时跑 M5/M7 | — | wire/payload、DATAGRAM frames/packet、ACK 比例、TOS | 校验模型（表 A–E） |
| M15 | `perf record -g -p <server/client>` M5/M9 | — | 热点（quinn/rustls/relay/tokio） | 确认下一步优化方向 |

**A/B 方法**：同一二进制跑「配置 A vs B」；「旧 HEAD vs refactor」跑两个 tag（wire 不兼容，
需成对替换 server/client）；每组 3×60 s，先 10 s warmup，取中位与 min；CPU 用 `perf stat` 的
task-clock 归一化（pps/CPU-second 比绝对 pps 稳）。macOS 只跑 M1/M5/M8 做功能回归。

### 5.5 建议先做的 3 个 pilot（1–2 天内可完成，直接决定 refactor 方向）

1. **MTU pilot**（M5 + tcpdump + `stats().path.current_mtu`）：确认 1200→1360 在 Linux 上的
   真实 wire/pps/CPU 收益；顺便验证 PMTU 是否真的不升。
2. **同线程 pilot**（M12 + M3）：比较 `MYQUIC2_SHARD_RUNTIME=0/1` 与「relay 任务迁移」
   （F10）的 pps/CPU/尾延迟；这决定架构改动优先级。
3. **单流 ceiling pilot**（M5 payload 1420、单 assoc 饱和 + 2 shard striping 原型）：
   确认 W3 是否真的被单 cwnd 限制；这决定是否值得做 bonding。

---

## 6. 风险与开放问题（给 Lead 决策用）

### 6.1 风险

1. **PMTU 假设错误**：把 `initial_mtu` 默认抬到 1400/1472 在真实路径 MTU 更小的部署上会触发
   black-hole 回退（一次丢包风暴，quinn 会降回 1200）；必须由部署配置确认或做启动探测。
2. **wire 变更的兼容性**：用户允许 wire 不兼容，但 README 的「matched deployment」意味着两端
   必须同时升级；`alpn="h3"` 默认无版本门禁（`src/mqp/ack.rs:3-13`）。refactor 应显式加
   ALPN/控制面版本协商，避免灰度期事故。
3. **控制面复杂度**：flow 生命周期 + 优先级 + 信用 + 多路径叠加容易引入状态 bug；建议先做
   「per-direction flow 表 + 位图 ACK + server push」，优先级/信用/FEC 分阶段。
4. **短 flow 摊销**：DNS 型流量占比高时，显式 flow 控制可能比 inline 更差；必须按 N 帧阈值
   自适应，并在 `udpdomain` 基准里验证。
5. **测量环境**：macOS 开发机 + 共享工作区无法给出可信 pps；所有性能结论必须在安静 Linux
   目标机上复测；本文所有百分比都是方向性模型。
6. **内存/准入**：opt-in 8/16/8 窗口把每连接 14.25→26.25 MiB，4096 连接从 ~57 GiB 到 ~105 GiB；
   若 server 是小内存路由器，窗口不能盲目放大（这属于配置而非协议问题，但要写进部署建议）。

### 6.2 开放问题

1. **目标 workload 权重**：单大流（VPN）vs 多小流扇出 vs 混合，哪个是优化目标？决定 bonding
   与跨 session 聚合是否在 scope。
2. **「全双工」是否只针对 UDP 数据面**？（TCP 路径（QUIC STREAM）本来就是全双工。）
3. **部署路径 MTU** 是否已知（WireGuard-1420 / PPPoE 1492 / 1500）？决定 `initial_mtu` 默认值。
4. **目标硬件**：2–4 核 ARM 路由器还是 x86 exit node？决定 server endpoint 数/线程拓扑建议。
5. **wire 不兼容窗口**：是否可以同时升级两端、无灰度共存需求？（影响是否必须做 CAPS/版本协商）
6. **是否接受控制面用 QUIC 流**（一条 bidi/uni 流）而不是 DATAGRAM？这是实现复杂度差异最大的
   一个决定（见 §4.9）。

---

## 附录 A：计算口径

- IPv4 固定开销/包 = 20(IP) + 8(UDP) + 27(QUIC: 1 flags + 8 DCID + 2 PN + 16 AEAD tag) = **55 B**；
  再加 DATAGRAM 帧头 3 B（1 kind + 2B varint len，payload ≥64 B）= **58 B**。
  IPv6 为 +20 B。
- `max_datagram_size = current_mtu − 29(QUIC 上界) − 9(Datagram::SIZE_BOUND) = MTU − 38`。
  `current_mtu` 是「最大 UDP payload」：IPv4 wire = MTU + 28。
- MQP-3 头：SINGLE flow0 = 5 B；extra flow = 6 B；inline v4 = +7 B、v6 = +19 B；
  TRAIN 头 6 B；item = 1 flags + 1–2 B LEB128 len +（可选 1 B flow）（可选 inline addr）；
  FRAG prefix = 11 B + addr；MQP-2 datagram prefix = 5 B + addr。
- 分片 chunk = `max_datagram_size − FRAG_PREFIX_LEN(11) − addr_len(7/19)`；
  MTU 1200 的 v4 chunk = 1162−11−7 = **1144 B**（`src/mqp/fragment.rs:211-216`）。
- 吞吐 = window / RTT；BDP = rate × RTT；BBR 初始 cwnd = 200×1200 B = 234 KiB；min cwnd = 4×MTU。
- 本文百分比均由 `python3` 按上述公式计算；workload 收益区间为模型/估算，非实测。

## 附录 B：主要引用清单

**仓库**：`Cargo.toml:20-47`、`Cargo.lock:1293-1338`；`src/transport/build.rs:130-281`；
`src/transport/limits.rs:1-102`；`src/config/tuning.rs:104-236,282-415`；
`src/config/server_conf.rs:20-34`；`src/config/client_conf.rs:15-30`；
`src/bin/myquic2-client/main.rs:88-107,150-300`；`src/bin/myquic2-client/pool.rs:429-460,806-813`；
`src/bin/myquic2-client/assoc.rs:180-430,960-1010`；`src/bin/myquic2-client/dispatcher.rs:700-870`；
`src/bin/myquic2-server/main.rs:125-170,328-556,566+`；`src/bin/myquic2-server/reader.rs:79-330,1132`；
`src/udp/send.rs:84-212`；`src/mqp/v3.rs:25-60,286-360`；`src/mqp/fragment.rs:29-75,211-216`；
`src/linux.rs:79-120,184-198`；`examples/frame_bench.rs:17-25`；`examples/hotpath_bench.rs:1-120,1228-1241`；
`PERF_ANALYSIS.md:326-343`；`PROTOCOL_ANALYSIS.md:79-184`；`README.md:147-190,590-745,755-790,859-866`；
`config-server.toml:15-17`；`config-client.toml:6-8`。

**quinn / quinn-proto / quinn-udp（registry）**：
`quinn-0.11.12/src/connection.rs:256-287,446-520,846-890,1020-1023,1221-1225,1334-1341,554`；
`quinn-proto-0.11.19/src/connection/mod.rs:463-770,950,3350-3408,3763-3787,1006,1563-1600`；
`quinn-proto-0.11.19/src/connection/datagrams.rs:31-65,86-108,125-155,212-227`；
`quinn-proto-0.11.19/src/connection/paths.rs:73,122`；`.../connection/mtud.rs:69-350,355-430`；
`quinn-proto-0.11.19/src/config/transport.rs:157-158,370-400,698-755`；
`quinn-proto-0.11.19/src/connection/stats.rs:136-176`；
`quinn-udp-0.5.16/src/unix.rs:119-140,189,237-252,433-581,614-632,719-799,806-855,978-996`；
`quinn-0.11.12/src/endpoint.rs:742-850`；`quinn-proto-0.11.19/src/endpoint.rs:148-260`。

---

## 给 Lead 的摘要（≤30 行）

1. QUIC 已全双工（两方向独立 PN/CC/丢包/RTT/PTO）；「全双工」缺的是 MQP-3 状态对称性+控制面。
2. 配置：quinn 0.11.12/proto 0.11.19/udp 0.5.16；BBR(初始 cwnd 234 KiB)；DGRAM 1/2 MiB；
   窗口 4/8/4 MiB；initial_mtu 1200；ACK thr 2/5ms、bulk 8/10ms；keepalive 5s/idle 15s；
   ECN 默认开(Linux)；server 只有 interactive 预设→bulk 不对称；gso 配置无效(仅日志)。
3. GSO/GRO 仅 Linux(10 段/sendmsg、GRO 64)；macOS 本 quinn-udp 无 GSO/GRO、每包 1 syscall，
   server 默认 1 shard → macOS 数字不可外推。
4. send_datagram 无竞争 ~50–150 ns，但 driver 整轮 poll 持锁(10–20 包加密+syscall)，跨线程
   可阻塞 5–25 µs(Linux)/30–80 µs(macOS)→ 生产者与 driver 同线程是 pps 最便宜优化。
5. quinn 已自动合包(小包 17–18 帧/包)→跨 session 聚合仅 wire 1–3%+send 调用；TRAIN 相对
   「已合包的单帧」小包 wire −8%/send −18×（已实现）；bulk 无收益，1 payload=1 send 由 MTU 决定。
6. MTU 1200→1360：1200B payload 2 分片→1 帧（wire −6.6%、调用 −50%）；1420B 需 1472；
   PMTU 只在队列排空时探测，饱和连接可能永停 1200——最高性价比的配置杠杆。
7. 全双工 gap：flow 表 client 单方拥有、server 不能 push→纯上行/入站小包多 4–18%(v6 更甚)；
   无 CTL 控制面(ACK/close/caps/优先级/接收反馈)；一 TRAIN 一方向一 session；512B+ 走 MQP-2 分片。
   传输侧真耦合仅：同 driver 任务/state 锁/核、反向 ACK(0.6–2.9%)、同方向共享 cwnd。
8. 推荐定义 D1–D6：数据面对称 / 每 session 每方向一张 flow 表(发送方分配) / 控制面双向(建议
   QUIC 流) / 无方向依赖(纯上行也压缩) / 每方向独立调度 / `udpbidir` 可验收；≠两方向各 100% 带宽。
9. 杠杆排序：配置(MTU/窗口)>同线程化/每连接聚合发送>控制面+per-dir flow(4–18% 小包)>
   server per-class transport>单流 striping(仅单大流 +30–80%，高风险)>FEC/NACK(默认不做)>跨 session 聚合。
10. 诚实判断：bulk 吞吐的协议 wire 重写 ≤1–3%；10–30% 来自 MTU/窗口/分片消除/同线程化；
    单 flow 天花板只能多连接/多路径。全双工是能力/公平/延迟项，不是吞吐倍增器。
11. 测量：必须 Linux 2–4 核+tc netem(70/140ms、0/0.5/2% loss)；补 quinn stats(cwnd/rtt/
    current_mtu/ios)+send_calls/payloads_per_frame/方向字节；新增 udpbidir；矩阵 §5.4 M0–M15。
12. P0：initial_mtu 按部署设 1400(1420B 业务 1472)、窗口按 BDP、F10 同线程化、server bulk 预设
    统一、加计数器；先跑 3 pilot(MTU/同线程/单流上限)再定 P1/P2。开放问题见 §6.2（workload、
    是否仅 UDP、部署 MTU、目标硬件、灰度窗口、控制面用 QUIC 流可否）。
