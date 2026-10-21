# 02 · 上行数据路径（client → server）深度分析

> **范围与基线**：仓库 `/Users/eric/WorkSpace/MyQUIC2`，HEAD `d2f9658` / `v0.2.0`。本报告只读分析，**未修改** `src/`、`Cargo.toml`、配置与 README，未运行 `cargo build/test`；数值计算用 `python3`（模型脚本逻辑在 §6.1 给出，并与本目录 `model.py` / `model-output.txt` 的候选 A 做交叉核对）。
> **"上行"定义**：client → server，包括 SOCKS5 UDP ASSOCIATE 的 DATAGRAM 和 SOCKS5 CONNECT 的 TCP 流字节。
> **外部依赖**：quinn 0.11.12 / quinn-proto 0.11.19 / quinn-udp 0.5.16（`Cargo.lock` 锁定），引用其 crate 源码时标注 `quinn-0.11.12/src/...`，均从 `~/.cargo/registry` 只读获取。
> **口径提醒**：仓库内 `PROTOCOL_ANALYSIS.md`（基线 `348c52d`）的 §5 上行表以"客户端 2-pack、无 TRAIN"为前提，**对 HEAD 已过期**；`05-evidence.md` 已把该结论列为"必须视为过期"。本报告 §6 用当前 TRAIN 代码重算，并单独列出与旧表的差异。

---

## 0. 结论速览

1. **TRAIN/N-pack 的大头收益已经落地**：一个 association 在饱和时的 60 B 小包上行已经是 ~65.6–65.9 B wire/payload、55.6 次 `try_send_datagram`/1000 payload（`assoc.rs:704-714,930-1017`）。旧分析基于 2-pack 的"−10.8%~−20.5% / 9~19× calls"在 HEAD 上**不成立**，不要重复计账。
2. **上行剩下的协议级空间集中在三处**：① 域名目标与纯上行低速率流的 inline 地址（要 `FLOW_ACK`/域名 ACK 才能压）；② `>512 B` 的 payload 仍走 MQP-2（v3 紧凑 FRAG 未接线）；③ 跨 association 的 burst 不能合帧（TRAIN 头带 `sess u32`，一帧一 session）。高带宽 bulk 与 TCP 的协议空间 ≈ 0。
3. **量化上限（候选 A：连接级 flow id + 控制面 + 跨会话 TRAIN + 紧凑 FRAG，IPv4/MTU1200）**：DNS-域名单查询 **−15.5% wire**；纯上行 100 B 单包 **−5.9%**（IPv6 −12.1%）；32 会话×60 B **wire −8.0% / send calls −93.8%**（纯上行 −18.0%）；8 目标扇出 −3.5%；VPN 1200 B 仅 **−2.0%**；TCP bulk **0%**。**协议改造不是 bulk 的答案**。
4. **最大的一次性上行杠杆其实是传输配置与实现拓扑，不是 wire**：已知路径把 `initial_mtu` 从 1200 提到 1400（部署配置，非协议默认），VPN 1200 B 的 wire **−6.1%** 且帧数 2→1；客户端 relay 任务与 egress driver **分属两个 runtime/两组核**（`main.rs:49,210-263,379-388` vs `main.rs:508-582`），每帧一次跨核 state 锁 + driver wake（`05-evidence.md` §3 F10），模型 0.1–0.3 µs/帧 ⇒ 40–50k pps 约 **0.5–1.5% 单核**，且是尾延迟抖动来源；同时默认拓扑在 4 核机上会有 7 个 pinned slot 线程 + 主 runtime worker 的**过度订阅**（`main.rs:473-488`）。
5. **正确性/设计上的关键发现**：README 与旧分析说"纯上行 flow 永远 inline、每帧带地址"——**这句话按字面已不准确**。`open_mask`（`assoc.rs:378-381`）让同一 TRAIN 内同一 flow 只有第一项带 inline 地址，后续项压缩；纯上行的真实代价是"**每个 TRAIN 一次 inline open**"，低速率（1 包/burst）才退化为每帧带地址。这直接改变了 `FLOW_ACK` 的收益排序（§4.2、§6.3）。
6. **`thread::spawn per fragment` 假设不成立**：分片在 association 任务内同步逐片发出（`fragmenter.rs:349-380`，`assoc.rs:298-310`），没有 per-fragment 线程；上行方向唯一的 spawn 是每个 SOCKS 连接的任务（`main.rs:379-388`）。
7. **"zero-copy TCP" 只对了一半**：`write_chunk(Bytes)` 省掉 pump 缓冲→quinn 队列的那次拷贝（`tcp/pump.rs:310-322`），但 quinn 出包时仍 `put_slice` 拷贝进 packet buffer（`quinn-proto-0.11.19/src/connection/streams/state.rs:660-668`），再加上内核收发各一次，"0 拷贝"并不存在；TCP 上行协议层没有 headroom（§3）。

---

## 1. 口径、基线与建模假设

### 1.1 代码事实（本报告所有数字的前提）

| 事实 | 取值 | 证据 |
|---|---|---|
| QUIC DATAGRAM body 预算（`max_datagram_size()`） | MTU 1200 → **1162 B**；MTU 1400 → **1362 B**；MTU 1472 → 1434 B | `transport/build.rs:238-263`、`PROTOCOL_ANALYSIS.md:117-120`、quinn `Datagram::SIZE_BOUND`（body = MTU − predict_1rtt_overhead − 9） |
| IPv4 每 QUIC packet 固定开销 | IP 20 + UDP 8 + QUIC short header（flags 1 + DCID 8 + PN 2 + AEAD tag 16 = 27）= **55 B** | 任务给定口径；`PROTOCOL_ANALYSIS.md:117-118`；`src/transport/build.rs:175-198` |
| 每个 QUIC DATAGRAM frame 额外头 | type 1 B + varint(len) 1–2 B → body ≤63 B 时 **2 B**，否则 **3 B** | `quinn-proto-0.11.19/src/connection/datagrams.rs:204-219`（`datagram.encode`） |
| MQP-3 帧头 | SINGLE = `1+4+[1 flow]+[addr]`；TRAIN = `6 + 1 flow(same-flow)`；item = `1 flags+[1 flow]+varint(len)+[addr]`；FRAG = `11+[1 flow]+[addr]` | `src/mqp/v3.rs:63-66,143-149,261-267,542-567` |
| MQP-2 帧头 | 单帧 `5`=type+sess；FRAG `11`=type+sess+id+idx+total；地址另计 | `src/mqp/datagram.rs:9-11`、`src/mqp/fragment.rs:29` |
| 地址长度 | IPv4 7 B、IPv6 19 B、域名 `4+L` | `src/mqp/addr.rs:162-196` |
| 客户端默认拓扑 | TCP 槽 4 + UDP 槽（1 interactive + 2 bulk）= **7 个连接/endpoint/线程**；每槽独立 current-thread runtime（默认 `MYQUIC2_SHARD_RUNTIME` 开） | `src/config/tuning.rs:38,69`、`src/bin/myquic2-client/pool.rs:421-449,575-598`、`src/bin/myquic2-client/main.rs:210-263` |
| 上行 relay 任务所在 runtime | SOCKS accept / `handle_socks` / UDP association 都在 `#[tokio::main]` 多线程 runtime；quinn driver + dispatcher 在每槽 pinned current-thread runtime | `src/bin/myquic2-client/main.rs:49,379-388`、`main.rs:508-582` |
| 每帧 send 的 quinn 成本 | `send_datagram_wait` 每次 poll 取 connection-state 互斥锁 + `wake()` driver；非阻塞 poll（`now_or_never`），`Blocked` 即丢 | `src/udp/send.rs:24-95`、quinn-0.11.12 `connection.rs:476-481,846-888` |
| QUIC GSO | Linux 最多 64 segments/`sendmsg`；quinn 限制单次 transmit ≤10 segments、每驱动 poll ≤20 datagrams | quinn-udp-0.5.16 `unix.rs:820-860`；quinn-0.11.12 `connection.rs:1019-1075,1334,1341` |
| 多 DATAGRAM 合包 | quinn 在同一 transmit poll 内可把一个以上 DATAGRAM frame 填进同一 QUIC packet（预算内循环） | quinn-proto-0.11.19 `connection/mod.rs:3345-3355`（DATAGRAM 在 STREAM 之前填充） |
| 时钟 | `coarse_millis` ≈ quanta `recent()`（文档 ~4-5 ns；历史微基准 1.44 ns）；`mono_millis` ≈ 3.26 ns（历史微基准） | `src/time/coarse.rs:40-53`、`src/time/mono.rs:1-16`、`PERF_ANALYSIS.md:433` |
| 帧分配 | 每 MQP 帧一次 `Vec::with_capacity(exact)+Bytes::from`（exact-fit 快路径）；帧池化已实测否决 | `src/mqp/v3.rs:313,571,174`、`examples/frame_bench.rs:19-25`、`05-evidence.md` R1 |

### 1.2 建模假设（§4、§6 用）

- 只算 IPv4、无丢包、无 ACK-only 包、无 PMTU 抖动；MTU 1200（预算 1162）为主，MTU 1400（1362）单列。
- "wire B/payload"= 该 payload 摊到的全部线上字节（MQP 头 + 该 payload + QUIC DATAGRAM 帧头 + 该包分摊的 55 B）；一个 QUIC packet 装一个 MQP 帧，除非该帧本身就是 N 项的 TRAIN（或特别注明的"packed"合并情形）。
- "send calls/1000 payloads" = `try_send_datagram`（即 MQP 帧）次数 ×1000/1000；TCP 行是 `write_chunk` 次数。
- "现状"按 HEAD 代码的**实际行为**：≤512 B 进 v3；同一 drain burst 内 TRAIN 到 path budget 或 64 项；`n=1` 强制 SINGLE（`assoc.rs:959-971`）；纯上行 flow 同一 TRAIN 内靠 `open_mask` 压缩（`assoc.rs:378-381`）、跨 TRAIN 重新 inline；域名目标 `NO_FLOW` 每项带地址（`assoc.rs:354-366`）；>512 B 走 `DgramFragmenter`（MQP-2，`assoc.rs:301-310`、`fragmenter.rs:178-235`）。
- "候选 A"= 本目录 `01-wire` 正在评估的连接级 flow-id 重构：稳态 SINGLE = **2 B 头**（kind/flags 1 B + LEB128 flow id 1 B，flow id <128）；inline 开启帧 = kind 1 + flow 1 + sess u32 + addr；TRAIN = 2 B 头（同 flow 简单形式 item = varint(len)+payload；混合 flow item 再加 1 B flow id）；紧凑 FRAG = kind 1 + flow 1 + frag id 2 + packed idx/total 1 = **5 B 头**；控制面含 `FLOW_ACK`（域名目标额外带回解析 IP，供客户端写 SOCKS5 回包头/下行解压）。该口径与 `analysis/mqp3-refactor/model.py` 一致，本报告独立复算并补齐"低速率单包/每 burst 打包"两类形态。

---

## 2. UDP 上行端到端地图

### 2.1 代码路径

```text
app  ──UDP──▶ relay socket (每 association 一个, bind_relay)
             │  assoc.rs:583  recv_from().await  (awaited head, 1 syscall)
             │  assoc.rs:660  recv_burst()       (Linux recvmmsg, ≤32 条/次, batch.rs:528)
             ▼
        AppDgramCtx::process()  assoc.rs:176-459   ← 同步、无 await、不分配（域名除外）
             │  SOCKS5 UDP 头解析            assoc.rs:236-248
             │  app 源 IP/端口 pin + 1 Hz 活跃戳  assoc.rs:213-269
             │  event 时钟 coarse_millis()    assoc.rs:226
             │  egress memo / 1 s 刷新         assoc.rs:287-444 / egress.rs:139-240
             │  分类（interactive/bulk）+ 绑定 shard  pool.rs:642-664
             ▼
        PendingTrain 暂存 (≤512B)            assoc.rs:313-400
             │  flow 分配 / 确认位 / open_mask   assoc.rs:345-396, 850-856
             │  payload → pending_buf (memcpy)   assoc.rs:386
             ▼
        burst 末尾 flush                     assoc.rs:704-714
             │  n==1 → SINGLE；n≥2 → TRAIN     assoc.rs:944-1017
             │  encode_single/encode_train     v3.rs:151-198,285-347
             │  1 次精确分配 + 1 次 memcpy/payload + MQP 头
             ▼
        try_send_datagram()                  send.rs:84-95
             │  quinn state mutex + queue push + driver wake   (1 次/帧)
             │  Blocked/TooLarge 立即丢（不回退排队）
             ▼
        quinn driver (每槽 current-thread runtime)
             │  1 次 frame→packet 拷贝、1 次 AEAD、GSO 打包
             │  sendmsg(syscall) 每 ≤10 个 packet
             ▼
        UDP socket → server
```

### 2.2 每 payload / 每 frame 成本账（当前最优情形：IP flow 已确认、60 B、burst→18 项 TRAIN）

**每 payload（18 项 TRAIN，payload 60 B，IPv4，MTU1200）**

| 资源 | 数量 | 证据/说明 |
|---|---|---|
| relay 收包 syscall | **~0.06 次**（2 syscalls/32 条 burst：1 次 head `recv_from` + 1 次 `recvmmsg`） | `assoc.rs:583,660`、`batch.rs:528-546` |
| 内核→用户拷贝 | 1 × 60 B | recvmmsg 写入线程本地 `BURST_SLOT` |
| 用户态拷贝（payload） | **2 × 60 B**：staging `arena→pending_buf`（`assoc.rs:386`）+ `pending_buf→MQP 帧`（`v3.rs:343`）；quinn 出包再 1 × 60 B（见 per-frame） |  |
| 分配 | 0 堆分配（`pending_buf` 复用；`PendingTrain` 是 assoc future 内的 inline 结构，无堆分配，但每帧重建，见 §2.4） | `assoc.rs:578-580` |
| 原子操作 | coarse 时钟 1 load；`flow_confirmed` 1 relaxed load；egress generation 1 acquire load；stats 线程本地 cell（跨线程 RMW 每 256 条一次） | `assoc.rs:226,368`、`egress.rs:145`、`udp_stats.rs:93-120` |
| 线性扫描 | `FlowTable::flow_for` 1 次比较（单 flow 命中 slot 0）；扇出 8 平均 ~4 次、32 平均 ~16 次。上行**没有 hash 表**：egress memo 是数组下标，flow 解析是线性扫描（下行 hub/flow 查找才有 hash） | `v3.rs:722-728`、`egress.rs:139-165` |
| 任务唤醒 | 0（同一 burst 内同步处理）；burst 结束 1 次 relay 任务唤醒已摊薄 | `assoc.rs:632-703` |
| 统计 | 线程本地计数，无共享写 | `udp_stats.rs:93-120` |

**每 frame（18 payload 的 TRAIN，body 1122 B，wire 1180 B）**

| 资源 | 数量 | 说明 |
|---|---|---|
| 堆分配 | **1 次**（`Vec::with_capacity(1122)` → `Bytes::from`） | `v3.rs:313-346` |
| quinn connection-state 互斥锁 | **1 次** | `send.rs:84-95`；quinn SendDatagram::poll |
| driver 唤醒 | 1 次（当前拓扑是**跨核 wake**，见 §5） | 同上 |
| MQP 头 | 6 B TRAIN + 18×2 B item = 42 B | `v3.rs:314-343` |
| QUIC DATAGRAM frame 头 | 3 B | body >63 |
| packetize 拷贝 | 1122 B（frame body → quinn packet buffer） | quinn-proto `mod.rs:3345-3355` 后的 `datagram.encode` |
| AEAD | 1 个 packet（~1122 B） | aws-lc-rs（`Cargo.toml`） |
| `sendmsg` | 1 次（GSO 本可带 ≤10 packet，但此 burst 只有 1 个 packet） | quinn-udp `unix.rs:820-860` |
| 线上字节 | 1122 + 3 + 55 = **1180 B / 18 payload = 65.6 B/payload**（payload 效率 91.5%） |  |

> **换算**：稳态高 pps 单 flow 的 1000 payload ≈ **55.6 帧 / 55.6 次 quinn send / 55.6 次 `sendmsg` / 62.5 次 relay 收包 syscall**。这正是 HEAD 已经拿到的 TRAIN 收益。

### 2.3 其它三种上行形态的成本

| 形态 | 每 payload 关键成本 | 每 frame 关键成本 | 证据 |
|---|---|---|---|
| **域名目标（NO_FLOW inline，50 B 查询、L=11）** | 额外 **1 次 String 分配+释放**（`open_addr: addr.into_owned()`，`assoc.rs:393`；`TargetAddrRef::into_owned` 对 Domain 是 `to_owned()`，`addr.rs:115-120`）；MQP 头 21 B（SINGLE）或 item 18 B（TRAIN） | 1 分配 + 1 锁 + 1 wake，与普通帧相同 |  |
| **纯上行低速率（1 包/burst）** | 每个 payload 都是 1 个 SINGLE 帧：帧成本不摊薄；IP flow 的 inline open 每次重发地址（7/19 B） | 1000 帧/1000 payload → 1000 次分配+锁+wake+`sendmsg` | `assoc.rs:959-971` |
| **>512 B（MQP-2 路径，1200 B payload、MTU1200）** | 2 片：每片 1 次分配 + 1 次 encode 拷贝 + 1 次 quinn 锁/wake；每片头 18 B（FRAG 11 + IPv4 7） | **2 帧/ payload**，每帧各自独立 packet（总 wire 1352 B，见 §6 表） | `assoc.rs:301-310`、`fragmenter.rs:178-235,349-380`、`fragment.rs:29` |
| **>512 B 但能单帧（MTU1400/1362 预算）** | MQP-2 单帧 12 B 头（`5+7`），1 次分配/锁/wake | 1 帧/payload | 同上 |

### 2.4 实现层的四个"白付"成本（细节见 §8）

1. **域名每 payload 一次 `String` 分配**：`assoc.rs:393`；对本该 allocation-free 的 UDP staging 是唯一例外（注释 `assoc.rs:794-800` 说"Metadata only"，与 NO_FLOW 路径不符）。
2. **`PendingTrain::new` 每帧重建 64 个 `PendingItem`**（每个含 `Option<TargetAddr>`，约 56 B → **~3.5 KiB 零初始化 + 64 个 Option 的 drop** 每帧）：`assoc.rs:813-821`、`assoc.rs:384`。
3. **预算预检偏保守**：`worst_item` 无条件加 `header.len()`（`assoc.rs:323-332`），对已确认 flow 多算 7/19 B；60 B payload 时帧内项数从 18 降到 **16**（-11% 项/帧，即 +12.5% send calls）。实际编码 `encode_train` 会再精确算一次，所以只是浪费合帧率。
4. **`pending_buf` 初始容量只按 `BATCH_SMALL_MAX*2 = 1024 B`**（`assoc.rs:578`），装不下 1162/1362 B 的满帧，第一次满帧会 realloc 一次（之后保留容量）。

---

## 3. TCP 上行地图

### 3.1 建连与首包

- SOCKS CONNECT 后 `open_bi()`，把目标地址头（7/19/4+L B，最大 259 B 栈缓冲）作为**独立 stream write** 先写并 flush（`socks.rs:204-233`），目的是让"服务器先说话"的协议在 ~100 ms 内看到 header，而客户端**不等**服务器 dial ACK 就先回 SOCKS success（`socks.rs:234-252`）。
- 服务器真正的 dial ACK（MQP-2 `MQ|0x00|atyp|addr|port`，`ack.rs:26-49`）只在 `s2c` 方向被消费（`pump.rs:353-366`、`lib.rs:670-699`），**上行字节流不受 ACK 门控**——这是刻意省 1 RTT 的设计。
- 上行侧每 TCP flow 的协议开销：**一次地址头（7–259 B）**，之后纯 STREAM 帧，无 MQP 层每 payload 头。这是 TCP 与 UDP 的根本不同：**TCP 上行的协议头空间已经是理论最优**。

### 3.2 pump 的每 chunk 成本（16 KiB 读、`write_chunk` 路径）

| 资源 | 每 16 KiB chunk | 证据 |
|---|---|---|
| TCP read syscall | ~1（Tokio readiness + `read_buf`） | `pump.rs:288-305` |
| 内核→用户拷贝 | 16 KiB | 同上 |
| 用户态拷贝 | **1 次**（quinn 出包 `put_slice`）；`write_chunk` 把 `Bytes` move 进 quinn send queue，**该边界 0 拷贝** | `pump.rs:310-322`；quinn-proto `streams/state.rs:660-668` |
| 分配 | 稳态接近 0：双 16 KiB 缓冲在线程池轮换（`COPY_BUF_POOL_DEPTH=4`），`split_to().freeze()` 只产生 `Bytes` 句柄；ACK 及时释放时不需要重新分配 | `pump.rs:106-147,288-322`；`Cargo.toml` 注释 |
| quinn state 锁 + driver wake | **1 次/chunk**（跨核，见 §5；`write_chunk` 每次都要锁） | `pump.rs:315` |
| 流控等待 | 只在该 stream/connection send window（默认 4 MiB，`tuning.rs`）耗尽时 await；正常 bulk 上传会被 cwnd 限制但不会每 chunk park | `pump.rs:310-322` |
| 出包 | ~13 个 packet/16 KiB（MTU1400），每 packet 1 次 55 B 固定开销 + ~5 B STREAM 帧头 + AEAD | `PROTOCOL_ANALYSIS.md` 口径；quinn-proto STREAM 编码 |
| `sendmsg` | ~1.3 次/16 KiB（GSO ≤10 segments/次；driver 每 poll ≤20 datagrams） | quinn-0.11.12 `connection.rs:1019-1075`；quinn-udp `unix.rs:820-860` |
| ACK | 无应用层每 chunk 成本（driver 处理） |  |

### 3.3 "zero-copy" 的真实含义 & 上行协议 headroom

- `write_chunk(Bytes)` 只省掉 **pump 缓冲 → quinn 发送队列**这一次拷贝；quinn 出包仍拷贝 1 次；内核收发各 1 次。因此每个 16 KiB 上行 chunk 的拷贝量约为 **3×16 KiB**（内核收 + quinn 出包 + 内核发），`write_all` 小包路径是 4×。
- 每 16 KiB chunk 的线上开销：MTU1200 时 15 packet × 55 B + 15 × ~5 B ≈ **+5.6%**；MTU1400 时 13 packet ≈ **+4.8%**；MTU1472 时 12 packet ≈ **+4.5%**。其中 STREAM 帧头占 ~0.5%，**协议层能改的只有这 0.5% 里的一小部分，且收益 ≪ 1%**。
- 结论：**TCP 上行没有值得动 wire 的协议 headroom**；吞吐上限由 cwnd/窗口/MTU/CPU（pump 任务在主 runtime）决定。要提升只有传输配置（`initial_mtu`、8/16/8 MB 预设）与实现拓扑（pump 任务与 driver 同核、更大读块减少锁次数），见 §8。

---

## 4. MQP-3 上行缺口（逐条 + 证据 + 影响）

### 4.1 没有 FLOW_ACK：纯上行/低速率 flow 无法进入压缩态

- 现状：客户端只有在**成功 staged 一个该 flow 的压缩下行帧**后才 `confirm_flow`（`dispatcher.rs:284-288,324-326`，`hub.rs:55-57,139-149`）。服务端只有在其 flow 表里已有映射时才会发压缩下行（`reader.rs:137-154`），而映射来自上行的 inline open（`accept.rs:662-667,712-717,731-757`）。纯上行 flow 永远收不到这个证明。
- **修正旧结论**：同一 TRAIN 内，`open_mask`（`assoc.rs:378-381`、`PendingTrain::push` `assoc.rs:823-832`）使同一 flow 只有第一项 inline；服务端按 wire 顺序逐项处理并即时安装映射（`accept.rs:598-601,669-719`、`install_v3_flow` `accept.rs:731-757`），所以**一帧内"第一项开、后续项压"是安全的**（同一 DATAGRAM 原子到达）。因此"每帧带地址"只在 **1 payload/burst** 时成立；高速同 flow burst 的 inline 代价被摊薄到 7 B/**TRAIN**。
- 影响（IPv4，MTU1200）：
  - 低速率纯上行 100 B 单包：header 12 B vs 压缩 5 B → wire **170→163（−4.1%）**；IPv6 24→5 B → **182→163（−10.4%）**。
  - 高速单 flow 60 B TRAIN（18 项）：每个 TRAIN 省 7 B → 每 payload **−0.39 B（−0.6%）**。
  - 若同时把会话头缩到 2 B（候选 A）：低速率 170→160（−5.9%）；高速 65.9→64.2（−2.7%，其中大部分来自 2 B 头和 same-flow item 省 1 B/项，而非 ACK）。
  - 代价：每新 flow 1 个 `FLOW_ACK`（可并入服务端本来就要发的 ACK packet；纯上行时若没有 ACK 可搭则多 1 个小 DATAGRAM，~60 B/flow），且 **ACK 只能加速压缩、绝不能承载正确性**：丢失只是继续 inline，不能黑洞。

### 4.2 域名目标永远 `NO_FLOW` inline，下行也压不了

- 客户端：域名目标固定 `(MQP3_NO_FLOW, want_open=true)`（`assoc.rs:354-366`），每项带 `4+L` B 地址 + flow byte（`v3.rs:320-343`），并用 `open_addr` 持有 owned `TargetAddr`。
- 下行：客户端 flow 表里域名项是 `TargetAddr::Domain`，不是合法 SOCKS5 reply 源；dispatcher 对压缩下行只接受 `TargetAddr::Ip`（`dispatcher.rs:255-267,300-308`）。服务端 reader 用 `flow_for_ip` 找 flow（`reader.rs:137-154`），域名映射永远匹配不上，于是域名回包也 inline。
- 服务端其实已经安装域名映射（`accept.rs:745-755`），缺的是"解析后的 IP ↔ flow id"这一层。
- 影响：DNS-域名查询（L=11、50 B、1 包/burst）当前 wire **129 B**，压缩后（候选 A 2 B 头）**109 B（−15.5%）**；同 burst 双查询（A+AAAA）**100→82 B/payload（−18.0%）**。注意：这不是老文档的"33–38%"——那个数字是"tunnel payload + MQP 头"口径；按完整 IPv4 wire（含 55 B packet 开销）是 15.5%（L=11）/ 22.7%（L=20、40 B 查询）量级。
- 设计前提（必须一起解决）：① 服务端在域名解析/首包转发成功后，用 `FLOW_ACK` 带回 `(flow, resolved_ip)`；② 客户端把该 flow 的"上行目标=域名"与"下行源 IP=resolved_ip"并存（否则后续域名 payload 找不到 flow id）；③ 回复源端口变化时仍走现有 `S`（src override）inline 路径；④ 安全：客户端只把 ACK 里的 IP 用于 SOCKS5 回包头，授权仍由服务端 reply filter 决定，不改变 SSRF/allowlist 语义。

### 4.3 >512 B 离开 v3：MQP-2 单帧/FRAG 仍在生产路径

- 触发点：`payload.len() > BATCH_SMALL_MAX`（512）先 flush 掉 pending TRAIN，再 `frag.send`（`assoc.rs:298-310`；常量 `mqp/batch.rs:9`）。
- v3 `FRAG` 编解码器存在（`v3.rs:542-671`）但**未接线**：客户端/服务端收到 `MQP3_FRAG` 都直接计数丢弃（`dispatcher.rs:330-336`、`accept.rs:720-724`）；生产用 MQP-2 `DgramFragmenter`（`fragmenter.rs:178-394`），每片头 `11+addr`（IPv4 18 B）、重新分配/加锁/发一帧。
- 影响：1200 B payload、MTU1200 时 2 片、每片 18 B 头 → wire 1352 B；候选 A 紧凑 FRAG（5 B/片）→ 1325 B（**−2.0%**）。MTU1400 下 MQP-2 单帧（12 B 头）1270 vs 候选 A 单帧（2 B 头）1260（**−0.8%**）。**收益有限，价值在于统一路径/消除双协议面，而非 bulk 提速**。注意保留 32-bit fragment id（历史 u16 丢包悬崖实测，`05-evidence.md` R6）。

### 4.4 TRAIN 是 per-session：不同 association 的 burst 永远不合帧

- `encode_train(sess u32, ...)`（`v3.rs:285,314-316`）与每 association 一个 `PendingTrain`（`assoc.rs:578-580`）决定了**一帧只能属于一个 sess**。
- 不同 sess 的帧在同一 QUIC packet 里**可以**被 quinn 合包（`quinn-proto mod.rs:3345-3355`；quinn 在同一 transmit poll 内把多个 DATAGRAM frame 填入一个 packet），所以"55 B packet 开销"在饱和时已被摊薄；但**每帧的精确分配 + quinn state 锁 + 跨核 driver wake 仍然逐帧付**（`sendmsg` 与 packet 开销按 packet 摊薄，不逐帧）。
- 影响（32 会话 × 60 B，每会话 1 包/burst，聚合 50k pps）：现状已确认 flow 71.4 B/payload、纯上行 80.2 B/payload、**send calls 1000/1000 payloads**；跨会话 TRAIN（候选 A：2 B 头 + 每项 1 B flow id）→ 65.8 B/payload、**62.5 calls/1000（−93.8%）**，wire −8.0%/−18.0%，模型 CPU **−1.2~1.6% 单核**。这是本报告唯一一个"协议能大幅减少 send 调用"的工作负载；但 `05-evidence.md` R8 明确警告：**没有 profiling 证明 quinn send-state 锁/跨核 wake 是主瓶颈前，不要为跨会话重构**（模型收益 1–2% 量级，复杂度高）。

### 4.5 64-flow / 64-item 上限、NO_FLOW 回退、id 不复用

- `MQP3_MAX_FLOWS=64`、`MQP3_MAX_TRAIN_ITEMS=64`（`v3.rs:56,60`）；decoder 拒绝 >64（`v3.rs:449-451`），encoder 拒绝空/>64（`v3.rs:286-288`）。
- flow id 单调分配、**永不复活**（`v3.rs:679-690,737-746`）；表满回退 `NO_FLOW=0xFF` inline（`assoc.rs:367-376`）；wire 上 0x40..=0xFE 被 `valid_flow` 判非法（`v3.rs:85-90`），即 u8 的绝大部分 id 空间不可用。
- 长期存活的 association 若目标端口漂移/大扇出超过 64 个不同 `(ip,port)`/域名，会永久掉进 NO_FLOW inline（每 payload +7/19 B），且**无法淘汰旧 flow**（无 FLOW_CLOSE，且复用在当前语义下不安全）。这是控制面缺口的实际后果。内存侧 admission 每 session 记 4 KiB（`v3.rs:48-51`、`config/tuning.rs:309-317`），扩表需同步改预算。

### 4.6 预算检查与 Blocked/drop 策略

- 预算用 `limit = conn.max_datagram_size()`（live，`assoc.rs:298`），staging 用保守 `worst_item`（§2.4-3）；真正编码时 `encode_train` 精确算（`v3.rs:289-312`）。
- quinn 侧是非阻塞单次 poll（`send.rs:84-95`）：`Blocked` = 该帧被丢弃（QUIC DATAGRAM 语义），**不回退到重试队列**；只有下行回复路径有 detached retry（`retry.rs:208-236`）。TRAIN 的 `Blocked`/`TooLarge` 会逐项回退成 SINGLE/fragment（`assoc.rs:999-1016,893-921`），`ConnectionLost` 不回退（整帧报告一次失败），每次回退各自计数。
- 计数与日志有速率限制（`stats/warn.rs:1-80`、`assoc.rs:402-444`），不会在 drop 风暴里把日志变成瓶颈。
- 设计判断：上行"满了就丢"是合理的 UDP 语义；但要减少这种丢包，靠的是**减少每 payload 的帧数/发送量**（TRAIN/跨会话）而不是重试。

### 4.7 其它缺口

- **控制面完全缺失**：`MQP3_CTL=0x40` 只有常量、`is_v3` 识别（`v3.rs:25,73`），没有 opcode/编解码；dispatcher 对未知 kind 静默 `_ => {}`（`dispatcher.rs:337`）；README 明确"CTL reserved，无 CAPS/HELLO/FLOW_ACK opcode"（`README.md:606-609`）。
- **无 v3 观测计数**：没有 frame 类型/payload 数/inline 回退率/train 项数/ACK 数的统计（`stats/udp_stats.rs` 无 v3 字段），这会让任何"压缩率/回退率"验证只能靠抓包（`05-evidence.md` §3 已列为缺失项）。做协议改造前应先补计数。
- **没有 server-initiated flow / 无 SESS_CLOSE/FLOW_CLOSE**：UDP association 关闭后服务端 session 靠 180 s idle 回收（`server/table.rs` `SESS_IDLE_MS`，见 `05-evidence.md` §3），短会话 churn 会占着 socket/task/64 KiB 内核缓冲；这不是稳态 wire 问题，但影响容量与尾延迟。

---

## 5. 客户端拓扑与全双工干扰

### 5.1 拓扑（默认：4 TCP + 1 interactive UDP + 2 bulk UDP = 7 个 QUIC 连接）

| 槽 | 连接/任务 | 所在 OS 线程/runtime | 说明/证据 |
|---|---|---|---|
| TCP 0 | interactive 端口（DNS/STUN 等 pin） | 每槽独立 `current-thread` runtime（Linux 下 `pin_to_core`，macOS no-op） | `main.rs:210-263,473-488,508-582`；`linux.rs:184-196` |
| TCP 1–3 | bulk TCP 轮转 | 同上 | `pool.rs:270-323,712-784` |
| UDP 0 | interactive 类的**唯一**连接（所有 ≤512 B 首包/交互端口 association 共享） | 同上 | `pool.rs:588-598`（`Interactive => 0..1`） |
| UDP 1–2 | bulk 类的 2 个 shard（每 association 绑一个） | 同上；bulk 传输 preset（ACK 8/10 ms、2 MB DATAGRAM 缓冲） | `pool.rs:596-597,806-813`；`transport/build.rs:138-163` |
| 所有 SOCKS 任务 / UDP association relay / TCP pump | `handle_socks` + 双向 copy | **`#[tokio::main]` 多线程 runtime**（默认 worker=核数，未 pin） | `main.rs:49,379-388`；`assoc.rs:5-10`；`pump.rs:229-575` |
| 每槽 dispatcher（下行） | `read_datagram` + 4096 项 cache | 槽 runtime（与 driver 同线程） | `dispatcher.rs:725-871` |
| 每槽 conn loop / watchdog | 重连/静默检测 | 槽 runtime | `auth.rs:46+` |

### 5.2 上行/下行在哪里互相干扰

| 干扰点 | 机制 | 方向/影响 | 证据 |
|---|---|---|---|
| **connection-state 互斥锁 + 跨核 wake** | 上行 send 来自主 runtime worker；driver（收包/ACK/出包）在 pinned 槽线程。每次 `try_send_datagram` 锁同一 `ConnectionInner.state` 并 `wake()` 槽线程；该锁的 partner 是每收一个包都要拿锁的 driver | 双向：下行越重，上行 send 越容易抢锁/排队；上行 burst 又拖慢下行 ACK/收包延迟 | `send.rs:24-95`；quinn-0.11.12 `connection.rs:476-481,846-888`；`PERF_ANALYSIS.md` F10（状态：未修，`05-evidence.md` §3） |
| **单 driver 串行化两个方向** | 每次 poll 先收包/处理，再最多 20 个 datagrams 出包；收发共用这条线程 | 一个方向的饱和会推迟另一个方向的处理/ACK | quinn-0.11.12 `connection.rs:1019-1075,1334,1341` |
| **DATAGRAM 发送缓冲共享 + 丢最新** | 每个连接 1 MB（interactive）/2 MB（bulk）缓冲，所有 association 共享；满时丢最新包，无 per-flow 公平 | interactive 类所有小包 flow 抢一个缓冲/cwnd/驱动；一个 chatty flow 或 burst 可让其他 flow 丢包 | `transport/limits.rs:76-88`；`udp/send.rs:24-95`；`pool.rs:376-398` |
| **cwnd 共享** | UDP 与 TCP 已拆连接（`udp_split`），但同类内共享：interactive 只 1 条连接；bulk 2 条 shard 内共享。TCP 侧 3 个 bulk 槽轮转，但同槽多 stream 共享一个 cwnd | 同类多 flow 互相挤压；跨类不互挤（这是现有隔离的价值，别丢） | `pool.rs:421-449`；`transport/limits.rs:76-82` |
| **主 runtime CPU 竞争** | 所有 relay/encode/copy 在主 runtime；槽线程已 pin（Linux），主 worker 未 pin；默认 7 槽线程 + 核数个主 worker | 4 核机：11 个可运行线程抢 4 核；上行 relay 与下行 copy 互相抢 CPU，表现为吞吐抖动/尾延迟 | `main.rs:49,210-263,473-488`；`PERF_ANALYSIS.md` F3（未修） |
| **dispatcher 与 driver 同线程** | 下行爆量时 dispatcher 的 `sendmmsg`（≤32 帧/批）占住槽线程，driver 不能跑 | 上行 enqueue 的 wake 要等该线程；上行延迟抖动 | `dispatcher.rs:770-849`；`batch.rs:655-740` |
| **interactive 不 shard** | 所有 interactive association 一条连接一个 driver 核 | 多核客户端的小包上行 pps 上限≈单核 driver/AEAD 能力；与 wire 无关 | `pool.rs:588-598` |
| **无 DATAGRAM 优先级** | quinn 0.11 无 DATAGRAM TX 优先级；`set_priority` 只作用于 STREAM（`socks.rs:168-169`）；DATAGRAM 在 `populate_packet` 里排在 STREAM 前 | 若 UDP 与 TCP 共享连接（`udp_split=false` 或 fail-open 回退），UDP 会饿死 TCP stream；现在的拆连接是对策 | quinn-proto `mod.rs:3345-3355,3406`；`pool.rs:431-439` |

### 5.3 什么阻止一条连接"真正对称全双工"

1. **控制面把 flow 状态做成客户端单向拥有、下行镜像**：客户端开 flow，服务端从 inline open 学习；下行压缩依赖该学习结果。没有"服务端主动开 flow/确认 flow"的对称原语。
2. **纯上行 flow 没有显式确认**（§4.1），所以"双向都压缩"只在有下行回复的 flow 上成立；全双工压缩态不是协议不变量，而是副作用。
3. **一个 TRAIN 只能一个方向、一个 session**：上行 burst 与下行 reply 永远在两个 frame、两个方向，无法共享帧或 ack（除了 QUIC 层 packet/ACK）。
4. **每连接一个 driver 线程 + 一把 state 锁**：两个方向的 CPU 和锁在同一个串行点上；这属于 quinn 架构约束，只能靠多连接/多槽/任务同核缓解，不能靠 wire 改掉。
5. **无 per-flow TX 调度/优先级**：quinn 的 DATAGRAM 是先进先出共享缓冲，丢最新；协议里没有可被发送端消费的优先级字段。
6. **客户端 CPU 拓扑**：relay 任务与 driver 跨 runtime、跨核，上行方向天然比下行多一次跨核交接（§5.2 第一行）。

### 5.4 假设核验

- **`thread::spawn per fragment`：不存在。** 分片在 `DgramFragmenter::send` 的循环里同步逐片 `send_encoded`（`fragmenter.rs:349-380`），由 association 任务调用（`assoc.rs:298-310`）。**上行 payload 路径上没有 spawn**；客户端全流程的 spawn 只有：每 SOCKS 连接一次的任务（`main.rs:379-388`）、下行域名解析任务（`dispatcher.rs:587-604`）、以及每槽固定的 conn-loop/dispatcher（`main.rs:563-574,725-871`）。
- **runtime 订阅**：每槽一条 `watch` generation 通道（`pool.rs:20-54`），TCP flow 在 `wait_conn` 后持有连接句柄到 flow 结束，不参与该通道；UDP 走 `SharedEgress` 的 generation + 1 s memo（`egress.rs:139-240`）。reconnect 对上行的影响是：UDP 下一包重新 acquire（两次 quinn 锁，1 s 窗口内最多一次），TCP flow 直接失败（RST）；不构成持续干扰。

---

## 6. 上行 headroom 量化

### 6.1 模型（可复算）

```python
OVH=55; B=1162; B14=1362
dqh(body)=2 if body<=63 else 3            # QUIC DATAGRAM frame header
single(flow,addr,p)=1+4+(flow!=0)+addr+p  # current v3
item(flow,addr,p)=1+(flow!=0)+varint(p)+addr+p
train(items, header=6)=header+sum(item(...))                        # current
A_single(p)=2+p                                                     # candidate A 稳态
A_train_simple(n,p)=2+n*(varint(p)+p)                               # 同 flow 压缩项
A_train_flow(ps)=2+sum(1+varint(p)+p for p in ps)                   # 混合 flow，1 B flow id/项
A_frag(chunks)=sum(5+c for c in chunks)                             # 紧凑 FRAG
wire(body)=body+dqh(body)+OVH
```

（完整脚本逻辑与 §6.2 数字一致；`analysis/mqp3-refactor/model.py` 的候选 A 行与本报告候选 A 列交叉核对一致，差异只在"低速率按单包独立建 packet、TRAIN 按帧内项数摊薄"的处理。）

### 6.2 主表：上行 headroom（IPv4，无丢包；MTU1200/预算 1162，除非注明）

| 工作负载（每 burst 形态） | 现状 wire B/payload | 现状 send calls/1000 | 目标 A wire B/payload | 目标 A calls/1000 | Δwire | Δcalls | 备注 |
|---|---:|---:|---:|---:|---:|---:|---|
| DNS-over-SOCKS，域名 L=11，50 B，1 查询/burst | **129** | 1000 | **109** | 1000 | **−15.5%** | 0 | 收益 100% 来自"域名 ACK+压缩"（16 B 地址/flow 字节 + 3 B sess + 1 B DQH）；仅换 2 B 头但无 ACK 则为 0 |
| 同上，A+AAAA 两查询同 burst（TRAIN 2 项） | 100 | 500 | 82 | 500 | **−18.0%** | 0 | 每项 18→2 B 头 |
| 游戏/WebRTC 100 B，IP，纯上行，1 包/burst | **170** | 1000 | **160** | 1000 | **−5.9%** | 0 | 7 B inline 地址×每包；IPv6 182→160（−12.1%） |
| 游戏/WebRTC 100 B，IP，双向已确认 | 163 | 1000 | 160 | 1000 | −1.8% | 0 | flow 已压缩（5 B→2 B 头）；协议几乎没空间 |
| 游戏/WebRTC 60 B，IP，高速单 flow（TRAIN 18 项/帧） | **65.9** | 55.6 | **64.2** | 52.6 | **−2.7%** | −5.4% | 主要是 2 B 帧头 + same-flow 省 1 B/项 + 首项 inline 消除；**TRAIN 大头已落地** |
| 8 目标扇出，200 B，纯上行，1 包/flow/burst | **226** | 250 | **218** | 250 | **−3.5%** | 0 | 每 flow 首项 inline（7 B）；flow 已确认时现状 220，目标 218 |
| 32 会话 ×60 B/连接，已确认 flow，1 包/session/burst | 71.4（quinn 合包后） | **1000** | 65.8 | **62.5** | **−8.0%** | **−93.8%** | 合包是 quinn 现有行为；协议收益在帧/项头与 send 次数 |
| 同上，纯上行 flow | 80.2 | 1000 | 65.8 | 62.5 | **−18.0%** | **−93.8%** |  |
| VPN/bulk UDP 1200 B，MTU1200（预算 1162，2 片） | **1352** | 2000 | **1325** | 2000 | **−2.0%** | 0 | 紧凑 FRAG 5 B vs MQP-2 18 B/片；帧数不变 |
| VPN/bulk UDP 1200 B，MTU1400（预算 1362，1 帧） | 1270 | 1000 | 1260 | 1000 | −0.8% | 0 |  |
| TCP bulk，16 KiB chunk，MTU1200 / 1400 | 17299 / 17177 | 1000 | 同左 | 同左 | **0** | 0 | 协议无 headroom；MTU 1400 是传输配置（−0.7% wire、15→13 packet） |

> **多会话行的口径**：现状 71.4 / 80.2 B/payload 是"quinn 把同一 transmit poll 内 32 个 DATAGRAM frame 合进 2 个 QUIC packet"的最佳情况（§1.1 合包事实）；若驱动逐帧 poll（低速率、时序分散），现状会退化为每帧独占一个 packet 的 123 / 130 B/payload。目标 A 的 65.8 假设连接级 stager 能稳定把 32 项装进 2 帧。因此该行的绝对百分比依赖时序，不能当稳定收益。

> **保守增量 S（保留 sess u32、per-session TRAIN）参考**：DNS 单查询 129→112（−13.2%）；纯上行 100 B 170→163（−4.1%）；高速 60 B 65.9→65.6（−0.5%）；多会话 71.4→70.0（−2.0%，calls 同为 62.5 需跨会话能力）；VPN 1352→1337（−1.1%）。即"不做连接级 id 命名空间、只加 FLOW_ACK + 全尺寸 v3 + 跨会话 TRAIN"也能拿到大部分 wire 收益，但多会话 wire/CPU 收益会明显缩水。

### 6.3 收益归因（避免把实现收益记到协议头上）

| 改动 | 主要受益工作负载 | wire 贡献（单包 50-60 B 量级） | send-call/CPU 贡献 |
|---|---|---|---|
| `FLOW_ACK`/`FLOW_REJECT`（含域名 resolved IP） | 域名目标、纯上行低速率 | 域名 L=11：−20 B/查询；纯上行 IPv4：−7 B、IPv6：−19 B | 0（帧数不变；只是让压缩态可达） |
| 稳态头缩到 2 B（连接级 flow id，候选 A） | 所有低速率单包 | −3 B/帧（5→2）；**若无 ACK，对 pure-uplink 反而 +1 B**（inline open 形态 6+addr vs 当前 5+addr） | 0 |
| 紧凑 FRAG + v3 全尺寸 | VPN/大包 UDP | −13 B/片（IPv4）/-25 B/片（IPv6） | 0（片数不变） |
| 跨会话 TRAIN（连接级 stager） | 多 association 小包 | 32×60 B：−5.6~−14.4 B/payload | **−94% send calls（模型 −1.2~1.6% 单核 @50k pps）** |
| same-flow TRAIN 形式/每项 1 B len | 同 flow 高速 | −1 B/项（60 B 的二十分之一量级） | 0 |
| 控制面 SESS_CLOSE/FLOW_CLOSE | 短会话 churn | 0 | 资源回收，不是吞吐 |

关键点：**除"跨会话 TRAIN"外，协议改造都不减少每 1000 payload 的 send 调用**。HEAD 的 TRAIN 已经把同 association 的调用数从 1000 降到 55.6/1000（高 pps 小包）。所以"协议能提升 pps 上限/CPU"的说法只对多 association 场景成立，且量级 1–2% 单核，不是数量级。

### 6.4 wire / CPU 换算（按工作负载速率假设）

| 负载假设 | 现状 wire | 目标 A wire | 节省 | 附注 |
|---|---:|---:|---:|---|
| DNS 域名 20k qps（50 B 查询） | 2.58 MB/s | 2.18 MB/s | **−0.38 MB/s（−3.1 Mbps）** | 纯协议（域名 ACK） |
| 游戏纯上行 50k pps ×100 B | 8.50 MB/s | 8.00 MB/s | −0.50 MB/s（−4 Mbps） | 协议 |
| 32 会话 ×60 B，50k pps 聚合，已确认 | 3.57 MB/s | 3.29 MB/s | −0.28 MB/s | 协议 wire + **−46.9k frames/s** |
| 同上纯上行 | 4.01 MB/s | 3.29 MB/s | −0.72 MB/s |  |
| 8 目标扇出 20k pps ×200 B | 4.52 MB/s | 4.36 MB/s | −0.16 MB/s | 协议 |
| VPN 1200 B，5k pps | 6.76 MB/s | 6.63 MB/s | −0.13 MB/s | 协议 |
| VPN 1200 B，5k pps，**仅把 initial_mtu 1200→1400** | 6.76 MB/s | 6.35 MB/s | **−0.41 MB/s（−6.1%）** | **传输配置，非协议**；帧数 2→1 |
| TCP bulk 240 Mb/s（30 MB/s），MTU 1200→1400 | 31.7 MB/s | 31.45 MB/s | −0.22 MB/s | 传输配置（−0.7% wire、packet 15→13） |

CPU（模型，按 frames/1000 换算；单帧成本取 **250–350 ns**：`Vec+Bytes` 分配 30–80 ns + quinn 锁/wake/入队 200–300 ns，来自本仓库历史估算口径）：

| 场景 | 省下 frames/s | 模型 CPU（单核） | 证据等级 |
|---|---:|---:|---|
| 32 会话 ×60 B @50k pps（跨会话 TRAIN） | 46 875 | **1.2–1.6%** | 模型；未测量 |
| 高 pps 单 flow 60 B @100k pps（TRAIN 已实现） | 0（候选 A 每帧 18→19 项，约省 0.3k frames/s） | <0.01% | 模型 |
| 域名 ACK / 纯上行 ACK | 0（帧数不变） | ~0 |  |
| F10 跨 runtime 修复（impl，非协议） | 每帧 0.1–0.3 µs（估算） | **0.5–1.5%@40–50k pps** | 模型；待 Linux A/B |

### 6.5 headroom 结论

1. **按收益/风险比排序：域名 ACK（wire 15%+）≫ 纯上行/低速率 ACK（5~12% IPv4/IPv6）> 跨会话 TRAIN（CPU 1–2%、wire 8–18%，高复杂度）≈ MTU 部署配置（VPN −6.1%）> 紧凑 FRAG（−0.8~−2.0%）> 稳态头 2 B（−0.3~−3.3% 单包，取决于 payload）**。
2. 高速同 flow 小包的 wire 已经贴近下限（65.6 vs 候选 A 64.2，差 2.7%），再改协议最多 1–2%；**不要把"100k pps 小包"的期望建立在协议上**，它的上限在 CPU 拓扑（F10/F3）与 GSO/driver。
3. 对 bulk/TCP，"优化上行"的正确动作是传输配置（`initial_mtu`、窗口）+ 实现拓扑；协议改造对它们 ≤1–2%，不应作为重构理由。

---

## 7. 协议改造建议（上行视角，按收益/风险排序）

> 前提：用户允许 wire 不兼容、名称仍叫 MQP-3。下面区分"协议改动"与"实现改动"；所有收益均为 §6 模型值，未经 Linux 实测；与 `05-evidence.md` 的 do-not-repeat 清单冲突时以该清单为准。

### P0 — `FLOW_ACK`/`FLOW_REJECT`（含域名 resolved IP）：上行最值得做的协议改动

- **内容**：`CTL(0x40)` + opcode（`FLOW_ACK|sess|flow|[atyp|addr|port]`、`FLOW_REJECT|sess|flow|reason`）；服务端在 inline open 被接受（目标 socket 已建/已 send）后发送；域名目标在解析成功且首包转发后把 `resolved_ip` 放进 ACK；客户端 `dispatcher` 处理 CTL：IP flow 调 `confirm_flow`（复用 `hub.rs:139-149`），域名 flow 额外把 resolved IP 记为"该 flow 的下行源地址别名"（与既有 `TargetAddr::Domain` 并存）。ACK 必须幂等、可重复、丢失不致命（继续 inline），可并入服务端本来要发的 ACK 包（省一个 DATAGRAM）。
- **收益**：DNS-域名单查询 **−15.5%**、双查询 −18.0%；纯上行低速率 IPv4 **−4.1%**、IPv6 −10.4%；配合候选 A 的 2 B 头为 −5.9%/−12.1%；高速单 flow 仅 −0.6%（第一项 inline 消除）。
- **风险**：**中低**。新增 1 个控制帧类型 + 服务端发射点 + 客户端状态位；若 ACK 丢失/被伪造：丢失只延迟压缩（安全方向），伪造只能提前压缩（需要客户端确认"ACK 的 flow 确实与本地表项一致"）；服务端不需要为 ACK 建新状态；域名别名要限定"只用于 SOCKS5 回包头 + 下行解压，不参与授权"。`05-evidence.md` R14 要求评估控制帧丢失/黑洞/状态机成本——上面"永远可回退 inline"的约束就是对该风险的正面回答。
- **前置**：补 v3 计数（ACK 数、compress 率、inline 回退率），否则无法验收。

### P1 — v3 全尺寸 + 紧凑 FRAG 接线（去掉生产路径上的 MQP-2）

- **内容**：取消 `payload > 512 B` 时回退 MQP-2（`assoc.rs:301-310`），让 v3 SINGLE 承载所有能装进一帧的 payload，v3 紧凑 FRAG（`v3.rs:542-671`）接入重组器（key 改 `(sess, flow, id)`，保留 u32 id 与 2 s/256 KiB 语义），大包首帧仍 inline open、确认后压缩。
- **收益**：VPN 1200 B MTU1200 **−2.0%**（每片 18→5 B 头）、MTU1400 −0.8%；统一帧路径、消除 MQP-2 双解码面与 TRAIN 被大包打断的 flush；为"所有 payload 都能被 flow 压缩"打基础。
- **风险**：**中**。重组 key 迁移、partial 上限/淘汰、inline 首片与压缩后续片的顺序规则、乱序时首片未到先到压缩片的处理；8 KiB 上限可保持不变（可协商上限是独立议题，不是性能收益）。

### P2 — 跨会话 TRAIN / 连接级 stager（条件性，需 profiling 先证明）

- **内容**：新 frame kind（或 TRAIN 多 session 标志）：`2 B 头 + count + item(sess/flow id 1–2 B + len + payload)`；客户端需要 per-connection 的 stager（association 把待发项交给连接级队列/聚合器），服务端 per-connection 解复用。连接级 flow id（候选 A）能把 item 压到 1 B flow id；保守方案是 per-item `sess u16`（item +2 B）但仍能共享帧头/DQH/send。
- **收益**：32 会话×60 B：wire **−8.0%（已确认）/−18.0%（纯上行）**，send calls **−93.8%**，模型 CPU **1.2–1.6% 单核 @50k pps**；纯上行 packet 数 3→2。其它工作负载（单 association 饱和）**≈0**。
- **风险**：**高**。连接级 stager 引入跨任务同步（锁/队列）与"何时 flush"的延迟取舍（逐 association 的"burst 末立即 flush"不再直接可用，需要 ≤100 µs 级 deadline 或"最后一个写者 flush"），per-association 顺序必须保持；收益是 1–2% 单核量级，**若 Linux `perf` 不能证明 quinn send-state 锁/跨核 wake 是主瓶颈，不应做**（`05-evidence.md` R8 同结论）。建议先做 F10 的 A/B，再决定。

### P3 — 连接级 flow id 命名空间 / 2 B 稳态头（候选 A，长期）

- **内容**：flow id 由连接级命名空间分配（取代 per-session `sess+flow` 的 5/6 B 稳态头），OPEN 帧携带 `sess u32+addr` 建立映射；稳态 SINGLE 2 B、TRAIN 2 B、FRAG 5 B。
- **收益**：低速率单包/小包：−3 B/帧（60 B 单包 123→119，**−3.3%** wire；100 B 单包 163→160，−1.8%；DNS 在 P0 基础上再 −2.7%）；是 P2 item 压到 1 B 的前提；TRAIN 头 6→2 B（高速单 flow −0.3%）。
- **风险**：**高**。服务端需连接级 flow 表（内存/DoS/生命周期/鉴权）、session 生命周期与 flow 归属、id 复用与 splice 防护；admission 的 4 KiB/session 计费模型要重算；**且它单独不解决任何 inline/域名问题**——没有 P0 的 ACK，pure-uplink 反而 +1 B。建议作为 P0/P1/P2 之后的整体重构，而不是先做。

### P4 — 控制面生命周期（SESS_CLOSE/FLOW_CLOSE/CAPS）：非吞吐收益

- **内容**：幂等控制帧，显式释放 session/flow；CAPS/HELLO 仅用于灰度/回滚（`05-evidence.md` R4：不是性能特性）。
- **收益**：短会话 churn 的资源回收（服务端 socket + task + 64 KiB 内核缓冲）、flow 槽释放（缓解 64 上限）、CANARY/灰度能力；**不改变 B/payload 或稳态 CPU**。
- **风险**：中低（幂等 + 丢包不致命），但必须与 180 s idle 兜底共存。

### 明确不建议（uplink 视角）

- **优先级提示/ lane 字段**：quinn 0.11 不消费 DATAGRAM 优先级（`pool.rs:431-439` 已说明唯一隔离是独立连接）；加字段只会增加发送端分支，收益 0。
- **payload 压缩 / HPACK 式字典 / FEC / NACK 默认开启 / fragment train / u16 fragment id / 帧池化 / 改 MTU 默认值进协议**：均与 `05-evidence.md` §5 do-not-repeat 一致，不再展开。
- **为 bulk 吞吐重写协议**：1200 B 帧头占比 <1%，wire 上限 ≤1–2%（§6.2），不值得。

---

## 8. 实现层修复（单独记账，不冒充协议收益）

> 这一节全部是"不改 wire 也能拿"的收益；其中 F3/F10 需要 Linux 2–4 核实测，macOS 上 `pin_to_core` 是 no-op，本机测不出。

| # | 修复 | 证据 | 预期收益/风险 |
|---|---|---|---|
| I1 | **relay 任务与 egress driver 同核**（F10）：把 association relay / TCP pump 放到对应 slot 的 runtime（或反向：driver 所在的 pin 策略与主 runtime 分离） | `main.rs:49,210-263,379-388,508-582`；`05-evidence.md` §3 F10 未修 | 模型 0.1–0.3 µs/帧 → 40–50k pps 约 0.5–1.5% 单核 + 尾延迟；**先做 `MYQUIC2_SHARD_RUNTIME=0` A/B，不能盲改**（单 current-thread runtime 可能成为新瓶颈） |
| I2 | **线程拓扑/过度订阅**（F3）：默认 7 个槽线程（Linux pin）+ 主 runtime worker=核数；4 核机 11 线程。至少在小核机上按 `slots_total` 缩主 runtime worker 数，或 `slots_total >= cores` 时不 pin | `main.rs:473-488`；`linux.rs:184-196`；`PERF_ANALYSIS.md` F3 | 系统级吞吐/抖动；需 Linux 2/4 核基准；配置层可先降 `quic_conns`/`udp_egress_conns` |
| I3 | **interactive UDP 类允许 shard**（当前永远 1 条连接）：`udp_class_slots(Interactive)=0..1` 写死，`udp_bind` 对 Interactive 恒 0 | `pool.rs:588-598,613-635` | 多核客户端小包上行 pps 上限近似从"1 核 driver/AEAD"提升到 k 核；但 server 端每连接资源/调度也变多，需同时评估；风险中 |
| I4 | **域名 NO_FLOW 的每 payload String 分配**：`open_addr: addr.into_owned()` | `assoc.rs:393`；`addr.rs:115-120` | 20k qps 下 20k alloc/free/s，按 20–40 ns/次约 0.04–0.08% 单核 + allocator churn；改法：把地址字节追加进 `pending_buf`/独立 arena，flush 时 `from_utf8` 借出，或 `PendingItem` 内联短域名（≤23 B） |
| I5 | **`PendingTrain` 复用**，避免每帧重建 64 个 `PendingItem`（~3.5 KiB 零初始化 + 64 个 drop） | `assoc.rs:813-821,384` | 每帧 ~0.1 µs 级（3.5 KiB stores）；实现简单，风险低 |
| I6 | **预算预检用精确 item 长度**（已确认 flow 不再加 addr） | `assoc.rs:323-344` | 60 B payload 每帧 16→18 项（send calls −11%）；风险低（编码器仍会精确校验） |
| I7 | **`FlowTable::flow_for` 加 one-entry memo**（服务端 reader 已有 `last_flow`） | `v3.rs:722-728`；`server/reader.rs:117-144` | 扇出 32：每 payload ~16 次比较 → 1 次；~50–150 ns/payload，20k pps 约 0.1–0.3% 单核；风险低 |
| I8 | **`pending_buf` 预分配到 path budget（≥1434）** | `assoc.rs:578` | 每 association 一次 realloc；风险极低 |
| I9 | **clock 提到 burst 级**：`coarse_millis()` 现在每 datagram 一次 | `assoc.rs:226` | 1.4–5 ns/payload；风险低（memo/活跃戳只需 burst 级精度） |
| I10 | **TCP 首包 header 与第一段数据机会性合并**（仅当应用数据已 ready 时；保持"服务器先说话"协议仍单独 flush） | `socks.rs:204-233` | 每 TCP flow 省 ~1 个 packet（~80–130 B）；风险中（若应用等待服务器先说话，不能延迟 header） |
| I11 | **TCP 读块放大到 32/64 KiB**（减少 quinn `write_chunk` 锁次数/字节） | `pump.rs:66,288-322` | 240 Mb/s 下锁次数 4× 减少，模型 <0.1% 单核；风险低 |
| I12 | **`initial_mtu` 部署配置**：已知路径（WireGuard-1420/以太网）设 1360/1400（不改默认值） | `config/tuning.rs:160-198`、`config/client_conf.rs:66-80`、`transport/build.rs:238-263`；`05-evidence.md` R5 | VPN 1200 B **−6.1% wire、帧数 2→1**；TCP −0.7% wire、packet 15→13/16 KiB；这是上行单项收益最大的非协议杠杆 |
| I13 | **补 v3 观测计数**（frame type、inline 回退、train items、ACK/压缩率） | `stats/udp_stats.rs` 无 v3 字段；`05-evidence.md` §3 | 无直接收益，但是所有协议改造的验收前提 |

---

## 9. 测量与验收计划（与 `05-evidence.md` 的 harness 结论对齐）

1. **基线先测**：Linux 2–4 核目标机（非 macOS loopback），`hotpath_bench` 的 `udppaced`（1–512 B，可控 pps）、`udpps`（collapse 点）、`udpmulti`（多 association，唯一能暴露共享状态争用）、`udpdomain`/`udpdomainmulti`（域名）、`lat`（配 `tc qdisc netem delay 70ms loss 0.5%`）、`bulk`/`lattcp`（TCP）。同一轮内 A/B，不引用 README 历史 loopback 数字（`05-evidence.md` C11/C13）。
2. **必须补的计量**：wire bytes/send 调用数（strace -c 或临时计数器）、`myquic2_udp_send_syscalls`、QUIC DATAGRAM frames/packet（抓包）、CPU/pps、p50/p99、丢包分布；现有 harness 只打用户层 pps/loss，不能验证"更少帧/更少 wire"（`05-evidence.md` §4 已指出）。
3. **A/B 矩阵**：`MYQUIC2_SHARD_RUNTIME=0` vs 1（F10/F3）；`udp_split`/`udp_egress_conns`/`quic_conns` 组合（I3/I2）；`initial_mtu` 1200 vs 1400（I12）；`udp_fail_closed` 不变。
4. **协议验收**：P0 先做"ACK 计数 + 压缩率 + inline 回退率"；P1 做"FRAG 路径丢包/重组率"；P2 做"跨会话 stager 的 CPU + p99 延迟（flush deadline 不能引入 >1 ms 抖动）"。每项都必须有"现状 vs 改动"同机同轮数据，模型数字只能作为方向。

---

## 10. 开放问题（给 Lead 决策）

1. **目标函数排序**：是受限上行带宽（wire）、每核 pps/CPU、还是尾延迟？本报告显示三者导向不同：DNS/域名 → 域名 ACK；多 association → 跨会话 TRAIN/CPU 拓扑；bulk/TCP → 传输配置。若只允许做一件事，建议 P0（域名 ACK）。
2. **wire 不兼容的边界**：是否接受"连接级 flow id + 控制面"（候选 A）这种实质重写？如果只接受增量，P0+P1 是安全组合；P2/P3 需单独立项。
3. **`FLOW_ACK` 的可靠性模型**：允许"丢失只延迟压缩"吗？若要求"必须确认"则要重传/状态机，收益不变但复杂度上升；本报告建议前者。
4. **域名压缩的安全边界**：服务端返回 resolved IP 后，客户端把它写进 SOCKS5 回包头——需要确认这不改变 RFC1928 语义/应用行为（尤其多 A 记录、轮询、TTL 变化、DNS rebinding 场景）。
5. **interactive 单连接是否可改**：为什么 interactive 类"必须保持一条稳定连接"（`pool.rs` 注释）？每个 association 本来就绑定类/shard 终身，shard 化只改它骑哪条连接；若理由只是"简单"，I3 是低风险的多核扩展点。
6. **P2 前置验证**：是否有 Linux `perf`/`strace -c` 能证明 quinn send-state 锁 + 跨核 wake 是上行主瓶颈？没有的话，不建议为 1–2% 单核做连接级 stager（与 `05-evidence.md` R8 一致）。
7. **64 flow 上限的实际影响**：生产流量里是否存在 >64 目标/端口的长期 association（端口漂移、大扇出）？若有，FLOW_CLOSE/表扩容优先级需提前。
8. **v3 计数缺失**：是否把 I13 作为所有协议改动的前置 PR？否则无法证明"压缩率/回退率"，只能回到抓包。

---

## 给 Lead 的摘要（≤30 行）

1. 基线 HEAD d2f9658：TRAIN 已把同 association 小包上行从 1000 calls/1000 payload 降到 55.6（60 B/高速），60 B 已是 ~65.6–65.9 B wire/payload — 旧分析"2-pack −10~−20%"对 HEAD 过期，不要重复计账。
2. 上行剩余协议空间只有三块：域名目标/纯上行低速率的 inline 地址、>512 B 仍走 MQP-2、跨 association 不能合帧。bulk/TCP 协议 headroom ≈ 0。
3. 高收益排序：① FLOW_ACK（含域名 resolved IP）；② v3 全尺寸 + 紧凑 FRAG；③ 跨会话 TRAIN（条件性）；④ 连接级 flow id（候选 A）；⑤ 控制面生命周期。
4. FLOW_ACK 收益（模型，IPv4/MTU1200）：DNS-域名单查询 129→109 B（−15.5%），双查询 −18.0%；纯上行 100 B 170→160（−5.9%，IPv6 −12.1%）；高速单 flow 仅 −0.6%。
5. 修正旧结论：`open_mask` 使同一 TRAIN 内同一 flow 只首项 inline，纯上行代价是"每 TRAIN 一次 open"；只有 1 包/burst 才退化为每帧带地址（assoc.rs:378-381,823-832）。
6. 32 会话 ×60 B/连接（1 包/session/burst）：现状 71.4 B/payload、1000 calls/1000；候选 A 65.8 B、62.5 calls（wire −8.0%，CPU 模型 1.2–1.6% 单核 @50k pps）；纯上行现状 80.2 → −18%。
7. 8 目标扇出 200 B 纯上行 226→218（−3.5%）；VPN 1200 B 仅 1352→1325（−2.0% @MTU1200）或 1270→1260（−0.8% @1400）；TCP 0。
8. 单项最大既不是协议：`initial_mtu` 1200→1400（部署配置）使 VPN 1200 B wire −6.1%、帧数 2→1、TCP −0.7%/packet 15→13。
9. 实现层大头：relay 任务在主 runtime、driver/dispatcher 在 pinned 槽 runtime，每帧跨核 state 锁 + wake（F10 未修），模型 0.1–0.3 µs/帧 → 40–50k pps 0.5–1.5% 单核 + 抖动；默认 7 槽线程 + 主 worker 在 4 核机过度订阅（F3）。
10. interactive UDP 类只有 1 条连接（pool.rs:588-598），多核小包上行 pps 上限≈单核 driver/AEAD；是否允许 interactive shard 需要决策。
11. 无 FLOW_ACK/CTL/SESS_CLOSE，flow 表 64 项且 id 不复用：长寿命多目标 association 会永久掉 inline（每 payload +7/19 B），不能靠淘汰缓解。
12. 不建议：优先级 hint（quinn 不消费）、payload 压缩、FEC/NACK 默认、fragment train、u16 frag id、帧池化、改 MTU 默认值进协议、为 bulk 重写协议。
13. 建议落地顺序：先 I13 补 v3 计数 → P0 FLOW_ACK（wire 收益最大、风险低）→ P1 紧凑 FRAG/v3 全尺寸 → 同时做 F10/F3/MTU 的 Linux A/B → 由 profiling 决定 P2/P3。
14. 关键风险：FLOW_ACK 必须"丢失只延迟压缩、永不依赖其正确性"；域名 ACK 需要服务端建立 flow↔resolved IP 映射且不改变授权；跨会话 TRAIN 需要 per-association 顺序与 flush 延迟设计（≤100 µs 级）。
15. 开放问题：目标函数（带宽/pps/延迟）排序；是否接受连接级 id 重写；域名 resolved IP 写 SOCKS 回包的安全确认；interactive 是否可 shard；P2 是否有 Linux profiling 支撑；>64 flow 的真实流量画像；v3 计数是否作为前置 PR。
