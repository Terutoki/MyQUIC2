# MQP-2 协议层性能分析与 MQP-3 重设计建议

> 分析日期：2026-10-20 · 基线提交：`348c52d`
> 范围：**只分析 MQP-2 wire protocol / 帧语义 / 协议状态机**。
> 代码级热点（线程拓扑、recvmmsg 拷贝、重组器淘汰、统计原子等）见 `PERF_ANALYSIS.md`，本文不重复。
> 本文所有字节数/百分比均为**模型估算**（无丢包、IPv4、MTU 1200、quinn 合并 DATAGRAM 帧），
> 用于判断量级与方向；最终收益必须在 Linux 目标机用 `examples/hotpath_bench.rs` 复测。

---

## 0. 结论（TL;DR）

1. **MQP-2 的 wire format 对 bulk 流量已经接近最优。**
   单帧 IPv4 头的 12 B 在 1200 B 载荷里只占 0.9%；在 60 B 小包里占 16% 的增量字节，
   但同一包里 IP+UDP+QUIC 固定开销有 55 B，后者是前者的 4.6 倍。
   **因此“重写协议”对吞吐型业务的上限很低（≤1%），不值得为吞吐重写。**

2. **协议层仍有四块真实空间，集中在“小包 / 多目的地 / 域名目标 / 高 pps”：**

   | 编号 | 结构性问题 | 现状代价 | 可消除比例（模型） |
   |---|---|---|---|
   | P1 | 每帧重复携带目标地址，session 与 destination 未解耦 | IPv4 7 B、IPv6 19 B、域名 4+L B/帧；下行回包还要回显源地址 | 小包 9~11%，域名 33~38% |
   | P2 | BATCH 只能同目的地；客户端只做 2-pack；下行遇 source 变化就 flush | 多目的地/多源 burst 退化为逐包发送 | 扇出场景 15% 带宽、5~18× send 调用 |
   | P3 | 分片头重复 full address + sess，重组 key 冗余 | v4 18 B/片、v6 30 B/片、域名 15+L B/片 | 每片省 6~19 B；域名省 30+ B |
   | P4 | 无控制面：无能力协商、无显式 close、无 flow reject/ack | 会话靠 180 s idle 回收；新特性只能靠同版本部署；ALPN 默认 `h3` 无法做版本门禁 | 资源回收/灰度能力，非纯字节收益 |

3. **建议的重新设计不是“推倒重来”，而是 MQP-3 增量扩展：**
   - 引入 **session → flow 两级复用**：flow 绑定一个 `(association, destination)`，数据帧只带
     `type|flags | sess u32 | [flow u8]`（稳态 5 B，带 flow 6 B），地址只在建 flow 的首帧出现一次。
   - 引入 **TRAIN**：一个 QUIC DATAGRAM 内可混装多个 flow / 多个目的地的 payload，长度用 varint，
     同 flow 连续项 2 B/项，异 flow 项 3 B/项。
   - 引入 **紧凑 FRAG**：去掉每片地址，重组 key 变为 `(sess, flow, id)`，片头 11~12 B。
   - 引入 **CAPS/HELLO 协商 + CLOSE 控制帧**：老 peer 自动回退 MQP-2，新 peer 渐进启用；显式释放
     会话/flows，180 s idle 仅作兜底。

4. **量化预期（模型，保守取 sess 仍为 u32）：**
   - 小包单帧：wire −9.4%（IPv4 60 B，无批处理时）；域名目标 −33.4%。
   - 多目的地扇出：wire −15.4%（IPv4）、−37.8%（域名）；quinn send 调用 **18×** 减少。
   - 同目的地小包：相对当前 2-pack，wire −10.8%、调用 9×；但相对“已经实现 16-pack”的同一 wire
     protocol，只剩 −1.4% / 1.1× ——**说明同目的地的主要收益来自实现层的 N-pack，而不是新协议**。
   - 1200~1420 B bulk/分片：wire −0.9~1.1%，调用不变 —— 协议重设计对 bulk 基本无感。
   - CPU：按单次 `send_datagram` 200~300 ns 估，50~100k pps 的小包场景可省 **1~3% 单核**；
     这是“减少 quinn 调用/分配”的收益，不是协议头字节的收益。

5. **优先级建议：**
   - **Phase 0（不改 wire，先做）**：客户端 N-pack（F8）、batch 按预算而不是固定 16/512、
     已知路径把 `initial_mtu` 从 1200 提到 1360/1400。这一批能拿到同目的地场景的大部分 CPU 收益。
   - **Phase 1（MQP-3 核心）**：HELLO/CAPS + flow 地址压缩 + TRAIN + 紧凑 FRAG。
   - **Phase 2（控制面/鲁棒性）**：显式 CLOSE、FLOW_ACK/REJECT、可选的按 flow FEC、
     协商更大的重组上限。
   - **Phase 3（可选）**：跨 session 的 train、session id u16、NACK/重传。默认不做。

> 一句话：**MQP-2 不是当前性能的主要瓶颈；如果目标是高 pps、受限上行、域名目标或多目的地扇出，
> MQP-3 的 flow 化 + train 化值得做；如果目标只是 bulk 吞吐，优先调 MTU/窗口，协议不要动。**

---

## 1. 分析口径与关键事实

### 1.1 数据路径

```text
TCP:  QUIC stream head (atyp|addr|port) + raw bytes        （已经零拷贝，无协议头问题）
UDP:  MQP-2 frame → quinn DATAGRAM → QUIC packet → IP/UDP
```

MQP-2 的 UDP 帧有且只有三种形状（`src/mqp/`）：

| 帧 | 线上格式 | 固定头（IPv4 / IPv6 / 域名 L） |
|---|---|---|
| DATAGRAM | `0x02 \| sess u32 \| atyp \| addr \| port \| payload` | 12 / 24 / 9+L |
| FRAGMENT | `0x05 \| sess u32 \| id u32 \| idx u8 \| total u8 \| atyp \| addr \| port \| chunk` | 18 / 30 / 15+L |
| BATCH | `0x06 \| sess u32 \| atyp \| addr \| port \| count u8 \| (len u16 \| payload)*` | 13 / 25 / 10+L + 2/项 |

来源：`src/mqp/datagram.rs:11`（`DGRAM_PREFIX_LEN=5`）、`src/mqp/fragment.rs:29`
（`FRAG_PREFIX_LEN=11`）、`src/mqp/batch.rs:5-9`。地址编码与 SOCKS5 一致
（`src/mqp/addr.rs:114-160`）。

### 1.2 quinn 已经把多个 DATAGRAM 帧合并进同一个 QUIC packet

这一点决定了“MQP 层批处理”的真实收益边界。quinn-proto 0.11.19 的发送路径：

```rust
// quinn-proto-0.11.19/src/connection/mod.rs:3352
while buf.len() + Datagram::SIZE_BOUND < max_size && space_id == SpaceId::Data {
    match self.datagrams.write(buf, max_size) { ... }
}
```

`Datagram::encode` 每帧只加 `1 B type + varint len`（`frame.rs:896-907`）。也就是说：
**多个独立的 `send_datagram()` 调用，只要在同一个 transmit poll 里排队，就会共享一个 UDP/IP 包。**
因此 MQP `BATCH` 的收益不是“省掉 IP/UDP 头”（quinn 已经省了），而是：

1. 少 N−1 次 `send_datagram_wait()`：每次都要拿 quinn connection-state 互斥锁、检查发送缓冲、
   唤醒 driver（PERF_ANALYSIS F8/F10 已量化）；
2. 少 N−1 次 MQP 帧的精确容量分配（`Vec::with_capacity` → `Bytes::from`）；
3. 少 N−1 个 QUIC DATAGRAM 帧头（每帧 1+varint，约 2~3 B）；
4. 少 N−1 组 MQP 的 `type|sess|addr` 头（当前 12 B/帧）。

第 1、2 条是 CPU 收益，第 3、4 条是带宽收益。**第 1、2 条与 wire format 无关**，所以
Phase 0 的实现层 N-pack 就能拿到大部分；第 4 条才需要 MQP-3 的地址压缩。

### 1.3 每包开销模型

IPv4、MTU 1200 时：

- `max_datagram_size()` ≈ 1162 B（QUIC DATAGRAM body 预算；`src/mqp/datagram.rs:32-42`）；
- 每个承载数据的 QUIC packet 固定开销：IP 20 + UDP 8 + QUIC short header
  （flags 1 + DCID 8 + PN 2 + AEAD 16）= **55 B**；
- 每个 DATAGRAM 帧额外 1 + varint(len) = 2 B（≤63 B body）或 3 B。

因此单帧 60 B payload 的线上成本约为 `60 + 12 (MQP) + 3 (DQH) + 55 = 130 B`；
其中 MQP 头 9.2%，QUIC/IP/UDP 42.3%。**MQP 头的“天花板”就摆在这里。**

---

## 2. MQP-2 的字节成本与结构边界

### 2.1 单帧成本与 MQP 头占比（IPv4）

| payload | 帧 body | 线上（单帧独占一包） | MQP 头占线上 | MQP 头占增量字节* |
|---:|---:|---:|---:|---:|
| 28 B (STUN) | 40 | 97 B | 12.4% | 28.6% |
| 60 B (DNS) | 72 | 129 B | 9.3% | 16.0% |
| 200 B (game) | 212 | 269 B | 4.5% | 5.6% |
| 1200 B | 1212 | 1269 B | 0.95% | 0.99% |
| 域名 30 + 60 B | 99 | 156 B | 25.0% | 39.6% |

\* 增量字节 = payload + MQP header + DATAGRAM header，不含 55 B 的 IP/UDP/QUIC 固定开销。
当 quinn 把多帧合并进一个包时，55 B 被摊薄，MQP 头的占比会向“增量字节”一列靠拢。

这张表给出两个结论：

- **bulk（≥1200 B）**：MQP 头 <1%，改协议没有意义；
- **tiny（≤60 B）**：MQP 头占增量 16~29%，其中域名目标接近 40%；这里有真实空间，
  但最多也就把这 16~40% 压到 7~9%。

### 2.2 BATCH 的边界

`MAX_BATCH_ITEMS = 16`、`BATCH_SMALL_MAX = 512`（`src/mqp/batch.rs:7-9`）：

- 16 项对 28 B payload 只能填 `13 + 16×30 = 493 B`，不到 1162 B 预算的 43%；
- 对 60 B 是 `13 + 16×62 = 1005 B`，接近预算；
- 512 B 上限意味着两个 600 B 的 payload 即使同目的地也不能合帧；
- 客户端目前只做 **2-pack**（`src/bin/myquic2-client/assoc.rs:295-360`）；
- 服务端下行按 `(ip, port)` run 批处理，source 一变就 flush（`src/bin/myquic2-server/reader.rs:138-161`）。

所以“多目的地/多源 burst”是 BATCH 结构上覆盖不到的：一个 DNS 客户端轮流问 32 个 resolver，
或者一个游戏 session 同时收 8 个 peer 的包，当前每个包都是独立帧。

### 2.3 分片路径

`DgramFragmenter` 每片都带完整地址（`src/mqp/fragment.rs:180-192` 明确说明这是为了
“self-describing / 无需特殊处理乱序”）。代价：

- 2 片 1420 B（MTU 1200 的 WireGuard 典型）：每片 18 B 头，共 36 B，占 payload 的 2.5%；
- 域名 30 + 2 片：每片 45 B，共 90 B，占 payload 的 6.3%；
- 每个分片是一次独立的 `send_datagram` + 一次精确分配 + 一次 quinn state 锁；
- 重组器 key 是 `(sess, id)`，地址重复但地址并不参与 key。

同 MTU 下，分片的 packet 数由 chunk 大小决定，**TRAIN 不能减少“每片接近满 MTU”时的包数**，
所以分片优化主要是“每片头变短”，不是“包数变少”。这也是后文不把“fragment train”列为核心的原因。

### 2.4 下行回显地址

UDP 下行每个 reply 都带目标地址，因为客户端要用它填 SOCKS5 UDP response header
（`src/bin/myquic2-client/dispatcher.rs` 的 `stage_reply` / `send_reply`）。这是**协议语义要求**，
不是冗余；但它可以被 flow 绑定替代：客户端在发送时已经知道目标，flow id 就能反查。

### 2.5 固定成本不是协议能解决的

每个 outbound 数据报仍然有：

- 一次 MQP 帧精确容量分配（`Bytes::from(Vec)` 的 in-place 快路径，已经最优）；
- 一次 payload 拷贝进帧；
- 一次 quinn `send_datagram_wait` 的 state 锁 + 一次 driver wake；
- quinn 内部再拷贝一次进 packet buffer。

MQP-3 能减少第 1、3 条的“次数”，但**不能消除单次拷贝**，也不能绕过 quinn 的 API。
这是评估“重设计能带来多少”的上限。

---

## 3. 结构性问题清单

### P1【协议核心】每帧重复地址，session 与 destination 未解耦

**现状**：`sess` 标识一个 UDP ASSOCIATE，但每个 DATAGRAM/FRAGMENT 都要重新携带目标地址或源地址。
- 一个 association 通常只和一个目标通信（DNS resolver、game server、WireGuard peer），
  地址在会话生命周期内基本不变；每包重复是纯冗余。
- 域名目标的冗余最大：一个 30 B 域名 + port 每包 35 B，60 B DNS 查询的实际 MQP 头是 39 B，
  是 payload 的 65%。
- 下行服务端已经知道 reply 的 `(sess, source)` 对应关系，却仍要在每帧里回显地址。

**影响**：
- 小包带宽（尤其域名目标）；
- 每帧的 `AddrHeader::header()` 校验 / 编码（虽然 `DgramPrefixCache` 已把稳态同目标的成本降到
  一次比较，但域名比较仍是字符串比较）；
- **阻止了跨目的地的合帧**（BATCH 的 header 只有一个地址）。

### P2【结构】BATCH 的“同目的地”约束 + 客户端 2-pack + 下行 source-change flush

**现状**：
- 客户端只在相邻两个 ≤512 B payload 同 destination 且同 egress bind 时做 2-pack；
- 服务端下行把 ≤512 B reply 按 `(ip, port)` run 暂存，source 改变就 flush；
- `MAX_BATCH_ITEMS=16` 对 28 B payload 只填 43% 预算。

**影响**：
- 多目的地 fanout（DNS / 游戏 / WebRTC）完全退化为逐包；
- 同目的地小包也只合 2 个；
- 下行多源 burst 的合帧能力受 source 变化限制。

**注意**：这一条一半是**实现问题**（F8 已 deferred），一半是**协议问题**（没有 flow 概念，
batch header 只能共享一个地址）。Phase 0 能解决同目的地的一半；MQP-3 解决多目的地的一半。

### P3【结构】FRAGMENT 头与重组 key 冗余

- 每片重复 11 B 固定 + full address；
- 重组 key `(sess, id)`，但地址不参与 key；
- 每片都是一次独立的 quinn send / 分配；
- 32-bit id 是必要的（16-bit 在 3 s 重组窗口下有 21845/s 的丢包悬崖，
  `src/mqp/fragment.rs:19-28` 的注释已经给出历史数据），**不要为了省 2 B 改回 u16**。

### P4【结构】没有控制面

当前没有：
- 能力协商：新帧类型只能靠“同版本部署”；默认 ALPN 是 `h3`（`src/mqp/ack.rs:8-24`），
  没有版本门禁；`myquic2/3` 也需要显式配置；
- 显式 session close：客户端 SOCKS TCP 断开后，服务端 session 仍按 `SESS_IDLE_MS = 180000`
  存活（`src/bin/myquic2-server/table.rs:365`），期间持有 socket + 64 KiB 内核缓冲 + reader task；
- flow reject / ack：如果未来做地址压缩，需要知道“对端是否已建立映射”；
- 可协商的重组上限：8 KiB 是编译期常量（`src/mqp/fragment.rs:47`），无法按部署调整。

这不是纯带宽问题，但直接影响“能不能安全地做增量协议升级”和“短会话 churn 下的资源占用”。

### P5【可选】分片无恢复机制

一个 `F` 片 payload 的到达率是 `(1−p)^F`；MTU 1200 下 1420 B payload 是 2 片，
1% 丢包时到达率 98.01%（相对不丢包损失翻倍）。协议层可选：
- **FEC**：每 k 个 data 片加 1 个 XOR parity，恢复任意 1 片丢失；
- **NACK/选择性重传**：需要 ACK 通道，延迟 +1 RTT。

两者都不是默认值得开的：FEC 在 k 小时开销大（2 片 + 1 parity = +50% 字节），
NACK 改变 UDP 语义且需要新状态机。放到 Phase 2/3，按部署和丢包率 opt-in。

### P6【非协议】MTU 起步值

`DEFAULT_INITIAL_MTU = 1200`（`src/config/tuning.rs:192`）。在 MTU 1200 下：
- DATAGRAM 预算 1162 B，IPv4 MQP payload 上限 1150 B；
- 任何 >1150 B 的 UDP payload 都会分片；
- 在 PMTU 发现爬升前，包数多 18~23%。

已知路径（WireGuard-1420、PPPoE、以太网）把 `initial_mtu` 提到 1360/1400/1472，
是**比任何 MQP 重设计都便宜且收益更大的单项改动**。协议层能做的是协商“对端可接受的重组上限”，
但 MTU 本身是传输配置，不要混进 MQP 帧格式。

---

## 4. MQP-3：以 flow 为中心的增量协议

### 4.1 设计目标与硬约束

**目标**：
1. 稳态数据帧不带地址，越小包收益越大；
2. 一个 QUIC DATAGRAM 可以混装多个目的地/多个 session 的 payload；
3. 分片头变短、重组 key 变短，但不改变“任一片丢失即整包丢弃”的 UDP 语义；
4. 不增加首包 RTT、不等待、不改变现有 TCP 路径；
5. 老 peer 可以继续用 MQP-2，新 peer 用 CAPS 协商；
6. 所有表/队列有界，不能给未认证 peer 新的内存放大器。

**硬约束**（来自现有实现）：
- QUIC DATAGRAM 是唯一合适的载体；QUIC stream 会给 UDP 引入 HOL + 重传，不能用于数据面；
- 帧解码必须“未知类型只丢一个 DATAGRAM”，不能断连接（现有 decoder 已满足）；
- 32-bit fragment id 保留（重组窗口安全）；
- 8 KiB 载荷上限、2 s partial 超时、256 KiB/连接重组预算保留；
- auth/SSRF/full-cone/allowlist 语义不变；
- 默认 ALPN `h3` 不变（用 in-band CAPS 做能力门禁）。

### 4.2 核心抽象：session 与 flow

```text
session (u32, 保留现有语义：一个 UDP ASSOCIATE)
  └── flow (u8, 客户端分配, 0 = primary)
        = 一个 destination (atyp|addr|port)
        + 一个服务器侧 session socket
        + 一个客户端侧 relay/app 绑定
```

- **flow 0**：session 的第一个目的地，也是默认回包路径；数据帧可以完全省略 flow 字节。
- **flow 1..255**：同一 association 的额外目的地。数据帧带 1 B flow id。
- 一个 flow 一旦建立，dest 不变；客户端在 flow 上发送，服务端用 `(sess, flow)` 找回
  dest / allowlist / 会话 socket；下行 reply 用 flow id 表达“这是哪个目标的回包”，
  客户端用本地 flow 表还原 SOCKS5 response header。
- 同一 session 内相同 dest 复用同一 flow；不同 session 即使 dest 相同也是不同 flow
  （因为 relay socket / app 绑定不同）。

**为什么不是“每个 destination 一条 QUIC 连接”**：连接级状态（握手、CC、14 MiB 传输预算）
远大于 flow 表；而且 MQP 的连接复用正是为了避免这个。

**为什么不是 HPACK 式动态字典**：flow 绑定已经足够，且不需要维护双向同步的压缩上下文；
flow id 由客户端分配、服务端镜像，语义简单。

### 4.3 帧格式（MQP-3，协商后启用）

首字节采用 **高 4 bit 类型 + 低 4 bit flags**：

```text
bit 7..4 : kind    0x1 SINGLE, 0x2 TRAIN, 0x3 FRAG, 0x4 CTL
bit 3..0 : flags   I=INLINE_ADDR, F=FLOW_PRESENT, S=SRC_OVERRIDE, R=reserved

公共部分：sess u32 LE（保留现宽度；见 §4.10 的 u16 讨论）
```

#### (a) SINGLE — 单 payload

```text
[0x10 | flags] [sess u32] [flow u8 if F] [atyp|addr|port if I] [payload]
```

- 稳态、flow 0：`0x10 | sess | payload` = **5 B 头**；
- 额外 flow：`0x12 | sess | flow | payload` = **6 B 头**；
- 新 flow / 新 session 首帧：`0x13 | sess | flow | addr | payload`，IPv4 为 12 B，
  与 MQP-2 的 12 B 相同（v6 20 B vs 24 B，域名 1 B 更差），**首帧没有惩罚**。

#### (b) TRAIN — 多 payload 合帧

```text
[0x20 | flags] [sess u32] [count u8]
  [flow u8 if same-flow and flow != 0]
  item*: [iflg u8] [flow u8 if iflg.F] [len varint] [atyp|addr if iflg.I] [payload]
```

- 头 6 B；同 flow 连续项：`iflg + len8` = 2 B/项（与当前 BATCH 的 `len u16` 相同）；
- `SAME_FLOW` 标志只用于 **非 0 flow**：flow 0 是隐式的，若置位则解码器会
  把首项的 `iflg` 误读成 flow。flow 0 的 all-compressed TRAIN 用 mixed 形式
  （标志清零、每项无 flow 字节），wire 大小与置位时相同。
- 混合 flow：+1 B flow = 3 B/项；
- 一次性目的地：+7/19/4+L B inline addr，但仍与其他项共享一次 quinn send；
- `count` 不设固定 16 上限：编码器按 `limit` 填满，解码器校验 `count` 与边界；
  协商项 `max_train_items` 给出防御上限（例如 64）。
- 同目的地小包（28 B）：`6 + 38×30 = 1146 B`，约 38 项/帧；
- 混合 8 个目的地、200 B：`6 + 5×(3+200) = 1021 B`，5 项/帧。

**flush 规则与现在一致**：只装当前 drain burst 中已经到达的包，burst 结束就发，不等待凑满。
因此不增加延迟；`count` 上限只是防御，不参与调度。

#### (c) FRAG — 分片

```text
[0x30 | flags] [sess u32] [flow u8 if F] [id u32] [idx u8] [total u8] [addr if I] [chunk]
```

- 稳态（flow 0）：11 B 头；额外 flow：12 B；当前 v4 是 18 B；
- 每片不再重复地址；只有新 flow 的前几片带 `I`，保证 flow 建立前也能路由；
- 重组 key 变为 `(sess, flow, id)`，`id` 仍是 u32；
- 乱序/丢片语义不变：任一片缺失，partial 2 s 后过期。

**不做 fragment train**：在 MTU 1200 下每片 chunk ≈1144 B，一个 QUIC DATAGRAM 基本只装得下一片；
把多片塞进一个 train 不会减少包数，只会增加编码复杂度。真正值得做的是“片头变短”。

#### (d) CTL — 控制帧

```text
[0x4X] [opcode u8] [body]
```

| opcode | 方向 | 语义 |
|---|---|---|
| `HELLO` | C→S | magic `M3` + version + flags；连接建立后发送，重试若干次 |
| `CAPS` | S→C | version + flags + `max_train_items` + `max_flows/session` + `max_reassembly` |
| `FLOW_ACK` | S→C | `(sess, flow)` 已建立（上行单向 flow 的确认） |
| `FLOW_REJECT` | S→C | `(sess, flow, reason)`；客户端对该目的地回退 inline |
| `FLOW_CLOSE` | C→S | 释放一个 flow（可重试；idle 兜底） |
| `SESS_CLOSE` | C→S | 释放整个 session（socket/task/flow 立即回收） |

控制帧都是幂等的，允许重复；控制帧丢失不会导致连接失败，最坏只是晚一点压缩/晚一点释放。

### 4.4 地址压缩的自愈流程

UDP 是不可靠的，因此“建立了 flow 就一定还能路由”不能假设。设计成**首帧内联、收到回包后确认**：

```text
client                                          server
  |-- SINGLE I|F (sess,flow=0,addr,payload) ---->|  校验 SSRF；创建/复用 session；登记 flow
  |                                               |  发送到目标
  |<------------- SINGLE (sess,flow=0,payload) --|  回包带 flow；客户端确认映射
  |-- SINGLE (sess,flow=0,payload) ------------->|  之后全部 5 B 头
```

- 客户端对每个 flow 维护 `state = Inline | Compressed`；
- 新 flow 的前 N 帧（例如 3 帧）继续带 `I`，收到该 flow 的下行帧后转 `Compressed`；
- 纯上行 flow（没有回包）由服务端在登记后发 `FLOW_ACK`；收到 ack 后转 `Compressed`；
- 若 `FLOW_REJECT`/表满，保持 `Inline`（等价于今天的 12 B 头），不会黑洞；
- 服务端表项只在 session 生命周期内存在，**不在 session 存活时淘汰活跃 flow**；表满就 reject，
  客户端回退 inline。session 销毁时整表释放。
- flow id 在 session 内不复用；若 256 个用尽，新目的地继续 inline。这样避免“复用 id 把旧 flow 的
  残余分片拼进新 flow”的 splice 风险（与 fragment id 的安全窗口同理）。
- 若未来要复用，必须满足 `now - last_close >= FRAG_ID_SAFE_WINDOW_MS`，且旧 flow 无 partial。
  第一版建议直接不做复用。

> **当前实现（2026-10-20）**：没有 FLOW_ACK/REJECT。IP flow 一直 inline，
> 直到收到并成功暂存一个该 flow 的**压缩下行帧**（服务端只有在其 flow 表
> 已安装时才会这样编码），之后才压缩。收不到回包的纯上行 flow 保持 inline；
> 代价是每帧多 1 B flow + 地址，但不会因为前几帧丢失而永久黑洞。域名目标
> 每帧 inline（见 §4.5）。

### 4.5 下行地址与 full-cone

- 正常回包：服务端用 flow id 标记，客户端从本地 flow 表得到 `(atyp|addr|port)`，写 SOCKS5 头；
  **线上不再出现地址**。当前实现只对 **IP 目标**这样做；域名目标的 flow 表项是
  `TargetAddr::Domain`，客户端没有解析后的源 IP，所以下行保持 inline。
- 目标从同 IP 的另一个端口回包（现有 allowlist 允许）：服务端在该 flow 帧上置 `S` 并 inline
  实际源地址；客户端用帧内地址写 SOCKS5 头。额外 7/19 B，仅异常源发生。
- `udp_full_cone = true` 的 unsolicited 源：找不到 flow，使用 `SINGLE I`（sess + inline addr）
  投递；客户端按 `sess` 路由。语义与现在完全一致，只是没有压缩。
- 服务端 reply 的 allowlist ring（16 项）继续保留；flow 表只是在 ring 命中后提供 flow id，
  不增加每包查找成本。
- 但 ring 只有 16 个 IP，32-resolver 这类 fanout 会把早期目标挤出。当前实现把
  **精确 `(sess, flow) -> IP` 映射**作为 ring 未命中时的第二授权源：目标在建立
  flow 时已经过 SSRF/发送校验，之后即使 ring 淘汰了它，它的回包仍能通过；
  域名 flow（无 resolved IP）不参与这条路径。这样不必把 ring 扩到 32/64，
  也不用打开 full-cone。

### 4.6 能力协商与灰度

> **当前实现（2026-10-20）没有启用本节机制。** 按“不再兼容 MQP-2 对端”的
> 部署假设，客户端直接发 MQP-3，服务端同时接受 MQP-2/3 解码但下行也用
> MQP-3；没有 HELLO/CAPS，也没有 `mqp3=false` 回滚开关。下面保留为需要灰度
> 时的设计。

```text
new client                                  old server
  |-- CTL HELLO (0x4x, "M3", ver, flags) --->|   未知类型 → 丢弃该 DATAGRAM，连接不受影响
  |   (retry 3x)                              |
  |-- MQP-2 data ---------------------------->|   继续工作
```

```text
new client                                  new server
  |-- HELLO -------------------------------->|   识别
  |<--------------------------- CAPS --------|   支持 MQP-3
  |-- MQP-3 frames ------------------------->|   服务端 RX 始终兼容两种；收到首个 MQP-3 帧后 TX 切换
  |<--------------------------- MQP-3 -------|
```

- **新客户端 + 老服务端**：HELLO 被丢弃，无 CAPS → 客户端永远停留在 MQP-2。
- **老客户端 + 新服务端**：老客户端不发 HELLO → 服务端不发 CAPS，继续 MQP-2。
- 服务端只有在**收到首个 MQP-3 帧后**才切换下行编码，避免 CAPS 丢失时向尚未升级的客户端
  发新格式导致回包黑洞。
- CAPS 丢失：客户端重试 HELLO；服务端对每个 HELLO 重发 CAPS。
- 默认 ALPN 仍可保持 `h3`；需要硬门禁的部署可显式设 `alpn = "myquic2/4"`。
- 提供配置开关（例如 `mqp3 = false`）用于回滚；关闭后不发 CAPS、不主动用 MQP-3。

**为什么不用“直接 ALPN bump”**：`h3` 伪装是当前默认；强制 bump 会丢掉这个特性。
CAPS 是 in-band 能力协商，既不破坏伪装，也能安全灰度。ALPN bump 作为可选项保留给需要
fail-closed 的部署。

### 4.7 安全与资源边界

| 资源 | 上限 | 说明 |
|---|---|---|
| flows / session | 64（当前固定；按 u8 id 空间留安全余量） | `FlowTable` 固定数组；表满客户端回退 `NO_FLOW` inline |
| flows / connection | 无额外全局表（每 session 一个 64 槽表） | 服务端 session 全局 8192，内存约 4 MiB |
| train items | 协商 64 | 解码器校验；只是防御，编码按预算 |
| 重组 | 现有 8 KiB / 256 KiB / 2 s | 不变 |
| flow 表内存 | ≈ 每项 40~64 B | 8192 sessions × 64 flows × 64 B ≈ 32 MiB（最坏） |

- 服务端 **每帧** 仍走 `resolve_fast` / `forward_server_dgram` 的 SSRF 与
  allowlist 检查；flow 表本身不绕过 SSRF。它记录的 exact IP 只在 16 项
  allowlist ring 未命中时作为第二授权源（安装前已经过发送校验），不能凭空
  授权一个从未发送过的目标。域名 flow 重新解析时也重新过滤，避免 DNS
  rebinding 把已建 flow 变成内网跳板。
- flow id 是客户端选的，服务端只接受“已认证连接内”的映射；不会因为 flow id 冲突而跨 session 路由。
- 若同一个 flow id 被 inline 成不同地址，服务端删除该映射，后续 compressed 帧按未知 flow 丢弃，
  不会把 payload 改投到旧目标。
- full-cone 的 unsolicited 源走 inline 路径，不写入 flow 表（避免被任意源撑爆）。
- 不改变 auth、TLS、连接 admission、session fair-share、UDP 全锥策略。

### 4.8 与 TCP 路径的关系

**不动。** TCP 的地址只在 stream head 出现一次，已经在协议层最优；MQP-3 只改 UDP DATAGRAM。

### 4.9 明确不做的事

- 不把 UDP 放到 QUIC stream 上：HOL + 重传会把“丢包”变成“延迟”；
- 不做 fragment train：每片接近 MTU，包数不会减少；
- 不做跨 session 的 train（第一版）：需要连接级共享发送队列，quinn 已经会合包，
  剩下的只是 state 锁；收益不确定，先不做；
- 不做 payload 压缩：载荷主要是加密/随机数据；
- 不缩小 fragment id：u16 的历史丢包悬崖已有数据；
- 不默认开 FEC/NACK：改变 UDP 语义/带宽放大，留给 opt-in。

### 4.10 可选的进一步压缩：session id u16

本文的量化全部按 **sess 保持 u32** 计算（稳态 5 B 头），这是风险最低的方案。若后续确认：

- 客户端 hub 的 session id 分配改为 16-bit + free-list（4032 并发足够）；
- 关闭的 id 在服务端 180 s idle 窗口内不复用（或显式 SESS_CLOSE 后才复用）；
- 所有日志/统计/表 key 同步改宽；

则稳态头可再省 2 B（5 B → 3 B；额外 flow 6 B → 4 B）。对小包约再省 2~3% 带宽，
但会触碰 `hub.rs` / `table.rs` / 测试里的 id 语义，建议作为 Phase 3 的独立改动，
不要和 flow/train 混在一起。

---

## 5. 量化收益（模型）

### 5.1 假设

- IPv4；MTU 1200 → DATAGRAM 预算 1162 B；每 packet 固定开销 55 B；每个 DATAGRAM 帧 2~3 B；
- quinn 会把同一 poll 的多个 DATAGRAM 帧合并进一个 packet（已由源码确认）；
- 当前客户端上行按 **2-pack** 建模（现状）；服务端下行按同源 run 最多 16 项、≤512 B 建模；
- MQP-3 按 sess u32 + flow（稳态 5 B、额外 flow 6 B）+ TRAIN（2 B/同 flow 项、3 B/异 flow 项）
  建模；未计 FEC/ACK 开销；
- 不考虑丢包、ACK-only 包、GSO padding、PMTU 变化。

### 5.2 上行（client → server）

| 场景 | MQP-2 wire | MQP-2 send 调用 | MQP-3 wire | MQP-3 send 调用 | 带宽 | 调用 |
|---|---:|---:|---:|---:|---:|---:|
| DNS 60 B，同目的地，50k pps（现状 2-pack） | 3.67 MB/s | 25.0k/s | 3.28 MB/s | 2.8k/s | **−10.8%** | **9.0×** |
| 同上，假设已实现 16-pack（Phase 0） | 3.32 MB/s | 3.1k/s | 3.28 MB/s | 2.8k/s | −1.4% | 1.1× |
| DNS 60 B，32 个目的地，50k pps | 3.93 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−15.4%** | **18.0×** |
| 同上，域名 30 B | 5.35 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−37.8%** | **18.0×** |
| STUN 28 B，同目的地，100k pps（2-pack） | 3.98 MB/s | 50.0k/s | 3.17 MB/s | 2.6k/s | **−20.5%** | **19.0×** |
| 60 B 单帧，50k pps | 3.93 MB/s | 50.0k/s | 3.56 MB/s | 50.0k/s | −9.4% | 1.0× |
| 60 B 单帧，域名 30 B，20k pps | 2.14 MB/s | 20.0k/s | 1.42 MB/s | 20.0k/s | **−33.4%** | 1.0× |
| Game 200 B，8 个目的地，20k pps | 4.52 MB/s | 20.0k/s | 4.32 MB/s | 4.0k/s | −4.5% | **5.0×** |
| VPN 1420 B（2 分片），5k pps | 7.86 MB/s | 10.0k/s | 7.79 MB/s | 10.0k/s | −0.9% | 1.0× |

### 5.3 下行（server → client）

| 场景 | MQP-2 wire | MQP-2 send 调用 | MQP-3 wire | MQP-3 send 调用 | 带宽 | 调用 |
|---|---:|---:|---:|---:|---:|---:|
| 60 B 同源，50k pps | 3.32 MB/s | 3.1k/s | 3.28 MB/s | 2.8k/s | −1.4% | 1.1× |
| 60 B，8 个源交替，50k pps | 3.93 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−15.4%** | **18.0×** |
| 200 B，4 个源交替，20k pps | 4.52 MB/s | 20.0k/s | 4.32 MB/s | 4.0k/s | −4.5% | **5.0×** |
| 1000 B 同源，20k pps | 21.52 MB/s | 20.0k/s | 21.30 MB/s | 20.0k/s | −1.0% | 1.0× |
| 1420 B（2 分片），5k pps | 7.86 MB/s | 10.0k/s | 7.79 MB/s | 10.0k/s | −0.9% | 1.0× |

### 5.4 CPU 估算

PERF_ANALYSIS 的 F8 用 200~300 ns/次 `send_datagram` 估算；单帧还包括一次精确分配
（约 30~50 ns）。按 250 ns + 40 ns 计：

| 场景 | 省下的调用/s | 估算单核 CPU |
|---|---:|---:|
| DNS 60 B 同目的地，50k pps（2-pack → train） | 22.2k | 0.6~0.7% |
| DNS 60 B 32 目的地，50k pps | 47.2k | 1.3~1.5% |
| STUN 28 B 同目的地，100k pps | 47.4k | 1.3~1.5% |
| Game 200 B 8 目的地，20k pps | 16k | 0.4~0.5% |
| 单帧 / bulk / 分片 | 0 | ≈0 |

**结论**：协议重设计的 CPU 收益是“1~3% 单核”量级（在 50~100k pps 小包场景），
不是数量级提升。它真正的价值在**受限上行带宽**（10~38%）和**每核 pps 上限**（5~19× 更少调用）。

### 5.5 分片/FEC 的可选收益

| 场景 | 无 FEC 到达率（p=1%） | +1 parity | 额外字节 |
|---|---:|---:|---:|
| 2 片（1420 B） | 98.01% | 99.97%（3 片，任意 1 片可恢复） | +50% |
| 8 片（8 KiB） | 92.3% | 99.64%（9 片，任意 1 片可恢复） | +12.5% |

小 F 时 FEC 不划算（2 片 +1 parity 是 +50% 字节）；只有大载荷、高丢包、且应用愿意为
“少一次重传”付带宽时才 opt-in。默认不做。

### 5.6 什么时候值得

| 工作负载 | MQP-3 价值 | 建议 |
|---|---|---|
| 大包 bulk（≥1200 B）、LAN/数据中心 | ≈0 | 不做；调 MTU/窗口 |
| 同目的地小包、客户端单流 | 中（主要靠 N-pack） | 先做 Phase 0；MQP-3 视 CPU |
| 多目的地扇出（DNS/游戏/WebRTC） | **高**（5~18× 调用、15% 带宽） | 做 Phase 1 |
| 域名目标 UDP | **最高**（33~38% 带宽） | 做 Phase 1 |
| 受限上行 / 计费链路 | 高（小包 9~38%） | 做 Phase 1 |
| 需要快速回收短会话 | 中 | 做 Phase 2 的 SESS_CLOSE |
| 高丢包大载荷 | 中（FEC） | Phase 2/3，opt-in |

---

## 6. 实施路线

### Phase 0：不改 wire（先做，收益/风险比最高）

1. **客户端 N-pack**：把 `assoc.rs` 的 2-pack 扩成按预算的 16 项（照抄
   `server/reader.rs` 的 `reply_stage` / `flush_reply_batch` 模式）。
   - 只装当前 drain burst，不等待；
   - 保留 `PendingPack` 的“跨 burst 不遗留”语义；
   - 目标：同目的地小包调用数从 25k/s 降到 ~3k/s（50k pps）。
2. **batch 上限按预算**：`MAX_BATCH_ITEMS=16` 对 28 B payload 只填 43%；
   在 CAPS 协商或同版本部署下提高到 64，仍按 `limit` 计算。
   - 注意：默认 ALPN `h3` 不做版本门禁；跨版本部署时，老解码器会把 >16 项整帧拒绝。
     因此这一步要么与 CAPS 一起发（Phase 1），要么要求两端同版本升级。
3. **MTU**：已知路径把 `initial_mtu` 从 1200 提到 1360/1400；
   `>1150 B` 的 UDP payload 不再默认二分片，包数少 18~23%。
4. **验证**：`cargo test --all-targets` + `hotpath_bench udpps/udppaced/udpmulti/udpdomain`
   + Linux 2~4 核 CPU/pps。

> **Phase 0 落地状态（2026-10-20）**
>
> - **客户端 N-pack 已实现**：`AppDgramCtx` 的 2-pack 改为 burst 内最多
>   `MAX_BATCH_ITEMS=16` 项的 run；同目的地且 `batch_frame_len(...) <= limit`
>   时追加，否则立即 flush 当前 run。run 在 burst 结束、目的地变化、预算不足、
>   遇到不可 batch 的大包或表满时发送；只装当前 drain burst，不跨 await 等待。
> - **单包不套 BATCH**：run 长度为 1 时走普通 `0x02`，与旧路径逐字节一致；
>   长度 ≥2 时才编码 `0x06`。
> - **预算算术统一**：新增 `mqp::batch::batch_frame_len`，客户端 stager 和
>   服务端 `reply_stage` 都用它；`encode_batch` 的接受条件与 stager 的预检查
>   是同一套公式，避免“先拷贝、后拒帧”。
> - **未把 `MAX_BATCH_ITEMS` 提到 64**：默认 ALPN 仍是 `h3`，没有 CAPS/版本
>   门禁；旧解码器会整帧拒绝 >16 项。该项留到 Phase 1 的 CAPS 之后。
> - **`BATCH_SMALL_MAX=512` 保留**：它是 fate-sharing 上限，不是预算上限；
>   单包 512 B 以上的 payload 继续走单帧/分片。
> - **MTU 默认值未改**：仍为 1200。已知路径请在配置里显式设
>   `initial_mtu = 1360/1400`；默认改动会影响未知路径，不做隐式切换。
> - **验证**：`cargo test --all-targets` 全部通过，
>   `cargo clippy --all-targets -- -D warnings` 通过；新增客户端 16 项
>   BATCH 顺序/单帧测试，以及 `batch_frame_len` 与编码器一致性测试。
>   Linux 2~4 核上的 pps/CPU 数字仍需在目标机用 `hotpath_bench` 复测。
>
> Phase 1 落地后，客户端生产路径的 N-pack 已改发 MQP-3 `TRAIN`；这里描述的
> `0x06 BATCH` 客户端代码保留在 `#[cfg(test)]`，仅用于 MQP-2 解码/历史测试。

### Phase 1：MQP-3 核心（wire 扩展）

1. 新增 `src/mqp/v3.rs`（或 `mqp3/`）：
   - `FrameKind/Flags`、`SINGLE/TRAIN/FRAG/CTL` 编解码；
   - golden vectors + 边界/fuzz 测试；
   - 与 MQP-2 encoder 并存，decoder 同时接受两套。
2. CAPS/HELLO 协商 + 配置开关；老 peer 回退。
3. 客户端 flow 表 / 服务端 flow 表；`Inline → Compressed` 状态机；FLOW_ACK/REJECT。
4. 客户端上行 TRAIN（同一 association 的 burst 内混合 flow）；
5. 服务端下行：去掉“source 变化即 flush”，同一 burst 用一个 TRAIN；
6. FRAG 紧凑头 + `(sess, flow, id)` key；
7. 统计：frame type、flow count、train items、fallback inline 次数。

> **Phase 1 核心落地状态（2026-10-20）**
>
> 本轮按“**不再兼容 MQP-2 对端**”的部署假设实现，因此没有引入
> HELLO/CAPS/FLOW_ACK/FLOW_REJECT：
>
> - **`src/mqp/v3.rs` 已实现**：`SINGLE`/`TRAIN`/`FRAG` 编解码、LEB128
>   length、`FlowTable`、golden/boundary 测试。`SINGLE` 稳态为 5 B
>   （flow 0）或 6 B（额外 flow）；`TRAIN` 头 6 B，同 flow 额外项 2 B，
>   异 flow 项 3 B；`FRAG` 头 11/12 B + 可选地址。
> - **客户端上行已切到 v3**：`assoc.rs` 的 N-pack 改为 `PendingTrain`，
>   同一 drain burst 内可混装多个 flow；run 为 1 时发 `SINGLE`，≥2 时发
>   `TRAIN`。>512 B 或无法编码的载荷仍走 MQP-2 单帧/FRAG。
> - **flow 打开**：客户端对每个 IP flow 先 inline；收到并成功暂存该 flow 的
>   压缩下行帧后，才切到压缩。没有 ACK，因此纯上行 flow 保持 inline；这避免
>   首几帧丢失导致整个 flow 永久黑洞。TRAIN 内“首项 inline、后续项压缩”也是
>   安全的，服务端按 wire 顺序登记后再解后续项。会话 flow 表按每 session
>   4 KiB 计入 `per_session_memory_bytes` 的 admission 预算。
> - **域名目标保持 inline（`MQP3_NO_FLOW`）**：首个域名由服务端异步解析，
>   此时 session/flow 表可能尚未建立；强行压缩会在解析完成前黑洞。且客户端
>   只有域名、没有解析后的 IP，下行也无法安全地用域名填 SOCKS5 response
>   header。因此域名目标每帧带 inline 地址，但 TRAIN 仍共享 sess/QUIC 帧；
>   IP 目标才做 flow 压缩。域名收益因此低于模型中“完全压缩”的上界。
> - **服务端上行**：`accept.rs` 在 v2 FRAG/BATCH 之前识别 v3；按 session
>   从 FastSess/会话表取 flow 表；inline open 在转发目标后登记，compressed
>   项查表转发。未知 flow 只丢该项并计 `REFUSED`，不会猜测路由。
> - **服务端下行**：`reader.rs` 用同一个 session flow 表把 reply source 映射
>   回 flow id；IP flow 精确匹配 `(ip, port)` 时压缩，域名 flow、端口变化和
>   full-cone unsolicited 源一律 inline。下行 run 不再要求“同源”，一个 TRAIN
>   可混装多个源；run 为 1 时发 `SINGLE`。flow 表同时作为 16 项 allowlist
>   ring 未命中时的**精确 IP 授权回退**，所以 32-resolver fanout 不会因为
>   早期目标被 ring 淘汰而丢回包。
> - **FRAG 尚未接线**：v3 紧凑 FRAG 编解码已就绪，但重组器仍按
>   `(sess, id)` 处理 MQP-2 分片；大载荷两端继续用 v2 FRAG。下一步是把
>   reassembler key 扩成 `(sess, flow, id)` 并让 `DgramFragmenter` 支持 v3。
> - **无配置开关/无 CAPS**：当前是同一版本部署；新客户端对老服务端不会
>   回退。若需要灰度，需要补 Phase 2 的 CAPS + `mqp3=false`。
> - **验证**：`cargo fmt --all`、`cargo test --all-targets`、
>   `cargo clippy --all-targets -- -D warnings` 通过。新增 v3 codec、
>   客户端 open/compress、混合 flow TRAIN、服务端下行压缩/混合源/域名
>   inline，以及“TRAIN 内 open + compressed 到目标”的端到端单元测试。
>   macOS release 二进制 smoke：`udp`/`udpdomain` 1000/1000、
>   `udpmulti` 4×500 0 loss、`udppaced` 1k–5k pps 0 loss、
>   `udpps` 2 s 9985/9985；与 HEAD baseline 的 5k pps / `lat` p50 同量级。
>   Linux 2~4 核的 `udpps/udppaced/udpmulti/udpdomain` 仍需目标机复测。

**验收门槛**：
- `udpdomain` / 新增 `udpfanout`：wire −10%（v4）/ −30%（域名）；
- `udpfanout` 的 send 调用 ≥5× 减少；
- `lat` p50/p99 不回归（≤1%），丢包率不增加；
- `bulk` 吞吐不回归。

### Phase 2：控制面与鲁棒性

1. `SESS_CLOSE` / `FLOW_CLOSE`：短会话立即释放 socket/task/flow；180 s idle 仅兜底。
2. `FLOW_ACK` 超时/拒绝的指标与告警。
3. 可协商 `max_reassembly`（当前 8 KiB 编译期常量）。
4. 可选 FEC（按 flow / 端口 opt-in）、可选 NACK（独立设计，不混入第一版）。
5. 观测：flow 表 high-water、reject 次数、inline 回退率。

### Phase 3（可选）

- 跨 session 的 TRAIN（需要连接级共享 stager；只有 profiling 证明 state 锁是瓶颈才做）；
- session id u16（再省 2 B/帧，但触碰 id 生命周期）；
- 更激进的分片策略（例如按 flow 的 FEC 自适应）。

---

## 7. 验证计划

### 7.1 单元/兼容

- 每个帧的 golden bytes（v4/v6/domain、flow 0/非 0、inline/compressed、train 1/2/64 项）；
- 解码器 fuzz/截断测试：任意前缀不得 panic；未知类型只丢一帧；
- 跨版本：
  - 新 server + 旧 client（旧 client 不发 HELLO → 保持 MQP-2）；
  - 新 client + 旧 server（HELLO 被丢弃 → 保持 MQP-2）；
  - CAPS/HELLO 丢失 → 不黑洞、可重试。
- flow 生命周期：
  - 同目的地复用、fanout、源端口变化、full-cone unsolicited、flow 表满 reject、
  - session close 后 id 重用（3 s 窗口内禁止）、分片与 flow 交叉。

### 7.2 端到端

在 `examples/hotpath_bench.rs` 增加/复用：
- `udpdomain` / `udpdomainmulti`（域名目标）；
- 新增 `udpfanout`：一个 association、N 个目的地、每包轮转（覆盖 TRAIN/flow）；
- `udpps` / `udppaced`（高 pps 小包）；
- `udpmulti`（多 association）；
- `lat` / `lattcp`（延迟回归）；
- `bulk`（吞吐回归）。

用 `tc netem loss 1%` 验证分片/FEC；用 `perf stat`（context-switch、cycles、instructions）
和 `strace -c` 确认 send 调用/系统调用数量；用 `tcpdump -s 0 -w` 或用户态计数器核对 wire bytes。

### 7.3 目标机

Linux 2~4 核（OpenWrt/路由器形态）是重点：协议收益主要来自“少调用/少字节”，
而 macOS 上 `pin_to_core` 是 no-op、内核路径也不同，不能作为最终结论。

---

## 8. 反方观点与风险

1. **“quinn 已经合包了，MQP batch 没意义”**：对**包数**确实如此；对**每次 send 的 state 锁、
   分配、driver wake**不是。协议 TRAIN 的收益主要是后者；如果 profiling 显示 send 调用不是热点，
   MQP-3 的 CPU 价值会下降。
2. **“头压缩的同步状态很麻烦”**：确实。本设计用“首帧内联 + 收到回包/ACK 才压缩 + 表满 inline”
   避免黑洞；代价是纯上行 flow 需要 1 个 ACK，或者前 N 帧 inline。
3. **“flow 表是新内存攻击面”**：有界 + 只在认证连接内 + 表满 reject + session 销毁释放；
   最坏 8192 sessions × 64 flows × 64 B ≈ 32 MiB，可纳入 admission 计算。
4. **“跨 session train 更彻底”**：quinn 已经合包；跨 session 需要连接级共享队列，
   会引入一次队列 hop（延迟/锁），收益不确定，第一版不做。
5. **“FEC 应该默认开”**：2 片 +1 parity 是 +50% 字节；小 F 不划算。默认关，按部署 opt-in。
6. **“协议重设计能提升吞吐”**：不能。吞吐由 QUIC CC + 窗口 + MTU 决定；MQP 头在 bulk 里 <1%。
   如果目标是吞吐，先做 MTU/窗口。
7. **“默认 ALPN h3 下无法保证版本”**：CAPS 是 in-band 能力协商，正好解决这个问题；
   需要 fail-closed 的部署再显式 ALPN bump。

---

## 9. 最终建议

- **不要把“重写 MQP-2”作为吞吐优化**：它已经接近该做的极限；bulk 路径的瓶颈在 QUIC/内核/线程拓扑，
  不在 12 B 头。
- **先做 Phase 0**：客户端 N-pack、batch 预算化、MTU。这三项不改 wire、风险低，
  能拿到同目的地小包的大部分 CPU 收益。
- **如果目标包含多目的地/域名/高 pps/受限上行**，再做 **MQP-3 Phase 1**：
  flow 化（地址只出现一次）+ TRAIN（跨 flow 合帧）+ 紧凑 FRAG + CAPS 灰度。
  这是当前协议结构下**唯一能同时降低 wire bytes 和 send 调用数**的方向。
- **Phase 2 的 SESS_CLOSE** 对短会话 churn 的资源回收价值独立于性能，建议一起排期。
- **FEC/NACK、跨 session train、session id u16** 都留到有测量证据之后再决定。

---

## 附录 A：模型参数与复算

- 每 packet 固定开销 55 B = IPv4 20 + UDP 8 + QUIC short header（1 flags + 8 DCID + 2 PN + 16 AEAD）。
- DATAGRAM body 预算 1162 B（MTU 1200，quinn 已扣 QUIC 开销）；MQP IPv4 单帧 payload 上限 1150 B。
- 每个 MQP 帧的 QUIC DATAGRAM 头 = 1 + varint(len)；≤63 B body 为 2 B，否则 3 B。
- 当前上行按 2-pack；服务端下行按同源 run、≤16 项、≤512 B。
- MQP-3 按 sess u32：SINGLE 5 B / 带 flow 6 B；TRAIN 6 B + 2 B（同 flow 项）/ 3 B（异 flow 项）；
  FRAG 11/12 B；首帧 inline 地址另计。
- 复算脚本：分析时用 Python 对上述帧长逐包装箱（1162+9 B 上限）后求和；本文表格即为该脚本输出。
  脚本未提交到仓库，避免把“分析假设”固化成产品代码。

## 附录 B：与 `PERF_ANALYSIS.md` 的关系

| 本文项 | 与代码级报告的关系 |
|---|---|
| P2 客户端 2-pack | 即 PERF_ANALYSIS 的 **F8**（deferred）；本文把它列为 Phase 0 第一项 |
| P2 服务端 source-change flush | 对应 `reader.rs` 的 `staged_src`；本文建议用 TRAIN 解除该约束 |
| P3 分片头 | PERF_ANALYSIS 的 F4/F13 是**重组器 CPU**；本文是**wire 头**，两者独立 |
| P4 控制面 | PERF_ANALYSIS 未覆盖；属于协议/生命周期，不是热点 |
| §2.5 固定成本 | 对应 PERF_ANALYSIS §4“已确认优化到位、不建议动”的分配/quinn 锁结论 |
| MTU | 配置项，PERF_ANALYSIS 明确不分析配置；本文单独列为 Phase 0 |
