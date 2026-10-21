# MQP-3 重构可行性深度分析（wire rev2 · 仍名 MQP-3）

> 分析日期：2026-10-21 · 基线：`d2f9658`（v0.2.0，工作区干净）
> 范围：**MQP-3 UDP 数据面**（QUIC DATAGRAM）。TCP 走 QUIC stream，协议层无帧头，本文只在“为什么 TCP 不参与重构”处讨论。
> 方法：5 路并行只读深读 + Lead 综合（`analysis/mqp3-refactor/01-wire.md` … `05-evidence.md`），
> 所有收益数字都是**模型/源码算术**，不是目标机实测；证据分级见 §1.2。
> 命名约束：重构后的协议**仍叫 MQP-3**；wire 版本号只存在于控制面 `CAPS.wire_ver=2`，**不出现 “MQP-4” 字样**。
> 交互协议：用户已明确允许 wire 不兼容、新协议仍名 MQP-3、上行下行都要优化、要实现全双工。

---

## 0. 结论（TL;DR）

**一句话：MQP-3 确实还有空间，但空间是不均匀的——最大的一块在“域名目标”，其次在“单向/稀疏流、多 association、大包/分片、全双工入站”，而不在 bulk 吞吐。重构值得做，但应把它定位为“清掉结构性税 + 补控制面 + 真正全双工”，不能指望它把 bulk 吞吐提高一个量级。**

1. **现状比旧文档描述的更好，也比旧文档描述的更受限。**
   - 已落地：`SINGLE`/`TRAIN`、flow 0 隐式、同 burst 小包上行/下行合帧、下行混源 TRAIN、隐式 ACK（收到压缩下行帧才压缩上行）。
   - 未落地/结构性缺口：域名目标**双向永远 inline**；纯上行 flow 跨 TRAIN 重新 inline；`>512 B` 全部退回 MQP-2；v3 紧凑 FRAG codec 已写但零接线；**没有控制面**（无 CAPS/HELLO/FLOW_ACK/FLOW_CLOSE/SESS_CLOSE）；TRAIN 头带唯一 `sess u32`，**一帧只能一个 session**；每 session 一套 socket/task/暂存器，下行无法跨 session 合帧。
2. **协议层可兑现的最大收益（模型，IPv4/MTU1200）：**

   | 工作负载 | 现状 | wire rev2 | Δwire | Δsend 调用 | 证据等级 |
   |---|---|---:|---:|---:|---:|---|
   | DNS-over-SOCKS 域名查询（L=11，50 B，1 包/burst） | 129 B/payload | 109 B | **−15.5%**；域名 L=30 时上行 **−37.3%**、下行 v4 −13.1% / v6 −25.9% | 0 | 模型 |
   | 域名目标**下行回包**（首帧绑定后压缩） | 13 B 头/帧 | 5–6 B | v4 **−7~−8 B/回包**、v6 **−19~−20 B**；小包帧体 −7~−38% | 0 | 模型 |
   | 纯上行稀疏流（100 B，IPv4 / IPv6） | 170 / 182 B | 160 B | **−5.9% / −12.1%** | 0 | 模型 |
   | 高速同 flow 小包（60 B，18 项 TRAIN） | 65.9 B | 64.2 B | **−2.7%** | −5.4% | 模型 |
   | 32 session × 60 B（多 association 小包） | 71.4 B | 65.8 B | **−8.0%**（条件性） | **−93.8%** | 模型 |
   | VPN 1200 B（MTU1200，2 片） | 1352 B | 1325 B | −2.0%（协议）；**+ 配置 MTU1400 → −6.1%** | 0 | 模型 |
   | bulk TCP / bulk UDP | — | — | **≈0**（MQP 头 <1–3%） | 0 | 模型 |

3. **“大幅提高性能”要分清目标：**
   - 若目标是 **bulk 吞吐/大流量下载**：**不要为它重构协议**。MQP 头在 1200 B 包里 <1–3%，重写最多约 1–2%；真正 10–30% 来自 `initial_mtu`、窗口/BDP、同线程化、减少分片和丢包——这些是传输配置/实现，不是 wire。
   - 若目标是 **受限上行、DNS/域名、多 association、多 flow 扇出、VPN 小包、入站/服务器主动流**：重构有真实收益，见上表；域名类尤其明显。
   - 若目标包含 **全双工**：QUIC 传输层本来就是全双工；缺的是 MQP 状态的对称性、控制面和调度。这部分收益是“能力/公平/尾延迟”，不是吞吐倍增器。
4. **推荐路线：分阶段做“MQP-3 wire rev2”（候选 B：连接级 flow id + 对称双向所有权 + 完整 CTL 面），而不是一次性推倒。**
   - **Phase 0（先做，不改 wire）**：补测量（帧数/包数、send 调用、压缩率/回退率）、补 `udpfanout`/`udpbidir` 基准、按部署设 `initial_mtu`（已知路径 1360/1400）、修同线程化/线程拓扑（F10/F3）并 A/B、server 侧 per-class transport 不对称问题。
   - **Phase 1（wire rev2 核心，不兼容）**：控制面（HELLO/CAPS/FLOW_ACK/REJECT/CLOSE/SESS_CLOSE，走一条 QUIC bidi 流）+ 连接级 flow id（u16，client/server 半区）+ 去 `sess u32` + 全尺寸 DATA/TRAIN/compact FRAG + 域名/纯上行压缩。**名字仍是 MQP-3**。
   - **Phase 2（结构/全双工）**：连接级 stager（上行+下行）+ 跨 session TRAIN（依 Phase 0 测量决定）+ 服务端主动 flow（full-cone）+ 每 flow 公平/优先级。
   - **Phase 3（可选）**：B′ 1 B 短头、可协商重组上限、FEC/NACK opt-in。
5. **核心判断：** 如果只做一件“对大多数真实代理流量有确定性收益”的事，不是重构 wire，而是 **Phase 0 的 MTU/拓扑/测量**；如果要做“协议重构”，第一优先级是 **域名 flow 压缩**（上下行同时 −15~−38%），其次是 **控制面 + 全尺寸 v3 + 紧凑 FRAG**，最后才是 **跨 session 合帧**（收益依赖 quinn 合包率实测，工程最大）。
6. **需要用户拍板的问题**见 §9。最重要的三个：① 目标函数（受限上行带宽 / 每核 pps / 尾延迟）排序；② 是否接受同版本部署、完全放弃与 v0.2.0 对端共存；③ 控制面能否用 QUIC bidi 流（而不是 DATAGRAM）。

---

## 1. 分析口径与证据分级

### 1.1 数据路径与字节层

```text
UDP app payload
  → MQP-3 帧（SINGLE / TRAIN / FRAG；每帧一次精确分配，交给 quinn）
  → quinn DATAGRAM frame（1 B type + 1–2 B varint len）
  → QUIC packet（short header：1 flags + 8 DCID + 2 PN + 16 AEAD = 27 B）
  → UDP 8 B + IPv4 20 B（IPv6 +20 B）
```

固定成本（IPv4）：**每 QUIC packet 55 B**；DATAGRAM 预算 = `max_datagram_size()` ≈ MTU − 38
（MTU 1200 → 1162 B；MTU 1400 → 1362 B；MTU 1472 → 1434 B）。
多个 `send_datagram()` 在同一个 transmit poll 内排队时，quinn 会把多个 DATAGRAM frame 合进同一个
QUIC packet（`PROTOCOL_ANALYSIS.md` 已用 quinn-proto 源码确认；本仓库 quinn 0.11.12 / proto 0.11.19）。
因此：

- **TRAIN 的主要收益不是“省 IP/UDP 头”（quinn 已经合包），而是少 MQP 头、少帧分配、少 quinn state 锁/wake**；
- **包数由“发送时机 + quinn 合包”决定**，不由 MQP 帧格式单独决定；
- 任何“按 payload 算 wire”的表格都必须声明“quinn 合包生效/不生效”两个界。

### 1.2 证据分级（全文统一）

| 等级 | 含义 | 本文用例 |
|---|---|---|
| **[L实测]** | Linux 目标机实测 | **本仓库不存在任何 MQP-3 端到端 Linux 目标机测量**；唯一性能类 Linux 数据是 `8eebdca` 的窄范围容器 A/B |
| **[M实测]** | macOS 开发机实测（loopback/微基准） | frame_bench 帧池否决表、BATCH N-pack 原型 parity、u16 fragment id 丢包悬崖、sharded egress +16%、慢路径 +8.8% |
| **[模型]** | 源码常量 + wire 算术 + 单次成本×频率推导 | 本文绝大多数收益数字（含 §0 表） |
| **[代码事实]** | 静态可复核 | 帧格式、常量、状态机、per-session task 模型 |

**结论：本文所有“可兑现收益”必须理解为方向与量级，落地前必须在 Linux 2–4 核目标机用
`hotpath_bench` + `tc netem` 复测；macOS loopback 的数字（同一 harness 出现 0.30/0.98/0.236 ms
三种 p50）不能作为跨版本基线。**

### 1.3 已否决、不要重提的设计

来自 `05-evidence.md`（每条都有历史测量/人工结论；新分析不要重复计账）：

1. 帧缓冲池（`frame_bench`：同线程 +39–52%，跨线程 +128–324%，全部更慢）；
2. 客户端 BATCH N-pack（原型 parity 后回退；已被 MQP-3 `PendingTrain` 覆盖）；
3. 服务端下行 BATCH / source-run flush（已被 v3 TRAIN 混源取代）；
4. `fragment id` 改回 u16（历史 1k/4k/21.8k payload/s 下 4%/15%/50% 丢包悬崖）；
5. 改默认 MTU（1400→1360→1200 已定案；MTU 属部署配置，不进 wire 格式）；
6. fragment train（每片接近 MTU，包数不减）；
7. FEC/NACK 默认开启（2 片 +1 parity = +50% 字节；只可 opt-in）；
8. 为 bulk 吞吐重写协议（MQP 头 <1–3%）；
9. 跨 session TRAIN **无条件**作为收益项（必须先测 quinn 合包率/send 锁，否则只算 1–3%）；
10. 假设域名目标已经能省 33–38%（HEAD 域名双向 inline，必须先把 ACK/绑定做出来）。

---

## 2. 现状 MQP-3 的真实水平

### 2.1 生产路径

| 帧 | 线上布局 | 稳态头（IPv4） | 现状用途 |
|---|---|---|---|
| `SINGLE 0x10` | `kind/flags | sess u32 | [flow u8] | [addr] | payload` | **5 B**（flow 0）/ 6 B（额外 flow） | ≤512 B 且不能进 TRAIN 的单条；大包回退 |
| `TRAIN 0x20` | `kind/flags | sess u32 | count u8 | item*` | 6 B + 同 flow 2 B/项、异 flow 3 B/项 | 同 session、同一 drain burst 的小包 |
| `FRAG 0x30` | `kind/flags | sess u32 | [flow u8] | id u32 | idx | total | [addr] | chunk` | 11/12 B（codec 已实现） | **未接线**；生产仍用 MQP-2 `0x05`（11 B + full addr = 18/30/15+L B/片） |
| `CTL 0x40` | 仅常量 | — | **无实现** |

关键常量（`src/mqp/v3.rs`）：`MQP3_MAX_FLOWS = 64`、`MQP3_MAX_TRAIN_ITEMS = 64`、
`MQP3_FLOW_TABLE_MAX_BYTES = 4096`、`MQP3_NO_FLOW = 0xff`。
地址长度：IPv4 7 B、IPv6 19 B、域名 `4+L`（`src/mqp/addr.rs`）。
flow id 单调分配、会话存活期**永不复用**；表满回退 `NO_FLOW` inline。

### 2.2 已经做得好的部分（重构不应破坏）

1. **同 session 小包合帧已接近该模型下限**：饱和 60 B 上行已是 ~65.9 B wire/payload、
   **55.6 次 `try_send_datagram`/1000 payload**（旧文档“2-pack”结论已过期）。
2. **零分配热路径**：每帧一次精确容量 `Vec` + `Bytes::from`（exact-fit 快路径）；
   帧池化已被测量否决。
3. **下行混源 TRAIN**：同一 session 的多目标回包可混装一帧；下行 `run=1` 发 SINGLE。
4. **隐式 ACK**：收到压缩下行帧才压缩上行，避免首帧丢失黑洞；这套语义在新协议中应保留。
5. **安全不变量**：逐帧 SSRF/allowlist 鉴权、flow 只在真实发送成功后才安装、
   full-cone opt-in、协议上限（8 KiB 重组、2 s partial、256 KiB/连接）。

### 2.3 现状的三个“税”

| # | 税 | 现状代价 | 根因 |
|---|---|---|---|
| T1 | 每帧 `sess u32` | 4 B/帧；稳态 5–6 B 头中占 4 B | 数据面以 session 为第一等地址 |
| T2 | 域名/换端口/full-cone 永远 inline | `1+4+1+(4+L)+payload`；L=30 时 40 B 头 | 服务端 flow 表存的是 `TargetAddr::Domain`，`flow_for_ip` 只匹配 IP；客户端没有解析后 IP；无绑定/ACK 机制 |
| T3 | `>512 B` 掉出 v3 | v2 单帧 12/24 B 头；分片 18/30 B/片；每片独立 send/分配 | v3 FRAG codec 未接线 + 512 B fate-sharing 上限 |
| T4 | 一 TRAIN 一 session | 多 association 时每 session 各自一帧 | TRAIN 头唯一 `sess`；暂存器/reader task 也是 per-session |
| T5 | 无控制面 | 无 CAPS/ACK/CLOSE；纯上行 flow 跨 TRAIN 重新 inline；64 flow 用满后永久退化；短会话 180 s 才能回收 | 设计按“同版本部署、无控制面”落地 |

> 反直觉但重要的修正（`02-uplink.md` §0.5）：纯上行 flow **并非“每帧带地址”**。
> `open_mask` 让同一 TRAIN 内同一 flow 只有第一项 inline，后续项压缩；真实代价是
> “每个 TRAIN 一次 inline open”。只有低速率（1 包/burst）才退化为每帧带地址——
> 这决定了 `FLOW_ACK` 的收益排序：稀疏流 −6~−14%，高速流只有 −2% 量级。

---

## 3. 改进空间的上限：按层拆解

把“一个 UDP payload 的线上成本”拆成 5 层，能清楚看到协议能碰哪一层、天花板在哪：

| 层 | 成本 | 协议能否改变 | 结论 |
|---|---|---|---|
| L0 IP/UDP/QUIC packet | **55 B/包**（IPv4）+ 8/20 B IPv6 | **不能** | 小包单帧时占 ~42%（60 B）~61%（28 B）；只能靠“多 payload 同包/合帧/更高 MTU”摊薄 |
| L1 QUIC DATAGRAM frame | 2–3 B/帧 | 能（少帧） | TRAIN 把 N 帧变 1 帧；跨 session 合帧同理 |
| L2 MQP 头 | 5–6 B/帧；域名 +4+L；分片 18–30 B/片 | **能**（本文核心） | 稳态下限 ≈ 2 B（kind/flags 1 B + flow id 1 B）；分片下限 ≈ 5–8 B |
| L3 协议语义 | 每帧 sess、单 session TRAIN、无 ACK/close、地址重复 | **能**（需要不兼容 wire） | 域名/单向/多 session/大包/生命周期 |
| L4 实现/架构 | per-session socket/task/暂存器；每 session 1 recv syscall + 1 唤醒；1 MiB DATAGRAM 缓冲无公平性 | 不能靠 wire 单独解决 | 连接级 stager/reactor 是 CPU 与公平性的落点 |

**由此得到三个硬结论：**

1. **bulk 没有协议空间。** 1200 B payload 在 MTU1200/IPv4 2 片场景下 MQP 头占 payload 2.9%
   （36/1236），v6 4.8%（60/1260）；即使把稳态头从 5 B 降到 2 B、分片头从 18 降到 8，
   总 wire 只降 **1–3.5%**。吞吐由 QUIC CC/窗口/MTU/EDT 决定。
2. **小包/域名/多会话的协议空间真实存在，但天花板也有限。** 单帧 60 B 的 MQP 头 5 B 降到 2 B，
   独占一包时 wire −2.5%；TRAIN 已把同 flow 的项开销压到 2 B/项，再优化只剩 1 B/项量级。
   最大的单笔是**域名地址的 4+L B**（L=11 时 15 B，L=30 时 34 B）——这需要控制面/绑定，不是简单改帧格式。
3. **“全双工”不是吞吐倍增器。** QUIC 两方向独立 CC/PN/丢包恢复；传输侧真正的耦合只有
   同 driver task/state 锁/核、反向 ACK 带宽（0.6–2.9%）、同方向共享 cwnd。
   全双工的收益是**入站/服务器主动流可压缩、纯上行可压缩、双向公平调度、可验收**
   （D1–D6，§4），不是“两个方向各 100% 带宽”。

---

## 4. 全双工：定义、现状差距、验收

### 4.1 传输层事实：QUIC 本来就是全双工

- 两个方向独立包号空间、独立拥塞控制、独立丢包检测/PTO/RTT；
- DATAGRAM 两方向都可发；一条 QUIC 连接天然双向并发；
- 真正的跨方向耦合只有：同一个 connection driver task / state 锁 / 同一个核、
  反向 ACK 流量（占带宽 0.6–2.9%）、以及同方向内所有 flow 共享一个 cwnd 与一个 1 MiB DATAGRAM 缓冲。
- 结论：**“实现全双工”不是改传输，而是把 MQP 的状态机/控制面/调度做成对称**。

### 4.2 推荐定义：MQP-3 全双工 = D1–D6

| 编号 | 定义 | 现状差距 |
|---|---|---|
| **D1 数据面对称** | 任何帧类型（DATA/TRAIN/FRAG）可在两个方向发送；编解码不区分方向 | 帧格式本身对称，但下行受“flow 必须先由上行 open”限制；full-cone/服务端主动流没有压缩路径 |
| **D2 状态面对称** | 每条 session 在每个端点为“本端发送方向”和“本端接收方向”各维护一张 flow 表；id 由发送方分配；两端都能 open/close | 当前 flow 表是 **client 单方所有权**，server 只镜像；server 不能自造 flow id；客户端 `confirmed` 是单向位图 |
| **D3 控制面双向** | 控制通道双向可用（建议一条 QUIC bidi 流），承载 CAPS/HELLO/FLOW_ACK/REJECT/CLOSE/SESS_CLOSE/优先队列/信用 | **完全缺失**（`0x40` 只是保留常量） |
| **D4 无方向依赖** | 任一方在对方尚未在本方向发送 payload 时也能压缩/确认（纯上行流由 FLOW_ACK 确认；server push 由 server 半区 id open） | 纯上行 flow 跨 TRAIN 重新 inline；server 不能 push；域名永远 inline |
| **D5 独立调度** | 每方向独立做 TRAIN 打包、MTU 预算、优先级/加权调度；跨方向耦合只允许共享连接/CC，不允许共享“必须等对方”的状态 | 下行 per-session stager 无法跨 session；1 MiB DATAGRAM 缓冲 FIFO 无公平性，一个高速 flow 可让同连接其他 session 被 `Blocked` 丢包 |
| **D6 可测** | 新增 `udpbidir` 基准：双向同时跑，验收“双向合计 ≥1.6× 单向、p99 劣化 ≤10%、无静默丢包” | 当前 harness 没有双向模式 |

### 4.3 全双工的收益边界

- **不是**：把 bulk 吞吐翻倍；替代可靠性；让两方向各占满 100% 带宽。
- **是**：入站/服务器主动流（full-cone、P2P、推送）可压缩（模型 −4~−18% 小包 wire，
  v6 更明显）；纯上行流可压缩（稀疏 −5.9% v4 / −12.1% v6）；多 session 公平调度；
  生命周期控制；可验收的对称性。
- 传输耦合的收益（同线程化/每连接聚合）属于 CPU/尾延迟项：模型 −3~−15% CPU
  （`04-transport.md`），而不是带宽项。

---

## 5. 重构后的 MQP-3（wire rev2）设计

> **实施修订（2026-10-21）**：正式实施契约已落到 [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md)，codec 已实现于 `src/mqp/r2.rs`。为让旧 v2/v3 解析器安全丢弃 rev2 帧，实际首字节改为 `0x0X`（高 4 bit = 0，且避开 0x02/0x05/0x06），不再使用 `0x1X/0x2X/...`；flow id 改为**连接级 u32 单调、不复用**（彻底去掉 u16 复用/tombstone 风险）；`TRAIN dict` 头为 `4 B + nfl × idvarint`。下文帧表保留为设计背景，冲突处以 SPEC 为准。

> 本节是“候选 B：连接级 flow 命名空间 + 对称双向所有权 + 完整 CTL 面”的落地规格。
> 候选 A（保留 `sess u32` 的增量方案）作为低风险子集在 §5.11 对比；候选 C（u16 sess 折中）已否决。

### 5.1 目标与非目标

**目标**
1. 稳态数据帧头接近下限：**2–3 B**（无 `sess`，flow id LEB128 1–2 B）；
2. 一个 DATAGRAM 可混装 **不同 session/flow** 的 payload（TRAIN dict 模式）；
3. 域名目标、换端口源、full-cone 源双向都可压缩；
4. 纯上行/单向流可由 ACK 进入压缩态，不依赖对方发数据；
5. 大包与分片统一进 v3（不再有 v2 数据面 / 512 B 截断）；
6. 控制面：版本门禁、显式 ACK/REJECT/CLOSE、会话生命周期；
7. 安全/资源边界不弱于现状；名称仍是 MQP-3。

**非目标**
- 不改 TCP（QUIC stream）；
- 不改 DATAGRAM 不可靠语义；
- 不默认引入 FEC/重传；
- 不为 bulk 吞吐而改（见 §6.5）；
- 不引入 HPACK 式动态字典（flow 绑定已足够）；
- 不做 fragment train（近 MTU 分片时包数不减）。

### 5.2 命名与版本门禁

- 协议对外仍叫 **MQP-3**；数据面/文档/日志不出现 MQP-4。
- 控制面 `HELLO`/`CAPS` 携带 `wire_ver=2`；**不匹配 → 关闭连接并给出明确错误码**（同版本部署）。
- 默认 ALPN 保持 `h3`（伪装特性）；需要硬门禁的部署可选 ALPN `myquic2/3`。
- 老客户端 / 老服务端：新服务端收到老 v3 帧仍可保留一版只读解码做诊断；新客户端连老服务端时
  HELLO 无响应 → 超时失败（不做静默降级，因为 wire 已不兼容）。**本次重构不承诺混合版本运行。**

### 5.3 命名模型：连接级 flow id + 对称半区

```text
连接（QUIC）
 ├── session（UDP association；只在 open/CTL 出现 u32 完整 id）
 │    └── flow = (session, target, 方向归属)
 │          ├── client-owned id：0x0001..0x7FFE   （客户端分配，server 镜像）
 │          └── server-owned id：0x8001..0xFFFE   （服务端分配，client 镜像）
 └── flow id 0x0000 = inline/no-flow（表满、一次性源、诊断）
```

- **id 编码**：u16 值使用 LEB128；常见活跃 id <128 → **1 B**；`HI` flag 表示服务端半区，
  解码时 `id |= 0x8000`（实际编码 `id-0x8000`，仍是 1 B）。
- **两个半区**让两端都能独立 open/close，不需要协调 id 分配；`0x7FFF`/`0xFFFF` 保留。
- **open 帧自描述**：`OPEN` flag + `sess u32` + `addr`。首帧仍 inline（不增加首包 RTT），
  重复 open 幂等；同一 id 不同 `(sess,addr)` → 丢弃并计数（防串流）。
- **确认**：任一方向的压缩帧隐式确认（收到即证明对端已安装映射）；纯上行/单向由控制面
  `FLOW_ACK` 显式确认；`FLOW_REJECT` 表示策略/表满/DNS 失败，客户端回退 inline。
- **关闭/复用**：`FLOW_CLOSE` 后 id 进入 tombstone，**≥3 s**（= 2×FRAG_TIMEOUT + sweep，
  与 `FRAG_ID_SAFE_WINDOW_MS` 同一论证）才可复用；id 耗尽回退 `DATA INLINE`。
- **表上限**：每连接 `max_conn_flows`（建议 4096，CAPS 协商）+ 每 session 64（或协商值）；
  超限走 inline/REJECT；内存按 admission 计费（当前 4 KiB/session 的记账模型要同步更新）。

### 5.4 数据帧（双向同一套）

首字节：高 4 bit kind，低 4 bit flags。**数据帧不再携带 `sess`**（`sess` 只在 OPEN/CTL）。

| 帧 | 布局 | 稳态头 | open 头（IPv4/IPv6/域名） | 说明 |
|---|---|---|---:|---|
| `DATA 0x10` | `0x1X | idvarint | [sess u32 + addr if OPEN] | payload` | **2 B**（id≤127）/3/4 | 13 / 25 / 40 | 无长度字段，payload = DATAGRAM 剩余 |
| `DATA INLINE 0x12` | `0x12 | sess u32 | addr | payload` | — | 12 / 24 / 39 | 表满/一次性源 fail-safe，≈v2 单帧 |
| `TRAIN same 0x21` | `0x21 | count u8 | idvarint | item*`；item = `len varint | payload` | header **3 B**（id≤127；2 B id 则 4 B）；item **1–2 B** | — | 整帧同 flow、全部压缩；小包下限形态 |
| `TRAIN dict 0x22` | `0x22 | count u8 | nfl u8 | idvarint[nfl] | item*`；item = `idx u8 | len varint | payload` | header **3+nfl**（id≤127）；item **2–3 B** | — | 混合 flow；**item 可跨 session**（flow→session 在表里） |
| `FRAG 0x30` | `0x3X | idvarint | frag_id u32 | idx u8 | total u8 | [sess u32 + addr if OPEN] | chunk` | **8 B**（id≤127），open 首片 19/31/46 | — | key = `(flow, frag_id)`；重组上限沿用现状 |

**关键行为**
- `TRAIN same` 是一等公民：60 B payload 时 `3 + N×(1+60)`，比现状 `6 + N×(2+60)` 每项省 1 B、
  帧头省 2 B；这覆盖“单 flow 高 pps”的主流场景。
- `TRAIN dict` 的首部含 **flow 字典**（`3+nfl` 字节，nfl 个 id），item 用 1 B idx 引用；比“每项带 id”省 1 B/项，
  适合 8–32 flow 扇出；跨 session 时由 flow 表解析 session。
- 首帧 OPEN 的字节数与现状 inline 相同（v4 13 B / v6 25 B / 域名 40 B 起），**没有首包惩罚**。
- 解码器必须在解析前校验：帧长 ≤ `max_datagram_size()`、id 在协商范围、count ≤ 协商上限、
  每项 len ≤ min(8192, 剩余)、TRAIN 精确吃到帧尾、未知 kind/opcode/保留 flag → 计数丢弃不 panic。
- **不采用**：1 B 短头（B′）、`sess u24`、12/20-bit 拆位——都是 <1 B/帧的 cosmetic；
  kind 空间预留，Phase 3 再评估。

### 5.5 控制面（一条 QUIC bidi 流）

| opcode | 方向 | 内容 | 语义 |
|---|---|---|---|
| `0x01 HELLO` | C→S | magic `M3` + `wire_ver u16` + flags | 连接建立后立即发；不匹配 → 关闭 |
| `0x02 CAPS` | S→C | ver + flags + max_conn_flows + max_flows/session + max_train_items + max_reassembly + 能力位 | 服务端能力；可重发 |
| `0x10 FLOW_ACK` | 双向 | `sess u32 | id | status | [resolved addr]` | 安装成功/纯上行确认/域名解析结果 |
| `0x11 FLOW_REJECT` | 双向 | `sess u32 | id | reason` | 策略拒绝/表满/DNS 失败；客户端回退 inline |
| `0x12 FLOW_CLOSE` | 双向 | `sess u32 | id` | 释放 flow，进入 tombstone 窗口 |
| `0x20 SESS_CLOSE` | 双向 | `sess u32 | reason` | 立即释放 server socket/task/flow 表/permit |
| `0x30 PING` | 双向 | 时间戳/序号 | 可选，QUIC keepalive 已足够时可不做 |

- **可靠性**：走 QUIC 流，由 QUIC 负责重传/排序，控制面不需要自定义 ACK 状态机；
- **幂等**：所有 opcode 允许重复；未知 opcode 跳过该帧（有长度前缀），不 panic；
- **有界**：单帧 ≤ 512 B、流上速率/总量受限、解析前长度校验；控制流是**不可信输入**；
- **与数据面的顺序**：控制流与 DATAGRAM 彼此独立排序；因此**首帧数据必须自描述**（OPEN），
  不能依赖“先收到 OPEN 再收到 DATA”。这保留现有“首帧 inline、后续压缩”的安全语义。
- **为什么不用 DATAGRAM 做控制面**：需要自己做重传/去重/顺序；而控制帧低频、小、幂等，
  一条 bidi 流最省事、最可靠。若未来要“控制面也不可靠”，可加 CTL DATAGRAM 作为 hint，
  但正确性不依赖它。

### 5.6 压缩与确认：双向绑定语义（本设计最重要的行为变化）

现有隐式 ACK 只覆盖“有下行数据”的 flow。rev2 把“绑定”做成双向对称：

```text
上行（client→server，域名目标为例）
  C --DATA OPEN(sess, flow=5, domain, payload)--> S     # 首帧 inline，0 额外字节 vs 今天
  S: 解析/SSRF/建 session socket/发送；安装 flow->(session, domain, resolved_ip)
  S --CTL FLOW_ACK(sess, 5, [resolved_ip])-----> C     # 纯上行也确认；域名带解析结果
  C: 进入压缩态
  C --DATA(flow=5, payload)-------------------> S     # 2 B 头
  S: 回包来源 == resolved_ip? 是→压缩；否→首帧 inline 绑定（见下）

下行（server→client，域名/换端口/full-cone 为例）
  S --DATA(flow=5, INLINE actual_src)---------> C     # 与今天 NO_FLOW inline 同为 13 B，0 成本
  C: 记录 flow->reply_src（这是写 SOCKS5 reply header 的地址，行为与今天一致）
  C --DATA(flow=5, payload)-------------------> S     # 客户端的下一条压缩上行帧 = 隐式 ACK
  S: 转压缩；源漂移（多 A/anycast/端口变化）→ 重新发一次 INLINE 绑定帧，退回 BindPending
```

- **域名回包**：客户端用**首次 inline 回包的实际源 IP** 写 SOCKS5 reply header——**不改变现有行为**，
  不需要“把域名回显给 app”这种有争议的语义；`FLOW_ACK.resolved_ip` 只用于**上行**压缩/预判，
  不用于替代实际源。
- **`SRC` flag** 在新协议里正式启用：inline 地址是“实际源”，不是 flow 绑定的目标；用于换端口/anycast。
- **绑定帧丢失**：退化为今天的 inline（不黑洞）；绑定表有 TTL 并随源刷新。
- **安全**：绑定/压缩只改变“源地址怎么表达”，**不扩大可达目标**；逐回包鉴权仍走
  allowlist ring + 精确 flow 回退；`udp_full_cone` 仍是 opt-in；server-owned flow 只在
  full-cone 模式下创建，并计入 unsolicited 统计。
- **纯上行 flow**：`FLOW_ACK` 之后压缩；ACK 丢失只延迟压缩（客户端继续 inline），
  正确性永不依赖 ACK 到达——这与现有隐式 ACK 的保守性一致。

### 5.7 大包与分片：统一进 v3，删除 v2 数据面

- `DATA` 单帧可承载到 `max_datagram_size()`；**513 B ~ 单帧上限**不再退回 v2（省 7/22 B/帧）。
- 超过单帧 → `FRAG`（8 B 头，稳态不再重复地址）；key = `(flow, frag_id)`；
  保留 u32 frag id（历史 u16 丢包悬崖）、8 KiB payload cap、2 s partial、256 KiB/连接预算。
- 首片/新 flow 前几片可带 `OPEN`（inline addr），保证 flow 未确认也能重组；之后压缩。
- **512 B fate-sharing 上限重新谈判**：新协议不再需要“≤512 B 才进 v3”的协议层截断；
  但“一个 TRAIN/包丢失会同时丢多个 payload”的 fate-sharing 风险仍在，应由
  `max_train_items`/`max_frame_bytes` 策略控制，而不是硬编码 512。建议：交互类默认
  `max_train_items=16`、bulk 类可协商更大；跨 session 合帧只对 bulk 类默认开启。
- v2 decoder 保留一个版本用于诊断/大包兼容不需要（wire 不兼容），但**不再有 v2 发送路径**。

### 5.8 会话生命周期与资源账

| 项 | 现状 | rev2 |
|---|---|---|
| 短会话回收 | 180 s idle（`SESS_IDLE_MS`） | `SESS_CLOSE` 立即释放 socket/task/flow 表/permit；idle 仅兜底 |
| flow 释放/复用 | id 永不复用；64 满后永久 inline | `FLOW_CLOSE` + 3 s tombstone 后复用；表满 `REJECT` 回退 inline |
| churn 上限 | >45 association/s 可能吃满 8192 池（268 KiB/session 记账） | 显式 close 后不再积累僵尸；admission 记账随表上限/连接级表更新 |
| 跨 session | 不可合帧 | `TRAIN dict` 可混装（可选，Phase 2） |
| 每连接公平 | 1 MiB DATAGRAM 缓冲 FIFO，无公平性 | 连接级 stager + 每 session/flow 配额（DRR）或优先级类 |

### 5.9 安全与资源不变量（任何实现都必须保持）

1. **逐条鉴权不变**：跨 session/跨 flow 合帧只是装载方式；每个 item 进入 stager **之前**必须已通过
   现有源鉴权（allowlist ring 或精确 flow 回退）。
2. **SSRF 不变**：目标过滤只发生在上行/解析；下行压缩只改“源地址怎么表达”；`allow_private` 语义不变。
3. **flow 安装条件不变**：只在“目标接受了一次真实发送”之后安装（`accepted` 条件）。
4. **连接级 id 不得跨 session 解析**：flow 表项必须携带 session；客户端/服务端逐项用该 item 的 flow
   查自己的表，禁止把 A session 的 id 解析成 B 的源。
5. **full-cone 仍 opt-in**：server-owned flow 只在 full-cone 下创建；unsolicited 统计保留。
6. **不可信输入**：控制流/数据帧解析前全部长度/范围校验；未知 kind/opcode 丢弃不 panic；
   控制流有速率/总量上限；表有界并计入 admission。
7. **id 复用安全窗**：FLOW_CLOSE 后 ≥3 s 才能复用；tombstone 覆盖重组窗口；耗尽回退 inline。
8. **不新增内存放大器**：连接级 flow 表/控制流缓冲都要有硬上限，并纳入 `max_peer_memory_mb` 记账。

### 5.10 可选与后续（Phase 2/3）

- **连接级 egress stager（上行 + 下行）**：每连接一个发送队列/聚合器；session reader/assoc 把 item
  推入，聚合器按路径预算组帧、跨 session 合帧、按 session 配额调度。**这是跨 session TRAIN 和
  D5 公平性的落点**；收益依赖 Phase 0 测量的 quinn 合包率（不合包界 −34%~−61%，理想合包界 −1.6%）；
  CPU 模型服务端 −11~−14%、50k pps ≈1% 单核。**先测量，再决定是否全量。**
- **server-owned flow / full-cone**：服务端首次见到 unsolicited 源时用 server 半区 id + inline 绑定；
  之后压缩（模型 −37% 该场景）。只允许在 `udp_full_cone=true` 下启用。
- **B′ 1 B 短头**：kind 空间预留 `0x50..0x5F` 表示“最近 16 个热 flow”，稳态 1 B；
  收益 60 B 时 −1.6%、28 B 时 −3.3%；属 cosmetic，Phase 3。
- **可协商重组上限**（CAPS）与 **FEC/NACK opt-in**：只按丢包链路实测决定，不做默认。
- **单流 striping/多连接**：只对“单大流 + 高丢包/高 RTT”研究，高风险，不混入协议核心。

### 5.11 候选 A / B / C 对比

| 维度 | A：保留 `sess u32` 增量 | **B：连接级 flow id（推荐）** | C：u16 sess 折中（否决） |
|---|---|---|---|
| 稳态头 | 5/6 → 5/6（只改 CTL/FRAG/大包） | **2–3 B** | 3/4 B（wrap 风险） |
| 域名/纯上行压缩 | ✅（需 FLOW_ACK/绑定） | ✅ | ✅ |
| 大包/紧凑 FRAG | ✅ | ✅ | ✅ |
| 跨 session TRAIN | ❌ | ✅（dict） | 部分（MULTI_SESS） |
| 服务端主动 flow（D2/D4） | ❌ | ✅（半区） | ❌ |
| 全双工 D1–D6 | 部分 | ✅ | 部分 |
| 工程/风险 | 低（增量） | 中高（新命名空间/表/控制面） | 高（id 回绕 + 跨 association 串流风险） |
| 作为 | 低风险子集/回退 | **目标架构** | 不做 |

候选 C 否决理由（`01-wire.md` §6.3）：客户端 session id 是单调 u32、服务端靠 180 s idle 回收；
缩成 u16 后 65,536 次分配即回绕，>364 assoc/s 就可能让新 association 拿到服务端仍认为属于旧
association 的 id → 回包串流。收益仅 2 B/帧，不值得。

---

## 6. 收益量化

### 6.1 统一假设（模型）

- IPv4；MTU 1200 → DATAGRAM 预算 1162 B（另列 1362）；
- 每 packet 固定 55 B、每 DATAGRAM frame 2–3 B；
- 一个 QUIC packet 装一个 MQP 帧，除非注明“quinn 合包/连接级 stager”；
- 无丢包、无 ACK-only 包、无 PMTU 抖动；不含 FEC；
- “send calls/1000” = `try_send_datagram` 次数；TCP 行是 `write_chunk` 次数。
- 详细公式与可复算脚本：`analysis/mqp3-refactor/model.py`、`model-output.txt`；
  交叉验证：`01-wire.md` §7、`02-uplink.md` §6、`03-downlink.md` §3。

### 6.2 分工作负载收益

| 工作负载 | 现状 | rev2 | 变化 | 归因 |
|---|---:|---:|---:|---|
| DNS 域名查询 L=11，50 B，1/burst | 129 B/payload | 109 B | **−15.5%** | 域名 ACK + 压缩（100% 来自地址/flow/sess 字节） |
| 域名 L=30，60 B 上行（wire 报告口径） | 97,564 B/1000 | 61,189 B/1000 | **−37.3%** | 同上；头部 40 B→2 B |
| 域名目标下行回包（首帧绑定后） | 13 B 头 | 5–6 B | **v4 −7~−8 B、v6 −19~−20 B/回包**（wire 报告口径：每 1000 payload v4 −12.8%、v6 −25.7%） | 绑定 + 压缩；小包帧体 −7~−38% |
| 纯上行稀疏 100 B（IPv4 / IPv6） | 170 / 182 B | 160 B | **−5.9% / −12.1%** | FLOW_ACK；v6 地址更贵 |
| 纯上行稀疏 60 B（wire 报告） | 72,000 B/1000 | 62,000 B/1000 | **−13.9%** | 同上 + 稳态头 2 B |
| 高速同 flow 60 B（TRAIN 18 项） | 65.9 B/payload、55.6 calls | 64.2 B、52.6 calls | −2.7% / −5.4% | 帧头 2 B + 项 1 B + 首项 inline 消除 |
| 8 flow 同 session 扇出 200 B | 226 B | 218 B | −3.5% | COMPACT 项/帧头 |
| 32 session × 60 B（1 包/session/burst） | 71.4 B、1000 calls | 65.8 B、62.5 calls | **−8.0% / −93.8%** | 条件性：需要连接级 stager + quinn 合包；worst case 现状 123 B/payload |
| VPN/bulk UDP 1200 B @MTU1200（2 片） | 1352 B | 1325 B | −2.0% | 紧凑 FRAG 8 B vs 18 B/片 |
| 同上 @MTU1400（1 帧，配置） | 1270 B | 1260 B | −0.8% | 协议；MTU 配置本身再 −6.1% |
| bulk TCP 16 KiB chunk | 17,299 B | 17,299 B | **0** | 流上无 MQP 头 |
| full-cone 下行 60 B（server-originated） | 97,564 B/1000 | 61,328 B/1000 | **−37.1%** | server 半区 id + 绑定 |
| 短会话 churn（>45 assoc/s） | 180 s 僵尸 ×268 KiB | 立即回收 | 内存/fd/任务确定性下降 | SESS_CLOSE |

> 表内百分比是“该工作负载类”的 MQP 增量字节节省，不是端到端应用吞吐提升。
> 对 bulk，端到端提升主要来自 MTU/窗口/拓扑（10–30%），MQP 协议 ≤2%。

### 6.3 CPU / send 调用 / 延迟

| 项 | 量级 | 说明 |
|---|---|---|
| 同 association 小包 | 现状已 55.6 calls/1000；rev2 52.6 | 协议只再省 ~5% 调用 |
| 多 association（32 session） | 1000 → 62.5 calls/1000（**−94%**） | 连接级 stager；服务端 CPU 模型 −11~−14%，50k pps ≈1% 单核 |
| 域名 ACK | 不减少调用 | 只改 wire |
| 同线程化（F10，实现） | 0.1–0.3 µs/帧 → 40–50k pps **0.5–1.5% 单核** + 尾延迟 | 不改 wire；Linux `MYQUIC2_SHARD_RUNTIME=0` A/B 后再定 |
| 连接级 stager 新增成本 | 入队/出队 ~0.04–0.08 µs/项 | 需要“排空即发”，不能引入人为等待；交互类默认不跨 session 合帧 |
| 延迟 | TRAIN/绑定不增加等待；fate-sharing 使一次丢包跨 session 相关 | 交互类可配“不参与跨 session 合帧”；p99 验收见 §7 |

### 6.4 fate-sharing / 丢包语义（必须显式接受）

- 一个 TRAIN/QUIC packet 丢失会同时丢 N 个 payload：**期望丢包率不变**（每包 N 条、包数 1/N），
  但**时间上跨流相关**（一次 qdisc 丢包同时命中多个 session/flow）。
- 对 DNS/一次性请求无影响；对 RTP/游戏/交互流，建议：
  - 交互类默认 `max_train_items` 小（16），不参与跨 session 合帧；
  - bulk 类可跨 session 合帧；
  - 提供配置开关（按 flow/端口分类），并在 `udpbidir`/`netem` 下验收 p99。
- 这也回应了仓库对 BATCH “fate-sharing” 的既有顾虑：**期望不变、突发相关、需可配**。

### 6.5 现实检查：哪里能“大幅”，哪里不能

| 目标 | 协议重构能给的 | 真正的大头 |
|---|---:|---|
| bulk TCP/UDP 吞吐 | ≤1–2% | MTU（1200→1400：VPN −6.1%、帧数 2→1）、窗口/BDP、同线程化、丢包恢复；单流天花板只能多连接 |
| 域名/DNS-over-SOCKS | **−15~−38% wire** | 已达到该模型上限；剩下是控制面/语义工作 |
| 受限上行小包 | −2~−14%（看 burst 形态） | 部分已由 TRAIN 拿到；域名/单向是新增 |
| 多 association 小包 | −8~−18% wire + 94% calls（条件性） | 连接级 stager；quinn 合包率决定 wire 落点 |
| 每核 pps / CPU | 1–5%（50–100k pps） | 同线程化/线程拓扑/GSO（传输/实现） |
| 尾延迟/公平 | 改善（stager 调度/配额） | reactor 化（I5）才能消掉每回包唤醒 |
| 生命周期/内存 | churn 与 64-flow 退化确定性修复 | admission/表上限 |

**如果用户所说的“大幅”= bulk 吞吐翻倍：答案是“协议重构做不到”；应转向传输/多连接/MTU。**
**如果“大幅”= 特定工作负载的 wire/调用/资源：域名类 15–38%、多会话 8–18%+94%、全双工入站 4–18%，是真实的。**

---

## 7. 实施路线（分阶段，名称始终 MQP-3）

### Phase 0：不改 wire，先测量 + 拿传输/配置收益（1–2 周量级）

1. **补测量**（所有协议验收的前置）：
   - `try_send_datagram` 帧数/方向；QUIC packet 数（tcpdump/qlog）；每连接帧/包比（决定跨 session 收益）；
   - MQP 帧级计数：kind、TRAIN items、flow 压缩率、inline 回退率、FLOW_REJECT 率；
   - quinn `stats()`：cwnd/rtt/current_mtu/PLPMTU 探测/丢失；
   - 新增 `udpfanout`（1 association × N 目的地轮转）与 `udpbidir`（双向同时）。
2. **传输/配置**（非协议，收益最大且风险低）：
   - 已知路径按部署设 `initial_mtu=1360/1400`（保持默认 1200 不动，避免未知路径黑洞）；
   - 核对窗口/BDP 预设（4/8/4 默认 vs 8/16/8）；
   - 修 server 侧 per-class transport 不对称（server 目前只有 interactive 预设）；
   - `MYQUIC2_SHARD_RUNTIME=0` A/B + 线程拓扑（F10/F3）在 Linux 2–4 核实测后决定。
3. **实现层低风险项**：`last_flow` 多槽 memo/鉴权阶段复用 flow id、run==1 免 arena 拷贝、
   >512 B 直发 v3 SINGLE（先在兼容格式内验证）。
4. **验收**：Linux 2–4 核 + `tc netem`（70/140 ms、0/0.5/2% loss）基线；同机同轮 A/B。

### Phase 1：wire rev2 核心（不兼容；仍名 MQP-3）

1. 控制面 bidi 流：`HELLO/CAPS`（wire_ver=2）+ `FLOW_ACK/REJECT/CLOSE/SESS_CLOSE`；
2. 连接级 flow id（u16，client/server 半区）+ 去 `sess` 的 `DATA`/`TRAIN`/`FRAG`；
3. 全尺寸 v3（删除 v2 发送面）+ 紧凑 FRAG 接线 + `(flow, frag_id)` 重组 key；
4. 域名/换端口/full-cone 绑定 + 双向隐式 ACK + 纯上行 `FLOW_ACK`；
5. flow close/reuse（3 s tombstone）、表上限、admission 记账更新；
6. 命名：代码/文档/日志全部仍称 MQP-3；`CAPS.wire_ver=2` 只是内部版本。

**验收门槛（模型目标，需 Linux 实测）**：
- `udpdomain` 域名类 wire **−15% 以上**（L=11）/ **−30% 以上**（L=30）；
- `udppaced`（1–512 B）p99 不回归 >5%，loss 不增加；
- `udpsweep` 全尺寸（含 8 KiB 分片）正确；
- 纯上行稀疏流 wire −5% 以上（v6 −10% 以上）；
- churn 压测：`SESS_CLOSE` 后 8192 池不因僵尸耗尽；64-flow 退化可恢复。

### Phase 2：结构/全双工（依 Phase 0/1 测量）

1. 连接级 stager（上行 + 下行）：跨 session `TRAIN dict`、每 session 配额/DRR、flush 策略“排空即发”；
2. server-owned flow / full-cone 压缩；
3. 每 flow 优先级/信用（可选，解决 1 MiB DATAGRAM 缓冲无公平性）；
4. `udpbidir` 验收：双向合计 ≥1.6× 单向、p99 劣化 ≤10%、无静默丢包；
5. 多 session 目标：帧/调用/分配 **−90% 以上**（32 session）；wire 视 quinn 合包率取 −8~−34%。

### Phase 3：可选

- B′ 1 B 短头（kind 空间已预留）；
- CAPS 协商更大重组上限；
- FEC/NACK opt-in（只按 netem 实测决定）；
- 单流 striping/多连接研究（高风险，不混入协议核心）。

### 迁移与回滚

- **同版本部署**：协议不承诺与 v0.2.0 对端共存；`HELLO/CAPS` 不匹配即关闭并报错（fail-fast），
  不静默降级。
- 默认 ALPN 保持 `h3`；需要硬门禁的部署可显式 ALPN bump（可选，不影响伪装默认）。
- 每个 Phase 独立 feature/构建开关；Phase 1 之前先落 Phase 0 的基线与计数器，保证每步可 A/B。

---

## 8. 风险、反方观点与未决证据

### 8.1 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| **无 Linux 目标机实测** | 全部收益是模型；macOS loopback 不可外推（GSO/GRO/pin 都不同） | Phase 0 先建 Linux + netem 基线；每项改动同机同轮 A/B |
| 控制面复杂度 | bidi 流、状态机、版本门禁、失败路径 | 控制帧幂等；正确性不依赖 ACK 到达；控制流有界、不可信输入 |
| 域名/SOCKS 语义 | 多 A/anycast/端口漂移；reply header 用哪个 IP | 用“首次 inline 回包的实际源”写 SOCKS 头（保持现状）；resolved IP 只用于上行压缩；源漂移重绑定 |
| fate-sharing | 跨 session 合帧让丢包跨流相关 | 交互类不参与/小 `max_train_items`；bulk 类才开启；netem 验收 p99 |
| 连接级表内存/攻击面 | 每连接 4096 flow 表 | CAPS 协商上限 + admission 记账 + 解析前校验 + 未知 id 丢弃 |
| id 复用串流 | close 后复用可能把旧延迟帧拼到新 flow | 3 s tombstone（覆盖重组窗口）；耗尽回退 inline |
| quinn 限制 | 无 per-flow 调度、1 MiB DATAGRAM 缓冲 FIFO | 连接级 stager/配额在应用层做；不改 quinn |
| 收益被高估 | 旧文档的 2-pack 基线与 −18× 调用已过期 | 本报告改用 HEAD 实际行为；所有数字标 [模型]，给出两个合包界 |
| 版本伪装 | 默认 ALPN `h3` 与 wire 硬门禁冲突 | in-band HELLO/CAPS；需要 fail-closed 才 ALPN bump |

### 8.2 反方观点（必须正面回答）

1. **“quinn 已经合包了，TRAIN/跨 session 没意义”**：对**包数**确实如此；对 MQP 头、帧分配、
   quinn state 锁/唤醒、以及低速率多 session 的合包失败场景，仍有意义（见 §6.3/§6.5）。
   但**跨 session 的 wire 收益必须由 Phase 0 的帧/包比测量决定**，不能先假定。
2. **“全双工只是概念，QUIC 本来就是双向”**：传输层对；协议层不对——纯上行不能压缩、
   server 不能 push、TRAIN 不能跨 session、无控制面。D1–D6 是可实现的对称性，不是营销词。
3. **“重构能大幅提高吞吐”**：不能。bulk 头 <1–3%，重构 ≤2%；真正 10–30% 在 MTU/窗口/拓扑/丢包。
4. **“控制面用 DATAGRAM 更简单”**：需要自己实现重传/去重；控制帧低频小且幂等，QUIC 流更可靠。
   若担心尾延迟，可把“非必须 hint”放 DATAGRAM，但正确性路径走流。
5. **“域名压缩会改变 app 行为”**：不改变——下行仍用实际源 IP 写 SOCKS reply header；
   只有上行地址从 inline 变 flow id，app 不可见。
6. **“先把 512 B 上限去掉就行”**：只做去截断能把 513–1150 B 的 v2 12 B 头降到 5–6 B，
   但真正的大头是域名（4+L B）与 per-frame `sess`；且要重设计 fate-sharing。

### 8.3 尚未回答/需要证据的问题

- quinn 在“多 session、低速率”下的真实合包率（帧/包比）——决定跨 session 收益落点；
- Linux 2–4 核目标机上，send state 锁/跨核 wake 是否真是瓶颈（决定 F10/连接级 stager 优先级）；
- 生产流量中域名目标、>64 flow 长连接、多 association 的真实占比；
- 控制流 bidi 与现有 auth uni stream 的集成成本；
- 目标环境 MTU 分布（1200/1400/1472）与丢包率（决定 FEC/MTU 收益）。

---

## 9. 最终建议与需要拍板的问题

### 9.1 建议

1. **不要把“重构协议”当作 bulk 吞吐优化**；bulk 先做 Phase 0 的 MTU/窗口/拓扑。
2. **如果目标包含域名/DNS、受限上行、多 association、VPN 小包、入站/服务器主动流**：
   做 **MQP-3 wire rev2（候选 B）**，按 Phase 1→2 落地；预期是
   **域名类 −15~−38% wire、纯上行 −6~−14%、多会话 −8~−18% wire + ~94% fewer sends、
   全双工入站 −4~−18% 小包 wire**，而不是数量级吞吐。
3. **如果只想要低风险收益**：先做 **候选 A 子集**（保留 `sess u32`：FLOW_ACK/域名绑定 +
   全尺寸 v3 + 紧凑 FRAG + SESS_CLOSE/FLOW_CLOSE），能拿到大部分字节/生命周期收益，
   但没有“真全双工/跨 session”。
4. **无论选哪条，Phase 0 的测量与传输配置都先做**；没有 Linux 基线，任何“大幅”主张都不可验收。
5. **命名/兼容**：新 wire 仍叫 MQP-3；`CAPS.wire_ver=2` 做门禁；放弃与 v0.2.0 对端共存
   （用户已允许）；不引入 “MQP-4” 字样。

### 9.2 需要用户拍板的问题

1. **目标函数排序**：受限上行带宽（wire）/ 每核 pps/CPU / 尾延迟——决定先做域名 ACK、
   连接级 stager、还是同线程化。
2. **是否接受同版本部署**（完全放弃与 v0.2.0 对端共存）？若要求混合版本，需要额外 ALPN/双栈
   发布工程，且收益不变、复杂度显著上升。
3. **控制面能否用一条 QUIC bidi 流**（而不是 DATAGRAM）？这是实现复杂度差异最大的决定。
4. **域名回包 SOCKS5 语义**：确认可以继续用“首次 inline 回包的实际源 IP”（不改 app 行为），
   以及多 A/anycast/端口漂移时的重绑定策略。
5. **是否要 server-initiated/full-cone flow 的一等公民压缩**（决定是否保留 server 半区 id）。
6. **目标硬件与 MTU 分布**：Linux 2–4 核 ARM 路由器 vs x86 exit？已知路径 MTU 1200/1400/1472？
7. **“大幅”的验收定义**：是域名类 −30% wire、多会话 −90% 调用、还是 bulk 吞吐翻倍？
   前两者可做，第三者不应由协议重构承诺。

---

## 附录 A：新帧字节示例（rev2 实际实现，golden 来自 `src/mqp/r2.rs`）

> 首字节固定 `0x0X`（高 4 bit=0，避开 0x02/0x05/0x06），旧 v2/v3 解析器会安全丢弃；flow id 为
> 连接级 u32 单调不复用（`wire_id = local<<1 | owner`）。完整规格见 [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md)。

```text
DATA steady wire_id=5, payload "abc":
  00 05 61 62 63                                   ; 2 B 头
DATA open wire_id=5, sess=7, 192.0.2.1:53, "abc":
  01 01 05 07 00 00 00 01 C0 00 02 01 00 35 61 62 63   ; 14 B 头
DATA inline (无 flow), sess=7, 192.0.2.1:53, "z":
  01 02 07 00 00 00 01 C0 00 02 01 00 35 7A        ; 13 B 头
TRAIN same wire_id=5, "abc"+"de":
  04 00 02 05 03 61 62 63 02 64 65                 ; 3 B 头 + id
TRAIN dict flows 5,9, items(0=abc,1=de):
  04 01 02 02 05 09 00 03 61 62 63 01 02 64 65     ; 4 B 头 + 2 ids
FRAG steady wire_id=5, frag_id=0x12345678, idx=1/3, "abc":
  08 05 78 56 34 12 01 03 61 62 63                 ; 8 B 头
CTL HELLO (M3, wire_ver=2, flags=0):
  0C 01 4D 33 02 00 00 00                          ; 8 B
CTL FLOW_ACK(wire_id=5, status=open):
  0C 10 05 00                                      ; 4 B
CTL SESS_CLOSE(sess=7, reason=0):
  0C 20 07 00 00 00 00                             ; 7 B
```

## 附录 B：支撑报告与复算材料

| 文件 | 内容 |
|---|---|
| `analysis/mqp3-refactor/01-wire.md` | 帧格式/头开销全矩阵、候选 A/B/C、解码器 DoS、golden bytes |
| `analysis/mqp3-refactor/02-uplink.md` | 客户端上行逐段成本、headroom 表、实现层收益（F10/F3 等） |
| `analysis/mqp3-refactor/03-downlink.md` | 服务端下行逐段成本、per-session stager 模型、域名绑定洞察、P1–P7 排序 |
| `analysis/mqp3-refactor/04-transport.md` | quinn 事实、每包成本、D1–D6 全双工定义、杠杆×workload、benchmark 矩阵 |
| `analysis/mqp3-refactor/05-evidence.md` | 证据分级、已否决设计、harness 模式/缺口、文档漂移 |
| `analysis/mqp3-refactor/model.py` / `model-output.txt` | Lead 侧 wire 模型（可复算；假设全部写在脚本头） |

## 附录 C：必须保留的不变量清单（实现评审用）

- [ ] 逐帧/逐 item 鉴权在进入任何 stager 之前完成；跨 session 合帧不绕过 allowlist/flow 回退。
- [ ] SSRF/`allow_private` 语义不变；下行压缩只改变源地址表达。
- [ ] flow 只在目标接受真实发送后安装；未知 id/未确认 open 只丢当前 item。
- [ ] 连接级 id 不跨 session 解析；每 item 用其 flow 所属 session。
- [ ] full-cone 仍 opt-in；server-owned flow 只在 full-cone 下创建并计入 unsolicited。
- [ ] 控制流/数据帧解析前长度/范围校验；未知 kind/opcode 计数丢弃、不 panic。
- [ ] id 复用 ≥3 s tombstone；表有界并计入 admission；无新增内存放大器。
- [ ] 每帧 ≤ `max_datagram_size()`；重组 8 KiB / 2 s / 256 KiB 上限不变（除非 CAPS 显式协商）。
- [ ] 默认 ALPN 仍 `h3`；无 “MQP-4” 命名；wire_ver 只出现在 CAPS/日志。

---

## 10. 实施进度（2026-10-21）

> 本节记录分析落地状态；实现契约与细节以 [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md) 为准。

- **Phase 1a + 1b 已落地**：rev2 codec（`src/mqp/r2.rs`，15 unit）、flow state（`src/mqp/r2_flow.rs`，10 unit）、
  rev2 fragmentation/reassembly（`src/udp/r2_frag.rs` + `src/udp/r2_reasm.rs`，16 unit）、
  客户端全尺寸 rev2（单帧 DATA 或 `R2Fragmenter`，下行 `R2Reassembler`）、服务端 rev2 ingress FRAG/下行全尺寸；
  `cargo test --all-targets` **390 passed / 0 failed**（lib 186 + client 114 + server 90），
  `clippy --all-targets -D warnings`、`fmt --check` 干净。
- **真实 loopback 矩阵**：`udpsweep` 8–8000 B 全过（>512 B 双向 rev2 FRAG）、`udppaced` 325000/325000
  （0 % loss，60 s reporter `steady=274140 train=358/854 frag=1200/4500/1200 inline=0 drops=0`）、
  域名 1000/1000、8-flow 扇出 2000/2000、`udpbidir` 30000/30000、1000 B 单帧 2000/2000。
- **Phase 2 已落地**：`R2Stager` 已接入 client 上行 + server 下行（连接级跨 session `TRAIN dict`、round-robin 公平、
  有界队列、CAPS max_train_items、SESS_CLOSE/FLOW_CLOSE purge）；`R2Reassembler::drop_session/drop_flow` 严格 teardown；
  Linux netem 矩阵脚本 `scripts/linux-bench-matrix.sh`。
- **实测**：8 assoc × 1000 pps × 128 B × 65 s：519 992/519 992、0 % loss；client **0.743 frames/payload**（Phase-1b ≈0.99，
  约 −26 % DATAGRAM 发送），stage 0 丢/0 队满；416 tests 全绿。
- **全双工对称已完整**：server-owned full-cone flow（server OPEN|SRC + client 接受/复用 + server ingress 转发）
  已落地；`SESS_CLOSE` 双端 purge；424 tests 全绿。
- **仍未完成（可选/外部）**：Linux 目标机实测、Blocked 下严格保序、旧 v3/v2 发送路径最终清理。
