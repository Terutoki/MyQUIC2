# MQP-3 wire rev2 — 实施规格（不兼容旧版，仍名 MQP-3）

> 基线：`d2f9658`（v0.2.0） · 决策：**小包优先**、不兼容旧 wire、不做 bulk 吞吐目标、上行下行对称（全双工目标 D1–D6）。
> 本文件是实现契约：先落 codec，再按阶段接线。所有版本标识只在 `CTL HELLO/CAPS` 的 `wire_ver=2` 里出现，
> 代码/文档/日志**不得出现 "MQP-4"**。

---

## 0. 目标与阶段

| 阶段 | 内容 | 主要收益 |
|---|---|---|
| **1a** | rev2 codec + 生产 UDP 切换（IP flow）：去 `sess`、稳态 2 B 头、`DATA/TRAIN/FRAG/CTL`、`FLOW_ACK`（纯上行）、`SESS_CLOSE`；域名暂保持 inline | 所有小包 −3 B/帧；纯上行稀疏 −6~−14%；`>512 B` 统一进 v3（−7~−22 B/帧/片） |
| **1b** | 域名 flow 绑定与下行压缩：首帧 `OPEN`（双向）、`OPEN|SRC` 重绑定、server-owned flow；域名双向压缩 | 域名类 −15~−38% wire（上下行） |
| **2** | 连接级 stager + 跨 session `TRAIN dict` + 每 session 配额/公平 | 多 association：send 调用 −90%+，wire −8~−18%（条件性） |
| **3** | 可选：B′ 1 B 短头、FEC opt-in、更大重组上限 | <1 B/帧级 |

**非目标**：bulk 吞吐（MQP 头 <1–3%）、payload 压缩、fragment train、u16 frag id、与 v0.2.0 混合部署。

---

## 1. 第一字节安全检查（为什么 rev2 能与旧实现并存而不误解析）

旧代码的分发顺序（已核对）：

- 服务端 `accept.rs`：`is_v3(d)` → 否则 `d[0]==0x05`（MQP-2 FRAG）→ 否则 `is_batch`（0x06）→ 否则 `decode_datagram_ref`（要求 0x02）→ 否则丢弃。
- 客户端 `dispatcher.rs`：`is_v3` → `is_batch` → `0x05` → `decode_datagram_ref`（0x02）→ 否则丢弃。

因此 **rev2 所有帧的第一字节固定为 `0x0X`（高 4 bit == 0），且避开 0x02/0x05/0x06**，
旧 v2 与旧 v3 解析器都会把它当未知帧丢弃，不会误路由：

```text
first byte = 0b0000_0000 | kind/flags
  0x00 DATA steady        0x01 DATA extended
  0x04 TRAIN              0x08 FRAG steady
  0x09 FRAG extended      0x0C CTL
```

- 混合部署：新服务端遇到旧客户端（首字节 `0x1X/0x2X/0x3X/0x4X`）→ 非法首字节丢弃；
  新客户端遇到旧服务端（rev2 首字节 `0x0X`）→ 旧端丢弃。
- **不承诺混合版本可用**：双方都升级；`HELLO/CAPS` 只做 fail-fast/能力协商（见 §6）。
- 服务端在未收到 HELLO 时也拒绝 rev2 数据（返回计数器 `REFUSED`），避免“新服务端 + 旧客户端”出现任何
  非预期通路；客户端未收到 CAPS 时不发送 UDP 数据（连接在池预热阶段完成协商，不增加首包 RTT）。

---

## 2. flow id 与 session

### 2.1 wire id

```text
wire_id u32 = (local_id << 1) | owner
  owner = 0  client 分配；owner = 1  server 分配
  local_id 从 1 开始单调递增，连接存活期内永不复用
  wire_id == 0 保留（非法数据帧；无 flow 用 INLINE 形式）
  上限：local_id <= 0x7FFF_FFFF（耗尽后回退 INLINE，实际不可达）
```

- 编码：LEB128；常见活跃 id < 64 → **1 B**。
- 不复用 ⇒ 旧 flow 的延迟帧只会命中“已关闭”的表项并被丢弃，不会串到新目标；无需 tombstone/复用窗口。
- 半区所有权：client 只分配 owner=0，server 只分配 owner=1。两端都能 open/close/ack（D2）。

### 2.2 数据面不再携带 `sess`

`session u32` 只出现在：

1. `DATA/FRAG` 的 `OPEN`/`INLINE` 扩展头；
2. `CTL SESS_CLOSE`；
3. 控制面（HELLO/CAPS 不带 session）。

稳态压缩帧只带 `wire_id`。接收端用**每连接 flow 表**把 `wire_id → (session, target, state, reply_src)`。

### 2.3 每端两张表

| 表 | 位置 | key | value | 用途 |
|---|---|---|---|---|
| `FlowRegistry` | 每 QUIC 连接一份，client/server 对称 | `wire_id` | `Arc<FlowBinding>` | 接收方向解析 id；下行 dispatcher / 上行 accept |
| `SessionFlows` | 每 session 一份（现有 `FlowTable` 改造） | `TargetAddr`（client）/ 回包 `SocketAddr`（server） | `wire_id + Arc<FlowBinding>` | 发送方向按目标找 id；server 下行按源找 id |

`FlowBinding`（两端共用）：

```text
wire_id: u32
session: u32
target: TargetAddr        // client: 请求目标；server: 已安装的绑定目标
state: AtomicU8           // Opening(0) / Open(1) / Closed(2)
reply_src: ArcSwapOption<SocketAddr>  // client 下行用：SOCKS5 reply header 的源地址
resolved: SmallVec<SocketAddr>        // server 下行用：域名 flow 的解析结果（匹配源 IP）
```

- 分配/插入只在新 flow 时发生；热路径只读 `Arc` + 原子。
- `FlowRegistry` 用 `parking_lot::RwLock<HashMap<u32, Arc<FlowBinding>>>`（读多写少，Phase 1 先正确性；
  若 profiling 显示锁竞争，Phase 2 改分片/ArcSwap 快照）。
- 每连接 live flow 上限：`max_conn_flows`（默认 4096，`CAPS` 协商）；每 session 上限 64（可协商）。
  超限：发送侧回退 `INLINE`；接收侧 `FLOW_REJECT`。

---

## 3. 帧格式

> 共同规则：一个 QUIC DATAGRAM body 只承载一个 MQP rev2 帧；`DATA/FRAG` 的 payload 为 DATAGRAM 剩余字节；
> 所有 varint 为 LEB128 u32；解码器必须在分配/切片前校验长度，截断/非法 flag/未知 opcode 只丢当前帧。

### 3.1 `DATA`（0x00 / 0x01）

```text
steady:  0x00 | wire_id varint | payload
extended: 0x01 | flags u8 | [wire_id varint if !INLINE] | [sess u32 if OPEN or INLINE]
          | [addr if OPEN or INLINE] | payload

flags: OPEN=0x01, INLINE=0x02, SRC=0x04;  OPEN|INLINE 互斥；其余位必须为 0
INLINE:  无 wire_id；sess+addr 自描述（表满/一次性目标/诊断的 fail-safe）
OPEN:    wire_id 绑定到 (sess, addr)；addr 的语义：
          - client 发起的 flow：目的地（普通 OPEN）
          - server 发起的 flow：回包源地址（OPEN|SRC）
          - 已有 flow 的源漂移重绑定：同一 wire_id + OPEN|SRC + 新源地址
SRC:     addr 是实际源，而非目标（下行换端口/anycast/full-cone）
```

| 形态 | IPv4 头 | IPv6 头 | 域名 L 头 |
|---|---:|---:|---:|
| steady（id<64） | **2 B** | 2 B | 2 B |
| steady（id<8192） | 3 B | 3 B | 3 B |
| OPEN（v4/v6/domain） | 14 B | 26 B | 11+L B |
| INLINE（v4/v6/domain） | 13 B | 25 B | 10+L B |

> OPEN 比旧 v3 inline 多 1 B（多一个 flags 字节），但只在**每个 flow 的首帧/重绑定帧**付出；稳态省 3–4 B/帧。
> 后续可把 OPEN 的 flags 折进保留位，收益 1 B/flow，不作为第一阶段目标。

### 3.2 `TRAIN`（0x04）

```text
0x04 | form u8 | count u8 | ...
form = 0 (same):  wire_id varint | item*
form = 1 (dict):  nfl u8 | wire_id varint * nfl | item*
item (same):  len varint | payload
item (dict):  idx u8 | len varint | payload
```

- 只允许**已确认（Open）**的 flow；新 flow 的首帧必须用 `DATA OPEN` 单独发送（不做 per-item inline）。
- `count ≤ max_train_items`（默认 64，`CAPS` 协商）；`nfl ≤ min(count, 64)` 且 dict id 互异。
- 解码时任何 id 未安装 → 丢弃该 item（计数），其余继续；长度必须精确吃到帧尾。
- 跨 session 允许：dict 中不同 `wire_id` 可属于不同 session（Phase 2 才由连接级 stager 产生）。
- 头大小：same = 3 B + id varint；dict = 4 B + nfl × id varint（kind/form/count/nfl）；item 同 flow 1 B len（≤127 B payload），dict item 再加 1 B idx。

### 3.3 `FRAG`（0x08 / 0x09）

```text
steady:   0x08 | wire_id varint | frag_id u32 LE | idx u8 | total u8 | chunk
extended: 0x09 | flags u8 | [wire_id if !INLINE] | frag_id u32 | idx u8 | total u8
          | [sess u32 if OPEN or INLINE] | [addr if OPEN or INLINE] | chunk
```

- flags 同 DATA（OPEN/INLINE/SRC）；稳态头 **8 B**（旧 v2 18 B / 旧 v3 codec 11 B）。
- `1 ≤ total ≤ 64`、`idx < total`、chunk 非空；key = `(wire_id, frag_id)`。
- 首片可带 `OPEN`（inline addr）保证 flow 未安装也能重组；之后片压缩。
- 保留 u32 `frag_id`、8 KiB payload cap、2 s partial、256 KiB/连接/256 partials 的既有边界。

### 3.4 `CTL`（0x0C，DATAGRAM 载体）

控制帧**走 DATAGRAM、幂等、允许丢失**（丢失只延迟压缩/回收，正确性永不依赖它到达）。
旧端对 `0x0C` 首字节一律丢弃，天然安全。

```text
0x0C | opcode u8 | body
0x01 HELLO       : "M3" | wire_ver u16 (=2) | flags u16
0x02 CAPS        : "M3" | wire_ver u16 | flags u16 | max_conn_flows u16
                   | max_flows_sess u16 | max_train_items u8 | max_frame_bytes u16
                   | max_reassembly u16
0x10 FLOW_ACK    : wire_id varint | status u8 (0=open/confirmed)
0x11 FLOW_REJECT : wire_id varint | reason u8 (1=policy, 2=table_full, 3=dns)
0x12 FLOW_CLOSE  : wire_id varint
0x20 SESS_CLOSE  : sess u32 | reason u8
```

- **HELLO/CAPS**：客户端连接建立后立即发 HELLO；未收到 CAPS 前不发送 UDP 数据（连接池预热期完成）。
  服务端每收到一个 HELLO 回一次 CAPS（100 ms 节流）。版本不匹配 → 客户端关闭连接并报错（fail-fast）。
- **FLOW_ACK**：服务端安装 flow 成功后发送；客户端收到后把该 flow 从 `Opening` 置 `Open`，开始压缩上行。
  ACK 丢失 → 客户端继续发 OPEN（幂等），服务端重复安装/重复 ACK，只延迟压缩，不黑洞。
- **FLOW_REJECT**：策略/表满/DNS 失败；客户端对该目标回退 `INLINE`（可 TTL 后重试）。
- **FLOW_CLOSE/SESS_CLOSE**：发送 3 次（间隔 ~50 ms）；丢失由 180 s idle 兜底。
- 控制帧有速率/总量上限；未知 opcode/截断 → 计数丢弃，不断连接。

---

## 4. 绑定、确认与全双工语义

### 4.1 上行（client→server）

```text
新 flow:
  C --DATA OPEN(id, sess, dest, payload)--> S
  S: 校验 SSRF/策略 → 建/复用 session → 发送目标 → 安装 flow → CTL FLOW_ACK(id)
  C: Opening → Open；之后 DATA steady（2 B）或进 TRAIN
纯上行 flow: 只靠 FLOW_ACK 确认；稀疏流从 12/13 B 头降到 2–3 B。
重复 OPEN（ACK 丢失/首帧丢失）：幂等重装/重 ACK。
```

### 4.2 下行（server→client），含域名/换端口/full-cone

```text
命中精确 (session, src) → 压缩 DATA(id) / TRAIN
域名 flow / 源端口变化 / anycast:
  S --DATA OPEN|SRC(id, sess, actual_src, payload)--> C
  C: 绑定 reply_src=actual_src（写 SOCKS5 reply header，行为与今天 inline 一致）→ 置 Open
  S: 安装 (session, src)→id 反向映射；后续同源回包压缩
full-cone unsolicited（无匹配 flow）:
  S 分配 owner=1 的新 wire_id → DATA OPEN|SRC(id, sess, src) → 后续压缩
  （仅 `udp_full_cone=true`，计入 unsolicited）
```

- 域名/A anycast 的多地址：server 在 flow 的 `resolved` 集合里匹配源 IP；匹配到就压缩，否则重绑定。
- 首帧字节数与今天的 inline 相同（v4 13 B / v6 25 B / 域名 10+L B）→ **0 首帧代价**。
- 客户端压缩下行只依赖“本端已有的 binding.reply_src”；不依赖上行是否已压缩。

### 4.3 全双工（D1–D6）在本 wire 上的落点

- D1 数据面：DATA/TRAIN/FRAG 两方向同一套编解码；
- D2 状态面：每端每方向可 open/close/ack，id 半区所有权；
- D3 控制面：HELLO/CAPS/ACK/REJECT/CLOSE/SESS_CLOSE 双向；
- D4 无方向依赖：纯上行靠 FLOW_ACK；server-owned flow 让 downlink-only 流可压缩；
- D5 独立调度：Phase 2 连接级 stager + 每 session 配额（Phase 1 保持 per-session flush，不退化）；
- D6 可测：`udpbidir` + 方向字节/帧计数（Phase 0 基准工具已在做）。

---

## 5. 安全与资源不变量

1. 逐帧/逐 item 鉴权在进入任何 stager 之前完成；跨 session TRAIN 不绕过 allowlist/flow 回退。
2. SSRF/`allow_private` 语义不变；rev2 只改“源地址怎么表达”。
3. flow 只在目标接受真实发送后安装；未知/未确认 id 只丢当前 item。
4. 半区 id 不得跨 session 解析：registry 项必须携带 session；客户端逐 item 用其 id 查本端表。
5. full-cone 仍 opt-in；server-owned flow 只在 full-cone 下创建并计入 unsolicited。
6. 控制帧/数据帧解析前长度/范围校验；未知首字节/opcode/flag → 计数丢弃、不 panic。
7. 表有界并计入 admission；`max_conn_flows`/`max_flows_sess`/`max_frame_bytes` 由 CAPS 协商。
8. 不可复用 wire_id（单调）⇒ 无 splice 风险；耗尽回退 INLINE。

---

## 6. 版本协商与混合部署

- 客户端：连接建立 → 发 HELLO（重试至 CAPS 或 1.5 s 超时）→ 校验 `wire_ver==2` → 池 slot 标 ready，才允许 UDP 数据。
- 服务端：未收到 HELLO 时 rev2 数据仅计数丢弃；收到 HELLO 回 CAPS；HELLO 版本不符回 CAPS(自身版本) 并计数。
- 新客户端 + 旧服务端：HELLO 被旧端丢弃 → 无 CAPS → 1.5 s 后关闭连接并报错（不静默降级）。
- 旧客户端 + 新服务端：旧帧首字节非法 → 丢弃；服务端可对同一连接连续非法帧计数超阈值后关闭。
- 默认 ALPN 仍 `h3`；需要 fail-closed 的部署可显式 ALPN bump（可选，不进本阶段）。
- 协议名字始终 **MQP-3**；`wire_ver=2` 只存在于 CAPS/日志。

---

## 7. 客户端/服务端集成点（Phase 1a 改造清单）

### 7.1 共享库

| 文件 | 改动 |
|---|---|
| `src/mqp/r2.rs`（新） | 本规格的 codec + golden/malformed 测试 |
| `src/mqp.rs` | `pub mod r2;` + re-export |
| `src/mqp/r2_flow.rs`（新，Phase 1a/1b） | `FlowBinding`、`FlowRegistry`、`SessionFlows`、`CtlState`（HELLO/CAPS/确认状态） |
| `src/stats/udp_stats.rs` | 新计数：r2 帧 kind、train items、inline 回退、flow open/ack/reject/close、压缩率 |

### 7.2 客户端

| 文件 | 改动 |
|---|---|
| `bin/myquic2-client/assoc.rs` | `PendingTrain` 改用 rev2 `DATA/TRAIN`；每目标按 `SessionFlows` 找 `wire_id`；`Opening→Open` 由 ACK/下行确认；`>512 B` 改走 rev2 FRAG |
| `bin/myquic2-client/hub.rs` | `AssocEntry` 增加 `session` 与 `Arc<ConnFlowRegistry>` 句柄；`confirmed` 位图改为 binding 状态 |
| `bin/myquic2-client/dispatcher.rs` | 解析 rev2 `DATA/TRAIN/FRAG/CTL`；`wire_id → FlowBinding → session → DispatchCache`；处理 `FLOW_ACK/REJECT/CLOSE`、`OPEN|SRC` 重绑定 |
| `bin/myquic2-client/pool.rs` | 每连接创建 `ConnFlowRegistry`/`CtlState`；HELLO/CAPS 在 slot ready 前完成；重连时重建 |
| `bin/myquic2-client/egress.rs` | 发送 HELLO（连接 ready 路径）；控制帧发送（ACK 处理后的 CLOSE 等） |

### 7.3 服务端

| 文件 | 改动 |
|---|---|
| `bin/myquic2-server/accept.rs` | rev2 入口：首字节 0x0X；未 HELLO 丢弃；解 DATA/TRAIN/FRAG；`wire_id→FlowBinding→session`；OPEN 安装后发 FLOW_ACK |
| `bin/myquic2-server/reader.rs` | 下行用 rev2 DATA/TRAIN/FRAG；`(session, src)→wire_id` 反向表；域名/换端口 `OPEN|SRC` 绑定；full-cone server-owned id |
| `bin/myquic2-server/table.rs` | `SessEntry` 持有 `SessionFlows`/wire_id 反向表；SESS_CLOSE 立即回收 |
| `bin/myquic2-server/forward.rs` | 解析域名后把 `resolved` 写入 flow binding（Phase 1b） |

### 7.4 移除/保留

- Phase 1a 完成后：删除 UDP 生产路径的 MQP-2 发送（`DgramFragmenter` 的 v2 逻辑保留仅测试/兼容解码一版）。
- 旧 v3 codec 保留一个版本用于诊断/回滚二进制，但生产不再发送；后续删除。
- TCP 路径不动（QUIC stream 无 MQP 头）。

---

## 8. 测试与验收

### 8.1 单元

- 每个帧 golden bytes（steady/open/inline、v4/v6/domain、same/dict train、frag、所有 CTL opcode）；
- 截断/坏 flag/未知 opcode/超长 id/`idx>=total`/`count` 越界：不 panic、返回 `MqpError`；
- **首字节安全测试**：对每个 rev2 帧断言 `is_v3(first)==false`，且 first 不在 `{0x02,0x05,0x06}`；
- varint 边界（127/128/16383/16384/2^31-1）、TRAIN 64 项、FRAG 64 片；
- `FlowRegistry`/`SessionFlows` 并发/生命周期/上限测试。

### 8.2 端到端

| 场景 | 验收 |
|---|---|
| `udpsweep` 全尺寸 | 字节校验全过（含 8 KiB 分片） |
| `udpdomain` / `udpdomainmulti` | 域名上下行压缩生效（计数）；wire 模型 −15%~−37% |
| `udppaced` 1–512 B | p99 不回归 >5%，0 静默丢包 |
| `udpfanout`（新增） | 1 association × N dest 的 TRAIN/混目的正确；调用数下降 |
| `udpmulti` + churn | SESS_CLOSE 立即回收；8192 池不耗尽 |
| `udpbidir`（新增） | 双向合计 ≥1.6× 单向、p99 劣化 ≤10% |
| `bulk` / `lat` | bulk 不回归；lat p50/p99 不回归（同机同轮） |
| 混合版本 | 新客户端+旧服务端 fail-fast；旧客户端+新服务端只丢弃并计数 |

### 8.3 基准（Linux 2–4 核 + `tc netem` 70/140 ms、0/0.5/2% loss）

- 计数器：rev2 帧 kind、TRAIN items、inline fallback、flow open/ack/reject、压缩率、方向字节、
  `send_datagram` 调用、QUIC packet 数（qlog/tcpdump）、quinn stats（cwnd/rtt/mtu）。
- A/B：rev2 vs HEAD；MTU 1200 vs 1400；`MYQUIC2_SHARD_RUNTIME=0/1`。

---

## 9. 实施顺序（本轮起）

1. **本文件 + `src/mqp/r2.rs` codec**（可编译、单测通过；不改生产路径）。
2. `r2_flow.rs` 状态类型 + 单测。
3. 客户端/服务端 Phase 1a 接线（可加临时 feature/常量开关，默认关；测试通过后切换）。
4. `udpfanout`/`udpbidir` 基准（并行进行中）。
5. Phase 1b 域名绑定/下行压缩；Phase 2 stager/跨 session。
6. 清理旧发送路径、更新 README/配置/统计。

---

## 10. 实施状态（2026-10-21，Phase 1a 已落地）

### 10.1 已交付

| 层 | 内容 | 测试 |
|---|---|---|
| codec | `src/mqp/r2.rs`：DATA steady/OPEN/INLINE、TRAIN same/dict、FRAG（codec 就绪）、CTL 全部 opcode、首字节安全校验、varint/边界/截断测试 | 15 unit |
| flow state | `src/mqp/r2_flow.rs`：`FlowBinding`（状态/reply_src/resolved）、`SessionFlows`、`FlowRegistry`（含 `remove_session`）、`FlowIds`、`CtlState` | 10 unit |
| client | `src/bin/myquic2-client/rev2.rs`（新）：每连接 `ConnRev2`、HELLO→CAPS 门禁、OPEN→steady/TRAIN/INLINE 状态机、全尺寸 rev2（单帧 DATA 否则 `R2Fragmenter`）、下行 `R2Reassembler`、burst/deferred flush、FLOW_REJECT TTL 回退、SESS_CLOSE×3；`pool/egress/auth/dispatcher/assoc/...` 接线 | 114 bin tests |
| server | `accept.rs`：`R2ConnState`、HELLO/CAPS 门、rev2 入口（OPEN/steady/TRAIN/INLINE/**FRAG**）、SSRF/策略复用、安装 registry+SessionFlows、FLOW_ACK/REJECT、SESS_CLOSE/FLOW_CLOSE、sweep 清理；`reader.rs`：`match_source` → steady/TRAIN/OPEN|SRC 下行 + 全尺寸 rev2 FRAG/单帧；`table/forward` 接线 | 90 bin tests |
| frag | `src/udp/r2_frag.rs`：`R2Fragmenter` + `R2FragFlow::{Steady,Opening,Inline}`，聚合背压门（all-or-nothing）、单帧内嵌/碎片自适应 | 7 unit |
| stage | `src/udp/r2_stage.rs`：Phase 2 连接级跨 session 聚集原语 `R2Stager`（per-session FIFO + round-robin 公平、`TRAIN dict` 跨 session 合帧、Open/Inline 独立帧、有界队列） | 9 unit |
| reasm | `src/udp/r2_reasm.rs`：`R2Reassembler`（`(wire_id,frag_id)`/INLINE key、OPEN ctx 一致性、8 KiB/2 s/256 partials/256 KiB、无 tombstone） | 9 unit |
| bench | `examples/hotpath_bench.rs`：`echomulti`、`udpfanout`（IP/domain 扇出）、`udpbidir`（全双工） | clippy/rustfmt clean |

### 10.2 已验证（macOS loopback，release 二进制，临时配置；Phase 1b 后）

- 全部 UDP 尺寸走 rev2：`udpsweep` 8/128/512/1000/2000/3000/5000/8000 B **ALL OK**（>`512 B` 为
  rev2 单帧 DATA 或 rev2 FRAG 双向，无 legacy 帧）。
- `udppaced` rev2 128 B @5k pps **325000/325000, 0.000 % loss**；60 s reporter 含 FRAG：
  `flow_open=31 open=499 steady=274140 train=358/854 frag=1200/4500/1200 inline=0 unknown_id=0 drops=0`
  （7 条 UDP 连接，`hello=14 caps=14`）。
- `udpdomain` 域名目标 1000/1000；`udpfanout` 8 混 flow 2000/2000；`udp` 1000 B 单帧 2000/2000；
  `udpbidir` 全双工 30000/30000；`lat` p50 ≈ 197 µs；`udpmulti` 8 assoc 15987/16000（0.08% 启动损失）。
- `cargo test --all-targets`：**390 passed / 0 failed**（lib 186 + client 114 + server 90）；
  `cargo clippy --all-targets -- -D warnings`、`cargo fmt --check` 干净。
- admission 现在按 **2 × `FRAG_MAX_HELD_BYTES`** 计费（legacy + rev2 两个重组器并存），
  默认 per-connection transport term 14.25 → **14.5 MiB**。

### 10.3 Phase 2 已完成（2026-10-21）

- **client 上行**：`ConnRev2` 持有连接级 `R2Stager`（`Arc<parking_lot::Mutex<...>>`，锁只覆盖一次 push/drain、不跨 await）；
  ≤512 B payload 以 `Steady/Open/Inline` item 入队，burst 末尾/大包前/association 退出/队满时 drain；`>512 B` 走
  单帧 DATA / `R2Fragmenter` 并在前先 drain（保序）；teardown 逐项记 `EGRESS_DEAD`。
- **server 下行**：`R2ConnState` 持有连接级 stager（所有 session reply reader 共享）；小回复按 Exact/Rebind/Inline
  入队，burst 边界 drain，跨 session round-robin 合成 `TRAIN dict`；大回复先 drain 再走直接路径；`SESS_CLOSE`/`FLOW_CLOSE`
  同时 purge 队列项与在途 partial。
- **协商上限**：`CAPS.max_train_items` 已用于 stager 分帧；`max_frame_bytes` 已用于客户端定帧长。
- **测量**（release，macOS loopback，`udpmultipaced` 8 assoc × 1000 pps × 128 B × 65 s）：
  519 992/519 992，0.000 % loss；client `stage=467846p/467180d/347639f/467845i/0x/0full` →
  **0.743 frames/payload，较 Phase-1b 基线 ≈0.99 减少约 26 % 的客户端 DATAGRAM 发送**；`udppaced`/`udpsweep`(8–8000 B)/`udpfanout`/`udpdomain` 同构建全过。
- **全双工对称（D2/D4）**：server 对 full-cone/unsolicited 源创建 **server-owned flow**（`DATA OPEN|SRC`，owner bit 1），
  安装 registry + session 反向表，后续同源回包压缩；client 接受未知 server-owned `OPEN|SRC`（小包/分片首片）并安装绑定，
  app 回包复用同一 id（steady/stager/fragment），server ingress 接受该 id 并转发到远端源；非 full-cone 仍 inline。
  `SESS_CLOSE` 同时 purge 双端排队项、registry 绑定与在途 partial。
- **测试**：`cargo test --all-targets` **423 passed / 0 failed**（lib 199 + client 124 + server 100）；clippy/fmt clean。

### 10.5 仍待完成（可选/后续）

1. **Linux 2–4 核目标机实测**（netem 70/140 ms、0/0.5/2 % loss）：脚本已就绪，需目标机执行。
3. **backpressure 下的严格保序**：大回复遇到 Blocked 且队列仍有项时可能越过（UDP 语义允许；如需严格需 retry-later）。
4. **app-facing relay socket 64 KiB 缓冲的突发丢包**：`udpmulti` batch=64 的 0.03–0.13 % 丢包定位在 client relay socket
   （threshold 48→64 batch；`MYQUIC2_SESS_SOCKET_BUF=1 MiB` 后 0 丢包），与 stager/协议无关，属既有配置/实现项。
5. 旧 v3/v2 发送路径最终清理与文档/配置收敛。

### 10.4 未完成（Phase 2 其余）

1. **CAPS 协商上限实际生效**：`max_conn_flows/max_flows_sess/max_frame_bytes/max_reassembly` 目前
   `max_frame_bytes` 客户端已用于定帧长，其余仍用编译期默认；需把 registry/session/帧长 cap
   改为连接级协商值。
2. **server-owned / full-cone flow**（D2/D4 完整）：id 半区/FlowIds 已就绪，尚未接线。
3. **Phase 2**：连接级 stager + 跨 session `TRAIN dict` + 每 session 配额/公平；`udpbidir` 验收门槛。
4. **Linux 2–4 核目标机**基准（netem 70/140 ms、0/0.5/2 % loss）——本机 macOS loopback 不能外推。
5. 旧 v3/v2 发送路径清理（服务端 small-path 仍有 last-resort legacy fallback）与 README/配置最终收敛。
6. `R2Reassembler` 的 SESS_CLOSE/FLOW_CLOSE 主动 purge（当前由 2 s 超时/完成时 registry 解析兜底，
   属 UDP late-arrival 语义）；如需严格释放，加 shared-lib `drop_session/drop_flow` 钩子。
7. `R2Fragmenter` 的 `Blocked` 不单独计 BUFFER_FULL（与单帧一致，仅可观测性差异）。
