# MQP-3 wire 格式与编解码深度分析（task-1）

> 分析对象：`/Users/eric/WorkSpace/MyQUIC2`，HEAD `d2f9658` / `v0.2.0`（`git log --oneline -1` 已核对）。
> 方式：**只读代码审计 + python3 算术建模**；未修改 `src/`、未执行 `cargo build/test`、未做网络测量。
> 结论中每个字节数都给了**帧布局 + 公式 + 假设**；后文表格中的百分比均为 MQP 层字节，不含 IP/UDP/QUIC 开销（除特别注明）。
>
> 证据分级：
> - **[代码]**：直接读源码得到的结构/常量，附 `file:line`。
> - **[文档/既有测量]**：仓库 README / `PROTOCOL_ANALYSIS.md` / 代码注释里记录的历史测量，本次未复测。
> - **[模型]**：本文用 §7.1 公式算出的估算值（无丢包、理想打包、IPv4 默认），用于判断量级与方向。
>
> 术语：上行 = client→server（app→target），下行 = server→client（target→app）；`limit` = `quinn::Connection::max_datagram_size()`，即**一个 QUIC DATAGRAM body 的预算**，`limit = MTU − 38`（README.md:777，`src/mqp/fragment.rs:64` 取 1162 = 1200−38）；本文用 `limit=1162 (MTU 1200)` 与 `limit=1362 (MTU 1400)` 两档。所有域名的地址开销按 `L=30` 字节计算（`4+L=34`，公式对一般 `L` 成立）。

---

## 0. 执行摘要（先给结论）

1. **当前 v0.2.0 的 MQP-3 只完成了“同 session、IP 目标、≤512 B”的 flow/TRAIN 压缩**。三条最大结构性缺口是：
   域名目标两个方向都无法压缩（§4-L1）、纯上行 flow 永远不压缩（§4-L2）、>512 B 全部退回 MQP-2（§4-L3）；再叠加**没有控制面**（§4-L4）和 **v3 FRAG 未接线**（§4-L5）。
2. **字节上最大的单笔收益是域名目标压缩**：上行查询方向当前每帧 40 B 头（60 B 载荷 + 30 B 域名时占 MQP 字节 40%），加 FLOW_ACK 后可降到 5→2 B 头，**每 1000 个 payload 从 97,564 B 降到约 61,300 B（−37%）**；下行回包方向当前是 `NO_FLOW`+inline IP（v4 13 B / v6 25 B 头），ACK 后同样压到 5→2 B，**v4 −13%、v6 −26%**。[模型]
3. 纯上行 IP flow（收不到回包、无法被隐式确认）当前每帧 12/13 B 头，FLOW_ACK 后 5→2 B：**稀疏单向流 −9.7%~−13.9%；高速单向流因每 TRAIN 只重复一次地址，约 −2%**。[模型]
4. >512 B 载荷与分片统一进 v3 帧后，**大包头 12/24 B → 5/6 B（A）/2/3 B（B），分片头 18/30 B → 11（A）/8（B）B/片**；1200 B @MTU1200 的 2 片场景 wire −1.1%~−1.6%，IPv6 2 片 −3.0%~−3.5%，8192 B 8 片 −0.7%~−1.0%。**bulk 吞吐不会因此改变**（MQP 头在 1200 B 包里<1%，§8.3）。
5. **跨 session 打包**（同一 QUIC 连接上多个 SOCKS association 的小包合成一个 TRAIN）每次调用可换 4×（8 session×4 item）到 16×（32 session×1 item）的 quinn send 次数，wire 省 2%~4.3%；价值在 CPU/锁，不在带宽。[模型]
6. **推荐方向：候选 B —— 连接级 flow-id 命名空间 + 对称双向所有权 + 完整 CTL 面**（§6.2）。它用 2~3 B 稳态头（去掉每帧 `sess u32`）、8 B 分片头、跨 session TRAIN、域名/单向 flow 的 FLOW_ACK、服务端主动 flow（full-cone）压缩；候选 A（保留 `sess u32` 的增量方案，§6.1）作为低风险子集可先落地；候选 C（u16 sess 折中，§6.3）因 id 复用安全代价**不建议**。
7. **命名约束**：全程仍称 **MQP-3**；建议在 CTL 的 HELLO/CAPS 里带 wire-version 字节（本文示例 `ver=2`），ALPN 仍叫 `myquic2/3` 或另加后缀——重设计只改变 MQP-3 的 wire 版本，不引入任何新协议代号（§6.2/§9-Q2）。
8. **未做测量**：本文所有百分比必须理解为模型值；落地前后的 A/B 必须在 Linux 目标机用 `examples/hotpath_bench.rs` + 真实 app 负载复测（§9-Q8）。

---

## 1. 背景与本文范围

MyQUIC2 是一个 SOCKS5-over-QUIC 代理：TCP 走 QUIC stream，UDP 走 QUIC DATAGRAM，MQP-3 是 UDP 数据面的自定义帧格式（README.md:145、README.md:590-745）。数据面拓扑（[代码]）：

- 客户端每条 UDP association（SOCKS5 UDP ASSOCIATE，上限 4032，`src/config/tuning.rs:116`）在 `assoc.rs` 里把 app 的 `RSV|FRAG|ATYP|ADDR|PORT|payload` 解出 payload，选一条 egress QUIC 连接（4 条 TCP 连接 + 1 条 interactive UDP + 2 条 bulk UDP shard，`src/config/tuning.rs:38,69`）发 DATAGRAM；同一个 QUIC 连接会被**多个 association 共享**。
- 服务端每个 UDP session 一个 relay socket + 一个 reader task（`src/bin/myquic2-server/reader.rs:729`），`sess` 由客户端分配（`src/bin/myquic2-client/hub.rs:326-353`，单调 u32、0 保留），服务端 session 表是**每 QUIC 连接一张**（`src/bin/myquic2-server/accept.rs:797`，`SessTable` 按 `sess` 索引，`src/bin/myquic2-server/table.rs:58-64,91-97`）。
- Flow 表是**每 session 一张**：`FlowTable [Option<Arc<TargetAddr>>; 64] + next`（`src/mqp/v3.rs:683-792`），客户端 uplink 分配、服务端从 inline open 镜像安装（`src/bin/myquic2-server/accept.rs:731-770`），下行用同一张表把“回包源地址”映射回 flow id（`src/bin/myquic2-server/reader.rs:128-171`）。

本文范围：**只分析 wire 帧 / 编解码 / 帧级状态语义**。CPU 热点、调度、连接拓扑的代码级问题见 `PERF_ANALYSIS.md` 与团队其他报告，不重复。

---

## 2. 现状 wire 规格（逐帧、精确到字节）

### 2.1 帧类型总表

| 首字节（高 4 bit = kind，低 4 bit = flags） | 名称 | v0.2.0 生产状态 | 证据 |
|---|---|---|---|
| `0x10` | `SINGLE` | 生产，双向；仅 ≤512 B 走这里 | `src/mqp/v3.rs:22,29-34`；`src/bin/myquic2-client/assoc.rs:301`；`src/bin/myquic2-server/reader.rs:629` |
| `0x20` | `TRAIN` | 生产，双向，混合 flow/目的地 | `src/mqp/v3.rs:23,37-42` |
| `0x30` | `FRAG` | **codec 已写、未接线**（生产走 MQP-2 `0x05`） | `src/mqp/v3.rs:24,66,542-671`；`src/bin/myquic2-client/dispatcher.rs:330-335`；`src/bin/myquic2-server/accept.rs:720-724` |
| `0x40` | `CTL` | **仅常量**，无任何 opcode/编解码 | `src/mqp/v3.rs:25`；README.md:610 |
| `0x02` | MQP-2 `DATAGRAM` | 生产：≤512 B 的兜底 + >512 B 单帧 | `src/mqp/datagram.rs:7,11`；`src/bin/myquic2-client/assoc.rs:882`；`src/bin/myquic2-server/reader.rs:199` |
| `0x05` | MQP-2 `FRAGMENT` | 生产：>limit 的载荷（每片重复完整地址） | `src/mqp/fragment.rs:14,29,178-183`；`src/udp/fragmenter.rs:349-380` |
| `0x06` | MQP-2 `BATCH` | 两端仍解码（兼容/测试），**生产已不发送** | `src/bin/myquic2-server/accept.rs:1041`；`src/bin/myquic2-client/dispatcher.rs:347`；发送端仅 `#[cfg(test)]`：`src/bin/myquic2-client/assoc.rs:1166-1167` |

> 关键事实①：`is_v3` 只把 `0x10/0x20/0x30/0x40` 识别为 v3（`src/mqp/v3.rs:70-75`）。其它 kind 值（`0x50..`）会被当作 v2 解码并 `REFUSED`（`src/bin/myquic2-server/accept.rs:1041-1127`；客户端 `src/bin/myquic2-client/dispatcher.rs:786` 的 `sess_of` 也为 `None`）——**无法前向扩展 kind**。
> 关键事实②：`CTL 0x40` 帧进入 v3 分支后，内层 `match` 的 `_ => {}` 直接静默丢弃（服务端 `src/bin/myquic2-server/accept.rs:725`；客户端 `src/bin/myquic2-client/dispatcher.rs:341`），**不计数、不报错**；且因为 `v3_sess` 要求前 5 B（`src/mqp/v3.rs:78-83`），长度 <5 B 的 CTL 会被算作 `REFUSED`。将来加控制面必须改这条 drop 规则。

### 2.2 公共地址编码（SOCKS5 同构）

`atyp u8 | addr | port u16 BE`：`0x01`=IPv4（1+4+2=7 B）、`0x04`=IPv6（1+16+2=19 B）、`0x03`=domain（1+len+host+2=4+L B，L∈1..=255）。不允许 unspecified/带 scope_id 的 v6（`src/mqp/addr.rs:122-160,165-196`）。解码是零分配的借用形式（`TargetAddrRef`，`src/mqp/addr.rs:198-245`）。

### 2.3 `SINGLE`（0x10）

```text
0x10|flags(1) | sess u32 LE(4) | [flow u8, if flags.F] | [addr, if flags.I] | payload…（到 DATAGRAM 末尾）
flags: I=0x1 inline address, F=0x2 flow byte present, S=0x4 inline addr 是实际源（覆盖 flow 绑定）
```
[代码] `src/mqp/v3.rs:151-245`；golden bytes 见 `src/mqp/v3.rs:814-844`。

- header = `1 + 4 + [1 if flow≠0] + [addr_len if I]`。**flow 0 隐式**，稳态 5 B；额外 flow 6 B；open 首帧 IPv4 12/13 B、IPv6 24/25 B、域名 40 B（NO_FLOW=0xFF 非 0，必须带 flow 字节）。
- **没有长度字段**：payload 吃到 DATAGRAM 末尾，因此一个 DATAGRAM body 只能放一个 SINGLE。
- 编解码：[代码] 编码 1 次 `header()` 校验/测长 + 1 次精确 `Vec::with_capacity` + 1 次 payload memcpy + `Bytes::from(Vec)`（`len==capacity` 走 in-place adopt，无二次分配，`src/mqp/v3.rs:151-198`）。解码零分配，仅切片（`src/mqp/v3.rs:200-245`）。

### 2.4 `TRAIN`（0x20）

```text
0x20|flags(1) | sess u32 LE(4) | count u8(1)
  [flow u8, if flags.SAME_FLOW && flow≠0]
  item*: iflg u8(1) | [flow u8, if iflg.F] | len varint(1–2) | [addr, if iflg.I] | payload(len)
flags: bit0 = SAME_FLOW（所有项同一非 0 flow，flow 只出现在 header）
iflg: F=0x1 flow byte, I=0x2 inline addr, S=0x4 src override（item flags 与 frame flags 的位含义不同）
```
[代码] `src/mqp/v3.rs:260-347`（编码）、`437-515`（解码）；golden 见 `src/mqp/v3.rs:907-945`。

- header = 6 B（mixed）或 7 B（SAME_FLOW 且 flow≠0）；`count` 1..=64（`src/mqp/v3.rs:60,286-287,449-451`）。
- 每项固定 1 B `iflg` + 1–2 B LEB128 长度；额外 flow +1 B。**flow 0 项 ≈ 2 B/项**（28/60 B 载荷），128–16383 B 载荷 ≈ 3 B/项。
- **SAME_FLOW 不能用于 flow 0**：编码端只在 `items[0].flow != 0` 时才写 header 的 flow 字节（`src/mqp/v3.rs:296-309,317-319`），而解码端一见 SAME_FLOW 就读 1 B flow（`452-463`），因此对 flow 0 置位会错位；测试把这一行为钉死（`src/mqp/v3.rs:947-968`）。
  **但字节上这没有损失**：flow 0 的 mixed 形式 = `6 + n·(1+len)`，而“合法化的 SAME_FLOW+flow0”需要 header 多 1 B、每项不变 = `7 + n·(1+len)`，反而多 1 B；flow 0 的 mixed 已是最小编码（§4-L9 会再次强调）。
- 编码：[代码] 先整帧校验一遍（每项 `header()` 测长，`src/mqp/v3.rs:285-309`），再 1 次精确 `Vec` 填充（`313-346`）；调用点用栈上固定数组收集 `TrainItem`（64×~40 B，`src/bin/myquic2-client/assoc.rs:972-998`；`src/bin/myquic2-server/reader.rs:243-267`）。
- 解码：[代码] 先整帧校验（防恶意帧 panic，`src/mqp/v3.rs:464-505`），迭代器再解析一遍（`391-433`）——**每项解码两次**（inline 地址的 `TargetAddrRef::decode` 也执行两次），CPU 常数很小（§4-L16）。
- 一个 DATAGRAM body 只放一个 TRAIN；TRAIN 不跨 drain burst（客户端在 burst 结束 flush，`src/bin/myquic2-client/assoc.rs:566-572,704-714`；服务端在 burst 结束/大包/退出前 flush，`src/bin/myquic2-server/reader.rs:640-680`）。
- **run-of-1 不发 TRAIN**：`n==1` 直接发 SINGLE（客户端 `src/bin/myquic2-client/assoc.rs:959-970`；服务端 `src/bin/myquic2-server/reader.rs:293-301`）。

### 2.5 v3 `FRAG`（0x30，未接线）

```text
0x30|flags(1) | sess u32 LE(4) | [flow u8, if F] | id u32 LE(4) | idx u8 | total u8 | [addr, if I] | chunk…
```
[代码] `src/mqp/v3.rs:66,542-671`；prefix = 11 B（flow 0）/12 B（额外 flow），另有 inline addr 时再加 7/19/4+L。生产无任何调用者（grep `encode_fragment_v3|decode_fragment_v3` 仅命中 `src/mqp/v3.rs`；`dispatcher.rs:330-335`、`accept.rs:720-724` 收到即 `REFUSED`）。所以**该格式当前是纯死重**。

### 2.6 MQP-2 帧（>512 B 与分片的生产路径）

| 帧 | 布局 | 固定头（v4 / v6 / domain L） | 代码 |
|---|---|---|---|
| `0x02` DATAGRAM | `0x02 \| sess u32 \| addr \| payload` | 12 / 24 / 9+L | `src/mqp/datagram.rs:7,11,73-108` |
| `0x05` FRAGMENT | `0x05 \| sess u32 \| id u32 \| idx u8 \| total u8 \| addr \| chunk` | 18 / 30 / 15+L（**每个分片都重复完整地址**） | `src/mqp/fragment.rs:14,29,178-183,219-261` |
| `0x06` BATCH | `0x06 \| sess u32 \| addr \| count u8 \| (len u16 LE \| payload)*` | 13 / 25 / 10+L + 2/项 | `src/mqp/batch.rs:5-9,20-79` |

- 分片参数：`MQP_FRAG_MAX_PAYLOAD=8192`、`MQP_FRAG_MAX_TOTAL=64`、`FRAG_TIMEOUT=2 s`、每连接 `FRAG_MAX_HELD_BYTES=256 KiB`、`FRAG_MAX_PARTIALS=256`（`src/mqp/fragment.rs:47,55,107,116,165,176`）；重组 key = `(sess u32, id u32)`（`src/udp/reassembler.rs:392`）。
- 发送端 `DgramFragmenter::send`（`src/udp/fragmenter.rs:178-394`）：先走 `DgramPrefixCache` 的 N=1 快路径（缓存 `type|sess|addr`，`src/mqp/datagram.rs:147-217`），装不下才分片；**分片 id 是 u32**，wrap 后有 3 s 复用安全窗（`FRAG_ID_SAFE_WINDOW_MS`，`src/mqp/fragment.rs:145`）。每片一次 frame 分配 + 一次 memcpy；每片一次 `quinn send_datagram`（连接状态锁）。
- 解码：全部借用、零分配（`src/mqp/datagram.rs:225-232`；`src/mqp/fragment.rs:263-279`；`src/mqp/batch.rs:158-198`），进入重组器时 chunk 被 **malloc+memcpy** 一次（有意为之的内存记账，`src/udp/reassembler.rs:203-289`）。

### 2.7 生产路径矩阵（谁在什么时候用哪个帧）

| 方向 | 载荷条件 | 当前帧 | 证据 |
|---|---|---|---|
| 上行 | ≤512 B，可打包 | `TRAIN`（多 flow/目的地） | `src/bin/myquic2-client/assoc.rs:298-401` |
| 上行 | ≤512 B，run=1 | `SINGLE` | `src/bin/myquic2-client/assoc.rs:959-970` |
| 上行 | >512 B | MQP-2 `0x02`（装得下）或 `0x05` 分片 | `src/bin/myquic2-client/assoc.rs:301-310,882` |
| 上行 | 任意尺寸、TRAIN/SINGLE 被 quinn 拒绝（Blocked/TooLarge） | MQP-2 `0x02`/`0x05` 兜底 | `src/bin/myquic2-client/assoc.rs:882,996-1016` |
| 下行 | ≤512 B，可打包 | `TRAIN`（混合源） | `src/bin/myquic2-server/reader.rs:626-680` |
| 下行 | ≤512 B，run=1 | `SINGLE` | `src/bin/myquic2-server/reader.rs:176-206,293-301` |
| 下行 | >512 B | MQP-2 `0x02`/`0x05` | `src/bin/myquic2-server/reader.rs:675-677` |
| 下行 | 任意尺寸兜底 | MQP-2 `0x02`/`0x05` | `src/bin/myquic2-server/reader.rs:199` |

**为什么 512 B 是分界？** 它不是 wire 限制，而是复用旧 BATCH 常量 `BATCH_SMALL_MAX=512`（`src/mqp/batch.rs:9`）作 staging 上限：客户端 `payload.len() > BATCH_SMALL_MAX` 直接走 v2（`src/bin/myquic2-client/assoc.rs:301`），服务端同样 `n <= BATCH_SMALL_MAX` 才进 v3 staging（`src/bin/myquic2-server/reader.rs:629`）。v3 SINGLE 本身可以承载任意 ≤ limit−header 的 payload（`src/mqp/v3.rs:143-174`），代码里没有任何 wire 级理由让 513 B 掉回 v2。

---

## 3. 当前每 payload 头开销矩阵

> 符号：`p`=payload 字节；`L`=domain 长度；`H`=每 payload 的 MQP 头字节；`share=H/(H+p)`。
> 假设：无丢包；TRAIN 场景假设每个 flush burst 有 32 个 payload（`LAST_HOP_DRAIN=32`，`src/udp/batch.rs:46`）；`limit=1162`；`L=30`。

### 3.1 单帧（standalone，`SINGLE`/`0x02`）：头与占比

| 场景 | H | p=28 | p=60 | p=200 | p=512 | 说明 |
|---|---:|---:|---:|---:|---:|---|
| IPv4 flow0 steady | 5 | 15.2% | 7.7% | 2.4% | 1.0% | v3；生产实际形态 |
| IPv4 extra flow steady | 6 | 17.6% | 9.1% | 2.9% | 1.2% | +flow byte |
| IPv6 flow0 steady | 5 | 15.2% | 7.7% | 2.4% | 1.0% | 地址不进 wire |
| IPv6 extra flow steady | 6 | 17.6% | 9.1% | 2.9% | 1.2% | |
| domain 地址（**上行**，永远 inline） | 40 | 58.8% | 40.0% | 16.7% | 7.2% | `NO_FLOW=0xFF`，10+L |
| domain 目标的**回包**（下行，inline IPv4） | 13 | 31.7% | 17.8% | 6.1% | 2.5% | `NO_FLOW`+IP，1+4+1+7 |
| domain 目标的**回包**（下行，inline IPv6） | 25 | 47.2% | 29.4% | 11.1% | 4.7% | 1+4+1+19 |
| IPv4 flow0 first/open | 12 | 30.0% | 16.7% | 5.7% | 2.3% | 带 7 B 地址 |
| IPv4 extra flow first | 13 | 31.7% | 17.8% | 6.1% | 2.5% | |
| IPv6 flow0 first | 24 | 46.2% | 28.6% | 10.7% | 4.5% | 带 19 B 地址 |
| IPv6 extra flow first | 25 | 47.2% | 29.4% | 11.1% | 4.7% | |
| domain first（=永远） | 40 | 58.8% | 40.0% | 16.7% | 7.2% | |

> 注：flow 0 的“first”只在 open 帧出现。**生产上“first”的持续长度由“是否收到过压缩下行”决定**（`src/bin/myquic2-client/hub.rs:45-59,139-149`；`src/bin/myquic2-client/assoc.rs:345-377`）；纯上行 flow 永远是 first 形态。

### 3.2 TRAIN 每项开销（含 header 摊薄）

当前每项 = `1 B iflg + [1 B flow if 额外 flow] + (1–2 B) len`；header 6 B（mixed）/7 B（SAME_FLOW 非 0）。`flow0` 是隐式的。

| 场景 | 每项开销（p<128 / p≥128） | 说明 |
|---|---:|---|
| IPv4 flow0 steady | 2 / 3 | 最常见（同 destination 小包流） |
| IPv4 extra flow steady（mixed） | 3 / 4 | |
| IPv4 extra flow steady（SAME_FLOW） | 2 / 3 + header 7 | 同 flow 整帧 |
| IPv4 flow0 first/open | 9 / 10 | 每帧每 flow 只重复一次开地址（同帧后续项压缩，`already_open` 位图，`src/bin/myquic2-client/assoc.rs:378-396`） |
| IPv4 extra first/open | 10 / 11 | |
| IPv6 flow0 first/open | 21 / 22 | |
| IPv6 extra first/open | 22 / 23 | |
| domain（永远 inline） | 37 / 38 | `1+1+len+34` = 37/38 |

摊薄到每个 payload：`overhead = H_train/n + item`。以 flow0、60 B 为例：

| n（每 TRAIN 项数） | 2 | 4 | 8 | 16 | 18 |
|---|---:|---:|---:|---:|---:|
| 当前（header 6 + 2 B/项） | 5.00 | 3.50 | 2.75 | 2.38 | 2.33 |

### 3.3 >512 B 的 v2 开销（每 payload / 每分片）

`limit=1162`（MTU 1200）：v4 单帧上限=1150 B、分片 chunk=1144 B；v6 单帧上限=1138 B、chunk=1132 B；domain L=30 单帧上限=1123 B、chunk=1117 B。

| payload p | v4 头/片数 | v6 头/片数 | domain 头/片数 |
|---|---:|---:|---:|
| 513 | 12 / 1 帧 | 24 / 1 | 39 / 1 |
| 1000 | 12 / 1 | 24 / 1 | 39 / 1 |
| 1200 | **36 / 2**（18 B×2） | **60 / 2**（30×2） | **90 / 2** |
| 1420 | 36 / 2 | 60 / 2 | 90 / 2 |
| 8192 | 144 / 8 | 240 / 8 | 360 / 8 |

`limit=1362`（MTU 1400）：v4 单帧上限=1350 B、分片 chunk=1344；v6 上限=1338、chunk=1332；domain 上限=1323、chunk=1317。

| payload p | v4 头/片数 | v6 头/片数 | domain 头/片数 |
|---|---:|---:|---:|
| 1200 | 12 / 1 | 24 / 1 | 39 / 1 |
| 1420 | 36 / 2 | 60 / 2 | 90 / 2 |
| 8192 | 126 / 7 | 210 / 7 | 315 / 7 |

> 也就是说：**默认 MTU 1200 时，1200 B 的 payload 必然 2 片、每片重复 7/19/34 B 地址**；把 `initial_mtu` 提到 1400 后 1200 B 变单帧（README.md:777 已有建议）。协议层能做的只是把“每片 18/30 B 头”压到 8–12 B。

---

## 4. 现存 wire 低效 / 限制全清单（带证据与量化）

> P0 = 阻断“上下行都优化 / full duplex / 可演进”目标的协议结构问题；P1 = 实际字节/CPU 开销；P2 = 死码/一致性/攻击面。

### P0

**L1 域名目标两个方向都无法 flow 压缩**。[代码]
- 上行：client 对 `TargetAddrRef::Domain` 硬编码 `(MQP3_NO_FLOW, true)`，每帧 inline（`src/bin/myquic2-client/assoc.rs:355-377`）；不分配 flow slot。
- 下行：server 只对 `flow_for_ip(src)` 命中的 **IP** flow 压缩（`src/bin/myquic2-server/reader.rs:134-152`），而 `FlowTable::flow_for` 比较整个 `TargetAddr`，Domain 项永远不匹配 IP（`src/mqp/v3.rs:722-733`）→ 域名回包一律 `NO_FLOW` inline；`reader.rs:100-107` 的注释确认“domain target 的 resolved IP client 不知道”。
- 代价：
  - 上行：**每帧 37–40 B 头**（L=30），60 B DNS 查询时 MQP 字节 100 B、头占 40%；每 1000 payload 97,564 B → 加 FLOW_ACK≈61,300 B（**−37%**）。
  - 下行：回包是 `NO_FLOW`+**inline IP**（v4 13 B / v6 25 B 头；不是 40 B，因为 server 回的是解析后的 IP），同样无法压缩；ACK 后压到 2–5 B，每 1000 payload v4 70,378→61,189（**−13%**）、v6 82,564→61,189（**−26%**）。[模型]

**L2 纯上行 flow 永远不压缩**。[代码]
- 唯一“确认”来源是客户端成功 stage 一个该 flow 的**压缩下行帧**（`src/bin/myquic2-client/dispatcher.rs:283-289,318-326` → `AssocEntry::confirm_flow`，`src/bin/myquic2-client/hub.rs:139-149`）；没有 FLOW_ACK。
- 纯上行（日志/遥测/单向游戏输入/DNS 无响应）永远保持 inline：SINGLE 12/13 B、TRAIN 每帧每 flow 重复一次 7/19/34 B 地址。
- 代价：稀疏单向流 60 B 时 72 B/payload（v4）→ 加 ACK 后 65 B（A）/62 B（B），**−9.7% / −13.9%**；高速单向流（32 payload/burst，每 TRAIN 只重复 1 次地址）约 −2%。[模型]

**L3 >512 B 与所有分片退回 MQP-2，地址在每片重复**。[代码]
- 路径：`src/bin/myquic2-client/assoc.rs:301-310`、`src/bin/myquic2-server/reader.rs:629-677`、`src/bin/myquic2-client/assoc.rs:882`、`src/bin/myquic2-server/reader.rs:199`。
- 代价：513–1150 B 单帧头 12/24 B（v4/v6）而不是 5/6（A）或 2/3（B）；1200 B @1162 是 36/60 B/2 帧而不是 22/16 B；8192 B 是 144/240 B 而不是 88/64 B。
- 额外：v2 的每一片都重复 `sess u32`，且重组器按 `(sess,id)` 而不是 `(sess,flow,id)` 键控（`src/udp/reassembler.rs:392`），因此 v3 FRAG 即使接线也要先改重组器（README.md:664-670 已指出）。

**L4 完全没有控制面**。[代码]
- `MQP3_CTL=0x40` 只是常量（`src/mqp/v3.rs:25`），全仓库没有 opcode/encode/decode；README.md:610 明确 “reserved; no CAPS/HELLO/FLOW_ACK opcodes implemented”。
- 缺失后果：
  1. 无 HELLO/CAPS → 无能力协商、无 in-band 版本门禁（默认 ALPN 还是 `h3` 伪装，`src/mqp/ack.rs:1-22`；`normalize_alpn` 默认返回 h3），只能靠 TLS 失败或静默丢包。
  2. 无 FLOW_ACK/REJECT → L1/L2；服务端 table full/SSRF 拒绝时客户端无从得知，只能一直 inline。
  3. 无 SESS_CLOSE/FLOW_CLOSE → session 只能靠 180 s idle 回收（`src/bin/myquic2-server/table.rs:382`；60 s sweep，`accept.rs:799-812`），服务端 socket/reader task 至少多活 0–180 s；flow id 也因 “never reuse” 只能整会话丢弃（`src/mqp/v3.rs:675-690`）。
  4. 无法协商 `max_flows`/`max_train_items`/`max_reassembly`/新特性——新格式只能整体升级。

**L5 v3 FRAG 已实现但未接线**。[代码] `src/mqp/v3.rs:542-671` 无生产调用；两端收到 `0x30` 直接 `REFUSED` 计数（`src/bin/myquic2-client/dispatcher.rs:330-335`；`src/bin/myquic2-server/accept.rs:720-724`）。现状 wire 上它是一段“占着 kind、永远不出现”的死格式。

### P1（字节 / 每帧开销）

**L6 每帧 4 B `sess u32`**。[代码] 所有 v3 帧都带：SINGLE/TRAIN/FRAG header（`src/mqp/v3.rs:63,186,313-315,583`）。稳态头 5 B 的 80% 是它。去掉这 4 B（→ 候选 B 的 2 B 头）相当于 28 B payload 的 9.1%、60 B 的 4.6% MQP 字节；只换 u16（省 2 B）则是 6.1%/3.1%。
- 注意：**单纯缩成 u16 不是免费的**，见候选 C 的复用安全分析（§6.3）。

**L7 每帧一个 session，TRAIN 不能跨 session 合帧**。[代码]
- 帧头只有一个 `sess`（`src/mqp/v3.rs:63`）；客户端按 association 任务分别 staging/flush（`src/bin/myquic2-client/assoc.rs:566-580,704-714,1027-1074`），服务端按 `sess_reader_task` 分别 flush（`src/bin/myquic2-server/reader.rs:729-900`）。同一 QUIC 连接上多个 association 的小包**只能各自成帧**。
- 代价（[模型]）：32 个 session 各 1 个 60 B payload 的一轮，当前 32 帧/2080 B → 合帧后 2 帧/2020 B（wire −2.9%，**send 调用 16×**）；8 session×4 payload/轮：8 帧 → 2 帧（**4×**），wire −2.1%。价值主要在 CPU/锁，不在带宽（§7.3）。

**L8 TRAIN 每项 2–4 B**。[代码] `1 B iflg + [1 B flow] + 1–2 B len`（`src/mqp/v3.rs:260-267,320-343`）。即使整帧全部是同一 flow 且无 inline/open，也强制每项 1 B flags——该字节在“all-compressed same flow”场景是纯冗余。候选 A 的 COMPACT 项可省 1 B/项（60 B 小包：每 1000 payload ~1,000 B，−1.6%；28 B：−3.3%）。[模型]

**L9 “SAME_FLOW 不能用于 flow 0”是表达缺口，不是字节损失**。[代码+推导] 见 §2.4：flow 0 mixed = `6+2n`，若强行 SAME_FLOW+flow0 = `7+2n`，更大。真正可省的是 L8 的每项 flags 字节。把它列进“限制”是因为：flag 位被浪费、解码器多一条不可达分支、且“紧凑项模式”必须重新定义才能同时覆盖 flow 0 与非 0。

**L10 64 flow/session + 单调不复用**。[代码] `MQP3_MAX_FLOWS=64`（`src/mqp/v3.rs:53-56`），`insert` 单调、`next>=64` 后返回 None（`737-746`），`remove` 只在“inline open 与现有 id 冲突”时清空、**不会**降 `next`（`770-791`；测试 `1047-1061` 钉住不复用）；表满后客户端对**新目的地永远 inline**（`src/bin/myquic2-client/assoc.rs:367-377`）。
- 代价：长时间高 churn 的 association（游戏反复换房、DNS 轮询很多 resolver）在第 65 个目的地后永久退化到 12/13 B 头（小包 +7/8 B/帧）；且 `MQP3_FLOW_TABLE_MAX_BYTES=4096` 作为每 session admission 记账（`src/mqp/v3.rs:48-51`；`src/config/tuning.rs:309-317`），不能简单靠“加大表”解决，需要控制面 + 生命周期。

**L11 512 B staging cap 是代码政策而不是 wire 限制**。[代码] 复用 `BATCH_SMALL_MAX`（`src/mqp/batch.rs:9`；客户端 `src/bin/myquic2-client/assoc.rs:301`；服务端 `src/bin/myquic2-server/reader.rs:629`；staging 缓冲按 `BATCH_SMALL_MAX*2` 预分配，`assoc.rs:578`）。它直接造成 L3：只要把“大 payload 走 v3 SINGLE/FRAG”接上，就能删掉 v2 数据面（代价是 scheduler 要区分“可入 TRAIN 的小项”和“单独发给大项”）。

**L12 flow 表按 session 存 + 4 KiB/session 记账**。[代码] `AssocEntry.flows: ArcSwap<FlowTable>`（`src/bin/myquic2-client/hub.rs:57-59`）；server 每 `SessEntry.flows`（`src/bin/myquic2-server/table.rs:51-56`）；每 session 收费 4096 B（`src/mqp/v3.rs:51`、`src/config/tuning.rs:316`）。若改成连接级 flow 表，这笔记账要改成“每连接上限”，并进 `per_connection_memory_bytes`（当前只含 `FRAG_MAX_HELD_BYTES`，`src/config/tuning.rs:282-287`）。

**L13 `idx u8/total u8` 与 8 KiB 重组上限：不是当前瓶颈**。[代码] `MQP_FRAG_MAX_TOTAL=64` 在 QUIC 最小 MTU 下已经覆盖 UDP max：`ceil(65507/(1162−11−19))=58 ≤ 64`（`src/mqp/fragment.rs:57-75` 有编译期断言）。真正的限制是 `MQP_FRAG_MAX_PAYLOAD=8192`（`src/mqp/fragment.rs:31-47`，loss-amplification 论证）——它挡住 >8 KiB 的 UDP 载荷（NFS/大 EDNS0 等），但加宽 `total` 并无必要；若未来通过 CAPS 协商更大重组上限，64 片 × ~1132 B 仍 ≥ 64 KiB 的 UDP 上限，保持 u8 即可。

### P2（死码 / 一致性 / 攻击面）

**L14 CTL/未知 kind 的静默丢弃规则**。[代码] 见 §2.1 关键事实②：CTL 静默丢（`accept.rs:725`、`dispatcher.rs:341`），<5 B 的 CTL 记 `REFUSED`（`v3_sess` 条件，`src/mqp/v3.rs:78-83`），`0x50+` 的未知 kind 被当 v2 丢弃。新格式必须改为“未知 kind/opcode → 计数丢弃 + 不 panic + 不误解析”，并且给 CTL 一条独立于 v3_sess 最小长度的入口。

**L15 `SRC` flag 是死特性**。[代码] codec 完整实现（`src/mqp/v3.rs:32-34,38-39,229-234`），但**所有生产调用点 `src_override` 都是 `false`**（`src/bin/myquic2-client/assoc.rs:975,992`；`src/bin/myquic2-server/reader.rs:248,259`；只有测试里出现过非 false 的语义讨论）。目标换端口回包的现状是 `NO_FLOW` inline 完整源地址（`src/bin/myquic2-server/reader.rs:134-152`），并不用 `S`。新格式要么用它（压缩“同 flow 但源端口变了”的回包），要么删掉。

**L16 TRAIN 解码两遍**。[代码] 先 `decode_train` 全帧校验（`src/mqp/v3.rs:464-505`）再 `TrainItems` 重解（`394-428`），inline address 的 decode 执行两次。CPU 常数小（每项几十 ns），不是 wire 问题，但新格式设计时可以让校验与解析共用一次扫描。

**L17 旧 MQP-2 数据面死码/双实现**。[代码] `0x06 BATCH` 两端仍解码（`accept.rs:1041`；`dispatcher.rs:347`）但生产不发送（客户端发送函数是 `#[cfg(test)]`，`assoc.rs:1151-1167`）；`0x02/0x05` 仍有两套编码器、prefix cache、重组器（`src/mqp/datagram.rs`、`fragment.rs`、`src/udp/fragmenter.rs`、`reassembler.rs`）。新协议若不再兼容 v0.2.0，应把 `0x02/0x05/0x06` 解码一并删除，减少攻击面与代码分叉。

### 额外的身份/安全面（不是字节问题，但决定新格式能不能安全落地）

**L18 会话/flow id 的可信边界**。[代码]
- `sess` 由客户端进程分配（`hub.rs:326-353`，0 保留；服务端拒绝 `s==0`，`src/bin/myquic2-server/reader.rs:956-960`），session 表**每连接独立**（`accept.rs:797`）→ 跨客户端无碰撞面；同一连接内是单 trust domain（客户端进程自己）。
- flow 压缩帧的 id 解析失败只丢该帧并 `REFUSED`（`accept.rs:640-666,700-719`；`dispatcher.rs:246-289,291-326`），**不会猜路由**；inline open 与已有 id 冲突时服务端删除旧绑定而不是覆盖（`accept.rs:731-770`）→ fail-closed。这些不变量在新格式里必须保留并强化（连接级 id 一旦复用，错路由的后果从“本 session 丢包”升级为“别的 association 收错包”）。

---

## 5. 设计空间分析（不兼容重设计，仍叫 MQP-3）

### 5.1 两种寻址模型

| | **Model S：session-scoped（现状/候选 A/C）** | **Model K：connection-scoped（候选 B）** |
|---|---|---|
| 数据帧地址 | `sess u32`（每帧）+ `flow u8`（可选） | 只有 `flow id`（连接级）；session 只出现在 open/CTL |
| flow 表 | 每 session 64 项，session 销毁即释放 | 每连接 N 项；entry = `(sess, target, dir/owner)` |
| 热路径查找 | 先 sess 表/FastSess，再 session 内数组索引 | 一次连接级 id 表查找；sess 只用于 open 与投递 |
| 跨 session TRAIN | 不能（帧头单 sess） | 天然可以（item 只带 flow id） |
| 内存/记账 | 4 KiB/session（`v3.rs:51`） | 需新增 per-connection 上限（建议 4096 项×~40 B≈160 KiB，可配） |
| 全双工对称性 | 下行依赖上行的 flow 表（镜像） | 双向都可独立 open；服务端可主动流 |
| 实现改动 | 小：改 codec + 控制面 | 大：连接级表 + 每连接 TX staging + 生命周期/DoS |

> 结论：**要同时满足“上行下行都优化 + 真 full duplex + 跨 session 打包”，Model K（connection-scoped）是唯一自洽的模型**。Model S 能做到 L1/L2/L3 的大部分字节收益，但 L7（跨 session）和“服务端主动 flow”做不到。

### 5.2 flow/session id 编码候选

| 方案 | 稳态每帧 id 成本 | id 空间 | 复用安全 | 评价 |
|---|---|---|---|---|
| 现状：`sess u32 + flow u8` | 4 B（+1 可选） | u32×u8 | 会话内不复用 | 太贵；见 L6 |
| `sess u16 + flow u8` | 2 B（+1） | 65535×64 | **危险**：u16 wrap 65,536 次分配后与 180 s 内仍存活的旧 session 撞 id（§6.3） | 除非配可靠 SESS_CLOSE/ACK，不建议 |
| `sess u24` | 3 B | 16.7M | wrap 需 93k/s 才在 180 s 内复用，实际安全 | 比 u32 只省 1 B，鸡肋 |
| 连接级 `u16` varint | 1 B（id≤127）/2 B（≤16383）/3 B | 65,535/连接 | 单调分配 + 3 s 复用窗（同 `FRAG_ID_SAFE_WINDOW_MS` 思路）+ close 后 guard | **推荐**；32k 活 flow 对 1024–4032 session/连接足够 |
| 连接级 `u32` | 4 B（或 varint 3–5 B） | 4.29e9 | 实际永不复用，最安全 | 字节上没有意义 |
| 12/20-bit 位域 | 1.5 B 级 | 4096/1M | 中 | 收益 <1 B，解码复杂，不推荐 |
| “短 id” nibble 模式（可选） | **1 B**（kind 高 4 bit 中留位 +低 4 bit 短 id） | 16 个热 flow/方向 | 与 u16 主空间共存 | 只在稀疏小包场景再省 1 B（60 B 时 1.6%），可作为 B 的可选扩展（§6.2-B′） |

### 5.3 方向与所有权：三种候选

1. **共享双向 id（client 权威）**：现状语义。客户端分配、服务端镜像；下行回包复用客户端 flow id（`reader.rs:128-171` 已经是这个行为）。优点：零额外下行 open、协议简单；缺点：服务端**不能主动开 flow**（full-cone/换端口回包只能 forever inline），且下行完全依赖上行的 open 是否到达。
2. **per-direction sender-owned（各管各的方向）**：每侧为自己的发送目标分配 id，接收侧按“到达方向”查各自的表。真对称、服务端可主动流；代价是同一逻辑 flow 可能出现两个 id（除非做镜像优化），且下行首包要一次 inline open。
3. **单一命名空间 + 所有权半区（推荐折中）**：一个连接级表，id 低半区归 client、高半区归 server（用 flags 的 1 bit 表达高半区，使 varint 仍 1–2 B）；两侧都可 open；同一逻辑 flow 只有 1 个 entry，镜像/服务端主动流都只是“谁先 open”。**候选 B 采用这一种。**

### 5.4 session 与 flow 的映射 / 生命周期

- `session` = 一个 SOCKS UDP association（客户端）/ 一个 relay socket（服务端）。**只承载“投递到哪个 app socket / 哪个目标”的路由**。
- `flow` = `(session, target)`；连接级 id；创建者（client 或 server）在 open 帧里写 `session u32 + addr`；接收侧校验后安装 `flow → (session, target, owner, state)`。
- session 的创建保持现状的“隐式创建”：第一个引用它的 open 即创建（服务端仍然做 SSRF/私有地址校验后才安装，`forward_server_dgram` 路径）；关闭用 CTL `SESS_CLOSE`（幂等、可重发），180 s idle 仍是兜底。
- flow 关闭用 `FLOW_CLOSE`；`flow id` 只有在 `now − close ≥ 2×FRAG 窗口` 后才允许复用（与 fragment id 同一套 splice 论证，`src/mqp/fragment.rs:118-145`），否则回退 inline；id 空间耗尽同样回退 inline（不是丢包）。

### 5.5 控制面需求清单

| opcode | 方向 | 必要性 | 内容（建议） | 作用 |
|---|---|---|---|---|
| `HELLO` | C→S | 必须 | magic `M3`、wire-ver u8、flags u8/u16 | in-band 版本断言；缺失/版本不符 → 连接级 fail-closed |
| `CAPS` | S→C | 必须 | ver、feature bits、max_conn_flows、max_flow_per_session、max_reassembly、max_train_items | 能力协商/限额；跨版本灰度 |
| `FLOW_ACK` | S→C（双向对称版可两侧） | 必须 | `sess u32 + flow id + status + [resolved addr]` | ①纯上行 flow 确认压缩；②域名 open 回传解析到的 IP（client 拿它写 SOCKS5 reply header）；③table full/SSRF reject 时回 REJECT（同帧或独立 opcode） |
| `FLOW_REJECT` | S→C | 必须 | sess、flow、reason | 客户端对此 flow 永久 inline |
| `FLOW_CLOSE` | 双向 | 可选（推荐） | sess、flow | 快速释放表项与重组 partial |
| `SESS_CLOSE` | C→S | 推荐 | sess、reason | 立即释放 relay socket/reader task，不再等 180 s |
| ACK piggyback（位） | 双向 | 可选 | 帧 flags 的 1 bit + 1 个 flow id | 有反向流量时用“回来的一帧”确认 open，避免额外 CTL 帧 |

控制帧全部是 **DATAGRAM 上的不可靠、幂等**帧；丢一次最多晚一点压缩/晚一点释放，不影响正确性。`HELLO/CAPS` 建议在连接建立后发送 2–3 次（或直到收到 CAPS），但**不阻塞数据**：数据帧的格式由版本决定，二者必须同版本部署（README.md:723-737 已明确 matched deployment）。

### 5.6 安全 / 内存边界

| 风险 | 现状 | 新格式要求 |
|---|---|---|
| 压缩帧指向不存在的 flow | 丢该帧+计数（`accept.rs:640-666`；`dispatcher.rs:246-289`） | 保持；未知 id 永不分配 |
| 延迟帧在 id 复用后错投给**另一个 session** | 现状 id 不复用→不存在 | **关键新增风险**：连接级 id 必须“不复用或复用前 ≥2×FRAG 窗口且旧 session 已关闭”，并保留 tombstone（否则是跨 app 错投，比丢包严重） |
| inline open 冲突（同 id 不同地址） | 服务端删旧绑定（fail-closed，`accept.rs:731-770`） | 保持 fail-closed，且**不得**跨 owner 半区/跨 session 覆盖 |
| open 洪水（每条 open 一次 resolve/SSRF/socket） | session 表有 fair-share（1024–4096/连接，`table.rs:416-421`）、全局 8192（`table.rs:374`）、idle 回收 | 连接级 flow 表需 per-conn/per-session 双 cap + 每秒 open 速率限制；超限回 `FLOW_REJECT`，不分配 |
| 伪造/重放 | TLS 1.3 内，QUIC DATAGRAM 不可重放 | 不需要每帧 MAC；不要把 DATAGRAM 用于 0-RTT 敏感路径（现状 auth token 只 1-RTT，README.md:737） |
| 内存 | 每 session 4 KiB flow 记账 + 256 KiB/连接重组（`src/config/tuning.rs:282-287,309-317`） | 连接级表（建议默认 4096 项，`~40 B/项`≈160 KiB/连接）计入 `per_connection_memory_bytes`；重组上限不变 |

### 5.7 解码器 DoS 限制（新格式建议，全部在解析前校验）

1. 帧长 ≤ `conn.max_datagram_size()`；截断即丢，不 panic。
2. `DATA`：flow id varint ≤3 B 且值在已协商范围；`OPEN` 的 `sess` 非 0、addr 经 `TargetAddrRef::decode` 校验（unspecified/scope 拒绝，`src/mqp/addr.rs:122-160`）。
3. `TRAIN`：`count ∈ 1..=max_train_items(=64)`；flow 字典 `nfl ≤ count` 且 id 互异；每项 len ≤ `min(8192, 帧剩余)`；**必须精确吃到帧尾**（现状如此，`src/mqp/v3.rs:506-508`）。
4. `FRAG`：`1 ≤ total ≤ 64`、`idx < total`、chunk 非空且 ≤帧剩余；`(flow,id)` 的 partial 总量 ≤8 KiB、每连接 `held ≤256 KiB`、partials ≤256（沿用现状常量，`src/mqp/fragment.rs:165,176`）。
5. 未知 kind / CTL opcode / 保留 flag 位 → **计数丢弃**（不是静默、不是 panic）；新 kind 不得落入 v2 解析。
6. flow 安装：校验通过（session 存在或可创建、目标经 SSRF/策略、连接/会话 cap 未满）才 insert；否则 `FLOW_REJECT`。
7. CTL 帧长度固定/有界；HELLO magic/ver 不符 → 连接级错误码关闭（不做部分解析）。

---

## 6. 候选 wire 格式（3 个）

> 共同约定：一个 QUIC DATAGRAM body 仍只承载**一个** MQP 帧（与现状一致，`encode_single` 无 len 字段；TRAIN 负责打包）；首字节高 4 bit = kind，低 4 bit = flags。**协议名全程 MQP-3**；CAPS 里的 `wire-ver` 只是 MQP-3 的内部 wire 版本号（示例 =2），候选 A/B/C 只是本文的分析代号。
> 下列所有 `flow id` 均为**连接级**（候选 B）或**session 内 u8**（候选 A/C），示例中的 id 取值按对应假设；`sess u32` 在 open/CTL 中保留 u32（open 频率低，避免任何复用风险）。

### 6.1 候选 A —— session-scoped 增量（低风险子集）

**目标**：保留现有帧语法，补控制面、把 v3 FRAG 和大包接进生产、加 domain/pure-uplink 压缩与紧凑 TRAIN；不引入连接级表。

**帧表**

| 帧 | 布局（A） | 稳态头 | open 头 | 相对现状变化 |
|---|---|---:|---:|---|
| `SINGLE 0x10` | `0x10\|flags \| sess u32 \| [flow u8] \| [addr] \| payload` | 5 / 6 | 12/13/24/25/40 | 不变；**用于所有 ≤limit−header 的 payload**（不再 512 截断） |
| `TRAIN 0x20` | `0x20\|flags \| sess u32 \| count u8 \| [flow u8 if SAME_FLOW≠0] \| item*`；新增 flag `COMPACT=0x2`：所有项已压缩时省略 iflg——整帧同 flow（或全 flow 0）时 item = `len varint \| payload`，混合 flow 时 item = `flow u8 \| len varint \| payload` | header 6/7，item 1–2 | item 9/10/21/22/37 | COMPACT 对“同 flow”项省 1 B/项，对混合 flow 项保持 2 B/项 |
| `FRAG 0x30` | `0x30\|flags \| sess u32 \| [flow u8] \| id u32 \| idx u8 \| total u8 \| [addr on open] \| chunk` | **11 / 12** | 18/30/46（首片） | 接线；稳态无地址 |
| `CTL 0x40` | `0x41 HELLO`、`0x42 CAPS`、`0x43 FLOW_ACK(sess u32+flow u8+status+[resolved addr])`、`0x44 FLOW_REJECT`、`0x45 FLOW_CLOSE`、`0x46 SESS_CLOSE` | — | — | 新增 |

**关键行为**
- 域名目标：client 给域名分配 flow（不再强制 NO_FLOW），open 帧 inline domain；server 解析/SSRF 通过后安装 `flow→(domain, resolved_ip)` 并回 `FLOW_ACK(resolved_ip)`；之后上行用 flow 压缩，下行从该 resolved_ip 来的回包用**同一 flow id** 压缩（client 用 ACK 里的 IP 写 SOCKS5 reply header）。
- 纯上行 IP flow：server 在 open 安装成功后回 `FLOW_ACK`（无 addr），client 立即转压缩。
- 大包/分片：全部走 `SINGLE`/`FRAG`，v2 数据面废弃（解码可留一版）。
- 不支持：跨 session TRAIN、服务端主动 flow（full-cone 仍 inline）。

**示例编码（sess=7）**
```text
SINGLE 稳态 IPv4 flow0, payload "abc":
  10 07 00 00 00 61 62 63                          ; 5 B header
SINGLE open IPv4 flow2 + 1.2.3.4:53:
  13 07 00 00 00 02 01 01 02 03 04 00 35 78        ; I|F, 13 B header
TRAIN COMPACT flow0, 2×("abc","de"):
  22 07 00 00 00 02 03 61 62 63 02 64 65           ; 0x22=TRAIN|COMPACT, 6 B hdr
FRAG steady flow0, id=0x12345678, idx=1/3, chunk="abc":
  30 07 00 00 00 78 56 34 12 01 03 61 62 63        ; 11 B hdr
CTL FLOW_ACK(domain, resolved 1.2.3.4:53):
  43 07 00 00 00 01 00 01 01 02 03 04 00 35        ; 14 B
```

### 6.2 候选 B —— connection-scoped 对称全双工（**推荐**）

**核心**：数据帧只带连接级 flow id；`session` 只出现在 open（`sess u32`）与 CTL；TRAIN 项可跨 session；两侧都可 open（id 分半区）；FRAG key = `(flow, id)`。

**id 命名空间与 flags（候选 B 定义）**
- flow id = `u16`：`0x0000` 保留为 “inline/no-flow”；`0x0001..0x7FFE` 归 **client 分配**；`0x8001..0xFFFE` 归 **server 分配**；`0x7FFF/0xFFFF` 保留。
- 首字节 flags（数据帧）：`0x1 OPEN`（本帧携带 `sess u32 + addr` 的 open 描述）、`0x2 INLINE`（无 flow，`sess u32 + addr` 内联；与 OPEN 互斥，用于表满/一次性源，inline 地址即实际源，无需单独的 SRC 位）、`0x4 HI`（flow id 属服务端半区；解码时 `id |= 0x8000`）、`0x8 ACK`（可选：header 之后、OPEN 描述之前放 `nack u8 + ack 项（1 B flags + idvarint）[nack]`，用于确认对端已收的 flow）。
- 编码：id 用 LEB128，`HI` 时对 `id−0x8000` 编码 → 常见 1–127 的 id 恒为 1 B。

**帧表**

| 帧 | 布局（B） | 稳态头 | open 头（含 sess+addr） | 说明 |
|---|---|---:|---:|---|
| `DATA 0x10` | `0x10\|flags \| idvarint \| [sess u32 + addr if OPEN] \| payload` | **2**（id≤127）/3/4 | 13 / 25 / 40 | 无长度字段；一个 DATAGRAM 一个 payload |
| `DATA inline 0x12` | `0x12 \| sess u32 \| addr \| payload` | —（12/24/39） | — | 表满/无 flow 的 fail-safe 路径（≈v2 单帧） |
| `TRAIN same 0x21` | `0x21 \| count u8 \| idvarint \| item*`；item=`len varint \| payload` | header **3**（id≤127）；item **1–2** | — | 整帧同 flow，全部压缩 |
| `TRAIN dict 0x22` | `0x22 \| count u8 \| nfl u8 \| entry[nfl] \| item*`；entry = 1 B（bit7=HI 服务端半区、bit6=LONG 后随 varint id、低 6 bit=id 或 0），常见 1 B/flow；item=`idx u8 \| len varint \| payload`（idx 0..63） | header **3+k**（k=本帧不同 flow 数）；item **2–3** | — | 混合 flow；dict 只摊薄“同一 flow 多项”，**每项 1 B flow 引用模式（inline-flow）也必须保留**，当 flow 数≈项数时它更省；item 可跨 session（flow→session 在表里） |
| `FRAG 0x30` | `0x30\|flags \| idvarint \| id u32 \| idx u8 \| total u8 \| [sess u32 + addr if OPEN] \| chunk` | **8**（id≤127）/9/10 | 19 / 31 / 46（首片） | key=`(flow, frag id)`；重组内存上限沿用现状 |
| `CTL 0x40` | `0x41 HELLO`、`0x42 CAPS`、`0x43 FLOW_ACK(sess u32+idvarint+status+[addr])`、`0x44 FLOW_REJECT`、`0x45 FLOW_CLOSE`、`0x46 SESS_CLOSE` | — | — | 幂等 |

**打开/确认/关闭**
- open：`DATA`/`FRAG` 带 `OPEN` + `sess` + `addr`（+payload）。重复 open 幂等（同 id 同 `(sess,addr)` 视为重传；不同则丢弃并计数）。
- 确认：任一方向的 `ACK` 位/`FLOW_ACK` 都能确认（用于纯上行 + 域名 resolved-IP 回传）；请求/响应流量有**隐式确认**（对方第一个压缩帧即可证明映射已安装，和现状 `confirm_flow` 语义一致，`src/bin/myquic2-client/hub.rs:139-149`）。
- 关闭：`FLOW_CLOSE`/`SESS_CLOSE`；id 复用 guard ≥ `2×FRAG_TIMEOUT+Sweep`（3 s，与 `FRAG_ID_SAFE_WINDOW_MS` 同一论证，`src/mqp/fragment.rs:118-145`），tombstone 保留同窗口；超限/耗尽回退 `DATA INLINE`。
- 下行 mirror：服务端若已有该目标的 client flow，直接用 client id 回包（现状行为，零额外 open）；full-cone/换端口等 server-originated 流用自己的半区 id open 一次后压缩。

**示例编码**
```text
DATA steady client flow 5, payload "abc":
  10 05 61 62 63                                   ; 2 B header
DATA steady server-owned flow 5, payload "abc":
  14 05 61 62 63                                   ; flags.HI=0x4
DATA open flow 5, sess=7, 1.2.3.4:53, payload "abc":
  11 05 07 00 00 00 01 01 02 03 04 00 35 61 62 63  ; 13 B hdr
DATA inline (no flow), sess=7, 1.2.3.4:53, "abc":
  12 07 00 00 00 01 01 02 03 04 00 35 61 62 63     ; 12 B hdr
TRAIN same flow 5, 2×("abc","de"):
  21 02 05 03 61 62 63 02 64 65                    ; 3 B hdr + 4+3 B
TRAIN dict flows 5,9 (items flow5="abc", flow9="de"):
  22 02 02 05 09 00 03 61 62 63 01 02 64 65        ; 5 B hdr + 5+4 B
FRAG steady flow 5, frag id=0x12345678, idx=1/3, "abc":
  30 05 78 56 34 12 01 03 61 62 63                 ; 8 B hdr
CTL HELLO (M3, ver=2, flags=0):
  41 4D 33 02 00                                   ; 5 B
CTL CAPS (M3, ver=2, flags u16=0; max_conn_flows u16=0x1000,
          max_flow_per_sess u8=64, max_reassembly u16=0x2000, max_train u8=64):
  42 4D 33 02 00 00 00 10 40 00 20 40              ; 12 B
CTL FLOW_ACK(domain flow 5, resolved 1.2.3.4:53):
  43 07 00 00 00 05 00 01 01 02 03 04 00 35        ; 14 B
CTL FLOW_CLOSE(sess=7, flow=5):
  45 07 00 00 00 05                                ; 6 B
```

**B′（可选，1 B 稳态头）**：把 `0x50..0x5F` 的 16 个 kind 值定义为 “DATA short”：`0x50|lo` 中低 4 bit = 热 flow 槽号（每方向 16 个，由 `CAPS` 协商或固定为最近使用的 16 个 id），payload 紧跟；稳态头 **1 B**。收益：60 B 时再 −1.6%、28 B 时 −3.3%；代价：多一组 kind、热流映射状态、解码分支。**可以现在就把 kind 空间留出来，实现放第二阶段。**

### 6.3 候选 C —— session 桶 + u16 sess（**不推荐**）

**想法**：保留“session 是第一等地址”的模型，把 `sess u32→u16`（稳态头 5→3 B），TRAIN 加 `MULTI_SESS` 字典实现跨 session 打包，FRAG 用 `(sess u16, flow u8, id)`。

| 帧 | 布局（C） | 稳态头 |
|---|---|---:|
| `SINGLE 0x10` | `0x10\|flags \| sess u16 \| [flow u8] \| [addr] \| payload` | 3 / 4 |
| `TRAIN 0x20` | `0x20\|flags \| sess u16 \| count u8 \| [nsess u8 + sess u16×n if MULTI] \| [flow u8 if SAME_FLOW] \| item*`（MULTI 时 item +1 B sess index） | 4 / 5 |
| `FRAG 0x30` | `0x30\|flags \| sess u16 \| [flow u8] \| id u32 \| idx \| total \| [addr] \| chunk` | 9 / 10 |
| `CTL 0x40` | 同 A，但 sess u16 | — |

**为什么否决（复用安全）**：
- 客户端 session id 是**单调分配、从不复用**的 u32（`hub.rs:326-353`），服务端 session 只靠 180 s idle 或 sweep 回收（`table.rs:382`；`accept.rs:799-812`）。改成 u16 后，65,536 次分配就回绕；只要客户端在 180 s 内创建超过 65,536 个 association（平均 364 个/s，繁忙客户端/恶意本地 app 都能做到），**新 association 会拿到一个服务端仍认为属于旧 association 的 sess id**：服务端把新流量的回包投进旧 relay socket（错误的目标/端口），客户端 hub 却把回包投给新 app → 跨 association 串流。
- 要安全复用必须引入**可靠**的 SESS_CLOSE 确认（QUIC stream 或带重传的 CTL）、或 180 s 复用 guard（把新 session 速率压到 364/s）、或再带 1 B generation（稳态回到 4 B，收益只剩 1 B）。收益（2 B/帧）不足以抵消这套状态机与“串流”风险；而候选 B 把 sess 从数据帧里整个删掉，根本不存在复用问题。
- 例外：如果 product 明确要求“保留 session 为中心、且流量低 churn”，C 的 `MULTI_SESS` 也能拿到 L7 的 send 调用收益；但此时不如直接做 B。

---

## 7. 字节 / 调用节省模型

### 7.1 公式与假设

**假设（全部为模型输入，不是测量）**
- A1：只计 MQP 层，不含 IP/UDP/QUIC 头；每个 DATAGRAM 帧的 QUIC 层还有约 `1 B type + varint(len)` ≈2–3 B（两个候选一样，故不进入对比；帧数少时更省）。
- A2：`limit = 1162`（MTU 1200）与 `1362`（MTU 1400）。
- A3：无丢包/乱序；domain L=30；IPv4 默认。
- A4：TRAIN 只在同一 flush burst 内打包，burst=32 payload（`LAST_HOP_DRAIN=32`，`src/udp/batch.rs:46`）；每帧按预算贪心装，run-of-1 发单帧（现状行为，候选保持）。
- A5：候选 B 的 flow id ≤127（1 B varint），open 带 `sess u32`；候选 A 保持 `sess u32`。
- A6：候选的字节数是**按 §6 帧表手算**，未实现、未实测。

**公式**
```text
单帧：            W = p + H_single
TRAIN(n 项)：     W = H_train + Σ_i (O_item + p_i) ≈ H_train + n·(O_item + p)
                  n_max = floor((limit − H_train) / (O_item + p))     # 同尺寸项
分片：            F = ceil(p / (limit − H_frag)) ;  W = p + F·H_frag
每 1000 payload： W1000 = Σ每帧帧长 ;  Frames1000 = Σ帧数
省比：            save% = (W_cur − W_new) / W_cur
调用：            每 DATAGRAM 帧 = 1 次 quinn send（1 次连接状态锁，
                  src/bin/myquic2-client/egress.rs:110-112；src/bin/myquic2-server/reader.rs:503-506）
CPU 量级：        ΔCPU ≈ Δframes · c_send，c_send ≈ 200–300 ns/帧
                  （[文档/既有测量] PROTOCOL_ANALYSIS.md §4 的估算口径，本次未复测）
```

### 7.2 工作负载矩阵（每 1000 payload，`limit=1162`；`1362` 只列不同项）

| 工作负载 | 当前 字节/帧数 | A 字节/帧数 | B 字节/帧数 | A save | B save |
|---|---:|---:|---:|---:|---:|
| W1 IPv4 60 B 同目的地（32/burst） | 62,378 / 63 | 61,378 / 63 | 61,189 / 63 | −1.6% | −1.9% |
| W1b IPv4 28 B 同目的地 | 30,192 / 32 | 29,192 / 32 | 29,096 / 32 | −3.3% | −3.6% |
| W2 8 flow 同 session 扇出 60 B | 63,378 / 63 | 62,378 / 63 | 62,189 / 63 | −1.6% | −1.9% |
| W2b 8 flow 扇出 200 B | 205,314 / 219 | 204,314 / 219 | 203,657 / 219 | −0.5% | −0.8% |
| W3 **域名上行** 60 B（L=30，domain 地址） | **97,564 / 94** | **61,378 / 63** | **61,189 / 63** | **−37.1%** | **−37.3%** |
| W3b 域名**下行回包** 60 B（v4，inline IP） | 70,378 / 63 | 61,378 / 63 | 61,189 / 63 | **−12.8%** | **−13.1%** |
| W3c 域名**下行回包** 60 B（v6，inline IP） | 82,564 / 94 | 61,378 / 63 | 61,189 / 63 | **−25.7%** | **−25.9%** |
| W4 跨 8 session×4 项 60 B | 63,500 / 250 | 63,500 / 250 | 62,189 / 63 | 0 | **−2.1%（调用 4×）** |
| W5 跨 32 session×1 项 60 B | 65,000 / 1000 | 65,000 / 1000 | 62,189 / 63 | 0 | **−4.3%（调用 16×）** |
| W7 高速单向 60 B（32/burst，无回包） | 62,602 / 63 | 61,378 / 63 | 61,189 / 63 | −2.0% | −2.3% |
| W7b **稀疏单向** 60 B（1/burst） | 72,000 / 1000 | 65,000 / 1000 | 62,000 / 1000 | **−9.7%** | **−13.9%** |
| W8 bulk 1200 B IPv4（@1162，2 片） | 1,236,000 / 2000 | 1,222,000 / 2000 | 1,216,000 / 2000 | −1.1% | −1.6% |
| W8 v6 1200 B @1162（2 片） | 1,260,000 / 2000 | 1,222,000 / 2000 | 1,216,000 / 2000 | −3.0% | −3.5% |
| W9 full-cone 下行 60 B 单源（server-originated，v4 inline IP） | 70,378 / 63 | 70,378 / 63（A 不支持） | 61,201 / 64 | 0 | **−13.0%**（v6 −25.9%） |

`limit=1362` 的差异（其余行与 1162 相同）：
- W8 bulk 1200 B IPv4：当前 1,212,000/1000 帧 → A 1,205,000 → B 1,202,000（−0.6% / −0.8%）；
- W8 v6 1200 B：当前 1,224,000/1000 → A 1,205,000 → B 1,202,000（−1.6% / −1.8%）；
- W8 1420 B（任何 MTU 都 2 片）：v4 当前 36 B → A 22 → B 16（−1.0% / −1.4% of 1456 B）；v6 当前 60 → 22/16（−2.7% / −3.0%）。
- W2b 200 B 扇出：帧数 219→188，字节曲线同上（−0.5%/−0.8%）。
- W3c 域名下行（v6）：当前 1362 时为 82,378 B / 63 帧（1162 时 82,564 / 94 帧），A/B 不变 → −25.5%/−25.7%。

### 7.3 每类工作负载的结论（给决策用）

| 工作负载类 | 字节收益 | 调用收益 | 说明 |
|---|---|---|---|
| 域名目标（DNS/game by hostname/WebRTC） | 上行 **−35% ~ −38%**；下行 v4 −13%、v6 −26% | 帧数 94→63/1000（上行） | 最大收益；需 FLOW_ACK 带 resolved IP；下行当前是 inline IP（不是 domain 地址）所以降幅小于上行 |
| 稀疏纯上行（遥测/单向流） | −10% ~ −14% | 1× | 需 FLOW_ACK；B 比 A 多省 3 B/帧 |
| 高速同目的地小包 | −1.6% ~ −3.4% | ~1× | 现有 TRAIN 已摊销；只剩 header/项开销 |
| 多目的地同 session 扇出 | −0.5% ~ −1.9% | ~1× | 现有 TRAIN 已支持；B 的 dict 头在“项少 flow 多”时反而不如 A，故 B 需保留 inline-flow 模式 |
| 跨 session 小包 | −2% ~ −4.3% | **4× ~ 16×** | **CPU/锁收益为主**；需要两端都做 connection 级 staging（最大工程项） |
| 513 B ~ 单帧上限（新覆盖） | 头 12/24→5/6（A）或 2/3（B）；即每 payload v4 −7（A）/−10（B）、v6 −19（A）/−22（B） | ~1× | 默认 MTU 下 v6 收益翻倍；接近 v2 单帧上限的 payload（v4 1150/v6 1138）在 A/B 下上限 1157/1160，还可能 2 帧→1 帧 |
| 分片/bulk（1200–8192 B） | −0.7% ~ −3.5% | 1×（片数基本不变） | 协议头不是 bulk 瓶颈（§8.3） |
| full-cone 下行 | v4 −13%、v6 −26%（仅 B） | 63→64（多 1 个 open 帧） | 需要服务端主动 flow；A/C(client 权威) 做不到；当前回包是 inline IP 而非 domain 地址 |

### 7.4 按 §3 矩阵的逐 payload 字节（standalone；省比 = 相对当前同场景）

| p | 目标 | flow | 形态 | 当前 字节 | A 字节 | B 字节 | A save | B save |
|---:|---|---:|---|---:|---:|---:|---:|---:|
| 28 | v4/v6 | 0 | steady | 5+28=33 | 33 | 30 | 0 | **−9.1%** |
| 28 | v4/v6 | 1 | steady | 34 | 34 | 30 | 0 | **−11.8%** |
| 60 | v4/v6 | 0 | steady | 65 | 65 | 62 | 0 | −4.6% |
| 60 | v4/v6 | 1 | steady | 66 | 66 | 62 | 0 | −6.1% |
| 200 | v4/v6 | 0 | steady | 205 | 205 | 202 | 0 | −1.5% |
| 512 | v4/v6 | 0 | steady | 517 | 517 | 514 | 0 | −0.6% |
| 28 | domain（上行地址） | 0 | steady（当前 inline / A,B 需先 ACK） | 68 | 33 | 30 | **−51.5%** | **−55.9%** |
| 60 | domain（上行地址） | 0 | steady（同上） | 100 | 65 | 62 | **−35.0%** | **−38.0%** |
| 200 | domain（上行地址） | 0 | steady（同上） | 240 | 205 | 202 | −14.6% | −15.8% |
| 512 | domain（上行地址） | 0 | steady（同上） | 552 | 517 | 514 | −6.3% | −6.9% |
| 60 | domain 回包（v4） | 0 | steady（当前 NO_FLOW+inline IP / A,B 需先 ACK） | 73 | 65 | 62 | −11.0% | **−15.1%** |
| 60 | domain 回包（v6） | 0 | steady（同上） | 85 | 65 | 62 | −23.5% | **−27.1%** |
| 28 | v4 | 0 | first（open） | 12+28=40 | 40 | 41 | 0 | −2.5%（B 多 1 B flow id） |
| 60 | v6 | 0 | first（open） | 24+60=84 | 84 | 85 | 0 | −1.2% |
| 1200 v4 @1162 | v4 | — | 2 片 | 1,236 | 1,222 | 1,216 | −1.1% | −1.6% |
| 1200 v6 @1162 | v6 | — | 2 片 | 1,260 | 1,222 | 1,216 | −3.0% | −3.5% |
| 1200 v4 @1362 | v4 | — | 1 帧 | 1,212 | 1,205 | 1,202 | −0.6% | −0.8% |
| 1200 v6 @1362 | v6 | — | 1 帧 | 1,224 | 1,205 | 1,202 | −1.6% | −1.8% |
| 8192 @1162 | v4 | — | 8 片 | 8,336 | 8,280 | 8,256 | −0.7% | −1.0% |
| 8192 @1162 | v6 | — | 8 片 | 8,432 | 8,280 | 8,256 | −1.8% | −2.1% |

> 表中 steady 的 B 列 2 B 假设 flow id ≤127；id 128–16383 时 B 稳态头 3 B，收益相应减 1 B。TRAIN 场景的逐项开销与摊薄见 §3.2 与 §7.2（TRAIN 比单帧再省 2–4 B/帧的固定头，且 B 的 same-flow 项为 1 B/项）。

---

## 8. 推荐

### 8.1 方向

**做候选 B（连接级 flow 命名空间 + 对称双向 + 完整 CTL 面），分两阶段落地；候选 A 作为该方向的“字节子集”先上线验证。**

理由：
1. 它同时解决 P0 的 L1（域名双向）、L2（纯上行）、L3（>512/分片）、L4（控制面）、L5（FRAG 接线）、L7（跨 session）——A 只能解决前五个，且拿不到“真 full duplex”（服务端主动 flow）与跨 session。
2. 稳态头 2 B、分片头 8 B 已接近该模型的熵下界（kind/flags 1 B + id 1 B；分片 + id u32+idx+total）。剩余可选项只有 B′ 的 1 B 短头，收益 1 B/payload，**属于 cosmetic，可在 kind 空间里预留、后做**。
3. 现状每帧 4 B `sess` 是 5 B 稳态头的 80%；只要还想做“高 pps 小包/受限上行”，这是必须清掉的固定税。
4. 复用安全反过来证明“保留 session 在数据帧里并缩窄”不划算（候选 C）：B 把 sess 移出数据面后，u16 id + 3 s 复用窗即可安全。

**落地顺序（同一 wire，分功能启用；不是两套 wire）**
- 阶段 0（前置，非 wire）：改 per-connection TX staging 抽象（两端），让连接级聚合有落点；否则跨 session 永远是 0。
- 阶段 1：CAPS/HELLO + DATA/TRAIN/FRAG 新格式 + v3 FRAG 接线 + 域名/单向 FLOW_ACK；此时可以先只用 client 半区 id（等价于“共享双向 id”），先拿 L1/L2/L3/L5。
- 阶段 2：server 半区 id + 服务端主动 flow（full-cone）+ 跨 session TRAIN（启用 dict 模式）；需要阶段 0 的 staging。
- 阶段 3（可选）：B′ 1 B 短头；更大重组上限（CAPS 协商）；删除 v2 解码。

### 8.2 哪些改动是“真收益”，哪些是 cosmetic

**真收益**（按 ROI 排序）
1. **域名 flow 压缩（L1）**：上行 −35%~−38% MQP 字节；下行（当前 inline IP 回包）v4 −13%、v6 −26%；实现中等（server 要存 resolved IP 并回 ACK；client 要写 SOCKS5 reply header）。
2. **纯上行/单向 flow 的 FLOW_ACK（L2）**：稀疏单向 −10%~−14%。
3. **>512 B 与 FRAG 统一进 v3（L3/L5/L11）**：v2 数据面删除；单帧头 v4 12→5/2、v6 24→5/2（A/B）；分片头 v2 18/30 B → A 11 B / B 8 B（每片 v4 −7~−10、v6 −19~−22）；v6 与接近单帧上限的 payload 收益最大。
4. **跨 session TRAIN（L7）**：4×–16× send 调用，CPU/锁收益；wire 只 −2%~−4.3%。
5. **去掉每帧 sess（L6，B）**：稳态 −3 B/帧；稀疏小包 −4.6%（60 B）/ −9.1%（28 B）。
6. **服务端主动 flow（full-cone，B）**：该场景 v4 −13%、v6 −26%（当前回包是 inline IP，不是 domain 地址）。
7. **COMPACT TRAIN 项（L8）**：−1 B/项，1.6%~3.4%（小包）。

**cosmetic / 不建议**
- B′ 1 B 短头、`sess u24`、12/20-bit 拆位：<1 B/帧级别，先预留空间即可。
- “SAME_FLOW for flow 0”：字节上无收益（§4-L9），只需在新格式里用 COMPACT/显式全 0-flow 语义取代。
- 加宽 `idx/total`（L13）：无必要；8 KiB→更大重组上限是独立产品决策（loss amplification，`src/mqp/fragment.rs:31-47`）。
- 内容压缩/FEC/重传：与本文目标无关，不引入。
- **不要为了 bulk 吞吐改协议**：见 8.3。

### 8.3 bulk 现实检查

1200 B payload 的 MQP 头即使在最差场景（MTU 1200、IPv6、2 片）也只占该 payload 的 5%（60/1260）；IPv4 是 2.9%（36/1236）。改成 B 只能把它降到 1.3%（16/1216，v4/v6 分片头同宽），**IPv4 总 wire 节省 ≤1.6%、IPv6 ≤3.5%**；而同一 1200 B UDP 报文外层的 IP+UDP+QUIC（约 55–80 B）以及 QUIC 拥塞控制/MTU 才是吞吐主项。**bulk 的可行优化是配置（`initial_mtu` 1200→1360/1400，README.md:777）和减少分片/避免丢片放大，不是协议头。** 协议重设计的价值集中在：域名目标、高 pps 小包、多目的地/多 session 扇出、以及“每帧一次 quinn send”的 CPU。

### 8.4 风险与对策

| 风险 | 对策 |
|---|---|
| 连接级表的生命周期/内存/DoS | 双 cap（连接/会话）+ open 速率限制 + `FLOW_REJECT` 回退 inline；默认 4096 项/连接并计入 `per_connection_memory_bytes` |
| id 复用导致跨 session 错投 | 不复用；复用需 ≥2×FRAG 窗口 + close + tombstone；tombstone 命中 fail-closed |
| 跨 session staging 的公平性/队头 | 每连接一个 stager 会成为热点：用每 worker/每连接分片、有界队列、按 burst flush；不要跨 burst 等待 |
| CAPS/HELLO 丢失导致不压缩 | 压缩只在“确认”后启用（现状语义），丢失最多晚压缩；HELLO/CAPS 重发若干次 |
| 版本错配 | ALPN fail-closed（建议默认用 `myquic2/3` 而不是 `h3` 伪装，或 CAPS magic 不匹配即关连接）；同版本部署前提不变 |
| 实现回归面大 | 先落候选 A 的字节收益（L1/L2/L3)，B 的连接级表/staging 分阶段；每阶段保留 v2 解码兜底一版 |

---

## 9. 歧义与开放问题（不臆造答案）

- **Q1 “full duplex” 的定义**：本文按“双向使用同一套帧语法、双方都能压缩/发数据、下行不依赖上行 open”解释。若用户的意思是“双向独立调度/独立拥塞/独立连接”，那超出 wire 范围，需 Lead 澄清。
- **Q2 ALPN/版本门禁**：任务只要求协议仍叫 MQP-3；未说明 ALPN 字符串能否改、是否允许灰度期双栈。本文建议 CAPS 带 wire-ver、ALPN 保守用 `myquic2/3`（或另加后缀），不引入新协议代号。
- **Q3 是否需要兼容 v0.2.0 对端**：任务说允许不兼容重设计，本文按“不需要混合版本、同版本部署”写；若需要灰度，需要额外的“双格式探测/ALPN 后缀”设计，本文未展开。
- **Q4 域名 ACK 的语义**：server 回传的 resolved IP 与目标实际回包源 IP 可能不同（多 A/anycast/换端口）。本文规则：flow 压缩只用于“与 ACK/已安装映射一致”的源；不一致时用 `INLINE` 一帧回退（inline 地址即实际源）。SOCKS5 reply header 用哪个 IP 需产品确认（现状用回包实际源）。
- **Q5 服务端主动 flow（full-cone）是否要压缩**：决定 B 是否值得保留 server 半区/双向 ownership；若产品不需要，B 可退化成“单权威共享 id”（更简单，字节相同）。
- **Q6 flow 表默认上限**：本文建议 4096/连接、64/会话；实际值取决于内存预算（`max_peer_memory_mb`）与客户端 4032 association 上限，需产品给数。
- **Q7 MTU 分布**：bulk/分片的收益量级取决于部署 MTU（1200 默认 vs 1400 已知路径）；需目标环境数据。
- **Q8 测量**：本文没有 Linux 目标机数据；域名压缩、跨 session staging 的 CPU 收益必须用 `hotpath_bench` + 真实 app 复测。另：`FRAG_ID_SAFE_WINDOW` 注释里 “under 0.01% below ~1.4M fragmented payloads/s” 与公式 `W/(2^32·1000/pps+W)` 不符（1.4M/s 时约 0.098%），属注释笔误，不影响代码语义——重设计文档时建议修正（`src/mqp/fragment.rs:131-138`）。
- **Q9 控制面可靠性载体**：CTL 走 DATAGRAM（不可靠、幂等）还是 QUIC stream（可靠但多一条流）？本文倾向 DATAGRAM + 重发；`SESS_CLOSE` 若要求“立即且可靠”可走 QUIC stream。

---

## 10. 给 Lead 的摘要（≤30 行）

1. **现状**：v0.2.0 的 MQP-3 只有“同 session、IP 目标、≤512 B”的 flow/TRAIN 压缩；v3 FRAG codec 已写但零调用；CTL 只有常量。
2. **最大结构性缺口**：域名目标双向都不能压缩（上行每帧 40 B 头、L=30；下行回包 inline IP 13/25 B 头）；纯上行 flow 永久 inline（无 FLOW_ACK）；>512 B 全部回退 MQP-2（每片重复完整地址）；无控制面、无法跨 session 合帧。
3. **字节最大单笔收益 = 域名 flow 压缩**：上行每 1000 个从 97,564 B → ~61,300 B（**−37%**）；下行回包（当前 inline IP）v4 70,378→61,189（−13%）、v6 82,564→61,189（−26%）；需要 FLOW_ACK 回传 resolved IP。
4. **纯上行/单向**：稀疏流 60 B 从 72,000 → 62,000~65,000/1000（**−10%~−14%**；高速流因 TRAIN 摊销约 −2%）。
5. **>512 B / 分片**：头 12/24→5/6（A）或 2/3（B）；片头 18/30→11/8；1200 B@MTU1200 2 片 −1.1%~−1.6%（v6 −3.0%~−3.5%）；8192 B 8 片 −0.7%~−1.0%。
6. **跨 session TRAIN**：send 调用 4×（8×4）~16×（32×1），wire −2%~−4.3%；价值在 quinn 锁/分配 CPU，但需要两端 connection 级 staging（最大工程项）。
7. **推荐候选 B**：连接级 flow id（u16，varint 1–2 B；id 半区归 client/server 双方可 open）+ 数据帧去 sess（稳态 2 B、分片 8 B）+ TRAIN 项可跨 session（same-flow 1 B/项、dict 模式 2 B/项）+ 完整 CTL（HELLO/CAPS/FLOW_ACK/REJECT/CLOSE）+ 域名/单向 ACK + 服务端主动 flow。
8. **候选 A（保留 sess u32 的增量）** 作为低风险子集先做：拿域名/单向压缩、FRAG 接线、大包 v3 化、COMPACT 项（−1 B/项），不做跨 session/服务端主动 flow。
9. **候选 C（u16 sess 折中）否决**：65,536 次分配即 wrap，180 s 内 >364 assoc/s 就会复用仍在服务端的旧 session → 跨 association 串流；要安全得加可靠 close 或 generation，收益不足以抵消。
10. **bulk 现实**：1200 B 包 MQP 头 1.0%（v4 单帧）~4.8%（v6 2 片）；重设计对 bulk 吞吐影响 IPv4 ≤1.6%、IPv6 ≤3.5%，**不要为 bulk 改协议**；bulk 该调 `initial_mtu`/窗口。
11. **cosmetic**：B′ 1 B 短头、sess u24、12/20-bit 拆位、加宽 idx/total、flow0 的 SAME_FLOW——收益 <1 B/帧或本来无字节损失，预留 kind 空间即可，不必为它们单独设计。
12. **证据与口径**：全部数字 = 只读代码审计 + python3 模型（无丢包、burst=32、L=30、MTU 1200/1400）；未 build/test/实测；落地前需 Linux `hotpath_bench` 复测。
13. **开放问题**：full duplex 定义；ALPN/版本门禁是否可改；是否要兼容 v0.2.0 灰度；域名 ACK 的 IP 语义（多 A/anycast）；是否要 full-cone 的服务端主动 flow（决定 B vs B-lite）；flow 表上限与内存预算；目标 MTU 分布。
14. **建议下一步**：Lead 拍板 B（推荐）还是 A（保守）→ 我方可继续输出候选 B 的完整 wire spec + 迁移/测试矩阵（本报告 §6.2 已有帧表与示例编码）。

---

### 附录 A：关键常量与出处（便于复核）

| 常量 | 值 | 出处 |
|---|---:|---|
| `MQP3_TRAIN_HEADER_LEN` | 6 | `src/mqp/v3.rs:63` |
| `MQP3_FRAG_PREFIX_LEN` | 11 | `src/mqp/v3.rs:66` |
| `MQP3_MAX_FLOWS` / `MQP3_MAX_TRAIN_ITEMS` | 64 / 64 | `src/mqp/v3.rs:56,60` |
| `MQP3_FLOW_TABLE_MAX_BYTES` | 4096 | `src/mqp/v3.rs:51` |
| `DGRAM_PREFIX_LEN` / `MQP_DGRAM_TYPE` | 5 / 0x02 | `src/mqp/datagram.rs:7,11` |
| `FRAG_PREFIX_LEN` / `MQP_DGRAM_FRAG` | 11 / 0x05 | `src/mqp/fragment.rs:14,29` |
| `MQP_FRAG_MAX_PAYLOAD` / `MQP_FRAG_MAX_TOTAL` | 8192 / 64 | `src/mqp/fragment.rs:47,55` |
| `FRAG_TIMEOUT_MS` / `FRAG_SWEEP_INTERVAL_MS` / `FRAG_ID_SAFE_WINDOW_MS` | 2000 / 500 / 3000 | `src/mqp/fragment.rs:107,116,145` |
| `FRAG_MAX_HELD_BYTES` / `FRAG_MAX_PARTIALS` | 256 KiB / 256 | `src/mqp/fragment.rs:165,176` |
| `MIN_PATH_DGRAM_BUDGET` | 1162 | `src/mqp/fragment.rs:64` |
| `BATCH_SMALL_MAX` / `MAX_BATCH_ITEMS` | 512 / 16 | `src/mqp/batch.rs:7,9` |
| `LAST_HOP_DRAIN` | 32 | `src/udp/batch.rs:46` |
| `MAX_UDP_ASSOCS` | 4032 | `src/config/tuning.rs:116` |
| `MAX_SESSIONS_GLOBAL` / `LOCAL_SESS_MAX` / `SESS_IDLE_MS` | 8192 / 4096 / 180,000 | `src/bin/myquic2-server/table.rs:374,375,382` |
| `DEFAULT_INITIAL_MTU` / 上下限 | 1200 / 1200..=1472 | `src/config/tuning.rs:193-198` |
| DATAGRAM 预算 | `MTU − 38` | README.md:777 |
| ALPN 默认 | `h3`（`myquic2/3` 可选） | `src/mqp/ack.rs:1-22` |

### 附录 B：现状帧的 golden bytes（可直接对拍）

| 场景 | 字节（hex） | 总长 |
|---|---|---:|
| SINGLE steady flow0, sess=7, payload "abc" | `10 07 00 00 00 61 62 63` | 8 |
| SINGLE steady flow2, sess=7, payload "abc" | `12 07 00 00 00 02 61 62 63` | 9 |
| SINGLE open flow0, sess=7, 1.2.3.4:53, "abc" | `11 07 00 00 00 01 01 02 03 04 00 35 61 62 63` | 15 |
| TRAIN 2×flow0 ("abc","de"), sess=7 | `20 07 00 00 00 02 00 03 61 62 63 00 02 64 65` | 15 |
| TRAIN SAME_FLOW flow3 2 项, sess=7 | `21 07 00 00 00 02 03 00 03 61 62 63 00 02 64 65` | 16 |
| FRAG v3 steady flow1, sess=7, id=0x12345678, idx=1/3, "abc" | `32 07 00 00 00 01 78 56 34 12 01 03 61 62 63` | 15 |
| MQP-2 0x02, sess=7, 1.2.3.4:53, "abc" | `02 07 00 00 00 01 01 02 03 04 00 35 61 62 63` | 15 |
| MQP-2 0x05, sess=7, id=0x12345678, idx=1/3, 1.2.3.4:53, "abc" | `05 07 00 00 00 78 56 34 12 01 03 01 01 02 03 04 00 35 61 62 63` | 19 |

> 现有 golden 测试见 `src/mqp/v3.rs:814-844,907-945,947-968,994-1010`；上表与之一致（`0x12` 的 flow 字节位置、TRAIN item 的 `iflg|len|payload` 顺序）。

---

*（报告完）*
