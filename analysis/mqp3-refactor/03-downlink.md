# MQP-3 下行（server → client）数据通路深度分析

> **基线**：`HEAD d2f9658` / `v0.2.0`（本文所有 `file:line` 均指该提交）
> **范围**：服务端把目标回包送回客户端这条下行链路的**协议结构 + 实现结构**，以及
> "一条 QUIC 连接承载大量 UDP session"这一工作负载下的下行扩展性。
> **方法**：只读代码审查 + 模型算术；**未运行 cargo build/test、未做 perf**。
> 所有 ns / CPU 数字都是**模型估算**（锚点见 §3.4），字节数是确定性的协议算术。
> 字节口径沿用仓库既有分析：`PROTOCOL_ANALYSIS.md:108-110`（每包 55 B：IP 20 + UDP 8 +
> QUIC short header 27）、`PROTOCOL_ANALYSIS.md:509-516`（MTU 1200 → DATAGRAM 预算 1162 B；
> 预算 1362 B 对应 1400 B 路径；每个 DATAGRAM 帧另有 3 B 帧头）。
> 说明：55 B/包 与 1162 B/帧 两个口径来自不同层的估算（两者相加会略超 1200 B），
> 本文按任务指定沿用；它们只影响**绝对**线上字节，不改变各方案的相对排序（见 §3.6）。

---

## 0. TL;DR

1. **下行的结构性瓶颈不在"每回包多几字节 MQP 头"，而在"一个 session 一个独立发送上下文"**：
   每 session 一个 socket + 一个 reader task + 一个私有 TRAIN 暂存器（`reader.rs:720-766`、
   `reader.rs:1132-1143`），而 `TRAIN` 帧头携带唯一的 `sess u32`（`v3.rs:63`），所以
   **同一条 QUIC 连接上不同 session 的回包在协议上永远不可能合进一个 DATAGRAM**。
2. **小回包（≤512 B）在单 session 内已经批得很好**（同 session 的 burst 最多 64 项/预算填满，
   `reader.rs:629-664`）；缺口集中在"多 session 同时有回包"与"单 session 多 flow 交替回包"。
   前者被协议禁止合帧，后者被 `last_flow` 单条 memo + 64 槽线性扫描打穿（`reader.rs:137-145`、
   `v3.rs:730-733`）。
3. **"一连接 32 session、每 session 1 flow、88 B 回包"的量化结果**（1000 回包，B=1162）：
   现状 = **1000 个 DATAGRAM 帧 / 1000 次 `send_datagram` / 1000 次帧分配**；
   连接级暂存器（每项带 sess）= **84 帧 / 84 次调用 / 84 次分配**（11.9×）。
   线上字节：若 quinn 的"同 poll 多 DATAGRAM 合包"不生效 → **−34.4%**；
   若理想合包（12 帧/包）→ **仅 −1.6%**。**真实值在两者之间，必须先测 quinn 合包率**（§3.6）。
   协议能确定的收益是 **帧数/调用数/分配数 12–36×**，不是吞吐数量级。
4. **下行真正"白送"的字节在压缩语义，而不是合帧**：域名目标回包、换端口/full-cone 回包目前
   永远 inline（`reader.rs:146-154`），13 B 头 vs 压缩后 5–6 B 头；而**首帧绑定成本是 0 字节**
   （`flow + inline` 与今天的 `NO_FLOW + inline` 同为 13 B）→ 一个"下行 flow→源地址绑定"
   协议语义即可把这些回包省 **7–8 B(v4)/19–20 B(v6)/回包**（小包 ≈ 7–38% 帧体）。
5. **控制面缺口是下行生命周期成本，不是带宽**：无 `SESS_CLOSE/FLOW_CLOSE`，短会话 zombie 占坑
   180 s → 关联 churn > **45 个/s** 即可能吃满全局 8192 session 池（§4.2）；flow 表 64 槽用满后
   该 session 的所有新目标**永久退化为 inline**（§4.3）。
6. **协议 vs 实现要分开卖**：
   - **协议层（必须改 wire）**：P1 跨 session TRAIN、P2 下行 flow 源绑定（域名/换端口/full-cone）、
     P3 控制面 close/ack、P4 >512 B 的 v3 大帧、P5 紧凑 FRAG、P6 CAPS、P7 连接级 id。
   - **纯实现层（wire 不动）**：I1 复用鉴权阶段已查到的 flow id + per-reader 源→flow 小 memo、
     I2 单条 run 免 arena 拷贝、I3 flow 表/allowlist 索引化、I4 连接级暂存器与公平调度、
     I5 per-connection 回包 reactor（去每 session task/timer）、I6 >512 B 直接发 v3 SINGLE。
   其中 **I1/I2/I6 是无风险净收益**；**P1 必须与 I4 一起做才有意义**（见 §5.3 里程碑）。

---

## 1. 现状：下行端到端通路

### 1.1 会话模型：一 session = 一 socket + 一 task + 一暂存器

| 资源 | 位置 | 说明 |
|---|---|---|
| 内核 UDP socket | `reader.rs:1102-1121` | `udp_socket_dual_small("[::]:0")`，每 session 一个临时端口；`SO_*BUF` = 64 KiB/方向（`lib.rs:244`） |
| reader task | `reader.rs:1132-1143` | 每 session 一个 `tokio::spawn(sess_reader_task)` |
| 读缓冲 | `reader.rs:7-15, 739` | 8 KiB+1（`UDP_RECV_MAX+slack`），线程局部池只回收缓冲、不共享 socket/task（`reader.rs:28-65`） |
| 60 s 定时器 | `reader.rs:732-733` | 每 session 一个 interval：idle 判定 + PMTU 刷新 |
| 回包暂存器 | `reader.rs:758-766` | `arena: Vec<u8>` + `staged: Vec<ReplyItem>` **task 私有**，最大一帧 |
| flow 表句柄 | `reader.rs:1130-1131`、`table.rs:51-56` | `Arc<ArcSwap<FlowTable>>`，与上行共享（客户端 open、服务端镜像） |
| allowlist 镜像 | reader task 局部（`reader.rs:748-757`） | epoch 门控的 `Arc<RecentAddrs>` |

> 关键结论：**下行发送上下文（连接、stager、缓存）的粒度是 session，不是 QUIC 连接。**
> 一条连接上 4032 个 session（`tuning.rs:116` `MAX_UDP_ASSOCS=4032`）就是 4032 套上述资源。

### 1.2 阶段逐段（file:line 证据）

```text
目标回包
 ① 目标 socket 可读 → reader task 唤醒
 ② rs.recv_from(&mut buf) 取 head（reader.rs:768-772）
 ③ 一个 wakeup 内再 drain 最多 31 条：recvmmsg 到线程局部 scratch，
    在 borrow 内原地处理（reader.rs:806-902；udp/batch.rs:528-546, 591-611）
 ④ handle_session_reply（全同步，reader.rs:480-717）：
    ④a 截断检测 → ④b limit==0 处理 → ④c unmap 源地址
    ④d 回包源鉴权：epoch 门控 allowlist 16 环（reader.rs:579-594, pin.rs:22-54）
       └ ring miss 时用 per-session flow 表做第二授权源（reader.rs:596-608, v3.rs:730-733）
    ④e FullCone 例外（reader.rs:609-618）
    ④f 源地址 → flow id：`flow_for_ip`（一槽 memo，miss 时 64 槽线性扫描）
       （reader.rs:124-145；v3.rs:722-733）
    ④g 小于等于 512 B → arena 拷贝 + staged.push（reader.rs:629-664, 124-174）
 ⑤ burst 结束/预算不足 → flush_reply_train（reader.rs:906-915, 665-674）
 ⑥ run==1 → v3 SINGLE；run>1 → v3 TRAIN；编码器按预算精确算长
    （reader.rs:215-298；v3.rs:151-198, 285-347）
 ⑦ try_send_datagram → quinn::send_datagram_wait 单次 poll（每帧一次 connection-state
    互斥锁）→ 进 quinn 发送队列（udp/send.rs:84-95；reader.rs:503-511）
 ⑧ quinn driver：DATAGRAM 帧编码（body 再拷入 packet）+ AEAD + sendmsg/GSO
 ⑨ 客户端 dispatcher：read_datagram 逐帧 pop → 解码/flow 还原 → 写回 app socket
    （client/dispatcher.rs:225-344, 663-723, 769-849）
```

大回包分支：`n > BATCH_SMALL_MAX(512)` → 先 flush 已暂存 TRAIN，再走 **MQP-2**
`DgramFragmenter::send`（`reader.rs:665-716`、`udp/fragmenter.rs:178-394`）：能装下就
`0x02` 单帧（12 B 头，IPv4），装不下就 `0x05` 分片（每片 18 B 头 + 重复地址）。

### 1.3 每回包成本账（小回包 ≤512 B、IP flow、稳态）

下表的粒度是**一条回包**；"每帧"列只在 run>1 时摊薄。假设 Linux + 分片运行时（当前默认）。

| 成本项 | 每回包计数 | 证据 / 备注 |
|---|---|---|
| 系统调用 — 收 | 1 次 `recv_from`（head） | `reader.rs:769`；同一 wakeup 的后续回包每 31 条摊 1 次 `recvmmsg`（`udp/batch.rs:528`） |
| 系统调用 — 发 | ≈1 次/quinn 包（按帧数摊薄） | 驱动层 sendmsg/GSO；`send_datagram` 本身不直接 syscall |
| quinn 互斥锁 | **1 次/帧** | `SendDatagram::poll` 内 connection-state 锁，`udp/send.rs:84-95`、`reader.rs:503-511` |
| 用户态内存拷贝 | **3 次**（arena 1 + 编码 1 + quinn packet 1） | arena：`reader.rs:164-165`；编码：`v3.rs:196, 343`；packet：quinn-proto `Datagram::encode`（`PROTOCOL_ANALYSIS.md:79-95`） |
| 分配 | **1 次/帧**（精确大小 `Vec`→`Bytes`，无二次控制块） | `v3.rs:313`、`v3.rs:174`、`mqp/datagram.rs:44-72` 注释 |
| 任务跳转 | **0**（整条处理同步，不走 channel） | `reader.rs:471-478`、`reader.rs:814-842` |
| 唤醒 | 1 次/socket 就绪（≈1/回包）；1 次/帧唤醒 quinn driver | `try_send_datagram` 的 `now_or_never` 单 poll（`udp/send.rs:71-83`） |
| 表扫描 — allowlist | 16 槽线性扫描 | `pin.rs:24-27, 47-53`（`RecentAddrs` 280 B，clone-on-write） |
| 表扫描 — flow | 0（memo 命中）/ **64 槽+ArcSwap load**（memo miss） | `reader.rs:137-145`；环 miss 时**再扫一遍**（`reader.rs:601` + `607` 使 memo 失效） |
| 原子操作 | coarse 时钟 2 relaxed load、epoch 1 load、`last2` ≤1 store/s、stats 线程局部 | `time/coarse.rs`、`stats/udp_stats.rs:89-121` |
| 线上 — 每帧固定 | TRAIN 头 6 B（`v3.rs:63`）+ 每项 2 B（同 flow）/3 B（异 flow） | `v3.rs:261-267` |
| 线上 — 每载荷 | 0（flow 0 压缩）/ 1 B（额外 flow）/ +7·19 B（inline） | `v3.rs:143-149` |
| 线上 — QUIC/DATAGRAM | 3 B DATAGRAM 帧头 + 55 B/包（按同包帧数摊薄） | `PROTOCOL_ANALYSIS.md:108-110` |

**"每帧 vs 每载荷"拆分（重要的是这个）**：

- **每帧（可摊薄）**：quinn 锁、帧分配、TRAIN 头、DATAGRAM 帧头、55 B 包开销、driver 的
  AEAD+syscall。这些是"合帧"能省的。
- **每载荷（摊不薄）**：收 syscall、socket 唤醒、allowlist 扫描、flow 查找、arena 拷贝、
  编码拷贝、quinn packet 拷贝、kernel 收发拷贝。这些只能靠"少回包 / 少拷贝 / 少扫描"。
- CPU 的**大头每载荷**（收 syscall ≈1 µs、driver 摊 ≈0.1 µs、唤醒 ≈0.2 µs），所以
  **协议合帧对下行 CPU 的上限 ≈ 0.2–0.3 µs/回包（约 10–15%）**；这是 §3 表格里
  "帧数 12–36×↓ 但 CPU 只降 ~10–15%"的原因。

### 1.4 回包形态的成本差异

| 形态 | 走哪条路 | 固定头 | 额外每回包成本 |
|---|---|---|---|
| ≤512 B、IP flow 已知 | v3 TRAIN（同 session 内） | 5–6 B | arena 拷贝；run==1 时 arena 拷贝**纯浪费**（§1.5） |
| ≤512 B、域名目标 | v3 SINGLE/TRAIN **inline** | 13 B(v4)/25 B(v6) | 无 flow 压缩、无跨帧复用 |
| ≤512 B、换端口/full-cone | `NO_FLOW` inline | 13/25 B | 同上；`MQP3_FLAG_SRC` 定义了但服务端从不置位（`v3.rs:31-34`、`reader.rs:189,258`） |
| 513 B–B（单帧装得下） | **MQP-2** `0x02` | 12 B(v4)/24 B(v6) | 掉出 v3：没有 flow 压缩、客户端走 v2 解码、前缀缓存按 session 重建 |
| >B | **MQP-2** `0x05` 分片 | 18/30 B/片 | F 次分配、F 次 quinn 锁、F 个发送队列项；地址每片重复 |

### 1.5 一个具体的实现层浪费：run==1 的 arena 拷贝

`handle_session_reply` 先把载荷拷进 arena（`reader.rs:164-165`），burst 结束
`flush_reply_train` 若发现 `staged.len()==1` 就调 `flush_reply_single`，后者把
**同一个 arena 切片**再编进新帧（`reader.rs:231-240`、`179-206`）。对"一个 wakeup 只有一条
回包"（DNS 请求/响应、游戏 keepalive、单流媒体）的稳态，这就是**每回包多一次完整 payload
拷贝**。修法：第一条只记借用、第二条到达时才落 arena（I2，§5.2）。这是纯实现改动，0 风险。

### 1.6 任务/CPU 扩展性（每 session 一套任务栈）

- 每 session：1 个 task + 1 个 60 s interval + 1 个 socket + 8 KiB 用户态缓冲。4032 session/
  连接 = 4032 个 task/定时器/socket（`tuning.rs:116`）；全局 8192（`table.rs:374`）→ 用户态
  读缓冲上限 64 MiB（缓冲池只回收，不跨 task 共享，`reader.rs:28-65`）。
- 每回包 1 次 socket 唤醒 + 1 次调度；在分片运行时的 current-thread runtime 上，同一连接的
  所有 session reader 串行跑在一个核上（`main.rs:466-536`），所以"多 session"的 CPU 是
  **线性叠加**，没有并行度；线程拓扑只能靠多条 QUIC 连接/多个 ingress endpoint 横向扩。
- 每条连接共享 1 MiB 的 DATAGRAM 发送缓冲（`transport/limits.rs:84`、`build.rs:158-164`）；
  一个 session 的目标高速回包可以填满它，此时**别的 session 的回包被判 `Blocked` 并丢弃**
  （`udp/send.rs:28-41, 60-69`）——跨 session 无公平性、无隔离。这是结构性问题，见 §2 G8。

---

## 2. 下行缺口清单（带证据与量级）

| # | 缺口 | 证据 | 量级 / 后果 |
|---|---|---|---|
| **G1** | TRAIN 头只有一个 `sess u32`，**协议上不能跨 session 合帧** | `v3.rs:63`（`1+4+1`）、`reader.rs:263`（`encode_train(s, …)`）、`reader.rs:215-298` | 多 session 同时回包时帧数 = 回包数（§3）；这是 P1 的根因 |
| **G2** | 暂存器/arena 每 reader task 私有，**无法共享一帧缓冲** | `reader.rs:758-766`、`reader.rs:720-766` | 跨 session 合帧要求"连接级 stager"，是 I4 的根因；也是 G8 公平性的解 |
| **G3** | >512 B 回包整体掉出 v3 | `reader.rs:629`、`reader.rs:665-716`、`mqp/batch.rs:9` | 每帧多 7 B(v4)/18 B(v6) 头；丢 flow 压缩；客户端走 v2 路径；>B 时按 MQP-2 分片（18/30 B/片） |
| **G4** | 域名目标回包永远 inline | `reader.rs:146-154`；flow 表项存 `Domain`（`accept.rs:745`），而 `flow_for_ip` 只匹配 IP 项（`v3.rs:730-733`） | 每回包 13 B vs 5–6 B（v4）：小包 7–38% 帧体；见 §4.4 |
| **G5** | 换端口/full-cone 源永远 `NO_FLOW` inline；`SRC` 标志从未使用 | `v3.rs:31-34`（定义）、`reader.rs:189,258`（从不置 true）、`reader.rs:609-618` | 同上 13 B；TFTP/游戏重定向/WebRTC 这类"换端口"流量全部吃这个税 |
| **G6** | 鉴权 ring 仅 16 项；miss 后 flow 回退要**查两遍**（鉴权一遍 + 暂存一遍），且单槽 `last_flow` memo 对多源交替无效 | `pin.rs:35`、`reader.rs:596-608`、`reader.rs:137-145`、`reader.rs:602-608` | 32-flow 扇出：每回包 ~50–200 ns 额外（ArcSwap load + 2×64 槽扫描）；见 §3.5 |
| **G7** | 无控制面：无 `SESS_CLOSE/FLOW_CLOSE/FLOW_ACK/CAPS` | `v3.rs:25`（0x40 已保留，但无 encoder/decoder）；两端均 `_ => {}` 忽略（`accept.rs:718-725`、`client/dispatcher.rs:330-338`）；仓库自己留 TODO（`client/hub.rs:55`） | 生命周期/内存/churn：§4；也让"域名下行压缩/纯上行 flow 压缩"没有确认通道 |
| **G8** | 每连接 1 MiB DATAGRAM 缓冲无跨 session 公平性 | `transport/limits.rs:84`、`build.rs:158-164`、`udp/send.rs:60-69` | 一个高速 flow 可让同连接其它 session 的回包被判 `Blocked` 丢弃；无协议级公平，只能靠 stager 调度 |
| **G9** | 每 session task/socket/timer，回包路径无跨 session 批处理 | `reader.rs:1132-1143, 732-733, 739` | 每回包 1 recv syscall + 1 唤醒；多 session 线性叠 CPU；§1.6 |
| **G10** | run==1 时 arena 拷贝纯浪费 | `reader.rs:164-165` vs `231-240` | 每回包多 1 次 payload 拷贝（§1.5） |

---

## 3. "一条连接承载大量 session"的量化

### 3.1 口径与假设

- 工作负载 **W32**：一条 QUIC 连接上 32 个独立 UDP session（例：32 个 DNS 客户端、32 个
  独立 VPN 关联、32 路并发 UDP 应用），每 session 1 个 flow（flow id 0），回包
  **88 B** payload（典型 DNS/EDNS 响应），共 **1000 条回包**；目标回包交错到达。
- 预算 **B = 1162**（1200 路径）/ **1362**（1400 路径）；每 DATAGRAM 帧 **3 B** QUIC 帧头；
  每 UDP 包 **55 B** IP/UDP/QUIC 开销（`PROTOCOL_ANALYSIS.md:108-110`）。
- **quinn 合包**：quinn 在同一 transmit poll 里会把多个已排队的 DATAGRAM 帧写进同一个 QUIC
  包（`PROTOCOL_ANALYSIS.md:79-95`，quinn-proto `connection/mod.rs`）。**它是否发生取决于
  driver 何时被调度**：分片 current-thread runtime 上一个 reader 的一次 `send_datagram` 可能
  立刻唤醒 driver，也可能与其他 reader 的发送合并。所以给出**两个界**：
  - **不合包**：每帧独占一个 QUIC 包（55 B 开销/帧）；
  - **理想合包**：同包塞满 `floor(B/(3+帧体))` 帧（55 B 开销被摊薄）。
  真实部署在两者之间；**帧数/调用数/分配数在两种情况下都不变**，是确定收益。
- 现状建模："每 session 回包交错，一个 wakeup 通常只有 1 条回包" → run==1 → 每回包一个
  SINGLE（5 B 头，flow 0）；同 session 内多条回包时现状会合成 TRAIN（§3.5）。
- 连接级方案三个变体（都**保留现有 per-session flow id 语义**，只改"一个 DATAGRAM 里放多个
  session 的项"）：
  - **A（推荐第一步）**：新帧形 `TRAIN_X`：头 `kind/flags + count`（2 B），**每项带 sess u32**
    （`flags 1 + sess 4 + len varint 1 + payload`）。**不需要连接级 id 空间**，客户端逐项按
    sess 分发即可。
  - **B**：头里放"本帧 session 表"（`2 + 4×k + count`），每项 1 B session 下标。
  - **C（任务里说的"连接级 id"）**：连接级 u16 flow id，项里不再带 sess（`1+2+1+P`）。

### 3.2 主表：1000 回包 / 32 session / 88 B（当前 vs 连接级暂存器）

**B = 1162（MTU 1200）**

| 方案 | 每帧项数 | DATAGRAM 帧 | quinn 发送调用 | 帧分配 | 包数/字节（不合包） | 包数/字节（理想合包） | 线上 B/回包（合包界） | payload 效率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 现状 per-session stager | 1（W32 下 session 间交错） | **1000** | **1000** | **1000** | 1000 / **151.0 KB** | 84 / 100.6 KB | 100.6 | 87.5% |
| 连接级 A（每项 sess u32） | 12 | **84** | **84** | **84** | 84 / 99.0 KB | 84 / 99.0 KB | 99.0 | 88.9% |
| 连接级 B（帧内 session 表） | 12 | 84 | 84 | 84 | 84 / 100.2 KB | 84 / 100.2 KB | 100.2 | 87.9% |
| 连接级 C（连接级 u16 id） | 12 | **84** | **84** | **84** | 84 / 97.0 KB | 84 / 97.0 KB | 97.0 | 90.7% |

- **对"不合包"界：A 省 34.4%，C 省 35.7%**（省的是 1000→84 个包的 55 B 开销）；
- **对"理想合包"界：A 只省 1.6%，C 省 3.6%**（合包已经把 55 B 摊掉，只剩 MQP/DQH 头）；
- **确定性收益：帧数/发送调用/分配数 1000 → 84（11.9×）**，与 quinn 合包无关；
- **A vs C**：每回包只差 2 B（sess u32 vs u16+无 session 表），C 不值得为 2 B 引入连接级 id
  空间；**A 是"协议改动最小、收益几乎全拿"的方案**。

**B = 1362（MTU 1400）**

| 方案 | 每帧项数 | 帧数 | 不合包字节 | 理想合包字节 | 线上 B/回包 |
|---|---:|---:|---:|---:|---:|
| 现状 | 1 | 1000 | 151.0 KB | 72 包 / 100.0 KB | 100.0 |
| 连接级 A | 14 | **72** | 98.3 KB（−34.9%） | 72 / 98.3 KB（−1.6%） | 98.3 |
| 连接级 C | 14 | 72 | 96.3 KB（−36.2%） | 72 / 96.3 KB（−3.6%） | 96.3 |

> B 从 1162 升到 1362 对 W32 的收益只有 ~1%（每帧多装 2 项，55 B 摊得更薄），
> **MTU 的主要价值在"少分片"和大回包**（`tuning.rs:186-193`），不在小回包合帧。

### 3.3 敏感性：回包越小，合帧越值钱；越大越不值

| payload | 现状帧数 | 连接级 A 帧数 | 现状线上 B/回包（不/理想合包） | A 线上 B/回包 | A 相对不合包 | A 相对理想合包 |
|---:|---:|---:|---:|---:|---:|---:|
| 28 B | 1000 | **30** | 91.0 / 37.8 | 35.8 | **−60.7%** | **−5.2%** |
| 88 B | 1000 | 84 | 151.0 / 100.6 | 99.0 | −34.4% | −1.6% |
| 200 B | 1000 | 200 | 263.0 / 219.0 | 218.0 | −17.1% | −0.5% |

（B=1162。C 方案在 28 B 时 28 帧 / 33.7 B/回包，相对理想合包 −10.8%。）

**读法**：W32 的价值取决于 quinn 合包率。
- 若线上实测"1000 个回包 ≈ 1000 个 QUIC 包"（没有合包）→ 合帧省 17–61% 字节。
- 若实测"≈84 个包"（合包生效）→ 只省 0.5–11%，**主要收益是把"依赖调度巧合的合包"变成
  "协议保证的合包"**，以及 12–36× 的 send 调用/分配/客户端帧 pop 下降。
- **必须先测**：现状下 DATAGRAM 帧数 vs QUIC 包数之比（§7）。

### 3.4 CPU 账：连接级暂存器的真实上限

每事件估算锚点：收 syscall（含内核拷贝）≈1.0 µs；quinn `send_datagram_wait` ≈250 ns
（`PROTOCOL_ANALYSIS.md:542-557` 用 200–300 ns）；帧分配 ≈35 ns；88 B memcpy ≈8 ns；
Current-thread runtime 唤醒+调度 ≈200 ns；客户端 `read_datagram` pop ≈150 ns；
客户端发 app socket 1 次 syscall ≈0.8 µs。以下为**模型估算**：

| 每回包 CPU（W32，88 B） | 现状 | 连接级 A | 变化 |
|---|---:|---:|---:|
| 收 syscall（不可消） | 1.0 µs | 1.0 µs | 0 |
| socket 唤醒/调度（不可消，除非 reactor 化） | 0.20 µs | 0.20 µs | 0 |
| 鉴权+flow 查找+暂存拷贝 | ~0.05 µs | ~0.05 µs | 0 |
| quinn `send_datagram`（逐帧） | 0.25 µs | 0.25/12 ≈ 0.02 µs | **−0.23 µs** |
| 帧分配 | 0.035 µs | 0.003 µs | −0.03 µs |
| stager 入队/出队（新增） | 0 | ~0.04–0.08 µs | **+0.04–0.08 µs** |
| driver 每包摊（AEAD+sendmsg ≈0.95 µs/包，同包帧数摊） | 0.08 µs（12 帧/包） | 0.08 µs（帧变满） | ≈0 |
| **服务端净变化** | | | **≈ −0.18 ~ −0.22 µs/回包（−11~14%）** |
| 客户端：帧 pop+decode+cache（84 帧替 1000 帧） | ~0.20 µs | ~0.02 µs | **−0.18 µs/回包** |

- 50k 回包/s：服务端省 ≈ **9–11 ms/s ≈ 1% 单核**，客户端省 ≈ **0.9% 单核**；
  200k 回包/s：合计 ≈ **4–5% 单核**。
- **结论**：P1+I4 是"低个位数 CPU% + 线上字节的确定性上限"，不是数量级提速；
  它的真正价值是（a）当合包不生效时把线上字节打下来，（b）为 G8 的公平调度提供落点，
  （c）为后续连接级 id / 大帧统一腾出结构。
- 真正的大头是"每回包 1 收 syscall + 1 发 syscall + 1 次唤醒"，只有 **I5（per-connection
  reactor）** 能动唤醒/调度那 ~0.2 µs；syscall 数仍然消不掉。

### 3.5 对照：单 session 32 flow（VPN 一个关联）——跨 session 合帧帮不上

- 一个 session 一个 relay socket：32 个 flow 的回包全从**同一个 socket** 回来，
  现状 per-session stager 已能把它们合成一个 TRAIN：`n = floor((B−6)/(P+3))`
  （头 6 B + 每项 flags/flow/len 3 B）→ 88 B 时 12 项/帧，**1000 回包 = 84 帧**，已接近最优。
- 因此该场景的收益**不在 P1**，而在：
  1. **flow 查找**：32 个源交替回包 → 单槽 `last_flow` memo 每回包失效 →
     `flows.load()`(ArcSwap) + `flow_for_ip` 64 槽扫描，**每回包 ~50–150 ns**（I1）；
  2. **allowlist 环 16 < 32**：环 miss → 鉴权再走一次 flow 表扫描 + 让 memo 失效 →
     环 miss 的回包 ~100–200 ns（I1/I3）；
  3. **域名/换端口 flow 的压缩**（P2）与 **>512 B 的 v3 化**（P4/I6）。
- 量化：32-flow、100k pps 时，flow 查找/环 miss 约 **0.5–1.5% 单核**，属"免费但不大"；
  P2 对域名目标则是 7–8 B/回包的**确定性字节收益**（§3.3/§4.4）。

### 3.6 边界说明（口径自洽性）

- 55 B/包 与 1162 B/帧 来自不同层估算（两者相加 > 1200 B），但本报告的结论只依赖**差额**：
  去掉 55 B 项后，W32/88 B 的"理想合包"收益从 1.6% 变成 ~5.2%（只剩 DQH+MQP 头差），
  "不合包"界不变（仍是每帧一个包）→ **排序与结论不变**。
- 若实际 quinn `max_datagram_size` 与 1162/1362 略有差异，每帧项数 ±1，表格数字变化 <2%。

---

## 4. 会话生命周期、控制面对下行的影响

### 4.1 180 s idle、sweeper、teardown 的真实成本

- **idle 判定**：reader 自己的 60 s tick 同时做 idle 判定和 PMTU 刷新，条件
  `now - last2 >= SESS_IDLE_MS(180 s)`（`reader.rs:773-789`、`table.rs:382`）；
  每连接另有 60 s sweeper 调 `sweep_all`（`accept.rs:798-818`、`table.rs:310-333`），
  连接关闭时 `drain_all`（`table.rs:297-308`）。
- **正常 teardown**：burst 外 break → 回收读缓冲、清线程 memo、从 shard 摘除、释放全局
  permit（`reader.rs:921-940`）。成本 O(1)/session。
- **sweep 成本**：每连接 60 s 一次，8 个 shard 各一次读锁扫描 + 过期项写锁摘除
  （`table.rs:310-333`）。4032 session/连接时单次 ~4032 次原子 load + 比较，**µs 级**；
  但 4096 条连接各有一个 sweeper task（`accept.rs:801-817`）→ ~68 次唤醒/s，可忽略。
- **真正的成本是"死会话活着"**：一个关联在客户端退出后，服务端 session/socket/task/
  flow 表/KV 仍保留**最长 180 s**（没有 `SESS_CLOSE`）。这期间：
  - 全局 permit 被占（`MAX_SESSIONS_GLOBAL=8192`，`table.rs:374`）、
  - 内核 socket 与 8 KiB 读缓冲被占、reader task 与 60 s 定时器被占、
  - 目标继续发的回包被投递到一个没人读的会话（转发后被丢弃）。

### 4.2 内存与 churn 量化（SESS_CLOSE 的价值）

`per_session_memory_bytes()`（`config/tuning.rs:309-317`）在 Linux/64 KiB 默认下：
`2×(2×64 KiB) + 8 KiB+1 + 4 KiB = 274,433 B ≈ 268 KiB`（`lib.rs:244`、
`v3.rs:51` MQP-3 flow 表计费）。8192 session → **2.14 GiB** 记账内存。

zombie 稳态数 = 关联关闭率 × 180 s：

| 关联 churn | 180 s 后 zombie 数 | 对比全局 8192 池 | zombie 记账内存 |
|---:|---:|---|---:|
| 10 /s | 1,800 | 22% | 471 MiB |
| **45 /s** | 8,100 | **≈ 100%（临界）** | 2.12 GiB |
| 100 /s | 18,000 | **超限 → 新 session 被 `SESSION_FULL` 拒绝** | 4.71 GiB |
| 806 /s（4032 并发 × 5 s 寿命的理论上限） | 145,080 | 严重超限 | 约 38 GiB（记账口径） |

> **短关联 churn > 约 45 个/s 时，服务端的全局 session 池会被"已死但未回收"的会话吃满**，
> 表现为新关联建不起来（全局池耗尽时 `get_or_create_sess` 返回 `None`：
> `reader.rs:1077-1097` `SESSION_FULL` 分支；上行调用点 `forward.rs:357` 的 `?` 直接丢包），
> 且 DATAGRAM 无回执，客户端只会看到 UDP 丢包。
> `SESS_CLOSE`（P3）把回收从"≤180 s 后"变成"立即"，这是**可用性修复**，不是性能微调。
> 同时它省下 268 KiB/session 的记账内存和内核 fd 压力。
> `FLOW_CLOSE` 则解决 §4.3 的永久退化。

### 4.3 flow 表 64 槽用满 → 永久退化

- 客户端 flow id 单调分配、**存活期内永不复用**（`v3.rs:683-690` 注释、`insert`/`next`、
  `MQP3_MAX_FLOWS=64`）。服务端镜像同一张表（`accept.rs:731-757`）。
- 表满后：上行新目标只能 `NO_FLOW` inline（客户端，`assoc.rs`）；服务端 flow 表满时回包也只能
  `NO_FLOW` inline（`reader.rs:150-154`）。
- **退化是不可逆的**：一个长寿命关联（游戏/WebRTC/常驻 VPN）访问超过 64 个目标后，后续所有
  目标**永久**多付 7–8 B/回包（v4；13 B 头 vs 5–6 B 头），小回包上最高 +24%（28 B payload 时
  41 B vs 33 B 帧体）。`FLOW_CLOSE` + 安全窗口后复用（`FRAG_ID_SAFE_WINDOW_MS=3 s`，
  `fragment.rs:145`）可以恢复压缩，且 id 复用风险可控（只需覆盖重组窗口）。
- 量化：长连接、10 个新目标/小时的场景，约 6.4 h 后进入永久 inline；之后每回包 +7–8 B。

### 4.4 域名解析路径与"下行能否压缩域名目标"

现状上行解析链（只在上行首个 datagram 付一次，不在回包路径）：
`resolve_forward_target`（线程 DNS memo → session `DestMemo`，`forward.rs:286-321`）→
miss 时 `DnsGate.claim` 合并 + `tokio::spawn` 一个 resolver（`forward.rs:383-426`，
`DNS_GATE_SLOTS=8`，`forward.rs:13`）→ moka 正缓存（TTL 120 s，10240 项，
`dns/store.rs:56,67`）→ `sess_dest_store` 写入 `DestMemo`（`pin.rs:79-88,546-580`）。
**下行路径本身不做 DNS**：reader 只看到回包源 IP。

缺口：`FlowTable` 的域名项存的是 `TargetAddr::Domain`（`accept.rs:745`），
`flow_for_ip` 只匹配 IP 项（`v3.rs:730-733`），所以域名目标回包**永远是 inline**
（`reader.rs:146-154` 的注释就是这个意思）。而客户端也确实不知道解析后的 IP，
不能拿域名去填 SOCKS5 UDP reply 的源地址。

**关键洞察（P2）：不需要新的控制帧也能修，而且首帧 0 字节成本。**

今天域名回包 = `NO_FLOW + inline`，SINGLE 头 = `1+4+1+7 = 13 B`（v4）；
若改成 `flow + inline`（`MQP3_FLAG_INLINE`，flow 非 0）→ 同样是 `1+4+1+7 = 13 B`，
**一个字节都不多**。语义升级为"这帧内联地址 = 该 flow 的实际源地址"：
1. 客户端收到 `flow + inline` 后，把 `flow → 源地址(IP:port)` 记进下行绑定表，
   之后收到**压缩帧**（`flow`、无 inline）时用它构造 SOCKS5 reply 头；
2. 客户端下次对该 flow 的上行帧就可以压缩（它本来就只在"收到过该 flow 的下行帧"后压缩，
   `client/dispatcher.rs:286-288` `confirm_flow`）——这条**压缩上行帧就是隐式 ACK**；
3. 服务端观察到该 flow 的压缩上行帧后，把状态从 `BindPending` 切到 `Bound`，之后回包压缩；
   源地址变化（DNS 轮转/端口漂移）→ 重新发一次 `flow + inline` 绑定帧、退回 `BindPending`。
- 收益：域名目标回包 **−7~8 B/回包(v4) / −19~20 B(v6)**（flow 0 时省 8/20 B，额外 flow 时省 7/19 B；88 B payload 时 ≈−7% 帧体，28 B 时 ≈−19%，8 B 时 ≈−38%）。换端口源同一条机制（绑定帧 13 B = 今天 `NO_FLOW` inline 的 13 B，0 成本）。
- 代价：绑定那一轮 RTT 内仍 inline（最多 1 个 RTT）；纯上行 flow（没有回包）不受影响；
  服务端需在 flow 表项附一个 `reply_src: Option<SocketAddr>`（+24 B/项，最大 64 项 → +1.5 KiB/
  session，需同步调 `MQP3_FLOW_TABLE_MAX_BYTES` 记账，`v3.rs:51`）。
- **`FLOW_ACK` 控制帧还有独立价值，但不是下行压缩的必要条件**：它能让"纯上行 flow"
  也立刻压缩（上行收益），也能在"绑定帧丢失 + 对端不重发上行"时做保底确认。
  如果做控制面，`FLOW_ACK` 应携带 `(sess, flow, source_ip[:port])`，语义与上述绑定帧一致。

### 4.5 full-cone / server-initiated flow

- `udp_full_cone`（`config/server_conf.rs:36-56`、`reader.rs:609-618`）：任意源都被接受、
  计 `unsolicited`。这类源**没有上行 flow**，所以今天只能 `NO_FLOW` inline。
- "server-initiated flow"可以让它变成一等公民：服务端首次见到某源时发一帧
  `新 flow id + inline 源地址`（字节等同今天的 inline 帧），客户端建立绑定后压缩。
  但 flow id 空间目前是**客户端分配的**（`hub.rs:alloc_sess`/assoc flow 表）；
  服务端自造 id 需要协议约定（例如保留 `128..=255` 给服务端发起，或引入 `FLOW_OPEN` 控制帧）。
- 策略边界不变：这只影响"源地址怎么表达"，**不扩大** `udp_full_cone` 已经开的口子；
  建议服务端发起的 flow 只允许在 `ReplyFilter::FullCone` 下创建，并计入 unsolicited 统计。

---

## 5. 协议改动排序（协议层 vs 纯实现层）

### 5.1 协议层（需要改 wire；用户已允许不兼容重构，名字仍叫 MQP-3）

| 序 | 改动 | 具体内容 | 预期收益 | 风险 | 前置 |
|---|---|---|---|---|---|
| **P1** | **跨 session TRAIN（`TRAIN_X`）** | 新帧形：头 `kind/flags + count`（无 sess），**每项显式带 sess u32**（方案 A；§3.2）。保留现有同 session TRAIN 不变（1 项 run 退回 SINGLE，字节与今天持平）；接收端逐项按 sess 分发。方案 C（连接级 u16 id）只再省 2 B/项，**不建议第一版做** | 多 session 工作负载：**帧/发送调用/分配 11.9×↓**（32 session、88 B）；线上字节：不合包界 **−34%**、理想合包界 **−1.6%**；客户端帧 pop 同降。CPU ≈ −0.2 µs/回包（服务端） | **中高**：必须配 I4（连接级 stager）；flush 时机（不能等，靠"stager 排空即发"）；同一包内多 session 丢失相关性变化（期望丢包率不变，见 §5.4）；客户端逐项 demux | I4 |
| **P2** | **下行 flow→源地址绑定** | `flow + inline` 首次回包（字节 = 今天的 `NO_FLOW+inline`）建立绑定 → 客户端学源 → 压缩上行作隐式 ACK → 服务端转压缩。覆盖：域名目标、换端口源、full-cone 源（配合 P3/保留 id 段） | 域名/换端口回包 **−7~8 B(v4)/−19~20 B(v6)/回包**（小包 −7~38% 帧体）；让 `FLAG_SRC` 真正上岗；解除"域名永远 inline"的结构性税 | **中**：服务端 flow 表要加 `reply_src`（+记账）；源漂移重绑定；绑定帧丢失退化为今天的 inline（不黑洞） | 无（可先做域名，见 §4.4） |
| **P3** | **控制面：`SESS_CLOSE` / `FLOW_CLOSE`**（可选加 `FLOW_ACK`/`CAPS`） | 0x40 已保留（`v3.rs:25`）；幂等、可重复、idle 兜底。`SESS_CLOSE` 立即释放 socket/task/flow 表/permit；`FLOW_CLOSE` 释放 flow 并允许安全窗口后复用 id | 可用性：churn **>45 关联/s** 时不再吃满 8192 池（§4.2）；每 session 立即回收 **268 KiB** 记账 + fd；`FLOW_CLOSE` 修复 64-flow 永久 inline（+7~8 B/回包的退化） | **低**：幂等帧，丢了最坏退化成今天；`CAPS` 只在需要灰度时加 | 无 |
| **P4** | **>512 B 回包 v3 化** | 单帧装得下的回包发 **v3 SINGLE**（可带压缩 flow）；>B 的分片发 **v3 `FRAG`**（11–12 B 片头，无地址）并接通两端重组（key 变成 `(sess, flow, id)`） | 每大包/每片省 **6–7 B(v4) / 18 B(v6)**；8000 B payload 6–7 片共省 42–49 B（v4）；同时去掉客户端 v2 解码分支 | **低**：codec 已实现（`v3.rs:542-671`），只差"服务端愿意发 + 客户端愿意收/重组"；重组要有 flow→地址解析 | 无（可与 P2 合并） |
| **P5** | **紧凑 FRAG 全链** | 与 P4 同源；若 P4 已做则本项合并。IPv6 收益更大 | 同上 | 低 | P4 |
| **P6** | **CAPS/HELLO 协商** | 首连协商 `max_train_items`、是否支持 `TRAIN_X`、连接级 id 等 | 仅灰度/混部需要；用户允许不兼容 → 与 P1 同时上线时可省 | 低 | 无 |
| **P7** | **连接级 flow id（u16）/session id u16** | 在 P1 之上再省 2–3 B/项；需要连接级 id 表（内存/上限/回收） | 每项再省 ~2 B（88 B 时 ~2%） | **高**：id 空间归谁、连接级表上限、与 per-session flow 生命周期/ACK 语义耦合；**建议押后**，用测量决定 | P1 |

### 5.2 纯实现层（wire 完全不动）

| 序 | 改动 | 证据 | 收益 | 风险 |
|---|---|---|---|---|
| **I1** | 鉴权阶段若查到了 flow id，**直接传给暂存**；`last_flow` 从 1 槽扩成小 memo（4–8 槽）或 flow 表加 IP 索引 | `reader.rs:601` 丢掉 flow id；`reader.rs:137-145` 单槽；`v3.rs:722-733` 64 槽线性 | 32-flow 扇出每回包 **−50~150 ns**；环 miss 时省掉第二次扫描 | 低（纯局部） |
| **I2** | run==1 时免 arena 拷贝（首条借用、第二条才落 arena） | `reader.rs:164-165` vs `231-240` | 每回包省 1 次 payload 拷贝（~8–10 ns + 缓存压力） | 极低 |
| **I3** | allowlist 快路径：IPv4 存 u32 比较；或扩到 32 项 | `pin.rs:22-54` | 16 槽扫描 → 4 次字比较；环 miss 率减半 | 低（内存 280 B→~0.6 KiB/session） |
| **I4** | **连接级 stager**（shared arena + 单次 flush + 每 session 配额/DRR） | `reader.rs:758-766`；G8 | P1 的落点；顺带修 G8 公平、TooLarge 探测/PMTU 缓存集中到连接级 | 中高：新增 task/锁/anchor；flush 策略决定收益（burst 型才赚） |
| **I5** | per-connection 回包 reactor（一个 task poll 所有 session socket） | `reader.rs:1132-1143` | 去掉 4032 task/定时器；每回包省一次唤醒/调度（~0.2 µs） | 高：状态从 task 局部变共享表（allowlist/flow/last_flow 都要搬）；建议先测 I4 再决定 |
| **I6** | >512 B 直接发 v3 SINGLE（codec 已存在），不等 P4 | `reader.rs:665-716` | 每大回包省 6–7 B；去掉 v2 前缀缓存 | 低（客户端已能解 v3 SINGLE） |
| **I7** | 回包侧 stats/计数合并（每帧一次而非每回包） | `reader.rs:267-272` | 微小（线程局部，已便宜） | 低 |
| **I8** | `initial_mtu` 1200→1400（配置默认） | `tuning.rs:186-198` | 大回包少分片（18–23% 包数）；对 W32 小回包 ~1% | 低（镜像两端；已有黑洞回退） |

### 5.3 组合与里程碑建议

1. **M0（零协议风险，先做）**：I1 + I2 + I6 + I8，并**加测量**（§7）：得出"现状 DATAGRAM 帧数
   vs QUIC 包数"和"多 session 下行 pps/CPU 基线"。
2. **M1（下行字节，低风险）**：P2（先只做"域名/IP flow 绑定"，服务端侧 `reply_src` +
   客户端绑定表 + 压缩上行确认）→ 域名/换端口回包立省 7–8 B(v4)/19–20 B(v6)。可与 M0 并行。
3. **M2（控制面，可用性）**：P3 `SESS_CLOSE` + `FLOW_CLOSE`（+ `CAPS` 可选）。这是 churn 与
   长寿命关联退化的解，独立于合帧，收益确定、风险低。
4. **M3（结构，收益取决于测量）**：I4 连接级 stager + P1 `TRAIN_X`。只有 M0 测出
   "quinn 合包不生效、且多 session 工作负载占比高"时才值得全量投入；否则只做 I4 的公平调度
   部分（G8）即可。
5. **M4（可选）**：P4/P5 大帧 v3 化 + compact FRAG；P7 连接级 id 押后。
6. **全双工注意**：P1/P2/P3 的 id/ACK 语义应同时服务上行——两边共用一个连接级 stager 抽象
   （客户端上行 per-connection 合并 + 服务端下行 per-connection 合并），
   `FLOW_ACK/CLOSE` 双向复用，避免再出现"上行优化完下行还是 per-session"的割裂。

### 5.4 策略与安全不变量（任何方案都必须保持）

1. **鉴权仍按 flow/回包逐条做**：跨 session 合帧只是"装载方式"，每个 item 在进入 stager
   **之前**必须已通过 `handle_session_reply` 现有的源鉴权（allowlist 环或 flow 表回退，
   `reader.rs:579-618`）；flow 的安装仍只发生在"目标接受了一次真实发送之后"
   （`accept.rs:730-757` 的 `accepted` 条件）。
2. **SSRF 不变**：目标过滤发生在**上行/解析**（`forward.rs:343-345`、`443-473`），
   下行压缩只改"源地址怎么表达"，不新增可达目标；`allow_private` 语义不变。
3. **连接级 id 不得跨 session 解析**：即使做 P7，id 表项必须携带所在 session，
   服务端不能把 A session 的 id 解析成 B session 的源；客户端必须逐项用**该 item 的 sess**
   查自己的表（今天帧级 sess 的检查在 `client/dispatcher.rs:251-254, 296-299`）。
4. **full-cone 仍是 opt-in**：server-initiated flow 只在 `ReplyFilter::FullCone` 下允许，
   且计入 unsolicited（`reader.rs:609-618`）。
5. **丢包相关性**：一个跨 session 包丢失会同时影响 N 个 session 的各 1 条 datagram。
   按期望算**每个应用 datagram 的丢失概率不变**（每包 N 条、包数 1/N），但丢失在
   **时间上跨流相关**（一次 qdisc 丢包同时命中 32 个 flow）。对 DNS/一次性请求无影响；
   对 RTP/游戏，建议给 stager 一个"低延迟 flow 不参与跨 session 合帧"的开关
   （按 flow/端口分类，或按 item 年龄 flush）。这也回应了仓库对 BATCH 的
   "fate-sharing" 顾虑（`udp/send.rs:214-223`）——结论是**期望不变、突发相关，需可配**。

---

## 6. TCP 下行（`src/tcp/pump.rs`）

- **"零拷贝"声明的准确性**：对 QUIC→TCP（s2c）方向**在用户态是准确的**：
  `recv.read_chunks(&mut batch)` 一次拿最多 8 个 `Bytes`（quinn assembler 的切片，
  `pump.rs:367-390`），再 `write_batch_vectored` 用 `write_vectored` 一次 syscall 交给内核
  （`pump.rs:168-227, 412-416`）——pump 内**没有 payload memcpy**。
  仍存在的拷贝是：quinn 收到流数据时自己做的入队拷贝、以及内核 `copy_from_user`，两者都不是
  应用层能消除的。反方向（c2s）用 `write_chunk` 转交所有权以避免拷贝（`pump.rs:306-322`，
  ≥8 KiB 阈值 `pump.rs:74`），也符合注释。
- **协议层余量：零**。MQP-3 在 TCP 流上**不加任何帧头**（流首部是地址头，`pump.rs:53-61`
  的 dial ACK 只在连接建立时读一次），所以下行带宽没有"协议头"可省。
- 剩余可做的都是实现/传输层，且都不大：
  - `COPY_BATCH=8`（`pump.rs:83`）→ 每个 `write_vectored` 最多 ~11 KiB；提高到 16/32 可
    减少大流量下的 syscall 次数（当前每 ~11 KiB 一次 write + 每 8 段一次读锁）；
  - 空闲看门狗/进度戳已按 100 ms 节流（`pump.rs:91, 149-166`），无每 chunk 开销；
  - `initial_mtu`/窗口（§5.2 I8、`tuning.rs`）影响更大；
  - 每条流 2×16 KiB 双缓冲计入 `stream_pump_memory_bytes`（`tuning.rs:377-379`），是内存
    不是带宽问题。
- 结论：**TCP 下行没有协议级优化空间**；不要为 TCP 改 MQP-3。

---

## 7. 验证计划（本任务未运行；给出最小可信测量集）

1. **测 quinn 合包率（P1 是否值得的前提）**：
   同一连接、32 session、88 B 回包，固定 pps；需要三个数：
   (a) 应用回包数 —— `udp_stats::datagrams`（一次 `payload()` 计一条，`stats/udp_stats.rs:89-121`）；
   (b) `try_send_datagram` 的**帧数** —— 仓库没有现成计数器，最小改动是在
   `udp/send.rs:84-95` 入口加一个线程局部/原子计数（只为测量）；
   (c) **QUIC 包数** —— 服务端 `tcpdump -i lo udp port <listen>` 或 quinn qlog（`batch_report`
   的 `send_syscalls` 统计的是**最后一跳发给目标**的 syscall，`udp/batch.rs:72-74`，与下行无关）。
   `帧数/包数` 就是当前合包率；它决定 P1 的字节收益落在 §3.2 的哪一端。
2. **现状 per-session stager 的下行基线**：`examples/hotpath_bench.rs` 的 `udpps/udppaced/
   udpmulti`（README 已有 loopback 结果，Linux 2–4 核仍缺，`README.md:866` 自认缺口）；
   加一个"32 session × 1 flow、88 B、50k pps"的用例。
3. **多 flow 扇出**：1 session × 32 flow、50k pps，对比 I1 前后服务端 CPU/pps。
4. **M1（P2）字节验证**：域名目标回包抓包，确认首帧 `flow+inline`（13 B）后转压缩帧（5–6 B），
   并验证绑定帧丢失时回退 inline 不黑洞。
5. **M2（P3）可用性验证**：churn 压测（100 关联/s、5 s 寿命），对比 `SESSION_FULL` 计数
   （`stats/drops.rs`）在有无 `SESS_CLOSE` 时的差异。
6. **正确性**：P1 需要新增"TRAIN_X 逐项 sess demux / 乱序 / 跨 session 鉴权"单测；
   P2 需要"绑定帧丢失 + 重绑定"单测；沿用 `server/tests.rs` 的端到端风格。

---

## 附录 A：关键算术（可复算）

- W32/88 B/B=1162：现状 SINGLE 体 = `1+4+0+88 = 93`；包 = `55 + 3 + 93 = 151 B`。
  1000 回包 → 1000 帧 → **151,000 B**。理想合包：`floor(1162/(3+93)) = 12` 帧/包 →
  `84 包 × 55 + 1000 × 96 = 100,620 B`。
- 连接级 A：项 = `1+4+1+88 = 94`；`floor((1162−2)/94) = 12` 项/帧 → 84 帧 →
  `84 × (55+3+2+12×94) ≈ 99,040 B`（每帧一包，因为帧体 1131 B 再加 55+3 已近 1200）。
- 连接级 C：项 = `1+2+1+88 = 92`；`floor(1160/92) = 12` 项/帧 → 84 帧 → 97,040 B。
- 单 session 32 flow：项 = `1+1+1+88 = 91`；`floor((1162−6)/91) = 12` 项/帧 → 84 帧（已接近最优）。
- 域名/换端口 inline：`1+4+1+7+88 = 101 B`；压缩：`1+4+88 = 93 B`（额外 flow 再 +1 B = 94）→
  v4 省 7–8 B；v6 inline `1+4+1+19+88 = 113` → 省 19–20 B。
- 会话内存：`2×(2×64 KiB) + 8 KiB + 1 + 4 KiB = 274,433 B`；
  churn 临界 = `8192 / 180 s ≈ 45.5 /s`。

## 附录 B：本文引用的关键符号索引

- 下行 reader：`src/bin/myquic2-server/reader.rs:720-941`（任务）、`:480-717`（每回包）、
  `:215-298`（flush）、`:124-174`（暂存）
- 会话表/生命周期：`table.rs:12-57`（SessEntry）、`:310-333`（sweep）、`:374-382`（上限/idle）
- 鉴权/allowlist：`pin.rs:22-54`、`reader.rs:579-618`
- 协议 codec：`mqp/v3.rs:22-66`（常量）、`:151-198`（SINGLE）、`:285-347`（TRAIN）、
  `:542-671`（FRAG）、`:684-792`（FlowTable）
- 发送：`udp/send.rs:84-95`、`udp/fragmenter.rs:178-394`
- 客户端下行：`client/dispatcher.rs:225-344`（v3 分发）、`:663-723`（flush）、`:769-849`（drain）
- 配置/内存：`config/tuning.rs:116-133, 282-317`、`lib.rs:244`、`transport/limits.rs:84`

---

## 给 Lead 的摘要

1. 下行根因是**发送上下文粒度 = session**：一 session 一 socket/task/私有 stager（reader.rs:720-766,1132-1143），而 TRAIN 头带唯一 sess（v3.rs:63）→ 跨 session 回包在协议上不能合帧。
2. 小回包在**单 session 内已批得很好**（≤64 项按预算）；缺的是多 session 同时回包、以及单 session 多 flow 交替回包。
3. W32（32 session、1 flow、88 B、1000 回包、B=1162）：现状 1000 帧/1000 send/1000 分配；连接级暂存器（TRAIN_X，每项 sess u32）= 84/84/84（11.9×）。
4. 线上字节：**若 quinn 合包不生效 −34.4%；若理想合包仅 −1.6%**（B=1362：−34.9% / −1.6%）。真实值在两者之间，**帧/调用/分配 11.9× 是确定收益**。
5. 28 B 小包：30 帧、不合包界 −60.7%、理想合包界 −5.2%；200 B：−17.1% / −0.5%。回包越小合帧越值钱。
6. CPU：合帧只省 quinn send+分配 ≈0.25 µs/回包，扣掉 stager 入队 ≈ −0.18~−0.22 µs（服务端 −11~14%），50k pps ≈ 1% 单核；大头是每回包 1 收 syscall + 1 发 syscall + 1 唤醒，协议动不了。
7. 下行"白送"字节在压缩：域名/换端口/full-cone 回包永远 inline（13 B vs 5–6 B）。**首帧绑定 0 字节成本**（flow+inline 与 NO_FLOW+inline 同为 13 B）→ 每个此类回包省 **7–8 B(v4)/19–20 B(v6)**；这是 P2，比 P1 确定性更高。
8. P2 机制：首回包 flow+inline 建绑定 → 客户端学源 → 其压缩上行帧即隐式 ACK → 服务端转压缩；源漂移重绑定；不需要新控制帧（FLOW_ACK 的独立价值是纯上行 flow）。
9. 控制面缺口是生命周期，不是带宽：churn > **45 关联/s** 即可能吃满 8192 池（zombie×268 KiB）；无 FLOW_CLOSE 时 64 flow 用满后该关联**永久 inline**（+7–8 B/回包）。
10. >512 B 掉出 v3（MQP-2 12 B 头；分片 18 B/片）：大回包省 6–7 B(v4)/18 B(v6)，codec 已存在（v3 SINGLE/FRAG），属"接线"级改动。
11. 协议排序：P2（域名绑定，字节确定）→ P3（close，可用性确定）→ P4/I6（大帧 v3）→ P1+I4（跨 session 合帧，收益取决于合包测量）→ P6 CAPS → P7 连接级 id（押后）。
12. 纯实现层先做：I1 复用鉴权阶段 flow id + per-reader 源→flow memo（32-flow 扇出 −50~150 ns/回包）、I2 run==1 免 arena 拷贝、I6 >512 直发 v3 SINGLE、I8 initial_mtu 1400。
13. 单 session 32 flow 的 VPN 场景**不能从 P1 获益**（已合帧）；它的收益在 I1/P2/I6。
14. G8：每连接共享 1 MiB DATAGRAM 缓冲无公平性，一个 flow 可让别的 session 被判 Blocked 丢包；连接级 stager（I4）是落点。
15. 安全不变量：逐回包鉴权不变（reader.rs:579-618）、SSRF 不变、连接级 id 不得跨 session 解析、full-cone 仍 opt-in。
16. TCP 下行零拷贝声明在用户态成立（read_chunks+write_vectored）；MQP-3 在流上无帧头 → **TCP 下行无协议级收益**。
17. 必须先测：现状"1000 回包 = 多少 QUIC 包"（决定 P1 收益落点）+ 32 session × 88 B 的 pps/CPU 基线（README:866 自认 Linux 缺口）。
18. 建议里程碑：M0=I1+I2+I6+I8+测量；M1=P2；M2=P3；M3=I4+P1（依测量）；M4=P4/P5。
19. 风险最大的是 P1：要新建连接级 stager（I4）、定 flush 策略（排空即发，不人为等待）、处理跨 session 丢包相关（期望丢包率不变，但突发相关，需要可配开关）。
20. 全双工：P1/P2/P3 的 id/ACK 语义应上行/下行共用一套连接级抽象，避免两边裂开。
