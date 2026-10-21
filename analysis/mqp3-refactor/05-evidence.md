# 05 · 既有证据、已否决设计与基准工具盘点

> 读取基线：HEAD `d2f9658`（2026-10-20 17:42 +0800，`chore(release): v0.2.0`，自称仅版本号；工作区干净）。
> 读取时间：2026-10-21 06:40 +0800。方法：只读（git/grep/read）+ 一次 <60 s 的本机 smoke（未构建、未改仓库、未跑 cargo build/test）。
> 目的：为「MQP-3 能否重构以获得大幅性能收益（允许 wire 不兼容、名称仍为 MQP-3、双向全双工）」提供证据底座，避免重复已做工作、避免重提已被测量否决的设计。
>
> **证据分级（全文统一）**
> - **[L实测]** 在 Linux 上实测（本仓库仅有一例，且是 Linux 容器/虚拟化；无真实 Linux 目标机数据）
> - **[M实测]** 在 macOS 实测（Apple M4 / 开发机；含 loopback 端到端、微基准）
> - **[模型]** 由源码常量、wire 格式算术、窗口/RTT/BDP、单次成本 × 频率假设推导，无端到端测量
> - **[断言]** 文档声称、无可追溯测点，或只有定性描述
> - **[代码事实]** 静态可复核事实（不是性能证据；用于校验文档中的计数/常量类主张）

---

## 0. 三个必须先校正的前提

| # | 常见误解 | 事实（本仓库） | 影响 |
|---|---|---|---|
| 0.1 | `PROTOCOL_ANALYSIS.md` 是「MQP-3 落地前」的独立文档 | git 上**首次入库就是 `530188e`（MQP-3 实现同一提交）**；文首自报基线 `348c52d`。主体 §0–§5 按 MQP-2 现状建模，§6/§4.4/§4.5/§4.6 带「当前实现（2026-10-20）」后验注记 | 文档是「实现前设计 + 实现后状态注记」的混合体。引用 §2/§5 的「现状」时必须按 `348c52d` 对待；§6 状态注记与 HEAD 一致，可当 HEAD 事实用 |
| 0.2 | `PERF_ANALYSIS.md` 的行号可直接对 HEAD 使用 | 基线 `d73809f`；`348c52d` 已修 F1/F2/F4–F7/F9/F11/F12/F14 部分；`530188e` 又大改 `assoc.rs`/`reader.rs`/`accept.rs` | F1–F14 **状态表仍有效**（本次逐符号复核）；但 **file:line 全部是旧基线**，F5/F8 的行号尤其已失效。新文档只能引用「状态结论」，引用行号需以 HEAD grep 为准 |
| 0.3 | MQP-3 的收益「已有测量」 | 仓库与全部 git 历史中**没有任何 Linux 目标机 MQP-3 端到端测量**。仅有：macOS loopback smoke、macOS 微基准、一次 Linux 容器内针对特定优化的 A/B（`8eebdca`）、Linux CI 的测试运行 | 所有 MQP-3 收益数字（wire −9%…−38%、调用 −18×、CPU 1–3%）都是**模型**。新分析若声称收益，必须自带 Linux 基准计划，不能引用「已测量」 |

补充：`d2f9658` 是纯版本提交（`Cargo.toml:3` = 0.2.0），代码与 `373da0e` 相同；`182b09e` 只改 README；`373da0e` 只放宽一个 Linux admission 测试下限。

---

## 1. 证据清单

### 1.1 协议/wire 与结构事实（大多为代码推导，可信度高）

| # | 主张/数值 | 出处 | 证据类 | HEAD 状态 |
|---|---|---|---|---|
| A1 | MQP-2 固定头：DATAGRAM 5 B 前缀（IPv4 共 12 B）、FRAG 11 B 前缀（IPv4 共 18 B）、BATCH 前缀；IPv6/域名见原表 | `src/mqp/datagram.rs:11`（`DGRAM_PREFIX_LEN=5`）、`src/mqp/fragment.rs:29`（`FRAG_PREFIX_LEN=11`）、`src/mqp/batch.rs:9`（`BATCH_SMALL_MAX=512`）、`PROTOCOL_ANALYSIS.md:71-73` | 代码事实 | ✅ 一致 |
| A2 | MQP-3 头：SINGLE 稳态 5 B / 额外 flow 6 B；TRAIN 6 B + 同 flow 2 B/项、异 flow 3 B/项；FRAG 11/12 B（+可选地址） | `src/mqp/v3.rs:22-66`（常量）、`:143-199`（encode_single）、`:261-346`（encode_train）、`:542-660`（v3 FRAG codec）、`README.md:619-662` | 代码事实 | ✅ 一致（v3 已生产使用） |
| A3 | 下行头节省：IPv4 flow0 12→5 B（省 7）、额外 flow 省 6、IPv6 省 19/18 B；域名/异源/unsolicited 用 `NO_FLOW=0xff` inline，单帧反而比 v2 大 1 B | `README.md:710-721`、`src/mqp/v3.rs:46`、`src/bin/myquic2-server/reader.rs:137-154` | 代码事实（算术） | ✅ 一致 |
| A4 | 每包固定开销 55 B（IPv4 20+UDP 8+QUIC short header 27）；MTU 1200 时 DATAGRAM body 预算 1162 B；DATAGRAM 帧头 1+varint ≈2–3 B | `PROTOCOL_ANALYSIS.md:103-113, 772-781`；依据 quinn-proto 0.11.19 源码（非本仓库代码） | 模型（依赖源码核对） | ✅ 口径仍成立（quinn 0.11.x 未变） |
| A5 | bulk（≥1200 B）时 MQP 头 <1% 线上字节 → 为吞吐重写协议上限 ≤1% | `PROTOCOL_ANALYSIS.md:16,41,134-136,574` | 模型（算术） | ✅ 仍成立（且是反对「为吞吐重写」的核心依据） |
| A6 | MQP-3 已落地部分：客户端上行 SINGLE/TRAIN、服务端下/上行 v3、flow 表、下行隐式 ACK 压缩；**域目标全程 inline、紧凑 FRAG 未接线、无 CAPS/HELLO/FLOW_ACK** | `530188e`；`src/bin/myquic2-client/assoc.rs:566-798`；`src/bin/myquic2-server/accept.rs:603-760,985-990`；`src/bin/myquic2-server/reader.rs:115-260`；`README.md:664-739` | 代码事实 | ✅ 与 HEAD 一致（182b09e 文档化） |
| A7 | 客户端 flow 压缩状态机 = 「收到压缩下行帧才确认」，纯上行 flow 永远 inline；服务端 flow 表同时是 16 项 allowlist ring 失配时的第二授权源（精确 `(sess,flow)->IP`） | `src/bin/myquic2-client/hub.rs:51-57,139-152`；`src/bin/myquic2-client/dispatcher.rs:258-290`；`src/bin/myquic2-server/reader.rs:586-612`；`README.md:664-706` | 代码事实 | ✅ 一致 |
| A8 | 512 B 是 fate-sharing 上限而非 wire 上限：>512 B 的 UDP payload 仍走 MQP-2 单帧/FRAG；v3 staging 只在 ≤512 B | `src/mqp/batch.rs:9`；`src/bin/myquic2-client/assoc.rs:301`；`src/bin/myquic2-server/reader.rs:629`；`README.md:696-699` | 代码事实 | ✅ 一致 |

> **对 §1.1 的一句话**：wire 头压缩这部分的「现状数字」是可靠的、可复核的；但它们是**字节算术**，不是端到端收益测量。

### 1.2 性能模型与估算（不可当测量用）

| # | 主张/数值 | 出处 | 证据类 | HEAD 状态 |
|---|---|---|---|---|
| B1 | 小包单帧 wire −9.4%（IPv4 60 B）；域名目标 −33.4% | `PROTOCOL_ANALYSIS.md:36-43, 527-528` | 模型 | ⚠️ 域名部分**未实现**（HEAD 域目标 inline，收益拿不到）；单帧 -9.4% 依赖 flow 压缩，仅 IP 目标成立 |
| B2 | 多目的地扇出 wire −15.4%（v4）/−37.8%（域名），send 调用 −18× | `PROTOCOL_ANALYSIS.md:38, 524-525` | 模型 | ⚠️ 调用部分依赖 TRAIN 实现（已实现，但**无调用计数验证**）；域名 -37.8% 未实现 |
| B3 | 同目的地小包：相对现状 2-pack −10.8%/9×，相对已实现 16-pack 仅 −1.4%/1.1× | `PROTOCOL_ANALYSIS.md:39-40, 522-523` | 模型 | ❌ 「现状 2-pack」已过期（HEAD 是 TRAIN）；该对比在 HEAD 无意义 |
| B4 | CPU：50–100k pps 小包省 1–3% 单核（按 send_datagram 200–300 ns + 分配 30–50 ns） | `PROTOCOL_ANALYSIS.md:42-43, 542-556`；`PERF_ANALYSIS.md:298` | 模型（成本估算 × 频率） | ⚠️ 量级参考；未在 Linux 实测 |
| B5 | 8 源 60 B 下行 fanout @50k replies/s ≈ −15% bytes / ~18× fewer sends | `README.md:702-706`（原文即写 modeled） | 模型 | ⚠️ 依赖 TRAIN 混源（已实现），但收益未测 |
| B6 | MQP-2 BATCH 下行：7.8% wire reduction @P=128/N=16，~2.5% @P=512 | `c8e5c3d` commit message「PER-DATAGRAM COST MODEL」 | 模型 | ❌ BATCH 下行已被 MQP-3 TRAIN 取代（`530188e`），设计不再适用 |
| B7 | MTU 1200 起步：PMTU 发现前包数多 18–23%，>1150 B payload 默认 2 分片 | `src/config/tuning.rs:183-193`；`README.md:584,758,777`；`d73809f`/`661ce08`/`952001e` commit | 模型（算术） | ✅ 口径一致；默认值决策见 §2 |
| B8 | 吞吐上限：4/8/4 MB 窗口 @140 ms ≈ 240 Mb/s；2/4/2 ≈ 114 Mb/s；8/16/8 ≈ 300 Mb/s | `src/config/tuning.rs:201-204`；`src/transport/limits.rs:3-23`；`README.md:774-776,758-759` | 模型（窗口/RTT BDP） | ⚠️ 全部是窗口算术，**无 Linux 端到端吞吐测量**；`README.md:29`「connection count scales linearly」属[断言] |
| B9 | F8 客户端 N-pack：send 次数 0.5→1/8~1/13，40k pps ≈ 0.3–0.6% 核 | `PERF_ANALYSIS.md:298-299` | 模型 | ❌ F8 原提案已作废（见 §2/R2），但同量级估算可参考 |
| B10 | 跨 session TRAIN 收益不确定（quinn 已合包，只剩 state 锁） | `PROTOCOL_ANALYSIS.md:483-488, 746-749` | 断言/推理 | ✅ 仍成立（无 profiling 前不应提） |
| B11 | session id u16 再省 2 B/帧（5→3），小包再省 2–3% | `PROTOCOL_ANALYSIS.md:493-503` | 模型 | ⏳ 未实现（Phase 3）；wire 不兼容约束已解除，但 id 生命周期风险仍在 |
| B12 | FEC：2 片 +1 parity = +50% 字节；到达率 98.01%→99.97%；8 片 92.3%→99.64% | `PROTOCOL_ANALYSIS.md:238-244, 558-566` | 模型（算术） | ✅ 仍成立；无丢包链路实测 |
| B13 | F2 16 槽冲突概率：A=5 约 50%、A=8 约 88%、A=10 约 97% | `PERF_ANALYSIS.md:146-147` | 模型（生日问题） | ✅ 修复后已不适用（符号在，见 1.3/1.4） |
| B14 | 慢路径放大：F1 1–3 µs/包；F10 跨核 0.1–0.3 µs/包 ≈ 0.5–1.3% 核 @40k pps；F4 256 项扫描 181 ns → 0.4% @20k/s | `PERF_ANALYSIS.md:117-119, 207-213, 337-338` | 混合：181 ns 是微基准 [M实测]，其余为模型 | ⚠️ F1/F4 已修；F10 未修（见 §3） |

### 1.3 实测证据（几乎全在 macOS；注意「哪台机器、什么负载」）

| # | 测量内容 | 数值 | 出处 | 证据类 | 可用于新分析？ |
|---|---|---|---|---|---|
| C1 | **frame pool 否决**：plain `Vec::with_capacity`+`Bytes::from` vs 池化 | 128 B 同线程 15–19→22–25 ns（+45–52%）；128 B 跨线程 29–38→123–147 ns（+284–324%）；1200 B 同线程 +39–42%；1200 B 跨线程 +128–158%；2 M 帧/格、两轮、M 系列+mimalloc | `examples/frame_bench.rs:19-25`；`0fb941d` commit | [M实测] | ✅ 直接堵死「帧池化」 |
| C2 | `hotpath_bench` 内嵌基线（2026-09-30，macOS loopback，4TCP+2UDP，8 线程 echo） | udpraw 控制 73129 pps；udp 窗控 26847 pps；udpps 5 s offered 96485 / goodput 2586 pps（loss 96.9%）；60 s 105350 / 370（99.6%） | `examples/hotpath_bench.rs:1232-1240` | [M实测] | ❌ 过期（早于 `c8e5c3d`/`e4fd3bc` 的 pending 与 shard 化；README 现称 ~40k recv pps） |
| C3 | sharded egress/ingress A/B（macOS M4 10 核，3 轮） | udpmulti 8×20k：14.8–16.2k→16.9–17.0k pps（+8%）；udpps 8 s/128 B：34.8–42.5k→41.8–43.7k pps（+4%，噪声内）；3 路 aggregate 58.5/61.7k→69.3/70.7k（+16%）；k=4 72.4k、k=8 73.3k | `e4fd3bc` commit message | [M实测] | ✅ 可作为「多 association 上界」参考；与协议无关 |
| C4 | Linux 容器（podman aarch64，release）单次 A/B：某 per-packet 优化 | `udp 20k` 前后均 ~3800 pps（1000 B 永不批处理）；`udppaced` 10k–50k 全程 parity（0–0.4% loss），90k 3 轮 5.89% vs 5.82%（~0.7pp 噪声） | `8eebdca` commit message | [L实测]（容器/虚拟化，范围窄） | ⚠️ 只能证明「该改动无可测收益」，不能代表 MQP-3 |
| C5 | 客户端 2-pack 与「N-pack(≤16) 原型」 | N-pack 原型**测过**：与基线 parity、collapse 时丢包分布略差 → 以「不可测 complexity」回退 | `8eebdca` commit message（"What was deliberately NOT changed" 段） | [M实测] | ✅ 直接堵死「BATCH N-pack」重提 |
| C6 | MQP-2 BATCH 下行真机冒烟 | 线上抓到 31k 次 flush、n=1..16，其中 ~23% 达 16 项上限 | `c8e5c3d` commit message | [M实测] | ⚠️ BATCH 已退役，仅作历史 |
| C7 | 慢路径 CPU 放大（loopback 定量） | 20 000 datagrams、1 vs 2 session：70.2 µs vs 76.3 µs server CPU/交付数据报（+8.8%） | `src/bin/myquic2-server/accept.rs:893-896`；`b542cb2`/`661ce08` | [M实测] | ✅ 可作「慢路径绕不过去」的量化参照 |
| C8 | u16 fragment id 的丢包悬崖（历史测量） | 1000/s 丢 ~4%、4000/s ~15%、21845/s 50% | `src/mqp/fragment.rs:19-28`；`952001e` commit | [M实测]（历史，平台未注明） | ✅ 直接堵死「fragment id 改回 u16」 |
| C9 | 窗口预设 E2E 冒烟（debug 二进制，loopback） | UDP 128 B 7.5–10.1k pkt/s（~120–162 Mb/s），RTT 0.26–0.90 ms | `952001e` commit | [M实测] | ⚠️ debug 构建，仅供量级 |
| C10 | MQP-3 release smoke（macOS loopback，`530188e` 同树） | udp/udpdomain 1000/1000；udpmulti 4×500 0 loss；udppaced 1k/2k/3k/5k pps 0 loss；udpps 2 s 10803/10803；`lat` p50 ~0.98 ms vs baseline ~0.985 ms | `530188e` commit；`README.md:866`；`PROTOCOL_ANALYSIS.md:678-681` | [M实测] | ⚠️ 功能正确性证据可靠；**延迟/吞吐数值不可复现**（见 C11） |
| C11 | 本次复核 smoke（2026-10-21，macOS 开发机，release 二进制=530188e 树，loopback） | udpps 2 s/128 B：sent 86 134 pps、recv 21 036 pps、loss 66.0%；udppaced 3k pps：6000/6000、0 loss；`lat` n=60/payload 64：p50 **236 µs**、p99 583 µs；`udp` 200×1000 B batch16：23.7k pps | 本报告 §4.2（可直接复跑） | [M实测]（本分析） | ✅ 证明 harness 可用；同时说明 README 的 loopback 延迟数（0.30/0.98 ms）不稳定/不可比 |
| C12 | 历史 README/提交中的 UDP N=1 soak | open-loop 128 B ~40k recv pps @~66k sent（称上次 hop batching 前 ~2.6k）；closed-loop ~30k pps/0 loss；udpraw ~82k pps | `README.md:867` | [M实测] | ⚠️ 与 C11（21k@86k）差异大；只可作同一机器内相对比较 |
| C13 | 若干 macOS 微基准（PERF_ANALYSIS 引用，`/tmp` 脚本未入库） | min_by_key 256 项 ~181 ns；1.4 KB 回复拼接 ~17.5 ns；共享 `fetch_add` 22.6/24.6 vs 批处理 0.21 ns；2800 B 指纹 ~45 ns + assemble ~60 ns；socket 额外 getsockopt +1.5–1.7 µs；coarse 1.44 ns / mono 3.26 ns | `PERF_ANALYSIS.md:207,240,355-356,372,386-387,433` | [M实测]（引用 `/tmp` 微基准，未入库） | ⚠️ 只可作「单事件成本」量级；无法从仓库复跑 |
| C14 | 生命周期/恢复类数字 | SIGTERM 0.9 s 重拨；kill -9 20.6 s 恢复；SIGTERM 退出 0.05 s | `c8e5c3d`、`README.md:863` | [M实测] | ✅ 与协议无关，可引用 |

### 1.4 计数/构建/内存事实

| # | 主张 | 核对结果 | 出处 | 证据类 |
|---|---|---|---|---|
| D1 | 测试 301 passed（lib 145 + client 81 + server 75，macOS） | 静态计数复核=**301**（macOS 可运行）；Linux 为 **305**（149+81+75；多 4 个 `cfg(target_os="linux")` 测试） | `README.md:861`、`530188e` commit；本次静态统计（`src/linux.rs:365,388,407`、`src/udp/batch.rs:790` 为 Linux-only） | 代码事实 |
| D2 | 内存口径：per-conn 14.25 MiB；UDP session pool ~1.09 GiB(non-Linux)/~2.09 GiB(Linux)；worst case ~60/36/108 GiB；MQP-3 flow 表 4 KiB/session | 常量与算术一致；`MQP3_FLOW_TABLE_MAX_BYTES=4096` | `README.md:778-788`、`src/mqp/v3.rs:51`、`config-server.toml:39-43` | 代码事实（admission 算术有单测钉住；非 RSS 实测） |
| D3 | 构建工具链 Rust 1.99.0 / edition 2024 / version 0.2.0 | 一致 | `rust-toolchain.toml`、`Cargo.toml:3-5` | 代码事实 |
| D4 | release 二进制与 bench 已存在 | `target/release/{myquic2-server,myquic2-client}`、`target/release/examples/hotpath_bench` 构建于 2026-10-20 16:27（530188e 树；d2f9658 仅改版本） | 本次 `ls/stat` | 代码事实 |
| D5 | 二进制无 `--version` | `--version` 报 clap "unexpected argument" | 本次实测 | 代码事实（文档没写，但会影响脚本化） |

### 1.5 过期标记速查

- ❌ **必须视为过期**：`PROTOCOL_ANALYSIS.md:145`「客户端只做 2-pack」、§5.1:513「现状按 2-pack 建模」、§5.2/5.3 全表（2-pack 前提）；`PERF_ANALYSIS.md` 的 F8「deferred」结论（HEAD 已由 TRAIN 实现同类能力）；`hotpath_bench.rs:1232-1240` 的 2026-09-30 基线；`dist/openwrt-x86_64/config-server.toml.sample:40` 的 2.06 GiB。
- ⚠️ **部分过期**：`PROTOCOL_ANALYSIS.md` 的域名压缩/紧凑 FRAG 收益（模型成立、实现未接线）；`PERF_ANALYSIS.md` 全部 file:line；README 的 loopback 性能数字。
- ✅ **仍有效**：wire 头尺寸/节省算术；bulk 头占比；frame-pool 否决；BATCH N-pack 原型 parity；u32 fragment id；MTU 默认 1200 的决策；F3/F10/F13 未决状态。

---

## 2. 已否决 / 已测量掉 / 已决策的设计（**新分析不要重提**）

| # | 设计/提案 | 当时的证据与理由 | 对「新的、wire 不兼容的 MQP-3」是否仍成立 |
|---|---|---|---|
| R1 | **帧缓冲池**（`Bytes::from_owner` + 分片可复用栈） | [M实测] 全部单元更慢：同线程 +39–52%，跨线程 +128–324%；根因 `from_owner` 每帧 box 控制块 + 固定 2048 B 容量永远走不到 exact-fit 快路径 | **仍成立**。MQP-3 编码仍是 `Vec::with_capacity(exact)+Bytes::from`（`src/mqp/v3.rs:174,313,571`），TRAIN 只是把更多 payload 摊到一帧；生命周期没变。除非改变所有权模型（例如自管 buffer 交给自定义 send API），否则不要重提 |
| R2 | **客户端 BATCH N-pack（F8：2-pack→16-pack）** | [M实测] 原型 parity、collapse 丢包分布略差，被判「不可测 complexity」回退（`8eebdca`）；随后 `530188e` 用 MQP-3 `PendingTrain`（≤64 项）实现了同一能力 | **仍成立（不要重提 BATCH N-pack）**：功能已被 TRAIN 覆盖且更强（可混 flow）。`PERF_ANALYSIS.md:287-303` 的 F8 文字已过时；新分析若要提「N-pack」，应视为**已实现项** |
| R3 | **服务端下行 BATCH**（4ef084a/c8e5c3d） | [模型] 7.8% wire；[M实测] 线上 23% 帧达 16 项上限；随后 `530188e` 改为 v3 TRAIN 下行（混源、run=1 发 SINGLE） | **仍成立（BATCH 已退役）**。对 HEAD 再提 BATCH 会与 TRAIN 冲突 |
| R4 | **保留 MQP-2 对端兼容 / CAPS+HELLO 灰度** | `530188e` 明确「按不兼容对端」部署，删掉 peer 兼容；MQP-2 解码器只为大 payload/测试保留；CAPS/HELLO 未实现 | **前提已变但结论仍成立**：用户明确允许 wire 不兼容、名称仍 MQP-3 → 不需要兼容层。若未来要灰度，CAPS 是**发布/回滚**特性，不是性能收益，不要混进性能论 |
| R5 | **改默认 MTU**（1400 → 1360 → 1200） | `661ce08` 默认 1400；`952001e` 1360；`d73809f` 最终 1200=QUIC floor：未知路径上 default 改大会造成黑洞/丢包突发；已知路径请在配置里写 1360/1400 | **仍成立**。MTU 属传输配置，不是 MQP 帧格式；MQP-3 不应把 MTU 默认值卷进协议重构。若新分析要提 MTU，应作为**部署配置建议**，并引用 B7 模型 + 无 Linux 实测 |
| R6 | **fragment id 改回 u16** | [M实测] u16 历史丢包悬崖：4%/15%/50% @1k/4k/21.8k payload/s；u32 仅多 2 B | **仍成立**。新协议若改 fragment 语义也必须保留 ≥32-bit id 或等价防重用机制 |
| R7 | **fragment train**（把多片塞进一个 TRAIN） | [模型] MTU 1200 下每片 chunk≈1144 B，一帧基本只装一片，包数不减少 | **仍成立**（算术）。紧凑 FRAG 头（省 6–19 B/片）才是分片侧唯一值得做的 |
| R8 | **跨 session TRAIN**（Phase 3） | [断言/推理] quinn 已把同 poll 的 DATAGRAM 合进一个 packet；跨 session 需连接级共享 stager → 引入队列 hop/锁；收益不确定 | **仍成立**：没有 profiling 证明 send state 锁是瓶颈之前不要提。若提，必须附 Linux `perf`/`strace -c` 证据 |
| R9 | **FEC / NACK 默认开启** | [模型] 2 片 +1 parity=+50% 字节；NACK 改变 UDP 语义、需新状态机；只应 opt-in | **仍成立**。新协议可把 FEC 做成协商 opt-in，但不能作为默认收益来源；无丢包链路实测 |
| R10 | **payload 压缩** | [断言] 载荷主要是加密/随机数据，压不动，且增加 CPU/缓冲/延迟 | **仍成立（但只是断言）**：仓库没有载荷熵测量。若新分析要真正论证，需要样本测量；否则照旧不做 |
| R11 | **「重写协议提升 bulk 吞吐」** | [模型] bulk 头 <1%，吞吐由 CC/窗口/MTU 决定（B5/A5/B8） | **仍成立**。新分析不应把 bulk 吞吐作为 MQP-3 重构的目标收益 |
| R12 | **HPACK 式动态字典 / 每目的建一条 QUIC 连接** | [推理] flow 绑定已足够且无需双向同步压缩上下文；连接级状态（握手/CC/传输预算）远大于 flow 表 | **仍成立**（设计推理，无测量） |
| R13 | **512 B fate-sharing 上限** | 设计选择：>512 B 不走 v3 staging，保留 v2 单帧/FRAG；下限保护「一帧丢失只损失同源 ≤512 B × ≤16 项」 | **不一定仍成立**：这是**可重新谈判的设计取舍**（wire 不兼容后 TRAIN 的 fate-sharing 面可以重设计）。但**没有任何测量数据**支持更优取值；新分析若要改，必须给出帧丢失放大模型 + Linux 丢包/延迟 A/B，不能当既有结论 |
| R14 | **显式 ACK 换纯上行 flow 压缩（FLOW_ACK）** | `530188e` 选择「下行压缩帧即隐式 ACK」：无控制面、避免丢首帧黑洞；代价是纯上行 flow 永远 inline | **仍成立**：当前设计正确性已被 smoke/单测覆盖。新协议若要加 CTL/ACK，须评估控制帧丢失/黑洞与状态机成本，不能只算 1 B 收益 |
| R15 | **共享/内部 TLS 握手改协议门禁（ALPN bump 代替 CAPS）** | 默认 ALPN `h3` 是伪装特性；CAPS 是 in-band 灰度方案（未实现） | **仍成立**（若需灰度）；纯性能重构不需要 |

---

## 3. 未决项与可被协议重构吸收的项（HEAD 代码映射）

| 项 | HEAD 代码位置 | 当前状态 | 证据/备注 |
|---|---|---|---|
| **F8** 客户端 N-pack | `src/bin/myquic2-client/assoc.rs:798-1080`（`PendingTrain`，≤64 项）、`:566-798`（burst 内 staging） | **已由 MQP-3 TRAIN 实现（不同设计）** | `PERF_ANALYSIS.md:58,287-303` 的「deferred」与 2-pack 行号已过期；不要按 BATCH 重做 |
| **F13** 重组器 hash/分配融合 | `src/udp/reassembler.rs:403,448,459-465,523,537,334`（3 次探测/完成时 5–6 次、`prints_of`、`assemble`） | **未做（deferred）** | `PERF_ANALYSIS.md:63,379-392`；收益 ~4 ns/片 + 完成时 30–45 ns，风险不划算；代码自 `348c52d` 后未再动 |
| **F3** 线程拓扑过度订阅 | `src/bin/myquic2-client/main.rs:210-244,473-496,508-543`；`src/linux.rs` `pin_to_core` | **未做（待 Linux 2–4 核基准）** | `PERF_ANALYSIS.md:53,167-190`；macOS `pin_to_core` no-op，本机测不出；这是**系统级收益**而非协议收益 |
| **F10** relay 任务跨 runtime | `src/bin/myquic2-client/socks.rs:139`、`assoc.rs:5-10`、`main.rs:379-388,508-543` | **未做（待 `MYQUIC2_SHARD_RUNTIME=0` A/B）** | `PERF_ANALYSIS.md:60,326-340`；0.1–0.3 µs/包模型收益；代码未动 |
| **紧凑 FRAG 接线** | codec：`src/mqp/v3.rs:542-660`；v2 发送：`src/udp/fragmenter.rs:8-23,351`；重组 key `(sess,id)`：`src/udp/reassembler.rs:26-30,187` | **codec 有、未接线** | `README.md:651-662`；`530188e` follow-up 明列；模型收益 6–19 B/片（v4/v6），无实现/测量 |
| **CAPS / HELLO** | 无代码（仅 `PROTOCOL_ANALYSIS.md:424-456` 设计） | **缺失** | `README.md:736-739` 明说无 CAPS/无 `mqp3=false` |
| **FLOW_ACK / FLOW_REJECT** | 无代码；替代=隐式下行确认 `hub.rs:51-57,139-152`、`dispatcher.rs:258-290` | **缺失（设计替代）** | 纯上行 flow 保持 inline：每帧多 1 B flow + 地址。README:674-676 承认此代价 |
| **SESS_CLOSE / FLOW_CLOSE** | 无代码；兜底=`SESS_IDLE_MS=180_000` `src/bin/myquic2-server/table.rs:382`；sweeper `reader.rs:777,1034`、`table.rs:318,353` | **缺失** | 只影响短会话 churn 的资源回收，不影响稳态吞吐；Phase 2 计划 |
| **域名目标压缩** | 客户端显式 `NO_FLOW` inline：`assoc.rs:355-365`；服务端域 flow 不参与压缩：`reader.rs:129-154` | **有意未实现** | 原因（安全+客户端无解析 IP+SOCKS 回包需要源地址）见 `README.md:677-681`、`src/bin/myquic2-client/dispatcher.rs:258-262`；模型 33–38% 域名收益**未兑现** |
| **纯上行 flow 压缩** | 同上隐式 ACK 机制 | **有意未实现** | 需要 FLOW_ACK；纯上行 flow 每帧 inline，收益模型 9–11% 拿不到 |
| **session id u16** | `src/bin/myquic2-client/hub.rs:295-345`（进程级单调 u32 `fetch_add`，不复用） | **未做（Phase 3）** | `PROTOCOL_ANALYSIS.md:493-503`；省 2 B/帧；触碰 id 生命周期/180 s 不复用约束 |
| **v3 观测计数**（frame type / flow count / train items / inline fallback） | 无（`src/stats/udp_stats.rs` 无 v3 字段；`src/mqp/v3.rs` 无计数） | **缺失** | `PROTOCOL_ANALYSIS.md:636`（Phase 1 第 7 项）未落地；新协议矩阵必须先补，否则无法验证压缩率/回退率 |
| **可协商重组上限**（8 KiB 现为编译期常量） | `src/mqp/fragment.rs` 常量、`udp/reassembler.rs` 上限 | **缺失** | Phase 2 设计；对性能影响小 |
| **MTU/重组协商** | 无 | **缺失（有意）** | `PROTOCOL_ANALYSIS.md:254-255`：MTU 属传输配置，不进 MQP 帧 |

> 结论：真正「可被一次 wire 不兼容重构吸收」的协议项只有 **紧凑 FRAG 接线**、**域名/纯上行 flow 压缩（需控制面）**、**session id u16** 三类；F3/F10/F13 是**系统/实现层**，与 wire 是否兼容无关，不应打包进「协议重构」叙事。

---

## 4. 基准工具盘点：`examples/hotpath_bench.rs`

### 4.1 全部模式（HEAD 共 20 个入口）

| 模式 | CLI | 测量内容 | 输出指标 |
|---|---|---|---|
| `echo` | `echo <port>` | UDP echo 靶（8×SO_REUSEPORT 线程，`hotpath_bench.rs:232-258`） | 无（靶） |
| `techo` | `techo <port>` | TCP echo 靶（逐字节回显） | 无（靶） |
| `utag` | `utag <port> <tag>` | 带 tag 的 UDP echo 靶（`udpdomainswitch` 用） | 无（靶） |
| `server` | `server <port> <bytes> <count>` | TCP 下发靶（bulk 用） | 无（靶） |
| `reply` | `reply <port>` | 一次性 HTTP-ish 回复靶（`tcp` 用） | 无（靶） |
| `tcp` | `tcp <socks> <host:port> <n> [conc=16]` | N 次 SOCKS5 CONNECT + 1 次回复 | flows/s, ok, reply_bytes |
| `bulk` | `bulk <socks> <host:port> <mb> [conc=4]` | 并行下载 MiB，TCP pump 吞吐 | MB/s + complete + SHORT 警告 |
| `udp` | `udp <socks> <host:port> <n> [batch=64]` | 单 association 发 N×**1000 B** 收 N 回包 | sent/recv/batch/wall/recv_pps（无 loss%） |
| `udpdomain` | `udpdomain <socks> <host:port> <n> [batch=64]` | 同上但 SOCKS 目标为**域名**（每包 DNS 路径） | 同上 |
| `udpdomainswitch` | `udpdomainswitch <socks> <portA> <portB> <n>` | 同 session 交替两个域名/IP 目标，查错投 | ok_alpha/ok_beta/misrouted |
| `udpdomainmulti` | `udpdomainmulti <socks> <port> <domains> <assocs> <n>` | 多 association × 多域名，压 DNS memo | sent/recv/recv_pps |
| `udpmulti` | `udpmulti <socks> <host:port> <assocs> <n> [batch=64]` | 多 association 并行（唯一能暴露共享状态争用的模式） | complete/failed_assocs/sent/recv/loss%/recv_pps |
| `udpraw` | `udpraw <target> <assocs> <n> [batch=64]` | 不经代理的 loopback 控制组 | recv_pps/loss% |
| `udpps` | `udpps <socks> <host:port> <secs> [payload=128]`（payload 64–200） | 单 association **无节流 blast** | sent/recv/send_errs/sent_pps/recv_pps/loss% |
| `udppaced` | `udppaced <socks> <host:port> <secs> [payload=128] [pps=20000]`（payload 1–512） | 单 association **按绝对时间轴节流** 的小包 soak | 同上 + target_pps；pace 偏差 >5% 告警 |
| `lat` | `lat <socks> <host:port> <n> [payload=64]` | 串行 UDP 请求→回包 RTT（需 `echo` 靶） | samples/lost/stale/bad + p50/p90/p99/p999/max/mean µs |
| `lattcp` | `lattcp <socks> <host:port> <n> [bytes=64]` | 每次迭代新建 CONNECT + 首字节回显 | connect/echo 两组百分位 |
| `udpsweep` | `udpsweep <socks> <host:port> <n> <sizes> [batch=16]` | 按 size 逐包字节校验（含 >512 B/8 KiB 分片/重组） | verified/mismatched/lost + ALL OK/FAILURES |
| `tcpecho` | `tcpecho <socks> <host:port> <bytes>` | TCP 逐字节回显校验 | echoed/mismatched/MB/s/OK |
| `chan` | `chan <n> [depth=256]` | 无网络，测 dispatcher→association mpsc hop 成本 | per_msg/loop_only/queue_cost ns |

### 4.2 本次 smoke 结果（2026-10-21，macOS 开发机，loopback，release 二进制，<60 s）

命令见 §4.3；二进制为 `target/release`（530188e 树，未重建）。对应上面 C11。

```text
udpps     2 s 128 B : sent=172269 (86.1k pps) recv=58577 (21.0k pps) loss=65.997%
udppaced  2 s 128 B 3000 pps : sent=6000 recv=6000 loss=0.000%
lat       n=60 payload=64 : p50=236 p90=262 p99=583 µs lost=0 bad=0
udp       n=200 payload=1000 batch=16 : recv_pps=23660
```

解读：① harness 与命令可用；② `udpps` blast 仍复现「缓冲/BBR 崩溃」（与模式注释一致）；③ `udppaced` 3k pps 0 loss；④ **loopback 延迟数字不稳定**（本次 p50 236 µs，README 同项有 0.30 ms/0.98 ms 两个值），不能当回归阈值，只能同机同轮比较。

### 4.3 运行方法（精确命令，占位符可替换）

```sh
# 0) 仓库根目录执行（配置里的 cert_file/server-cert.pem 等是相对路径）
cd /Users/eric/WorkSpace/MyQUIC2

# 1) 如需重建（现有二进制来自 530188e 树，HEAD 只改版本号；不重建也能跑）
cargo build --release --bins --example hotpath_bench

# 2) 三个进程：UDP/TCP 靶、server、client
./target/release/examples/hotpath_bench echo  <ECHO_PORT> &     # 例如 19290
./target/release/examples/hotpath_bench techo <TECHO_PORT> &    # 例如 19291（lattcp/tcpecho）
./target/release/myquic2-server --config config-server.toml &
./target/release/myquic2-client --config config-client.toml &
# 端口取自配置：server [::]:8443，client SOCKS [::]:1080；config-server.toml 已开 allow_private=true

# 3) 典型矩阵
H=./target/release/examples/hotpath_bench; S=127.0.0.1:1080
$H udp        $S 127.0.0.1:<ECHO_PORT> 2000 16
$H udppaced   $S 127.0.0.1:<ECHO_PORT> 10 128 20000
$H udpps      $S 127.0.0.1:<ECHO_PORT> 5 128
$H udpmulti   $S 127.0.0.1:<ECHO_PORT> 8 20000 64
$H lat        $S 127.0.0.1:<ECHO_PORT> 500 64
$H udpsweep   $S 127.0.0.1:<ECHO_PORT> 64 8,128,512,2000,8000 4
$H bulk       $S 127.0.0.1:<BULK_PORT> 16 4        # 需另起 server 靶
# 4) 延迟要整形路径（Linux）：tc qdisc add dev lo root netem delay 70ms loss 0.5%; 测完 del
```

注意：① 顺序应先起靶再起 client；② `udppaced` 若 `sent_pps` 明显低于 `target_pps`，是 harness/回环成为瓶颈，不是隧道；`udpps` 是无节流 blast，只适合看 loss 崩塌点；③ `lat` 的 `<host:port>` 必须是 IPv4 字面量（源文件 `hotpath_bench.rs:71-73`）。

### 4.4 对新协议矩阵的缺口（**新分析必须先补**）

1. **没有 `udpfanout`**：`PROTOCOL_ANALYSIS.md:684-685,723` 的验收门槛（wire −10%/−30%、send ≥5×）依赖「一个 association、N 个目的地轮转」，但 harness 无此模式（grep 全仓确认只有设计文本提及）。这是测量 MQP-3 核心卖点（混目的 TRAIN）的唯一端到端形状。
2. **吞吐类模式看不见小包批处理收益**：`udp`/`udpdomain`/`udpmulti` 固定 1000 B（`hotpath_bench.rs:779,1198,452`），1000 B 永不批处理（模式头注释 `:50-56` 自述）；能压到 1–512 B 的只有 `udppaced`（节流）与 `udpps`（blast，崩溃不可比）。
3. **没有 wire bytes / send 调用计数**：只打印用户层 datagrams/pps/loss/MB/s；60 s reporter 的 `udp relay` 是应用字节，不是 MQP 帧字节或 QUIC DATAGRAM 数；`metrics` 的 `myquic2_udp_{send_group_size,send_syscalls}`（`src/udp/batch.rs:156-204`）只统计 last-hop UDP syscall，且无 recorder 时是 no-op。要验证「fewer send_datagram/更少 wire」，只能 `strace -c`/`perf` 或临时加计数器。
4. **没有 MQP 帧级计数**：frame kind、TRAIN items、flow 压缩率、inline fallback 率都无计数器（§3 末项），因此「压缩是否生效/域名是否回退」只能看日志或抓包。
5. **没有协议 A/B 开关**：无 `mqp3=false`、无编译期 feature、无第二套编码器并存的开关；新旧对比必须自建分支/双二进制，且 client/server 必须成对替换。
6. **吞吐/pps 模式看不见延迟**：模块头 `:85-94` 明说 loopback ~0 RTT；`lat`/`lattcp` 必须配 netem（Linux）才可信。
7. 文档漂移：模式头注释 `:5-108` 与 usage 串 `:214-219` 漏列多个已实现模式（`utag`/`udpdomain`/`udpdomainswitch`/`udpdomainmulti`/`udpraw`/`udpsweep`/`tcpecho`/`reply`）；`hotpath_bench.rs:1232-1240` 内嵌基线过期（见 C2）。
8. 无 Linux 目标机自动流程：所有运行说明都假设手动起进程；CI 只做功能性 smoke（`.github/workflows/release.yml:119-133`：tcpecho/tcp/udpsweep/udpps 各一次，不比较性能）。

---

## 5. 不要重复提出的清单（do-not-repeat）

1. **不要重提帧缓冲池**——已被 `frame_bench` 全格测量否决（+39–52% 同线程 / +128–324% 跨线程）；先打败这张表再谈。
2. **不要重提「客户端 BATCH 2-pack→16-pack」**——原型已测 parity 并回退；HEAD 已被 `PendingTrain`/TRAIN 覆盖，F8 文字已过期。
3. **不要重提服务端下行 BATCH/source-run flush 优化**——已被 v3 TRAIN 混源取代。
4. **不要建议「为 bulk 吞吐重写协议」**——bulk 头 <1%，吞吐由窗口/CC/MTU 决定。
5. **不要把 MTU 默认值改动写进协议重构**——1400→1360→1200 的决策是「未知路径安全」；MTU 属配置。
6. **不要提议 fragment id 改 u16**——有历史丢包悬崖实测。
7. **不要提 fragment train**——近 MTU 分片时包数不减少（算术已定）。
8. **不要提跨 session TRAIN**——除非有 profiling 证明 quinn send state 锁是主瓶颈；否则收益不确定、复杂度高。
9. **不要把 FEC/NACK 作为默认收益**——2 片 +50% 字节；只可 opt-in。
10. **不要假设域名目标能省 33–38%**——HEAD 明确域名 inline；要拿这笔收益必须先解决「客户端无解析 IP / SOCKS 回包源地址 / DNS rebinding 安全」三个问题并接线。
11. **不要假设纯上行 flow 会压缩**——隐式 ACK 只覆盖有下行的 flow；要改需引入 FLOW_ACK（控制面）。
12. **不要用 `PROTOCOL_ANALYSIS.md` §5 的表格当「预期收益已测量」**——它们全是模型，且以「域名压缩 + 紧凑 FRAG + 2-pack 现状」为前提。
13. **不要引用 README 的 loopback 延迟/pps 数字当基线**——同一个 harness 存在三个来源的 p50（README 旧树 debug 0.30 ms / README MQP-3 release 0.98 ms / 本次 release smoke 0.236 ms），且 40k vs 21k recv pps 差异巨大；只能同机同轮 A/B。
14. **不要把「测试 301」当 Linux 数字**——Linux 是 305（4 个 Linux-only 测试）；README 已注明是 macOS dev box。
15. **不要重复 PERF_ANALYSIS 的 file:line**——全部是 `d73809f` 基线；状态结论可用、行号需重查。

---

## 6. 文档 ↔ 代码漂移清单

| # | 位置 | 文档说 | HEAD 事实 | 影响 |
|---|---|---|---|---|
| G1 | `PROTOCOL_ANALYSIS.md:145,513,520-540` | 客户端现状是 2-pack，模型按 2-pack 算 | `assoc.rs:798-1080` `PendingTrain`（≤64 项 TRAIN）；2-pack 仅在测试注释 `assoc.rs:1222` 出现 | 「相对现状 2-pack」的收益表失效；不要再用 |
| G2 | `PERF_ANALYSIS.md:58` F8 状态 | F8 deferred | 同类能力已由 TRAIN 实现；F8 文字/行号过期 | 状态表其余项仍有效；F8 行需整体重写 |
| G3 | `PERF_ANALYSIS.md` 全部 file:line | 基线 `d73809f` | `348c52d`/`530188e` 多次改动；F5/F8 行号失效 | 只引用结论，不引用行号 |
| G4 | `README.md:865` vs `:866` | 前者 `lat p50≈0.30 ms/p99≈0.90 ms`（debug，旧树），后者 `lat p50≈0.98 ms`（MQP-3 release） | 本次 release smoke p50=236 µs；三者互不一致 | loopback 延迟不可作跨版本阈值；WAN 需 netem |
| G5 | `README.md:867` vs `hotpath_bench.rs:1232-1240` | README：N=1 soak ~40k recv pps（上次 hop batching 前 ~2.6k） | 代码内基线（2026-09-30）为 goodput 2.6k/370 pps；本次 21k recv pps @86k sent | 两处代表不同时期；只能引用「数量级/相对」 |
| G6 | `README.md:861` | 301 passed | macOS 静态计数=301 ✅；Linux=305（+4 个 `cfg(linux)` 测试） | 建议补一句 Linux 数字 |
| G7 | `dist/openwrt-x86_64/config-server.toml.sample:40` | session pool ~2.06 GiB Linux | 仓库 `config-server.toml:41` 与 README:779 已是 ~1.09/2.09 GiB（MQP-3 flow 表 4 KiB 已计入） | 分发样例配置注释过期 |
| G8 | `examples/hotpath_bench.rs:5-108,214-219` | 模式/usage 列表 | 实际多 7–8 个入口（见 §4.4 第 7 条） | 使用者易漏掉 `udpdomainswitch`/`udpsweep` 等 |
| G9 | `PROTOCOL_ANALYSIS.md:684-685,723` | 验收标准包含新增 `udpfanout` | harness 无该模式 | 该验收标准无法执行 |
| G10 | `README.md:29` | 「connection count scales linearly」 | 无测量数据（历史最多测到 24 associations/3 路 aggregate） | 应降级为断言 |
| G11 | `PROTOCOL_ANALYSIS.md:401-405,426-429,638-681` | 「当前实现」状态注记 | 与 HEAD 代码一致（域 inline/FRAG 未接线/无 CAPS） | 可放心作为 HEAD 事实引用 |
| G12 | `PERF_ANALYSIS.md:412-436`「不建议动」清单 | 帧池化/前缀缓存/BATCH 解码/重组拷贝等 | 与 HEAD 一致；其中 BATCH 解码仍保留但生产路径已换 TRAIN | 结论可用；「BATCH 解码」语境已变 |

---

## 7. 给 Lead 的摘要（≤30 行）

```text
1. HEAD d2f9658 仅版本号；工作区干净。PROTOCOL_ANALYSIS 实为 530188e（MQP-3 同一提交）入库，
   主体按 MQP-2/348c52d 现状建模；PERF_ANALYSIS 基线 d73809f，其行号对 HEAD 全部失效。
2. 最硬结论：仓库与 git 历史中没有任何 Linux 目标机 MQP-3 端到端测量。MQP-3 收益数字
   （wire −9~38%、调用 −18×、CPU 1–3%）全部是模型；唯一性能类 [L实测] 是 8eebdca 的窄范围容器 A/B。
   新分析若声称"大幅收益"，必须自带 Linux 基准计划（Linux 2–4 核是文档反复声明的验收门槛，
   但从未执行）。
3. 现有模型给出的协议层上限：tiny/域名/扇出 wire −9~38%，CPU 仅 1–3% 单核（50–100k pps），
   bulk ~0。且 HEAD 实现拿不到模型上界：域名目标 inline、紧凑 FRAG 未接线、纯上行 flow 不压缩。
4. 已测量否决、禁止重提：帧池化（frame_bench：+39–52%/+128–324%）；客户端 BATCH N-pack
   （原型 parity 后回退，已被 TRAIN 取代）；u16 fragment id（4%/15%/50% 丢包悬崖）；MTU 默认改大
   （1400→1360→1200 已定案，MTU 属配置非协议）；FEC/NACK 默认开（+50% 字节）。
5. 已决策但新分析可重审：512 B fate-sharing 上限、session id u16（模型 2–3%）、
   域/纯上行压缩（需控制面+安全设计）。注意：用户允许 wire 不兼容并不消除这些的
   生命周期/丢失放大风险；目前无任何测量支持改它们。
6. 可被重构吸收的真实协议缺口只有：紧凑 FRAG 接线（6–19 B/片）、域名+纯上行 flow 压缩
   （需 ACK/CAPS）、session id u16。F3/F10/F13 是系统/实现层，与 wire 无关，别打包进协议叙事。
7. Harness 缺口（必须先补）：无 udpfanout；udp/udpmulti 用 1000 B（永不批处理）；无 wire bytes/
   send 调用计数；无 MQP 帧级计数；无协议 A/B 开关；无 Linux 目标机流程。现有 release 二进制
   可直接短跑（本次 smoke：udppaced 3k pps 0 loss；lat p50 236 µs；udpps blast loss 66%）。
8. 文档漂移要点：README 三处 loopback 延迟（0.30/0.98/0.236 ms）不可比；N=1 soak 40k vs
   代码注释 2.6k vs 本次 21k；测试 301 是 macOS（Linux 305）；dist 样例内存注释 2.06 vs 2.09 GiB。
9. 建议新分析的证据策略：所有收益主张标注 [模型]/[待 Linux 实测]；先补 harness（fanout + 计数器
   + A/B 二进制），再谈"大幅"。
```
