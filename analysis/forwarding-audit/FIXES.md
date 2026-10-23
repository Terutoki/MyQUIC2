# TCP/UDP 转发审计修复报告（fix round）

**基线**：HEAD `7232088` + 本轮未提交改动（14 个文件，+1407/−157；见 §6 文件清单）
**审计报告**：`analysis/forwarding-audit/REPORT.md`（问题定义与证据）；逐条审计 `tcp.md` / `udp.md` / `socks.md`
**验证**：`analysis/forwarding-audit/fix-verification.md`（fmt/check/clippy/tests 全绿）；`fix-bench.md`（修复后 A/B 与外部准入行为验证）
**原则**：只修“能修且值得修”的问题；服务端代码、MQP-3 线格式保持不变；SOCKS5 热路径不引入新成本；所有新行为都有测试或可外部观测的证据。

---

## 1. 总览

- **P0（审计 §7 建议）全部完成**：UDP 共享会话预算 + 默认预留 SOCKS 份额 + 满时驱逐最老空闲 peer + 扫描限流；TCP 三层准入（per-listener `max_conns` → 进程级 `max_forward_conns` → 共享 8192 relay 限流）。
- **P1 完成**：Linux ICMP 异步错误不再 20ms 全 peer 停顿（限流 + 连续错误让出）；服务端每 peer 成本、churn 规则、wildcard 回复源地址全部写入 README/样例配置。
- **P2 完成一部分**：单次哈希查找、raw 加入 flush 分组 key、mapped-loopback 误报、mapped-unspecified 目标、跨族 overlap 误拒、转发日志窗口与 SOCKS 解耦、监听器数量上限、`#[inline]` 消除抽取边界。
- **明确不修（文档化或设计决策）**：见 §5。
- **验证**：`cargo fmt --check` / `cargo check --all-targets` / `cargo clippy --all-targets -D warnings` 全绿；**566 tests 全绿**（lib 273 + client 168 + server 119 + E2E 6，基线 555，新增 11 个测试）。修复后基准见 `fix-bench.md`。

---

## 2. 逐项修复映射

### 2.1 P0 / P1（资源与正确性）

| 审计编号 | 严重度 | 问题 | 修复 | 证据/测试 |
|---|---|---|---|---|
| UDPF-01 | S1 | 默认单监听器可占满整个 4032 hub；churn >~20 源/s 长期占满 → 新 SOCKS `UDP ASSOCIATE` 被拒，最长 180s | 新增进程级 `max_forward_sessions`（默认 3/4，即 3024，至少留 1/4 给 SOCKS）；每监听器 `max_sessions` 默认改为该预算；满时**驱逐本监听器最老且 idle ≥5s 的 peer**（跳过 `replied` 未折叠的接收型流）并重试一次；拒绝按 `REFUSED`（监听器/预算）vs `SESSION_FULL`（hub）分账 | `forward_udp.rs` 内联测试：budget 上限+释放、空闲驱逐（fresh peer 不驱逐、replied 保护）、扫描限流；config 测试 `forward_budgets_reserve_a_socks_share_by_default`（含 caps 1..=8 的预留断言） |
| T-01 | S2 | TCP 转发无 per-listener/聚合上限，单监听器可占满 8192 共享 relay 许可 → SOCKS 拒新连接 | 三层准入：`spec.max_conns`（默认=进程预算）→ 进程级 `max_forward_conns`（默认 6144=3/4，至少留 2048 给 SOCKS）→ `socks_conn_limiter()`（8192）；三层 permit 均持有到连接结束，按层独立限流告警 | `forward.rs::TcpAdmission::try_admit` + 3 个内联测试（每层拒绝释放外层 permit、成功持三 permit 到释放、外层优先拒绝）；config 测试 `tcp_forward_max_conns_parses_clamps_and_defaults` |
| UDPF-04 | S2 | Linux 异步 ICMP 错误：`recv` 错误后 sleep 20ms 停顿所有 peer；send 侧错误可能误丢无关回复 | 删除 20ms 无条件 sleep：连续错误计数、每 32 次连续错误 `yield_now`，成功接收即清零；transient 分类加入 `ErrorKind::OutOfMemory` 与 unix `ENOBUFS`/`ENOMEM`；transient/fatal 使用独立限流窗口（fatal 日志不会被 transient 吞掉） | `forward_udp.rs` 内联测试 `recv_error_classification_covers_resource_errors_but_not_broken_sockets`；既有 `udp_forward_recv_error_classification_matches_linux_icmp_semantics` 仍绿 |
| UDPF-02 | S2 | 每个 UDP peer = 一个完整服务端 session（fd+reader+~288KiB 计费），创建在共享 reader 内联 → HOL | **文档化 + 由 P0 预算限制规模**（服务端“不改代码”是特性约束）：README/样例写明每 peer 服务端成本、8192 池与公平份额，要求按服务端预算设置 `max_sessions`/`max_forward_sessions` | `README.md` §TCP/UDP forwarding（limits/operational notes）；`config-client.toml` 注释 |
| UDPF-03 | S2 | wildcard UDP 监听器回复源地址由路由选择（多宿主/严格客户端丢包） | **文档化**（实现 `IP_PKTINFO` 回填需要改共享 recv/send 路径，跨平台风险大，本轮不做）：README 明确“多宿主请绑定具体地址”，并对比 SOCKS 的行为 | README "IPv4 and IPv6" / operational notes |
| UDPF-05 | S3 | 单监听器单任务，单核 pps 上限 | 文档化（与 plan §11 一致；SO_REUSEPORT 分片留待实测成为瓶颈再做）；本轮没有引入额外单核开销（见 UDPF-06/UDPF-04） | README limits 表 |
| U-3（审计 §7） | S3 | `[::ffff:127.0.0.1]` 监听误报 “not loopback” | 新增 `util::listen_is_loopback()`（先 unmapped v4 再判断），TCP/UDP 转发告警共用 | `util.rs`；`forward.rs`/`forward_udp.rs` 使用 |

### 2.2 P2（清理项，本轮已完成）

| 编号 | 修复 |
|---|---|
| UDPF-06 | `handle_datagram` 稳态单次哈希查找：先 `get_mut`，miss 才 `create_peer` + 再取；send 体抽成 `send_peer_payload` |
| UDPF-07（部分） | 拒绝/致命/transient 日志窗口按层拆分；转发连接/会话拒绝分别限流；启动日志携带生效上限（TCP: `max_conns`/`forward_conn_budget`/`shared_relay_limit`；UDP: `max_sessions`/`forward_session_budget`） |
| UDPF-08 | 错误分类扩展到 `OutOfMemory` + unix `ENOBUFS`/`ENOMEM`，资源类错误不再永久停监听器 |
| UDPF-10（部分） | `flush_staged` 分组 key 加入 `raw`（防止未来同 socket 两种回程模式混进一个 sendmsg）；新增 UDP 预算/驱逐/限流测试 |
| UDPF-11 | 未做公平性调度（UDP 语义下可接受）；文档提示单一 flooding peer 会占用监听任务 |
| T-02 | target 校验先 unmapped 再判 `unspecified`：`[::ffff:0.0.0.0]:p`、`[::]:p`、`0.0.0.0:p` 均拒绝；新增测试 |
| T-03 | `listen_overlaps` 改为非对称跨族规则：`0.0.0.0:P` 不覆盖具体 v6（合法组合不再误拒）；`[::]:P` 双栈覆盖 v4/v6 仍拒绝；新增测试 |
| T-04 | 转发 abort 使用独立日志窗口，不再消耗 SOCKS 的 `tcp_abort_log_due()`；失败行保持独立限流 |
| T-05 | 新增 `MAX_FORWARD_LISTENERS = 256`（每协议），启动即报错；O(n²) 校验被 256 上限约束 |
| T-06（部分） | `socks_listen` 在**任何转发 listener bind 之前**解析（无效配置不再出现“先绑转发端口再失败”）；bind 仍发生在 QUIC 池启动后（fail-fast 性质不变，残留见 §5） |
| T-07（部分） | mapped-loopback 误报已修；link-local listen 仍在 bind 时失败（残留，见 §5） |
| R-01（review） | `TcpAdmission` 抽为可测 seam + 3 个测试钉住三层 permit 生命周期；`tune_relay_tcp` 移到准入之后（拒绝连接不再做无用 setsockopt） |
| R-02（review） | `default_forward_share` 改为 `cap - max(cap/4,1)`（`max_udp_assocs` 2..=7 也保留 SOCKS 预留）+ caps 1..=8 测试 |
| R-04（review） | TCP 启动行补齐进程级预算与共享上限 |
| 性能残留风险 | `send_payload_uplink` 加 `#[inline]`，消除抽取函数调用边界对 SOCKS UDP 单包路径的不确定性 |

---

## 3. 新增/变化的配置

```toml
# 顶层（均可选；默认值保证 SOCKS 至少保留 1/4 预算）
# max_forward_conns   = 6144   # 所有 [[tcp_forward]] 并发连接总预算（默认 3/4 * 8192）
# max_forward_sessions= 3024   # 所有 [[udp_forward]] peer 会话总预算（默认 3/4 * max_udp_assocs）

[[tcp_forward]]
listen = "127.0.0.1:8080"
target = "example.com:80"
# max_conns = 1024             # 本监听器并发上限；缺省 = 进程级 max_forward_conns

[[udp_forward]]
listen = "127.0.0.1:5353"
target = "1.1.1.1:53"
# max_sessions = 1024          # 本监听器 peer 上限；缺省 = max_forward_sessions（3024）
```

行为变化（向后兼容旧配置，但默认值语义变了）：
- `udp_forward.max_sessions` 缺省值从“全局 4032”变为“转发预算 3024”（SOCKS 至少保留 1008）。
- UDP 表满时不再直接拒新 peer：先尝试驱逐本监听器 **idle ≥5s** 的最老 peer 再重试一次（每 100ms 最多扫描一次，避免 spoofed-source flood 把 O(peers) 扫描放大成 CPU DoS）。
- TCP 转发新增三层准入；默认配置下单个监听器最多占 6144，SOCKS 至少保留 2048 个 relay 许可。
- 启动即失败的新情形：`max_conns = 0`、`max_sessions = 0`、`[::ffff:0.0.0.0]` 形式 target、超过 256 个同名监听器、或原先被误拒的合法跨族组合现在**允许**。

---

## 4. 验证

| 门禁 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | PASS（0 diff） |
| `cargo check --workspace --all-targets` | PASS（0 warnings） |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS（0 warnings） |
| `cargo test --lib` | **273 passed** |
| `cargo test --bin myquic2-client` | **168 passed**（含 7 个新内联测试） |
| `cargo test --bin myquic2-server` | **119 passed** |
| `cargo test --test forward_e2e` | **6 passed**（全部转发进程级 E2E） |
| 合计 | **566 passed, 0 failed**（基线 555） |

新增测试清单：
- `config::client_conf::tests`: `forward_budgets_reserve_a_socks_share_by_default`、`tcp_forward_max_conns_parses_clamps_and_defaults`、`cross_family_listen_overlap_is_asymmetric`、`forward_listener_count_is_capped`（+ 既有用例更新）
- `forward::tests`: `admission_holds_one_permit_from_each_level_until_released`、`admission_refusals_release_every_earlier_level`、`admission_refuses_at_the_outermost_exhausted_level`
- `forward_udp::tests`: `forward_budget_refuses_extra_peers_and_releases_on_drop`、`listener_cap_evicts_only_a_peer_idle_past_the_floor`、`eviction_scan_is_throttled_against_a_refusal_flood`、`recv_error_classification_covers_resource_errors_but_not_broken_sockets`
- 逐条门禁证据：`analysis/forwarding-audit/fix-verification.md`（含最终树 addendum：diff sha256 变更后重跑全部门禁仍全绿）。

### 4.1 修复后实测（`fix-bench.md`）

**SOCKS5 ECHO A/B（修复后 HEAD vs 父版本 `1135076`，3 组交替重复）**

| 指标 | parent | 修复后 HEAD | 结论 |
|---|---|---|---|
| UDP 未节流 blast clean pps 中位 | 31,704.5（26/30 clean） | 29,644（19/30 clean） | **−6.5%**；修复前同口径为 −7.6%（比值 0.924→0.935）→ 该差异**与本轮修复无关，是 `41031b4` 特性代码本身的既有差异**（修复轮未改 SOCKS UDP 分发形态） |
| UDP blast 丢包 run 比例 | 4/30 | 11/30 | 与修复前同方向（两轮合并 13/85 vs 30/85，Fisher p=0.0044） |
| `udppaced` 30k / `udpbidir` 20k | 中位 0% / 0.000% | 中位 0% / 0.000% | 无差异 |
| UDP 串行延迟（隔离测量 p50/p99） | 116 / 282 µs | 119 / 295 µs | 无差异（区间重叠） |
| TCP `lattcp` connect/echo p50 | 103 / 130 µs | 104 / 132 µs | 无差异 |
| TCP 8MiB `tcpecho` 稳态（快模式） | 88.9 MB/s | 87.7 MB/s | 无差异（双峰现象两版等频） |

> 结论：修复轮**没有引入**新的 SOCKS5 TCP/UDP ECHO 回归。审计阶段发现的“未节流 UDP blast −6.5~7.6%”**依然存在，且归因于 v0.2.2 转发特性提交本身**（修复轮无法也无意改变它；见 REPORT.md 与 bench.md 的归因讨论——静态每包成本仅 ~1ns，量级上更符合编译布局/内联扰动，建议 Linux + PGO 复核后再决定是否作为发布门禁）。

**外部准入行为验证（独立 python 客户端，真实二进制）**

| 检查 | 结果 |
|---|---|
| B1 `tcp_forward max_conns=2`：5 个并发连接 | **2 admitted / 3 RST**；关闭一个立即放行；日志出现 listener limit WARN → PASS |
| B2 `max_forward_conns=2`（监听器上限 5） | **2 admitted / 3 RST**；日志出现 forward budget WARN → PASS |
| B3 `udp_forward max_sessions=2`，5 个不同源 socket | **2 个 peer 收到回复 / 3 个被拒**；日志出现 session limit WARN 与计数 → PASS |
| B4 驱逐（A 收到回复后 idle，B 重试） | B 在 **4.94s** 被接纳（A idle 5.44s；修复前 34.52s）→ PASS；5s 下限仍被遵守 |
| B4c 对照（A 无回复活动） | 0.71s 接纳（5s 下限生效）→ PASS |
| B5 转发路径 sanity | UDP forward 30,573 pps clean（与修复前同噪声）；50 peers 100,000/100,000、0% 丢包；TCP SHA-256 10/10 匹配、稳态 87.8–95.5 MB/s → PASS |

> B4 的 34.5s→4.94s 是修复轮末尾的一处补强：驱逐扫描现在用 `idle_since_tick(now, EVICT_MIN_IDLE_MS)` **折叠**未处理的 `replied` 活动（而不是跳过该 peer），避免“刚收到回复的 peer 要等 30s idle tick 才能被驱逐”；接收型活跃流仍受保护（每次回复会重设 flag）。已验证并重跑全部门禁。

---

## 5. 明确不修 / 残留（含理由）

| 项 | 状态 | 理由 |
|---|---|---|
| 服务端每 peer 一个 session 的成本/HOL（UDPF-02） | 仅文档化 | 特性约束是“服务端零改动”；增加服务端配额是产品决策，留待后续 |
| wildcard 回复源地址（UDPF-03/U-3） | 仅文档化 | `IP_PKTINFO` 需要改共享 recv/send 路径（SOCKS 也受影响面）且跨平台差异大；先要求多宿主绑定具体地址 |
| 单监听器单核上限（UDPF-05） | 文档化 | plan §11 已知；SO_REUSEPORT 分片列为后续实测驱动项 |
| 无会话 gauge/任务监管/自动重启（UDPF-07 余项） | 未做 | 需要扩展 60s reporter/监管面；不影响正确性，建议后续独立改动 |
| UDP per-peer 公平性（UDPF-11） | 未做 | UDP 语义允许丢包；文档提示 |
| bind 仍发生在 QUIC 池启动后（T-06 余项） | 未做 | fail-fast 性质未变；把 bind 整体前移会重构启动拓扑，风险大于收益 |
| link-local listen 仅 bind 时失败（T-07 余项） | 未做 | 需要平台相关的 scope-id 处理，保持现状即可（启动仍失败，只是错误阶段晚） |
| RST-vs-FIN / 多监听器交互测试（T-08 余项） | 未做 | 已有进程级 E2E 覆盖主路径；补 RST 断言需扩展 E2E 工具，列为后续 |
| SOCKS 入口 target 的 mapped-unspecified 防御（review R-06） | 未做 | 既有 wire 层行为，非本次回归；`allow_private=false` 仍过滤 |
| 顶层 `max_forward_*=0` 静默 clamp（review R-03） | 保持 | 与既有 `max_udp_assocs` 的全局 knob 约定一致（全局 clamp、每项报错）；README 已写明 |

---

## 6. 文件清单（git diff --stat）

```
 README.md                                       |  67 ++-   # 新配置键/预算/成本/churn/wildcard 文档 + 测试计数
 config-client.toml                              |  33 +-    # 新键注释与默认值
 dist/openwrt-x86_64/config-client.toml.sample   |  33 +-    # 同上
 src/bin/myquic2-client/assoc.rs                 |   6 +     # #[inline] send_payload_uplink
 src/bin/myquic2-client/dispatcher.rs            |   8 +-    # raw 加入 flush run key
 src/bin/myquic2-client/forward.rs               | 283 +++-  # TCP 三层准入 + 独立日志窗口 + 准入测试
 src/bin/myquic2-client/forward_udp.rs           | 735 +++-- # UDP 预算/驱逐(含 replied 折叠)/限流扫描/ICMP 修复/单次查找 + 测试
 src/bin/myquic2-client/main.rs                  |  33 +-    # 共享预算 wiring、socks_listen 先解析、启动日志
 src/bin/myquic2-client/socks.rs                 |  16 +-    # MAX_SOCKS_CONNS 单一来源
 src/bin/myquic2-client/tests.rs                 |   4 +     # spawn 调用点参数
 src/bin/myquic2-client/util.rs                  |  19 +      # listen_is_loopback
 src/config/client_conf.rs                       | 286 +++-  # 新配置键/预算/校验/overlap/target 规则 + 测试
 src/config/tuning.rs                            |  22 +      # MAX_SOCKS_CONNS + DEFAULT_FORWARD_CONNS
 src/lib.rs                                      |  19 +-     # re-export
 14 files changed, 1407 insertions(+), 157 deletions(-)
```

**状态**：修复轮未提交（工作区 diff，基 HEAD `7232088`）；最终树经 `fix-verification.md`（含 addendum）判定 **GO**（fmt/clippy/check 全绿、**566 tests** 全绿），`fix-bench.md` 提供修复后实测与外部准入验证（含 B4 修复后复测）。
