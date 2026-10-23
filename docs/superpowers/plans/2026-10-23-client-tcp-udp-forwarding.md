# 客户端 TCP/UDP 转发（Port Forward over QUIC）设计方案

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `myquic2-client` 中新增可配置的 TCP/UDP 端口转发：本地监听 `IP:port`，把收到的原始 TCP 字节流 / UDP 数据报经现有 QUIC 通道送到 `myquic2-server`，由服务端按现有逻辑连接/发送到配置的固定目的地。

**Architecture:** 完全复用现有两条数据平面，不新增 wire 协议、不改服务端：TCP 走一条 QUIC 双向流（先写 MQP 目标地址头，再双向字节泵），UDP 走 MQP-3 rev2 DATAGRAM（每个客户端源地址一个 client session，复用 `UdpHub` / `AssocEntry` / `UplinkFlows` / `SharedEgress`）。客户端新增两个监听模块；唯一必要的共享代码改动是给 dispatcher 的回程加 "raw 负载" 回程模式（SOCKS 关联回 SOCKS5 UDP 头，转发监听器回原始 payload），以及把 SOCKS 关联里的 UDP 上行发送块抽成共享函数。

**Tech Stack:** Rust 1.99 / edition 2024、tokio、quinn 0.11、MQP-3 rev2（仓库内 `src/mqp`、`src/udp`）、`bytes`、`arc-swap`、`foldhash`、`socket2`、`serde`/`toml`；不新增运行时依赖，测试新增 dev-dependency `tempfile`。

**Spec:** 本文档（仓库内没有独立 spec；需求见 §1，协议事实见 [MQP3_REV2_SPEC.md](../../../MQP3_REV2_SPEC.md) 与 [README.md](../../../README.md#-mqp-3-rev2-protocol-in-depth)）。

## Global Constraints

- 工具链固定 Rust `1.99.0`、edition 2024（`rust-toolchain.toml`）；`cargo fmt --all --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets` 全绿是合并门槛。
- 配置结构体都是 `#[serde(deny_unknown_fields)]`：拼错字段必须启动失败，不能静默取默认值。
- 服务端（`src/bin/myquic2-server/**`）**零改动**；本功能只改客户端 + 共享配置/回调模式。
- 不新增运行时第三方 crate。新增 dev-dependency 仅允许 `tempfile`（进程级 E2E 测试的临时目录）。
- release profile `panic = "abort"`，但测试/dev 会 unwind：任何持有 `UdpHub` 槽位的结构必须用 `Drop` 保证 "一次 alloc_sess 对应一次 release"。
- 现有 SOCKS5 行为、MQP wire、热路径分配/加锁形状不得改变；抽共享函数必须是逐行等价搬移。
- 配置默认值向后兼容：没有 `[[tcp_forward]]` / `[[udp_forward]]` 的旧配置文件必须原样工作。

## Review Focus

1. **UDP 回程不能带 SOCKS5 UDP 头**：转发端 app 收到的是原始 payload，若 dispatcher 仍写 `RSV|FRAG|ATYP|ADDR|PORT`，对端会把头当数据（DNS/游戏/QUIC 全部解析失败）。测试落在 Task 3。
2. **监听配置错误必须启动即失败**：拼错的 listen/target、重复监听、端口 0 不能变成 "少一个监听器但进程正常"，否则用户以为在转发。测试落在 Task 1 与 Task 7。
3. **session 槽位恰好释放一次**：空闲回收、shutdown、任务 panic 三条路径都不能泄漏 `UdpHub` 槽位或把 relay socket 永久留在 hub 里。测试落在 Task 5。
4. **服务端策略失败要快速失败、不能挂住**：目标在私网而服务端 `allow_private=false` 时，TCP 必须让 app 看到连接被关闭而不是永久等待。测试落在 Task 7。
5. **TCP 半关闭与大 payload 完整透传**：request/response 半关闭、>16 KiB 数据不能截断或丢最后一段。测试落在 Task 4 与 Task 7。

---

## 1. 需求

### 1.1 目标

1. `config-client.toml` 中可按数组配置多个 **TCP 转发监听器** 与 **UDP 转发监听器**，每项声明本地 `listen = "IP:port"` 与远端 `target = "host:port"`。
2. TCP：接受本地连接，把字节流通过一条 QUIC 双向流送到服务端，由服务端直连 `target`，双向透传；对端关闭 → 本地 FIN，反之亦然。
3. UDP：在本地 socket 上收数据报，按客户端源地址（`IP:port`）区分会话，经现有 MQP-3 rev2 DATAGRAM 路径送到服务端，由服务端从它自己的 session socket 发往 `target`；`target` 的回包原样送回对应客户端源地址，**不带任何 SOCKS 头**。
4. 目的地解析保持在出口（服务端）：配置的 `target` 可以是 IP 字面量或域名，域名由服务端解析并套用现有 SSRF/`allow_private` 策略。
5. 最大程度复用成熟组件：QUIC/TLS/congestion 继续由 quinn/rustls 提供；TCP 字节泵用现有 `copy_tcp_quic_acked`；UDP 复用 MQP-3 rev2 codec/stager/registry、`UdpHub`/`AssocEntry`/`SharedEgress`、Linux `recvmmsg`/`sendmmsg` 批处理；配置用 serde/toml；socket 选项用现有 `socket2`/rustix helper。

### 1.2 非目标（YAGNI）

- 服务端监听端口（反向隧道 / frp server 侧 `[[proxy]]` 形态）——本需求只在 client 配置。
- 动态目的地（已有 SOCKS5 CONNECT / UDP ASSOCIATE 覆盖，不重复实现）。
- 热加载 / 管理 API；监听器在进程生命周期内固定。
- UDP 的可靠/有序语义（继续遵守 MQP-3 "不做可靠 UDP" 的非目标）。
- 客户端侧 DNS 解析（破坏 "在出口解析并鉴权" 的现有安全不变量）。
- 新的 wire frame、MQP 版本协商、服务端策略扩展。

### 1.3 语义定义

| 项 | TCP 转发 | UDP 转发 |
|---|---|---|
| 入站复用 | 每条本地 TCP 连接 = 一条 QUIC bidi stream | 每个客户端源 `IP:port` = 一个 client session（MQP rev2 `sess`） |
| 上游连接 | 服务端为每条流 `connect(target)` | 服务端为每个 session 建一个 64 KiB session socket，`sendto(target)` |
| 回程 | QUIC stream 数据 → 本地 TCP | 服务端 session 收包 → MQP 回程 → 监听 socket `sendto(客户端源)`，**无 SOCKS 头** |
| 生命周期 | 连接关闭/半关闭/300 s 空闲/QUIC 断线即断 | 180 s 无双向活动回收 session（与 SOCKS 关联一致）；QUIC 重连后沿用同一 `sess` 自动重开 flow |
| 失败语义 | 建流失败 → 关闭本地 TCP（RST），app 自行重试 | 数据报丢失（UDP 语义）；无 egress 时丢弃并计数 |
| 目标 | `TargetAddr::Ip` 或 `Domain`（服务端解析） | 同左 |

---

## 2. 现状调研结论（复用什么、缺什么）

### 2.1 TCP 路径已经完整

- 客户端 SOCKS `CONNECT` 路径就是我们要的转发：`handle_socks` → `pool.pick_tcp_index(&target)` → `slot.wait_conn()` → `conn.open_bi()`（带 5 s 超时与死连接清理 `retire_dead_slot`）→ 先单独写出 `AddrHeader` → `copy_tcp_quic_acked(...)`。见 [socks.rs:126-312](../../../src/bin/myquic2-client/socks.rs#L126-L312)。
- 服务端 `handle_tcp_stream` 读 header、DNS/happy-eyeballs、写 MQP dial ACK、再双向泵。见 [tcp.rs:27-210](../../../src/bin/myquic2-server/tcp.rs#L27-L210)。**服务端不需要任何改动。**
- `copy_tcp_quic_acked` 已实现：QUIC→TCP 方向先消费 dial ACK；TCP→QUIC 方向不等待 ACK；空闲超时；失败时 RST。见 [pump.rs:53-62](../../../src/tcp/pump.rs#L53-L62)。

**结论：TCP 转发 = 去掉 SOCKS 协商/应答后的同一段代码。**

### 2.2 UDP 路径已经具备 "关联 = session" 的全部机器

- 客户端 `handle_udp_associate`：`hub.alloc_sess()` → 建 relay socket → `AssocEntry` 发布到 `UdpHub` → 入站 app 数据报经 `send_uplink` 走 egress；回程由该 QUIC 连接的 dispatcher 通过 hub 找到 `AssocEntry` 并 `send_to` 到 `entry.app`。见 [assoc.rs:6-34](../../../src/bin/myquic2-client/assoc.rs#L6-L34)、[assoc.rs:483-781](../../../src/bin/myquic2-client/assoc.rs#L483-L781)。
- `UdpHub`：进程级 session 上限、session id 分配、ArcSwap 分片表、`AssocEntry` 生命周期位。见 [hub.rs:238-402](../../../src/bin/myquic2-client/hub.rs#L238-L402)。
- `AssocEntry`：持有 relay socket、app 地址、回程活动标志与空闲时间戳；dispatcher 直接向 `entry.relay` 写、向 `entry.app` 送。见 [hub.rs:41-196](../../../src/bin/myquic2-client/hub.rs#L41-L196)。
- rev2 上行：`UplinkFlows` + `send_uplink` + connection 级 stager + `drain_assoc_stage`；`send_uplink` 内部处理重连同步（`up.sync`）、OPEN/ACK、INLINE、TRAIN、FRAG。见 [rev2.rs:600-780](../../../src/bin/myquic2-client/rev2.rs#L600-L780)、[rev2.rs:1112-1140](../../../src/bin/myquic2-client/rev2.rs#L1112-L1140)。
- 出口选择：`SharedEgress`（每 egress 绑定的 single-flight + 线程本地 memo）、`Pool::udp_class` / `udp_bind`。见 [egress.rs:164-260](../../../src/bin/myquic2-client/egress.rs#L164-L260)、[pool.rs:724-760](../../../src/bin/myquic2-client/pool.rs#L724-L760)。
- Linux 批量收发：`recv_burst` / `with_burst_msg` / `udp_try_send_grouped`。见 [batch.rs:528-600](../../../src/udp/batch.rs#L528-L600)、[dispatcher.rs:696-760](../../../src/bin/myquic2-client/dispatcher.rs#L696-L760)。

**结论：UDP 转发 = 新写一个"多 peer 的入站入口"，把每个 peer 映射到一个 `AssocEntry` + `UplinkFlows`，其余全部复用。**

### 2.3 唯一的结构性缺口：dispatcher 回程写死了 SOCKS5 UDP 头

`StagedReply` 与 `flush_staged` 总是把 `encode_reply_header(dst)` 放到 payload 前（[dispatcher.rs:75-97](../../../src/bin/myquic2-client/dispatcher.rs#L75-L97)、[dispatcher.rs:696-760](../../../src/bin/myquic2-client/dispatcher.rs#L696-L760)）。原始 UDP 转发的对端期望裸 payload，因此 `AssocEntry` 需要携带回程模式，`StagedReply` 需要透传它，`flush_staged` / `dispatch_one` 在 raw 模式下只发 payload。

### 2.4 不能"一个监听器一个共享 session"

服务端一个 session 只有一个 relay socket，回包全部来自 `target` 这同一个源；若多个客户端 peer 共用一个 session，回包无法区分该发给谁。**必须 per-peer session**：client session 的 `sess` 号是回程 demux 的唯一键（dispatcher 用 `sess → AssocEntry → app 地址`）。

### 2.5 服务器端策略（不改代码，但要写进文档）

- 目标在私网/loopback（`127.0.0.1`、`10/8`、`192.168/16`）时，服务端必须 `allow_private = true`，否则被 SSRF 策略拒绝，TCP 流被 reset、UDP 不回包。见 [pin.rs:320-430](../../../src/bin/myquic2-server/pin.rs#L320-L430)。
- 未配置 `auth_token` + `allow_private = true` 是危险组合；启动时已有告警（[main.rs:319-350](../../../src/bin/myquic2-server/main.rs#L319-L350)）。文档中必须在转发章节重复。

---

## 3. 总体架构

```text
               config-client.toml
   [[tcp_forward]] listen=127.0.0.1:8080  target=example.com:80
   [[udp_forward]] listen=127.0.0.1:5353  target=1.1.1.1:53
                        │
                        ▼
  ┌──────────────────────────── client process ────────────────────────────┐
  │ forward.rs: TcpForwardListener ×N           forward_udp.rs: UdpForwarder │
  │  accept → pick pool slot → open_bi          recv_from/recvmmsg           │
  │  write AddrHeader → copy_tcp_quic_acked     peer→PeerSession{sess, hub   │
  │                                             entry, UplinkFlows, frag,   │
  │                                             UdpBind} → send_uplink       │
  │                        │                              │                 │
  │                        ▼                              ▼                 │
  │              ConnPool (4 TCP + 3 UDP slots)   UdpHub / AssocEntry        │
  │                        │                     (raw 回程模式)              │
  └────────────────────────┼──────────────────────────────┼─────────────────┘
                           ▼                              ▼
                    QUIC bidi stream              MQP-3 rev2 DATAGRAM
                           └─────────── QUIC/TLS ─────────┘
                                        │
  ┌─────────────────────────────────────▼──────────── server process ───────┐
  │ accept.rs / reader.rs: 已有逻辑（零改动）                                  │
  │  TCP: read target → DNS → happy-eyeballs connect → pump                  │
  │  UDP: DATA OPEN(target) → resolve → session socket → sendmmsg           │
  │       回包 → 源匹配 → DATA OPEN|SRC / steady                            │
  └─────────────────────────────────────────────────────────────────────────┘
```

模块划分（client bin 内，遵循现有扁平模块风格）：

| 新文件 | 职责 |
|---|---|
| `src/bin/myquic2-client/forward.rs` | 配置→监听的启动/绑定、TCP accept 循环、TCP relay、转发专用日志节流 |
| `src/bin/myquic2-client/forward_udp.rs` | UDP 监听循环、peer 表、per-peer session 生命周期、空闲 sweep、raw 回程注册 |

共享 lib 改动：

| 文件 | 改动 |
|---|---|
| `src/config/client_conf.rs` | 新配置结构 `ForwardEntry` / `UdpForwardEntry`、字段、解析/校验为 `TcpForwardSpec` / `UdpForwardSpec` |
| `src/bin/myquic2-client/dispatcher.rs` | `StagedReply.raw`、`AssocEntry` 回程模式、`flush_staged` / `dispatch_one` 分支 |
| `src/bin/myquic2-client/hub.rs` | `AssocEntry` 增加 `raw_reply: bool`（`new` 默认 SOCKS；新增 `new_raw`） |
| `src/bin/myquic2-client/assoc.rs` | 把 "egress 取句柄 + send_uplink + recover" 抽成 `send_payload_uplink`，SOCKS 与转发共用（逐行等价） |
| `src/bin/myquic2-client/main.rs` | `mod forward; mod forward_udp;`、启动时校验/绑定/spawn、日志、shutdown 接线 |
| `src/bin/myquic2-client/tests.rs` | 单元测试 |
| `tests/forward_e2e.rs`（新） | 进程级 E2E（真实 server + client 二进制） |
| `config-client.toml`、`dist/openwrt-x86_64/config-client.toml.sample`、`README.md` | 文档/示例 |
| `Cargo.toml` | dev-dependency: `tempfile` |

---

## 4. 配置设计

### 4.1 TOML schema

```toml
# ---- TCP 转发（可配多个；省略 = 关闭）----
# listen: 本地监听地址，必须是 IP 字面量 + 端口（不支持主机名解析本地绑定）
# target: 经 QUIC 到达服务端后，由服务端连接的目标；IP 或域名均可，
#         域名由服务端解析（受服务端 dns_ip_preference / allow_private / SSRF 策略约束）
[[tcp_forward]]
listen = "127.0.0.1:8080"
target = "example.com:80"

[[tcp_forward]]
listen = "127.0.0.1:8443"
target = "10.0.0.5:443"        # 私网目标：服务端必须 allow_private = true

# ---- UDP 转发（可配多个；省略 = 关闭）----
# 每个客户端源 IP:port 建立一个独立 session；180 s 双向无活动回收。
# max_sessions: 本监听器并发 peer 上限（可选，默认 = 全局 max_udp_assocs；
#               与 SOCKS 关联共享进程级 4032 上限）。
[[udp_forward]]
listen = "127.0.0.1:5353"
target = "1.1.1.1:53"
# max_sessions = 1024
```

> TCP 与 UDP 可以监听**同一个** `IP:port`（协议不同，互不冲突）；同一协议内重复监听是配置错误。

### 4.2 类型与解析

```rust
// src/config/client_conf.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardEntry {
    pub listen: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForwardEntry {
    pub listen: String,
    pub target: String,
    #[serde(default)]
    pub max_sessions: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TcpForwardSpec {
    pub listen: std::net::SocketAddr,
    pub target: crate::mqp::addr::TargetAddr,
}

#[derive(Debug, Clone)]
pub struct UdpForwardSpec {
    pub listen: std::net::SocketAddr,
    pub target: crate::mqp::addr::TargetAddr,
    /// 1..=MAX_UDP_ASSOCS
    pub max_sessions: usize,
}

impl ClientConf {
    pub fn tcp_forwards(&self) -> anyhow::Result<Vec<TcpForwardSpec>>;
    pub fn udp_forwards(&self) -> anyhow::Result<Vec<UdpForwardSpec>>;
}
```

`ClientConf` 只增加两个字段（旧配置 JSON/TOML 不变）：

```rust
#[serde(default)]
pub tcp_forward: Vec<ForwardEntry>,
#[serde(default)]
pub udp_forward: Vec<UdpForwardEntry>,
```

### 4.3 校验规则（启动即失败，错误信息带索引和字段名）

| 规则 | 错误示例 |
|---|---|
| `listen` 必须能解析为 `SocketAddr` | `tcp_forward[0].listen "127.0.0.1": missing :port` |
| `listen` 端口必须非 0 | `udp_forward[1].listen "0.0.0.0:0": port 0 is not a valid listen port` |
| 同一协议内 `listen` 不得重复 | `tcp_forward[2].listen "127.0.0.1:8080": duplicate of tcp_forward[0]` |
| TCP `listen` 不得与 `socks_listen` 相同 | `tcp_forward[0].listen ...: duplicate of socks_listen` |
| `target` 先按 `SocketAddr` 解析；失败则按最后一个 `:` 拆 `host:port` | `tcp_forward[0].target "example.com": missing :port` |
| target 端口非 0 | `udp_forward[0].target "1.1.1.1:0": port 0 is not a valid target port` |
| target 域名非空、≤255 B、不含空白/控制字符；无括号的 IPv6 字面量报错 | `tcp_forward[0].target "::1:80": IPv6 literal must be bracketed` |
| target IP 不得为 unspecified（`0.0.0.0` / `::`，wire 编码本身会拒绝） | `udp_forward[0].target "0.0.0.0:53": unspecified address` |
| `max_sessions` clamp `1..=MAX_UDP_ASSOCS`（`0` 报错而不是静默禁用） | `udp_forward[0].max_sessions 0: must be >= 1` |

`max_sessions` 默认 = `ClientConf::udp_assoc_count()`（全局 `max_udp_assocs`），即默认不额外限制；文档建议高 fan-out 监听器显式配置。

### 4.4 启动顺序与告警

`client_main` 在 **SOCKS accept 循环之前**：解析配置 → 绑定所有监听（任一个失败 = 进程启动失败）→ spawn 任务 → 打日志。每项日志一行：

```text
tcp_forward 127.0.0.1:8080 -> example.com:80 via QUIC (listener bound)
udp_forward 127.0.0.1:5353 -> 1.1.1.1:53 (max_sessions=1024, per-peer sessions, 180s idle reap)
```

非 loopback 监听额外 `warn!`：

```text
tcp_forward listen 0.0.0.0:8080 is not loopback: any host that can reach it can
use the tunnel to example.com:80 (bind 127.0.0.1 or firewall the port)
```

---

## 5. TCP 转发详细设计

### 5.1 启动

```rust
// forward.rs
pub(crate) fn spawn_tcp_forward(
    spec: TcpForwardSpec,
    pool: ConnPool,
    egress: Arc<SharedEgress>,            // 死连接自愈需要 retire_dead_slot
    timeout: Duration,                    // = reconnect_timeout_secs.max(1)，与 SOCKS 一致
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>>;
```

- `tokio::net::TcpListener::from_std(tcp_listener_dual(&listen.to_string())?)`：复用双栈绑定与 `linux::tune_tcp_listener`。
- 绑定在 spawn 前完成，失败直接向上返回，实现 "启动即失败"。

### 5.2 accept 循环

```text
loop {
  select! {
    accepted = listener.accept() => {
      transient error (EMFILE/ECONNABORTED) → rate-limited warn, 50ms sleep, continue
      linux::tune_relay_tcp(&sock)
      permit = socks_conn_limiter().clone().try_acquire_owned()   // 复用进程级 8192 上限
      spawn(relay_tcp_forward(sock, target.clone(), pool.clone(), egress.clone(), timeout))
    }
    _ = shutdown.changed() => break
  }
}
```

复用 `socks_conn_limiter()` 而不是新开额度：避免 "SOCKS 8192 + 每转发监听器各自 8192" 把进程 fd/task 上限乘出多份。日志注明 "relay connection limit"（已有函数名不改，注释说明转发共享）。

### 5.3 relay

```rust
pub(crate) async fn relay_tcp_forward(
    sock: tokio::net::TcpStream,
    target: TargetAddr,
    pool: ConnPool,
    egress: Arc<SharedEgress>,
    timeout: Duration,
) -> anyhow::Result<()>;
```

步骤与 `handle_socks` 的 CONNECT 后半段一致（去掉 SOCKS 协商与应答）：

1. `let slot_idx = pool.pick_tcp_index(&target); let slot = pool.slot(slot_idx);`
2. `slot.wait_conn(&mut gen_rx, timeout)`；失败 → 关闭本地 TCP。
3. `conn.open_bi()`（5 s 超时）；失败时若 `conn.close_reason().is_some()` → `retire_dead_slot(&slot, slot_idx, &egress, &conn)`（与 SOCKS 完全相同的死连接自愈）。
4. `if pool.is_interactive(&target) { send.set_priority(10) }`。
5. 单独写出 `AddrHeader`（`[0u8; AddrHeader::MAX_LEN]` + `encode_into`），5 s 超时；失败 → `send.reset(0x04)` / `recv.stop(0x04)`。
6. 调 `copy_tcp_quic_acked(sock, send, recv, Duration::from_secs(300), TCP_DIAL_ACK_TIMEOUT)`。
7. 失败日志用 `tcp_abort_log_due()` 节流，格式对齐现有 `warn_socks_end`。

**失败语义**：在进入泵之前失败时，主动把 TCP 连接以 RST 关闭（`sock.set_linger(Some(Duration::ZERO))` 后 drop），让 app 看到 `Connection reset` 而不是干净 FIN —— 与泵内部 "异常结束用 RST" 的既有约定一致；没有 SOCKS 应答可以表达错误。进入泵之后由泵负责 RST/STOP_SENDING。

**为什么不做失败重试**：`pick_tcp_index` 已在选择期避开不健康连接；与 SOCKS 一样，应用层重试是既有约定。重试会引入 "已读 app 字节后换连接" 的复杂语义，YAGNI。

### 5.4 上限 / 观测

- 并发流上限：进程级 `MAX_SOCKS_CONNS`（8192，semaphore）与 QUIC `MAX_BIDI_STREAMS_PER_CONN` 的既有约束，服务端 stream share 上限不变。
- 观测：clean-fin `debug!`（up/down 字节数），异常 `warn!`（RST 原因 + 连接 stats，节流），启动/绑定 `info!`/`warn!`。不新增指标结构。

### 5.5 时序

```text
app → listen:connect
  client: accept → pick slot → open_bi → write AddrHeader(target)
  server: accept_bi → read target → DNS/SSRF → connect(target) → write dial ACK
  client: copy_tcp_quic_acked (recv 方向先吃 ACK)
  app bytes ⇄ QUIC stream ⇄ target bytes
  app FIN → stream FIN → server shutdown target write
  target EOF → stream FIN → client shutdown app write
```

---

## 6. UDP 转发详细设计

### 6.1 为什么 per-peer session

见 §2.4：服务端的回包只有 "session" 一个归属维度，session 内所有 flow 共享同一个上游 socket 与同一个源地址；多个客户端 peer 若共享 session，回包无法 demux。因此：

```text
(listener, peer src IP:port) ── 1:1 ──> (client hub sess) ── 1:1 ──> server session ──> target
```

同一监听器的不同 peer 得到不同 server session（目标看到的源端口不同），这是 UDP NAT 的常规语义；文档写明。

### 6.2 数据结构

```rust
// forward_udp.rs
pub(crate) fn spawn_udp_forward(
    spec: UdpForwardSpec,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>>;

struct UdpForwarder {
    listener: Arc<tokio::net::UdpSocket>,   // udp_socket_dual(listen)，4 MB 端点级缓冲
    target: TargetAddr,                      // 固定目的，编码成 TargetAddrRef 复用
    max_sessions: usize,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    peers: HashMap<SocketAddr, PeerSession, foldhash::fast::RandomState>,
}

struct PeerSession {
    sess: u32,
    hub: Arc<UdpHub>,               // Drop 里释放槽位，panicked task 也不泄漏
    entry: Arc<AssocEntry>,         // relay = listener（Arc 克隆），app = peer，raw_reply = true
    uplink: UplinkFlows,
    frag: R2Fragmenter,
    bind: Option<UdpBind>,          // 首个数据报定 class/shard，之后固定
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        self.entry.alive.store(false, Relaxed);
        self.hub.release(self.sess);     // unpublish + 槽位 -1，恰好一次
    }
}
```

`AssocEntry` 复用点：`relay` 就是监听 socket（发送源端口 = 监听端口，对端可接受）；`app` 固定为 peer 源地址；dispatcher 回程无需知道这是转发，只需 `raw_reply` 决定是否加 SOCKS 头。

### 6.3 入站循环

```text
recv_from(&mut buf) 头事件（或 recv_burst 批量）
  → 每个数据报:
      now = coarse_millis()
      peers.get_mut(&src) 不存在 → create_peer(src, now)
      entry.touch(now)（内部 1 s 节流）
      send_payload_uplink(pool, egress, sess, &target_ref, payload,
                          &mut bind, &mut uplink, &mut frag, now, SessionKind::Forward)
  → burst 结束: 对本次 burst touch 过的每个不同 UdpBind 调 drain_assoc_stage
     （connection 级 stager 跨 session 打 TRAIN，天然复用）
  → idle tick（30 s，带 jitter 相位，复用 ASSOC_IDLE_TICK_SECS）:
      对每个 peer: entry.idle_since_tick(now, ASSOC_IDLE_MS)
        真 → send_sess_close(&egress, &pool, bind, sess, uplink.epoch)
             peers.remove(&src)（Drop 释放槽位）
  → shutdown: 对所有 peer 做上面同样的 close+release，然后退出
```

细节：

- **缓冲/截断**：复用 `ASSOC_RECV_BUF_LEN` 与 `assoc_recv_buf()` 线程本地池；`n >= ASSOC_RECV_BUF_LEN` 记 `TOO_LARGE` 并 `warn_oversize_recv`（与 SOCKS 一致）。
- **批量接收**：Linux 走 `recv_burst` + `with_burst_msg`（线程本地 recvmmsg scratch，纯同步使用，无跨 await 借用）；其他平台走 `try_recv_from` 循环。
- **创建失败**：`hub.alloc_sess() == None` → 全局预算耗尽 → `dgram_drops::SESSION_FULL` + 节流 warn；`peers.len() >= max_sessions` → `dgram_drops::REFUSED` + 节流 warn（区分 "全局没容量" vs "本监听器策略满"）。
- **会话计数**：成功创建 peer session 时调 `udp_stats::session()`，与 SOCKS 关联同一计数器，60 s reporter 自动覆盖。
- **DoS 边界**：peer 表上限由 `max_sessions` 与全局 `MAX_UDP_ASSOCS` 双重约束；源地址可伪造，但只能消耗到上限，且每个 session 只服务于固定目标。
- **空闲语义**：`entry.mark_replied()` 由 dispatcher 回程写，`idle_since_tick` 在 tick 时折叠 —— 与 SOCKS 相同的 "双向活动都算存活"，因此收流 > 发流的 peer 不会被误杀。
- **重连**：`send_uplink` 内部 `up.sync(rev2, sess)` 在连接 epoch 变化时重建 flow；180 s 空闲期内 QUIC 重连后，同一 peer 的下一个数据报自动在新连接上 `OPEN` 同一 `sess`，服务端新建 session，对端无感（UDP 语义下可接受短暂丢包）。
- **单监听器单任务**：v1 一个监听器一个 task 顺序处理所有 peer（与 SOCKS 每关联一个 task 不同，但对端是单 socket，天然串行）；性能路径仍是与 SOCKS uplink 完全相同的 `send_uplink`/stager。未来要高 pps 可对监听 socket 做 `SO_REUSEPORT` 多分片（复用 `udp_socket_dual_reuseport`，kernel 按 4-tuple 粘住 peer），不在本期范围。

### 6.4 raw 回程模式（唯一必要的共享改动）

1. `hub.rs`：`AssocEntry { pub(crate) raw_reply: bool }`；
   - `AssocEntry::new(relay)` → `raw_reply: false`（SOCKS，行为不变）；
   - 新增 `AssocEntry::new_raw(relay)` → `raw_reply: true`（转发）。
2. `dispatcher.rs`：
   - `StagedReply { ..., raw: bool }`，所有构造点从 `entry.raw_reply` 取（`stage_reply`、`stage_reply_follow`、`stage_v3_reply` 加参数、`dispatch_stage_multi` 的两个 batch 内联构造点、`dispatch_stage` 的直构点）。
   - `flush_staged`：对每个 send frame，raw 时 header 长度 0、只发 payload（`SendFrame` 支持空 header，Linux 走 `sendmmsg` iovec，portable 走 `try_send_to`）；非 raw 保持原样。
   - `dispatch_one`：raw 时 `udp_try_send_slice(sock, map_for_dual(app), &payload)`，否则保持 `encode_reply`。
3. 热路径代价：每个 staged reply 多一个 bool 装载与分支；不带 header 的 datagram 反而少一次 22 B 头编码。SOCKS 路径行为与字节输出不变。

### 6.5 上行共享函数（脱敏搬移，避免复制 60 行 egress/drop 逻辑）

从 `AppDgramCtx::process` 的发送段（[assoc.rs:366-460](../../../src/bin/myquic2-client/assoc.rs#L366-L460)）原样抽出：

```rust
// assoc.rs
pub(crate) enum SessionKind { Socks, Forward }

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_payload_uplink(
    pool: &ConnPool,
    egress_shared: &SharedEgress,
    sess: u32,
    target: &TargetAddrRef<'_>,
    payload: &[u8],
    bind: &mut Option<UdpBind>,
    uplink: &mut UplinkFlows,
    frag: &mut R2Fragmenter,
    now: u64,
    kind: SessionKind,
);
```

内容逐行等价：首次数据报选 `pool.udp_class` / `pool.udp_bind`、`egress_shared.with_fresh(... send_uplink ...)`、miss 时 `generation` + `acquire` + `memo_store`、`recover_send_outcome`、fragmented debug 日志。区别仅在日志前缀（`udp assoc {sess}` vs `udp forward {sess}`），用 `SessionKind` 的 `&'static str` 参数化，**不引入动态格式化到热路径**（debug 日志本来就在首次 bind 时才走）。

`process()` 改为调用该函数后 `return AppDgram::Continue`，其余 SOCKS 校验/锁定逻辑不动。

### 6.6 时序

```text
peer A ──udp──> listen:5353
  client: peer-table miss → alloc_sess(sessA) → AssocEntry(raw, relay=listen, app=A) → hub.publish
          send_uplink: DATA OPEN(sessA, target) / 后续 steady|TRAIN
  server: 建 session(sessA) → session socket → sendto(target)
  target ──> server session socket ──> DATA OPEN|SRC / steady ──> client dispatcher
  client dispatcher: sessA → AssocEntry → flush raw payload → listen.send_to(A)
```

---

## 7. 复用与依赖决策（"不重复造轮子" 清单）

| 需求 | 采用 | 说明 |
|---|---|---|
| TCP 字节泵 / ACK / 半关闭 / RST | `myquic2::tcp::copy_tcp_quic_acked`（现有） | 逐行复用；不引 `tokio::io::copy_bidirectional`（会丢 MQP dial ACK 与 RST 约定） |
| TCP 监听/双栈/调优 | `tcp_listener_dual` + `linux::tune_relay_tcp`（现有） | 不自己写 socket 选项 |
| QUIC 流/连接/池 | `quinn` + `ConnPool`/`ConnSlot`/`retire_dead_slot`（现有） | 不新建连接管理 |
| UDP 多路复用/flow | MQP-3 rev2: `UplinkFlows`、`send_uplink`、stager、fragmenter（现有） | 不新增 wire |
| session 注册与回程 demux | `UdpHub`/`AssocEntry`/`UdpHub::alloc_sess`（现有） | 只加 raw 回程 bool |
| 出口连接选择/重连 | `SharedEgress` + per-binding single-flight + 线程本地 memo（现有） | 不重复实现 |
| Linux 批量收发 | `recv_burst`/`with_burst_msg`/`udp_try_send_grouped`（现有） | 复用 `recvmmsg`/`sendmmsg` |
| 小表 hasher | `foldhash`（现有依赖） | 与 hub/DNS/fragment 表一致 |
| 配置 | `serde` + `toml` + `deny_unknown_fields`（现有） | 不手写解析器 |
| socket 选项 | `socket2` / `rustix` helper（现有） | 不直接 unsafe libc |
| E2E 临时目录 | **新增 dev-dependency** `tempfile = "3"` | 仅测试 |

**明确不引入**（避免为 "用库" 而用库）：

- `dashmap`：peer 表由单个监听任务独占，不需要并发 map；引入只会多一层哈希 + shard。
- `moka`：已是依赖（DNS 缓存），但其 future cache 的 TTL 回调不适合 "发 SESS_CLOSE + hub 槽位释放" 的生命周期；现有 30 s tick + `AssocEntry::idle_since_tick` 已是同语义实现。
- `tokio-util`：`CancellationToken` 与现有 `watch` shutdown 重复；`copy_bidirectional` 见上。
- `fast-socks5` / `socks5-impl`：转发路径没有 SOCKS 帧；现有 crate 仅 SOCKS 路径用。
- 任何 "UDP relay" 第三方 crate：现有 MQP 数据平面已是本项目的核心成熟组件，替换等于重写。
- 客户端 DNS 解析库：违反出口解析不变量。

---

## 8. 服务端改动

**代码：零改动。** 需要写进文档的不是改动，而是使用约束：

| 场景 | 服务端要求 |
|---|---|
| target 是公网地址 | 默认即可 |
| target 是私网 / loopback | `config-server.toml: allow_private = true` |
| 高 fan-out UDP 转发 | 受服务端 `MAX_SESSIONS_GLOBAL`（8192）与每连接 fair-share 约束；同一 client 连接承载的 session 数受 fair share（1024..=4096）限制；转发 peer 多时建议提高 `quic_conns` 让 session 分散到多条连接 |
| 安全 | 必须配 `auth_token`；`allow_private = true` + 空 token 是开放代理姿态（服务端已有 warn） |
| UDP 全锥 | 转发场景**不要**开 `udp_full_cone`（转发只需要目标回包，restricted 即可） |

可选后续（不在本期）：服务端按 destination 的 allowlist（`ipnet` 已是依赖）——本期用 `allow_private` + 网络 ACL 即可。

---

## 9. 安全

1. **开放监听器**：`listen` 绑定到非 loopback 时，任何能访问该地址的 peer 都能用这条隧道访问固定 target。启动 `warn!`，README/示例配置默认写 `127.0.0.1`；建议 LAN 场景显式绑定内网 IP + 防火墙。
2. **固定目标比 SOCKS 安全**：转发不能指定任意 destination，只到配置的一个 target；即使监听器意外暴露，可滥用面远小于 SOCKS。
3. **UDP 反射/欺骗**：每个源地址都能创建一个 session（直到上限），目标可被用于放大（如 DNS）。缓解：`max_sessions` + 全局 4032 上限 + 只允许配置的 target；文档建议对公网监听器做 ACL。
4. **SSRF 不变量保持**：客户端不解析域名、不做策略判断；服务端仍在出口执行 `allow_private` / SSRF / reply-source 策略，转发没有绕过任何现有检查。
5. **会话混淆**：`sess` 由本进程 `hub.alloc_sess` 唯一分配，回程 dispatcher 用 `sess → AssocEntry` 解引用，peer 无法伪造别的 peer 的 sess；`AssocEntry.app` 在创建时固定为源地址，之后不改变。
6. **资源边界**：TCP 走既有 semaphore / stream share；UDP 走 `max_sessions` + 全局 hub cap + 服务端 session cap；所有上限失败路径都计数 + 节流告警，不静默。

---

## 10. 观测性

| 级别 | 内容 |
|---|---|
| start | 每个监听器一行 `tcp_forward/udp_forward ... -> target ... (bound)`；非 loopback `warn!`；UDP 打 `max_sessions` / idle 语义 |
| drop | `dgram_drops`: `TOO_LARGE`（超长数据报）、`SESSION_FULL`（全局 hub 满）、`REFUSED`（本监听器 `max_sessions` 满）、`NO_EGRESS`/`EGRESS_DEAD`/`BUFFER_FULL`（复用现有 send 判定路径） |
| close | TCP clean fin `debug!`（up/down B）；异常 `warn!`（节流，含 rtt/cwnd/lost）；UDP session 建立/回收 `debug!` |
| 60 s reporter | 不新增字段；`dgram_drops` 已有总量与 `udp_stats::session()` 计数自动覆盖转发 session |

---

## 11. 性能

- **TCP**：与 SOCKS 完全相同的泵和池路径，无新增拷贝；转发只省掉 SOCKS 协商/应答。
- **UDP 入站**：每数据报成本 = 一次 foldhash HashMap 查找 + 既有 `send_uplink`（与 SOCKS 关联一致）+ `entry.touch` 一次 relaxed load；无锁、无跨任务队列。burst 内复用 `recvmmsg`，burst 末 stager 统一 drain，跨 peer/跨 session 仍可打 `TRAIN dict`（stager 是 connection 级的，天然受益）。
- **回程**：raw 模式少写 10-22 B SOCKS 头，`sendmmsg` 分组不变。
- **上限**：一个 UDP 监听器一个任务；单核 pps 上限与 SOCKS 单关联任务同量级。若未来实测成为瓶颈，再按 §6.3 末尾的 `SO_REUSEPORT` 分片方案扩展（复用现成 `udp_socket_dual_reuseport`）。
- **回归门槛**：不改 SOCKS 热路径的分配/加锁形状；`send_payload_uplink` 抽取是等价搬移，现有 530 个测试全绿 + 可选跑 `cargo run --release --example hotpath_bench` 对比。

---

## 12. 文件改动清单

| 文件 | 动作 | 内容 |
|---|---|---|
| `src/config/client_conf.rs` | modify | `ForwardEntry`/`UdpForwardEntry`/`TcpForwardSpec`/`UdpForwardSpec`、字段、解析校验；错误信息带索引 |
| `src/bin/myquic2-client/forward.rs` | create | `spawn_tcp_forward`、`relay_tcp_forward`、转发日志节流 |
| `src/bin/myquic2-client/forward_udp.rs` | create | `spawn_udp_forward`、`UdpForwarder`、`PeerSession`、`handle_datagram`、`sweep_idle`、shutdown |
| `src/bin/myquic2-client/hub.rs` | modify | `AssocEntry.raw_reply` + `new_raw`（`new` 行为不变） |
| `src/bin/myquic2-client/dispatcher.rs` | modify | `StagedReply.raw`、构造点、`flush_staged`/`dispatch_one` 分支 |
| `src/bin/myquic2-client/assoc.rs` | modify | 抽 `send_payload_uplink`/`SessionKind`，SOCKS 路径改为调用（逐行等价） |
| `src/bin/myquic2-client/main.rs` | modify | `mod forward; mod forward_udp;`、启动校验/绑定/spawn/日志、`shutdown_rx` 传递 |
| `src/bin/myquic2-client/tests.rs` | modify | 新增单元测试（见 §13） |
| `tests/forward_e2e.rs` | create | 进程级 E2E（真实二进制 + 临时配置 + 本地 echo 服务） |
| `Cargo.toml` | modify | `[dev-dependencies] tempfile = "3"` |
| `config-client.toml` | modify | 注释形式的 `[[tcp_forward]]` / `[[udp_forward]]` 示例 |
| `dist/openwrt-x86_64/config-client.toml.sample` | modify | 同上 |
| `README.md` | modify | 配置章节 + 新 "TCP/UDP 转发" 小节（语义、服务端 `allow_private`、安全建议） |

预计：生产代码 ~900-1100 行（含测试 ~1500-1800 行），文档 ~60 行。

---

## 13. 实施任务（TDD，按顺序）

依赖关系：Task 1 → Task 2 → Task 3 → Task 4 → Task 5 → Task 6 → Task 7 → Task 8 → Task 9。Task 2/3 必须先于 4/5，因为转发模块直接消费它们的产物。

### Task 1: 配置结构与校验

**Files:**
- Modify: `src/config/client_conf.rs`
- Test: `src/config/client_conf.rs`（`#[cfg(test)] mod tests`，或 lib 现有测试位置）

**Interfaces:**
- Produces: `ForwardEntry { listen: String, target: String }`、`UdpForwardEntry { listen, target, max_sessions: Option<usize> }`、`TcpForwardSpec { listen: SocketAddr, target: TargetAddr }`、`UdpForwardSpec { listen, target, max_sessions: usize }`；`ClientConf::tcp_forwards() -> anyhow::Result<Vec<TcpForwardSpec>>`、`ClientConf::udp_forwards() -> anyhow::Result<Vec<UdpForwardSpec>>`。
- Consumes: `TargetAddr`（`crate::mqp::addr`）、`MAX_UDP_ASSOCS`/`udp_assoc_count()`。

- [ ] **Step 1: 先写失败测试（TOML 解析 + 全部校验分支）**

```rust
#[test]
fn client_conf_parses_forward_tables() {
    let c: ClientConf = toml::from_str(r#"
socks_listen = "127.0.0.1:1080"
server_addr = "127.0.0.1:8443"
server_name = "test.com"
server_cert_file = "server-cert.pem"
[[tcp_forward]]
listen = "127.0.0.1:8080"
target = "example.com:80"
[[tcp_forward]]
listen = "127.0.0.1:8081"
target = "10.0.0.5:443"
[[udp_forward]]
listen = "127.0.0.1:5353"
target = "1.1.1.1:53"
"#).unwrap();
    assert_eq!(c.tcp_forward.len(), 2);
    let tcp = c.tcp_forwards().unwrap();
    assert_eq!(tcp[1].target, TargetAddr::Ip("10.0.0.5:443".parse().unwrap()));
    let udp = c.udp_forwards().unwrap();
    assert_eq!(udp[0].target, TargetAddr::Ip("1.1.1.1:53".parse().unwrap()));
    assert_eq!(udp[0].max_sessions, c.udp_assoc_count());
}

#[test]
fn client_conf_without_forward_tables_still_parses() { /* 旧配置字符串 → 两个 Vec 为空 */ }

#[test]
fn forward_conf_rejects_bad_listen_target_and_duplicates() {
    for (toml, needle) in [
        (/* listen 无端口 */, "missing :port"),
        (/* listen 端口 0 */, "port 0"),
        (/* target 无端口 */, "missing :port"),
        (/* target 端口 0 */, "port 0"),
        (/* target 0.0.0.0 */, "unspecified"),
        (/* 重复 tcp listen */, "duplicate"),
        (/* tcp listen == socks_listen */, "socks_listen"),
        (/* max_sessions = 0 */, "max_sessions"),
        (/* 未知字段 typo */, "unknown field"),
    ] { /* assert err.to_string().contains(needle) */ }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p myquic2 client_conf_parses_forward_tables -- --nocapture`
Expected: FAIL（字段/类型不存在）

- [ ] **Step 3: 实现配置结构、字段与校验函数**

在 `client_conf.rs` 增加结构体/字段；实现 `tcp_forwards()`/`udp_forwards()` 与私有 `parse_listen`/`parse_target`/重复检查。规则按 §4.3；`max_sessions` 缺省用 `self.udp_assoc_count()`，显式 0 报错，其余 clamp `1..=MAX_UDP_ASSOCS`。target 解析顺序：`SocketAddr` → 最后 `:` 拆 host/port（无括号 IPv6 报错）→ 校验域名长度/空白、端口、unspecified。

- [ ] **Step 4: 跑测试确认通过，并跑全量编译**

Run: `cargo test -p myquic2 client_conf_ -- --nocapture && cargo check --all-targets`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config/client_conf.rs
git commit -m "feat(config): add client tcp/udp forward listener config with startup validation"
```

### Task 2: 抽取共享 UDP 上行发送函数

**Files:**
- Modify: `src/bin/myquic2-client/assoc.rs`
- Test: 现有 `src/bin/myquic2-client/tests.rs` 的 UDP uplink 测试必须原样全绿（不需要新增测试；这一步是等价重构。）

**Interfaces:**
- Produces: `pub(crate) enum SessionKind { Socks, Forward }`；`pub(crate) fn send_payload_uplink(pool, egress_shared, sess, target, payload, bind, uplink, frag, now, kind)`（签名见 §6.5）。
- Consumes: `ConnPool::udp_class/udp_bind`、`SharedEgress::with_fresh/acquire/memo_store/generation`、`send_uplink`、`recover_send_outcome`、`dgram_drops`。

- [ ] **Step 1: 先用测试锁住当前行为（若现有测试已覆盖则跳过新测试）**

确认这些现有测试通过：`client_rev2_open_until_ack_then_steady_and_train`、`egress_stays_on_its_connection_while_it_lives`、`expired_dead_handle_is_invalidated_not_served`、`memo_hit_serves_a_dead_handle_and_the_send_reports_it`、`too_large_refreshes_the_budget_without_discarding_the_handle`。

Run: `cargo test -p myquic2 --bin myquic2-client`
Expected: PASS（重构前基线；全量 client 单测）

- [ ] **Step 2: 把 `AppDgramCtx::process` 的发送段搬进 `send_payload_uplink`**

逐行等价搬移（含注释）；`process()` 只保留 framing、源地址锁定、`now`/touch 计算，然后 `send_payload_uplink(..., SessionKind::Socks); AppDgram::Continue`。日志前缀由 `SessionKind::as_str()` 提供。

- [ ] **Step 3: 跑同一个测试集确认零行为变化**

Run: `cargo test -p myquic2 --bin myquic2-client && cargo clippy --all-targets -- -D warnings`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/bin/myquic2-client/assoc.rs
git commit -m "refactor(client): extract shared UDP uplink send path from SOCKS associate"
```

### Task 3: dispatcher raw 回程模式

**Files:**
- Modify: `src/bin/myquic2-client/hub.rs`、`src/bin/myquic2-client/dispatcher.rs`
- Test: `src/bin/myquic2-client/tests.rs`

**Interfaces:**
- Produces: `AssocEntry::new_raw(relay: Arc<tokio::net::UdpSocket>) -> Self`（`raw_reply = true`；`new` 保持 false）；`StagedReply { sock, app, dst, payload, raw: bool }`；把 `stage_reply` 提升为 `pub(crate)`（`tests.rs` 与 `dispatcher` 同 crate 不同模块，glob 拿不到私有项）。
- Consumes: 现有 `flush_staged`/`dispatch_one` 调用方（签名不变）。

- [ ] **Step 1: 写失败测试：raw 回程只发裸 payload**

```rust
#[tokio::test]
async fn raw_reply_frames_payload_without_socks_header() {
    // peer socket 绑 127.0.0.1:0；listener = 另一个 socket 的 Arc。
    // entry = AssocEntry::new_raw(listener.clone()); entry.app.store(Some(peer_addr));
    // hub.publish(7, entry.clone()).
    // s = stage_reply(&entry, peer_addr, dst, payload) → assert!(s.raw);
    // flush_staged(&mut vec![s], &mut hdrs, &mut offs);
    // 在 peer socket 上收包：字节 == payload（长度 == payload.len()，没有 3+addr 的 SOCKS5 头）。
}

#[tokio::test]
async fn socks_reply_keeps_socks5_header_byte_layout() {
    // AssocEntry::new(...) 同流程；在 peer socket 上收到的数据报满足 SOCKS5 UDP 头：
    // RSV/FRAG=0, ATYP=0x01, addr/port == dst，其后是 payload。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p myquic2 raw_reply_frames_payload_without_socks_header -- --nocapture`
Expected: FAIL（`new_raw` 不存在 / 收到带头的字节）

- [ ] **Step 3: 实现 `raw_reply` 与所有构造点/发送分支**

`hub.rs`: 字段 + 两个构造函数。`dispatcher.rs`: `StagedReply.raw`；`stage_reply` 改 `pub(crate)` 并从 `entry` 取 raw；`stage_reply_follow` 同理；`stage_v3_reply` 增加 `raw: bool` 参数；`dispatch_stage_multi` 的两个内联构造点从 `entry.raw_reply` 取；`flush_staged` 对 `staged[k..k+n]` 按 run 首项的 `raw` 决定 `offs` 是否 push（raw → `(start, 0)`，即空 header）；`dispatch_one` raw 时绕过 `encode_reply` 直接 `udp_try_send_slice(sock, map_for_dual(app), &payload)`。

- [ ] **Step 4: 跑新测试 + 全部现有 client 测试**

Run: `cargo test -p myquic2 --bin myquic2-client`
Expected: PASS（含原有 SOCKS 头断言测试不变）

- [ ] **Step 5: Commit**

```bash
git add src/bin/myquic2-client/hub.rs src/bin/myquic2-client/dispatcher.rs
git commit -m "feat(client): add raw UDP reply mode for forward listeners"
```

### Task 4: TCP 转发监听器

**Files:**
- Create: `src/bin/myquic2-client/forward.rs`
- Modify: `src/bin/myquic2-client/main.rs`（只加 `mod forward;`，接线在 Task 6）
- Test: `src/bin/myquic2-client/tests.rs`

**Interfaces:**
- Produces: `pub(crate) fn spawn_tcp_forward(spec: TcpForwardSpec, pool: ConnPool, egress: Arc<SharedEgress>, timeout: Duration, shutdown: watch::Receiver<bool>) -> anyhow::Result<tokio::task::JoinHandle<()>>`；`pub(crate) async fn relay_tcp_forward(sock: tokio::net::TcpStream, target: TargetAddr, pool: ConnPool, egress: Arc<SharedEgress>, timeout: Duration) -> anyhow::Result<()>`。
- Consumes: `tcp_listener_dual`、`linux::tune_relay_tcp`、`socks_conn_limiter`、`ConnPool::pick_tcp_index/is_interactive/slot/wait_conn`、`retire_dead_slot`、`socks::TCP_DIAL_ACK_TIMEOUT`、`copy_tcp_quic_acked`、`AddrHeader`。

- [ ] **Step 1: 写失败测试：真实 QUIC 对端 + 假 server 验证 relay**

```rust
#[tokio::test]
async fn tcp_forward_relays_bytes_and_header_to_fixed_target() {
    // real_connection_with_server() 建真实 client/server quinn 连接。
    // 把 conn 发布进一个 ConnPool 的 slot 0（tests 内 pub(crate) 可写）：
    //   pool.slot(0).shared.store(Some(Arc::new(client_conn))); slot.live.store(true);
    // 假 server 任务：server_conn.accept_bi() → 读 header → TargetAddr::decode →
    //   assert == 配置 target → 写 MQP ACK（encode_tcp_ack_into）→ echo 数据 → finish。
    // 本地建立 TcpListener + connect/accept，得到 app 侧 TcpStream。
    // relay_tcp_forward(app_sock, target, pool, egress, 5s).await
    // 断言 app 写入的 "ping" 回显为 "pong-echo"，读取到 EOF（半关闭）。
}

#[tokio::test]
async fn tcp_forward_closes_app_socket_when_no_quic_connection() {
    // 空 pool（slot 不 publish）→ relay 在 timeout 内失败 → app 侧 read 返回 Err(ConnectionReset) 或 EOF(0)，不 hang。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p myquic2 tcp_forward_ -- --nocapture`
Expected: FAIL（函数不存在）

- [ ] **Step 3: 实现 `forward.rs`**

按 §5.1/5.2/5.3 实现。注意：
- accept 循环里对 accept 错误节流（复用 `claim_log_window_counted` 模式，新增独立 static 槽位）；
- 失败路径在进入泵前 `set_linger(Some(Duration::ZERO))` 再 drop（RST）；
- `relay_tcp_forward` 不写任何 SOCKS 字节；
- 日志使用 `warn!`/`debug!` 并节流，不新增指标。

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p myquic2 tcp_forward_ -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bin/myquic2-client/forward.rs src/bin/myquic2-client/main.rs
git commit -m "feat(client): add TCP forward listener relaying over QUIC streams"
```

### Task 5: UDP 转发监听器

**Files:**
- Create: `src/bin/myquic2-client/forward_udp.rs`
- Modify: `src/bin/myquic2-client/main.rs`（只加 `mod forward_udp;`）
- Test: `src/bin/myquic2-client/tests.rs`

**Interfaces:**
- Produces: `pub(crate) fn spawn_udp_forward(spec: UdpForwardSpec, pool: ConnPool, hub: Arc<UdpHub>, egress: Arc<SharedEgress>, shutdown: watch::Receiver<bool>) -> anyhow::Result<tokio::task::JoinHandle<()>>`；`pub(crate) struct UdpForwarder` 与 `pub(crate) fn handle_datagram(&mut self, src: SocketAddr, payload: &[u8], now: u64)` / `pub(crate) fn sweep_idle(&mut self, now: u64)`（`tests.rs` 同 crate 访问）。
- Consumes: `UdpHub::{alloc_sess,publish,release}`、`AssocEntry::new_raw`、`send_payload_uplink(SessionKind::Forward)`、`drain_assoc_stage`、`send_sess_close`、`recv_burst`/`with_burst_msg`/`try_recv_from`、`assoc_recv_buf`/`assoc_recycle_buf`、`ASSOC_IDLE_TICK_SECS`/`ASSOC_IDLE_MS`、`jitter_ms`、`dgram_drops`。

- [ ] **Step 1: 写失败测试：peer demux + raw 回程 + 上限**

```rust
#[tokio::test]
async fn udp_forward_maps_each_peer_to_its_own_session() {
    // 构造 UdpForwarder（socket 绑 127.0.0.1:0，target = 固定 IP:port）
    // 用 egress 测试桩（同 Task 2 测试的 SharedEgress 发布方式）或真实 quinn 对端
    // handle_datagram(peerA, b"a", now); handle_datagram(peerB, b"b", now);
    // 断言 hub.len() == 2、两个 entry 的 app 分别为 A/B、server 端收到两条 DATA OPEN 且 sess 不同、target 相同。
    // 再注入 downlink（复用 dispatch_r2 + flush_staged），断言 peerA 只收到 A 的 reply，peerB 只收到 B 的 reply，且字节是裸 payload。
}

#[tokio::test]
async fn udp_forward_per_listener_cap_and_global_cap_are_counted() {
    // max_sessions=1 时第二个 peer 被 REFUSED 丢弃；hub 容量用满时 alloc_sess None → SESSION_FULL。
}

#[tokio::test]
async fn udp_forward_idle_sweep_closes_session_and_releases_hub_slot() {
    // 创建 peer 后调用 sweep_idle(last + ASSOC_IDLE_MS + 1)：
    // 断言 hub.entry(sess) == None、hub.len() 归零、entry.is_alive() == false，
    // 且 egress 可用时 server 收到 SESS_CLOSE（不可用时不 panic）。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p myquic2 udp_forward_ -- --nocapture`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `forward_udp.rs`**

按 §6.2/6.3 实现：`UdpForwarder::handle_datagram`（同步、可单测）、`sweep_idle`、`shutdown_all`、`run()`（select：recv head / burst / idle tick / shutdown）。`PeerSession::Drop` 释放 hub 槽位；正常回收先 `send_sess_close` 再 remove。`max_sessions` 检查在 alloc 前；`alloc_sess` None 与本地 cap 分别计数。

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p myquic2 udp_forward_ -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bin/myquic2-client/forward_udp.rs src/bin/myquic2-client/main.rs
git commit -m "feat(client): add UDP forward listener with per-peer sessions over MQP-3 rev2"
```

### Task 6: 主程序接线（启动校验、绑定、日志、shutdown）

**Files:**
- Modify: `src/bin/myquic2-client/main.rs`
- Test: `src/bin/myquic2-client/tests.rs`

**Interfaces:**
- Consumes: Task 1 的 `ClientConf::{tcp_forwards,udp_forwards}`、Task 4/5 的 `spawn_*`。
- Produces: `client_main` 在 SOCKS accept 循环前调用；任一 bind 失败 `bail!`。

- [ ] **Step 1: 写失败测试：绑定失败必须向上返回错误（启动即失败）**

```rust
#[tokio::test]
async fn tcp_forward_bind_conflict_is_a_startup_error() {
    // 先占住 127.0.0.1:port（std TcpListener），再 spawn_tcp_forward(spec.listen = 同址)
    // 断言 Err 且错误文本包含 "bind" / "in use"，而不是 Ok(JoinHandle)。
}

#[tokio::test]
async fn udp_forward_bind_conflict_is_a_startup_error() {
    // 同上，占住 UDP 端口（std UdpSocket）后再 spawn_udp_forward。
    // 两个测试覆盖 Review Focus #2 的 "启动即失败" 一半（另一半是 Task 1 的配置校验）。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p myquic2 forward_bind_conflict -- --nocapture`
Expected: FAIL（`spawn_*` 尚未接线 / 未返回错误）

- [ ] **Step 3: 接线**

在 `client_main` 中、`let listen: SocketAddr = c.socks_listen.parse()` 之前（并把现有的 `let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));` 提前到这里，删除原位置的重复定义）：

```rust
let tcp_fwd = c.tcp_forwards()?;
let udp_fwd = c.udp_forwards()?;
let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
for spec in tcp_fwd {
    if !spec.listen.ip().is_loopback() { warn!(...); }
    info!("tcp_forward {} -> {} via QUIC (bound)", spec.listen, display_target(&spec.target));
    forward::spawn_tcp_forward(spec, pool.clone(), egress_shared.clone(), timeout, shutdown_rx.clone())?;
}
for spec in udp_fwd { /* 同构，udp 传给 forward_udp::spawn_udp_forward */ }
```

`TargetAddr` 需要一个日志显示 helper（`Ip(addr)` / `Domain(host:port)`）；不要为日志实现 `Display` 到 MQP 类型上（避免扩大公共 API），在 client bin 内写 `fn display_target(&TargetAddr) -> String`。

- [ ] **Step 4: 跑绑定冲突测试 + 编译 + 全量测试**

Run: `cargo test -p myquic2 forward_bind_conflict -- --nocapture && cargo test --all-targets`
Expected: PASS（此时 E2E 尚未加）

- [ ] **Step 5: Commit**

```bash
git add src/bin/myquic2-client/main.rs
git commit -m "feat(client): wire forward listeners into startup with validation and shutdown"
```

### Task 7: 进程级 E2E 集成测试

**Files:**
- Create: `tests/forward_e2e.rs`
- Modify: `Cargo.toml`（`[dev-dependencies] tempfile = "3"`）

**Interfaces:**
- Consumes: `env!("CARGO_BIN_EXE_myquic2-server")`、`env!("CARGO_BIN_EXE_myquic2-client")`、`myquic2::gen_self_signed_files`、临时配置。
- Produces: 5 个 E2E 测试（见下）。

- [ ] **Step 1: 写 E2E 骨架（进程管理 + 临时配置 + 端口分配）并先跑 TCP 用例**

```rust
struct Harness { dir: tempfile::TempDir, server: Child, client: Child }
impl Drop for Harness { /* kill + wait 两个子进程 */ }

fn free_tcp_port() -> u16;  // std bind 127.0.0.1:0 → port → drop
fn free_udp_port() -> u16;
fn write_configs(dir, server_port, socks_port) -> (server_toml, client_toml);
fn spawn_bin(path: &str, cfg: &Path) -> Child; // stdout/stderr 重定向到 dir 下文件

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_e2e_roundtrip_half_close_and_parallel() {
    // 1) 起本地 TCP echo server（tokio）
    // 2) 配 [[tcp_forward]] listen=free_port target=echo_addr；server allow_private=true
    // 3) 起 server + client 进程；轮询 connect 监听端口（≤15 s），每次尝试发送 "ping" 等 echo，失败重试
    // 4) 验证：回显正确、app shutdown write 后读到 EOF、32 条并发连接各自正确
}
```

- [ ] **Step 2: 跑 TCP 用例确认通过（这是首个真实链路验证）**

Run: `cargo test --test forward_e2e tcp_forward_e2e -- --nocapture`
Expected: PASS

- [ ] **Step 3: 加 UDP、策略失败与启动失败用例**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn udp_forward_e2e_two_peers_get_their_own_replies() {
    // 本地 UDP echo server（回包格式 "echo:<payload>"）
    // [[udp_forward]] target=echo；两个独立 peer socket 发送不同 token，各自收到自己的 echo，低概率丢包用重试
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_forward_e2e_accepts_large_8k_payload() {
    // 8 KiB payload（协议上限）多次发送并重试，断言完整返回，覆盖 FRAG 路径
}

#[tokio::test(flavor = "multi_thread")]
async fn private_target_fails_fast_without_allow_private_on_server() {
    // server allow_private=false；target=127.0.0.1:echo；TCP 连接建立后必须在下述超时内
    // 收到 RST/EOF 而不是永久挂起（≤25 s 的 dial ACK 超时是上限；实际应在数百 ms 内失败）
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_forward_config_fails_client_startup() {
    // client 配置写 [[tcp_forward]] listen = "127.0.0.1"（缺端口）→ 启动 client 进程：
    // 退出码非 0，且 stderr 日志包含 tcp_forward[0].listen 与 "missing :port"。
    // 覆盖 Review Focus #2 的进程级行为：绝不带病启动。
}
```

- [ ] **Step 4: 跑全部 E2E**

Run: `cargo test --test forward_e2e -- --nocapture`
Expected: PASS（若 env 无法 spawn 二进制则说明原因，不允许 skip 静默通过）

- [ ] **Step 5: Commit**

```bash
git add tests/forward_e2e.rs Cargo.toml Cargo.lock
git commit -m "test(e2e): cover client tcp/udp forward listeners against real binaries"
```

### Task 8: 文档与示例配置

**Files:**
- Modify: `config-client.toml`、`dist/openwrt-x86_64/config-client.toml.sample`、`README.md`

**Interfaces:** 无代码接口。

- [ ] **Step 1: 两份示例配置追加注释块**

内容 = §4.1 示例 + 一句 "私网目标需要服务端 allow_private = true" + 一句 "非 loopback 监听 = 本机可达者均可使用该隧道"。

- [ ] **Step 2: README 增加 "TCP/UDP 转发" 小节**

放在 `## ⚙️ Configuration` 之后：配置样例、语义表（§1.3）、服务端要求（§8）、安全建议（§9）、限制（180 s 回收、全局 4032 上限、单监听器任务）。

- [ ] **Step 3: 更新 README 配置索引行**

`- **TCP/UDP 转发：** tcp_forward / udp_forward（监听地址 + 固定目的地；服务端无改动）`

- [ ] **Step 4: Commit**

```bash
git add config-client.toml dist/openwrt-x86_64/config-client.toml.sample README.md
git commit -m "docs: document client tcp/udp forward listeners and server requirements"
```

### Task 9: 验证与自审

- [ ] **Step 1: 格式化与静态检查**

Run: `cargo fmt --all --check && cargo clippy --all-targets -- -D warnings`
Expected: 无输出/通过

- [ ] **Step 2: 全量测试（含 Linux gated 测试若在 Linux/CI）**

Run: `cargo test --all-targets`
Expected: 全绿；客户端测试数从 149 增加到 ≥160

- [ ] **Step 3: 手工冒烟（可选但建议）**

```bash
# 本地起 server（allow_private=true）+ 两个 echo 服务（TCP:9001, UDP:9002）
# client 配 tcp_forward 127.0.0.1:8080 -> 127.0.0.1:9001
#            udp_forward 127.0.0.1:5353 -> 127.0.0.1:9002
nc 127.0.0.1 8080            # TCP 回显
dig @127.0.0.1 -p 5353 ...   # 或 nc -u 手测 UDP 回显
```

- [ ] **Step 4: 自审 vs Review Focus**

逐条确认 §Review Focus 的 5 个失效模式都有对应测试且通过；确认 `git diff` 中服务端目录为空；确认无新增运行时依赖（`git diff Cargo.toml` 只有 dev-dependencies）。

- [ ] **Step 5: Commit（如还有 fmt/doc 微调）**

```bash
git add -A
git commit -m "chore: final verification for client forward feature"
```

---

## 14. 测试矩阵

| 层 | 覆盖 | 文件 |
|---|---|---|
| 配置单元 | 解析、旧配置兼容、全部非法输入、重复监听、max_sessions clamp | `src/config/client_conf.rs` tests |
| 共享 uplink 回归 | Task 2 前后现有 rev2/egress 测试不变 | `src/bin/myquic2-client/tests.rs`（既有） |
| dispatcher raw | raw 无 SOCKS 头、SOCKS 头字节不变、batch/TRAIN/frag 各 staging 路径 | `tests.rs`（新 2 个 + 既有） |
| TCP relay | header 正确、双向字节、半关闭、无连接失败即关、并发 | `tests.rs`（新 2-3 个，真实 QUIC pair） |
| UDP forward | per-peer session、raw 回程 demux、8 KiB/超长、cap、idle sweep + SESS_CLOSE、shutdown 释放 | `tests.rs`（新 4-5 个） |
| E2E 进程 | server+client 真实二进制：TCP 回显/半关闭/并发、UDP 多 peer、8 KiB、allow_private=false 快速失败、非法配置启动失败 | `tests/forward_e2e.rs` |
| 手工 | netcat/dig 冒烟、`scripts/linux-bench-matrix.sh` 回归（可选） | — |

---

## 15. 验收标准

1. `config-client.toml` 增加 `[[tcp_forward]]` / `[[udp_forward]]` 后，本地 TCP/UDP 客户端可通过 QUIC 访问固定目的地；移除后行为与当前版本一致。
2. TCP：双向任意大小数据、半关闭、并发连接、服务端拒绝时快速失败。
3. UDP：多 peer 各自独立回程、8 KiB 数据报、超长丢弃并计数、180 s 空闲回收且服务端收到 SESS_CLOSE、全局/单监听器上限生效。
4. 服务端代码零改动；`allow_private` 约束写入文档。
5. 全量测试、Clippy、fmt 全绿；无新增运行时依赖；SOCKS 既有测试一条不改。
6. 日志/计数可回答：监听器绑没绑上、丢包属于哪一类、session 有多少、为什么回收。

---

## 16. 备选方案与取舍（为什么不是别的做法）

| 备选 | 结论 | 原因 |
|---|---|---|
| 客户端内部回环到自己的 SOCKS5 端口 | 拒绝 | 每条连接/每个数据报多一次本地中转、多一条控制连接；回程还要重新套 SOCKS 头再剥掉，等于用协议适配层制造 bug |
| 新增 wire frame / 服务端新监听器 | 拒绝 | 服务端现有 TCP header 与 rev2 `DATA OPEN` 已完整表达 "固定目的地"，新增协议只会扩大 wire 兼容面 |
| 用 QUIC stream 封装 UDP（长度前缀） | 拒绝 | 重复 MQP-3 rev2 已经解决的 flow id / stager / FRAG / 回程 demux；且流式语义会给 UDP 引入 HOL |
| 每个 peer 一条专属 relay socket + 专属 task | 拒绝 | 每 peer 一个 fd、一份内核缓冲和一个任务，把 SOCKS 关联模型直接乘以 peer 数；本设计用一个 listener fd + 单任务 peer 表达到同等语义 |
| 一个监听器一个共享 session（peer 混传） | 拒绝 | 回包无法 demux（§2.4） |
| 客户端解析域名后只发 IP | 拒绝 | 破坏 "出口解析 + SSRF 策略" 不变量；服务端 `allow_private` 等策略会失效 |

## 17. 待确认决策（实施前请确认）

1. **配置命名**：`[[tcp_forward]]` / `[[udp_forward]]` 两组数组（本文推荐，简单、可同时监同一端口的不同协议）还是统一 `[[forward]]` + `proto = "tcp"|"udp"`？
2. **UDP 会话语义**：per-peer（源 `IP:port`）独立 session（本文推荐，回程可 demux）——确认接受 "同一监听器不同 peer 在目标侧表现为不同源端口、180 s 空闲回收"。
3. **UDP 每监听器 `max_sessions`**：是否保留该可选字段（默认 = 全局上限）？还是 v1 只依赖 `max_udp_assocs`？
4. **服务端安全边界**：本期不改服务端，仅文档要求 `allow_private` + `auth_token`；是否需要同步把 "仅允许特定 destination" 的服务端 allowlist 提上日程（`ipnet` 已是依赖）？
5. **执行方式**：确认后按 `superpowers:subagent-driven-development`（每任务独立 subagent + reviewer）还是 `superpowers:executing-plans`（本会话内直接实现）执行。
