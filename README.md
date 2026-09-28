<div align="center">

# ⚡ MyQUIC2

**超高性能 · 把 TCP 和 UDP 塞进一条极速的 QUIC 隧道**

SOCKS5 入口 · QUIC / TLS 1.3 出口 · 自研极简协议 MQP-2 · 为极速与低延迟而生

[![Rust](https://img.shields.io/badge/Rust-1.88%2B-dea584?logo=rust&logoColor=white)](#-构建)
[![QUIC](https://img.shields.io/badge/QUIC-TLS%201.3-38bdf8)](#-架构)
[![Performance](https://img.shields.io/badge/Performance-blazing%20fast-f97316)](#-性能设计)
[![Protocol](https://img.shields.io/badge/Protocol-MQP--2-f59e0b)](#-mqp-2-协议)
[![Tests](https://img.shields.io/badge/Tests-159%20passing-16a34a)](#-验证)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20OpenWrt-6366f1)](#-构建)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](#-license)

[✨ 亮点](#-亮点) · [🏗️ 架构](#-架构) · [🚀 快速开始](#-快速开始) · [⚙️ 配置](#-配置) · [📡 协议](#-mqp-2-协议) · [🚀 性能设计](#-性能设计) · [📦 构建](#-构建)

</div>

---

## ✨ 亮点

| | 特性 | 说明 |
|---|---|---|
| 🚀 | **TCP + UDP 全覆盖** | 标准 SOCKS5（`CONNECT` / `UDP ASSOCIATE`），IPv4 / IPv6 / 域名 |
| 🧬 | **MQP-2 精简协议** | TCP 头之后**零额外字节**；UDP 支持分片重组，单载荷最大 8 KiB |
| ⚡ | **极致性能** | 零拷贝手写热路径 + BBR + GSO/GRO；单连接撑满链路，多连接线性扩展 |
| 🔀 | **连接隔离** | 4 条 TCP 连接 + 2 条按业务分类的 UDP 专用连接；UDP 永不与 TCP 抢拥塞窗口 |
| 🛡️ | **安全** | TLS 1.3 + Ed25519 证书固定；可选 `auth_token`（常数时间比较）防止开放代理 |
| 🌐 | **服务端 DNS** | 出口侧解析 + 60 s 正/负缓存 + 单飞合并，跨境访问更准确 |
| ♻️ | **断线自愈** | 服务端崩溃后 ~20 s 自动检测、秒级重拨，UDP 会话自动恢复 |
| 📦 | **OpenWrt 开箱即用** | 静态 musl 二进制（v1–v4 四档 CPU），单文件约 4.4 MB |

---

## 🏗️ 架构

```mermaid
flowchart LR
    APP["🖥️ 应用（curl / 浏览器 / 游戏）"] -->|"SOCKS5 · :1080"| C["🚀 myquic2-client"]
    C -->|"QUIC · TLS 1.3 · MQP-2"| S["🛰️ myquic2-server · :8443"]
    S -->|"TCP / UDP"| NET["🌐 目标网络"]
```

| 单元 | 源 | 职责 |
|---|---|---|
| `myquic2`（库） | `src/lib.rs` | MQP-2 编解码 · 配置 · TLS · 传输 · DNS · 分片重组 · 统计 |
| `myquic2-client` | `src/bin/myquic2-client/` | SOCKS5 入口 → 连接池 → QUIC 出口；含重连、分类 UDP 出口、分发器中继 |
| `myquic2-server` | `src/bin/myquic2-server/` | QUIC 入口 → Token 鉴权 → 目标拨号；含会话表、重组、出口调度 |

**数据面映射**

- **TCP**：1 条 TCP 连接 = 1 条 QUIC 双向流，头之后即裸字节流；SOCKS 成功应答是乐观的（不等远端拨号）。
- **UDP**：1 个 SOCKS 关联 = 1 个会话 ID，走 QUIC DATAGRAM（不可靠、无队头阻塞）；超单帧载荷自动分片，对端重组，**要么完整送达、要么整体丢弃**。

---

## 🚀 快速开始

```sh
# 1️⃣ 启动服务端（首次运行自动生成 Ed25519 自签证书）
./myquic2-server --config config-server.toml

# 2️⃣ 只把 server-cert.pem（证书，勿拷私钥）复制到客户端侧

# 3️⃣ 启动客户端
./myquic2-client --config config-client.toml

# 4️⃣ 使用（浏览器 / 系统代理同理）
curl --socks5 127.0.0.1:1080 https://example.com
```

> 💡 日志级别用 `RUST_LOG` 控制：`RUST_LOG=myquic2_client=debug,myquic2_server=debug`

---

## ⚙️ 配置

<details>
<summary><b>服务端 <code>config-server.toml</code></b> — 点击展开</summary>

<br>

```toml
listen = "[::]:8443"           # QUIC 入口（双栈）
cert_file = "server-cert.pem"  # 自签证书（首次自动生成）
key_file = "server-key.pem"
server_name = "test.com"       # 证书 SAN + 期望的 SNI
congestion = "bbr"             # bbr | cubic
keep_alive_secs = 5            # 1–300，空闲 = max(3×, 15s)
allow_private = false          # 公网出口务必保持 false
auth_token = ""                # 共享密钥；两端一致，留空 = 不鉴权（需防火墙隔离）

# max_connections = 4096       # 连接上限（无 token 时默认 256）
# max_peer_memory_mb = 512     # 对端可占用内存上限
```

</details>

<details>
<summary><b>客户端 <code>config-client.toml</code></b> — 点击展开</summary>

<br>

```toml
socks_listen = "[::]:1080"
server_addr = "127.0.0.1:8443"
server_name = "test.com"              # 必须匹配证书 SAN
server_cert_file = "server-cert.pem"  # 固定服务端证书
congestion = "bbr"
keep_alive_secs = 5
reconnect_timeout_secs = 5
auth_token = ""                       # 与服务端一致
quic_conns = 4                        # TCP 池大小 1–8（UDP 另有专用连接）

# udp_split = true                    # 交互/批量 UDP 分连接（默认开）
# udp_fail_closed = true              # UDP 无可用连接时丢弃而非降级
# interactive_ports = [53, 123, 3478, 3479, 3480, 3481]
```

</details>

| 要点 | 说明 |
|---|---|
| 🔐 `auth_token` | 建议必设；空 token 时服务端是开放中继，只能靠防火墙 |
| 🧵 `quic_conns` | TCP 池大小；DNS/NTP/STUN 等交互端口固定走 0 号槽，UDP 另有 2 条分类连接 |
| 🛡️ `allow_private` | 是否允许回连内网/环回目标（默认 `false`） |

---

## 📡 MQP-2 协议

```text
TCP 打开（流头，仅一次）   atyp | addr | port                            → 响应: "MQ" | 0x00 | 绑定地址
UDP 数据报               0x02 | sess | atyp | addr | port | payload
UDP 分片                 0x05 | sess | id | idx | total | atyp | addr | port | chunk
鉴权                    uni 流（类型 0x02）携带 token（1-RTT 发送，永不进入 0-RTT）
```

- 🎯 地址编码与 SOCKS5 完全一致（IPv4 / IPv6 / 域名），可字节级复用 IP 头。
- 🧩 每个分片自带完整地址 → 乱序可直接重组；丢任一分片则整体丢弃（UDP 语义，不重传）。
- ⏱️ 分片部分过期时间 2 s，单连接重组内存上限 256 KiB（超限先回收复用守卫，绝不动在途载荷）。
- 🔒 token 只在 1-RTT 发送：0-RTT 早期数据可被重放，bearer 密钥绝不进入。

---

## 🔒 安全模型

- **服务端身份**：客户端固定自签 Ed25519 证书指纹（永远开启）。
- **客户端身份**：可选共享密钥 `auth_token`，常数时间比较；未通过前不接受任何流 / 数据报。
- **出口策略**：`allow_private = false` 时过滤内网 / 环回 / CGNAT / 文档等非全局地址（含 NAT64 内嵌 IPv4）。
- **UDP 防伪造**：客户端锁定首个应用 `(ip, port)`；服务端按会话 16 条目的目标主机白名单校验回包来源。

---

## 🚀 性能设计

- **热路径极致精简**：零拷贝 TCP ↔ QUIC 泵、线程本地无锁 memo、每包零分配 —— 代理自身几乎不引入额外开销。
- **现代拥塞控制**：BBR 默认、Cubic 备选，ECN + 自适应 PMTU，配合 GSO/GRO 批量收发，单连接即可撑满链路。
- **为高延迟而生**：默认传输参数按长途跨境链路调优，优先保证低排队延迟。
- **连接级隔离**：TCP、交互 UDP、批量 UDP 各持独立拥塞窗口，互不抢带宽、互不排队。
- **窗口可调**：按链路 BDP 放大两端传输窗口即可继续抬升吞吐；纯 TOML 配置，无需重编译。

---

## 📦 OpenWrt 部署

```sh
scp dist/openwrt-x86_64/myquic2-{server,client}-v1 root@router:/usr/bin/
# 目标机重命名 + chmod +x；配置中一律使用绝对路径
```

| CPU 级别 | 适用 |
|---|---|
| **v1** | 任何 x86-64（N100 / J4125 等，默认推荐） |
| v2 / v3 / v4 | 需 SSE4.2 / AVX2 / AVX512；选错会 `Illegal instruction` |

---

## 🗂️ 项目结构

```text
MyQUIC2/
├── src/
│   ├── lib.rs                 # 薄门面：模块声明 + 公开重导出
│   ├── mqp/                   # MQP-2 编解码（地址 / 数据报 / 分片 / ACK）
│   ├── config/                # TOML 配置与传输参数
│   ├── tls/                   # 证书生成 + 客户端 / 服务端 TLS
│   ├── transport/             # QUIC 传输构建（BBR / GSO / 窗口 / 限制）
│   ├── dns/                   # 分片缓存 · 单飞 · memo · 出口策略
│   ├── time/ · sync/          # 时钟（mono / coarse）· 锁助手
│   ├── stats/                 # 丢包 / 中继计数与限速告警
│   ├── udp/                   # 发送 · 分片器 · 重组器 · 重试池
│   ├── tcp/                   # TCP ↔ QUIC 泵
│   └── bin/
│       ├── myquic2-client/    # pool · egress · hub · dispatcher · socks · assoc · auth · reporter
│       └── myquic2-server/    # accept · auth · table · memo · forward · reader · tcp · pin · reporter
├── examples/                  # zero_rtt_probe · hotpath_bench
└── dist/openwrt-x86_64/       # 静态 musl 产物（v1–v4）+ 示例配置
```

---

## ✅ 验证

- `cargo test --all-targets`：**159 通过 / 0 失败**（`--no-default-features` 下 158 通过）
- `cargo clippy --all-targets -- -D warnings`、`cargo fmt --check`：双特性集全部干净
- 真实二进制 E2E：TCP 1 MiB 字节级校验 ✅ · UDP 8–8000 B 扫频（含分片路径）0 丢包 ✅ · `kill -9` 重启：检测 ~20 s / 重拨 <1 s / TCP+UDP 全绿 ✅

---

## 🛠️ 构建

```sh
cargo build --release          # 本机
cargo test --all-targets       # 测试
```

<details>
<summary><b>交叉编译 OpenWrt 静态 musl（v1–v4）</b> — 点击展开</summary>

<br>

```sh
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild   # 需要 zig 在 PATH

# 一次编译一个 CPU 级别（顺序执行，避免相互覆盖）
for v in x86-64 x86-64-v2 x86-64-v3 x86-64-v4; do
  case $v in x86-64) n=v1;; x86-64-v2) n=v2;; x86-64-v3) n=v3;; x86-64-v4) n=v4;; esac
  cargo zigbuild --release --target x86_64-unknown-linux-musl \
    --config 'profile.release.strip="symbols"' \
    --config "target.x86_64-unknown-linux-musl.rustflags=[\"-C\", \"target-cpu=$v\"]" \
    --bin myquic2-server --bin myquic2-client
  cp target/x86_64-unknown-linux-musl/release/myquic2-server dist/openwrt-x86_64/myquic2-server-$n
  cp target/x86_64-unknown-linux-musl/release/myquic2-client dist/openwrt-x86_64/myquic2-client-$n
  echo "built $n"
done
```

</details>

---

## 📄 License

MIT © MyQUIC2

<div align="center">
<sub>Built with 🦀 Rust</sub>
</div>
