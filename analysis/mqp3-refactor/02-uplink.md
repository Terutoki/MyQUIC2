# 02 · Uplink data path (client → server) deep analysis

> **Scope and baseline**: repository `/Users/eric/WorkSpace/MyQUIC2`, HEAD `d2f9658` / `v0.2.0`. This report is read-only analysis; it **did not modify** `src/`, `Cargo.toml`, configuration, or README, and did not run `cargo build/test`; numerical calculations use `python3` (the model script logic is given in §6.1 and cross-checked against candidate A in this directory's `model.py` / `model-output.txt`).
> **"Uplink" definition**: client → server, including SOCKS5 UDP ASSOCIATE DATAGRAM and SOCKS5 CONNECT TCP stream bytes.
> **External dependencies**: quinn 0.11.12 / quinn-proto 0.11.19 / quinn-udp 0.5.16 (locked by `Cargo.lock`); crate source citations are marked `quinn-0.11.12/src/...`, all obtained read-only from `~/.cargo/registry`.
> **Basis note**: the §5 uplink table of the repository's `PROTOCOL_ANALYSIS.md` (baseline `348c52d`) assumes "client 2-pack, no TRAIN", and **is outdated for HEAD**; `05-evidence.md` already lists that conclusion as "must be treated as outdated". §6 of this report recomputes with the current TRAIN code and separately lists the differences from the old table.

---

## 0. Executive summary

1. **The bulk of the TRAIN/N-pack gain is already realized**: at saturation, a single association's 60 B small-packet uplink is already ~65.6–65.9 B wire/payload, 55.6 `try_send_datagram` calls/1000 payloads (`assoc.rs:704-714,930-1017`). The old analysis's "−10.8%~−20.5% / 9~19× calls" based on 2-pack **does not hold** on HEAD; do not double count.
2. **The remaining protocol-level uplink space is concentrated in three places**: ① inline addresses for domain targets and pure-uplink low-rate flows (requires `FLOW_ACK`/domain ACK to compress); ② `>512 B` payloads still go through MQP-2 (v3 compact FRAG is not wired up); ③ bursts from different associations cannot be coalesced into one frame (the TRAIN header carries `sess u32`, one frame per session). The protocol space for high-bandwidth bulk and TCP ≈ 0.
3. **Quantified upper bound (candidate A: connection-level flow id + control plane + cross-session TRAIN + compact FRAG, IPv4/MTU1200)**: DNS domain single query **−15.5% wire**; pure-uplink 100 B single packet **−5.9%** (IPv6 −12.1%); 32 sessions×60 B **wire −8.0% / send calls −93.8%** (pure uplink −18.0%); 8-target fan-out −3.5%; VPN 1200 B only **−2.0%**; TCP bulk **0%**. **A protocol redesign is not the answer for bulk.**
4. **The largest one-time uplink lever is actually transport configuration and implementation topology, not wire**: raising `initial_mtu` from 1200 to 1400 on known paths (deployment configuration, not the protocol default) cuts VPN 1200 B wire by **−6.1%** and frames from 2→1; the client relay task and the egress driver **live on two runtimes/two sets of cores** (`main.rs:49,210-263,379-388` vs `main.rs:508-582`), with one cross-core state lock + driver wake per frame (`05-evidence.md` §3 F10), model 0.1–0.3 µs/frame ⇒ 40–50k pps about **0.5–1.5% single core**, and it is a source of tail-latency jitter; also, the default topology on a 4-core machine has **oversubscription** of 7 pinned slot threads + main runtime workers (`main.rs:473-488`).
5. **Key correctness/design finding**: the README and the old analysis say "pure-uplink flows are always inline, with the address on every frame" — **this statement is literally no longer accurate**. `open_mask` (`assoc.rs:378-381`) makes only the first item of the same flow within the same TRAIN carry an inline address, and subsequent items are compressed; the real cost of pure uplink is "**one inline open per TRAIN**", and only at low rate (1 packet/burst) does it degrade to an address per frame. This directly changes the gain ranking of `FLOW_ACK` (§4.2, §6.3).
6. **The `thread::spawn per fragment` assumption does not hold**: fragments are sent synchronously one by one inside the association task (`fragmenter.rs:349-380`, `assoc.rs:298-310`); there is no per-fragment thread. The only spawn in the uplink direction is the per-SOCKS-connection task (`main.rs:379-388`).
7. **"Zero-copy TCP" is only half true**: `write_chunk(Bytes)` eliminates the pump-buffer→quinn-queue copy (`tcp/pump.rs:310-322`), but quinn still copies into the packet buffer with `put_slice` during packetization (`quinn-proto-0.11.19/src/connection/streams/state.rs:660-668`), plus one copy each for kernel receive and transmit, so "0 copies" does not exist; the TCP uplink protocol layer has no headroom (§3).

---

## 1. Basis, baseline, and modeling assumptions

### 1.1 Code facts (the premise of every number in this report)

| Fact | Value | Evidence |
|---|---|---|
| QUIC DATAGRAM body budget (`max_datagram_size()`) | MTU 1200 → **1162 B**; MTU 1400 → **1362 B**; MTU 1472 → 1434 B | `transport/build.rs:238-263`, `PROTOCOL_ANALYSIS.md:117-120`, quinn `Datagram::SIZE_BOUND` (body = MTU − predict_1rtt_overhead − 9) |
| Fixed IPv4 overhead per QUIC packet | IP 20 + UDP 8 + QUIC short header (flags 1 + DCID 8 + PN 2 + AEAD tag 16 = 27) = **55 B** | task-provided basis; `PROTOCOL_ANALYSIS.md:117-118`; `src/transport/build.rs:175-198` |
| Extra header per QUIC DATAGRAM frame | type 1 B + varint(len) 1–2 B → **2 B** when body ≤63 B, otherwise **3 B** | `quinn-proto-0.11.19/src/connection/datagrams.rs:204-219` (`datagram.encode`) |
| MQP-3 frame headers | SINGLE = `1+4+[1 flow]+[addr]`; TRAIN = `6 + 1 flow(same-flow)`; item = `1 flags+[1 flow]+varint(len)+[addr]`; FRAG = `11+[1 flow]+[addr]` | `src/mqp/v3.rs:63-66,143-149,261-267,542-567` |
| MQP-2 frame headers | single frame `5`=type+sess; FRAG `11`=type+sess+id+idx+total; address counted separately | `src/mqp/datagram.rs:9-11`, `src/mqp/fragment.rs:29` |
| Address length | IPv4 7 B, IPv6 19 B, domain `4+L` | `src/mqp/addr.rs:162-196` |
| Client default topology | 4 TCP slots + UDP slots (1 interactive + 2 bulk) = **7 connections/endpoint/thread**; each slot has its own current-thread runtime (`MYQUIC2_SHARD_RUNTIME` on by default) | `src/config/tuning.rs:38,69`, `src/bin/myquic2-client/pool.rs:421-449,575-598`, `src/bin/myquic2-client/main.rs:210-263` |
| Runtime hosting the uplink relay task | SOCKS accept / `handle_socks` / UDP association all run on the `#[tokio::main]` multi-threaded runtime; the quinn driver + dispatcher run on the per-slot pinned current-thread runtime | `src/bin/myquic2-client/main.rs:49,379-388`, `main.rs:508-582` |
| quinn cost of each frame send | `send_datagram_wait` takes the connection-state mutex and `wake()`s the driver on every poll; non-blocking poll (`now_or_never`), `Blocked` means drop | `src/udp/send.rs:24-95`, quinn-0.11.12 `connection.rs:476-481,846-888` |
| QUIC GSO | Linux up to 64 segments per `sendmsg`; quinn limits a single transmit to ≤10 segments and each driver poll to ≤20 datagrams | quinn-udp-0.5.16 `unix.rs:820-860`; quinn-0.11.12 `connection.rs:1019-1075,1334,1341` |
| Multiple DATAGRAMs per packet | quinn can fill more than one DATAGRAM frame into the same QUIC packet within one transmit poll (loop within budget) | quinn-proto-0.11.19 `connection/mod.rs:3345-3355` (DATAGRAMs are filled before STREAM) |
| Clock | `coarse_millis` ≈ quanta `recent()` (documented ~4-5 ns; historical microbenchmark 1.44 ns); `mono_millis` ≈ 3.26 ns (historical microbenchmark) | `src/time/coarse.rs:40-53`, `src/time/mono.rs:1-16`, `PERF_ANALYSIS.md:433` |
| Frame allocation | one `Vec::with_capacity(exact)+Bytes::from` per MQP frame (exact-fit fast path); frame pooling has been measured and rejected | `src/mqp/v3.rs:313,571,174`, `examples/frame_bench.rs:19-25`, `05-evidence.md` R1 |

### 1.2 Modeling assumptions (used in §4 and §6)

- IPv4 only, no packet loss, no ACK-only packets, no PMTU jitter; MTU 1200 (budget 1162) is primary, MTU 1400 (1362) is listed separately.
- "wire B/payload" = all on-wire bytes apportioned to that payload (MQP header + that payload + QUIC DATAGRAM frame header + the 55 B apportioned to that packet); one QUIC packet carries one MQP frame, unless that frame is itself an N-item TRAIN (or the specifically noted "packed" coalescing case).
- "send calls/1000 payloads" = number of `try_send_datagram` calls (i.e. MQP frames) ×1000/1000; TCP rows use the number of `write_chunk` calls.
- "Current" follows the **actual behavior** of the HEAD code: ≤512 B goes to v3; within the same drain burst, TRAIN up to the path budget or 64 items; `n=1` forces SINGLE (`assoc.rs:959-971`); pure-uplink flows are compressed within the same TRAIN via `open_mask` (`assoc.rs:378-381`) and re-inline across TRAINs; domain targets use `NO_FLOW` with the address on every item (`assoc.rs:354-366`); >512 B goes through `DgramFragmenter` (MQP-2, `assoc.rs:301-310`, `fragmenter.rs:178-235`).
- "Candidate A" = the connection-level flow-id refactor being evaluated in `01-wire` in this directory: steady-state SINGLE = **2 B header** (kind/flags 1 B + LEB128 flow id 1 B, flow id <128); inline open frame = kind 1 + flow 1 + sess u32 + addr; TRAIN = 2 B header (same-flow simple form item = varint(len)+payload; mixed-flow item adds 1 B flow id); compact FRAG = kind 1 + flow 1 + frag id 2 + packed idx/total 1 = **5 B header**; the control plane includes `FLOW_ACK` (domain targets additionally carry back the resolved IP, for the client to write the SOCKS5 reply header / downlink decompression). This basis is consistent with `analysis/mqp3-refactor/model.py`; this report independently recomputes and fills in the two shapes "low-rate single packet / per-burst packing".

---

## 2. UDP uplink end-to-end map

### 2.1 Code path

```text
app  ──UDP──▶ relay socket (one per association, bind_relay)
             │  assoc.rs:583  recv_from().await  (awaited head, 1 syscall)
             │  assoc.rs:660  recv_burst()       (Linux recvmmsg, ≤32 per call, batch.rs:528)
             ▼
        AppDgramCtx::process()  assoc.rs:176-459   ← synchronous, no await, no allocation (except domains)
             │  SOCKS5 UDP header parse            assoc.rs:236-248
             │  app source IP/port pin + 1 Hz activity stamp  assoc.rs:213-269
             │  event clock coarse_millis()    assoc.rs:226
             │  egress memo / 1 s refresh         assoc.rs:287-444 / egress.rs:139-240
             │  classification (interactive/bulk) + shard binding  pool.rs:642-664
             ▼
        PendingTrain staging (≤512B)            assoc.rs:313-400
             │  flow allocation / confirm bit / open_mask   assoc.rs:345-396, 850-856
             │  payload → pending_buf (memcpy)   assoc.rs:386
             ▼
        flush at end of burst                     assoc.rs:704-714
             │  n==1 → SINGLE; n≥2 → TRAIN      assoc.rs:944-1017
             │  encode_single/encode_train     v3.rs:151-198,285-347
             │  1 exact allocation + 1 memcpy/payload + MQP header
             ▼
        try_send_datagram()                  send.rs:84-95
             │  quinn state mutex + queue push + driver wake   (1 per frame)
             │  Blocked/TooLarge dropped immediately (no fallback queueing)
             ▼
        quinn driver (per-slot current-thread runtime)
             │  1 frame→packet copy, 1 AEAD, GSO packing
             │  sendmsg(syscall) every ≤10 packets
             ▼
        UDP socket → server
```

### 2.2 Per-payload / per-frame cost accounting (current best case: IP flow already confirmed, 60 B, burst→18-item TRAIN)

**Per payload (18-item TRAIN, payload 60 B, IPv4, MTU1200)**

| Resource | Amount | Evidence/notes |
|---|---|---|
| relay receive syscalls | **~0.06 calls** (2 syscalls per 32-packet burst: 1 head `recv_from` + 1 `recvmmsg`) | `assoc.rs:583,660`, `batch.rs:528-546` |
| Kernel→user copy | 1 × 60 B | recvmmsg writes into the thread-local `BURST_SLOT` |
| User-space copies (payload) | **2 × 60 B**: staging `arena→pending_buf` (`assoc.rs:386`) + `pending_buf→MQP frame` (`v3.rs:343`); quinn packetization adds another 1 × 60 B (see per-frame) |  |
| Allocations | 0 heap allocations (`pending_buf` is reused; `PendingTrain` is an inline struct within the assoc future, no heap allocation, but it is rebuilt per frame, see §2.4) | `assoc.rs:578-580` |
| Atomic operations | coarse clock 1 load; `flow_confirmed` 1 relaxed load; egress generation 1 acquire load; stats thread-local cell (cross-thread RMW once per 256 packets) | `assoc.rs:226,368`, `egress.rs:145`, `udp_stats.rs:93-120` |
| Linear scan | `FlowTable::flow_for` 1 comparison (single flow hits slot 0); 8-way fan-out ~4 comparisons on average, 32-way ~16. The uplink has **no hash table**: the egress memo is an array index and flow resolution is a linear scan (only downlink hub/flow lookup has a hash) | `v3.rs:722-728`, `egress.rs:139-165` |
| Task wakeups | 0 (processed synchronously within the same burst); 1 relay task wakeup at burst end is already amortized | `assoc.rs:632-703` |
| Statistics | thread-local counters, no shared writes | `udp_stats.rs:93-120` |

**Per frame (TRAIN of 18 payloads, body 1122 B, wire 1180 B)**

| Resource | Amount | Notes |
|---|---|---|
| Heap allocation | **1** (`Vec::with_capacity(1122)` → `Bytes::from`) | `v3.rs:313-346` |
| quinn connection-state mutex | **1** | `send.rs:84-95`; quinn SendDatagram::poll |
| driver wakeup | 1 (the current topology is a **cross-core wake**, see §5) | same as above |
| MQP header | 6 B TRAIN + 18×2 B item = 42 B | `v3.rs:314-343` |
| QUIC DATAGRAM frame header | 3 B | body >63 |
| packetize copy | 1122 B (frame body → quinn packet buffer) | `datagram.encode` after quinn-proto `mod.rs:3345-3355` |
| AEAD | 1 packet (~1122 B) | aws-lc-rs (`Cargo.toml`) |
| `sendmsg` | 1 (GSO could carry ≤10 packets, but this burst has only 1 packet) | quinn-udp `unix.rs:820-860` |
| On-wire bytes | 1122 + 3 + 55 = **1180 B / 18 payload = 65.6 B/payload** (payload efficiency 91.5%) |  |

> **Conversion**: at steady-state high pps for a single flow, 1000 payloads ≈ **55.6 frames / 55.6 quinn sends / 55.6 `sendmsg` / 62.5 relay receive syscalls**. This is exactly the TRAIN gain HEAD already has.

### 2.3 Cost of the other three uplink shapes

| Shape | Key per-payload cost | Key per-frame cost | Evidence |
|---|---|---|---|
| **Domain target (NO_FLOW inline, 50 B query, L=11)** | extra **1 `String` allocation + free** (`open_addr: addr.into_owned()`, `assoc.rs:393`; `TargetAddrRef::into_owned` is `to_owned()` for Domain, `addr.rs:115-120`); MQP header 21 B (SINGLE) or item 18 B (TRAIN) | 1 allocation + 1 lock + 1 wake, same as a normal frame |  |
| **Pure uplink, low rate (1 packet/burst)** | every payload is 1 SINGLE frame: frame cost is not amortized; for an IP flow the inline open resends the address every time (7/19 B) | 1000 frames/1000 payloads → 1000 allocations+locks+`sendmsg` | `assoc.rs:959-971` |
| **>512 B (MQP-2 path, 1200 B payload, MTU1200)** | 2 fragments: per fragment 1 allocation + 1 encode copy + 1 quinn lock/wake; header 18 B per fragment (FRAG 11 + IPv4 7) | **2 frames/payload**, each frame in its own packet (total wire 1352 B, see §6 table) | `assoc.rs:301-310`, `fragmenter.rs:178-235,349-380`, `fragment.rs:29` |
| **>512 B but fits in one frame (MTU1400/1362 budget)** | MQP-2 single frame 12 B header (`5+7`), 1 allocation/lock/wake | 1 frame/payload | same as above |

### 2.4 Four "paid for nothing" costs at the implementation layer (details in §8)

1. **One `String` allocation per payload for domains**: `assoc.rs:393`; the only exception to a UDP staging path that should be allocation-free (the comment `assoc.rs:794-800` says "Metadata only", which does not match the NO_FLOW path).
2. **`PendingTrain::new` rebuilds 64 `PendingItem`s per frame** (each contains `Option<TargetAddr>`, ~56 B → **~3.5 KiB zero-init + drop of 64 Options** per frame): `assoc.rs:813-821`, `assoc.rs:384`.
3. **Budget pre-check is overly conservative**: `worst_item` unconditionally adds `header.len()` (`assoc.rs:323-332`), over-counting 7/19 B for already-confirmed flows; with a 60 B payload the items per frame drop from 18 to **16** (−11% items/frame, i.e. +12.5% send calls). The actual `encode_train` computes it precisely again, so this only wastes coalescing rate.
4. **`pending_buf` initial capacity is only `BATCH_SMALL_MAX*2 = 1024 B`** (`assoc.rs:578`), which cannot hold a full 1162/1362 B frame; the first full frame triggers one realloc (capacity is retained afterwards).

---

## 3. TCP uplink map

### 3.1 Connection setup and first packet

- After SOCKS CONNECT, `open_bi()`, and write the target address header (7/19/4+L B, max 259 B stack buffer) as an **independent stream write** first and flush it (`socks.rs:204-233`); the purpose is to let protocols in which "the server speaks first" see the header within ~100 ms, while the client returns SOCKS success **without waiting** for the server dial ACK (`socks.rs:234-252`).
- The server's actual dial ACK (MQP-2 `MQ|0x00|atyp|addr|port`, `ack.rs:26-49`) is only consumed in the `s2c` direction (`pump.rs:353-366`, `lib.rs:670-699`); **the uplink byte stream is not ACK-gated** — this is a deliberate design to save 1 RTT.
- Per-TCP-flow protocol overhead on the uplink: **one address header (7–259 B)**, then pure STREAM frames, with no MQP-layer per-payload header. This is the fundamental difference between TCP and UDP: **the TCP uplink protocol-header space is already theoretically optimal**.

### 3.2 Per-chunk cost of the pump (16 KiB reads, `write_chunk` path)

| Resource | Per 16 KiB chunk | Evidence |
|---|---|---|
| TCP read syscall | ~1 (Tokio readiness + `read_buf`) | `pump.rs:288-305` |
| Kernel→user copy | 16 KiB | same as above |
| User-space copies | **1** (quinn packetization `put_slice`); `write_chunk` moves `Bytes` into the quinn send queue, **0 copies at that boundary** | `pump.rs:310-322`; quinn-proto `streams/state.rs:660-668` |
| Allocations | near 0 in steady state: two 16 KiB buffers rotate in the thread pool (`COPY_BUF_POOL_DEPTH=4`), `split_to().freeze()` only produces a `Bytes` handle; no reallocation is needed when ACKs release promptly | `pump.rs:106-147,288-322`; `Cargo.toml` comment |
| quinn state lock + driver wake | **1 per chunk** (cross-core, see §5; `write_chunk` locks every time) | `pump.rs:315` |
| Flow-control wait | awaits only when that stream/connection send window (default 4 MiB, `tuning.rs`) is exhausted; normal bulk upload is cwnd-limited but does not park per chunk | `pump.rs:310-322` |
| Packetization | ~13 packets/16 KiB (MTU1400), each packet 1× 55 B fixed overhead + ~5 B STREAM frame header + AEAD | `PROTOCOL_ANALYSIS.md` basis; quinn-proto STREAM encoding |
| `sendmsg` | ~1.3 per 16 KiB (GSO ≤10 segments per call; driver ≤20 datagrams per poll) | quinn-0.11.12 `connection.rs:1019-1075`; quinn-udp `unix.rs:820-860` |
| ACK | no per-chunk application-layer cost (handled by the driver) |  |

### 3.3 What "zero-copy" really means & uplink protocol headroom

- `write_chunk(Bytes)` only eliminates the **pump buffer → quinn send queue** copy; quinn packetization still copies once; kernel receive and transmit each copy once. So each 16 KiB uplink chunk copies about **3×16 KiB** (kernel receive + quinn packetization + kernel transmit); the `write_all` small-packet path is 4×.
- On-wire overhead per 16 KiB chunk: at MTU1200, 15 packets × 55 B + 15 × ~5 B ≈ **+5.6%**; at MTU1400, 13 packets ≈ **+4.8%**; at MTU1472, 12 packets ≈ **+4.5%**. STREAM frame headers account for ~0.5%, and **the protocol layer can only change a small part of that 0.5%, with gains ≪ 1%**.
- Conclusion: **the TCP uplink has no protocol headroom worth touching the wire for**; the throughput ceiling is determined by cwnd/window/MTU/CPU (the pump task is on the main runtime). The only improvements are transport configuration (`initial_mtu`, the 8/16/8 MB presets) and implementation topology (pump task on the same core as the driver, larger read chunks to reduce lock count), see §8.

---

## 4. MQP-3 uplink gaps (item by item + evidence + impact)

### 4.1 No FLOW_ACK: pure-uplink/low-rate flows cannot enter the compressed state

- Current state: the client only calls `confirm_flow` after **successfully staging a compressed downlink frame for that flow** (`dispatcher.rs:284-288,324-326`, `hub.rs:55-57,139-149`). The server only sends compressed downlink when a mapping already exists in its flow table (`reader.rs:137-154`), and the mapping comes from the uplink inline open (`accept.rs:662-667,712-717,731-757`). A pure-uplink flow never receives this proof.
- **Correcting the old conclusion**: within the same TRAIN, `open_mask` (`assoc.rs:378-381`, `PendingTrain::push` `assoc.rs:823-832`) makes only the first item of the same flow inline; the server processes items in wire order and installs the mapping immediately (`accept.rs:598-601,669-719`, `install_v3_flow` `accept.rs:731-757`), so **"first item opens, subsequent items compress" within one frame is safe** (the same DATAGRAM arrives atomically). Therefore "address on every frame" only holds at **1 payload/burst**; the inline cost of a high-rate same-flow burst is amortized to 7 B/**TRAIN**.
- Impact (IPv4, MTU1200):
  - Low-rate pure uplink 100 B single packet: header 12 B vs compressed 5 B → wire **170→163 (−4.1%)**; IPv6 24→5 B → **182→163 (−10.4%)**.
  - High-rate single-flow 60 B TRAIN (18 items): saves 7 B per TRAIN → **−0.39 B (−0.6%)** per payload.
  - If the session header is also shrunk to 2 B (candidate A): low rate 170→160 (−5.9%); high rate 65.9→64.2 (−2.7%, most of which comes from the 2 B header and the same-flow item saving 1 B/item, not from the ACK).
  - Cost: 1 `FLOW_ACK` per new flow (can be merged into the ACK packet the server has to send anyway; in pure uplink, if there is no ACK to piggyback on, 1 extra small DATAGRAM, ~60 B/flow), and **the ACK can only accelerate compression, never carry correctness**: loss just means continuing inline, it must not blackhole.

### 4.2 Domain targets are always `NO_FLOW` inline and cannot be compressed on the downlink either

- Client: domain targets are fixed at `(MQP3_NO_FLOW, want_open=true)` (`assoc.rs:354-366`), each item carries a `4+L` B address + flow byte (`v3.rs:320-343`), and `open_addr` holds an owned `TargetAddr`.
- Downlink: the domain entry in the client flow table is `TargetAddr::Domain`, which is not a valid SOCKS5 reply source; the dispatcher only accepts `TargetAddr::Ip` for compressed downlink (`dispatcher.rs:255-267,300-308`). The server reader uses `flow_for_ip` to find the flow (`reader.rs:137-154`); a domain mapping never matches, so domain replies are also inline.
- The server actually already installs domain mappings (`accept.rs:745-755`); what is missing is the "resolved IP ↔ flow id" layer.
- Impact: DNS-domain query (L=11, 50 B, 1 packet/burst) currently wire **129 B**, after compression (candidate A 2 B header) **109 B (−15.5%)**; two queries in the same burst (A+AAAA) **100→82 B/payload (−18.0%)**. Note: this is not the old document's "33–38%" — that number uses the "tunnel payload + MQP header" basis; on a full IPv4 wire basis (including the 55 B packet overhead) it is 15.5% (L=11) / 22.7% (L=20, 40 B query) magnitude.
- Design prerequisites (must be solved together): ① the server, after domain resolution/first-packet forwarding succeeds, carries back `(flow, resolved_ip)` in `FLOW_ACK`; ② the client keeps both "uplink target = domain" and "downlink source IP = resolved_ip" for that flow (otherwise subsequent domain payloads cannot find the flow id); ③ when the reply source port changes, still use the existing `S` (src override) inline path; ④ security: the client uses the IP in the ACK only for the SOCKS5 reply header, authorization is still decided by the server reply filter, and SSRF/allowlist semantics are unchanged.

### 4.3 >512 B leaves v3: MQP-2 single-frame/FRAG still on the production path

- Trigger: `payload.len() > BATCH_SMALL_MAX` (512) first flushes the pending TRAIN, then `frag.send` (`assoc.rs:298-310`; constant `mqp/batch.rs:9`).
- The v3 `FRAG` codec exists (`v3.rs:542-671`) but is **not wired up**: both client and server count and drop `MQP3_FRAG` (`dispatcher.rs:330-336`, `accept.rs:720-724`); production uses the MQP-2 `DgramFragmenter` (`fragmenter.rs:178-394`), with header `11+addr` per fragment (IPv4 18 B), reallocating/locking/sending one frame each time.
- Impact: 1200 B payload at MTU1200 → 2 fragments, 18 B header each → wire 1352 B; candidate A compact FRAG (5 B/fragment) → 1325 B (**−2.0%**). At MTU1400, MQP-2 single frame (12 B header) 1270 vs candidate A single frame (2 B header) 1260 (**−0.8%**). **The gain is limited; the value is unifying the path/eliminating the dual protocol surface, not bulk speedup**. Note to keep the 32-bit fragment id (historical u16 packet-loss cliff measurement, `05-evidence.md` R6).

### 4.4 TRAIN is per-session: bursts from different associations are never coalesced

- `encode_train(sess u32, ...)` (`v3.rs:285,314-316`) and one `PendingTrain` per association (`assoc.rs:578-580`) mean **a frame can only belong to one sess**.
- Frames of different sess **can** be coalesced by quinn into the same QUIC packet (`quinn-proto mod.rs:3345-3355`; quinn fills multiple DATAGRAM frames into one packet within the same transmit poll), so the "55 B packet overhead" is already amortized at saturation; but **the per-frame exact allocation + quinn state lock + cross-core driver wake are still paid per frame** (`sendmsg` and packet overhead are amortized per packet, not per frame).
- Impact (32 sessions × 60 B, 1 packet/session/burst, aggregate 50k pps): currently confirmed flow 71.4 B/payload, pure uplink 80.2 B/payload, **send calls 1000/1000 payloads**; cross-session TRAIN (candidate A: 2 B header + 1 B flow id per item) → 65.8 B/payload, **62.5 calls/1000 (−93.8%)**, wire −8.0%/−18.0%, model CPU **−1.2~1.6% single core**. This is the only workload in this report where "the protocol can substantially reduce send calls"; but `05-evidence.md` R8 explicitly warns: **do not refactor for cross-session before profiling proves that the quinn send-state lock/cross-core wake is the main bottleneck** (model gain is on the order of 1–2%, high complexity).

### 4.5 64-flow / 64-item limits, NO_FLOW fallback, ids not reused

- `MQP3_MAX_FLOWS=64`, `MQP3_MAX_TRAIN_ITEMS=64` (`v3.rs:56,60`); the decoder rejects >64 (`v3.rs:449-451`), the encoder rejects empty/>64 (`v3.rs:286-288`).
- flow ids are allocated monotonically and **never resurrected** (`v3.rs:679-690,737-746`); when the table is full it falls back to `NO_FLOW=0xFF` inline (`assoc.rs:367-376`); on the wire 0x40..=0xFE is judged invalid by `valid_flow` (`v3.rs:85-90`), i.e. most of the u8 id space is unusable.
- A long-lived association whose target ports drift/large fan-out exceeds 64 distinct `(ip,port)`/domains will permanently fall into NO_FLOW inline (+7/19 B per payload), and **cannot evict old flows** (no FLOW_CLOSE, and reuse is unsafe under current semantics). This is the practical consequence of the control-plane gap. On the memory side, admission accounts 4 KiB per session (`v3.rs:48-51`, `config/tuning.rs:309-317`); expanding the table requires updating the budget accordingly.

### 4.6 Budget check and Blocked/drop policy

- The budget uses `limit = conn.max_datagram_size()` (live, `assoc.rs:298`); staging uses the conservative `worst_item` (§2.4-3); actual encoding computes precisely in `encode_train` (`v3.rs:289-312`).
- On the quinn side it is a non-blocking single poll (`send.rs:84-95`): `Blocked` = the frame is dropped (QUIC DATAGRAM semantics), **no fallback to a retry queue**; only the downlink reply path has a detached retry (`retry.rs:208-236`). A TRAIN's `Blocked`/`TooLarge` falls back item-by-item into SINGLE/fragment (`assoc.rs:999-1016,893-921`), `ConnectionLost` does not fall back (reports the whole frame as one failure), and each fallback is counted separately.
- Counters and logs are rate-limited (`stats/warn.rs:1-80`, `assoc.rs:402-444`), so a drop storm will not make logging a bottleneck.
- Design judgment: uplink "drop when full" is reasonable UDP semantics; but to reduce such drops, the answer is **reducing frames/sends per payload** (TRAIN/cross-session), not retries.

### 4.7 Other gaps

- **Control plane entirely missing**: `MQP3_CTL=0x40` exists only as a constant and `is_v3` recognition (`v3.rs:25,73`), with no opcode/codec; the dispatcher silently does `_ => {}` for unknown kinds (`dispatcher.rs:337`); the README explicitly says "CTL reserved, no CAPS/HELLO/FLOW_ACK opcode" (`README.md:606-609`).
- **No v3 observation counters**: no statistics for frame types/payload counts/inline fallback rate/train item counts/ACK counts (`stats/udp_stats.rs` has no v3 fields), which means any verification of "compression rate/fallback rate" can only rely on packet captures (`05-evidence.md` §3 already lists this as missing). Counters should be added before any protocol change.
- **No server-initiated flow / no SESS_CLOSE/FLOW_CLOSE**: after a UDP association closes, the server session is reclaimed by the 180 s idle (`server/table.rs` `SESS_IDLE_MS`, see `05-evidence.md` §3); short-session churn holds sockets/tasks/64 KiB kernel buffers; this is not a steady-state wire problem, but affects capacity and tail latency.

---

## 5. Client topology and full-duplex interference

### 5.1 Topology (default: 4 TCP + 1 interactive UDP + 2 bulk UDP = 7 QUIC connections)

| Slot | Connection/task | OS thread/runtime | Notes/evidence |
|---|---|---|---|
| TCP 0 | interactive port (DNS/STUN etc. pin) | per-slot dedicated `current-thread` runtime (`pin_to_core` on Linux, no-op on macOS) | `main.rs:210-263,473-488,508-582`; `linux.rs:184-196` |
| TCP 1–3 | bulk TCP round-robin | same as above | `pool.rs:270-323,712-784` |
| UDP 0 | the **only** connection for the interactive class (all ≤512 B first-packet/interactive-port associations share it) | same as above | `pool.rs:588-598` (`Interactive => 0..1`) |
| UDP 1–2 | the 2 shards of the bulk class (each association binds one) | same as above; bulk transport preset (ACK 8/10 ms, 2 MB DATAGRAM buffer) | `pool.rs:596-597,806-813`; `transport/build.rs:138-163` |
| All SOCKS tasks / UDP association relay / TCP pump | `handle_socks` + bidirectional copy | **`#[tokio::main]` multi-threaded runtime** (default workers = cores, not pinned) | `main.rs:49,379-388`; `assoc.rs:5-10`; `pump.rs:229-575` |
| Per-slot dispatcher (downlink) | `read_datagram` + 4096-entry cache | slot runtime (same thread as the driver) | `dispatcher.rs:725-871` |
| Per-slot conn loop / watchdog | reconnect/silence detection | slot runtime | `auth.rs:46+` |

### 5.2 Where uplink/downlink interfere with each other

| Interference point | Mechanism | Direction/impact | Evidence |
|---|---|---|---|
| **connection-state mutex + cross-core wake** | uplink sends come from main-runtime workers; the driver (receive/ACK/packetization) is on the pinned slot thread. Every `try_send_datagram` locks the same `ConnectionInner.state` and `wake()`s the slot thread; the lock's partner is the driver, which takes the lock on every received packet | both directions: the heavier the downlink, the more the uplink send contends/queues for the lock; an uplink burst in turn slows down downlink ACK/receive latency | `send.rs:24-95`; quinn-0.11.12 `connection.rs:476-481,846-888`; `PERF_ANALYSIS.md` F10 (status: unfixed, `05-evidence.md` §3) |
| **single driver serializes both directions** | each poll first receives/processes, then sends at most 20 datagrams; receive and send share this thread | saturation in one direction delays processing/ACK in the other | quinn-0.11.12 `connection.rs:1019-1075,1334,1341` |
| **DATAGRAM send buffer shared + drop-newest** | 1 MB (interactive)/2 MB (bulk) buffer per connection, shared by all associations; when full, drops the newest packet, with no per-flow fairness | all interactive small-packet flows contend for one buffer/cwnd/driver; one chatty flow or burst can cause other flows to drop | `transport/limits.rs:76-88`; `udp/send.rs:24-95`; `pool.rs:376-398` |
| **cwnd shared** | UDP and TCP already use separate connections (`udp_split`), but within a class it is shared: interactive has only 1 connection; bulk is shared within 2 shards. On the TCP side 3 bulk slots round-robin, but multiple streams in the same slot share one cwnd | multiple flows in the same class squeeze each other; across classes they do not (this is the value of the existing isolation, don't lose it) | `pool.rs:421-449`; `transport/limits.rs:76-82` |
| **main runtime CPU contention** | all relay/encode/copy on the main runtime; slot threads are pinned (Linux), main workers are not; default 7 slot threads + cores-number main workers | 4-core machine: 11 runnable threads for 4 cores; uplink relay and downlink copy contend for CPU, showing as throughput jitter/tail latency | `main.rs:49,210-263,473-488`; `PERF_ANALYSIS.md` F3 (unfixed) |
| **dispatcher on the same thread as driver** | when the downlink is bursting, the dispatcher's `sendmmsg` (≤32 frames/batch) occupies the slot thread and the driver cannot run | the uplink enqueue wake has to wait for that thread; uplink latency jitter | `dispatcher.rs:770-849`; `batch.rs:655-740` |
| **interactive not sharded** | all interactive associations on one connection, one driver core | the small-packet uplink pps ceiling of a multi-core client ≈ single-core driver/AEAD capability; unrelated to wire | `pool.rs:588-598` |
| **no DATAGRAM priority** | quinn 0.11 has no DATAGRAM TX priority; `set_priority` only applies to STREAM (`socks.rs:168-169`); DATAGRAM is populated before STREAM in `populate_packet` | if UDP and TCP share a connection (`udp_split=false` or fail-open fallback), UDP starves TCP streams; the current connection split is the countermeasure | quinn-proto `mod.rs:3345-3355,3406`; `pool.rs:431-439` |

### 5.3 What prevents a connection from being "truly symmetric full-duplex"

1. **The control plane makes flow state unilaterally owned by the client, mirrored downlink**: the client opens flows, the server learns from inline opens; downlink compression depends on that learning result. There is no symmetric primitive for "the server actively opens/confirms a flow".
2. **Pure-uplink flows have no explicit confirmation** (§4.1), so "compress both directions" only holds for flows with downlink replies; the full-duplex compressed state is not a protocol invariant but a side effect.
3. **One TRAIN can only carry one direction, one session**: uplink bursts and downlink replies are always in two frames and two directions, unable to share a frame or ack (except QUIC-layer packet/ACK).
4. **One driver thread per connection + one state lock**: CPU and locks for both directions meet at the same serialization point; this is a quinn architectural constraint and can only be mitigated by more connections/more slots/tasks on the same core, not fixed by wire changes.
5. **No per-flow TX scheduling/priority**: quinn's DATAGRAM is a FIFO shared buffer that drops the newest; the protocol has no priority field the sender could consume.
6. **Client CPU topology**: relay tasks and driver are on different runtimes/cores, so the uplink direction inherently has one more cross-core handoff than downlink (§5.2 first row).

### 5.4 Assumption verification

- **`thread::spawn per fragment`: does not exist.** Fragmentation is sent synchronously fragment by fragment in the `DgramFragmenter::send` loop (`fragmenter.rs:349-380`), called by the association task (`assoc.rs:298-310`). **There is no spawn on the uplink payload path**; the only spawns in the whole client flow are: one task per SOCKS connection (`main.rs:379-388`), the downlink domain-resolution task (`dispatcher.rs:587-604`), and the fixed per-slot conn-loop/dispatcher (`main.rs:563-574,725-871`).
- **runtime subscription**: one `watch` generation channel per slot (`pool.rs:20-54`); a TCP flow holds its connection handle after `wait_conn` until the flow ends and does not participate in that channel; UDP uses `SharedEgress`'s generation + 1 s memo (`egress.rs:139-240`). The impact of reconnect on the uplink: for UDP, the next packet re-acquires (two quinn locks, at most once per 1 s window); TCP flows fail directly (RST); it does not constitute sustained interference.

---

## 6. Uplink headroom quantification

### 6.1 Model (recomputable)

```python
OVH=55; B=1162; B14=1362
dqh(body)=2 if body<=63 else 3            # QUIC DATAGRAM frame header
single(flow,addr,p)=1+4+(flow!=0)+addr+p  # current v3
item(flow,addr,p)=1+(flow!=0)+varint(p)+addr+p
train(items, header=6)=header+sum(item(...))                        # current
A_single(p)=2+p                                                     # candidate A steady state
A_train_simple(n,p)=2+n*(varint(p)+p)                               # same-flow compressed item
A_train_flow(ps)=2+sum(1+varint(p)+p for p in ps)                   # mixed flow, 1 B flow id/item
A_frag(chunks)=sum(5+c for c in chunks)                             # compact FRAG
wire(body)=body+dqh(body)+OVH
```

(Full script logic is consistent with the §6.2 numbers; the candidate A row in `analysis/mqp3-refactor/model.py` cross-checks with this report's candidate A column; the only difference is the handling of "low rate builds an independent packet per packet, TRAIN amortizes by items in frame".)

### 6.2 Main table: uplink headroom (IPv4, no packet loss; MTU1200/budget 1162 unless noted)

| Workload (per-burst shape) | Current wire B/payload | Current send calls/1000 | Target A wire B/payload | Target A calls/1000 | Δwire | Δcalls | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| DNS-over-SOCKS, domain L=11, 50 B, 1 query/burst | **129** | 1000 | **109** | 1000 | **−15.5%** | 0 | gain is 100% from "domain ACK+compression" (16 B address/flow byte + 3 B sess + 1 B DQH); merely switching to a 2 B header without ACK yields 0 |
| same as above, A+AAAA two queries in same burst (TRAIN 2 items) | 100 | 500 | 82 | 500 | **−18.0%** | 0 | per item 18→2 B header |
| gaming/WebRTC 100 B, IP, pure uplink, 1 packet/burst | **170** | 1000 | **160** | 1000 | **−5.9%** | 0 | 7 B inline address × per packet; IPv6 182→160 (−12.1%) |
| gaming/WebRTC 100 B, IP, both directions confirmed | 163 | 1000 | 160 | 1000 | −1.8% | 0 | flow already compressed (5 B→2 B header); the protocol has almost no room |
| gaming/WebRTC 60 B, IP, high-rate single flow (TRAIN 18 items/frame) | **65.9** | 55.6 | **64.2** | 52.6 | **−2.7%** | −5.4% | mostly 2 B frame header + same-flow saving 1 B/item + eliminating first-item inline; **the bulk of the TRAIN gain is already realized** |
| 8-target fan-out, 200 B, pure uplink, 1 packet/flow/burst | **226** | 250 | **218** | 250 | **−3.5%** | 0 | inline 7 B for each flow's first item; if the flow is already confirmed, current 220, target 218 |
| 32 sessions ×60 B/connection, confirmed flow, 1 packet/session/burst | 71.4 (after quinn coalescing) | **1000** | 65.8 | **62.5** | **−8.0%** | **−93.8%** | coalescing is existing quinn behavior; the protocol gain is in frame/item headers and send count |
| same as above, pure uplink flow | 80.2 | 1000 | 65.8 | 62.5 | **−18.0%** | **−93.8%** |  |
| VPN/bulk UDP 1200 B, MTU1200 (budget 1162, 2 fragments) | **1352** | 2000 | **1325** | 2000 | **−2.0%** | 0 | compact FRAG 5 B vs MQP-2 18 B/fragment; frame count unchanged |
| VPN/bulk UDP 1200 B, MTU1400 (budget 1362, 1 frame) | 1270 | 1000 | 1260 | 1000 | −0.8% | 0 |  |
| TCP bulk, 16 KiB chunk, MTU1200 / 1400 | 17299 / 17177 | 1000 | same as left | same as left | **0** | 0 | no protocol headroom; MTU 1400 is transport configuration (−0.7% wire, 15→13 packets) |

> **Basis for the multi-session rows**: the current 71.4 / 80.2 B/payload is the best case where "quinn coalesces 32 DATAGRAM frames from the same transmit poll into 2 QUIC packets" (§1.1 coalescing fact); if the driver polls frame-by-frame (low rate, temporally scattered), current degrades to one packet per frame at 123 / 130 B/payload. Target A's 65.8 assumes the connection-level stager can stably pack 32 items into 2 frames. Therefore the absolute percentage of that row depends on timing and must not be treated as a stable gain.

> **Conservative incremental S (keep sess u32, per-session TRAIN) reference**: DNS single query 129→112 (−13.2%); pure uplink 100 B 170→163 (−4.1%); high-rate 60 B 65.9→65.6 (−0.5%); multi-session 71.4→70.0 (−2.0%, calls of 62.5 require cross-session capability); VPN 1352→1337 (−1.1%). That is, "no connection-level id namespace, only FLOW_ACK + full-size v3 + cross-session TRAIN" also captures most of the wire gain, but the multi-session wire/CPU gain shrinks noticeably.

### 6.3 Gain attribution (avoid attributing implementation gains to the protocol)

| Change | Mainly benefiting workload | wire contribution (single packet 50-60 B magnitude) | send-call/CPU contribution |
|---|---|---|---|
| `FLOW_ACK`/`FLOW_REJECT` (including domain resolved IP) | domain targets, pure-uplink low rate | domain L=11: −20 B/query; pure uplink IPv4: −7 B, IPv6: −19 B | 0 (frame count unchanged; it only makes the compressed state reachable) |
| Steady-state header shrunk to 2 B (connection-level flow id, candidate A) | all low-rate single packets | −3 B/frame (5→2); **without ACK, pure-uplink actually +1 B** (inline open shape 6+addr vs current 5+addr) | 0 |
| Compact FRAG + full-size v3 | VPN/large-packet UDP | −13 B/fragment (IPv4) / −25 B/fragment (IPv6) | 0 (fragment count unchanged) |
| Cross-session TRAIN (connection-level stager) | multi-association small packets | 32×60 B: −5.6~−14.4 B/payload | **−94% send calls (model −1.2~1.6% single core @50k pps)** |
| same-flow TRAIN form / 1 B len per item | same-flow high rate | −1 B/item (one-twentieth magnitude of 60 B) | 0 |
| Control plane SESS_CLOSE/FLOW_CLOSE | short-session churn | 0 | resource reclamation, not throughput |

Key point: **except for "cross-session TRAIN", no protocol change reduces send calls per 1000 payloads**. HEAD's TRAIN has already reduced same-association calls from 1000 to 55.6/1000 (high-pps small packets). So the claim "the protocol can raise the pps ceiling/CPU" only holds for multi-association scenarios, and the magnitude is 1–2% single core, not an order of magnitude.

### 6.4 wire / CPU conversion (per workload rate assumptions)

| Load assumption | Current wire | Target A wire | Savings | Notes |
|---|---:|---:|---:|---|
| DNS domain 20k qps (50 B query) | 2.58 MB/s | 2.18 MB/s | **−0.38 MB/s (−3.1 Mbps)** | protocol only (domain ACK) |
| Gaming pure uplink 50k pps ×100 B | 8.50 MB/s | 8.00 MB/s | −0.50 MB/s (−4 Mbps) | protocol |
| 32 sessions ×60 B, 50k pps aggregate, confirmed | 3.57 MB/s | 3.29 MB/s | −0.28 MB/s | protocol wire + **−46.9k frames/s** |
| same, pure uplink | 4.01 MB/s | 3.29 MB/s | −0.72 MB/s |  |
| 8-target fan-out 20k pps ×200 B | 4.52 MB/s | 4.36 MB/s | −0.16 MB/s | protocol |
| VPN 1200 B, 5k pps | 6.76 MB/s | 6.63 MB/s | −0.13 MB/s | protocol |
| VPN 1200 B, 5k pps, **only `initial_mtu` 1200→1400** | 6.76 MB/s | 6.35 MB/s | **−0.41 MB/s (−6.1%)** | **transport configuration, not protocol**; frames 2→1 |
| TCP bulk 240 Mb/s (30 MB/s), MTU 1200→1400 | 31.7 MB/s | 31.45 MB/s | −0.22 MB/s | transport configuration (−0.7% wire, packet 15→13) |

CPU (model, converted per frames/1000; per-frame cost **250–350 ns**: `Vec+Bytes` allocation 30–80 ns + quinn lock/wake/enqueue 200–300 ns, from this repository's historical estimation basis):

| Scenario | frames/s saved | Model CPU (single core) | Evidence level |
|---|---:|---:|---|
| 32 sessions ×60 B @50k pps (cross-session TRAIN) | 46 875 | **1.2–1.6%** | model; not measured |
| high-pps single flow 60 B @100k pps (TRAIN already implemented) | 0 (candidate A 18→19 items per frame, saves ~0.3k frames/s) | <0.01% | model |
| domain ACK / pure-uplink ACK | 0 (frame count unchanged) | ~0 |  |
| F10 cross-runtime fix (impl, not protocol) | 0.1–0.3 µs per frame (estimate) | **0.5–1.5%@40–50k pps** | model; pending Linux A/B |

### 6.5 headroom conclusion

1. **Sorted by gain/risk: domain ACK (wire 15%+) ≫ pure-uplink/low-rate ACK (5~12% IPv4/IPv6) > cross-session TRAIN (CPU 1–2%, wire 8–18%, high complexity) ≈ MTU deployment configuration (VPN −6.1%) > compact FRAG (−0.8~−2.0%) > steady-state 2 B header (−0.3~−3.3% single packet, depends on payload)**.
2. The wire for high-rate same-flow small packets is already close to the lower bound (65.6 vs candidate A 64.2, 2.7% apart); further protocol changes yield at most 1–2%; **do not build expectations for "100k pps small packets" on the protocol**, its ceiling is in CPU topology (F10/F3) and GSO/driver.
3. For bulk/TCP, the correct action for "optimizing the uplink" is transport configuration (`initial_mtu`, window) + implementation topology; protocol changes give ≤1–2% for them and should not be used as a refactor rationale.

---

## 7. Protocol change recommendations (uplink perspective, sorted by gain/risk)

> Premise: the user allows wire incompatibility, and the name stays MQP-3. Below, "protocol change" and "implementation change" are distinguished; all gains are §6 model values, not measured on Linux; where they conflict with the do-not-repeat list in `05-evidence.md`, that list wins.

### P0 — `FLOW_ACK`/`FLOW_REJECT` (including domain resolved IP): the most worthwhile protocol change for the uplink

- **Content**: `CTL(0x40)` + opcode (`FLOW_ACK|sess|flow|[atyp|addr|port]`, `FLOW_REJECT|sess|flow|reason`); the server sends it after an inline open is accepted (target socket established/sent); for domain targets, after successful resolution and first-packet forwarding, put `resolved_ip` into the ACK; the client `dispatcher` handles CTL: for IP flows call `confirm_flow` (reuse `hub.rs:139-149`), for domain flows additionally record the resolved IP as "the downlink source address alias of that flow" (coexisting with the existing `TargetAddr::Domain`). The ACK must be idempotent, repeatable, and loss-tolerant (continue inline), and can be merged into the ACK packet the server has to send anyway (saving one DATAGRAM).
- **Gain**: DNS-domain single query **−15.5%**, two queries −18.0%; pure-uplink low rate IPv4 **−4.1%**, IPv6 −10.4%; with candidate A's 2 B header −5.9%/−12.1%; high-rate single flow only −0.6% (first-item inline elimination).
- **Risk**: **medium-low**. One new control frame type + server emission point + client state bit; if the ACK is lost/forged: loss only delays compression (safe direction), forgery can only advance compression (requires the client to confirm "the ACK's flow really matches the local table entry"); the server needs no new state for the ACK; the domain alias must be restricted to "used only for the SOCKS5 reply header + downlink decompression, not involved in authorization". `05-evidence.md` R14 requires evaluating control-frame loss/blackhole/state-machine cost — the constraint "always able to fall back to inline" above is the direct answer to that risk.
- **Prerequisite**: add v3 counters (ACK count, compress rate, inline fallback rate), otherwise it cannot be accepted.

### P1 — v3 full-size + compact FRAG wiring (remove MQP-2 from the production path)

- **Content**: cancel the fallback to MQP-2 when `payload > 512 B` (`assoc.rs:301-310`), let v3 SINGLE carry all payloads that fit in one frame, wire v3 compact FRAG (`v3.rs:542-671`) into the reassembler (key changed to `(sess, flow, id)`, keep u32 id and 2 s/256 KiB semantics), the first frame of a large packet still inline open, compressed after confirmation.
- **Gain**: VPN 1200 B MTU1200 **−2.0%** (18→5 B header per fragment), MTU1400 −0.8%; unify the frame path, eliminate the MQP-2 dual decode surface and the flush where TRAIN is interrupted by large packets; lays the foundation for "all payloads can be flow-compressed".
- **Risk**: **medium**. Reassembly key migration, partial cap/eviction, ordering rules for inline first fragment vs compressed subsequent fragments, handling compressed fragments arriving before the first fragment under reordering; the 8 KiB cap can stay unchanged (negotiable caps is a separate topic, not a performance gain).

### P2 — cross-session TRAIN / connection-level stager (conditional, requires prior profiling proof)

- **Content**: new frame kind (or TRAIN multi-session flag): `2 B header + count + item(sess/flow id 1–2 B + len + payload)`; the client needs a per-connection stager (associations hand pending items to a connection-level queue/aggregator), the server demultiplexes per connection. Connection-level flow id (candidate A) can compress the item to 1 B flow id; the conservative option is per-item `sess u16` (item +2 B) but still shares frame header/DQH/send.
- **Gain**: 32 sessions ×60 B: wire **−8.0% (confirmed) / −18.0% (pure uplink)**, send calls **−93.8%**, model CPU **1.2–1.6% single core @50k pps**; pure-uplink packet count 3→2. Other workloads (single association saturated) **≈0**.
- **Risk**: **high**. The connection-level stager introduces cross-task synchronization (lock/queue) and a latency tradeoff for "when to flush" (per-association "flush immediately at burst end" is no longer directly usable, it needs a ≤100 µs-level deadline or "last writer flushes"), per-association ordering must be preserved; the gain is 1–2% single-core magnitude, **if Linux `perf` cannot prove that the quinn send-state lock/cross-core wake is the main bottleneck, do not do it** (same conclusion as `05-evidence.md` R8). Suggest doing the F10 A/B first, then deciding.

### P3 — connection-level flow id namespace / 2 B steady-state header (candidate A, long term)

- **Content**: flow ids allocated from a connection-level namespace (replacing the per-session `sess+flow` 5/6 B steady-state header), the OPEN frame carries `sess u32+addr` to establish the mapping; steady-state SINGLE 2 B, TRAIN 2 B, FRAG 5 B.
- **Gain**: low-rate single/small packets: −3 B/frame (60 B single packet 123→119, **−3.3%** wire; 100 B single packet 163→160, −1.8%; DNS another −2.7% on top of P0); it is the prerequisite for compressing the P2 item to 1 B; TRAIN header 6→2 B (high-rate single flow −0.3%).
- **Risk**: **high**. The server needs a connection-level flow table (memory/DoS/lifecycle/authorization), session lifecycle and flow ownership, id reuse and splice protection; admission's 4 KiB/session accounting model must be recomputed; **and by itself it solves no inline/domain problem** — without P0's ACK, pure-uplink is actually +1 B. Suggest treating it as an overall refactor after P0/P1/P2, not doing it first.

### P4 — control-plane lifecycle (SESS_CLOSE/FLOW_CLOSE/CAPS): non-throughput gains

- **Content**: idempotent control frames, explicit session/flow release; CAPS/HELLO only for canary/rollback (`05-evidence.md` R4: not a performance feature).
- **Gain**: resource reclamation for short-session churn (server socket + task + 64 KiB kernel buffer), flow slot release (mitigating the 64 cap), CANARY/canary capability; **does not change B/payload or steady-state CPU**.
- **Risk**: medium-low (idempotent + loss-tolerant), but must coexist with the 180 s idle fallback.

### Explicitly not recommended (uplink perspective)

- **Priority hints/lane field**: quinn 0.11 does not consume DATAGRAM priority (`pool.rs:431-439` already states that the only isolation is a separate connection); adding a field only adds sender branches, gain 0.
- **Payload compression / HPACK-style dictionary / FEC / NACK on by default / fragment train / u16 fragment id / frame pooling / changing the MTU default into the protocol**: all consistent with `05-evidence.md` §5 do-not-repeat, not expanded further.
- **Rewriting the protocol for bulk throughput**: at 1200 B the frame header is <1%, the wire ceiling is ≤1–2% (§6.2), not worth it.

---

## 8. Implementation-layer fixes (accounted separately, not passed off as protocol gains)

> Everything in this section is a gain obtainable "without changing the wire"; F3/F10 require Linux 2–4 core real measurements — on macOS `pin_to_core` is a no-op, so it cannot be measured on this machine.

| # | Fix | Evidence | Expected gain/risk |
|---|---|---|---|
| I1 | **relay task and egress driver on the same core** (F10): put the association relay / TCP pump on the corresponding slot's runtime (or the reverse: separate the driver's pin policy from the main runtime) | `main.rs:49,210-263,379-388,508-582`; `05-evidence.md` §3 F10 unfixed | model 0.1–0.3 µs/frame → 40–50k pps about 0.5–1.5% single core + tail latency; **first do a `MYQUIC2_SHARD_RUNTIME=0` A/B, do not change blindly** (a single current-thread runtime may become the new bottleneck) |
| I2 | **Thread topology/oversubscription** (F3): default 7 slot threads (Linux pinned) + main runtime workers = cores; 4-core machine 11 threads. At least on small-core machines scale main runtime workers by `slots_total`, or do not pin when `slots_total >= cores` | `main.rs:473-488`; `linux.rs:184-196`; `PERF_ANALYSIS.md` F3 | system-level throughput/jitter; needs Linux 2/4-core benchmarks; at the configuration level can first lower `quic_conns`/`udp_egress_conns` |
| I3 | **Allow sharding for the interactive UDP class** (currently always 1 connection): `udp_class_slots(Interactive)=0..1` hardcoded, `udp_bind` always 0 for Interactive | `pool.rs:588-598,613-635` | the multi-core client small-packet uplink pps ceiling rises approximately from "1 core driver/AEAD" to k cores; but server-side per-connection resources/scheduling also grow, needs joint evaluation; medium risk |
| I4 | **Per-payload `String` allocation for domain NO_FLOW**: `open_addr: addr.into_owned()` | `assoc.rs:393`; `addr.rs:115-120` | at 20k qps 20k alloc/free/s, at 20–40 ns per call about 0.04–0.08% single core + allocator churn; fix: append the address bytes into `pending_buf`/a separate arena and borrow them out with `from_utf8` at flush, or inline short domains (≤23 B) in `PendingItem` |
| I5 | **`PendingTrain` reuse**, avoiding rebuilding 64 `PendingItem`s per frame (~3.5 KiB zero-init + 64 drops) | `assoc.rs:813-821,384` | ~0.1 µs-level per frame (3.5 KiB stores); simple implementation, low risk |
| I6 | **Budget pre-check uses exact item length** (confirmed flows no longer add addr) | `assoc.rs:323-344` | 60 B payload 16→18 items per frame (send calls −11%); low risk (the encoder still validates precisely) |
| I7 | **Add a one-entry memo to `FlowTable::flow_for`** (the server reader already has `last_flow`) | `v3.rs:722-728`; `server/reader.rs:117-144` | fan-out 32: ~16 comparisons per payload → 1; ~50–150 ns/payload, 20k pps about 0.1–0.3% single core; low risk |
| I8 | **Pre-allocate `pending_buf` to the path budget (≥1434)** | `assoc.rs:578` | one realloc per association; very low risk |
| I9 | **Hoist the clock to burst level**: `coarse_millis()` currently once per datagram | `assoc.rs:226` | 1.4–5 ns/payload; low risk (memo/activity stamp only needs burst-level precision) |
| I10 | **Opportunistically merge the TCP first-packet header with the first data segment** (only when application data is already ready; keep a separate flush for "server speaks first" protocols) | `socks.rs:204-233` | saves ~1 packet per TCP flow (~80–130 B); medium risk (if the application waits for the server to speak first, the header must not be delayed) |
| I11 | **Increase TCP read chunks to 32/64 KiB** (reduce quinn `write_chunk` locks per byte) | `pump.rs:66,288-322` | at 240 Mb/s lock count reduced 4×, model <0.1% single core; low risk |
| I12 | **`initial_mtu` deployment configuration**: set 1360/1400 on known paths (WireGuard-1420/Ethernet) (do not change the default) | `config/tuning.rs:160-198`, `config/client_conf.rs:66-80`, `transport/build.rs:238-263`; `05-evidence.md` R5 | VPN 1200 B **−6.1% wire, frames 2→1**; TCP −0.7% wire, packet 15→13/16 KiB; this is the largest single-item non-protocol lever for the uplink |
| I13 | **Add v3 observation counters** (frame type, inline fallback, train items, ACK/compress rate) | `stats/udp_stats.rs` has no v3 fields; `05-evidence.md` §3 | no direct gain, but the acceptance prerequisite for all protocol changes |

---

## 9. Measurement and acceptance plan (aligned with the harness conclusions in `05-evidence.md`)

1. **Measure the baseline first**: Linux 2–4 core target machine (not macOS loopback), `hotpath_bench`'s `udppaced` (1–512 B, controllable pps), `udpps` (collapse point), `udpmulti` (multiple associations, the only one that can expose shared-state contention), `udpdomain`/`udpdomainmulti` (domains), `lat` (with `tc qdisc netem delay 70ms loss 0.5%`), `bulk`/`lattcp` (TCP). A/B within the same round; do not cite README historical loopback numbers (`05-evidence.md` C11/C13).
2. **Measurements that must be added**: wire bytes/send call count (strace -c or temporary counters), `myquic2_udp_send_syscalls`, QUIC DATAGRAM frames/packet (packet capture), CPU/pps, p50/p99, loss distribution; the existing harness only prints user-level pps/loss and cannot verify "fewer frames/less wire" (`05-evidence.md` §4 already points this out).
3. **A/B matrix**: `MYQUIC2_SHARD_RUNTIME=0` vs 1 (F10/F3); `udp_split`/`udp_egress_conns`/`quic_conns` combinations (I3/I2); `initial_mtu` 1200 vs 1400 (I12); `udp_fail_closed` unchanged.
4. **Protocol acceptance**: P0 first does "ACK count + compression rate + inline fallback rate"; P1 does "FRAG path loss/reassembly rate"; P2 does "cross-session stager CPU + p99 latency (the flush deadline must not introduce >1 ms jitter)". Every item must have "current vs changed" same-machine same-round data; model numbers are only directional.

---

## 10. Open questions (for the Lead to decide)

1. **Objective function ordering**: constrained uplink bandwidth (wire), per-core pps/CPU, or tail latency? This report shows the three lead in different directions: DNS/domain → domain ACK; multi-association → cross-session TRAIN/CPU topology; bulk/TCP → transport configuration. If only one thing is allowed, recommend P0 (domain ACK).
2. **Boundary of wire incompatibility**: is a substantial rewrite like "connection-level flow id + control plane" (candidate A) acceptable? If only incremental changes are acceptable, P0+P1 is a safe combination; P2/P3 need separate projects.
3. **Reliability model of `FLOW_ACK`**: is "loss only delays compression" acceptable? If "must confirm" is required then retransmission/state machine is needed, same gain but higher complexity; this report recommends the former.
4. **Security boundary of domain compression**: after the server returns the resolved IP, the client writes it into the SOCKS5 reply header — need to confirm this does not change RFC1928 semantics/application behavior (especially multiple A records, round-robin, TTL changes, DNS rebinding scenarios).
5. **Can the interactive single connection be changed**: why must the interactive class "keep one stable connection" (`pool.rs` comment)? Each association is bound to a class/shard for life anyway, sharding only changes which connection it rides; if the reason is just "simplicity", I3 is a low-risk multi-core scaling point.
6. **P2 prerequisite verification**: is there Linux `perf`/`strace -c` that can prove the quinn send-state lock + cross-core wake is the main uplink bottleneck? If not, do not build a connection-level stager for 1–2% single core (consistent with `05-evidence.md` R8).
7. **Practical impact of the 64-flow cap**: does production traffic contain long-lived associations with >64 targets/ports (port drift, large fan-out)? If so, FLOW_CLOSE/table expansion needs higher priority.
8. **Missing v3 counters**: should I13 be a prerequisite PR for all protocol changes? Otherwise "compression rate/fallback rate" cannot be proven, and one must go back to packet captures.

---

## Summary for the Lead (≤30 lines)

1. Baseline HEAD d2f9658: TRAIN has already reduced same-association small-packet uplink from 1000 calls/1000 payload to 55.6 (60 B/high rate); 60 B is already ~65.6–65.9 B wire/payload — the old analysis "2-pack −10~−20%" is outdated for HEAD, do not double count.
2. The remaining uplink protocol space is only three blocks: inline addresses for domain targets/pure-uplink low rate, >512 B still on MQP-2, cross-association frames cannot be coalesced. bulk/TCP protocol headroom ≈ 0.
3. Gain ordering: ① FLOW_ACK (including domain resolved IP); ② v3 full-size + compact FRAG; ③ cross-session TRAIN (conditional); ④ connection-level flow id (candidate A); ⑤ control-plane lifecycle.
4. FLOW_ACK gains (model, IPv4/MTU1200): DNS-domain single query 129→109 B (−15.5%), two queries −18.0%; pure uplink 100 B 170→160 (−5.9%, IPv6 −12.1%); high-rate single flow only −0.6%.
5. Correcting the old conclusion: `open_mask` makes only the first item of the same flow inline within the same TRAIN; the pure-uplink cost is "one open per TRAIN"; only 1 packet/burst degrades to an address per frame (assoc.rs:378-381,823-832).
6. 32 sessions ×60 B/connection (1 packet/session/burst): current 71.4 B/payload, 1000 calls/1000; candidate A 65.8 B, 62.5 calls (wire −8.0%, CPU model 1.2–1.6% single core @50k pps); pure uplink current 80.2 → −18%.
7. 8-target fan-out 200 B pure uplink 226→218 (−3.5%); VPN 1200 B only 1352→1325 (−2.0% @MTU1200) or 1270→1260 (−0.8% @1400); TCP 0.
8. The largest single item is not the protocol: `initial_mtu` 1200→1400 (deployment configuration) makes VPN 1200 B wire −6.1%, frames 2→1, TCP −0.7%/packet 15→13.
9. Implementation-layer big items: relay task on the main runtime, driver/dispatcher on the pinned slot runtime, per-frame cross-core state lock + wake (F10 unfixed), model 0.1–0.3 µs/frame → 40–50k pps 0.5–1.5% single core + jitter; default 7 slot threads + main workers oversubscribed on a 4-core machine (F3).
10. The interactive UDP class has only 1 connection (pool.rs:588-598), multi-core small-packet uplink pps ceiling ≈ single-core driver/AEAD; whether to allow interactive sharding needs a decision.
11. No FLOW_ACK/CTL/SESS_CLOSE, flow table 64 entries and ids not reused: long-lived multi-target associations permanently fall to inline (+7/19 B per payload) and cannot be mitigated by eviction.
12. Not recommended: priority hint (quinn does not consume), payload compression, FEC/NACK default, fragment train, u16 frag id, frame pooling, changing the MTU default into the protocol, rewriting the protocol for bulk.
13. Suggested landing order: first I13 add v3 counters → P0 FLOW_ACK (largest wire gain, low risk) → P1 compact FRAG/v3 full-size → in parallel do F10/F3/MTU Linux A/B → profiling decides P2/P3.
14. Key risk: FLOW_ACK must "loss only delays compression, never depend on its correctness"; domain ACK requires the server to establish a flow↔resolved IP mapping without changing authorization; cross-session TRAIN requires per-association ordering and flush latency design (≤100 µs level).
15. Open questions: objective function ordering (bandwidth/pps/latency); whether to accept connection-level id rewrite; security confirmation of writing the domain resolved IP into the SOCKS reply; whether interactive can be sharded; whether P2 has Linux profiling support; real traffic profile for >64 flows; whether v3 counters should be a prerequisite PR.
