# MQP-3 wire format and codec deep analysis (task-1)

> Subject: `/Users/eric/WorkSpace/MyQUIC2`, HEAD `d2f9658` / `v0.2.0` (verified with `git log --oneline -1`).
> Method: **read-only code audit + python3 arithmetic modeling**; no modifications to `src/`, no `cargo build/test`, no network measurements.
> Every byte count in the conclusions comes with **frame layout + formula + assumptions**; all percentages in the tables below are MQP-layer bytes, excluding IP/UDP/QUIC overhead (unless noted otherwise).
>
> Evidence grading:
> - **[Code]**: structures/constants obtained by reading the source directly, with `file:line`.
> - **[Doc/existing measurement]**: historical measurements recorded in the repository README / `PROTOCOL_ANALYSIS.md` / code comments, not re-measured this time.
> - **[Model]**: estimates computed with the §7.1 formulas (no packet loss, ideal packing, IPv4 default), used to judge magnitude and direction.
>
> Terminology: uplink = client→server (app→target), downlink = server→client (target→app); `limit` = `quinn::Connection::max_datagram_size()`, i.e. the **budget for one QUIC DATAGRAM body**, `limit = MTU − 38` (README.md:777, `src/mqp/fragment.rs:64` takes 1162 = 1200−38); this document uses two settings: `limit=1162 (MTU 1200)` and `limit=1362 (MTU 1400)`. Address overhead for all domain names is computed as `L=30` bytes (`4+L=34`; the formulas hold for general `L`).
>
> **README line references** below point to the baseline README at `d2f9658`; the README has since been expanded, so its line numbers have shifted. File-level claims are unaffected.

---

## 0. Executive summary (conclusions first)

1. **MQP-3 in the current v0.2.0 only implements flow/TRAIN compression for "same session, IP target, ≤512 B"**. The three biggest structural gaps are:
   domain targets cannot be compressed in either direction (§4-L1), pure-uplink flows are never compressed (§4-L2), and everything >512 B falls back to MQP-2 (§4-L3); on top of that there is **no control plane** (§4-L4) and **v3 FRAG is not wired** (§4-L5).
2. **The largest single byte win is domain-target compression**: the uplink query direction currently has a 40 B header per frame (60 B payload + 30 B domain means 40% of MQP bytes); with FLOW_ACK it can drop to a 5→2 B header, **from 97,564 B to about 61,300 B per 1000 payloads (−37%)**; the downlink reply direction currently uses `NO_FLOW`+inline IP (v4 13 B / v6 25 B header), which after ACK also compresses to 5→2 B, **v4 −13%, v6 −26%**. [Model]
3. Pure-uplink IP flows (no replies received, cannot be implicitly confirmed) currently have 12/13 B headers per frame; after FLOW_ACK 5→2 B: **sparse unidirectional flows −9.7%~−13.9%; high-rate unidirectional flows about −2% because the address is repeated only once per TRAIN**. [Model]
4. Payloads >512 B and fragmentation unified into v3 frames: **large-packet header 12/24 B → 5/6 B (A)/2/3 B (B), fragment header 18/30 B → 11 (A)/8 (B) B per fragment**; 1200 B @MTU1200 with 2 fragments wire −1.1%~−1.6%, IPv6 2 fragments −3.0%~−3.5%, 8192 B 8 fragments −0.7%~−1.0%. **bulk throughput does not change because of this** (the MQP header is <1% of a 1200 B packet, §8.3).
5. **Cross-session packing** (merging small packets from multiple SOCKS associations on the same QUIC connection into one TRAIN) can reduce quinn send calls per round by 4× (8 sessions×4 items) to 16× (32 sessions×1 item), saving 2%~4.3% on the wire; the value is in CPU/locks, not bandwidth. [Model]
6. **Recommended direction: candidate B — connection-level flow-id namespace + symmetric bidirectional ownership + full CTL plane** (§6.2). It uses a 2~3 B steady-state header (removing the per-frame `sess u32`), an 8 B fragment header, cross-session TRAIN, FLOW_ACK for domain/unidirectional flows, and compression of server-initiated flows (full-cone); candidate A (the incremental option that keeps `sess u32`, §6.1) can land first as a low-risk subset; candidate C (u16 sess compromise, §6.3) is **not recommended** because of the id-reuse safety cost.
7. **Naming constraint**: still called **MQP-3** throughout; it is suggested that the CTL HELLO/CAPS carry a wire-version byte (example in this document `ver=2`), and ALPN remains `myquic2/3` or gets an additional suffix — the redesign only changes MQP-3's wire version and introduces no new protocol codename (§6.2/§9-Q2).
8. **No measurements were done**: every percentage in this document must be understood as a model value; the A/B before and after landing must be re-measured on a Linux target machine with `examples/hotpath_bench.rs` + real app workloads (§9-Q8).

---

## 1. Background and scope of this document

MyQUIC2 is a SOCKS5-over-QUIC proxy: TCP goes over QUIC stream, UDP goes over QUIC DATAGRAM, and MQP-3 is the custom frame format of the UDP data plane (README.md:145, README.md:590-745). Data-plane topology ([Code]):

- Each client UDP association (SOCKS5 UDP ASSOCIATE, cap 4032, `src/config/tuning.rs:116`) extracts the payload from the app's `RSV|FRAG|ATYP|ADDR|PORT|payload` in `assoc.rs`, picks an egress QUIC connection (4 TCP connections + 1 interactive UDP + 2 bulk UDP shards, `src/config/tuning.rs:38,69`) and sends a DATAGRAM; the same QUIC connection is **shared by multiple associations**.
- On the server, each UDP session has one relay socket + one reader task (`src/bin/myquic2-server/reader.rs:729`); `sess` is allocated by the client (`src/bin/myquic2-client/hub.rs:326-353`, monotonic u32, 0 reserved), and the server session table is **one per QUIC connection** (`src/bin/myquic2-server/accept.rs:797`, `SessTable` indexed by `sess`, `src/bin/myquic2-server/table.rs:58-64,91-97`).
- The flow table is **one per session**: `FlowTable [Option<Arc<TargetAddr>>; 64] + next` (`src/mqp/v3.rs:683-792`), allocated by the client on uplink and installed on the server by mirroring from the inline open (`src/bin/myquic2-server/accept.rs:731-770`); downlink uses the same table to map "reply source address" back to a flow id (`src/bin/myquic2-server/reader.rs:128-171`).

Scope of this document: **only wire frames / codec / frame-level state semantics**. Code-level issues of CPU hotspots, scheduling, and connection topology are covered in `PERF_ANALYSIS.md` and other team reports and are not repeated here.

---

## 2. Current wire specification (frame by frame, byte exact)

### 2.1 Frame type summary table

| First byte (high 4 bits = kind, low 4 bits = flags) | Name | v0.2.0 production status | Evidence |
|---|---|---|---|
| `0x10` | `SINGLE` | Production, both directions; only ≤512 B goes here | `src/mqp/v3.rs:22,29-34`; `src/bin/myquic2-client/assoc.rs:301`; `src/bin/myquic2-server/reader.rs:629` |
| `0x20` | `TRAIN` | Production, both directions, mixed flow/destination | `src/mqp/v3.rs:23,37-42` |
| `0x30` | `FRAG` | **codec written, not wired** (production uses MQP-2 `0x05`) | `src/mqp/v3.rs:24,66,542-671`; `src/bin/myquic2-client/dispatcher.rs:330-335`; `src/bin/myquic2-server/accept.rs:720-724` |
| `0x40` | `CTL` | **constant only**, no opcode/codec at all | `src/mqp/v3.rs:25`; README.md:610 |
| `0x02` | MQP-2 `DATAGRAM` | Production: fallback for ≤512 B + single frame for >512 B | `src/mqp/datagram.rs:7,11`; `src/bin/myquic2-client/assoc.rs:882`; `src/bin/myquic2-server/reader.rs:199` |
| `0x05` | MQP-2 `FRAGMENT` | Production: payloads > limit (each fragment repeats the full address) | `src/mqp/fragment.rs:14,29,178-183`; `src/udp/fragmenter.rs:349-380` |
| `0x06` | MQP-2 `BATCH` | Both ends still decode (compatibility/tests), **production no longer sends** | `src/bin/myquic2-server/accept.rs:1041`; `src/bin/myquic2-client/dispatcher.rs:347`; sender is `#[cfg(test)]` only: `src/bin/myquic2-client/assoc.rs:1166-1167` |

> Key fact 1: `is_v3` only recognizes `0x10/0x20/0x30/0x40` as v3 (`src/mqp/v3.rs:70-75`). Other kind values (`0x50..`) are decoded as v2 and `REFUSED` (`src/bin/myquic2-server/accept.rs:1041-1127`; the client's `sess_of` in `src/bin/myquic2-client/dispatcher.rs:786` is also `None`) — **the kind space cannot be extended forward**.
> Key fact 2: after a `CTL 0x40` frame enters the v3 branch, the inner `match`'s `_ => {}` silently drops it (server `src/bin/myquic2-server/accept.rs:725`; client `src/bin/myquic2-client/dispatcher.rs:341`), **without counting and without error**; and because `v3_sess` requires the first 5 B (`src/mqp/v3.rs:78-83`), CTL frames shorter than 5 B are counted as `REFUSED`. Adding a control plane in the future must change this drop rule.

### 2.2 Common address encoding (isomorphic to SOCKS5)

`atyp u8 | addr | port u16 BE`: `0x01`=IPv4 (1+4+2=7 B), `0x04`=IPv6 (1+16+2=19 B), `0x03`=domain (1+len+host+2=4+L B, L∈1..=255). unspecified/v6 with scope_id is not allowed (`src/mqp/addr.rs:122-160,165-196`). Decoding is a zero-allocation borrowed form (`TargetAddrRef`, `src/mqp/addr.rs:198-245`).

### 2.3 `SINGLE` (0x10)

```text
0x10|flags(1) | sess u32 LE(4) | [flow u8, if flags.F] | [addr, if flags.I] | payload… (to the end of the DATAGRAM)
flags: I=0x1 inline address, F=0x2 flow byte present, S=0x4 inline addr is the actual source (overrides the flow binding)
```
[Code] `src/mqp/v3.rs:151-245`; golden bytes in `src/mqp/v3.rs:814-844`.

- header = `1 + 4 + [1 if flow≠0] + [addr_len if I]`. **flow 0 is implicit**, steady state 5 B; extra flow 6 B; open first frame IPv4 12/13 B, IPv6 24/25 B, domain 40 B (NO_FLOW=0xFF is non-zero, so the flow byte must be present).
- **No length field**: the payload runs to the end of the DATAGRAM, so one DATAGRAM body can hold only one SINGLE.
- Codec: [Code] encoding does one `header()` validation/length measurement + one exact `Vec::with_capacity` + one payload memcpy + `Bytes::from(Vec)` (`len==capacity` takes the in-place adopt path, no second allocation, `src/mqp/v3.rs:151-198`). Decoding is zero-allocation, slicing only (`src/mqp/v3.rs:200-245`).

### 2.4 `TRAIN` (0x20)

```text
0x20|flags(1) | sess u32 LE(4) | count u8(1)
  [flow u8, if flags.SAME_FLOW && flow≠0]
  item*: iflg u8(1) | [flow u8, if iflg.F] | len varint(1–2) | [addr, if iflg.I] | payload(len)
flags: bit0 = SAME_FLOW (all items share the same non-zero flow; flow appears only in the header)
iflg: F=0x1 flow byte, I=0x2 inline addr, S=0x4 src override (item flags and frame flags have different bit meanings)
```
[Code] `src/mqp/v3.rs:260-347` (encode), `437-515` (decode); golden in `src/mqp/v3.rs:907-945`.

- header = 6 B (mixed) or 7 B (SAME_FLOW with flow≠0); `count` 1..=64 (`src/mqp/v3.rs:60,286-287,449-451`).
- Each item has a fixed 1 B `iflg` + 1–2 B LEB128 length; extra flow +1 B. **flow 0 item ≈ 2 B/item** (28/60 B payload), 128–16383 B payload ≈ 3 B/item.
- **SAME_FLOW cannot be used for flow 0**: the encoder writes the header flow byte only when `items[0].flow != 0` (`src/mqp/v3.rs:296-309,317-319`), while the decoder reads 1 B of flow as soon as it sees SAME_FLOW (`452-463`), so setting the flag for flow 0 misaligns the frame; a test pins this behavior (`src/mqp/v3.rs:947-968`).
  **But there is no byte loss**: the mixed form for flow 0 = `6 + n·(1+len)`, whereas a "legalized SAME_FLOW+flow0" needs 1 extra B in the header with items unchanged = `7 + n·(1+len)`, which is 1 B larger; the mixed form for flow 0 is already the minimal encoding (§4-L9 will stress this again).
- Encoding: [Code] validates the whole frame once first (each item's `header()` length measurement, `src/mqp/v3.rs:285-309`), then one exact `Vec` fill (`313-346`); call sites collect `TrainItem`s in a fixed on-stack array (64×~40 B, `src/bin/myquic2-client/assoc.rs:972-998`; `src/bin/myquic2-server/reader.rs:243-267`).
- Decoding: [Code] validates the whole frame first (to prevent malicious frames from panicking, `src/mqp/v3.rs:464-505`), then the iterator parses it again (`391-433`) — **every item is decoded twice** (the `TargetAddrRef::decode` for inline addresses also runs twice); the CPU constant is very small (§4-L16).
- One DATAGRAM body holds only one TRAIN; a TRAIN does not span drain bursts (the client flushes at burst end, `src/bin/myquic2-client/assoc.rs:566-572,704-714`; the server flushes at burst end/large packet/before exit, `src/bin/myquic2-server/reader.rs:640-680`).
- **run-of-1 does not send TRAIN**: `n==1` sends SINGLE directly (client `src/bin/myquic2-client/assoc.rs:959-970`; server `src/bin/myquic2-server/reader.rs:293-301`).

### 2.5 v3 `FRAG` (0x30, not wired)

```text
0x30|flags(1) | sess u32 LE(4) | [flow u8, if F] | id u32 LE(4) | idx u8 | total u8 | [addr, if I] | chunk…
```
[Code] `src/mqp/v3.rs:66,542-671`; prefix = 11 B (flow 0)/12 B (extra flow), plus another 7/19/4+L when an inline addr is present. There is no production caller (grep `encode_fragment_v3|decode_fragment_v3` only hits `src/mqp/v3.rs`; `dispatcher.rs:330-335` and `accept.rs:720-724` `REFUSED` it on receipt). So **this format is currently pure dead weight**.

### 2.6 MQP-2 frames (the production path for >512 B and fragmentation)

| Frame | Layout | Fixed header (v4 / v6 / domain L) | Code |
|---|---|---|---|
| `0x02` DATAGRAM | `0x02 \| sess u32 \| addr \| payload` | 12 / 24 / 9+L | `src/mqp/datagram.rs:7,11,73-108` |
| `0x05` FRAGMENT | `0x05 \| sess u32 \| id u32 \| idx u8 \| total u8 \| addr \| chunk` | 18 / 30 / 15+L (**every fragment repeats the full address**) | `src/mqp/fragment.rs:14,29,178-183,219-261` |
| `0x06` BATCH | `0x06 \| sess u32 \| addr \| count u8 \| (len u16 LE \| payload)*` | 13 / 25 / 10+L + 2/item | `src/mqp/batch.rs:5-9,20-79` |

- Fragment parameters: `MQP_FRAG_MAX_PAYLOAD=8192`, `MQP_FRAG_MAX_TOTAL=64`, `FRAG_TIMEOUT=2 s`, per-connection `FRAG_MAX_HELD_BYTES=256 KiB`, `FRAG_MAX_PARTIALS=256` (`src/mqp/fragment.rs:47,55,107,116,165,176`); reassembly key = `(sess u32, id u32)` (`src/udp/reassembler.rs:392`).
- Sender `DgramFragmenter::send` (`src/udp/fragmenter.rs:178-394`): first takes the `DgramPrefixCache` N=1 fast path (caches `type|sess|addr`, `src/mqp/datagram.rs:147-217`), and fragments only if it does not fit; **the fragment id is u32**, and after wrap there is a 3 s reuse-safe window (`FRAG_ID_SAFE_WINDOW_MS`, `src/mqp/fragment.rs:145`). Each fragment costs one frame allocation + one memcpy; each fragment is one `quinn send_datagram` (connection state lock).
- Decoding: all borrowed, zero-allocation (`src/mqp/datagram.rs:225-232`; `src/mqp/fragment.rs:263-279`; `src/mqp/batch.rs:158-198`); when entering the reassembler the chunk is **malloc+memcpy**'d once (intentional memory accounting, `src/udp/reassembler.rs:203-289`).

### 2.7 Production path matrix (who uses which frame and when)

| Direction | Payload condition | Current frame | Evidence |
|---|---|---|---|
| uplink | ≤512 B, packable | `TRAIN` (multiple flows/destinations) | `src/bin/myquic2-client/assoc.rs:298-401` |
| uplink | ≤512 B, run=1 | `SINGLE` | `src/bin/myquic2-client/assoc.rs:959-970` |
| uplink | >512 B | MQP-2 `0x02` (if it fits) or `0x05` fragments | `src/bin/myquic2-client/assoc.rs:301-310,882` |
| uplink | any size, TRAIN/SINGLE rejected by quinn (Blocked/TooLarge) | MQP-2 `0x02`/`0x05` fallback | `src/bin/myquic2-client/assoc.rs:882,996-1016` |
| downlink | ≤512 B, packable | `TRAIN` (mixed sources) | `src/bin/myquic2-server/reader.rs:626-680` |
| downlink | ≤512 B, run=1 | `SINGLE` | `src/bin/myquic2-server/reader.rs:176-206,293-301` |
| downlink | >512 B | MQP-2 `0x02`/`0x05` | `src/bin/myquic2-server/reader.rs:675-677` |
| downlink | any-size fallback | MQP-2 `0x02`/`0x05` | `src/bin/myquic2-server/reader.rs:199` |

**Why is 512 B the boundary?** It is not a wire limit, but reuse of the old BATCH constant `BATCH_SMALL_MAX=512` (`src/mqp/batch.rs:9`) as the staging cap: the client goes to v2 directly when `payload.len() > BATCH_SMALL_MAX` (`src/bin/myquic2-client/assoc.rs:301`), and the server likewise only enters v3 staging when `n <= BATCH_SMALL_MAX` (`src/bin/myquic2-server/reader.rs:629`). v3 SINGLE itself can carry any payload ≤ limit−header (`src/mqp/v3.rs:143-174`); there is no wire-level reason in the code for 513 B to fall back to v2.

---

## 3. Current per-payload header overhead matrix

> Symbols: `p`=payload bytes; `L`=domain length; `H`=MQP header bytes per payload; `share=H/(H+p)`.
> Assumptions: no packet loss; TRAIN scenarios assume 32 payloads per flush burst (`LAST_HOP_DRAIN=32`, `src/udp/batch.rs:46`); `limit=1162`; `L=30`.

### 3.1 Single frame (standalone, `SINGLE`/`0x02`): header and share

| Scenario | H | p=28 | p=60 | p=200 | p=512 | Notes |
|---|---:|---:|---:|---:|---:|---|
| IPv4 flow0 steady | 5 | 15.2% | 7.7% | 2.4% | 1.0% | v3; actual production shape |
| IPv4 extra flow steady | 6 | 17.6% | 9.1% | 2.9% | 1.2% | +flow byte |
| IPv6 flow0 steady | 5 | 15.2% | 7.7% | 2.4% | 1.0% | address not on the wire |
| IPv6 extra flow steady | 6 | 17.6% | 9.1% | 2.9% | 1.2% | |
| domain address (**uplink**, always inline) | 40 | 58.8% | 40.0% | 16.7% | 7.2% | `NO_FLOW=0xFF`, 10+L |
| **reply for** domain target (downlink, inline IPv4) | 13 | 31.7% | 17.8% | 6.1% | 2.5% | `NO_FLOW`+IP, 1+4+1+7 |
| **reply for** domain target (downlink, inline IPv6) | 25 | 47.2% | 29.4% | 11.1% | 4.7% | 1+4+1+19 |
| IPv4 flow0 first/open | 12 | 30.0% | 16.7% | 5.7% | 2.3% | with 7 B address |
| IPv4 extra flow first | 13 | 31.7% | 17.8% | 6.1% | 2.5% | |
| IPv6 flow0 first | 24 | 46.2% | 28.6% | 10.7% | 4.5% | with 19 B address |
| IPv6 extra flow first | 25 | 47.2% | 29.4% | 11.1% | 4.7% | |
| domain first (=always) | 40 | 58.8% | 40.0% | 16.7% | 7.2% | |

> Note: the "first" shape for flow 0 only appears in the open frame. **In production, how long the "first" shape persists is determined by "whether a compressed downlink has been received"** (`src/bin/myquic2-client/hub.rs:45-59,139-149`; `src/bin/myquic2-client/assoc.rs:345-377`); pure-uplink flows are always in the first shape.

### 3.2 TRAIN per-item overhead (including header amortization)

Current per item = `1 B iflg + [1 B flow if extra flow] + (1–2 B) len`; header 6 B (mixed)/7 B (SAME_FLOW non-zero). `flow0` is implicit.

| Scenario | Per-item overhead (p<128 / p≥128) | Notes |
|---|---:|---|
| IPv4 flow0 steady | 2 / 3 | most common (small-packet flow to the same destination) |
| IPv4 extra flow steady (mixed) | 3 / 4 | |
| IPv4 extra flow steady (SAME_FLOW) | 2 / 3 + header 7 | whole frame same flow |
| IPv4 flow0 first/open | 9 / 10 | the open address is repeated only once per flow per frame (subsequent items in the same frame are compressed, `already_open` bitmap, `src/bin/myquic2-client/assoc.rs:378-396`) |
| IPv4 extra first/open | 10 / 11 | |
| IPv6 flow0 first/open | 21 / 22 | |
| IPv6 extra first/open | 22 / 23 | |
| domain (always inline) | 37 / 38 | `1+1+len+34` = 37/38 |

Amortized to each payload: `overhead = H_train/n + item`. Taking flow0 and 60 B as an example:

| n (items per TRAIN) | 2 | 4 | 8 | 16 | 18 |
|---|---:|---:|---:|---:|---:|
| Current (header 6 + 2 B/item) | 5.00 | 3.50 | 2.75 | 2.38 | 2.33 |

### 3.3 v2 overhead for >512 B (per payload / per fragment)

`limit=1162` (MTU 1200): v4 single-frame cap=1150 B, fragment chunk=1144 B; v6 single-frame cap=1138 B, chunk=1132 B; domain L=30 single-frame cap=1123 B, chunk=1117 B.

| payload p | v4 header/fragments | v6 header/fragments | domain header/fragments |
|---|---:|---:|---:|
| 513 | 12 / 1 frame | 24 / 1 | 39 / 1 |
| 1000 | 12 / 1 | 24 / 1 | 39 / 1 |
| 1200 | **36 / 2** (18 B×2) | **60 / 2** (30×2) | **90 / 2** |
| 1420 | 36 / 2 | 60 / 2 | 90 / 2 |
| 8192 | 144 / 8 | 240 / 8 | 360 / 8 |

`limit=1362` (MTU 1400): v4 single-frame cap=1350 B, fragment chunk=1344; v6 cap=1338, chunk=1332; domain cap=1323, chunk=1317.

| payload p | v4 header/fragments | v6 header/fragments | domain header/fragments |
|---|---:|---:|---:|
| 1200 | 12 / 1 | 24 / 1 | 39 / 1 |
| 1420 | 36 / 2 | 60 / 2 | 90 / 2 |
| 8192 | 126 / 7 | 210 / 7 | 315 / 7 |

> That is: **with the default MTU of 1200, a 1200 B payload necessarily becomes 2 fragments, each repeating a 7/19/34 B address**; raising `initial_mtu` to 1400 turns 1200 B into a single frame (README.md:777 already has this suggestion). The only thing the protocol layer can do is compress the "18/30 B header per fragment" to 8–12 B.

---

## 4. Complete list of existing wire inefficiencies / limitations (with evidence and quantification)

> P0 = protocol structure problems that block the "optimize both uplink and downlink / full duplex / evolvable" goals; P1 = actual byte/CPU overhead; P2 = dead code/consistency/attack surface.

### P0

**L1 Domain targets cannot be flow-compressed in either direction.** [Code]
- Uplink: the client hardcodes `(MQP3_NO_FLOW, true)` for `TargetAddrRef::Domain`, inline in every frame (`src/bin/myquic2-client/assoc.rs:355-377`); it does not allocate a flow slot.
- Downlink: the server compresses only the **IP** flow hit by `flow_for_ip(src)` (`src/bin/myquic2-server/reader.rs:134-152`), while `FlowTable::flow_for` compares the whole `TargetAddr` and a Domain entry never matches an IP (`src/mqp/v3.rs:722-733`) → domain replies are always `NO_FLOW` inline; the comment at `reader.rs:100-107` confirms "the client does not know the resolved IP of a domain target".
- Cost:
  - Uplink: **37–40 B header per frame** (L=30); for a 60 B DNS query the MQP bytes are 100 B and the header accounts for 40%; per 1000 payloads 97,564 B → with FLOW_ACK ≈61,300 B (**−37%**).
  - Downlink: replies are `NO_FLOW`+**inline IP** (v4 13 B / v6 25 B header; not 40 B, because the server returns the resolved IP), and likewise cannot be compressed; after ACK it drops to 2–5 B, per 1000 payloads v4 70,378→61,189 (**−13%**), v6 82,564→61,189 (**−26%**). [Model]

**L2 Pure-uplink flows are never compressed.** [Code]
- The only source of "confirmation" is the client successfully staging a **compressed downlink frame** for that flow (`src/bin/myquic2-client/dispatcher.rs:283-289,318-326` → `AssocEntry::confirm_flow`, `src/bin/myquic2-client/hub.rs:139-149`); there is no FLOW_ACK.
- Pure uplink (logs/telemetry/unidirectional game input/DNS with no response) always stays inline: SINGLE 12/13 B, TRAIN repeats a 7/19/34 B address once per flow per frame.
- Cost: a sparse unidirectional flow at 60 B is 72 B/payload (v4) → with ACK 65 B (A)/62 B (B), **−9.7% / −13.9%**; a high-rate unidirectional flow (32 payloads/burst, address repeated only once per TRAIN) about −2%. [Model]

**L3 >512 B and all fragmentation fall back to MQP-2, with the address repeated in every fragment.** [Code]
- Path: `src/bin/myquic2-client/assoc.rs:301-310`, `src/bin/myquic2-server/reader.rs:629-677`, `src/bin/myquic2-client/assoc.rs:882`, `src/bin/myquic2-server/reader.rs:199`.
- Cost: 513–1150 B single-frame header 12/24 B (v4/v6) instead of 5/6 (A) or 2/3 (B); 1200 B @1162 is 36/60 B over 2 frames instead of 22/16 B; 8192 B is 144/240 B instead of 88/64 B.
- Extra: every v2 fragment repeats `sess u32`, and the reassembler keys on `(sess,id)` rather than `(sess,flow,id)` (`src/udp/reassembler.rs:392`), so even wiring v3 FRAG requires changing the reassembler first (README.md:664-670 already points this out).

**L4 There is no control plane at all.** [Code]
- `MQP3_CTL=0x40` is only a constant (`src/mqp/v3.rs:25`); the whole repository has no opcode/encode/decode; README.md:610 explicitly says "reserved; no CAPS/HELLO/FLOW_ACK opcodes implemented".
- Consequences of the gap:
  1. No HELLO/CAPS → no capability negotiation, no in-band version gate (the default ALPN is still the `h3` disguise, `src/mqp/ack.rs:1-22`; `normalize_alpn` returns h3 by default); the only signals are TLS failure or silent packet drops.
  2. No FLOW_ACK/REJECT → L1/L2; when the server rejects due to table full/SSRF, the client has no way to know and can only stay inline forever.
  3. No SESS_CLOSE/FLOW_CLOSE → sessions can only be reclaimed by 180 s idle (`src/bin/myquic2-server/table.rs:382`; 60 s sweep, `accept.rs:799-812`), so the server socket/reader task lives at least 0–180 s longer; flow ids can also only be discarded with the whole session because of "never reuse" (`src/mqp/v3.rs:675-690`).
  4. Cannot negotiate `max_flows`/`max_train_items`/`max_reassembly`/new features — a new format can only be upgraded wholesale.

**L5 v3 FRAG is implemented but not wired.** [Code] `src/mqp/v3.rs:542-671` has no production caller; both ends directly `REFUSED` and count `0x30` (`src/bin/myquic2-client/dispatcher.rs:330-335`; `src/bin/myquic2-server/accept.rs:720-724`). On the current wire it is a dead format that "occupies a kind and never appears".

### P1 (bytes / per-frame overhead)

**L6 4 B `sess u32` per frame.** [Code] Every v3 frame carries it: SINGLE/TRAIN/FRAG header (`src/mqp/v3.rs:63,186,313-315,583`). It is 80% of the 5 B steady-state header. Removing these 4 B (→ candidate B's 2 B header) equals 9.1% of the MQP bytes for a 28 B payload and 4.6% for 60 B; switching only to u16 (saving 2 B) gives 6.1%/3.1%.
- Note: **simply shrinking to u16 is not free**, see the reuse-safety analysis of candidate C (§6.3).

**L7 One session per frame; TRAIN cannot merge frames across sessions.** [Code]
- The frame header has only one `sess` (`src/mqp/v3.rs:63`); the client stages/flushes separately per association task (`src/bin/myquic2-client/assoc.rs:566-580,704-714,1027-1074`), and the server flushes separately per `sess_reader_task` (`src/bin/myquic2-server/reader.rs:729-900`). Small packets from multiple associations on the same QUIC connection **can only become separate frames**.
- Cost ([Model]): for one round of 32 sessions each with 1 60 B payload, currently 32 frames/2080 B → after merging 2 frames/2020 B (wire −2.9%, **send calls 16×**); 8 sessions×4 payloads/round: 8 frames → 2 frames (**4×**), wire −2.1%. The value is mainly CPU/locks, not bandwidth (§7.3).

**L8 TRAIN 2–4 B per item.** [Code] `1 B iflg + [1 B flow] + 1–2 B len` (`src/mqp/v3.rs:260-267,320-343`). Even when the entire frame is the same flow with no inline/open, each item is forced to carry 1 B of flags — that byte is pure redundancy in the "all-compressed same flow" case. Candidate A's COMPACT item saves 1 B/item (60 B small packets: ~1,000 B per 1000 payloads, −1.6%; 28 B: −3.3%). [Model]

**L9 "SAME_FLOW cannot be used for flow 0" is an expressiveness gap, not a byte loss.** [Code+derivation] See §2.4: flow 0 mixed = `6+2n`; forcing SAME_FLOW+flow0 = `7+2n`, which is larger. What can really be saved is L8's per-item flags byte. It is listed under "limitations" because: a flag bit is wasted, the decoder has one more unreachable branch, and the "compact item mode" must be redefined to cover both flow 0 and non-zero.

**L10 64 flows/session + monotonic no-reuse.** [Code] `MQP3_MAX_FLOWS=64` (`src/mqp/v3.rs:53-56`); `insert` is monotonic and returns None once `next>=64` (`737-746`); `remove` only clears when an "inline open conflicts with an existing id" and does **not** lower `next` (`770-791`; test `1047-1061` pins the no-reuse behavior); once the table is full the client stays inline forever for **new destinations** (`src/bin/myquic2-client/assoc.rs:367-377`).
- Cost: long-lived high-churn associations (games repeatedly changing rooms, DNS polling many resolvers) permanently degrade to a 12/13 B header after the 65th destination (+7/8 B/frame for small packets); and `MQP3_FLOW_TABLE_MAX_BYTES=4096` serves as per-session admission accounting (`src/mqp/v3.rs:48-51`; `src/config/tuning.rs:309-317`), which cannot be solved simply by "making the table bigger"; it needs a control plane + lifecycle.

**L11 The 512 B staging cap is code policy, not a wire limit.** [Code] It reuses `BATCH_SMALL_MAX` (`src/mqp/batch.rs:9`; client `src/bin/myquic2-client/assoc.rs:301`; server `src/bin/myquic2-server/reader.rs:629`; the staging buffer is preallocated as `BATCH_SMALL_MAX*2`, `assoc.rs:578`). It directly causes L3: as soon as "large payloads go over v3 SINGLE/FRAG" is wired up, the v2 data plane can be deleted (at the cost of the scheduler having to distinguish "small items that can enter a TRAIN" from "large items sent separately").

**L12 Flow table stored per session + 4 KiB/session accounting.** [Code] `AssocEntry.flows: ArcSwap<FlowTable>` (`src/bin/myquic2-client/hub.rs:57-59`); server per `SessEntry.flows` (`src/bin/myquic2-server/table.rs:51-56`); 4096 B charged per session (`src/mqp/v3.rs:51`, `src/config/tuning.rs:316`). If changed to a connection-level flow table, this accounting must become a "per-connection cap" and enter `per_connection_memory_bytes` (currently only contains `FRAG_MAX_HELD_BYTES`, `src/config/tuning.rs:282-287`).

**L13 `idx u8/total u8` and the 8 KiB reassembly cap: not the current bottleneck.** [Code] `MQP_FRAG_MAX_TOTAL=64` already covers the UDP max at QUIC's minimum MTU: `ceil(65507/(1162−11−19))=58 ≤ 64` (`src/mqp/fragment.rs:57-75` has a compile-time assertion). The real limit is `MQP_FRAG_MAX_PAYLOAD=8192` (`src/mqp/fragment.rs:31-47`, the loss-amplification argument) — it blocks UDP payloads >8 KiB (NFS/large EDNS0 etc.), but widening `total` is unnecessary; if a larger reassembly cap is negotiated through CAPS in the future, 64 fragments × ~1132 B still ≥ the 64 KiB UDP max, so u8 can stay.

### P2 (dead code / consistency / attack surface)

**L14 Silent drop rules for CTL/unknown kinds.** [Code] See §2.1 key fact 2: CTL is silently dropped (`accept.rs:725`, `dispatcher.rs:341`), CTL <5 B is counted as `REFUSED` (`v3_sess` condition, `src/mqp/v3.rs:78-83`), and unknown kinds `0x50+` are dropped as v2. The new format must change to "unknown kind/opcode → counted drop + no panic + no misparse", and give CTL an entry point independent of the `v3_sess` minimum length.

**L15 The `SRC` flag is a dead feature.** [Code] The codec is fully implemented (`src/mqp/v3.rs:32-34,38-39,229-234`), but **all production call sites pass `src_override` as `false`** (`src/bin/myquic2-client/assoc.rs:975,992`; `src/bin/myquic2-server/reader.rs:248,259`; only tests ever discuss non-false semantics). The current handling of a reply from a target on a different port is `NO_FLOW` inline full source address (`src/bin/myquic2-server/reader.rs:134-152`), and it does not use `S`. The new format should either use it (compressing replies "same flow but source port changed") or delete it.

**L16 TRAIN is decoded twice.** [Code] First `decode_train` validates the whole frame (`src/mqp/v3.rs:464-505`), then `TrainItems` re-parses it (`394-428`), so the inline address decode runs twice. The CPU constant is small (tens of ns per item); it is not a wire problem, but a new format design could share a single scan between validation and parsing.

**L17 Old MQP-2 data plane dead code/dual implementation.** [Code] `0x06 BATCH` is still decoded on both ends (`accept.rs:1041`; `dispatcher.rs:347`) but production no longer sends it (the client send function is `#[cfg(test)]`, `assoc.rs:1151-1167`); `0x02/0x05` still have two encoders, a prefix cache, and a reassembler (`src/mqp/datagram.rs`, `fragment.rs`, `src/udp/fragmenter.rs`, `reassembler.rs`). If the new protocol no longer needs v0.2.0 compatibility, `0x02/0x05/0x06` decoding should be deleted as well, reducing attack surface and code forking.

### Extra identity/security surface (not a byte problem, but it determines whether the new format can land safely)

**L18 Trust boundary of session/flow ids.** [Code]
- `sess` is allocated by the client process (`hub.rs:326-353`, 0 reserved; the server rejects `s==0`, `src/bin/myquic2-server/reader.rs:956-960`), and the session table is **independent per connection** (`accept.rs:797`) → no collision surface across clients; within one connection it is a single trust domain (the client process itself).
- Failed id resolution on a flow-compressed frame only drops that frame and counts `REFUSED` (`accept.rs:640-666,700-719`; `dispatcher.rs:246-289,291-326`); **it never guesses routing**; when an inline open conflicts with an existing id the server deletes the old binding rather than overwriting (`accept.rs:731-770`) → fail-closed. These invariants must be preserved and strengthened in the new format (once connection-level ids can be reused, the consequence of misrouting escalates from "packet loss in this session" to "another association receives the wrong packet").

---

## 5. Design space analysis (incompatible redesign, still called MQP-3)

### 5.1 Two addressing models

| | **Model S: session-scoped (current/candidates A/C)** | **Model K: connection-scoped (candidate B)** |
|---|---|---|
| Data frame address | `sess u32` (per frame) + `flow u8` (optional) | only `flow id` (connection-level); session appears only in open/CTL |
| flow table | 64 entries per session, freed when the session is destroyed | N entries per connection; entry = `(sess, target, dir/owner)` |
| Hot-path lookup | sess table/FastSess first, then in-session array index | one connection-level id table lookup; sess only for open and delivery |
| Cross-session TRAIN | not possible (frame header has a single sess) | naturally possible (items carry only flow id) |
| Memory/accounting | 4 KiB/session (`v3.rs:51`) | needs a new per-connection cap (suggest 4096 entries×~40 B≈160 KiB, configurable) |
| Full-duplex symmetry | downlink depends on the uplink's flow table (mirror) | both directions can open independently; the server can initiate flows |
| Implementation change | small: change codec + control plane | large: connection-level table + per-connection TX staging + lifecycle/DoS |

> Conclusion: **to simultaneously satisfy "optimize both uplink and downlink + true full duplex + cross-session packing", Model K (connection-scoped) is the only self-consistent model**. Model S can achieve most of the byte gains of L1/L2/L3, but cannot do L7 (cross-session) or "server-initiated flows".

### 5.2 flow/session id encoding candidates

| Option | Steady-state per-frame id cost | id space | Reuse safety | Assessment |
|---|---|---|---|---|
| Current: `sess u32 + flow u8` | 4 B (+1 optional) | u32×u8 | no reuse within a session | too expensive; see L6 |
| `sess u16 + flow u8` | 2 B (+1) | 65535×64 | **dangerous**: after 65,536 allocations a u16 wrap collides with an old session still alive within 180 s (§6.3) | not recommended unless paired with reliable SESS_CLOSE/ACK |
| `sess u24` | 3 B | 16.7M | wrap needs 93k/s to reuse within 180 s, practically safe | saves only 1 B vs u32, neither here nor there |
| connection-level `u16` varint | 1 B (id≤127)/2 B (≤16383)/3 B | 65,535/connection | monotonic allocation + 3 s reuse window (same idea as `FRAG_ID_SAFE_WINDOW_MS`) + guard after close | **recommended**; 32k live flows is enough for 1024–4032 sessions/connection |
| connection-level `u32` | 4 B (or varint 3–5 B) | 4.29e9 | practically never reused, safest | meaningless in bytes |
| 12/20-bit bitfield | on the order of 1.5 B | 4096/1M | medium | gain <1 B, complex decoding, not recommended |
| "short id" nibble mode (optional) | **1 B** (reserve a slot in the kind's high 4 bits + low 4 bits short id) | 16 hot flows/direction | coexists with the u16 main space | saves another 1 B only in sparse small-packet scenarios (1.6% at 60 B); can be an optional extension of B (§6.2-B′) |

### 5.3 Direction and ownership: three candidates

1. **Shared bidirectional id (client authoritative)**: current semantics. The client allocates, the server mirrors; downlink replies reuse the client's flow id (`reader.rs:128-171` already behaves this way). Pros: zero extra downlink opens, simple protocol; cons: the server **cannot initiate flows** (full-cone/port-changed replies can only be inline forever), and downlink depends entirely on whether the uplink open arrived.
2. **per-direction sender-owned (each side manages its own direction)**: each side allocates ids for its own send targets, and the receiving side looks up its own table by "arrival direction". Truly symmetric, the server can initiate flows; the cost is that the same logical flow may have two ids (unless a mirror optimization is done), and the first downlink packet needs one inline open.
3. **Single namespace + ownership half (recommended compromise)**: one connection-level table, the low half of ids belongs to the client and the high half to the server (using 1 flag bit to express the high half so the varint stays 1–2 B); both sides can open; the same logical flow has only 1 entry, and mirroring/server-initiated flows are just "who opens first". **Candidate B uses this one.**

### 5.4 session and flow mapping / lifecycle

- `session` = one SOCKS UDP association (client) / one relay socket (server). **It only carries the routing of "which app socket / which target to deliver to"**.
- `flow` = `(session, target)`; connection-level id; the creator (client or server) writes `session u32 + addr` in the open frame; the receiving side validates and then installs `flow → (session, target, owner, state)`.
- Session creation keeps the current "implicit creation": the first open that references it creates it (the server still performs SSRF/private-address validation before installing, on the `forward_server_dgram` path); close uses CTL `SESS_CLOSE` (idempotent, resendable), with 180 s idle still as the fallback.
- Flow close uses `FLOW_CLOSE`; a `flow id` may be reused only after `now − close ≥ 2×FRAG window` (the same splice argument as fragment id, `src/mqp/fragment.rs:118-145`), otherwise fall back to inline; id space exhaustion also falls back to inline (not packet loss).

### 5.5 Control plane requirements list

| opcode | Direction | Necessity | Content (suggested) | Purpose |
|---|---|---|---|---|
| `HELLO` | C→S | required | magic `M3`, wire-ver u8, flags u8/u16 | in-band version assertion; missing/mismatched version → connection-level fail-closed |
| `CAPS` | S→C | required | ver, feature bits, max_conn_flows, max_flow_per_session, max_reassembly, max_train_items | capability negotiation/limits; cross-version canary |
| `FLOW_ACK` | S→C (both sides in the symmetric bidirectional version) | required | `sess u32 + flow id + status + [resolved addr]` | ① confirm compression for pure-uplink flows; ② return the resolved IP for a domain open (the client uses it to write the SOCKS5 reply header); ③ reply REJECT on table full/SSRF reject (same frame or separate opcode) |
| `FLOW_REJECT` | S→C | required | sess, flow, reason | the client stays inline forever for this flow |
| `FLOW_CLOSE` | both directions | optional (recommended) | sess, flow | quickly release table entries and reassembly partials |
| `SESS_CLOSE` | C→S | recommended | sess, reason | immediately release the relay socket/reader task instead of waiting 180 s |
| ACK piggyback (bit) | both directions | optional | 1 bit in frame flags + 1 flow id | when there is reverse traffic, use "the frame coming back" to confirm the open, avoiding an extra CTL frame |

Control frames are all **unreliable, idempotent** frames over DATAGRAM; losing one at most delays compression/release slightly and never affects correctness. `HELLO/CAPS` is suggested to be sent 2–3 times after connection establishment (or until CAPS is received), but **must not block data**: the data frame format is determined by the version, and the two must be deployed with the same version (README.md:723-737 already states matched deployment).

### 5.6 Security / memory boundaries

| Risk | Current state | New format requirement |
|---|---|---|
| Compressed frame points to a non-existent flow | drop the frame + count (`accept.rs:640-666`; `dispatcher.rs:246-289`) | keep; never allocate unknown ids |
| A delayed frame misdelivered to **another session** after id reuse | current ids are not reused → does not exist | **key new risk**: connection-level ids must be "not reused, or reused only after ≥2×FRAG window and the old session is closed", and a tombstone must be kept (otherwise it is cross-app misdelivery, worse than packet loss) |
| inline open conflict (same id, different address) | server deletes the old binding (fail-closed, `accept.rs:731-770`) | keep fail-closed, and **must not** overwrite across owner halves/sessions |
| open flood (one resolve/SSRF/socket per open) | session table has fair-share (1024–4096/connection, `table.rs:416-421`), global 8192 (`table.rs:374`), idle reclamation | connection-level flow table needs double caps per-conn/per-session + per-second open rate limit; over limit reply `FLOW_REJECT`, no allocation |
| Forgery/replay | inside TLS 1.3, QUIC DATAGRAM cannot be replayed | no per-frame MAC needed; do not use DATAGRAM for 0-RTT sensitive paths (current auth token is 1-RTT only, README.md:737) |
| Memory | 4 KiB flow accounting per session + 256 KiB/connection reassembly (`src/config/tuning.rs:282-287,309-317`) | connection-level table (suggest default 4096 entries, `~40 B/entry`≈160 KiB/connection) counted in `per_connection_memory_bytes`; reassembly cap unchanged |

### 5.7 Decoder DoS limits (suggested for the new format, all validated before parsing)

1. Frame length ≤ `conn.max_datagram_size()`; truncation means drop, no panic.
2. `DATA`: flow id varint ≤3 B and value within the negotiated range; `OPEN`'s `sess` non-zero, addr validated via `TargetAddrRef::decode` (unspecified/scope rejected, `src/mqp/addr.rs:122-160`).
3. `TRAIN`: `count ∈ 1..=max_train_items(=64)`; flow dictionary `nfl ≤ count` with distinct ids; each item len ≤ `min(8192, bytes remaining in the frame)`; **must consume exactly to the end of the frame** (current behavior, `src/mqp/v3.rs:506-508`).
4. `FRAG`: `1 ≤ total ≤ 64`, `idx < total`, chunk non-empty and ≤ bytes remaining in the frame; total partials per `(flow,id)` ≤8 KiB, per connection `held ≤256 KiB`, partials ≤256 (reusing the current constants, `src/mqp/fragment.rs:165,176`).
5. Unknown kind / CTL opcode / reserved flag bits → **counted drop** (not silent, not panic); new kinds must not fall into v2 parsing.
6. flow installation: insert only after validation passes (session exists or can be created, target passes SSRF/policy, connection/session caps not full); otherwise `FLOW_REJECT`.
7. CTL frames have fixed/bounded length; HELLO magic/ver mismatch → close with a connection-level error code (no partial parsing).

---

## 6. Candidate wire formats (3)

> Common conventions: one QUIC DATAGRAM body still carries **exactly one** MQP frame (same as current, `encode_single` has no len field; TRAIN does the packing); the first byte's high 4 bits = kind, low 4 bits = flags. **The protocol name is MQP-3 throughout**; `wire-ver` in CAPS is only MQP-3's internal wire version number (example =2), and candidates A/B/C are only analysis labels in this document.
> All `flow id`s below are **connection-level** (candidate B) or **in-session u8** (candidates A/C); the id values in the examples follow the corresponding assumption; `sess u32` stays u32 in open/CTL (opens are infrequent, avoiding any reuse risk).

### 6.1 Candidate A — session-scoped incremental (low-risk subset)

**Goal**: keep the existing frame syntax, add the control plane, wire v3 FRAG and large packets into production, add domain/pure-uplink compression and compact TRAIN; do not introduce a connection-level table.

**Frame table**

| Frame | Layout (A) | Steady-state header | open header | Change vs current |
|---|---|---:|---:|---|
| `SINGLE 0x10` | `0x10\|flags \| sess u32 \| [flow u8] \| [addr] \| payload` | 5 / 6 | 12/13/24/25/40 | unchanged; **used for all payloads ≤limit−header** (no more 512 truncation) |
| `TRAIN 0x20` | `0x20\|flags \| sess u32 \| count u8 \| [flow u8 if SAME_FLOW≠0] \| item*`; new flag `COMPACT=0x2`: when all items are compressed, omit iflg — for a whole frame of the same flow (or all flow 0) item = `len varint \| payload`, for mixed flows item = `flow u8 \| len varint \| payload` | header 6/7, item 1–2 | item 9/10/21/22/37 | COMPACT saves 1 B/item for "same flow" items and keeps 2 B/item for mixed-flow items |
| `FRAG 0x30` | `0x30\|flags \| sess u32 \| [flow u8] \| id u32 \| idx u8 \| total u8 \| [addr on open] \| chunk` | **11 / 12** | 18/30/46 (first fragment) | wire it up; steady state has no address |
| `CTL 0x40` | `0x41 HELLO`, `0x42 CAPS`, `0x43 FLOW_ACK(sess u32+flow u8+status+[resolved addr])`, `0x44 FLOW_REJECT`, `0x45 FLOW_CLOSE`, `0x46 SESS_CLOSE` | — | — | new |

**Key behavior**
- Domain targets: the client allocates a flow for the domain (no longer forcing NO_FLOW), with the open frame inline domain; after the server resolves and passes SSRF it installs `flow→(domain, resolved_ip)` and replies `FLOW_ACK(resolved_ip)`; afterwards uplink uses flow compression, and downlink replies coming from that resolved_ip use **the same flow id** for compression (the client uses the IP in the ACK to write the SOCKS5 reply header).
- Pure-uplink IP flows: the server replies `FLOW_ACK` (no addr) after the open installs successfully, and the client switches to compression immediately.
- Large packets/fragments: all go through `SINGLE`/`FRAG`, and the v2 data plane is deprecated (decoding may be kept for one version).
- Not supported: cross-session TRAIN, server-initiated flows (full-cone stays inline).

**Example encoding (sess=7)**
```text
SINGLE steady IPv4 flow0, payload "abc":
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

### 6.2 Candidate B — connection-scoped symmetric full duplex (**recommended**)

**Core**: data frames carry only a connection-level flow id; `session` appears only in open (`sess u32`) and CTL; TRAIN items can cross sessions; both sides can open (ids split into halves); FRAG key = `(flow, id)`.

**id namespace and flags (candidate B definition)**
- flow id = `u16`: `0x0000` reserved as "inline/no-flow"; `0x0001..0x7FFE` belong to **client allocation**; `0x8001..0xFFFE` belong to **server allocation**; `0x7FFF/0xFFFF` reserved.
- First-byte flags (data frames): `0x1 OPEN` (this frame carries the open description `sess u32 + addr`), `0x2 INLINE` (no flow, `sess u32 + addr` inline; mutually exclusive with OPEN, used for table-full/one-off sources; the inline address is the actual source, so no separate SRC bit is needed), `0x4 HI` (the flow id belongs to the server half; on decode `id |= 0x8000`), `0x8 ACK` (optional: after the header and before the OPEN description place `nack u8 + ack item (1 B flags + idvarint) [nack]`, used to confirm flows the peer has received).
- Encoding: ids use LEB128; with `HI` encode `id−0x8000` → common ids 1–127 are always 1 B.

**Frame table**

| Frame | Layout (B) | Steady-state header | open header (incl. sess+addr) | Notes |
|---|---|---:|---:|---|
| `DATA 0x10` | `0x10\|flags \| idvarint \| [sess u32 + addr if OPEN] \| payload` | **2** (id≤127)/3/4 | 13 / 25 / 40 | no length field; one payload per DATAGRAM |
| `DATA inline 0x12` | `0x12 \| sess u32 \| addr \| payload` | — (12/24/39) | — | fail-safe path for table full/no flow (≈v2 single frame) |
| `TRAIN same 0x21` | `0x21 \| count u8 \| idvarint \| item*`; item=`len varint \| payload` | header **3** (id≤127); item **1–2** | — | whole frame same flow, all compressed |
| `TRAIN dict 0x22` | `0x22 \| count u8 \| nfl u8 \| entry[nfl] \| item*`; entry = 1 B (bit7=HI server half, bit6=LONG followed by varint id, low 6 bits=id or 0), typically 1 B/flow; item=`idx u8 \| len varint \| payload` (idx 0..63) | header **3+k** (k=number of distinct flows in this frame); item **2–3** | — | mixed flows; the dict only amortizes "multiple items of the same flow", **the 1 B per-item flow-reference mode (inline-flow) must also be kept**, since it is cheaper when the flow count ≈ item count; items can cross sessions (flow→session is in the table) |
| `FRAG 0x30` | `0x30\|flags \| idvarint \| id u32 \| idx u8 \| total u8 \| [sess u32 + addr if OPEN] \| chunk` | **8** (id≤127)/9/10 | 19 / 31 / 46 (first fragment) | key=`(flow, frag id)`; reassembly memory cap unchanged |
| `CTL 0x40` | `0x41 HELLO`, `0x42 CAPS`, `0x43 FLOW_ACK(sess u32+idvarint+status+[addr])`, `0x44 FLOW_REJECT`, `0x45 FLOW_CLOSE`, `0x46 SESS_CLOSE` | — | — | idempotent |

**Open/confirm/close**
- open: `DATA`/`FRAG` carries `OPEN` + `sess` + `addr` (+payload). Repeated opens are idempotent (same id with same `(sess,addr)` is treated as a retransmission; different → discard and count).
- confirm: the `ACK` bit/`FLOW_ACK` in either direction can confirm (used for pure uplink + domain resolved-IP return); request/response traffic has **implicit confirmation** (the peer's first compressed frame proves the mapping is installed, consistent with the current `confirm_flow` semantics, `src/bin/myquic2-client/hub.rs:139-149`).
- close: `FLOW_CLOSE`/`SESS_CLOSE`; id reuse guard ≥ `2×FRAG_TIMEOUT+Sweep` (3 s, the same argument as `FRAG_ID_SAFE_WINDOW_MS`, `src/mqp/fragment.rs:118-145`), tombstones kept for the same window; over limit/exhausted → fall back to `DATA INLINE`.
- downlink mirror: if the server already has a client flow for that target, reply directly with the client id (current behavior, zero extra open); server-originated flows such as full-cone/port-changed open once with an id from its own half and then compress.

**Example encoding**
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

**B′ (optional, 1 B steady-state header)**: define the 16 kind values `0x50..0x5F` as "DATA short": the low 4 bits of `0x50|lo` = hot flow slot number (16 per direction, negotiated by `CAPS` or fixed to the 16 most recently used ids), with the payload immediately following; steady-state header **1 B**. Gain: another −1.6% at 60 B, −3.3% at 28 B; cost: one more kind group, hot-flow mapping state, decode branches. **The kind space can be reserved now, with the implementation in the second phase.**

### 6.3 Candidate C — session bucket + u16 sess (**not recommended**)

**Idea**: keep the "session is a first-class address" model, shrink `sess u32→u16` (steady-state header 5→3 B), add a `MULTI_SESS` dictionary to TRAIN for cross-session packing, and use `(sess u16, flow u8, id)` for FRAG.

| Frame | Layout (C) | Steady-state header |
|---|---|---:|
| `SINGLE 0x10` | `0x10\|flags \| sess u16 \| [flow u8] \| [addr] \| payload` | 3 / 4 |
| `TRAIN 0x20` | `0x20\|flags \| sess u16 \| count u8 \| [nsess u8 + sess u16×n if MULTI] \| [flow u8 if SAME_FLOW] \| item*` (with MULTI, item +1 B sess index) | 4 / 5 |
| `FRAG 0x30` | `0x30\|flags \| sess u16 \| [flow u8] \| id u32 \| idx \| total \| [addr] \| chunk` | 9 / 10 |
| `CTL 0x40` | same as A, but sess u16 | — |

**Why rejected (reuse safety)**:
- The client session id is a **monotonically allocated, never reused** u32 (`hub.rs:326-353`), and server sessions are reclaimed only by 180 s idle or sweep (`table.rs:382`; `accept.rs:799-812`). After changing to u16, 65,536 allocations wrap; as long as the client creates more than 65,536 associations within 180 s (average 364/s, achievable by a busy client or a malicious local app), **a new association gets a sess id that the server still considers to belong to an old association**: the server delivers replies for new traffic into the old relay socket (wrong target/port), while the client hub delivers the replies to the new app → cross-association stream mixing.
- To reuse safely you must introduce **reliable** SESS_CLOSE confirmation (QUIC stream or CTL with retransmission), or a 180 s reuse guard (limiting new sessions to 364/s), or another 1 B generation (steady state back to 4 B, leaving only 1 B of gain). The gain (2 B/frame) is not enough to offset this state machine and the "stream mixing" risk; candidate B removes sess from data frames entirely, so the reuse problem does not exist at all.
- Exception: if the product explicitly requires "session-centric, low-churn traffic", C's `MULTI_SESS` can also get L7's send-call gain; but in that case it is better to just do B.

---

## 7. Byte / call savings model

### 7.1 Formulas and assumptions

**Assumptions (all model inputs, not measurements)**
- A1: MQP layer only, excluding IP/UDP/QUIC headers; each DATAGRAM frame has about `1 B type + varint(len)` ≈2–3 B at the QUIC layer (the same for both candidates, so it does not enter the comparison; fewer frames saves more).
- A2: `limit = 1162` (MTU 1200) and `1362` (MTU 1400).
- A3: no packet loss/reordering; domain L=30; IPv4 default.
- A4: TRAIN only packs within the same flush burst, burst=32 payloads (`LAST_HOP_DRAIN=32`, `src/udp/batch.rs:46`); each frame greedily packs to budget, run-of-1 sends a single frame (current behavior, kept by the candidates).
- A5: candidate B's flow id ≤127 (1 B varint), open carries `sess u32`; candidate A keeps `sess u32`.
- A6: candidate byte counts are **hand-computed from the §6 frame tables**, not implemented, not measured.

**Formulas**
```text
Single frame:      W = p + H_single
TRAIN (n items):   W = H_train + Σ_i (O_item + p_i) ≈ H_train + n·(O_item + p)
                   n_max = floor((limit − H_train) / (O_item + p))     # same-size items
Fragmentation:     F = ceil(p / (limit − H_frag)) ;  W = p + F·H_frag
Per 1000 payloads: W1000 = Σ per-frame length ;  Frames1000 = Σ frame count
Savings ratio:     save% = (W_cur − W_new) / W_cur
Calls:             each DATAGRAM frame = 1 quinn send (1 connection state lock,
                   src/bin/myquic2-client/egress.rs:110-112; src/bin/myquic2-server/reader.rs:503-506)
CPU magnitude:     ΔCPU ≈ Δframes · c_send, c_send ≈ 200–300 ns/frame
                   ([Doc/existing measurement] estimation basis from PROTOCOL_ANALYSIS.md §4, not re-measured this time)
```

### 7.2 Workload matrix (per 1000 payloads, `limit=1162`; `1362` lists only differing entries)

| Workload | Current bytes/frames | A bytes/frames | B bytes/frames | A save | B save |
|---|---:|---:|---:|---:|---:|
| W1 IPv4 60 B same destination (32/burst) | 62,378 / 63 | 61,378 / 63 | 61,189 / 63 | −1.6% | −1.9% |
| W1b IPv4 28 B same destination | 30,192 / 32 | 29,192 / 32 | 29,096 / 32 | −3.3% | −3.6% |
| W2 8 flows same session, fan-out 60 B | 63,378 / 63 | 62,378 / 63 | 62,189 / 63 | −1.6% | −1.9% |
| W2b 8 flows fan-out 200 B | 205,314 / 219 | 204,314 / 219 | 203,657 / 219 | −0.5% | −0.8% |
| W3 **domain uplink** 60 B (L=30, domain address) | **97,564 / 94** | **61,378 / 63** | **61,189 / 63** | **−37.1%** | **−37.3%** |
| W3b domain **downlink replies** 60 B (v4, inline IP) | 70,378 / 63 | 61,378 / 63 | 61,189 / 63 | **−12.8%** | **−13.1%** |
| W3c domain **downlink replies** 60 B (v6, inline IP) | 82,564 / 94 | 61,378 / 63 | 61,189 / 63 | **−25.7%** | **−25.9%** |
| W4 across 8 sessions×4 items, 60 B | 63,500 / 250 | 63,500 / 250 | 62,189 / 63 | 0 | **−2.1% (calls 4×)** |
| W5 across 32 sessions×1 item, 60 B | 65,000 / 1000 | 65,000 / 1000 | 62,189 / 63 | 0 | **−4.3% (calls 16×)** |
| W7 high-rate unidirectional 60 B (32/burst, no replies) | 62,602 / 63 | 61,378 / 63 | 61,189 / 63 | −2.0% | −2.3% |
| W7b **sparse unidirectional** 60 B (1/burst) | 72,000 / 1000 | 65,000 / 1000 | 62,000 / 1000 | **−9.7%** | **−13.9%** |
| W8 bulk 1200 B IPv4 (@1162, 2 fragments) | 1,236,000 / 2000 | 1,222,000 / 2000 | 1,216,000 / 2000 | −1.1% | −1.6% |
| W8 v6 1200 B @1162 (2 fragments) | 1,260,000 / 2000 | 1,222,000 / 2000 | 1,216,000 / 2000 | −3.0% | −3.5% |
| W9 full-cone downlink 60 B single source (server-originated, v4 inline IP) | 70,378 / 63 | 70,378 / 63 (A does not support) | 61,201 / 64 | 0 | **−13.0%** (v6 −25.9%) |

Differences at `limit=1362` (the other rows are the same as 1162):
- W8 bulk 1200 B IPv4: current 1,212,000/1000 frames → A 1,205,000 → B 1,202,000 (−0.6% / −0.8%);
- W8 v6 1200 B: current 1,224,000/1000 → A 1,205,000 → B 1,202,000 (−1.6% / −1.8%);
- W8 1420 B (2 fragments at any MTU): v4 current 36 B → A 22 → B 16 (−1.0% / −1.4% of 1456 B); v6 current 60 → 22/16 (−2.7% / −3.0%).
- W2b 200 B fan-out: frame count 219→188, byte curve as above (−0.5%/−0.8%).
- W3c domain downlink (v6): at 1362 currently 82,378 B / 63 frames (at 1162 82,564 / 94 frames), A/B unchanged → −25.5%/−25.7%.

### 7.3 Conclusions per workload class (for decision-making)

| Workload class | Byte gain | Call gain | Notes |
|---|---|---|---|
| Domain targets (DNS/game by hostname/WebRTC) | uplink **−35% ~ −38%**; downlink v4 −13%, v6 −26% | frame count 94→63/1000 (uplink) | biggest gain; needs FLOW_ACK with resolved IP; downlink is currently inline IP (not a domain address) so the reduction is smaller than uplink |
| Sparse pure uplink (telemetry/unidirectional) | −10% ~ −14% | 1× | needs FLOW_ACK; B saves 3 B/frame more than A |
| High-rate same-destination small packets | −1.6% ~ −3.4% | ~1× | existing TRAIN already amortizes; only header/item overhead remains |
| Multi-destination same-session fan-out | −0.5% ~ −1.9% | ~1× | existing TRAIN already supports it; B's dict header is worse than A when there are "few items, many flows", so B must keep the inline-flow mode |
| Cross-session small packets | −2% ~ −4.3% | **4× ~ 16×** | **mainly CPU/lock gain**; requires connection-level staging on both ends (largest engineering item) |
| 513 B ~ single-frame cap (newly covered) | header 12/24→5/6 (A) or 2/3 (B); i.e. per payload v4 −7 (A)/−10 (B), v6 −19 (A)/−22 (B) | ~1× | at the default MTU the v6 gain doubles; payloads near the v2 single-frame cap (v4 1150/v6 1138) have a cap of 1157/1160 under A/B, and may also go from 2 frames to 1 |
| Fragmentation/bulk (1200–8192 B) | −0.7% ~ −3.5% | 1× (fragment count basically unchanged) | the protocol header is not the bulk bottleneck (§8.3) |
| full-cone downlink | v4 −13%, v6 −26% (B only) | 63→64 (one more open frame) | needs server-initiated flows; A/C (client authoritative) cannot do it; current replies are inline IP rather than a domain address |

### 7.4 Per-payload bytes according to the §3 matrix (standalone; save ratio = relative to current in the same scenario)

| p | Target | flow | Shape | Current bytes | A bytes | B bytes | A save | B save |
|---:|---|---:|---|---:|---:|---:|---:|---:|
| 28 | v4/v6 | 0 | steady | 5+28=33 | 33 | 30 | 0 | **−9.1%** |
| 28 | v4/v6 | 1 | steady | 34 | 34 | 30 | 0 | **−11.8%** |
| 60 | v4/v6 | 0 | steady | 65 | 65 | 62 | 0 | −4.6% |
| 60 | v4/v6 | 1 | steady | 66 | 66 | 62 | 0 | −6.1% |
| 200 | v4/v6 | 0 | steady | 205 | 205 | 202 | 0 | −1.5% |
| 512 | v4/v6 | 0 | steady | 517 | 517 | 514 | 0 | −0.6% |
| 28 | domain (uplink address) | 0 | steady (currently inline / A,B need ACK first) | 68 | 33 | 30 | **−51.5%** | **−55.9%** |
| 60 | domain (uplink address) | 0 | steady (same as above) | 100 | 65 | 62 | **−35.0%** | **−38.0%** |
| 200 | domain (uplink address) | 0 | steady (same as above) | 240 | 205 | 202 | −14.6% | −15.8% |
| 512 | domain (uplink address) | 0 | steady (same as above) | 552 | 517 | 514 | −6.3% | −6.9% |
| 60 | domain reply (v4) | 0 | steady (currently NO_FLOW+inline IP / A,B need ACK first) | 73 | 65 | 62 | −11.0% | **−15.1%** |
| 60 | domain reply (v6) | 0 | steady (same as above) | 85 | 65 | 62 | −23.5% | **−27.1%** |
| 28 | v4 | 0 | first (open) | 12+28=40 | 40 | 41 | 0 | −2.5% (B has 1 extra B for flow id) |
| 60 | v6 | 0 | first (open) | 24+60=84 | 84 | 85 | 0 | −1.2% |
| 1200 v4 @1162 | v4 | — | 2 fragments | 1,236 | 1,222 | 1,216 | −1.1% | −1.6% |
| 1200 v6 @1162 | v6 | — | 2 fragments | 1,260 | 1,222 | 1,216 | −3.0% | −3.5% |
| 1200 v4 @1362 | v4 | — | 1 frame | 1,212 | 1,205 | 1,202 | −0.6% | −0.8% |
| 1200 v6 @1362 | v6 | — | 1 frame | 1,224 | 1,205 | 1,202 | −1.6% | −1.8% |
| 8192 @1162 | v4 | — | 8 fragments | 8,336 | 8,280 | 8,256 | −0.7% | −1.0% |
| 8192 @1162 | v6 | — | 8 fragments | 8,432 | 8,280 | 8,256 | −1.8% | −2.1% |

> The 2 B in the B column for steady rows assumes flow id ≤127; for ids 128–16383 B's steady-state header is 3 B, and the gain decreases by 1 B accordingly. TRAIN per-item overhead and amortization are in §3.2 and §7.2 (TRAIN saves another 2–4 B/frame of fixed header vs single frames, and B's same-flow item is 1 B/item).

---

## 8. Recommendation

### 8.1 Direction

**Do candidate B (connection-level flow namespace + symmetric bidirectional + full CTL plane), landing in two phases; candidate A serves as the "byte subset" of that direction and goes live first for validation.**

Reasons:
1. It simultaneously solves P0's L1 (domain bidirectional), L2 (pure uplink), L3 (>512/fragmentation), L4 (control plane), L5 (FRAG wiring), L7 (cross-session) — A can only solve the first five and cannot get "true full duplex" (server-initiated flows) or cross-session.
2. The 2 B steady-state header and 8 B fragment header are already close to the entropy lower bound of this model (kind/flags 1 B + id 1 B; fragment + id u32+idx+total). The only remaining option is B′'s 1 B short header, a gain of 1 B/payload, **cosmetic, can be reserved in the kind space and done later**.
3. The current 4 B `sess` per frame is 80% of the 5 B steady-state header; as long as you still want "high-pps small packets/constrained uplink", this is a fixed tax that must be removed.
4. Reuse safety conversely proves that "keeping session in the data frame and narrowing it" is not worth it (candidate C): after B moves sess out of the data plane, a u16 id + 3 s reuse window is safe.

**Landing order (same wire, features enabled in stages; not two wires)**
- Phase 0 (prerequisite, non-wire): change the per-connection TX staging abstraction (both ends) so connection-level aggregation has a place to land; otherwise cross-session is always 0.
- Phase 1: CAPS/HELLO + new DATA/TRAIN/FRAG formats + v3 FRAG wiring + domain/unidirectional FLOW_ACK; at this point you can use only client-half ids first (equivalent to "shared bidirectional id") and get L1/L2/L3/L5 first.
- Phase 2: server-half ids + server-initiated flows (full-cone) + cross-session TRAIN (enable dict mode); requires the staging from phase 0.
- Phase 3 (optional): B′ 1 B short header; larger reassembly cap (CAPS negotiation); delete v2 decoding.

### 8.2 Which changes are "real gains" and which are cosmetic

**Real gains** (sorted by ROI)
1. **Domain flow compression (L1)**: uplink −35%~−38% MQP bytes; downlink (currently inline IP replies) v4 −13%, v6 −26%; medium implementation effort (the server must store the resolved IP and reply ACK; the client must write the SOCKS5 reply header).
2. **FLOW_ACK for pure-uplink/unidirectional flows (L2)**: sparse unidirectional −10%~−14%.
3. **>512 B and FRAG unified into v3 (L3/L5/L11)**: v2 data plane deleted; single-frame header v4 12→5/2, v6 24→5/2 (A/B); fragment header v2 18/30 B → A 11 B / B 8 B (per fragment v4 −7~−10, v6 −19~−22); the biggest gains are on v6 and payloads near the single-frame cap.
4. **Cross-session TRAIN (L7)**: 4×–16× send calls, CPU/lock gain; wire only −2%~−4.3%.
5. **Remove per-frame sess (L6, B)**: steady state −3 B/frame; sparse small packets −4.6% (60 B)/−9.1% (28 B).
6. **Server-initiated flows (full-cone, B)**: in that scenario v4 −13%, v6 −26% (current replies are inline IP, not a domain address).
7. **COMPACT TRAIN items (L8)**: −1 B/item, 1.6%~3.4% (small packets).

**cosmetic / not recommended**
- B′ 1 B short header, `sess u24`, 12/20-bit bit-splitting: on the order of <1 B/frame, just reserve the space first.
- "SAME_FLOW for flow 0": no byte gain (§4-L9), only needs to be replaced by COMPACT/explicit all-0-flow semantics in the new format.
- Widening `idx/total` (L13): unnecessary; moving the reassembly cap from 8 KiB to larger is a separate product decision (loss amplification, `src/mqp/fragment.rs:31-47`).
- Content compression/FEC/retransmission: unrelated to this document's goals, not introduced.
- **Do not change the protocol for bulk throughput**: see 8.3.

### 8.3 Bulk reality check

For a 1200 B payload, the MQP header even in the worst case (MTU 1200, IPv6, 2 fragments) is only 5% of that payload (60/1260); IPv4 is 2.9% (36/1236). Changing to B can only bring it down to 1.3% (16/1216, the v4/v6 fragment header is the same width), **total IPv4 wire savings ≤1.6%, IPv6 ≤3.5%**; meanwhile the IP+UDP+QUIC (about 55–80 B) outer layers of the same 1200 B UDP datagram, plus QUIC congestion control/MTU, are the main throughput factors. **The feasible bulk optimizations are configuration (`initial_mtu` 1200→1360/1400, README.md:777) and reducing fragmentation/avoiding fragment-loss amplification, not the protocol header.** The value of the protocol redesign is concentrated in: domain targets, high-pps small packets, multi-destination/multi-session fan-out, and the CPU of "one quinn send per frame".

### 8.4 Risks and mitigations

| Risk | Mitigation |
|---|---|
| connection-level table lifecycle/memory/DoS | double caps (connection/session) + open rate limit + `FLOW_REJECT` fallback to inline; default 4096 entries/connection and counted in `per_connection_memory_bytes` |
| id reuse causing cross-session misdelivery | no reuse; reuse requires ≥2×FRAG window + close + tombstone; tombstone hit fail-closed |
| cross-session staging fairness/head-of-line | one stager per connection becomes a hotspot: shard per worker/per connection, bounded queues, flush per burst; do not wait across bursts |
| CAPS/HELLO loss preventing compression | compression only enabled after "confirmation" (current semantics); loss at most delays compression; resend HELLO/CAPS several times |
| version mismatch | ALPN fail-closed (suggest default `myquic2/3` instead of the `h3` disguise, or close the connection when the CAPS magic mismatches); the same-version deployment prerequisite is unchanged |
| large implementation regression surface | land candidate A's byte gains first (L1/L2/L3), then B's connection-level table/staging in phases; keep v2 decoding as a fallback for one version per phase |

---

## 9. Ambiguities and open questions (no invented answers)

- **Q1 Definition of "full duplex"**: this document interprets it as "both directions use the same frame syntax, both sides can compress/send data, and downlink does not depend on uplink open". If the user means "independent scheduling/congestion/connections per direction", that is beyond wire scope and needs Lead clarification.
- **Q2 ALPN/version gate**: the task only requires the protocol to still be called MQP-3; it does not state whether the ALPN string may change or whether dual-stack during a canary period is allowed. This document suggests CAPS carry wire-ver and ALPN conservatively use `myquic2/3` (or add a suffix), introducing no new protocol codename.
- **Q3 Whether compatibility with v0.2.0 peers is needed**: the task says an incompatible redesign is allowed; this document is written assuming "no mixed versions, same-version deployment"; if a canary is needed, an additional "dual-format probing/ALPN suffix" design is required, which this document does not elaborate.
- **Q4 Semantics of the domain ACK**: the resolved IP returned by the server may differ from the target's actual reply source IP (multiple A/anycast/port change). This document's rule: flow compression is only used for sources "consistent with the ACK/installed mapping"; when inconsistent, fall back for one frame with `INLINE` (the inline address is the actual source). Which IP to use in the SOCKS5 reply header needs product confirmation (currently the actual reply source).
- **Q5 Whether server-initiated flows (full-cone) should be compressed**: determines whether B is worth keeping the server half/bidirectional ownership; if the product does not need it, B can degenerate to "single authoritative shared id" (simpler, same bytes).
- **Q6 Default flow table cap**: this document suggests 4096/connection, 64/session; the actual values depend on the memory budget (`max_peer_memory_mb`) and the client's 4032 association cap, and need product input.
- **Q7 MTU distribution**: the magnitude of bulk/fragmentation gains depends on the deployment MTU (1200 default vs 1400 known path); target-environment data is needed.
- **Q8 Measurement**: this document has no Linux target-machine data; the CPU gains of domain compression and cross-session staging must be re-measured with `hotpath_bench` + a real app. Also: the comment in `FRAG_ID_SAFE_WINDOW` saying "under 0.01% below ~1.4M fragmented payloads/s" does not match the formula `W/(2^32·1000/pps+W)` (about 0.098% at 1.4M/s), a comment typo that does not affect code semantics — worth correcting when the document redesign is done (`src/mqp/fragment.rs:131-138`).
- **Q9 Control-plane reliability carrier**: should CTL go over DATAGRAM (unreliable, idempotent) or a QUIC stream (reliable but one more stream)? This document leans toward DATAGRAM + resend; `SESS_CLOSE` can go over a QUIC stream if "immediate and reliable" is required.

---

## 10. Summary for the Lead (≤30 lines)

1. **Current state**: MQP-3 in v0.2.0 only has "same session, IP target, ≤512 B" flow/TRAIN compression; the v3 FRAG codec is written but never called; CTL is only a constant.
2. **Biggest structural gaps**: domain targets cannot be compressed in either direction (uplink 40 B header per frame, L=30; downlink replies inline IP 13/25 B header); pure-uplink flows stay inline forever (no FLOW_ACK); everything >512 B falls back to MQP-2 (full address repeated in every fragment); no control plane, no cross-session frame merging.
3. **Largest single byte win = domain flow compression**: uplink per 1000 from 97,564 B → ~61,300 B (**−37%**); downlink replies (currently inline IP) v4 70,378→61,189 (−13%), v6 82,564→61,189 (−26%); requires FLOW_ACK to return the resolved IP.
4. **Pure uplink/unidirectional**: sparse flow 60 B from 72,000 → 62,000~65,000/1000 (**−10%~−14%**; high-rate flows about −2% due to TRAIN amortization).
5. **>512 B / fragmentation**: header 12/24→5/6 (A) or 2/3 (B); fragment header 18/30→11/8; 1200 B@MTU1200 2 fragments −1.1%~−1.6% (v6 −3.0%~−3.5%); 8192 B 8 fragments −0.7%~−1.0%.
6. **Cross-session TRAIN**: send calls 4× (8×4)~16× (32×1), wire −2%~−4.3%; the value is in quinn locks/allocation CPU, but requires connection-level staging on both ends (largest engineering item).
7. **Recommended candidate B**: connection-level flow id (u16, varint 1–2 B; id halves for client/server, both can open) + remove sess from data frames (2 B steady state, 8 B fragment) + TRAIN items can cross sessions (same-flow 1 B/item, dict mode 2 B/item) + full CTL (HELLO/CAPS/FLOW_ACK/REJECT/CLOSE) + domain/unidirectional ACK + server-initiated flows.
8. **Candidate A (incremental with sess u32 kept)** as a low-risk subset first: gets domain/unidirectional compression, FRAG wiring, large-packet v3 conversion, COMPACT items (−1 B/item), no cross-session/server-initiated flows.
9. **Candidate C (u16 sess compromise) rejected**: wraps after 65,536 allocations; >364 assoc/s within 180 s reuses an old session still on the server → cross-association stream mixing; making it safe requires reliable close or generation, and the gain does not offset that.
10. **Bulk reality**: 1200 B packet MQP header 1.0% (v4 single frame)~4.8% (v6 2 fragments); the redesign affects bulk throughput by IPv4 ≤1.6%, IPv6 ≤3.5%, **do not change the protocol for bulk**; bulk should tune `initial_mtu`/windows.
11. **cosmetic**: B′ 1 B short header, sess u24, 12/20-bit bit-splitting, widening idx/total, SAME_FLOW for flow0 — gain <1 B/frame or no byte loss at all; just reserve kind space, no need to design for them separately.
12. **Evidence and basis**: all numbers = read-only code audit + python3 model (no packet loss, burst=32, L=30, MTU 1200/1400); no build/test/measurement; re-measure with Linux `hotpath_bench` before landing.
13. **Open questions**: full duplex definition; whether the ALPN/version gate can change; whether v0.2.0 canary compatibility is needed; IP semantics of the domain ACK (multiple A/anycast); whether full-cone server-initiated flows are needed (decides B vs B-lite); flow table caps and memory budget; target MTU distribution.
14. **Suggested next step**: the Lead decides B (recommended) or A (conservative) → we can then produce the complete wire spec + migration/test matrix for candidate B (this report's §6.2 already has the frame tables and example encodings).

---

### Appendix A: Key constants and sources (for verification)

| Constant | Value | Source |
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
| `DEFAULT_INITIAL_MTU` / lower and upper bounds | 1200 / 1200..=1472 | `src/config/tuning.rs:193-198` |
| DATAGRAM budget | `MTU − 38` | README.md:777 |
| ALPN default | `h3` (`myquic2/3` optional) | `src/mqp/ack.rs:1-22` |

### Appendix B: Golden bytes of current frames (directly comparable)

| Scenario | Bytes (hex) | Total length |
|---|---|---:|
| SINGLE steady flow0, sess=7, payload "abc" | `10 07 00 00 00 61 62 63` | 8 |
| SINGLE steady flow2, sess=7, payload "abc" | `12 07 00 00 00 02 61 62 63` | 9 |
| SINGLE open flow0, sess=7, 1.2.3.4:53, "abc" | `11 07 00 00 00 01 01 02 03 04 00 35 61 62 63` | 15 |
| TRAIN 2×flow0 ("abc","de"), sess=7 | `20 07 00 00 00 02 00 03 61 62 63 00 02 64 65` | 15 |
| TRAIN SAME_FLOW flow3 2 items, sess=7 | `21 07 00 00 00 02 03 00 03 61 62 63 00 02 64 65` | 16 |
| FRAG v3 steady flow1, sess=7, id=0x12345678, idx=1/3, "abc" | `32 07 00 00 00 01 78 56 34 12 01 03 61 62 63` | 15 |
| MQP-2 0x02, sess=7, 1.2.3.4:53, "abc" | `02 07 00 00 00 01 01 02 03 04 00 35 61 62 63` | 15 |
| MQP-2 0x05, sess=7, id=0x12345678, idx=1/3, 1.2.3.4:53, "abc" | `05 07 00 00 00 78 56 34 12 01 03 01 01 02 03 04 00 35 61 62 63` | 19 |

> Existing golden tests are at `src/mqp/v3.rs:814-844,907-945,947-968,994-1010`; the table above matches them (the flow byte position of `0x12`, the `iflg|len|payload` order of TRAIN items).

---

*(End of report)*
