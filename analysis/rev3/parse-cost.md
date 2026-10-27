# MQP-3 rev2 → rev3: per-DATAGRAM parse/encode cost and wire-header audit

**Task:** `task-3` (parse-cost). **Scope:** the MQP-3 rev2 codec (`src/mqp/r2.rs`,
`src/mqp/r2_flow.rs`, `src/mqp/addr.rs`), the UDP data paths (`src/udp/r2_stage.rs`,
`src/udp/r2_frag.rs`, `src/udp/r2_reasm.rs`, `src/udp/send.rs`), receive dispatch
(`src/bin/myquic2-client/dispatcher.rs`, `src/bin/myquic2-server/accept.rs`) and
send/egress (`src/bin/myquic2-client/rev2.rs`, `src/bin/myquic2-server/reader.rs`).
**Backward compatibility is explicitly not a requirement** for the redesign, so
§6 prices a clean-slate format.

**Evidence labels used throughout:**
- `[code]` — read directly in the tree, with `file:line` and a quoted line.
- `[derived]` — arithmetic from the code's own length functions / wire rules.
- `[estimate]` — a cost model built from the cited operations plus the in-repo
  measured ns baselines (`examples/frame_bench.rs`, `PERF_ANALYSIS.md` §4);
  **not measured in this task** (cargo was reserved for the Lead).
- `[measured]` — an existing measurement in the repository.

**Reproduce:** `cargo run --release --example rev3_bench` (source written this
task, §7). It prints every codec/table micro-cost used to price the "cheap wins"
below, plus the wire-header tables of §1.

---

## 0. TL;DR (12 findings, ranked by expected value)

1. **The "2 B steady DATA header" is a 63-flow illusion.** `wire_id=(local<<1)|owner`
   is a LEB128 varint; `local_id=64` makes `wire_id=128`, so the **64th flow an
   endpoint ever opens** turns every later steady DATA header from 2 B into 3 B —
   and ids are monotone and never reused, so it never shrinks. A 4096-flow
   connection averages **2.985 B/steady frame**, not 2 B. `[derived]` from
   `r2.rs:143-148,172-179,275-277` + `r2_flow.rs:52,759-771`.
2. **A one-packet (DNS-like) flow is ~37 % more wire on the default OPEN path
   than on the INLINE path**, because every `DATA OPEN` is answered with a
   separate `CTL FLOW_ACK` DATAGRAM: 3 QUIC packets / **192 B** for a 1-up/1-down
   120 B payload versus 2 packets / **140 B** INLINE. The ACK only pays for
   itself after **~6.6 total frames** on the flow. `[derived]` from
   `accept.rs:2333-2344` (ACK per install) + §1.4.
3. **TRAIN decode is a double pass with two by-value `[u32;64]` (256 B) copies**
   per frame: `decode_train` validates every item eagerly (`r2.rs:633-650`),
   `TrainFrame`/`TrainItems` embed the array by value (`r2.rs:531-558`), and both
   endpoints call `items()` twice (dedupe pass + dispatch pass). `[code]`
   `accept.rs:2477,2497`; `dispatcher.rs:1203,1240`.
4. **The TRAIN encoder re-validates its own stager's dedupe with two O(n²) scans
   while holding the stager mutex**: `unique.contains` per item
   (`r2_stage.rs:593`) + `valid_train_flows`' `flows[..i].contains(f)`
   (`r2.rs:477`) + a 1 KiB `[(u8,&[u8]);64]` stack array zeroed per frame
   (`r2_stage.rs:643`) + a foldhash map insert per flow (`r2_stage.rs:639-642`).
   Costs almost nothing at the typical 2–8 flows, but ~0.3–1.2 µs/frame at 64
   flows (plus a matching O(n²) in the decoder) — the encoder share inside the lock. `[code]` + `[estimate]`.
5. **`FlowBinding::mark_open()` is an unconditional `compare_exchange` RMW per
   downlink frame** (`r2_flow.rs:146-153`) that is a no-op after the first
   frame; it runs per DATA (`dispatcher.rs:1135`), per FRAG completion
   (`:1351`) and per distinct TRAIN id (`:1253`). Load-then-CAS removes it from
   steady state. `[code]`
6. **The server reply path lost the legacy per-source memo**: `match_source`
   (`r2_flow.rs:325-366`) scans up to 64 bindings *per reply*
   (`reader.rs:1044`), each candidate paying an `ArcSwapOption` load + an atomic
   load (+ an `ArcSwap` load + up to 16 compares for a domain flow). The legacy
   v3 stager had a one-entry `last_flow` memo (`reader.rs:134-155`); rev2 does
   not. `[code]` + `[estimate]` 5–250 ns/reply by flow count.
7. **`FlowRegistry` is still `RwLock<HashMap<…>>` on every frame**
   (`r2_flow.rs:436-441,587-589`): ~10–20 ns/frame for lock + hash + `Arc`
   clone. A direct-indexed slot table (mask + full-id compare + `Arc` clone,
   16 B/slot × 4096 = 64 KiB/connection worst case, grown lazily) is ~2–4 ns and
   is smaller than the current 3.53 MiB/connection worst-case admission charge
   (`README.md:404`). `[code]` + `[estimate]`, measured by `rev3_bench`.
8. **The uplink target lookup is a single-slot memo over a 64-entry linear
   scan** (`r2_flow.rs:291-297`, `rev2.rs:1052-1068`); alternating targets
   (`udpfanout` shape) miss the memo every datagram and pay O(flows/2)
   `TargetAddr` compares + one `Arc` clone. A foldhash map or 4-slot memo is a
   cheap fix. `[code]`
9. **An avoidable payload copy on each staged small payload**: the client copies
   app payload → owned `Bytes` at push (`rev2.rs:774,794`), then copies it again
   into the frame at drain; the server downlink does the same
   (`reader.rs:1111`). Copy count per staged payload is **3** (recv→owned,
   owned→frame, frame→quinn TX). The first is removable by building the frame at
   push (a design change, not frame pooling — pooling stays rejected,
   `frame_bench.rs:6-25`). `[code]`
10. **Both endpoints classify the first byte 2–4 times per frame**: server
    `is_v3` → `is_r2` → `kind` → `kind` (`accept.rs:3009,3027,2656,2724`);
    client `is_r2` → `kind` (`dispatcher.rs:1441,1414`). 1–3 ns/frame, trivial
    but free to fix. `[code]`
11. **The receive path is already zero-copy and must not regress**: server
    ingress `DATA` forwards a quinn-owned `Bytes` view straight into an
    `sendmmsg` iovec (`accept.rs:3006-3008`, `251-286`), and client downlink
    does the same (`dispatcher.rs:724-814`). The only per-frame copies are the
    codec encode (send) and the stager's owned-payload copy. `[code]`
12. **Wire redesign is worth ~1 B/steady frame and ~36 % on one-shot flows, not
    bulk.** Steady MQP header goes 2 B/3 B → 1 B/2 B (packed kind+id, stable to
    the 4096-flow cap); `sess u32` → u16 session index and a per-connection
    address dictionary take OPEN from 14–27 B to 12–24 B full / 6 B on an
    address-dict hit; one-shot flows drop from 192 B to ~122–128 B wire.
    Bulk/FRAG gains are <1 %. `[derived]` §6.

---

## 1. Wire layout, exact bytes, id-width math

### 1.1 Frame forms (from the code's own length functions)

All numbers are **MQP header bytes**, i.e. excluding the QUIC DATAGRAM frame
(2–3 B, `MQP3_REFACTOR_ANALYSIS.md:147`) and the 55 B IPv4 IP/UDP/QUIC fixed cost
(`MQP3_REFACTOR_ANALYSIS.md:146`). LEB128 = `varint_len` (`r2.rs:172-179`):
1 B for n≤127, 2 B for n≤16383, 3 B for n≤2²¹−1, 4 B for n≤2²⁸−1, 5 B for u32.

| Form | Formula (`[code]`) | IPv4 (7 B addr) | IPv6 (19 B) | Domain (4+L) |
|---|---|---:|---:|---:|
| DATA steady, id<128 | `1+varint(id)` `r2.rs:275-277` | **2** | 2 | 2 |
| DATA steady, id<16384 | same | **3** | 3 | 3 |
| DATA steady, id<2²¹ | same | **4** | 4 | 4 |
| DATA OPEN/OPEN\|SRC, id<128 | `2+varint(id)+4+addr` `r2.rs:281-283` | **14** | 26 | 11+L |
| DATA OPEN, id<16384 | same | **15** | 27 | 12+L |
| DATA INLINE | `2+4+addr` `r2.rs:287-289` | **13** | 25 | 10+L |
| TRAIN same, id<128 | `3+varint(id)+Σ(varint(len)+len)` `r2.rs:430-440` | 4 + per item 1 B len (payload≤127) | — | — |
| TRAIN same, id<16384 | same | 5 + per item 1 B len | — | — |
| TRAIN dict | `4+Σvarint(fid)+Σ(1+varint(len)+len)` `r2.rs:444-456` | 4 + 1–2 B/flow + 2 B/item (idx+len ≤127 B payload) | — | — |
| FRAG steady, id<128 | `1+varint(id)+4+1+1` `r2.rs:686-688` | **8** | 8 | 8 |
| FRAG steady, id<16384 | same | **9** | 9 | 9 |
| FRAG open, id<128 | `2+varint(id)+4+1+1+4+addr` `r2.rs:692-694` | **20** | 32 | 17+L |
| FRAG open, id<16384 | same | **21** | 33 | 18+L |
| FRAG inline | `2+4+1+1+4+addr` `r2.rs:698-700` | **19** | 31 | 16+L |
| CTL HELLO | `Ctl::len` `r2.rs:906-914` | **8** | | |
| CTL CAPS | same | **17** | | |
| CTL FLOW_ACK / FLOW_REJECT | `3+varint(id)` | **4** (id<128) / **5** | | |
| CTL FLOW_CLOSE | `2+varint(id)` | **3** / 4 | | |
| CTL SESS_CLOSE | fixed 7 | **7** | | |

Golden anchors in the tree: DATA steady id 5 = `[0x00,0x05]` 2 B
(`r2.rs:1113-1119`), OPEN v4 id 5 = 14 B (`r2.rs:1122-1130`), TRAIN same 2 items =
9 B (`r2.rs:1153-1161`), FRAG steady id 5 = 8 B (`r2.rs:1238-1245`),
FRAG open tests `r2_frag.rs:322-335` (open v4 = 20, inline v4 = 19, steady = 8).
README tables agree for the 1-byte-id case (`README.md:193-198`).

### 1.2 The id-width cliff: how many flows before the header grows

`make_wire_id` (`r2.rs:143-148`):

```rust
pub fn make_wire_id(local_id: u32, server_owned: bool) -> Option<u32> {
    if local_id == 0 || local_id > (u32::MAX >> 1) { return None; }
    Some((local_id << 1) | u32::from(server_owned))
}
```

`FlowIds::alloc` is monotone 1,2,3,… (`r2_flow.rs:759-771`); ids are **never
reused while the connection lives** (`r2_flow.rs:38-40`, `README.md:151`). The
live cap is 4096 flows/connection (`r2.rs:101`, `r2_flow.rs:40`), but the
*header width* depends on **how many flows the endpoint has ever opened**, not on
how many are live.

LEB128 thresholds on `wire_id = 2·local + owner`:

| varint | wire_id | local_id | flows per owner at this width | steady DATA hdr |
|---|---|---|---:|---:|
| 1 B | 2…127 | 1…63 | **63** | **2 B** |
| 2 B | 128…16383 | 64…8191 | 8128 | **3 B** |
| 3 B | 16384…2²¹−1 | 8192…1 048 575 | — | **4 B** |
| 4 B | ≥2²¹ | ≥1 048 576 | — | **5 B** |

Because the owner bit is the low bit, **both endpoints get exactly 63 one-byte
ids** (126 flow ids total for a connection whose two halves each opened ≤63
flows); the 64th flow of *either half* makes that half's ids two-byte. The owner
bit changes which id is even/odd but not the threshold. `[derived]`

**Answer to "how many flows can a connection open before the steady DATA header
grows from 2 B to 3 B": 63 per endpoint** (the 64th `FlowIds::alloc` call on that
endpoint returns `wire_id ≥ 128`). From 3 B to 4 B: the **8192nd** flow opened.
This is a lifetime count: closing a flow does not give the id back, so once a
connection has opened 64 flows, *every* later steady frame is 3 B for the life of
the connection.

**Average header (steady DATA) over a connection that has ever opened N flows**
`(min(N,63)·2 + max(0,min(N,8191)−63)·3 + …)/N` `[derived]`:

| N (flows ever) | avg id bytes | **avg DATA hdr** | avg TRAIN-same hdr | avg dict flow-id | avg FRAG steady hdr | % frames at 2 B |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1.000 | **2.000** | 4.000 | 1.000 | 8.000 | 100 % |
| 63 | 1.000 | **2.000** | 4.000 | 1.000 | 8.000 | 100 % |
| 64 | 1.016 | **2.016** | 4.016 | 1.016 | 8.016 | 98.4 % |
| 128 | 1.508 | **2.508** | 4.508 | 1.508 | 8.508 | 49.2 % |
| 256 | 1.754 | **2.754** | 4.754 | 1.754 | 8.754 | 24.6 % |
| 512 | 1.877 | **2.877** | 4.877 | 1.877 | 8.877 | 12.3 % |
| 1024 | 1.938 | **2.938** | 4.938 | 1.938 | 8.938 | 6.2 % |
| 4096 (the cap) | 1.985 | **2.985** | 4.985 | 1.985 | 8.985 | 1.5 % |
| 8191 | 1.992 | **2.992** | 4.992 | 1.992 | 8.992 | 0.8 % |
| 8192 (local 8192 ⇒ 3 B varint, 4 B header) | 1.992 | **2.992** | 4.992 | 1.992 | 8.992 | 0.8 % |

The same growth hits: TRAIN same-flow header (4→5 B), every dict flow id
(1→2 B), FRAG steady (8→9→10 B), FRAG open/inline id field, and CTL
ACK/REJECT/CLOSE (+1 B each). `[derived]`

**Realistic averages.** With stated assumptions:
- *Steady game/VoIP flow, ≤63 flows ever*: 2 B.
- *Router with one flow per destination, 4096-flow cap*: **2.985 B** (≈3).
- *DNS-heavy connection* (assumption: 25 % OPEN first frames at 15 B, 10 %
  INLINE at 13 B, 65 % steady at 3 B): **7.0 B/payload**.
- *TRAIN-packed multi-assoc small packets*: per-item overhead 2 B (dict,
  idx+len) + 4 B/frame + 1–2 B/flow; 18-item same-flow train of 60 B payloads =
  (4+18·1)/18 = **1.22 B/item** (id<128) or 1.28 B (id≥128).

The README's "2 B for `wire_id < 128`" is arithmetically true (`README.md:83,151`)
but its *steady-state* reading is only true for the first 63 lifetime flows per
endpoint; `README.md:151` states the 64 boundary correctly ("local id below 64").
The 4096-flow-cap connection lives at **≈3 B**, and the table at
`README.md:195-196` omits the 64-boundary row.

### 1.3 The one-packet flow: OPEN vs INLINE vs clean slate

Fixed cost per QUIC packet for IPv4: 55 B L0 (`MQP3_REFACTOR_ANALYSIS.md:146`) +
2 B QUIC DATAGRAM frame = **57 B**; payload 60 B each direction; server reply
compresses to steady DATA after install. `[derived]`

| Path | Uplink | Downlink | Wire bytes | Packets | vs payload |
|---|---|---:|---:|---:|---:|
| **Current, default (OPEN + FLOW_ACK)** | `57+14 = 71` | ACK `57+4 = 61`; reply `57+2/3 = 59/60` | **191–192** | **3** | 120 B → 1.60× |
| Current, INLINE fail-safe | `57+13 = 70` | `57+13 = 70` | **140** | 2 | 1.17× |
| Clean slate (packed id, no ACK, OPEN 6 B = addr-dict hit) | `57+6 = 63` | `57+2 = 59` | **122** | 2 | 1.02× |

The default path is the **OPEN path**: `send_uplink` finds/creates a binding for
every new target before staging (`rev2.rs:758-796`), and the server answers every
successful install with `FLOW_ACK` (`accept.rs:2333-2344`,
`r2_send_ctl` → `try_send_datagram`, `accept.rs:1517-1519`). The INLINE path is
only the table-full/id-exhausted fail-safe.

**Break-even algebra.** Let S = total payload frames on the flow (uplink +
downlink), h = steady header (2 or 3 B), h_open = 14 B, h_ack = 4 B:
- full-wire: `OPEN(S) = (57+14) + (57+4) + (S−1)(57+h) = 73 + (57+h)S` vs
  `INLINE(S) = 70S`. For h=2: `73 ≤ 11S` → **S ≥ 6.64 (7 frames)**;
  h=3 → **S ≥ 7.2 (8 frames)**.
- MQP-header only (ignoring the extra packet's L0/QUIC cost):
  `OPEN = 18 + h(S−1)` vs `13S` → **S ≥ ≈1.5** — i.e. *if the ACK packet were
  free*, OPEN would win immediately. **The 57–61 B fixed cost of the extra
  DATAGRAM is the entire penalty.**

So for every flow that will carry <7 payload frames, OPEN+ACK is worse on the
wire than INLINE — and one-shot DNS queries are exactly that shape. The OPEN
path does buy downlink compression (13 B → 2/3 B) and future uplink saving
(13→2/3 B); the algebra above already includes both. It does *not* include the
server CPU for installing two tables + one ACK send, nor the client dispatch of
the ACK, nor the loss/reorder window where the client keeps re-sending OPEN
(the ACK is the only way to switch to steady before a reply arrives).

**Cheap policy fix (no wire change):** open a flow on the **second** payload for
a target, not the first (INLINE the first, remember "seen once" in a bounded
per-association/connection set). One-shot flows then cost 140 B instead of
192 B (−27 %) and one fewer QUIC packet/send/dispatch; a 2-payload flow costs ~11 B more
(it still pays the ACK, same packet count); ≥7-frame flows are unaffected after
the open. A complementary server-side
rule is to suppress `FLOW_ACK` on first install and send it on the first
**duplicate** OPEN (a duplicate proves the client is still sending) — this keeps
downlink compression, kills the ACK packet for one-shot flows, and costs one
extra 11 B OPEN (`14` vs `3`) on the second uplink frame. `[derived]` +
`[estimate]`.

### 1.4 Steady-state and bulk overhead (where bytes are *not* worth chasing)

| Workload | MQP bytes | total wire (incl. 57 B L0) | MQP share | clean-slate MQP | saving |
|---|---:|---:|---:|---:|---:|
| DNS 60 B steady DATA (id<128) | 2 | 119 | 1.7 % | 1 | 0.8 % of packet |
| DNS 60 B steady DATA (id≥128) | 3 | 120 | 2.5 % | 1–2 | 0.8–1.7 % |
| Steady 128 B flow | 2–3 | 187–188 | 1.1–1.6 % | 1–2 | 0.5–1.1 % |
| Steady 60 B, TRAIN **same** 18 items | 4+18×1 = 22 (2.0 %) | 1159 | — | 22 (early) / 21 (id≥128) | 0–1 B (<0.1 %) |
| FRAG steady, 8 KiB / 8 × 1154 B chunks | 8×8 = 64 (0.78 %) | 8192+8×57+64 = 8712 | 0.73 % | 8×7 = 56 | 8 B (0.09 %) |
| Bulk 1200 B, 1 frame at MTU 1400 | 2–3 | 1259–1260 | 0.2 % | 1–2 | ≤0.2 % |

Bulk and steady flows are at the transport floor: ≤1 B/frame, i.e. **≤0.2 %
wire** for full-MTU payloads. The wire redesign's money is in (a) the
OPEN/ACK/session/address bytes of *short* flows and (b) removing the id-width
cliff; §6 quantifies.

---

## 2. Per-DATAGRAM operation tables

Counts are per frame unless stated. They exclude quinn's AEAD/packet assembly
(transport, not MQP), but include the quinn API costs the MQP layer pays
(`read_datagram`/`send_datagram_wait` take quinn's connection-state mutex every
call — `send.rs:80-83`, `quinn-0.11.12/src/connection.rs:823,858`). "RMW" =
atomic read-modify-write (cache-line-locked on x86); "ld" = plain/relaxed load.

### 2.1 Receive — one steady DATA frame, server ingress (hot path)

Route: `read_datagram` → `is_v3`/`is_r2` → `handle_r2_ingress` → `kind` →
`r2_dispatch_frame` → `kind` → `r2_ingress_data` → `decode_data` →
`slice_ref` → `udp_stats::payload` → `registry.get` → `try_stage` →
`flush_staged_sends` (`accept.rs:3006-3040,2645-2748,2355-2434,1973-2005`).

| Step | alloc | memcpy | locks | RMW | ld/st | syscall |
|---|---:|---:|---:|---:|---:|---:|
| quinn `read_datagram` poll | 0 (view of quinn's buf) | 0 | 1 quinn Mutex | ≈2 | queue pop | recv amortised by driver |
| first-byte classify ×3 | 0 | 0 | 0 | 0 | 3 byte loads | 0 |
| `r2::decode_data` | 0 | 0 | 0 | 0 | 1–5 byte loads | 0 |
| `d.slice_ref(payload)` `accept.rs:2377` | 0 | 0 | 0 | **1** (refcount) | | 0 |
| `udp_stats::payload(len)` `:2378` | 0 | 0 | 0 | 0 (256-batched) | 4 TLS cells + 1 coarse-clock ld | 0 |
| `registry.get(id)` `:1935` | 0 | 0 | **1 parking_lot RwLock read** | 2 lock + **1 Arc clone** | 1 hash calc | 0 |
| `state()`,`target_ip()` | 0 | 0 | 0 | 0 | 2 ld | 0 |
| `try_stage` fast path `accept.rs:475-…` | 0 | 0 | 0 (fast slot hit) | 2 (`Weak::upgrade`) | 3–5 ld + 1–64 slot compares | 0 |
| staging push | 0 (Vec prealloc 32) | 0 | 0 | 0 | | 0 |
| `flush_staged_sends` sendmmsg | 0 | **0** (iovec to target) | 0 | refcount drops | | **1 per (sock,dst) run; 1/≤32 payload** |
| **total** | **0 heap** | **0 payload copies** | **2** (quinn + registry) | **~7** | ~10 | **≈1/32** |

### 2.2 Receive — one steady DATA frame, client downlink

Route: `reader.read_datagram` → `is_r2` → `dispatch_r2` → `kind` →
`dispatch_r2_data` → `decode_data` → `registry.get` → `mark_open` →
`reply_src()` → `r2_lookup` → `stage_reply` → `flush_staged`
(`dispatcher.rs:1528-1598,1405-1426,1061-1148,733-814,161-218`).

| Step | alloc | memcpy | locks | RMW | ld/st | syscall |
|---|---:|---:|---:|---:|---:|---:|
| quinn `read_datagram` | 0 | 0 | 1 quinn Mutex | ≈2 | | recv amortised |
| classify ×2 | 0 | 0 | 0 | 0 | 2 ld | 0 |
| `decode_data` | 0 | 0 | 0 | 0 | | 0 |
| `registry.get(id)` `:1095,:1322` | 0 | 0 | **1 RwLock read** | 2 lock + 1 Arc clone | | 0 |
| `binding.mark_open()` `:1135` | 0 | 0 | 0 | **1 CAS (always)** | | 0 |
| `reply_src()` `r2_flow.rs:184-186` | 0 | 0 | 0 | 0 | ArcSwapOption ld (≈1–2) | 0 |
| `r2_lookup` `dispatcher.rs:161-218` | 0 | 0 | 0 | **2** (`Weak::upgrade`) | 2 ld | 0 |
| `stage_reply` `:101-116` | 0 | 0 | 0 | **1** (relay Arc clone) | 1 st (`mark_replied`) | 0 |
| `slice_ref(payload)` `:1144` | 0 | 0 | 0 | **1** | | 0 |
| `udp_stats::payload` | 0 | 0 | 0 | 0 | 4 TLS + clock | 0 |
| `counters::rx_frame` | 0 | 0 | 0 | 0 | TLS cell | 0 |
| `flush_staged` header encode + sendmmsg | 0 | ≤22 B header | 0 | refcount drops | | **1 per run (≤32)** |
| **total** | **0 heap** | **≤22 B** | **2** | **~9–10** | ~12 | **≈1/32** |

### 2.3 Receive — one TRAIN frame (server; client is the same shape)

Server: `decode_train` (eager validation pass) + a hash-dedupe pass over
`items()` + `get_batch` (one lock for all ids) + dispatch pass over `items()`
again (`accept.rs:2450-2514`). Client: same two `items()` passes + per-session
run memo (`dispatcher.rs:1191-1286`).

| Step | per frame | per item | evidence |
|---|---|---|---|
| eager item validation (varint len + bounds) | count × (1 varint + bounds) | 1 varint decode | `r2.rs:633-650` |
| `TrainFrame` by-value return | 280 B stack (1+1+1+256+16) | — | `r2.rs:531-538` |
| `items()` construction | **256 B memcpy** (flows array) | — | `r2.rs:543-550` |
| second `items()` for dispatch | **256 B memcpy** | — | `accept.rs:2477,2497`; `dispatcher.rs:1203,1240` |
| dedupe open-addressing pass | 64×u16 + 128×u16 stack arrays | 1 hash + 1–2 probes | `accept.rs:2470-2495` |
| `get_batch` | 1 RwLock read | 1 hash probe + 1 Arc clone per distinct id | `r2_flow.rs:601-606` |
| `bump_train_item` + `udp_stats::payload` | — | 2 TLS-cell records | `accept.rs:2498-2499` |
| `d.slice_ref(item)` | — | **1 RMW** | `accept.rs:2500` |
| forward + `try_stage` | — | 2 RMW (`Weak::upgrade`) + compares | `accept.rs:2502-2513` |
| alloc | **0** | 0 | |
| payload copies | **0** | 0 (Bytes views → sendmmsg iovec) | `accept.rs:251-286` |
| locks | **1 RwLock read** (+ quinn) | 0 | |
| syscall | 1 sendmmsg / run | 0 | |

Measured decode cost is in `rev3_bench` (§7); the double pass + array copies are
priced there directly against a single-pass reference decoder.

### 2.4 Receive — FRAG (per fragment, server or client reassembler)

`r2::decode_frag` (`r2.rs:798-860`) + `R2Reassembler::push` (`r2_reasm.rs:360-643`).

| Operation | per fragment | evidence |
|---|---|---|
| decode | 1–2 varints + bounds; **0 alloc** | `r2.rs:798-859` |
| single-fragment payload | **0 copies** (view of the frame `Bytes`) | `r2_reasm.rs:417-425` |
| inline/OPEN context | `addr.into_owned()` → **String alloc for a domain**, per fragment | `r2_reasm.rs:397-403` |
| partial lookup | **2–3 hash probes**: `contains_key` + `get`, then `entry` for new | `r2_reasm.rs:430-431,527-530` |
| multi-fragment chunk | **1 memcpy** into the assembly buffer (or 1 alloc+copy as `PendingChunk` when out of order) | `r2_reasm.rs:231-247,584-595` |
| retained accounting | `recompute_retained()` per fragment (sum over pending + capacities) | `r2_reasm.rs:284-292,603-607` |
| order deque | push + `prune_orders()` integer compare | `r2_reasm.rs:617-625` |
| completion | `Bytes::from(buf)` — **no second copy** | `r2_reasm.rs:631-642` |
| locks | 0 (reader task owns `&mut R2Reassembler`) | |
| stats | 1 payload booking per completed payload (`accept.rs:2556`) | |

### 2.5 Receive — CTL

| Opcode | operations | cost |
|---|---|---|
| HELLO | `decode_ctl` (0 alloc) + `mark_hello` store + `caps_due` check + maybe `set_caps` (**RwLock write**, once) + encode+send CAPS (1 alloc) | one-time |
| CAPS | `decode_ctl` + `ctl.set_caps` RwLock write + 2 atomic stores + `stager.lock().set_max_train_items` | one-time |
| FLOW_ACK | `decode_ctl` + `registry.get` (RwLock + Arc clone) + 2 stores | 1 lock/frame |
| FLOW_REJECT/CLOSE | `r2_remove_flow`: registry **write** lock + by_session index write lock + `rcu` clone of the whole 64-slot `SessionFlows` (alloc + 512 B copy) + `SessionFlows::remove` scan + reasm retain scan + stager lock | cold, rate-capped |
| SESS_CLOSE | CTL rate Mutex (`r2_flow.rs:857-868`) + 2 DNS-cancel maps + reasm retain + stager lock + session shard **write** lock + registry by_session/map **write** locks + reader abort | cold, rate-capped (`CTL_MAX_PER_SEC = 8192`) |

`FLOW_CLOSE`/`FLOW_REJECT`/`SESS_CLOSE` are rate-limited
(`r2_flow.rs:810,857-868`, `accept.rs:1814-1821`) — they are not a per-frame
worry; the *per-frame* CTL is FLOW_ACK.

### 2.6 Send — client uplink, staged small payload (≤512 B, the common shape)

Route: `send_uplink` → `ensure_binding` → `Bytes::copy_from_slice` →
`push_stage` (stager Mutex) → later `drain_staged` → `pack_batch` (stager Mutex)
→ `encode_data_steady`/`encode_train_dict` → `send_packed_frames` →
`try_send_datagram` (quinn Mutex) (`rev2.rs:733-805,1046-1131`,
`r2_stage.rs:944-1000,841-889`).

| Step | alloc | memcpy | locks | RMW |
|---|---:|---:|---:|---:|
| `ensure_binding` memo hit `rev2.rs:1052-1058` | 0 | 0 | 0 | 2 (Arc clone/drop) |
| `frame_limit` | 0 | 0 | 0 | 0 (u16 ld) |
| `addr.header()` validate | 0 | 0 | 0 | 0 |
| `Bytes::copy_from_slice(payload)` `:774,794` | **1** | **1** (payload) | 0 | refcount init |
| `push_stage` `:264-266` | 0 | 0 | **1 parking_lot Mutex** | 2 |
| drain: `pack_batch` | 0 | 0 | **1 Mutex** | 2 |
| drain: frame encode (`Vec` exact + `Bytes::from`) | **1** | **1** (payload into frame) | 0 | refcount init |
| drain: `try_send_datagram` | 0 | 0 | **1 quinn Mutex** | ≈2 |
| quinn TX `Datagram::encode` (driver task) | 0 | **1** (frame→packet) | — | — |
| `udp_stats::payload` on Sent | 0 | 0 | 0 | 4 TLS + clock |
| **total** | **2 allocs** | **3 payload copies** | **3** | ~10 |

Staging itself is cheap; the CPU is: 2 allocations, 3 copies, 3 locks, ~10 RMW
per payload. Encoder cost (`frame_bench`-calibrated): an exact 128 B frame costs
**15–19 ns** same-thread (alloc + header+payload copy + `Bytes::from` + free);
at 1200 B, 25 ns same-thread / 51–53 ns cross-thread `[measured]`
(`frame_bench.rs:17-25`). Copying into quinn's packet is the third copy and is
unavoidable through `send_datagram` (`send.rs:66-69` documents it:
"Bytes are copied per datagram regardless (quinn assembles each datagram frame
with `extend_from_slice`)").

### 2.7 Send — the other four shapes

| Shape | allocs | payload copies | locks | syscall |
|---|---:|---:|---:|---|
| Standalone DATA steady (`try_single_data` `rev2.rs:964-998`) | 1 (frame) | 2 (payload→frame, frame→packet) | 1 quinn | driver |
| DATA OPEN / INLINE standalone (`encode_data_open/inline`) | 1 | 2 | 1 quinn | driver |
| FRAG (`r2_frag.rs:146-285`) | **1 per fragment** | **2 per fragment** | **1 quinn Mutex per fragment** (`try_send_datagram` `:247`) + `datagram_send_buffer_space()` only after a Blocked/aggregate gate (`:197-210`) | driver |
| CTL (`r2_send_ctl` `accept.rs:1517-1519`) | 1 | 1 | 1 quinn | driver |
| SESS_CLOSE ×3 (`accept.rs:1533-1539`) | 3 | 3 | 3 quinn | driver |

Note there is no per-frame `sendmsg` syscall in the app: `try_send_datagram`
queues into quinn's DATAGRAM buffer and the connection driver batches packets
(quinn may coalesce several DATAGRAM frames per UDP packet). The per-frame cost
here is the quinn state mutex + the copy into the packet.

### 2.8 Where the CPU actually goes (per steady DATA frame, app-level)

Using the table costs above plus the in-repo baselines (coarse clock 1.44 ns,
mono 3.26 ns — `PERF_ANALYSIS.md:463`; 128 B frame 15–19 ns —
`frame_bench.rs:17-25`) `[estimate]`:

| Component | client downlink | server ingress |
|---|---:|---:|
| quinn `read_datagram` poll + state mutex | 5–15 ns | 5–15 ns |
| first-byte classify | 1–2 ns | 2–4 ns |
| **`r2::decode_data` (the codec parse)** | **2–6 ns** | **2–6 ns** |
| registry lookup (lock+hash+Arc) | 10–20 ns | 10–20 ns |
| binding state atomics (`mark_open` CAS etc.) | 5–10 ns | 1–2 ns |
| session/association lookup (Weak upgrade + Arc) | 5–10 ns | 3–8 ns |
| stats (`payload`, `rx_frame`, counter cells) | 3–6 ns | 2–5 ns |
| staging + header encode + sendmmsg (amortised) | 6–15 ns | 6–15 ns |
| **≈ total MQP layer** | **40–80 ns** | **35–75 ns** |

So the **codec parse is ~5–10 % of the per-datagram app cost**; the state
plumbing (registry/session/Arc/atomics) and quinn's per-call mutex dominate. The
encoder is a bigger share of the send path (§2.6: 15–19 ns of a ~60–90 ns staged
send, ~20–30 %), half of which is the one allocation + the necessary payload
copy.

---

## 3. Findings (P1…P16)

Each finding: mechanism → decisive `file:line` → cost → fix → confidence.
Rejected designs from `MQP3_REFACTOR_ANALYSIS.md:79-92` are **not** re-proposed
(frame pooling, u16 fragment id, MTU default, BATCH N-pack, cross-session TRAIN
as a pure win).

### P1 [wire, high confidence] The 2 B→3 B id-width cliff at 63 lifetime flows

- Mechanism: LEB128 `wire_id` with monotone, never-reused ids. The 64th flow an
  endpoint opens ⇒ `wire_id=128` ⇒ 3 B steady header forever; 8192nd ⇒ 4 B.
  `r2.rs:143-148` (`Some((local_id << 1) | u32::from(server_owned))`),
  `r2.rs:172-179` (`while n >= 0x80 { n >>= 7; len += 1; }`),
  `r2.rs:275-277` (`1 + varint_len(id) + payload_len`).
- Cost: +1 B on every steady DATA/TRAIN-same-header/dict-flow-id/FRAG header for
  the rest of the connection's life; a 4096-flow connection averages 2.985 B.
  For a DNS-class 60 B payload that is 1.7 %→2.5 % of MQP, ~0.8 % of the QUIC
  packet — small per packet, but permanent and unbounded by the live cap.
- Fix (wire): packed kind+id header — 1 B when the id fits beside the kind
  (~15–31 flows/owner), **2 B for the whole 8192-wire-id/4096-flow space**
  (3 kind bits + 13 id bits), no growth. §6.
- Alternative fix (no wire change): make `FlowIds` return dense ids from a
  free-list plus a generation bit, so a connection with ≤63 **live** flows keeps
  1-byte ids forever. Requires safe reuse: close must be confirmed (CTL
  FLOW_CLOSE + ACK) and ids quarantined ≥ the max DATAGRAM reorder window (2 s,
  same as `FRAG_TIMEOUT_MS`) so a late frame cannot hit a new flow. The
  repository deliberately chose never-reuse to avoid tombstones
  (`r2_flow.rs:17-19`, `README.md:151`); with a control-plane ACK and a
  generation bit this is safe, but it is a state-machine change, not a codec
  change. **Recommend the packed-header option** (no state risk).

### P2 [CPU, high confidence] TRAIN decode double pass + two 256 B by-value arrays

- `decode_train` validates every item eagerly (`r2.rs:633-650`: "Validate items
  eagerly: every length must fit inside the frame"), then `TrainItems::next`
  re-decodes the same varints (`r2.rs:560-584`). `TrainFrame` stores
  `flows: [u32; R2_MAX_TRAIN_ITEMS]` (`r2.rs:536`, 256 B) and `items()` copies
  it into `TrainItems` (`r2.rs:543-550`: `flows: self.flows`); `TrainItems` also
  embeds the array (`r2.rs:556`). Both endpoints call `items()` **twice**
  (dedupe pass + dispatch pass): `accept.rs:2477` and `:2497`;
  `dispatcher.rs:1203` and `:1240`.
- Cost `[estimate]`: ~280 B return copy + 2×256 B + one extra item pass per
  frame. Measured by `rev3_bench` against a single-pass reference decoder; the
  expected shape is ~10–40 ns/frame at 64 items (0.2–0.6 ns/item) for the array
  copies + ~1–2 ns/item for the second parse.
- Fix: `TrainFrame::items(&self) -> TrainItems<'_, 'a>` borrowing `&'f [u32]`
  (no copies), and validate lazily during iteration (like `decode_batch`'s
  "validate then iterate lazily" alternative) or store item offsets from the
  validation pass to skip re-decoding varints. The encoder/decoder symmetry
  tests are unchanged; only the array ownership moves.

### P3 [CPU, med-high] TRAIN encode: two O(n²) dedupe scans + 1 KiB stack init + hashmap build, under the stager lock

- Stager: `let new_flow = !unique.contains(&wire_id);` per item
  (`r2_stage.rs:593`) — O(flows) per item, O(flows²) per frame;
  `let mut items: [(u8, &[u8]); r2::R2_MAX_TRAIN_ITEMS] = [(0, &[]); …]`
  (`r2_stage.rs:643`) zero-initializes 1 KiB per frame; `flow_idx` foldhash map
  insert per flow (`r2_stage.rs:639-642`); all inside the stager `Mutex` held by
  `pack_one_frame` (`r2_stage.rs:444-556`).
- Codec: `encode_train_dict` → `train_dict_len` → `valid_train_flows` repeats
  the uniqueness check in O(nfl²) (`r2.rs:466-487`, decisive line
  `if !valid_wire_id(*f) || flows[..i].contains(f)` at `r2.rs:477`) and
  `train_dict_len` walks every item for `varint_len` (`r2.rs:451-455`), then the
  encoder walks everything again (`r2.rs:507-527`). The **decoder** repeats the
  same O(nfl²) uniqueness check (`r2.rs:615-621`:
  `flows[..i].contains(&id)` per flow) on every dict train received.
- Cost `[estimate]`: nfl=64/64 items ≈ three O(n²) scans (encoder stager
  dedupe + codec validation + decoder validation) = 3×2016 u32 compares + 64
  hashmap inserts + 1 KiB memset + 2 varint passes ≈ **0.3–1.2 µs/frame**
  worst case (encoder share under the lock); nfl=2–8 typical ≈ 15–60 ns/frame
  and not worth special-casing. This is the only O(n²) on the data plane.
- Fix: a trusted encoder entry point that skips `valid_train_flows` (the stager
  already guarantees unique flows and in-range indices by construction), and
  make the stager use the `flow_idx` map it already builds to do dedupe in O(1)
  instead of `unique.contains`. Keeps the wire bytes identical (pinned by
  `train_dict_keeps_one_slot_per_flow_and_item_order`, `r2_stage.rs:1086-1105`).

### P4 [CPU, high confidence] `mark_open()` unconditional CAS per downlink frame

- `r2_flow.rs:146-153`: `self.state.compare_exchange(Opening, Open, Relaxed,
  Relaxed)` executes regardless of state. Called per downlink DATA
  (`dispatcher.rs:1135`), per FRAG completion (`:1351`), per distinct TRAIN id
  (`:1253`), per FLOW_ACK (`:995`).
- Cost `[estimate]`: 1 locked RMW ≈ 5–15 cycles (~2–4 ns) per frame that is a
  no-op after the first. Fix: `if self.state.load(Relaxed) == Opening { CAS }`
  (or `store(Open)` behind a `!= Closed` load). The `Closed`-never-reopens
  invariant is preserved because only `Opening` takes the CAS.

### P5 [CPU, med-high] Server reply path scans up to 64 bindings per reply (`match_source`), legacy memo dropped

- `reader.rs:1044`: `let mut r2_match = r2.flows.load().match_source(src)…` runs
  for **every** reply, before the small/large split.
- `r2_flow.rs:325-366` (`match_source`): one pass over
  `entries.iter().flatten()` (up to 64), each candidate does
  `b.reply_src()` = `ArcSwapOption::load` (`r2_flow.rs:184-186`) + a
  `reply_src_acked()` load (`:179-181`) + target compares; a domain candidate
  adds `resolved_contains` = `ArcSwap` load + up to 16 compares
  (`r2_flow.rs:221-223`).
- The legacy v3 stager has a one-entry memo for exactly this
  (`reader.rs:134-155`: `last_flow: &mut Option<(SocketAddr, u8)>`); the rev2
  `R2ReplyState` (`reader.rs:197-212`) kept only the table handle.
- Cost `[estimate]`: n=1 flow (steady single-target): ~3–6 ns; n=8: ~20–40 ns;
  n=64: ~120–250 ns **per reply**; plus one `Arc` clone of the matched binding.
- Fix: memoise `(src, Arc<FlowBinding>)` in `R2ReplyState` (1 `SocketAddr`
  compare on hit, invalidated when the accepted flow set changes or the binding
  is closed), or key a small reverse map by the packed reply source. The
  single-pass "learned reply_src wins over target" semantics
  (`r2_flow.rs:309-366`) must be preserved on a miss.

### P6 [CPU, med] `FlowRegistry` lock+hash per frame; direct-indexed table alternative

- `r2_flow.rs:436-441`: `map: RwLock<HashMap<u32, Arc<FlowBinding>, foldhash…>>`
  plus a `by_session` index and an atomic server-flow count. `get` =
  `self.map.read().get(&wire_id).cloned()` (`:587-589`). Called per DATA frame on
  the client downlink (`dispatcher.rs:1095,1322`), per single-frame/FRAG
  completion on server ingress (`accept.rs:1935`), and once per TRAIN via
  `get_batch` (`:2496`).
- Cost `[estimate]`: uncontended parking_lot read+release ≈ 2 RMW (≈5–10 ns) +
  foldhash ≈1–2 ns + probe + `Arc` clone/drop ≈ 2 RMW → **10–20 ns/frame**.
  Uplink `ensure_binding`/`insert_new` are cold (write lock only on new flows)
  so contention is not the issue; the per-frame latency is.
- Fix: **direct-indexed slot table** (details and memory math in §4):
  mask + full-id compare + `Arc` clone ≈ **2–4 ns** (`rev3_bench` measures
  both). 16 B/slot × 8192 slots = 128 KiB/connection worst case; index by
  `wire_id` (or `local_id` with a full-id compare) and grow lazily with
  `FlowIds::allocated()` so a 64-flow connection uses 1–2 KiB. This is ~28×
  smaller than the current 4096×904 B admission charge (`README.md:404`) and
  removes a shared cache line from the per-frame path.

### P7 [CPU, med] Uplink target lookup: single-slot memo over a 64-slot linear scan

- `rev2.rs:1052-1058` memo; on a miss `flows.find(addr)`
  (`rev2.rs:1061`) = `r2_flow.rs:291-297`
  `entries.iter().flatten().find(|b| b.target.as_ref() == *addr).cloned()`.
- The memo only hits when consecutive payloads share the exact target. The
  `udpfanout`/`udpdomain` shapes alternate targets, so they miss every packet and
  pay O(positions) `TargetAddr` compares (a `String` compare for domain targets)
  plus one `Arc` clone/drop on the match. `[estimate]` n=8 → ~4 compares +
  Arc ≈ 10–20 ns/payload; n=64 → ~30–80 ns.
- Fix: replace the array scan with a foldhash `HashMap<TargetAddrRef…>`-keyed
  map for the session's ≤64 flows (or a 4-slot MRU memo for the common 2–4
  target shapes). The memo is still worth keeping as the first-level hit.

### P8 [CPU, high confidence] Redundant first-byte classification per frame

- Server: `is_v3(&d)` (`accept.rs:3009`) → `r2::is_r2(&d)` (`:3027`, which calls
  `kind`) → `r2::kind(&d)` in `handle_r2_ingress` (`:2656`) → `r2::kind(&d)` in
  `r2_dispatch_frame` (`:2724`); plus `d.get(1)` for the HELLO check (`:2663`).
  Client: `r2::is_r2` (`dispatcher.rs:1441`) → `r2::kind` (`:1414`).
- Cost: 2–4 first-byte loads/branches per frame, ~1–3 ns `[estimate]`; trivial,
  but it is pure avoidable work on every packet. Fix: classify once in the reader
  loop and pass `R2Kind` (or the decoded frame) down. Also removes the
  `kind()` double-match in `decode_*` if the dispatcher pre-decodes.

### P9 [CPU, med] Staged small payloads pay an extra allocation + copy

- Client uplink: `payload: Bytes::copy_from_slice(payload)` when staging
  (`rev2.rs:774,794`); server downlink: same (`reader.rs:1111`). Then the drain
  copies the payload again into the frame (`encode_*` `extend_from_slice`) and
  quinn copies the frame into the TX packet (`send.rs:66-69`).
- Cost `[estimate]`: `Bytes::copy_from_slice(128 B)` ≈ alloc+copy ≈ 10–16 ns
  (~15–20 % of the staged-send path); 3 copies per staged payload.
- Fix (design, not pooling): let the push stage the payload **directly into a
  per-connection pending-frame buffer** (encode header+payload at push), so the
  drain freezes one `Bytes`; removes one alloc + one copy. Constraints: the
  current requeue/drop accounting is per item and per frame
  (`r2_stage.rs:131-151,764-787`); a monolithic frame loses per-item ownership
  for `requeue_unsent`/`drop_flow`, so this only works if the pending buffer
  records `(offset,len)` per item and the drop paths count from that. **Not**
  the rejected frame-pool design (`frame_bench.rs:6-25`): this is one exact
  `Vec`/`BytesMut` per frame, same as today, just filled earlier and once.
  Risk: medium; do it only after the cheap wins.

### P10 [CPU/wire, med] `set_reply_src` allocates an `Arc<SocketAddr>` per rebind; `reply_src` is an ArcSwap load

- `r2_flow.rs:166-169`: `self.reply_src.store(Some(Arc::new(src)))` — one
  allocation for a 32-bit-address value, on every server rebind
  (`reader.rs:1117-1119` after a sent `OPEN|SRC`) and every client
  `OPEN|SRC` (`dispatcher.rs:1129,1361`). `reply_src()`
  (`r2_flow.rs:184-186`) is an `ArcSwapOption` load per candidate in
  `match_source`, i.e. per candidate *per reply*.
- Fix: store the address in `AtomicU64` for IPv4 (pack ip+port) and fall back to
  `ArcSwapOption` only for IPv6, or keep `ArcSwap<SocketAddr>` without the Option
  and a separate "unset" sentinel; removes the rebind allocation and makes the
  common load a plain 8 B relaxed load. Rebinds are not per-packet, so this is a
  small win mostly in code simplicity.

### P11 [wire/CPU, high confidence] `put_addr` zero-fills the address then overwrites it

- `r2.rs:250-255`:
  ```rust
  fn put_addr(out: &mut Vec<u8>, addr: &AddrHeader<'_>) {
      let start = out.len();
      out.resize(start + addr.len(), 0);
      let n = addr.encode_into(&mut out[start..]);
  ```
  `Vec::resize` memsets `addr.len()` bytes that `encode_into` immediately
  overwrites. On OPEN/INLINE/FRAG-open/frag-inline encodes this is 7/19/(4+L) B
  of dead stores `[code]`.
- Fix: write into the Vec's spare capacity (`spare_capacity_mut` + `set_len`) or
  build the header in a stack `[u8; AddrHeader::MAX_LEN]` and `extend_from_slice`
  once (one 7–259 B copy instead of a memset+copy). ~1 ns/OPEN, trivial but free.

### P12 [CPU, high confidence] Encoders traverse every varint twice (`varint_len` then `put_varint`)

- `r2.rs:172-187`: `varint_len` loop, then `put_varint` loop; called from
  `data_steady_len`+`encode_data_steady` (`:275-305`), all OPEN/INLINE/FRAG
  encoders, and `train_*_len`+`encode_train_*`. For a 1–3 byte id that is 2–6
  loop iterations instead of 1–3.
- Fix: encode the varint once into a stack `[u8; 5]`, take `n` as the length, and
  use it for the exact `Vec::with_capacity` (the same one-allocation property
  `Bytes::from(Vec)` relies on — `frame_bench.rs:6-25`). `[estimate]` 1–2 ns per
  encoded frame; measured by the `ref_encode_data_steady` cell.

### P13 [CPU, med] Per-payload stats read the coarse clock on every record

- `udp_stats::payload` (`udp_stats.rs:140-172`) does 3 thread-local cell updates
  + `L_MAX_SEEN` compare + `maybe_time_publish()` (`:89-97`) which calls
  `coarse_millis()` = `OnceLock` load + quanta atomic load (`src/time/coarse.rs:47-57`).
  Called per payload on both ends (`accept.rs:2378,2499,2556`; client
  `dispatcher.rs:1089,1145,1270,1279,1392`).
- Cost `[estimate]`: ~2–5 ns/payload. Not worth restructuring; the only cheap
  tweak is checking the time gate once per N records behind an existing count
  cell (saves ~1–2 ns/payload) — low priority.

### P14 [CPU, med] FRAG reassembler: 2–3 hash probes per fragment, retained recompute, context clone

- `r2_reasm.rs:430-431`: `contains_key` + `get` (2 probes) then `entry`
  (`:527-530`) = 3 probes for the first fragment, 2 for middles; per-fragment
  `recompute_retained()` (`:603`) walks the pending list and reads capacities;
  `incoming` builds `addr.into_owned()`/`FragCtx` (`:397-408`) and clones it into
  the partial (`:530-533`).
- Cost `[estimate]`: ~2–5 ns/fragment + 1 String alloc for a domain inline
  context per fragment. For 8 KiB payloads at ~1150 B chunks (8 fragments) that
  is ~20–50 ns per payload — negligible against 8 KiB of copying, but it is on
  the peer-controlled path. Fix: single `entry` lookup for existing partials
  (check `idx` bounds after the lookup), splice the fragment without
  `contains_key`, and store an `Arc<FragCtx>` instead of cloning / compare
  borrowed `TargetAddrRef` before `into_owned`.

### P15 [wire/CPU, low] `slice_ref` per frame (1 refcount RMW) and quinn-owned frame view

- `accept.rs:2377`, `dispatcher.rs:1088,1144,1272,1281` each do
  `d.slice_ref(f.payload)` — one refcount RMW per frame to create the payload
  view. `[estimate]` 1–3 ns. Fix only if the staging structs can carry
  `(frame: Bytes, off, len)` instead of a new `Bytes` (the stager needs owned
  payloads across tasks; the ingress `StagedSend` could carry the frame + offset
  because it is consumed within the same burst). Medium effort, low payoff.

### P16 [wire, med] Fragmented INLINE/OPEN repeats `sess u32` + full address on every fragment

- `r2_frag.rs:15-17` documents the INLINE form: "every fragment carries `INLINE` +
  `sess u32 + addr`". Wire cost per fragment: 19 B IPv4 / 31 B IPv6 / 16+L B
  domain (`r2_frag.rs:337-344` golden tests), versus 8–9 B steady. On an 8 KiB
  payload split into 8 chunks that is ~88–248 B extra (~1–3 % of the payload).
- This is the fail-safe path (no flow id): the clean fix is a **u16 session
  index + connection-level address dictionary** in the extended header (§6),
  which also collapses the `DATA OPEN` and `DATA INLINE` headers. CPU-wise, the
  inline path also pays `into_owned()` per fragment (P14/W4).
- Whether to keep FRAG for large payloads at all: see §8 answer — yes for UDP
  semantics; do not move bulk to a reliable stream.

---

## 4. Registry / session-table analysis and the direct-indexed alternative

### 4.1 Current structures (`[code]`)

| Structure | Shape | Per-packet cost |
|---|---|---|
| `FlowRegistry` (`r2_flow.rs:436-441`) | `RwLock<HashMap<u32, Arc<FlowBinding>, foldhash::fast>>` + `RwLock<HashMap<u32, Vec<u32>>>` (by-session index) + `AtomicUsize` server-flow count | `get`: 1 RwLock read (2 RMW) + hash (1–2 ns) + probe + `Arc` clone; `get_batch` (TRAIN): one lock for all ids (`:601-606`) |
| `SessionFlows` (`r2_flow.rs:240-406`) | `[Option<Arc<FlowBinding>>; 64]` (512 B) + linear scans | `find` O(flows) target compare + `Arc` clone; `match_source` one-pass O(flows) with 2 atomic loads/candidate (plus up to 16 resolved compares for domain flows) |
| `SessTable` (`server/table.rs:13-76`) | 8 shards × `RwLock<HashMap<u32, SessEntry, foldhash>>`; per-connection 64-slot `FastSess` linear-probed table (`accept.rs:288-348,386-397`) | steady ingress: fast slot hit = a few compares + `Weak::upgrade` (2 RMW), no shard lock; slow path: one shard read lock |
| `FlowBinding` (`r2_flow.rs:84-118`) | wire id, session, owned `TargetAddr`, `AtomicU8` state, `ArcSwapOption<SocketAddr>` reply_src, `AtomicBool` acked, `ArcSwap<Vec<SocketAddr>>` resolved | state load per frame; reply_src load per candidate (reply path); resolved load per candidate (domain reply path) |
| `FlowIds` (`r2_flow.rs:743-778`) | `AtomicU32` monotone | one `try_update` per new flow (cold) |

Memory budget: documentation charges 4096 × 904 B = 3.53 MiB per connection for
registry capacity (`README.md:404`). The `HashMap` itself is ~16 B/bucket ×
1.14 load factor ≈ 18 B/entry for `(u32, Arc)` + the `Arc<FlowBinding>` body
(owned target ~32–40 B, atomics, two atomics-sized `ArcSwap` handles ≈ 80–100 B)
+ by-session `Vec` entries (4 B) + the per-session reverse tables (512 B per
session, not per flow — a 4096-flow connection with 64 sessions pays 32 KiB).

### 4.2 Direct-indexed plan (wire-compatible today, natural for rev3)

**Observation:** the live-flow cap is 4096/connection and `wire_id = 2·local +
owner`, so the **live id set is bounded by 8192 wire ids**; only the monotone
allocation can push ids beyond it over the connection's lifetime.

**Table:** `Vec<Option<(u32, Arc<FlowBinding>)>>` — 16 B/slot (`Arc` niche means
`Option<Arc>` alone is 8 B; the `(u32, Arc)` pair is 16 B; the stored `u32` is
the **full** `wire_id`, so a stale frame whose index aliases a new flow fails the
compare — the never-reuse safety no longer depends on the index).
- index = `wire_id as usize & (CAP-1)` (or `local_id & (CAP-1)` with the full-id
  compare), CAP = 8192 → 128 KiB worst case/connection; CAP = 4096 with
  `wire_id >> 1` indexing → 64 KiB.
- **Grow lazily** with `FlowIds::allocated()` (next power of two, start 64 slots
  = 1 KiB): a 64-flow connection pays 1 KiB, not 64 KiB. When the connection
  would exceed the CAP, fall back to the current `INLINE` fail-safe for new
  flows (or keep a small overflow hash map); either way the *bounded* worst case
  is 128 KiB, ~28× below the current 3.53 MiB charge.
- **Concurrency:** one `RwLock` for insert/remove + per-slot `ArcSwapOption` (or
  a plain `AtomicPtr` with the binding kept alive elsewhere) for lock-free
  reads. The client's dispatcher is one task per connection, but the *uplink*
  `ensure_binding`/`insert_new` runs from every association task on the same
  connection, so a single global registry lock is also a cross-core cache line;
  per-slot handles remove it from the lookup path entirely.
- **Cost:** mask + one load + full-id compare + `Arc` clone ≈ **2–4 ns** vs
  **10–20 ns** for lock+hash (measured side-by-side in `rev3_bench`,
  `bench_registry`).

**SessionFlows alternatives:**
- `find` (uplink target → id): foldhash `HashMap` keyed by the target with ≤64
  entries, or a 4-slot MRU memo for the 2–4 target shapes. `[estimate]`
  10–80 ns → 2–6 ns per payload on multi-target sessions.
- `match_source` (server reply): memo `(SocketAddr, Arc<FlowBinding>)` in
  `R2ReplyState` (steady 1-flow session: one compare), falling back to the
  current single-pass scan only on a memo miss; keep a reverse map only if
  profiles show many flows/session. This is exactly the memo the legacy v3 path
  keeps (`reader.rs:134-155`).

---

## 5. Cheap wins vs wire redesign

### 5.1 Cheap wins (no wire change; ordered by payoff/risk)

| # | Change | Est. saving | Confidence | Evidence |
|---|---|---|---:|---|
| C1 | TRAIN: single-pass iterate, borrow flow list (no 256 B copies) | 10–40 ns/TRAIN + 1–2 ns/item | high | P2, `rev3_bench` vs `ref_*` |
| C2 | TRAIN encode: trusted path + reuse `flow_idx` for dedupe (drop 2×O(n²)) | 15–40 ns/typical frame; 0.3–0.7 µs/64-flow frame (lock hold shrinks) | med-high | P3 |
| C3 | `mark_open`: load-then-CAS | 2–5 ns/downlink frame & per distinct TRAIN id | high | P4 |
| C4 | Server reply-source memo | 20–200 ns/reply for n≥8 flows/session | med-high | P5 |
| C5 | Registry direct table | 8–15 ns/frame | med | P6, §4 |
| C6 | Uplink target map / 4-slot memo | 10–80 ns/payload on multi-target | med | P7 |
| C7 | Classify first byte once | 1–3 ns/frame | high | P8 |
| C8 | Policy: INLINE-first, OPEN on 2nd payload to a target (or suppress first-install ACK) | **~52 B + 1 packet per one-shot flow** (−27 % wire on that flow) | med-high | §1.3 |
| C9 | Stats: move coarse-clock gate behind a count check | 1–2 ns/payload | med | P13 |
| C10 | Single varint encode (stack `[u8;5]`) | 1–2 ns/encoded frame | high | P12 |
| C11 | `put_addr` without memset | ~1 ns/OPEN | high | P11 |
| C12 | FRAG reassembler: one partial lookup + `Arc<FragCtx>` / borrow compare | 1–3 ns/fragment; removes a String alloc per domain inline fragment | med | P14/P16 |
| C13 | `reply_src` as packed atomic (IPv4) | removes 1 alloc/rebind; cheaper per-candidate load | med | P10 |
| C14 | Avoid `slice_ref` RMW by staging `(frame, off, len)` | 1–3 ns/frame | med (plumbing) | P15 |
| C15 | Remove intermediate payload `Bytes` copy on staged send (frame built at push) | 10–16 ns + 1 alloc/payload | med risk | P9 |

If C1–C8 all land, the expected per-datagram app CPU win is roughly
**15–50 ns** on top of the current 40–80 ns MQP-layer cost (i.e. **20–40 % of the
MQP-layer CPU**, or ~5–10 % of the whole per-packet path once quinn/syscalls are
included) `[estimate]`. None of it changes the wire.

### 5.2 Needs wire redesign

| # | Change | Saving | Confidence | Note |
|---|---|---|---:|---|
| W1 | Packed kind+id steady header: 1 B (first ~15–31 flows/owner), 2 B for the full 4096-flow space | **1 B/steady frame after 63 flows**; −1 B for every flow the 1 B short form covers; removes the 2→3→4 B cliff | high | §1.2, §6 |
| W2 | No separate FLOW_ACK for flows whose correctness does not need it (piggyback ACK bit in any downlink frame; explicit ACK only for uplink-only flows) | **~61 B + 1 packet per opened flow** that gets a downlink | med-high | §1.3 |
| W3 | u16 session **index** in OPEN/INLINE/FRAG-extended (connection-scoped; 4032-association process cap is far below 65536) | −2 B per OPEN/INLINE/FRAG-open/FRAG-inline | high (bytes) | `README.md:399` cap; `r2.rs:281-289,692-700` |
| W4 | Per-connection address dictionary refs (first OPEN carries the full address, later OPENs/INLINEs a 1 B ref; safe because the first OPEN is retried until FLOW_ACK) | −6 B (v4) / −18 B (v6) / −(L+3) B (domain) on repeat opens | med (state/ACK complexity) | §6 |
| W5 | FRAG idx/total packed into one byte (total ≤16 common; escape for 64) | −1 B/fragment (0.09 % of an 1150 B chunk) | high (bytes), low value | `r2.rs:686-700` |
| W6 | TRAIN: no meaningful byte win (already 2 B/item dict, 1 B/item length) | ≈0 until ids reach 2 B; then packed ids match varint | high | §1.1, §6 |
| W7 | CTL bodies compressed (HELLO 8→4, CAPS 17→12, SESS_CLOSE 7→3) | −5…−13 B per control frame; one-shot per connection/association | high (bytes), low value | `r2.rs:906-966` |

**Wire-redesign total for the target workloads:** step flow −1 B/frame (≤1 % of
packet); one-shot/DNS flow up to −70 B and one fewer packet (−36 %) via W2+W3+W4;
OPEN v6 with a dictionary 26→~6 B; bulk/FRAG ≈ 0. See §6 for the arithmetic and
the honest end-to-end ceiling.

---

## 6. Clean-slate format: what is actually achievable (backward compat not required)

Design goal: preserve every invariant that matters — one frame per DATAGRAM,
first-frame self-description, loss tolerance, never-reuse safety, bounded
peer-fillable state — while removing the header dead weight.

### 6.1 Proposed packed header

```
byte 0: kind(3) | flags(1) | id_hi(4)     2-byte base form, 13-bit flow id
byte 1: id_lo(8)                          = 8192 wire ids = 4096 flows/owner
1-byte short form: kind(3) | id(5)        ids 0..31 (≈15 flows/owner; a design
                                          can fold the owner bit into the kind
                                          space to reach 31/owner)
```

- **steady DATA: 1 B** (short form) for the first ~15–31 flows/owner, **2 B** for
  every other id up to the 4096-flow cap — and it never grows.
  Current: 2 B for the first 63, then 3 B, then 4 B.
- Flags (OPEN/INLINE/SRC) live in the extended byte after the kind byte, so the
  steady form keeps the kind in 3 bits.
- Why 2 B and not 1 B universally: the receiver must distinguish data from
  control and a flow id is needed; 13 bits is the minimum for the full
  4096-flow cap (2·4096 = 8192). 1 B can only hold ~5 id bits, so the 1 B form
  only covers a handful of flows per owner (how many depends on whether the
  owner bit is folded into the kind space — a design choice, not free bytes).

### 6.2 Clean-slate frame headers (wire only, this proposal)

| Frame | Current | Clean slate | How |
|---|---:|---:|---|
| DATA steady, first ~15–31 flows/owner | 2 | **1** | packed short form (exact split is a design choice) |
| DATA steady, any id ≤8191 | 2–4 | **2** | packed 13-bit id |
| DATA OPEN v4 / OPEN\|SRC v4 | 14–15 | **12** full / **6** dict | 2 B packed id + 2 B u16 session index + 7 B v4 / 1 B addr-dict ref + 1 B ext |
| DATA OPEN v6 | 26–27 | **24** full / **6** dict | dictionary makes v6 equal to v4 |
| DATA INLINE v4 | 13 | **10** full / **4** dict | 1 B kind/flags + 2 B session index + 7 B v4 / 1 B addr-dict ref |
| TRAIN same, id<8192 | 4–5 + 1 B/len-item | **4** + 1 B/len-item | 2 B base (kind/form/count) + 2 B packed id; equal early, −1 B after 64 flows |
| TRAIN dict | 4 + 1–2 B/flow + 2 B/item | **≈ same** (keep varint ids) | no byte win; the CPU win comes from single-pass decode/encode |
| FRAG steady | 8–10 | **8** (7 for short id) | 2 B packed id + 4 B frag_id + 1 B packed idx/total + 1 B kind/flags |
| FRAG open v4 | 20–21 | **17** full / **11** dict | 1 B kind/flags + 2 B id + 4 B frag_id + 1 B idx/total + 2 B session + addr |
| FRAG inline v4 | 19 | **15** full / **9** dict | 1 B kind/flags + 4 B frag_id + 1 B idx/total + 2 B session + addr |
| CTL FLOW_ACK | 4–5 | **3**, or 1 bit piggybacked | piggyback is the win |
| CTL SESS_CLOSE | 7 | **3** | 1 B kind/opcode + 2 B session index |
| CTL HELLO / CAPS | 8 / 17 | 4 / 12–13 | one kind/opcode byte; CAPS keeps its negotiated fields |

### 6.3 End-to-end effect (IPv4, 55 B L0 + 2 B DATAGRAM frame per packet)

| Workload | Current wire | Clean slate | Δ |
|---|---:|---:|---:|
| One-packet flow (60 B each way), repeated target (addr-dict hit) | 192 B / 3 pkts | **122 B / 2 pkts** | **−36 %, −1 packet, −1 send+dispatch** |
| One-packet flow, **novel** target (full addr in OPEN) | 192 B / 3 pkts | **128 B / 2 pkts** | **−33 %, −1 packet** |
| One-packet flow, INLINE path today (no OPEN) | 140 B / 2 pkts | 122 B / 2 pkts | −13 % |
| DNS 60 B steady | 119–120 B | 118–119 B | −0.8 % |
| Steady 128 B flow | 187–188 B | 186–187 B | −0.5 % |
| Multi-assoc TRAIN same, 18×60 B | 1159 B/frame (57+4+18·61) | 1159 B early / 1158 B at id≥128 | 0 / −0.09 % |
| 8 KiB FRAG | 8192 + 8·(57+8) = 8712 | 8704 | −0.09 % |
| Bulk 1200 B at MTU 1400 | 1259–1260 | 1258–1259 | −0.1 % |

**Honest conclusion:** a clean-slate format cannot move bulk or steady flows
(≤1 B/frame, ≤0.2–0.8 % of a packet — the 55 B L0 cost dominates and the MQP
header is already 1–2.5 %). Its real wins are (1) **removing the FLOW_ACK
DATAGRAM and the 63-flow growth cliff** (−33…−36 % wire and −1 packet for
one-shot flows, which are the dominant DNS/telemetry shape; −36 % when the
target is already in the address dictionary, −33 % for a novel target), (2) **u16 session
index + address dictionary** for OPEN/INLINE (14–27 B → 5–12 B, and IPv6 stops
being more expensive than IPv4), and (3) making OPEN cheap enough that
compression no longer needs a 7-frame break-even. For cross-session small-packet
traffic the wire is already near its floor; the remaining CPU headroom is in
§5.1, not in bytes.

---

## 7. Micro-benchmark: `examples/rev3_bench.rs`

**Status:** written this task (new file; no existing file modified). Not run —
cargo is reserved for the Lead, per the task rules.

**Command:**
```sh
cargo run --release --example rev3_bench
```

**What it measures** (min of 5 rounds after 10 % warmup; ns/op printed, plus
static wire tables at the end):

| Group | Cells | Purpose |
|---|---|---|
| DATA decode | steady id 2 / 200 / 20000 (2/3/4 B hdr) × 128 B payload; OPEN v4/v6/domain; INLINE v4 | price the codec parse and the address-decode (domain UTF-8) delta |
| TRAIN decode | same-form n=1/8/64: decode only, decode+iterate once, **decode+iterate twice (production)**, and a **single-pass reference decoder**; dict nfl=2/8/64 production vs reference | price the double pass + 256 B array copies (P2) |
| FRAG decode | steady 9 B header, 1100 B chunk | codec-only fragment cost (reassembler excluded) |
| DATA encode | steady id 2/200/20000; **reference single-varint-pass encoder**; OPEN/INLINE | price the double varint traversal + exact-Vec path (P12) |
| TRAIN encode | same n=64 encode vs `train_same_len` alone; dict nfl=2/8/64 `train_dict_len` alone vs full encode vs **reference write-only encoder** with precomputed capacity | price the O(n²) validation pass (P3) |
| FlowRegistry | `get(hot)` and cycling 64 ids vs a **direct-indexed table** (`DirectTable`); `get_batch(64)` | price P6/§4 |
| SessionFlows | `find` slot 0 / slot n−1 for n=1/8/64; `match_source` last/first for n=1/8/64 | price P5/P7 |
| Wire tables | steady headers for local ids 1/63/64/127/128/8191/8192/1 048 575 × both owners; OPEN/INLINE/FRAG/TRAIN/CTL header sizes; **LEB128 length vs flows-ever table** | reproduce every §1 number from the production length functions |

**How to read it / expected shape (hypotheses to confirm, not measured here):**
- `decode DATA steady` should be ~1.5–4 ns and barely move between 2 B and 4 B
  headers; OPEN IPv4 ~3–6 ns; the domain OPEN delta over IPv4 is the UTF-8
  validation cost.
- `decode+iterate twice` should be materially above `decode` alone (the eager
  pass + 256 B copies); the `ref single-pass` cell is the lower bound and the
  delta is the value of P2. Expect the gap to grow with n=64.
- `encode steady` ≈ the frame_bench "plain 128 B same-thread" cell (15–19 ns
  `[measured]`); the `ref` encoder shows the double-varint cost (expect ~1–3 ns).
- `train_dict_len` alone at nfl=64 should be visibly super-linear vs nfl=2
  (O(n²) duplicate scan); `encode_train_dict` ≈ `train_dict_len` + write; the
  `ref write-only` cell is the floor.
- `get` vs `DirectTable::get`: expect the lock+hash cell ~3–5× the direct cell;
  `get_batch(64)` should be far below 64× a single `get` (that is why it exists).
- `match_source` at n=64 worst case should be the single largest table cell
  (per-reply cost) — compare with n=1 to see the O(flows) scan.
- The wire table must reproduce §1 exactly; if it does not, the report table is
  wrong and the code should win.

**Existing benches to pair with this:**
- `cargo run --release --example frame_bench` — the per-frame allocation /
  `Bytes::from` cost and the rejected pooled design (`frame_bench.rs:1-38`).
- `cargo run --release --example hotpath_bench -- udppaced/udpfanout/udpmulti…`
  — end-to-end pps/loss/frames-per-payload; this is where a wire change must be
  validated (a header-byte change is invisible to loopback throughput; use the
  frames/payload counter and a netem path, per README §9/§17).

**Interpreting a win:** a codec-cell win of X ns/frame only matters end-to-end
if per-datagram app CPU is ~40–80 ns (§2.8); a 10 ns/frame win is ~5–10 % of
that. A wire win of 1 B/frame is 0.5–0.8 % of a small packet; the one-shot
OPEN/ACK elimination is the only wire change worth a benchmark campaign by
itself (−1 packet/flow).

---

## 8. Assumptions, uncertainties, and answers to the remaining questions

**Distribution assumptions used for averages:** "steady header average" is over
flows *ever opened* on one connection/endpoint (ids monotone, never reused, cap
4096 live). The mixed workload (7.0 B/payload) assumes 25 % OPEN first frames,
10 % INLINE, 65 % steady at 3 B; changing those weights moves the number
roughly linearly. Payload sizes 60/128 B and IPv4 unless stated; IPv6 adds 12 B
per address on OPEN/INLINE/FRAG-open/FRAG-inline and 0 on steady/FRAG-steady.
L0 uses 55 B IPv4 + 2 B DATAGRAM frame from `MQP3_REFACTOR_ANALYSIS.md:146-147`;
the exact QUIC short-header/PN/tag split varies ±2 B with DCID/PN encoding, so
all full-wire numbers are ±2 B.

**Uncertainties:**
- No ns value here is measured on this machine in this task; all `[estimate]`
  cells need `rev3_bench` (and ideally `perf stat`) to become `[measured]`. The
  bench's reference codecs are the honest measurement of P2/P3/P12; the table
  cells (P5/P6/P7) are the honest measurement of the lookup costs.
- Atomic/RMW counts are from the code, not from a counter; architecture and
  contention change their cost. All counts are for an uncontended single-thread
  path (one connection's reader task / one association task).
- The quinn-internal costs (`read_datagram` state mutex per poll,
  `send_datagram_wait` state mutex per frame, TX `extend_from_slice` copy) are
  from quinn 0.11.12 / quinn-proto 0.11.19 sources in the local registry, not
  from measurements.
- The one-packet-flow policy change (C8) assumes the app's first reply arrives
  through the same session socket (true for SOCKS5 UDP ASSOCIATE; the server
  admits the source via `RecentAddrs`/flow tables — `reader.rs:1015-1058`).
  It also assumes one-shot flows are common; a workload of long flows is
  unaffected because the open happens on the second payload.
- The address-dictionary (W4) needs an install/confirm policy: the first OPEN
  with the full address is retried until `FLOW_ACK` (so a lost first OPEN cannot
  leave the receiver without the address), and a dictionary entry is only
  referenced after the flow that installed it is ACKed. Without that, a lost
  first frame would make the ref undecodable — this is the main risk of W4.
- Clean-slate numbers assume the invariants are kept (one frame per DATAGRAM,
  first-byte self-description, bounded state, idempotent control) and do not
  count the CPU cost of the new state (address/session dictionaries are small
  and cold).

**Should large UDP payloads move to a reliable QUIC stream?** No wholesale:
- `FRAG` wire overhead is already 8–9 B per ~1150 B chunk (0.7–0.9 %) and its
  CPU is one copy per chunk into the assembly buffer + 2–3 hash probes/fragment
  (P14); reassembly is bounded (8 KiB, 256 partials, 256 KiB/conn, 2 s).
- A stream would add stream-frame overhead, per-payload stream open/close or
  framing, flow-control blocking and **head-of-line blocking** — the opposite of
  the UDP contract the relay sells (README §11: no retransmission, no HOL
  blocking intentionally). It would also require a new reliability state
  machine and buffering, which is a much larger risk than any header byte saved.
- A reasonable optional scope is a reliable-stream **fallback for very large
  (>4–8 KiB) or FEC-required payloads** where loss amplification is unacceptable,
  selected per payload size class; that is a product decision, not a parse-cost
  win. For ≤8 KiB UDP payloads keep DATAGRAM+FRAG.

**What remains genuinely unknown / needs the Lead's measurement:** the true
share of one-shot flows (drives C8/W2 value); the real nfl distribution in dict
trains (drives P3 value); whether `match_source` O(flows) shows up in a profile
(drives P5); and the end-to-end pps delta of the cheap wins (needs
`hotpath_bench udppaced` before/after on a Linux target).

---

## 9. File:line index (decisive evidence)

Codec — `src/mqp/r2.rs`: id construction `:143-148`; varints `:172-211`; lengths
`:275-289,686-700`; DATA encode `:291-354`; DATA decode `:356-424`; TRAIN
lengths `:430-456`; `valid_train_flows` `:466-487`; TRAIN encode `:489-527`;
`TrainFrame`/`TrainItems`/`items` `:531-584`; `decode_train` + eager validation
`:586-661`; FRAG encode/decode `:706-860`; CTL `:864-1043`; `put_addr` `:250-255`;
goldens `:1113-1313`.
Flow state — `src/mqp/r2_flow.rs`: caps `:36-53`; `FlowBinding` `:84-224`
(`mark_open` `:146-153`, `set_reply_src` `:166-169`, `reply_src` `:184-186`,
`resolved_contains` `:221-223`); `SessionFlows` `:240-406` (`find` `:291-297`,
`match_source` `:325-366`); `FlowRegistry` `:436-738` (`get` `:587-589`,
`get_batch` `:601-606`); `FlowIds` `:743-778`; `CtlState`/rate `:781-869`.
Address — `src/mqp/addr.rs`: `encode_into` `:81-106`; `encode` `:122-160`;
`header` `:165-196`; `decode` (UTF-8 `:239`) `:198-245`.
Stager — `src/udp/r2_stage.rs`: `push` `:386-411`; `pack_one_frame`
`:467-556`; `take_steady_head` (`unique.contains` `:593`) `:574-619`;
`encode_train_run` (`items` array `:643`) `:631-654`; `send_packed_frames`
`:841-889`; `drain_staged` `:944-1000`.
Client send — `src/bin/myquic2-client/rev2.rs`: `frame_limit` `:246-255`;
`push_stage`/`drain_stage` `:264-287`; `send_uplink` `:733-805` (payload copies
`:774,:794`); `stage_or_count` `:813-866`; `send_standalone` `:917-956`;
`try_single_data` `:964-998`; `ensure_binding` `:1046-1131` (memo `:1052-1058`,
`flows.find` `:1061`); counters `:1191-1285`.
Client receive — `src/bin/myquic2-client/dispatcher.rs`: `stage_reply`
`:101-116`; `lookup_entry` `:161-218`; `flush_staged` `:733-814`; `r2_lookup`
`:845-859`; `send_flow_ack` `:870-884`; dispatch `:1061-1148` (`mark_open`
`:1135`), `:1184-1286` (TRAIN, `:1203,1240,1253`), `:1294-1396` (FRAG),
`:1405-1426` (kind), `:1431-1458` (is_r2), reader loop `:1460-1630`.
Fragmenter — `src/udp/r2_frag.rs`: `FragPlan` `:70-122`; `send` `:146-285`
(per-fragment `try_send_datagram` `:247`); header goldens `:309-335`.
Reassembler — `src/udp/r2_reasm.rs`: `Partial`/`buf_write` `:148-293`; `push`
`:360-643` (`into_owned` `:400`, zero-copy `:417-425`, probes `:430-431,527-530`,
`recompute_retained` `:284-292,603`, `prune_orders` `:625,735-752`); expiry
`:697-723`.
Send wrapper — `src/udp/send.rs`: `try_send_datagram` `:84-95`; quinn-copy note
`:66-69`; per-poll mutex note `:80-83`.
Server ingress — `src/bin/myquic2-server/accept.rs`: `r2_send_ctl` `:1517-1519`;
`sess_close` `:1533-1540`; `r2_install` `:1606-1673`; `r2_handle_ctl`
`:1794-1910`; `r2_forward_flow_resolved` `:1962-2006`; `r2_ingress_open`
`:2184-2351` (ACK `:2336-2344`); `r2_ingress_data` `:2355-2434`; `r2_ingress_train`
`:2440-2515`; `r2_ingress_frag` `:2531-2632`; `handle_r2_ingress` `:2645-2709`;
`r2_dispatch_frame` `:2713-2748`; reader loop/classification `:3006-3041`;
staging/fast path `:230-286,304-397,475-…`.
Server reply — `src/bin/myquic2-server/reader.rs`: legacy memo `:124-184`;
`R2ReplyState` `:197-212`; `stage_open_src` `:398-444`; `handle_session_reply`
`:927-1150` (`match_source` `:1044`, copy `:1111`); `sess_reader_task`
`:1207-1281,1413-1499`.
Stats — `src/stats/udp_stats.rs` `:21-172`; `src/stats/drops.rs` `:239-241`;
`src/time/coarse.rs` `:47-57`.
Bounds/claims — `README.md:83,151,193-198,404`; `MQP3_REFACTOR_ANALYSIS.md:79-92,
140-165,399-466`; `PERF_ANALYSIS.md:44-100,426-466`; `examples/frame_bench.rs:1-38`.
