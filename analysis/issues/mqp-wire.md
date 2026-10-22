# MQP-3 rev2 audit — `src/mqp/**` + `src/tcp/**` (wire codec, flow state, TCP pump)

Auditor: mqp-wire (teammate). Commit: `8f0d685` (clean worktree). Read-only audit: no source/test/config
files were modified; the only file written is this report (plus `/tmp` scratch, unused).

## 1. Scope and method

Read in full:

- `src/mqp.rs`, `src/mqp/r2.rs`, `src/mqp/r2_flow.rs`, `src/mqp/v3.rs`, `src/mqp/batch.rs`,
  `src/mqp/datagram.rs`, `src/mqp/fragment.rs`, `src/mqp/ack.rs`, `src/mqp/addr.rs`, `src/mqp/error.rs`
- `src/tcp.rs`, `src/tcp/pump.rs`
- `MQP3_REV2_SPEC.md` (all 416 lines) and the `8f0d685` diff for `src/mqp` + `src/tcp`.

Reachability was proven by tracing every codec entry point into the two production binaries:
`src/bin/myquic2-client/{rev2.rs,dispatcher.rs,assoc.rs,pool.rs,socks.rs,hub.rs}` and
`src/bin/myquic2-server/{accept.rs,reader.rs,table.rs,forward.rs,tcp.rs}`; call sites for the rev2 datapath in
`src/udp/{r2_stage.rs,r2_frag.rs,r2_reasm.rs}` were read where the codec contract depends on them. Counters and
`Cargo.lock` deps (`quinn 0.11.12`, `bytes 1.12.1`) were checked where byte semantics depend on them
(`Bytes::slice_ref` on empty slices; `BytesMut::try_reclaim`). No `cargo test`/`cargo check` was run (not needed:
tree is known-green per the brief; targeted code reading only).

## 2. Are the legacy codecs live? (MQP-2 v2 / old MQP-3 v3)

Verdict: **legacy send paths are test-only; legacy decode paths are live production code on both ends.**

- Encoders of the old wires are `#[cfg(test)]` or reachable only from such code: server `flush_reply_single`
  (`reader.rs:585`), `flush_reply_train` (`:622`), `reply_stage` (`:731`), `flush_reply_batch`
  (`:777`), `reply_stage_v3` (`:134`); client `flush_pending_batch` (`assoc.rs:778`) and
  `flush_deferred_batch` (`assoc.rs:846`). `encode_batch_with_header`'s only non-test user is
  `send_udp_batch` (`udp/send.rs:223`), whose only callers are those cfg(test) functions. No production path
  emits `0x02/0x05/0x06`, `0x1X..0x4X`, or old-v3 FRAG/PING frames — this matches spec §7.4.
- The **decoders** are live and peer-reachable: server `accept.rs:2406` (`is_v3` → `handle_v3_ingress` at
  `:634`), `:2439` (`0x05` → `decode_fragment` + legacy `DgramReassembler`), `:2490` (`0x06` BATCH),
  `:2579` (`0x02` single); client `dispatcher.rs:1219-1235` → `dispatch_stage_multi` (`:247`, v3 at `:255`,
  `decode_batch` at `:369`) → `dispatch_stage` (`:452`, `0x05` at `:541`, `0x02` at `:562`).
  None of these paths is gated on `HELLO`/wire version (by design: old peers never send rev2 CTL).

I audited all legacy decoders for the S0 classes (panic / unbounded allocation / slice OOB) and found none:
`decode_single`/`decode_train`/`decode_fragment_v3` all bound their reads and the v3 `TrainItems`
`expect()`s are reachable only after `decode_train`'s identical pre-validation pass (the iterator walks the same
bytes with the same parser, so it cannot diverge); `decode_batch`/`decode_datagram_ref`/`decode_fragment` are
bounds-checked (`fragment.rs:263-279`); the legacy reassembler re-validates `total/idx` before touching memory.
There is, however, one **legacy-only wire strictness defect** worth noting without severity inflation:

- `v3::get_varint` (`src/mqp/v3.rs:140-155`) accumulates with `wrapping_shl` and returns `Ok` for a 5-byte
  encoding whose 5th byte has any value 0x00..0x7F, silently truncating bits ≥ 32 instead of reporting overflow
  (the rev2 codec correctly rejects this, `r2.rs:196-203`). Consequence: a non-canonical/overflowing TRAIN item
  length is accepted with a wrapped value; both the validation pass and the iterator parse identically, so this
  is an interoperability/robustness defect, not a memory-safety one. Only the old-v3 decoder is affected; rev2
  does not use it. **Confidence: high; severity: not S0/S1** (legacy inbound compat only).

Since legacy decode branches remain live attack surface with no production sender, deleting them (or gating them
behind a config flag) is the cheapest surface reduction; this is a recommendation, not a finding.

## 3. Findings, severity-sorted

| id | sev | title | primary evidence | confidence |
|---|---|---|---|---|
| PW-1 | **S1** | Zero-length TRAIN item: local encoder emits it, local decoder rejects the whole frame → cross-session silent payload loss, both directions | `r2.rs:630-637` vs `r2.rs:428-456`, `r2_stage.rs:581-595`, `reader.rs:1052-1074`, `assoc.rs:243-247` | high |
| PW-2 | **S1** | A lost `DATA OPEN\|SRC` (binding frame) permanently black-holes that flow's downlink; the client never sends `FLOW_ACK`/`FLOW_REJECT` (spec §3.4/§4.3 D2-D3 require bidirectional ACK), so the server cannot retry or learn | `reader.rs:526-552`, `:1075-1083`, `r2_flow.rs:269-300`, `dispatcher.rs:756-758`, `:964-978`, `rev2.rs:391-396,430-436`, `accept.rs:1329-1343` | high |
| PW-3 | **S2** | `CTL SESS_CLOSE` has no rate/duplicate cap and costs a full-registry `retain` (up to 4096 entries) per 7-byte frame on both endpoints → remote CPU amplification + head-of-line block on the datagram task; contradicts spec §3.4 "Control frames have rate/total caps" | `accept.rs:1275-1287`, `r2_flow.rs:500-508`, `dispatcher.rs:888-896`; 3× retransmit senders `rev2.rs:447-453`, `accept.rs:1148-1155` | high (mechanism) / medium (impact) |
| PW-4 | **S2** | Negotiated `CAPS` limits `max_conn_flows`/`max_flows_sess`/`max_reassembly` are decoded and then never consumed anywhere; spec §2.3/§5.7 makes them negotiated bounds (only `max_frame_bytes`/`max_train_items` take effect) | `r2.rs:857-861` (fields), grep: no reader outside `r2.rs`; client `rev2.rs:178-193`; server registry cap `accept.rs:1023-1024` | high |
| PW-5 | **S2** | Literal `MQP-4` appears in README and the refactor analysis doc, although the contract says `code/docs/logs must not contain "MQP-4"` | `README.md:26`, `README.md:133`, `MQP3_REFACTOR_ANALYSIS.md:7,227,583,650`; `MQP3_REV2_SPEC.md:5` | high |
| PW-6 | **S2** | Client uplink new-target path scans the whole per-connection flow registry under a read-lock hold (`find_server_flow`, up to 4096 entries) before every new flow; under unique-target churn this is O(flows) per new datagram and blocks installs/removes (writers) for the duration | `r2_flow.rs:479-493`, `rev2.rs:923-939` | high (scan) / medium (materiality) |

Below, S1 first. "Spec" line numbers refer to `MQP3_REV2_SPEC.md` at `8f0d685`.

---

### PW-1 (S1) — TRAIN with a zero-length item is produced locally and rejected locally; the whole frame (up to 64 items from many sessions) is silently dropped

**Wire rule.** Spec §3.2 defines a TRAIN item as `item (same): len varint | payload` / `item (dict): idx u8 |
len varint | payload`. Nothing requires `len ≥ 1` (contrast §3.3: "chunk non-empty" for FRAG), and the common
rules (§3 line 104) let `DATA` payloads be empty. So `len == 0` is a legal TRAIN item, and the local encoder
agrees.

**Encoder (accepts it).**
`src/mqp/r2.rs:428-440` (`train_same_len`) and `:442-456` (`train_dict_len`) size items with
`varint_len(p.len() as u32) + p.len()` — an empty payload is size 1 and is emitted verbatim by
`encode_train_dict` (`r2.rs:501-521`) / `encode_train_same` (`:483-499`). There is no `len > 0` check on either
encoder.

**Production code feeds it empty payloads.**
Client uplink: `assoc.rs:243-247` extracts the SOCKS5 payload as `&msg[payload_off..]` with only
`payload_off > msg.len()` rejected, so a header-only app datagram yields `payload == &[]`. `send_uplink` then
takes the `payload.len() <= BATCH_SMALL_MAX` branch unfiltered (`rev2.rs:609-627`, `Bytes::copy_from_slice(&[])`)
and pushes it into the connection stager. The stager admits it too: `r2_stage.rs:584-585`
(`add = 1 + varint_len(0) + 0`), `take_steady_head` pops it into the run and `encode_train_run`
(`r2_stage.rs:620-645`) passes the empty `&[u8]` to `encode_train_dict`.
Server downlink: the reply reader has no `n == 0` filter (`reader.rs:1182-1186`, head `&buf[..n]` at `:1232`), and
`handle_session_reply` (which starts `let n = payload.len();` at `:909`) stages every `n <= BATCH_SMALL_MAX`
reply, including `n == 0`, as `R2StageItem { payload: Bytes::copy_from_slice(payload) }` (`reader.rs:1052-1074`);
the same connection-scoped stager then coalesces it into a cross-session `TRAIN dict`.
A zero-length UDP datagram is legal and trivially produced by (a) the local app via a SOCKS header-only datagram
and (b) any remote target/attacker by replying with a 0-byte UDP datagram.

**Decoder (rejects the whole frame).**
`src/mqp/r2.rs:630-637`:
```rust
let len = get_varint(b, &mut p)? as usize;
let end = p.checked_add(len)...;
if end > b.len() || len == 0 {
    return Err(MqpError::Malformed("bad r2 train item length"));
}
```
A `len == 0` item therefore makes the receiver reject the *entire TRAIN*. Callers drop the frame and count once:
server `accept.rs:1865-1868` (`decode_train` Err → `r2_refuse`), client `dispatcher.rs:1021-1024`
(`counters::rx_drop`).

**Impact.**
One empty payload poisons the whole train: up to 64 payloads are dropped, and because the Phase-2 stager packs
*all sessions of a connection* into one dict TRAIN, the victims are other associations' datagrams. It is silent
(one counter bump for the frame; the payloads were already booked as `Sent` on the sending side). A remote
target can trigger it server→client on demand (reply 0-byte datagrams while other sessions' replies queue); a
local app can trigger it client→server. This is the only encode/decode asymmetry I found in the rev2 codec.
Related, same class (encoder accepts what the decoder rejects, not reachable from shipped production code):
`encode_train_dict` (`r2.rs:501`) accepts `flows.len() > items.len()`, but `decode_train` rejects `nfl > count`
(`r2.rs:606`).

**Spec violation.** Yes: §3.2 permits a zero-length item (only §3.3 requires non-empty chunks), and the module's
own doc claims "every decoder validates ... and returns MqpError instead of panicking on peer-controlled input"
(`r2.rs:37-38`) while the encoder is allowed to produce frames its own decoder refuses. The TRAIN loss also
breaks §3.2's "drop that item (counted), continue with the rest" rule (there is no per-item recovery at the
receiver — the framing cannot be walked past a rejected item) and the spirit of §5.6/§3 line 105 ("truncation ...
drops only the current frame").

**Minimal fix direction.** Accept `len == 0` in `decode_train` (drop the `|| len == 0` check; the exact-end
validation already bounds the walk), and add a golden/round-trip test for empty train items. Optionally also
reject `flows.len() > items.len()` in `encode_train_dict` for codec symmetry, and/or filter empty payloads at the
two stage sites if the intent is to forbid them (but the decoder must then still accept them for interop).

**Trigger example.** Dict TRAIN, two flows `A=2, B=4`, items `(0, b"")`, `(1, b"x")`:
`04 01 02 02 02 04 00 00 01 01 78` — `decode_train` returns `Malformed("bad r2 train item length")` and the
receiver drops item B too.

---

### PW-2 (S1) — A lost `DATA OPEN|SRC` permanently black-holes a flow's downlink; client→server ACK/REJECT is unimplemented, so nothing retries or detects it

**Mechanism (downlink binding is learned optimistically).**
For a domain-target flow, a source-port change/anycast, or a full-cone server-owned flow, the server's first
downlink reply must be `DATA OPEN|SRC` (`reader.rs:477-579`, small path `:1052-1084`; spec §3.1/§4.2).
The server records the learned source at the moment the datagram is queued, not when the peer proves receipt:
- single-frame rebind: `reader.rs:526-531` — `if out == R2LargeReply::Sent { binding.set_reply_src(src); … }`
  (`Sent` = `try_send_datagram` returned `Sent`, i.e. quinn accepted it — QUIC DATAGRAMs are unreliable);
- fragmented rebind: `reader.rs:545-551` — sets `reply_src` when all fragments were *queued*;
- small rebind: `stage_open_src` returns `true` on `DatagramSend::Sent` (`reader.rs:389-392`) and the caller sets
  `binding.set_reply_src(src)` (`reader.rs:1075-1083`).

From then on, `SessionFlows::match_source` returns `Exact` forever, because its first test is
`if b.reply_src() == Some(src) { return Some(SourceMatch::Exact(b.clone())) }` (`r2_flow.rs:275-277`), and
`reply_src` is never cleared. **The server can never send a second `OPEN|SRC` for that binding.**

**Client side.**
`dispatch_r2_data` learns the source only from an `OPEN|SRC` frame that actually arrives
(`dispatcher.rs:964-969`) and then computes the SOCKS5 reply address as
`binding.reply_src().or_else(|| binding.target.socket_addr())` (`dispatcher.rs:756-758`). If the `OPEN|SRC` was
lost:
- domain target → `reply_src` is `None`, `target.socket_addr()` is `None` → every later steady frame is dropped
  (`dispatcher.rs:974-978`: `REFUSED` + `rx_drop`);
- IP target with a source-port change/anycast → replies are written to the *original target* address
  (`dispatcher.rs:756`), i.e. the app sees the wrong source (connected UDP sockets drop them);
- full-cone server-owned flow → the client never learns the id at all, so steady frames hit
  `rx_unknown_id` (`dispatcher.rs:939-952`).

**Why it is permanent.** There is no retransmission or recovery hook:
- the client never sends `CTL FLOW_ACK` (or `FLOW_REJECT`, or `FLOW_CLOSE`) — the only rev2 CTL frames the client
  encodes are `HELLO` (`rev2.rs:391-396`) and `SESS_CLOSE` (`rev2.rs:430-454`); grep for `encode_ctl` in
  `src/bin` finds exactly those two;
- the server's handlers for them are dead code in practice: `accept.rs:1329-1343` ("Server-owned flows are Phase
  1b; a client ACK can only confirm one") is never entered from our client, and `r2_flow.rs` has no state to
  distinguish "binding frame sent" from "binding frame acknowledged";
- a second possibility for the client to force a rebind (e.g. re-`OPEN`/`FLOW_CLOSE`) does not exist either; the
  uplink keeps using the same (client-side `Open`) binding.
The flow therefore stays downlink-dead until `SESS_CLOSE`/association end. The spec's loss-tolerance claim is
explicit: §3.4 line 164 "Control frames travel over DATAGRAM … loss only delays compression/reclamation;
correctness never depends on their arrival", and §4.3 line 224 "D3 control plane: HELLO/CAPS/ACK/REJECT/CLOSE/
SESS_CLOSE bidirectional", while §4.2 lines 203-209 define the client's `reply_src` learning as the mechanism.
The benchmark acceptance in §8.3 runs at 0.5 % and 2 % loss, so this is inside the protocol's stated envelope:
at 2 % loss, roughly 2 % of domain/source-change flows are permanently black-holed. With long-lived
associations (DNS via one SOCKS UDP association reuses one flow per target), one lost frame disables *all*
later replies for that target.

**Secondary, same root.** When the client *cannot install* a server-owned `OPEN|SRC` (connection registry full
or id conflict), `install_server_flow` only counts `REFUSED`/`rx_drop` (`dispatcher.rs:806-831`) and returns; it
does not `FLOW_REJECT` the id, so the server keeps sending steady frames for a binding the client will never
have. Spec §3.4/§2.3 define `FLOW_REJECT` as the receive-side reaction to a full table ("Over limit: … the
receive side FLOW_REJECT"), and this direction is missing entirely.

**Minimal fix direction.** Make the downlink binding frame confirmed before it is depended on:
1. client sends `CTL FLOW_ACK{id}` (and `FLOW_REJECT{id, TABLE_FULL}` when install fails) — the server handlers
   already exist;
2. server keeps `reply_src` unset (so `match_source` still returns `Rebind`) until either an ACK arrives or the
   first steady frame in the opposite direction is seen, and re-sends `OPEN|SRC` (idempotent) on subsequent
   replies until then. This also fixes the full-cone "unknown id" case and the lost-first-fragment case.

---

### PW-3 (S2) — `SESS_CLOSE` retransmissions are not capped: each 7-byte frame sweeps the whole flow registry on both endpoints

`CTL SESS_CLOSE` is sent 3× per association exit by design (`rev2.rs:447-453` client, `accept.rs:1148-1155`
server) and is idempotent, so duplicate frames are ordinary traffic. Processing a duplicate is not cheap:

- server: `r2_handle_ctl` (`accept.rs:1366-1384`) → `r2_close_session` (`:1275-1287`). The registry purge runs
  **before** the "session already gone" early return:
  ```rust
  let entry = ss.take_session(sess);
  let purged = state.registry.remove_session(sess);   // accept.rs:1280
  ...
  let Some(entry) = entry else { return false; };     // duplicate closes already paid the sweep
  ```
  and `FlowRegistry::remove_session` is `map.retain(|_, b| b.session != session)` over the whole map under the
  write lock (`r2_flow.rs:503-508`). The map holds up to 4096 bindings (`R2_MAX_FLOWS_PER_CONN`).
- client: every `Ctl::SessClose` does `rev2.registry.remove_session(sess)` unconditionally
  (`dispatcher.rs:888-896`), same 4096-entry `retain` under the write lock; plus `r2_reasm.drop_session`
  (≤256 partials) and a stager lock/queue drop.

`r2_close_session` is invoked inline from the datagram-reader task (`accept.rs:2086`/`2160`), so the sweep also
delays every later data frame in the same burst; the client's sweep runs on the per-connection dispatcher task
with the same effect. A peer can send `0x0C 0x20 <4-byte sess> <reason>` at line rate for *any* session id
(including non-existent ones — that is exactly the duplicate case), paying O(flows) per 7-byte frame: a
~4000-entry map walk plus a write-lock acquire for a frame that needs no work. Two-three× more from the
retransmission design.

Spec deviation: §3.4 line 186 says "Control frames have rate/total caps; unknown opcode/truncation → counted and
dropped". There is a CAPS throttle, but no rate/total cap on `FLOW_CLOSE`/`FLOW_REJECT`/`SESS_CLOSE` handling,
and `SESS_CLOSE` in particular is not de-duplicated.

**Minimal fix direction.** De-duplicate: only run the registry sweep when `take_session` actually returned an
entry (the purge-by-session is already covered by `r2_close_entry_bindings` for the real entry, and a
late/duplicate close cannot have a live binding left once the first close ran); and/or bound the CTL opcode
processing per second (token bucket) with a counted drop, which the spec already permits. On the client, install
the same "one sweep per session id per generation" guard.

---

### PW-4 (S2) — Three of the four negotiated `CAPS` limits are decoded and then never used

Spec §2.3 lines 95-98 ("Per-connection live flow cap: `max_conn_flows` (default 4096, negotiated via CAPS);
per-session cap 64 (negotiable)") and §5.7 line 239 ("`max_conn_flows`/`max_flows_sess`/`max_frame_bytes` are
negotiated by CAPS") define a negotiation contract. The codec carries all fields (`r2.rs:852-876`, encode
`:921-931`, decode `:971-984`), but a tree-wide search for `max_conn_flows|max_flows_sess|max_reassembly`
outside `r2.rs` and tests returns **nothing**: the only `Caps` fields ever read are `wire_ver`
(`rev2.rs:181-192`), `max_frame_bytes` (`rev2.rs:184-190,207-216`) and `max_train_items` (`rev2.rs:191`,
`r2_stage.rs:237-241`). Both endpoints keep the compile-time constants: client `ConnRev2` uses
`R2_MAX_FLOWS_PER_CONN` (`rev2.rs:163`) and the per-session 64-entry array (`r2_flow.rs:36,208`); the server
instantiate `FlowRegistry::new(R2_MAX_FLOWS_PER_CONN)` (`accept.rs:1023-1024`).
`MQP3_REV2_SPEC.md` §10.5.1 already lists this as unfinished, i.e. the code and the normative sections disagree.
Today the shipped pair is self-consistent because the server advertises exactly those defaults, so there is no
runtime impact *between these two binaries*; the defect is a forward-compatibility/contract violation (a peer
honouring different limits would not be honoured, and `max_reassembly` is entirely dead).

**Minimal fix direction.** Either consume the fields (pass them into `FlowRegistry`/`SessionFlows`/`R2Reassembler`
construction per connection) or make the codec's `Caps` carry only what is honoured, and mark the rest reserved
in the spec. At minimum, record the deviation in §2.3/§5.7 as normative-until-implemented.

---

### PW-5 (S2) — README/doc literal "MQP-4"

`MQP3_REV2_SPEC.md:5`: "code/docs/logs **must not contain \"MQP-4\"**". The literal string is present in
`README.md:26`, `README.md:133`, and `MQP3_REFACTOR_ANALYSIS.md:7,227,583,650` (all as negations such as
"there is no MQP-4", but the literal constraint is violated). No source file contains it (grep over `*.rs`:
clean). Doc-only; no wire/runtime impact, but it is the one contract check the brief pins for README and it
fails. **Fix:** reword to avoid the token (e.g. "no successor name has been introduced").

---

### PW-6 (S2) — full-registry scan on the client new-target uplink path

`ensure_binding` is on the per-datagram uplink path. When the destination is not in the association's 64-slot
reverse table, it scans the *connection-wide* 4096-entry registry to find a reusable server-owned flow:

- `rev2.rs:923-939` calls `rev2.registry.find_server_flow(sess, addr)`;
- `r2_flow.rs:479-493` does `self.map.read().values().find(|b| r2::wire_id_server_owned(...) && ...)` — a full
  hash-map values scan while holding the read lock.

Cost: O(registry size) Arc/shared-ref scans per new target. It is only per *new* flow (a steady target hits the
`UplinkFlows::last` memo, `rev2.rs:880-886`), and the audit-hardening commit added a `has_capacity` short-circuit
for the full-table case, so the worst realistic case is a client with a few thousand live flows plus continuous
unique-target churn (DNS fan-out / scanning workloads): each such datagram pays a 4096-entry walk and blocks
registry writers (flow installs/removes) for the duration. Not a per-payload cliff for steady flows, but it is
exactly the "scan over flows with lock scope" pattern the audit was meant to remove, and the spec's §2.3 goal
("the hot path only reads `Arc` + atomics") is only met for the steady state.

**Minimal fix direction.** Maintain a per-connection `HashSet<(u32 session, TargetAddrRef-ish key)>`/count of
server-owned flows (updated on install/remove) so a connection that never accepted a server-owned flow skips the
scan entirely, and make the lookup keyed (`BySession` map / per-session reverse table) instead of a values scan.

---

## 4. Checked and found sound (no finding)

These were explicitly verified against the spec and/or the hostile-input contract; listing them so the Lead can
see coverage rather than absence of checking.

**Wire codec (`src/mqp/r2.rs`, `addr.rs`, `ack.rs`)**

- First-byte safety: every kind byte is `0x00/0x01/0x04/0x08/0x09/0x0C` (`r2.rs:61-66`), high nibble 0, none of
  `0x02/0x05/0x06`; dispatch order on both ends is `is_v3 → is_r2 → 0x05 → 0x06 → 0x02` (server
  `accept.rs:2406/2424/2439/2490/2579`) and `is_r2 → v3/batch/0x02/0x05` (client `dispatcher.rs:1219`, `:255`,
  `:369`, `:541`, `:562`) — no byte can be claimed by two parsers. Spec §1 verified.
- Every rev2 decoder is bounds-checked before slicing/allocating and returns `MqpError`; no allocation is driven
  by a length field: `decode_data` (`:356-424`), `decode_train` (`:580-649`), `decode_frag` (`:786-848`),
  `decode_ctl` (`:956-1031`), `TargetAddrRef::decode` (`addr.rs:198-245`). Hostile-input reasoning: no panic and
  no unbounded allocation found (the only allocations on decode paths are `TargetAddr`/`String` only where the
  decoder caller converts, e.g. `accept.rs:1791` after shape checks).
- LEB128: `get_varint` (`r2.rs:189-211`) rejects >5 bytes and overflow (`byte & 0xF0 != 0` on the 5th byte);
  `varint_len`/`put_varint` round-trip boundaries (127/128/16383/16384/2^31-1/u32::MAX, tests at `:1327-1348`).
  It *accepts* non-canonical/overlong encodings (legal LEB128, no length/slice impact) — noted, not a defect.
- Golden byte lengths vs spec §3.1/§3.2/§3.3 tables: steady DATA 2 B; OPEN/INLINE v4 14/13, v6 26/25, domain
  11+L/10+L (`data_*_len` `r2.rs:275-289`); TRAIN same 3+id, dict 4+nfl×id (`:430-456`); FRAG steady header 8 B
  (`:674-688`); CTL 8/17/… (`:894-902`). All match the spec and the golden tests.
- CTL opcodes/bodies exactly per §3.4 (`encode_ctl` `:910-954`, `decode_ctl` `:956-1031`), including trailing-byte
  rejection and id-0 rejection; HELLO/CAPS magic+length checks; unknown opcode is a counted drop.
- `wire_id` construction/validation: `make_wire_id` rejects 0 and `local > 0x7FFF_FFFF`; `FlowIds::alloc`
  (`r2_flow.rs:539-551`) is monotonic via `try_update` and returns `None` at exhaustion; receiver rejects
  `wire_id 0` on every data/CTL form. Ids are never reused in any sender path I traced (client
  `FlowRegistry::insert_new`, server `install_unsolicited`; `ensure_binding` allocates a fresh id when a binding
  is `Closed`, `rev2.rs:887-896,940-953`). Spec §2.1/§5.8 satisfied.
- Half-space ownership: server rejects a client `DATA OPEN` on a server-owned id (`accept.rs:1654-1661`), client
  installs only server-owned unknown ids from `OPEN|SRC` (`dispatcher.rs:806-814`); client-owned ids cannot be
  installed as server flows and server-owned ids never collide (owner bit). Spec §2.1/§5.4-5.5 satisfied.
- `DATA`/`FRAG` flag semantics: OPEN/INLINE mutual exclusion and reserved-bit rejection (`r2.rs:372-387`,
  `:788-806`); SRC requires OPEN/INLINE; `INLINE` carries no id and is the fail-safe (`decode_data`). Spec
  §3.1/§3.3 satisfied.
- FRAG: `1 ≤ total ≤ 64`, `idx < total`, non-empty chunk enforced at decode (`frag_meta_ok` `r2.rs:690-692`) and
  re-checked by the reassembler; `frag_id` u32; key `(wire_id, frag_id)`; 8 KiB/2 s/256/256 KiB bounds live in
  `udp/r2_reasm.rs` and are enforced before allocation (I read `push`/`buf_write`/`drain_pending`/`prune_orders`
  for the codec contract: `chunk_off + chunk.len() == d.len()` is verified at `r2_reasm.rs:309-311`, and the
  no-copy view arithmetic is checked with `checked_add`). Spec §3.3 bounds hold.
- Encoder/decoder budget consistency for lengths: `data_*_len`/`frag_*_len`/`train_*_len` are the single source
  for `with_capacity` and the `total > limit` test, and each encoder re-checks the same arithmetic; the
  `debug_assert_eq!(v.len(), total)` pairs are consistent in all forms (the PW-1 empty-item case is a semantic,
  not an arithmetic, divergence).
- `Src`/`Open` rebind semantics per §3.1: server `OPEN|SRC` with the actual source on rebind
  (`reader.rs:521-553`), client `reply_src` learning (`dispatcher.rs:960-969`), domain resolved-IP matching in
  `SessionFlows::match_source` (`r2_flow.rs:269-300`) with exact-before-rebind precedence and single-pass scan.

**Flow state (`src/mqp/r2_flow.rs`)**

- `FlowBinding` state transitions: `Opening→Open` via CAS, `Closed` terminal and never reopened
  (`r2_flow.rs:131-144`); registry `insert` is idempotent for `(session,target)` and returns `Conflict` for a
  different `(session,target)` (`:387-400`); `insert_new` checks capacity **before** consuming a monotonic id
  (`:423-448`, the P1 defect fixed by `8f0d685` — verified the id-leak is actually gone); `remove_session`/
  `clear`/`get_batch` are single-lock-hold (`:456-517`); `resolved`/`reply_src` are lock-free snapshots and the
  reply path filters `Closed` bindings (`reader.rs:1006-1010`). Registry cap is enforced on insert and the
  receive side answers `FLOW_REJECT` (`accept.rs:1670-1672,1760`, `reader.rs:1631`), matching §2.3.
- `SessionFlows` insert/find/remove, duplicate-id idempotence and the 64-entry cap behave as documented
  (`r2_flow.rs:304-327`); the reverse-table entry always carries the session, so cross-session resolution is
  impossible (spec §5.4).
- `CtlState` HELLO gate: pre-HELLO buffer is `8 frames / 16 KiB` (`accept.rs:962-963,1108-1120`), only a
  matching `wire_ver=2` HELLO opens it (`accept.rs:1314-1327`), wrong-version HELLO still gets CAPS but never
  releases the buffer, overflow is counted — spec §6/§3.4 exactly.

**TCP pump (`src/tcp/pump.rs`, callers `bin/myquic2-client/socks.rs:261`, `bin/myquic2-server/tcp.rs:206`)**

- Byte accounting: TCP→QUIC `total += n` only after the write is accepted, both the zero-copy
  (`split_to(n).freeze()` + `write_chunk`) and copy (`write_all`) arms (`pump.rs:336-356`); QUIC→TCP
  `batch_bytes = Σ len` over exactly the `n` returned by `read_chunks`, incremented only after
  `write_batch_vectored` wrote everything (`:401-455`); stale `batch` entries are cleared so assembler buffers
  are not pinned (`:428-430,449-451`).
- Partial writes: `write_batch_vectored` (`:192-251`) builds up to `COPY_BATCH` iovecs (with `take`, the
  fixed-size array cannot overflow), and advances `(skip, off)` correctly for partial vectored writes including
  an offset first iovec, empty entries and a write that exactly finishes a buffer; `n == 0` → `WriteZero`
  (never a silent short write).
- Idle/timeout: per-direction stamps + shared stamp AND-gate; a completed direction is exempt; the shared-only
  expiry arm covers "one side silent, nothing flowing"; fixed 5 s cadence re-armed from a fixed epoch
  (`:486-556`). 300 s callers pass it, `copy_tcp_quic` disables it with `u32::MAX` seconds and skips the timer.
- ACK accounting: the client's `MQP-2` dial ACK is consumed by `read_mqp_ack` before the download loop and is
  *not* counted in the app byte total (`:379-392`); a missing/bad ACK tears down with RST (never a FIN posing as
  success); the server ACK is a fixed 10/22-byte stack frame (`bin/myquic2-server/tcp.rs:191-205`,
  `mqp/ack.rs:129-134`), and `read_mqp_ack` rejects unknown atyp/`0.0.0.0:0` (`lib.rs:677-706`).
- Abort disposition: RST via `SO_LINGER=0` (`abort_tcp` `:610-617`) on any abnormal end, QUIC `reset`/`stop`
  only for the direction that had *not* completed (`:563-600`), so a truncated transfer is never advertised as a
  clean FIN; a clean both-EOF end FINs the TCP side (`:564-567`).
- Buffer pool: `reserve_copy_chunk` (`:114-128`) is correct — `BytesMut::try_reclaim(k)` (bytes 1.12.1) returns
  true only when it actually reserved ≥ k (`bytes_mut.rs:857-868`), including the exact `len+COPY_CHUNK`
  replacement when a frozen split half pins the allocation; pool retains only ≤2×COPY_CHUNK buffers and ≤4 per
  thread (`:150-162`), matching the admission charge claimed in the commit message.
- `reserve_copy_chunk`'s data-preserving path and the c2s double-buffer rotation were re-derived: the buffer
  handed to `read_buf` is always empty, the frozen half's allocation is released by quinn's ACK, and no
  unbounded growth is possible.

**Other spec-conformance checks (pass)**

- §2.2: `sess` appears only in OPEN/INLINE DATA/FRAG headers, `SESS_CLOSE`, and the control plane — no steady
  frame carries it (verified in all three codecs' encoders/decoders).
- §3 line 104: exactly one MQP frame per QUIC DATAGRAM body (each handler consumes the whole `d`; rev2 encoders
  produce one frame per `Bytes`).
- §4.1 uplink OPEN/ACK idempotency: duplicate OPEN forwards its payload, re-installs idempotently and re-ACKs
  (`accept.rs:1662-1765`); the client keeps sending OPEN while `Opening` (`rev2.rs:803-810`, stager `Open` kind).
- §4.2 downlink compression depends only on the client's local `reply_src`/target (`dispatcher.rs:756-758`).
- §5.3 install-after-real-send: server forwards the OPEN payload before `r2_install` (`accept.rs:1674-1750`);
  failed install only means no compression.
- §5.1/§5.2: TRAIN items resolve through validated bindings only, and the server re-applies the SSRF policy on
  the forward path (`forward.rs:445-466`, `accept.rs:1677-1683`).
- MAC/binding of the stream ACK (`mqp/ack.rs`) and the TCP header parser (`bin/myquic2-server/tcp.rs:243-267`:
  fixed max 259-byte stack buffer, exact lengths, domain ≤255) are bounds-safe.

## 5. Cross-domain notes (not scored here)

- **`src/udp/r2_reasm.rs`** consumes the codec's `FragRef::chunk_off` contract correctly and enforces
  total/idx/chunk/held-byte bounds; the codec's no-copy FRAG design depends on `chunk_off + chunk.len() ==
  d.len()`, which it verifies (`:309-311`). No defect found in the codec/reassembler boundary.
- **`src/udp/r2_stage.rs`** is the component that turns the PW-1 codec asymmetry into real loss (it admits and
  packs empty payloads, `:584-585`); the fix can be either at `decode_train` or at the two stage sites (see
  PW-1). Its drain/requeue accounting (`send_packed_frames`, `requeue_unsent`) looked consistent.
- **`src/udp/r2_frag.rs`**'s `FragPlan`/encoder arithmetic equals the codec's `frag_*_len` and respects the live
  limit; the only asymmetry is that a partial/blocked fragmented payload is queued and later expired, which is
  documented UDP semantics.
- Legacy decoders (`v3.rs`, `batch.rs`, `datagram.rs`, `fragment.rs`) are live inbound compat paths (see §2);
  the v3 `get_varint` overflow acceptance is the only defect I found there and it is not severe. Recommend
  deleting these branches once the one-release compat window closes (spec §7.4).
- `src/bin/*` server session-lifetime code (reader/accept/table) was read only where the rev2 state machine
  crosses into it (install, SESS_CLOSE, reap, reply_src learning); other teammates own the full audit of those
  files.

## 6. Residual uncertainty / not verified

- No runtime reproduction was executed (read-only audit; brief asked for targeted analysis, not a test run).
  PW-1 can be reproduced with the byte sequence in its section; PW-2 needs a dropped datagram (e.g. netem) or a
  unit harness that drops the first `OPEN|SRC`; PW-3 can be measured with a registry-filling micro-benchmark.
- PW-3's impact estimate (CPU amplification, head-of-line) is analytical; the mechanism (sweep per duplicate
  frame) is code-proven.
- PW-2's severity assumes lossy links are in scope (spec §8.3 explicitly benchmarks 0.5 %/2 % loss). On a
  loss-free path it is latent, not observable.
- `cargo test`/clippy were not run (tree is stated clean at `8f0d685`); findings are code-reading conclusions.
