# rev3 integration plan (implementation, phase 2/3)

> Status: planning document written while round-1 implementation streams (max 0-RTT + Phase 0 + r3 codec)
> are in flight. This is the exact seam list the Lead uses to wire rev3 into the client/server data plane
> without rewriting the flow/stager/reassembly layers.

## 0. Decisions fixed for the integration

1. **Wire selection is per-connection, decided by config + ALPN, not by framing.**
   - `wire_rev = 2 | 3` in `src/config/{client_conf,server_conf}.rs` (serde default **3** after green,
     initially 2 while integrating). Both endpoints must match; mismatch fails the TLS handshake.
   - `rev3` implies ALPN `myquic2/r3` (dedicated identifier, fail-fast). `rev2` keeps the existing
     `h3` / `myquic2/3` behavior. Config validation refuses `wire_rev=3 && alpn=h3`.
2. **Identity stays the bearer token, sent in 0-RTT** (user explicitly waived replay/security; max 0-RTT is
   the priority). mTLS is NOT implemented. Token/HELLO are already early-data-eligible after round 1.
3. **Internal ids stay `u32`.** `r2_flow`, `r2_stage`, `r2_reasm` keep using `wire_id: u32`; the rev3 codec
   adapter maps `u16 fid <-> u32 internal wire_id`:
   - client-owned: `internal = local << 1` (even), `fid = local - 1`, `local = 1..=0x2000`
   - server-owned: `internal = (local << 1) | 1`, `fid = 0x2000 + (local - 1)`
   - `local = 0` or `> 0x2000` => no fid => INLINE fallback (documented exhaustion).
   - helper pair: `fid_for(wire_id) -> Option<u16>`, `wire_id_for(fid) -> Option<u32>` in the adapter module.
4. **Codec seam = one new module `src/mqp/wire.rs`** (Lead-owned) that both endpoints and the stager/frag
   call instead of `r2::encode_*` / `r2::decode_*` directly:
   - `enum Wire { Rev2, Rev3 }`, `Wire::alpn()`, `Wire::from_rev(u8)`.
   - encode functions with the same signatures as the `r2` ones plus a leading `wire: Wire`:
     `encode_data_steady / encode_data_open / encode_data_inline / encode_train_same /
      encode_train_dict / encode_frag_steady / encode_frag_open / encode_frag_inline`.
     rev3 path encodes r3 frames after `fid_for()`; rev2 path passes through (must produce byte-identical
     output to today).
   - decode adapter types so existing handlers keep their shape:
     `DataView<'a>` (plain struct), `TrainView<'a>` + `TrainItems<'a>` (Iterator<Item = (u32, &[u8])>),
     `FragView<'a>`, each an enum over rev2/rev3 borrowed decoders; `decode_data/decode_train/decode_frag`
     return these after mapping fids to internal wire_ids. `FrameKind` + `kind(wire, &[u8])`.
   - control messages: rev2 keeps `r2::encode_ctl/decode_ctl`; rev3 uses `r3::encode_ctl_message` over the
     reliable control stream (see §2). The adapter exposes `encode_ctl_datagram(wire, ...)` for rev2 only.
5. **No HELLO/CAPS on rev3.** Client: skip `rev2::handshake()` entirely, set `ready=true` with default caps
   at publish. Server: no `hello_seen` gate (round-1 Phase 0 already removes it); ignore `CTL` datagrams on
   rev3 (or treat as protocol error counted). ALPN is the version gate.
6. **No FLOW_ACK on rev3.** Replace with bounded context redundancy K=2:
   - sender: a binding starts `Opening`; count sends; the first 2 payloads use OPEN/SRC context; on the 3rd
     the binding is marked open locally (`mark_open`) and steady frames are used from then on;
   - receiver: installs idempotently; no ACK is ever emitted;
   - repair: receiver that gets a steady frame for an unknown fid sends `NEED_CONTEXT(fid)` on the control
     stream (rate-limited, e.g. 256/s/conn); sender re-arms the 2-context window on receipt;
   - downlink rebind: server assumes learned `reply_src` is installed after 2 consecutive `OPEN|SRC` sends
     (`reply_src_acked` treated as `sent_count>=2` for rev3) instead of waiting for client ACK; client still
     updates/uses it as today.
7. **Rare control moves to one reliable client-opened bidi stream** (first byte `0xFF`, then
   `type:u8|len:u16le|body` from `r3`):
   `ASSOC_CLOSE`, `FLOW_CLOSE`, `REJECT`, `NEED_CONTEXT`, `SESS_CLOSE`, `GOAWAY`.
   Client opens it immediately after publish (in 0-RTT when resuming); server dispatches streams by first
   byte in the TCP accept loop (0xFF => control; else address atyp). All messages are idempotent and bounded.
   Datagram `CTL` frames are deleted for rev3; `SESS_CLOSE x3`/`FLOW_REJECT` datagrams are not sent on rev3.
8. **0-RTT applies equally to rev3**: token, control stream, OPEN frames and TCP headers can ride the first
   0-RTT flight; rev3 decoders must therefore not depend on any pre-handshake control message.

## 1. Integration steps (each is a testable increment)

**Step 1 — `src/mqp/wire.rs` adapter + unit tests (Lead).**
Wire enum, id mapping, encode/decode adapters, rev2 byte-identity tests (encode through the adapter with
`Wire::Rev2` equals `r2::encode_*` exactly, round-trips through both). No call-site changes yet.

**Step 2 — config/ALPN plumbing (Lead).**
`wire_rev` fields, `Wire` stored on `ConnRev2` (client) and `R2ConnState`/`handle_conn` (server), ALPN
selection + validation, README/config sample updates. Default stays rev2 until step 6 flips it.

**Step 3 — client send path on rev3 (teammate A).**
`client/rev2.rs` (`send_uplink`, `try_single_data`, `send_standalone`, `stage_or_count`), `r2_stage.rs`
encode calls and `r2_frag.rs` -> `wire::encode_*`; binding open policy (K=2, no ACK wait) per §0.6; skip
HELLO/CAPS when wire==Rev3; open the control stream after publish; NEED_CONTEXT re-arm; keep rev2 behavior
byte-identical when wire==Rev2.

**Step 4 — client receive/control path on rev3 (teammate A).**
`client/dispatcher.rs`: decode via adapter, rev3 control-stream reader task, remove `send_flow_ack` on rev3,
NEED_CONTEXT on unknown fid, SESS_CLOSE via stream, CAPS handling bypassed on rev3.

**Step 5 — server ingress/egress/control on rev3 (teammate B).**
`server/accept.rs` (dispatch by conn wire, `decode_*` adapter, no FLOW_ACK on rev3, install idempotent,
NEED_CONTEXT reply on unknown fid, no CTL datagrams on rev3, control-stream accept dispatch 0xFF),
`server/reader.rs` (encode via adapter; rev3 reply-context policy = 2 SRC repeats then steady; REJECT/
SESS_CLOSE via control stream), `server/forward.rs`/`table.rs` untouched if possible.

**Step 6 — tests + default flip.**
New loopback E2E tests for rev3 (datagram round-trip, TCP stream round-trip, 0-RTT + rev3, NEED_CONTEXT
recovery, SESS_CLOSE via stream, malformed-frame matrix); keep rev2 tests green with `wire_rev=2`; then flip
both config defaults to 3, update config samples/README, run the full suite.

## 2. Control-stream framing / state (from design-options §4.2)

```
client-opened bidi stream, first byte 0xFF, then messages:
  type:u8 | len:u16le | body       (len <= 64; unknown type/len => drop frame + count)
  0x01 ASSOC_CLOSE  C->S { sess:u32, reason:u8 }
  0x02 FLOW_CLOSE   both { fid:u16,  reason:u8 }
  0x81 REJECT       S->C { fid:u16,  reason:u8 }
  0x82 NEED_CONTEXT both { fid:u16 }
  0x83 SESS_CLOSE   S->C { sess:u32, reason:u8 }
  0x84 GOAWAY       S->C { }
```
Server TCP path already dispatches by first byte (`atyp` 0x01/0x03/0x04); `0xFF` is unambiguous there.
On the client the stream is opened by us; the server's stream must be drained/closed on teardown.

## 3. Verification per step

- Step 1: `cargo test --lib wire` (byte identity + round-trips + mapping boundaries).
- Steps 2-5: `cargo check --bins`, then targeted tests with both wire revisions.
- Step 6: full `cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`;
  plus a rev3 loopback E2E: TCP CONNECT, UDP datagram, domain target, 8 KiB FRAG, 0-RTT resumption.
- Keep `/tmp/myquic2-baseline` (HEAD worktree) for differential test comparison.

## 4. Risks / known open points

- two wire paths in one codebase for one release (acceptable; rollback = config flip).
- rev3 fid exhaustion at 8191 lifetime flow opens/conn (falls back to INLINE; recommended).
- rev3 first byte overlaps the TCP atyp space by design; the dispatch is per plane (DATAGRAM vs stream),
  never by first byte on DATAGRAMs.
- 0-RTT + rev3 control stream must be idempotent; no OPEN/ACK ordering dependencies anywhere.
