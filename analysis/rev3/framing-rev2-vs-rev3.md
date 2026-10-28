# Rev2 vs rev3 frame aggregation

**Question.** Does rev2 aggregate payloads into fewer DATAGRAM frames than rev3 —
i.e. does rev2 have a frame-aggregation mechanism that rev3 lacks?

**Answer.** No. The aggregation policy is shared. Both revisions push small
payloads into the same connection-scoped `R2Stager`, pack one run per DATAGRAM
(a `TRAIN` for multiple items, a steady `DATA` for one), and drain at the same
points with the same limits:

| Policy | Value | Used by |
|---|---:|---|
| small-payload staging cap | 512 B | rev2 and rev3 |
| train items per frame | 64 (`CAPS.max_train_items`) | rev2 and rev3 |
| burst ingress bound | 32 datagrams (`LAST_HOP_DRAIN`) | rev2 and rev3 |
| drain triggers | burst end + one-train opportunistic + queue-full retry | rev2 and rev3 |
| cross-session packing | one connection stager, round-robin over sessions | rev2 and rev3 |

The only difference is the codec. rev2 emits `DATA` for a single item and
`TRAIN DICT` for a run; rev3 emits `DATA`, and for a run chooses `SAME_EQUAL`
(single flow, equal lengths), `SAME` (single flow, mixed lengths), or `DICT`
(multiple flows). After the rev3 admission fix (`packed_steady_len` costs the
frame the encoder actually emits), rev3's single-flow capacity is equal to or
larger than rev2's. Rev2's only advantage is a narrow multi-flow `DICT` header
effect (1-byte varints vs 2-byte fids), worth at most 3 extra items per frame
and only when dozens of low-id flows meet in one frame.

## Exact frame sizes

Budget `limit = 1162 B` (1200 B MTU); `L` is the payload length, `n` the item
count. Sizes are from `src/mqp/r2.rs` and `src/mqp/r3.rs`; the stager's
`packed_steady_len` now mirrors these exactly.

| Form | Wire length |
|---|---|
| rev2 steady `DATA` | `1 + varint(wire_id) + L` |
| rev2 `TRAIN DICT` | `4 + Σ varint(fid) + Σ (1 + varint(L) + L)` |
| rev3 steady `DATA` | `2 + L` |
| rev3 `SAME_EQUAL` | `4 + item_len_len(L) + n·L` |
| rev3 `SAME` | `4 + Σ (item_len_len(L) + L)` |
| rev3 `DICT` | `3 + 2·nfl + Σ (1 + item_len_len(L) + L)` |

`item_len_len` is 1 B for `L < 255` and 3 B otherwise; `varint(wire_id)` is 1 B
for the first 63 local ids per owner and 2 B after that. A single-item run is a
steady `DATA`, never a `TRAIN`.

## Single flow, constant payload

This is the shape `SAME_EQUAL` exists for: one association sending a burst of
equal-size datagrams. Capacity per frame and frames for 1,000 payloads:

| `L` | rev2 cap | rev2 full frame | rev3 cap | rev3 full frame | frames/1,000 rev2 / rev3 |
|---:|---:|---:|---:|---:|---:|
| 18 | 57 | 1,145 B | **64** | 1,157 B | 18 / **16** |
| 60 | 18 | 1,121 B | **19** | 1,145 B | 56 / **53** |
| 128 | 8 | 1,053 B | **9** | 1,157 B | 125 / **112** |
| 254 | 4 | 1,033 B | 4 | 1,021 B | 250 / 250 |
| 255 | 4 | 1,037 B | 4 | 1,027 B | 250 / 250 |
| 512 | 2 | 1,035 B | 2 | 1,031 B | 500 / 500 |

The rev3 capacity gain is exactly the bytes rev2 spends on a per-item index and
length: 2 B/item for `L < 128`, 3 B/item for `128 ≤ L < 255`, and 3 B/item minus
the 3-byte escape for `L ≥ 255`.

### The P0 fix in burst terms

Before the fix, rev3 admission charged every item the `DICT` size (`idx + len +
2 B fid`) even when the encoder emitted `SAME_EQUAL`, so these runs stopped at
rev2's capacity. The stager now costs the emitted form, and the common burst
boundaries land one frame earlier:

| Burst | rev2 (DICT) | rev3 before fix (DICT bound) | rev3 after fix (`SAME_EQUAL`) |
|---|---:|---:|---:|
| 9 × 128 B | 2 frames `[8, 1]` | 2 frames `[8, 1]` | **1 frame `[9]`** |
| 19 × 60 B | 2 frames `[18, 1]` | 2 frames `[18, 1]` | **1 frame `[19]`** |
| 64 × 18 B | 2 frames `[57, 7]` | 2 frames `[57, 7]` | **1 frame `[64]`** |
| 64 × 60 B | 4 `[18, 18, 18, 10]` | 4 | 4 `[19, 19, 19, 7]` |
| 64 × 128 B | 8 `[8 × 8]` | 8 `[8 × 8]` | 8 `[9 × 7, 1]` |
| 64 × 512 B | 32 `[2 × 32]` | 32 `[2 × 32]` | 32 `[2 × 32]` |

Both directions use this stager: client uplink (`rev2.rs:send_uplink` →
`ConnRev2::stager`, drained at the association burst end in `assoc.rs:820`) and
server replies (`reader.rs:1349` → the connection stager, drained per session
reader). `BATCH_SMALL_MAX` and `LAST_HOP_DRAIN` are wire-independent.

## Multi-flow `DICT`

With `nfl` distinct flows, rev2 spends `Σ varint(fid)` on the dictionary and
rev3 spends exactly `2·nfl`. At 1 B varints (the first 63 flows per owner),
rev2 saves `nfl − 1 B` per frame. That is 0–7 B for the usual 1–8 flows but
63 B at 64 flows. Per-item costs are equal for `L < 128` (rev2: `1 + 1 + L`;
rev3: `1 + 1 + L`), so the whole difference is the dictionary header.

The saving only becomes a capacity difference when the frame carries enough
items to include many distinct flows. Driven through the stager:

| Shape (payloads) | rev2 | rev3 | difference |
|---|---:|---:|---:|
| 8 flows × 8 × 128 B (64) | 8 frames | 8 frames | none |
| 64 flows × 8 × 15 B (512) | 8 frames | 9 frames | rev2 −1 frame (12.5 %) |
| 64 flows × 8 × 16 B (512) | 9 frames | 9 frames | none |
| 64 flows × 8 × 18 B (512) | 10 frames | 10 frames | none |
| 64 flows × 8 × 26 B (512) | 13 frames | 14 frames | rev2 −1 frame |
| 64 flows × 8 × 128 B (512) | 64 frames | 64 frames | none |
| 64 flows × 8 × 512 B (512) | 256 frames | 256 frames | none |

The 64-flow × 15 B row is the largest realized gap found: rev2 packs 64 items,
rev3 packs 61. Three items per frame is the ceiling in this shape because the
run cannot exceed `max_train_items = 64` and rev3's dictionary costs 2 B/flow.
The edge depends on the flow ids staying narrow: every 2-byte varint eats one
byte of the 63-byte header advantage, and with all 64 ids at 2 bytes rev2's
header is 132 B against rev3's 131 B, so the edge is gone. It also needs the
frame to carry enough items to see many distinct flows: at 128 B only 8 items
fit, so `nfl = 8` and the 7 B header difference does not change capacity; at
512 B only 2 items fit. The measured 64-flow × 128 B and × 512 B shapes are
therefore ties despite having 64 flows in the queue.

No multi-flow shape produced a large frame-count difference: in the worst
realized shape rev2 fits 64 items against rev3's 61 (4.9 % more capacity), which
on a 512-payload burst rounds to 8 vs 9 frames. The 8-association shapes used by
the README benchmark are ties.

## Startup context is not a rev2 advantage

`uses_binding_context` (`rev2.rs:1462`) gates the first frame of a flow:

* rev2: `!binding.is_open()` — every staged payload is a standalone `DATA OPEN`
  until the server's `FLOW_ACK` arrives. At 1,000 pps and a non-zero RTT that
  is many standalone frames per flow.
* rev3: `!handshake_done || binding.take_context_slot()` with
  `R3_CONTEXT_REPEATS = 2` — at most two standalone context frames per flow,
  then steady frames that can join a train; `NEED_CONTEXT` re-arms them only
  when the receiver actually missed the binding.

So rev2 does not aggregate *earlier* than rev3 at flow start; if anything it
sends more standalone frames before the first train.

## Conclusion

* rev2 has no aggregation mechanism that rev3 lacks: same stager, same limits,
  same drain schedule, same cross-session round-robin.
* After the P0 fix, rev3 is equal or better for single-flow bursts, which is
  where `SAME_EQUAL` applies; the fix is worth one frame on 9 × 128 B,
  19 × 60 B, and 64 × 18 B, and 5–11 % of frames on long single-flow streams.
* rev2's only edge is the low-id multi-flow `DICT` header: at most 3 items per
  frame, realized as one extra frame in a few 64-flow tiny-payload shapes. It
  is not a general aggregation advantage and cannot explain a large frame-count
  gap.
* The README's `0.743 frames/payload` was measured on rev2; it reflects the
  shared stager, not a rev2-only form. For multi-payload traffic rev3 should now
  be at or below that number. The one rev3 startup cost is the two context
  frames per flow, which is bounded and is usually less than rev2's standalone
  `OPEN` repetition until `FLOW_ACK`.

## Reproduce

`cargo test --lib r2_stage` runs the regression locks added with the fix:

* `rev3_equal_length_runs_fill_one_datagram` — 9 × 128 B, 19 × 60 B and
  64 × 18 B each fit one 1,162 B frame.
* `rev3_equal_length_run_stops_at_the_exact_size` — a tenth 128 B item starts
  the next frame instead of overfilling.
* `rev3_length_change_sends_the_tail_steadily` — the equal-length prefix is
  `SAME_EQUAL`; the odd-length tail follows as steady `DATA` and is not dropped.
* `packed_steady_len_matches_the_encoded_frame` — the admission cost equals the
  encoded length for `DATA`, `SAME_EQUAL`, `SAME` and `DICT` on both wires.

The frame counts in the tables were produced by pushing the same item shape into
`R2Stager::new_with_wire(wire)` and draining one frame at a time (`next_frame`,
test-only; `pack_batch` with `max_frames = 1` has the same effect through the
public API).
