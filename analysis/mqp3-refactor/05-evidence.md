# 05 · Inventory of Existing Evidence, Rejected Designs, and Benchmark Tooling

> Read baseline: HEAD `d2f9658` (2026-10-20 17:42 +0800, `chore(release): v0.2.0`, self-described as version number only; working tree clean).
> Read time: 2026-10-21 06:40 +0800. Method: read-only (git/grep/read) + one <60 s local smoke (no build, no repo changes, no cargo build/test).
> Purpose: provide an evidence base for "whether MQP-3 can be refactored to obtain substantial performance gains (wire-incompatible allowed, name still MQP-3, bidirectional full duplex)", to avoid repeating work already done and avoid re-proposing designs already rejected by measurement.
>
> **Evidence grading (uniform throughout)**
> - **[L-measured]** measured on Linux (only one instance in this repo, and it is a Linux container/virtualized; no real Linux target-machine data)
> - **[M-measured]** measured on macOS (Apple M4 / dev machine; includes loopback end-to-end, microbenchmarks)
> - **[Model]** derived from source constants, wire-format arithmetic, window/RTT/BDP, per-call cost × frequency assumptions, without end-to-end measurement
> - **[Assertion]** claimed in documentation, with no traceable measurement point, or only qualitative description
> - **[Code fact]** statically verifiable fact (not performance evidence; used to check count/constant-type claims in documentation)
>
> **README line references** below point to the baseline README at `d2f9658`; the README has since been expanded, so its line numbers have shifted. File-level claims are unaffected.

---

## 0. Three premises that must be corrected first

| # | Common misunderstanding | Fact (this repo) | Impact |
|---|---|---|---|
| 0.1 | `PROTOCOL_ANALYSIS.md` is an independent document from "before MQP-3 landed" | In git, its **first commit is `530188e` (the same commit as the MQP-3 implementation)**; the document's opening self-reports baseline `348c52d`. The main body §0–§5 models the MQP-2 status quo; §6/§4.4/§4.5/§4.6 carry posterior notes for "current implementation (2026-10-20)" | The document is a hybrid of "pre-implementation design + post-implementation status notes". When citing the "status quo" of §2/§5, it must be treated as `348c52d`; the §6 status notes are consistent with HEAD and can be used as HEAD facts |
| 0.2 | The line numbers in `PERF_ANALYSIS.md` can be used directly against HEAD | Baseline `d73809f`; `348c52d` has fixed parts of F1/F2/F4–F7/F9/F11/F12/F14; `530188e` further heavily changed `assoc.rs`/`reader.rs`/`accept.rs` | The F1–F14 **status table is still valid** (re-checked symbol by symbol this time); but **all file:line are from the old baseline**, and F5/F8 line numbers in particular are no longer valid. New documents may only cite "status conclusions"; citing line numbers must be based on HEAD grep |
| 0.3 | MQP-3 gains "have already been measured" | There is **no Linux target-machine MQP-3 end-to-end measurement** in the repo or anywhere in git history. There are only: macOS loopback smoke, macOS microbenchmarks, one Linux container A/B for a specific optimization (`8eebdca`), and Linux CI test runs | All MQP-3 gain numbers (wire −9%…−38%, calls −18×, CPU 1–3%) are **models**. If a new analysis claims gains, it must bring its own Linux benchmark plan and cannot cite "already measured" |

Supplement: `d2f9658` is a pure version commit (`Cargo.toml:3` = 0.2.0), code identical to `373da0e`; `182b09e` only changes README; `373da0e` only relaxes one Linux admission test lower bound.

---

## 1. Evidence inventory

### 1.1 Protocol/wire and structural facts (mostly code-derived, high confidence)

| # | Claim/value | Source | Evidence class | HEAD status |
|---|---|---|---|---|
| A1 | MQP-2 fixed header: DATAGRAM 5 B prefix (IPv4 total 12 B), FRAG 11 B prefix (IPv4 total 18 B), BATCH prefix; IPv6/domain see original table | `src/mqp/datagram.rs:11` (`DGRAM_PREFIX_LEN=5`), `src/mqp/fragment.rs:29` (`FRAG_PREFIX_LEN=11`), `src/mqp/batch.rs:9` (`BATCH_SMALL_MAX=512`), `PROTOCOL_ANALYSIS.md:71-73` | Code fact | ✅ Consistent |
| A2 | MQP-3 header: SINGLE steady state 5 B / additional flow 6 B; TRAIN 6 B + 2 B/item for same flow, 3 B/item for different flows; FRAG 11/12 B (+ optional address) | `src/mqp/v3.rs:22-66` (constants), `:143-199` (encode_single), `:261-346` (encode_train), `:542-660` (v3 FRAG codec), `README.md:619-662` | Code fact | ✅ Consistent (v3 already in production use) |
| A3 | Downlink header savings: IPv4 flow0 12→5 B (save 7), additional flow saves 6, IPv6 saves 19/18 B; domain/different-source/unsolicited use `NO_FLOW=0xff` inline, and a single frame is actually 1 B larger than v2 | `README.md:710-721`, `src/mqp/v3.rs:46`, `src/bin/myquic2-server/reader.rs:137-154` | Code fact (arithmetic) | ✅ Consistent |
| A4 | Per-packet fixed overhead 55 B (IPv4 20+UDP 8+QUIC short header 27); with MTU 1200 the DATAGRAM body budget is 1162 B; DATAGRAM frame header 1+varint ≈2–3 B | `PROTOCOL_ANALYSIS.md:103-113, 772-781`; based on quinn-proto 0.11.19 source (not this repo's code) | Model (relies on source cross-check) | ✅ Framing still holds (quinn 0.11.x unchanged) |
| A5 | At bulk (≥1200 B), the MQP header is <1% of wire bytes → the upper bound for rewriting the protocol for throughput is ≤1% | `PROTOCOL_ANALYSIS.md:16,41,134-136,574` | Model (arithmetic) | ✅ Still holds (and is the core basis against "rewrite for throughput") |
| A6 | Parts of MQP-3 already landed: client uplink SINGLE/TRAIN, server downlink/uplink v3, flow table, downlink implicit ACK compression; **domain targets are inline throughout, compact FRAG is not wired up, no CAPS/HELLO/FLOW_ACK** | `530188e`; `src/bin/myquic2-client/assoc.rs:566-798`; `src/bin/myquic2-server/accept.rs:603-760,985-990`; `src/bin/myquic2-server/reader.rs:115-260`; `README.md:664-739` | Code fact | ✅ Consistent with HEAD (documented by 182b09e) |
| A7 | Client flow compression state machine = "confirm only upon receiving a compressed downlink frame"; pure uplink flow is always inline; the server flow table is simultaneously the second authorization source when the 16-entry allowlist ring mismatches (exact `(sess,flow)->IP`) | `src/bin/myquic2-client/hub.rs:51-57,139-152`; `src/bin/myquic2-client/dispatcher.rs:258-290`; `src/bin/myquic2-server/reader.rs:586-612`; `README.md:664-706` | Code fact | ✅ Consistent |
| A8 | 512 B is a fate-sharing cap rather than a wire cap: UDP payloads >512 B still go through MQP-2 single-frame/FRAG; v3 staging only at ≤512 B | `src/mqp/batch.rs:9`; `src/bin/myquic2-client/assoc.rs:301`; `src/bin/myquic2-server/reader.rs:629`; `README.md:696-699` | Code fact | ✅ Consistent |

> **One sentence on §1.1**: The "current numbers" for wire header compression are reliable and re-checkable; but they are **byte arithmetic**, not end-to-end gain measurements.

### 1.2 Performance models and estimates (not usable as measurements)

| # | Claim/value | Source | Evidence class | HEAD status |
|---|---|---|---|---|
| B1 | Small-packet single-frame wire −9.4% (IPv4 60 B); domain target −33.4% | `PROTOCOL_ANALYSIS.md:36-43, 527-528` | Model | ⚠️ The domain part is **not implemented** (HEAD keeps domain targets inline, so the gain is unattainable); the single-frame -9.4% depends on flow compression and holds only for IP targets |
| B2 | Multi-destination fanout wire −15.4% (v4) / −37.8% (domain), send calls −18× | `PROTOCOL_ANALYSIS.md:38, 524-525` | Model | ⚠️ The call part depends on the TRAIN implementation (implemented, but **no call-count verification**); domain -37.8% not implemented |
| B3 | Same-destination small packets: −10.8%/9× relative to the current 2-pack; only −1.4%/1.1× relative to the implemented 16-pack | `PROTOCOL_ANALYSIS.md:39-40, 522-523` | Model | ❌ "Current 2-pack" is outdated (HEAD is TRAIN); this comparison is meaningless at HEAD |
| B4 | CPU: 50–100k pps small packets save 1–3% on one core (based on send_datagram 200–300 ns + allocation 30–50 ns) | `PROTOCOL_ANALYSIS.md:42-43, 542-556`; `PERF_ANALYSIS.md:298` | Model (cost estimate × frequency) | ⚠️ Order-of-magnitude reference; not measured on Linux |
| B5 | 8-source 60 B downlink fanout @50k replies/s ≈ −15% bytes / ~18× fewer sends | `README.md:702-706` (the original text already says modeled) | Model | ⚠️ Depends on TRAIN mixed-source (implemented), but the gain is unmeasured |
| B6 | MQP-2 BATCH downlink: 7.8% wire reduction @P=128/N=16, ~2.5% @P=512 | `c8e5c3d` commit message "PER-DATAGRAM COST MODEL" | Model | ❌ BATCH downlink has been replaced by MQP-3 TRAIN (`530188e`); the design no longer applies |
| B7 | MTU 1200 starting point: before PMTU discovery packet count is 18–23% higher; >1150 B payload defaults to 2 fragments | `src/config/tuning.rs:183-193`; `README.md:584,758,777`; `d73809f`/`661ce08`/`952001e` commit | Model (arithmetic) | ✅ Framing consistent; default-value decision see §2 |
| B8 | Throughput cap: 4/8/4 MB window @140 ms ≈ 240 Mb/s; 2/4/2 ≈ 114 Mb/s; 8/16/8 ≈ 300 Mb/s | `src/config/tuning.rs:201-204`; `src/transport/limits.rs:3-23`; `README.md:774-776,758-759` | Model (window/RTT BDP) | ⚠️ All are window arithmetic, **no Linux end-to-end throughput measurement**; `README.md:29` "connection count scales linearly" is an [assertion] |
| B9 | F8 client N-pack: send count 0.5→1/8~1/13, 40k pps ≈ 0.3–0.6% core | `PERF_ANALYSIS.md:298-299` | Model | ❌ The original F8 proposal is deprecated (see §2/R2), but the same order-of-magnitude estimate is a reference |
| B10 | Cross-session TRAIN gain uncertain (quinn already coalesces, only the state lock remains) | `PROTOCOL_ANALYSIS.md:483-488, 746-749` | Assertion/reasoning | ✅ Still holds (should not be raised before profiling) |
| B11 | session id u16 saves another 2 B/frame (5→3), small packets another 2–3% | `PROTOCOL_ANALYSIS.md:493-503` | Model | ⏳ Not implemented (Phase 3); the wire-incompatible constraint is lifted, but id lifecycle risk remains |
| B12 | FEC: 2 fragments +1 parity = +50% bytes; arrival rate 98.01%→99.97%; 8 fragments 92.3%→99.64% | `PROTOCOL_ANALYSIS.md:238-244, 558-566` | Model (arithmetic) | ✅ Still holds; no lossy-link measurement |
| B13 | F2 16-slot collision probability: A=5 about 50%, A=8 about 88%, A=10 about 97% | `PERF_ANALYSIS.md:146-147` | Model (birthday problem) | ✅ No longer applicable after the fix (symbol remains, see 1.3/1.4) |
| B14 | Slow-path amplification: F1 1–3 µs/packet; F10 cross-core 0.1–0.3 µs/packet ≈ 0.5–1.3% core @40k pps; F4 256-entry scan 181 ns → 0.4% @20k/s | `PERF_ANALYSIS.md:117-119, 207-213, 337-338` | Mixed: 181 ns is a microbenchmark [M-measured], the rest are models | ⚠️ F1/F4 fixed; F10 not fixed (see §3) |

### 1.3 Measured evidence (almost entirely on macOS; note "which machine, what load")

| # | What was measured | Value | Source | Evidence class | Usable for new analysis? |
|---|---|---|---|---|---|
| C1 | **frame pool rejection**: plain `Vec::with_capacity`+`Bytes::from` vs pooled | 128 B same-thread 15–19→22–25 ns (+45–52%); 128 B cross-thread 29–38→123–147 ns (+284–324%); 1200 B same-thread +39–42%; 1200 B cross-thread +128–158%; 2 M frames/cell, two rounds, M series + mimalloc | `examples/frame_bench.rs:19-25`; `0fb941d` commit | [M-measured] | ✅ Directly blocks "frame pooling" |
| C2 | `hotpath_bench` embedded baseline (2026-09-30, macOS loopback, 4TCP+2UDP, 8-thread echo) | udpraw control 73129 pps; udp window control 26847 pps; udpps 5 s offered 96485 / goodput 2586 pps (loss 96.9%); 60 s 105350 / 370 (99.6%) | `examples/hotpath_bench.rs:1232-1240` | [M-measured] | ❌ Outdated (earlier than the pending and sharding work in `c8e5c3d`/`e4fd3bc`; README now claims ~40k recv pps) |
| C3 | sharded egress/ingress A/B (macOS M4 10 cores, 3 rounds) | udpmulti 8×20k: 14.8–16.2k→16.9–17.0k pps (+8%); udpps 8 s/128 B: 34.8–42.5k→41.8–43.7k pps (+4%, within noise); 3-way aggregate 58.5/61.7k→69.3/70.7k (+16%); k=4 72.4k, k=8 73.3k | `e4fd3bc` commit message | [M-measured] | ✅ Usable as a "multi-association upper bound" reference; protocol-independent |
| C4 | Linux container (podman aarch64, release) single A/B: some per-packet optimization | `udp 20k` ~3800 pps both before and after (1000 B never batched); `udppaced` 10k–50k parity throughout (0–0.4% loss), 90k 3 rounds 5.89% vs 5.82% (~0.7pp noise) | `8eebdca` commit message | [L-measured] (container/virtualized, narrow scope) | ⚠️ Can only prove "that change had no measurable gain"; cannot represent MQP-3 |
| C5 | Client 2-pack and the "N-pack(≤16) prototype" | The N-pack prototype **was measured**: parity with baseline, slightly worse loss distribution on collapse → reverted as "unmeasurable complexity" | `8eebdca` commit message ("What was deliberately NOT changed" section) | [M-measured] | ✅ Directly blocks re-proposing "BATCH N-pack" |
| C6 | MQP-2 BATCH downlink real-machine smoke | Captured 31k flushes on the wire, n=1..16, of which ~23% reached the 16-item cap | `c8e5c3d` commit message | [M-measured] | ⚠️ BATCH retired; historical only |
| C7 | Slow-path CPU amplification (loopback quantitative) | 20 000 datagrams, 1 vs 2 sessions: 70.2 µs vs 76.3 µs server CPU per delivered datagram (+8.8%) | `src/bin/myquic2-server/accept.rs:893-896`; `b542cb2`/`661ce08` | [M-measured] | ✅ Usable as a quantitative reference that "the slow path cannot be bypassed" |
| C8 | Packet-loss cliff of u16 fragment id (historical measurement) | 1000/s ~4% loss, 4000/s ~15%, 21845/s 50% | `src/mqp/fragment.rs:19-28`; `952001e` commit | [M-measured] (historical, platform not stated) | ✅ Directly blocks "change fragment id back to u16" |
| C9 | Window preset E2E smoke (debug binary, loopback) | UDP 128 B 7.5–10.1k pkt/s (~120–162 Mb/s), RTT 0.26–0.90 ms | `952001e` commit | [M-measured] | ⚠️ debug build, order of magnitude only |
| C10 | MQP-3 release smoke (macOS loopback, same tree as `530188e`) | udp/udpdomain 1000/1000; udpmulti 4×500 0 loss; udppaced 1k/2k/3k/5k pps 0 loss; udpps 2 s 10803/10803; `lat` p50 ~0.98 ms vs baseline ~0.985 ms | `530188e` commit; `README.md:866`; `PROTOCOL_ANALYSIS.md:678-681` | [M-measured] | ⚠️ Functional correctness evidence is reliable; **latency/throughput numbers are not reproducible** (see C11) |
| C11 | This review's smoke (2026-10-21, macOS dev machine, release binary = 530188e tree, loopback) | udpps 2 s/128 B: sent 86 134 pps, recv 21 036 pps, loss 66.0%; udppaced 3k pps: 6000/6000, 0 loss; `lat` n=60/payload 64: p50 **236 µs**, p99 583 µs; `udp` 200×1000 B batch16: 23.7k pps | This report §4.2 (directly re-runnable) | [M-measured] (this analysis) | ✅ Proves the harness is usable; also shows README's loopback latency numbers (0.30/0.98 ms) are unstable/incomparable |
| C12 | UDP N=1 soak in historical README/commits | open-loop 128 B ~40k recv pps @~66k sent (said ~2.6k before the last hop batching); closed-loop ~30k pps/0 loss; udpraw ~82k pps | `README.md:867` | [M-measured] | ⚠️ Large difference from C11 (21k@86k); only usable for relative comparison within the same machine |
| C13 | Several macOS microbenchmarks (cited by PERF_ANALYSIS, `/tmp` scripts not committed) | min_by_key 256 entries ~181 ns; 1.4 KB reply concatenation ~17.5 ns; shared `fetch_add` 22.6/24.6 vs batching 0.21 ns; 2800 B fingerprint ~45 ns + assemble ~60 ns; socket extra getsockopt +1.5–1.7 µs; coarse 1.44 ns / mono 3.26 ns | `PERF_ANALYSIS.md:207,240,355-356,372,386-387,433` | [M-measured] (cites `/tmp` microbenchmarks, not committed) | ⚠️ Only usable as "per-event cost" order of magnitude; cannot be re-run from the repo |
| C14 | Lifecycle/recovery numbers | SIGTERM 0.9 s redial; kill -9 20.6 s recovery; SIGTERM exit 0.05 s | `c8e5c3d`, `README.md:863` | [M-measured] | ✅ Protocol-independent, citable |

### 1.4 Count/build/memory facts

| # | Claim | Verification result | Source | Evidence class |
|---|---|---|---|---|
| D1 | Tests 301 passed (lib 145 + client 81 + server 75, macOS) | Static count check = **301** (runnable on macOS); Linux is **305** (149+81+75; 4 more `cfg(target_os="linux")` tests) | `README.md:861`, `530188e` commit; this static count (`src/linux.rs:365,388,407`, `src/udp/batch.rs:790` are Linux-only) | Code fact |
| D2 | Memory figures: per-conn 14.25 MiB; UDP session pool ~1.09 GiB(non-Linux)/~2.09 GiB(Linux); worst case ~60/36/108 GiB; MQP-3 flow table 4 KiB/session | Constants and arithmetic consistent; `MQP3_FLOW_TABLE_MAX_BYTES=4096` | `README.md:778-788`, `src/mqp/v3.rs:51`, `config-server.toml:39-43` | Code fact (admission arithmetic pinned by unit tests; not an RSS measurement) |
| D3 | Build toolchain Rust 1.99.0 / edition 2024 / version 0.2.0 | Consistent | `rust-toolchain.toml`, `Cargo.toml:3-5` | Code fact |
| D4 | release binaries and bench already exist | `target/release/{myquic2-server,myquic2-client}`, `target/release/examples/hotpath_bench` built at 2026-10-20 16:27 (530188e tree; d2f9658 only changes the version) | this `ls/stat` | Code fact |
| D5 | Binary has no `--version` | `--version` reports clap "unexpected argument" | this measurement | Code fact (not documented, but affects scripting) |

### 1.5 Staleness quick reference

- ❌ **Must be considered outdated**: `PROTOCOL_ANALYSIS.md:145` "the client only does 2-pack", §5.1:513 "status quo modeled as 2-pack", all tables in §5.2/5.3 (2-pack premise); the F8 "deferred" conclusion in `PERF_ANALYSIS.md` (HEAD already implements the same capability via TRAIN); the 2026-09-30 baseline at `hotpath_bench.rs:1232-1240`; the 2.06 GiB at `dist/openwrt-x86_64/config-server.toml.sample:40`.
- ⚠️ **Partially outdated**: the domain compression/compact FRAG gains in `PROTOCOL_ANALYSIS.md` (the model holds, the implementation is not wired); all file:line in `PERF_ANALYSIS.md`; the README loopback performance numbers.
- ✅ **Still valid**: wire header size/savings arithmetic; bulk header share; frame-pool rejection; BATCH N-pack prototype parity; u32 fragment id; the decision to default MTU to 1200; F3/F10/F13 unresolved status.

---

## 2. Rejected / measured-out / decided designs (**do not re-propose in new analysis**)

| # | Design/proposal | Evidence and rationale at the time | Does it still hold for a "new, wire-incompatible MQP-3"? |
|---|---|---|---|
| R1 | **Frame buffer pool** (`Bytes::from_owner` + fragment reusable stack) | [M-measured] Every cell slower: same-thread +39–52%, cross-thread +128–324%; root cause: `from_owner` boxes a control block per frame + fixed 2048 B capacity never reaches the exact-fit fast path | **Still holds**. MQP-3 encoding is still `Vec::with_capacity(exact)+Bytes::from` (`src/mqp/v3.rs:174,313,571`); TRAIN merely amortizes more payload into one frame; the lifecycle is unchanged. Unless the ownership model changes (e.g., self-managed buffers handed to a custom send API), do not re-propose |
| R2 | **Client BATCH N-pack (F8: 2-pack→16-pack)** | [M-measured] Prototype parity, slightly worse loss distribution on collapse, judged "unmeasurable complexity" and reverted (`8eebdca`); subsequently `530188e` implemented the same capability with MQP-3 `PendingTrain` (≤64 items) | **Still holds (do not re-propose BATCH N-pack)**: the functionality is already covered by TRAIN and is stronger (can mix flows). The F8 text at `PERF_ANALYSIS.md:287-303` is outdated; if new analysis wants to raise "N-pack", it should be treated as an **implemented item** |
| R3 | **Server downlink BATCH** (4ef084a/c8e5c3d) | [Model] 7.8% wire; [M-measured] 23% of frames on the wire reached the 16-item cap; subsequently `530188e` changed to v3 TRAIN downlink (mixed source, run=1 sends SINGLE) | **Still holds (BATCH retired)**. Proposing BATCH again for HEAD would conflict with TRAIN |
| R4 | **Keep MQP-2 peer compatibility / CAPS+HELLO canary** | `530188e` explicitly deploys "as an incompatible peer" and deletes peer compatibility; the MQP-2 decoder is kept only for large payloads/tests; CAPS/HELLO not implemented | **Premise changed but conclusion still holds**: the user explicitly allows wire incompatibility, name still MQP-3 → no compatibility layer needed. If a canary is wanted in the future, CAPS is a **release/rollback** feature, not a performance gain; do not mix it into the performance argument |
| R5 | **Change the default MTU** (1400 → 1360 → 1200) | `661ce08` default 1400; `952001e` 1360; `d73809f` final 1200 = QUIC floor: increasing the default on unknown paths causes black holes/loss bursts; for known paths write 1360/1400 in the configuration | **Still holds**. MTU is a transport configuration, not an MQP frame format; MQP-3 should not roll the MTU default into the protocol refactor. If new analysis raises MTU, it should be a **deployment configuration recommendation**, citing the B7 model + no Linux measurement |
| R6 | **Change fragment id back to u16** | [M-measured] u16 historical packet-loss cliff: 4%/15%/50% @1k/4k/21.8k payload/s; u32 costs only 2 B more | **Still holds**. If the new protocol changes fragment semantics, it must retain a ≥32-bit id or an equivalent anti-reuse mechanism |
| R7 | **fragment train** (pack multiple fragments into one TRAIN) | [Model] At MTU 1200 each fragment chunk ≈1144 B, one frame basically holds only one fragment, packet count is not reduced | **Still holds** (arithmetic). The compact FRAG header (saves 6–19 B/fragment) is the only worthwhile thing on the fragmentation side |
| R8 | **Cross-session TRAIN** (Phase 3) | [Assertion/reasoning] quinn already coalesces DATAGRAMs from the same poll into one packet; cross-session requires a connection-level shared stager → introduces queue hops/locks; gain uncertain | **Still holds**: do not raise it before profiling proves the send state lock is the bottleneck. If raised, it must include Linux `perf`/`strace -c` evidence |
| R9 | **FEC / NACK enabled by default** | [Model] 2 fragments +1 parity = +50% bytes; NACK changes UDP semantics and requires a new state machine; should only be opt-in | **Still holds**. The new protocol may make FEC a negotiated opt-in, but it cannot be a default gain source; no lossy-link measurement |
| R10 | **payload compression** | [Assertion] payload is mostly encrypted/random data, incompressible, and adds CPU/buffering/latency | **Still holds (but only an assertion)**: the repo has no payload entropy measurement. If new analysis wants to really argue it, sample measurements are needed; otherwise leave it out as before |
| R11 | **"Rewrite the protocol to improve bulk throughput"** | [Model] bulk header <1%, throughput is determined by CC/window/MTU (B5/A5/B8) | **Still holds**. New analysis should not treat bulk throughput as a target gain of the MQP-3 refactor |
| R12 | **HPACK-style dynamic dictionary / one QUIC connection per destination** | [Reasoning] flow binding is already sufficient and needs no bidirectionally synchronized compression context; connection-level state (handshake/CC/transport budget) far exceeds the flow table | **Still holds** (design reasoning, no measurement) |
| R13 | **512 B fate-sharing cap** | Design choice: >512 B does not go through v3 staging, retains v2 single-frame/FRAG; the cap protects "one lost frame only loses same-source ≤512 B × ≤16 items" | **Not necessarily still holds**: this is a **renegotiable design trade-off** (after wire incompatibility, TRAIN's fate-sharing surface can be redesigned). But **no measurement data** supports a better value; if new analysis wants to change it, it must provide a frame-loss amplification model + Linux loss/latency A/B; it cannot be treated as an established conclusion |
| R14 | **Explicit ACK in exchange for pure-uplink flow compression (FLOW_ACK)** | `530188e` chose "a downlink compressed frame is an implicit ACK": no control plane, avoids the first-frame-loss black hole; the cost is that pure uplink flow is always inline | **Still holds**: the current design's correctness is covered by smoke/unit tests. If the new protocol adds CTL/ACK, it must evaluate control-frame loss/black hole and state machine cost; it cannot just count the 1 B gain |
| R15 | **Shared/internal TLS handshake as a protocol gate (ALPN bump instead of CAPS)** | Default ALPN `h3` is a camouflage feature; CAPS is an in-band canary scheme (unimplemented) | **Still holds** (if a canary is needed); a pure performance refactor does not need it |

---

## 3. Open items and items absorbable by the protocol refactor (HEAD code mapping)

| Item | HEAD code location | Current status | Evidence/notes |
|---|---|---|---|
| **F8** client N-pack | `src/bin/myquic2-client/assoc.rs:798-1080` (`PendingTrain`, ≤64 items), `:566-798` (staging within a burst) | **Implemented by MQP-3 TRAIN (different design)** | The "deferred" and 2-pack line numbers at `PERF_ANALYSIS.md:58,287-303` are outdated; do not redo it as BATCH |
| **F13** reassembler hash/allocation fusion | `src/udp/reassembler.rs:403,448,459-465,523,537,334` (3 probes/5–6 at completion, `prints_of`, `assemble`) | **Not done (deferred)** | `PERF_ANALYSIS.md:63,379-392`; gain ~4 ns/fragment + 30–45 ns at completion, the risk is not worth it; code untouched since `348c52d` |
| **F3** thread topology oversubscription | `src/bin/myquic2-client/main.rs:210-244,473-496,508-543`; `src/linux.rs` `pin_to_core` | **Not done (pending Linux 2–4 core benchmark)** | `PERF_ANALYSIS.md:53,167-190`; macOS `pin_to_core` is a no-op, cannot be measured on this machine; this is a **system-level gain**, not a protocol gain |
| **F10** relay task cross-runtime | `src/bin/myquic2-client/socks.rs:139`, `assoc.rs:5-10`, `main.rs:379-388,508-543` | **Not done (pending `MYQUIC2_SHARD_RUNTIME=0` A/B)** | `PERF_ANALYSIS.md:60,326-340`; 0.1–0.3 µs/packet model gain; code untouched |
| **Compact FRAG wiring** | codec: `src/mqp/v3.rs:542-660`; v2 send: `src/udp/fragmenter.rs:8-23,351`; reassembly key `(sess,id)`: `src/udp/reassembler.rs:26-30,187` | **codec exists, not wired** | `README.md:651-662`; explicitly listed in the `530188e` follow-up; model gain 6–19 B/fragment (v4/v6), no implementation/measurement |
| **CAPS / HELLO** | no code (only the design at `PROTOCOL_ANALYSIS.md:424-456`) | **Missing** | `README.md:736-739` explicitly states no CAPS/no `mqp3=false` |
| **FLOW_ACK / FLOW_REJECT** | no code; substitute = implicit downlink confirmation `hub.rs:51-57,139-152`, `dispatcher.rs:258-290` | **Missing (design substitute)** | Pure uplink flow stays inline: each frame costs 1 B more flow + address. README:674-676 acknowledges this cost |
| **SESS_CLOSE / FLOW_CLOSE** | no code; fallback = `SESS_IDLE_MS=180_000` `src/bin/myquic2-server/table.rs:382`; sweeper `reader.rs:777,1034`, `table.rs:318,353` | **Missing** | Only affects resource reclamation under short-session churn, not steady-state throughput; Phase 2 plan |
| **Domain target compression** | client explicitly `NO_FLOW` inline: `assoc.rs:355-365`; server domain flow does not participate in compression: `reader.rs:129-154` | **Intentionally not implemented** | Reason (security + client has no resolved IP + SOCKS replies need the source address) see `README.md:677-681`, `src/bin/myquic2-client/dispatcher.rs:258-262`; the model's 33–38% domain gain is **not realized** |
| **Pure uplink flow compression** | same implicit ACK mechanism as above | **Intentionally not implemented** | Requires FLOW_ACK; pure uplink flow is inline per frame, so the 9–11% gain model is unattainable |
| **session id u16** | `src/bin/myquic2-client/hub.rs:295-345` (process-level monotonic u32 `fetch_add`, no reuse) | **Not done (Phase 3)** | `PROTOCOL_ANALYSIS.md:493-503`; saves 2 B/frame; touches id lifecycle/180 s no-reuse constraint |
| **v3 observability counters** (frame type / flow count / train items / inline fallback) | none (`src/stats/udp_stats.rs` has no v3 fields; `src/mqp/v3.rs` has no counters) | **Missing** | `PROTOCOL_ANALYSIS.md:636` (Phase 1 item 7) not landed; the new protocol matrix must add these first, otherwise compression rate/fallback rate cannot be verified |
| **Negotiable reassembly cap** (8 KiB is currently a compile-time constant) | `src/mqp/fragment.rs` constants, `udp/reassembler.rs` cap | **Missing** | Phase 2 design; small performance impact |
| **MTU/reassembly negotiation** | none | **Missing (intentional)** | `PROTOCOL_ANALYSIS.md:254-255`: MTU is transport configuration, does not enter MQP frames |

> Conclusion: The only protocol items truly "absorbable by one wire-incompatible refactor" are **compact FRAG wiring**, **domain/pure-uplink flow compression (needs a control plane)**, and **session id u16**; F3/F10/F13 are **system/implementation layer**, unrelated to wire compatibility, and should not be packaged into the "protocol refactor" narrative.

---

## 4. Benchmark tooling inventory: `examples/hotpath_bench.rs`

### 4.1 All modes (HEAD has 20 entry points)

| Mode | CLI | What it measures | Output metrics |
|---|---|---|---|
| `echo` | `echo <port>` | UDP echo target (8×SO_REUSEPORT threads, `hotpath_bench.rs:232-258`) | none (target) |
| `techo` | `techo <port>` | TCP echo target (byte-by-byte echo) | none (target) |
| `utag` | `utag <port> <tag>` | Tagged UDP echo target (used by `udpdomainswitch`) | none (target) |
| `server` | `server <port> <bytes> <count>` | TCP downstream target (for bulk) | none (target) |
| `reply` | `reply <port>` | One-shot HTTP-ish reply target (used by `tcp`) | none (target) |
| `tcp` | `tcp <socks> <host:port> <n> [conc=16]` | N SOCKS5 CONNECTs + 1 reply | flows/s, ok, reply_bytes |
| `bulk` | `bulk <socks> <host:port> <mb> [conc=4]` | Parallel MiB download, TCP pump throughput | MB/s + complete + SHORT warning |
| `udp` | `udp <socks> <host:port> <n> [batch=64]` | Single association sends N×**1000 B** and receives N replies | sent/recv/batch/wall/recv_pps (no loss%) |
| `udpdomain` | `udpdomain <socks> <host:port> <n> [batch=64]` | Same as above but the SOCKS target is a **domain** (DNS path per packet) | same as above |
| `udpdomainswitch` | `udpdomainswitch <socks> <portA> <portB> <n>` | Same session alternating two domain/IP targets, checks misrouting | ok_alpha/ok_beta/misrouted |
| `udpdomainmulti` | `udpdomainmulti <socks> <port> <domains> <assocs> <n>` | Multiple associations × multiple domains, exercises DNS memo | sent/recv/recv_pps |
| `udpmulti` | `udpmulti <socks> <host:port> <assocs> <n> [batch=64]` | Multiple associations in parallel (the only mode that can expose shared-state contention) | complete/failed_assocs/sent/recv/loss%/recv_pps |
| `udpraw` | `udpraw <target> <assocs> <n> [batch=64]` | Loopback control group without the proxy | recv_pps/loss% |
| `udpps` | `udpps <socks> <host:port> <secs> [payload=128]` (payload 64–200) | Single association **unthrottled blast** | sent/recv/send_errs/sent_pps/recv_pps/loss% |
| `udppaced` | `udppaced <socks> <host:port> <secs> [payload=128] [pps=20000]` (payload 1–512) | Single association **paced by an absolute timeline** small-packet soak | same as above + target_pps; warns if pace deviation >5% |
| `lat` | `lat <socks> <host:port> <n> [payload=64]` | Serial UDP request→reply RTT (requires an `echo` target) | samples/lost/stale/bad + p50/p90/p99/p999/max/mean µs |
| `lattcp` | `lattcp <socks> <host:port> <n> [bytes=64]` | New CONNECT per iteration + first-byte echo | connect/echo two percentile groups |
| `udpsweep` | `udpsweep <socks> <host:port> <n> <sizes> [batch=16]` | Per-packet byte verification by size (incl. >512 B/8 KiB fragmentation/reassembly) | verified/mismatched/lost + ALL OK/FAILURES |
| `tcpecho` | `tcpecho <socks> <host:port> <bytes>` | TCP byte-by-byte echo verification | echoed/mismatched/MB/s/OK |
| `chan` | `chan <n> [depth=256]` | No network; measures dispatcher→association mpsc hop cost | per_msg/loop_only/queue_cost ns |

### 4.2 This smoke's results (2026-10-21, macOS dev machine, loopback, release binary, <60 s)

Commands see §4.3; the binary is from `target/release` (530188e tree, not rebuilt). Corresponds to C11 above.

```text
udpps     2 s 128 B : sent=172269 (86.1k pps) recv=58577 (21.0k pps) loss=65.997%
udppaced  2 s 128 B 3000 pps : sent=6000 recv=6000 loss=0.000%
lat       n=60 payload=64 : p50=236 p90=262 p99=583 µs lost=0 bad=0
udp       n=200 payload=1000 batch=16 : recv_pps=23660
```

Interpretation: ① the harness and commands work; ② the `udpps` blast still reproduces "buffer/BBR collapse" (consistent with the mode comment); ③ `udppaced` 3k pps 0 loss; ④ **loopback latency numbers are unstable** (this run p50 236 µs; the README has two values for the same item, 0.30 ms/0.98 ms), so they cannot be used as regression thresholds, only for same-machine same-round comparison.

### 4.3 How to run (exact commands, placeholders replaceable)

```sh
# 0) Run from the repo root (cert_file/server-cert.pem etc. in the config are relative paths)
cd /Users/eric/WorkSpace/MyQUIC2

# 1) Rebuild if needed (the existing binaries are from the 530188e tree; HEAD only changes the version number, so they run without rebuild)
cargo build --release --bins --example hotpath_bench

# 2) Three processes: UDP/TCP targets, server, client
./target/release/examples/hotpath_bench echo  <ECHO_PORT> &     # e.g. 19290
./target/release/examples/hotpath_bench techo <TECHO_PORT> &    # e.g. 19291 (lattcp/tcpecho)
./target/release/myquic2-server --config config-server.toml &
./target/release/myquic2-client --config config-client.toml &
# Ports from the config: server [::]:8443, client SOCKS [::]:1080; config-server.toml already has allow_private=true

# 3) Typical matrix
H=./target/release/examples/hotpath_bench; S=127.0.0.1:1080
$H udp        $S 127.0.0.1:<ECHO_PORT> 2000 16
$H udppaced   $S 127.0.0.1:<ECHO_PORT> 10 128 20000
$H udpps      $S 127.0.0.1:<ECHO_PORT> 5 128
$H udpmulti   $S 127.0.0.1:<ECHO_PORT> 8 20000 64
$H lat        $S 127.0.0.1:<ECHO_PORT> 500 64
$H udpsweep   $S 127.0.0.1:<ECHO_PORT> 64 8,128,512,2000,8000 4
$H bulk       $S 127.0.0.1:<BULK_PORT> 16 4        # needs a separate server target
# 4) Latency needs a shaped path (Linux): tc qdisc add dev lo root netem delay 70ms loss 0.5%; del after the test
```

Note: ① start the targets before the client; ② if `udppaced`'s `sent_pps` is noticeably below `target_pps`, the harness/loopback is the bottleneck, not the tunnel; `udpps` is an unthrottled blast, only suitable for seeing the loss collapse point; ③ `lat`'s `<host:port>` must be an IPv4 literal (source `hotpath_bench.rs:71-73`).

### 4.4 Gaps for the new protocol matrix (**new analysis must fill these first**)

1. **No `udpfanout`**: the acceptance thresholds in `PROTOCOL_ANALYSIS.md:684-685,723` (wire −10%/−30%, send ≥5×) depend on "one association, N destinations rotating", but the harness has no such mode (grep across the repo confirms only design text mentions it). This is the only end-to-end shape for measuring MQP-3's core selling point (mixed-destination TRAIN).
2. **Throughput modes cannot see small-packet batching gains**: `udp`/`udpdomain`/`udpmulti` are fixed at 1000 B (`hotpath_bench.rs:779,1198,452`), and 1000 B is never batched (the mode header comment `:50-56` says so); only `udppaced` (paced) and `udpps` (blast, collapse incomparable) can go down to 1–512 B.
3. **No wire bytes / send call counting**: only user-layer datagrams/pps/loss/MB/s are printed; the 60 s reporter's `udp relay` is application bytes, not MQP frame bytes or QUIC DATAGRAM counts; `metrics`'s `myquic2_udp_{send_group_size,send_syscalls}` (`src/udp/batch.rs:156-204`) only counts last-hop UDP syscalls and is a no-op without a recorder. To verify "fewer send_datagram/less wire", only `strace -c`/`perf` or temporary counters are possible.
4. **No MQP frame-level counters**: frame kind, TRAIN items, flow compression rate, and inline fallback rate all lack counters (last item of §3), so "whether compression is effective/whether the domain falls back" can only be seen in logs or packet captures.
5. **No protocol A/B switch**: no `mqp3=false`, no compile-time feature, no switch to run two encoders side by side; old/new comparison requires a custom branch/two binaries, and client/server must be replaced in pairs.
6. **Throughput/pps modes cannot see latency**: the module header `:85-94` explicitly says loopback ~0 RTT; `lat`/`lattcp` must be paired with netem (Linux) to be credible.
7. Documentation drift: the mode header comments `:5-108` and the usage string `:214-219` omit several implemented modes (`utag`/`udpdomain`/`udpdomainswitch`/`udpdomainmulti`/`udpraw`/`udpsweep`/`tcpecho`/`reply`); the embedded baseline at `hotpath_bench.rs:1232-1240` is outdated (see C2).
8. No Linux target-machine automation: all run instructions assume manual process startup; CI only does functional smoke (`.github/workflows/release.yml:119-133`: tcpecho/tcp/udpsweep/udpps once each, no performance comparison).

---

## 5. Do-not-repeat list

1. **Do not re-propose the frame buffer pool** — already rejected by full-cell measurement in `frame_bench` (+39–52% same-thread / +128–324% cross-thread); beat that table first before discussing it.
2. **Do not re-propose "client BATCH 2-pack→16-pack"** — the prototype was measured at parity and reverted; HEAD is already covered by `PendingTrain`/TRAIN, and the F8 text is outdated.
3. **Do not re-propose server downlink BATCH/source-run flush optimization** — already replaced by v3 TRAIN mixed-source.
4. **Do not suggest "rewrite the protocol for bulk throughput"** — bulk header <1%, throughput is determined by window/CC/MTU.
5. **Do not write MTU default changes into the protocol refactor** — the 1400→1360→1200 decision was "safety on unknown paths"; MTU is configuration.
6. **Do not propose changing fragment id to u16** — there is a historical measured packet-loss cliff.
7. **Do not raise fragment train** — near-MTU fragmentation does not reduce packet count (arithmetic is settled).
8. **Do not raise cross-session TRAIN** — unless profiling proves the quinn send state lock is the main bottleneck; otherwise the gain is uncertain and complexity high.
9. **Do not treat FEC/NACK as a default gain** — 2 fragments +50% bytes; opt-in only.
10. **Do not assume domain targets can save 33–38%** — HEAD explicitly keeps domains inline; to obtain that gain, three problems must first be solved and wired: "client has no resolved IP / SOCKS reply source address / DNS rebinding security".
11. **Do not assume pure uplink flows are compressed** — implicit ACK only covers flows with a downlink; changing this requires FLOW_ACK (control plane).
12. **Do not use the §5 tables of `PROTOCOL_ANALYSIS.md` as "expected gains already measured"** — they are all models, and they assume "domain compression + compact FRAG + 2-pack status quo".
13. **Do not cite README loopback latency/pps numbers as a baseline** — the same harness has p50 values from three sources (README old tree debug 0.30 ms / README MQP-3 release 0.98 ms / this release smoke 0.236 ms), and 40k vs 21k recv pps differ greatly; only same-machine same-round A/B is valid.
14. **Do not treat "301 tests" as a Linux number** — Linux is 305 (4 Linux-only tests); the README already notes it is a macOS dev box.
15. **Do not repeat PERF_ANALYSIS's file:line** — all are from the `d73809f` baseline; status conclusions are usable, line numbers need re-checking.

---

## 6. Documentation ↔ code drift list

| # | Location | Documentation says | HEAD fact | Impact |
|---|---|---|---|---|
| G1 | `PROTOCOL_ANALYSIS.md:145,513,520-540` | The client status quo is 2-pack, and the model is computed on a 2-pack basis | `assoc.rs:798-1080` `PendingTrain` (≤64-item TRAIN); 2-pack appears only in the test comment `assoc.rs:1222` | The gain tables "relative to the current 2-pack" are invalid; do not use them |
| G2 | `PERF_ANALYSIS.md:58` F8 status | F8 deferred | The same capability has been implemented by TRAIN; the F8 text/line numbers are outdated | The rest of the status table is still valid; the F8 row needs a full rewrite |
| G3 | all file:line in `PERF_ANALYSIS.md` | Baseline `d73809f` | Multiple changes in `348c52d`/`530188e`; F5/F8 line numbers invalid | Cite conclusions only, not line numbers |
| G4 | `README.md:865` vs `:866` | The former `lat p50≈0.30 ms/p99≈0.90 ms` (debug, old tree), the latter `lat p50≈0.98 ms` (MQP-3 release) | This release smoke p50 = 236 µs; the three are mutually inconsistent | Loopback latency cannot be a cross-version threshold; WAN needs netem |
| G5 | `README.md:867` vs `hotpath_bench.rs:1232-1240` | README: N=1 soak ~40k recv pps (~2.6k before the last hop batching) | The in-code baseline (2026-09-30) is goodput 2.6k/370 pps; this run 21k recv pps @86k sent | The two represent different periods; only "order of magnitude/relative" can be cited |
| G6 | `README.md:861` | 301 passed | macOS static count = 301 ✅; Linux = 305 (+4 `cfg(linux)` tests) | Suggest adding a sentence with the Linux number |
| G7 | `dist/openwrt-x86_64/config-server.toml.sample:40` | session pool ~2.06 GiB Linux | Repo `config-server.toml:41` and README:779 are already ~1.09/2.09 GiB (MQP-3 flow table 4 KiB already counted) | Distributed sample config comment outdated |
| G8 | `examples/hotpath_bench.rs:5-108,214-219` | Mode/usage list | Actually 7–8 more entry points (see §4.4 item 7) | Users easily miss `udpdomainswitch`/`udpsweep` etc. |
| G9 | `PROTOCOL_ANALYSIS.md:684-685,723` | Acceptance criteria include a new `udpfanout` | The harness has no such mode | That acceptance criterion cannot be executed |
| G10 | `README.md:29` | "connection count scales linearly" | No measurement data (historically measured at most 24 associations/3-way aggregate) | Should be downgraded to an assertion |
| G11 | `PROTOCOL_ANALYSIS.md:401-405,426-429,638-681` | "Current implementation" status notes | Consistent with HEAD code (domains inline/FRAG not wired/no CAPS) | Safe to cite as HEAD facts |
| G12 | `PERF_ANALYSIS.md:412-436` "not recommended to touch" list | Frame pooling/prefix cache/BATCH decoding/reassembly copy etc. | Consistent with HEAD; BATCH decoding is retained but the production path has switched to TRAIN | Conclusions usable; the "BATCH decoding" context has changed |

---

## 7. Summary for the Lead (≤30 lines)

```text
1. HEAD d2f9658 is version-number only; working tree clean. PROTOCOL_ANALYSIS actually entered the repo
   in 530188e (the same commit as MQP-3), and its main body models the MQP-2/348c52d status quo; the
   PERF_ANALYSIS baseline is d73809f, and all its line numbers are invalid against HEAD.
2. Hardest conclusion: there is no Linux target-machine MQP-3 end-to-end measurement in the repo or git
   history. The MQP-3 gain numbers (wire −9~38%, calls −18×, CPU 1–3%) are all models; the only
   performance-related [L-measured] is the narrow-scope container A/B in 8eebdca. If new analysis claims
   "substantial gains", it must bring its own Linux benchmark plan (Linux 2–4 cores is the acceptance
   threshold repeatedly stated in the docs, but never executed).
3. Protocol-layer ceiling given by the existing models: tiny/domain/fanout wire −9~38%, CPU only 1–3% on
   one core (50–100k pps), bulk ~0. And the HEAD implementation cannot reach the model upper bounds:
   domain targets inline, compact FRAG not wired, pure uplink flow not compressed.
4. Measured-out and prohibited from re-proposal: frame pooling (frame_bench: +39–52%/+128–324%); client
   BATCH N-pack (prototype parity then reverted, already replaced by TRAIN); u16 fragment id (4%/15%/50%
   loss cliff); increasing the default MTU (1400→1360→1200 settled; MTU is configuration, not protocol);
   FEC/NACK on by default (+50% bytes).
5. Decided but re-reviewable in new analysis: 512 B fate-sharing cap, session id u16 (model 2–3%),
   domain/pure-uplink compression (needs control plane + security design). Note: the user allowing wire
   incompatibility does not eliminate their lifecycle/loss-amplification risks; currently no measurement
   supports changing them.
6. The only real protocol gaps absorbable by the refactor are: compact FRAG wiring (6–19 B/fragment),
   domain + pure-uplink flow compression (needs ACK/CAPS), session id u16. F3/F10/F13 are
   system/implementation layer, unrelated to wire; do not package them into the protocol narrative.
7. Harness gaps (must fill first): no udpfanout; udp/udpmulti use 1000 B (never batched); no wire bytes/
   send call counting; no MQP frame-level counters; no protocol A/B switch; no Linux target-machine flow.
   The existing release binary can run short tests directly (this smoke: udppaced 3k pps 0 loss; lat p50
   236 µs; udpps blast loss 66%).
8. Documentation drift highlights: the three README loopback latency values (0.30/0.98/0.236 ms) are
   incomparable; N=1 soak 40k vs the code comment's 2.6k vs this run's 21k; tests 301 is macOS (Linux
   305); dist sample memory comment 2.06 vs 2.09 GiB.
9. Recommended evidence strategy for new analysis: label every gain claim [model]/[pending Linux
   measurement]; fill the harness first (fanout + counters + A/B binaries), then discuss "substantial".
```
