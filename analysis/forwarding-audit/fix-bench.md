# Post-fix benchmark + external admission checks (task-9)

Repo: `/Users/eric/WorkSpace/MyQUIC2`. Working tree = HEAD `7232088` + the **uncommitted fix round** (14 modified files; `git status --short`: `forward.rs` +283, `forward_udp.rs` +739, `client_conf.rs` +286, `main.rs`, `socks.rs`, `util.rs`, `assoc.rs`, `dispatcher.rs`, `tuning.rs`, `lib.rs`, tests, README/config samples). Audit baseline: `analysis/forwarding-audit/bench.md` (pre-fix). Date: 2026-10-23.
Build: `CARGO_TARGET_DIR=/tmp/mq2-target-head cargo build --release --bin myquic2-server --bin myquic2-client --example hotpath_bench` → **38.47 s** (incremental; main tree `target/` untouched). Parent arm reuses `/tmp/mq2-target-parent/release/myquic2-client` (`39997607…`), unchanged since the pre-fix audit.

| binary | sha256 |
|---|---|
| post-fix server (used for **both** arms) | `23b207c19d14101f16b3daf8433eee0d981c9073f2926381397d559b117d2a96` |
| post-fix client | `cc5723e4c201836485ddca621c4dfd320d13a61a6133b8e6988451aa4630f8d5` |
| parent client `1135076` | `39997607bf60ce99e6e01e06f18394f8aa91d985c7d4a38954683c34db0eca0b` |
| `examples/hotpath_bench` | `9b3fc7c2ffdd10fc0db19590ec17cd849b5f505464236ea583b452a665c064f1` (unchanged) |

Topology/ports/certs/targets/configs are identical to the pre-fix audit (`/tmp/mq2-bench`): HEAD server `127.0.0.1:18443` (BBR, gso, `quic_endpoints=1`, `allow_private=true`, auth off), SOCKS `127.0.0.1:18080`, `techo` TCP echo `19000`, `echo` UDP echo `19001`, plain BBR/gso/`quic_conns=4` client config. Method: fresh server+client pair per arm-run, arms interleaved with rotated order, warm-up discarded, 5 s-stall `udp` runs excluded from pps but counted as lossy. System load average 3.16–6.84 on 10 cores during the campaign (unrelated workload; raw logs carry the per-run `uptime` line).

## A. SOCKS5 ECHO A/B — post-fix HEAD vs parent (fresh interleaved campaign)

3 reps/arm, every arm-run = 10 × `udp` blast (n=10,000, batch 64) + 3 × `udppaced` 30 k pps + 2 × `udpbidir` 20 k pps + 5 × `lat` + 3 × `lattcp` + 5 × `tcpecho` 8 MiB. 30 measured UDP-blast runs per arm, 18 latency runs per arm.

| metric | parent `1135076` | post-fix HEAD | pre-fix HEAD (bench.md) | pre-fix parent (bench.md) |
|---|---|---|---|---|
| `udp` blast clean pps median [min; IQR; max] | **31,704.5** [27,752; 30,716–33,017; 34,252] (26/30 clean) | **29,644** [26,537; 27,526–33,676; 35,303] (19/30 clean) | 30,571 (28/40 clean) | 33,088 (34/40 clean) |
| clean-pps ratio HEAD/parent | — | **0.935 (−6.5 %)** | **0.924 (−7.6 %)** | — |
| lossy blast runs | 4/30 (13.3 %) | 11/30 (36.7 %) | 12/40 (30 %) | 6/40 (15 %) |
| `udppaced` 30 k loss %, 6 runs/arm | median 0 (max 0.2) | median 0 (max 1.8, n=12) | median 0 | median 0 |
| `udppaced` 30 k recv_pps median | 27,234.5 | 27,216.5 | identical | identical |
| `udpbidir` 20 k loss % | 0.000 all 6 runs | median 0 (one 0.2) | 0.000 | 0.000 |
| `lat` p50 / p99 (µs, in-suite) | 117 / 300.5 | 116 / 355 | 116 / 327 | 116 / 320 |
| `lat` isolated fresh-client p50 / p99 (3 reps × 5 runs) | 116 / 282 | 119 / 295 | pre-fix isolated: 116 / 327 (HEAD) | pre-fix isolated: 116 / 320 |
| `lattcp` connect / echo p50 (µs) | 103 / 130 | 104 / 132 | 100.5 / 132 | 99 / 131 |
| `tcpecho` 8 MiB MB/s (18 runs/arm) | median 54.9; fast-mode (>70 MB/s) 7/18, median 88.9 | median 47.2; fast-mode 4/18, median 87.7 | fast mode ~89.1 | fast mode ~89.5 |

**Verdict A: the fix round did not change the SOCKS5 ECHO numbers, and the earlier unpaced-blast delta persisted.**
- HEAD/parent clean-pps ratio went **0.924 (pre-fix) → 0.935 (post-fix)**, i.e. the −7.6 % finding is reproduced as −6.5 % and is **not** explained or removed by the fix round. The relative excess of lossy blast runs also persisted (30 % vs 15 % pre-fix; 36.7 % vs 13.3 % post-fix). Merging both rounds: 30/85 lossy runs for HEAD vs 13/85 for parent (Fisher two-sided **p = 0.0044**), so this is a stable property of the `41031b4` client feature code (the fix round touched forward paths and shared plumbing, not the SOCKS UDP dispatch shape that bench.md §2.5 flagged).
- Both arms' absolute medians are 4–5 % below the previous campaign (parent 33,088 → 31,704; pre-fix HEAD 30,571 → 29,644), i.e. machine-level drift hit both arms; the ratio is the comparable lens.
- Steady-state/paced UDP, serial latency (isolated), TCP connect/echo latency and TCP bulk steady-state throughput are unchanged vs parent and vs the pre-fix round. The in-suite `lat` p99 HEAD>parent gap seen pre-fix reappears (355 vs 300 µs) but again does not reproduce isolated (295 vs 282 µs, overlapping ranges) — same unresolved tail note as bench.md §2.3.

## B. External admission checks (new behaviour)

Each check used a dedicated client config (all archived), fresh server+client, and an external python client; output archived in `fix-bench-raw/fix-b.out` (+ `-b4c.out`).

### B1 TCP per-listener cap — `[[tcp_forward]] max_conns = 2` — **PASS**
5 raw TCP connections opened/most-probed sequentially and held open: `conn[0..1] verdict=admitted`, `conn[2..4] verdict=refused-RST (ConnectionResetError 54)` → **2 admitted / 3 RST**. Closing one admitted connection: `after_close_new=admitted attempt=0` → capacity returned immediately.
Client log evidence: `WARN myquic2_client::forward: tcp_forward 127.0.0.1:18181 listener connection limit 2 reached; dropping 127.0.0.1:57480`

### B2 TCP process-wide forward budget — `max_forward_conns = 2` (listener `max_conns = 5`) — **PASS**
Same shape: **2 admitted / 3 RST**, closing one admits the next (`attempt=0`).
Client log evidence: `WARN … tcp_forward 127.0.0.1:18181 process-wide forward connection budget exhausted; dropping 127.0.0.1:57489 (raise max_forward_conns or lower max_conns)`

### B3 UDP per-listener cap — `[[udp_forward]] max_sessions = 2` — **PASS** (primary), with a latency caveat (see B4)
5 distinct ephemeral source sockets, one 20 B datagram each, 0.6 s reply timeout: `peer[0..1] admitted` (RTT 1.9/1.6 ms), `peer[2..4] refused-timeout` → **2 admitted / 3 refused**. Warning lines present with drop counters and suppression: `udp_forward 127.0.0.1:19001 listener session limit 2 reached; dropping datagram from 127.0.0.1:57874 (1 so far)` … `(14 so far)`.
Aging extension: after 5.2 s idle, a fresh peer was admitted after **27.50 s** of retries — correct direction (eventually admits, <<180 s) but far above the 5 s idle floor; root cause is the same `replied`-fold behaviour as B4.

### B4 Eviction — `max_sessions = 1`, peer A sent and **received a reply**, then stayed idle; peer B retried every 100 ms — **PASS vs the 180 s idle-reap criterion, NOT vs the expected <10 s**
`peerA=admitted(reply received)`, `peerB=admitted attempts=50 b_admit_latency=34.52 s a_idle_at_admit=35.02 s`.

**Root cause identified in the code (not a test artifact):** the admission eviction scan (`forward_udp.rs::evict_one_idle`) deliberately skips peers whose `AssocEntry::replied` flag is set ("reply activity the tick has not folded yet must keep the peer"), and that flag is folded into the idle stamp only by the listener's idle tick every `ASSOC_IDLE_TICK_SECS = 30` (`hub.rs`). A peer that ever received a reply therefore becomes evictable only after the next 30 s tick **plus** the 5 s `EVICT_MIN_IDLE_MS` floor → measured 34.5 s; bounded worst case ≈ 35 s + tick jitter, still far below the 180 s reap.

**B4c control — PASS:** rerun with a flaky echo target that drops the first datagram per source (so A has a session but **no reply activity**): `peerB=admitted attempts=2 b_admit_latency=0.70 s a_idle_at_admit=6.71 s`. This proves the 5 s `EVICT_MIN_IDLE_MS` floor itself works; the 34.5 s in B4 is entirely the pending-`replied` fold path.
(B4b, a black-hole-target control, is **invalid by design** — the fixed target never echoes B either, so admission cannot be observed; kept in raw only for transparency.)

### B5 Forwarding-path regression sanity (default limits) — **PASS**
- UDP forward pps (1000 B, n=10,000, batch 64, 5 runs): 29,961 / 30,874 / **30,573** clean (median of clean), plus 2 runs that lost 1 datagram (0.020 %; same 5 s-stall artifact) — versus pre-fix 32,267; within load/run noise, no loss increase beyond the single-datagram tail.
- 50 concurrent UDP peers × 2000 datagrams (128 B, batch 32), twice: **100,000/100,000 delivered, 49,167 pps and 51,391 pps, 0.000 % loss** both runs.
- TCP forward SHA-256 integrity, 8 MiB ×10: **10/10 `sha256_match=True`**, steady state 87.8–95.5 MB/s (first 3 connections 20.0–63.1 MB/s warm-up, same bimodality as the SOCKS path).

### B results matrix

| check | verdict | key evidence |
|---|---|---|
| B1 tcp_forward `max_conns=2` | **PASS** | 2/5 admitted, 3 RST; close→new admitted; listener-limit WARN |
| B2 `max_forward_conns=2` | **PASS** | 2/5 admitted, 3 RST; close→new admitted; budget-exhausted WARN |
| B3 udp_forward `max_sessions=2` | **PASS** | 2/5 peers replied, 3 refused; session-limit WARN with counters |
| B4 eviction (reply-active peer) | **PASS (180 s) / deviation (<10 s)**: 34.52 s admit, A idle 35.02 s | pending `replied` flag folded only at the 30 s idle tick |
| B4c eviction floor control (no reply activity) | **PASS** | admit latency 0.70 s, A idle 6.71 s |
| B5 forward pps / 50 peers / TCP SHA-256 | **PASS** | see numbers above |

## C. Cleanup and scope

- Every server/client/target/helper process started for these checks was killed by captured PID; final `ps aux | grep -E 'myquic2-(server|client)|hotpath_bench|flaky_echo'` → **NONE**. No leftover daemons; the one orphan from a failed first B-run was found and killed (PID 26107) before the rerun.
- Only `/tmp` build dirs used (`/tmp/mq2-target-head`, `/tmp/mq2-target-parent`); main tree `target/` untouched; no repository source file modified by this task. Writes limited to `analysis/forwarding-audit/fix-bench.md` and `fix-bench-raw/`.
- Raw logs: `fix-bench-raw/{fix-ab.out, fix-ab-{parent,fixed}-r{1..3}.log, fix-b.out, fix-b4c.out, postfix-latfocus.out, fix-b*-client.log, binary-sha256-postfix.txt, configs/, scripts/}`.

## Go / no-go

- **Regression: GO.** The fix round causes no new regression in SOCKS5 UDP/TCP ECHO, no regression in the forwarding paths, and the TCP forward integrity/SHA-256 and multi-peer UDP numbers are clean. The pre-fix unpaced-UDP-blast HEAD-vs-parent delta (−7.6 %) **persists unchanged** (−6.5 %) and is therefore attributable to the `41031b4` feature code, not to this fix round.
- **Admission behaviour: GO with one documented caveat.** The new three-level limits are enforced end-to-end from outside the process and are observable per level in the client log (B1/B2/B3). Eviction works and is bounded well under the 180 s reap, but for a peer that received a reply the measured admit latency is **34.5 s, not <10 s**, because the `replied` guard is only cleared by the 30 s idle tick. If the product intent is "a waiting UDP peer is admitted within roughly the 5 s floor", the owner should consider folding/consuming `replied` during the eviction scan (or shortening the fold interval); if 34.5 s worst case is acceptable, no code change is needed. This is the only open item from this task.

## B4 follow-up (post-fold) — task-11

The Lead fixed the B4 caveat after the run above: `evict_one_idle` (src/bin/myquic2-client/forward_udp.rs) now **folds** pending reply activity with `AssocEntry::idle_since_tick(now, EVICT_MIN_IDLE_MS)` (consumes `replied`, stamps `last = now`) instead of skipping flagged peers. Inline test updated; workspace gate green (fmt/clippy, 566 tests). Only B4 and its B4c control were re-run; the change is confined to eviction victim selection.

Rebuild: `CARGO_TARGET_DIR=/tmp/mq2-target-head cargo build --release --bin myquic2-client --bin myquic2-server --example hotpath_bench` → 33.28 s. Post-fold client sha256 `d700b48084aa0490cbff98f55f1ee41dcf30e038c353818d788f1c4d1a72ada3` (server unchanged `23b207c1…`, i.e. client-only change). Harness: same configs (`fix-bench-raw/configs/client-fix-b4.toml` `max_sessions=1` → echo target; `client-fix-b4c.toml` → flaky target), `fix-bench-raw/scripts/task11_run.sh`, raw output `fix-bench-raw/fix-b4-followup.out`.

| check | pre-fold (task-9) | **post-fold (task-11)** | verdict |
|---|---|---|---|
| B4: A sends+gets reply, goes idle; B retries every 100 ms | A admitted, **B admitted after 34.52 s** (A idle 35.02 s) | A admitted; **B admitted after 4.94 s, A idle 5.44 s at admit** | **PASS** — ~floor (5 s) + one scan, well under 10 s |
| B4c control: no reply activity (flaky target drops 1st datagram/source) | B admitted after 0.70 s (A idle 6.71 s) | B admitted after 0.71 s (A idle 6.71 s) | **PASS** (unchanged) |

Evidence (post-fold run): `peerA=admitted(reply received)` / `peerB=admitted attempts=8 b_admit_latency=4.94s a_idle_at_admit=5.44s` / `EVICT_RESULT PASS`; client log shows the expected refusal line with counters before the eviction (`udp_forward 127.0.0.1:19001 listener session limit 1 reached; dropping datagram … (1 so far)`, `(3 so far)`), then B's session is admitted. `a_idle_at_admit = 5.44 s ≥ EVICT_MIN_IDLE_MS` confirms the 5 s floor is still respected (the fold does not evict a peer that is genuinely active/recent). Raw: `fix-bench-raw/fix-b4-followup.out`, `fix-bench-raw/fix-b4-followup-client.log`, `fix-bench-raw/fix-b4-followup-b4c-client.log`.

**Result: the B4 caveat is closed.** With the fold in place a reply-active idle peer is evicted and the waiting peer admitted in **4.94 s** instead of 34.5 s; the B4c floor control is unchanged at 0.71 s. The Go/no-go above remains **GO** with no open admission-latency item. All processes started for this re-run were killed (final `ps` check: NONE).
