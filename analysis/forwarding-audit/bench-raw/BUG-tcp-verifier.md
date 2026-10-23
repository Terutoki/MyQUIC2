# S0 outcome — the TCP "mismatch" lines were a verifier bug, not relay corruption

Context: scenario C (`bench-raw/forward.out`, `tcp-bulk` lines from the *first* run) reported
`mismatched=1` and `mismatched=4` on 2 of 4 TCP bulk runs through the `tcp_forward`
listener. The lead flagged this as a potential S0 (data corruption). It was investigated and
**closed as a benchmark-harness artifact**. No relay bug exists.

## Root cause (old verifier in `bench_forward.py::tcp_bulk`)

```python
payload = bytes((i % 251) for i in range(65536))   # 65536 B
...
start = recv % len(payload)                        # stream offset within the pattern
reps  = payload * (8 if k > 2 * len(payload) else 2)   # 131072 or 524288 B
exp   = reps[start:start + k]
if len(exp) != k or bytes(buf[:k]) != exp:
    mism += 1
```

When `k <= 131072`, `reps` is only 131072 B, so for any nonzero `start` with
`start + k > 131072` the expected slice is truncated and the `len(exp) != k` guard counts a
false mismatch. `recv_into` on this path regularly returns 65–131 KiB chunks, so 1–4 chunks
per 8 MiB transfer were misflagged. The relay and the echo target were never involved.

## Fix

Build the expected bytes long enough for every possible `start + k` (recv buffer is 256 KiB,
offset < 64 KiB → 512 KiB suffices):

```python
reps = payload * 8          # 524288 B
exp  = reps[start:start + k]
```

## Verification (corrected verifiers, same binaries/config; files in this directory)

| check | runs | result | artifact |
|---|---|---|---|
| SHA-256 of the whole 8 MiB echoed stream, direct to the `techo` target (no proxy) | 5 | 5/5 hash match | `tcp-integrity.out` |
| SHA-256 through `tcp_forward` listener `127.0.0.1:18181` | 10 | **10/10 hash match**, 18.6–91.5 MB/s | `tcp-integrity.out` |
| SHA-256 through SOCKS `tcpecho` (Rust harness, byte compare) | 10 | **10/10 OK**, 73.4–95.2 MB/s | `tcp-integrity.out` |
| corrected chunk-by-chunk compare, direct target | 10 | 0 bad chunks | `dbg-chunk-compare.txt` |
| corrected chunk-by-chunk compare, through forward listener | 20 | 0 bad chunks | `dbg-chunk-compare.txt` |

Verifier scripts: `scripts/tcpverify.py` (SHA-256 full stream), `scripts/tcpdebug.py`
(chunk compare with first-mismatch diagnostics), `scripts/bench_forward.py` (fixed).
Reproduce:

```sh
# with server + client-head-b running and hotpath_bench targets up:
python3 scripts/tcpverify.py 127.0.0.1:19000 8388608 direct
python3 scripts/tcpverify.py 127.0.0.1:18181 8388608 fwd
python3 scripts/tcpdebug.py 18181 20
```

**Do not cite the old `tcp-bulk ... FAIL` lines as corruption evidence; they were produced by
a buggy comparator and are superseded by the SHA-256 results above.**
