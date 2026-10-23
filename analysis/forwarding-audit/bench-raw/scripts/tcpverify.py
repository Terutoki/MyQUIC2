#!/usr/bin/env python3
"""Robust TCP echo integrity verifier (SHA-256, no offset arithmetic).

Writes a deterministic byte stream to `endpoint` (forward listener or direct
echo target), half-closes, then hashes everything read back and compares with
the expected stream hash. Any duplication, reordering, loss or corruption
changes the hash. Payload: repeating 0..250 pattern (251 period), `total` bytes.
"""
import hashlib
import socket
import sys
import threading
import time

PATTERN = bytes((i % 251) for i in range(65536))


def expected_stream(total):
    reps = total // len(PATTERN) + 1
    return (PATTERN * reps)[:total]


def run(endpoint, total, label):
    host, port = endpoint.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=10)
    sock.settimeout(10)
    stream = expected_stream(total)
    want = hashlib.sha256(stream).hexdigest()
    sent = [0]
    writer_err = [None]

    def writer():
        try:
            view = memoryview(stream)
            while sent[0] < total:
                k = sock.send(view[sent[0]:sent[0] + 65536])
                sent[0] += k
            sock.shutdown(socket.SHUT_WR)
        except OSError as e:  # peer closed early: report as harness error, not corruption
            writer_err[0] = repr(e)

    t0 = time.perf_counter()
    th = threading.Thread(target=writer)
    th.start()
    got = 0
    h = hashlib.sha256()
    buf = bytearray(256 * 1024)
    while got < total:
        try:
            k = sock.recv_into(buf)
        except socket.timeout:
            break
        if k == 0:
            break
        h.update(buf[:k])
        got += k
    th.join()
    dt = time.perf_counter() - t0
    sock.close()
    ok = (h.hexdigest() == want) and got == total and sent[0] == total and writer_err[0] is None
    print(f"tcpverify {label} endpoint={endpoint} bytes={total} echoed={got} "
          f"sha256_match={h.hexdigest() == want} wall={dt:.3f}s {got/dt/1e6:.1f} MB/s "
          f"{'OK' if ok else 'FAIL'} writer_err={writer_err[0]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1], int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else "-"))
