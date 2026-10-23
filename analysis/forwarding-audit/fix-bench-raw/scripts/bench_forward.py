#!/usr/bin/env python3
"""Scenario C: raw forwarding-path benchmarks for MyQUIC2.

Talks directly to the client's fixed-destination forward listeners (no SOCKS5):
  udp-pps    <listen> <n> [batch] [payload]   pipelined UDP echo throughput
  udp-lat    <listen> <n> [payload]           serial UDP request->echo latency
  udp-multi  <listen> <peers> <n_per_peer> [batch] [payload]
  tcp-bulk   <listen> <bytes>                 TCP echo throughput (write+read)
  tcp-lat    <listen> <n> [bytes]             serial TCP request->echo latency
Prints one machine-readable line per run plus FAIL/OK.
"""
import socket
import struct
import sys
import threading
import time


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    rank = max(1, int(len(sorted_vals) * p + 0.999999))
    return sorted_vals[min(rank, len(sorted_vals)) - 1]


def lat_summary(samples):
    s = sorted(samples)
    mean = sum(s) / len(s) if s else 0.0
    return (f"p50={pct(s,0.50):.0f} p90={pct(s,0.90):.0f} p99={pct(s,0.99):.0f} "
            f"max={s[-1] if s else 0:.0f} mean={mean:.0f}")


def split_udp(addr):
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def udp_pps(listen, n, batch, payload):
    host, port = split_udp(listen)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect((host, port))
    pkt = bytes((i % 251) for i in range(payload))
    sent = recv = mism = 0
    stalled = 0
    buf = bytearray(65536)
    t0 = time.perf_counter()
    while recv < n:
        while sent < n and sent - recv < batch:
            try:
                s.send(pkt)
                sent += 1
            except OSError:
                break
        try:
            k = s.recv_into(buf)
            if k != payload or bytes(buf[:k]) != pkt:
                mism += 1
            recv += 1
            stalled = 0
        except socket.timeout:
            stalled += 1
            if stalled >= 10:
                break
    dt = time.perf_counter() - t0
    print(f"udp-pps listen={listen} n={n} batch={batch} payload={payload} "
          f"sent={sent} recv={recv} mismatched={mism} wall={dt:.3f}s "
          f"recv_pps={recv/dt:.0f} loss={(100.0*(sent-recv)/sent if sent else 0):.3f}% "
          f"{'OK' if mism == 0 and recv == n else 'INCOMPLETE'}")


def udp_lat(listen, n, payload):
    host, port = split_udp(listen)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.connect((host, port))
    samples = []
    lost = 0
    t0 = time.perf_counter()
    for i in range(n):
        pkt = struct.pack(">Q", i) + bytes((i % 251) for _ in range(payload - 8))
        started = time.perf_counter()
        s.send(pkt)
        try:
            data = s.recv(65536)
        except socket.timeout:
            lost += 1
            continue
        if len(data) != payload or data[8:] != pkt[8:] or struct.unpack(">Q", data[:8])[0] != i:
            lost += 1
            continue
        samples.append((time.perf_counter() - started) * 1e6)
    dt = time.perf_counter() - t0
    print(f"udp-lat listen={listen} n={n} payload={payload} samples={len(samples)} "
          f"lost={lost} wall={dt:.3f}s {lat_summary(samples)} us "
          f"{'OK' if not lost else 'LOSSY'}")


def udp_multi(listen, peers, n_per_peer, batch, payload):
    host, port = split_udp(listen)
    results = []
    lock = threading.Lock()

    def peer(idx):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect((host, port))
        pkt = struct.pack(">I", idx) + bytes((idx % 251) for _ in range(payload - 4))
        sent = recv = mism = 0
        stalled = 0
        buf = bytearray(65536)
        t0 = time.perf_counter()
        while recv < n_per_peer:
            while sent < n_per_peer and sent - recv < batch:
                try:
                    s.send(pkt)
                    sent += 1
                except OSError:
                    break
            try:
                k = s.recv_into(buf)
                if k != payload or bytes(buf[:k]) != pkt:
                    mism += 1
                recv += 1
                stalled = 0
            except socket.timeout:
                stalled += 1
                if stalled >= 10:
                    break
        with lock:
            results.append((time.perf_counter() - t0, sent, recv, mism))
        s.close()

    threads = [threading.Thread(target=peer, args=(i,)) for i in range(peers)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.perf_counter() - t0
    sent = sum(r[1] for r in results)
    recv = sum(r[2] for r in results)
    mism = sum(r[3] for r in results)
    wall = max((r[0] for r in results), default=0.0)
    print(f"udp-multi listen={listen} peers={peers} n_per_peer={n_per_peer} batch={batch} "
          f"payload={payload} sent={sent} recv={recv} mismatched={mism} wall={dt:.3f}s "
          f"recv_pps={recv/dt:.0f} loss={(100.0*(sent-recv)/sent if sent else 0):.3f}% "
          f"max_peer_wall={wall:.3f}s "
          f"{'OK' if mism == 0 and recv == sent == peers*n_per_peer else 'INCOMPLETE'}")


def tcp_bulk(listen, total):
    host, port = split_udp(listen)
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    payload = bytes((i % 251) for i in range(65536))
    sent = [0]
    recv = mism = 0
    t0 = time.perf_counter()

    def writer():
        try:
            while sent[0] < total:
                k = min(len(payload), total - sent[0])
                sock.sendall(payload[:k])
                sent[0] += k
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    writer_done = threading.Event()

    def run_writer():
        writer()
        writer_done.set()

    th = threading.Thread(target=run_writer)
    th.start()
    buf = bytearray(256 * 1024)
    while recv < total:
        try:
            k = sock.recv_into(buf)
        except socket.timeout:
            break
        if k == 0:
            break
        start = recv % len(payload)
        reps = payload * 8
        exp = reps[start:start + k]
        if len(exp) != k or bytes(buf[:k]) != exp:
            mism += 1
        recv += k
    th.join()
    dt = time.perf_counter() - t0
    ok = mism == 0 and recv == total and writer_done.is_set() and sent[0] == total
    print(f"tcp-bulk listen={listen} bytes={total} echoed={recv} mismatched={mism} "
          f"wall={dt:.3f}s {recv/dt/1e6:.1f} MB/s {'OK' if ok else 'FAIL'}")
    sock.close()
    return 0 if ok else 1


def tcp_lat(listen, n, payload):
    host, port = split_udp(listen)
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(2.0)
    pkt = bytes((i % 251) for i in range(payload))
    samples = []
    lost = 0
    t0 = time.perf_counter()
    for _ in range(n):
        started = time.perf_counter()
        sock.sendall(pkt)
        got = 0
        ok = True
        while got < payload:
            k = sock.recv_into(bytearray(payload))
            if k == 0:
                ok = False
                break
            got += k
        if ok:
            samples.append((time.perf_counter() - started) * 1e6)
        else:
            lost += 1
    dt = time.perf_counter() - t0
    print(f"tcp-lat listen={listen} n={n} payload={payload} samples={len(samples)} "
          f"lost={lost} wall={dt:.3f}s {lat_summary(samples)} us "
          f"{'OK' if not lost else 'LOSSY'}")
    sock.close()


def main():
    cmd = sys.argv[1]
    if cmd == "udp-pps":
        udp_pps(sys.argv[2], int(sys.argv[3]),
                int(sys.argv[4]) if len(sys.argv) > 4 else 64,
                int(sys.argv[5]) if len(sys.argv) > 5 else 1000)
    elif cmd == "udp-lat":
        udp_lat(sys.argv[2], int(sys.argv[3]),
                int(sys.argv[4]) if len(sys.argv) > 4 else 64)
    elif cmd == "udp-multi":
        udp_multi(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                  int(sys.argv[5]) if len(sys.argv) > 5 else 32,
                  int(sys.argv[6]) if len(sys.argv) > 6 else 128)
    elif cmd == "tcp-bulk":
        sys.exit(tcp_bulk(sys.argv[2], int(sys.argv[3])))
    elif cmd == "tcp-lat":
        tcp_lat(sys.argv[2], int(sys.argv[3]),
                int(sys.argv[4]) if len(sys.argv) > 4 else 64)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
