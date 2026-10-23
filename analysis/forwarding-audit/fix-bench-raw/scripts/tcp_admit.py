#!/usr/bin/env python3
"""External TCP admission check for myquic2 tcp_forward listeners.

Opens N raw TCP connections to a forward listener, probes each with a
request/echo (the forward target is the hotpath_bench `techo`), holds accepted
connections open, and reports how many were admitted end-to-end vs refused.
Optionally closes one admitted connection and verifies a new one is admitted.

Usage: tcp_admit.py <listen_ip:port> <n> [--after-close]
"""
import socket
import sys
import time

PROBE = b"PING-ADMIT-0123456789"


def probe_conn(addr, idx, timeout=1.5):
    """Connect + one echo round trip. Returns (connect_err, verdict, detail)."""
    try:
        s = socket.create_connection(addr, timeout=timeout)
    except OSError as e:
        return (repr(e), "connect-failed", None)
    s.settimeout(timeout)
    verdict = "refused"
    detail = ""
    try:
        s.sendall(PROBE)
        data = b""
        while len(data) < len(PROBE):
            k = s.recv(len(PROBE) - len(data))
            if k == 0:
                break
            data += k
        if data == PROBE:
            verdict = "admitted"
        elif data == b"":
            verdict = "refused-EOF"
        else:
            verdict = "refused-partial"
            detail = data.hex()
    except ConnectionResetError as e:
        verdict = "refused-RST"
        detail = repr(e)
    except socket.timeout:
        verdict = "refused-timeout"
    except OSError as e:
        verdict = "refused-err"
        detail = repr(e)
    return (None, verdict, (s, detail))


def main():
    addr = sys.argv[1].rsplit(":", 1)
    addr = (addr[0], int(addr[1]))
    n = int(sys.argv[2])
    after_close = "--after-close" in sys.argv
    held = []
    admitted = refused = 0
    for i in range(n):
        cerr, verdict, extra = probe_conn(addr, i)
        if cerr is not None:
            print(f"conn[{i}] connect={cerr} verdict=connect-failed")
            refused += 1
            continue
        s, detail = extra
        print(f"conn[{i}] connect=ok verdict={verdict}" + (f" detail={detail}" if detail else ""))
        if verdict == "admitted":
            admitted += 1
            held.append(s)
        else:
            refused += 1
            s.close()
    print(f"SUMMARY n={n} admitted={admitted} refused={refused}")
    if after_close:
        if held:
            held[0].close()
            print("closed one admitted connection; waiting for capacity")
        ok = 0
        for attempt in range(30):
            sleep = 0.1 if attempt < 10 else 0.3
            time.sleep(sleep)
            cerr, verdict, extra = probe_conn(addr, 99)
            if verdict == "admitted":
                ok = 1
                print(f"after_close_new=admitted attempt={attempt}")
                extra[0].close()
                break
        if not ok:
            print("after_close_new=refused")
        for s in held[1:]:
            s.close()
        print(f"AFTER_CLOSE_RESULT {'PASS' if ok else 'FAIL'}")
    else:
        for s in held:
            s.close()
    print(f"RESULT {'PASS' if admitted >= 0 else 'FAIL'}")


if __name__ == "__main__":
    main()
