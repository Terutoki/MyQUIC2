import socket, threading, sys, time
PAT = bytes((i % 251) for i in range(65536))
TOTAL = 8388608

def run(port, label):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(10)
    sent = [0]
    def writer():
        while sent[0] < TOTAL:
            k = min(len(PAT), TOTAL - sent[0])
            s.sendall(PAT[:k]); sent[0] += k
        s.shutdown(socket.SHUT_WR)
    th = threading.Thread(target=writer); th.start()
    buf = bytearray(256*1024); recv = 0; bad = 0; details = []
    while recv < TOTAL:
        try: k = s.recv_into(buf)
        except socket.timeout: break
        if k == 0: break
        start = recv % len(PAT)
        exp = (PAT*8)[start:start+k]
        got = bytes(buf[:k])
        if got != exp:
            bad += 1
            if len(details) < 3:
                i = next((j for j in range(min(len(got), len(exp))) if got[j] != exp[j]), 0)
                details.append((recv, k, start, i, got[i:i+8].hex(), exp[i:i+8].hex()))
        recv += k
    th.join(); s.close()
    print(f"{label} port={port} recv={recv} bad_chunks={bad} details={details}", flush=True)
    return bad, recv

if __name__ == "__main__":
    port = int(sys.argv[1]); n = int(sys.argv[2])
    tot_bad = 0
    for i in range(n):
        b, r = run(port, f"run{i}")
        tot_bad += b
    print("TOTAL_BAD_CHUNKS", tot_bad)
    sys.exit(0 if tot_bad == 0 else 1)
