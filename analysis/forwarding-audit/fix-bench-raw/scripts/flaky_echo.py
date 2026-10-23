#!/usr/bin/env python3
"""UDP echo target that DROPS the first datagram from each source address and
echoes every subsequent one. Used to create a peer session with no reply
activity (so the client's `replied` flag stays clear) while still letting
another peer verify admission via a reply."""
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
seen = set()
print(f"flaky echo on 127.0.0.1:{port} (drops first datagram per source)", flush=True)
while True:
    data, src = s.recvfrom(65535)
    if src not in seen:
        seen.add(src)
        continue
    s.sendto(data, src)
