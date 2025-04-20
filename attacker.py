#!/usr/bin/env python3
import sys
import threading
import time
import random
from socket import (
    socket,      # the class
    AF_INET,
    SOCK_DGRAM,
    SOL_SOCKET,
    SO_BROADCAST,
    SO_REUSEADDR,
    SO_REUSEPORT,
)


PORT         = 50000
BROADCAST_IP = "255.255.255.255"
K_THRESHOLD  = int(sys.argv[1]) if len(sys.argv) > 1 else 3
INJECT_DELAY = 5  # seconds between injections


# stash valid share‐literals by senderID
stored_shares = {}  # { node_id: set of node_chunk literals }

def sniff_shares():

    sniffer = socket(AF_INET, SOCK_DGRAM)
    sniffer.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sniffer.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    sniffer.bind(("", PORT))
    print(f"[+] Sniffer listening on UDP port {PORT}…\n")
    while True:
        data, addr = sniffer.recvfrom(4096)
        try:
            parts       = data.decode('utf-8').split("||")
            node_chunk  = parts[0].strip()
            node_hash   = parts[1].strip()
            node_id  = parts[2].strip()
            k_str      = parts[3].strip()
        except ValueError:
            print(f"[!] Malformed packet from {addr}: {data!r}\n")
            continue

        print(f"[+] INTERCEPT from {addr}:")
        print(f"    • chunk:    {node_chunk}")
        print(f"    • hash:     {node_hash}")
        print(f"    • senderID: {node_id}")
        print(f"    • k:        {k_str}\n")

        try:
            node_chunk_bytes = eval(node_chunk_literal)
        except Exception:
            # skip anything that's not a valid bytes literal
            continue

        # stash for later replay
        stored_shares.setdefault(node_id, set()).add(node_chunk_bytes)


def generate_fake_shares():
 
    injector = socket(AF_INET, SOCK_DGRAM)
    injector.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    while True:
        shares_copy = stored_shares.copy()
        shares = shares_copy.items()
        for node_id, chunks in shares:
            if not chunks:
                continue
            fake_chunk = random.choice(list(chunks))
            fake_hash  = str(random.getrandbits(64))
            escaped       = ''.join(f"\\x{b:02x}" for b in fake_bytes)
            fake_literal  = f'b"{escaped}"'

            msg = f"{fake_literal}||{fake_hash}||{node_id}||{K_THRESHOLD}"
            injector.sendto(msg.encode('utf-8'), (BROADCAST_IP, PORT))
            print(f"[!] INJECTED fake share → sender={node_id}, hash={fake_hash}\n")
            time.sleep(INJECT_DELAY)

if __name__ == "__main__":
    t1 = threading.Thread(target=sniff_shares,    daemon=True)
    t2 = threading.Thread(target=generate_fake_shares, daemon=True)
    t1.start()
    t2.start()
    # keep main thread alive
    while True:
        time.sleep(1)
