#!/usr/bin/env python3
"""sweep2.py - GET-style request sweep with strict oracle.

Sends 'A5 req 00' (empty payload) for req in 0x01..0x24, several repeats,
and flags a HIT only when a NEW non-heartbeat (cmd != 0x07) frame appears
right after the send - those are device responses to the request.

Usage: python sweep2.py
"""
import threading
import time

import hid

BASELINE_S = 6
WATCH_S = 1.0
REPEAT = 3


def main():
    path = None
    for d in hid.enumerate(0xE2B7, 0x7001):
        path = d["path"]
        break
    if path is None:
        raise SystemExit("cooler not found")

    h = hid.device()
    h.open_path(path)
    h.set_nonblocking(1)

    seen = {}
    lock = threading.Lock()
    log = []  # (t, frame)

    def reader():
        while True:
            data = h.read(64, timeout_ms=100)
            if data:
                with lock:
                    f = bytes(data)
                    seen[f.hex()] = seen.get(f.hex(), 0) + 1
                    log.append((time.time(), f))
                    if len(log) > 50000:
                        del log[:25000]

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(BASELINE_S)
    with lock:
        base = set(seen)
    print(f"baseline {len(base)} unique frames")

    hits = []
    for req in range(0x01, 0x25):
        for rep in range(REPEAT):
            frame = bytes([0xA5, req, 0x00])
            h.write(frame + bytes(64 - len(frame)))
            t1 = time.time()
            time.sleep(WATCH_S)
            with lock:
                win = [f for t, f in log if t > t1 - WATCH_S - 0.2]
            new = []
            for f in win:
                if f.hex() not in base and f[1] != 0x07:
                    new.append(f)
            if new:
                hits.append((req, rep, [f.hex() for f in new]))
                # include in baseline so we don't spam
                with lock:
                    for f in new:
                        base.add(f.hex())
                print(f"HIT req=0x{req:02X} rep={rep} -> {[f.hex() for f in new]}")
                break
        else:
            continue
    print(f"\n# hits: {len(hits)}")
    for req, rep, fs in hits:
        print(f"  req=0x{req:02X} -> {fs}")
    h.close()


if __name__ == "__main__":
    main()
