#!/usr/bin/env python3
"""sweep3.py - ACK-oracle write-command sweep (cmd 0x19..0x40).

The device acknowledges accepted commands with a frame
  A5 05 <cmd> <status> <value> ...
so a HIT = receiving a frame starting 'a505' whose 4th byte equals the
command we just sent. Heartbeat noise (cmd 0x07) is ignored.

Usage: python sweep3.py
"""
import threading
import time

import hid

BASELINE_S = 4
WATCH_S = 0.9
PAYLOADS = [
    (b"\x00\x00", "00-00"), (b"\x00\x01", "00-01"), (b"\x01\x00", "01-00"),
    (b"\x00\x02", "00-02"), (b"\x02\x00", "02-00"), (b"\x00\x03", "00-03"),
    (b"\x03\x00", "03-00"), (b"\x01", "01"), (b"\x00", "00"),
    (b"\x00\x00\x00", "000"), (b"\x01\x01", "01-01"),
]


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

    log = []
    lock = threading.Lock()

    def reader():
        while True:
            d = h.read(64, timeout_ms=100)
            if d:
                with lock:
                    log.append((time.time(), bytes(d)))
                    if len(log) > 50000:
                        del log[:25000]

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(BASELINE_S)

    hits = []
    for cmd in range(0x19, 0x41):
        for payload, label in PAYLOADS:
            frame = bytes([0xA5, cmd, len(payload)]) + payload
            h.write(frame + bytes(64 - len(frame)))
            t1 = time.time()
            time.sleep(WATCH_S + 0.25)
            found = None
            with lock:
                for t, f in log:
                    if t < t1 - WATCH_S - 0.3:
                        continue
                    if len(f) > 4 and f[0] == 0xA5 and f[1] == 0x05 and f[2] == cmd:
                        found = f.hex()
                        break
            if found:
                hits.append((cmd, label, found))
                print(f"HIT cmd=0x{cmd:02X} {label} -> {found}")
                break
        else:
            continue
    print(f"\n# {len(hits)} accepted-command hits")
    for cmd, label, found in hits:
        print(f"  0x{cmd:02X} ({label}) ack={found}")
    h.close()


if __name__ == "__main__":
    main()
