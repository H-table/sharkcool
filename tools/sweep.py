#!/usr/bin/env python3
"""sweep.py - oracle-based write-command discovery for BRB02 cooler.

Opens the cooler, watches incoming frames in a reader thread, and sends
candidate "A5 cmd len payload" frames. A candidate is flagged as a HIT if,
within a short window after sending, a NEW unique frame appears (one not
seen in the baseline) — the device acknowledges accepted commands with
response frames (we observed A5 05 24 config responses after app actions).

Usage: python sweep.py [--baseline 10]
"""
import sys
import threading
import time

import hid

BASELINE_S = 8
WATCH_S = 1.3
GAP_S = 0.4


def main():
    path = None
    for d in hid.enumerate(0xE2B7, 0x7001):
        path = d["path"]
        break
    if path is None:
        sys.exit("cooler not found")

    h = hid.device()
    h.open_path(path)
    h.set_nonblocking(1)

    seen = {}          # hex -> count
    lock = threading.Lock()
    timestamps = []    # (t, hex)

    def reader():
        while True:
            data = h.read(64, timeout_ms=100)
            if data:
                with lock:
                    hexs = bytes(data).hex()
                    seen[hexs] = seen.get(hexs, 0) + 1
                    timestamps.append((time.time(), hexs))
                    if len(timestamps) > 200000:
                        del timestamps[:100000]

    th = threading.Thread(target=reader, daemon=True)
    th.start()

    print(f"baseline: listening {BASELINE_S}s ...")
    base = {}
    t0 = time.time()
    while time.time() - t0 < BASELINE_S:
        time.sleep(0.2)
        with lock:
            base = dict(seen)
    print(f"baseline frames: {len(base)} unique")
    interesting = {k for k in base if k.startswith("a50524") or k.startswith("a50926") or k.startswith("a51326")}

    def send(b):
        buf = bytes([0xA5]) + b
        padded = buf + bytes(64 - len(buf))
        h.write(padded)

    hits = []
    # candidate families: SetCoolingConfig(mode) guesses for cmd 01..0x18
    # payloads: [mode, 0], [0, mode], [mode], [00 mode]... plus fan on/off
    payloads = [
        (b"\x00\x00", "cfg0"), (b"\x01\x00", "mode1"), (b"\x02\x00", "mode2"),
        (b"\x03\x00", "mode3"), (b"\x00\x01", "mode1b"), (b"\x00\x02", "mode2b"),
        (b"\x00\x03", "mode3b"), (b"\x01", "m1c"), (b"\x02", "m2c"),
        (b"\x03", "m3c"), (b"\x00", "m0c"), (b"\x01\x01", "on1"), (b"\x00\x00\x01", "on2"),
    ]
    total = 0
    for cmd in range(0x01, 0x19):
        for payload, label in payloads:
            frame = bytes([cmd, len(payload)] + list(payload))
            before = len(seen)
            before_rpm = None
            send(frame)
            total += 1
            # watch window
            t1 = time.time()
            newly = []
            while time.time() - t1 < WATCH_S:
                time.sleep(0.1)
            with lock:
                for k, c in seen.items():
                    if c >= 1:  # check
                        pass
                # collect frames seen in window
                win = [hexs for t, hexs in timestamps if t1 - 1.5 <= t <= time.time()]
                newly = list(dict.fromkeys(w for w in win if w not in base))
                if len(newly) > 1:
                    break
            if newly:
                hits.append((frame, label, newly))
                print(f"HIT  cmd=0x{cmd:02X} {label} -> {newly}")
                # update baseline so repeated hits still count
                with lock:
                    for k in newly:
                        base[k] = base.get(k, 0) + 1
                time.sleep(1.0)
            time.sleep(GAP_S)
        print(f"[cmd {cmd:02X} done]")
    print(f"\n# {total} candidates, {len(hits)} hits")
    for frame, label, newly in hits:
        print(f"  {frame.hex(' ')}  {label}  ->  {newly}")
    h.close()


if __name__ == "__main__":
    main()
