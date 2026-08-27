#!/usr/bin/env python3
"""decode.py - live decode of BRB02 cooler heartbeat (RPM monitor MVP).

Reads input reports, decodes A5-framed packets, prints fan RPM (u16le)
and the secondary u16 field, plus counts other command frames.

Usage: python decode.py [seconds]
"""
import sys
import time
from collections import Counter

import hid


def main():
    secs = 10
    if len(sys.argv) > 1:
        secs = int(sys.argv[1])
    path = None
    for d in hid.enumerate(0xE2B7, 0x7001):
        path = d["path"]
        break
    if path is None:
        sys.exit("cooler not found")

    h = hid.device()
    h.open_path(path)
    h.set_nonblocking(1)
    print(f"decoding {secs}s ...\n")

    cmdctr = Counter()
    t0 = time.time()
    n = 0
    while time.time() - t0 < secs:
        data = h.read(64, timeout_ms=200)
        if not data:
            continue
        b = bytes(data)
        n += 1
        if len(b) >= 9 and b[0] == 0xA5:
            cmd, ln = b[1], b[2]
            cmdctr[cmd] += 1
            if cmd == 0x07 and ln == 0x06:
                rpm = int.from_bytes(b[3:5], "little")
                field2 = int.from_bytes(b[5:7], "little")
                ts = time.time() - t0
                bar = "#" * min(50, (rpm - 2000) // 30) if rpm > 2000 else ""
                print(f"t={ts:5.1f}s  cmd=07 RPM={rpm:5d}  f2={field2:5d}  {bar}")
            else:
                print(f"t={time.time()-t0:5.1f}s  cmd=0x{cmd:02X} len=0x{ln:02X} "
                      f"payload={b[3:3+ln].hex(' ')}")
    h.close()
    print(f"\n# {n} reports; cmd histogram: "
          + ", ".join(f"0x{c:02X}x{k}" for c, k in cmdctr.most_common()))


if __name__ == "__main__":
    main()
