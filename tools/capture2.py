#!/usr/bin/env python3
"""capture2.py - collect unique frames from the cooler for T seconds.

Opens the cooler HID path, reads input reports, dedupes by payload,
records timestamp/count for each unique frame, prints a summary and
saves a hex dump to frames_live.hex.

Usage: python capture2.py [seconds]
"""
import sys
import time
from collections import defaultdict

import hid


def main():
    secs = 60
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
    print(f"listening {secs}s on vid=0xE2B7 pid=0x7001 ...")

    seen = defaultdict(list)   # hex -> [timestamps]
    t0 = time.time()
    while time.time() - t0 < secs:
        data = h.read(64, timeout_ms=200)
        if data:
            seen[bytes(data).hex()].append(time.time())
    h.close()

    print(f"\n# total unique frames: {len(seen)}")
    rows = sorted(seen.items(), key=lambda kv: -len(kv[1]))
    with open("frames_live.hex", "w", encoding="utf-8") as fo:
        for idx, (hexs, ts) in enumerate(rows):
            first = ts[0] - t0
            print(f"[{idx:03d}] x{len(ts):4d} first@+{first:6.2f}s "
                  f"avg_gap={sum(ts[i+1]-ts[i] for i in range(len(ts)-1))/max(1,len(ts)-1)*1000:7.0f}ms")
            print(f"       {hexs}")
            fo.write(f"[{idx:03d}] x{len(ts):4d} {hexs}\n")
    print("# saved to frames_live.hex")


if __name__ == "__main__":
    main()
