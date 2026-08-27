#!/usr/bin/env python3
"""capture3.py - windowed capture + diff for protocol decoding.

Usage: python capture3.py [total_s] [win_s]
  default: total=90s, windows of 30s. Prints unique frames per window and
  the diff between window 1 (idle) and later windows (after user action).
"""
import sys
import time
from collections import defaultdict

import hid

TOTAL = 90
WIN = 30


def main():
    global TOTAL, WIN
    if len(sys.argv) > 1:
        TOTAL = int(sys.argv[1])
    if len(sys.argv) > 2:
        WIN = int(sys.argv[2])

    path = None
    for d in hid.enumerate(0xE2B7, 0x7001):
        path = d["path"]
        break
    if path is None:
        sys.exit("cooler not found")

    h = hid.device()
    h.open_path(path)
    h.set_nonblocking(1)
    nwin = (TOTAL + WIN - 1) // WIN
    print(f"windows={nwin} win={WIN}s total={TOTAL}s")
    print(">>> NOW: keep everything idle for window 1; "
          "change fan/mode during later windows <<<")

    winframes = [defaultdict(int) for _ in range(nwin)]
    t0 = time.time()
    cur = 0
    while time.time() - t0 < TOTAL:
        data = h.read(64, timeout_ms=200)
        if data:
            el = time.time() - t0
            cur = min(int(el // WIN), nwin - 1)
            winframes[cur][bytes(data).hex()] += 1
    h.close()

    for i, wf in enumerate(winframes):
        print(f"\n===== WINDOW {i} (t={i*WIN}s..{(i+1)*WIN}s) frames: {len(wf)} unique =====")
        for hexs, cnt in sorted(wf.items(), key=lambda kv: -kv[1]):
            print(f"  x{cnt:4d}  {hexs}")

    base = set(winframes[0])
    for i in range(1, nwin):
        later = set(winframes[i])
        newf = later - base
        gone = base - later
        print(f"\n===== DIFF window{i} vs window0 =====")
        for f in sorted(newf):
            print(f"  +NEW  {f}")
        for f in sorted(gone):
            print(f"  -GONE {f}")


if __name__ == "__main__":
    main()
