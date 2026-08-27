#!/usr/bin/env python3
"""extract_frames.py - pull raw USBFrames embedded in 黑鲨装备箱 logs.

The DLL logs every packet with
  'CUSBNetworkCenter::dataReceived Read Data, ba.size(N), strTemp('
  'strDataToSend('  /  'UsbWorkerInterrupt::readData' ...
followed by raw binary. This script finds those markers and dumps the
following bytes as hex.

Usage: python extract_frames.py <logfile> [--max N] [--out file.hex]
"""
import sys

MARKERS = [
    b"strTemp(",        # incoming data, binary follows
    b"strDataToSend(",  # outgoing data
]


def main():
    args = list(sys.argv[1:])
    maxn = 200
    if "--max" in args:
        i = args.index("--max")
        maxn = int(args[i + 1])
        del args[i:i + 2]
    out = None
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        del args[i:i + 2]
    if not args:
        sys.exit("usage: extract_frames.py <logfile> [--max N] [--out file]")
    path = args[0]

    with open(path, "rb") as f:
        data = f.read()
    print(f"# {path} ({len(data)} bytes)")

    collected = []
    for marker in MARKERS:
        start = 0
        while True:
            i = data.find(marker, start)
            if i == -1:
                break
            # peek: next 90 bytes
            chunk = data[i + len(marker):i + len(marker) + 96]
            # strip trailing zeros/nonprintables heuristically: try to find
            # the next real text marker boundary
            j = 0
            while j < len(chunk):
                b = chunk[j]
                if b == 0x00:
                    # zero padding likely - check if rest is zeros
                    if all(x == 0 for x in chunk[j:]):
                        break
                if 0x20 <= b < 0x7F and b not in (0x2D,) and chunk[j:j+6].isalnum():
                    # possible start of next text -> but hex text has spaces;
                    # don't break on spaces-only runs
                    nxt = chunk[j:j+1]
                    # a real text run after binary would look like "----..."
                    if chunk[j:j+5] == b"----C" or chunk[j:j+3] == b"CUS":
                        break
                j += 1
            payload = chunk[:j]
            collected.append((marker, payload))
            start = i + 2
            if len(collected) >= maxn:
                break
        if len(collected) >= maxn:
            break

    print(f"# found {len(collected)} frames")
    lines = []
    for idx, (marker, payload) in enumerate(collected):
        hx = payload.hex(" ")
        print(f"[{idx:04d}] {marker.decode()} {hx}")
        lines.append(f"[{idx:04d}] {marker.decode()} {hx}")
    if out:
        with open(out, "w", encoding="utf-8") as fo:
            fo.write("\n".join(lines) + "\n")
        print(f"# saved to {out}")


if __name__ == "__main__":
    main()
