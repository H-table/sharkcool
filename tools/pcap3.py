#!/usr/bin/env python3
"""pcap3.py - parse USBPcap pcap (28-byte header + dlen@24) and extract
all 64-byte interrupt data frames with direction guess."""
import struct
import sys


def main():
    path = sys.argv[1]
    buf = open(path, "rb").read()
    off = 24
    out = []
    while off + 16 <= len(buf):
        ts, us, incl, orig = struct.unpack_from("<IIII", buf, off)
        rec = buf[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(rec) < 28:
            continue
        hlen = struct.unpack_from("<I", rec, 0)[0]
        dlen = rec[23]
        is_in = bool(rec[21] & 0x80)
        if hlen != 28 or dlen <= 0 or dlen > 128 or dlen > len(rec) - 27:
            continue
        data = rec[28:28 + dlen]
        b20 = rec[20:24]
        is_in = (b20[2] & 0x80) != 0 if len(b20) >= 3 else False
        if dlen == 64 or data[0] == 0xA5:
            out.append((is_in, dlen, data))
    print("# 64B/A5 frames:", len(out))
    for is_in, dlen, data in out:
        print("%s len=%d: %s" % ("IN " if is_in else "OUT", dlen, data.hex(" ")))
    # stats
    from collections import Counter
    c = Counter("IN" if i else "OUT" for i, _, _ in out)
    print("# by dir:", dict(c))


if __name__ == "__main__":
    main()
