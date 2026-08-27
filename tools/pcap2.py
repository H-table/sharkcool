#!/usr/bin/env python3
"""pcap2.py - USBPcap parser v2: header = 28B, data_len at offset 24."""
import struct
import sys


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    buf = open(path, "rb").read()
    off = 24
    n = 0
    out = []
    while off + 16 <= len(buf):
        ts, us, incl, orig = struct.unpack_from("<IIII", buf, off)
        rec = buf[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(rec) < 28:
            continue
        hlen = struct.unpack_from("<I", rec, 0)[0]
        dlen = struct.unpack_from("<I", rec, 24)[0]
        if hlen not in (28, 48, 64) or dlen > len(rec) - hlen or dlen > 128:
            continue
        data = rec[hlen:hlen + dlen]
        if not data:
            continue
        n += 1
        # direction guess: bytes 20-23 ('02 00 80 02': 0x80 at +22 => IN?)
        b20 = rec[20:24]
        is_in = (b20[2] & 0x80) != 0 if len(b20) >= 3 else False
        if data[0] == 0xA5 or b"\xa502" in data or (len(data) >= 2 and data[0] == 0x00 and data[1] == 0xA5):
            out.append((n, is_in, dlen, data.hex()))
            print("#%-6d %s len=%d: %s" % (n, "IN" if is_in else "OUT", dlen, data.hex()[:140]))
    print("\n# records:", n)
    with open("extract2.txt", "w") as fo:
        for n2, is_in, dlen, hx in out:
            fo.write("%d %s %d %s\n" % (n2, "IN" if is_in else "OUT", dlen, hx))
    print("# A5 candidates: %d (extract2.txt)" % len(out))


if __name__ == "__main__":
    main()
