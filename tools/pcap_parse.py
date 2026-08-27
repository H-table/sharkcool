#!/usr/bin/env python3
"""pcap_parse.py - extract USB interrupt transfers from USBPcap pcap.

USBPcap per-record header (32-bit): ts_sec, ts_frac, header_len, irp_id,
status, function, info, bus, device, endpoint, transfer, data_length.
Use: python pcap_parse.py <file> [--all]
"""
import struct
import sys


def main():
    f = sys.argv[1]
    showall = "--all" in sys.argv
    with open(f, "rb") as fh:
        buf = fh.read()
    # pcap global header 24 bytes
    magic, vmaj, vmin, tz, sig, snap, netw = struct.unpack_from("<IHHiIII", buf, 0)
    off = 24
    n = 0
    frames = []
    while off + 16 <= len(buf):
        ts_sec, ts_usec, incl, orig = struct.unpack_from("<IIII", buf, off)
        off += 16
        if off + incl > len(buf):
            break
        rec = buf[off:off + incl]
        off += incl
        if len(rec) < 64:
            continue
        ts2, tsfrac = struct.unpack_from("<QQ", rec, 0)
        (hdrlen, irp, status, function, info,
         bus, dev, ep, transfer, dlen) = struct.unpack_from("<IIIIIIIIII", rec, 16)
        if dlen > 0 and 64 + dlen <= len(rec):
            data = rec[64:64 + dlen]
            # transfer: 0=control,1=iso,2=bulk,3=interrupt
            is_in = bool(ep & 0x80)
            if transfer == 3:
                n += 1
                frames.append((bus, dev, ep, is_in, data.hex()))
                if showall or data[0] == 0xA5 or b"\xa5" in data[:8]:
                    print("bus%s dev%s ep=0x%02X %s len=%d: %s"
                          % (bus, dev, ep, "IN " if is_in else "OUT", dlen, data.hex()[:120]))
    print("\n# interrupt records: %d" % n)
    out = "out_frames.txt"
    with open(out, "w") as fo:
        for bus, dev, ep, is_in, hx in frames:
            fo.write("%s %s %s %s\n" % (bus, dev, "IN" if is_in else "OUT", hx))
    print("# saved", out)


if __name__ == "__main__":
    main()
