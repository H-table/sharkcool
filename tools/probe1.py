#!/usr/bin/env python3
"""probe1.py - Black Shark 风神Pro cooler enumeration probe.

Lists every HID device matching Black Shark vendor VID 0xE2B7 (and all
vendor-defined devices for comparison), then tries to open the cooler and
read any incoming reports for a short window.

Usage: python probe1.py
"""
import sys
import time

try:
    import hid
except ImportError:
    sys.exit("hidapi not installed: pip install hidapi")

BLACKSHARK_VID = 0xE2B7
COOLER_PID = 0x7001


def safe(s):
    if s is None:
        return ""
    s = str(s)
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in s)


def main():
    print(f"hidapi version: {getattr(hid, 'version', '?')}")
    print("-" * 80)

    # 1. enumerate all, keep vendor-defined / matching
    devices = hid.enumerate(0, 0)
    targets = []
    print("== ALL VENDOR-DEFINED / 0xE2B7 DEVICES ==")
    for d in devices:
        vid, pid = d["vendor_id"], d["product_id"]
        up, u = d.get("usage_page", 0), d.get("usage", 0)
        if vid == BLACKSHARK_VID or up >= 0xFF00 or pid == COOLER_PID:
            targets.append(d)
            print(
                f"VID={vid:04X} PID={pid:04X} usage_page=0x{up:04X} usage=0x{u:04X} "
                f"iface={d.get('interface_number')} rel={d.get('release_number')} "
                f"path={d.get('path')}"
            )
            print(f"    manufacturer={safe(d.get('manufacturer_string'))!r}")
            print(f"    product     ={safe(d.get('product_string'))!r}")
            print(f"    serial      ={safe(d.get('serial_number'))!r}")
    print("-" * 80)

    if not targets:
        sys.exit("no matching device found - is the cooler plugged in?")

    # 2. attempt open + read on every matching device
    for d in targets:
        path = d.get("path")
        print(f"== TRY OPEN {d['vendor_id']:04X}:{d['product_id']:04X} path={path} ==")
        try:
            h = hid.device()
            h.open_path(path)
            h.set_nonblocking(1)
            print("    opened OK; reading reports for 3s...")
            t0 = time.time()
            n = 0
            while time.time() - t0 < 3:
                data = h.read(64, timeout_ms=100)
                if data:
                    n += 1
                    print(f"    [{n}] {bytes(data).hex(' ')}")
            print(f"    total input reports in 3s: {n}")
            h.close()
        except Exception as e:
            print(f"    open/read failed: {e!r}")
    print("done.")


if __name__ == "__main__":
    main()
