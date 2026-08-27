#!/usr/bin/env python3
"""logscan.py - scan 黑鲨装备箱 TextLog .data logs for protocol traces.

Extracts printable ASCII / UTF-16LE strings from a log chunk and prints
lines matching interesting keywords (hid, usb, report, cmd, packet, hex).

Usage: python logscan.py <logfile> [keyword ...]
"""
import re
import sys

KEYWORDS = [
    r"hid", r"usb", r"report", r"packet", r"cmd", r"0x[0-9a-fA-F]{2,}",
    r"\bAA\b", r"55", r"brb02", r"cooler", r"temp", r"rpm", r"fan",
    r"brb", r"comm", r"send", r"recv", r"read", r"write", r"open",
]


def strings(data):
    # ASCII strings
    for m in re.finditer(rb"[\x20-\x7E]{6,}", data):
        yield m.group().decode("ascii", "replace")
    # UTF-16LE strings
    for m in re.finditer(rb"(?:[\x20-\x7E]\x00){6,}", data):
        yield m.group().decode("utf-16-le", "replace")


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: logscan.py <logfile> [keyword ...] [--max N]")
    args = list(sys.argv[1:])
    maxn = 200
    if "--max" in args:
        i = args.index("--max")
        maxn = int(args[i + 1])
        del args[i:i + 2]
    path = args[0]
    kws = args[1:] or KEYWORDS
    rx = re.compile("|".join(f"({k})" for k in kws), re.IGNORECASE)

    with open(path, "rb") as f:
        data = f.read()

    print(f"# file: {path}  ({len(data)} bytes)")
    seen = 0
    for s in strings(data):
        if rx.search(s):
            print(s.strip()[:300])
            seen += 1
            if seen >= maxn:
                print(f"# ... truncated at {maxn}")
                break
    print(f"# matched {seen} strings")


if __name__ == "__main__":
    main()
