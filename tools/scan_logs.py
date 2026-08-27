#!/usr/bin/env python3
"""scan_logs.py - search 黑鲨装备箱 log dirs for send-path traces."""
import os
import re
import sys

ROOTS = [
    r"D:\Program Files (x86)\BlackSharkEquipmentBox\Log",
    os.path.join(os.environ.get("TEMP", r"C:\Users\17493\AppData\Local\Temp"),
                 "Log.BlackSharkEquipmentBox"),
]
KEY = b"strDataToSend"
KEY2 = b"SendData"


def main():
    hits = []
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for fn in os.listdir(root):
            p = os.path.join(root, fn)
            try:
                with open(p, "rb") as f:
                    data = f.read()
            except Exception:
                continue
            n1 = data.count(KEY)
            n2 = data.count(KEY2)
            if n1 or n2:
                hits.append((p, n1, n2, len(data)))
    hits.sort(key=lambda h: -h[1])
    for p, n1, n2, sz in hits:
        print(f"{n1:6d} strDataToSend  {n2:8d} SendData  {sz:10d} {p}")
    if not hits:
        print("no strDataToSend/SendData found in any log")
        sys.exit(1)


if __name__ == "__main__":
    main()
