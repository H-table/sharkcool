#!/usr/bin/env python3
"""exe_scan.py - scan the 黑鲨装备箱 EXE (or any file) for protocol
artifacts: A5 frame templates (.rdata) and A5-write instructions (.text).

Usage: python exe_scan.py <exe>
"""
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from dll_disasm import parse_pe, rva2off


def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        buf = f.read()
    print(f"# file {path}: {len(buf)} bytes")
    pe = parse_pe(buf)
    if pe is None:
        print("not a PE")
        return
    image_base = pe["image_base"]
    print(f"image_base=0x{image_base:X}")

    # ---- .rdata template scan: A5 cmd(len<=0x40) len(<=0x40) ----
    for secname, vaddr, vsize, pptr, psize in pe["secs"]:
        if secname not in (".rdata", ".data"):
            continue
        print(f"\n== {secname} template scan ==")
        cnt = 0
        for i in range(pptr, pptr + min(psize, len(buf) - pptr)):
            if buf[i] == 0xA5 and i + 3 + 2 < len(buf):
                cmd = buf[i + 1]
                ln = buf[i + 2]
                if 0 < cmd <= 0x30 and 0 < ln <= 0x40:
                    # require most of the next 48 bytes to be zero padding
                    nxt = buf[i + 3 + ln:i + 3 + ln + 48]
                    if len(nxt) < 40:
                        continue
                    zeros = nxt.count(0)
                    if zeros < 32:
                        continue
                    templ = buf[i:i + 3 + ln]
                    print(f"  rva=0x{vaddr + (i - pptr):08X}: {templ.hex(' ')}")
                    cnt += 1
                    if cnt > 60:
                        print("  ... more")
                        break
        print(f"  # {cnt} candidates")

    # ---- .data: dump every A5 neighborhood ----
    for secname, vaddr, vsize, pptr, psize in pe["secs"]:
        if secname not in (".data", ".bss"):
            continue
        print(f"\n== {secname} all A5 neighborhoods ==")
        end = min(pptr + psize, len(buf))
        start = pptr
        i = start
        while True:
            i = buf.find(b"\xa5", i, end)
            if i == -1:
                break
            rva = vaddr + (i - pptr)
            lo = max(start, i - 16)
            hi = min(end, i + 40)
            print(f"  rva=0x{rva:08X}: {buf[lo:hi].hex(' ')}")
            i += 1

    # ---- .text scan for A5 stores ----
    for secname, vaddr, vsize, pptr, psize in pe["secs"]:
        if secname != ".text":
            continue
        print(f"\n== .text A5-store scan (rva 0x{vaddr:X} size {psize}) ==")
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        hits = []
        end = min(pptr + psize, len(buf))
        for i in range(pptr, end - 4):
            if buf[i] == 0xC6:
                modrm = buf[i + 1]
                if (modrm & 0xC0) != 0xC0 and ((modrm >> 3) & 7) == 1 and buf[i + 3] == 0xA5:
                    hits.append(i - pptr)
                elif buf[i + 2] == 0xA5:
                    hits.append(i - pptr)
            elif buf[i:i + 4] == b"\xa5\x00\x00\x00":
                hits.append(i - pptr)
        print(f" # {len(hits)} hits")
        for h in hits[:80]:
            rva = vaddr + h
            off = rva2off(pe, rva - 8)
            if off is None:
                continue
            ins = list(md.disasm(buf[off:off + 0x50], rva - 8 + image_base))
            print(f"  --- rva 0x{rva:X} ---")
            for insn in ins[:14]:
                print(f"    {insn.address:08X}: {insn.mnemonic:<8} {insn.op_str}")


if __name__ == "__main__":
    main()
