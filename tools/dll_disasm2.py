#!/usr/bin/env python3
"""dll_disasm2.py - follow call chain from exports and scan for the A5
frame-builder patterns in Brb02CoolerComm.dll.

Usage:
  python dll_disasm2.py <dll> <va>...         # disassemble given VAs (call-follow)
  python dll_disasm2.py <dll> --scan          # scan .text for A5 stores
"""
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from dll_disasm import parse_pe, rva2off, get_exports  # reuse


def disasm_at(pe, rva, maxlen=0x100, stop_ret=True):
    buf = pe["buf"]
    off = rva2off(pe, rva)
    if off is None:
        return []
    code = buf[off:off + maxlen]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    insns = []
    for insn in md.disasm(code, rva + pe["image_base"]):
        insns.append(insn)
        if stop_ret and insn.mnemonic == "ret" and len(insns) > 3:
            break
    return insns


def follow(pe, start_rva, depth=3, seen=None):
    if seen is None:
        seen = set()
    if start_rva in seen or start_rva == 0:
        return
    seen.add(start_rva)
    print(f"\n===== fn rva=0x{start_rva:X} =====")
    insns = disasm_at(pe, start_rva)
    calls = []
    for i in insns:
        marker = ""
        for op in ["0xa5", "0x", "]"]:
            if op in i.op_str.lower():
                break
        print(f"  {i.address:08X}: {i.mnemonic:<8} {i.op_str}")
        if i.mnemonic == "call":
            tgt = i.op_str
            if tgt.startswith("0x"):
                calls.append(int(tgt, 16) - pe["image_base"])
    if depth > 0:
        for c in calls:
            follow(pe, c, depth - 1, seen)


def scan(pe):
    buf = pe["buf"]
    text = [s for s in pe["secs"] if s[0] == ".text"]
    if not text:
        print("no .text")
        return
    _, vaddr, vsize, pptr, psize = text[0]
    start, end = pptr, pptr + psize
    hits = []

    # brute: C6 <modrm with reg=1> [disp] A5  (mov byte [reg+disp], A5)
    for i in range(start, end - 4):
        b = buf[i]
        if b == 0xC6:
            modrm = buf[i + 1]
            if (modrm & 0xC0) != 0xC0 and ((modrm >> 3) & 7) == 1:
                if buf[i + 3] == 0xA5:
                    hits.append(i - start)
            elif buf[i + 2] == 0xA5:
                hits.append(i - start)
        elif buf[i:i + 4] == b"\xa5\x00\x00\x00":
            hits.append(i - start)

    print(f"# {len(hits)} hits")
    for h in hits[:120]:
        rva = vaddr + h
        print(f"\n--- hit at rva 0x{rva:X} ---")
        for insn in disasm_at(pe, max(0, rva - 10), 0x70, stop_ret=False):
            print(f"  {insn.address:08X}: {insn.mnemonic:<8} {insn.op_str}")


def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        buf = f.read()
    pe = parse_pe(buf)
    if pe is None:
        sys.exit("not a PE")
    print(f"image_base=0x{pe['image_base']:X}")
    if sys.argv[2] == "--scan":
        scan(pe)
        return
    for arg in sys.argv[2:]:
        va = int(arg, 16)
        rva = va - pe["image_base"]
        follow(pe, rva)


if __name__ == "__main__":
    main()
