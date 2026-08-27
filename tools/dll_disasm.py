#!/usr/bin/env python3
"""dll_disasm.py - disassemble selected exports of Brb02CoolerComm.dll
to extract the wire protocol constants (cmd IDs, payload templates).

Usage: python dll_disasm.py <dll> [export-filter ...]
"""
import sys


def parse_pe(buf):
    if buf[:2] != b"MZ":
        return None
    peoff = int.from_bytes(buf[0x3C:0x40], "little")
    coff = peoff + 4
    num_sections = int.from_bytes(buf[coff + 2:coff + 4], "little")
    opt_size = int.from_bytes(buf[coff + 16:coff + 18], "little")
    opt = coff + 20
    magic = buf[opt:opt + 2]
    if magic == b"\x0b\x01":
        dd = opt + 96
    else:
        dd = opt + 112
    image_base = int.from_bytes(buf[opt + 28:opt + 36], "little") if magic == b"\x0b\x02" else int.from_bytes(buf[opt + 28:opt + 32], "little")
    exp_rva = int.from_bytes(buf[dd:dd + 4], "little")
    exp_size = int.from_bytes(buf[dd + 4:dd + 8], "little")
    secs = []
    for i in range(num_sections):
        s = coff + 20 + opt_size + i * 40
        name = buf[s:s + 8].rstrip(b"\x00").decode("latin1")
        vsize = int.from_bytes(buf[s + 8:s + 12], "little")
        vaddr = int.from_bytes(buf[s + 12:s + 16], "little")
        psize = int.from_bytes(buf[s + 16:s + 20], "little")
        pptr = int.from_bytes(buf[s + 20:s + 24], "little")
        secs.append((name, vaddr, vsize, pptr, psize))
    return {"buf": buf, "secs": secs, "exp_rva": exp_rva, "exp": exp_size, "image_base": image_base}


def rva2off(pe, rva):
    for name, vaddr, vsize, pptr, psize in pe["secs"]:
        if vaddr <= rva < vaddr + max(vsize, psize):
            return pptr + (rva - vaddr)
    return None


def get_exports(pe):
    buf = pe["buf"]
    off = rva2off(pe, pe["exp_rva"])
    if off is None:
        return {}
    n_funcs = int.from_bytes(buf[off + 20:off + 24], "little")
    n_names = int.from_bytes(buf[off + 24:off + 28], "little")
    funcs_rva = int.from_bytes(buf[off + 28:off + 32], "little")
    names_rva = int.from_bytes(buf[off + 32:off + 36], "little")
    ords_rva = int.from_bytes(buf[off + 36:off + 40], "little")
    exports = {}  # name -> rva
    for i in range(n_names):
        no = rva2off(pe, int.from_bytes(buf[rva2off(pe, names_rva) + i * 4:rva2off(pe, names_rva) + i * 4 + 4], "little"))
        name_off = rva2off(pe, int.from_bytes(buf[rva2off(pe, names_rva) + i * 4:rva2off(pe, names_rva) + i * 4 + 4], "little"))
        name = buf[name_off:buf.find(b"\x00", name_off)].decode("latin1")
        ord_idx = int.from_bytes(buf[rva2off(pe, ords_rva) + i * 2:rva2off(pe, ords_rva) + i * 2 + 2], "little")
        frva = int.from_bytes(buf[rva2off(pe, funcs_rva) + ord_idx * 4:rva2off(pe, funcs_rva) + ord_idx * 4 + 4], "little")
        exports[name] = frva
    return exports


def disasm(pe, rva, maxlen=0x140):
    buf = pe["buf"]
    off = rva2off(pe, rva)
    if off is None:
        return []
    code = buf[off:off + maxlen]
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    insns = []
    for insn in md.disasm(code, rva + pe["image_base"]):
        insns.append(insn)
        if insn.mnemonic == "ret" and len(insns) > 4:
            break
    return insns


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: dll_disasm.py <dll> [export-filter ...]")
    path = sys.argv[1]
    filt = sys.argv[2:]
    with open(path, "rb") as f:
        buf = f.read()
    pe = parse_pe(buf)
    if pe is None:
        sys.exit("not a PE")
    exports = get_exports(pe)
    print(f"# {len(exports)} exports in {path}")
    targets = [n for n in sorted(exports) if (not filt or any(f in n for f in filt))]
    print("# targets:", ", ".join(targets) if targets else "(none; use filters like coolerSet)")
    for name in targets:
        rva = exports[name]
        print(f"\n===== {name} (rva=0x{rva:X}) =====")
        insns = disasm(pe, rva)
        for i in insns:
            print(f"  {i.address:08X}: {i.mnemonic:<8} {i.op_str}")


if __name__ == "__main__":
    main()
