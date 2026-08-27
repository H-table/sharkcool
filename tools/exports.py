#!/usr/bin/env python3
"""exports.py - list PE exports of a DLL (for RE recon).

Usage: python exports.py <dll> [dll2 ...]
"""
import sys


def read_cstr(buf, off):
    end = buf.find(b"\x00", off)
    return buf[off:end].decode("utf-8", "replace") if end != -1 else ""


def parse_exports(path):
    with open(path, "rb") as f:
        buf = f.read()
    if buf[:2] != b"MZ":
        return None, "not a PE file"
    peoff = int.from_bytes(buf[0x3C:0x40], "little")
    if buf[peoff:peoff + 4] != b"PE\x00\x00":
        return None, "no PE header"
    # COFF
    coff = peoff + 4
    num_sections = int.from_bytes(buf[coff + 2:coff + 4], "little")
    opt_size = int.from_bytes(buf[coff + 16:coff + 18], "little")
    opt = coff + 20
    magic = buf[opt:opt + 2]
    if magic == b"\x0b\x01":  # PE32
        dd = opt + 96
    elif magic == b"\x0b\x02":  # PE32+
        dd = opt + 112
    else:
        return None, f"unknown optional header magic {magic!r}"
    exp_rva, exp_size = int.from_bytes(buf[dd + 0:dd + 4], "little"), \
                        int.from_bytes(buf[dd + 4:dd + 8], "little")
    if exp_rva == 0:
        return None, "no exports"
    # section headers
    sec = opt + opt_size
    sections = []
    for i in range(num_sections):
        s = sec + i * 40
        vaddr = int.from_bytes(buf[s + 12:s + 16], "little")
        vsize = int.from_bytes(buf[s + 8:s + 12], "little")
        pptr = int.from_bytes(buf[s + 20:s + 24], "little")
        psize = int.from_bytes(buf[s + 16:s + 20], "little")
        sections.append((vaddr, vsize, pptr, psize))

    def rva2off(rva):
        for vaddr, vsize, pptr, psize in sections:
            if vaddr <= rva < vaddr + max(vsize, psize):
                return pptr + (rva - vaddr)
        return None

    off = rva2off(exp_rva)
    if off is None:
        return None, "export dir not mapped"
    n_funcs = int.from_bytes(buf[off + 20:off + 24], "little")
    n_names = int.from_bytes(buf[off + 24:off + 28], "little")
    funcs_rva = int.from_bytes(buf[off + 28:off + 32], "little")
    names_rva = int.from_bytes(buf[off + 32:off + 36], "little")
    ords_rva = int.from_bytes(buf[off + 36:off + 40], "little")
    names = []
    for i in range(n_names):
        no = rva2off(int.from_bytes(buf[rva2off(names_rva) + i * 4:rva2off(names_rva) + i * 4 + 4], "little"))
        if no is not None:
            names.append(read_cstr(buf, no))
    forward = []
    for i in range(n_funcs):
        fo = rva2off(int.from_bytes(buf[rva2off(funcs_rva) + i * 4:rva2off(funcs_rva) + i * 4 + 4], "little"))
        if fo is None:
            continue
        s = read_cstr(buf, fo)
        if s.endswith(".dll"):
            forward.append(s)
    return {"names": names, "forward": forward}, None


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: exports.py <dll> [dll2 ...]")
    for p in sys.argv[1:]:
        try:
            info, err = parse_exports(p)
        except Exception as e:
            print(f"== {p}: parse error {e!r}")
            continue
        print(f"== {p} ==")
        if err:
            print(f"   {err}")
            continue
        names = info["names"]
        print(f"   {len(names)} named exports:")
        for n in sorted(names):
            print(f"      {n}")
        for f in info["forward"]:
            print(f"   [forward] {f}")


if __name__ == "__main__":
    main()
