#!/usr/bin/env python3
"""imports.py - parse PE import table and list imported functions."""
import struct
import sys


def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        buf = f.read()
    peoff = struct.unpack_from("<I", buf, 0x3C)[0]
    coff = peoff + 4
    nsec = struct.unpack_from("<H", buf, coff + 2)[0]
    optsz = struct.unpack_from("<H", buf, coff + 16)[0]
    opt = coff + 20
    magic = buf[opt:opt + 2]
    if magic == b"\x0b\x01":
        dd = opt + 96
    else:
        dd = opt + 112
    imp_rva = struct.unpack_from("<I", buf, dd + 8)[0]
    secs = []
    for i in range(nsec):
        s = coff + 20 + optsz + i * 40
        v = struct.unpack_from("<I", buf, s + 12)[0]
        p = struct.unpack_from("<I", buf, s + 20)[0]
        ps = struct.unpack_from("<I", buf, s + 16)[0]
        secs.append((v, p, ps))

    def r2o(rva):
        for v, p, ps in secs:
            if v <= rva < v + ps:
                return p + (rva - v)
        return None

    off = r2o(imp_rva)
    imports = {}
    while True:
        i = struct.unpack_from("<I", buf, off)[0]
        if i == 0:
            break
        nameoff = r2o(i)
        dllname = buf[nameoff:buf.find(b"\x00", nameoff)].decode("latin1")
        thunk = struct.unpack_from("<I", buf, off + 16)[0]
        funcs = []
        toff = r2o(thunk)
        k = 0
        while True:
            v = struct.unpack_from("<I", buf, toff + k * 4)[0]
            if v == 0:
                break
            if v & 0x80000000:
                funcs.append("#ord%d" % (v & 0xFFFF))
            else:
                fo = r2o(v)
                nm = buf[fo + 2:buf.find(b"\x00", fo + 2)].decode("latin1")
                funcs.append(nm)
            k += 1
        imports[dllname] = funcs
        off += 20
    for d, fs in sorted(imports.items()):
        print("== %s (%d) ==" % (d, len(fs)))
        for x in fs:
            print("   ", x)


if __name__ == "__main__":
    main()
