#!/usr/bin/env python3
"""memscan.py - scan own process memory for A5-framed packets after the
DLL builds one (called from dll_probe context). Run with 32-bit python."""
import ctypes
import ctypes.wintypes as wt
import struct

kernel32 = ctypes.windll.kernel32
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def scan():
    addr = 0
    found = []
    while addr < 0x7FFFFFFF:
        mbi = MEMORY_BASIC_INFORMATION()
        ok = kernel32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi))
        if not ok:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        prot = mbi.Protect
        if mbi.State == MEM_COMMIT and base and size and (
                prot & (PAGE_READWRITE | PAGE_WRITECOPY) and
                not (prot & 0x100)):  # readable writable, no-guard
            try:
                buf = ctypes.string_at(base, size)
            except Exception:
                buf = None
            if buf:
                i = buf.find(b"\xa5")
                cnt = 0
                while i != -1 and cnt < 5000:
                    # require A5 <cmd<=0x60> <len 2..0x20> then at least a few
                    # zeros after payload within a 32-byte window
                    if i + 32 <= len(buf):
                        window = buf[i:i + 32]
                        ln = window[2]
                        if window[1] < 0x60 and 0 < ln <= 0x20:
                            tail = window[3 + ln:32]
                            if len(tail) >= 3 and tail.count(0) >= max(2, len(tail) - 2):
                                found.append((base + i, window.hex()))
                    i = buf.find(b"\xa5", i + 1)
                    cnt += 1
        addr = base + size if size else addr + 0x1000
    return found


if __name__ == "__main__":
    hits = scan()
    print("# candidate frames:", len(hits))
    for addr, hx in hits[:100]:
        print("  0x%08X: %s" % (addr, hx))
