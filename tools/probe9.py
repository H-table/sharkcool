#!/usr/bin/env python3
"""probe9.py - RAW DUMP EVERYTHING in the send hook. No parsing assumptions."""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
os.add_dll_directory(APP_DIR)
ctypes.windll.kernel32.SetDllDirectoryW(APP_DIR)
dll = ctypes.WinDLL(os.path.join(APP_DIR, "Brb02CoolerComm.dll"))

print("init ->", dll.coolerInit())
time.sleep(0.4)

CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)


@CB1
def hook(a, b):
    print("[hook] a=0x%08X b=0x%08X" % (a, b))
    # dump a 64 bytes, then walk: deref a, deref u32(a), deref u32(u32(a))
    for ptr, label, n in ((a, "a", 96),):
        try:
            raw = ctypes.string_at(ptr, n)
            print("  a[%d]: %s" % (n, raw.hex()))
        except Exception as e:
            print("  a err", e)
    try:
        p1 = struct.unpack_from("<I", ctypes.string_at(a, 4))[0]
        print("  *a = 0x%08X" % p1)
        if 0x10000 < p1 < 0x7F000000:
            r1 = ctypes.string_at(p1, 96)
            print("  *a[96]: %s" % r1.hex())
            p2 = struct.unpack_from("<I", r1, 0)[0]
            print("  **a = 0x%08X" % p2)
            if 0x10000 < p2 < 0x7F000000:
                r2 = ctypes.string_at(p2, 96)
                print("  **a[96]: %s" % r2.hex())
    except Exception as e:
        print("  chain err", e)
    return None


f = dll.coolerRegisterSendCmd
f.argtypes = [ctypes.c_void_p]
f.restype = ctypes.c_int
print("reg send ->", f(ctypes.cast(hook, ctypes.c_void_p).value))


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
dll.coolerSetCoolingConfig.restype = ctypes.c_int
c = Cfg(); c.b0 = 1
print("== mode 1 ==")
dll.coolerSetCoolingConfig(c, 0)
time.sleep(1.2)
dll.coolerUninit()
