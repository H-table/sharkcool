#!/usr/bin/env python3
"""probe10.py - find {18 00 00 00 08 00 00 00 <ptr> 59 00 00 00} inside the
hook arg, deref ptr at every 4-byte offset, hunt for A5."""
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

CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
captured = []


@CB1
def hook(a):
    raw = ctypes.string_at(a, 256)
    idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00")
    while idx != -1:
        v = struct.unpack_from("<I", raw, idx + 8)[0]
        print("struct@%d ptr=0x%08X" % (idx + 8, v))
        if 0x10000 < v < 0x7F000000:
            for delta in (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40):
                try:
                    d = ctypes.string_at(v + delta, 64)
                except Exception:
                    continue
                if b"\xa5" in d[:40]:
                    print("  ***** A5 at ptr+%d: %s" % (delta, d.hex()))
                    captured.append((delta, d))
                elif delta in (12, 16, 20):
                    print("  ptr+%d: %s" % (delta, d.hex()[:48]))
        idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00", idx + 1)
    return None


f = dll.coolerRegisterSendCmd
f.argtypes = [ctypes.c_void_p]
f.restype = ctypes.c_int
print("reg send ->", f(ctypes.cast(hook, ctypes.c_void_p).value))


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
dll.coolerSetCoolingConfig.restype = ctypes.c_int
for mode in (1, 2, 3):
    c = Cfg(); c.b0 = mode
    print("== mode", mode, "==")
    dll.coolerSetCoolingConfig(c, 0)
    time.sleep(1.0)
print("=== captured:", len(captured))
for delta, d in captured:
    print("  +%d: %s" % (delta, d.hex()))
dll.coolerUninit()
