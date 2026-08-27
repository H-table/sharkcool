#!/usr/bin/env python3
"""probe8.py - QByteArray-by-value final decode:
hook arg = QByteArray object (x86: one 4-byte pointer to QByteArrayData)
          -> QByteArrayData {int size; int alloc; int offset; char data[]}
Need 32-bit python. No libusb preload (matches probe4 env where hook fired).
"""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
os.add_dll_directory(APP_DIR)
k32 = ctypes.windll.kernel32
k32.SetDllDirectoryW(APP_DIR)
dll = ctypes.WinDLL(os.path.join(APP_DIR, "Brb02CoolerComm.dll"))

print("init ->", dll.coolerInit())
time.sleep(0.4)

captured = []
CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)


@CB1
def hook(a, maybe_size):
    # a = QByteArray object (ptr to QBA data) OR direct pointer; explore both
    p = a
    print("[hook] a=0x%08X size_arg=%d" % (a, maybe_size))
    # path 1: a points to QByteArrayData
    for off, label in ((0, "a"), ):
        try:
            size, alloc, offset = struct.unpack("<qqi", ctypes.string_at(p, 20))
            if 0 <= size <= 128:
                d = ctypes.string_at(p + 20 + offset, size) if size else b""
                print("  [%s] QBA(size=%d alloc=%d off=%d) data=%s" % (label, size, alloc, offset, d.hex()))
                if b"\xa5" in d[:8]:
                    captured.append(d)
        except Exception as e:
            print("  ", label, "err", e)
    # path 2: *a is a pointer
    try:
        q = struct.unpack_from("<I", ctypes.string_at(p, 4))[0]
        if 0x10000 < q < 0x7F000000:
            size, alloc, offset = struct.unpack("<qqi", ctypes.string_at(q, 20))
            if 0 <= size <= 128:
                d = ctypes.string_at(q + 20 + offset, size) if size else b""
                print("  [*a] QBA(size=%d alloc=%d off=%d) data=%s" % (size, alloc, offset, d.hex()))
                if b"\xa5" in d[:8]:
                    captured.append(d)
    except Exception:
        pass
    return None


f = dll.coolerRegisterSendCmd
f.argtypes = [ctypes.c_void_p]
f.restype = ctypes.c_int
print("reg send ->", f(ctypes.cast(hook, ctypes.c_void_p).value))


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
dll.coolerSetCoolingConfig.restype = ctypes.c_int
for mode in (0, 1, 2, 3):
    c = Cfg(); c.b0 = mode
    print("== mode", mode, "==")
    dll.coolerSetCoolingConfig(c, 0)
    time.sleep(1.0)

print("\n=== captured frames:", [d.hex() for d in captured])
dll.coolerUninit()
