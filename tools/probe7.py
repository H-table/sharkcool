#!/usr/bin/env python3
"""probe7.py - 32-bit harness attempt #2: preload CRT + libusb, register
conn state callback correctly, connect, drive SetCoolingConfig, and dump
the send hook with QByteArray heuristics (size field first).

Run from Py311-embed32 dir with DLLs copied next to python.exe.
"""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
os.add_dll_directory(APP_DIR)
k32 = ctypes.windll.kernel32
k32.SetDllDirectoryW(APP_DIR)

# 1. CRT + libusb first (search: python.exe dir now has them)
for d in ("vcruntime140.dll", "msvcp140.dll", "TextLog.dll", "libusb-1.0.dll"):
    h = k32.LoadLibraryW(d)
    print("load", d, "->", h)

dll = ctypes.WinDLL(os.path.join(APP_DIR, "Brb02CoolerComm.dll"))
print("comm dll loaded")
print("init ->", dll.coolerInit())
time.sleep(0.5)

hooks = []
captured = []


def reg(fname, cb):
    f = getattr(dll, fname)
    f.argtypes = [ctypes.c_void_p]
    f.restype = ctypes.c_int
    return f(ctypes.cast(cb, ctypes.c_void_p).value)


CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
CB_ST = ctypes.CFUNCTYPE(None, ctypes.c_int)


@CB1
def sendhook(a):
    # QByteArray-by-value: pointer to QByteArrayData {qptr size; qptr alloc; int offset;}
    p = a
    try:
        raw = ctypes.string_at(p, 24)
        size, alloc, offset = struct.unpack("<qqi", raw)
        if 0 < size <= 128:
            data = ctypes.string_at(p + (offset if offset > 0 else 24), min(size, 80))
            print("QBA size=%d alloc=%d off=%d: %s" % (size, alloc, offset, data.hex()))
            captured.append((size, data))
    except Exception as e:
        pass
    return None


@CB_ST
def statecb(s):
    print("  >> conn state:", s)


print("reg send ->", reg("coolerRegisterSendCmd", sendhook))
print("reg recv ->", reg("coolerRegisterRecvCmd", sendhook))

f = dll.coolerConnByUsb
f.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
f.restype = ctypes.c_int
r = f(ctypes.cast(statecb, ctypes.c_void_p).value, ctypes.cast(statecb, ctypes.c_void_p).value, 0)
print("conn ->", r)
time.sleep(2.5)


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
dll.coolerSetCoolingConfig.restype = ctypes.c_int
for mode in (1, 2):
    c = Cfg(); c.b0 = mode
    print("== mode %d ==" % mode)
    dll.coolerSetCoolingConfig(c, 0)
    time.sleep(1.2)

print("\n=== captured:", [(s, d.hex()) for s, d in captured])
dll.coolerUninit()
