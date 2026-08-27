#!/usr/bin/env python3
"""probe4.py - hook with (data, size) signature variant."""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
DLL_PATH = os.path.join(APP_DIR, "Brb02CoolerComm.dll")

os.add_dll_directory(APP_DIR)
ctypes.windll.kernel32.SetDllDirectoryW(APP_DIR)
dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)

hits = []


def try_cb(restype, argtypes, label):
    CB = ctypes.CFUNCTYPE(restype, *argtypes)

    @CB
    def hook(*args):
        print("[%s] args= %s" % (label, ["0x%08X" % a if isinstance(a, int) else a for a in args]))
        if len(args) >= 2 and args[0]:
            p = args[0]
            try:
                raw = ctypes.string_at(p, max(2, min(128, args[1] if isinstance(args[1], int) and 0 < args[1] < 4096 else 80)))
                print("   DATA(%d): %s" % (len(raw), raw.hex()))
                hits.append(raw)
            except Exception as e:
                print("   err", e)
        return None

    f = dll.coolerRegisterSendCmd
    f.argtypes = [ctypes.c_void_p]
    f.restype = ctypes.c_int
    r = f(ctypes.cast(hook, ctypes.c_void_p).value)
    return r, hook


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


def main():
    dll.coolerInit()
    r1, h1 = try_cb(None, (ctypes.c_void_p, ctypes.c_int), "data,size")
    print("reg (data,size) ->", r1)
    time.sleep(0.8)
    cfg = Cfg(); cfg.b0 = 1
    dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
    dll.coolerSetCoolingConfig(cfg, 0)
    time.sleep(1.2)

    r2, h2 = try_cb(None, (ctypes.c_void_p, ctypes.c_void_p), "ptr,ptr")
    print("reg (ptr,ptr) ->", r2)
    time.sleep(0.8)
    cfg2 = Cfg(); cfg2.b0 = 2
    dll.coolerSetCoolingConfig(cfg2, 0)
    time.sleep(1.2)

    r3, h3 = try_cb(None, (ctypes.c_void_p, ctypes.c_int, ctypes.c_int), "ptr,i,i")
    print("reg (ptr,i,i) ->", r3)
    time.sleep(0.8)
    cfg3 = Cfg(); cfg3.b0 = 3
    dll.coolerSetCoolingConfig(cfg3, 0)
    time.sleep(1.2)

    print("\n=== captured:", len(hits))
    for h in hits:
        print("  ", h.hex())
    dll.coolerUninit()


if __name__ == "__main__":
    main()
