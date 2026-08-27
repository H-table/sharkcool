#!/usr/bin/env python3
"""probe5.py - full end-to-end: preload libusb, register conn callback,
drive coolerSetCoolingConfig, dump BOTH hook args. 32-bit python only."""
import ctypes
import os
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
DLL_PATH = os.path.join(APP_DIR, "Brb02CoolerComm.dll")

os.add_dll_directory(APP_DIR)
k32 = ctypes.windll.kernel32
k32.SetDllDirectoryW(APP_DIR)

# preload libusb so the comm DLL's import resolves
h = k32.LoadLibraryW(os.path.join(APP_DIR, "libusb-1.0.dll"))
print("libusb preload:", h)

dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)

CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
CB2 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)


def dump(p, n=96):
    try:
        return ctypes.string_at(p, n).hex()
    except Exception:
        return "<err>"


def make_hook(label):
    @CB1
    def hook(a):
        import struct as _s
        print("[%s hook] a=0x%08X" % (label, a))
        try:
            raw = ctypes.string_at(a, 512)
        except Exception:
            raw = b""
        idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00")
        while idx != -1:
            v = _s.unpack_from("<I", raw, idx + 8)[0]
            print("  {size=24}@%d ptr=0x%08X" % (idx + 8, v))
            if 0x10000 < v < 0x7F000000:
                for delta in (0, -8, 12, 16):
                    try:
                        d = ctypes.string_at(v + delta, 72)
                        print("  deref[%+d] %s" % (delta, d.hex()))
                    except Exception:
                        pass
            idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00", idx + 1)
        return None
    return hook


def make_hook2(label):
    @CB2
    def hook(a, b):
        print("[%s hook2] a=0x%08X b=0x%08X" % (label, a, b))
        print("   A dump: %s" % dump(a))
        print("   B dump: %s" % dump(b))
        return None
    return hook


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


def reg(fname, cb):
    f = getattr(dll, fname)
    f.argtypes = [ctypes.c_void_p]
    f.restype = ctypes.c_int
    return f(ctypes.cast(cb, ctypes.c_void_p).value)


def main():
    dll.coolerInit()
    time.sleep(0.5)

    print("--- register recv hook2 (a,b) ---")
    h2 = make_hook2("recv")
    print("reg:", reg("coolerRegisterRecvCmd", h2))
    print("--- register send hook1 (a) ---")
    h1 = make_hook("send")
    print("reg:", reg("coolerRegisterSendCmd", h1))

    print("--- conn with callbacks ---")
    conn_cb = ctypes.CFUNCTYPE(None, ctypes.c_int)(lambda s: print("  conn state:", s))
    f = dll.coolerConnByUsb
    f.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    f.restype = ctypes.c_int
    for args in [(conn_cb, 0, 0), (conn_cb, conn_cb, 0), (0, 0, 0)]:
        try:
            r = f(*[ctypes.cast(a, ctypes.c_void_p).value if isinstance(a, ctypes.CFUNCTYPE) else a for a in args])
            print("coolerConnByUsb", args, "->", r)
            time.sleep(2)
        except Exception as e:
            print("conn", args, "err:", e)

    dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
    dll.coolerSetCoolingConfig.restype = ctypes.c_int
    for mode in (1, 2, 3):
        c = Cfg()
        c.b0 = mode
        print("== SetCoolingConfig mode=%d ==" % mode)
        dll.coolerSetCoolingConfig(c, 0)
        time.sleep(1.5)

    dll.coolerUninit()


if __name__ == "__main__":
    main()
