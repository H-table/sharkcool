#!/usr/bin/env python3
"""dll_probe2.py - focused: deref the twin heap pointers in the hook arg.
The send-hook arg contains consecutive heap pointers (8 bytes apart) at
+160-ish; one is QByteArrayData (size/alloc/offset) the other is the data.
MUST run with 32-bit python.
"""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
DLL_PATH = os.path.join(APP_DIR, "Brb02CoolerComm.dll")

os.add_dll_directory(APP_DIR)
ctypes.windll.kernel32.SetDllDirectoryW(APP_DIR)

dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)
CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
frames = []


@CB
def send_hook(data):
    raw = ctypes.string_at(data - 64, 448)
    # find pair of heap ptrs p, p+8 within the dump
    found = None
    for off in range(0, 384):
        v = struct.unpack_from("<I", raw, off)[0]
        if v > 0x100000 and v < 0x7F000000 and (v & 7) == 0:
            s2 = raw[off + 4:off + 8]
            w = struct.unpack_from("<I", raw, off + 4)[0]
            if 0x100000 < w < 0x7F000000 and (v - w) in (8, -8):
                found = v
                break
    print("[HOOK] anchored mode-ptr scan")
    anchor = b"\x4a\x91\x27\x5a\x88\x9b\x64\x5a"
    idx = raw.find(anchor)
    if idx != -1:
        v = struct.unpack_from("<I", raw, idx + 8)[0]
        print("  anchored ptr @+%d = 0x%08X" % (idx + 8, v))
        if 0x100000 < v < 0x7F000000:
            for delta in (0, -8, 4, 12):
                try:
                    d = ctypes.string_at(v + delta, 72)
                except Exception:
                    continue
                print("  deref[%+d] %s" % (delta, d.hex()))
                if b"\xa5" in d[:12]:
                    print("  ******** A5 FRAME: %s" % d.hex())
                    frames.append(d)
    # full hexdump of the region (always)
    for off in range(0, 448, 16):
        chunk = raw[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        print("  DUMP +%03d: %s" % (off, hexs))
    print()


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


def reg_send(cb):
    f = dll.coolerRegisterSendCmd
    f.argtypes = [ctypes.c_void_p]
    f.restype = ctypes.c_int
    return f(ctypes.cast(cb, ctypes.c_void_p).value)


def main():
    dll.coolerInit()
    print("reg send ->", reg_send(send_hook))
    time.sleep(1)
    for mode in (0, 1, 2, 3):
        cfg = Cfg()
        cfg.b0 = mode
        print("== SetCoolingConfig mode=%d ==" % mode)
        dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
        dll.coolerSetCoolingConfig.restype = ctypes.c_int
        dll.coolerSetCoolingConfig(cfg, 0)
        time.sleep(1.0)
    print("\n===== FRAMES =====")
    for f in frames:
        print("  %s" % f.hex())
    dll.coolerUninit()


if __name__ == "__main__":
    main()
