#!/usr/bin/env python3
"""dll_probe.py - 32-bit ctypes harness for Brb02CoolerComm.dll.

Loads the official 32-bit Qt DLL, registers a SEND hook (coolerRegisterSendCmd)
and drives coolerSetFanSwitch / coolerSetCoolingConfig / coolerSetCoolingSource.
When the DLL sends a frame, the hook callback receives the QByteArray and we
dump its exact bytes.

MUST run with 32-bit python:
  D:\\Dev tools\\Py311-embed32\\python.exe dll_probe.py
"""
import ctypes
import os
import struct
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
DLL_PATH = os.path.join(APP_DIR, "Brb02CoolerComm.dll")

os.add_dll_directory(APP_DIR)
k32 = ctypes.windll.kernel32
k32.SetDllDirectoryW(APP_DIR)

dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)  # __cdecl -> WinDLL ok

CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p)

frames = []


def try_parse_qba(p):
    """Try to reconstruct a QByteArray from various plausible layouts."""
    if not p:
        return None
    for off, name in ((0, "obj"), (24, "data24")):
        try:
            raw = ctypes.string_at(p + off, 128)
            return raw
        except Exception:
            pass
    return None


@CB
def send_hook(data):
    print("[HOOK] ptr=%s" % hex(data))
    base = data - 64
    raw = ctypes.string_at(base, 384)
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        mark = "<<< A5" if b"\xa5" in chunk else ""
        print("  +%03d: %s  %s %s" % (off, hexs, asc, mark))
    frames.append(raw)


def reg_send(cb):
    ptr = ctypes.cast(cb, ctypes.c_void_p).value
    f = dll.coolerRegisterSendCmd
    f.argtypes = [ctypes.c_void_p]
    f.restype = ctypes.c_int
    r = f(ptr)
    return r


def main():
    print("== loading", DLL_PATH, "==")
    try:
        r = dll.coolerInit()
    except Exception as e:
        print("coolerInit call error:", e)
        raise
    print("coolerInit ->", r)
    r2 = reg_send(send_hook)
    print("coolerRegisterSendCmd ->", r2)

    # try register recv too (best effort, signature guess)
    try:
        dll.coolerRegisterRecvCmd.argtypes = [ctypes.c_void_p]
        rr = dll.coolerRegisterRecvCmd(ctypes.cast(send_hook, ctypes.c_void_p).value)
        print("coolerRegisterRecvCmd ->", rr)
    except Exception as e:
        print("recv rc:", e)

    # connect: 3 args (guess vid, pid, iface)
    for args in [(0xE2B7, 0x7001, 0), (0xE2B7, 0x7001, 1), (0, 0, 0)]:
        try:
            dll.coolerConnByUsb.argtypes = [ctypes.c_int] * 3
            dll.coolerConnByUsb.restype = ctypes.c_int
            rc = dll.coolerConnByUsb(*args)
            print("coolerConnByUsb%s -> %d" % (args, rc))
            time.sleep(1.5)
            if frames:
                break
        except Exception as e:
            print("conn err:", e)

    print("== frames so far:", len(frames))

    # drive commands
    def fire(name, fn, *args):
        print("-- firing %s%s" % (name, args))
        try:
            fn.argtypes = [ctypes.c_int] * len(args)
            fn.restype = ctypes.c_int
            rc = fn(*args)
            print("   rc =", rc)
        except Exception as e:
            print("   err:", e)
        time.sleep(1.2)

    fire("coolerSetFanSwitch", dll.coolerSetFanSwitch, 1)
    fire("coolerSetFanSwitch", dll.coolerSetFanSwitch, 0)
    fire("coolerSetCoolingSource", dll.coolerSetCoolingSource, 1)
    fire("coolerSetCoolingSource", dll.coolerSetCoolingSource, 2)

    # SetCoolingConfig: 20-byte struct by value + 1 byte arg.
    # ctypes can pass a structure by value.
    class Cfg(ctypes.Structure):
        _fields_ = [("b0", ctypes.c_uint8)] * 20

    for mode in (0, 1, 2, 3):
        cfg = Cfg()
        cfg.b0 = mode
        print("-- fire SetCoolingConfig mode=%d" % mode)
        try:
            dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
            dll.coolerSetCoolingConfig.restype = ctypes.c_int
            rc = dll.coolerSetCoolingConfig(cfg, 0)
            print("   rc =", rc)
        except Exception as e:
            print("   err:", e)
        time.sleep(1.2)

    print("\n===== CAPTURED FRAMES =====")
    for f in frames:
        print("  %s" % f.hex())
    dll.coolerUninit()
    print("done")


if __name__ == "__main__":
    main()
