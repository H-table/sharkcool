#!/usr/bin/env python3
"""probe6.py - instantiate QCoreApplication to fix DLL paths, then drive
the real device via official DLL. Run with 32-bit python from APP_DIR."""
import ctypes
import os
import time

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
os.add_dll_directory(APP_DIR)
k32 = ctypes.windll.kernel32
k32.SetDllDirectoryW(APP_DIR)

# --- 1. QCoreApplication ---
qt5 = k32.LoadLibraryW(os.path.join(APP_DIR, "Qt5Core.dll"))
print("Qt5Core:", qt5)
argvbuf = ctypes.create_string_buffer(b"sharkprobe\x00", 16)
argc = ctypes.c_int(1)
argv = (ctypes.c_char_p * 2)(ctypes.addressof(argvbuf), None)
ctor_addr = k32.GetProcAddress(qt5, b"??0QCoreApplication@@QAE@AAHPAPADH@Z")
k32.GetProcAddress.restype = ctypes.c_void_p
ctor_addr = k32.GetProcAddress(qt5, b"??0QCoreApplication@@QAE@AAHPAPADH@Z")

qapp_obj = (ctypes.c_void_p * 128)()  # 4-byte aligned storage for QCoreApplication
ctor_addr = k32.GetProcAddress(qt5, b"??0QCoreApplication@@QAE@AAHPAPADH@Z")
k32.GetProcAddress.restype = ctypes.c_void_p
ctor_addr = k32.GetProcAddress(qt5, b"??0QCoreApplication@@QAE@AAHPAPADH@Z")
print("ctor @ 0x%08X" % ctor_addr)
CTORF = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                           ctypes.POINTER(ctypes.c_char_p), ctypes.c_int)
ctor = CTORF(ctor_addr)
ctor(ctypes.addressof(qapp_obj), ctypes.byref(argc), argv, 0)
time.sleep(0.3)
print("QCoreApplication created")

# --- 2. preload libusb then load comm dll ---
h = k32.LoadLibraryW(os.path.join(APP_DIR, "libusb-1.0.dll"))
print("libusb:", h)
dll = ctypes.WinDLL(os.path.join(APP_DIR, "Brb02CoolerComm.dll"))

CB1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
STATE = ctypes.CFUNCTYPE(None, ctypes.c_int)

send_hook = None
frames = []


def make_send():
    @CB1
    def hook(a):
        raw = ctypes.string_at(a, 256)
        idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00")
        while idx != -1 and idx < 200:
            import struct as _s
            v = _s.unpack_from("<I", raw, idx + 8)[0]
            try:
                d = ctypes.string_at(v, 72)
                print("[hook] size24pt 0x%08X -> %s" % (v, d.hex()))
                if b"\xa5" in d:
                    frames.append(d)
            except Exception:
                pass
            idx = raw.find(b"\x18\x00\x00\x00\x08\x00\x00\x00", idx + 1)
        return None
    return hook


def main():
    print("init:", dll.coolerInit())
    time.sleep(0.5)
    global send_hook
    send_hook = make_send()
    dll.coolerRegisterSendCmd.argtypes = [ctypes.c_void_p]
    dll.coolerRegisterSendCmd.restype = ctypes.c_int
    r = dll.coolerRegisterSendCmd(ctypes.cast(send_hook, ctypes.c_void_p).value)
    print("reg send:", r)

    # state callback conn
    dll.coolerConnByUsb.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    dll.coolerConnByUsb.restype = ctypes.c_int
    st = STATE(lambda s: print("  [connstate]", s))
    r = dll.coolerConnByUsb(ctypes.cast(st, ctypes.c_void_p).value, 0, 0)
    print("conn:", r)
    time.sleep(2)

    class Cfg(ctypes.Structure):
        _fields_ = [("b0", ctypes.c_uint8)] * 20

    dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
    dll.coolerSetCoolingConfig.restype = ctypes.c_int
    for mode in (1, 2, 3):
        c = Cfg(); c.b0 = mode
        print("== mode", mode, "==")
        dll.coolerSetCoolingConfig(c, 0)
        time.sleep(1.5)
    dll.coolerUninit()
    print("done; frames:", len(frames))


if __name__ == "__main__":
    main()
