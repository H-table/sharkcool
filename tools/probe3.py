#!/usr/bin/env python3
"""probe3.py - drive coolerSetCoolingConfig via official DLL (32-bit), then
scan the whole process memory for the A5 frame it built. 32-bit python only."""
import ctypes
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import memscan

APP_DIR = r"D:\Program Files (x86)\BlackSharkEquipmentBox"
DLL_PATH = os.path.join(APP_DIR, "Brb02CoolerComm.dll")

os.add_dll_directory(APP_DIR)
ctypes.windll.kernel32.SetDllDirectoryW(APP_DIR)
dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)


class Cfg(ctypes.Structure):
    _fields_ = [("b0", ctypes.c_uint8)] * 20


def main():
    dll.coolerInit()
    time.sleep(1)
    dll.coolerSetCoolingConfig.argtypes = [Cfg, ctypes.c_byte]
    dll.coolerSetCoolingConfig.restype = ctypes.c_int
    for mode in (0, 1, 2, 3):
        cfg = Cfg()
        cfg.b0 = mode
        dll.coolerSetCoolingConfig(cfg, 0)
        print("== fired mode %d, scanning..." % mode)
        time.sleep(0.6)
        hits = memscan.scan()
        print("# hits: %d" % len(hits))
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "hits_mode%d.txt" % mode), "w") as f:
            for addr, hx in hits:
                f.write("0x%08X %s\n" % (addr, hx))
    dll.coolerUninit()


if __name__ == "__main__":
    main()
