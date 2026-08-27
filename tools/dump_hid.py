#!/usr/bin/env python3
"""dump_hid.py - dump HID device capabilities via hid.dll (no driver changes).

Uses the Windows hid.dll API (HidD_GetPreparsedData + HidP_GetCaps +
HidP_GetValueCaps) to show report IDs, sizes and usage pages for the
Black Shark cooler.

Usage: python dump_hid.py [hid_path]
        (hid_path from probe1 output; default: first E2B7:7001 device)
"""
import ctypes
from ctypes import wintypes
import sys

import hid

# ---- structs from hidpi.h ----
class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_ushort),
        ("UsagePage", ctypes.c_ushort),
        ("InputReportByteLength", ctypes.c_ushort),
        ("OutputReportByteLength", ctypes.c_ushort),
        ("FeatureReportByteLength", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort * 17),
        ("NumberLinkCollectionNodes", ctypes.c_ushort),
        ("NumberInputButtonCaps", ctypes.c_ushort),
        ("NumberInputValueCaps", ctypes.c_ushort),
        ("NumberInputDataIndices", ctypes.c_ushort),
        ("NumberOutputButtonCaps", ctypes.c_ushort),
        ("NumberOutputValueCaps", ctypes.c_ushort),
        ("NumberOutputDataIndices", ctypes.c_ushort),
        ("NumberFeatureButtonCaps", ctypes.c_ushort),
        ("NumberFeatureValueCaps", ctypes.c_ushort),
        ("NumberFeatureDataIndices", ctypes.c_ushort),
    ]


class HIDP_VALUE_CAPS(ctypes.Structure):
    _fields_ = [
        ("UsagePage", ctypes.c_ushort),
        ("ReportID", ctypes.c_ubyte),
        ("IsAlias", ctypes.c_ubyte),
        ("BitField", ctypes.c_ushort),
        ("LinkCollection", ctypes.c_ushort),
        ("LinkUsage", ctypes.c_ushort),
        ("LinkUsagePage", ctypes.c_ushort),
        ("IsRange", ctypes.c_ubyte),
        ("IsStringRange", ctypes.c_ubyte),
        ("IsStringAlias", ctypes.c_ubyte),
        ("Reserved", ctypes.c_ubyte),
        ("Reserved2", ctypes.c_ubyte),
        ("Range", ctypes.c_ubyte * 16),
        ("NotRange", ctypes.c_ubyte * 20),
    ]


def fopen(path):
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_RW = 0x00000003
    OPEN_EXISTING = 0x00000003
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    h = k32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW,
                        None, OPEN_EXISTING, 0, None)
    if h == wintypes.HANDLE(-1).value or not h:
        print(f"CreateFileW failed, GetLastError={k32.GetLastError()}")
        return None
    return h


def main():
    path = None
    if len(sys.argv) > 1:
        path = sys.argv[1].encode()
    else:
        for d in hid.enumerate(0xE2B7, 0x7001):
            path = d["path"]
            break
    if path is None:
        sys.exit("device not found")
    if isinstance(path, bytes):
        path = path.decode("utf-8", "replace")
    print("path:", path)

    h = fopen(path)
    if h is None:
        sys.exit("cannot open device")
    print("CreateFileW OK, handle:", h)

    # HidD_GetPreparsedData
    prep = ctypes.c_void_p()
    hid_dll = ctypes.windll.hid
    hid_dll.HidD_GetPreparsedData.argtypes = [wintypes.HANDLE,
                                              ctypes.POINTER(ctypes.c_void_p)]
    ok = hid_dll.HidD_GetPreparsedData(h, ctypes.byref(prep))
    print("HidD_GetPreparsedData:", ok, "GetLastError:",
          ctypes.windll.kernel32.GetLastError())
    if not ok:
        sys.exit("preparsed failed")

    caps = HIDP_CAPS()
    ok = ctypes.windll.hid.HidP_GetCaps(prep, ctypes.byref(caps))
    print(f"HidP_GetCaps: ok={ok}")
    print(f"  UsagePage=0x{caps.UsagePage:04X} Usage=0x{caps.Usage:04X}")
    print(f"  InputReportByteLength ={caps.InputReportByteLength}")
    print(f"  OutputReportByteLength={caps.OutputReportByteLength}")
    print(f"  FeatureReportByteLength={caps.FeatureReportByteLength}")
    print(f"  input  caps: v={caps.NumberInputValueCaps} b={caps.NumberInputButtonCaps}")
    print(f"  output caps: v={caps.NumberOutputValueCaps} b={caps.NumberOutputButtonCaps}")
    print(f"  feature caps: v={caps.NumberFeatureValueCaps} b={caps.NumberFeatureButtonCaps}")

    def dump_vcaps(report_type, n):
        if n == 0:
            return
        arr = (HIDP_VALUE_CAPS * n)()
        got = ctypes.windll.hid.HidP_GetValueCaps(report_type, arr,
                                                  ctypes.byref(ctypes.c_ulong(n)),
                                                  prep)
        print(f"  --- value caps type={report_type} (got {got}) ---")
        for c in arr:
            rd = getattr(c, "Range", None)
            lo = rd if rd is None else None
            print(f"    ReportID={c.ReportID} UsagePage=0x{c.UsagePage:04X} "
                  f"Usage=0x{c.NotRange[0] << 8 | c.NotRange[1]:04X} "
                  f"BitField=0x{c.BitField:04X} vmin={c.Range[0]} vmax={c.Range[2]}")

    dump_vcaps(0, caps.NumberInputValueCaps)    # HidP_Input = 0
    dump_vcaps(1, caps.NumberOutputValueCaps)   # HidP_Output = 1
    dump_vcaps(2, caps.NumberFeatureValueCaps)  # HidP_Feature = 2

    ctypes.windll.hid.HidD_FreePreparsedData(prep)
    ctypes.windll.kernel32.CloseHandle(h)


if __name__ == "__main__":
    main()
