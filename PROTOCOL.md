# BRB02 Cooler Protocol Notes (黑鲨风神Pro / 黑鲨装备箱)

Reverse-engineered 2026-08-27/28 from live HID captures + official DLL
analysis (32-bit ctypes harness, see tools/dll_probe*.py).

## Round 3 (USBPcap 抓包基础设施 — 已打通 90%)

拓扑解码：**散热器接 C 口 → 1A86:80A0/80A1 内部 Hub（非标准VID）
→ ROOT_HUB30\5&1A4B2349 (root hub #2)**。另一条链（05E3:0610/0620 hub →
ROOT_HUB30\5&345A21F6, root hub #1）是普通 A 口链。

- USBPcap（1.5.4.0）已以管理员静默安装；`-I` 已初始化（USB3 捕获）。
- **过滤驱动绑定**：手动 `UpperFilters=USBPcap` 注册表写到两个 root hub 的
  PnP 枚举键，root hub #1 重启成功 → **usb1.pcap 能抓到完整子树**
  （tshark 验证：`usb.transfer_type==1` (interrupt) 数据可提取）。
- **root hub #2（C 口链）重启失败：`Device is pending system reboot`** —
  USBPcap 官方要求一次系统重启才能让 filter 挂到 C 口 root hub。
- `pnputil /restart-device`/`disable-device` 均无法绕过；**重启后重跑即可**：
  ```
  USBPcapCMD.exe -d \\.\USBPcap2 -o cap.pcap -A --inject-descriptors
  tshark -r cap.pcap -Y 'usb.transfer_type==1' -T fields \
    -e usb.endpoint_address -e usb.data_len -e usb.capdata
  ```
  （tshark 已装：C:\Program Files\Wireshark\tshark.exe）
- 备用路径：把散热器换到任意 USB-A 口（root hub #1 的 filter 已生效）。
- 竞品数据说明：A 链上有 Synaptics 触控板（0x81/8B 大量 interrupt）、
  Razer 鼠标、Xbox 适配器（bulk）、ITE 048D 等，按 vendor 过滤即可。

## 官方 DLL 逆向工具链 (round 2 findings)

32-bit Python (embed win32, `D:\Dev tools\Py311-embed32`) loads
Brb02CoolerComm.dll directly (Qt5Core etc. via os.add_dll_directory);

- `coolerInit()` ✓ (returns 1)
- `coolerRegisterSendCmd(cb)` — callback fires when the DLL's send path
  runs (even without a device!). Callback receives a STRUCT pointer whose
  layout contains Qt internals + a [size][alloc][ptr][0x59..] block;
  config-size detected = 0x18 (24 = A5 + cmd + 0x14 + 20-byte struct!)
- `coolerConnByUsb` = 3 args where arg1 is CALLED as a function pointer
  (state callback); naive (vid,pid,iface) guesses crash → proper
  signature: (cb_hid_state, userdata?, ...)
- libusb fails with `LIBUSB_ERROR_NO_MEM` because Qt
  applicationDirPath = "\" (no QCoreApplication). Preloading
  libusb-1.0.dll does NOT fix; QCoreApplication construction from
  ctypes (thiscall@Qt5Core `??0QCoreApplication@@QAE@AAHPAPADH@Z`)
  still AVs on write 0x0 — needs a real Qt bootstrap (next round
  options: tiny 32-bit C helper compiled with embedded Qt? or run the
  probe as a Qt plugin loaded by the EXE? or USBPcap with elevation).

## 已确认的帧格式

Frame: `A5 [cmd:u8] [len:u8] [payload:len bytes]`, 64B report,
no checksum visible (device→host side confirmed). Response frames often
= request cmd + 2. Connect exchange decoded in detail below.

## Device

- VID `0xE2B7` PID `0x7001` — USB Composite (single HID interface), Jieli Technology MCU
- HID Usage Page `0xFFA0`, Usage `0x0002` (vendor-defined)
- Report: Input 65B (64 + report ID 0), Output 65B — no Feature reports
- Firmware: BRB02 Cooler v3.0.3 (latest known)
- Official app: 黑鲨装备箱 1.0.8.5 (`D:\Program Files (x86)\BlackSharkEquipmentBox`)
- DevDLL: `Brb02CoolerComm.dll` (Qt 5.15.2, 32-bit, libusb interrupt transfers)
  exports: coolerInit/coolerConnByUsb/coolerSetCoolingConfig/coolerSetFanSwitch/
  coolerSetRgbLightingEffects/coolerIssueSystemInfo/coolerRegisterSendCmd/coolerRegisterRecvCmd/...
  Its strings leak struct names: structBrb02FirmwareHeartBeatNotify,
  structBrb02GetCurCoolingConfigResponse, structBrb02SetFanSwitchResponse, ...
  Command enum originated from "BGM02Mouse" protocol; TLV types include
  Set/GetReportRate, Set/GetTemperatureInfo.
- Iton_HIDMOU_Com_x86.dll = modified hidapi raw layer (different product VID 0x369B; not needed)

## Frame format

```
A5 [cmd:u8] [len:u8] [payload:len bytes] [zeros to 64B]   -- no checksum observed
```

Reads (device -> host), observed:

| cmd | len | period | meaning |
|-----|-----|--------|---------|
| 0x07 | 0x06 | ~1s (x2 reports) | **HeartBeatNotify**: payload = [RPM u16le] [field2 u16le] |
| 0x05 | 0x07 | 1s | stable status frame; payload[0]=0x00, [2]=0x54 (const so far) |
| 0x05 | 0x24 | on config change | config response (36B) — appears after app-side fan/mode change |
| 0x09 | 0x26 | occasional | short response (payload has u16 RPM + status byte) |
| 0x13 | 0x26 | occasional | TLV response; carries temperature info (SetTemperatureInfo echo) |

Heartbeat decode (verified live):
- `A5 07 06 06 09 01 C2 ...` -> RPM=0x0906=2310, field2=0x01C2
- `A5 07 06 8E 08 01 49 ...` -> RPM=0x088E=2190, field2=0x0149
- Observed RPM range 2190..3660; field2 stays 0x01xx (maybe current/load/%
  of something — TBD)
- Frame 0x05/0x07 stable both during auto and max-fan phases
- Max-fan change produced extra 0x07 heartbeats with RPM 3360..3660 and
  cmd 0x05 len 0x24 response + 0x09/0x13 frames

## Write commands (verified/confirmed so far)

- Official app writes are also 65-byte (report ID 0x00 + 64B) — same framing
  as ours; framing confirmed via libusb debug logging (LIBUSB_DEBUG=255).
- The device ACKs accepted commands with
  `A5 05 <cmd> <status?> <value?> ...`  (e.g. `A5 05 24 00 E1`, `A5 05 24 01 C0`,
  `A5 05 08 00 6A`, `A5 05 10 00 B0`, `A5 05 11 01 A0`)
- Known command ids referenced by ACKs: 0x07(?), 0x08, 0x10, 0x11, 0x24,
  0xC0, 0xC1 (0xC0/0xC1 likely inverter/反充 related — ini
  `showedInverterModeGuidance=1`)
- static template found in exe .data: `A5 07 05 00 00 00 00 02`
- GetFirmwareVersion(RESP) = `A5 09 01 33 2E 30 2E 33 6F` = "3.0.3"+0x6F
  (ascii!) -> request likely `A5 07 05 00 00 00 00 02` (response cmd 09 = req 07 + 2)

## Device response frames (full connect exchange, 2026-08-27)

During app startup the device answers a burst (responses embed a 2-byte
sequence 00 00, 00 01, ...):

- `A5 05 08 00 6A ...`            (x4)
- `A5 05 07 00 54 ...`            (1 Hz stable)
- `A5 05 24 00 E1 / 01 C0 ...`    (config ack; appears after fan change)
- `A5 05 10 00 B0 / 11 01 A0 / C0 00 97 / C1 01 87`  (acks)
- `A5 09 26 00 00 <n> ...`        (n=01..04; GetDeviceInfo blocks)
- `A5 09 01 33 2E 30 2E 33 6F`    (firmware "3.0.3")
- `A5 0C 14 <n> ...`              (n=01..08; device info sub-blocks,
  `A5 0C 14 11 BE 0A 50 01 00 00 00 AE` style)
- `A5 13 26 00 01 <tag> 14 <20B>` (TLV: tag 01/02/03/04, len 0x14=20;
  temperature/info push echo, `02 14` variant in f[006])
- `A5 13 25 00 01 01 14 ...`      (len 0x25 variant)

Frame format everywhere: `A5 [cmd] [len] [payload]`, no visible checksum.
- SetCoolingConfig / GetCurCoolingConfig / GetAnyCoolingConfig
- SetFanSwitch (on/off), SetCoolingSource
- SetRgbLightingSwitch / SetRgbLightingEffects / GetCurRgbLightingEffects
- SetLcdScreenSwitch / SetLcdShowPos
- IssueSystemInfo (push CPU/GPU temps to cooler screen, TLV SetTemperatureInfo)
- GetFirmwareVersion, GetDeviceInfo, EnterBootMode (firmware flash - DANGER),
  RestoreFactorySettings, FactoryTest* (do not use casually)
- App ini keys: coolingMode0..3 (0/1), DeviceUUID, IsLaunchWithWindows

## Tooling

Windows capture tips:
- hidapi (`pip install hidapi`) opens device concurrently with official app OK
- official app logs USB traffic but UTF-8-mangles binary frames
- `python sharkcool/decode.py` = live RPM reader (MVP baseline)
- frames archive: sharkcool/frames_live.hex, PROTOCOL above

## TODO / unknowns

1. Exact write-byte templates (SetCoolingConfig mode/fan, SetFanSwitch,
   RGB, LCD screen off/on, IssueSystemInfo) — differential experiment or USBPcap
2. field2 semantics (0x01xx)
3. cmd 0x05 0x07 payload[2]=0x54 meaning
4. CPU/GPU temp source for screen push (WMI thermal zone / nvidia-smi / LibreHardwareMonitor)
5. Port protocol to Go (hidapi via karalabe/hid or gohid) — Wails v2 app
