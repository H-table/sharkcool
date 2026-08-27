# BRB02 Cooler Protocol Notes (黑鲨风神Pro / 黑鲨装备箱)

Reverse-engineered 2026-08-27/28 from live HID captures + official DLL
analysis (32-bit ctypes harness, see tools/dll_probe*.py).

## ✅ Round 7: 写命令帧 100% 破解（2026-08-28 02:20 抓包实锤）

**通道：`\\.\USBPcap3`（C 口链，1A86 hub + E2B7 散热器）** —— 之前所有
抓包都错抓了 USBPcap1/2（A 口链）。USBPcapCMD + python 直解器
(tools/pcap3.py)：

- USBPcap 记录布局（1.5.4.0，28 字节头）：`hlen=rec[0:4]`，
  `方向/端点=rec[21]`（0x81 IN），**`dlen=rec[23]`**，数据=rec[28:28+dlen]，
  但**每帧第 1 字节实际是 A5**（rec[27] 处）= 完整帧 `A5 + 63B`。
- **SetCoolingConfig（实测 3 次对照）：**
  ```
  模式2: A5 09 24 00 00 03 60 0B 40
  模式3: A5 09 24 00 00 04 CE 0D B1
  格式:  A5 09 24 [00 00] [模式ID] [RPM u16le] [byte] 0x00...
         - len=0x24 (36B)，设备回 A5 05 24 00 E1 (配置确认)
         - 模式2: modeId=03, RPM=0x0B60=2912
         - 模式3: modeId=04, RPM=0x0DCE=3534
  ```
- **其他已确认命令**（双向）：
  - `A5 06 26 [0x00/0x01][序号][校验]` = GetDeviceInfo 类请求 xN
    （周期 ~2s；响应 `A5 09 26 00 00 [序号] ...` 与 `A5 13 26 ...`）
  - `A5 13 24 00 01 01 14 [6×u16le 温度数据]` = IssueSystemInfo
    （温度推送，事件触发；设备回 `A5 13 26 00 01 ...`）
  - `A5 1A 07 ...` = 周期状态/传感器列表（电池/温度表，0.1s）
  - IN 心跳 `A5 07 06 [RPM u16le][f2 u16le]`、状态 `A5 05 07 00 54`
  - 配置确认 `A5 05 24 00 E1`
- 设备配置描述符：EP 0x81 IN interrupt（64B）+ **BULK 端点 0x02/0x82**！

## 抓包工具（已验证可复现）
```
USBPcapCMD.exe -d \\.\USBPcap3 -o cap.pcap -A --inject-descriptors
python tools/pcap3.py cap.pcap   # 直解 64B 帧
```

## Round 6 (libusb 代理 v2：Win32 纯 API + 调用追踪；app 失败点缩到 init 之后)

- 对照实验定案：**真库下 app 稳定(30s+)，代理下退出** —— 代理相关。
- proxy2（libusb_proxy2.c，TinyCC，零 CRT，CreateFileA/WriteFile 日志，
  GetTempPathA→%TEMP%\libusb_proxy2.log）部署后：
  - harness 全序：init=0、open(0xE2B7,0x7001) 成功、claim=0 —— **转发正确**。
  - app 内：`[proxy] init real=... f=...` 且 **`init rc=0 ctx=...` ×2** ——
    **libusb_init 在 app 里成功**，但 app 随即 exit=1，且未再调用
    get_device_list/open —— 失败点缩到「init 之后、GetDeviceList 之前」。
  - 推测：app 在该间隙做了运行时 GetProcAddress 取附加 API
    （proxy2 已补 libusb_get_version/set_option/has_capability 导出，仍退出）
    或依赖 libusb 内部行为（如 hotplug 回调注册时机）。
  - **下一步首选**：给代理补全常用 libusb 导出集（get_string_descriptor_ascii、
    control_transfer、bulk_transfer、alloc_transfer、get_configuration 等 ~20 个）
    再试；备选：重启走 USBPcap（已 100% 就绪，见 Round 3）。
- **恢复原厂**：验证后已把 app 目录 libusb-1.0.dll 恢复为真实库，
  现 app 正常运行（备份：tools/libusb-1.0_original.dll、
  app/libusb-1.0_real.dll；proxy 各版本在 tools/）。



**重大进展**：管理员 + Program Files 可写 → TinyCC (tcc-0.9.27) 编译
`tools/libusb_proxy.c` → 部署为 `D:\Program Files (x86)\BlackSharkEquipmentBox\libusb-1.0.dll`
（原库改名 libusb-1.0_real.dll，备份在 tools/libusb-1.0_original.dll）。

- 代理转发 Brb02CoolerComm.dll 的 14 个 + 装备箱 exe 的 3 个额外 libusb
  导入（hotplug_register/deregister_callback, handle_events_timeout_completed
  —— 缺这 3 个会导致 app 以 0xC0000139 退出！），并在
  `libusb_interrupt_transfer` 处 fwrite 记录双向数据到 %TEMP%\libusb_proxy.log。
- 32 位 python 验证：代理 init=0、devlist=10、open(0xE2B7,0x7001) 成功、
  interrupt IN 可读 —— **代理转发 100% 工作**。
- app（装备箱.exe）在代理下启动可达 `dialogMain::dialogMain 627` 但随后
  CrashRpt 崩溃（01:47-01:50，4 次）。同期代理日志曾捕获
  `ep=0x81 IN len=64 r=0: a5...`（app 已收包后崩）。
- harness 中 comm DLL 仍报 `Failed to initialize libusb: NO_MEM`
  （Qt applicationDirPath="\" 影响；与代理无关，对 USB 抓包通路无影响）。

**下一步两条路**（任一即达终局）：
1. 系统重启 → USBPcap 已绑定 C 口 root hub → 抓 30 秒 + 用户点模式2 → 帧到手。
2. 修复代理下 app 崩溃（排查 QtWebEngine 交互期；日志已从 %02x 改 fwrite），
   重跑 app → 拦截写帧。
- tshark 已就绪：`C:\Program Files\Wireshark\tshark.exe`，命令见 Round 3 章节。

## Round 4 findings (DLL 发送钩子结构解析)

- `coolerRegisterSendCmd` 钩子在 32 位 harness 中稳定触发（即使无设备）。
- hook 参数 = **Qt 元调用层结构**：反复出现签名
  `[u32][u32][0x14][0xFFFFFFFF][0d0a++]`（0x14=20 字节配置结构、0d0a=CRLF）
  —— 结合 Qt5Core 指针段（0x58/0x5A...）判断为 QMetaObject::activate 的
  参数数组或 QByteArrayData 元数据；帧数据在本轮探测中始终未直接出现
  （每次 "A5" 命中均为堆指针低位，非协议帧）。
- **结论**：官方写帧的可靠来源 = USB 抓包（USBPcap，等重启覆盖 C 口 root hub）。
- 另确认 `{18 00 00 00 / 08 00 00 00 / <ptr> / 59 00 00 00}` 结构稳定存在，
  ptr 指向 Qt 内部对象（cookie 0x57/0x5A 结尾的 dword 为 Qt 分配器标记）。

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
