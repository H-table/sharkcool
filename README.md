# SharkCool — 黑鲨风神Pro 散热器开源控制器

![Go](https://img.shields.io/badge/Go-1.27+-00ADD8)
![Wails](https://img.shields.io/badge/Wails-v2-8B5CF6)
![License](https://img.shields.io/badge/License-MIT-green)

一个开源的 **黑鲨风神Pro 笔记本散热器（BRB02）** 桌面控制软件（灵感来自 [THRM](https://github.com/TIANLI0/THRM)）。
不需要运行官方「黑鲨装备箱」也能监控和控制你的散热器。

## ✨ 功能

- **实时转速监视**：从散热器 USB HID 读取风扇转速（2190~3660 RPM 区间已验证），逐秒刷新
- **温度显示**：GPU（nvidia-smi）与 CPU（WMI 热区，尽力而为）温度
- **模式控制**：一键切换散热器工作模式 ✅ **已实测**（模式2→~2912 RPM、模式3→~3534 RPM；协议经 USB 抓包逆向，见 [PROTOCOL.md](PROTOCOL.md)）
- **开机自启**：一个开关搞定
- **纯 Go HID 栈**：零 cgo、零第三方驱动——直接使用 Windows SetupAPI + CreateFile/ReadFile，与官方软件可同时运行
- **自动重连**：拔插散热器自动恢复
- **实验发送框**：可手动发送 A5 帧做协议实验（高级功能）

## 🖥️ 支持平台

- Windows 10 / 11 x64（需要 WebView2 运行时，Win11 自带）

## 📥 安装

发布页下载安装包（或便携版 zip），双击运行即可。首次运行自动连接散热器。

## 🛠️ 从源码构建

```bash
# 依赖：Go 1.27+、Node.js 18+、Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

wails init -n sharkcool-gui -t vanilla   # 或直接克隆本项目
cd sharkcool-gui
npm install
wails build
# 产物: build/bin/sharkcool-gui.exe
```

## 📡 协议速览（详见 [PROTOCOL.md](sharkcool/PROTOCOL.md)）

```
A5 [cmd:u8] [len:u8] [payload:len bytes]  （64 字节报告，无校验和）
```

| cmd | 方向 | 含义 |
|-----|------|------|
| 0x05 | 设备→主机 | 状态帧 |
| 0x07 | 设备→主机 | 心跳（小端 u16 × 2：风扇转速 + 副字段）|
| — | 主机→设备 | 模式/开关等控制命令（详见协议文档）|

## ⚠️ 免责声明

- 本项目为社区逆向工程产物，与黑鲨科技无任何关系，未经官方授权
- 请勿生成/发送固件升级（EnterBootMode）、恢复出厂等危险命令，可能导致设备损坏
- 使用风险自负

## 📄 许可

[MIT](LICENSE)
