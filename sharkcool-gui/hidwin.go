package main

// Pure-Go (no cgo) HID access for Windows: enumerate the Black Shark cooler
// (VID 0xE2B7 / PID 0x7001) via SetupAPI and do read/write on the HID
// device interface with CreateFile/ReadFile/WriteFile.
// This mirrors what hidapi does internally, minus the C dependency.

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// GUID_DEVINTERFACE_HID
	guidDevInterfaceHID = windows.GUID{Data1: 0x4d1e55b2, Data2: 0xf16f, Data3: 0x11cf, Data4: [8]byte{0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}}

	setupapi = windows.NewLazySystemDLL("setupapi.dll")

	procGetClassDevs       = setupapi.NewProc("SetupDiGetClassDevsW")
	procEnumDeviceIfaces   = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procGetDeviceIfaceDet  = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procDestroyDevInfoList = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procGetDevInstanceID   = setupapi.NewProc("SetupDiGetDeviceInstanceIdW")
)

const (
	digcfPresent         = 0x00000002
	digcfDeviceInterface = 0x00000010
	invalidHandleValue   = ^uintptr(0)
	// SP_DEVICE_INTERFACE_DETAIL_DATA_W: cbSize must equal
	// sizeof(struct)=8 on x64 (the function validates it), but the
	// DevicePath WCHAR[] starts right after the 4-byte cbSize with no
	// padding (path offset 4).
	hidCbSize    = 8
	pathOffset   = 4
	reportBufSize = 65
	// report ID byte + 64 byte payload for output reports
	outputBufSize = 65
)

type spDevInfoData struct {
	cbSize    uint32
	classGUID windows.GUID
	devInst   uintptr
	reserved  uintptr
}

type spDeviceInterfaceData struct {
	cbSize        uint32
	interfaceGUID windows.GUID
	flags         uint32
	reserved      uintptr
}

// hidConn wraps a HID device handle.
type hidConn struct {
	h   windows.Handle
	mu  sync.Mutex
	rMu sync.Mutex
}

// findCoolerPath enumerates HID interfaces and returns the device path whose
// interface path contains the Black Shark VID/PID.
func findCoolerPath(vid, pid uint16) (string, error) {
	hDev, _, err := procGetClassDevs.Call(
		uintptr(unsafe.Pointer(&guidDevInterfaceHID)),
		0, 0,
		digcfPresent|digcfDeviceInterface)
	if hDev == invalidHandleValue {
		return "", fmt.Errorf("SetupDiGetClassDevs failed: %v", err)
	}
	defer procDestroyDevInfoList.Call(hDev)

	want := fmt.Sprintf("vid_%04x&pid_%04x", vid, pid)
	for idx := uint32(0); ; idx++ {
		iface := spDeviceInterfaceData{cbSize: uint32(unsafe.Sizeof(spDeviceInterfaceData{}))}
		r, _, _ := procEnumDeviceIfaces.Call(
			hDev, 0,
			uintptr(unsafe.Pointer(&guidDevInterfaceHID)),
			uintptr(idx),
			uintptr(unsafe.Pointer(&iface)))
		if r == 0 {
			break // no more interfaces
		}

		var required uint32
		procGetDeviceIfaceDet.Call(
			hDev,
			uintptr(unsafe.Pointer(&iface)),
			0, 0,
			uintptr(unsafe.Pointer(&required)), 0)
		detail := make([]byte, required+64)
		*(*uint32)(unsafe.Pointer(&detail[0])) = hidCbSize
		// DeviceInfoData must be NULL (hidapi-compatible behavior)
		r, _, _ = procGetDeviceIfaceDet.Call(
			hDev,
			uintptr(unsafe.Pointer(&iface)),
			uintptr(unsafe.Pointer(&detail[0])),
			uintptr(len(detail)),
			0, 0)
		if r == 0 {
			continue
		}

		// path = wide string right after the 4-byte cbSize (packed struct)
		buf := detail[pathOffset:]
		pathLen := 0
		for pathLen+1 < len(buf) {
			if buf[pathLen] == 0 && buf[pathLen+1] == 0 {
				break
			}
			pathLen += 2
		}
		path := syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), pathLen/2))
		if strings.Contains(strings.ToLower(path), want) {
			return path, nil
		}
	}
	return "", fmt.Errorf("cooler (VID %04X PID %04X) not found", vid, pid)
}

// openConn opens the cooler HID interface.
func openConn(vid, pid uint16) (*hidConn, error) {
	path, err := findCoolerPath(vid, pid)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		return nil, fmt.Errorf("CreateFile: %w", err)
	}
	return &hidConn{h: h}, nil
}

// Read blocks until an input report arrives. Returns payload without the
// report-ID prefix when the ID is 0.
func (c *hidConn) Read(buf []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	tmp := make([]byte, reportBufSize)
	var n uint32
	err := windows.ReadFile(c.h, tmp, &n, nil)
	if err != nil {
		return 0, err
	}
	if n > 0 && tmp[0] == 0x00 {
		// strip default report-ID byte
		copy(buf, tmp[1:n])
		return int(n - 1), nil
	}
	copy(buf, tmp[:n])
	return int(n), nil
}

// Write sends an output report (payload without report ID; the 0x00 ID
// byte is prepended).
func (c *hidConn) Write(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(buf) >= outputBufSize {
		buf = buf[:outputBufSize-1]
	}
	tmp := make([]byte, outputBufSize)
	tmp[0] = 0x00 // report ID
	copy(tmp[1:], buf)
	var n uint32
	err := windows.WriteFile(c.h, tmp, &n, nil)
	if err != nil {
		return 0, err
	}
	return int(n - 1), nil
}

// Close releases the device handle.
func (c *hidConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h != 0 {
		windows.CloseHandle(c.h)
		c.h = 0
	}
	return nil
}
