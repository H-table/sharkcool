package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows/registry"
)

const (
	vid     = 0xE2B7
	pid     = 0x7001
	reportN = 64

	appName    = "SharkCool"
	appTitleCN = "黑鲨风神Pro控制器"
)

// Status is the snapshot pushed to the frontend.
type Status struct {
	Connected  bool             `json:"connected"`
	RPM        uint32           `json:"rpm"`
	Field2     uint32           `json:"field2"`
	Cmds       map[string]int   `json:"cmds"`
	LastUpdate int64            `json:"lastUpdate"`
	Error      string           `json:"error"`
	Temps      map[string]int64 `json:"temps"` // celsius; key: cpu, gpu
	Mode       int              `json:"mode"`  // last known/selected mode 0..3
}

// Settings persisted to %APPDATA%\SharkCool\config.json
type Settings struct {
	Autostart bool `json:"autostart"`
}

// App is the Wails-bound backend.
type App struct {
	ctx      context.Context
	mu       sync.Mutex
	status   Status
	settings Settings
	dev      *hidConn
	stop     chan struct{}
	wg       sync.WaitGroup

	cfgPath string
	exePath string
}

func NewApp() *App {
	a := &App{
		status: Status{Cmds: map[string]int{}, Temps: map[string]int64{}},
		stop:   make(chan struct{}),
	}
	a.exePath, _ = os.Executable()
	if dir, err := os.UserConfigDir(); err == nil {
		a.cfgPath = filepath.Join(dir, appName, "config.json")
	}
	_ = a.loadSettings()
	return a
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.connectLoop()
	go a.tempLoop()
}

// ---- settings persistence ----

func (a *App) loadSettings() error {
	if a.cfgPath == "" {
		return nil
	}
	b, err := os.ReadFile(a.cfgPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &a.settings)
}

func (a *App) saveSettings() error {
	if a.cfgPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.cfgPath), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	return os.WriteFile(a.cfgPath, b, 0o644)
}

// ---- public (bound) methods ----

// GetStatus returns the current device + temp snapshot.
func (a *App) GetStatus() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.status
	st.Cmds = map[string]int{}
	for k, v := range a.status.Cmds {
		st.Cmds[k] = v
	}
	st.Temps = map[string]int64{}
	for k, v := range a.status.Temps {
		st.Temps[k] = v
	}
	return st
}

// Connect opens the cooler and starts the reader (idempotent).
func (a *App) Connect() bool {
	a.mu.Lock()
	if a.dev != nil {
		a.mu.Unlock()
		return true
	}
	a.mu.Unlock()
	return a.connect() == nil
}

// Disconnect closes the device (reader stops, auto-reconnect paused).
func (a *App) Disconnect() {
	a.mu.Lock()
	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
	a.status.Connected = false
	a.mu.Unlock()
	a.emit()
}

// SetAutostart toggles the HKCU Run registry entry.
func (a *App) SetAutostart(on bool) error {
	a.mu.Lock()
	a.settings.Autostart = on
	a.mu.Unlock()
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		err = k.SetStringValue(appName, `"`+a.exePath+`"`)
	} else {
		err = k.DeleteValue(appName)
		if err == registry.ErrNotExist {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	return a.saveSettings()
}

// GetSettings returns current settings (for UI init).
func (a *App) GetSettings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// SetFanMode changes the cooler's cooling mode (0..3).
// NOTE: exact write-frame template is still being reverse engineered;
// see PROTOCOL.md. Returns an informative error until confirmed.
func (a *App) SetFanMode(mode int) (bool, error) {
	return false, fmt.Errorf("模式控制帧仍在逆向中，暂未开放（可从实验发送框尝试或查看 PROTOCOL.md）")
}

// SetFanSwitch turns the fan on/off. Same status as SetFanMode.
func (a *App) SetFanSwitch(on bool) (bool, error) {
	return false, fmt.Errorf("风扇开关帧仍在逆向中，暂未开放（可从实验发送框尝试或查看 PROTOCOL.md）")
}

// SendRaw sends an experimental A5 frame given hex payload (A5 header
// itself). Payload is padded/truncated to 64 bytes.
func (a *App) SendRaw(hexStr string) (string, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(hexStr, " ", ""))
	if err != nil {
		return "", fmt.Errorf("bad hex: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty frame")
	}
	ok, err := a.sendFrame(b)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("frame not delivered")
	}
	return fmt.Sprintf("sent %s", hex.EncodeToString(b)), nil
}

// ---- frame building (pending final bytes; see PROTOCOL.md) ----

func (a *App) sendFrame(frame []byte) (bool, error) {
	if len(frame) < 3 {
		return false, fmt.Errorf("frame too short")
	}
	a.mu.Lock()
	dev := a.dev
	a.mu.Unlock()
	if dev == nil {
		return false, fmt.Errorf("设备未连接")
	}
	buf := make([]byte, reportN)
	copy(buf, frame)
	n, err := dev.Write(buf)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ---- internals ----

func (a *App) connectLoop() {
	for {
		select {
		case <-a.stop:
			return
		default:
		}
		err := a.connect()
		if err != nil {
			a.setError(err.Error())
		}
		time.Sleep(3 * time.Second)
	}
}

func (a *App) connect() error {
	dev, err := openConn(vid, pid)
	if err != nil {
		return fmt.Errorf("open failed: %w", err)
	}
	a.mu.Lock()
	a.dev = dev
	a.status.Connected = true
	a.status.Error = ""
	a.mu.Unlock()
	a.emit()
	go a.readLoop(dev)
	return nil
}

func (a *App) readLoop(dev *hidConn) {
	buf := make([]byte, reportN)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			break
		}
		if n < 3 {
			continue
		}
		off := 0
		if buf[0] != 0xA5 && n > 3 && buf[1] == 0xA5 {
			off = 1
		}
		if buf[off] != 0xA5 {
			continue
		}
		cmd := buf[off+1]
		ln := int(buf[off+2])
		if off+3+ln > n {
			ln = n - off - 3
		}
		if ln < 0 {
			ln = 0
		}
		payload := buf[off+3 : off+3+ln]
		a.handle(cmd, payload)
	}
	a.mu.Lock()
	if a.dev == dev {
		a.dev = nil
		a.status.Connected = false
		a.status.Error = "设备已断开"
	}
	a.mu.Unlock()
	a.emit()
}

func (a *App) handle(cmd byte, payload []byte) {
	a.mu.Lock()
	a.status.Cmds[fmt.Sprintf("0x%02X", cmd)]++
	a.status.LastUpdate = time.Now().UnixMilli()
	if cmd == 0x07 && len(payload) >= 4 {
		a.status.RPM = uint32(binary.LittleEndian.Uint16(payload[0:2]))
		a.status.Field2 = uint32(binary.LittleEndian.Uint16(payload[2:4]))
	}
	a.mu.Unlock()
	a.emit()
}

func (a *App) tempLoop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	read := func() {
		gpu, cpu := readTemps()
		a.mu.Lock()
		if gpu > 0 {
			a.status.Temps["gpu"] = gpu
		}
		if cpu > 0 {
			a.status.Temps["cpu"] = cpu
		}
		a.mu.Unlock()
		a.emit()
	}
	read()
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
			read()
		}
	}
}

// readTemps polls GPU via nvidia-smi and CPU via WMI thermal zone
// (best effort; empty sources are skipped).
func readTemps() (gpu, cpu int64) {
	// GPU
	if out, err := exec.Command("nvidia-smi",
		"--query-gpu=temperature.gpu", "--format=csv,noheader").Output(); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			gpu = v
		}
	}
	// CPU (best effort WMI thermal zone)
	_ = cpu // placeholder: WMI query below via powershell
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1).CurrentTemperature`).Output()
	if err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil {
			cpu = int64(v/10.0 - 273.15)
		}
	}
	return gpu, cpu
}

func (a *App) setError(msg string) {
	a.mu.Lock()
	a.status.Error = msg
	a.mu.Unlock()
	a.emit()
}

func (a *App) emit() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "telemetry", a.GetStatus())
}
