import './style.css';
import './app.css';

const $ = (id) => document.getElementById(id);

function render(st) {
    $('conn-dot').className = 'dot ' + (st.connected ? 'ok' : 'off');
    $('conn-text').textContent = st.connected ? '已连接' : (st.error ? st.error : '未连接');
    $('rpm').textContent = st.rpm ? st.rpm : '--';
    if (st.rpm) {
        const pct = Math.max(0, Math.min(100, (st.rpm - 1500) / 2500 * 100));
        $('rpmbar').style.width = pct.toFixed(1) + '%';
    }
    if (st.temps) {
        $('gpuT').textContent = st.temps.gpu ?? '--';
        $('cpuT').textContent = st.temps.cpu ?? '--';
    }
    if (st.lastUpdate) {
        $('update-time').textContent = '更新于 ' + new Date(st.lastUpdate).toLocaleTimeString();
    }
    document.querySelectorAll('.mode-btn').forEach((b) => {
        b.classList.toggle('active', parseInt(b.dataset.mode, 10) === st.mode);
    });
}

async function refresh() {
    try {
        const st = await window.go.main.App.GetStatus();
        render(st);
    } catch (e) {
        console.error(e);
    }
}

window.__connect = async () => {
    try { await window.go.main.App.Connect(); } catch (e) { console.error(e); }
    refresh();
};

window.__send = async () => {
    const hexStr = $('raw-input').value.trim();
    if (!hexStr) return;
    try {
        const res = await window.go.main.App.SendRaw(hexStr);
        $('raw-result').textContent = res;
    } catch (e) {
        $('raw-result').textContent = '发送失败: ' + e;
    }
};

window.__auto = async () => {
    const on = $('autostart').checked;
    try {
        await window.go.main.App.SetAutostart(on);
    } catch (e) {
        console.error(e);
        $('autostart').checked = !on;
    }
};

document.querySelectorAll('.mode-btn').forEach((b) => {
    b.addEventListener('click', async () => {
        $('mode-result').textContent = '切换中…';
        try {
            const ok = await window.go.main.App.SetFanMode(parseInt(b.dataset.mode, 10));
            $('mode-result').textContent = ok ? '已发送' : '发送未成功';
        } catch (e) {
            $('mode-result').textContent = '失败: ' + e;
        }
    });
});

document.getElementById('fan-switch').addEventListener('click', async () => {
    try {
        const ok = await window.go.main.App.SetFanSwitch(true);
        $('mode-result').textContent = ok ? '风扇开关指令已发送' : '发送未成功';
    } catch (e) {
        $('mode-result').textContent = '失败: ' + e;
    }
});

window.addEventListener('DOMContentLoaded', async () => {
    refresh();
    setInterval(refresh, 2000);
    try {
        const s = await window.go.main.App.GetSettings();
        $('autostart').checked = !!s.autostart;
    } catch (e) { /* ignore */ }
    if (window.runtime && window.runtime.EventsOn) {
        window.runtime.EventsOn('telemetry', (st) => render(st));
    }
});
