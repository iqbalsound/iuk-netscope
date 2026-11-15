#!/usr/bin/env python3
"""IUK-NetScope - interface discovery + nmap-powered network scanner.

Author : Iqbal Uddin Khan
Targets: Linux (developed for Kubuntu). Use ONLY on networks/devices you own
         or have written permission to test.
"""
from __future__ import annotations

import argparse, atexit, csv, ipaddress, json, os, queue, re, shlex, shutil
import queue, socket, subprocess, sys, tempfile, threading, time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

__version__ = "0.0.1"
TOOL = "IUK-NetScope"
AUTHOR = "Iqbal Uddin Khan"
REPORT_DIR = Path(os.environ.get("IUK_REPORT_DIR", Path.home() / "iuk-netscope-reports"))
IS_WIN = os.name == "nt"
CONFIG = (Path(os.environ.get("APPDATA", Path.home())) / "iuk-netscope" / "config.json") if IS_WIN \
    else Path.home() / ".config" / "iuk-netscope" / "config.json"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WIN else 0   # no console flashes from the windowed .exe


def is_admin():
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def find_exe(name):
    """shutil.which plus the default Nmap install folder on Windows (PATH is stale right after install)."""
    p = shutil.which(name)
    if p or not IS_WIN or name != "nmap":
        return p
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if base and (Path(base) / "Nmap" / "nmap.exe").exists():
            return str(Path(base) / "Nmap" / "nmap.exe")
    return None


if IS_WIN:
    os.system("")   # enables ANSI colours in the Windows console

# --------------------------------------------------------------------------- themes
THEMES = {
    "dark":   dict(bg="#1e1e2e", alt="#252536", head="#313244", fg="#cdd6f4", accent="#89b4fa",
                   good="#a6e3a1", warn="#f9e2af", bad="#f38ba8", dim="#7f849c"),
    "matrix": dict(bg="#000000", alt="#041404", head="#003b00", fg="#00ff41", accent="#39ff14",
                   good="#00ff41", warn="#ccff00", bad="#ff3b3b", dim="#008f11"),
    "light":  dict(bg="#ffffff", alt="#f6f8fa", head="#eaeef2", fg="#1f2328", accent="#0969da",
                   good="#1a7f37", warn="#9a6700", bad="#cf222e", dim="#656d76"),
    "ocean":  dict(bg="#0b2545", alt="#0f3057", head="#13315c", fg="#d8f3ff", accent="#00b4d8",
                   good="#90e0ef", warn="#ffd166", bad="#ff6b6b", dim="#7ba7c7"),
}
STATE = {"theme": "dark", "font_size": 12, "sudo": False, "yes": False,
         "geometry": "", "notify": True, "gui_admin": True}
SESSION: list = []      # every result table produced this session (feeds the reports)
LOG: list = []          # commands run this session


class UI:
    color = bool(sys.stdout and sys.stdout.isatty())
    gui = False
    width = None


def _rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def C(role, text, bold=False):
    text = str(text)
    if not UI.color:
        return text
    r, g, b = _rgb(THEMES[STATE["theme"]][role])
    return f"\x1b[{'1;' if bold else ''}38;2;{r};{g};{b}m{text}\x1b[0m"


def _default_sink(level, msg):
    role = {"info": "dim", "warn": "warn", "err": "bad", "ok": "good"}[level]
    print(C(role, {"warn": "[!] ", "err": "[x] "}.get(level, "") + str(msg)))


SINK = _default_sink          # the GUI replaces this to show messages in its Activity view


def info(m): SINK("info", m)
def warn(m): SINK("warn", m)
def err(m): SINK("err", m)
def ok(m): SINK("ok", m)


class Cancelled(Exception):
    pass


class Ctl:
    """Cancellation + progress handle shared between a worker and the GUI."""
    def __init__(self, on_progress=None):
        self.cancelled, self.proc = False, None
        self.on_progress = on_progress or (lambda p: None)

    def cancel(self):
        self.cancelled = True
        if self.proc and self.proc.poll() is None:
            try: self.proc.terminate()
            except Exception: pass

    def check(self):
        if self.cancelled:
            raise Cancelled()


PERSIST = ("theme", "font_size", "geometry", "notify", "gui_admin")


def load_config():
    try:
        STATE.update({k: v for k, v in json.loads(CONFIG.read_text()).items() if k in PERSIST})
    except Exception:
        pass


def save_config():
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps({k: STATE[k] for k in PERSIST}))
    except Exception:
        pass


def term_colors():
    """Best-effort: ask the terminal to adopt the theme bg/fg (xterm, kitty, etc.)."""
    if UI.color and not UI.gui and not IS_WIN and sys.stdout and sys.stdout.isatty():
        t = THEMES[STATE["theme"]]
        sys.stdout.write(f"\x1b]11;{t['bg']}\x07\x1b]10;{t['fg']}\x07")
        sys.stdout.flush()


def term_reset():
    if UI.color and not UI.gui and not IS_WIN and sys.stdout and sys.stdout.isatty():
        sys.stdout.write("\x1b]111\x07\x1b]110\x07")
        sys.stdout.flush()


def term_font(size):
    """Change terminal font size where the terminal allows it."""
    if os.environ.get("KITTY_WINDOW_ID") and shutil.which("kitty"):
        run(["kitty", "@", "set-font-size", str(size)])
    elif os.environ.get("TERM", "").startswith("xterm") and not os.environ.get("KONSOLE_VERSION"):
        sys.stdout.write(f"\x1b]50;xft:monospace:size={size}\x07")
        sys.stdout.flush()
    else:
        info("This terminal does not allow apps to change its font. Use Ctrl+Shift+'+' / Ctrl+'-' "
             "(Konsole: Ctrl+Shift+'+'), or run  `iuk_netscope.py gui`  for the desktop app "
             "with live font sizing.")


# --------------------------------------------------------------------------- helpers
def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=NOWIN,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired as e:
        o = e.stdout or ""
        return 124, o.decode() if isinstance(o, bytes) else o, "timed out"


def T(title, headers, rows, note=""):
    return {"title": title, "headers": headers, "rows": rows, "note": note}


GOOD = {"open", "up", "yes", "connected", "online", "paired", "reachable", "*"}
BAD = {"down", "no", "offline", "closed", "failed"}
WARN = {"filtered", "open|filtered", "unknown", "stale", "incomplete"}


def cell_role(v):
    s = str(v).strip().lower()
    return "good" if s in GOOD else "bad" if s in BAD else "warn" if s in WARN else "fg"


def render(t):
    heads, rows = t["headers"], t["rows"]
    print()
    print(C("accent", f"▌ {t['title']}", True) + C("dim", f"  [{len(rows)} row(s)]"))
    if t.get("note"):
        print(C("dim", "  " + t["note"]))
    if not rows:
        print(C("dim", "  (nothing found)"))
        return
    flat = [[str(x).replace("\n", " ⏎ ") for x in r] for r in rows]
    width = UI.width or shutil.get_terminal_size((120, 30)).columns
    w = [max(len(str(h)), *(len(r[i]) for r in flat)) for i, h in enumerate(heads)]
    while sum(w) + 3 * (len(w) - 1) + 2 > width and max(w) > 10:
        w[w.index(max(w))] -= 1
    cut = lambda s, n: s if len(s) <= n else s[:max(n - 1, 1)] + "…"
    print("  " + " │ ".join(C("accent", cut(str(h), w[i]).ljust(w[i]), True) for i, h in enumerate(heads)))
    print("  " + C("dim", "─┼─".join("─" * x for x in w)))
    for r in flat:
        print("  " + " │ ".join(C(cell_role(v), cut(v, w[i]).ljust(w[i])) for i, v in enumerate(r)))


TABLE_SINK = render           # the GUI replaces this to show tables as result tabs


def emit(tables):
    for t in (tables if isinstance(tables, list) else [tables]):
        SESSION.append(t)
        TABLE_SINK(t)


def read(p):
    try:
        return Path(p).read_text().strip()
    except Exception:
        return ""



# --------------------------------------------------------------------------- Windows backends
def ps_json(script, timeout=45):
    """Run a PowerShell snippet and return its output as a list of dicts."""
    rc, out, _ = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                      script + " | ConvertTo-Json -Compress -Depth 3"], timeout=timeout)
    out = out.strip()
    if not out:
        return []
    try:
        d = json.loads(out)
    except ValueError:
        return []
    return d if isinstance(d, list) else [d]


def _kv_blocks(text):
    """Parse `key : value` lines (netsh style) into a list of dicts, new block at each repeated first key."""
    blocks, cur = [], {}
    for line in text.splitlines():
        m = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", line)
        if not m:
            continue
        k, v = m[1].strip(), m[2].strip()
        if k in cur:
            blocks.append(cur)
            cur = {}
        cur[k] = v
    if cur:
        blocks.append(cur)
    return blocks


def _win_wifi_links():
    _, out, _ = run(["netsh", "wlan", "show", "interfaces"], timeout=15)
    links = {}
    for b in _kv_blocks(out):
        if "Name" in b:
            links[b["Name"]] = dict(ssid=b.get("SSID", ""), bssid=b.get("BSSID", "").lower(), state=b.get("State", ""),
                                    signal=b.get("Signal", ""), rate=b.get("Receive rate (Mbps)", ""))
    return links


def _win_interfaces():
    ads = ps_json("Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,PhysicalMediaType,InterfaceIndex,MtuSize")
    ips = ps_json("Get-NetIPAddress | Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressFamily")
    links = _win_wifi_links()
    rows = []
    for a in ads:
        idx = a.get("InterfaceIndex")
        v4 = ", ".join(f"{i['IPAddress']}/{i['PrefixLength']}" for i in ips
                       if i.get("InterfaceIndex") == idx and str(i.get("AddressFamily")) in ("2", "IPv4"))
        v6 = ", ".join(f"{i['IPAddress']}/{i['PrefixLength']}" for i in ips
                       if i.get("InterfaceIndex") == idx and str(i.get("AddressFamily")) in ("23", "IPv6")
                       and not str(i["IPAddress"]).lower().startswith("fe80"))
        media, desc = str(a.get("PhysicalMediaType", "")), str(a.get("InterfaceDescription", ""))
        low = (media + " " + desc).lower()
        kind = ("wifi" if "802.11" in low or "wireless" in low or "wi-fi" in low else
                "bluetooth" if "bluetooth" in low else
                "virtual" if any(w in low for w in ("virtual", "hyper-v", "vmware", "virtualbox", "loopback", "tap-", "tunnel", "vpn")) else
                "ethernet")
        lk = links.get(a.get("Name"), {})
        link = "; ".join(x for x in (f"SSID: {lk['ssid']}" if lk.get("ssid") else "", f"signal: {lk['signal']}" if lk.get("signal") else "",
                                      f"tx bitrate: {lk['rate']} Mbit/s" if lk.get("rate") else "") if x)
        rows.append([a.get("Name", ""), kind, "up" if str(a.get("Status")).lower() == "up" else str(a.get("Status", "")).lower(),
                     str(a.get("MacAddress", "")).replace("-", ":").lower(), v4, v6, a.get("MtuSize", ""),
                     str(a.get("LinkSpeed", "")), desc, link])
    return T("Network interfaces (Ethernet / Wi-Fi / virtual)",
             ["Name", "Kind", "State", "MAC", "IPv4", "IPv6", "MTU", "Speed", "Driver", "Wi-Fi link"], rows)


def _chan_freq(ch):
    try:
        c = int(ch)
    except (TypeError, ValueError):
        return ""
    return f"{2412 + 5 * (c - 1) if c <= 14 else 5000 + 5 * c} MHz"


def _win_wifi():
    hdr = ["Connected", "SSID", "BSSID", "Channel", "Freq", "Rate", "Signal %", "Bars", "Security"]
    _, out, e = run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
    if not out.strip():
        warn(e.strip() or "netsh returned nothing - is there a Wi-Fi adapter and is the WLAN AutoConfig service running?")
    links = _win_wifi_links()
    cur = {b for l in links.values() if l["state"].lower() == "connected" for b in [l["bssid"]]}
    ssid = auth = ""
    rows, row = [], None
    for line in out.splitlines():
        if m := re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line):
            ssid, auth, row = m[1].strip(), "", None
        elif m := re.match(r"^\s*Authentication\s*:\s*(.*)$", line):
            auth = m[1].strip()
        elif m := re.match(r"^\s*BSSID\s+\d+\s*:\s*(\S+)", line):
            row = dict(ssid=ssid, bssid=m[1].lower(), auth=auth, sig="", ch="", rate="")
            rows.append(row)
        elif row is not None:
            if m := re.match(r"^\s*Signal\s*:\s*(\d+)%", line):
                row["sig"] = m[1]
            elif m := re.match(r"^\s*Channel\s*:\s*(\d+)", line):
                row["ch"] = m[1]
    out_rows = []
    for r in rows:
        sig = int(r["sig"]) if r["sig"].isdigit() else 0
        out_rows.append(["yes" if r["bssid"] in cur else "no", r["ssid"] or "<hidden>", r["bssid"], r["ch"], _chan_freq(r["ch"]), "",
                         r["sig"], "▂▄▆█"[: max(1, min(4, sig // 25 + (1 if sig % 25 else 0)))] if sig else "", r["auth"] or "open/none"])
    out_rows.sort(key=lambda r: -int(r[6]) if r[6].isdigit() else 0)
    return T("Wi-Fi networks in range", hdr, out_rows)


def _win_neighbors():
    _, out, _ = run(["arp", "-a"], timeout=15)
    rows, ifc = [], ""
    for line in out.splitlines():
        if m := re.match(r"^\s*Interface:\s*(\S+)", line):
            ifc = m[1]
        elif m := re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)", line):
            if int(m[1].split(".")[0]) < 224 and not m[2].lower().startswith("ff-ff-ff"):
                rows.append([m[1], m[2].replace("-", ":").lower(), ifc, m[3].lower()])
    return T("ARP / neighbour cache", ["IP", "MAC", "Interface", "State"], rows)


def _win_usb():
    rows = []
    for d in ps_json("Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\\*' } | Select-Object FriendlyName,Manufacturer,InstanceId,Class,Status"):
        iid = str(d.get("InstanceId", ""))
        m = re.search(r"VID_(\w{4})&PID_(\w{4})", iid, re.I)
        serial = iid.split("\\")[-1] if "&" not in iid.split("\\")[-1] else ""
        rows.append(["", "", iid, f"{m[1].lower()}:{m[2].lower()}" if m else "", d.get("FriendlyName", ""), d.get("Manufacturer", ""),
                     d.get("FriendlyName", ""), d.get("Class", ""), "", "", serial, ""])
    return T("USB devices", ["Bus", "Dev", "Port path", "VID:PID", "Description", "Manufacturer", "Product",
                             "Class", "Speed", "USB ver", "Serial", "Max power"], rows)


def _win_bluetooth():
    ch = ["Controller", "Name", "Default"]
    dh = ["MAC", "Name", "Alias", "Class", "Icon", "Paired", "Trusted", "Connected", "RSSI", "UUIDs", "Modalias"]
    ctl, devs = [], []
    for d in ps_json("Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName,Status,InstanceId"):
        iid, name = str(d.get("InstanceId", "")), str(d.get("FriendlyName", ""))
        m = re.search(r"DEV_([0-9A-Fa-f]{12})", iid)
        if m:
            mac = ":".join(m[1][i:i + 2] for i in range(0, 12, 2)).upper()
            devs.append([mac, name, "", "", "", "yes", "", "yes" if str(d.get("Status")) == "OK" else "no", "", "", ""])
        elif re.search(r"radio|adapter|controller|wireless", name, re.I) and not iid.upper().startswith("BTH\\MS_"):
            ctl.append([iid.split("\\")[-1] or iid, name, "yes" if not ctl else "no"])
    note = "Windows lists paired devices only; scanning for new devices is available on Linux (BlueZ)."
    return [T("Bluetooth controllers", ch, ctl), T("Bluetooth devices (paired)", dh, devs, note)]


def _win_ping(target, count):
    rc, out, e = run(["ping", "-n", str(count), "-w", "2000", target], timeout=count * 4 + 10)
    ip = re.search(r"Pinging (\S+)(?: \[([^\]]+)\])? with", out)
    reps = re.findall(r"(?:bytes|Bytes)=\d+\s+(?:time|Zeit|temps)[=<]\s*(\d+)\s*ms\s+TTL=(\d+)", out, re.I)
    st = re.search(r"Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)", out)
    rt = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", out)
    ttl = reps[0][1] if reps else ""
    guess = ""
    if ttl:
        guess = "Linux/Unix/macOS" if int(ttl) <= 64 else "Windows" if int(ttl) <= 128 else "Network device/Solaris"
    vals = [int(r[0]) for r in reps]
    jit = f"{(max(vals) - min(vals)):.0f}" if vals else ""
    summ = T(f"Ping summary: {target}",
             ["Target", "IP", "Sent", "Received", "Loss %", "Min ms", "Avg ms", "Max ms", "Jitter ms", "TTL", "OS hint (TTL)"],
             [[target, (ip[2] or ip[1]) if ip else "", st[1] if st else "", st[2] if st else "", st[4] if st else "",
               rt[1] if rt else "", rt[3] if rt else "", rt[2] if rt else "", jit, ttl, guess]])
    return [summ, T(f"Ping replies: {target}", ["Seq", "TTL", "Time ms"], [[i + 1, r[1], r[0]] for i, r in enumerate(reps)])]


def _win_default_route():
    r = ps_json("Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 InterfaceAlias,NextHop")
    return (r[0].get("InterfaceAlias"), r[0].get("NextHop")) if r else (None, None)


# --------------------------------------------------------------------------- interfaces
def classify(name):
    base = Path("/sys/class/net") / name
    if name == "lo":
        return "loopback"
    if (base / "wireless").exists() or (base / "phy80211").exists():
        return "wifi"
    if (base / "bridge").exists():
        return "bridge"
    real = str(base.resolve())
    if "/virtual/" in real:
        return "vpn" if name.startswith(("tun", "tap", "wg", "ppp")) else "virtual"
    return "ethernet (USB)" if "/usb" in real else "ethernet"


def t_interfaces():
    if IS_WIN:
        return _win_interfaces()
    rc, out, e = run(["ip", "-j", "addr"])
    rows = []
    try:
        data = json.loads(out)
    except Exception:
        err(e or "could not read interfaces (is `ip` installed?)")
        data = []
    for i in data:
        n = i["ifname"]
        v4 = ", ".join(f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []) if a["family"] == "inet")
        v6 = ", ".join(f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []) if a["family"] == "inet6")
        kind = classify(n)
        link = ""
        if kind == "wifi" and shutil.which("iw"):
            _, o, _ = run(["iw", "dev", n, "link"])
            bits = [m.group(0).strip() for m in re.finditer(r"(SSID: .*|signal: .*|tx bitrate: .*)", o)]
            link = "; ".join(bits)
        drv = Path(f"/sys/class/net/{n}/device/driver")
        spd = read(f"/sys/class/net/{n}/speed")
        rows.append([n, kind, i.get("operstate", "").lower(), i.get("address", ""), v4, v6,
                     i.get("mtu", ""), f"{spd} Mbps" if spd.lstrip("-").isdigit() and int(spd) > 0 else "",
                     drv.resolve().name if drv.exists() else "", link])
    return T("Network interfaces (Ethernet / Wi-Fi / virtual)",
             ["Name", "Kind", "State", "MAC", "IPv4", "IPv6", "MTU", "Speed", "Driver", "Wi-Fi link"], rows)


def t_wifi(rescan=True):
    if IS_WIN:
        return _win_wifi()
    hdr = ["Connected", "SSID", "BSSID", "Channel", "Freq", "Rate", "Signal %", "Bars", "Security"]
    if not shutil.which("nmcli"):
        warn("nmcli not found - install NetworkManager (sudo apt install network-manager).")
        return T("Wi-Fi networks in range", hdr, [])
    rc, out, e = run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
                      "dev", "wifi", "list", "--rescan", "yes" if rescan else "no"], timeout=45)
    if rc != 0:
        warn(e.strip() or "Wi-Fi scan failed (no Wi-Fi adapter, or radio is off: `nmcli radio wifi on`).")
    rows = []
    for line in out.splitlines():
        f = [x.replace("\\:", ":").replace("\\\\", "\\") for x in re.split(r"(?<!\\):", line)]
        if len(f) < 9:
            continue
        rows.append(["yes" if f[0].strip() == "*" else "no", f[1] or "<hidden>", f[2], f[3], f[4], f[5],
                     f[6], f[7], f[8] or "open/none"])
    rows.sort(key=lambda r: -int(r[6]) if r[6].isdigit() else 0)
    return T("Wi-Fi networks in range", hdr, rows)


def t_bluetooth(seconds=8):
    if IS_WIN:
        return _win_bluetooth()
    ch = ["Controller", "Name", "Default"]
    dh = ["MAC", "Name", "Alias", "Class", "Icon", "Paired", "Trusted", "Connected", "RSSI", "UUIDs", "Modalias"]
    if not shutil.which("bluetoothctl"):
        warn("bluetoothctl not found (sudo apt install bluez).")
        return [T("Bluetooth controllers", ch, []), T("Bluetooth devices", dh, [])]
    _, o, _ = run(["bluetoothctl", "list"])
    ctl = [[m[1], m[2].replace(" [default]", ""), "yes" if "[default]" in m[2] else "no"]
           for m in re.finditer(r"Controller (\S+) (.*)", o)]
    if not ctl:
        warn("No Bluetooth controller found (check `rfkill list` and `systemctl status bluetooth`).")
    info(f"Scanning Bluetooth for {seconds}s ...")
    run(["bluetoothctl", "--timeout", str(seconds), "scan", "on"], timeout=seconds + 15)
    _, o, _ = run(["bluetoothctl", "devices"])
    rows = []
    for m in re.finditer(r"Device (\S+) (.*)", o):
        mac = m[1]
        _, d, _ = run(["bluetoothctl", "info", mac])
        g = lambda k: (re.search(rf"^\s*{k}: (.*)$", d, re.M) or [None, ""])[1].strip()
        rows.append([mac, m[2], g("Alias"), g("Class"), g("Icon"), g("Paired"), g("Trusted"), g("Connected"),
                     g("RSSI"), len(re.findall(r"UUID:", d)), g("Modalias")])
    return [T("Bluetooth controllers", ch, ctl), T("Bluetooth devices (nearby / known)", dh, rows)]


USB_CLASS = {"00": "Per-interface", "01": "Audio", "02": "Communications", "03": "HID", "07": "Printer",
             "08": "Mass storage", "09": "Hub", "0b": "Smart card", "0e": "Video", "e0": "Wireless", "ff": "Vendor specific"}


def t_usb():
    if IS_WIN:
        return _win_usb()
    names = {}
    if shutil.which("lsusb"):
        _, o, _ = run(["lsusb"])
        for m in re.finditer(r"ID (\w{4}:\w{4}) (.*)", o):
            names[m[1].lower()] = m[2]
    rows = []
    for d in sorted(Path("/sys/bus/usb/devices").glob("*")):
        if not (d / "idVendor").exists():
            continue
        r = lambda n: read(d / n)
        vp = f"{r('idVendor')}:{r('idProduct')}"
        rows.append([r("busnum"), r("devnum"), d.name, vp, names.get(vp.lower(), ""), r("manufacturer"),
                     r("product"), USB_CLASS.get(r("bDeviceClass").lower(), r("bDeviceClass")),
                     r("speed") + " Mbps", r("version"), r("serial"), r("bMaxPower")])
    return T("USB devices", ["Bus", "Dev", "Port path", "VID:PID", "Description", "Manufacturer", "Product",
                             "Class", "Speed", "USB ver", "Serial", "Max power"], rows)


# --------------------------------------------------------------------------- ping / dns / arp
def t_ping(target, count=4):
    if IS_WIN:
        return _win_ping(target, count)
    rc, out, e = run(["ping", "-c", str(count), "-W", "2", target], timeout=count * 4 + 10)
    if rc == 127:
        err(e)
    sent = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss", out, re.S)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    ip = re.search(r"PING \S+ \(([^)]+)\)", out)
    ttls = re.findall(r"ttl=(\d+)", out, re.I)
    guess = ""
    if ttls:
        t = int(ttls[0])
        guess = "Linux/Unix/macOS" if t <= 64 else "Windows" if t <= 128 else "Network device/Solaris"
    summ = T(f"Ping summary: {target}",
             ["Target", "IP", "Sent", "Received", "Loss %", "Min ms", "Avg ms", "Max ms", "Jitter ms", "TTL", "OS hint (TTL)"],
             [[target, ip[1] if ip else "", sent[1] if sent else "", sent[2] if sent else "", sent[3] if sent else "",
               *(rtt.groups() if rtt else ["", "", "", ""]), ttls[0] if ttls else "", guess]])
    reps = T(f"Ping replies: {target}", ["Seq", "TTL", "Time ms"],
             [[a, b, c] for a, b, c in re.findall(r"icmp_seq=(\d+) ttl=(\d+) time=([\d.]+)", out)])
    return [summ, reps]


def t_nslookup(name, types, server=None):
    rows = []
    is_ip = False
    try:
        ipaddress.ip_address(name)
        is_ip = True
    except ValueError:
        pass
    for rt in (["PTR"] if is_ip else types):
        if shutil.which("nslookup"):
            cmd = ["nslookup"] + ([] if is_ip else [f"-type={rt}"]) + [name] + ([server] if server else [])
            _, out, e = run(cmd, timeout=20)
            blocks = out.strip().split("\n\n")
            res = (re.search(r"Server:\s*(\S+)", blocks[0]) or [None, ""])[1] if blocks else ""
            body = "\n".join(blocks[1:]) if len(blocks) > 1 else (e.strip() if not out.strip() else "")
            lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("Non-authoritative")]
            for l in lines or ["(no answer)"]:
                rows.append([rt, name, res, l])
        else:  # fallback without nslookup
            try:
                if is_ip:
                    rows.append(["PTR", name, "system", socket.gethostbyaddr(name)[0]])
                elif rt in ("A", "AAAA"):
                    fam = socket.AF_INET if rt == "A" else socket.AF_INET6
                    for x in {i[4][0] for i in socket.getaddrinfo(name, None, fam)}:
                        rows.append([rt, name, "system", x])
            except Exception as ex:
                rows.append([rt, name, "system", f"(failed: {ex})"])
    return T(f"DNS lookup: {name}", ["Type", "Query", "Resolver", "Answer"], rows)


def t_neighbors():
    if IS_WIN:
        return _win_neighbors()
    _, out, _ = run(["ip", "-j", "neigh"])
    try:
        d = json.loads(out)
    except Exception:
        d = []
    return T("ARP / neighbour cache", ["IP", "MAC", "Interface", "State"],
             [[n.get("dst", ""), n.get("lladdr", ""), n.get("dev", ""), ",".join(n.get("state", [])).lower()] for n in d])


def local_subnet():
    if IS_WIN:
        name, _ = _win_default_route()
        return iface_subnet(name) if name else None
    try:
        _, o, _ = run(["ip", "-j", "route", "get", "1.1.1.1"])
        dev = json.loads(o)[0]["dev"]
        _, o, _ = run(["ip", "-j", "-4", "addr", "show", "dev", dev])
        a = json.loads(o)[0]["addr_info"][0]
        return str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
    except Exception:
        _, o, _ = run(["ip", "-j", "-4", "addr"])
        for i in json.loads(o or "[]"):
            for a in i.get("addr_info", []):
                if i["ifname"] != "lo":
                    return str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
    return None


# --------------------------------------------------------------------------- nmap
PROFILES = {
    "quick": ["-T4", "-F"], "full": ["-p-", "-sV", "-T4"], "stealth": ["-sS", "-T2"],
    "udp": ["-sU", "--top-ports", "100"], "os": ["-O", "--osscan-guess", "-sV"],
    "aggressive": ["-A", "-T4"], "discovery": ["-sn", "-PR"], "safe-scripts": ["-sV", "--script", "default,safe"],
}
TYPE_FLAG = {"syn": "-sS", "connect": "-sT", "udp": "-sU", "ack": "-sA", "window": "-sW", "fin": "-sF",
             "null": "-sN", "xmas": "-sX", "maimon": "-sM", "none": "-sn"}
RAW_FLAGS = {"-sS", "-sU", "-sA", "-sW", "-sF", "-sN", "-sX", "-sM", "-O", "-A", "-PR"}


def build_args(a, preset=None):
    x = list(PROFILES.get(a.profile or "", []))
    add = lambda *f: x.extend(f) if f[0] not in x else None
    if preset == "os":
        add("-O")
    if a.type:
        add(TYPE_FLAG[a.type])
    if a.ports:
        add("-p", "-" if a.ports == "all" else a.ports)
    elif a.top:
        add("--top-ports", str(a.top))
    elif a.fast:
        add("-F")
    if a.sv:
        add("-sV")
        if a.intensity is not None:
            add("--version-intensity", str(a.intensity))
    if a.osdetect:
        add("-O")
    if a.guess:
        add("--osscan-guess")
    if a.limit:
        add("--osscan-limit")
    if a.aggressive:
        add("-A")
    if a.script:
        add("--script", a.script)
    if a.traceroute:
        add("--traceroute")
    if a.timing is not None:
        add(f"-T{a.timing}")
    if a.no_ping:
        add("-Pn")
    if a.no_dns:
        add("-n")
    if a.reason:
        add("--reason")
    if a.args:
        x += shlex.split(a.args)
    return x


def parse_nmap(xml_text, label):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    fin = root.find("runstats/finished")
    meta = [["Nmap version", root.get("version", "")], ["Command", re.sub(r"-oX \S+ ?", "", root.get("args", "")).replace("-v --stats-every 2s ", "")],
            ["Started", datetime.fromtimestamp(int(root.get("start"))).strftime("%Y-%m-%d %H:%M:%S") if root.get("start") else ""],
            ["Summary", fin.get("summary", "") if fin is not None else ""]]
    hosts, ports, osr, scr, trace = [], [], [], [], []
    for h in root.findall("host"):
        st = h.find("status")
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr"), a.get("vendor", "")
        names = ", ".join(n.get("name") for n in h.findall("hostnames/hostname"))
        tm = h.find("times")
        lat = f"{int(tm.get('srtt')) / 1000:.1f} ms" if tm is not None and tm.get("srtt") else ""
        up = h.find("uptime")
        dist = h.find("distance")
        opens = 0
        for p in h.findall("ports/port"):
            s, sv = p.find("state"), p.find("service")
            sv = sv if sv is not None else ET.Element("service")
            if s is not None and s.get("state") == "open":
                opens += 1
            ports.append([ip, p.get("portid"), p.get("protocol"), s.get("state") if s is not None else "",
                          s.get("reason", "") if s is not None else "", sv.get("name", ""), sv.get("product", ""),
                          sv.get("version", ""), sv.get("extrainfo", ""), sv.get("ostype", ""),
                          ", ".join(c.text for c in p.findall("service/cpe") if c.text)])
            for sc in p.findall("script"):
                scr.append([ip, f"{p.get('portid')}/{p.get('protocol')}", sc.get("id"), sc.get("output", "")])
        for sc in h.findall("hostscript/script"):
            scr.append([ip, "host", sc.get("id"), sc.get("output", "")])
        best = ""
        for m in h.findall("os/osmatch"):
            c = m.find("osclass")
            cp = ", ".join(x.text for x in m.findall("osclass/cpe") if x.text)
            osr.append([ip, m.get("name"), m.get("accuracy") + "%",
                        c.get("type", "") if c is not None else "", c.get("vendor", "") if c is not None else "",
                        c.get("osfamily", "") if c is not None else "", c.get("osgen", "") if c is not None else "", cp])
            if not best:
                best = f"{m.get('name')} ({m.get('accuracy')}%)"
        for hop in h.findall("trace/hop"):
            trace.append([ip, hop.get("ttl"), hop.get("ipaddr"), hop.get("rtt"), hop.get("host", "")])
        ex = h.find("ports/extraports")
        hosts.append([ip, names, st.get("state") if st is not None else "", st.get("reason", "") if st is not None else "",
                      mac, vendor, lat, opens, f"{ex.get('count')} {ex.get('state')}" if ex is not None else "", best,
                      up.get("lastboot", "") if up is not None else "", dist.get("value", "") if dist is not None else ""])
    out = [T(f"{label} - hosts", ["IP", "Hostname", "State", "Reason", "MAC", "Vendor", "Latency", "Open ports",
                                  "Not shown", "Best OS guess", "Last boot", "Hops"], hosts)]
    if ports:
        out.append(T(f"{label} - ports & services", ["Host", "Port", "Proto", "State", "Reason", "Service", "Product",
                                                      "Version", "Extra info", "OS type", "CPE"], ports))
    if osr:
        out.append(T(f"{label} - OS detection", ["Host", "OS match", "Accuracy", "Type", "Vendor", "Family", "Gen", "CPE"], osr))
    if scr:
        out.append(T(f"{label} - script output", ["Host", "Port", "Script", "Output"], scr))
    if trace:
        out.append(T(f"{label} - traceroute", ["Host", "TTL", "Hop IP", "RTT ms", "Hop name"], trace))
    out.append(T(f"{label} - scan info", ["Item", "Value"], meta))
    return out


def private_target(t):
    try:
        n = ipaddress.ip_network(t, strict=False)
        return n.is_private or n.is_loopback or n.is_link_local
    except ValueError:
        pass
    if re.fullmatch(r"[\d.,*\-/]+", t):
        o = [int(x) for x in re.findall(r"\d+", t)[:2]] + [0, 0]
        return o[0] in (10, 127) or (o[0] == 192 and o[1] == 168) or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 169 and o[1] == 254)
    try:
        return ipaddress.ip_address(socket.gethostbyname(t)).is_private
    except Exception:
        return False


def confirm_scope(targets):
    outside = [t for t in targets if not private_target(t)]
    if not outside or STATE["yes"]:
        return True
    warn("Targets outside private/local ranges: " + ", ".join(outside))
    if UI.gui or not (sys.stdin and sys.stdin.isatty()):
        err("Add --yes to confirm you are authorised to scan them.")
        return False
    return input("Type YES to confirm you have permission to scan these: ").strip() == "YES"


def elevator():
    """Command prefix used to run privileged tools (polkit dialog in the GUI, sudo in a terminal)."""
    if is_admin() or IS_WIN:
        return []
    return ["pkexec"] if UI.gui and shutil.which("pkexec") else ["sudo"]


def stream(cmd, ctl, on_line):
    """Run a command, feeding each output line to on_line. Honours ctl.cancel()."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                             creationflags=NOWIN, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        on_line(f"{cmd[0]}: command not found")
        return 127
    ctl.proc = p
    lines: queue.Queue = queue.Queue()

    def reader():
        for ln in p.stdout:
            lines.put(ln.rstrip("\n"))
        lines.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def abort():
        try: p.terminate()
        except Exception: pass
        time.sleep(1.2)
        if p.poll() is None:
            warn("Stop requested, but an administrator-level process can't be signalled by a normal user. "
                 "It will finish in the background; its results are discarded.")
        raise Cancelled()

    while True:
        try:
            item = lines.get(timeout=0.3)
        except queue.Empty:
            if ctl.cancelled:
                abort()
            continue
        if item is None:
            break
        on_line(item)
        if ctl.cancelled:
            abort()
    p.wait()
    ctl.proc = None
    return p.returncode


def adapt_args(args, can_root):
    """Without admin rights, swap raw-socket options for unprivileged equivalents (and say so)."""
    if can_root:
        return args
    out, notes = [], []
    for a in args:
        if a in ("-PR", "-O", "--osscan-guess", "--osscan-limit"):
            notes.append(a)
        elif a == "-sS":
            out.append("-sT"); notes.append("-sS->-sT")
        elif a in ("-sU", "-sA", "-sW", "-sF", "-sN", "-sX", "-sM"):
            err(f"{a} needs administrator rights - tick 'Use administrator rights' (GUI) or use --sudo (CLI).")
            return None
        elif a == "-A":
            out += ["-sV", "-sC", "--traceroute"]; notes.append("-A reduced to -sV -sC --traceroute")
        else:
            out.append(a)
    if notes:
        warn("No admin rights - adjusted nmap options: " + ", ".join(notes))
    return out


NMAP_LOG = re.compile(r"^(Nmap scan report|Discovered open port|Initiating|Completed|Stats:|Nmap done|NSE: Script scanning|WARNING|Warning|QUITTING)")


def nmap_collect(label, targets, args, ctl=None):
    """Run nmap with live progress. Returns result tables (does not display them)."""
    ctl = ctl or Ctl()
    nm = find_exe("nmap")
    if not nm:
        err("nmap is not installed - " + ("run: winget install -e --id Insecure.Nmap  (or https://nmap.org/download)" if IS_WIN else "run `iuk_netscope.py doctor` or: sudo apt install nmap"))
        return []
    tg = []
    for t in targets:
        if t == "auto":
            sn = local_subnet()
            if not sn:
                err("Could not detect the local subnet - give a target explicitly.")
                return []
            info(f"auto target = {sn}")
            t = sn
        tg.append(t)
    for t in tg:
        try:
            n = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if n.num_addresses > MAX_TARGET:
            err(f"{t} covers {n.num_addresses:,} addresses (limit {MAX_TARGET:,}). Use a smaller range, e.g. a /16 or /24.")
            return []
    if not confirm_scope(tg):
        return []
    can_root = is_admin() or (STATE["sudo"] and not IS_WIN)
    if IS_WIN and not is_admin() and (RAW_FLAGS & set(args)):
        warn("Not running as Administrator - restart IUK-NetScope with right-click > Run as administrator for OS detection / SYN scans.")
    args = adapt_args(args, can_root)
    if args is None:
        return []
    pre = elevator() if (RAW_FLAGS & set(args)) and not is_admin() else []
    tmp = tempfile.mkdtemp(prefix="iuknet-")
    xml_path = os.path.join(tmp, "scan.xml")
    cmd = pre + [nm, "-v", "--stats-every", "2s", "-oX", xml_path] + args + tg
    shown = " ".join(shlex.quote(c) for c in cmd[len(pre):]).replace(xml_path, "<xml>")
    info("$ " + shown)
    LOG.append("$ " + shown)
    if pre:
        info(f"Administrator rights requested via {pre[0]} - approve the prompt if one appears.")

    def on_line(ln):
        m = re.search(r"About ([\d.]+)% done", ln)
        if m:
            ctl.on_progress(float(m.group(1)))
        if NMAP_LOG.match(ln):
            (ok if ln.startswith("Discovered open port") else info)("  " + ln)

    try:
        rc = stream(cmd, ctl, on_line)
        xml = Path(xml_path).read_text() if os.path.exists(xml_path) else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    tabs = parse_nmap(xml, label) if xml.strip() else []
    if not tabs:
        err(f"nmap produced no result (exit code {rc}).")
    return tabs


def nmap_scan(label, targets, args, ctl=None):
    emit(nmap_collect(label, targets, args, ctl))


def arp_scan(target, ctl=None):
    nmap_scan("ARP scan", [target], ["-sn", "-PR"], ctl)


# --------------------------------------------------------------------------- dependencies
DEPS = [  # (command, apt package, required, purpose)
    ("nmap", "nmap", True, "scan engine: ports, services, OS detection, host discovery"),
    ("ip", "iproute2", True, "interface, route and neighbour (ARP) information"),
    ("ping", "iputils-ping", True, "ICMP ping"),
    ("nslookup", "dnsutils", False, "DNS lookups"),
    ("nmcli", "network-manager", False, "Wi-Fi scanning"),
    ("iw", "iw", False, "Wi-Fi link details"),
    ("bluetoothctl", "bluez", False, "Bluetooth scanning"),
    ("lsusb", "usbutils", False, "USB vendor names"),
    ("pkexec", "pkexec", False, "graphical administrator prompt"),
    ("notify-send", "libnotify-bin", False, "desktop notifications when a scan ends"),
]
PY_DEPS = [("tkinter", "python3-tk", True, "desktop app window"), ("reportlab", "python3-reportlab", True, "PDF reports")]


WIN_DEPS = [
    ("nmap", "Insecure.Nmap", True, "scan engine (installer also adds Npcap for raw scans)"),
    ("ping", "built into Windows", False, "ICMP ping"),
    ("nslookup", "built into Windows", False, "DNS lookups"),
    ("netsh", "built into Windows", False, "Wi-Fi scanning"),
    ("powershell", "built into Windows", False, "interfaces, USB, Bluetooth"),
]


def check_deps():
    import importlib.util
    frozen = getattr(sys, "frozen", False)
    rows = [dict(name=c, pkg=p, required=r, found=bool(find_exe(c)), why=w) for c, p, r, w in (WIN_DEPS if IS_WIN else DEPS)]
    rows += [dict(name=m, pkg=p, required=r, found=frozen or importlib.util.find_spec(m) is not None, why=w)
             for m, p, r, w in ([] if IS_WIN and frozen else PY_DEPS)]
    return rows


def dep_table():
    return T("Dependencies", ["Component", "apt package", "Needed", "Installed", "Used for"],
             [[d["name"], d["pkg"], "required" if d["required"] else "optional", "yes" if d["found"] else "no", d["why"]]
              for d in check_deps()])


def install_missing(pkgs, ctl=None):
    ctl = ctl or Ctl()
    if not pkgs:
        ok("Nothing to install.")
        return True
    if IS_WIN:
        if not shutil.which("winget"):
            err("winget not found. Install Nmap manually from https://nmap.org/download (tick Npcap).")
            return False
        good = True
        for p in pkgs:
            cmd = ["winget", "install", "-e", "--id", p, "--accept-package-agreements", "--accept-source-agreements"]
            info("$ " + " ".join(cmd))
            good = stream(cmd, ctl, lambda l: info("  " + l)) == 0 and good
        if good:
            ok("Installed: " + ", ".join(pkgs))
        else:
            err("winget failed - install Nmap from https://nmap.org/download")
        return good
    cmd = elevator() + ["apt-get", "install", "-y"] + pkgs
    info("$ " + " ".join(cmd))
    rc = stream(cmd, ctl, lambda l: info("  " + l))
    if rc == 0:
        ok("Installed: " + ", ".join(pkgs))
        return True
    err("Install failed. Run manually:  sudo apt update && sudo apt install -y " + " ".join(pkgs))
    return False


# --------------------------------------------------------------------------- built-in quick scans
KIND_LABEL = {"interface": "Network interface", "lan": "LAN device (IP)", "bluetooth": "Bluetooth device", "wifi": "Wi-Fi network (SSID)"}


def iface_rows():
    return t_interfaces()["rows"]


def iface_subnet(name):
    if IS_WIN:
        for r in iface_rows():
            if r[0] == name and r[4]:
                return str(ipaddress.ip_network(r[4].split(",")[0].strip(), strict=False))
        return None
    try:
        _, o, _ = run(["ip", "-j", "-4", "addr", "show", "dev", name])
        a = json.loads(o)[0]["addr_info"][0]
        return str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
    except Exception:
        return None


def iface_gateway(name):
    if IS_WIN:
        n, gw = _win_default_route()
        return gw if n == name and gw and gw != "0.0.0.0" else None
    try:
        _, o, _ = run(["ip", "-j", "route", "show", "default", "dev", name])
        return json.loads(o)[0]["gateway"]
    except Exception:
        return None


def wifi_iface(ssid=None):
    cands = [r for r in iface_rows() if r[1] == "wifi" and r[4]]
    for r in cands:
        if ssid and f"SSID: {ssid}" in r[9]:
            return r[0]
    return cands[0][0] if cands else None


def up_hosts(tabs):
    for t in tabs:
        if t["title"].endswith("- hosts"):
            return [r[0] for r in t["rows"] if r[2] == "up" and r[0]]
    return []


def iface_ip(name):
    for r in iface_rows():
        if r[0] == name and r[4]:
            return r[4].split(",")[0].split("/")[0].strip()
    return None


MAX_SWEEP = 4096          # addresses swept automatically from an interface
MAX_TARGET = 65536        # hard limit for any CIDR target


def sweep(name, ctl, label=None):
    sn = iface_subnet(name)
    if not sn:
        err(f"{name} has no IPv4 network to scan (is it connected?).")
        return []
    net = ipaddress.ip_network(sn)
    if net.is_loopback:
        err(f"{name} is the loopback interface - there are no other devices to find. Pick a real network adapter.")
        return []
    if net.num_addresses > MAX_SWEEP:
        ip = iface_ip(name)
        small = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        warn(f"{sn} is very large ({net.num_addresses:,} addresses) - sweeping only {small}. Use Advanced nmap for a wider range.")
        sn = small
    info(f"Sweeping {sn} on {name} ...")
    tabs = nmap_collect(label or f"{name} devices", [sn], ["-sn", "-PR"] + ([] if IS_WIN else ["-e", name]), ctl)
    emit(tabs)
    return up_hosts(tabs)


def _hosts_scan(name, ctl, args, label, cap):
    hosts = sweep(name, ctl)
    if not hosts:
        return
    if len(hosts) > cap:
        warn(f"{len(hosts)} hosts found - scanning the first {cap}.")
    info(f"Scanning {min(len(hosts), cap)} live host(s) ...")
    emit(nmap_collect(label, hosts[:cap], args, ctl))


def _iface_info(name, ctl):
    t = t_interfaces()
    emit(T(f"Interface {name}", t["headers"], [r for r in t["rows"] if r[0] == name]))
    _, o, _ = run(["ip", "-j", "route", "show", "dev", name])
    try:
        emit(T(f"Routes on {name}", ["Destination", "Gateway", "Protocol", "Source", "Metric"],
               [[r.get("dst", ""), r.get("gateway", ""), r.get("protocol", ""), r.get("prefsrc", ""), r.get("metric", "")] for r in json.loads(o)]))
    except Exception:
        pass
    n = t_neighbors()
    emit(T(f"Neighbours on {name}", n["headers"], [r for r in n["rows"] if r[2] == name]))


def _gateway(name, ctl):
    gw = iface_gateway(name)
    if not gw:
        err(f"No default gateway on {name}.")
        return
    info(f"Gateway on {name}: {gw}")
    emit(t_ping(gw, 4))
    emit(nmap_collect(f"gateway {gw}", [gw], ["-sV", "-T4", "--top-ports", "200", "--reason"], ctl))


def _lan_full(ip, ctl):
    emit(t_ping(ip, 4)); ctl.check()
    emit(t_nslookup(ip, ["A", "AAAA", "PTR"])); ctl.check()
    emit(nmap_collect(f"{ip} full", [ip], ["-A", "-T4", "--reason"], ctl))


def _lan(args, label_fmt):
    return lambda v, ctl: emit(nmap_collect(label_fmt.format(v), [v], args, ctl))


def bt_info(mac):
    _, out, _ = run(["bluetoothctl", "info", mac])
    rows = [[m[1].strip(), m[2].strip()] for m in re.finditer(r"^\s+([A-Za-z ]+): (.*)$", out, re.M)]
    return rows, out


def _bt_info(mac, ctl):
    if not shutil.which("bluetoothctl"):
        err("bluetoothctl missing - sudo apt install bluez"); return
    rows, out = bt_info(mac)
    if not rows:
        info("Device not in cache - scanning for 8 s ...")
        run(["bluetoothctl", "--timeout", "8", "scan", "on"], timeout=25)
        rows, out = bt_info(mac)
    if not rows:
        err(f"No information for {mac}. Is the device on and in range?"); return
    emit(T(f"Bluetooth device {mac}", ["Property", "Value"], rows))


def _bt_rssi(mac, ctl):
    rows = []
    for i in range(1, 6):
        ctl.check()
        run(["bluetoothctl", "--timeout", "4", "scan", "on"], timeout=15)
        r, _ = bt_info(mac)
        d = dict(r)
        rssi = (re.search(r"-?\d+", d.get("RSSI", "")) or [""])[0]
        prox = ""
        if rssi:
            v = int(rssi)
            prox = "very close" if v > -50 else "near" if v > -70 else "far" if v > -85 else "very far"
        rows.append([i, datetime.now().strftime("%H:%M:%S"), rssi, d.get("TxPower", ""), prox])
        info(f"  sample {i}/5: RSSI {rssi or 'n/a'} dBm {prox}")
        ctl.on_progress(i * 20)
    emit(T(f"Bluetooth signal strength {mac}", ["Sample", "Time", "RSSI dBm", "TxPower", "Proximity (approx.)"], rows))


def _bt_services(mac, ctl):
    rows, _ = bt_info(mac)
    emit(T(f"Bluetooth services {mac}", ["Service (UUID)"], [[v] for k, v in rows if k == "UUID"]))


def _bt_l2ping(mac, ctl):
    if not shutil.which("l2ping"):
        err("l2ping missing - sudo apt install bluez"); return
    cmd = (elevator() if not is_admin() else []) + ["l2ping", "-c", "4", mac]
    out = []
    stream(cmd, ctl, lambda l: (out.append(l), info("  " + l)))
    emit(T(f"Bluetooth l2ping {mac}", ["Output"], [[l] for l in out]))


def wifi_aps(ssid):
    t = t_wifi()
    return t, [r for r in t["rows"] if r[1] == ssid]


def band(freq):
    m = re.search(r"\d+", freq or "")
    f = int(m[0]) if m else 0
    return "2.4 GHz" if f < 3000 else "5 GHz" if f < 5900 else "6 GHz"


def _wifi_details(ssid, ctl):
    t, aps = wifi_aps(ssid)
    emit(T(f"Wi-Fi '{ssid}' access points", ["Connected", "BSSID", "Channel", "Band", "Freq", "Rate", "Signal %", "Security"],
           [[r[0], r[2], r[3], band(r[4]), r[4], r[5], r[6], r[8]] for r in aps]))


def _wifi_channels(ssid, ctl):
    t, aps = wifi_aps(ssid)
    mine = {r[3] for r in aps}
    g = {}
    for r in t["rows"]:
        g.setdefault((r[3], band(r[4])), []).append(int(r[6]) if r[6].isdigit() else 0)
    rows = [[ch, bd, len(v), max(v), round(sum(v) / len(v)), "yes" if ch in mine else ""]
            for (ch, bd), v in sorted(g.items(), key=lambda x: (x[0][1], int(x[0][0]) if x[0][0].isdigit() else 0))]
    emit(T("Wi-Fi channel usage nearby", ["Channel", "Band", "Networks", "Strongest %", "Average %", f"Used by '{ssid}'"], rows,
           "More networks on a channel = more interference. Pick a quieter channel on your own router."))


def _wifi_lan(ssid, ctl):
    _, aps = wifi_aps(ssid)
    if not any(r[0] == "yes" for r in aps):
        warn(f"You are not connected to '{ssid}'. Connect to it first - this tool never joins networks for you.")
        return
    ifc = wifi_iface(ssid)
    sweep(ifc, ctl, f"'{ssid}' devices") if ifc else err("No Wi-Fi interface with an IPv4 address.")


def _wifi_gateway(ssid, ctl):
    _, aps = wifi_aps(ssid)
    if not any(r[0] == "yes" for r in aps):
        warn(f"You are not connected to '{ssid}'. Connect first."); return
    ifc = wifi_iface(ssid)
    _gateway(ifc, ctl) if ifc else err("No Wi-Fi interface found.")


BUILTIN = {
    "interface": [
        dict(id="info", label="Interface details, routes and neighbours", desc="Quick, read-only look at this interface: addresses, link speed, routes and known neighbours.", root=False, fn=_iface_info),
        dict(id="discover", label="Find all devices on this network", desc="ARP/ping sweep of the interface's subnet: IP, MAC, vendor, hostname and latency of every live device.", root=True, fn=lambda v, c: sweep(v, c)),
        dict(id="quick", label="Devices + quick port scan (top 100)", desc="Finds every live device, then checks the 100 most common ports on each.", root=True, fn=lambda v, c: _hosts_scan(v, c, ["-T4", "--top-ports", "100", "--reason"], f"{v} quick ports", 256)),
        dict(id="audit", label="Network audit (services + OS)", desc="Finds devices, then service versions, OS guess and top-1000 ports. Slow on big networks.", root=True, fn=lambda v, c: _hosts_scan(v, c, ["-sV", "-O", "--osscan-guess", "-T4", "--top-ports", "1000"], f"{v} audit", 64)),
        dict(id="gateway", label="Check my router / gateway", desc="Pings the default gateway and scans it for open ports and services.", root=False, fn=_gateway),
    ],
    "lan": [
        dict(id="ping", label="Ping and latency", desc="Is it alive? Packet loss, latency, jitter and an OS hint from the TTL.", root=False, fn=lambda v, c: emit(t_ping(v, 5))),
        dict(id="dns", label="DNS / reverse lookup", desc="Resolves the name or finds the hostname behind an IP.", root=False, fn=lambda v, c: emit(t_nslookup(v, ["A", "AAAA", "MX", "NS", "TXT"]))),
        dict(id="quick", label="Quick port scan (top 100)", desc="Fast check of the 100 most common ports.", root=False, fn=_lan(["-T4", "--top-ports", "100", "--reason"], "{} quick ports")),
        dict(id="services", label="Services and versions (top 1000)", desc="Open ports plus the software and version behind each one.", root=False, fn=_lan(["-sV", "-T4"], "{} services")),
        dict(id="os", label="Operating-system fingerprint", desc="Guesses the OS, device type and uptime. Best with admin rights.", root=True, fn=_lan(["-O", "--osscan-guess", "-sV", "-T4"], "{} OS")),
        dict(id="alltcp", label="All 65,535 TCP ports", desc="Thorough but slow: every TCP port.", root=False, fn=_lan(["-p-", "-T4"], "{} all TCP")),
        dict(id="udp", label="Common UDP ports (top 50)", desc="UDP services such as DNS, SNMP and DHCP. Needs admin rights; slow.", root=True, fn=_lan(["-sU", "--top-ports", "50", "-T4"], "{} UDP")),
        dict(id="full", label="Everything (ping + DNS + aggressive)", desc="Ping, DNS, then nmap -A: services, OS, scripts and traceroute.", root=True, fn=_lan_full),
    ],
    "bluetooth": [
        dict(id="info", label="Device details", desc="Name, class, paired/trusted state, signal and supported services.", root=False, fn=_bt_info),
        dict(id="rssi", label="Signal strength check (5 samples)", desc="Measures RSSI five times to judge distance and stability.", root=False, fn=_bt_rssi),
        dict(id="services", label="Supported services", desc="Lists the profiles the device advertises (audio, HID, serial, battery...).", root=False, fn=_bt_services),
        dict(id="l2ping", label="L2CAP ping (reachability)", desc="Bluetooth-level ping. Needs admin rights and a device that answers.", root=True, fn=_bt_l2ping),
    ],
    "wifi": [
        dict(id="details", label="Access-point details", desc="Every access point broadcasting this SSID: BSSID, channel, band, signal, security.", root=False, fn=_wifi_details),
        dict(id="channels", label="Channel congestion", desc="How crowded each channel is around you, and which ones this network uses.", root=False, fn=_wifi_channels),
        dict(id="lan", label="Find devices on this Wi-Fi", desc="If you are connected to it: sweep its subnet for every device.", root=True, fn=_wifi_lan),
        dict(id="gateway", label="Check this Wi-Fi's router", desc="If you are connected to it: ping and scan the router.", root=False, fn=_wifi_gateway),
    ],
}


def discover_choices(kind, ctl=None):
    """Return [(display text, value)] for the 'pick one' list of a quick scan."""
    out = []
    if kind == "interface":
        rows = sorted(iface_rows(), key=lambda r: (r[1] == "loopback", not r[4], r[2] != "up"))
        out = [(f"{r[0]}  ·  {r[1]}  ·  {r[4] or 'no IPv4'}  ·  {r[2]}", r[0]) for r in rows]
    elif kind == "lan":
        seen = {}
        for r in t_neighbors()["rows"]:
            if r[0] and ":" not in r[0] and "failed" not in r[3]:
                seen[r[0]] = f"{r[0]}  ·  {r[1] or '?'}  ·  {r[2]}"
        for t in SESSION:
            if t["title"].endswith("- hosts") or t["title"].endswith("devices - hosts"):
                for r in t["rows"]:
                    if r[2] == "up" and r[0]:
                        seen.setdefault(r[0], f"{r[0]}  ·  {r[1] or r[4] or ''}")
        for r in iface_rows():
            g = iface_gateway(r[0])
            if g:
                seen[g] = f"{g}  ·  router (via {r[0]})"
        out = [(d, ip) for ip, d in sorted(((i, d) for i, d in seen.items() if ":" not in i), key=lambda x: ipaddress.ip_address(x[0]))]
    elif kind == "bluetooth":
        tabs = t_bluetooth(6)
        out = [(f"{r[1] or r[2]}  ·  {r[0]}  ·  RSSI {r[8] or 'n/a'}", r[0]) for r in tabs[1]["rows"]]
    elif kind == "wifi":
        best = {}
        for r in t_wifi()["rows"]:
            if r[1] != "<hidden>" and (r[1] not in best or int(r[6] or 0) > int(best[r[1]][6] or 0)):
                best[r[1]] = r
        out = [(f"{s}  ·  ch {r[3]}  ·  {r[6]}%  ·  {r[8]}", s) for s, r in sorted(best.items(), key=lambda x: -int(x[1][6] or 0))]
    return out


def run_builtin(kind, sid, value, ctl=None):
    ctl = ctl or Ctl()
    sc = next(x for x in BUILTIN[kind] if x["id"] == sid)
    if kind == "bluetooth" and IS_WIN:
        err("Bluetooth detail scans need BlueZ (Linux). On Windows use Tools > Bluetooth devices to list paired devices.")
        return
    LOG.append(f"quick {kind} {value!r} -> {sc['label']}")
    try:
        sc["fn"](value, ctl)
    except Cancelled:
        warn("Stopped.")


def full_sweep(ctl=None, bt_seconds=6, arp=True):
    ctl = ctl or Ctl()
    steps = [("Interfaces", t_interfaces), ("Wi-Fi networks", t_wifi), ("Bluetooth", lambda: t_bluetooth(bt_seconds)),
             ("USB devices", t_usb), ("ARP / neighbour cache", t_neighbors)]
    for i, (name, fn) in enumerate(steps):
        ctl.check()
        info(f"{name} ...")
        emit(fn())
        ctl.on_progress((i + 1) * 100 / (len(steps) + (1 if arp else 0)))
    if arp:
        ctl.check()
        info("ARP sweep of the local subnet ...")
        arp_scan("auto", ctl)
    ok("Full sweep finished.")



# --------------------------------------------------------------------------- reports
def make_pdf(path, tables, theme):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        err("reportlab missing: sudo apt install python3-reportlab   (or `pip install reportlab` inside a venv)")
        return False
    th, col = THEMES[theme], colors.HexColor
    page, margin = landscape(A4), 28
    avail = page[0] - 2 * margin
    mk = lambda n, **k: ParagraphStyle(n, **{"fontName": "Helvetica", "textColor": col(th["fg"]), **k})
    h1, h2 = mk("h1", fontName="Helvetica-Bold", fontSize=22, textColor=col(th["accent"]), spaceAfter=8, leading=26), \
        mk("h2", fontName="Helvetica-Bold", fontSize=12, textColor=col(th["accent"]), spaceBefore=12, spaceAfter=4)
    body, cell = mk("b", fontSize=9, leading=12), mk("c", fontSize=7, leading=8.6)
    head = mk("hd", fontSize=7, leading=8.6, fontName="Helvetica-Bold", textColor=col(th["accent"]))
    P = lambda s, st: Paragraph(escape(str(s)).replace("\n", "<br/>"), st)
    story = [P(f"{TOOL} - Scan Report", h1),
             P(f"Author: {AUTHOR}   |   Version {__version__}   |   Theme: {theme}", body),
             P(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}   |   Host: {socket.gethostname()}", body),
             P("Commands run", h2)] + [P(c, body) for c in LOG or ["(none)"]] + [P("Contents", h2)]
    story += [P(f"{t['title']} - {len(t['rows'])} row(s)", body) for t in tables]
    for t in tables:
        story.append(P(t["title"], h2))
        if not t["rows"]:
            story.append(P("(nothing found)", body))
            continue
        wt = [min(max(len(str(h)), *(len(str(r[i])) for r in t["rows"])), 40) + 4 for i, h in enumerate(t["headers"])]
        cw = [avail * x / sum(wt) for x in wt]
        clip = lambda v: (str(v)[:1200] + " ...(truncated, see CSV)") if len(str(v)) > 1200 else v
        data = [[P(h, head) for h in t["headers"]]] + [[P(clip(v), cell) for v in r] for r in t["rows"]]
        tb = Table(data, colWidths=cw, repeatRows=1)
        tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), col(th["head"])),
                                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [col(th["bg"]), col(th["alt"])]),
                                ("GRID", (0, 0), (-1, -1), 0.25, col(th["dim"])), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
        story += [tb, Spacer(1, 6)]

    def deco(c, d):
        c.saveState()
        c.setFillColor(col(th["bg"]))
        c.rect(0, 0, page[0], page[1], stroke=0, fill=1)
        c.setFillColor(col(th["dim"]))
        c.setFont("Helvetica", 7)
        c.drawString(margin, 14, f"{TOOL}  |  {AUTHOR}")
        c.drawRightString(page[0] - margin, 14, f"Page {d.page}")
        c.restoreState()

    SimpleDocTemplate(str(path), pagesize=page, leftMargin=margin, rightMargin=margin, topMargin=margin,
                      bottomMargin=30, title=f"{TOOL} Report", author=AUTHOR).build(story, onFirstPage=deco, onLaterPages=deco)
    return True


def write_csv(base, tables):
    for i, t in enumerate(tables, 1):
        slug = re.sub(r"[^A-Za-z0-9]+", "_", t["title"]).strip("_")[:50]
        with open(base / f"{i:02d}_{slug}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(t["headers"])
            w.writerows(t["rows"])
    with open(base / "all_results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["section", "row", "field", "value"])
        for t in tables:
            for n, r in enumerate(t["rows"], 1):
                for h, v in zip(t["headers"], r):
                    w.writerow([t["title"], n, h, v])


def write_reports(formats, name=None, theme=None, base_dir=None):
    if not SESSION:
        warn("Nothing to report yet - run a scan first.")
        return None
    fm = {x.strip().lower() for x in formats.split(",")}
    base = Path(base_dir or REPORT_DIR) / f"{name or 'scan'}-{datetime.now():%Y%m%d-%H%M%S}"
    base.mkdir(parents=True, exist_ok=True)
    if "csv" in fm:
        write_csv(base, SESSION)
        ok(f"CSV  -> {base}/all_results.csv (+ one CSV per section)")
    if "json" in fm:
        (base / "results.json").write_text(json.dumps({"tool": TOOL, "version": __version__, "author": AUTHOR,
                                                       "commands": LOG, "tables": SESSION}, indent=2))
        ok(f"JSON -> {base}/results.json")
    if "pdf" in fm and make_pdf(base / "report.pdf", SESSION, theme or STATE["theme"]):
        ok(f"PDF  -> {base}/report.pdf")
    return base


# --------------------------------------------------------------------------- CLI
def add_nmap_options(p):
    p.add_argument("targets", nargs="+", help="IP / hostname / CIDR / range, or 'auto' for the local subnet")
    p.add_argument("--profile", choices=list(PROFILES), help="preset: " + ", ".join(PROFILES))
    p.add_argument("-p", "--ports", help="ports: 22,80,1-1024 or 'all'")
    p.add_argument("--top", type=int, help="scan the N most common ports")
    p.add_argument("-F", "--fast", action="store_true", help="fast (top 100)")
    p.add_argument("--type", choices=list(TYPE_FLAG), help="scan technique")
    p.add_argument("--sv", action="store_true", help="service/version detection (-sV)")
    p.add_argument("--intensity", type=int, choices=range(10), help="version intensity 0-9")
    p.add_argument("--os", dest="osdetect", action="store_true", help="OS detection (-O)")
    p.add_argument("--guess", action="store_true", help="--osscan-guess")
    p.add_argument("--limit", action="store_true", help="--osscan-limit")
    p.add_argument("-A", "--aggressive", action="store_true", help="-A (OS + version + scripts + traceroute)")
    p.add_argument("--script", help="NSE scripts/categories, e.g. default,safe")
    p.add_argument("--traceroute", action="store_true")
    p.add_argument("-T", "--timing", type=int, choices=range(6), help="timing template 0-5")
    p.add_argument("--no-ping", action="store_true", help="-Pn: skip host discovery")
    p.add_argument("-n", "--no-dns", action="store_true", help="never resolve DNS")
    p.add_argument("--reason", action="store_true", help="show port state reasons")
    p.add_argument("--args", default="", help='ANY extra nmap options, e.g. --args "--max-retries 1 -sC"')


def build_parser():
    p = argparse.ArgumentParser(prog="iuk_netscope", description=f"{TOOL} v{__version__} by {AUTHOR}",
                                epilog="Global options go BEFORE the command. Authorised use only.")
    p.add_argument("--theme", choices=list(THEMES))
    p.add_argument("--font-size", type=int, metavar="N", help="font size (GUI console always; terminal where supported)")
    p.add_argument("--sudo", action="store_true", help="run nmap via sudo (needed for -sS, -O, ARP)")
    p.add_argument("--yes", action="store_true", help="confirm authorisation for non-private targets")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--out", help="report folder")
    p.add_argument("--report", nargs="?", const="pdf,csv", metavar="FORMATS", help="auto-report after the command: pdf,csv,json")
    p.add_argument("--gui", action="store_true", help="open the desktop app")
    p.add_argument("--version", action="version", version=f"{TOOL} {__version__}")
    s = p.add_subparsers(dest="cmd")
    s.add_parser("interfaces", help="Ethernet / Wi-Fi / virtual interface details")
    s.add_parser("wifi", help="Wi-Fi networks in range")
    b = s.add_parser("bluetooth", help="Bluetooth controllers and nearby devices")
    b.add_argument("--seconds", type=int, default=8)
    s.add_parser("usb", help="USB devices")
    a = s.add_parser("all", help="interfaces + Wi-Fi + Bluetooth + USB + ARP scan of local subnet")
    a.add_argument("--seconds", type=int, default=8, help="Bluetooth scan time")
    a.add_argument("--no-arp", action="store_true")
    pi = s.add_parser("ping", help="ICMP ping with stats")
    pi.add_argument("targets", nargs="+")
    pi.add_argument("-c", "--count", type=int, default=4)
    ns = s.add_parser("nslookup", help="DNS lookup")
    ns.add_argument("names", nargs="+")
    ns.add_argument("-t", "--types", default="A,AAAA,MX,NS,TXT", help="record types, comma separated")
    ns.add_argument("-s", "--server")
    ar = s.add_parser("arp", help="ARP cache + ARP host discovery")
    ar.add_argument("target", nargs="?", default="auto")
    ar.add_argument("--no-scan", action="store_true", help="only show the cache")
    for n, h in (("ports", "open-port / service scan"), ("osscan", "OS detection scan"), ("scan", "full nmap front-end")):
        sp = s.add_parser(n, help=h)
        add_nmap_options(sp)
        sp.set_defaults(preset="os" if n == "osscan" else None)
    qk = s.add_parser("quick", help="built-in scans: pick an interface, LAN IP, Bluetooth ID or Wi-Fi SSID")
    qk.add_argument("kind", nargs="?", choices=list(KIND_LABEL), help="what to scan")
    qk.add_argument("value", nargs="?", help="interface name / IP / Bluetooth MAC / SSID (omit to list choices)")
    qk.add_argument("--scan", help="built-in scan id (omit to list them)")
    s.add_parser("doctor", help="check dependencies (nmap etc.) and offer to install them")
    r = s.add_parser("report", help="build PDF/CSV/JSON from everything run this session")
    r.add_argument("--formats", default="pdf,csv")
    r.add_argument("--name")
    r.add_argument("--pdf-theme", choices=list(THEMES), help="theme for the PDF (use 'light' to print)")
    th = s.add_parser("theme", help="show / set theme")
    th.add_argument("name", nargs="?", choices=list(THEMES))
    f = s.add_parser("font", help="show / set font size")
    f.add_argument("size", nargs="?", type=int)
    s.add_parser("session", help="list results collected so far")
    s.add_parser("clear", help="clear screen")
    s.add_parser("shell", help="interactive prompt (default)")
    s.add_parser("gui", help="desktop app (resizable window, themes, live font size)")
    return p


def set_theme(name):
    STATE["theme"] = name
    save_config()
    term_colors()


def set_font(size):
    STATE["font_size"] = max(6, min(48, size))
    save_config()
    term_font(STATE["font_size"])


def execute(a, line=""):
    c = a.cmd
    LOG.append(line or c)
    if c == "interfaces": emit(t_interfaces())
    elif c == "wifi": emit(t_wifi())
    elif c == "bluetooth": emit(t_bluetooth(a.seconds))
    elif c == "usb": emit(t_usb())
    elif c == "all":
        full_sweep(None, a.seconds, not a.no_arp)
    elif c == "doctor":
        emit(dep_table())
        miss = [d["pkg"] for d in check_deps() if not d["found"] and d["pkg"] != "pkexec" and not d["pkg"].startswith("built into")]
        if miss and sys.stdin and sys.stdin.isatty() and input("Install missing packages now? [y/N] ").lower() == "y":
            install_missing(sorted(set(miss)))
    elif c == "quick":
        quick_cli(a)
    elif c == "ping":
        for t in a.targets:
            emit(t_ping(t, a.count))
    elif c == "nslookup":
        for n in a.names:
            emit(t_nslookup(n, [x.strip().upper() for x in a.types.split(",")], a.server))
    elif c == "arp":
        emit(t_neighbors())
        if not a.no_scan:
            arp_scan(a.target)
    elif c in ("ports", "osscan", "scan"):
        nmap_scan(c, a.targets, build_args(a, a.preset))
    elif c == "report":
        write_reports(a.formats, a.name, a.pdf_theme)
    elif c == "theme":
        if a.name: set_theme(a.name)
        print(" ".join(C("accent", n, True) if n == STATE["theme"] else n for n in THEMES))
    elif c == "font":
        if a.size: set_font(a.size)
        print(f"font size = {STATE['font_size']}")
    elif c == "session":
        for i, t in enumerate(SESSION, 1):
            print(f"{i:>3}. {t['title']}  [{len(t['rows'])} rows]")
        if not SESSION: print("(empty)")
    elif c == "clear":
        print("\033c", end="")


def quick_cli(a):
    if not a.kind:
        for k, lst in BUILTIN.items():
            print(C("accent", f"{k}  ({KIND_LABEL[k]})", True))
            for x in lst:
                print(f"   {x['id']:<10} {x['label']}" + (C("warn", "  [admin]") if x["root"] else ""))
        return
    if not a.value:
        for d, v in discover_choices(a.kind):
            print(f"  {v:<22} {d}")
        return
    sid = a.scan or BUILTIN[a.kind][0]["id"]
    if sid not in [x["id"] for x in BUILTIN[a.kind]]:
        err(f"unknown scan '{sid}' - run `quick {a.kind}` to see ids"); return
    run_builtin(a.kind, sid, a.value)


def apply_globals(a):
    if a.theme: STATE["theme"] = a.theme
    if a.font_size: STATE["font_size"] = a.font_size
    if a.sudo: STATE["sudo"] = True
    if a.yes: STATE["yes"] = True
    if a.no_color: UI.color = False
    if a.out:
        global REPORT_DIR
        REPORT_DIR = Path(a.out).expanduser()


def execute_line(parser, line):
    line = line.strip()
    if not line:
        return
    try:
        a = parser.parse_args(shlex.split(line))
    except SystemExit:
        return
    except ValueError as e:
        err(str(e))
        return
    apply_globals(a)
    if a.cmd and a.cmd not in ("shell", "gui"):
        try:
            execute(a, line)
        except Exception as e:  # keep the shell alive
            err(f"{type(e).__name__}: {e}")


def banner():
    print(C("accent", "╭────────────────────────────────────────────────────╮", True))
    print(C("accent", "│ ", True) + C("fg", f"{TOOL} v{__version__}  ·  by {AUTHOR}".ljust(51), True) + C("accent", "│", True))
    print(C("accent", "│ ", True) + C("dim", "Wi-Fi · Bluetooth · USB · Ethernet · Nmap · Reports".ljust(51)) + C("accent", "│", True))
    print(C("accent", "╰────────────────────────────────────────────────────╯", True))
    print(C("warn", "Authorised testing only.") + C("dim", "  Type `-h` for help, `all` for a full sweep, `exit` to quit."))


HAVE_RL = False


def shell(parser):
    global HAVE_RL
    try:
        import readline
        HAVE_RL = True
        hf = Path.home() / ".iuk_netscope_history"
        try: readline.read_history_file(hf)
        except Exception: pass
        atexit.register(lambda: readline.write_history_file(hf))
    except ImportError:
        pass
    term_colors()
    banner()
    while True:
        try:
            r, g, b = _rgb(THEMES[STATE["theme"]]["accent"])
            a, z = ("\001", "\002") if HAVE_RL else ("", "")
            pr = f"{a}\x1b[1;38;2;{r};{g};{b}m{z}iuk-netscope ❯{a}\x1b[0m{z} " if UI.color else "iuk-netscope > "
            line = input(pr)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip() in ("exit", "quit", "q"):
            break
        execute_line(parser, line)


def launch_gui():
    sys.modules.setdefault("iuk_netscope", sys.modules[__name__])
    try:
        import iuk_netscope_gui as g
    except ImportError as e:
        err(f"Cannot start the desktop app ({e}). Install: sudo apt install python3-tk")
        return
    g.main()


def main(argv=None):
    load_config()
    parser = build_parser()
    a = parser.parse_args(argv)
    apply_globals(a)
    if a.gui or a.cmd == "gui":
        return launch_gui()
    atexit.register(term_reset)
    if a.font_size:
        term_font(a.font_size)
    if a.cmd in (None, "shell"):
        if not (sys.stdin and sys.stdin.isatty()):
            parser.print_help(); return
        return shell(parser)
    term_colors()
    execute(a, " ".join(argv if argv is not None else sys.argv[1:]))
    if a.report:
        write_reports(a.report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
    except BrokenPipeError:          # e.g. `iuk-netscope quick | head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
