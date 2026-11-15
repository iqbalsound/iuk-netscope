#!/usr/bin/env python3
"""IUK-NetScope desktop app (v0.0.1) - by Iqbal Uddin Khan.

Resizable window, live Activity view in the centre, result tabs, built-in quick scans,
themes (dark / matrix / light / ocean), adjustable font size. Scans run in background
threads, so minimising the window never interrupts them; a desktop notification
announces completion. Use only on networks you own or are authorised to test.
"""
from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import types
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

try:
    import iuk_netscope as core
except ImportError:  # running from another directory
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import iuk_netscope as core

APP_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
ICON_NAMES = ("icon.png", "/usr/share/icons/hicolor/256x256/apps/iuk-netscope.png")
GOOD, BAD, WARN = core.GOOD, core.BAD, core.WARN


# ============================================================================ widgets
class ScrollFrame(ttk.Frame):
    """Vertically scrollable container so the side panel never gets cut off on small windows."""

    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)

    def _enter(self, _):
        self.canvas.bind_all("<Button-4>", lambda e: self._scroll(-1))
        self.canvas.bind_all("<Button-5>", lambda e: self._scroll(1))
        self.canvas.bind_all("<MouseWheel>", lambda e: self._scroll(-1 if e.delta > 0 else 1))

    def _leave(self, _):
        for ev in ("<Button-4>", "<Button-5>", "<MouseWheel>"):
            self.canvas.unbind_all(ev)

    def _scroll(self, d):
        if self.inner.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(d, "units")


class ResultTab(ttk.Frame):
    """One result table: sortable, filterable, copyable."""

    def __init__(self, parent, table, app):
        super().__init__(parent)
        self.table, self.app = table, app
        self.headers, self.rows = table["headers"], table["rows"]
        self.sort_col, self.sort_rev = None, False
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Label(top, text=table["title"], style="Title.TLabel").pack(side="left")
        self.count = ttk.Label(top, style="Dim.TLabel")
        self.count.pack(side="left", padx=10)
        self.q = tk.StringVar()
        ttk.Entry(top, textvariable=self.q, width=24).pack(side="right")
        ttk.Label(top, text="Filter  ").pack(side="right")
        self.q.trace_add("write", lambda *_: self.fill())
        if table.get("note"):
            ttk.Label(self, text=table["note"], style="Dim.TLabel", wraplength=900).pack(anchor="w", padx=8)
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        ids = [f"c{i}" for i in range(len(self.headers))]
        self.tv = ttk.Treeview(body, columns=ids, show="headings", selectmode="extended")
        for i, h in enumerate(self.headers):
            self.tv.heading(ids[i], text=h, command=lambda i=i: self.sort(i))
        vs = ttk.Scrollbar(body, orient="vertical", command=self.tv.yview)
        hs = ttk.Scrollbar(body, orient="horizontal", command=self.tv.xview)
        self.tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy row", command=self.copy_row)
        self.menu.add_command(label="Copy cell", command=self.copy_cell)
        self.menu.add_command(label="Copy all visible rows (TSV)", command=self.copy_all)
        self.menu.add_separator()
        self.menu.add_command(label="Use IP as LAN target", command=self.use_ip)
        self.tv.bind("<Button-3>", self.popup)
        self.tv.bind("<Control-c>", lambda e: self.copy_row())
        self.tv.bind("<Double-1>", lambda e: self.use_ip(silent=True))
        self._cell = ""
        self.fill()
        self.refit()
        self.recolor()

    def role(self, row):
        for i, h in enumerate(self.headers):
            v = str(row[i]).strip().lower()
            if h == "State":
                return "good" if v in GOOD else "bad" if v in BAD else "warn" if v in WARN else ""
            if h == "Connected" and v == "yes":
                return "good"
        return ""

    def fill(self):
        q = self.q.get().lower()
        self.tv.delete(*self.tv.get_children())
        rows = [r for r in self.rows if not q or any(q in str(c).lower() for c in r)]
        if self.sort_col is not None:
            def key(r):
                v = str(r[self.sort_col])
                try:
                    return (0, float(v.replace("%", "").split()[0]), "")
                except (ValueError, IndexError):
                    return (1, 0, v.lower())
            rows.sort(key=key, reverse=self.sort_rev)
        for r in rows:
            tag = self.role(r)
            self.tv.insert("", "end", values=[str(c).replace("\n", " ⏎ ") for c in r], tags=(tag,) if tag else ())
        self.count.configure(text=f"{len(rows)} of {len(self.rows)} rows")

    def sort(self, i):
        self.sort_rev = (not self.sort_rev) if self.sort_col == i else False
        self.sort_col = i
        self.fill()

    def refit(self):
        f = tkfont.nametofont("TkDefaultFont")
        for i, h in enumerate(self.headers):
            w = max([f.measure(str(h)) + 34] + [f.measure(str(r[i]).replace("\n", " ")[:70]) + 18 for r in self.rows[:300]])
            last = i == len(self.headers) - 1
            self.tv.column(f"c{i}", width=min(w, 900 if last else 460), minwidth=60, stretch=last)

    def recolor(self):
        t = core.THEMES[core.STATE["theme"]]
        for tag in ("good", "warn", "bad"):
            self.tv.tag_configure(tag, foreground=t[tag])

    def popup(self, e):
        row = self.tv.identify_row(e.y)
        if row:
            if row not in self.tv.selection():
                self.tv.selection_set(row)
            col = self.tv.identify_column(e.x)
            vals = self.tv.item(row, "values")
            idx = int(col[1:]) - 1 if col else 0
            self._cell = vals[idx] if 0 <= idx < len(vals) else ""
            self.menu.tk_popup(e.x_root, e.y_root)

    def _clip(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def copy_row(self):
        self._clip("\n".join("\t".join(self.tv.item(i, "values")) for i in self.tv.selection()))

    def copy_cell(self):
        self._clip(self._cell)

    def copy_all(self):
        self._clip("\t".join(self.headers) + "\n" + "\n".join("\t".join(self.tv.item(i, "values")) for i in self.tv.get_children()))

    def use_ip(self, silent=False):
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", self._cell or "".join(self.tv.item(self.tv.focus(), "values")[:1]))
        if m:
            self.app.use_target(m[1])


# ============================================================================ main app
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.job = None
        self.ctl = core.Ctl()
        self.tabs: list[ResultTab] = []
        self.choice_map: dict[str, str] = {}
        self.tk_widgets: list = []
        core.UI.gui, core.UI.color = True, False
        core.SINK = lambda lvl, msg: self.q.put(("log", lvl, str(msg)))
        core.TABLE_SINK = lambda t: self.q.put(("table", t))

        root.title(f"{core.TOOL} {core.__version__} - {core.AUTHOR}")
        root.minsize(920, 600)
        root.geometry(core.STATE.get("geometry") or self.default_geometry())
        self.set_icon()
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.f_title = tkfont.Font(weight="bold")
        self.theme_var = tk.StringVar(value=core.STATE["theme"])
        self.admin_var = tk.BooleanVar(value=core.STATE.get("gui_admin", True))
        self.notify_var = tk.BooleanVar(value=core.STATE.get("notify", True))
        self.autoscroll = tk.BooleanVar(value=True)
        self.switch_var = tk.BooleanVar(value=True)

        self.build_menu()
        self.build_toolbar()
        self.build_status()
        self.build_main()
        self.apply_fonts()
        self.apply_theme()
        self.bind_keys()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<FocusIn>", self.on_focus)
        root.after(50, self.pump)
        root.after(150, self.place_sash)
        self.welcome()
        self.on_kind()
        threading.Thread(target=self.startup_checks, daemon=True).start()

    # ---------------------------------------------------------------- window helpers
    def default_geometry(self):
        w, h = min(1320, self.root.winfo_screenwidth() - 80), min(800, self.root.winfo_screenheight() - 100)
        return f"{w}x{h}+{(self.root.winfo_screenwidth() - w) // 2}+{max((self.root.winfo_screenheight() - h) // 2 - 20, 0)}"

    def set_icon(self):
        for n in ICON_NAMES:
            p = Path(n) if os.path.isabs(n) else APP_DIR / n
            if p.exists():
                try:
                    self.icon = tk.PhotoImage(file=str(p))
                    self.root.iconphoto(True, self.icon)
                except tk.TclError:
                    pass
                break

    def place_sash(self, tries=0):
        self.root.update_idletasks()
        want = max(340, min(430, self.root.winfo_width() // 3))
        try:
            self.main.sashpos(0, want)
            if abs(self.main.sashpos(0) - want) > 8 and tries < 10:
                self.root.after(150, lambda: self.place_sash(tries + 1))
        except tk.TclError:
            pass

    def use_target(self, ip):
        self.kind.set("lan")
        self.on_kind(refresh=False)
        self.choice.set(ip)
        self.left_nb.select(0)
        self.log("info", f"Target set to {ip} - choose a scan on the left and press Start.")

    # ---------------------------------------------------------------- menu / toolbar / status
    def build_menu(self):
        m = tk.Menu(self.root)
        self.tk_widgets.append(m)
        f = tk.Menu(m, tearoff=0)
        f.add_command(label="Export PDF report…", accelerator="Ctrl+E", command=lambda: self.export("pdf"))
        f.add_command(label="Export PDF (light, print-friendly)…", command=lambda: self.export("pdf", "light"))
        f.add_command(label="Export CSV…", command=lambda: self.export("csv"))
        f.add_command(label="Export JSON…", command=lambda: self.export("json"))
        f.add_command(label="Open reports folder", command=self.open_reports)
        f.add_separator()
        f.add_command(label="Quit", accelerator="Ctrl+Q", command=self.on_close)
        s = tk.Menu(m, tearoff=0)
        s.add_command(label="Start quick scan", accelerator="Ctrl+Enter", command=self.start_quick)
        s.add_command(label="Refresh pick-list", accelerator="F5", command=self.refresh_choices)
        s.add_command(label="Full hardware sweep", command=self.full_sweep)
        s.add_command(label="Stop", accelerator="Ctrl+.", command=self.stop)
        s.add_separator()
        s.add_command(label="Clear results", command=self.clear_results)
        v = tk.Menu(m, tearoff=0)
        tm = tk.Menu(v, tearoff=0)
        for n in core.THEMES:
            tm.add_radiobutton(label=n.capitalize(), value=n, variable=self.theme_var, command=lambda n=n: self.set_theme(n))
        v.add_cascade(label="Theme", menu=tm)
        v.add_command(label="Larger text", accelerator="Ctrl +", command=lambda: self.resize(+1))
        v.add_command(label="Smaller text", accelerator="Ctrl -", command=lambda: self.resize(-1))
        v.add_command(label="Reset text size", accelerator="Ctrl 0", command=lambda: self.resize(0, 12))
        v.add_separator()
        v.add_checkbutton(label="Show results when a scan finishes", variable=self.switch_var)
        v.add_checkbutton(label="Notify when a scan finishes", variable=self.notify_var, command=self.save_flags)
        t = tk.Menu(m, tearoff=0)
        t.add_command(label="Check / install dependencies…", command=self.deps_dialog)
        h = tk.Menu(m, tearoff=0)
        h.add_command(label="About", command=self.about)
        for label, menu in (("File", f), ("Scan", s), ("View", v), ("Tools", t), ("Help", h)):
            m.add_cascade(label=label, menu=menu)
            self.tk_widgets.append(menu)
        self.tk_widgets.extend([tm])
        self.root.config(menu=m)

    def build_toolbar(self):
        bar = ttk.Frame(self.root, style="Bar.TFrame")
        bar.pack(side="top", fill="x")
        inner = ttk.Frame(bar, style="Bar.TFrame")
        inner.pack(fill="x", padx=8, pady=6)
        self.btn_sweep = ttk.Button(inner, text="⚡ Full sweep", command=self.full_sweep)
        self.btn_stop = ttk.Button(inner, text="■ Stop", command=self.stop, state="disabled")
        for b in (self.btn_sweep, self.btn_stop):
            b.pack(side="left", padx=(0, 6))
        ttk.Separator(inner, orient="vertical").pack(side="left", fill="y", padx=6)
        for text, fn in (("PDF", lambda: self.export("pdf")), ("CSV", lambda: self.export("csv")), ("Clear", self.clear_results)):
            ttk.Button(inner, text=text, command=fn).pack(side="left", padx=(0, 6))
        ttk.Button(inner, text="A+", width=3, command=lambda: self.resize(+1)).pack(side="right", padx=(6, 0))
        ttk.Button(inner, text="A−", width=3, command=lambda: self.resize(-1)).pack(side="right")
        cb = ttk.Combobox(inner, textvariable=self.theme_var, values=list(core.THEMES), state="readonly", width=8)
        cb.pack(side="right", padx=8)
        cb.bind("<<ComboboxSelected>>", lambda e: self.set_theme(self.theme_var.get()))
        ttk.Label(inner, text="Theme", style="Bar.TLabel").pack(side="right")

    def build_status(self):
        bar = ttk.Frame(self.root, style="Bar.TFrame")
        bar.pack(side="bottom", fill="x")
        self.status = ttk.Label(bar, text="Ready", style="Bar.TLabel")
        self.status.pack(side="left", padx=10, pady=4)
        self.nmap_lbl = ttk.Label(bar, text="nmap …", style="Bar.TLabel", cursor="hand2")
        self.nmap_lbl.pack(side="right", padx=10)
        self.nmap_lbl.bind("<Button-1>", lambda e: self.deps_dialog())
        self.elapsed = ttk.Label(bar, text="", style="Bar.TLabel")
        self.elapsed.pack(side="right", padx=10)
        self.pb = ttk.Progressbar(bar, mode="indeterminate", length=220)
        self.pb.pack(side="right", padx=6, pady=4)

    def build_main(self):
        self.main = ttk.PanedWindow(self.root, orient="horizontal")
        self.main.pack(fill="both", expand=True)
        left = ttk.Frame(self.main, width=390)
        left.pack_propagate(False)
        center = ttk.Frame(self.main)
        self.main.add(left, weight=0)
        self.main.add(center, weight=1)
        # ---- left: Quick Scan / Advanced / Tools
        self.left_nb = ttk.Notebook(left)
        self.left_nb.pack(fill="both", expand=True, padx=(8, 4), pady=8)
        for name, builder in (("Quick Scan", self.build_quick), ("Advanced nmap", self.build_advanced), ("Tools", self.build_tools)):
            sf = ScrollFrame(self.left_nb)
            self.tk_widgets.append(sf.canvas)
            self.left_nb.add(sf, text=f" {name} ")
            builder(sf.inner)
        # ---- centre: Activity + result tabs
        self.nb = ttk.Notebook(center)
        self.nb.pack(fill="both", expand=True, padx=(4, 8), pady=8)
        self.act = ttk.Frame(self.nb)
        self.nb.add(self.act, text=" ◉ Activity ")
        top = ttk.Frame(self.act)
        top.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Label(top, text="Live activity - everything the tool is doing", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Clear log", command=self.clear_log).pack(side="right")
        ttk.Button(top, text="Copy log", command=self.copy_log).pack(side="right", padx=6)
        ttk.Checkbutton(top, text="Auto-scroll", variable=self.autoscroll).pack(side="right", padx=6)
        body = ttk.Frame(self.act)
        body.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.logbox = tk.Text(body, wrap="word", state="disabled", borderwidth=0, padx=10, pady=8, font="TkFixedFont", cursor="arrow")
        sb = ttk.Scrollbar(body, command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=sb.set)
        self.logbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tk_widgets.append(self.logbox)
        self.nb.bind("<Button-3>", self.tab_menu)
        self.nb.bind("<Button-2>", self.close_tab_at)
        self.tabmenu = tk.Menu(self.root, tearoff=0)
        self.tk_widgets.append(self.tabmenu)
        self.tabmenu.add_command(label="Close tab", command=self.close_tab)
        self._tab_idx = None

    # ---- Quick Scan tab
    def build_quick(self, f):
        pad = dict(anchor="w", padx=6)
        ttk.Label(f, text="1  What do you want to scan?", style="Step.TLabel").pack(pady=(10, 4), **pad)
        self.kind = tk.StringVar(value="interface")
        for k, label in core.KIND_LABEL.items():
            ttk.Radiobutton(f, text=label, value=k, variable=self.kind, command=self.on_kind).pack(padx=22, pady=1, anchor="w")
        ttk.Label(f, text="2  Pick one", style="Step.TLabel").pack(pady=(14, 4), **pad)
        self.choice = tk.StringVar()
        self.choice_cb = ttk.Combobox(f, textvariable=self.choice, state="readonly")
        self.choice_cb.pack(fill="x", padx=6)
        row = ttk.Frame(f)
        row.pack(fill="x", padx=6, pady=4)
        ttk.Button(row, text="⟳ Refresh list", command=self.refresh_choices).pack(side="left")
        self.found = ttk.Label(row, text="", style="Dim.TLabel")
        self.found.pack(side="left", padx=8)
        self.hint = ttk.Label(f, text="", style="Dim.TLabel", wraplength=320, justify="left")
        self.hint.pack(fill="x", padx=6)
        ttk.Label(f, text="3  Choose a scan", style="Step.TLabel").pack(pady=(14, 4), **pad)
        self.scan_var = tk.StringVar()
        self.scan_cb = ttk.Combobox(f, textvariable=self.scan_var, state="readonly")
        self.scan_cb.pack(fill="x", padx=6)
        self.scan_cb.bind("<<ComboboxSelected>>", lambda e: self.on_scan())
        self.scan_desc = ttk.Label(f, text="", wraplength=320, justify="left")
        self.scan_desc.pack(fill="x", padx=6, pady=(6, 0))
        self.scan_badge = ttk.Label(f, text="", style="Warn.TLabel")
        self.scan_badge.pack(anchor="w", padx=6)
        self.btn_start = ttk.Button(f, text="▶  Start scan", style="Accent.TButton", command=self.start_quick)
        self.btn_start.pack(fill="x", padx=6, pady=(14, 6), ipady=5)
        ttk.Separator(f).pack(fill="x", padx=6, pady=6)
        if core.IS_WIN:
            ttk.Label(f, text=("Running as Administrator ✔" if core.is_admin() else
                               "Tip: right-click the app > Run as administrator for OS detection, SYN/UDP scans and ARP sweeps."),
                      style="Dim.TLabel", wraplength=320, justify="left").pack(anchor="w", padx=6, pady=2)
        else:
            ttk.Checkbutton(f, text="Use admin rights when needed", variable=self.admin_var, command=self.save_flags).pack(anchor="w", padx=6, pady=2)
        ttk.Checkbutton(f, text="Notify me when a scan ends", variable=self.notify_var, command=self.save_flags).pack(anchor="w", padx=6, pady=2)
        ttk.Label(f, text="Scans keep running if you minimise the window.", style="Dim.TLabel", wraplength=320).pack(anchor="w", padx=6, pady=(6, 10))
        f.bind("<Configure>", lambda e: [w.configure(wraplength=max(e.width - 24, 160)) for w in (self.hint, self.scan_desc)])

    def on_kind(self, refresh=True):
        k = self.kind.get()
        self.choice_cb.configure(state="normal" if k == "lan" else "readonly")
        self.choice.set("")
        self.choice_cb["values"] = ()
        self.found.configure(text="")
        self.hint.configure(text={
            "interface": "Ethernet, Wi-Fi, USB-tethering and virtual adapters on this computer.",
            "lan": "Devices seen on your network. You can also type any IP or hostname. Don't see yours? Run 'Find all devices' on an interface first.",
            "bluetooth": "Press Refresh to scan for nearby Bluetooth devices (about 6 seconds).",
            "wifi": "Press Refresh to list Wi-Fi networks in range. This tool never joins networks.",
        }[k])
        self.scans = core.BUILTIN[k]
        self.scan_cb["values"] = [s["label"] for s in self.scans]
        self.scan_cb.current(0)
        self.on_scan()
        if refresh and k in ("interface", "lan") and not self.job:
            self.refresh_choices()

    def on_scan(self):
        i = self.scan_cb.current()
        sc = self.scans[i if i >= 0 else 0]
        self.scan_desc.configure(text=sc["desc"])
        self.scan_badge.configure(text="⚠ Works best with administrator rights" if sc["root"] else "")

    def refresh_choices(self):
        k = self.kind.get()

        def fn(ctl):
            core.info(f"Looking for {core.KIND_LABEL[k].lower()} choices ...")
            ch = core.discover_choices(k, ctl)
            self.q.put(("choices", k, ch))
        self.start_job(f"Refresh {core.KIND_LABEL[k]} list", fn, select_results=False)

    def selected_value(self):
        shown = self.choice.get().strip()
        return self.choice_map.get(shown, shown.split()[0] if self.kind.get() == "lan" and shown else shown)

    def start_quick(self):
        k, val = self.kind.get(), self.selected_value()
        if not val:
            messagebox.showinfo("Pick one", f"Please pick a {core.KIND_LABEL[k].lower()} first (use ⟳ Refresh list).")
            return
        sc = self.scans[max(self.scan_cb.current(), 0)]
        if k == "lan" and not self.confirm_scope([val]):
            return
        self.start_job(f"{sc['label']} → {val}", lambda ctl: core.run_builtin(k, sc["id"], val, ctl))

    # ---- Advanced tab
    def build_advanced(self, f):
        self.adv = {}
        pad = dict(anchor="w", padx=6)

        def entry(label, key, default="", width=None, tip=None):
            ttk.Label(f, text=label).pack(pady=(8, 1), **pad)
            v = tk.StringVar(value=default)
            ttk.Entry(f, textvariable=v).pack(fill="x", padx=6)
            v.trace_add("write", lambda *_: self.preview())
            self.adv[key] = v
            return v

        def combo(label, key, values, default=""):
            ttk.Label(f, text=label).pack(pady=(8, 1), **pad)
            v = tk.StringVar(value=default)
            ttk.Combobox(f, textvariable=v, values=values, state="readonly").pack(fill="x", padx=6)
            v.trace_add("write", lambda *_: self.preview())
            self.adv[key] = v

        entry("Target(s) - IP, hostname, CIDR, range, or 'auto'", "targets", "auto")
        combo("Profile", "profile", ["(none)"] + list(core.PROFILES), "(none)")
        combo("Scan technique", "type", ["(default)"] + list(core.TYPE_FLAG), "(default)")
        entry("Ports  (e.g. 22,80,1-1024 or 'all')", "ports")
        entry("Top-N ports", "top")
        combo("Timing (0 slow … 5 fast)", "timing", ["(default)", "0", "1", "2", "3", "4", "5"], "(default)")
        entry("NSE scripts (e.g. default,safe)", "script")
        ttk.Label(f, text="Options").pack(pady=(10, 2), **pad)
        for key, label in (("sv", "Service / version detection (-sV)"), ("osdetect", "OS detection (-O)"), ("guess", "Guess OS aggressively"),
                           ("aggressive", "Aggressive (-A)"), ("traceroute", "Traceroute"), ("no_ping", "Skip host discovery (-Pn)"),
                           ("no_dns", "No DNS resolution (-n)"), ("reason", "Show reasons")):
            v = tk.BooleanVar()
            ttk.Checkbutton(f, text=label, variable=v, command=self.preview).pack(padx=18, anchor="w")
            self.adv[key] = v
        entry("Extra nmap arguments (anything nmap supports)", "args")
        ttk.Label(f, text="Command preview").pack(pady=(10, 1), **pad)
        self.prev = ttk.Label(f, text="", style="Dim.TLabel", wraplength=320, justify="left")
        self.prev.pack(fill="x", padx=6)
        f.bind("<Configure>", lambda e: self.prev.configure(wraplength=max(e.width - 24, 160)))
        ttk.Button(f, text="▶  Run nmap", style="Accent.TButton", command=self.run_advanced).pack(fill="x", padx=6, pady=12, ipady=5)
        self.preview()

    def adv_ns(self):
        g = lambda k: self.adv[k].get()
        norm = lambda v: None if v in ("", "(none)", "(default)") else v
        top = g("top").strip()
        return types.SimpleNamespace(
            profile=norm(g("profile")), type=norm(g("type")), ports=g("ports").strip() or None,
            top=int(top) if top.isdigit() else None, fast=False, sv=g("sv"), intensity=None, osdetect=g("osdetect"),
            guess=g("guess"), limit=False, aggressive=g("aggressive"), script=g("script").strip() or None,
            traceroute=g("traceroute"), timing=int(g("timing")) if g("timing").isdigit() else None,
            no_ping=g("no_ping"), no_dns=g("no_dns"), reason=g("reason"), args=g("args").strip())

    def preview(self):
        try:
            args = core.build_args(self.adv_ns())
        except ValueError as e:
            self.prev.configure(text=f"(check the extra arguments: {e})")
            return
        self.prev.configure(text="nmap " + " ".join(args + re.split(r"[,\s]+", self.adv["targets"].get().strip()))) if hasattr(self, "prev") else None

    def run_advanced(self):
        targets = [t for t in re.split(r"[,\s]+", self.adv["targets"].get().strip()) if t]
        if not targets:
            messagebox.showinfo("Target needed", "Enter at least one target (or 'auto').")
            return
        if not self.confirm_scope(targets):
            return
        args = core.build_args(self.adv_ns())
        self.start_job("nmap " + " ".join(args + targets)[:60], lambda ctl: core.nmap_scan("nmap", targets, args, ctl))

    # ---- Tools tab
    def build_tools(self, f):
        pad = dict(anchor="w", padx=6)
        ttk.Label(f, text="Host / IP / domain", style="Step.TLabel").pack(pady=(10, 2), **pad)
        self.t_host = tk.StringVar()
        ttk.Entry(f, textvariable=self.t_host).pack(fill="x", padx=6)
        r = ttk.Frame(f)
        r.pack(fill="x", padx=6, pady=6)
        ttk.Button(r, text="Ping", command=self.tool_ping).pack(side="left")
        ttk.Label(r, text="  count").pack(side="left")
        self.t_count = tk.IntVar(value=4)
        ttk.Spinbox(r, from_=1, to=50, width=4, textvariable=self.t_count).pack(side="left", padx=4)
        ttk.Label(f, text="DNS record types").pack(pady=(8, 1), **pad)
        self.t_types = tk.StringVar(value="A,AAAA,MX,NS,TXT")
        ttk.Entry(f, textvariable=self.t_types).pack(fill="x", padx=6)
        ttk.Button(f, text="DNS lookup (nslookup)", command=self.tool_dns).pack(fill="x", padx=6, pady=6)
        ttk.Button(f, text="ARP cache + ARP sweep (local network)", command=self.tool_arp).pack(fill="x", padx=6, pady=2)
        ttk.Separator(f).pack(fill="x", padx=6, pady=10)
        ttk.Label(f, text="This computer", style="Step.TLabel").pack(**pad)
        for text, fn in (("Interfaces (Ethernet / Wi-Fi)", lambda c: core.emit(core.t_interfaces())),
                         ("Wi-Fi networks in range", lambda c: core.emit(core.t_wifi())),
                         ("Bluetooth devices", lambda c: core.emit(core.t_bluetooth(8))),
                         ("USB devices", lambda c: core.emit(core.t_usb()))):
            ttk.Button(f, text=text, command=lambda fn=fn, text=text: self.start_job(text, fn)).pack(fill="x", padx=6, pady=2)
        ttk.Button(f, text="⚡ Full hardware sweep", style="Accent.TButton", command=self.full_sweep).pack(fill="x", padx=6, pady=(10, 4), ipady=4)
        ttk.Separator(f).pack(fill="x", padx=6, pady=10)
        ttk.Button(f, text="Check / install dependencies", command=self.deps_dialog).pack(fill="x", padx=6, pady=(0, 12))

    def _hosts(self):
        h = [x for x in re.split(r"[,\s]+", self.t_host.get().strip()) if x]
        if not h:
            messagebox.showinfo("Host needed", "Type a host, IP or domain first.")
        return h

    def tool_ping(self):
        h, n = self._hosts(), self.t_count.get()
        h and self.start_job(f"Ping {', '.join(h)}", lambda c: [core.emit(core.t_ping(x, n)) for x in h])

    def tool_dns(self):
        h, ty = self._hosts(), [x.strip().upper() for x in self.t_types.get().split(",") if x.strip()]
        h and self.start_job(f"DNS {', '.join(h)}", lambda c: [core.emit(core.t_nslookup(x, ty)) for x in h])

    def tool_arp(self):
        self.start_job("ARP cache + sweep", lambda c: (core.emit(core.t_neighbors()), core.arp_scan("auto", c)))

    def full_sweep(self):
        self.start_job("Full hardware sweep", lambda c: core.full_sweep(c, 6, True))

    # ---------------------------------------------------------------- jobs
    def confirm_scope(self, targets):
        out = [t for t in targets if t != "auto" and not core.private_target(t)]
        if not out:
            return True
        ok = messagebox.askokcancel(
            "Confirm authorisation",
            "These targets are outside your private network:\n\n  " + "\n  ".join(out) +
            "\n\nScan only systems you own or have written permission to test.\nContinue?", icon="warning")
        core.STATE["yes"] = ok
        return ok

    def start_job(self, title, fn, select_results=True):
        if self.job:
            messagebox.showinfo("Busy", "A job is already running. Wait for it to finish or press Stop.")
            return False
        core.STATE["sudo"] = bool(self.admin_var.get())
        self.ctl = core.Ctl(on_progress=lambda p: self.q.put(("progress", p)))
        self.job = dict(title=title, t0=time.time(), tables=0, first=None, select=select_results)
        self.set_busy(True)
        self.nb.select(self.act)
        self.log("cmd", f"▶ {title}")

        def work():
            err = None
            try:
                fn(self.ctl)
            except core.Cancelled:
                self.q.put(("log", "warn", "Stopped by user."))
            except Exception as e:  # keep the app alive, show the reason
                err = e
                self.q.put(("log", "err", f"{type(e).__name__}: {e}"))
            self.q.put(("done", err))

        threading.Thread(target=work, daemon=True).start()
        return True

    def stop(self):
        if self.job:
            self.log("warn", "Stopping ...")
            self.ctl.cancel()

    def set_busy(self, busy):
        st = "disabled" if busy else "normal"
        self.btn_start.configure(state=st)
        self.btn_sweep.configure(state=st)
        self.btn_stop.configure(state="normal" if busy else "disabled")
        if busy:
            self.pb.configure(mode="indeterminate", value=0)
            self.pb.start(14)
            self.status.configure(text=f"Working: {self.job['title']}")
            self.tick()
        else:
            self.pb.stop()
            self.pb.configure(mode="determinate", value=0)

    def tick(self):
        if self.job:
            s = int(time.time() - self.job["t0"])
            self.elapsed.configure(text=f"{s // 60:02d}:{s % 60:02d}")
            self.root.after(500, self.tick)

    def finish(self, err):
        job, self.job = self.job, None
        secs = time.time() - job["t0"]
        self.set_busy(False)
        core.STATE["yes"] = False
        msg = f"{job['title']} - finished in {secs:.1f}s" + (f", {job['tables']} result table(s)" if job["tables"] else "")
        self.status.configure(text=("Error: " if err else "Done: ") + msg)
        self.log("err" if err else "ok", msg)
        if job["select"] and job["first"] is not None and self.switch_var.get():
            self.nb.select(job["first"])
        self.attention(("Scan finished" if not err else "Scan failed"), msg)

    def attention(self, title, msg):
        if self.root.state() == "iconic" or not self.root.focus_displayof():
            self.root.title(f"✔ {title} - {core.TOOL}")
            self.root.bell()
        if self.notify_var.get() and shutil.which("notify-send"):
            try:
                subprocess.Popen(["notify-send", "-a", core.TOOL, "-i", "dialog-information", title, msg])
            except OSError:
                pass

    def on_focus(self, _=None):
        self.root.title(f"{core.TOOL} {core.__version__} - {core.AUTHOR}")

    # ---------------------------------------------------------------- event pump
    def pump(self):
        try:
            for _ in range(200):
                ev = self.q.get_nowait()
                kind = ev[0]
                if kind == "log":
                    self.log(ev[1], ev[2])
                elif kind == "table":
                    self.add_table(ev[1])
                elif kind == "progress":
                    if str(self.pb.cget("mode")) != "determinate":
                        self.pb.stop()
                        self.pb.configure(mode="determinate")
                    self.pb.configure(value=ev[1])
                elif kind == "choices":
                    self.set_choices(ev[1], ev[2])
                elif kind == "nmap":
                    self.nmap_lbl.configure(text=ev[1])
                elif kind == "deps":
                    self.deps_prompt(ev[1])
                elif kind == "done":
                    self.finish(ev[1])
        except queue.Empty:
            pass
        self.root.after(50, self.pump)

    def set_choices(self, kind, choices):
        if kind != self.kind.get():
            return
        self.choice_map = {d: v for d, v in choices}
        self.choice_cb["values"] = [d for d, _ in choices]
        self.found.configure(text=f"{len(choices)} found")
        if choices:
            self.choice_cb.current(0)
        else:
            self.log("warn", f"No {core.KIND_LABEL[kind].lower()} found. Check that the adapter is on / in range.")

    # ---------------------------------------------------------------- activity log + tabs
    ICON = {"info": "  ", "ok": "✔ ", "warn": "⚠ ", "err": "✖ ", "cmd": ""}

    def log(self, level, msg):
        t = self.logbox
        t.configure(state="normal")
        t.insert("end", datetime.now().strftime("%H:%M:%S  "), "time")
        t.insert("end", self.ICON.get(level, "") + msg + "\n", level)
        t.configure(state="disabled")
        if self.autoscroll.get():
            t.see("end")

    def clear_log(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")

    def copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.logbox.get("1.0", "end"))
        self.status.configure(text="Activity log copied to clipboard")

    def welcome(self):
        self.log("cmd", f"{core.TOOL} v{core.__version__}  -  by {core.AUTHOR}")
        self.log("warn", "Authorised testing only - scan networks and devices you own or have permission to test.")
        self.log("info", "Start on the left: 1) what to scan  2) pick one  3) choose a scan  ->  ▶ Start.")
        self.log("info", "Progress and every command appear here live; results open as tabs when a scan finishes.")

    def add_table(self, t):
        tab = ResultTab(self.nb, t, self)
        self.nb.add(tab, text=" " + t["title"][:30] + (" … " if len(t["title"]) > 30 else " "))
        self.tabs.append(tab)
        if self.job:
            self.job["tables"] += 1
            if self.job["first"] is None:
                self.job["first"] = tab
        self.log("info", f"  + result: {t['title']} ({len(t['rows'])} rows)")

    def tab_menu(self, e):
        try:
            self._tab_idx = self.nb.index(f"@{e.x},{e.y}")
        except tk.TclError:
            return
        if self._tab_idx > 0:
            self.tabmenu.tk_popup(e.x_root, e.y_root)

    def close_tab(self):
        if self._tab_idx and self._tab_idx > 0:
            w = self.nb.nametowidget(self.nb.tabs()[self._tab_idx])
            self.nb.forget(w)
            if w in self.tabs:
                self.tabs.remove(w)

    def close_tab_at(self, e):
        try:
            self._tab_idx = self.nb.index(f"@{e.x},{e.y}")
        except tk.TclError:
            return
        self.close_tab()

    def clear_results(self):
        if self.job:
            return
        if self.tabs and not messagebox.askyesno("Clear results", "Remove all result tabs and the data used for reports?"):
            return
        for t in list(self.tabs):
            self.nb.forget(t)
        self.tabs.clear()
        core.SESSION.clear()
        core.LOG.clear()
        self.status.configure(text="Results cleared")

    # ---------------------------------------------------------------- reports
    def export(self, fmt, theme=None):
        if not core.SESSION:
            messagebox.showinfo("Nothing to export", "Run a scan first - results appear as tabs.")
            return
        d = filedialog.askdirectory(title="Choose a folder for the report", initialdir=str(core.REPORT_DIR) if core.REPORT_DIR.exists() else str(Path.home()))
        if not d:
            return

        def fn(ctl):
            p = core.write_reports(fmt, "netscope", theme, d)
            if p:
                self.q.put(("log", "ok", f"Saved in {p}"))
        self.start_job(f"Export {fmt.upper()}", fn, select_results=False)

    def open_reports(self):
        core.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if core.IS_WIN:
            os.startfile(str(core.REPORT_DIR))  # noqa: S606
        elif shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", str(core.REPORT_DIR)])

    # ---------------------------------------------------------------- dependencies
    def startup_checks(self):
        try:
            nm = core.find_exe("nmap") or "nmap"
            _, o, _ = core.run([nm, "--version"], timeout=10)
            m = re.search(r"Nmap version ([\d.]+\w*)", o)
            self.q.put(("nmap", f"nmap {m[1]} ✓" if m else "nmap ✗ - click to install"))
        except Exception:
            self.q.put(("nmap", "nmap ✗ - click to install"))
        missing = [d for d in core.check_deps() if d["required"] and not d["found"]]
        if missing:
            self.q.put(("deps", missing))

    def deps_prompt(self, missing):
        names = ", ".join(d["name"] for d in missing)
        if messagebox.askyesno("Required components missing",
                               f"IUK-NetScope needs: {names}\n\nInstall them now? (asks for your administrator password)"):
            self.install([d["pkg"] for d in missing])

    def install(self, pkgs):
        pkgs = sorted(set(pkgs))
        self.start_job("Install " + ", ".join(pkgs), lambda ctl: core.install_missing(pkgs, ctl), select_results=False)
        self.root.after(1500, lambda: threading.Thread(target=self.startup_checks, daemon=True).start())

    def deps_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Dependencies")
        win.transient(self.root)
        win.geometry("760x420")
        t = core.THEMES[core.STATE["theme"]]
        win.configure(bg=t["bg"])
        ttk.Label(win, text="Components used by IUK-NetScope", style="Title.TLabel").pack(anchor="w", padx=12, pady=(12, 4))
        cols = ("Component", "Package", "Needed", "Installed", "Used for")
        tv = ttk.Treeview(win, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (110, 140, 80, 80, 320)):
            tv.heading(c, text=c)
            tv.column(c, width=w, stretch=(c == "Used for"))
        deps = core.check_deps()
        for d in deps:
            tv.insert("", "end", values=(d["name"], d["pkg"], "required" if d["required"] else "optional",
                                         "✔ yes" if d["found"] else "✖ no", d["why"]), tags=("good" if d["found"] else "bad",))
        tv.tag_configure("good", foreground=t["good"])
        tv.tag_configure("bad", foreground=t["bad"])
        tv.pack(fill="both", expand=True, padx=12, pady=6)
        miss = [d["pkg"] for d in deps if not d["found"]]
        row = ttk.Frame(win)
        row.pack(fill="x", padx=12, pady=10)
        ttk.Button(row, text="Close", command=win.destroy).pack(side="right")
        b = ttk.Button(row, text=f"Install {len(miss)} missing package(s)" if miss else "Everything is installed ✔", style="Accent.TButton",
                       state="normal" if miss else "disabled", command=lambda: (win.destroy(), self.install(miss)))
        b.pack(side="right", padx=8)

    def about(self):
        messagebox.showinfo(f"About {core.TOOL}",
                            f"{core.TOOL} v{core.__version__}\nby {core.AUTHOR}\n\nInterface discovery (Wi-Fi, Bluetooth, USB, Ethernet)\n"
                            "and nmap-powered scanning with PDF/CSV reports.\n\nAuthorised use only.")

    # ---------------------------------------------------------------- theme / fonts / keys
    def save_flags(self):
        core.STATE["gui_admin"] = bool(self.admin_var.get())
        core.STATE["notify"] = bool(self.notify_var.get())
        core.save_config()

    def set_theme(self, name):
        core.STATE["theme"] = name
        self.theme_var.set(name)
        core.save_config()
        self.apply_theme()

    def resize(self, delta, absolute=None):
        s = absolute if absolute is not None else core.STATE["font_size"] + delta
        core.STATE["font_size"] = max(7, min(40, s))
        core.save_config()
        self.apply_fonts()

    def apply_fonts(self):
        s = core.STATE["font_size"]
        for n in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont", "TkTooltipFont", "TkFixedFont"):
            tkfont.nametofont(n).configure(size=s)
        self.f_title.configure(size=s + 3)
        lh = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        self.style.configure("Treeview", rowheight=int(lh * 1.6))
        self.style.configure("Treeview.Heading", padding=(6, 4))
        for t in self.tabs:
            t.refit()
        self.status.configure(text=f"Text size {s}") if hasattr(self, "status") else None

    def apply_theme(self):
        t, st = core.THEMES[core.STATE["theme"]], self.style
        st.theme_use("clam")
        st.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["alt"], bordercolor=t["head"],
                     lightcolor=t["bg"], darkcolor=t["bg"], troughcolor=t["alt"], focuscolor=t["accent"], insertcolor=t["fg"],
                     selectbackground=t["accent"], selectforeground=t["bg"])
        st.configure("TFrame", background=t["bg"])
        st.configure("Bar.TFrame", background=t["alt"])
        st.configure("TLabel", background=t["bg"], foreground=t["fg"])
        st.configure("Bar.TLabel", background=t["alt"], foreground=t["fg"])
        st.configure("Title.TLabel", font=self.f_title, foreground=t["accent"])
        st.configure("Step.TLabel", font=self.f_title, foreground=t["accent"])
        st.configure("Dim.TLabel", foreground=t["dim"])
        st.configure("Warn.TLabel", foreground=t["warn"])
        st.configure("TButton", background=t["head"], foreground=t["fg"], padding=(10, 5), borderwidth=1, relief="flat", bordercolor=t["dim"])
        st.map("TButton", background=[("active", t["accent"]), ("disabled", t["alt"])],
               foreground=[("active", t["bg"]), ("disabled", t["dim"])])
        st.configure("Accent.TButton", background=t["accent"], foreground=t["bg"], font=self.f_title)
        st.map("Accent.TButton", background=[("active", t["fg"]), ("disabled", t["alt"])], foreground=[("disabled", t["dim"])])
        st.configure("TNotebook", background=t["bg"], borderwidth=0, tabmargins=(2, 4, 2, 0))
        st.configure("TNotebook.Tab", background=t["head"], foreground=t["dim"], padding=(12, 6))
        st.map("TNotebook.Tab", background=[("selected", t["alt"])], foreground=[("selected", t["accent"])])
        st.configure("Treeview", background=t["bg"], fieldbackground=t["bg"], foreground=t["fg"], bordercolor=t["head"])
        st.configure("Treeview.Heading", background=t["head"], foreground=t["accent"], relief="flat")
        st.map("Treeview", background=[("selected", t["accent"])], foreground=[("selected", t["bg"])])
        st.map("Treeview.Heading", background=[("active", t["alt"])])
        for w in ("TEntry", "TCombobox", "TSpinbox"):
            st.configure(w, fieldbackground=t["alt"], foreground=t["fg"], insertcolor=t["fg"], bordercolor=t["head"], arrowcolor=t["accent"])
        st.map("TCombobox", fieldbackground=[("readonly", t["alt"])], foreground=[("readonly", t["fg"])])
        for w in ("TCheckbutton", "TRadiobutton"):
            st.configure(w, background=t["bg"], foreground=t["fg"], indicatorcolor=t["alt"])
            st.map(w, indicatorcolor=[("selected", t["accent"])], background=[("active", t["bg"])], foreground=[("active", t["accent"])])
        st.configure("TProgressbar", background=t["accent"], troughcolor=t["alt"], bordercolor=t["head"])
        for sb in ("TScrollbar", "Vertical.TScrollbar", "Horizontal.TScrollbar"):
            st.configure(sb, background=t["head"], troughcolor=t["bg"], arrowcolor=t["accent"], bordercolor=t["bg"],
                         lightcolor=t["head"], darkcolor=t["head"], gripcount=0)
            st.map(sb, background=[("active", t["dim"]), ("pressed", t["accent"])])
        st.configure("TSeparator", background=t["head"])
        st.configure("TPanedwindow", background=t["head"])
        self.root.configure(bg=t["bg"])
        self.root.option_add("*TCombobox*Listbox.background", t["alt"])
        self.root.option_add("*TCombobox*Listbox.foreground", t["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", t["accent"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", t["bg"])
        for w in self.tk_widgets:
            try:
                if isinstance(w, tk.Menu):
                    w.configure(bg=t["alt"], fg=t["fg"], activebackground=t["accent"], activeforeground=t["bg"], borderwidth=0)
                elif isinstance(w, tk.Canvas):
                    w.configure(bg=t["bg"])
                else:
                    w.configure(bg=t["bg"], fg=t["fg"], insertbackground=t["fg"], selectbackground=t["accent"], selectforeground=t["bg"])
            except tk.TclError:
                pass
        lb = self.logbox
        lb.tag_configure("time", foreground=t["dim"])
        lb.tag_configure("info", foreground=t["fg"])
        lb.tag_configure("cmd", foreground=t["accent"], font=self.f_title)
        lb.tag_configure("ok", foreground=t["good"])
        lb.tag_configure("warn", foreground=t["warn"])
        lb.tag_configure("err", foreground=t["bad"])
        for tab in self.tabs:
            tab.recolor()

    def bind_keys(self):
        r = self.root
        for k in ("<Control-plus>", "<Control-equal>", "<Control-KP_Add>"):
            r.bind_all(k, lambda e: self.resize(+1))
        for k in ("<Control-minus>", "<Control-KP_Subtract>"):
            r.bind_all(k, lambda e: self.resize(-1))
        r.bind_all("<Control-0>", lambda e: self.resize(0, 12))
        r.bind_all("<Control-Button-4>", lambda e: self.resize(+1))
        r.bind_all("<Control-Button-5>", lambda e: self.resize(-1))
        r.bind_all("<Control-MouseWheel>", lambda e: self.resize(+1 if e.delta > 0 else -1))
        r.bind_all("<Control-Return>", lambda e: self.start_quick())
        r.bind_all("<F5>", lambda e: self.refresh_choices())
        r.bind_all("<Control-period>", lambda e: self.stop())
        r.bind_all("<Control-e>", lambda e: self.export("pdf"))
        r.bind_all("<Control-q>", lambda e: self.on_close())

    def on_close(self):
        if self.job and not messagebox.askyesno("Scan running", "A job is still running. Quit anyway?"):
            return
        if self.job:
            self.ctl.cancel()
        if self.root.state() == "normal":
            core.STATE["geometry"] = self.root.geometry()
        core.save_config()
        self.root.destroy()


def main():
    core.load_config()
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
