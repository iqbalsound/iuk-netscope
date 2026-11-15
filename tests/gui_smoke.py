"""Headless GUI smoke test (needs a display, e.g. xvfb-run). Exits 0 on success."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tkinter as tk  # noqa: E402
import iuk_netscope as core  # noqa: E402
import iuk_netscope_gui as gui  # noqa: E402

errors, result = [], {}
root = tk.Tk()
root.report_callback_exception = lambda *a: errors.append(a[1])
app = gui.App(root)


def start():
    for theme in core.THEMES:                      # every theme must apply cleanly
        app.set_theme(theme)
    app.resize(+2); app.resize(-2)
    app.kind.set("lan"); app.on_kind(refresh=False)
    app.choice.set("127.0.0.1")
    app.scan_cb.current([s["id"] for s in app.scans].index("ping")); app.on_scan()
    result["started"] = app.start_quick()


def wait(n=0):
    if app.job and n < 100:
        root.after(300, lambda: wait(n + 1))
        return
    result["tabs"] = len(app.tabs)
    for t in app.tabs:                             # exercise filter + sort + copy paths
        t.q.set("x"); t.q.set(""); t.sort(0); t.refit()
    app.build_adv = app.preview()                  # advanced-tab preview must not raise
    root.destroy()


root.after(500, start)
root.after(1500, wait)
root.after(60000, root.destroy)
root.mainloop()
ok = not errors and result.get("tabs", 0) >= 1
print("GUI smoke:", "OK" if ok else "FAILED", result, errors)
sys.exit(0 if ok else 1)
