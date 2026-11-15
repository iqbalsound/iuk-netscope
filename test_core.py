"""Unit tests - run with:  python -m unittest discover -s tests -v   (works on Linux and Windows)."""
import json, os, re, sys, tempfile, types, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import iuk_netscope as core  # noqa: E402

NMAP_XML = """<nmaprun scanner="nmap" args="nmap -sV 10.0.0.5" start="1760000000" version="7.94"><host><status state="up" reason="arp-response"/>
<address addr="10.0.0.5" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TP-Link"/>
<hostnames><hostname name="router.lan"/></hostnames><ports><extraports state="closed" count="997"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6"><cpe>cpe:/a:openbsd:openssh:9.6</cpe></service>
<script id="ssh-hostkey" output="256 abc&#10;line2"/></port><port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/><service name="http"/></port></ports>
<os><osmatch name="Linux 5.4" accuracy="98"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="98"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os>
<times srtt="1200"/></host><runstats><finished summary="done"/></runstats></nmaprun>"""

NS = lambda **k: types.SimpleNamespace(**{**dict(profile=None, type=None, ports=None, top=None, fast=False, sv=False, intensity=None,
                                                  osdetect=False, guess=False, limit=False, aggressive=False, script=None, traceroute=False,
                                                  timing=None, no_ping=False, no_dns=False, reason=False, args=""), **k})


class CoreTests(unittest.TestCase):
    def setUp(self):
        core.SESSION.clear(); core.LOG.clear()

    def test_version_format(self):
        self.assertRegex(core.__version__, r"^\d+\.\d+\.\d+$")

    def test_parse_nmap(self):
        tabs = {t["title"].split(" - ")[1]: t for t in core.parse_nmap(NMAP_XML, "t")}
        self.assertEqual(list(tabs)[0], "hosts")            # hosts first, scan info last
        self.assertEqual(list(tabs)[-1], "scan info")
        self.assertEqual(tabs["hosts"]["rows"][0][0], "10.0.0.5")
        self.assertEqual(tabs["hosts"]["rows"][0][7], 1)     # one open port
        self.assertEqual(len(tabs["ports & services"]["rows"]), 2)
        self.assertEqual(tabs["OS detection"]["rows"][0][1], "Linux 5.4")
        self.assertIn("ssh-hostkey", tabs["script output"]["rows"][0])

    def test_build_args(self):
        a = core.build_args(NS(ports="all", type="syn", sv=True, timing=4, args="--max-retries 1"))
        self.assertEqual(a, ["-sS", "-p", "-", "-sV", "-T4", "--max-retries", "1"])
        self.assertEqual(core.build_args(NS(profile="quick")), ["-T4", "-F"])
        self.assertEqual(core.build_args(NS(osdetect=True), "os"), ["-O"])  # no duplicate -O

    def test_adapt_args(self):
        self.assertEqual(core.adapt_args(["-sS", "-O"], True), ["-sS", "-O"])
        with mock.patch.object(core, "warn"):
            self.assertEqual(core.adapt_args(["-sS", "-O", "-PR", "-A"], False), ["-sT", "-sV", "-sC", "--traceroute"])
        with mock.patch.object(core, "err"):
            self.assertIsNone(core.adapt_args(["-sU"], False))

    def test_private_target(self):
        for t in ("10.1.2.3", "192.168.0.0/24", "172.16.5.1", "127.0.0.1", "192.168.1.1-50"):
            self.assertTrue(core.private_target(t), t)
        for t in ("8.8.8.8", "1.1.1.0/24"):
            self.assertFalse(core.private_target(t), t)

    def test_builtin_registry(self):
        for kind, lst in core.BUILTIN.items():
            self.assertIn(kind, core.KIND_LABEL)
            ids = [x["id"] for x in lst]
            self.assertEqual(len(ids), len(set(ids)))
            for x in lst:
                self.assertTrue(callable(x["fn"]) and x["label"] and x["desc"])

    def test_parser(self):
        p = core.build_parser()
        a = p.parse_args(["--theme", "ocean", "quick", "lan", "10.0.0.1", "--scan", "ping"])
        self.assertEqual((a.cmd, a.kind, a.value, a.scan, a.theme), ("quick", "lan", "10.0.0.1", "ping", "ocean"))
        for cmd in ("interfaces", "wifi", "usb", "doctor", "session", "gui", "shell", "bluetooth", "all"):
            self.assertEqual(p.parse_args([cmd]).cmd, cmd)
        self.assertEqual(p.parse_args(["ports", "x", "-p", "all", "--type", "syn"]).type, "syn")

    def test_reports(self):
        core.emit(core.parse_nmap(NMAP_XML, "t"))
        with tempfile.TemporaryDirectory() as d:
            base = core.write_reports("pdf,csv,json", "unit", "light", d)
            self.assertTrue((base / "report.pdf").stat().st_size > 1000)
            self.assertTrue((base / "all_results.csv").exists() and (base / "results.json").exists())
            self.assertEqual(json.loads((base / "results.json").read_text())["tool"], "IUK-NetScope")

    def test_deps(self):
        rows = core.check_deps()
        self.assertTrue(rows and all({"name", "pkg", "required", "found"} <= set(r) for r in rows))

    def test_sweep_guards(self):
        errs = []
        with mock.patch.object(core, "err", errs.append), mock.patch.object(core, "iface_subnet", lambda n: "127.0.0.0/8"):
            self.assertEqual(core.sweep("lo", core.Ctl()), [])
        self.assertTrue(any("loopback" in e for e in errs))
        errs.clear()
        with mock.patch.object(core, "err", errs.append), mock.patch.object(core, "find_exe", lambda n: "/usr/bin/nmap"):
            self.assertEqual(core.nmap_collect("x", ["10.0.0.0/8"], ["-sn"]), [])
        self.assertTrue(any("covers" in e for e in errs))

    def test_legacy_console_encoding(self):
        """A cp1252 console (Windows default) must not crash when tables with box characters are printed."""
        import io
        raw = io.BytesIO()
        fake = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        with mock.patch.object(sys, "stdout", fake):
            core.fix_stdio()
            core.render(core.T("Test \u258c title", ["A", "B"], [["x", "\u2502"]]))
            sys.stdout.flush()
        self.assertIn(b"Test", raw.getvalue())

    def test_cancel(self):
        c = core.Ctl()
        c.cancel()
        with self.assertRaises(core.Cancelled):
            c.check()


class WindowsParserTests(unittest.TestCase):
    """Windows backends, fed with canned netsh / arp / ping / PowerShell output (runs on any OS)."""
    WIFI = """Interface name : Wi-Fi \nThere are 2 networks currently visible. \n\nSSID 1 : HomeNet \n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP \n    BSSID 1                 : aa:bb:cc:dd:ee:01\n         Signal             : 88%  \n         Radio type         : 802.11ac\n         Channel            : 36 \n    BSSID 2                 : aa:bb:cc:dd:ee:02\n         Signal             : 40%  \n         Channel            : 6 \n\nSSID 2 : \n    Network type            : Infrastructure\n    Authentication          : Open\n    BSSID 1                 : 11:22:33:44:55:66\n         Signal             : 20%\n         Channel            : 1\n"""
    IFACES = """There is 1 interface on the system:\n\n    Name                   : Wi-Fi\n    Description            : Intel(R) Wi-Fi 6\n    State                  : connected\n    SSID                   : HomeNet\n    BSSID                  : aa:bb:cc:dd:ee:01\n    Signal                 : 88%\n    Receive rate (Mbps)    : 866\n"""
    ARP = """Interface: 192.168.1.5 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"""
    PING = """Pinging 8.8.8.8 with 32 bytes of data:\nReply from 8.8.8.8: bytes=32 time=12ms TTL=117\nReply from 8.8.8.8: bytes=32 time<1ms TTL=117\n\nPing statistics for 8.8.8.8:\n    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 0ms, Maximum = 12ms, Average = 6ms\n"""

    def fake_run(self, cmd, timeout=60):
        text = {"arp": self.ARP, "ping": self.PING}.get(cmd[0], "")
        if cmd[0] == "netsh":
            text = self.WIFI if cmd[3] == "networks" else self.IFACES
        return 0, text, ""

    def fake_ps(self, script, timeout=45):
        if "Get-NetAdapter" in script:
            return [dict(Name="Wi-Fi", InterfaceDescription="Intel(R) Wi-Fi 6", Status="Up", MacAddress="AA-BB-CC-00-11-22", LinkSpeed="866 Mbps", PhysicalMediaType="Native 802.11", InterfaceIndex=7, MtuSize=1500),
                    dict(Name="Ethernet", InterfaceDescription="Realtek PCIe GbE", Status="Disconnected", MacAddress="AA-BB-CC-00-11-33", LinkSpeed="0 bps", PhysicalMediaType="802.3", InterfaceIndex=3, MtuSize=1500),
                    dict(Name="vEthernet (WSL)", InterfaceDescription="Hyper-V Virtual Ethernet Adapter", Status="Up", MacAddress="00-15-5D-00-00-01", LinkSpeed="10 Gbps", PhysicalMediaType="Unspecified", InterfaceIndex=9, MtuSize=1500)]
        if "Get-NetIPAddress" in script:
            return [dict(InterfaceIndex=7, IPAddress="192.168.1.5", PrefixLength=24, AddressFamily=2),
                    dict(InterfaceIndex=7, IPAddress="fe80::1", PrefixLength=64, AddressFamily=23),
                    dict(InterfaceIndex=7, IPAddress="2001:db8::5", PrefixLength=64, AddressFamily=23)]
        if "Get-NetRoute" in script:
            return [dict(InterfaceAlias="Wi-Fi", NextHop="192.168.1.1")]
        if "USB" in script:
            return [dict(FriendlyName="USB Composite Device", Manufacturer="(Standard)", InstanceId="USB\\VID_8087&PID_0024\\5&abc&0&1", Class="USB", Status="OK"),
                    dict(FriendlyName="Flash Drive", Manufacturer="SanDisk", InstanceId="USB\\VID_0781&PID_5581\\4C530001", Class="USB", Status="OK")]
        if "Bluetooth" in script:
            return [dict(FriendlyName="Intel(R) Wireless Bluetooth(R)", Status="OK", InstanceId="USB\\VID_8087&PID_0033\\5&1"),
                    dict(FriendlyName="Headset", Status="OK", InstanceId="BTHENUM\\DEV_001122334455\\7&2")]
        return []

    def setUp(self):
        self.p = [mock.patch.object(core, "IS_WIN", True), mock.patch.object(core, "run", self.fake_run),
                  mock.patch.object(core, "ps_json", self.fake_ps)]
        for p in self.p: p.start()

    def tearDown(self):
        for p in self.p: p.stop()

    def test_wifi(self):
        rows = core.t_wifi()["rows"]
        self.assertEqual(len(rows), 3)
        top = rows[0]
        self.assertEqual((top[0], top[1], top[2], top[3], top[6], top[8]), ("yes", "HomeNet", "aa:bb:cc:dd:ee:01", "36", "88", "WPA2-Personal"))
        self.assertEqual(core.band(top[4]), "5 GHz")
        self.assertEqual(rows[1][0], "no")
        self.assertEqual(rows[-1][1], "<hidden>")

    def test_interfaces(self):
        by = {r[0]: r for r in core.t_interfaces()["rows"]}
        self.assertEqual(by["Wi-Fi"][1:5], ["wifi", "up", "aa:bb:cc:00:11:22", "192.168.1.5/24"])
        self.assertEqual(by["Wi-Fi"][5], "2001:db8::5/64")
        self.assertIn("SSID: HomeNet", by["Wi-Fi"][9])
        self.assertEqual(by["Ethernet"][1], "ethernet")
        self.assertEqual(by["vEthernet (WSL)"][1], "virtual")

    def test_subnet_gateway(self):
        self.assertEqual(core.local_subnet(), "192.168.1.0/24")
        self.assertEqual(core.iface_gateway("Wi-Fi"), "192.168.1.1")
        self.assertEqual(core.wifi_iface("HomeNet"), "Wi-Fi")

    def test_arp(self):
        self.assertEqual(core.t_neighbors()["rows"], [["192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.5", "dynamic"]])

    def test_ping(self):
        summ, reps = core.t_ping("8.8.8.8", 2)
        r = summ["rows"][0]
        self.assertEqual((r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[9]), ("8.8.8.8", "2", "2", "0", "0", "6", "12", "117"))
        self.assertEqual(len(reps["rows"]), 2)

    def test_usb_bluetooth(self):
        usb = core.t_usb()["rows"]
        self.assertEqual(usb[0][3], "8087:0024")
        self.assertEqual(usb[1][10], "4C530001")
        ctl, dev = core.t_bluetooth()
        self.assertEqual(dev["rows"][0][0], "00:11:22:33:44:55")
        self.assertEqual(len(ctl["rows"]), 1)

    def test_choices(self):
        ch = core.discover_choices("interface")
        self.assertTrue(any(v == "Wi-Fi" for _, v in ch))


if __name__ == "__main__":
    unittest.main()
