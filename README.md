# IUK-NetScope v0.0.1

Wi-Fi, Bluetooth, USB and Ethernet discovery + nmap-powered scanning, by **Iqbal Uddin Khan**.
Desktop app and CLI. Reports as PDF / CSV / JSON. Themes: `dark` `matrix` `light` `ocean`.

> Use only on networks and devices you own or have written permission to test.

## Install
| Platform | How |
|---|---|
| Kubuntu / Ubuntu / Debian | `sudo apt install ./iuk-netscope_0.0.1_all.deb` (apt pulls in **nmap** and everything else) |
| Fedora / RHEL / Rocky | `sudo dnf install ./iuk-netscope-0.0.1-1.noarch.rpm` |
| Windows 10/11 | unzip `IUK-NetScope-0.0.1-windows-x64.zip`, run `IUK-NetScope.exe`. nmap is required: `winget install -e --id Insecure.Nmap` (the app offers to do it). |
| From source (Linux) | `./install.sh` |

All files are on the **Releases** page. Missing a component? App: *Tools > Check / install dependencies*; CLI: `iuk-netscope doctor`.

## Desktop app (`iuk-netscope`, or the IUK-NetScope menu entry)
* **Quick Scan**: choose what to scan (network interface / LAN IP / Bluetooth device / Wi-Fi SSID), pick one, pick a built-in scan, Start.
* **Activity** tab (centre): live log of every command; results open as sortable, filterable tabs.
* Resizable; scans keep running while minimised; notification when finished. Text size: Ctrl +, Ctrl -, Ctrl 0.
* Admin rights (OS detection, SYN/UDP, ARP sweep): Linux - tick *Use admin rights* (polkit prompt); Windows - right-click > *Run as administrator*.

## CLI
```bash
iuk-netscope quick                      # list built-in scans
iuk-netscope --sudo quick interface wlan0 --scan discover
iuk-netscope --sudo --report pdf,csv scan 192.168.1.0/24 --profile aggressive
iuk-netscope all | ping 8.8.8.8 | nslookup example.com | arp | doctor
```
Global options (`--theme --font-size --sudo --yes --report`) go before the command.

## Platform notes
Linux is the primary platform. The Windows build uses `netsh`, PowerShell, `arp` and `ping`
instead of `ip`/`nmcli`/BlueZ: it lists paired (not nearby) Bluetooth devices, and ping parsing assumes an
English Windows. Safety limits: auto-sweeps are capped at a /20, any CIDR target at 65,536 addresses.

## Develop
```bash
python3 -m unittest discover -s tests -v          # unit tests (also run on Windows in CI)
xvfb-run -a python3 tests/gui_smoke.py            # headless GUI test
bash packaging/build_deb.sh && bash packaging/build_rpm.sh     # -> dist/
```
The version lives only in `iuk_netscope.py` (`__version__`); packages and the release tag are checked against it.

## Publish to GitHub over SSH
```bash
# one-time: SSH key + GitHub
ssh-keygen -t ed25519 -C "you@example.com"          # press Enter for defaults
cat ~/.ssh/id_ed25519.pub                            # GitHub > Settings > SSH and GPG keys > New SSH key
ssh -T git@github.com                                # expect: "Hi <user>! You've successfully authenticated"

# create an EMPTY repo named iuk-netscope on github.com (no README/licence), then:
git init -b main
git config user.name  "Iqbal Uddin Khan"
git config user.email "you@example.com"
git add . && git commit -m "IUK-NetScope v0.0.1"
git remote add origin git@github.com:iqbalsound/iuk-netscope.git
git push -u origin main                              # CI workflow runs

# release: tag must equal __version__
git tag v0.0.1 && git push origin v0.0.1             # Release workflow builds + publishes .deb .rpm .exe
```
Repo setting to check once: *Settings > Actions > General > Workflow permissions* = "Read and write" (the release job also requests `contents: write` itself).
To release a new version: change `__version__`, update `CHANGELOG.md`, commit, then tag `vX.Y.Z`.
