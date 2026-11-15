# Changelog

## v0.0.1 - first tracked release
- Desktop app: resizable window, live Activity view, result tabs, 4 themes, adjustable text size, Stop button.
- Scans run in background threads; desktop notification when finished.
- Quick Scan for a network interface, LAN IP, Bluetooth device or Wi-Fi SSID.
- nmap declared as a dependency (DEB/RPM `Depends`, installer, in-app check, winget on Windows).
- CLI: interfaces, wifi, bluetooth, usb, ping, nslookup, arp, ports, osscan, scan, quick, doctor, report.
- PDF / CSV / JSON reports.
- Packaging: DEB, RPM and Windows EXE via GitHub Actions; unit + GUI smoke tests.
- Safety: sweep size limits, authorisation prompt for non-private targets.
