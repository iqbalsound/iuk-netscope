#!/usr/bin/env bash
# Builds dist/iuk-netscope_<version>_all.deb  (apt installs nmap and the other dependencies automatically)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
V="$(python3 packaging/version.py)"
PKG="iuk-netscope_${V}_all"
B="build/deb/$PKG"
rm -rf "build/deb"; mkdir -p "$B/DEBIAN" "$B/opt/iuk-netscope" "$B/usr/bin" "$B/usr/share/applications" "$B/usr/share/icons/hicolor/256x256/apps" dist
install -m 755 iuk_netscope.py iuk_netscope_gui.py "$B/opt/iuk-netscope/"
install -m 644 icon.png "$B/opt/iuk-netscope/icon.png"
install -m 755 packaging/iuk-netscope "$B/usr/bin/iuk-netscope"
install -m 644 packaging/iuk-netscope.desktop "$B/usr/share/applications/iuk-netscope.desktop"
install -m 644 icon.png "$B/usr/share/icons/hicolor/256x256/apps/iuk-netscope.png"
cat > "$B/DEBIAN/control" << CTL
Package: iuk-netscope
Version: $V
Section: net
Priority: optional
Architecture: all
Maintainer: Iqbal Uddin Khan
Depends: python3 (>= 3.8), python3-tk, python3-reportlab, nmap, iproute2, iputils-ping
Recommends: dnsutils, network-manager, iw, bluez, usbutils, pkexec | policykit-1, libnotify-bin
Description: Wi-Fi, Bluetooth, USB and network scanner with nmap
 Desktop app and CLI by Iqbal Uddin Khan: interface discovery, ping, nslookup,
 ARP sweep, port and OS scans, built-in quick scans, PDF/CSV reports.
 Use only on networks you own or are authorised to test.
CTL
dpkg-deb --build --root-owner-group "$B" "dist/$PKG.deb"
echo "Built dist/$PKG.deb"
