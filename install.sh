#!/usr/bin/env bash
# IUK-NetScope installer for Kubuntu / Ubuntu / Debian: installs nmap + every dependency, adds a menu entry.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
REQUIRED="nmap python3 python3-tk python3-reportlab iproute2 iputils-ping"
OPTIONAL="dnsutils network-manager iw bluez usbutils pkexec libnotify-bin"
echo "==> Installing dependencies (needs sudo)"
sudo apt-get update
# shellcheck disable=SC2086
sudo apt-get install -y $REQUIRED
for p in $OPTIONAL; do
  if sudo apt-get install -y "$p" >/dev/null 2>&1; then echo "   + $p"; else echo "   - $p (not available, skipped)"; fi
done
echo "==> Installing launcher"
mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/256x256/apps
ln -sf "$PWD/packaging/iuk-netscope" ~/.local/bin/iuk-netscope
cp icon.png ~/.local/share/icons/hicolor/256x256/apps/iuk-netscope.png
sed "s|^Exec=.*|Exec=$PWD/packaging/iuk-netscope|" packaging/iuk-netscope.desktop > ~/.local/share/applications/iuk-netscope.desktop
update-desktop-database ~/.local/share/applications 2>/dev/null || true
echo "==> Done. Start 'IUK-NetScope' from the application menu, or run: iuk-netscope"
