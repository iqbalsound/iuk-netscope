#!/usr/bin/env bash
# Builds dist/iuk-netscope-<version>-1.noarch.rpm  (needs the `rpm` package: sudo apt install rpm  /  dnf install rpm-build)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
V="$(python3 packaging/version.py)"
TOP="$PWD/build/rpm"
rm -rf "$TOP"; mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT} dist
STAGE="build/rpm-stage/iuk-netscope-$V"
rm -rf build/rpm-stage; mkdir -p "$STAGE"
cp iuk_netscope.py iuk_netscope_gui.py icon.png LICENSE packaging/iuk-netscope packaging/iuk-netscope.desktop "$STAGE/"
tar -C build/rpm-stage -czf "$TOP/SOURCES/iuk-netscope-$V.tar.gz" "iuk-netscope-$V"
cp packaging/iuk-netscope.spec "$TOP/SPECS/"
rpmbuild -bb --define "_topdir $TOP" --define "ver $V" "$TOP/SPECS/iuk-netscope.spec"
cp "$TOP"/RPMS/noarch/iuk-netscope-*.rpm dist/
ls -1 dist/*.rpm
