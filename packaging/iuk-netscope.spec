%global debug_package %{nil}
Name:           iuk-netscope
Version:        %{ver}
Release:        1
Summary:        Wi-Fi, Bluetooth, USB and network scanner with nmap
License:        MIT
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
Requires:       python3 >= 3.8
Requires:       python3-tkinter
Requires:       python3-reportlab
Requires:       nmap
Requires:       iproute
Requires:       iputils
Recommends:     bind-utils
Recommends:     NetworkManager
Recommends:     iw
Recommends:     bluez
Recommends:     usbutils
Recommends:     polkit
Recommends:     libnotify

%description
Desktop app and CLI by Iqbal Uddin Khan: interface discovery (Wi-Fi, Bluetooth,
USB, Ethernet), ping, nslookup, ARP sweep, port and OS scans through nmap,
built-in quick scans and PDF/CSV reports. Use only on networks you own or are
authorised to test.

%prep
%setup -q

%build

%install
install -d %{buildroot}/opt/iuk-netscope %{buildroot}%{_bindir} %{buildroot}%{_datadir}/applications %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
install -m 755 iuk_netscope.py iuk_netscope_gui.py %{buildroot}/opt/iuk-netscope/
install -m 644 icon.png %{buildroot}/opt/iuk-netscope/icon.png
install -m 755 iuk-netscope %{buildroot}%{_bindir}/iuk-netscope
install -m 644 iuk-netscope.desktop %{buildroot}%{_datadir}/applications/iuk-netscope.desktop
install -m 644 icon.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/iuk-netscope.png

%files
%license LICENSE
/opt/iuk-netscope
%{_bindir}/iuk-netscope
%{_datadir}/applications/iuk-netscope.desktop
%{_datadir}/icons/hicolor/256x256/apps/iuk-netscope.png

%changelog
* Sun Nov 15 2026 Iqbal Uddin Khan - 0.0.1-1
- Initial release
