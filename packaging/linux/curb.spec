Name:           curb
Version:        %{?_version}%{!?_version:0.4.5}
Release:        1%{?dist}
Summary:        Default-deny application internet limiter
License:        AGPL-3.0-or-later
URL:            https://github.com/OceanEilonwy/curb
Requires:       nftables
Requires:       polkit
Requires:       fontconfig

%description
Curb blocks all outbound traffic by default at the OS firewall (nftables +
NFQUEUE) and allows only explicitly approved apps, games, and DNS whitelists.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/libexec/curb
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor/128x128/apps
mkdir -p %{buildroot}/usr/share/icons/hicolor/32x32/apps
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps
mkdir -p %{buildroot}/usr/share/polkit-1/actions
mkdir -p %{buildroot}/usr/share/doc/curb

install -m 0755 %{_sourcedir}/curb-app %{buildroot}/usr/bin/curb-app
install -m 0755 %{_sourcedir}/curb-cli %{buildroot}/usr/bin/curb-cli
install -m 0755 %{_sourcedir}/curb-service %{buildroot}/usr/libexec/curb/curb-service
install -m 0644 %{_sourcedir}/curb.service %{buildroot}/usr/lib/systemd/system/curb.service
install -m 0644 %{_sourcedir}/curb.desktop %{buildroot}/usr/share/applications/curb.desktop
install -m 0644 %{_sourcedir}/org.curb.policy %{buildroot}/usr/share/polkit-1/actions/org.curb.policy
install -m 0644 %{_sourcedir}/icon-128.png %{buildroot}/usr/share/icons/hicolor/128x128/apps/curb.png
install -m 0644 %{_sourcedir}/icon-32.png %{buildroot}/usr/share/icons/hicolor/32x32/apps/curb.png
install -m 0644 %{_sourcedir}/icon.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/curb.svg
install -m 0644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/doc/curb/LICENSE
install -m 0644 %{_sourcedir}/README.md %{buildroot}/usr/share/doc/curb/README.md

%post
command -v curb-cli >/dev/null 2>&1 && curb-cli upgrade >/dev/null 2>&1 || true

%preun
if [ "$1" -eq 0 ]; then
    command -v curb-cli >/dev/null 2>&1 && curb-cli uninstall >/dev/null 2>&1 || true
fi

%files
/usr/bin/curb-app
/usr/bin/curb-cli
/usr/libexec/curb/curb-service
/usr/lib/systemd/system/curb.service
/usr/share/applications/curb.desktop
/usr/share/icons/hicolor/128x128/apps/curb.png
/usr/share/icons/hicolor/32x32/apps/curb.png
/usr/share/icons/hicolor/scalable/apps/curb.svg
/usr/share/polkit-1/actions/org.curb.policy
%doc /usr/share/doc/curb/README.md
%license /usr/share/doc/curb/LICENSE
