Name:           curb-relay
Version:        %{?_version}%{!?_version:0.4.7}
Release:        1%{?dist}
Summary:        Zero-knowledge P2P relay and encrypted backup server for Curb
License:        AGPL-3.0-or-later
URL:            https://github.com/OceanEilonwy/curb

%description
Self-hostable zero-knowledge P2P rendezvous relay proxy and optional
end-to-end encrypted settings backup server for Curb.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/share/doc/curb-relay

install -m 0755 %{_sourcedir}/curb-relay %{buildroot}/usr/bin/curb-relay
install -m 0644 %{_sourcedir}/curb-relay.service %{buildroot}/usr/lib/systemd/system/curb-relay.service
install -m 0644 %{_sourcedir}/curb-relay.env.example %{buildroot}/usr/share/doc/curb-relay/curb-relay.env.example
install -m 0644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/doc/curb-relay/LICENSE
install -m 0644 %{_sourcedir}/README.md %{buildroot}/usr/share/doc/curb-relay/README.md

%post
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%preun
if [ "$1" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable --now curb-relay.service >/dev/null 2>&1 || true
    fi
fi

%files
/usr/bin/curb-relay
/usr/lib/systemd/system/curb-relay.service
%doc /usr/share/doc/curb-relay/curb-relay.env.example
%doc /usr/share/doc/curb-relay/README.md
%license /usr/share/doc/curb-relay/LICENSE
