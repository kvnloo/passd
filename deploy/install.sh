#!/bin/sh
set -eu
umask 022

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 2 ]; then
    echo 'Usage as root: deploy/install.sh ADMIN_USER TAILNET_IPV4:PORT or ADMIN_USER [TAILNET_IPV6]:PORT' >&2
    exit 2
fi
admin=$1
listen=$2
case "$admin" in
    -* | passd) echo 'Specify a separate administrator account' >&2; exit 2 ;;
esac
id "$admin" >/dev/null
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# Validate before touching the host. These ranges match passd.gateway.
python3 - "$listen" <<'PY'
import ipaddress
import sys

host, sep, port = sys.argv[1].rpartition(":")
try:
    if host.startswith("[") and host.endswith("]"):
        address = ipaddress.IPv6Address(host[1:-1])
    else:
        address = ipaddress.IPv4Address(host)
    if not sep or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError
    if not any(address in ipaddress.ip_network(cidr)
               for cidr in ("100.64.0.0/10", "fd7a:115c:a1e0::/48")):
        raise ValueError
except ValueError:
    sys.exit("Expected a tailnet IPv4:PORT or [IPv6]:PORT")
PY

getent group passd >/dev/null || groupadd --system passd
getent group passd-admin >/dev/null || groupadd --system passd-admin
getent passwd passd >/dev/null || useradd --system --gid passd --home-dir /var/lib/passd --shell /usr/sbin/nologin passd
usermod --append --groups passd-admin "$admin"
install -d -o passd -g passd -m 0700 /var/lib/passd

install -d -o root -g root -m 0755 /opt/passd
python3 -m venv /opt/passd
/opt/passd/bin/python -m pip install "$src"
install -o root -g root -m 0755 "$src/deploy/unlock.py" /opt/passd/bin/passd-unlock
install -d -o root -g root -m 0755 /opt/passd/readiness
install -o root -g root -m 0755 "$src/deploy/e2e-readiness.sh" /opt/passd/readiness/
install -o root -g root -m 0644 "$src/deploy/e2e_readiness.py" /opt/passd/readiness/

install -o root -g root -m 0644 "$src/deploy/passd.conf" /etc/tmpfiles.d/passd.conf
systemd-tmpfiles --create /etc/tmpfiles.d/passd.conf
install -o root -g root -m 0644 "$src/deploy/passd.service" "$src/deploy/passd-gateway.service" /etc/systemd/system/
install -o root -g root -m 0644 /dev/null /etc/passd-gateway.conf
printf 'PASSD_GATEWAY_LISTEN=%s\n' "$listen" > /etc/passd-gateway.conf
systemctl daemon-reload
systemctl enable passd.service passd-gateway.service
