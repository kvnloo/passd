#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run deploy/uninstall.sh as root' >&2
    exit 2
fi
# Stop before removing executables, units or the FIFO.
for unit in passd-gateway.service passd.service; do
    if [ -f "/etc/systemd/system/$unit" ]; then
        systemctl disable --now "$unit"
    fi
done
rm -f /etc/systemd/system/passd.service /etc/systemd/system/passd-gateway.service
rm -f /etc/tmpfiles.d/passd.conf /etc/passd-gateway.conf
rm -rf /opt/passd /run/passd /run/passd-unlock
systemctl daemon-reload
# Keep the account, groups and encrypted data so a reinstall can reopen it.
