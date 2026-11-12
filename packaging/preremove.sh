#!/bin/sh
# Stop and disable rustbgpd on a real removal (deb `remove`, rpm $1=0),
# before the payload goes, so ExecStopPost still finds /usr/bin/rustbgpd and
# releases any EVPN core-isolation links. An upgrade (deb `upgrade`, rpm
# $1=1) leaves a running daemon alone; postinstall says to restart it.
set -e

case "$1" in
    remove|0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl stop rustbgpd.service 'rustbgpd@*.service' || true
fi
# Disabling the template also removes each instance's enablement link.
systemctl --no-reload disable rustbgpd.service 'rustbgpd@.service' \
    >/dev/null 2>&1 || true

exit 0
