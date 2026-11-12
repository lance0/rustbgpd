#!/bin/sh
set -e

# Pick up the new/changed unit when installing onto a live system.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

# deb: `configure <old-version>` on upgrade; rpm: $1 counts installed
# versions, 2 or more on upgrade.
case "$1" in
    configure) upgrade=${2:+yes} ;;
    1) upgrade= ;;
    [0-9]*) upgrade=yes ;;
    *) exit 0 ;; # deb abort-upgrade, abort-remove, ...
esac

if [ -n "$upgrade" ] && systemctl is-active --quiet rustbgpd.service \
        'rustbgpd@*.service' 2>/dev/null; then
    # Deliberate: the package never restarts a routing daemon.
    echo "rustbgpd upgraded, but the running daemon was not restarted and still"
    echo "runs the old binary: restart required to load the new binary. Check the"
    echo "config with 'rustbgpd --check --strict', then: systemctl restart rustbgpd"
    echo "('rbgp health' reports the running version)."
elif [ -n "$upgrade" ]; then
    echo "rustbgpd upgraded. It is not running; start it with: systemctl start rustbgpd"
else
    echo "rustbgpd installed. Edit /etc/rustbgpd/config.toml (ASN, router_id,"
    echo "neighbors), then: systemctl enable --now rustbgpd"
fi

exit 0
