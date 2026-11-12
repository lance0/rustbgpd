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

active=
if [ -n "$upgrade" ] && [ -d /run/systemd/system ]; then
    active=$(systemctl list-units --plain --no-legend --state=active \
        rustbgpd.service 'rustbgpd@*.service' 2>/dev/null | awk '{ print $1 }')
fi

if [ -n "$active" ]; then
    # Deliberate: the package never restarts a routing daemon.
    echo "rustbgpd upgraded, but these units were not restarted and still run the"
    echo "old binary; restart required to load the new binary. For each unit, check"
    echo "the config it runs, then restart that unit:"
    for unit in $active; do
        # The config is the last argument of the unit's ExecStart.
        config=$(systemctl show -P ExecStart "$unit" 2>/dev/null |
            sed -n 's/.*argv\[\]=\([^;]*\) ;.*/\1/p' | awk '{ print $NF }')
        echo "  $unit:"
        echo "    /usr/bin/rustbgpd --check --strict ${config:-<its config>}"
        echo "    systemctl restart $unit"
    done
    echo "Then check that 'rbgp health' on each unit's API (--addr for a template"
    echo "instance) reports the package version."
elif [ -n "$upgrade" ]; then
    echo "rustbgpd upgraded. It is not running; start it with: systemctl start rustbgpd"
else
    echo "rustbgpd installed. Edit /etc/rustbgpd/config.toml (ASN, router_id,"
    echo "neighbors), then: systemctl enable --now rustbgpd"
fi

exit 0
