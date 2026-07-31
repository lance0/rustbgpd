#!/bin/sh
set -e

# Pick up the new/changed unit when installing onto a live system.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

echo "rustbgpd installed. Edit /etc/rustbgpd/config.toml (ASN, router_id,"
echo "neighbors), then: systemctl enable --now rustbgpd"

exit 0
