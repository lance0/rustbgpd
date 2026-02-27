#!/bin/sh
set -e

# Configure interface IP (passed as env vars by containerlab exec or entrypoint)
if [ -n "$IFACE" ] && [ -n "$ADDR" ]; then
    ip addr add "$ADDR" dev "$IFACE"
    ip link set "$IFACE" up
fi

exec /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml
