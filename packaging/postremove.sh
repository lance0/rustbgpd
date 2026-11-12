#!/bin/sh
# Forget the removed units. /var/lib/rustbgpd, /etc/rustbgpd edits and the
# rustbgpd user stay for a reinstall.
set -e

case "$1" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
        fi
        ;;
esac

exit 0
