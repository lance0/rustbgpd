#!/bin/sh
# Create the rustbgpd service user before payload extraction so the
# packaged file ownership (root:rustbgpd on /etc/rustbgpd) resolves.
set -e

getent group rustbgpd >/dev/null 2>&1 || groupadd --system rustbgpd
getent passwd rustbgpd >/dev/null 2>&1 || useradd --system \
    --gid rustbgpd \
    --home-dir /var/lib/rustbgpd \
    --no-create-home \
    --shell /usr/sbin/nologin \
    rustbgpd

exit 0
