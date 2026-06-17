#!/bin/sh
# M72 PE (GoBGP) startup — control-plane only.
#
# The test driver injects and withdraws all EVPN route state through the
# gobgp CLI. GoBGP has no local EVPN dataplane in this proof.

set -eu

nohup gobgpd -f /config/gobgp.toml \
    >/var/log/gobgpd.log 2>&1 &

sleep 1
