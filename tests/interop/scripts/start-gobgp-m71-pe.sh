#!/bin/sh
# M71 PE (GoBGP) startup — control-plane only.
#
# Unlike the M65 single-active PE (start-gobgp-sa-pe.sh), the M71 PE has
# no CE attachment circuit or VXLAN dataplane: it is purely the EVPN
# route source for the rustbgpd VTEP's ESI overlay-index Type 5 receive
# proof. All EVPN route state (the ESI overlay Type 5 and the Type 1
# EAD-per-ES / EAD-per-EVI rows) is injected/withdrawn by the test
# driver through the gobgp CLI; gobgpd only speaks BGP here.

set -eu

# Start gobgpd. nohup + & so the exec returns immediately and
# `sleep infinity` (the container's PID 1) keeps the netns alive.
nohup gobgpd -f /config/gobgp.toml \
    >/var/log/gobgpd.log 2>&1 &

# Tiny pause so the first `docker exec pe gobgp ...` finds gobgpd up.
sleep 1
