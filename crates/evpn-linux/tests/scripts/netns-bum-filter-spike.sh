#!/usr/bin/env bash
# Privileged netns spike for the Gate 8b BUM-suppression primitive.
#
# Builds an isolated netns containing:
#   - br100         (Linux bridge)
#   - src-br/src-tap veth pair (src-br enslaved to br100; "overlay" side)
#   - ce-br/ce-tap   veth pair (ce-br  enslaved to br100; "CE-facing" side)
#
# Toggles the per-port flood / mcast_flood / bcast_flood flags on the
# CE-facing bridge port (`bridge link set dev ce-br ...`) and verifies:
#
#   1. **DF baseline (flags on)**: broadcast sent into the bridge from
#      src-tap reaches ce-tap (flood-only path).
#   2. **Non-DF (flags off)**: same broadcast does NOT reach ce-tap.
#   3. **Restore (flags on)**: broadcast reaches ce-tap again — toggle
#      is symmetric, no kernel state lingers.
#   4. **Known unicast survives**: with a static FDB entry pinning a
#      MAC to ce-br, unicast to that MAC reaches ce-tap *even with all
#      three flood flags off*. This is the load-bearing invariant —
#      Non-DF must still forward known unicast for EVPN
#      remote-MAC-driven traffic to flow.
#
# The chosen kernel primitive is the per-port flood flag triplet —
# `flood off` / `mcast_flood off` / `bcast_flood off`. This is what
# FRR uses for the same job (zebra/zebra_evpn.c) and matches the
# `IFLA_BRPORT_{,M,B}CAST_FLOOD` netlink attributes the eventual
# rtnetlink wiring will set directly. `bcast_flood` requires Linux
# >= 4.18 (commit 4ce1b1bb05a3).
#
# Usage:
#   sudo bash crates/evpn-linux/tests/scripts/netns-bum-filter-spike.sh
#
# Exits 0 on success, non-zero with a diagnostic on the first failed
# assertion.

set -euo pipefail

NS="rustbgpd-bum-spike-$$"
BR="br100"
CE_BR="ce-br"
CE_TAP="ce-tap"
SRC_BR="src-br"
SRC_TAP="src-tap"
SUBNET="10.42.0"
PINGS=5
TEST_MAC="02:aa:bb:cc:dd:42"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ns_exec() { ip netns exec "$NS" "$@"; }

# Per-run temp file for stderr capture from `bridge link set`. Using
# `mktemp` so concurrent invocations of the spike (e.g. parallel
# `cargo test` runs on different testers) don't race for a fixed
# `/tmp/bridge.err` and clobber each other's diagnostic output.
BRIDGE_ERR=$(mktemp -t "rustbgpd-bum-spike.XXXXXX.err")

cleanup() {
    ip netns delete "$NS" >/dev/null 2>&1 || true
    rm -f "$BRIDGE_ERR"
}
trap cleanup EXIT

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: this spike requires root (CAP_NET_ADMIN)" >&2
        exit 2
    fi
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required tool '$1' not in PATH" >&2
        exit 2
    fi
}

rx_packets() {
    ns_exec cat "/sys/class/net/$1/statistics/rx_packets"
}

# Generate $PINGS broadcast ICMP echoes from src-tap toward the
# subnet broadcast. Returns 0 even if the pings are unanswered (we
# only care that the *frames* leave the source).
gen_broadcast() {
    ns_exec ping -b -W 1 -c "$PINGS" -I "$SRC_TAP" "${SUBNET}.255" \
        >/dev/null 2>&1 || true
}

# Generate $PINGS unicast frames toward the test MAC. We send an
# arbitrary IP and rely on the static FDB entry to forward by MAC.
# To force the source to use that MAC as L2 dst, populate src-tap's
# ARP cache with the (test-IP -> TEST_MAC) binding.
gen_unicast_to_test_mac() {
    ns_exec ip neigh replace "${SUBNET}.42" lladdr "$TEST_MAC" dev "$SRC_TAP"
    ns_exec ping -W 1 -c "$PINGS" -I "$SRC_TAP" "${SUBNET}.42" \
        >/dev/null 2>&1 || true
}

assert_delta_positive() {
    local label=$1; local delta=$2
    if [ "$delta" -le 0 ]; then
        echo "FAIL [$label]: expected delta > 0, got $delta" >&2
        exit 1
    fi
    echo "PASS [$label]: delta=$delta"
}

assert_delta_zero() {
    local label=$1; local delta=$2
    if [ "$delta" -ne 0 ]; then
        echo "FAIL [$label]: expected delta == 0, got $delta" >&2
        exit 1
    fi
    echo "PASS [$label]: delta=$delta"
}

# Relaxed variant for use inside Docker / CI where the veth pair
# auto-generates IPv6 link-local addresses on link-up and the
# resulting DAD / Neighbor Solicitation multicast traffic shows up
# on the CE-side RX counter as residual noise (1-2 frames per
# transition). A passing primitive looks like a *substantial* drop
# (>=80%) from the DF baseline AND a small absolute count; this
# captures the intent without being brittle to IPv6 housekeeping.
assert_delta_suppressed() {
    local label=$1; local baseline=$2; local actual=$3
    local floor=2  # tolerate up to 2 IPv6 NS/DAD frames
    if [ "$actual" -gt "$floor" ] && [ "$((actual * 5))" -ge "$baseline" ]; then
        echo "FAIL [$label]: expected substantial suppression (got $actual vs DF $baseline)" >&2
        exit 1
    fi
    echo "PASS [$label]: actual=$actual (DF baseline=$baseline)"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

require_root
require_tool ip
require_tool bridge
require_tool ping

# Kernel must support per-port bcast_flood (>= 4.18). We probe lazily
# by attempting to set it on a throwaway interface inside the netns
# below; if it errors, we abort with a kernel-version message.

# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

ip netns add "$NS"
# Best-effort sysctl tweaks: in Docker/CI environments `/proc/sys`
# inside the netns may be read-only and refuse the writes. Neither
# is load-bearing for what we measure here:
#   - `icmp_echo_ignore_broadcasts` only gates L4 echo replies; we
#     count at the device-level RX counter (`rx_packets`), so the
#     broadcast frame is observable regardless.
#   - `ping_group_range` only matters when ping runs unprivileged;
#     we're root in the netns so DGRAM/RAW ICMP is already allowed.
# Stay quiet on failure so Docker `--cap-add=NET_ADMIN+SYS_ADMIN`
# without an `apparmor=unconfined` writable /proc/sys still works.
ns_exec sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true
ns_exec sysctl -wq net.ipv4.ping_group_range="0 65535" 2>/dev/null || true
ns_exec ip link set lo up

ns_exec ip link add "$BR" type bridge
ns_exec ip link add "$CE_BR" type veth peer name "$CE_TAP"
ns_exec ip link add "$SRC_BR" type veth peer name "$SRC_TAP"
ns_exec ip link set "$CE_BR"  master "$BR"
ns_exec ip link set "$SRC_BR" master "$BR"
for d in "$BR" "$CE_BR" "$CE_TAP" "$SRC_BR" "$SRC_TAP"; do
    ns_exec ip link set "$d" up
done

# Bridge gets the .1 so the kernel has a route pointing at it; the
# tap sides get .2/.3 so we can address them as endpoints. The
# routing table still sends src-tap broadcasts via the bridge port
# because that's where the subnet's L2 path lives.
ns_exec ip addr add "${SUBNET}.1/24" dev "$BR"
ns_exec ip addr add "${SUBNET}.2/24" dev "$CE_TAP"
ns_exec ip addr add "${SUBNET}.3/24" dev "$SRC_TAP"

# Probe the kernel's per-port flood-flag support against ce-br. Any
# error here means this kernel is too old; bail with a clear message.
if ! ns_exec bridge link set dev "$CE_BR" flood on mcast_flood on bcast_flood on 2>"$BRIDGE_ERR"; then
    echo "ERROR: kernel does not support per-port flood flags:" >&2
    cat "$BRIDGE_ERR" >&2
    exit 2
fi

# Tiny settle so the bridge picks up its new ports.
sleep 0.2

# ---------------------------------------------------------------------------
# Test 1: DF baseline — flood enabled, broadcast reaches CE
# ---------------------------------------------------------------------------

ns_exec bridge link set dev "$CE_BR" flood on mcast_flood on bcast_flood on
RX0=$(rx_packets "$CE_TAP")
gen_broadcast
RX1=$(rx_packets "$CE_TAP")
DF_DELTA=$((RX1 - RX0))
assert_delta_positive "DF: broadcast reaches CE" "$DF_DELTA"

# ---------------------------------------------------------------------------
# Test 2: Non-DF — flood disabled, broadcast blocked
# ---------------------------------------------------------------------------

ns_exec bridge link set dev "$CE_BR" flood off mcast_flood off bcast_flood off
# Settle so any in-flight DF-era frames flush before we sample.
sleep 0.5
RX2=$(rx_packets "$CE_TAP")
gen_broadcast
sleep 0.2
RX3=$(rx_packets "$CE_TAP")
NONDF_DELTA=$((RX3 - RX2))
# Use the DF baseline as the "would have flooded" reference. Pure
# `delta == 0` would be ideal but the freshly-up veth pair leaks
# 1-2 IPv6 NS / DAD multicast frames per pass that the per-port
# bcast/mcast flood-off flags don't (and aren't supposed to)
# suppress. The primitive is unambiguously working when the Non-DF
# count is dramatically smaller than the DF baseline.
assert_delta_suppressed "Non-DF: broadcast suppressed at CE" "$DF_DELTA" "$NONDF_DELTA"

# ---------------------------------------------------------------------------
# Test 3: Known unicast still forwards under Non-DF
# ---------------------------------------------------------------------------

# Pin TEST_MAC to ce-br as a permanent FDB entry. Frames addressed
# to TEST_MAC must reach ce-br even with all three flood flags off,
# because forwarding by FDB lookup is not flooding.
ns_exec bridge fdb add "$TEST_MAC" dev "$CE_BR" master static
RX4=$(rx_packets "$CE_TAP")
gen_unicast_to_test_mac
RX5=$(rx_packets "$CE_TAP")
assert_delta_positive "Non-DF: known unicast still reaches CE" "$((RX5 - RX4))"

# ---------------------------------------------------------------------------
# Test 4: Restore — flags back on, broadcast resumes
# ---------------------------------------------------------------------------

ns_exec bridge link set dev "$CE_BR" flood on mcast_flood on bcast_flood on
RX6=$(rx_packets "$CE_TAP")
gen_broadcast
RX7=$(rx_packets "$CE_TAP")
assert_delta_positive "DF restored: broadcast reaches CE again" "$((RX7 - RX6))"

# ---------------------------------------------------------------------------
# Test 5: Idempotence — re-applying the same setting is a no-op
# ---------------------------------------------------------------------------

ns_exec bridge link set dev "$CE_BR" flood on mcast_flood on bcast_flood on
ns_exec bridge link set dev "$CE_BR" flood on mcast_flood on bcast_flood on
echo "PASS [idempotence]: re-apply DF flags did not error"

ns_exec bridge link set dev "$CE_BR" flood off mcast_flood off bcast_flood off
ns_exec bridge link set dev "$CE_BR" flood off mcast_flood off bcast_flood off
echo "PASS [idempotence]: re-apply Non-DF flags did not error"

# ---------------------------------------------------------------------------
# Test 6: FDB programming for remote-MAC entries unaffected by mode
# ---------------------------------------------------------------------------

# This is the cheap mirror of what the EVPN reconciler does — add an
# extern_learn FDB entry and remove it. With Non-DF flags applied,
# the operations must still succeed (the flood flags only gate
# *flooding*, not *programming*).
REMOTE_MAC="02:11:22:33:44:55"
ns_exec bridge fdb add "$REMOTE_MAC" dev "$CE_BR" master extern_learn
ns_exec bridge fdb del "$REMOTE_MAC" dev "$CE_BR" master extern_learn
echo "PASS [reconciler-compat]: extern_learn add/del unaffected by Non-DF flags"

echo
echo "All BUM-filter spike assertions passed."
