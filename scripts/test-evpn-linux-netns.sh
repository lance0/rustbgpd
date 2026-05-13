#!/usr/bin/env bash
# Run the privileged EVPN Linux netns integration tests.
#
# This is the host-side convenience wrapper for the tests gated by
# EVPN_LINUX_NETNS=1. It intentionally runs the test binaries
# sequentially because they create network namespaces and re-exec into
# them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "ERROR: $*" >&2
    exit 2
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "missing required tool '$1'. Install iproute2/iputils and make sure cargo is in PATH."
    fi
}

if [ "$(uname -s)" != "Linux" ]; then
    die "EVPN Linux netns tests require Linux; current system is $(uname -s)"
fi

require_tool cargo
require_tool ip
require_tool bridge
require_tool ping

if [ ! -f "$REPO_ROOT/Cargo.toml" ]; then
    die "could not locate workspace Cargo.toml at $REPO_ROOT/Cargo.toml"
fi

probe_ns="rustbgpd-netns-preflight-$$"
cleanup_probe() {
    ip netns delete "$probe_ns" >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT

if ! preflight_out="$(ip netns add "$probe_ns" 2>&1)"; then
    cat >&2 <<EOF
ERROR: unable to create a network namespace.

These tests require CAP_NET_ADMIN and CAP_SYS_ADMIN. Run from a
privileged shell, for example:

  sudo -E env "PATH=$PATH" bash scripts/test-evpn-linux-netns.sh

ip netns add output:
$preflight_out
EOF
    exit 2
fi

if ! ip -n "$probe_ns" link set lo up >/dev/null 2>&1; then
    die "created a netns but could not configure it; check CAP_NET_ADMIN / AppArmor restrictions"
fi
cleanup_probe
trap - EXIT

tests=(
    "netns_bum_filter:BUM port-flag primitive"
    "netns_dataplane:single-dst VTEP FDB path"
    "netns_l3_install:L3 route/neighbor/FDB install path"
    "netns_fdb_nhg:FDB nexthop-group path"
    "netns_nexthop_raw:raw nexthop socket path"
)

cd "$REPO_ROOT"

echo "[evpn-netns] running ${#tests[@]} privileged EVPN Linux test binaries"
for entry in "${tests[@]}"; do
    test_bin="${entry%%:*}"
    label="${entry#*:}"
    echo
    echo "[evpn-netns] >>> $label ($test_bin)"
    EVPN_LINUX_NETNS=1 RUST_BACKTRACE="${RUST_BACKTRACE:-1}" \
        cargo test -p rustbgpd-evpn-linux --test "$test_bin" -- \
        --test-threads=1 --nocapture
done

echo
echo "[evpn-netns] all privileged EVPN Linux netns tests passed"
