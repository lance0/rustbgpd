#!/usr/bin/env bash
# ADR-0069 BGP unnumbered Linux/socket primitive spike.
#
# Runs the gated Rust netns proof for:
#   - active TCP connect to fe80::peer%ifindex;
#   - passive accept observation for scoped link-local peers;
#   - IPv6 Hop-Limit/GTSM-style socket options;
#   - IPv4 route install via IPv6 link-local gateway + dev.
#
# Prefer the Docker harness, which supplies the required userland:
#
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh bgp_unnumbered

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$REPO_ROOT"

if [ "${EVPN_LINUX_NETNS:-0}" != "1" ]; then
    echo "ERROR: set EVPN_LINUX_NETNS=1 and run with CAP_NET_ADMIN + CAP_SYS_ADMIN" >&2
    exit 2
fi

cargo test -p rustbgpd-evpn-linux --test netns_bgp_unnumbered -- --nocapture
