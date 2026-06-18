#!/usr/bin/env bash
# Run the privileged netns integration tests inside a Docker
# container so the host kernel doesn't need iproute2 / iputils-ping /
# a Rust toolchain pre-installed and the test artifacts can't leak
# netnses into the host.
#
# Two test bundles live here:
#   - Gate 8b BUM port-flag tests (`netns_bum_filter`).
#   - ADR-0059 slice 3b FDB nexthop group tests
#     (`netns_fdb_nhg`) — requires kernel >= 5.8 for NDA_NH_ID.
#   - ADR-0061 Slice 4 general unicast FIB runtime validation
#     (`src/fib_runtime.rs`) — proves configured non-reserved
#     Linux tables receive and drain daemon-owned routes, including
#     ADR-0066 unicast multipath/ECMP install + failover.
#   - ADR-0067 single-hop BFD actor validation (`src/bfd_runtime.rs`)
#     — proves the real UDP socket path: TTL/Hop-Limit-255 discard
#     (RFC 5881), decode/demux, the session reaching Up, and
#     detection-timer expiry when the peer goes silent.
#
# Requires:
#   - Docker daemon running on a Linux host with kernel >= 5.8 for
#     the fdb_nhg selectors (>= 4.18 if running only the Gate 8b
#     bundle). The container shares the host's `net` capabilities
#     via `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN --security-opt
#     apparmor=unconfined`.
#   - Repo checkout at the script's grand-grand-grand-parent (the
#     workspace root containing Cargo.toml).
#
# Usage:
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh
#       (default: Gate 8b "all" — both spike + roundtrip)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh spike
#       (Gate 8b spike only)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh roundtrip
#       (Gate 8b netlink round-trip only)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg
#       (ADR-0059 slice 3b: both fdb_nhg tests)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg_roundtrip
#       (slice 3b round-trip install/remove only)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg_cve
#       (slice 3b CVE-2025-39851 guard negative path only)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh fib_runtime
#       (ADR-0061 Slice 4 general unicast FIB runtime validation)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh bfd_runtime
#       (ADR-0067 single-hop BFD actor netns validation)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh bgp_unnumbered
#       (ADR-0069 BGP unnumbered Linux/socket primitive spike)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier
#       (ADR-0085 RTNLGRP_LINK carrier monitor veth transitions)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh ac_gate
#       (single-active AC-gate IFLA_BRPORT_STATE round-trip +
#        flood-flag non-clobber proof)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh dataplane_vlan_fdb
#       (ADR-0089 VLAN-scoped single-dst FDB add/remove proof)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh svd_fdb_vni
#       (LAN-64 SVD collect-metadata explicit FDB VNI proof)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_multipath
#       (LAN-70 L3VNI multipath + FDB-NHG kernel-shape proof)
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_all_active_writer
#       (LAN-76 production actor all-active Type 5 L3 writer proof)
#
# Exits 0 on green; surfaces the inner cargo exit code otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-rustbgpd-netns-tests:latest}"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

# Test selector. `bum_*` runs the Gate 8b harness; `fdb_nhg` runs
# the ADR-0059 slice 3b FDB nexthop group integration test;
# `fib_runtime` / `bfd_runtime` run same-module `-p rustbgpd` daemon
# runtime tests (ADR-0061 FIB / ADR-0067 BFD). `bgp_unnumbered` runs the
# ADR-0069 evpn-linux integration proof; `link_carrier` runs the
# ADR-0085 RTNLGRP_LINK carrier monitor proof; `dataplane_vlan_fdb`
# runs the ADR-0089 VLAN-scoped FDB proof; `svd_fdb_vni` runs the
# LAN-64 collect-metadata VXLAN explicit-FDB-VNI proof; `l3_multipath`
# runs the LAN-70 L3VNI route-multipath + FDB-NHG proof; `l3_all_active_writer`
# runs the LAN-76 production actor all-active L3 writer proof.
TEST_BIN="netns_bum_filter"
EXACT_FILTER=1
# Module-path filter for `-p rustbgpd` daemon netns tests (fib/bfd);
# empty means the default `netns_*` evpn-linux integration binary.
RUSTBGPD_TEST_FILTER=""
case "${1:-all}" in
    spike)      FILTER="bum_filter_spike_validates_kernel_primitive" ;;
    roundtrip)  FILTER="linux_dataplane_set_bum_port_flags_round_trip" ;;
    all|"")     FILTER="" ;;
    fdb_nhg)    TEST_BIN="netns_fdb_nhg"; FILTER="" ;;
    fdb_nhg_roundtrip)  TEST_BIN="netns_fdb_nhg"; FILTER="round_trip_install_and_remove_fdb_nhg" ;;
    fdb_nhg_cve)        TEST_BIN="netns_fdb_nhg"; FILTER="cve_guard_blocks_install_when_learning_enabled" ;;
    fib_runtime)        FILTER=""; RUSTBGPD_TEST_FILTER="fib_runtime::tests::netns_general_unicast_fib_" ;;
    bfd_runtime)        FILTER=""; RUSTBGPD_TEST_FILTER="bfd_runtime::tests::netns::" ;;
    bgp_unnumbered)     TEST_BIN="netns_bgp_unnumbered"; FILTER="" ;;
    link_carrier)       TEST_BIN="netns_link_carrier"; FILTER="" ;;
    ac_gate)            TEST_BIN="netns_ac_gate"; FILTER="" ;;
    dataplane_vlan_fdb) TEST_BIN="netns_dataplane"; FILTER="linux_dataplane_programs_vlan_scoped_remote_mac_add_remove" ;;
    svd_fdb_vni)        TEST_BIN="netns_svd"; FILTER="svd_topology_is_ready_and_programs_vni_scoped_fdb_rows" ;;
    l3_multipath)       TEST_BIN="netns_l3_install"; FILTER="l3vxlan_all_active_multipath_kernel_shape" ;;
    l3_all_active_writer) TEST_BIN="netns_l3_install"; FILTER="linux_reconcile_actor_"; EXACT_FILTER=0 ;;
    *)
        echo "ERROR: unknown filter '$1' — pick one of: spike, roundtrip, all, fdb_nhg, fdb_nhg_roundtrip, fdb_nhg_cve, fib_runtime, bfd_runtime, bgp_unnumbered, link_carrier, ac_gate, dataplane_vlan_fdb, svd_fdb_vni, l3_multipath, l3_all_active_writer" >&2
        exit 2
        ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found in PATH" >&2
    exit 2
fi

# Build only when the Dockerfile is newer than the cached image, or
# the image is missing. Saves rebuild time on hot iterations. Set
# `SKIP_BUILD=1` to assert the image already exists and bail out
# rather than rebuild — used by CI where a sibling step pre-builds
# via GHA layer cache and the local Dockerfile mtime would otherwise
# trip the rebuild check.
if [ "${SKIP_BUILD:-0}" = "1" ]; then
    if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        echo "ERROR: SKIP_BUILD=1 but image $IMAGE_TAG not found" >&2
        exit 2
    fi
    echo "[harness] SKIP_BUILD=1 — using pre-built $IMAGE_TAG"
else
    needs_build=1
    if docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        image_built=$(docker image inspect "$IMAGE_TAG" --format '{{.Created}}')
        image_built_ts=$(date -d "$image_built" +%s 2>/dev/null || echo 0)
        dockerfile_ts=$(stat -c %Y "$DOCKERFILE" 2>/dev/null || stat -f %m "$DOCKERFILE")
        if [ "$image_built_ts" -ge "$dockerfile_ts" ]; then
            needs_build=0
        fi
    fi

    if [ "$needs_build" -eq 1 ]; then
        echo "[harness] building $IMAGE_TAG"
        docker build -f "$DOCKERFILE" -t "$IMAGE_TAG" "$REPO_ROOT"
    else
        echo "[harness] reusing cached $IMAGE_TAG"
    fi
fi

# Per-runner volume names so concurrent invocations on the same
# host don't fight for the same target/ cache. The user can override
# via env to share caches intentionally (e.g. for CI).
CARGO_CACHE_VOL="${CARGO_CACHE_VOL:-rustbgpd-netns-tests-cargo}"
TARGET_CACHE_VOL="${TARGET_CACHE_VOL:-rustbgpd-netns-tests-target}"

# Capability + privilege rationale:
#   - --cap-add=NET_ADMIN: required for `bridge link set ... flood off`
#   - --cap-add=SYS_ADMIN: required for `ip netns add` (CLONE_NEWNET).
#   - We deliberately do NOT use `--privileged` — keeping the cap set
#     tight so the harness runs on hardened CI runners that ban
#     privileged containers.

DOCKER_ARGS=(
    --rm
    --cap-add=NET_ADMIN
    --cap-add=SYS_ADMIN
    # Without `--security-opt apparmor=unconfined`, `ip netns add`'s
    # `mount --make-shared /run/netns` call returns EACCES on hosts
    # where Docker uses the default Ubuntu AppArmor profile (which
    # is everywhere outside very stripped images). NET_ADMIN +
    # SYS_ADMIN don't help — AppArmor's mount mediation runs
    # independently of POSIX caps.
    --security-opt apparmor=unconfined
    -e EVPN_LINUX_NETNS=1
    -e RUST_BACKTRACE=1
    -e CARGO_TERM_COLOR=always
    -v "${REPO_ROOT}:/work"
    -v "${CARGO_CACHE_VOL}:/usr/local/cargo/registry"
    -v "${TARGET_CACHE_VOL}:/work/target"
    -w /work
)

# `--test-threads=1`: the privileged tests both create their own
# netnses and re-exec into them; running them in parallel inside
# the same container risks them clobbering each other on the
# `/proc/$$/ns` namespace inheritance the inner re-exec depends on.
if [ -n "$RUSTBGPD_TEST_FILTER" ]; then
    # The rustbgpd binary's gRPC types are generated from
    # `proto/rustbgpd.proto` by `rustbgpd-api`'s build script into that crate's
    # OUT_DIR. The persistent `$TARGET_CACHE_VOL` can retain a stale generated
    # module when the proto changes but cargo's incremental fingerprint does not
    # re-run the build script (the proto lives outside the crate dir), which
    # surfaces as "struct FibRouteStatus has no field named ..." compile errors.
    # Force a regeneration of just that crate before building so the cached
    # volume can't ship a stale proto. Cheap: only `rustbgpd-api` is rebuilt.
    # Single-quote the filter inside the `sh -c` program so it reaches
    # `cargo test` verbatim even if it ever gains whitespace / shell
    # metacharacters (today it is a plain module path).
    TEST_ARGS=(
        sh -c "cargo clean -p rustbgpd-api && cargo test -p rustbgpd '${RUSTBGPD_TEST_FILTER}' -- --test-threads=1 --nocapture"
    )
else
    TEST_ARGS=(
        cargo test -p rustbgpd-evpn-linux --test "$TEST_BIN"
        --
        --test-threads=1 --nocapture
    )
    if [ -n "$FILTER" ]; then
        if [ "$EXACT_FILTER" = "1" ]; then
            TEST_ARGS+=("--exact" "$FILTER")
        else
            TEST_ARGS+=("$FILTER")
        fi
    fi
fi

echo "[harness] running: ${TEST_ARGS[*]}"
exec docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG" "${TEST_ARGS[@]}"
