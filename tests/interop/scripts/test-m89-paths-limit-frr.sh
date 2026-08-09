#!/usr/bin/env bash
# M89: experimental Paths-Limit capability 76 against FRR 10.3.1.
# Three independent source ASes originate one v4 and one v6 NLRI. FRR's
# receive preferences cap rustbgpd Add-Path export at 2 and 3 respectively.

TOPO="m89-paths-limit-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

FRR_IMAGE="quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c"
FRR_VERSION="bgpd version 10.3.1_git"
SINK_ADDR="10.89.4.2"
V4_PREFIX="192.0.2.89/32"
V6_PREFIX="2001:db8:89::/48"
SOURCE_A="clab-${TOPO}-source-a"
SOURCE_B="clab-${TOPO}-source-b"
SOURCE_C="clab-${TOPO}-source-c"
SINK="clab-${TOPO}-sink"
WAIT_ATTEMPTS="${M89_WAIT_ATTEMPTS:-45}"

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

frr_neighbor() {
    docker exec "$1" vtysh -c "show bgp neighbors $2 json" 2>/dev/null \
        | jq -c --arg peer "$2" '.[$peer]'
}

wait_for() {
    local label=${1:?}
    shift
    for i in $(seq 1 "$WAIT_ATTEMPTS"); do
        if "$@"; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label"
    return 1
}

assert_frr_identity() {
    local container expected_image_id
    expected_image_id=$(docker image inspect -f '{{.Id}}' "$FRR_IMAGE")
    for container in "$SOURCE_A" "$SOURCE_B" "$SOURCE_C" "$SINK"; do
        local image_id version logs
        image_id=$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null || true)
        version=$(docker exec "$container" /usr/lib/frr/bgpd --version 2>/dev/null \
            | sed -n '1p' || true)
        logs=$(docker logs "$container" 2>&1 || true)
        if [ "$image_id" = "$expected_image_id" ]; then
            ok "$container image ID matches the pinned FRR digest"
        else
            fail "$container image ID '$image_id' (want '$expected_image_id')"
        fi
        if [ "$version" = "$FRR_VERSION" ]; then
            ok "$container runtime is exactly FRR 10.3.1_git"
        else
            fail "$container runtime version '$version' (want '$FRR_VERSION')"
        fi
        if grep -Eqi 'unknown command|processing failure' <<< "$logs"; then
            fail "$container reported an FRR configuration-processing error"
            grep -Ei 'unknown command|processing failure' <<< "$logs" >&2 || true
        else
            ok "$container accepted its complete FRR configuration"
        fi
    done
}

session_is_established() {
    frr_neighbor "$1" "$2" | jq -e '.bgpState == "Established"' >/dev/null
}

all_sessions_are_exact() {
    session_is_established "$SOURCE_A" 10.89.1.1 \
        && session_is_established "$SOURCE_B" 10.89.2.1 \
        && session_is_established "$SOURCE_C" 10.89.3.1 \
        && session_is_established "$SINK" 10.89.4.1
}

wait_all_sessions() {
    wait_for "all four exact FRR sessions are Established" all_sessions_are_exact || true
}

recheck_all_sessions() {
    if all_sessions_are_exact; then
        ok "all four exact FRR sessions remain Established"
    else
        fail "one or more exact FRR sessions left Established"
    fi
}

candidate_shape_is_exact() {
    local family=${1:?} prefix=${2:?}
    # Next hops are pinned per family: v4 is the session address, v6 is the
    # route-map-set global (see frr-bgpd-m89-source-a.conf). A link-local or
    # unspecified v6 next hop here would mean the sources raced their zebra
    # address sync again.
    local nh1=10.89.1.2 nh2=10.89.2.2 nh3=10.89.3.2
    if [ "$family" = ipv6_unicast ]; then
        nh1=fd89:1::2 nh2=fd89:2::2 nh3=fd89:3::2
    fi
    {
        rbgp rib received 10.89.1.2 -a "$family" -j 2>/dev/null
        rbgp rib received 10.89.2.2 -a "$family" -j 2>/dev/null
        rbgp rib received 10.89.3.2 -a "$family" -j 2>/dev/null
    } | jq -se --arg prefix "$prefix" --arg nh1 "$nh1" --arg nh2 "$nh2" --arg nh3 "$nh3" '
        add | map(select(.prefix == $prefix)) |
        length == 3
        and ([.[] | {peer: .peer_address, as_path, next_hop}] | sort_by(.peer)) == [
            {"peer":"10.89.1.2","as_path":[65002],"next_hop":$nh1},
            {"peer":"10.89.2.2","as_path":[65003],"next_hop":$nh2},
            {"peer":"10.89.3.2","as_path":[65004],"next_hop":$nh3}
        ]
    ' >/dev/null
}

frr_caps_are_exact() {
    frr_neighbor "$SINK" 10.89.4.1 | jq -e '
        .neighborCapabilities.addPath.ipv4Unicast == {
            "txAdvertisedAndReceived":false,"txAdvertised":false,"txReceived":true,
            "rxAdvertisedAndReceived":true,"rxAdvertised":true,"rxReceived":true
        }
        and .neighborCapabilities.addPath.ipv6Unicast == {
            "txAdvertisedAndReceived":false,"txAdvertised":false,"txReceived":true,
            "rxAdvertisedAndReceived":true,"rxAdvertised":true,"rxReceived":true
        }
        and .neighborCapabilities.pathsLimit.ipv4Unicast == {
            "advertisedAndReceived":true,"advertisedPathsLimit":2,"receivedPathsLimit":7
        }
        and .neighborCapabilities.pathsLimit.ipv6Unicast == {
            "advertisedAndReceived":true,"advertisedPathsLimit":3,"receivedPathsLimit":7
        }
    ' >/dev/null
}

rust_caps_are_exact() {
    # Load-bearing: exact object equality goes red if the removed raw sentinel
    # key returns or the live finite field-6 values change.
    rbgp neighbor "$SINK_ADDR" -j 2>/dev/null | jq -e '
        .add_path_send == true and .add_path_receive == true
        and .add_path_send_max == 4
        and (.paths_limits | sort_by(.family)) == [
            {"family":"ipv4_unicast","configured_receive_max":7,
             "advertised_receive_max":7,"received_receive_max":2,
             "effective_send_limit":2,"effective_send_active":true},
            {"family":"ipv6_unicast","configured_receive_max":7,
             "advertised_receive_max":7,"received_receive_max":3,
             "effective_send_limit":3,"effective_send_active":true}
        ]
    ' >/dev/null
}

adj_count_is_exact() {
    local family=${1:?} prefix=${2:?} want=${3:?}
    rbgp rib advertised "$SINK_ADDR" -a "$family" -j 2>/dev/null \
        | jq -e --arg prefix "$prefix" --argjson want "$want" \
            '[.[] | select(.prefix == $prefix)] | length == $want' >/dev/null
}

sink_paths_are_exact() {
    local family=${1:?} prefix=${2:?} want=${3:?} asns=${4:?}
    docker exec "$SINK" vtysh -c "show bgp $family unicast $prefix json" 2>/dev/null \
        | jq -e --argjson want "$want" --argjson asns "$asns" '
            (.paths | length) == $want
            and ([.paths[].addpathRxId] | length) == $want
            and ([.paths[].addpathRxId] | all(. > 0))
            and ([.paths[].addpathRxId] | unique | length) == $want
            and ([.paths[].aspath.string | split(" ")[-1] | tonumber] | sort) == $asns
        ' >/dev/null
}

complete_proof_is_exact() {
    # Candidate inventory is deliberately first: no cap claim is evaluated
    # until all three independent source paths exist in each family.
    candidate_shape_is_exact ipv4_unicast "$V4_PREFIX" \
        && candidate_shape_is_exact ipv6_unicast "$V6_PREFIX" \
        && frr_caps_are_exact \
        && rust_caps_are_exact \
        && adj_count_is_exact ipv4_unicast "$V4_PREFIX" 2 \
        && adj_count_is_exact ipv6_unicast "$V6_PREFIX" 3 \
        && sink_paths_are_exact ipv4 "$V4_PREFIX" 2 '[65002,65003]' \
        && sink_paths_are_exact ipv6 "$V6_PREFIX" 3 '[65002,65003,65004]'
}

assert_complete_proof() {
    if wait_for "complete dual-stack Paths-Limit proof converged" complete_proof_is_exact; then
        ok "rustbgpd has exactly 3 IPv4 candidates from AS65002/65003/65004"
        ok "rustbgpd has exactly 3 IPv6 candidates from AS65002/65003/65004"
        ok "FRR typed Add-Path/Paths-Limit state is exactly v4=2/7, v6=3/7"
        ok "rustbgpd configured/advertised/received/effective limits are exact"
        ok "IPv4 Adj-RIB-Out and FRR RIB each contain exactly 2 paths"
        ok "IPv6 Adj-RIB-Out and FRR RIB each contain exactly 3 paths"
        ok "all sink Add-Path receive IDs are nonzero and unique per family"
        ok "sink source-AS membership is exactly 65002/65003 and 65002/65003/65004"
    else
        candidate_shape_is_exact ipv4_unicast "$V4_PREFIX" || fail "IPv4 candidate inventory is not exactly 3"
        candidate_shape_is_exact ipv6_unicast "$V6_PREFIX" || fail "IPv6 candidate inventory is not exactly 3"
        frr_caps_are_exact || fail "FRR typed Add-Path/Paths-Limit state is not exact"
        rust_caps_are_exact || fail "rustbgpd configured/advertised/received/effective limits are not exact"
        adj_count_is_exact ipv4_unicast "$V4_PREFIX" 2 || fail "IPv4 Adj-RIB-Out is not exactly 2 paths"
        adj_count_is_exact ipv6_unicast "$V6_PREFIX" 3 || fail "IPv6 Adj-RIB-Out is not exactly 3 paths"
        sink_paths_are_exact ipv4 "$V4_PREFIX" 2 '[65002,65003]' || fail "FRR IPv4 RIB is not the exact 2-path set"
        sink_paths_are_exact ipv6 "$V6_PREFIX" 3 '[65002,65003,65004]' || fail "FRR IPv6 RIB is not the exact 3-path set"
    fi
}

main() {
    log "M89 experimental Paths-Limit receipt (expired draft-abraitis-idr-addpath-paths-limit-04)"
    resolve_grpc_addr
    start_rustbgpd
    assert_frr_identity
    wait_all_sessions
    assert_complete_proof
    recheck_all_sessions
    log "Results: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

main "$@"
