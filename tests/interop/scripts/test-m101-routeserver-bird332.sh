#!/usr/bin/env bash
# M101 — BIRD 3.3.2 real-wire malformed type-40 route-server proof.
#
# Exact 27/0 contract:
#   1 gRPC readiness; 2-3 both initial sessions; 4 raw e0 28 01 00;
#   5-6 accepted post-policy Adj-RIB-In + unrelated communities;
#   7-9 FRR downstream survival + exact AS_PATH/NEXT_HOP/communities;
#   10-12 exact RFC 7606 disposition deltas; 13-15 import deny,
#   explain, and positive control; 16-21 member-scoped export deny,
#   advertised/explain surfaces, and positive controls; 22-24 deterministic
#   withdrawal from Adj-RIB-In, Loc-RIB, and FRR; 25-27 both sessions remain
#   Established with unchanged flap counters.
#
# This lab is deliberately IPv4-unicast only. It does not claim RFC 8669
# Prefix-SID, labeled-unicast, SR, or AS_SET coverage.

set -euo pipefail

TOPO="m101-routeserver-bird332"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
FRR="clab-${TOPO}-frr"
BIRD_IMAGE="bird:v3.3.2-m101"
FRR_IMAGE="quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c"
BIRD_VERSION="BIRD version 3.3.2"
FRR_VERSION="bgpd version 10.3.1_git"
BIRD_ADDR="10.101.1.2"
FRR_ADDR="10.101.2.2"
RS_FRR_ADDR="10.101.2.1"
MALFORMED_PREFIX="198.51.100.0/24"
IMPORT_DENY_PREFIX="198.51.101.0/24"
EXPORT_DENY_PREFIX="198.51.102.0/24"
CONTROL_PREFIX="198.51.103.0/24"
CAPTURE_PATH="/tmp/m101-bird-to-rs.pcap"
CAPTURE_LOG="/tmp/m101-tshark.log"
CAPTURE_RUNNING=0
M101_DISCARD_BEFORE=0
M101_TAW_BEFORE=0
M101_RESET_BEFORE=0
BIRD_STATE_BEFORE=""
FRR_STATE_BEFORE=""

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

rs_neighbor_state() {
    grpcurl_call \
        -d "{\"address\": \"${1:?}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

frr_prefix_json() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast ${1:?} json" 2>/dev/null
}

frr_has_prefix() {
    frr_prefix_json "$1" | jq -e '.paths | length >= 1' >/dev/null 2>&1
}

rs_received_has_prefix() {
    rs_ctl rib received "$BIRD_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'any(.[]?; .prefix == $prefix)' >/dev/null
}

rs_loc_has_prefix() {
    rs_ctl rib --prefix "$1" -j \
        | jq -e --arg prefix "$1" 'any(.[]?; .prefix == $prefix)' >/dev/null
}

rs_advertised_has_prefix() {
    rs_ctl rib advertised "$FRR_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'any(.[]?; .prefix == $prefix)' >/dev/null
}

wait_for() {
    local label=${1:?}
    shift
    for _ in $(seq 1 45); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    log "timeout waiting for: $label"
    return 1
}

wait_for_absence() {
    local label=${1:?}
    shift
    for _ in $(seq 1 30); do
        if ! "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    log "timeout waiting for absence: $label"
    return 1
}

require_sleeping_identity() {
    local container=${1:?} expected_image=${2:?} binary=${3:?} expected_version=${4:?}
    local configured_image local_image container_image command version
    configured_image=$(docker inspect -f '{{.Config.Image}}' "$container")
    local_image=$(docker image inspect -f '{{.Id}}' "$expected_image")
    container_image=$(docker inspect -f '{{.Image}}' "$container")
    command=$(docker inspect -f '{{json .Config.Cmd}}' "$container")
    version=$(docker exec "$container" "$binary" --version 2>&1 | sed -n '1p')

    [ "$configured_image" = "$expected_image" ] || {
        echo "ERROR: $container configured image '$configured_image' (want '$expected_image')" >&2
        return 1
    }
    [ "$container_image" = "$local_image" ] || {
        echo "ERROR: $container local image '$container_image' (want '$local_image')" >&2
        return 1
    }
    [ "$command" = '["sleep","infinity"]' ] || {
        echo "ERROR: $container is not the required sleeping container: $command" >&2
        return 1
    }
    [ "$version" = "$expected_version" ] || {
        echo "ERROR: $container runtime '$version' (want '$expected_version')" >&2
        return 1
    }
    log "$container identity: $expected_image -> $local_image; runtime $expected_version"
}

preflight_identities_and_configs() {
    require_sleeping_identity "$BIRD" "$BIRD_IMAGE" bird "$BIRD_VERSION"
    require_sleeping_identity "$FRR" "$FRR_IMAGE" /usr/lib/frr/bgpd "$FRR_VERSION"
    docker exec "$BIRD" bird -p -c /etc/bird/bird.conf >/dev/null 2>&1 || {
        echo "ERROR: BIRD 3.3.2 rejected the M101 configuration" >&2
        return 1
    }
    docker exec "$FRR" /usr/lib/frr/bgpd -C -f /etc/frr/frr.conf >/dev/null 2>&1 || {
        echo "ERROR: FRR 10.3.1 rejected the M101 configuration" >&2
        return 1
    }
    log "Both exact sleeping peer images and configurations passed preflight"
}

start_capture() {
    log "Arming BIRD-side tshark before any BGP daemon starts"
    docker exec "$BIRD" rm -f "$CAPTURE_PATH" "$CAPTURE_LOG"
    docker exec -d "$BIRD" sh -c \
        'tshark -i eth1 -w "$1" "tcp port 179" >"$2" 2>&1' \
        sh "$CAPTURE_PATH" "$CAPTURE_LOG"
    CAPTURE_RUNNING=1
    sleep 2
    if ! docker exec "$BIRD" sh -c \
        'cat /proc/[0-9]*/comm 2>/dev/null | grep -x tshark' >/dev/null; then
        echo "ERROR: M101 tshark did not stay running after startup" >&2
        docker exec "$BIRD" sh -c \
            'tail -n 80 "$1" 2>/dev/null || true' sh "$CAPTURE_LOG" >&2 || true
        return 1
    fi
}

stop_capture() {
    local capture_pid
    capture_pid=$(docker exec "$BIRD" sh -c '
        found=0
        capture_pid=
        for file in /proc/[0-9]*/comm; do
            [ "$(cat "$file" 2>/dev/null)" = tshark ] || continue
            capture_pid=${file#/proc/}; capture_pid=${capture_pid%/comm}
            found=$((found + 1))
        done
        [ "$found" -eq 1 ] || exit 1
        printf "%s\n" "$capture_pid"
    ') || {
        echo "ERROR: expected exactly one M101 tshark process" >&2
        return 1
    }
    docker exec "$BIRD" sh -c 'kill -INT "$1"' sh "$capture_pid"
    for _ in $(seq 1 10); do
        if ! docker exec "$BIRD" sh -c \
            'cat /proc/[0-9]*/comm 2>/dev/null | grep -x tshark' >/dev/null; then
            docker exec "$BIRD" test -s "$CAPTURE_PATH"
            docker exec "$BIRD" tshark -r "$CAPTURE_PATH" -c 1 >/dev/null 2>&1
            CAPTURE_RUNNING=0
            return 0
        fi
        sleep 1
    done
    echo "ERROR: M101 tshark did not flush and stop" >&2
    return 1
}

m101_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ "$CAPTURE_RUNNING" -eq 1 ]; then
        docker exec "$BIRD" sh -c '
            for file in /proc/[0-9]*/comm; do
                [ "$(cat "$file" 2>/dev/null)" = tshark ] || continue
                pid=${file#/proc/}; pid=${pid%/comm}; kill -INT "$pid" 2>/dev/null
            done
        ' >/dev/null 2>&1
    fi
    _cleanup_on_exit
    exit "$exit_code"
}
trap m101_on_exit EXIT INT TERM HUP

start_bird() {
    docker exec "$BIRD" sh -c \
        'bird -d -c /etc/bird/bird.conf >/tmp/m101-bird.log 2>&1 &'
}

start_frr() {
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start >/dev/null 2>&1
}

bird_established() {
    docker exec "$BIRD" birdc show protocols 2>/dev/null \
        | awk '$1 == "routeserver" && $0 ~ /Established/ { found=1 } END { exit !found }'
}

frr_established() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $RS_FRR_ADDR json" 2>/dev/null \
        | jq -e --arg peer "$RS_FRR_ADDR" '.[$peer].bgpState == "Established"' >/dev/null
}

metric_value() {
    local disposition=${1:?}
    curl -fsS "http://${RUST_IP}:9179/metrics" \
        | awk -v peer="$BIRD_ADDR" -v disposition="$disposition" '
            $1 ~ /^bgp_update_malformed_total/ \
                && $1 ~ "peer=\\\"" peer "\\\"" \
                && $1 ~ "disposition=\\\"" disposition "\\\"" {
                    print $2; found=1
                }
            END { if (!found) print 0 }
        ' | tail -1
}

counter_delta_is() {
    local disposition=${1:?} before=${2:?} want=${3:?}
    local after
    after=$(metric_value "$disposition")
    awk -v before="$before" -v after="$after" -v want="$want" \
        'BEGIN { exit !((after - before) == want) }'
}

assert_raw_type40_tuple() {
    local payloads oracle
    payloads=$(mktemp /tmp/m101-payloads.XXXXXX.tsv)
    oracle=$(mktemp /tmp/m101-oracle.XXXXXX.py)
    if ! docker exec "$BIRD" tshark -r "$CAPTURE_PATH" \
        -Y "ip.src == $BIRD_ADDR && ip.dst == 10.101.1.1 && tcp.len > 0" \
        -T fields -E separator=/t \
        -e tcp.stream -e ip.src -e ip.dst -e tcp.seq_raw -e tcp.payload \
        >"$payloads"; then
        rm -f "$payloads" "$oracle"
        fail "could not export BIRD-to-rustbgpd TCP payloads"
        return
    fi
    cat >"$oracle" <<'PY'
import collections
import ipaddress
import sys

target = ipaddress.ip_network("198.51.100.0/24")
segments = collections.defaultdict(list)
for raw in open(sys.argv[1], encoding="utf-8"):
    fields = raw.rstrip("\n").split("\t")
    if len(fields) != 5 or not fields[4]:
        continue
    stream, source, destination, sequence, payload = fields
    segments[(stream, source, destination)].append((int(sequence), bytes.fromhex(payload.replace(":", ""))))

def reassemble(parts):
    out = bytearray()
    cursor = min(sequence for sequence, _ in parts)
    for sequence, payload in sorted(parts):
        if sequence > cursor:
            raise ValueError(f"TCP gap {cursor}->{sequence}")
        overlap = max(0, cursor - sequence)
        if overlap < len(payload):
            out.extend(payload[overlap:])
            cursor = sequence + len(payload)
    return bytes(out)

def nlri_contains(data):
    offset = 0
    while offset < len(data):
        plen = data[offset]
        offset += 1
        octets = (plen + 7) // 8
        if offset + octets > len(data):
            raise ValueError("truncated NLRI")
        raw = data[offset:offset + octets] + b"\x00" * (4 - octets)
        offset += octets
        if ipaddress.ip_network((ipaddress.ip_address(raw), plen), strict=False) == target:
            return True
    return False

matching = []
for key, parts in segments.items():
    data = reassemble(parts)
    offset = 0
    while offset + 19 <= len(data):
        marker = data.find(b"\xff" * 16, offset)
        if marker < 0 or marker + 19 > len(data):
            break
        length = int.from_bytes(data[marker + 16:marker + 18], "big")
        if length < 19 or marker + length > len(data):
            offset = marker + 1
            continue
        message = data[marker:marker + length]
        offset = marker + length
        if message[18] != 2:
            continue
        body = message[19:]
        if len(body) < 4:
            raise ValueError("short UPDATE")
        withdrawn_len = int.from_bytes(body[:2], "big")
        attr_len_offset = 2 + withdrawn_len
        if attr_len_offset + 2 > len(body):
            raise ValueError("truncated withdrawn routes")
        attrs_len = int.from_bytes(body[attr_len_offset:attr_len_offset + 2], "big")
        attrs_start = attr_len_offset + 2
        attrs_end = attrs_start + attrs_len
        if attrs_end > len(body):
            raise ValueError("truncated path attributes")
        if not nlri_contains(body[attrs_end:]):
            continue
        attrs = body[attrs_start:attrs_end]
        cursor = 0
        tuples = []
        while cursor < len(attrs):
            start = cursor
            if cursor + 3 > len(attrs):
                raise ValueError("short path-attribute header")
            flags, code = attrs[cursor], attrs[cursor + 1]
            cursor += 2
            if flags & 0x10:
                if cursor + 2 > len(attrs):
                    raise ValueError("short extended attribute length")
                size = int.from_bytes(attrs[cursor:cursor + 2], "big")
                cursor += 2
            else:
                size = attrs[cursor]
                cursor += 1
            cursor += size
            if cursor > len(attrs):
                raise ValueError("truncated path-attribute value")
            if code == 40:
                tuples.append(attrs[start:cursor].hex())
        matching.append(tuples)

if not matching:
    raise SystemExit("no BIRD announcement for 198.51.100.0/24")
if any(tuples != ["e0280100"] for tuples in matching):
    raise SystemExit(f"type-40 tuple mismatch: {matching}")
print(f"{len(matching)} matching UPDATE(s), exact tuple e0 28 01 00")
PY
    local result
    if result=$(python3 "$oracle" "$payloads" 2>&1); then
        ok "raw BIRD UPDATE carries $result"
    else
        fail "raw type-40 oracle failed: $result"
    fi
    rm -f "$payloads" "$oracle"
}

assert_initial_sessions() {
    if bird_established; then
        ok "BIRD 3.3.2 member session is Established"
    else
        fail "BIRD 3.3.2 member session is not Established"
    fi
    if frr_established; then
        ok "FRR 10.3.1 control-member session is Established"
    else
        fail "FRR 10.3.1 control-member session is not Established"
    fi
    BIRD_STATE_BEFORE=$(rs_neighbor_state "$BIRD_ADDR")
    FRR_STATE_BEFORE=$(rs_neighbor_state "$FRR_ADDR")
}

assert_received_and_downstream() {
    local received frr
    received=$(rs_ctl rib received "$BIRD_ADDR" -a ipv4 -j)
    frr=$(frr_prefix_json "$MALFORMED_PREFIX")
    if printf '%s\n' "$received" | jq -e --arg p "$MALFORMED_PREFIX" --arg nh "$BIRD_ADDR" '
        [.[] | select(.prefix == $p)]
        | length == 1 and .[0].peer_address == $nh and .[0].as_path == [65001]
          and .[0].next_hop == $nh
    ' >/dev/null; then
        ok "malformed-route announcement is accepted in post-policy Adj-RIB-In"
    else
        fail "post-policy Adj-RIB-In lost or changed the accepted malformed route"
    fi
    if printf '%s\n' "$received" | jq -e --arg p "$MALFORMED_PREFIX" '
        [.[] | select(.prefix == $p)] | length == 1
        and (.[0].communities | index("65001:101") != null)
        and (.[0].large_communities | index("65001:101:40") != null)
    ' >/dev/null; then
        ok "Adj-RIB-In preserves standard and Large Communities beside type 40"
    else
        fail "Adj-RIB-In did not preserve both unrelated communities"
    fi
    if printf '%s\n' "$frr" | jq -e '.paths | length == 1' >/dev/null; then
        ok "FRR receives the route after rustbgpd discards only malformed type 40"
    else
        fail "FRR did not receive the attribute-discard survivor"
    fi
    if printf '%s\n' "$frr" | jq -e --arg nh "$BIRD_ADDR" '
        .paths[0].aspath.string == "65001" and .paths[0].nexthops[0].ip == $nh
    ' >/dev/null; then
        ok "FRR sees exact transparent AS_PATH 65001 and NEXT_HOP 10.101.1.2"
    else
        fail "FRR transparent AS_PATH/NEXT_HOP changed"
    fi
    if printf '%s\n' "$frr" | jq -e '
        (.paths[0].community.string | test("(^| )65001:101( |$)"))
        and (.paths[0].largeCommunity.string | test("(^| )65001:101:40( |$)"))
    ' >/dev/null; then
        ok "FRR preserves the unrelated standard and Large Communities"
    else
        fail "FRR lost an unrelated community attribute"
    fi
}

assert_disposition_deltas() {
    if counter_delta_is attribute_discard "$M101_DISCARD_BEFORE" 1; then
        ok "malformed metric attribute_discard delta is exactly +1"
    else
        fail "malformed metric attribute_discard delta is not exactly +1"
    fi
    if counter_delta_is treat_as_withdraw "$M101_TAW_BEFORE" 0; then
        ok "malformed metric treat_as_withdraw delta is exactly +0"
    else
        fail "malformed metric treat_as_withdraw delta is not exactly +0"
    fi
    if counter_delta_is session_reset "$M101_RESET_BEFORE" 0; then
        ok "malformed metric session_reset delta is exactly +0"
    else
        fail "malformed metric session_reset delta is not exactly +0"
    fi
}

assert_policy_surfaces() {
    local explain
    if ! rs_loc_has_prefix "$IMPORT_DENY_PREFIX"; then
        ok "import policy denies 198.51.101.0/24 from the Loc-RIB"
    else
        fail "import-denied prefix leaked into the Loc-RIB"
    fi
    explain=$(rs_ctl policy explain --neighbor "$BIRD_ADDR" --prefix "$IMPORT_DENY_PREFIX" || true)
    if grep -q 'm101-import' <<<"$explain" && grep -q '^  deny' <<<"$explain"; then
        ok "import explain names the m101-import deny decision"
    else
        fail "import explain did not expose the m101-import deny"
    fi
    if rs_loc_has_prefix "$CONTROL_PREFIX"; then
        ok "import positive control 198.51.103.0/24 is present in the Loc-RIB"
    else
        fail "import positive control is missing from the Loc-RIB"
    fi

    if rs_loc_has_prefix "$EXPORT_DENY_PREFIX"; then
        ok "member-scoped export-denied prefix remains present in the Loc-RIB"
    else
        fail "export-denied prefix is absent before the per-member boundary"
    fi
    if ! rs_advertised_has_prefix "$EXPORT_DENY_PREFIX"; then
        ok "FRR Adj-RIB-Out omits the member-scoped export deny"
    else
        fail "FRR Adj-RIB-Out contains the export-denied prefix"
    fi
    explain=$(rs_ctl rib --prefix "$EXPORT_DENY_PREFIX" advertised "$FRR_ADDR" --explain || true)
    if grep -q '^Deny' <<<"$explain" && grep -q 'm101-export-to-frr' <<<"$explain"; then
        ok "export explain reports Deny via m101-export-to-frr"
    else
        fail "export explain did not expose the member-scoped deny"
    fi
    if ! frr_has_prefix "$EXPORT_DENY_PREFIX"; then
        ok "FRR lacks the member-scoped export-denied prefix"
    else
        fail "FRR received the member-scoped export-denied prefix"
    fi
    if rs_advertised_has_prefix "$CONTROL_PREFIX"; then
        ok "export positive control is present on the FRR advertised surface"
    else
        fail "export positive control is missing from FRR Adj-RIB-Out"
    fi
    if frr_has_prefix "$CONTROL_PREFIX"; then
        ok "FRR receives the export positive control"
    else
        fail "FRR is missing the export positive control"
    fi
}

assert_withdrawal() {
    docker exec "$BIRD" birdc disable malformed_probe >/dev/null
    if wait_for_absence "$MALFORMED_PREFIX in Adj-RIB-In" rs_received_has_prefix "$MALFORMED_PREFIX"; then
        ok "withdraw removes the malformed prefix from Adj-RIB-In"
    else
        fail "malformed prefix remained in Adj-RIB-In after withdrawal"
    fi
    if wait_for_absence "$MALFORMED_PREFIX in Loc-RIB" rs_loc_has_prefix "$MALFORMED_PREFIX"; then
        ok "withdraw removes the malformed prefix from the Loc-RIB"
    else
        fail "malformed prefix remained in the Loc-RIB after withdrawal"
    fi
    if wait_for_absence "$MALFORMED_PREFIX on FRR" frr_has_prefix "$MALFORMED_PREFIX"; then
        ok "withdraw removes the malformed prefix from FRR"
    else
        fail "malformed prefix remained on FRR after withdrawal"
    fi
}

assert_final_session_stability() {
    local bird_after frr_after
    bird_after=$(rs_neighbor_state "$BIRD_ADDR")
    frr_after=$(rs_neighbor_state "$FRR_ADDR")
    if printf '%s\n' "$bird_after" | jq -e '.state == "SESSION_STATE_ESTABLISHED"' >/dev/null; then
        ok "BIRD session remains Established after withdrawal"
    else
        fail "BIRD session left Established"
    fi
    if jq -en --argjson before "$BIRD_STATE_BEFORE" --argjson after "$bird_after" '
        (($before.flapCount // 0) | tonumber) == (($after.flapCount // 0) | tonumber)
    ' >/dev/null; then
        ok "BIRD session flap count is unchanged"
    else
        fail "BIRD session flap count changed"
    fi
    if jq -en --argjson before "$FRR_STATE_BEFORE" --argjson after "$frr_after" '
        $after.state == "SESSION_STATE_ESTABLISHED"
        and (($before.flapCount // 0) | tonumber) == (($after.flapCount // 0) | tonumber)
    ' >/dev/null && frr_established; then
        ok "FRR session remains Established with unchanged flap count"
    else
        fail "FRR session state or flap count changed"
    fi
}

main() {
    log "M101: BIRD 3.3.2 real-wire attribute-discard route-server proof"
    resolve_grpc_addr
    preflight_identities_and_configs
    start_capture

    # No BGP daemon is started before both identity checks and capture arming.
    start_rustbgpd
    RUST_IP=$(resolve_ip "$RUSTBGPD")
    M101_DISCARD_BEFORE=$(metric_value attribute_discard)
    M101_TAW_BEFORE=$(metric_value treat_as_withdraw)
    M101_RESET_BEFORE=$(metric_value session_reset)
    start_frr
    start_bird

    wait_for "BIRD session" bird_established || true
    wait_for "FRR session" frr_established || true
    wait_for "$MALFORMED_PREFIX in Adj-RIB-In" rs_received_has_prefix "$MALFORMED_PREFIX" || true
    wait_for "$MALFORMED_PREFIX on FRR" frr_has_prefix "$MALFORMED_PREFIX" || true
    wait_for "$CONTROL_PREFIX on FRR" frr_has_prefix "$CONTROL_PREFIX" || true
    wait_for "attribute_discard delta" counter_delta_is attribute_discard "$M101_DISCARD_BEFORE" 1 || true

    assert_initial_sessions
    stop_capture
    assert_raw_type40_tuple
    assert_received_and_downstream
    assert_disposition_deltas
    assert_policy_surfaces
    assert_withdrawal
    assert_final_session_stability

    # shellcheck disable=SC2154 # pass/fail are provided by test-lib.sh
    if [ "$pass" -ne 27 ] || [ "$fail" -ne 0 ]; then
        fail "M101 accounting drift: expected exactly 27/0, got $pass/$fail before accounting guard"
    fi
    print_summary
}

main "$@"
