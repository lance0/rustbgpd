#!/usr/bin/env bash
# M83 interop test — route-server profile, multi-stack receipt
# (RFC 7947 / RFC 7948 / RFC 9234 / ADR-0101 proof-ladder closer).
#
# rustbgpd is the route server (AS 65500) for three member stacks —
# BIRD 2.0.12, GoBGP 3.x (Add-Path receive), FRR 10.3.1 — with a
# StayRTR RTR fixture feeding ROV and a tshark capture on the RS↔BIRD
# link for the byte-level assertions.
#
# First-AS relaxation per stack (client-side, RFC 7947 §2.2.2.1):
#   FRR 10.3.1  — per-neighbor `no neighbor X enforce-first-as`
#                 (global form alone is insufficient, the M19 finding)
#   BIRD 2.0.12 — `enforce first as off` (explicit; also the default)
#   GoBGP 3.x   — no first-AS enforcement exists; nothing to disable
#
# Assertions:
#    1  RTR: both VRPs loaded from StayRTR (bgp_rpki_vrp_count == 2)
#    2  BIRD member session Established
#    3  GoBGP member session Established
#    4  FRR member session Established
#   --- transparency, client views (RFC 7947 §2.2) ---
#    5  BIRD: 100.66.0.0/24 AS_PATH = "65002" (leftmost = originator,
#       no 65500 anywhere)
#    6  BIRD: NEXT_HOP = 10.83.2.2 (GoBGP's address, not the RS's)
#    7  BIRD: MED 77 verbatim
#    8  BIRD: standard community 65002:222 verbatim
#    9  BIRD: large community 65002:2:2 verbatim
#   10  FRR: 203.0.113.0/24 AS_PATH = "65001", no 65500
#   11  FRR: NEXT_HOP = 10.83.1.2 (BIRD's address)
#   12  FRR: MED 120 verbatim
#   13  FRR: standard community 65001:111 verbatim
#   14  FRR: large community 65001:1:1 verbatim
#   15  GoBGP: 100.67.0.0/24 AS_PATH = [65003], no 65500
#   16  GoBGP: NEXT_HOP = 10.83.3.2 (FRR's address)
#   --- RFC 9234 OTC toward clients (role = route_server) ---
#   17  FRR reports OTC on a reflected route
#   18  BIRD reports BGP.otc: 65500 on a reflected route
#   --- per-member policy views ---
#   19  FRR lacks 100.69.0.0/24 (member-scoped deny chain)
#   20  GoBGP holds 100.69.0.0/24 (deny is scoped to FRR only)
#   21  `rbgp rib advertised` to FRR agrees (prefix absent)
#   22  `rbgp rib advertised` to GoBGP agrees (prefix present)
#   --- ROV at import (RTR fixture) ---
#   23  RPKI-invalid 100.68.0.0/24 absent on BIRD
#   24  RPKI-invalid 100.68.0.0/24 absent on GoBGP
#   25  import explain names the reject-rpki-invalid deny
#   --- RFC 7947 §2.3 path-hiding contrast (ADR-0101) ---
#   26  (a) FRR single-best: 100.65.0.0/24 absent (the best is denied
#       toward FRR by community 65001:666 — path hidden, pinned)
#   27  (a) GoBGP holds BIRD's best for the same prefix (sanity)
#   28  (a) export explain toward FRR: Deny, naming deny-to-frr
#   29  (b) after per_client_best flip (sed + SIGHUP + session bounce):
#       `rbgp neighbor` shows Distribution Mode per-client-best
#   30  (b) FRR receives the runner-up: AS_PATH 65002
#   31  (b) FRR runner-up NEXT_HOP = 10.83.2.2 (still the originator's)
#   32  (b) export explain: per-client ladder — candidate 1 of 2 denied
#       by deny-to-frr, runner-up advertised
#   33  (b) export explain decision Advertise with route peer = GoBGP
#   34  (c) withdrawing the runner-up's source converges FRR to nothing
#       (best still denied — no stale runner-up)
#   35  (d) Add-Path member: GoBGP holds BOTH paths for 100.70.0.0/24
#       (from AS 65001 and AS 65003)
#   --- byte-level wire assertions (tshark, RS→BIRD) ---
#   36  no RS→BIRD UPDATE carries 65500 in any AS_PATH segment
#   37  wire NEXT_HOP 10.83.2.2 on the 100.66.0.0/24 UPDATE
#   38  wire MED 77 verbatim
#   39  wire community 65002:222 verbatim
#   40  wire large community 65002:2:2 verbatim
#   41  wire OTC path attribute (type code 35) present on RS→BIRD
#       announcements (value pinned as 65500 by assertion 18)
#   42  EoR: on the final RS→BIRD TCP stream, the exact snapshotted
#       nonempty initial prefix set precedes one IPv4-unicast End-of-RIB
#       (later live deltas do not redefine the initial update)
#   --- withdraw propagation + reload stability ---
#   43  BIRD withdraws 203.0.113.0/24 → gone on FRR
#   44  BIRD withdraws 203.0.113.0/24 → gone on GoBGP
#   45  policy reload changes still-present FRR route 100.67.0.0/24
#       from LP 100→110 and bumps its import-chain install generation
#   46  FRR remains authoritatively Established/non-stale with unchanged
#       flap count, nondecreasing uptime, and cumulative session marker
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deploy -t tests/interop/m83-routeserver-multistack.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m83-routeserver-multistack.sh

check_ipv4_eor_order() {
    python3 - "${1:?}" "${2:?}" "${3:?}" <<'PY'
import ipaddress
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
expected_path = sys.argv[2]
events_path = sys.argv[3]

with open(expected_path, encoding="utf-8") as handle:
    expected = [
        str(ipaddress.ip_network(line.strip(), strict=False))
        for line in handle
        if line.strip()
    ]
if not expected:
    raise SystemExit("expected initial-prefix inventory is empty")
if len(expected) != len(set(expected)):
    raise SystemExit("expected initial-prefix inventory contains duplicates")


def nlri_prefixes(bgp):
    prefixes = []
    paired_fields = set()
    for node in bgp.iter():
        children = list(node)
        addr_fields = [
            field for field in children
            if field.get("name") == "bgp.nlri_prefix"
        ]
        if not addr_fields:
            continue
        length_fields = [
            field for field in children
            if field.get("name") == "bgp.prefix_length"
        ]
        if len(length_fields) != 1:
            continue
        length = length_fields[0].get("show")
        if length is None:
            raise SystemExit("NLRI prefix length has no decoded value")
        for field in addr_fields:
            address = field.get("show")
            if address is None:
                raise SystemExit("NLRI prefix has no decoded value")
            prefixes.append(
                str(ipaddress.ip_network(f"{address}/{length}", strict=False))
            )
            paired_fields.add(id(field))

    # Some synthetic fixtures and dissector versions expose the CIDR in the
    # address field itself. Accept that representation, but never guess a mask.
    for field in bgp.findall(".//field[@name='bgp.nlri_prefix']"):
        if id(field) in paired_fields:
            continue
        value = field.get("show")
        if value is None or "/" not in value:
            raise SystemExit(
                f"NLRI {value!r} has no associated bgp.prefix_length"
            )
        prefixes.append(str(ipaddress.ip_network(value, strict=False)))
    return prefixes


def is_ipv4_eor(bgp, prefixes):
    withdrawn = bgp.find(
        ".//field[@name='bgp.update.withdrawn_routes.length']"
    )
    attrs = bgp.find(
        ".//field[@name='bgp.update.path_attributes.length']"
    )
    codes = bgp.findall(
        ".//field[@name='bgp.update.path_attribute.type_code']"
    )
    return (
        bgp.get("size") == "23"
        and withdrawn is not None
        and withdrawn.get("show") == "0"
        and attrs is not None
        and attrs.get("show") == "0"
        and not codes
        and not prefixes
    )


events = []
for packet in root.findall("packet"):
    frame_field = packet.find(".//field[@name='frame.number']")
    if frame_field is None or frame_field.get("show") is None:
        raise SystemExit("packet missing frame.number")
    frame = int(frame_field.get("show"))
    stream_field = packet.find(".//field[@name='tcp.stream']")
    if stream_field is None or stream_field.get("show") is None:
        raise SystemExit(f"BGP packet in frame {frame} missing tcp.stream")
    stream = stream_field.get("show")
    for index, bgp in enumerate(packet.findall(".//proto[@name='bgp']"), 1):
        bgp_type = bgp.find(".//field[@name='bgp.type']")
        if bgp_type is not None:
            prefixes = nlri_prefixes(bgp)
            events.append({
                "key": (frame, index),
                "stream": stream,
                "type": bgp_type.get("show"),
                "prefixes": prefixes,
                "eor": is_ipv4_eor(bgp, prefixes),
            })

opens = [event for event in events if event["type"] == "1"]
if not opens:
    raise SystemExit("no RS-to-BIRD OPEN in capture")
target_open = max(opens, key=lambda event: event["key"])
target_stream = target_open["stream"]
stream_events = [
    event for event in events
    if event["stream"] == target_stream
    and event["key"] > target_open["key"]
]
eors = [event for event in stream_events if event["eor"]]
first_eor_key = eors[0]["key"] if eors else None

with open(events_path, "w", encoding="utf-8") as handle:
    for event in events:
        key = f"{event['key'][0]}.{event['key'][1]}"
        target = " target" if event["stream"] == target_stream else ""
        if event is target_open:
            phase = " target-open"
        elif event["stream"] != target_stream or event["key"] <= target_open["key"]:
            phase = ""
        elif first_eor_key is None or event["key"] < first_eor_key:
            phase = " pre-eor"
        elif event["key"] == first_eor_key:
            phase = " eor"
        else:
            phase = " live"
        if event["type"] == "1":
            kind = "OPEN"
        elif event["eor"]:
            kind = "EOR"
        elif event["prefixes"]:
            kind = "UPDATE nlri=" + ",".join(event["prefixes"])
        else:
            kind = f"BGP type={event['type']}"
        handle.write(
            f"{key} stream={event['stream']}{target}{phase} {kind}\n"
        )

if len(eors) != 1:
    raise SystemExit(
        f"{len(eors)} exact IPv4 EoRs on final stream {target_stream} "
        f"after OPEN {target_open['key']} (want 1)"
    )

eor = eors[0]
observed = sorted({
    prefix
    for event in stream_events
    if event["key"] < eor["key"]
    for prefix in event["prefixes"]
})
expected = sorted(expected)
if observed != expected:
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    raise SystemExit(
        f"initial prefix set before EoR {eor['key']} on stream "
        f"{target_stream} differs: missing={missing}, unexpected={unexpected}"
    )
print(
    f"final stream {target_stream} OPEN {target_open['key']}; "
    f"{len(expected)} expected initial prefixes precede EoR {eor['key']}"
)
PY
}

self_test_ipv4_eor_order() {
    local expected valid expected_after missing unexpected
    expected=$(mktemp)
    valid=$(mktemp)
    expected_after=$(mktemp)
    missing=$(mktemp)
    unexpected=$(mktemp)
    printf '%s\n' 100.66.0.0/24 100.67.0.0/24 >"$expected"
    python3 - "$valid" "$expected_after" "$missing" "$unexpected" <<'PY'
from pathlib import Path
import sys

opening = """<proto name="bgp"><field name="bgp.type" show="1"/></proto>"""
def nlri(prefix, length=24):
    return f"""<proto name="bgp"><field name="bgp.type" show="2"/>
<field name="" showname="{prefix}/{length}">
<field name="bgp.prefix_length" show="{length}"/>
<field name="bgp.nlri_prefix" show="{prefix}"/></field></proto>"""

eor = """<proto name="bgp" size="23"><field name="bgp.type" show="2"/>
<field name="bgp.update.withdrawn_routes.length" show="0"/>
<field name="bgp.update.path_attributes.length" show="0"/></proto>"""

def packet(frame, stream, *messages):
    return f"""<packet><proto name="frame"><field name="frame.number" show="{frame}"/></proto>
<proto name="tcp"><field name="tcp.stream" show="{stream}"/></proto>
{''.join(messages)}</packet>"""

def pdml(*packets):
    return "<pdml>" + "".join(packets) + "</pdml>"

old_open = packet(1, 3, opening)
target_open = packet(2, 7, opening)
first = packet(3, 7, nlri("100.66.0.0"))
# Load-bearing fixtures:
# - removing tcp.stream scoping admits the other-stream prefix before EoR;
# - treating post-EoR traffic as initial admits the same-stream live delta;
# - weakening exact-set equality admits each missing/unexpected fixture;
# - frame-only ordering cannot distinguish the same-frame EoR-before-prefix.
other_stream_late = packet(4, 3, nlri("198.51.100.0"))
second_and_eor = packet(5, 7, nlri("100.67.0.0"), eor)
same_stream_live = packet(6, 7, nlri("192.0.2.0"))

Path(sys.argv[1]).write_text(pdml(
    old_open, target_open, first, second_and_eor,
    same_stream_live, other_stream_late,
))
Path(sys.argv[2]).write_text(pdml(
    target_open, first,
    packet(4, 7, eor, nlri("100.67.0.0")),
))
Path(sys.argv[3]).write_text(pdml(
    target_open, first, packet(4, 7, eor),
))
Path(sys.argv[4]).write_text(pdml(
    target_open, first,
    packet(4, 7, nlri("100.67.0.0"), nlri("203.0.113.0"), eor),
))
PY
    local events
    events=$(mktemp)
    if ! check_ipv4_eor_order "$valid" "$expected" "$events" >/dev/null; then
        rm -f "$expected" "$valid" "$expected_after" "$missing" "$unexpected" "$events"
        return 1
    fi
    local fixture diagnostic output
    while read -r fixture diagnostic; do
        if output=$(check_ipv4_eor_order \
            "$fixture" "$expected" "$events" 2>&1); then
            echo "ERROR: invalid EoR inventory fixture passed: $fixture" >&2
            rm -f "$expected" "$valid" "$expected_after" "$missing" "$unexpected" "$events"
            return 1
        fi
        if ! grep -qF "$diagnostic" <<<"$output"; then
            echo "ERROR: invalid fixture failed for the wrong reason: $output" >&2
            rm -f "$expected" "$valid" "$expected_after" "$missing" "$unexpected" "$events"
            return 1
        fi
    done <<EOF
$expected_after missing=['100.67.0.0/24']
$missing missing=['100.67.0.0/24']
$unexpected unexpected=['203.0.113.0/24']
EOF
    rm -f "$expected" "$valid" "$expected_after" "$missing" "$unexpected" "$events"
    echo "M83 stream-scoped IPv4 EoR inventory self-test passed"
}

authoritative_established_snapshot() {
    printf '%s\n' "${1:?}" | jq -e '
        type == "object"
        and .state == "SESSION_STATE_ESTABLISHED"
        and ((.stale // false) == false)
        and ((try ((.flapCount // 0) | tonumber) catch -1) >= 0)
        and ((try ((.uptimeSeconds // 0) | tonumber) catch -1) >= 0)
    ' >/dev/null
}

check_session_continuity() {
    local before=${1:?} after=${2:?} marker_before=${3:?} marker_after=${4:?}
    authoritative_established_snapshot "$before" || return 1
    authoritative_established_snapshot "$after" || return 1
    jq -en \
        --argjson before "$before" \
        --argjson after "$after" \
        --arg marker_before "$marker_before" \
        --arg marker_after "$marker_after" '
        (($before.flapCount // 0) | tonumber)
            == (($after.flapCount // 0) | tonumber)
        and (($after.uptimeSeconds // 0) | tonumber)
            >= (($before.uptimeSeconds // 0) | tonumber)
        and ($marker_before | test("^[1-9][0-9]*$"))
        and $marker_after == $marker_before
    ' >/dev/null
}

self_test_session_continuity() {
    local before healthy dropped stale flapped replaced marker_before marker_after
    before='{"state":"SESSION_STATE_ESTABLISHED","flapCount":2,"uptimeSeconds":120}'
    healthy='{"state":"SESSION_STATE_ESTABLISHED","flapCount":2,"uptimeSeconds":121}'
    dropped='{"state":"SESSION_STATE_ACTIVE","flapCount":2,"uptimeSeconds":0}'
    stale='{"state":"SESSION_STATE_ESTABLISHED","stale":true,"flapCount":2,"uptimeSeconds":121}'
    flapped='{"state":"SESSION_STATE_ESTABLISHED","flapCount":3,"uptimeSeconds":1}'
    replaced='{"state":"SESSION_STATE_ESTABLISHED","flapCount":2,"uptimeSeconds":1}'
    marker_before=7
    marker_after=7

    # The former proof was only this marker predicate. Demonstrate that it
    # accepts a peer that dropped and never reconnected before requiring the
    # production continuity oracle to reject that same fixture.
    if [ "$marker_before" != "$marker_after" ] || [ "$marker_after" = "0" ]; then
        echo "ERROR: marker-only discriminator fixture is invalid" >&2
        return 1
    fi
    if ! check_session_continuity "$before" "$healthy" "$marker_before" "$marker_after"; then
        echo "ERROR: healthy authoritative continuity fixture failed" >&2
        return 1
    fi
    for invalid in "$dropped" "$stale" "$flapped" "$replaced"; do
        if check_session_continuity "$before" "$invalid" "$marker_before" "$marker_after"; then
            echo "ERROR: invalid continuity fixture passed: $invalid" >&2
            return 1
        fi
    done
    echo "M83 authoritative session-continuity self-test passed"
}

self_test_signal_artifacts() {
    local script=${1:?}
    local scratch status sentinel child_log
    scratch=$(mktemp -d)
    child_log="$scratch/signal-child.log"

    # Keep this proof host-independent: artifact collection calls the exported
    # stubs instead of requiring the interop-only Docker/grpcurl/jq toolchain,
    # while still exercising the production signal handler, work-directory
    # copy, and cleanup ordering.
    docker() { return 0; }
    grpcurl() { return 0; }
    jq() { return 0; }
    export -f docker grpcurl jq
    set +e
    M83_ARTIFACT_ROOT="$scratch/artifacts" \
        RUNNER_TEMP="$scratch" \
        CLEANUP=0 \
        bash "$script" --self-test-signal-child >"$child_log" 2>&1
    status=$?
    unset -f docker grpcurl jq

    sentinel=$(find "$scratch/artifacts" -type f -name signal-sentinel -print -quit 2>/dev/null)
    if [ "$status" -ne 143 ] || [ -z "$sentinel" ] \
        || ! grep -qxF "preserve on TERM" "$sentinel"; then
        echo "ERROR: TERM handler status=$status sentinel=${sentinel:-missing}" >&2
        if [ -s "$child_log" ]; then
            echo "--- signal child output ---" >&2
            sed -n '1,200p' "$child_log" >&2
        fi
        rm -rf "$scratch"
        return 1
    fi
    rm -rf "$scratch"
    echo "M83 TERM failure-artifact self-test passed"
}

case "${1:-}" in
    --check-eor-order)
        if [ "$#" -ne 4 ]; then
            echo "usage: $0 --check-eor-order PDML EXPECTED_PREFIXES EVENTS" >&2
            exit 2
        fi
        check_ipv4_eor_order "$2" "$3" "$4"
        exit
        ;;
    --self-test-eor-order)
        self_test_ipv4_eor_order
        exit
        ;;
    --self-test-session-continuity)
        self_test_session_continuity
        exit
        ;;
    --self-test-signal-artifacts)
        self_test_signal_artifacts "$0"
        exit
        ;;
    --self-test-signal-child)
        # Continue through normal initialization so the subprocess proof uses
        # the production traps. It terminates immediately after they are armed.
        ;;
esac

TOPO="m83-routeserver-multistack"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
GOBGP="clab-${TOPO}-gobgp"
FRR="clab-${TOPO}-frr"
STAYRTR="clab-${TOPO}-stayrtr"

RS_BIRD_ADDR="10.83.1.1"
RS_GOBGP_ADDR="10.83.2.1"
RS_FRR_ADDR="10.83.3.1"
BIRD_ADDR="10.83.1.2"
GOBGP_ADDR="10.83.2.2"
FRR_ADDR="10.83.3.2"

M83_WORK_DIR=$(mktemp -d "${RUNNER_TEMP:-/tmp}/m83-work.XXXXXX")
M83_EXPECTED_PREFIXES="$M83_WORK_DIR/expected-initial-prefixes.txt"
M83_ADVERTISED_JSON="$M83_WORK_DIR/advertised-inventory.json"
M83_ADVERTISED_PREFIXES="$M83_WORK_DIR/advertised-prefixes.txt"
M83_FINAL_PDML="$M83_WORK_DIR/final-rs-to-bird.pdml"
M83_STREAM_EVENTS="$M83_WORK_DIR/final-rs-to-bird-events.txt"
M83_ARTIFACT_ROOT="${M83_ARTIFACT_ROOT:-${RUNNER_TEMP:-/tmp}/m83-failure-artifacts}"
M83_CAPTURE_RUNNING=0
M83_ARTIFACTS_COLLECTED=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

rs_neighbor_state() {
    grpcurl_call \
        -d "{\"address\": \"${1:?}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

birdc_route_all() {
    docker exec "$BIRD" birdc show route all for "${1:?}" 2>/dev/null
}

frr_prefix_json() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast ${1:?} json" 2>/dev/null
}

gobgp_prefix_json() {
    docker exec "$GOBGP" gobgp global rib -a ipv4 "${1:?}" -j 2>/dev/null || echo "{}"
}

gobgp_has_prefix() {
    gobgp_prefix_json "$1" | jq -e --arg p "$1" '.[$p] | length >= 1' >/dev/null 2>&1
}

frr_has_prefix() {
    frr_prefix_json "$1" | jq -e '.paths | length >= 1' >/dev/null 2>&1
}

# AS_PATH string of the first path FRR holds for a prefix.
frr_aspath() {
    frr_prefix_json "$1" | jq -r '.paths[0].aspath.string // empty' 2>/dev/null
}

frr_nexthop() {
    frr_prefix_json "$1" | jq -r '.paths[0].nexthops[0].ip // empty' 2>/dev/null
}

wait_bird_established() {
    log "Waiting for BIRD session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$BIRD" birdc show protocols 2>/dev/null \
            | awk '$1 == "routeserver"' | grep -q "Established"; then
            ok "BIRD session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BIRD session did not reach Established within 90s"
    docker exec "$BIRD" birdc show protocols all routeserver 2>/dev/null | tail -20 || true
    return 1
}

wait_gobgp_established() {
    log "Waiting for GoBGP session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$GOBGP" gobgp neighbor "$RS_GOBGP_ADDR" 2>/dev/null \
            | grep -qi "state = ESTABLISHED\|BGP state = established"; then
            ok "GoBGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP session did not reach Established within 90s"
    docker exec "$GOBGP" gobgp neighbor 2>/dev/null || true
    return 1
}

# Poll until a predicate command succeeds. wait_for <label> <attempts> cmd...
wait_for() {
    local label=${1:?} attempts=${2:?}
    shift 2
    for _ in $(seq 1 "$attempts"); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    log "timeout waiting for: $label"
    return 1
}

# tshark over the RS→BIRD capture (runs inside the BIRD container).
bird_tshark() {
    docker exec "$BIRD" tshark -r /tmp/m83.pcap "$@" 2>/dev/null
}

collect_failure_artifacts() {
    [ "$M83_ARTIFACTS_COLLECTED" = "0" ] || return 0
    M83_ARTIFACTS_COLLECTED=1

    local artifact_dir
    artifact_dir="$M83_ARTIFACT_ROOT/attempt-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mkdir -p "$artifact_dir"

    # A failure may leave tshark live. Give it a bounded chance to flush the
    # capture before copying the attempt evidence out of the containers.
    if [ "$M83_CAPTURE_RUNNING" = "1" ]; then
        docker exec "$BIRD" sh -c '
            for file in /proc/[0-9]*/comm; do
                [ "$(cat "$file" 2>/dev/null)" = tshark ] || continue
                pid=${file#/proc/}; pid=${pid%/comm}
                kill -INT "$pid" 2>/dev/null || true
            done
        ' >/dev/null 2>&1 || true
        for _ in $(seq 1 5); do
            docker exec "$BIRD" sh -c \
                '! cat /proc/[0-9]*/comm 2>/dev/null | grep -qx tshark' \
                >/dev/null 2>&1 && break
            sleep 1
        done
    fi

    cp -f "$M83_WORK_DIR"/* "$artifact_dir"/ 2>/dev/null || true
    docker cp "$BIRD:/tmp/m83.pcap" "$artifact_dir/m83.pcap" 2>/dev/null || true
    docker cp "$BIRD:/tmp/tshark.log" "$artifact_dir/tshark.log" 2>/dev/null || true
    docker cp "$BIRD:/tmp/bird.log" "$artifact_dir/bird.log" 2>/dev/null || true
    docker cp "$RUSTBGPD:/tmp/rustbgpd.log" \
        "$artifact_dir/rustbgpd.log" 2>/dev/null || true
    docker logs "$BIRD" >"$artifact_dir/bird-container.log" 2>&1 || true
    docker logs "$RUSTBGPD" >"$artifact_dir/rustbgpd-container.log" 2>&1 || true
    log "Retained failed-attempt evidence under $artifact_dir"
}

cleanup_m83_attempt() {
    rm -rf "$M83_WORK_DIR"
    if [ "${CLEANUP:-0}" = "1" ]; then
        _cleanup_on_exit || true
    fi
}

m83_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ "$exit_code" -ne 0 ] || [ "${fail:-0}" -gt 0 ]; then
        collect_failure_artifacts
    fi
    cleanup_m83_attempt
    exit "$exit_code"
}

m83_on_signal() {
    local signal_number=${1:?}
    trap - EXIT INT TERM HUP
    set +e
    collect_failure_artifacts
    cleanup_m83_attempt
    exit "$((128 + signal_number))"
}

# The shared cleanup trap cannot retain container-resident evidence because the
# topology may already be gone. Collect first, then honor its opt-in cleanup.
trap m83_on_exit EXIT
trap 'm83_on_signal 1' HUP
trap 'm83_on_signal 2' INT
trap 'm83_on_signal 15' TERM

if [ "${1:-}" = "--self-test-signal-child" ]; then
    printf '%s\n' "preserve on TERM" >"$M83_WORK_DIR/signal-sentinel"
    kill -TERM "$$"
    echo "ERROR: TERM handler returned to the test body" >&2
    exit 0
fi

# ---------------------------------------------------------------------------
# Phase 0: bring the stacks up
# ---------------------------------------------------------------------------

start_capture() {
    log "Starting tshark capture on the RS↔BIRD link (inside $BIRD)..."
    docker exec "$BIRD" sh -c 'rm -f /tmp/m83.pcap' || true
    docker exec -d "$BIRD" sh -c \
        'tshark -i eth1 -w /tmp/m83.pcap port 179 >/tmp/tshark.log 2>&1'
    M83_CAPTURE_RUNNING=1
    sleep 2
}

stop_capture() {
    log "Stopping tshark capture..."
    local signaled
    if ! signaled=$(docker exec "$BIRD" sh -c '
        found=0
        capture_pid=
        for file in /proc/[0-9]*/comm; do
            [ "$(cat "$file" 2>/dev/null)" = tshark ] || continue
            pid=${file#/proc/}; pid=${pid%/comm}
            capture_pid=$pid
            found=$((found + 1))
        done
        [ "$found" -eq 1 ] || {
            echo "expected exactly one tshark capture, found $found" >&2
            exit 1
        }
        kill -INT "$capture_pid" || exit 1
        printf "%s\n" "$capture_pid"
    '); then
        fail "could not identify and signal exactly one tshark capture"
        return 1
    fi

    for _ in $(seq 1 10); do
        if ! docker exec "$BIRD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -qx tshark; then
            if docker exec "$BIRD" test -s /tmp/m83.pcap \
                && docker exec "$BIRD" tshark -r /tmp/m83.pcap -c 1 >/dev/null 2>&1; then
                log "tshark capture $signaled terminated; pcap is nonempty and readable"
                M83_CAPTURE_RUNNING=0
                return 0
            fi
            fail "tshark terminated without a nonempty readable /tmp/m83.pcap"
            return 1
        fi
        sleep 1
    done
    fail "tshark did not flush and exit within 10s"
    return 1
}

start_bird() {
    log "Starting BIRD..."
    docker exec "$BIRD" sh -c \
        'mkdir -p /run/bird && (bird -d -c /etc/bird/bird.conf >/tmp/bird.log 2>&1 &)'
}

start_gobgpd() {
    log "Starting gobgpd..."
    docker exec -d "$GOBGP" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

# Patch the StayRTR management address into a /tmp copy of the RS
# config (the M21 pattern) so the per_client_best flip can edit +
# SIGHUP the live file. The rpol file rides along: relative
# `rpol_files` paths resolve against the config file's directory.
patch_rs_config() {
    local stayrtr_ip
    stayrtr_ip=$(resolve_ip "$STAYRTR")
    if [ -z "$stayrtr_ip" ]; then
        echo "ERROR: cannot resolve management IP for $STAYRTR" >&2
        exit 1
    fi
    log "StayRTR address: ${stayrtr_ip}:3323"
    docker exec "$RUSTBGPD" sh -c \
        "sed 's/STAYRTR_ADDR/${stayrtr_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml \
         && cp /etc/rustbgpd/m83-hygiene.rpol /tmp/m83-hygiene.rpol"
}

rs_sighup() {
    docker exec "$RUSTBGPD" sh -c '
        pid=$(grep -lF rustbgpd /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3)
        [ -n "$pid" ] && kill -HUP "$pid"
    '
}

inject_gobgp_routes() {
    log "Injecting GoBGP member routes..."
    docker exec "$GOBGP" gobgp global rib add -a ipv4 100.66.0.0/24 \
        origin igp nexthop "$GOBGP_ADDR" med 77 \
        community 65002:222 large-community 65002:2:2 \
        && ok "GoBGP probe 100.66.0.0/24 injected (MED 77, 65002:222, 65002:2:2)" \
        || fail "GoBGP probe injection failed"
    docker exec "$GOBGP" gobgp global rib add -a ipv4 100.65.0.0/24 \
        origin igp nexthop "$GOBGP_ADDR" \
        && ok "GoBGP overlap runner-up 100.65.0.0/24 injected" \
        || fail "GoBGP overlap injection failed"
}

# ---------------------------------------------------------------------------
# Assertion phases
# ---------------------------------------------------------------------------

test_rtr_vrps() {
    log "Assertion 1: StayRTR VRPs loaded over RTR"
    local count=""
    for _ in $(seq 1 30); do
        count=$(prom_value "$RUSTBGPD" 'bgp_rpki_vrp_count{af="ipv4"}')
        [ "${count:-0}" = "2" ] && break
        sleep 2
    done
    if [ "${count:-0}" = "2" ]; then
        ok "bgp_rpki_vrp_count = 2 (both VRPs delivered)"
    else
        fail "bgp_rpki_vrp_count = '${count:-}' (want 2)"
    fi
}

assert_bird_probe() {
    log "Assertions 5-9: BIRD's view of GoBGP's probe 100.66.0.0/24"
    local out=""
    for _ in $(seq 1 30); do
        out=$(birdc_route_all 100.66.0.0/24)
        echo "$out" | grep -q "BGP.as_path" && break
        sleep 2
    done

    local aspath
    aspath=$(echo "$out" | grep "BGP.as_path" | head -1 | sed 's/.*BGP.as_path: *//')
    if [ "$aspath" = "65002" ]; then
        ok "BIRD AS_PATH = '65002' (leftmost = originator, no 65500)"
    else
        fail "BIRD AS_PATH = '$aspath' (want '65002')"
        echo "$out" >&2
    fi
    if echo "$out" | grep -q "BGP.next_hop: ${GOBGP_ADDR}$"; then
        ok "BIRD NEXT_HOP = $GOBGP_ADDR (originator's, unmodified)"
    else
        fail "BIRD NEXT_HOP not preserved (want $GOBGP_ADDR)"
        echo "$out" | grep "BGP.next_hop" >&2 || true
    fi
    if echo "$out" | grep -q "BGP.med: 77"; then
        ok "BIRD MED = 77 verbatim"
    else
        fail "BIRD MED missing/modified (want 77)"
    fi
    if echo "$out" | grep -q "BGP.community:.*(65002,222)"; then
        ok "BIRD standard community (65002,222) verbatim"
    else
        fail "BIRD standard community 65002:222 missing"
    fi
    if echo "$out" | grep -q "BGP.large_community:.*(65002, 2, 2)"; then
        ok "BIRD large community (65002, 2, 2) verbatim"
    else
        fail "BIRD large community 65002:2:2 missing"
    fi
}

assert_frr_probe() {
    log "Assertions 10-14: FRR's view of BIRD's probe 203.0.113.0/24"
    wait_for "203.0.113.0/24 on FRR" 30 frr_has_prefix 203.0.113.0/24 || true

    local aspath
    aspath=$(frr_aspath 203.0.113.0/24)
    if [ "$aspath" = "65001" ]; then
        ok "FRR AS_PATH = '65001' (no 65500)"
    else
        fail "FRR AS_PATH = '$aspath' (want '65001')"
    fi
    local nh
    nh=$(frr_nexthop 203.0.113.0/24)
    if [ "$nh" = "$BIRD_ADDR" ]; then
        ok "FRR NEXT_HOP = $BIRD_ADDR (originator's, unmodified)"
    else
        fail "FRR NEXT_HOP = '$nh' (want $BIRD_ADDR)"
    fi
    local med
    med=$(frr_prefix_json 203.0.113.0/24 | jq -r '.paths[0].med // .paths[0].metric // empty')
    if [ "$med" = "120" ]; then
        ok "FRR MED = 120 verbatim"
    else
        fail "FRR MED = '$med' (want 120)"
    fi
    if frr_prefix_json 203.0.113.0/24 | jq -e '.paths[0].community.string | test("65001:111")' >/dev/null 2>&1; then
        ok "FRR standard community 65001:111 verbatim"
    else
        fail "FRR standard community 65001:111 missing"
    fi
    if frr_prefix_json 203.0.113.0/24 | jq -e '.paths[0].largeCommunity.string | test("65001:1:1")' >/dev/null 2>&1; then
        ok "FRR large community 65001:1:1 verbatim"
    else
        fail "FRR large community 65001:1:1 missing"
    fi
}

assert_gobgp_probe() {
    log "Assertions 15-16: GoBGP's view of FRR's probe 100.67.0.0/24"
    wait_for "100.67.0.0/24 on GoBGP" 30 gobgp_has_prefix 100.67.0.0/24 || true

    if gobgp_prefix_json 100.67.0.0/24 | jq -e '
        .["100.67.0.0/24"][0].attrs[] | select(.type == 2) |
        .as_paths == [{"segment_type": 2, "num": 1, "asns": [65003]}]' >/dev/null 2>&1; then
        ok "GoBGP AS_PATH = [65003] (no 65500)"
    else
        fail "GoBGP AS_PATH for 100.67.0.0/24 not [65003]"
        gobgp_prefix_json 100.67.0.0/24 | jq '.["100.67.0.0/24"][0].attrs' >&2 || true
    fi
    if gobgp_prefix_json 100.67.0.0/24 | jq -e --arg nh "$FRR_ADDR" '
        .["100.67.0.0/24"][0].attrs[] | select(.type == 3) | .nexthop == $nh' >/dev/null 2>&1; then
        ok "GoBGP NEXT_HOP = $FRR_ADDR (originator's, unmodified)"
    else
        fail "GoBGP NEXT_HOP for 100.67.0.0/24 not $FRR_ADDR"
    fi
}

assert_otc_client_views() {
    log "Assertions 17-18: RFC 9234 OTC toward clients (role = route_server)"
    if frr_prefix_json 203.0.113.0/24 \
        | grep -Eiq 'only[ -]?to[ -]?customer|"otc"|onlyToCustomer'; then
        ok "FRR reports OTC on the reflected route"
    else
        fail "FRR does not report OTC on 203.0.113.0/24"
    fi
    if birdc_route_all 100.66.0.0/24 | grep -q "BGP.otc: 65500"; then
        ok "BIRD reports BGP.otc: 65500"
    else
        fail "BIRD does not report BGP.otc: 65500 on 100.66.0.0/24"
        birdc_route_all 100.66.0.0/24 >&2 || true
    fi
}

assert_member_scoped_deny() {
    log "Assertions 19-22: member-scoped export view (100.69.0.0/24 denied to FRR only)"
    wait_for "100.69.0.0/24 on GoBGP" 30 gobgp_has_prefix 100.69.0.0/24 || true

    if frr_has_prefix 100.69.0.0/24; then
        fail "FRR holds 100.69.0.0/24 (member-scoped deny leaked)"
    else
        ok "FRR lacks 100.69.0.0/24 (deny-to-frr applied)"
    fi
    if gobgp_has_prefix 100.69.0.0/24; then
        ok "GoBGP holds 100.69.0.0/24 (deny scoped to FRR only)"
    else
        fail "GoBGP missing 100.69.0.0/24"
    fi
    if rs_ctl rib advertised "$FRR_ADDR" -a ipv4 | grep -qF "100.69.0.0/24"; then
        fail "rbgp rib advertised to FRR lists 100.69.0.0/24"
    else
        ok "rbgp rib advertised to FRR agrees: 100.69.0.0/24 absent"
    fi
    if rs_ctl rib advertised "$GOBGP_ADDR" -a ipv4 | grep -qF "100.69.0.0/24"; then
        ok "rbgp rib advertised to GoBGP agrees: 100.69.0.0/24 present"
    else
        fail "rbgp rib advertised to GoBGP missing 100.69.0.0/24"
    fi
}

assert_rov() {
    log "Assertions 23-25: ROV — RPKI-invalid rejected at import, explain names the term"
    # 100.67.0.0/24 (same member, not-found) already propagated, so the
    # absence of the invalid twin is convergence-safe to assert now.
    if birdc_route_all 100.68.0.0/24 | grep -q "BGP.as_path"; then
        fail "BIRD holds RPKI-invalid 100.68.0.0/24"
    else
        ok "BIRD lacks RPKI-invalid 100.68.0.0/24"
    fi
    if gobgp_has_prefix 100.68.0.0/24; then
        fail "GoBGP holds RPKI-invalid 100.68.0.0/24"
    else
        ok "GoBGP lacks RPKI-invalid 100.68.0.0/24"
    fi
    local explain
    explain=$(rs_ctl policy explain --neighbor "$FRR_ADDR" --prefix 100.68.0.0/24)
    if echo "$explain" | grep -q "reject-rpki-invalid"; then
        ok "import explain names reject-rpki-invalid for 100.68.0.0/24"
    else
        fail "import explain does not name reject-rpki-invalid"
        echo "$explain" >&2
    fi
}

assert_path_hiding_single_best() {
    log "Assertions 26-28: path hiding pinned (FRR single-best, best denied)"
    wait_for "100.65.0.0/24 on GoBGP" 30 \
        sh -c "docker exec $GOBGP gobgp global rib -a ipv4 100.65.0.0/24 -j 2>/dev/null \
            | jq -e '.\"100.65.0.0/24\" | length >= 1'" || true

    if frr_has_prefix 100.65.0.0/24; then
        fail "FRR holds 100.65.0.0/24 in single-best mode (path hiding NOT observed?)"
    else
        ok "FRR receives NOTHING for 100.65.0.0/24 (RFC 7947 §2.3 path hiding, pinned)"
    fi
    # Sanity: the best (BIRD's, tagged 65001:666) does flow to a member
    # whose chain permits it.
    if gobgp_prefix_json 100.65.0.0/24 | jq -e '
        [.["100.65.0.0/24"][].attrs[] | select(.type == 2) | .as_paths[0].asns[0]]
        | index(65001) != null' >/dev/null 2>&1; then
        ok "GoBGP holds BIRD's best for 100.65.0.0/24 (deny is FRR-scoped)"
    else
        fail "GoBGP missing BIRD's path for 100.65.0.0/24"
    fi
    local explain
    explain=$(rs_ctl rib --prefix 100.65.0.0/24 advertised "$FRR_ADDR" --explain)
    if echo "$explain" | grep -q "^Deny" && echo "$explain" | grep -q "deny-to-frr"; then
        ok "export explain: Deny naming deny-to-frr (truthful single-best hiding)"
    else
        fail "export explain did not report Deny via deny-to-frr"
        echo "$explain" >&2
    fi
}

flip_frr_per_client_best() {
    log "Flipping the FRR member to per_client_best (sed + SIGHUP + session bounce)..."
    docker exec "$RUSTBGPD" sh -c \
        'sed -i "s/^per_client_best = false/per_client_best = true/" /tmp/config.toml'
    rs_sighup
    sleep 2
    # The knob is live-effective-next-session (docs/reload-matrix.md):
    # bounce the session from the member side so the new session
    # registers per-client-best with the RIB manager.
    docker exec "$FRR" vtysh -c "clear bgp ${RS_FRR_ADDR}" >/dev/null 2>&1 || true
    wait_frr_established "$FRR" "$RS_FRR_ADDR" "FRR (post per_client_best flip)"
}

assert_per_client_best() {
    log "Assertions 29-33: per-client best-path (RFC 7947 §2.3.2, ADR-0101)"
    if rs_ctl neighbor "$FRR_ADDR" | grep "per-client-best" >/dev/null; then
        ok "rbgp neighbor shows Distribution Mode per-client-best"
    else
        fail "Distribution Mode per-client-best not reported"
        rs_ctl neighbor "$FRR_ADDR" >&2 || true
    fi

    wait_for "runner-up 100.65.0.0/24 on FRR" 30 frr_has_prefix 100.65.0.0/24 || true
    local aspath nh
    aspath=$(frr_aspath 100.65.0.0/24)
    if [ "$aspath" = "65002" ]; then
        ok "FRR receives the runner-up (AS_PATH 65002) instead of nothing"
    else
        fail "FRR runner-up AS_PATH = '$aspath' (want '65002')"
    fi
    nh=$(frr_nexthop 100.65.0.0/24)
    if [ "$nh" = "$GOBGP_ADDR" ]; then
        ok "runner-up NEXT_HOP = $GOBGP_ADDR (originator's, still transparent)"
    else
        fail "runner-up NEXT_HOP = '$nh' (want $GOBGP_ADDR)"
    fi

    local explain
    explain=$(rs_ctl rib --prefix 100.65.0.0/24 advertised "$FRR_ADDR" --explain)
    if echo "$explain" | grep -q "candidate 1 of 2" \
        && echo "$explain" | grep -q "denied by export policy" \
        && echo "$explain" | grep -q "deny-to-frr"; then
        ok "explain walks the per-client ladder: candidate 1 of 2 denied by deny-to-frr"
    else
        fail "per-client explain ladder missing/wrong"
        echo "$explain" >&2
    fi
    if echo "$explain" | grep -q "^Advertise" \
        && echo "$explain" | grep -q "Route peer: ${GOBGP_ADDR}"; then
        ok "explain decision Advertise with route peer $GOBGP_ADDR (the runner-up)"
    else
        fail "explain decision/route-peer wrong for the runner-up"
        echo "$explain" >&2
    fi
}

assert_runner_up_withdraw_converges() {
    log "Assertion 34: withdrawing the runner-up's source converges FRR"
    docker exec "$GOBGP" gobgp global rib del -a ipv4 100.65.0.0/24 >/dev/null 2>&1 \
        || log "gobgp rib del returned non-zero"
    local gone=0
    for _ in $(seq 1 30); do
        if ! frr_has_prefix 100.65.0.0/24; then
            gone=1
            break
        fi
        sleep 2
    done
    if [ "$gone" = "1" ]; then
        ok "FRR converged to no path (best still denied, runner-up withdrawn cleanly)"
    else
        fail "FRR still holds 100.65.0.0/24 after the runner-up withdraw"
        frr_prefix_json 100.65.0.0/24 | jq . >&2 || true
    fi
}

assert_add_path_both() {
    log "Assertion 35: Add-Path member sees BOTH paths for 100.70.0.0/24"
    wait_for "2 paths for 100.70.0.0/24 on GoBGP" 30 \
        sh -c "docker exec $GOBGP gobgp global rib -a ipv4 100.70.0.0/24 -j 2>/dev/null \
            | jq -e '.\"100.70.0.0/24\" | length == 2'" || true
    if gobgp_prefix_json 100.70.0.0/24 | jq -e '
        [.["100.70.0.0/24"][].attrs[] | select(.type == 2) | .as_paths[0].asns[0]]
        | sort == [65001, 65003]' >/dev/null 2>&1; then
        ok "GoBGP holds both candidate paths (AS 65001 + AS 65003) via Add-Path"
    else
        fail "GoBGP does not hold both paths for 100.70.0.0/24"
        gobgp_prefix_json 100.70.0.0/24 | jq . >&2 || true
    fi
}

assert_wire() {
    log "Assertions 36-42: byte-level wire pins (tshark on the RS→BIRD capture)"
    # RS→BIRD BGP UPDATEs regardless of which side initiated TCP.
    local base="ip.src == ${RS_BIRD_ADDR} && bgp.type == 2"

    local paths
    paths=$(bird_tshark -Y "$base" -T fields \
        -e bgp.update.path_attribute.as_path_segment.as4 | tr ',' '\n' | sort -u)
    if [ -n "$paths" ] && ! echo "$paths" | grep -qx "65500"; then
        ok "no RS→BIRD UPDATE carries 65500 in any AS_PATH segment (saw: $(echo "$paths" | grep -v '^$' | tr '\n' ' '))"
    else
        fail "AS_PATH wire check failed (segments: $(echo "$paths" | tr '\n' ' '))"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.next_hop == ${GOBGP_ADDR}" \
        -T fields -e frame.number | grep -q .; then
        ok "wire NEXT_HOP ${GOBGP_ADDR} on the 100.66.0.0/24 UPDATE"
    else
        fail "wire NEXT_HOP for 100.66.0.0/24 not ${GOBGP_ADDR}"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.multi_exit_disc == 77" \
        -T fields -e frame.number | grep -q .; then
        ok "wire MED 77 verbatim"
    else
        fail "wire MED 77 missing"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.community_as == 65002 && bgp.update.path_attribute.community_value == 222" \
        -T fields -e frame.number | grep -q .; then
        ok "wire community 65002:222 verbatim"
    else
        fail "wire community 65002:222 missing"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.large_communities.ga == 65002 && bgp.large_communities.ldp1 == 2 && bgp.large_communities.ldp2 == 2" \
        -T fields -e frame.number | grep -q .; then
        ok "wire large community 65002:2:2 verbatim"
    else
        fail "wire large community 65002:2:2 missing"
    fi

    if bird_tshark -Y "$base && bgp.update.path_attribute.type_code == 35 && bgp.nlri_prefix" \
        -T fields -e frame.number | grep -q .; then
        ok "wire OTC path attribute (type 35) on RS→BIRD announcements"
    else
        fail "wire OTC attribute (type 35) missing"
    fi

    # The final BIRD session is bounced over a snapshotted, quiesced
    # Adj-RIB-Out. PDML preserves each BGP PDU and tcp.stream identity:
    # the oracle requires that exact nonempty initial prefix set before
    # the stream's EoR, while allowing legal live deltas after it.
    local eor_order
    if bird_tshark \
        -Y "ip.src == ${RS_BIRD_ADDR} && ip.dst == ${BIRD_ADDR} && bgp" \
        -T pdml >"$M83_FINAL_PDML" \
        && eor_order=$(check_ipv4_eor_order \
            "$M83_FINAL_PDML" \
            "$M83_EXPECTED_PREFIXES" \
            "$M83_STREAM_EVENTS" 2>&1); then
        ok "IPv4-unicast EoR follows the exact initial inventory on one TCP stream: $eor_order"
    else
        fail "EoR ordering check failed: ${eor_order:-PDML export failed}"
    fi
}

quiesce_bird_origination() {
    log "Quiescing BIRD member-route origination before the EoR probe..."
    docker exec "$BIRD" birdc disable statics >/dev/null

    local received=""
    for _ in $(seq 1 30); do
        received=$(rs_ctl rib received "$BIRD_ADDR" -a ipv4 -j) || received=""
        if printf '%s\n' "$received" | jq -e '
            type == "array" and length == 0
        ' >/dev/null 2>&1; then
            ok "BIRD source protocols are quiet and Adj-RIB-In is empty"
            return 0
        fi
        sleep 2
    done
    fail "BIRD member-route inventory did not quiesce before the session bounce"
    printf '%s\n' "$received" >&2
    return 1
}

snapshot_bird_advertised_inventory() {
    # This is the known route-server view after the BIRD-originated paths are
    # quiesced: one GoBGP probe and two permitted FRR paths. It is deliberately
    # nonempty and checked before it becomes the byte-level oracle input.
    printf '%s\n' \
        100.66.0.0/24 \
        100.67.0.0/24 \
        100.70.0.0/24 \
        >"$M83_EXPECTED_PREFIXES"

    local inventory="" exact=0
    for _ in $(seq 1 30); do
        inventory=$(rs_ctl rib advertised "$BIRD_ADDR" -a ipv4 -j) || inventory=""
        if printf '%s\n' "$inventory" | jq -e 'type == "array"' >/dev/null 2>&1; then
            printf '%s\n' "$inventory" >"$M83_ADVERTISED_JSON"
            printf '%s\n' "$inventory" \
                | jq -r 'sort_by(.prefix) | .[].prefix' \
                >"$M83_ADVERTISED_PREFIXES"
            if [ -s "$M83_ADVERTISED_PREFIXES" ] \
                && cmp -s "$M83_EXPECTED_PREFIXES" "$M83_ADVERTISED_PREFIXES"; then
                exact=1
                break
            fi
        fi
        sleep 2
    done

    if [ "$exact" = "1" ]; then
        ok "snapshotted exact nonempty BIRD Adj-RIB-Out inventory (3 prefixes)"
        return 0
    fi
    fail "BIRD Adj-RIB-Out does not match the known three-prefix initial inventory"
    diff -u "$M83_EXPECTED_PREFIXES" "$M83_ADVERTISED_PREFIXES" >&2 || true
    return 1
}

# Bounce the BIRD session over the quiesced, snapshotted RS table so the last
# stream has a deterministic initial inventory followed by its EoR.
bounce_bird_session() {
    log "Bouncing the BIRD session over the snapshotted RS table (EoR ordering probe)..."
    docker exec "$BIRD" birdc restart routeserver >/dev/null 2>&1 || true
    wait_bird_established
    local prefix
    while IFS= read -r prefix; do
        wait_for "$prefix back on BIRD" 30 sh -c \
            "docker exec $BIRD birdc show route all for $prefix 2>/dev/null | grep -q BGP.as_path" \
            || return 1
    done <"$M83_EXPECTED_PREFIXES"
}

assert_withdraw_propagation() {
    log "Assertions 43-44: withdraw propagation (BIRD withdraws 203.0.113.0/24)"
    docker exec "$BIRD" birdc disable statics_uniq >/dev/null 2>&1 || true
    local gone_frr=0 gone_gobgp=0
    for _ in $(seq 1 30); do
        frr_has_prefix 203.0.113.0/24 || gone_frr=1
        gobgp_has_prefix 203.0.113.0/24 || gone_gobgp=1
        [ "$gone_frr" = "1" ] && [ "$gone_gobgp" = "1" ] && break
        sleep 2
    done
    if [ "$gone_frr" = "1" ]; then
        ok "203.0.113.0/24 withdrawn from FRR"
    else
        fail "203.0.113.0/24 still on FRR after withdraw"
    fi
    if [ "$gone_gobgp" = "1" ]; then
        ok "203.0.113.0/24 withdrawn from GoBGP"
    else
        fail "203.0.113.0/24 still on GoBGP after withdraw"
    fi
}

assert_reload_stability() {
    log "Assertions 45-46: live route change and session stability through a policy reload"
    local marker_before marker_after state_before state_after
    local flaps_before flaps_after uptime_before uptime_after
    local lp_before lp_after generation_before generation_after
    if ! marker_before=$(docker exec "$FRR" vtysh \
        -c "show bgp neighbors ${RS_FRR_ADDR} json" 2>/dev/null \
        | jq -er --arg p "$RS_FRR_ADDR" '.[$p].connectionsEstablished // 0'); then
        fail "FRR cumulative establishment marker unavailable before reload"
        return
    fi
    if ! state_before=$(rs_neighbor_state "$FRR_ADDR") \
        || ! authoritative_established_snapshot "$state_before"; then
        fail "FRR continuity baseline is not an authoritative, non-stale Established snapshot"
        return
    fi
    flaps_before=$(printf '%s\n' "$state_before" | jq -r '(.flapCount // 0) | tonumber')
    uptime_before=$(printf '%s\n' "$state_before" | jq -r '(.uptimeSeconds // 0) | tonumber')
    lp_before=$(rs_ctl rib --prefix 100.67.0.0/24 -j \
        | jq -er --arg peer "$FRR_ADDR" '
            [.[] | select(.prefix == "100.67.0.0/24" and .peer_address == $peer)]
            | if length == 1 then .[0].local_pref
              else error("FRR probe route is not uniquely present")
              end')
    generation_before=$(rs_ctl -j policy stats --peer "$FRR_ADDR" --direction import \
        | jq -er --arg peer "$FRR_ADDR" '
            [.chains[] | select(.peer_address == $peer and .direction == "import")]
            | if length == 1 then .[0].policy_generation
              else error("FRR import chain is not uniquely installed")
              end')
    if [ "$lp_before" != "100" ]; then
        fail "FRR probe 100.67.0.0/24 pre-reload LP is $lp_before (want 100)"
        return
    fi

    # 100.67.0.0/24 is uniquely sourced by FRR and remains present for
    # this phase. Mutate the not-found term that accepted it, then
    # require both the live route and installed-chain generation to move.
    docker exec "$RUSTBGPD" sh -c '
        set -e
        [ "$(grep -c "^set_local_pref = 100$" /tmp/config.toml)" -eq 1 ]
        sed -i "s/^set_local_pref = 100$/set_local_pref = 110/" /tmp/config.toml
        [ "$(grep -c "^set_local_pref = 110$" /tmp/config.toml)" -eq 1 ]
    '
    rs_sighup

    lp_after=$lp_before
    generation_after=$generation_before
    for _ in $(seq 1 20); do
        lp_after=$(rs_ctl rib --prefix 100.67.0.0/24 -j \
            | jq -er --arg peer "$FRR_ADDR" '
                [.[] | select(.prefix == "100.67.0.0/24" and .peer_address == $peer)]
                | if length == 1 then .[0].local_pref
                  else error("FRR probe route is not uniquely present")
                  end')
        generation_after=$(rs_ctl -j policy stats --peer "$FRR_ADDR" --direction import \
            | jq -er --arg peer "$FRR_ADDR" '
                [.chains[] | select(.peer_address == $peer and .direction == "import")]
                | if length == 1 then .[0].policy_generation
                  else error("FRR import chain is not uniquely installed")
                  end')
        [ "$lp_after" = "110" ] && [ "$generation_after" -gt "$generation_before" ] && break
        sleep 1
    done
    if [ "$lp_after" = "110" ] && [ "$generation_after" -gt "$generation_before" ]; then
        ok "FRR probe stayed present and changed LP 100→110; import generation $generation_before→$generation_after"
    else
        fail "live reload did not move FRR probe LP/generation (LP $lp_before→$lp_after, generation $generation_before→$generation_after)"
    fi

    marker_after=$(docker exec "$FRR" vtysh \
        -c "show bgp neighbors ${RS_FRR_ADDR} json" 2>/dev/null \
        | jq -er --arg p "$RS_FRR_ADDR" '.[$p].connectionsEstablished // 0') \
        || marker_after=""
    state_after=$(rs_neighbor_state "$FRR_ADDR") || state_after='{}'
    flaps_after=$(printf '%s\n' "$state_after" | jq -r '(.flapCount // 0) | tonumber' 2>/dev/null) \
        || flaps_after="unavailable"
    uptime_after=$(printf '%s\n' "$state_after" | jq -r '(.uptimeSeconds // 0) | tonumber' 2>/dev/null) \
        || uptime_after="unavailable"
    if check_session_continuity \
        "$state_before" "$state_after" "$marker_before" "$marker_after"; then
        ok "FRR stayed authoritatively Established/non-stale across reload (flapCount $flaps_before→$flaps_after, uptime $uptime_before→$uptime_after, connectionsEstablished=$marker_after)"
    else
        fail "FRR session continuity failed across reload (state=$(printf '%s\n' "$state_after" | jq -r '.state // "unavailable"' 2>/dev/null || echo unavailable), stale=$(printf '%s\n' "$state_after" | jq -r '.stale // false' 2>/dev/null || echo unavailable), flapCount $flaps_before→$flaps_after, uptime $uptime_before→$uptime_after, connectionsEstablished $marker_before→${marker_after:-unavailable})"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    log "M83 interop test: route-server profile, multi-stack (BIRD 2 + GoBGP + FRR + RTR)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_capture
    start_bird
    start_gobgpd
    patch_rs_config
    start_rustbgpd \
        "/usr/local/bin/rustbgpd /tmp/config.toml >/tmp/rustbgpd.log 2>&1"

    test_rtr_vrps
    wait_bird_established
    wait_gobgp_established
    wait_frr_established "$FRR" "$RS_FRR_ADDR" "FRR member"

    inject_gobgp_routes

    assert_bird_probe
    assert_frr_probe
    assert_gobgp_probe
    assert_otc_client_views
    assert_member_scoped_deny
    assert_rov
    assert_path_hiding_single_best
    flip_frr_per_client_best
    assert_per_client_best
    assert_runner_up_withdraw_converges
    assert_add_path_both

    # Prove the independent withdraw path before quiescing the remaining
    # BIRD-originated probes for the exact initial-table wire oracle.
    assert_withdraw_propagation
    quiesce_bird_origination
    snapshot_bird_advertised_inventory
    bounce_bird_session
    stop_capture
    assert_wire

    assert_reload_stability

    print_summary
}

main "$@"
