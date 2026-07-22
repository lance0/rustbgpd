#!/usr/bin/env bash
# M92 — GoBGP v4.7 incumbent vs rustbgpd candidate, dual-stack IXP
# route-server differential. The normal run uses three fresh daemon
# rounds: baseline (exit 0), one-line candidate export mutant (exit 1,
# exactly one rustbgpd_only IPv6 row), and byte-identical restore (exit
# 0). Set M92_COMPLETENESS_NEGATIVE=1 for the separate load-bearing
# proof that routes without GoBGP EoRs stop before snapshot/diff.
# Five source routes enter each RS; baseline exports four (2v4+2v6),
# and the mutant exports only the named fifth IPv6 control prefix.

TOPO="m92-gobgp-v47-rs-differential"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_RS="clab-${TOPO}-gobgp-rs"
TARGET="clab-${TOPO}-target"
SOURCE1="clab-${TOPO}-source1"
SOURCE2="clab-${TOPO}-source2"
RUST_CONFIG="$SCRIPT_DIR/../configs/rustbgpd-m92-rs.toml"
ADAPTER="scripts/ribsnap/gobgp-adjout-to-ribsnap.py"
TARGET_ADDR="192.0.2.11"
CONTROL_PREFIX="2001:db8:92ff::/48"
WORK=""
BASE_CONFIG_SHA=""
BASELINE_CONFIG_SHA=""
RESTORE_CONFIG_SHA=""

poll() {
    local tries=${1:?} label=${2:?}
    shift 2
    for i in $(seq 1 "$tries"); do
        if "$@" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "$label — timed out after ${tries}s"
    return 1
}

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

kill_round_daemons() {
    local container comm signal
    for container in "$RUSTBGPD" "$GOBGP_RS" "$SOURCE1" "$SOURCE2" "$TARGET"; do
        for comm in rustbgpd gobgpd bird tshark; do
            signal=TERM
            [ "$comm" = tshark ] && signal=INT
            docker exec "$container" sh -c '
                wanted=$1 signal=$2
                for file in /proc/[0-9]*/comm; do
                    [ "$(cat "$file" 2>/dev/null)" = "$wanted" ] || continue
                    pid=${file#/proc/}; pid=${pid%/comm}
                    kill -"$signal" "$pid" 2>/dev/null || true
                done
            ' sh "$comm" "$signal" >/dev/null 2>&1 || true
        done
    done
    for _ in $(seq 1 10); do
        if ! docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -Eq '^(rustbgpd|gobgpd|bird|tshark)$' \
            && ! docker exec "$GOBGP_RS" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -Eq '^(rustbgpd|gobgpd|bird|tshark)$' \
            && ! docker exec "$SOURCE1" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -Eq '^(rustbgpd|gobgpd|bird|tshark)$' \
            && ! docker exec "$SOURCE2" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -Eq '^(rustbgpd|gobgpd|bird|tshark)$' \
            && ! docker exec "$TARGET" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -Eq '^(rustbgpd|gobgpd|bird|tshark)$'; then
            docker exec "$RUSTBGPD" rm -f /var/lib/rustbgpd/gr-restart.toml
            return
        fi
        sleep 1
    done
    echo "ERROR: prior M92 daemon did not stop within 10s" >&2
    return 1
}

gobgp_established() {
    docker exec "${1:?}" gobgp neighbor "${2:?}" 2>/dev/null \
        | grep -Eqi 'state.*establish'
}

rust_established() {
    rs_ctl neighbor -j | jq -e --arg peer "${1:?}" \
        'any(.[]; .address == $peer and .state == "Established")' >/dev/null
}

bird_established() {
    docker exec "$TARGET" birdc show protocols 2>/dev/null \
        | awk -v protocol="${1:?}" '$1 == protocol && $6 == "Established" { found=1 } END { exit !found }'
}

prepare_configs() {
    local mode=${1:?}
    docker exec "$RUSTBGPD" sh -c 'cp /config/rustbgpd.toml /tmp/rustbgpd.toml'
    docker exec "$GOBGP_RS" sh -c 'cp /config/gobgp.toml /tmp/gobgp.toml'
    if [ "$mode" = mutant ]; then
        [ "$(docker exec "$RUSTBGPD" grep -c '^action = "deny" # M92_TARGET_V6_CONTROL$' /tmp/rustbgpd.toml)" = 1 ]
        docker exec "$RUSTBGPD" sed -i \
            's/^action = "deny" # M92_TARGET_V6_CONTROL$/action = "permit" # M92_TARGET_V6_CONTROL/' \
            /tmp/rustbgpd.toml
        [ "$(docker exec "$RUSTBGPD" grep -c '^action = "permit" # M92_TARGET_V6_CONTROL$' /tmp/rustbgpd.toml)" = 1 ]
    elif [ "$mode" = no-gobgp-gr ]; then
        [ "$(docker exec "$GOBGP_RS" grep -c '^enabled = true # M92_TARGET_GR$' /tmp/gobgp.toml)" = 1 ]
        docker exec "$GOBGP_RS" sed -i \
            's/^enabled = true # M92_TARGET_GR$/enabled = false # M92_TARGET_GR/' \
            /tmp/gobgp.toml
        [ "$(docker exec "$GOBGP_RS" grep -c '^enabled = false # M92_TARGET_GR$' /tmp/gobgp.toml)" = 1 ]
    fi
}

start_sources_and_servers() {
    docker exec -d "$RUSTBGPD" sh -c \
        'rustbgpd /tmp/rustbgpd.toml >/tmp/m92-rustbgpd.log 2>&1'
    docker exec -d "$GOBGP_RS" sh -c \
        'gobgpd -f /tmp/gobgp.toml >/tmp/m92-gobgp-rs.log 2>&1'
    docker exec -d "$SOURCE1" sh -c \
        'gobgpd -f /config/gobgp.toml >/tmp/m92-source1.log 2>&1'
    docker exec -d "$SOURCE2" sh -c \
        'gobgpd -f /config/gobgp.toml >/tmp/m92-source2.log 2>&1'

    poll 30 "source1→rustbgpd Established" gobgp_established "$SOURCE1" 192.0.2.9
    poll 30 "source1→GoBGP Established" gobgp_established "$SOURCE1" 192.0.2.10
    poll 30 "source2→rustbgpd Established" gobgp_established "$SOURCE2" 192.0.2.9
    poll 30 "source2→GoBGP Established" gobgp_established "$SOURCE2" 192.0.2.10
    poll 30 "rustbgpd source1 Established" rust_established 192.0.2.12
    poll 30 "rustbgpd source2 Established" rust_established 192.0.2.13
}

inject_sources() {
    docker exec "$SOURCE1" gobgp global rib add -a ipv4 198.51.100.0/24 \
        origin igp nexthop 192.0.2.12 med 92 community 64501:92 \
        large-community 64501:92:4
    docker exec "$SOURCE1" gobgp global rib add -a ipv6 2001:db8:9201::/48 \
        origin igp nexthop 2001:db8:92::12 med 192 community 64501:192 \
        large-community 64501:92:6
    docker exec "$SOURCE2" gobgp global rib add -a ipv4 203.0.113.0/24 \
        origin igp nexthop 192.0.2.13
    docker exec "$SOURCE2" gobgp global rib add -a ipv6 2001:db8:9202::/48 \
        origin igp nexthop 2001:db8:92::13
    docker exec "$SOURCE2" gobgp global rib add -a ipv6 "$CONTROL_PREFIX" \
        origin igp nexthop 2001:db8:92::13
}

gobgp_peer_inventory() {
    local peer=${1:?} out4 out6
    out4=$(mktemp "$WORK/adj-in-v4.XXXXXX")
    out6=$(mktemp "$WORK/adj-in-v6.XXXXXX")
    docker exec "$GOBGP_RS" gobgp neighbor "$peer" adj-in -a ipv4 -j >"$out4"
    docker exec "$GOBGP_RS" gobgp neighbor "$peer" adj-in -a ipv6 -j >"$out6"
    jq -r -s --arg peer "$peer" '
        (.[0] * .[1]) | [to_entries[] | .value[] |
        select(."peer-address" == $peer) | .nlri.prefix] | sort | join(" ")
    ' "$out4" "$out6"
}

rust_peer_inventory() {
    rs_ctl rib received "${1:?}" -j | jq -r 'map(.prefix) | sort | join(" ")'
}

gobgp_inventory_is() { [ "$(gobgp_peer_inventory "${1:?}")" = "${2:?}" ]; }
rust_inventory_is() { [ "$(rust_peer_inventory "${1:?}")" = "${2:?}" ]; }

assert_source_inventory() {
    local want1='198.51.100.0/24 2001:db8:9201::/48'
    local want2='2001:db8:9202::/48 2001:db8:92ff::/48 203.0.113.0/24'
    poll 20 "GoBGP source1 exact pre-target inventory" \
        gobgp_inventory_is 192.0.2.12 "$want1"
    poll 20 "GoBGP source2 exact pre-target inventory" \
        gobgp_inventory_is 192.0.2.13 "$want2"
    poll 20 "rustbgpd source1 exact pre-target inventory" \
        rust_inventory_is 192.0.2.12 "$want1"
    poll 20 "rustbgpd source2 exact pre-target inventory" \
        rust_inventory_is 192.0.2.13 "$want2"
}

start_target_capture() {
    docker exec "$TARGET" sh -c 'rm -f /tmp/m92.pcap'
    docker exec -d "$TARGET" sh -c \
        'tshark -i eth1 -w /tmp/m92.pcap tcp port 179 >/tmp/m92-tshark.log 2>&1'
    sleep 2
    docker exec -d "$TARGET" sh -c \
        'bird -d -c /config/bird.conf >/tmp/m92-bird.log 2>&1'
    poll 45 "BIRD incumbent session Established" bird_established incumbent
    poll 45 "BIRD candidate session Established" bird_established candidate
}

bird_inventory() {
    local protocol=${1:?} expected=${2:?} out4 out6 want6 prefix
    out4=$(docker exec "$TARGET" birdc "show route table master4 protocol $protocol all" 2>/dev/null)
    out6=$(docker exec "$TARGET" birdc "show route table master6 protocol $protocol all" 2>/dev/null)
    want6=2
    [ "$expected" = 5 ] && want6=3
    [ "$(grep -cF "[$protocol " <<<"$out4")" = 2 ] || return 1
    [ "$(grep -cF "[$protocol " <<<"$out6")" = "$want6" ] || return 1
    for prefix in 198.51.100.0/24 203.0.113.0/24; do
        grep -qF "$prefix" <<<"$out4" || return 1
    done
    for prefix in 2001:db8:9201::/48 2001:db8:9202::/48; do
        grep -qF "$prefix" <<<"$out6" || return 1
    done
    if [ "$expected" = 5 ]; then
        grep -qF "$CONTROL_PREFIX" <<<"$out6"
    elif grep -qF "$CONTROL_PREFIX" <<<"$out6"; then
        return 1
    fi
}

stop_capture() {
    docker exec "$TARGET" sh -c '
        for file in /proc/[0-9]*/comm; do
            [ "$(cat "$file" 2>/dev/null)" = tshark ] || continue
            pid=${file#/proc/}; pid=${pid%/comm}; kill -INT "$pid"
        done
    '
    for _ in $(seq 1 10); do
        if ! docker exec "$TARGET" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -qx tshark; then
            docker exec "$TARGET" test -s /tmp/m92.pcap
            docker exec "$TARGET" tshark -r /tmp/m92.pcap -c 1 >/dev/null
            return
        fi
        sleep 1
    done
    echo "ERROR: tshark did not flush and exit within 10s" >&2
    return 1
}

export_pdml() {
    local rs=${1:?} out=${2:?}
    docker exec "$TARGET" tshark -r /tmp/m92.pcap \
        -Y "ip.src == $rs && ip.dst == $TARGET_ADDR && bgp.type == 2" -T pdml >"$out"
}

check_eor_order() {
    python3 - "${1:?}" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
last = {4: None, 6: None}
eors = {4: [], 6: []}
nlri_count = {4: 0, 6: 0}
for packet in root.findall("packet"):
    frame_field = packet.find(".//field[@name='frame.number']")
    frame = int(frame_field.get("show"))
    for index, bgp in enumerate(packet.findall(".//proto[@name='bgp']"), 1):
        bgp_type = bgp.find(".//field[@name='bgp.type']")
        if bgp_type is None or bgp_type.get("show") != "2":
            continue
        key = (frame, index)
        if bgp.findall(".//field[@name='bgp.nlri_prefix']"):
            last[4] = key
            nlri_count[4] += 1
        if bgp.findall(".//field[@name='bgp.mp_reach_nlri_ipv6_prefix']"):
            last[6] = key
            nlri_count[6] += 1
        withdrawn = bgp.find(".//field[@name='bgp.update.withdrawn_routes.length']")
        attrs = bgp.find(".//field[@name='bgp.update.path_attributes.length']")
        codes = [field.get("show") for field in bgp.findall(
            ".//field[@name='bgp.update.path_attribute.type_code']")]
        if withdrawn is not None and attrs is not None:
            classic = bgp.findall(".//field[@name='bgp.nlri_prefix']")
            if (bgp.get("size") == "23" and withdrawn.get("show") == "0"
                    and attrs.get("show") == "0" and not codes and not classic):
                eors[4].append(key)
            if (bgp.get("size") == "29" and withdrawn.get("show") == "0"
                    and attrs.get("show") == "6" and codes == ["15"] and not classic):
                afi = bgp.find(".//field[@name='bgp.update.path_attribute.mp_unreach_nlri.afi']")
                safi = bgp.find(".//field[@name='bgp.update.path_attribute.mp_unreach_nlri.safi']")
                nlri = bgp.find(".//field[@name='bgp.update.path_attribute.mp_unreach_nlri']")
                withdrawn_v6 = bgp.findall(".//field[@name='bgp.mp_unreach_nlri_ipv6_prefix']")
                if (afi is not None and afi.get("show") == "2" and safi is not None
                        and safi.get("show") == "1" and nlri is not None
                        and nlri.get("show") == "" and not withdrawn_v6
                        and not bgp.findall(".//field[@name='bgp.mp_reach_nlri_ipv6_prefix']")):
                    eors[6].append(key)

print(f"counts v4_nlri={nlri_count[4]} v6_nlri={nlri_count[6]} "
      f"v4_eor={len(eors[4])} v6_eor={len(eors[6])}")
errors = []
for family in (4, 6):
    if last[family] is None:
        errors.append(f"IPv{family}: no NLRI-bearing UPDATE")
    if len(eors[family]) != 1:
        errors.append(f"IPv{family}: {len(eors[family])} exact EoRs (want 1)")
    elif last[family] is not None and eors[family][0] <= last[family]:
        errors.append(f"IPv{family}: EoR {eors[family][0]} not after final NLRI {last[family]}")
    elif last[family] is not None:
        print(f"IPv{family}: final NLRI {last[family]} < EoR {eors[family][0]}")
if errors:
    raise SystemExit("; ".join(errors))
PY
}

check_same_frame_tuple_fixture() {
    local fixture="$WORK/same-frame-tuples.pdml"
    python3 - "$fixture" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_text("""<pdml><packet>
<proto name="frame"><field name="frame.number" show="1"/></proto>
<proto name="bgp"><field name="bgp.type" show="2"/>
<field name="bgp.nlri_prefix" show="198.51.100.0/24"/></proto>
<proto name="bgp" size="23"><field name="bgp.type" show="2"/>
<field name="bgp.update.withdrawn_routes.length" show="0"/>
<field name="bgp.update.path_attributes.length" show="0"/></proto>
<proto name="bgp"><field name="bgp.type" show="2"/>
<field name="bgp.mp_reach_nlri_ipv6_prefix" show="2001:db8:9201::/48"/></proto>
<proto name="bgp" size="29"><field name="bgp.type" show="2"/>
<field name="bgp.update.withdrawn_routes.length" show="0"/>
<field name="bgp.update.path_attributes.length" show="6"/>
<field name="bgp.update.path_attribute.type_code" show="15"/>
<field name="bgp.update.path_attribute.mp_unreach_nlri.afi" show="2"/>
<field name="bgp.update.path_attribute.mp_unreach_nlri.safi" show="1"/>
<field name="bgp.update.path_attribute.mp_unreach_nlri" show=""/></proto>
</packet></pdml>""")
PY
    check_eor_order "$fixture" >/dev/null
    ok "PDML completeness orders coalesced BGP PDUs by (frame,PDU)"
}

capture_incumbent() {
    local out=${1:?} v4 v6
    v4=$(mktemp "$WORK/adj-out-v4.XXXXXX")
    v6=$(mktemp "$WORK/adj-out-v6.XXXXXX")
    docker exec "$GOBGP_RS" gobgp neighbor "$TARGET_ADDR" adj-out -a ipv4 -j >"$v4"
    docker exec "$GOBGP_RS" gobgp neighbor "$TARGET_ADDR" adj-out -a ipv6 -j >"$v6"
    jq -S -s '.[0] * .[1]' "$v4" "$v6" >"$out"
    jq -e '[.[] | .[]] | length == 2' "$v4" >/dev/null
    jq -e '[.[] | .[]] | length == 2' "$v6" >/dev/null
    jq -e '[.[] | .[]] | length == 4' "$out" >/dev/null
}

canonical_sha() {
    jq -S -c 'walk(if type == "object" then del(.age) else . end)' "${1:?}" \
        | sha256sum | cut -d' ' -f1
}

run_diff() {
    local round=${1:?} expected=${2:?} raw1 raw2 snap result rc before after
    raw1="$WORK/${round}-before.json"
    raw2="$WORK/${round}-after.json"
    snap="$WORK/${round}.ndjson"
    result="$WORK/${round}-diff.json"
    capture_incumbent "$raw1"
    python3 "$ADAPTER" --peer "$TARGET_ADDR" --peer-asn 64510 \
        --source m92-gobgp-v4.7-incumbent --generation 92 "$raw1" >"$snap"
    docker cp "$snap" "$RUSTBGPD:/tmp/m92-incumbent.ndjson" >/dev/null
    set +e
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 -j \
        diff advertised --neighbor "$TARGET_ADDR" \
        --against /tmp/m92-incumbent.ndjson \
        --family ipv4-unicast --family ipv6-unicast >"$result"
    rc=$?
    set -e
    capture_incumbent "$raw2"
    before=$(canonical_sha "$raw1")
    after=$(canonical_sha "$raw2")
    [ "$before" = "$after" ] || { fail "$round incumbent capture changed around diff"; return 1; }
    ok "$round incumbent captures canonically equal around one diff"

    if [ "$expected" = 0 ]; then
        [ "$rc" = 0 ] && jq -e '
            .verdict == "in_sync" and (.entries | length) == 0 and
            ([.summaries[].matched] | add) == 4
        ' "$result" >/dev/null
    else
        [ "$rc" = 1 ] && jq -e '
            .verdict == "divergent" and (.entries | length) == 1 and
            .entries[0].class == "rustbgpd_only" and
            .entries[0].nlri.addr == "2001:db8:92ff::" and
            .entries[0].nlri.len == 48 and
            ([.summaries[].rustbgpd_only] | add) == 1
        ' "$result" >/dev/null
    fi
}

run_round() {
    local round=${1:?} mode=${2:?} expected=${3:?} candidate_count=4
    [ "$mode" = mutant ] && candidate_count=5
    log "M92 fresh round: $round"
    kill_round_daemons
    prepare_configs "$mode"
    start_sources_and_servers
    inject_sources
    assert_source_inventory
    start_target_capture
    poll 30 "BIRD incumbent exact target inventory" bird_inventory incumbent 4
    poll 30 "BIRD candidate exact target inventory" bird_inventory candidate "$candidate_count"
    stop_capture
    export_pdml 192.0.2.10 "$WORK/${round}-incumbent.pdml"
    export_pdml 192.0.2.9 "$WORK/${round}-candidate.pdml"
    check_eor_order "$WORK/${round}-incumbent.pdml" >/dev/null
    ok "$round GoBGP IPv4/IPv6 EoRs follow final family NLRIs by (frame,PDU)"
    check_eor_order "$WORK/${round}-candidate.pdml" >/dev/null
    ok "$round rustbgpd IPv4/IPv6 EoRs follow final family NLRIs by (frame,PDU)"
    if run_diff "$round" "$expected"; then
        ok "$round differential exit $expected with exact semantic verdict"
    else
        fail "$round differential did not meet exit $expected contract"
        cat "$WORK/${round}-diff.json" >&2 || true
    fi
    local live_sha
    live_sha=$(docker exec "$RUSTBGPD" sha256sum /tmp/rustbgpd.toml | cut -d' ' -f1)
    if [ "$round" = baseline ]; then BASELINE_CONFIG_SHA=$live_sha; fi
    if [ "$round" = restore ]; then RESTORE_CONFIG_SHA=$live_sha; fi
}

run_completeness_negative() {
    log "M92 separate completeness negative: GoBGP target GR disabled"
    kill_round_daemons
    prepare_configs no-gobgp-gr
    start_sources_and_servers
    inject_sources
    assert_source_inventory
    start_target_capture
    poll 30 "negative: incumbent routes are present" bird_inventory incumbent 4
    poll 30 "negative: candidate routes are present" bird_inventory candidate 4
    stop_capture
    export_pdml 192.0.2.10 "$WORK/negative-incumbent.pdml"
    export_pdml 192.0.2.9 "$WORK/negative-candidate.pdml"
    check_eor_order "$WORK/negative-candidate.pdml" >/dev/null
    ok "negative: rustbgpd EoR authority remains complete"
    if check_eor_order "$WORK/negative-incumbent.pdml" >"$WORK/negative-error" 2>&1; then
        fail "negative: GoBGP unexpectedly supplied complete EoR authority"
    elif grep -q 'counts v4_nlri=2 v6_nlri=2 v4_eor=0 v6_eor=0' \
        "$WORK/negative-error"; then
        ok "negative: both GoBGP EoRs are absent after exact route-bearing floods; receipt stops before snapshot/diff"
    else
        fail "negative: refusal was not the expected missing-EoR cause"
        cat "$WORK/negative-error" >&2
    fi
}

main() {
    WORK=$(mktemp -d)
    trap 'rc=$?; trap - EXIT; set +e; rm -rf "$WORK"; kill_round_daemons; _cleanup_on_exit; exit "$rc"' EXIT
    BASE_CONFIG_SHA=$(sha256sum "$RUST_CONFIG" | cut -d' ' -f1)
    check_same_frame_tuple_fixture

    if [ "${M92_COMPLETENESS_NEGATIVE:-0}" = 1 ]; then
        run_completeness_negative
    else
        run_round baseline baseline 0
        run_round mutant mutant 1
        run_round restore baseline 0
        if [ "$BASELINE_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] \
            && [ "$RESTORE_CONFIG_SHA" = "$BASE_CONFIG_SHA" ]; then
            ok "baseline and restored candidate configs are byte-identical to the checked-in input"
        else
            fail "candidate config was not restored byte for byte"
        fi
    fi
    print_summary
}

main "$@"
