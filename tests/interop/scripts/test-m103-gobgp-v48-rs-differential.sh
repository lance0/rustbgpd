#!/usr/bin/env bash
# M103 — GoBGP v4.8 incumbent vs rustbgpd candidate, dual-stack IXP
# route-server differential. The normal run uses three fresh daemon
# rounds: baseline (exit 0), one-line candidate export mutant (exit 1,
# exactly one rustbgpd_only IPv6 row), and byte-identical restore (exit
# 0). Set M103_COMPLETENESS_NEGATIVE=1 for the separate load-bearing
# proof that routes without GoBGP EoRs stop before snapshot/diff.
# Five source routes enter each RS; baseline exports four (2v4+2v6),
# and the mutant exports only the named fifth IPv6 control prefix.

TOPO="m103-gobgp-v48-rs-differential"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF_TEST_MODE=${1:-}
if [ "$SELF_TEST_MODE" = --self-test-artifact-export ]; then
    set -euo pipefail
    pass=0
    fail=0
    _ts() { date +%H:%M:%S 2>/dev/null || true; }
else
    INTEROP_TEST_OPERATOR_AUTH=1
    export INTEROP_TEST_OPERATOR_AUTH
    # shellcheck source=test-lib.sh
    source "$SCRIPT_DIR/test-lib.sh"
    # `test-lib.sh` initializes the shared ledger; the fallback is visible to
    # the linter when the dynamic source path cannot be followed.
    pass=${pass:-0}
fi

GOBGP_RS="clab-${TOPO}-gobgp-rs"
TARGET="clab-${TOPO}-target"
SOURCE1="clab-${TOPO}-source1"
SOURCE2="clab-${TOPO}-source2"
RUST_CONFIG="$SCRIPT_DIR/../configs/rustbgpd-m92-rs.toml"
ADAPTER="scripts/ribsnap/gobgp-adjout-to-ribsnap.py"
V47_RAW="crates/cli/tests/fixtures/ribsnap/gobgp-v47-m92-adjout.json"
V47_GOLDEN="crates/cli/tests/fixtures/ribsnap/gobgp-v47-m92.expected.ndjson"
V48_RAW="crates/cli/tests/fixtures/ribsnap/gobgp-v48-m103-adjout.json"
V48_GOLDEN="crates/cli/tests/fixtures/ribsnap/gobgp-v48-m103.expected.ndjson"
TARGET_ADDR="192.0.2.11"
CONTROL_PREFIX="2001:db8:92ff::/48"
WORK=""
BASE_CONFIG_SHA=""
BASELINE_CONFIG_SHA=""
RESTORE_CONFIG_SHA=""
TRANSCRIPT=""
ARTIFACT_STAGE=""
SELF_TEST_ROOT=""

append_transcript() {
    [ -n "$TRANSCRIPT" ] || return 0
    printf '%s\n' "${1:?}" >>"$TRANSCRIPT"
}

log() {
    local timestamp line
    timestamp=$(_ts)
    line="[$timestamp TEST] $*"
    printf '\033[1;34m[%s TEST]\033[0m %s\n' "$timestamp" "$*"
    append_transcript "$line"
}

ok() {
    local timestamp line
    pass=$((pass + 1))
    timestamp=$(_ts)
    line="[$timestamp] PASS $*"
    printf '\033[1;32m  [%s] PASS\033[0m %s\n' "$timestamp" "$*"
    append_transcript "$line"
}

fail() {
    local timestamp line
    fail=$((fail + 1))
    timestamp=$(_ts)
    line="[$timestamp] FAIL $*"
    printf '\033[1;31m  [%s] FAIL\033[0m %s\n' "$timestamp" "$*"
    append_transcript "$line"
}

require_equal() {
    local actual=${1:?} expected=${2:?} label=${3:?}
    if [ "$actual" != "$expected" ]; then
        printf 'ERROR: %s: expected %s, got %s\n' "$label" "$expected" "$actual" >&2
        exit 1
    fi
}

require_file_sha() {
    local path=${1:?} expected=${2:?}
    require_equal "$(sha256sum "$path" | cut -d' ' -f1)" "$expected" "$path SHA-256"
}

container_file_sha() {
    docker exec "${1:?}" sha256sum "${2:?}" | cut -d' ' -f1
}

canonicalize_raw() {
    jq -S -c 'walk(if type == "object" then del(.age) else . end)' "${1:?}"
}

require_canonical_raw_equal() {
    local left=${1:?} right=${2:?} label=${3:?} left_canonical right_canonical
    left_canonical=$(mktemp "$WORK/canonical-left.XXXXXX")
    right_canonical=$(mktemp "$WORK/canonical-right.XXXXXX")
    canonicalize_raw "$left" >"$left_canonical"
    canonicalize_raw "$right" >"$right_canonical"
    if ! cmp -s "$left_canonical" "$right_canonical"; then
        echo "ERROR: $label differs after deleting only recursive age fields" >&2
        diff -u "$left_canonical" "$right_canonical" >&2 || true
        exit 1
    fi
}

preflight_m103_identity_and_inputs() {
    local container image_id rust_image_id bird_image_id

    require_file_sha "$RUST_CONFIG" ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m92-rs.toml" cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m92-source1.toml" b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m92-source2.toml" 27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1
    require_file_sha "$SCRIPT_DIR/../configs/bird-m92-target.conf" 61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b
    require_file_sha "$V47_RAW" ab8d50f0f7e468837e93d85a6ff69640f2937535db71c28fe5c624ed0d794c84
    require_file_sha "$V47_GOLDEN" 664ee668f34acfd4a3ba23066a7e22ce2d8c092ccf1852cb9252fb1a729f1dd6
    require_file_sha "$V48_RAW" ba8ba57929ea2add127682fac599914a3baf083e44140e9165e9cd61546173db
    require_file_sha "$V48_GOLDEN" fd30efb01c8967d0ba335c864dc38f6e6922ad93413fd2b0ef9d9755f3f6c830

    image_id=$(docker image inspect -f '{{.Id}}' gobgp:v4.8.0-m103)
    require_equal "$(docker image inspect -f '{{.Architecture}}' gobgp:v4.8.0-m103)" amd64 \
        "GoBGP image architecture"
    for container in "$GOBGP_RS" "$SOURCE1" "$SOURCE2"; do
        require_equal "$(docker inspect -f '{{.Config.Image}}' "$container")" \
            gobgp:v4.8.0-m103 "$container configured image"
        require_equal "$(docker inspect -f '{{.Image}}' "$container")" "$image_id" \
            "$container local image identity"
        require_equal "$(docker exec "$container" uname -m)" x86_64 \
            "$container runtime architecture"
        require_equal "$(docker exec "$container" gobgp --version)" \
            "gobgp version 4.8.0" "$container gobgp version"
        require_equal "$(docker exec "$container" gobgpd --version)" \
            "gobgpd version 4.8.0" "$container gobgpd version"
        require_equal "$(container_file_sha "$container" /usr/local/bin/gobgp)" \
            5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b \
            "$container gobgp binary SHA-256"
        require_equal "$(container_file_sha "$container" /usr/local/bin/gobgpd)" \
            710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97 \
            "$container gobgpd binary SHA-256"
    done
    rust_image_id=$(docker image inspect -f '{{.Id}}' rustbgpd:dev)
    require_equal "$(docker inspect -f '{{.Config.Image}}' "$RUSTBGPD")" rustbgpd:dev \
        "$RUSTBGPD configured image"
    require_equal "$(docker inspect -f '{{.Image}}' "$RUSTBGPD")" "$rust_image_id" \
        "$RUSTBGPD local image identity"
    bird_image_id=$(docker image inspect -f '{{.Id}}' bird:2-bookworm)
    require_equal "$(docker inspect -f '{{.Config.Image}}' "$TARGET")" bird:2-bookworm \
        "$TARGET configured image"
    require_equal "$(docker inspect -f '{{.Image}}' "$TARGET")" "$bird_image_id" \
        "$TARGET local image identity"
    require_equal "$(docker exec "$TARGET" bird --version 2>&1)" "BIRD version 2.0.12" \
        "$TARGET BIRD version"

    require_equal "$(container_file_sha "$RUSTBGPD" /config/rustbgpd.toml)" \
        ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141 \
        "current rustbgpd M92-derived config"
    require_equal "$(container_file_sha "$GOBGP_RS" /config/gobgp.toml)" \
        cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925 \
        "GoBGP RS config"
    require_equal "$(container_file_sha "$SOURCE1" /config/gobgp.toml)" \
        b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3 \
        "GoBGP source1 config"
    require_equal "$(container_file_sha "$SOURCE2" /config/gobgp.toml)" \
        27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1 \
        "GoBGP source2 config"
    require_equal "$(container_file_sha "$TARGET" /config/bird.conf)" \
        61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b \
        "BIRD target config"

    require_canonical_raw_equal "$V47_RAW" "$V48_RAW" \
        "archived GoBGP 4.7 and versioned GoBGP 4.8 raw oracles"
    tail -n +2 "$V47_GOLDEN" >"$WORK/v47-routes-and-trailer.ndjson"
    tail -n +2 "$V48_GOLDEN" >"$WORK/v48-routes-and-trailer.ndjson"
    if ! cmp -s "$WORK/v47-routes-and-trailer.ndjson" \
        "$WORK/v48-routes-and-trailer.ndjson"; then
        echo "ERROR: GoBGP 4.7/4.8 route records or trailer differ" >&2
        diff -u "$WORK/v47-routes-and-trailer.ndjson" \
            "$WORK/v48-routes-and-trailer.ndjson" >&2 || true
        exit 1
    fi
    jq -n \
        --arg topology "$TOPO" \
        --arg rust_image_id "$rust_image_id" \
        --arg gobgp_image_id "$image_id" \
        --arg bird_image_id "$bird_image_id" \
        '{
          schema: "m103-identities/1",
          topology: $topology,
          images: {
            rustbgpd: {configured: "rustbgpd:dev", local_id: $rust_image_id},
            gobgp: {
              configured: "gobgp:v4.8.0-m103", local_id: $gobgp_image_id,
              architecture: "amd64", runtime_architecture: "x86_64",
              containers: ["gobgp-rs", "source1", "source2"],
              gobgp_version: "gobgp version 4.8.0",
              gobgpd_version: "gobgpd version 4.8.0",
              gobgp_sha256: "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
              gobgpd_sha256: "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97"
            },
            bird: {
              configured: "bird:2-bookworm", local_id: $bird_image_id,
              version: "BIRD version 2.0.12"
            }
          },
          configs: {
            rustbgpd_current_sha256: "ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141",
            rustbgpd_historical_m92_sha256: "957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a",
            gobgp_rs_sha256: "cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925",
            gobgp_source1_sha256: "b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3",
            gobgp_source2_sha256: "27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1",
            bird_target_sha256: "61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b"
          }
        }' >"$WORK/identities.json"
    log "M103 identities and inputs preflighted; historical M92 rust config was 957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a"
}

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
    # grep reads to EOF (no -q): -q's early exit can SIGPIPE the docker
    # exec writer, and under pipefail a surviving daemon would then read
    # as a false "stopped" verdict (LAN-1039).
    for _ in $(seq 1 10); do
        if ! docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -E '^(rustbgpd|gobgpd|bird|tshark)$' >/dev/null \
            && ! docker exec "$GOBGP_RS" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -E '^(rustbgpd|gobgpd|bird|tshark)$' >/dev/null \
            && ! docker exec "$SOURCE1" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -E '^(rustbgpd|gobgpd|bird|tshark)$' >/dev/null \
            && ! docker exec "$SOURCE2" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -E '^(rustbgpd|gobgpd|bird|tshark)$' >/dev/null \
            && ! docker exec "$TARGET" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -E '^(rustbgpd|gobgpd|bird|tshark)$' >/dev/null; then
            docker exec "$RUSTBGPD" rm -f /var/lib/rustbgpd/gr-restart.toml
            return
        fi
        sleep 1
    done
    echo "ERROR: prior M103 daemon did not stop within 10s" >&2
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
        'rustbgpd /tmp/rustbgpd.toml >/tmp/m103-rustbgpd.log 2>&1'
    docker exec -d "$GOBGP_RS" sh -c \
        'gobgpd -f /tmp/gobgp.toml >/tmp/m103-gobgp-rs.log 2>&1'
    docker exec -d "$SOURCE1" sh -c \
        'gobgpd -f /config/gobgp.toml >/tmp/m103-source1.log 2>&1'
    docker exec -d "$SOURCE2" sh -c \
        'gobgpd -f /config/gobgp.toml >/tmp/m103-source2.log 2>&1'

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
    docker exec "$TARGET" sh -c 'rm -f /tmp/m103.pcap'
    docker exec -d "$TARGET" sh -c \
        'tshark -i eth1 -w /tmp/m103.pcap tcp port 179 >/tmp/m103-tshark.log 2>&1'
    sleep 2
    docker exec -d "$TARGET" sh -c \
        'bird -d -c /config/bird.conf >/tmp/m103-bird.log 2>&1'
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
    # grep reads to EOF (no -q): -q's early exit can SIGPIPE the docker
    # exec writer, and under pipefail a still-running tshark would then
    # read as a false "terminated" verdict (LAN-1039).
    for _ in $(seq 1 10); do
        if ! docker exec "$TARGET" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
            | grep -x tshark >/dev/null; then
            docker exec "$TARGET" test -s /tmp/m103.pcap
            docker exec "$TARGET" tshark -r /tmp/m103.pcap -c 1 >/dev/null
            return
        fi
        sleep 1
    done
    echo "ERROR: tshark did not flush and exit within 10s" >&2
    return 1
}

export_pdml() {
    local rs=${1:?} out=${2:?}
    docker exec "$TARGET" tshark -r /tmp/m103.pcap \
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
    canonicalize_raw "${1:?}" | sha256sum | cut -d' ' -f1
}

run_diff() {
    local round=${1:?} expected=${2:?} raw1 raw2 snap result rc before after
    raw1="$WORK/${round}-before.json"
    raw2="$WORK/${round}-after.json"
    snap="$WORK/${round}.ndjson"
    result="$WORK/${round}-diff.json"
    capture_incumbent "$raw1"
    require_canonical_raw_equal "$V47_RAW" "$raw1" \
        "$round live GoBGP 4.8 vs archived GoBGP 4.7 raw oracle"
    require_canonical_raw_equal "$V48_RAW" "$raw1" \
        "$round live GoBGP 4.8 vs versioned GoBGP 4.8 raw oracle"
    python3 "$ADAPTER" --peer "$TARGET_ADDR" --peer-asn 64510 \
        --source m103-gobgp-v4.8-incumbent --generation 103 "$raw1" >"$snap"
    if ! cmp -s "$V48_GOLDEN" "$snap"; then
        echo "ERROR: $round live GoBGP 4.8 adapter output differs from the M103 golden" >&2
        diff -u "$V48_GOLDEN" "$snap" >&2 || true
        exit 1
    fi
    docker cp "$snap" "$RUSTBGPD:/tmp/m103-incumbent.ndjson" >/dev/null
    set +e
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 -j \
        diff advertised --neighbor "$TARGET_ADDR" \
        --against /tmp/m103-incumbent.ndjson \
        --family ipv4-unicast --family ipv6-unicast >"$result"
    rc=$?
    set -e
    capture_incumbent "$raw2"
    require_canonical_raw_equal "$V47_RAW" "$raw2" \
        "$round post-diff GoBGP 4.8 vs archived GoBGP 4.7 raw oracle"
    require_canonical_raw_equal "$V48_RAW" "$raw2" \
        "$round post-diff GoBGP 4.8 vs versioned GoBGP 4.8 raw oracle"
    before=$(canonical_sha "$raw1")
    after=$(canonical_sha "$raw2")
    printf '%s  %s\n%s  %s\n' \
        "$before" "${round}-before.json" \
        "$after" "${round}-after.json" >"$WORK/${round}-canonical.sha256"
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
    log "M103 fresh round: $round"
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
    log "M103 separate completeness negative: GoBGP target GR disabled"
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
    check_eor_order "$WORK/negative-candidate.pdml" \
        >"$WORK/negative-candidate-verifier.txt"
    ok "negative: rustbgpd EoR authority remains complete"
    if check_eor_order "$WORK/negative-incumbent.pdml" \
        >"$WORK/negative-incumbent-verifier.txt" 2>&1; then
        fail "negative: GoBGP unexpectedly supplied complete EoR authority"
    elif grep -q 'counts v4_nlri=2 v6_nlri=2 v4_eor=0 v6_eor=0' \
        "$WORK/negative-incumbent-verifier.txt"; then
        ok "negative: both GoBGP EoRs are absent after exact route-bearing floods; receipt stops before snapshot/diff"
    else
        fail "negative: refusal was not the expected missing-EoR cause"
        cat "$WORK/negative-incumbent-verifier.txt" >&2
    fi
}

artifact_payload_files() {
    local mode=${1:?} round
    if [ "$mode" = normal ]; then
        for round in baseline mutant restore; do
            printf '%s\n' \
                "${round}-before.json" \
                "${round}-after.json" \
                "${round}-canonical.sha256" \
                "${round}.ndjson" \
                "${round}-diff.json" \
                "${round}-incumbent.pdml" \
                "${round}-candidate.pdml"
        done
    elif [ "$mode" = negative ]; then
        printf '%s\n' negative-candidate-verifier.txt negative-incumbent-verifier.txt
    else
        echo "ERROR: unknown M103 artifact mode: $mode" >&2
        return 1
    fi
    printf '%s\n' identities.json ledger.json transcript.log
}

artifact_all_files() {
    artifact_payload_files "${1:?}"
    printf '%s\n' artifact-manifest.sha256
}

validate_artifact_inventory() {
    local stage=${1:?} mode=${2:?} expected actual
    expected=$(artifact_all_files "$mode" | LC_ALL=C sort)
    actual=$(find "$stage" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
    [ "$actual" = "$expected" ] || {
        echo "ERROR: M103 $mode artifact inventory mismatch" >&2
        diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
        return 1
    }
    if find "$stage" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
        echo "ERROR: M103 artifact inventory contains a non-regular entry" >&2
        return 1
    fi
}

validate_artifact_payload() {
    local stage=${1:?} mode=${2:?} expected_pass size round before after hashes expected_hashes
    expected_pass=56
    [ "$mode" = negative ] && expected_pass=17

    jq -e '
      .schema == "m103-identities/1" and
      .topology == "m103-gobgp-v48-rs-differential" and
      .images.rustbgpd.configured == "rustbgpd:dev" and
      (.images.rustbgpd.local_id | startswith("sha256:")) and
      .images.gobgp.configured == "gobgp:v4.8.0-m103" and
      (.images.gobgp.local_id | startswith("sha256:")) and
      .images.gobgp.architecture == "amd64" and
      .images.gobgp.runtime_architecture == "x86_64" and
      .images.gobgp.containers == ["gobgp-rs", "source1", "source2"] and
      .images.gobgp.gobgp_version == "gobgp version 4.8.0" and
      .images.gobgp.gobgpd_version == "gobgpd version 4.8.0" and
      .images.gobgp.gobgp_sha256 == "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b" and
      .images.gobgp.gobgpd_sha256 == "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97" and
      .images.bird.configured == "bird:2-bookworm" and
      (.images.bird.local_id | startswith("sha256:")) and
      .images.bird.version == "BIRD version 2.0.12" and
      .configs.rustbgpd_current_sha256 == "ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141" and
      .configs.rustbgpd_historical_m92_sha256 == "957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a" and
      .configs.gobgp_rs_sha256 == "cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925" and
      .configs.gobgp_source1_sha256 == "b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3" and
      .configs.gobgp_source2_sha256 == "27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1" and
      .configs.bird_target_sha256 == "61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b"
    ' "$stage/identities.json" >/dev/null || return 1
    jq -e --arg mode "$mode" --argjson expected "$expected_pass" '
      .schema == "m103-ledger/1" and .mode == $mode and
      .passed == $expected and .failed == 0 and .expected == $expected
    ' "$stage/ledger.json" >/dev/null || return 1
    grep -q "Results: $expected_pass passed, 0 failed" "$stage/transcript.log" || return 1

    if [ "$mode" = normal ]; then
        for round in baseline mutant restore; do
            jq -e '[.[] | .[]] | length == 4' "$stage/${round}-before.json" >/dev/null
            jq -e '[.[] | .[]] | length == 4' "$stage/${round}-after.json" >/dev/null
            require_canonical_raw_equal "$V47_RAW" "$stage/${round}-before.json" \
                "$round exported before-capture vs archived GoBGP 4.7"
            require_canonical_raw_equal "$V47_RAW" "$stage/${round}-after.json" \
                "$round exported after-capture vs archived GoBGP 4.7"
            cmp -s "$V48_GOLDEN" "$stage/${round}.ndjson" || return 1
            python3 - "$stage/${round}-incumbent.pdml" \
                "$stage/${round}-candidate.pdml" <<'PY'
import sys
import xml.etree.ElementTree as ET
for path in sys.argv[1:]:
    ET.parse(path)
PY
            if [ "$round" = mutant ]; then
                jq -e '.verdict == "divergent" and (.entries | length) == 1 and
                  .entries[0].class == "rustbgpd_only" and
                  .entries[0].nlri.addr == "2001:db8:92ff::" and
                  .entries[0].nlri.len == 48' "$stage/${round}-diff.json" >/dev/null
            else
                jq -e '.verdict == "in_sync" and (.entries | length) == 0' \
                    "$stage/${round}-diff.json" >/dev/null
            fi
            before=$(canonical_sha "$stage/${round}-before.json")
            after=$(canonical_sha "$stage/${round}-after.json")
            expected_hashes=$(printf '%s  %s\n%s  %s\n' \
                "$before" "${round}-before.json" "$after" "${round}-after.json")
            hashes=$(cat "$stage/${round}-canonical.sha256")
            [ "$hashes" = "$expected_hashes" ] || return 1
        done
        size=$(du -sb "$stage" | cut -f1)
        [ "$size" -le 16777216 ] || return 1
    else
        grep -q 'counts v4_nlri=2 v6_nlri=2 v4_eor=1 v6_eor=1' \
            "$stage/negative-candidate-verifier.txt" || return 1
        grep -q 'counts v4_nlri=2 v6_nlri=2 v4_eor=0 v6_eor=0' \
            "$stage/negative-incumbent-verifier.txt" || return 1
        if find "$stage" -maxdepth 1 \( -name '*.json' -o -name '*.ndjson' -o -name '*.pdml' \) \
            ! -name identities.json ! -name ledger.json -print -quit | grep -q .; then
            echo "ERROR: negative evidence implies a route capture or diff" >&2
            return 1
        fi
        size=$(du -sb "$stage" | cut -f1)
        [ "$size" -le 1048576 ] || return 1
    fi
}

write_artifact_manifest() {
    local stage=${1:?} mode=${2:?} file
    : >"$stage/artifact-manifest.sha256"
    while IFS= read -r file; do
        (cd "$stage" && sha256sum "$file") >>"$stage/artifact-manifest.sha256"
    done < <(artifact_payload_files "$mode" | LC_ALL=C sort)
}

validate_artifact_stage() {
    local stage=${1:?} mode=${2:?}
    validate_artifact_inventory "$stage" "$mode" || return 1
    validate_artifact_payload "$stage" "$mode" || return 1
    (cd "$stage" && sha256sum -c artifact-manifest.sha256 >/dev/null) || return 1
}

export_success_artifacts() {
    local mode=${1:?} destination=${M103_ARTIFACT_DIR:-} round source
    [ -n "$destination" ] || return 0
    case "$destination" in
        /*) ;;
        *) echo "ERROR: M103_ARTIFACT_DIR must be an absolute path" >&2; return 1 ;;
    esac
    [ "$destination" != / ] || return 1
    case "$destination/" in
        "$WORK"/*) echo "ERROR: M103_ARTIFACT_DIR must survive WORK cleanup" >&2; return 1 ;;
    esac
    [ ! -e "$destination" ] || {
        echo "ERROR: M103_ARTIFACT_DIR already exists: $destination" >&2
        return 1
    }
    mkdir -p "$(dirname "$destination")"
    ARTIFACT_STAGE="${destination}.stage.$$"
    [ ! -e "$ARTIFACT_STAGE" ] || return 1
    mkdir "$ARTIFACT_STAGE"

    if [ "$mode" = normal ]; then
        for round in baseline mutant restore; do
            for source in \
                "${round}-before.json" "${round}-after.json" \
                "${round}-canonical.sha256" "${round}.ndjson" \
                "${round}-diff.json" "${round}-incumbent.pdml" \
                "${round}-candidate.pdml"; do
                cp "$WORK/$source" "$ARTIFACT_STAGE/$source" || return 1
            done
        done
    else
        cp "$WORK/negative-candidate-verifier.txt" \
            "$WORK/negative-incumbent-verifier.txt" "$ARTIFACT_STAGE/" || return 1
    fi
    cp "$WORK/identities.json" "$WORK/ledger.json" "$TRANSCRIPT" "$ARTIFACT_STAGE/" \
        || return 1
    write_artifact_manifest "$ARTIFACT_STAGE" "$mode" || return 1
    validate_artifact_stage "$ARTIFACT_STAGE" "$mode" || return 1
    mv "$ARTIFACT_STAGE" "$destination" || return 1
    ARTIFACT_STAGE=""
}

write_ledger() {
    local mode=${1:?} expected=${2:?}
    jq -n --arg mode "$mode" --argjson passed "$pass" \
        --argjson failed "$fail" --argjson expected "$expected" \
        '{schema: "m103-ledger/1", mode: $mode, passed: $passed,
          failed: $failed, expected: $expected}' >"$WORK/ledger.json"
}

cleanup_m103() {
    local rc=${1:?}
    trap - EXIT
    set +e
    [ -z "$ARTIFACT_STAGE" ] || rm -rf "$ARTIFACT_STAGE"
    rm -rf "$WORK"
    kill_round_daemons
    _cleanup_on_exit
    exit "$rc"
}

write_self_test_identity() {
    jq -n '{
      schema: "m103-identities/1", topology: "m103-gobgp-v48-rs-differential",
      images: {
        rustbgpd: {configured: "rustbgpd:dev", local_id: "sha256:selftest-rust"},
        gobgp: {configured: "gobgp:v4.8.0-m103", local_id: "sha256:selftest-gobgp",
          architecture: "amd64", runtime_architecture: "x86_64",
          containers: ["gobgp-rs", "source1", "source2"],
          gobgp_version: "gobgp version 4.8.0", gobgpd_version: "gobgpd version 4.8.0",
          gobgp_sha256: "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
          gobgpd_sha256: "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97"},
        bird: {configured: "bird:2-bookworm", local_id: "sha256:selftest-bird",
          version: "BIRD version 2.0.12"}},
      configs: {
        rustbgpd_current_sha256: "ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141",
        rustbgpd_historical_m92_sha256: "957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a",
        gobgp_rs_sha256: "cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925",
        gobgp_source1_sha256: "b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3",
        gobgp_source2_sha256: "27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1",
        bird_target_sha256: "61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b"}}
    ' >"${1:?}"
}

make_self_test_normal_work() {
    local round before after
    write_self_test_identity "$WORK/identities.json"
    printf '%s\n' '[00:00:00 TEST] Results: 56 passed, 0 failed' >"$TRANSCRIPT"
    printf '%s\n' '{"schema":"m103-ledger/1","mode":"normal","passed":56,"failed":0,"expected":56}' \
        >"$WORK/ledger.json"
    for round in baseline mutant restore; do
        cp "$V48_RAW" "$WORK/${round}-before.json"
        cp "$V48_RAW" "$WORK/${round}-after.json"
        cp "$V48_GOLDEN" "$WORK/${round}.ndjson"
        printf '%s\n' '<?xml version="1.0"?><pdml/>' >"$WORK/${round}-incumbent.pdml"
        printf '%s\n' '<?xml version="1.0"?><pdml/>' >"$WORK/${round}-candidate.pdml"
        if [ "$round" = mutant ]; then
            printf '%s\n' '{"verdict":"divergent","entries":[{"class":"rustbgpd_only","nlri":{"addr":"2001:db8:92ff::","len":48}}]}' \
                >"$WORK/${round}-diff.json"
        else
            printf '%s\n' '{"verdict":"in_sync","entries":[]}' >"$WORK/${round}-diff.json"
        fi
        before=$(canonical_sha "$WORK/${round}-before.json")
        after=$(canonical_sha "$WORK/${round}-after.json")
        printf '%s  %s\n%s  %s\n' "$before" "${round}-before.json" \
            "$after" "${round}-after.json" >"$WORK/${round}-canonical.sha256"
    done
}

make_self_test_negative_work() {
    write_self_test_identity "$WORK/identities.json"
    printf '%s\n' '[00:00:00 TEST] Results: 17 passed, 0 failed' >"$TRANSCRIPT"
    printf '%s\n' '{"schema":"m103-ledger/1","mode":"negative","passed":17,"failed":0,"expected":17}' \
        >"$WORK/ledger.json"
    printf '%s\n' \
        'counts v4_nlri=2 v6_nlri=2 v4_eor=1 v6_eor=1' \
        'IPv4: final NLRI (1, 1) < EoR (2, 1)' \
        'IPv6: final NLRI (1, 2) < EoR (2, 2)' \
        >"$WORK/negative-candidate-verifier.txt"
    printf '%s\n' \
        'counts v4_nlri=2 v6_nlri=2 v4_eor=0 v6_eor=0' \
        'IPv4: 0 exact EoRs (want 1); IPv6: 0 exact EoRs (want 1)' \
        >"$WORK/negative-incumbent-verifier.txt"
}

artifact_export_self_test() {
    local destination negative_destination a b c
    SELF_TEST_ROOT=$(mktemp -d)
    trap 'rm -rf "$SELF_TEST_ROOT"' EXIT
    WORK="$SELF_TEST_ROOT/work"
    TRANSCRIPT="$WORK/transcript.log"
    destination="$SELF_TEST_ROOT/exported"
    mkdir "$WORK"
    make_self_test_normal_work
    M103_ARTIFACT_DIR="$destination"
    export M103_ARTIFACT_DIR
    export_success_artifacts normal
    [ -d "$WORK" ] && [ -d "$destination" ]
    rm -rf "$WORK"
    [ -d "$destination" ]

    cp -a "$destination" "$SELF_TEST_ROOT/missing"
    rm "$SELF_TEST_ROOT/missing/transcript.log"
    if validate_artifact_stage "$SELF_TEST_ROOT/missing" normal >/dev/null 2>&1; then return 1; fi
    cp -a "$destination" "$SELF_TEST_ROOT/corrupt"
    printf '%s\n' '{"schema":"m103-ledger/1","mode":"normal","passed":55,"failed":0,"expected":56}' \
        >"$SELF_TEST_ROOT/corrupt/ledger.json"
    if validate_artifact_stage "$SELF_TEST_ROOT/corrupt" normal >/dev/null 2>&1; then return 1; fi
    cp -a "$destination" "$SELF_TEST_ROOT/unexpected"
    : >"$SELF_TEST_ROOT/unexpected/unexpected.txt"
    if validate_artifact_stage "$SELF_TEST_ROOT/unexpected" normal >/dev/null 2>&1; then return 1; fi

    a="$SELF_TEST_ROOT/a.json"; b="$SELF_TEST_ROOT/b.json"; c="$SELF_TEST_ROOT/c.json"
    printf '%s\n' '{"route":{"age":1,"best":false}}' >"$a"
    printf '%s\n' '{"route":{"age":999,"best":false}}' >"$b"
    printf '%s\n' '{"route":{"age":999,"best":true}}' >"$c"
    [ "$(canonical_sha "$a")" = "$(canonical_sha "$b")" ]
    [ "$(canonical_sha "$a")" != "$(canonical_sha "$c")" ]

    WORK="$SELF_TEST_ROOT/negative-work"
    TRANSCRIPT="$WORK/transcript.log"
    negative_destination="$SELF_TEST_ROOT/negative-exported"
    mkdir "$WORK"
    make_self_test_negative_work
    M103_ARTIFACT_DIR="$negative_destination"
    export M103_ARTIFACT_DIR
    export_success_artifacts negative
    validate_artifact_stage "$negative_destination" negative
    (( $(find "$negative_destination" -maxdepth 1 -type f | wc -l) == 6 ))
    trap - EXIT
    rm -rf "$SELF_TEST_ROOT"
    SELF_TEST_ROOT=""
}

main() {
    local mode expected_pass
    WORK=$(mktemp -d)
    TRANSCRIPT="$WORK/transcript.log"
    : >"$TRANSCRIPT"
    trap 'cleanup_m103 "$?"' EXIT
    BASE_CONFIG_SHA=$(sha256sum "$RUST_CONFIG" | cut -d' ' -f1)
    preflight_m103_identity_and_inputs
    check_same_frame_tuple_fixture

    if [ "${M103_COMPLETENESS_NEGATIVE:-0}" = 1 ]; then
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
    mode=normal
    expected_pass=56
    if [ "${M103_COMPLETENESS_NEGATIVE:-0}" = 1 ]; then
        mode=negative
        expected_pass=17
    fi
    if [ "$pass" != "$expected_pass" ]; then
        fail "M103 assertion ledger drifted: got $pass passes, want $expected_pass"
    fi
    print_summary
    write_ledger "$mode" "$expected_pass"
    export_success_artifacts "$mode"
}

if [ "$SELF_TEST_MODE" = --self-test-artifact-export ]; then
    artifact_export_self_test
else
    main "$@"
fi
