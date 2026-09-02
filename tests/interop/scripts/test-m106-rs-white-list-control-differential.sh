#!/usr/bin/env bash
# M106 interop test — arouteserver white-list / control-community
# differential lab.
#
# The M90 differential (scripts/test-m90-differential.sh, an immutable
# asset — its phases are copied here rather than shared) re-run on the
# M106 site (tests/interop/m106-rs-white-list-control-differential/):
# the M90 roster and corpus plus the two renderer surfaces under test,
# each proven against BIRD rendered by arouteserver proper from the same
# general.yml/clients.yml:
#   - IRR white lists: white_list_pref / white_list_asn (extra IRR
#     members) and white_list_route bound to an origin (an accept term
#     ahead of IRR enforcement, tagged route_validated_via_white_list);
#   - the daemon's fixed RFC 7947 §2.3.2 control-community matrix, which
#     the site configures exactly, so the rendered sessions keep
#     `rs_control_communities` on: per-target suppression, the
#     announce-to-none override, prepending, and scrubbing.
#
# Every manifest row gets the M90 verdict assertions (accept/reject on
# both daemons, explain naming the deciding policy and term, BIRD cause
# tags). Rows carrying an `export` block additionally assert what each
# target member actually received from BOTH route servers, read from
# that member's own Adj-RIB-In (`gobgp neighbor <rs> adj-in`): announced
# or suppressed, the tag communities present, the acted-on control
# communities scrubbed, and the AS_PATH length after prepending.
#
# Prerequisites: as for M90 (the same images and host tools), deployed
# from tests/interop/m106-rs-white-list-control-differential.clab.yml.
#
# Usage:
#   bash tests/interop/scripts/test-m106-rs-white-list-control-differential.sh

TOPO="m106-rs-white-list-control-differential"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

LAB_DIR="$SCRIPT_DIR/../m106-rs-white-list-control-differential"
MANIFEST="$LAB_DIR/announcements.json"
POLICY_EXPLAIN_FRAGMENT="$LAB_DIR/policy-explain.toml"

BIRD="clab-${TOPO}-bird"
RS_ADDR="192.0.2.9"

# Pinned official image: pierky/arouteserver:latest as of 2026-07-18
# (arouteserver 1.23.2), the same pin as M90. Override via M106_ARS_IMAGE.
ARS_IMAGE="${M106_ARS_IMAGE:-pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66}"
# BIRD 2 target for arouteserver's renderer. Debian bookworm's bird2
# package (the bird:2-bookworm image) is BIRD 2.0.12; 2.0.11 is the
# nearest version `arouteserver bird --help` offers.
BIRD_TARGET_VERSION="${M106_BIRD_TARGET_VERSION:-2.0.11}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# rbgp against the RS over the UDS listener the rendered config
# declares (operator principal; the render emits no TCP listener).
rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s unix:///var/lib/rustbgpd/grpc.sock "$@" 2>/dev/null
}

member_container() { echo "clab-${TOPO}-${1:?}"; }

# Poll until a command succeeds; usage: poll <tries> <sleep> <label> cmd...
poll() {
    local tries=${1:?} pause=${2:?} label=${3:?}
    shift 3
    for i in $(seq 1 "$tries"); do
        if "$@" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep "$pause"
    done
    fail "$label — timed out after $((tries * pause))s"
    return 1
}

# BIRD's full view of one exact net.
bird_route_all() {
    docker exec "$BIRD" birdc "show route ${1:?} all" 2>/dev/null
}

bird_filtered_route_all() {
    docker exec "$BIRD" birdc "show route ${1:?} filtered all" 2>/dev/null
}

# True if BIRD holds a path for the net from the given arouteserver
# client protocol (protocol names follow the client ids: AS64500_1 ...).
bird_has_from()   { bird_route_all "${1:?}" | grep -qF "[${2:?} "; }
bird_lacks_from() { ! bird_has_from "$1" "$2"; }

bird_filtered_has_tags() {
    local output cause=${3:?}
    output=$(bird_filtered_route_all "${1:?}")
    grep -qF "[${2:?} " <<<"$output" \
        && grep -Eq "\\(65520,[[:space:]]*0\\)" <<<"$output" \
        && grep -Eq "\\(65520,[[:space:]]*$cause\\)" <<<"$output" \
        && grep -Eq "\\(64496,[[:space:]]*65520,[[:space:]]*0\\)" <<<"$output" \
        && grep -Eq "\\(64496,[[:space:]]*65520,[[:space:]]*$cause\\)" <<<"$output" \
        && { [ "$cause" -ne 3 ] \
            || { grep -Eq "\\(64512,[[:space:]]*3\\)" <<<"$output" \
                && grep -Eq "\\(64496,[[:space:]]*65521,[[:space:]]*3\\)" <<<"$output"; }; }
}

rs_accepted_has()   { rs_ctl rib received "${1:?}" | grep -qF "${2:?}"; }
rs_accepted_lacks() { ! rs_accepted_has "$1" "$2"; }

# True if the member's rejected-route store retains the prefix with the
# canonical policy_reject reason token.
rs_rejected_has() {
    rs_ctl rib received "${1:?}" --rejected -j \
        | jq -e --arg p "${2:?}" \
            '[.rejected_routes[] | select(.prefix == $p and .reason == "policy_reject")] | length > 0' \
        >/dev/null 2>&1
}
rs_rejected_lacks() { ! rs_rejected_has "$1" "$2"; }

rs_established_count() {
    rs_ctl neighbor -j | jq '[.[] | select(.state == "Established")] | length' 2>/dev/null || echo 0
}

bird_established_count() {
    docker exec "$BIRD" birdc show protocols 2>/dev/null | grep -c "Established" || true
}

rs_sessions_up()   { [ "$(rs_established_count)" -ge 3 ]; }
bird_sessions_up() { [ "$(bird_established_count)" -ge 3 ]; }

# ---------------------------------------------------------------------------
# Phase 0a: render the BIRD side with arouteserver proper
# ---------------------------------------------------------------------------

ARS_WORK=""

render_bird_config() {
    log "Rendering bird.conf with arouteserver proper (containerized)..."

    if [[ "$ARS_IMAGE" == *0000000000000000* ]]; then
        echo "ERROR: the pierky/arouteserver image digest is still the TODO tripwire." >&2
        echo "Pin it in this script or export M106_ARS_IMAGE=<image@sha256:...>." >&2
        exit 1
    fi

    ARS_WORK=$(mktemp -d)
    cp "$LAB_DIR/general.yml" "$LAB_DIR/clients.yml" "$LAB_DIR/bogons.yml" \
        "$LAB_DIR/arouteserver.yml" "$LAB_DIR/bgpq4-stub.sh" "$ARS_WORK/"
    mkdir -p "$ARS_WORK/cache" "$ARS_WORK/out"
    chmod +x "$ARS_WORK/bgpq4-stub.sh"
    # The image may run unprivileged; the mount must be writable for
    # the IRR cache and the rendered output.
    chmod -R a+rwX "$ARS_WORK"

    if docker run --rm -v "$ARS_WORK:/site" "$ARS_IMAGE" \
        arouteserver bird --cfg /site/arouteserver.yml \
        --target-version "$BIRD_TARGET_VERSION" \
        -o /site/out/bird.conf; then
        ok "arouteserver bird render completed"
    else
        fail "arouteserver bird render failed"
        exit 1
    fi
    if [ -s "$ARS_WORK/out/bird.conf" ]; then
        ok "bird.conf rendered and non-empty"
    else
        fail "bird.conf missing or empty after the arouteserver run"
        exit 1
    fi

    docker cp "$ARS_WORK/out/bird.conf" "$BIRD":/etc/bird/bird.conf
}

# ---------------------------------------------------------------------------
# Phase 0b: render the rustbgpd side with rs-config-render
# ---------------------------------------------------------------------------

RENDER_DIR=""

render_rustbgpd_config() {
    log "Rendering rustbgpd config with rs-config-render from context.yml..."
    RENDER_DIR=$(mktemp -d)

    if cargo run --release -q -p rs-config-render -- \
        --context "$LAB_DIR/context.yml" --out-dir "$RENDER_DIR"; then
        ok "rs-config-render completed (exit 0 — no refusal, no implausible set, no shape drift)"
    else
        fail "rs-config-render failed"
        exit 1
    fi

    # This receipt asserts deciding policy/term attribution for every reject.
    # Keep the production and renderer defaults off; opt in only in the
    # generated lab config before its production validation gate.
    cat "$POLICY_EXPLAIN_FRAGMENT" >>"$RENDER_DIR/config.toml"

    # Load-bearing proof: suppressing shutdown-gated limit emission makes this
    # exact receipt/config assertion fail before either
    # daemon starts.
    if jq -e \
        '.clients | length == 3 and ([.[].id] | sort == ["AS64500_1", "AS64501_1", "AS64502_1"]) and all(.[]; .max_prefixes_ipv4 == 100 and .max_prefixes_ipv6 == 12000)' \
        "$RENDER_DIR/render-receipt.json" >/dev/null 2>&1 \
        && [ "$(grep -c '^max_prefixes_ipv4 = 100$' "$RENDER_DIR/config.toml")" -eq 3 ] \
        && [ "$(grep -c '^max_prefixes_ipv6 = 12000$' "$RENDER_DIR/config.toml")" -eq 3 ]; then
        ok "render receipt and config carry all 3 members with exact 100/12000 limits"
    else
        fail "render receipt/config missing exact 3-member 100/12000 max-prefix limits"
        cat "$RENDER_DIR/render-receipt.json" >&2 || true
        return 1
    fi
    if jq -e '
        .schema == "rustbgpd.arouteserver-reject-communities.v1" and
        .peers == ["192.0.2.11", "192.0.2.12", "192.0.2.13"] and
        .std == {"dynamic":"65520:dyn_val","cause_map":{"3":"64512:3"}} and
        .lrg == {"dynamic":"64496:65520:dyn_val","cause_map":{"3":"64496:65521:3"}}
    ' "$RENDER_DIR/birdwatcher-reject-communities.json" >/dev/null; then
        ok "renderer artifact carries the exact three members and configured communities"
    else
        fail "renderer reject-community artifact does not match the pinned site"
        return 1
    fi
    if cargo test -q -p birdwatcher-adapter \
        arouteserver_translation_is_scoped_scrubbed_deduped_and_conservative; then
        ok "adapter maps order-ambiguous length/RPKI reasons to generic zero only"
    else
        fail "adapter order-ambiguous generic fallback proof failed"
        return 1
    fi

    docker cp "$RENDER_DIR/config.toml" "$RUSTBGPD":/etc/rustbgpd/config.toml
    docker cp "$RENDER_DIR/policy" "$RUSTBGPD":/etc/rustbgpd/policy
    docker cp "$RENDER_DIR/datasets" "$RUSTBGPD":/etc/rustbgpd/datasets

    # The pipeline's own gate (cookbook step 3): the rendered config
    # must pass full validation before it may serve members.
    if docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check --strict /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rendered config passes rustbgpd --check --strict"
    else
        fail "rendered config FAILS rustbgpd --check --strict"
        docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check --strict /etc/rustbgpd/config.toml >&2 || true
        exit 1
    fi

    # Every generated policy carries in-language tests derived from the
    # site's own data; all must pass offline.
    local rpol
    for rpol in rs-hygiene client-as64500-1 client-as64501-1 client-as64502-1; do
        if docker exec "$RUSTBGPD" rbgp policy check "/etc/rustbgpd/policy/${rpol}.rpol" >/dev/null 2>&1; then
            ok "rbgp policy check ${rpol}.rpol"
        else
            fail "rbgp policy check ${rpol}.rpol failed"
            docker exec "$RUSTBGPD" rbgp policy check "/etc/rustbgpd/policy/${rpol}.rpol" >&2 || true
        fi
    done
}

# ---------------------------------------------------------------------------
# Phase 1: launch daemons and wait for the six sessions
# ---------------------------------------------------------------------------

start_daemons() {
    log "Starting BIRD..."
    docker exec "$BIRD" sh -c \
        'mkdir -p /run/bird && (bird -d -c /etc/bird/bird.conf >>/tmp/bird.log 2>&1 &)'

    log "Starting rustbgpd..."
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >>/var/log/rustbgpd.log 2>&1'
    local up=0
    for i in $(seq 1 20); do
        if rs_ctl global >/dev/null 2>&1; then
            ok "rustbgpd gRPC (UDS) ready (attempt $i)"
            up=1
            break
        fi
        sleep 1
    done
    if [ "$up" -ne 1 ]; then
        fail "rustbgpd gRPC (UDS) not reachable within 20s"
        docker exec "$RUSTBGPD" tail -40 /var/log/rustbgpd.log >&2 || true
        exit 1
    fi

    log "Starting GoBGP members..."
    local m
    for m in member1 member2 member3; do
        docker exec -d "$(member_container "$m")" sh -c \
            'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
    done

    poll 45 2 "rustbgpd RS: 3 member sessions Established" rs_sessions_up \
        || rs_ctl neighbor >&2 || true
    poll 45 2 "BIRD RS: 3 member sessions Established" bird_sessions_up \
        || docker exec "$BIRD" birdc show protocols >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 2: inject the canned announcement set
# ---------------------------------------------------------------------------

inject_announcements() {
    log "Injecting the canned announcement set from announcements.json..."
    local entry client ip prefix aspath communities large
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        aspath=$(jq -r '.aspath // empty' <<<"$entry")
        communities=$(jq -r '.communities // [] | join(",")' <<<"$entry")
        large=$(jq -r '.large_communities // [] | join(",")' <<<"$entry")
        # GoBGP prepends the member's own ASN toward the eBGP route
        # servers, so an injected `aspath 65551` goes on the wire as
        # "<member-asn> 65551". Optional communities ride along verbatim.
        local -a args=(global rib add -a ipv4 "$prefix" origin igp nexthop "$ip")
        local detail=""
        if [ -n "$aspath" ]; then
            args+=(aspath "$aspath")
            detail="$detail aspath $aspath"
        fi
        if [ -n "$communities" ]; then
            args+=(community "$communities")
            detail="$detail community $communities"
        fi
        if [ -n "$large" ]; then
            args+=(large-community "$large")
            detail="$detail large-community $large"
        fi
        docker exec "$(member_container "$client")" gobgp "${args[@]}" \
            && ok "$client injected $prefix${detail:+ (${detail# })}" \
            || fail "$client failed to inject $prefix${detail:+ (${detail# })}"
    done < <(jq -c '.[]' "$MANIFEST")
}

# ---------------------------------------------------------------------------
# Phase 3: per-entry differential verdicts
# ---------------------------------------------------------------------------

assert_accepts() {
    log "Asserting ACCEPT verdicts on both daemons..."
    local entry client ip prefix proto policy term explain
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        proto=$(jq -r '.bird_protocol' <<<"$entry")
        policy=$(jq -r '.policy // empty' <<<"$entry")
        term=$(jq -r '.term // empty' <<<"$entry")

        poll 15 2 "BIRD accepts $prefix from $client ($proto)" \
            bird_has_from "$prefix" "$proto"
        poll 15 2 "rustbgpd accepts $prefix from $client ($ip)" \
            rs_accepted_has "$ip" "$prefix"
        if rs_rejected_lacks "$ip" "$prefix"; then
            ok "rustbgpd rejected store clean of $prefix for $client"
        else
            fail "accepted $prefix from $client also sits in the rejected store"
        fi
        # An accept row may pin the accepting policy and term too.
        if [ -n "$term" ]; then
            explain=$(rs_ctl policy explain --neighbor "$ip" --prefix "$prefix" || true)
            if grep -qF -- "$policy" <<<"$explain" && grep -qw -- "$term" <<<"$explain"; then
                ok "explain names $policy / $term for accepted $prefix"
            else
                fail "explain does not name $policy / $term for accepted $prefix"
                echo "$explain" >&2
            fi
        fi
    done < <(jq -c '.[] | select(.expect == "accept")' "$MANIFEST")
}

assert_rejects() {
    log "Asserting REJECT verdicts on both daemons..."
    # All accepts have converged on both daemons by now, so absence of
    # a sibling announcement from the same session is meaningful (plus
    # a short settle for in-flight UPDATEs).
    sleep 2

    local entry client ip prefix proto policy term cause explain
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        proto=$(jq -r '.bird_protocol' <<<"$entry")
        policy=$(jq -r '.policy' <<<"$entry")
        term=$(jq -r '.term' <<<"$entry")
        cause=$(jq -r '.cause' <<<"$entry")

        # Positive signal first: the rejection is retained with the
        # canonical reason token.
        poll 15 2 "rustbgpd retains rejected $prefix from $client (reason policy_reject)" \
            rs_rejected_has "$ip" "$prefix"
        if rs_accepted_lacks "$ip" "$prefix"; then
            ok "rustbgpd accepted view clean of $prefix for $client"
        else
            fail "rejected $prefix from $client leaked into the accepted view"
        fi

        # The explain surface must name the generated policy and term.
        explain=$(rs_ctl policy explain --neighbor "$ip" --prefix "$prefix" || true)
        if grep -qF -- "$policy" <<<"$explain" && grep -qw -- "$term" <<<"$explain"; then
            ok "explain names $policy / $term for $prefix"
        else
            fail "explain does not name $policy / $term for $prefix"
            echo "$explain" >&2
        fi

        if bird_lacks_from "$prefix" "$proto"; then
            ok "BIRD rejects $prefix from $client (no path via $proto)"
        else
            fail "BIRD ACCEPTED $prefix from $client — differential verdict mismatch"
            bird_route_all "$prefix" >&2 || true
        fi
        if bird_filtered_has_tags "$prefix" "$proto" "$cause"; then
            ok "BIRD filtered route carries generic and cause $cause communities"
        else
            fail "BIRD filtered route lacks exact generic/cause $cause communities"
            bird_filtered_route_all "$prefix" >&2 || true
        fi
    done < <(jq -c '.[] | select(.expect == "reject")' "$MANIFEST")
}

assert_sessions_survived() {
    log "Post-verdict sanity: no session was torn down by the canned set..."
    if rs_sessions_up; then
        ok "rustbgpd still holds 3 Established member sessions"
    else
        fail "rustbgpd lost a member session ($(rs_established_count)/3 Established)"
    fi
    if bird_sessions_up; then
        ok "BIRD still holds 3 Established member sessions"
    else
        fail "BIRD lost a member session ($(bird_established_count)/3 Established)"
    fi
}

RS_RUSTBGPD="192.0.2.9"
RS_BIRD="192.0.2.10"

# ---------------------------------------------------------------------------
# Export assertions (member-side Adj-RIB-In from each route server)
# ---------------------------------------------------------------------------

# One member's view of one prefix as received from one route server,
# normalized to {communities, large, as_path_len}; "null" when absent.
member_path_from() {
    docker exec "$(member_container "${1:?}")" \
        gobgp neighbor "${2:?}" adj-in -a ipv4 -j 2>/dev/null \
        | jq -c --arg p "${3:?}" '
            (.[$p] // [])[0] // null
            | if . == null then null else {
                communities: [.attrs[]? | select(.type == 8) | .communities[]?
                              | "\(. / 65536 | floor):\(. % 65536)"],
                large: [.attrs[]? | select(.type == 32) | .value[]?
                        | "\(.ASN):\(.LocalData1):\(.LocalData2)"],
                as_path_len: ([.attrs[]? | select(.type == 2) | .as_paths[]? | .asns[]?] | length)
              } end'
}

member_has_path_from()   { [ "$(member_path_from "$1" "$2" "$3")" != "null" ]; }
member_lacks_path_from() { [ "$(member_path_from "$1" "$2" "$3")" = "null" ]; }

# Check one received path against the manifest expectation object.
assert_path_matches() {
    local member=${1:?} rs=${2:?} prefix=${3:?} expectation=${4:?} path
    path=$(member_path_from "$member" "$rs" "$prefix")
    if jq -e --argjson want "$expectation" '
        ($want.has_communities // []) as $has
        | ($want.lacks_communities // []) as $lacks
        | (.communities + .large) as $all
        | all($has[]; . as $c | $all | index($c) != null)
          and all($lacks[]; . as $c | $all | index($c) == null)
          and (($want.as_path_len == null) or (.as_path_len == $want.as_path_len))
    ' <<<"$path" >/dev/null 2>&1; then
        ok "$member holds $prefix from $rs with the expected communities/path ($path)"
    else
        fail "$member holds $prefix from $rs but not as expected: got $path, want $expectation"
        return 1
    fi
}

assert_exports() {
    log "Asserting per-target EXPORT outcomes at the members, from both route servers..."
    local entry client prefix targets target expectation announced rs
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        targets=$(jq -r '.export | keys[]' <<<"$entry")
        for target in $targets; do
            expectation=$(jq -c --arg t "$target" '.export[$t]' <<<"$entry")
            announced=$(jq -r '.announced' <<<"$expectation")
            for rs in "$RS_RUSTBGPD" "$RS_BIRD"; do
                if [ "$announced" = "true" ]; then
                    poll 15 2 "$target receives $prefix (from $client) via $rs" \
                        member_has_path_from "$target" "$rs" "$prefix" \
                        && assert_path_matches "$target" "$rs" "$prefix" "$expectation"
                fi
            done
        done
    done < <(jq -c '.[] | select(.export != null)' "$MANIFEST")

    # Announced siblings have converged, so absence is meaningful now.
    sleep 2
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        targets=$(jq -r '.export | to_entries[] | select(.value.announced == false) | .key' <<<"$entry")
        for target in $targets; do
            for rs in "$RS_RUSTBGPD" "$RS_BIRD"; do
                if member_lacks_path_from "$target" "$rs" "$prefix"; then
                    ok "$target does not receive $prefix (from $client) via $rs"
                else
                    fail "$target RECEIVED $prefix (from $client) via $rs — control community not honored"
                    member_path_from "$target" "$rs" "$prefix" >&2 || true
                fi
            done
        done
    done < <(jq -c '.[] | select(.export != null)' "$MANIFEST")
}

assert_control_knob_rendered() {
    log "Rendered sessions keep the control-community knob on..."
    if [ "$(grep -c '^rs_control_communities = true$' "$RENDER_DIR/config.toml")" -eq 3 ]; then
        ok "rendered config keeps rs_control_communities on for all 3 members"
    else
        fail "rendered config does not keep rs_control_communities on for all 3 members"
    fi
}

cleanup_workdirs() {
    [ -n "$ARS_WORK" ] && rm -rf "$ARS_WORK" || true
    [ -n "$RENDER_DIR" ] && rm -rf "$RENDER_DIR" || true
}

main() {
    log "M106 interop test: arouteserver white-list / control-community differential lab"
    log "Topology: $TOPO"

    if [ ! -f "$MANIFEST" ]; then
        echo "ERROR: manifest not found at $MANIFEST" >&2
        exit 1
    fi
    trap 'cleanup_workdirs; _cleanup_on_exit' EXIT

    render_bird_config
    render_rustbgpd_config
    assert_control_knob_rendered
    start_daemons
    inject_announcements
    assert_accepts
    assert_rejects
    assert_exports
    assert_sessions_survived

    print_summary
}

main "$@"
