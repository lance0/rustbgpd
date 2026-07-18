#!/usr/bin/env bash
# M90 interop test — arouteserver differential lab (ADR-0110 phase 1).
#
# One general.yml/clients.yml pair (tests/interop/m90-differential/)
# drives BOTH route servers:
#   - BIRD 2: config rendered at runtime by arouteserver PROPER, run
#     containerized from the official pierky/arouteserver image with
#     the lab's bogons.yml override and canned bgpq4 stub (the site's
#     AS-SETs are RFC 5398 documentation objects with no live IRR
#     data);
#   - rustbgpd: config rendered by tools/rs-config-render from the
#     site's template-context model. The checked-in
#     m90-differential/context.yml is hand-authored against the
#     renderer's fingerprint-pinned single-document shape so this lab
#     renders deterministically offline; the renderer equally ingests
#     the sectioned report arouteserver 1.23.2 emits (a real dump is
#     checked in as context-sectioned.yml, and the lab's
#     prove-context-ingestion.sh proves both forms render
#     identically against the pinned image). Because the BIRD side
#     ALWAYS re-runs arouteserver proper at lab runtime, drift
#     between context.yml and the site files surfaces as a verdict
#     mismatch — the differential is the guard.
#
# Three GoBGP members then announce the canned set from
# announcements.json, and every entry is asserted on BOTH daemons:
#   - accept: present on BIRD from that member's protocol, present in
#     `rbgp rib received <member>`, absent from the rejected store;
#   - reject: absent on BIRD from that member's protocol, present in
#     `rbgp rib received <member> --rejected` with reason
#     policy_reject, and `rbgp policy explain` names the generated
#     policy AND term from the manifest (hygiene-before-IRR ordering
#     makes the attribution deterministic).
#
# Also asserted along the way: the rendered rustbgpd config passes
# `rustbgpd --check`, every generated .rpol file passes its own
# in-language tests under `rbgp policy check`, and the render receipt
# lists all three members.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deploy -t tests/interop/m90-differential.clab.yml
#   - grpcurl + jq installed on the host; cargo (builds rs-config-render)
#   - the pierky/arouteserver image pinned below (pulled by digest)
#
# Usage:
#   bash tests/interop/scripts/test-m90-differential.sh

TOPO="m90-differential"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

LAB_DIR="$SCRIPT_DIR/../m90-differential"
MANIFEST="$LAB_DIR/announcements.json"

BIRD="clab-${TOPO}-bird"
RS_ADDR="192.0.2.9"

# Pinned official image: pierky/arouteserver:latest as of 2026-07-18
# (arouteserver 1.23.2). Refresh with `docker pull` + `docker inspect
# --format '{{index .RepoDigests 0}}'`, or override via M90_ARS_IMAGE.
ARS_IMAGE="${M90_ARS_IMAGE:-pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66}"
# BIRD 2 target for arouteserver's renderer. Debian bookworm's bird2
# package (the bird:2-bookworm image) is BIRD 2.0.12; 2.0.11 is the
# nearest version `arouteserver bird --help` offers.
BIRD_TARGET_VERSION="${M90_BIRD_TARGET_VERSION:-2.0.11}"

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

# True if BIRD holds a path for the net from the given arouteserver
# client protocol (protocol names follow the client ids: AS64500_1 ...).
bird_has_from()   { bird_route_all "${1:?}" | grep -qF "[${2:?} "; }
bird_lacks_from() { ! bird_has_from "$1" "$2"; }

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
        echo "Pin it in this script or export M90_ARS_IMAGE=<image@sha256:...>." >&2
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

    if jq -e '.clients | length == 3' "$RENDER_DIR/render-receipt.json" >/dev/null 2>&1; then
        ok "render receipt lists all 3 members"
    else
        fail "render receipt missing or does not list 3 members"
        cat "$RENDER_DIR/render-receipt.json" >&2 || true
    fi

    docker cp "$RENDER_DIR/config.toml" "$RUSTBGPD":/etc/rustbgpd/config.toml
    docker cp "$RENDER_DIR/policy" "$RUSTBGPD":/etc/rustbgpd/policy

    # The pipeline's own gate (cookbook step 3): the rendered config
    # must pass full validation before it may serve members.
    if docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rendered config passes rustbgpd --check"
    else
        fail "rendered config FAILS rustbgpd --check"
        docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check /etc/rustbgpd/config.toml >&2 || true
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
    local entry client ip prefix aspath
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        aspath=$(jq -r '.aspath // empty' <<<"$entry")
        # GoBGP prepends the member's own ASN toward the eBGP route
        # servers, so an injected `aspath 65551` goes on the wire as
        # "<member-asn> 65551".
        if [ -n "$aspath" ]; then
            docker exec "$(member_container "$client")" \
                gobgp global rib add -a ipv4 "$prefix" origin igp \
                nexthop "$ip" aspath "$aspath" \
                && ok "$client injected $prefix (aspath $aspath)" \
                || fail "$client failed to inject $prefix (aspath $aspath)"
        else
            docker exec "$(member_container "$client")" \
                gobgp global rib add -a ipv4 "$prefix" origin igp \
                nexthop "$ip" \
                && ok "$client injected $prefix" \
                || fail "$client failed to inject $prefix"
        fi
    done < <(jq -c '.[]' "$MANIFEST")
}

# ---------------------------------------------------------------------------
# Phase 3: per-entry differential verdicts
# ---------------------------------------------------------------------------

assert_accepts() {
    log "Asserting ACCEPT verdicts on both daemons..."
    local entry client ip prefix proto
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        proto=$(jq -r '.bird_protocol' <<<"$entry")

        poll 15 2 "BIRD accepts $prefix from $client ($proto)" \
            bird_has_from "$prefix" "$proto"
        poll 15 2 "rustbgpd accepts $prefix from $client ($ip)" \
            rs_accepted_has "$ip" "$prefix"
        if rs_rejected_lacks "$ip" "$prefix"; then
            ok "rustbgpd rejected store clean of $prefix for $client"
        else
            fail "accepted $prefix from $client also sits in the rejected store"
        fi
    done < <(jq -c '.[] | select(.expect == "accept")' "$MANIFEST")
}

assert_rejects() {
    log "Asserting REJECT verdicts on both daemons..."
    # All accepts have converged on both daemons by now, so absence of
    # a sibling announcement from the same session is meaningful (plus
    # a short settle for in-flight UPDATEs).
    sleep 2

    local entry client ip prefix proto policy term explain
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        proto=$(jq -r '.bird_protocol' <<<"$entry")
        policy=$(jq -r '.policy' <<<"$entry")
        term=$(jq -r '.term' <<<"$entry")

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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

cleanup_workdirs() {
    [ -n "$ARS_WORK" ] && rm -rf "$ARS_WORK" || true
    [ -n "$RENDER_DIR" ] && rm -rf "$RENDER_DIR" || true
}

main() {
    log "M90 interop test: arouteserver differential lab (ADR-0110 phase 1)"
    log "Topology: $TOPO"

    if [ ! -f "$MANIFEST" ]; then
        echo "ERROR: manifest not found at $MANIFEST" >&2
        exit 1
    fi
    # Chain onto test-lib's EXIT trap rather than replacing it.
    trap 'cleanup_workdirs; _cleanup_on_exit' EXIT

    render_bird_config
    render_rustbgpd_config
    start_daemons
    inject_announcements
    assert_accepts
    assert_rejects
    assert_sessions_survived

    print_summary
}

main "$@"
