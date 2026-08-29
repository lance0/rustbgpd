#!/usr/bin/env bash
# M104 — current-daemon sibling of the immutable M90 ARouteServer filtering
# differential. The exact M90 site/config fixtures remain read-only; only the
# daemon boundary moves to BIRD 2.19.2, GoBGP 4.8.0, and the checked-out
# rustbgpd SHA. The unchanged 11-row corpus must finish at 74 passed / 0 failed.

set -euo pipefail

TOPO="m104-arouteserver-current-rs-differential"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF_TEST_MODE=${1:-}
pass=0
fail=0
if [ "$SELF_TEST_MODE" != "--self-test-offline-contract" ] \
    && [ "$SELF_TEST_MODE" != "--preflight-arouteserver-image" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/test-lib.sh"
fi

LAB_DIR="$SCRIPT_DIR/../m90-differential"
MANIFEST="$LAB_DIR/announcements.json"
POLICY_EXPLAIN_FRAGMENT="$LAB_DIR/policy-explain.toml"

BIRD="clab-${TOPO}-bird"

readonly M104_BASE_SHA="350eb813b7a2a71ccfae2084d033253e96419cea"
readonly ARS_MANIFEST_DIGEST="sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66"
readonly ARS_IMAGE="pierky/arouteserver@$ARS_MANIFEST_DIGEST"
readonly ARS_CONFIG_DIGEST="sha256:4a08ef740f00a119f5897b0f834da9ff172a282c93d47fdff636c3b50c9aec93"
readonly ARS_VERSION="1.23.2"
readonly ARS_TAG_COMMIT="85f24252564822556bd93cb9eba1f73d1e8268ea"
readonly BIRD_IMAGE="bird:v2.19.2-m104"
readonly BIRD_VERSION="BIRD version 2.19.2"
readonly BIRD_TARGET_VERSION="2.16"
readonly GOBGP_IMAGE="gobgp:v4.8.0-m104"
readonly GOBGP_VERSION="gobgp version 4.8.0"
readonly GOBGPD_VERSION="gobgpd version 4.8.0"
readonly GOBGP_BINARY_SHA256="5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b"
readonly GOBGPD_BINARY_SHA256="710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97"

ARS_WORK=""
RENDER_DIR=""
SELF_TEST_WORK=""

require_equal() {
    local actual=${1:?} expected=${2:?} label=${3:?}
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: $label: expected '$expected', got '$actual'" >&2
        return 1
    fi
}

require_file_sha() {
    local path=${1:?} expected=${2:?}
    require_equal "$(sha256sum "$path" | cut -d' ' -f1)" "$expected" \
        "$path SHA-256"
}

container_file_sha() {
    docker exec "${1:?}" sha256sum "${2:?}" | cut -d' ' -f1
}

validate_manifest() {
    local manifest=${1:?}
    jq -e '
        type == "array" and length == 11 and
        ([.[] | (.client + ":" + .prefix)] | length == (unique | length)) and
        ([.[] | select(.expect == "accept")] | length == 4) and
        ([.[] | select(.expect == "reject")] | length == 7) and
        all(.[];
            (.client | IN("member1", "member2", "member3")) and
            (.ip | type == "string") and
            (.prefix | type == "string") and
            (.bird_protocol | type == "string") and
            (.expect | IN("accept", "reject")) and
            (if .expect == "reject" then
                (.cause | type == "number") and
                (.policy | type == "string" and length > 0) and
                (.term | type == "string" and length > 0)
             else
                (has("cause") | not) and (has("policy") | not) and
                (has("term") | not)
             end)) and
        ([.[] | select(.client == "member2" and .expect == "reject") | .term]
          == ["reject-irrdb-prefix-filtered", "reject-irrdb-prefix-filtered"])
    ' "$manifest" >/dev/null
}

preflight_m104_inputs() {
    local expected_sha=${M104_EXPECTED_GIT_SHA:?M104_EXPECTED_GIT_SHA must name the checked-out source SHA}
    [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || {
        echo "ERROR: M104_EXPECTED_GIT_SHA must be a full lowercase SHA" >&2
        return 1
    }
    require_equal "$(git rev-parse HEAD)" "$expected_sha" "checked-out rustbgpd SHA"
    git merge-base --is-ancestor "$M104_BASE_SHA" "$expected_sha" || {
        echo "ERROR: M104 source does not contain the post-M103 boundary $M104_BASE_SHA" >&2
        return 1
    }

    require_file_sha "$LAB_DIR/general.yml" c47fed81ba4c7b3671d8c3f3a26955037e5cef67e7c7b7650dc9bf3ceaeb214d
    require_file_sha "$LAB_DIR/clients.yml" 08ceca5f9bafb13139538096a94595d075b7a7dae9342deb26d7f5adfc337e1e
    require_file_sha "$LAB_DIR/context.yml" f979b7b72f9385bf5e10258b967c22da0ec1bd5b214ad9f42197fcd104471eda
    require_file_sha "$LAB_DIR/context-sectioned.yml" f61c2a6d88aae1bb11c9ea95a4dd73abfb3c2f2577df69316f10d49e436b8790
    require_file_sha "$MANIFEST" e55a7faea278b962139a17fe5daf81026761b6eef57cb8bb7807005c12f8164a
    require_file_sha "$LAB_DIR/bogons.yml" 26e7c313a41fd7a854f73c656a77415fd9c2bb9057b625a7592bd436ee26dfe5
    require_file_sha "$LAB_DIR/arouteserver.yml" c3b85f1af54c437ae50b0d4e1502b3a6e95cb2c4b12c255ac1c90cfc9eec5b19
    require_file_sha "$LAB_DIR/bgpq4-stub.sh" cebb06da5c9adff5184652bca877ab7956f137c5d9cd425b7c449ad0e950bb84
    require_file_sha "$POLICY_EXPLAIN_FRAGMENT" 811634752dee124d80be1b0836c61f1a5f20af32b3c94c7fb48536573fd98030
    require_file_sha "$LAB_DIR/prove-context-ingestion.sh" 638d50ee11b4ff4b55ae888d69ecde0225d4d69a6b6f6b9d7a1250b54e2b2270
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m90-member1.toml" b7d897cb35aa657d469dbc7c35d9bdff2b346dc7169bcf820a331a06866f33e2
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m90-member2.toml" 1cfea7eee37eb764a5ab8f090d7f3f25d252ed18d8ff0b9b7f9dbf5e2defd329
    require_file_sha "$SCRIPT_DIR/../configs/gobgp-m90-member3.toml" 27e3955e743203ba352f177eb5e0899d061520bd14e7c0412a02007073c74f72
    validate_manifest "$MANIFEST"
}

require_sleeping_image() {
    local container=${1:?} expected_image=${2:?} expected_id=${3:?}
    require_equal "$(docker inspect -f '{{.Config.Image}}' "$container")" \
        "$expected_image" "$container configured image"
    require_equal "$(docker inspect -f '{{.Image}}' "$container")" \
        "$expected_id" "$container local image identity"
    require_equal "$(docker inspect -f '{{json .Config.Cmd}}' "$container")" \
        '["sleep","infinity"]' "$container sleeping command"
}

validate_arouteserver_image_identity() {
    local image_metadata=${1:?} manifest_metadata=${2:?}
    local config_digest descriptor_digest local_id repo_digests

    if ! jq -e '
        type == "array" and length == 1 and
        (.[0].Id | type == "string" and length > 0) and
        (.[0].RepoDigests | type == "array" and length > 0) and
        (.[0].Architecture == "amd64") and
        (if .[0] | has("Descriptor") then
            (.[0].Descriptor | type == "object") and
            (.[0].Descriptor.digest | type == "string" and length > 0)
         else true end)
    ' <<<"$image_metadata" >/dev/null; then
        echo "ERROR: ARouteServer local image metadata is missing or malformed" >&2
        return 1
    fi

    local_id=$(jq -er '.[0].Id' <<<"$image_metadata")
    repo_digests=$(jq -ec '.[0].RepoDigests' <<<"$image_metadata")
    descriptor_digest=$(jq -r '.[0].Descriptor.digest // empty' <<<"$image_metadata")
    if ! jq -e --arg expected "$ARS_IMAGE" --arg repository 'pierky/arouteserver@' '
        all(.[]; type == "string") and
        ([.[] | select(. == $expected)] | length == 1) and
        all(.[] | select(startswith($repository)); . == $expected)
    ' <<<"$repo_digests" >/dev/null; then
        echo "ERROR: ARouteServer RepoDigests do not identify only the pinned manifest" >&2
        return 1
    fi

    if ! jq -e '
        type == "object" and
        .schemaVersion == 2 and
        .mediaType == "application/vnd.docker.distribution.manifest.v2+json" and
        (.config | type == "object") and
        ((.config | keys | sort) == ["digest", "mediaType", "size"]) and
        .config.mediaType == "application/vnd.docker.container.image.v1+json" and
        (.config.digest | type == "string" and length > 0) and
        (.config.size | type == "number" and . > 0)
    ' <<<"$manifest_metadata" >/dev/null; then
        echo "ERROR: ARouteServer registry manifest metadata is missing or malformed" >&2
        return 1
    fi
    config_digest=$(jq -er '.config.digest' <<<"$manifest_metadata")
    require_equal "$config_digest" "$ARS_CONFIG_DIGEST" \
        "ARouteServer registry config digest" || return 1

    case "$local_id" in
        "$ARS_CONFIG_DIGEST") ;;
        "$ARS_MANIFEST_DIGEST")
            if [ -z "$descriptor_digest" ]; then
                echo "ERROR: ARouteServer containerd descriptor digest is missing" >&2
                return 1
            fi
            require_equal "$descriptor_digest" "$ARS_MANIFEST_DIGEST" \
                "ARouteServer containerd descriptor digest" || return 1
            ;;
        *)
            echo "ERROR: ARouteServer local image ID is neither pinned config nor manifest digest" >&2
            return 1
            ;;
    esac
    if [ -n "$descriptor_digest" ]; then
        require_equal "$descriptor_digest" "$ARS_MANIFEST_DIGEST" \
            "ARouteServer local descriptor digest" || return 1
    fi
}

preflight_arouteserver_image_identity() {
    local image_metadata manifest_metadata
    image_metadata=$(docker image inspect "$ARS_IMAGE")
    manifest_metadata=$(docker buildx imagetools inspect --raw "$ARS_IMAGE")
    validate_arouteserver_image_identity "$image_metadata" "$manifest_metadata"
}

preflight_runtime_identities() {
    local rust_id bird_id gobgp_id container config expected_config
    rust_id=$(docker image inspect -f '{{.Id}}' rustbgpd:dev)
    bird_id=$(docker image inspect -f '{{.Id}}' "$BIRD_IMAGE")
    gobgp_id=$(docker image inspect -f '{{.Id}}' "$GOBGP_IMAGE")

    preflight_arouteserver_image_identity
    require_equal "$(docker run --rm "$ARS_IMAGE" python3 -c \
        'import importlib.metadata; print(importlib.metadata.version("arouteserver"))')" \
        "$ARS_VERSION" "ARouteServer Python package version"

    require_sleeping_image "$RUSTBGPD" rustbgpd:dev "$rust_id"
    require_sleeping_image "$BIRD" "$BIRD_IMAGE" "$bird_id"
    require_equal "$(docker exec "$BIRD" bird --version 2>&1)" \
        "$BIRD_VERSION" "$BIRD runtime version"

    for container in member1 member2 member3; do
        container="clab-${TOPO}-${container}"
        require_sleeping_image "$container" "$GOBGP_IMAGE" "$gobgp_id"
        require_equal "$(docker exec "$container" gobgp --version)" \
            "$GOBGP_VERSION" "$container gobgp version"
        require_equal "$(docker exec "$container" gobgpd --version)" \
            "$GOBGPD_VERSION" "$container gobgpd version"
        require_equal "$(container_file_sha "$container" /usr/local/bin/gobgp)" \
            "$GOBGP_BINARY_SHA256" "$container gobgp binary SHA-256"
        require_equal "$(container_file_sha "$container" /usr/local/bin/gobgpd)" \
            "$GOBGPD_BINARY_SHA256" "$container gobgpd binary SHA-256"
    done
    for config in member1 member2 member3; do
        case "$config" in
            member1) expected_config=b7d897cb35aa657d469dbc7c35d9bdff2b346dc7169bcf820a331a06866f33e2 ;;
            member2) expected_config=1cfea7eee37eb764a5ab8f090d7f3f25d252ed18d8ff0b9b7f9dbf5e2defd329 ;;
            member3) expected_config=27e3955e743203ba352f177eb5e0899d061520bd14e7c0412a02007073c74f72 ;;
        esac
        require_equal "$(container_file_sha "clab-${TOPO}-${config}" /config/gobgp.toml)" \
            "$expected_config" "$config mounted M90 config SHA-256"
    done

    log "M104 identities: source=$(git rev-parse HEAD) rustbgpd=$rust_id BIRD=$bird_id GoBGP=$gobgp_id"
    log "ARouteServer manifest=sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66 config=$ARS_CONFIG_DIGEST package=$ARS_VERSION tag_commit=$ARS_TAG_COMMIT"
}

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s unix:///var/lib/rustbgpd/grpc.sock "$@" 2>/dev/null
}

member_container() { echo "clab-${TOPO}-${1:?}"; }

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

bird_route_all() {
    docker exec "$BIRD" birdc "show route ${1:?} all" 2>/dev/null
}

bird_filtered_route_all() {
    docker exec "$BIRD" birdc "show route ${1:?} filtered all" 2>/dev/null
}

bird_has_from() { bird_route_all "${1:?}" | grep -qF "[${2:?} "; }
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

rs_accepted_has() { rs_ctl rib received "${1:?}" | grep -qF "${2:?}"; }
rs_accepted_lacks() { ! rs_accepted_has "$1" "$2"; }

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
    docker exec "$BIRD" birdc show protocols 2>/dev/null | grep -c Established || true
}

rs_sessions_up() { [ "$(rs_established_count)" -ge 3 ]; }
bird_sessions_up() { [ "$(bird_established_count)" -ge 3 ]; }

render_bird_config() {
    log "Rendering BIRD 2.16 target config with exact ARouteServer 1.23.2..."
    ARS_WORK=$(mktemp -d)
    cp "$LAB_DIR/general.yml" "$LAB_DIR/clients.yml" "$LAB_DIR/bogons.yml" \
        "$LAB_DIR/arouteserver.yml" "$LAB_DIR/bgpq4-stub.sh" "$ARS_WORK/"
    mkdir -p "$ARS_WORK/cache" "$ARS_WORK/out"
    chmod +x "$ARS_WORK/bgpq4-stub.sh"
    chmod -R a+rwX "$ARS_WORK"

    if docker run --rm -v "$ARS_WORK:/site" "$ARS_IMAGE" \
        arouteserver bird --cfg /site/arouteserver.yml \
        --target-version "$BIRD_TARGET_VERSION" \
        -o /site/out/bird.conf; then
        ok "ARouteServer BIRD 2.16 render completed"
    else
        fail "ARouteServer BIRD render failed"
        return 1
    fi
    if [ -s "$ARS_WORK/out/bird.conf" ]; then
        ok "bird.conf rendered and non-empty"
    else
        fail "bird.conf missing or empty after ARouteServer run"
        return 1
    fi
    docker cp "$ARS_WORK/out/bird.conf" "$BIRD":/etc/bird/bird.conf
    docker exec "$BIRD" bird -p -c /etc/bird/bird.conf >/dev/null 2>&1 || {
        echo "ERROR: exact BIRD 2.19.2 rejected the ARouteServer 2.16 target" >&2
        return 1
    }
    log "Exact BIRD 2.19.2 accepted the generated config with bird -p"
}

render_rustbgpd_config() {
    log "Rendering rustbgpd config from the immutable M90 context..."
    RENDER_DIR=$(mktemp -d)

    if cargo run --release -q -p rs-config-render -- \
        --context "$LAB_DIR/context.yml" --out-dir "$RENDER_DIR"; then
        ok "rs-config-render completed (exit 0)"
    else
        fail "rs-config-render failed"
        return 1
    fi
    cat "$POLICY_EXPLAIN_FRAGMENT" >>"$RENDER_DIR/config.toml"

    if jq -e \
        '.clients | length == 3 and ([.[].id] | sort == ["AS64500_1", "AS64501_1", "AS64502_1"]) and all(.[]; .max_prefixes_ipv4 == 100 and .max_prefixes_ipv6 == 12000)' \
        "$RENDER_DIR/render-receipt.json" >/dev/null 2>&1 \
        && [ "$(grep -c '^max_prefixes_ipv4 = 100$' "$RENDER_DIR/config.toml")" -eq 3 ] \
        && [ "$(grep -c '^max_prefixes_ipv6 = 12000$' "$RENDER_DIR/config.toml")" -eq 3 ]; then
        ok "render receipt and config carry all 3 exact 100/12000 limits"
    else
        fail "render receipt/config missing exact 3-member limits"
        return 1
    fi
    if jq -e '
        .schema == "rustbgpd.arouteserver-reject-communities.v1" and
        .peers == ["192.0.2.11", "192.0.2.12", "192.0.2.13"] and
        .std == {"dynamic":"65520:dyn_val","cause_map":{"3":"64512:3"}} and
        .lrg == {"dynamic":"64496:65520:dyn_val","cause_map":{"3":"64496:65521:3"}}
    ' "$RENDER_DIR/birdwatcher-reject-communities.json" >/dev/null; then
        ok "renderer artifact carries exact peers and reject communities"
    else
        fail "renderer reject-community artifact drifted"
        return 1
    fi
    if cargo test -q -p birdwatcher-adapter \
        arouteserver_translation_is_scoped_scrubbed_deduped_and_conservative; then
        ok "adapter maps order-ambiguous reasons conservatively"
    else
        fail "adapter order-ambiguous fallback proof failed"
        return 1
    fi

    docker cp "$RENDER_DIR/config.toml" "$RUSTBGPD":/etc/rustbgpd/config.toml
    docker cp "$RENDER_DIR/policy" "$RUSTBGPD":/etc/rustbgpd/policy
    docker cp "$RENDER_DIR/datasets" "$RUSTBGPD":/etc/rustbgpd/datasets

    if docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check --strict \
        /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rendered config passes rustbgpd --check --strict"
    else
        fail "rendered config fails rustbgpd --check --strict"
        return 1
    fi
    local rpol
    for rpol in rs-hygiene client-as64500-1 client-as64501-1 client-as64502-1; do
        if docker exec "$RUSTBGPD" rbgp policy check \
            "/etc/rustbgpd/policy/${rpol}.rpol" >/dev/null 2>&1; then
            ok "rbgp policy check ${rpol}.rpol"
        else
            fail "rbgp policy check ${rpol}.rpol failed"
        fi
    done
}

start_daemons() {
    log "Starting BIRD 2.19.2 after successful bird -p..."
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
        return 1
    fi

    log "Starting exact GoBGP 4.8.0 members..."
    local member
    for member in member1 member2 member3; do
        docker exec -d "$(member_container "$member")" sh -c \
            'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
    done
    poll 45 2 "rustbgpd RS: 3 member sessions Established" rs_sessions_up
    poll 45 2 "BIRD RS: 3 member sessions Established" bird_sessions_up
}

inject_announcements() {
    log "Injecting the immutable 11-row M90 corpus..."
    local entry client ip prefix aspath
    while IFS= read -r entry; do
        client=$(jq -r '.client' <<<"$entry")
        ip=$(jq -r '.ip' <<<"$entry")
        prefix=$(jq -r '.prefix' <<<"$entry")
        aspath=$(jq -r '.aspath // empty' <<<"$entry")
        if [ -n "$aspath" ]; then
            if docker exec "$(member_container "$client")" \
                gobgp global rib add -a ipv4 "$prefix" origin igp \
                nexthop "$ip" aspath "$aspath"; then
                ok "$client injected $prefix (aspath $aspath)"
            else
                fail "$client failed to inject $prefix (aspath $aspath)"
            fi
        else
            if docker exec "$(member_container "$client")" \
                gobgp global rib add -a ipv4 "$prefix" origin igp nexthop "$ip"; then
                ok "$client injected $prefix"
            else
                fail "$client failed to inject $prefix"
            fi
        fi
    done < <(jq -c '.[]' "$MANIFEST")
}

assert_accepts() {
    log "Asserting the four ACCEPT verdicts on both daemons..."
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
            fail "accepted $prefix from $client also sits in rejected store"
        fi
    done < <(jq -c '.[] | select(.expect == "accept")' "$MANIFEST")
}

assert_rejects() {
    log "Asserting the seven REJECT verdicts and exact current terms..."
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

        poll 15 2 "rustbgpd retains rejected $prefix from $client (policy_reject)" \
            rs_rejected_has "$ip" "$prefix"
        if rs_accepted_lacks "$ip" "$prefix"; then
            ok "rustbgpd accepted view clean of $prefix for $client"
        else
            fail "rejected $prefix from $client leaked into accepted view"
        fi
        explain=$(rs_ctl policy explain --neighbor "$ip" --prefix "$prefix" || true)
        if grep -qF -- "$policy" <<<"$explain" && grep -qw -- "$term" <<<"$explain"; then
            ok "explain names $policy / $term for $prefix"
        else
            fail "explain does not name $policy / $term for $prefix"
        fi
        if bird_lacks_from "$prefix" "$proto"; then
            ok "BIRD rejects $prefix from $client (no path via $proto)"
        else
            fail "BIRD accepted $prefix from $client"
        fi
        if bird_filtered_has_tags "$prefix" "$proto" "$cause"; then
            ok "BIRD filtered route carries generic and cause $cause communities"
        else
            fail "BIRD filtered route lacks exact generic/cause $cause communities"
        fi
    done < <(jq -c '.[] | select(.expect == "reject")' "$MANIFEST")
}

assert_sessions_survived() {
    log "Post-verdict session survival..."
    if rs_sessions_up; then
        ok "rustbgpd still holds 3 Established member sessions"
    else
        fail "rustbgpd lost a member session"
    fi
    if bird_sessions_up; then
        ok "BIRD still holds 3 Established member sessions"
    else
        fail "BIRD lost a member session"
    fi
}

cleanup_workdirs() {
    [ -z "$ARS_WORK" ] || rm -rf "$ARS_WORK"
    [ -z "$RENDER_DIR" ] || rm -rf "$RENDER_DIR"
}

cleanup_m104() {
    local exit_code=$? topo_file
    cleanup_workdirs
    if [ "${CLEANUP:-0}" = "1" ]; then
        topo_file="$(_clab_topology_file)"
        containerlab destroy -t "$topo_file" --cleanup >/dev/null 2>&1 || true
    fi
    return "$exit_code"
}

reject_arouteserver_identity_fixture() {
    local label=${1:?} image_metadata=${2:?} manifest_metadata=${3:?}
    if validate_arouteserver_image_identity "$image_metadata" "$manifest_metadata" \
        >/dev/null 2>&1; then
        echo "ERROR: $label escaped ARouteServer identity validation" >&2
        return 1
    fi
}

self_test_offline_contract() {
    local ambiguous classic containerd manifest missing_config missing_descriptor missing_repo
    local changed short swapped wrong_config wrong_id wrong_manifest
    M104_EXPECTED_GIT_SHA=$(git rev-parse HEAD)
    export M104_EXPECTED_GIT_SHA
    preflight_m104_inputs
    SELF_TEST_WORK=$(mktemp -d)
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT

    changed="$SELF_TEST_WORK/stale-term.json"
    jq 'map(if .term? == "reject-irrdb-prefix-filtered" then .term = "rest" else . end)' \
        "$MANIFEST" >"$changed"
    if validate_manifest "$changed"; then
        echo "ERROR: stale member2 IRR term escaped M104 manifest validation" >&2
        return 1
    fi
    if require_file_sha "$changed" e55a7faea278b962139a17fe5daf81026761b6eef57cb8bb7807005c12f8164a \
        >/dev/null 2>&1; then
        echo "ERROR: mutated M90 manifest escaped the immutable hash" >&2
        return 1
    fi

    short="$SELF_TEST_WORK/short.json"
    jq '.[0:10]' "$MANIFEST" >"$short"
    if validate_manifest "$short"; then
        echo "ERROR: shortened M90 corpus escaped exact cardinality validation" >&2
        return 1
    fi

    manifest=$(jq -cn --arg config "$ARS_CONFIG_DIGEST" '{
        schemaVersion: 2,
        mediaType: "application/vnd.docker.distribution.manifest.v2+json",
        config: {
            mediaType: "application/vnd.docker.container.image.v1+json",
            size: 8882,
            digest: $config
        },
        layers: []
    }')
    classic=$(jq -cn --arg id "$ARS_CONFIG_DIGEST" --arg image "$ARS_IMAGE" \
        '[{Id: $id, RepoDigests: [$image], Architecture: "amd64"}]')
    containerd=$(jq -cn --arg id "$ARS_MANIFEST_DIGEST" --arg image "$ARS_IMAGE" '{
        Id: $id,
        RepoDigests: [$image],
        Architecture: "amd64",
        Descriptor: {digest: $id}
    } | [.]')
    validate_arouteserver_image_identity "$classic" "$manifest"
    validate_arouteserver_image_identity "$containerd" "$manifest"

    swapped=$(jq -c --arg digest "$ARS_CONFIG_DIGEST" \
        '.[0].Descriptor = {digest: $digest}' <<<"$containerd")
    wrong_manifest=$(jq -c \
        '.[0].RepoDigests = ["pierky/arouteserver@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]' \
        <<<"$containerd")
    ambiguous=$(jq -c \
        '.[0].RepoDigests += ["pierky/arouteserver@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]' \
        <<<"$containerd")
    missing_descriptor=$(jq -c '.[0] | del(.Descriptor) | [.]' <<<"$containerd")
    missing_repo=$(jq -c '.[0] | del(.RepoDigests) | [.]' <<<"$containerd")
    wrong_id=$(jq -c \
        '.[0].Id = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        <<<"$containerd")
    wrong_config=$(jq -c \
        '.config.digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        <<<"$manifest")
    missing_config=$(jq -c 'del(.config.digest)' <<<"$manifest")
    reject_arouteserver_identity_fixture swapped "$swapped" "$manifest"
    reject_arouteserver_identity_fixture wrong_manifest "$wrong_manifest" "$manifest"
    reject_arouteserver_identity_fixture ambiguous "$ambiguous" "$manifest"
    reject_arouteserver_identity_fixture missing_descriptor "$missing_descriptor" "$manifest"
    reject_arouteserver_identity_fixture missing_repo "$missing_repo" "$manifest"
    reject_arouteserver_identity_fixture wrong_id "$wrong_id" "$manifest"
    reject_arouteserver_identity_fixture wrong_config "$containerd" "$wrong_config"
    reject_arouteserver_identity_fixture missing_config "$containerd" "$missing_config"
    echo "M104 offline contract self-test passed"
}

main() {
    log "M104 current-daemon ARouteServer route-server differential"
    trap cleanup_m104 EXIT
    preflight_m104_inputs
    preflight_runtime_identities
    render_bird_config
    render_rustbgpd_config
    start_daemons
    inject_announcements
    assert_accepts
    assert_rejects
    assert_sessions_survived

    require_equal "$pass" 74 "M104 positive ledger"
    require_equal "$fail" 0 "M104 failure ledger"
    print_summary
}

case "$SELF_TEST_MODE" in
    --self-test-offline-contract) self_test_offline_contract ;;
    --preflight-arouteserver-image) preflight_arouteserver_image_identity ;;
    *) main "$@" ;;
esac
