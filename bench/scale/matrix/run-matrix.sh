#!/usr/bin/env bash
# LAN-334 IXP receipt matrix: sequential reload-stall cells across daemons.
#
# Cells:
#   rustbgpd  bare release binary, SIGHUP reloads (the frozen receipt recipe)
#   bird      BIRD in docker --network=host, `birdc configure` reloads
#   openbgpd  OpenBGPD in docker --network=host, `bgpctl reload` reloads
#
# COMPETITOR_GENERATION selects one fail-closed pair of image references:
#   historical (default): BIRD 3.3.1 / OpenBGPD 9.1, the frozen receipt recipe
#   current: BIRD 3.3.2 / OpenBGPD 9.2, the explicit refresh generation
#
# One cell at a time: 1-min loadavg gate (< 2.0) before each cell, 5-minute
# cool-down after. Per-cell status files under the artifacts dir make the
# campaign resumable — a rerun skips cells whose status is `pass` (delete the
# status file to redo one). A cell aborts (campaign continues) on harness
# acceptance failure or daemon-tree RSS > 100 GiB.
#
# Usage: run-matrix.sh [cell ...]         (default: rustbgpd bird openbgpd)
# Knobs (env): N_PEERS=700 TOTAL_PREFIXES=400400 PORT=1790 RELOADS=4
#              CONTROL_SECS=30 BIRD_THREADS=8 FLAPSTORM= (K, optional)
#              COMPETITOR_GENERATION=historical|current
#              ARTIFACTS_DIR=bench/scale/matrix/artifacts
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
# shellcheck disable=SC1091 # REPO is resolved dynamically above
source "$REPO/tests/soak/host-lock.sh"
# shellcheck disable=SC1091 # REPO is resolved dynamically above
source "$REPO/bench/scale/host-quiet.sh"
# shellcheck disable=SC1091 # REPO is resolved dynamically above
source "$REPO/bench/scale/provenance.sh"
RSTALL="$REPO/bench/scale/reloadstall"
HARNESS="$REPO/bench/scale/target/release/reloadstall"
SAMPLER="$REPO/bench/scale/matrix/rss-sampler.sh"

N_PEERS="${N_PEERS:-700}"
TOTAL="${TOTAL_PREFIXES:-400400}"
PORT="${PORT:-1790}"
RELOADS="${RELOADS:-4}"
CONTROL_SECS="${CONTROL_SECS:-30}"
BIRD_THREADS="${BIRD_THREADS:-8}"
FLAPSTORM="${FLAPSTORM:-}"
ART="${ARTIFACTS_DIR:-$REPO/bench/scale/matrix/artifacts}"
COMPETITOR_GENERATION="${COMPETITOR_GENERATION:-historical}"
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB

competitor_image_ref() {
    local cell=$1
    case "$COMPETITOR_GENERATION:$cell" in
        historical:bird) printf '%s\n' bird:3.3.1 ;;
        historical:openbgpd) printf '%s\n' openbgpd/openbgpd:9.1 ;;
        current:bird) printf '%s\n' bird:v3.3.2-m101 ;;
        current:openbgpd)
            printf '%s\n' 'openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9'
            ;;
        historical:rustbgpd | current:rustbgpd) ;;
        *) return 1 ;;
    esac
}

case $COMPETITOR_GENERATION in
    historical | current) ;;
    *)
        echo "unknown COMPETITOR_GENERATION: $COMPETITOR_GENERATION (want historical|current)" >&2
        exit 2
        ;;
esac

inspect_competitor_image() {
    docker image inspect --format '{{.Id}}' "$1" 2>/dev/null
}

resolve_competitor_image() {
    local image_ref=$1
    inspect_competitor_image "$image_ref" || {
        docker pull "$image_ref" >/dev/null &&
            inspect_competitor_image "$image_ref"
    }
}

matrix_prepare_event() { :; }
recheck_source_git_identity() {
    local repo=$1 provenance_file=$2 stored current_commit current_tree current_dirty=false status
    local stored_commit stored_tree stored_dirty
    stored=$(jq -er '[.git.commit,.git.tree,(.git.dirty|tostring)] | @tsv' "$provenance_file") || return 1
    IFS=$'\t' read -r stored_commit stored_tree stored_dirty <<<"$stored"
    [[ $stored_commit =~ ^[0-9a-f]{40}$ && $stored_tree =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ $stored_dirty == true || $stored_dirty == false ]] || return 1
    current_commit=$(git -C "$repo" rev-parse 'HEAD^{commit}') || return 1
    current_tree=$(git -C "$repo" rev-parse 'HEAD^{tree}') || return 1
    status=$(git -C "$repo" status --porcelain=v1) || return 1
    [ -z "$status" ] || current_dirty=true
    [ "$stored_commit" = "$current_commit" ] &&
        [ "$stored_tree" = "$current_tree" ] &&
        [ "$stored_dirty" = "$current_dirty" ]
}
verify_live_competitor_identity() {
    local cell=$1 file=$2 expected_ref stored_ref stored_id live_id
    [ "$cell" != rustbgpd ] || return 0
    expected_ref=$(competitor_image_ref "$cell") || return 1
    stored_ref=$(jq -er '.workload.image_ref' "$file") || return 1
    stored_id=$(jq -er '.workload.image_id' "$file") || return 1
    [ "$stored_ref" = "$expected_ref" ] || return 1
    [[ $stored_id =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    live_id=$(inspect_competitor_image "$expected_ref") || return 1
    [ "$live_id" = "$stored_id" ]
}
prepare_selected_cell() {
    local cell=$1 status_file=$2 quiet_file=$3
    PREPARED_IMAGE_REF=""
    PREPARED_IMAGE_ID=""
    PREPARED_IMAGE_REF=$(competitor_image_ref "$cell") || return 1
    if [ -f "$status_file" ] && grep -qx pass "$status_file"; then
        matrix_prepare_event "$cell:resume-verify"
        recheck_cell_provenance "$cell" || return 1
        return 10
    fi
    if [ -n "$PREPARED_IMAGE_REF" ]; then
        matrix_prepare_event "$cell:resolve"
        PREPARED_IMAGE_ID=$(resolve_competitor_image "$PREPARED_IMAGE_REF") || return 1
    fi
    matrix_prepare_event "$cell:quiet"
    wait_for_rustbgpd_quiet_host "$quiet_file"
}

if [ "${1:-}" = --self-test-prepare-order ]; then
    [ "$#" -eq 4 ] || exit 2
    trace=$2 selected=$3 status=$4
    matrix_prepare_event() { printf '%s\n' "$1" >>"$trace"; }
    recheck_cell_provenance() {
        matrix_prepare_event "$1:live-verify"
        verify_live_competitor_identity "$1" "$status.provenance" &&
            [ -n "${MATRIX_SELF_TEST_REPO:-}" ] &&
            recheck_source_git_identity "$MATRIX_SELF_TEST_REPO" "$status.provenance"
    }
    inspect_competitor_image() {
        [ -z "${MATRIX_SELF_TEST_IMAGE_TRACE:-}" ] || printf '%s\n' "$1" >>"$MATRIX_SELF_TEST_IMAGE_TRACE"
        printf '%s\n' "${MATRIX_SELF_TEST_IMAGE_ID:-sha256:$(printf '%064d' 0)}"
    }
    wait_for_rustbgpd_quiet_host() { : >"$1"; }
    prepare_selected_cell "$selected" "$status" "$status.quiet"
    exit $?
fi

CELLS=("$@")
[ ${#CELLS[@]} -eq 0 ] && CELLS=(rustbgpd bird openbgpd)
for cell in "${CELLS[@]}"; do
    case $cell in rustbgpd | bird | openbgpd) ;; *)
        echo "unknown cell: $cell (want rustbgpd|bird|openbgpd)" >&2; exit 2 ;;
    esac
done
acquire_rustbgpd_host_lock || exit $?

[ -x "$HARNESS" ] || {
    echo "missing $HARNESS - build with: cd $RSTALL && cargo build --release" >&2
    exit 1
}
CAPTURED_COMMIT=$(git -C "$REPO" rev-parse HEAD) || exit 1
CAPTURED_TREE=$(git -C "$REPO" rev-parse 'HEAD^{tree}') || exit 1
CAPTURED_DIRTY=false
[ -z "$(git -C "$REPO" status --porcelain=v1)" ] || CAPTURED_DIRTY=true
mkdir -p "$ART"

COMMON_SOURCES=(bench/scale/provenance.sh bench/scale/matrix/run-matrix.sh
    bench/scale/matrix/verify-provenance.py bench/scale/matrix/rss-sampler.sh
    bench/scale/host-quiet.sh tests/soak/host-lock.sh)
declare -A SOURCE_HASHES
snapshot_source() {
    local relative=$1
    SOURCE_HASHES[$relative]=$(provenance_sha256_file "$REPO/$relative") || return 1
}
for relative in "${COMMON_SOURCES[@]}" bench/scale/target/release/reloadstall; do
    snapshot_source "$relative" || { echo "cannot hash $relative" >&2; exit 1; }
done

write_cell_provenance() {
    local cell=$1 generator=$2 workload_kind=$3 workload_name=$4 workload_hash=$5
    local common='{}' relative
    snapshot_source "$generator" || return 1
    for relative in "${COMMON_SOURCES[@]}"; do
        common=$(jq -c --arg key "$relative" --arg value "${SOURCE_HASHES[$relative]}" '. + {($key):$value}' <<<"$common") || return 1
    done
    local workload
    if [ "$workload_kind" = binary ]; then
        workload=$(jq -cn --arg binary "$workload_name" --arg sha256 "$workload_hash" '{binary:$binary,sha256:$sha256}') || return 1
    else
        workload=$(jq -cn --arg image_ref "$workload_name" --arg image_id "$workload_hash" '{image_ref:$image_ref,image_id:$image_id}') || return 1
    fi
    jq -n --arg cell "$cell" --arg commit "$CAPTURED_COMMIT" \
        --arg tree "$CAPTURED_TREE" --argjson dirty "$CAPTURED_DIRTY" \
        --arg toolchain "$(rustc -Vv)" --arg host "$(uname -srvmo)" \
        --argjson common "$common" --arg generator_path "$generator" \
        --arg generator_hash "${SOURCE_HASHES[$generator]}" \
        --arg reloadstall_hash "${SOURCE_HASHES[bench/scale/target/release/reloadstall]}" \
        --argjson workload "$workload" \
        '{schema:1,cell:$cell,git:{commit:$commit,tree:$tree,dirty:$dirty},toolchain:$toolchain,host:$host,sources:{common:$common,generator:{($generator_path):$generator_hash},reloadstall:{path:"bench/scale/target/release/reloadstall",sha256:$reloadstall_hash}},workload:$workload}' \
        >"$ART/$cell/provenance.json" || return 1
    python3 "$REPO/bench/scale/matrix/verify-provenance.py" \
        "$ART/$cell/provenance.json" "$cell" "$COMPETITOR_GENERATION"
}

recheck_cell_provenance() {
    local cell=$1 relative expected
    local file="$ART/$cell/provenance.json"
    python3 "$REPO/bench/scale/matrix/verify-provenance.py" \
        "$file" "$cell" "$COMPETITOR_GENERATION" || return 1
    while IFS=$'\t' read -r relative expected; do
        provenance_require_sha256 "$REPO/$relative" "$expected" || return 1
    done < <(jq -r '.sources.common + .sources.generator + {(.sources.reloadstall.path):.sources.reloadstall.sha256} | to_entries[] | [.key,.value] | @tsv' "$file")
    if [ "$cell" = rustbgpd ]; then
        provenance_require_sha256 "$REPO/$(jq -r '.workload.binary' "$file")" "$(jq -r '.workload.sha256' "$file")" || return 1
    else
        verify_live_competitor_identity "$cell" "$file" || return 1
    fi
    recheck_source_git_identity "$REPO" "$file"
}

# run_cell <cell>: everything for one matrix cell. Nonzero return = cell
# failed; the campaign moves on.
run_cell() {
    local cell=$1 prepared_image_ref=${2:-} prepared_image_id=${3:-}
    local cdir="$ART/$cell"
    # Short run dir: gen-scenario.py's gRPC UDS path must fit SUN_LEN.
    local run="/tmp/ixp-$cell"
    rm -rf "$run"
    mkdir -p "$cdir" "$run"

    local daemon_pid="" container="" reload_cmd="" pid_arg="" generator image_ref image_id workload_hash
    local live a b
    case $cell in
    rustbgpd)
        [ -x "$REPO/target/release/rustbgpd" ] || {
            echo "missing $REPO/target/release/rustbgpd (cargo build --release)" >&2
            return 1
        }
        generator=bench/scale/reloadstall/gen-scenario.py
        workload_hash=$(provenance_sha256_file "$REPO/target/release/rustbgpd") || return 1
        write_cell_provenance "$cell" "$generator" binary target/release/rustbgpd "$workload_hash" || return 1
        recheck_cell_provenance "$cell" || return 1
        python3 "$RSTALL/gen-scenario.py" "$N_PEERS" "$run" "$PORT" || return 1
        recheck_cell_provenance "$cell" || return 1
        "$REPO/target/release/rustbgpd" "$run/config.toml" \
            >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid # frozen recipe: real PID, SIGHUP reloads
        ;;
    bird)
        generator=bench/scale/reloadstall/gen-bird-scenario.py
        image_ref=$prepared_image_ref image_id=$prepared_image_id
        [ "$image_ref" = "$(competitor_image_ref bird)" ] && [[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
        write_cell_provenance "$cell" "$generator" image "$image_ref" "$image_id" || return 1
        recheck_cell_provenance "$cell" || return 1
        python3 "$RSTALL/gen-bird-scenario.py" "$N_PEERS" "$run" "$PORT" \
            "$BIRD_THREADS" /etc/bird "$COMPETITOR_GENERATION" || return 1
        recheck_cell_provenance "$cell" || return 1
        container="ixp-bird"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bird \
            "$image_id" bird -f -c /etc/bird/bird.conf >/dev/null || return 1
        reload_cmd="docker exec $container birdc configure"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0 # the outer sampler owns RSS
        ;;
    openbgpd)
        generator=bench/scale/reloadstall/gen-obgpd-scenario.py
        image_ref=$prepared_image_ref image_id=$prepared_image_id
        [ "$image_ref" = "$(competitor_image_ref openbgpd)" ] && [[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
        write_cell_provenance "$cell" "$generator" image "$image_ref" "$image_id" || return 1
        recheck_cell_provenance "$cell" || return 1
        python3 "$RSTALL/gen-obgpd-scenario.py" "$N_PEERS" "$run" "$PORT" \
            /etc/bgpd "$COMPETITOR_GENERATION" || return 1
        recheck_cell_provenance "$cell" || return 1
        container="ixp-obgpd"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bgpd \
            "$image_id" >/dev/null || return 1
        reload_cmd="docker exec $container bgpctl reload"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0
        ;;
    *)
        echo "unknown cell: $cell (want rustbgpd|bird|openbgpd)" >&2
        return 1
        ;;
    esac

    sleep 3
    if [ -n "$container" ]; then
        daemon_pid=$(docker inspect -f '{{.State.Pid}}' "$container") || daemon_pid=0
        if [ "$daemon_pid" -le 0 ]; then
            echo "cell $cell: container died at start" >&2
            docker logs "$container" >"$cdir/daemon.log" 2>&1
            docker rm -f "$container" >/dev/null 2>&1
            return 1
        fi
    elif [ ! -d "/proc/$daemon_pid" ]; then
        echo "cell $cell: daemon died at start (see $cdir/daemon.log)" >&2
        return 1
    fi

    "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!

    local hargs=("$N_PEERS" "$TOTAL" "$PORT" "$pid_arg" "$live" "$a" "$b"
        "$RELOADS" "$CONTROL_SECS")
    [ -n "$reload_cmd" ] && hargs+=("$N_PEERS" "$reload_cmd")
    [ -n "$FLAPSTORM" ] && hargs+=(--flapstorm "$FLAPSTORM")

    # Harness in the background so the RSS guard can abort the cell.
    "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    local hpid=$!
    local rc=""
    while kill -0 "$hpid" 2>/dev/null; do
        local last_kib
        last_kib=$(tail -n1 "$cdir/rss.csv" 2>/dev/null | cut -d, -f2)
        case ${last_kib:-} in
        '' | *[!0-9]*) ;;
        *)
            if [ "$last_kib" -gt "$RSS_LIMIT_KIB" ]; then
                echo "cell $cell: daemon RSS ${last_kib} KiB > 100 GiB, aborting cell" >&2
                kill "$hpid" 2>/dev/null
                rc=99
            fi
            ;;
        esac
        sleep 5
    done
    local hrc
    wait "$hpid"
    hrc=$?
    [ -z "$rc" ] && rc=$hrc

    # Collect artifacts, then teardown.
    kill "$sampler_pid" 2>/dev/null
    if [ -n "$container" ]; then
        docker logs "$container" >"$cdir/daemon.log" 2>&1
        docker rm -f "$container" >/dev/null 2>&1
    else
        kill "$daemon_pid" 2>/dev/null
    fi
    cp -r "$run" "$cdir/scenario"
    echo "cell $cell: harness rc=$rc (artifacts: $cdir)"
    [ "$rc" -ne 0 ] || recheck_cell_provenance "$cell" || return 1
    return "$rc"
}

for cell in "${CELLS[@]}"; do
    status_file="$ART/$cell/status"
    prepare_rc=0
    prepare_selected_cell "$cell" "$status_file" "$ART/$cell/quiet.tsv" || prepare_rc=$?
    if [ "$prepare_rc" -eq 10 ]; then
        echo "cell $cell: already pass, skipping (rm $status_file to rerun)"
        continue
    fi
    [ "$prepare_rc" -eq 0 ] || exit "$prepare_rc"
    echo "=== cell $cell start $(date -Is) ==="
    if run_cell "$cell" "$PREPARED_IMAGE_REF" "$PREPARED_IMAGE_ID"; then
        echo pass >"$status_file"
        echo "=== cell $cell PASS $(date -Is) ==="
    else
        echo "fail rc=$? $(date -Is)" >"$status_file"
        echo "=== cell $cell FAIL (campaign continues) ==="
    fi
    echo "cool-down 300s"
    sleep 300
done
echo "matrix done; per-cell status under $ART/*/status"
