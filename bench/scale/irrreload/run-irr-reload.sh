#!/usr/bin/env bash
# IRR-scale reload-receipt matrix: sequential policy-reload cells across
# daemons and, for rustbgpd, across both reload paths. See README.md for the
# precommitted measurement definitions, fairness protocol, and abort
# criteria.
#
# Cells:
#   rustbgpd-sighup  bare release binary; rs-config-render-derived .rpol
#                    member policy; SIGHUP parse-then-swap reloads
#   rustbgpd-txn     bare release binary; same dataset as inline
#                    [policy.definitions] chains; gRPC `rbgp config
#                    plan`+`apply` transactional reloads (txn-apply.sh)
#   bird             BIRD 3.3.x in docker --network=host; `birdc configure`
#   openbgpd         OpenBGPD 9.x in docker --network=host; `bgpctl reload`
#
# Usage: run-irr-reload.sh [cell ...]
#        (measured default: rustbgpd-sighup bird openbgpd)
#        (smoke default: all four cells)
#
# Modes:
#   SMOKE=1   pipeline proof at a tiny shape (10 members x 100-entry lists,
#             1 reload/cell, no host-quiet gates). NOT a measurement.
#   default   the measured shape. Requires a quiet host: runs
#             tests/soak/preflight.sh first (SKIP_PREFLIGHT=1 to override),
#             1-min loadavg gate before each cell, 300 s cool-downs.
#
# Knobs (env): N_MEMBERS TOTAL_PREFIXES MIN_LIST MAX_LIST SEED
#              CHANGED_FRACTION PORT RELOADS CONTROL_SECS BIRD_THREADS
#              CELL_TIMEOUT START_TIMEOUT ARTIFACTS_DIR SKIP_PREFLIGHT
#              TXN_MAX_CANDIDATE_BYTES
set -u
set -o pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
RSTALL="$REPO/bench/scale/reloadstall"
HARNESS="$RSTALL/target/release/reloadstall"
GEN="$RSTALL/gen-irr-scenario.py"
SAMPLER="$REPO/bench/scale/matrix/rss-sampler.sh"
TXN_APPLY="$REPO/bench/scale/irrreload/txn-apply.sh"
RBGP="$REPO/target/release/rbgp"
RENDER="$REPO/target/release/rs-config-render"
DAEMON="$REPO/target/release/rustbgpd"

SMOKE="${SMOKE:-}"
CELLS=("$@")
if [ ${#CELLS[@]} -eq 0 ]; then
    if [ -n "$SMOKE" ]; then
        CELLS=(rustbgpd-sighup rustbgpd-txn bird openbgpd)
    else
        CELLS=(rustbgpd-sighup bird openbgpd)
    fi
fi

TXN_ONLY=false
if [ ${#CELLS[@]} -eq 1 ] && [ "${CELLS[0]}" = rustbgpd-txn ]; then
    TXN_ONLY=true
fi
if [ -z "$SMOKE" ] && [[ " ${CELLS[*]} " == *" rustbgpd-txn "* ]] &&
    [ "$TXN_ONLY" != true ]; then
    echo "rustbgpd-txn must use a separate measured campaign and ARTIFACTS_DIR" >&2
    echo "run this full-shape comparison without it, then run rustbgpd-txn alone" >&2
    exit 2
fi

if [ -n "$SMOKE" ]; then
    N_MEMBERS="${N_MEMBERS:-10}"
    TOTAL_PREFIXES="${TOTAL_PREFIXES:-100}"
    MIN_LIST="${MIN_LIST:-100}"
    MAX_LIST="${MAX_LIST:-100}"
    RELOADS="${RELOADS:-1}"
    CONTROL_SECS="${CONTROL_SECS:-5}"
    CELL_TIMEOUT="${CELL_TIMEOUT:-900}"
    COOL_DOWN=5
elif [ "$TXN_ONLY" = true ]; then
    # The transaction candidate is carried in one tonic request. This
    # separate representative shape stays below the default 4 MiB decode
    # ceiling; the runner also checks the exact generated protobuf payload.
    N_MEMBERS="${N_MEMBERS:-10}"
    TOTAL_PREFIXES="${TOTAL_PREFIXES:-5720}"
    MIN_LIST="${MIN_LIST:-1000}"
    MAX_LIST="${MAX_LIST:-12000}"
    RELOADS="${RELOADS:-4}"
    CONTROL_SECS="${CONTROL_SECS:-30}"
    CELL_TIMEOUT="${CELL_TIMEOUT:-7200}"
    COOL_DOWN=300
else
    # The measured shape: 320 members, 572 announced /24s each (the IXP
    # matrix per-member slice), IRR filter lists log-uniform 1k-40k entries.
    N_MEMBERS="${N_MEMBERS:-320}"
    TOTAL_PREFIXES="${TOTAL_PREFIXES:-183040}"
    MIN_LIST="${MIN_LIST:-1000}"
    MAX_LIST="${MAX_LIST:-40000}"
    RELOADS="${RELOADS:-4}"
    CONTROL_SECS="${CONTROL_SECS:-30}"
    CELL_TIMEOUT="${CELL_TIMEOUT:-7200}"
    COOL_DOWN=300
fi
SEED="${SEED:-61}"
CHANGED_FRACTION="${CHANGED_FRACTION:-0.1}"
PORT="${PORT:-1790}"
# Daemon-start readiness ceiling (seconds). Parsing a multi-MB IRR
# policy takes far longer than a small-config boot, so readiness is
# polled (1 s cadence, until the BGP listener is up) instead of a
# fixed sleep; this is only the hard ceiling. A harness parameter, not
# a measurement — see README "Startup and readiness windows".
START_TIMEOUT="${START_TIMEOUT:-600}"
BIRD_THREADS="${BIRD_THREADS:-8}"
ART="${ARTIFACTS_DIR:-/tmp/irrreload-artifacts}"
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB (precommitted)
TONIC_MAX_DECODE_BYTES=4194304
# Apply carries candidate_toml (field 1) plus the required 22-byte
# runtime-snapshot token (field 2). At this candidate size, protobuf uses
# one-byte tags/field-2 length and a four-byte field-1 length:
# 4_194_275 + 5 + 24 = tonic's 4 MiB decoded-message ceiling exactly.
TXN_SAFE_CANDIDATE_BYTES=4194275
TXN_MAX_CANDIDATE_BYTES="${TXN_MAX_CANDIDATE_BYTES:-$TXN_SAFE_CANDIDATE_BYTES}"
case $TXN_MAX_CANDIDATE_BYTES in
'' | *[!0-9]*)
    echo "TXN_MAX_CANDIDATE_BYTES must be an integer" >&2
    exit 2
    ;;
esac
if [ "$TXN_MAX_CANDIDATE_BYTES" -gt "$TXN_SAFE_CANDIDATE_BYTES" ]; then
    echo "TXN_MAX_CANDIDATE_BYTES exceeds the safe apply-request ceiling" >&2
    echo "maximum: $TXN_SAFE_CANDIDATE_BYTES bytes under tonic's $TONIC_MAX_DECODE_BYTES-byte limit" >&2
    exit 2
fi

if [ -n "$SMOKE" ]; then
    CAMPAIGN_KIND=smoke
elif [ "$TXN_ONLY" = true ]; then
    CAMPAIGN_KIND=transaction-bounded
else
    CAMPAIGN_KIND=full-cross-daemon
fi

if [ -n "${DRY_RUN_PROTOCOL:-}" ]; then
    printf 'cells=%s\n' "$(IFS=,; echo "${CELLS[*]}")"
    printf 'shape=%s,%s,%s,%s\n' "$N_MEMBERS" "$TOTAL_PREFIXES" "$MIN_LIST" "$MAX_LIST"
    printf 'reloads=%s control_secs=%s txn_max_candidate_bytes=%s\n' \
        "$RELOADS" "$CONTROL_SECS" "$TXN_MAX_CANDIDATE_BYTES"
    exit 0
fi

for tool in docker jq python3 cargo ss sha256sum git awk timeout find sort setsid cmp mktemp; do
    command -v "$tool" >/dev/null || {
        echo "missing required tool: $tool" >&2
        exit 1
    }
done

if [ -z "$SMOKE" ] && [ -z "${SKIP_PREFLIGHT:-}" ]; then
    echo "=== host-quiet preflight (tests/soak/preflight.sh) ==="
    "$REPO/tests/soak/preflight.sh" || {
        echo "preflight failed; fix the host or set SKIP_PREFLIGHT=1" >&2
        exit 1
    }
fi

echo "=== builds ==="
(cd "$REPO" && cargo build --release -q -p rustbgpd -p rustbgpctl -p rs-config-render) || exit 1
(cd "$RSTALL" && cargo build --release -q) || exit 1
for bin in "$HARNESS" "$RBGP" "$RENDER" "$DAEMON"; do
    [ -x "$bin" ] || {
        echo "missing binary after build: $bin" >&2
        exit 1
    }
done
mkdir -p "$ART"
hash_file() {
    local output
    output=$(sha256sum -- "$1") || return 1
    printf '%s\n' "${output%% *}"
}

BIRD_IMAGE="bird:3.3.1"
OPENBGPD_IMAGE="openbgpd/openbgpd:9.1"
image_id_for_cells() {
    local cell=$1 image=$2
    if [[ " ${CELLS[*]} " != *" $cell "* ]]; then
        printf 'not-selected'
        return
    fi
    docker image inspect --format '{{.Id}}' "$image" 2>/dev/null || {
        docker pull "$image" >/dev/null || return 1
        docker image inspect --format '{{.Id}}' "$image"
    }
}
BIRD_IMAGE_ID=$(image_id_for_cells bird "$BIRD_IMAGE") || exit 1
OPENBGPD_IMAGE_ID=$(image_id_for_cells openbgpd "$OPENBGPD_IMAGE") || exit 1
DOCKER_VERSION=$(docker --version)
if [[ " ${CELLS[*]} " == *" bird "* || " ${CELLS[*]} " == *" openbgpd "* ]]; then
    DOCKER_VERSION=$(docker version --format '{{.Client.Version}}/{{.Server.Version}}') || exit 1
fi

# Seal resumability and retained evidence to the exact code, tools, and
# campaign inputs. All paths stay repository-relative and no host identity is
# recorded. A dirty checkout is represented by its byte-exact tracked diff
# plus content hashes for untracked files.
COMMIT=$(git -C "$REPO" rev-parse HEAD) || exit 1
DIRTY=false
[ -z "$(git -C "$REPO" status --porcelain=v1)" ] || DIRTY=true
DIRTY_STATE_SHA256=$(
    cd "$REPO" || exit 1
    git status --porcelain=v1
    git diff --binary HEAD --
    git ls-files --others --exclude-standard -z |
        while IFS= read -r -d '' path; do
            printf 'untracked %s ' "$path"
            hash_file "$path"
        done
) || exit 1
DIRTY_STATE_SHA256=$(printf '%s' "$DIRTY_STATE_SHA256" | sha256sum | cut -d' ' -f1) || exit 1
CAMPAIGN_PROVENANCE=$(jq -cn \
    --arg commit "$COMMIT" --argjson dirty "$DIRTY" \
    --arg dirty_state_sha256 "$DIRTY_STATE_SHA256" \
    --arg run_script_sha256 "$(hash_file "$REPO/bench/scale/irrreload/run-irr-reload.sh")" \
    --arg generator_sha256 "$(hash_file "$GEN")" \
    --arg sampler_sha256 "$(hash_file "$SAMPLER")" \
    --arg txn_apply_sha256 "$(hash_file "$TXN_APPLY")" \
    --arg harness_sha256 "$(hash_file "$HARNESS")" \
    --arg daemon_sha256 "$(hash_file "$DAEMON")" \
    --arg cli_sha256 "$(hash_file "$RBGP")" \
    --arg renderer_sha256 "$(hash_file "$RENDER")" \
    --arg cells "$(IFS=,; echo "${CELLS[*]}")" \
    --arg smoke "$SMOKE" --arg n_members "$N_MEMBERS" \
    --arg total_prefixes "$TOTAL_PREFIXES" --arg min_list "$MIN_LIST" \
    --arg max_list "$MAX_LIST" --arg seed "$SEED" \
    --arg changed_fraction "$CHANGED_FRACTION" --arg port "$PORT" \
    --arg reloads "$RELOADS" --arg control_secs "$CONTROL_SECS" \
    --arg campaign_kind "$CAMPAIGN_KIND" \
    --arg txn_max_candidate_bytes "$TXN_MAX_CANDIDATE_BYTES" \
    --arg cell_timeout "$CELL_TIMEOUT" --arg start_timeout "$START_TIMEOUT" \
    --arg bird_threads "$BIRD_THREADS" --arg skip_preflight "${SKIP_PREFLIGHT:-}" \
    --arg rustc "$(rustc -Vv)" --arg cargo "$(cargo -V)" \
    --arg python "$(python3 --version 2>&1)" --arg jq "$(jq --version)" \
    --arg docker "$DOCKER_VERSION" \
    --arg kernel "$(uname -srm)" \
    --arg cpu_model "$(awk -F: '/^model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)" \
    --arg bird_image "$BIRD_IMAGE" --arg bird_image_id "$BIRD_IMAGE_ID" \
    --arg openbgpd_image "$OPENBGPD_IMAGE" --arg openbgpd_image_id "$OPENBGPD_IMAGE_ID" \
    '{schema:2,git:{commit:$commit,dirty:$dirty,dirty_state_sha256:$dirty_state_sha256},scripts:{runner:$run_script_sha256,generator:$generator_sha256,rss_sampler:$sampler_sha256,txn_apply:$txn_apply_sha256},binaries:{reloadstall:$harness_sha256,rustbgpd:$daemon_sha256,rbgp:$cli_sha256,rs_config_render:$renderer_sha256},environment:{rustc:$rustc,cargo:$cargo,python:$python,jq:$jq,docker:$docker,kernel:$kernel,cpu_model:$cpu_model},inputs:{campaign_kind:$campaign_kind,cells:$cells,smoke:$smoke,n_members:$n_members,total_prefixes:$total_prefixes,min_list:$min_list,max_list:$max_list,seed:$seed,changed_fraction:$changed_fraction,port:$port,reloads:$reloads,control_secs:$control_secs,txn_max_candidate_bytes:$txn_max_candidate_bytes,cell_timeout:$cell_timeout,start_timeout:$start_timeout,bird_threads:$bird_threads,skip_preflight:$skip_preflight,bird_image:$bird_image,bird_image_id:$bird_image_id,openbgpd_image:$openbgpd_image,openbgpd_image_id:$openbgpd_image_id}}') || exit 1
CAMPAIGN_FINGERPRINT=$(printf '%s' "$CAMPAIGN_PROVENANCE" | sha256sum | cut -d' ' -f1) || exit 1
SEALED_CAMPAIGN_PROVENANCE=$(printf '%s\n' "$CAMPAIGN_PROVENANCE" | jq -cS \
    --arg fingerprint "$CAMPAIGN_FINGERPRINT" '. + {fingerprint:$fingerprint}') || exit 1
ARTIFACT_ROOT_EXISTING=false
if [ -e "$ART/provenance.json" ]; then
    ARTIFACT_ROOT_EXISTING=true
    PRIOR_FINGERPRINT=$(jq -er '.fingerprint | select(type == "string" and length > 0)' \
        "$ART/provenance.json" 2>/dev/null) || {
        echo "artifact root has malformed provenance; refusing to overwrite it" >&2
        echo "choose a fresh ARTIFACTS_DIR" >&2
        exit 2
    }
    PRIOR_PROVENANCE=$(jq -cS . "$ART/provenance.json" 2>/dev/null) || {
        echo "artifact root has malformed provenance; refusing to overwrite it" >&2
        echo "choose a fresh ARTIFACTS_DIR" >&2
        exit 2
    }
    if [ "$PRIOR_PROVENANCE" != "$SEALED_CAMPAIGN_PROVENANCE" ]; then
        echo "artifact root belongs to campaign $PRIOR_FINGERPRINT" >&2
        echo "refusing to overwrite or repair its provenance; choose a fresh ARTIFACTS_DIR" >&2
        exit 2
    fi
elif [ -n "$(find "$ART" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "non-empty artifact root has no provenance; refusing to overwrite it" >&2
    echo "choose a fresh ARTIFACTS_DIR" >&2
    exit 2
else
    printf '%s\n' "$SEALED_CAMPAIGN_PROVENANCE" >"$ART/provenance.json" || exit 1
fi
ROWS_HEADER="cell,reload,peers_total,peers_changed,peers_stable,prefixes,completion_p50_s,completion_p95_s,completion_max_s,changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
if [ -f "$ART/rows.csv" ] && [ "$(head -n1 "$ART/rows.csv")" != "$ROWS_HEADER" ]; then
    echo "artifact root has an incompatible rows.csv; choose a fresh ARTIFACTS_DIR" >&2
    exit 2
fi
if [ "$ARTIFACT_ROOT_EXISTING" = true ] && [ ! -f "$ART/rows.csv" ]; then
    echo "existing artifact root has no rows.csv; refusing to repair it" >&2
    echo "choose a fresh ARTIFACTS_DIR" >&2
    exit 2
fi
if [ "$ARTIFACT_ROOT_EXISTING" = false ]; then
    printf '%s\n' "$ROWS_HEADER" >"$ART/rows.csv"
fi

cell_receipt_matches() {
    local cdir=$1 cell scenario_sha dataset_sha evidence_sha actual_sha rows_tmp
    cell=${cdir##*/}
    scenario_sha=$(jq -er --arg fingerprint "$CAMPAIGN_FINGERPRINT" \
        'select(.fingerprint == $fingerprint) | .scenario.manifest_sha256' \
        "$cdir/provenance.json" 2>/dev/null) || return 1
    dataset_sha=$(jq -er --arg fingerprint "$CAMPAIGN_FINGERPRINT" \
        'select(.fingerprint == $fingerprint) | .scenario.dataset_sha256' \
        "$cdir/provenance.json" 2>/dev/null) || return 1
    [ -n "$scenario_sha" ] || return 1
    [ -n "$dataset_sha" ] || return 1
    actual_sha=$(hash_file "$cdir/scenario.sha256" 2>/dev/null) || return 1
    [ "$actual_sha" = "$scenario_sha" ] || return 1
    [ "$(cat "$ART/dataset.sha256" 2>/dev/null)" = "$dataset_sha" ] || return 1
    evidence_sha=$(awk -v fingerprint="$CAMPAIGN_FINGERPRINT" \
        -v scenario="$scenario_sha" -v dataset="$dataset_sha" \
        '$1 == "pass" && $2 == fingerprint && $3 == scenario && $4 == dataset && NF == 5 { print $5 }' \
        "$cdir/status" 2>/dev/null) || return 1
    [ -n "$evidence_sha" ] || return 1
    actual_sha=$(hash_file "$cdir/evidence.sha256" 2>/dev/null) || return 1
    [ "$actual_sha" = "$evidence_sha" ] || return 1
    (cd "$cdir" && sha256sum --check --strict --status evidence.sha256) || return 1
    validate_cell_rows "$cdir/rows.csv" "$cell" || return 1
    rows_tmp=$(mktemp "/tmp/irrreload-$cell-rows.XXXXXX") || return 1
    grep "^$cell," "$ART/rows.csv" >"$rows_tmp" || {
        rm -f "$rows_tmp"
        return 1
    }
    cmp -s "$cdir/rows.csv" "$rows_tmp"
    local rc=$?
    rm -f "$rows_tmp"
    return "$rc"
}

validate_cell_rows() {
    local rows=$1 cell=$2
    awk -F, -v cell="$cell" -v expected="$RELOADS" '
        function uint(v) { return v ~ /^[0-9]+$/ }
        function number(v) { return v ~ /^[0-9]+([.][0-9]+)?$/ }
        NF != 23 || $1 != cell || $2 != sprintf("%d", NR) { bad=1; next }
        !uint($3) || !uint($4) || !uint($5) || !uint($6) { bad=1 }
        !number($7) || !number($8) || !number($9) { bad=1 }
        !number($10) || !number($11) || !number($12) { bad=1 }
        !number($13) || !number($14) || !number($15) { bad=1 }
        !number($16) || !number($17) || !number($18) { bad=1 }
        !number($19) || !number($20) { bad=1 }
        !uint($21) || !uint($22) || !uint($23) { bad=1 }
        END { exit (bad || NR != expected) }
    ' "$rows"
}

seal_cell_evidence() {
    local cdir=$1 path digest
    local -a evidence_files=(
        daemon.log manifest.json provenance.json reloadstall.log rows.csv rss.csv scenario.sha256
    )
    : >"$cdir/evidence.sha256.tmp"
    for path in "${evidence_files[@]}"; do
        [ -f "$cdir/$path" ] || {
            echo "missing retained cell evidence: $path" >&2
            rm -f "$cdir/evidence.sha256.tmp"
            return 1
        }
        digest=$(hash_file "$cdir/$path") || return 1
        printf '%s  %s\n' "$digest" "$path" >>"$cdir/evidence.sha256.tmp" || return 1
    done
    mv "$cdir/evidence.sha256.tmp" "$cdir/evidence.sha256" || return 1
    CELL_EVIDENCE_SHA256=$(hash_file "$cdir/evidence.sha256") || return 1
}

seal_scenario() {
    local run=$1 cdir=$2 path digest
    local -a runtime_files=()
    mapfile -t runtime_files < <(
        jq -er '.runtime_files | select(type == "array" and length > 0)[]' \
            "$run/manifest.json"
    ) || return 1
    [ ${#runtime_files[@]} -gt 0 ] || return 1
    : >"$cdir/scenario.sha256"
    for path in "${runtime_files[@]}" manifest.json; do
        case $path in
        '' | /* | */* | *..*)
            echo "invalid runtime input path in manifest: $path" >&2
            return 1
            ;;
        esac
        [ -f "$run/$path" ] || {
            echo "runtime input missing: $path" >&2
            return 1
        }
        digest=$(hash_file "$run/$path") || return 1
        printf '%s  ./%s\n' "$digest" "$path" >>"$cdir/scenario.sha256" || return 1
    done
    sort -o "$cdir/scenario.sha256" "$cdir/scenario.sha256" || return 1
    CELL_SCENARIO_SHA256=$(hash_file "$cdir/scenario.sha256") || return 1
    CELL_DATASET_SHA256=$(jq -er '.dataset_sha256' "$run/manifest.json") || return 1
    if [ -f "$ART/dataset.sha256" ]; then
        if [ "$(cat "$ART/dataset.sha256")" != "$CELL_DATASET_SHA256" ]; then
            echo "cell dataset digest differs from the campaign dataset" >&2
            return 1
        fi
    else
        printf '%s\n' "$CELL_DATASET_SHA256" >"$ART/dataset.sha256" || return 1
    fi
    jq --arg scenario_sha "$CELL_SCENARIO_SHA256" \
        --arg dataset_sha "$CELL_DATASET_SHA256" \
        '. + {scenario:{manifest_sha256:$scenario_sha,dataset_sha256:$dataset_sha}}' \
        "$ART/provenance.json" >"$cdir/provenance.json"
}

ACTIVE_DAEMON_PID=""
ACTIVE_HARNESS_PID=""
ACTIVE_SAMPLER_PID=""
terminate_process_group() {
    # shellcheck disable=SC2317  # invoked directly and via trap
    local pid=$1 attempt
    [ -n "$pid" ] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || true
    for ((attempt = 0; attempt < 20; attempt++)); do
        kill -0 -- "-$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
cleanup_active_processes() {
    # shellcheck disable=SC2317  # invoked directly and via trap
    local pid
    for pid in "$ACTIVE_HARNESS_PID" "$ACTIVE_SAMPLER_PID" "$ACTIVE_DAEMON_PID"; do
        terminate_process_group "$pid"
    done
    ACTIVE_HARNESS_PID=""
    ACTIVE_SAMPLER_PID=""
    ACTIVE_DAEMON_PID=""
}
cleanup() {
    # shellcheck disable=SC2317  # invoked via trap
    cleanup_active_processes
    docker rm -f irr-bird irr-obgpd >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

load_gate() {
    [ -n "$SMOKE" ] && return 0
    local load
    while :; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        if awk -v l="$load" 'BEGIN { exit !(l < 2.0) }'; then return 0; fi
        echo "load_gate: 1-min loadavg $load >= 2.0, waiting 30s"
        sleep 30
    done
}

gen_scenario() {
    local cell=$1 run=$2
    shift 2
    python3 "$GEN" "$cell" "$N_MEMBERS" "$TOTAL_PREFIXES" "$run" \
        --port "$PORT" --seed "$SEED" --min-list "$MIN_LIST" \
        --max-list "$MAX_LIST" --changed-fraction "$CHANGED_FRACTION" "$@"
}

# wait_ready <cell> <cdir>: poll (1 s cadence, ceiling START_TIMEOUT)
# until the cell's daemon listens on $PORT — large-config parses take
# far longer than the fixed 3 s the small-config harness assumed. For
# container cells this also captures daemon_pid via docker inspect,
# retried until nonzero: a single immediate inspect used to race a
# slow-starting container and record pid=0. Fails fast if the daemon
# process/container dies first. Uses/sets the caller's daemon_pid and
# container.
wait_ready() {
    local cell=$1 cdir=$2 waited=0
    while :; do
        if [ -n "$container" ]; then
            if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != true ]; then
                echo "cell $cell: container died at start" >&2
                docker logs "$container" >"$cdir/daemon.log" 2>&1
                docker rm -f "$container" >/dev/null 2>&1
                return 1
            fi
            if [ "${daemon_pid:-0}" -le 0 ]; then
                daemon_pid=$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null) || daemon_pid=0
            fi
        elif [ ! -d "/proc/$daemon_pid" ]; then
            echo "cell $cell: daemon died at start (see $cdir/daemon.log)" >&2
            return 1
        fi
        if [ "${daemon_pid:-0}" -gt 0 ] && ss -ltnH "sport = :$PORT" | grep -q .; then
            return 0
        fi
        if [ "$waited" -ge "$START_TIMEOUT" ]; then
            echo "cell $cell: no listener on :$PORT after ${START_TIMEOUT}s" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# run_cell <cell>: one matrix cell. Nonzero return = cell failed; the
# campaign continues (matrix convention).
run_cell() {
    local cell=$1
    local cdir="$ART/$cell"
    # Short run dir: the gRPC UDS path must fit SUN_LEN.
    local run="/tmp/irr-$cell"
    rm -rf "$run"
    mkdir -p "$cdir" "$run"

    local daemon_pid="" container="" reload_cmd="" pid_arg=""
    local live a b
    CELL_SCENARIO_SHA256=""
    CELL_DATASET_SHA256=""
    CELL_EVIDENCE_SHA256=""
    case $cell in
    rustbgpd-sighup)
        gen_scenario rustbgpd "$run" --render-bin "$RENDER" || return 1
        seal_scenario "$run" "$cdir" || return 1
        setsid "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        ACTIVE_DAEMON_PID=$daemon_pid
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid # SIGHUP path: harness signals + samples this PID
        ;;
    rustbgpd-txn)
        gen_scenario rustbgpd-txn "$run" || return 1
        local candidate candidate_bytes
        for candidate in "$run/config.toml" "$run/candidate.toml" \
            "$run/gen-a.toml" "$run/gen-b.toml"; do
            candidate_bytes=$(wc -c <"$candidate") || return 1
            if [ "$candidate_bytes" -gt "$TXN_MAX_CANDIDATE_BYTES" ]; then
                echo "cell $cell: $(basename "$candidate") is ${candidate_bytes} bytes" >&2
                echo "candidate exceeds the ${TXN_MAX_CANDIDATE_BYTES}-byte tonic request budget" >&2
                echo "use a smaller separate transaction shape and a fresh ARTIFACTS_DIR" >&2
                return 1
            fi
        done
        seal_scenario "$run" "$cdir" || return 1
        setsid "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        ACTIVE_DAEMON_PID=$daemon_pid
        live="$run/candidate.toml" a="$run/gen-a.toml" b="$run/gen-b.toml"
        pid_arg=$daemon_pid # RSS from the real PID; reloads via reload_cmd
        reload_cmd="$TXN_APPLY $RBGP unix://$run/grpc.sock $run/candidate.toml"
        ;;
    bird)
        gen_scenario bird "$run" --threads "$BIRD_THREADS" || return 1
        seal_scenario "$run" "$cdir" || return 1
        container="irr-bird"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bird \
            "$BIRD_IMAGE_ID" bird -f -c /etc/bird/bird.conf >/dev/null || return 1
        reload_cmd="docker exec $container birdc configure"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0 # the outer sampler owns RSS
        ;;
    openbgpd)
        gen_scenario openbgpd "$run" || return 1
        seal_scenario "$run" "$cdir" || return 1
        container="irr-obgpd"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bgpd \
            "$OPENBGPD_IMAGE_ID" >/dev/null || return 1
        reload_cmd="docker exec $container bgpctl reload"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0
        ;;
    *)
        echo "unknown cell: $cell" >&2
        return 1
        ;;
    esac

    wait_ready "$cell" "$cdir" || return 1

    setsid "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!
    ACTIVE_SAMPLER_PID=$sampler_pid

    local hargs=("$N_MEMBERS" "$TOTAL_PREFIXES" "$PORT" "$pid_arg"
        "$live" "$a" "$b" "$RELOADS" "$CONTROL_SECS")
    # reload_cmd is positional arg 11, so cells using it pass an explicit
    # all-changed cohort (same completion semantics as the 9-arg form).
    [ -n "$reload_cmd" ] && hargs+=("$N_MEMBERS" "$reload_cmd")

    # Background so the precommitted RSS abort criterion can kill the cell.
    setsid timeout "$CELL_TIMEOUT" "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    local hpid=$!
    ACTIVE_HARNESS_PID=$hpid
    local rc=""
    while kill -0 "$hpid" 2>/dev/null; do
        if ! kill -0 "$sampler_pid" 2>/dev/null; then
            echo "cell $cell: RSS sampler exited before harness completion" >&2
            terminate_process_group "$hpid"
            rc=98
            break
        fi
        local last_kib
        last_kib=$(tail -n1 "$cdir/rss.csv" 2>/dev/null | cut -d, -f2)
        case ${last_kib:-} in
        '' | *[!0-9]*) ;;
        *)
            if [ "$last_kib" -gt "$RSS_LIMIT_KIB" ]; then
                echo "cell $cell: daemon RSS ${last_kib} KiB > 100 GiB, aborting cell" >&2
                terminate_process_group "$hpid"
                rc=99
                break
            fi
            ;;
        esac
        sleep 5
    done
    local hrc
    wait "$hpid"
    hrc=$?
    ACTIVE_HARNESS_PID=""
    [ -z "$rc" ] && rc=$hrc

    if [ -n "$container" ]; then
        docker logs "$container" >"$cdir/daemon.log" 2>&1
        docker rm -f "$container" >/dev/null 2>&1
    else
        terminate_process_group "$daemon_pid"
        ACTIVE_DAEMON_PID=""
    fi
    local sampler_rc=0
    wait "$sampler_pid" || sampler_rc=$?
    ACTIVE_SAMPLER_PID=""
    if [ "$sampler_rc" -ne 0 ]; then
        echo "cell $cell: RSS sampler failed rc=$sampler_rc" >&2
        rc=98
    elif ! awk -F, 'NR == 1 { if ($0 != "epoch_s,total_rss_kib,pids") bad=1; next } NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[1-9][0-9]*$/ || $3 !~ /^[1-9][0-9]*$/ { bad=1 } NR > 1 { rows++ } END { exit (bad || rows == 0) }' "$cdir/rss.csv"; then
        echo "cell $cell: RSS sampler produced empty or invalid data" >&2
        rc=98
    fi
    if ! cp "$run/manifest.json" "$cdir/manifest.json" ||
        [ "$(hash_file "$cdir/scenario.sha256" 2>/dev/null)" != "$CELL_SCENARIO_SHA256" ]; then
        echo "cell $cell: required manifest/provenance retention failed" >&2
        rc=97
    fi
    if [ "$rc" -eq 0 ]; then
        local rows_tmp="$cdir/rows.csv.tmp"
        grep '^reloadstall_csv,' "$cdir/reloadstall.log" |
            sed "s/^reloadstall_csv/$cell/" >"$rows_tmp"
        if ! validate_cell_rows "$rows_tmp" "$cell"; then
            echo "cell $cell: invalid, missing, or duplicate measurement rows" >&2
            rm -f "$rows_tmp"
            rc=96
        else
            if ! mv "$rows_tmp" "$cdir/rows.csv" ||
                ! sed -n '1,$p' "$cdir/rows.csv" >>"$ART/rows.csv"; then
                echo "cell $cell: failed to retain measurement rows" >&2
                rc=96
            elif ! seal_cell_evidence "$cdir"; then
                echo "cell $cell: failed to seal retained evidence" >&2
                rc=95
            else
                rm -rf "$run" # reproduces from the generator + manifest
            fi
        fi
    fi
    echo "cell $cell: harness rc=$rc (artifacts: $cdir)"
    return "$rc"
}

if [ "$ARTIFACT_ROOT_EXISTING" = true ]; then
    allowed_cells=",$(IFS=,; echo "${CELLS[*]}"),"
    if ! awk -F, -v allowed="$allowed_cells" '
        NR == 1 { next }
        index(allowed, "," $1 ",") == 0 { exit 1 }
    ' "$ART/rows.csv"; then
        echo "artifact root has measurement rows outside the selected cell roster" >&2
        echo "choose a fresh ARTIFACTS_DIR" >&2
        exit 2
    fi
    while IFS= read -r entry; do
        name=${entry##*/}
        case $name in
        provenance.json | rows.csv | dataset.sha256) ;;
        *)
            if [[ " ${CELLS[*]} " != *" $name "* ]]; then
                echo "artifact root has unexpected entry: $name" >&2
                echo "choose a fresh ARTIFACTS_DIR" >&2
                exit 2
            fi
            ;;
        esac
    done < <(find "$ART" -mindepth 1 -maxdepth 1 -print)
    any_existing_cell=false
    for cell in "${CELLS[@]}"; do
        existing_rows=$(grep -c "^$cell," "$ART/rows.csv" 2>/dev/null)
        if [ -e "$ART/$cell" ] || [ "${existing_rows:-0}" -ne 0 ]; then
            any_existing_cell=true
            if ! cell_receipt_matches "$ART/$cell" ||
                [ "${existing_rows:-0}" -ne "$RELOADS" ]; then
                echo "cell $cell: existing evidence is inconsistent and immutable" >&2
                echo "choose a fresh ARTIFACTS_DIR" >&2
                exit 2
            fi
        fi
    done
    if [ "$any_existing_cell" = false ] && [ -e "$ART/dataset.sha256" ]; then
        echo "artifact root has an unowned dataset digest; refusing to repair it" >&2
        echo "choose a fresh ARTIFACTS_DIR" >&2
        exit 2
    fi
fi

overall=0
for cell in "${CELLS[@]}"; do
    status_file="$ART/$cell/status"
    existing_rows=$(grep -c "^$cell," "$ART/rows.csv" 2>/dev/null)
    if cell_receipt_matches "$ART/$cell" &&
        [ "${existing_rows:-0}" -eq "$RELOADS" ]; then
        echo "cell $cell: matching fingerprint already passed, skipping"
        continue
    fi
    if [ -e "$ART/$cell" ] || [ "${existing_rows:-0}" -ne 0 ]; then
        echo "cell $cell: existing failed, interrupted, or inconsistent evidence is immutable" >&2
        echo "refusing to overwrite it; choose a fresh ARTIFACTS_DIR" >&2
        overall=1
        continue
    fi
    load_gate
    echo "=== cell $cell start $(date -Is) ==="
    CELL_SCENARIO_SHA256=""
    CELL_DATASET_SHA256=""
    CELL_EVIDENCE_SHA256=""
    if run_cell "$cell"; then
        echo "pass $CAMPAIGN_FINGERPRINT $CELL_SCENARIO_SHA256 $CELL_DATASET_SHA256 $CELL_EVIDENCE_SHA256" \
            >"$status_file"
        echo "=== cell $cell PASS $(date -Is) ==="
    else
        rc=$?
        cleanup
        mkdir -p "$ART/$cell"
        echo "fail $CAMPAIGN_FINGERPRINT ${CELL_SCENARIO_SHA256:-unavailable} ${CELL_DATASET_SHA256:-unavailable} ${CELL_EVIDENCE_SHA256:-unavailable} rc=$rc" \
            >"$status_file"
        echo "=== cell $cell FAIL ==="
        overall=1
    fi
    echo "cool-down ${COOL_DOWN}s"
    sleep "$COOL_DOWN"
done

# Completion gate: every requested cell passed and produced its rows.
for cell in "${CELLS[@]}"; do
    cell_receipt_matches "$ART/$cell" || overall=1
    rows=$(grep -c "^$cell," "$ART/rows.csv" 2>/dev/null)
    if [ "${rows:-0}" -ne "$RELOADS" ]; then
        echo "cell $cell: expected exactly $RELOADS measurement rows, found ${rows:-0}" >&2
        overall=1
    fi
done
echo "measurement rows: $ART/rows.csv"
exit "$overall"
