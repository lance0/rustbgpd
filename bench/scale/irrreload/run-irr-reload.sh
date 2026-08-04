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
#                    [policy.definitions] chains; streamed Plan + explicit
#                    plan-token Apply + commit-confirm (txn-apply.sh)
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
#   default   the measured shape. Requires clean origin/main, preflight +
#             host lock, two quiet samples per cell, and 300 s cool-downs.
#
# Knobs (env): N_MEMBERS TOTAL_PREFIXES MIN_LIST MAX_LIST SEED
#              CHANGED_FRACTION PORT RELOADS CONTROL_SECS BIRD_THREADS
#              CELL_TIMEOUT START_TIMEOUT ARTIFACTS_DIR TXN_MAX_CANDIDATE_BYTES
#
set -u
set -o pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
RSTALL="$REPO/bench/scale/reloadstall"
HARNESS="$RSTALL/target/release/reloadstall"
GEN="$RSTALL/gen-irr-scenario.py"
SAMPLER="$REPO/bench/scale/matrix/rss-sampler.sh"
TXN_APPLY="$REPO/bench/scale/irrreload/txn-apply.sh"
TXN_LIFECYCLE="$REPO/bench/scale/irrreload/txn-lifecycle.sh"
VERIFY="$REPO/bench/scale/irrreload/verify-receipt.py"
RBGP="$REPO/target/release/rbgp"
RENDER="$REPO/target/release/rs-config-render"
DAEMON="$REPO/target/release/rustbgpd"

SMOKE="${SMOKE:-}"
GROUPED_CELL=rustbgpd-sighup-grouped-control
CELLS=("$@")
if [ ${#CELLS[@]} -eq 0 ]; then
    if [ -n "$SMOKE" ]; then
        CELLS=(rustbgpd-sighup rustbgpd-txn bird openbgpd)
    else
        CELLS=(rustbgpd-sighup bird openbgpd)
    fi
fi

GROUPED_ONLY=false
if [[ " ${CELLS[*]} " == *" $GROUPED_CELL "* ]]; then
    if [ ${#CELLS[@]} -ne 1 ]; then
        echo "$GROUPED_CELL is a standalone control, never a comparison-table cell" >&2
        exit 2
    fi
    GROUPED_ONLY=true
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
# Hard readiness ceiling only; startup is not a reported measurement.
START_TIMEOUT="${START_TIMEOUT:-600}"
BIRD_THREADS="${BIRD_THREADS:-8}"
ART="${ARTIFACTS_DIR:-/tmp/irrreload-artifacts}"
PREFLIGHT_LOG=""
cleanup_preflight_log() { [ -z "$PREFLIGHT_LOG" ] || rm -f "$PREFLIGHT_LOG"; }
trap cleanup_preflight_log EXIT
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB (precommitted)
TOPOLOGY_CAPTURE_TIMEOUT=50
TXN_STREAM_MAX_BYTES=$((384 * 1024 * 1024))
TXN_MAX_CANDIDATE_BYTES="${TXN_MAX_CANDIDATE_BYTES:-$TXN_STREAM_MAX_BYTES}"
case $TXN_MAX_CANDIDATE_BYTES in
'' | *[!0-9]*)
    echo "TXN_MAX_CANDIDATE_BYTES must be an integer" >&2
    exit 2
    ;;
esac
if [ "$TXN_MAX_CANDIDATE_BYTES" -gt "$TXN_STREAM_MAX_BYTES" ]; then
    echo "TXN_MAX_CANDIDATE_BYTES exceeds the streamed candidate ceiling" >&2
    echo "maximum: $TXN_STREAM_MAX_BYTES bytes" >&2
    exit 2
fi

if [ -n "$SMOKE" ]; then
    CAMPAIGN_KIND=smoke
elif [ "$TXN_ONLY" = true ]; then
    CAMPAIGN_KIND=full-transaction
elif [ "$GROUPED_ONLY" = true ]; then
    CAMPAIGN_KIND=full-grouped-control
else
    CAMPAIGN_KIND=full-cross-daemon
fi

if [[ " ${CELLS[*]} " == *" rustbgpd-sighup "* || "$GROUPED_ONLY" = true ]] &&
    [ "$CONTROL_SECS" -lt 4 ]; then
    echo "rustbgpd SIGHUP cells need CONTROL_SECS >= 4 for pre-reload topology proof" >&2
    exit 2
fi

if [ -n "${DRY_RUN_PROTOCOL:-}" ]; then
    printf 'cells=%s\n' "$(IFS=,; echo "${CELLS[*]}")"
    printf 'campaign_kind=%s\n' "$CAMPAIGN_KIND"
    printf 'rustbgpd_private=path_hiding:true,admit_churn:true\n'
    printf 'rustbgpd_grouped_control=path_hiding:false,admit_churn:true,standalone:true\n'
    printf 'competitor_path_hiding=applicable:false,requested:true\n'
    printf 'shape=%s,%s,%s,%s\n' "$N_MEMBERS" "$TOTAL_PREFIXES" "$MIN_LIST" "$MAX_LIST"
    printf 'reloads=%s control_secs=%s txn_max_candidate_bytes=%s\n' \
        "$RELOADS" "$CONTROL_SECS" "$TXN_MAX_CANDIDATE_BYTES"
    exit 0
fi

for tool in docker jq python3 cargo curl flock ss sha256sum git awk timeout find sort setsid stdbuf cmp mktemp stat df env; do
    command -v "$tool" >/dev/null || {
        echo "missing required tool: $tool" >&2
        exit 1
    }
done

if [ -z "$SMOKE" ]; then
    if [ -n "${SKIP_PREFLIGHT:-}" ]; then
        echo "full measured campaigns cannot set SKIP_PREFLIGHT" >&2
        exit 2
    fi
    git -C "$REPO" fetch --quiet origin main || exit 1
    HEAD_COMMIT=$(git -C "$REPO" rev-parse HEAD) || exit 1
    ORIGIN_MAIN=$(git -C "$REPO" rev-parse origin/main) || exit 1
    if [ "$HEAD_COMMIT" != "$ORIGIN_MAIN" ] ||
        [ -n "$(git -C "$REPO" status --porcelain=v1)" ]; then
        echo "full measured campaigns require a clean HEAD exactly at origin/main" >&2
        exit 2
    fi
    if [ "$N_MEMBERS,$TOTAL_PREFIXES,$MIN_LIST,$MAX_LIST,$SEED,$RELOADS,$CHANGED_FRACTION,$PORT,$CONTROL_SECS,$TXN_MAX_CANDIDATE_BYTES,$CELL_TIMEOUT,$START_TIMEOUT,$BIRD_THREADS" != \
        "320,183040,1000,40000,61,4,0.1,1790,30,402653184,7200,600,8" ]; then
        echo "full measured campaigns require canonical workload knobs" >&2
        exit 2
    fi
    echo "=== host-quiet preflight (tests/soak/preflight.sh) ==="
    PREFLIGHT_LOG=$(mktemp /tmp/irrreload-preflight.XXXXXX) || exit 1
    "$REPO/tests/soak/preflight.sh" >"$PREFLIGHT_LOG" 2>&1 || {
        cat "$PREFLIGHT_LOG" >&2
        rm -f "$PREFLIGHT_LOG"
        echo "preflight failed; fix the named host condition" >&2
        exit 1
    }
fi

HOST_LOCK="${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}"
mkdir -p "$(dirname "$HOST_LOCK")"
exec {HOST_LOCK_FD}>"$HOST_LOCK"
flock -n "$HOST_LOCK_FD" || {
    echo "host benchmark lock is held: $HOST_LOCK" >&2
    exit 75
}

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
if [ -e "$ART/COMPLETED" ] || [ -e "$ART/SHA256SUMS" ]; then
    echo "completed artifact roots are immutable; choose a fresh ARTIFACTS_DIR" >&2
    exit 2
fi
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

COMMIT=$(git -C "$REPO" rev-parse HEAD) || exit 1
# Full provenance binds source, tools, binaries, images, and campaign inputs;
# dirty smoke runs include tracked diffs and untracked content hashes.
ORIGIN_MAIN=$(git -C "$REPO" rev-parse origin/main 2>/dev/null || printf unavailable)
HEAD_MATCHES_ORIGIN_MAIN=false
[ "$COMMIT" = "$ORIGIN_MAIN" ] && HEAD_MATCHES_ORIGIN_MAIN=true
CAMPAIGN_STARTED_EPOCH_NS=$(date +%s%N)
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
    --arg origin_main "$ORIGIN_MAIN" --argjson head_matches_origin_main "$HEAD_MATCHES_ORIGIN_MAIN" \
    --argjson started_at_epoch_ns "$CAMPAIGN_STARTED_EPOCH_NS" \
    --arg run_script_sha256 "$(hash_file "$REPO/bench/scale/irrreload/run-irr-reload.sh")" \
    --arg verifier_sha256 "$(hash_file "$VERIFY")" \
    --arg generator_sha256 "$(hash_file "$GEN")" \
    --arg sampler_sha256 "$(hash_file "$SAMPLER")" \
    --arg txn_apply_sha256 "$(hash_file "$TXN_APPLY")" \
    --arg txn_lifecycle_sha256 "$(hash_file "$TXN_LIFECYCLE")" \
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
    '{schema:3,started_at_epoch_ns:$started_at_epoch_ns,git:{commit:$commit,dirty:$dirty,dirty_state_sha256:$dirty_state_sha256,origin_main:$origin_main,head_matches_origin_main:$head_matches_origin_main},scripts:{runner:$run_script_sha256,verifier:$verifier_sha256,generator:$generator_sha256,rss_sampler:$sampler_sha256,txn_apply:$txn_apply_sha256,txn_lifecycle:$txn_lifecycle_sha256},binaries:{reloadstall:$harness_sha256,rustbgpd:$daemon_sha256,rbgp:$cli_sha256,rs_config_render:$renderer_sha256},environment:{rustc:$rustc,cargo:$cargo,python:$python,jq:$jq,docker:$docker,kernel:$kernel,cpu_model:$cpu_model},inputs:{campaign_kind:$campaign_kind,cells:$cells,smoke:$smoke,n_members:$n_members,total_prefixes:$total_prefixes,min_list:$min_list,max_list:$max_list,seed:$seed,changed_fraction:$changed_fraction,port:$port,reloads:$reloads,control_secs:$control_secs,txn_max_candidate_bytes:$txn_max_candidate_bytes,cell_timeout:$cell_timeout,start_timeout:$start_timeout,bird_threads:$bird_threads,skip_preflight:$skip_preflight,bird_image:$bird_image,bird_image_id:$bird_image_id,openbgpd_image:$openbgpd_image,openbgpd_image_id:$openbgpd_image_id}}') || exit 1
CAMPAIGN_FINGERPRINT=$(printf '%s' "$CAMPAIGN_PROVENANCE" | jq -cS . | sha256sum | cut -d' ' -f1) || exit 1
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
if [ -n "$PREFLIGHT_LOG" ]; then
    mv "$PREFLIGHT_LOG" "$ART/preflight.log" || exit 1
    PREFLIGHT_LOG=""
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
        daemon.log final-evidence/ready final-evidence/ack manifest.json process.tsv provenance.json reloadstall.log rows.csv rss.csv scenario.sha256
    )
    if [ -z "$SMOKE" ]; then
        evidence_files+=(quiet.tsv)
    fi
    case ${cdir##*/} in
    rustbgpd-txn)
        if [ -z "$SMOKE" ]; then
            evidence_files+=(transactions/cycles.jsonl transactions/lifecycle.json)
        fi
        ;;
    rustbgpd-sighup | "$GROUPED_CELL")
        evidence_files+=(config.toml topology.json topology.tsv metrics-1.prom metrics-2.prom metrics-3.prom pre-churn/ready pre-churn/ack)
        ;;
    esac
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
    cleanup_preflight_log
    docker rm -f irr-bird irr-obgpd >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

load_gate() {
    local cell=$1 load sample=1 quiet pswpin pswpout disk_kib first_pswpin first_pswpout port1790 port9179
    quiet="$ART/$cell/quiet.tsv"
    [ -n "$SMOKE" ] && return 0
    mkdir -p "$ART/$cell"
    printf 'sample\tepoch_s\tload1\tpswpin\tpswpout\tport1790_free\tport9179_free\tdisk_available_kib\n' >"$quiet"
    while [ "$sample" -le 2 ]; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        pswpin=$(awk '$1 == "pswpin" {print $2}' /proc/vmstat)
        pswpout=$(awk '$1 == "pswpout" {print $2}' /proc/vmstat)
        disk_kib=$(df -Pk "$ART" | awk 'NR == 2 {print $4}')
        port1790=$(ss -ltnH 'sport = :1790') || { echo "load_gate: cannot inspect port 1790" >&2; exit 1; }
        port9179=$(ss -ltnH 'sport = :9179') || { echo "load_gate: cannot inspect port 9179" >&2; exit 1; }
        if awk -v l="$load" 'BEGIN { exit !(l < 2.0) }' &&
            [ -z "$port1790" ] && [ -z "$port9179" ] &&
            [ "$disk_kib" -ge $((40 * 1024 * 1024)) ]; then
            printf '%s\t%s\t%s\t%s\t%s\ttrue\ttrue\t%s\n' \
                "$sample" "$(date +%s)" "$load" "$pswpin" "$pswpout" "$disk_kib" >>"$quiet"
            if [ "$sample" -eq 1 ]; then
                first_pswpin=$pswpin
                first_pswpout=$pswpout
            elif [ "$pswpin" != "$first_pswpin" ] || [ "$pswpout" != "$first_pswpout" ]; then
                echo "load_gate: swap activity observed; restarting quiet samples"
                printf 'sample\tepoch_s\tload1\tpswpin\tpswpout\tport1790_free\tport9179_free\tdisk_available_kib\n' >"$quiet"
                sample=1
                sleep 30
                continue
            fi
            sample=$((sample + 1))
        else
            echo "load_gate: waiting for load <2, free ports 1790/9179, and 40 GiB free on ART"
        fi
        [ "$sample" -gt 2 ] || sleep 30
    done
}

capture_topology() {
    local mode=$1 cdir=$2 run=$3 hpid=$4 barrier=$5 deadline sample entries
    deadline=$((SECONDS + CELL_TIMEOUT))
    while [ ! -e "$barrier/ready" ]; do
        kill -0 "$hpid" 2>/dev/null || {
            echo "topology: harness exited before pre-churn boundary" >&2
            return 1
        }
        [ "$SECONDS" -lt "$deadline" ] || {
            echo "topology: pre-churn boundary timed out" >&2
            return 1
        }
        sleep 0.2
    done
    entries=$(find "$barrier" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
    if [ "$entries" != ready ] || [ ! -f "$barrier/ready" ] || [ -L "$barrier/ready" ]; then
        echo "topology: pre-churn boundary is stale or non-regular" >&2
        return 1
    fi
    cp "$run/config.toml" "$cdir/config.toml" || return 1
    deadline=$((SECONDS + TOPOLOGY_CAPTURE_TIMEOUT))
    while [ "$SECONDS" -lt "$deadline" ] && kill -0 "$hpid" 2>/dev/null; do
        rm -f "$cdir/topology.json" "$cdir"/metrics-{1,2,3}.prom
        printf 'phase\tepoch_ns\n' >"$cdir/topology.tsv"
        for sample in 1 2 3; do
            curl -fsS --max-time 2 'http://127.0.0.1:9179/metrics' >"$cdir/metrics-$sample.prom" || break
            printf 'scrape%s\t%s\n' "$sample" "$(date +%s%N)" >>"$cdir/topology.tsv"
            [ "$sample" -eq 3 ] || sleep 1
        done
        if python3 "$VERIFY" topology --mode "$mode" --peers "$N_MEMBERS" --total "$TOTAL_PREFIXES" \
            --config "$cdir/config.toml" --timestamps "$cdir/topology.tsv" \
            --output "$cdir/topology.json" "$cdir"/metrics-{1,2,3}.prom 2>"$cdir/topology.error"; then
            rm -f "$cdir/topology.error"
            ack_pre_churn "$barrier" true "$cdir" && return 0
            return 1
        fi
        sleep 0.2
    done
    cat "$cdir/topology.error" >&2 2>/dev/null || true
    echo "topology: invalid pre-churn evidence; acknowledgement withheld" >&2
    return 1
}
ack_pre_churn() {
    local barrier=$1 evidence_valid=$2 cdir=$3 tmp
    tmp="$barrier/ack.tmp"
    [ "$evidence_valid" = true ] || return 1
    [ -f "$barrier/ready" ] && [ ! -L "$barrier/ready" ] && [ ! -e "$barrier/ack" ] || return 1
    printf 'ack\n' >"$tmp" || return 1
    mv -T "$tmp" "$barrier/ack" || return 1
    [ -f "$barrier/ack" ] && [ ! -L "$barrier/ack" ] || return 1
    mkdir -p "$cdir/pre-churn" || return 1
    cp "$barrier/ready" "$barrier/ack" "$cdir/pre-churn/" || return 1
}
ack_final_evidence() {
    local barrier=$1 cdir=$2 daemon_pid=$3 daemon_start=$4 after tmp
    [ -f "$barrier/ready" ] && [ ! -L "$barrier/ready" ] && [ ! -e "$barrier/ack" ] || return 1
    after=$(awk '{print $22}' "/proc/$daemon_pid/stat" 2>/dev/null) || return 1
    [ "$after" = "$daemon_start" ] || return 1
    printf 'pid\tstarttime_before\tstarttime_after\n%s\t%s\t%s\n' \
        "$daemon_pid" "$daemon_start" "$after" >"$cdir/process.tsv" || return 1
    tmp="$barrier/ack.tmp"
    printf 'ack\n' >"$tmp" || return 1
    mv -T "$tmp" "$barrier/ack" || return 1
    [ -f "$barrier/ack" ] && [ ! -L "$barrier/ack" ] || return 1
    mkdir -p "$cdir/final-evidence" || return 1
    cp "$barrier/ready" "$barrier/ack" "$cdir/final-evidence/" || return 1
}
bind_first_trigger() {
    local cdir=$1 trigger
    trigger=$(sed -n 's/^reload 1 .*wall_us=\([0-9][0-9]*\).*/\1/p' "$cdir/reloadstall.log" | head -n1)
    case $trigger in '' | *[!0-9]*) return 1 ;; esac
    python3 - "$cdir/topology.json" "$trigger" <<'PY'
import json, pathlib, sys
path, trigger = pathlib.Path(sys.argv[1]), int(sys.argv[2])
data = json.loads(path.read_text())
if data["scrape_epoch_ns"][-1] // 1000 >= trigger:
    raise SystemExit("topology proof did not precede the first reload trigger")
data["first_reload_wall_us"] = trigger
path.write_text(json.dumps(data, sort_keys=True) + "\n")
PY
}
gen_scenario() {
    local cell=$1 run=$2
    shift 2
    python3 "$GEN" "$cell" "$N_MEMBERS" "$TOTAL_PREFIXES" "$run" \
        --port "$PORT" --seed "$SEED" --min-list "$MIN_LIST" \
        --max-list "$MAX_LIST" --changed-fraction "$CHANGED_FRACTION" "$@"
}

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
            case $cell in
            rustbgpd-sighup | rustbgpd-txn | "$GROUPED_CELL")
                curl -fsS --max-time 2 'http://127.0.0.1:9179/readyz' >/dev/null 2>&1 &&
                    return 0
                ;;
            *)
                return 0
                ;;
            esac
        fi
        if [ "$waited" -ge "$START_TIMEOUT" ]; then
            case $cell in
            rustbgpd-sighup | rustbgpd-txn | "$GROUPED_CELL")
                if [ "${daemon_pid:-0}" -gt 0 ] && ss -ltnH "sport = :$PORT" | grep -q .; then
                    echo "cell $cell: startup readiness did not complete after ${START_TIMEOUT}s; rustbgpd also requires http://127.0.0.1:9179/readyz" >&2
                else
                    echo "cell $cell: no listener on :$PORT after ${START_TIMEOUT}s" >&2
                fi
                ;;
            *)
                echo "cell $cell: no listener on :$PORT after ${START_TIMEOUT}s" >&2
                ;;
            esac
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

run_cell() {
    local cell=$1
    local cdir="$ART/$cell"
    local run="/tmp/irr-$cell"
    rm -rf -- "$run" || return 1
    mkdir -p "$cdir" || return 1
    mkdir -m 0700 -- "$run" || return 1
    local daemon_pid="" daemon_start="" container="" reload_cmd="" pid_arg="" topology_mode="" barrier="" final_barrier="" final_acked=false
    local live a b entries generator_cell=$cell
    CELL_SCENARIO_SHA256=""
    CELL_DATASET_SHA256=""
    CELL_EVIDENCE_SHA256=""
    case $cell in
    rustbgpd-sighup)
        gen_scenario rustbgpd "$run" --render-bin "$RENDER" \
            --path-hiding true --admit-churn true || return 1
        seal_scenario "$run" "$cdir" || return 1
        setsid "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        ACTIVE_DAEMON_PID=$daemon_pid
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid
        topology_mode=private
        ;;
    "$GROUPED_CELL")
        generator_cell=rustbgpd
        gen_scenario "$generator_cell" "$run" --render-bin "$RENDER" \
            --path-hiding false --admit-churn true || return 1
        seal_scenario "$run" "$cdir" || return 1
        setsid "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        ACTIVE_DAEMON_PID=$daemon_pid
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid
        topology_mode=grouped
        ;;
    rustbgpd-txn)
        gen_scenario rustbgpd-txn "$run" --path-hiding true --admit-churn true || return 1
        local candidate candidate_bytes
        for candidate in "$run/config.toml" "$run/candidate.toml" \
            "$run/gen-a.toml" "$run/gen-b.toml"; do
            candidate_bytes=$(wc -c <"$candidate") || return 1
            if [ -z "$SMOKE" ] && [ "$candidate_bytes" -le $((10 * 1024 * 1024)) ]; then
                echo "cell $cell: $(basename "$candidate") is not above the 10 MiB history bound" >&2
                return 1
            fi
            if [ "$candidate_bytes" -gt "$TXN_MAX_CANDIDATE_BYTES" ]; then
                echo "cell $cell: $(basename "$candidate") is ${candidate_bytes} bytes" >&2
                echo "candidate exceeds the ${TXN_MAX_CANDIDATE_BYTES}-byte streamed request budget" >&2
                return 1
            fi
        done
        seal_scenario "$run" "$cdir" || return 1
        setsid "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        ACTIVE_DAEMON_PID=$daemon_pid
        live="$run/candidate.toml" a="$run/gen-a.toml" b="$run/gen-b.toml"
        pid_arg=$daemon_pid
        if [ -n "$SMOKE" ]; then
            reload_cmd=$(python3 -c 'import shlex,sys; print(shlex.join(sys.argv[1:]))' \
                env TXN_SMOKE=1 "$TXN_APPLY" "$RBGP" "unix://$run/grpc.sock" \
                "$run/candidate.toml" "$run/config.toml" "$run" "$cdir/transactions" \
                "$daemon_pid" "$cdir/daemon.log") || return 1
        else
            mkdir -p "$cdir/transactions" || return 1
            reload_cmd=$(python3 -c 'import shlex,sys; print(shlex.join(sys.argv[1:]))' \
                "$TXN_APPLY" "$RBGP" "unix://$run/grpc.sock" "$run/candidate.toml" \
                "$run/config.toml" "$run" "$cdir/transactions" "$daemon_pid" \
                "$cdir/daemon.log") || return 1
        fi
        ;;
    bird)
        gen_scenario bird "$run" --threads "$BIRD_THREADS" \
            --path-hiding true --admit-churn true || return 1
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
        gen_scenario openbgpd "$run" --path-hiding true --admit-churn true || return 1
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
    daemon_start=$(awk '{print $22}' "/proc/$daemon_pid/stat" 2>/dev/null) || return 1
    case $daemon_start in '' | *[!0-9]*) return 1 ;; esac

    setsid "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!
    ACTIVE_SAMPLER_PID=$sampler_pid
    local hargs=("$N_MEMBERS" "$TOTAL_PREFIXES" "$PORT" "$pid_arg"
        "$live" "$a" "$b" "$RELOADS" "$CONTROL_SECS")
    [ -n "$reload_cmd" ] && hargs+=("$N_MEMBERS" "$reload_cmd")
    # Background so the precommitted RSS abort criterion can kill the cell.
    final_barrier="$run/final-evidence"
    [ ! -e "$final_barrier" ] || return 1
    if [ -n "$topology_mode" ]; then
        barrier="$run/pre-churn-evidence"
        [ ! -e "$barrier" ] || return 1
        setsid env RELOADSTALL_PRE_CHURN_EVIDENCE_DIR="$barrier" \
            RELOADSTALL_EVIDENCE_DIR="$final_barrier" \
            timeout "$CELL_TIMEOUT" stdbuf -oL -eL "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    else
        setsid env RELOADSTALL_EVIDENCE_DIR="$final_barrier" \
            timeout "$CELL_TIMEOUT" stdbuf -oL -eL "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    fi
    local hpid=$!
    ACTIVE_HARNESS_PID=$hpid
    local rc=""
    if [ -n "$topology_mode" ] && ! capture_topology "$topology_mode" "$cdir" "$run" "$hpid" "$barrier"; then
        terminate_process_group "$hpid"
        rc=93
    fi
    while kill -0 "$hpid" 2>/dev/null; do
        if [ "$final_acked" != true ] && [ "$(awk '{print $22}' "/proc/$daemon_pid/stat" 2>/dev/null)" != "$daemon_start" ]; then
            echo "cell $cell: daemon PID/start identity changed" >&2
            terminate_process_group "$hpid"
            rc=94
            break
        fi
        if [ "$final_acked" != true ] && [ -e "$final_barrier/ready" ]; then
            entries=$(find "$final_barrier" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
            if [ "$entries" != ready ] || ! ack_final_evidence \
                "$final_barrier" "$cdir" "$daemon_pid" "$daemon_start"; then
                echo "cell $cell: final evidence identity/boundary validation failed" >&2
                terminate_process_group "$hpid"
                rc=92
                break
            fi
            final_acked=true
        fi
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
    if [ "$final_acked" != true ]; then
        echo "cell $cell: harness exited without a final evidence boundary" >&2
        rc=92
    elif [ -n "$topology_mode" ] && ! bind_first_trigger "$cdir"; then
        echo "cell $cell: first reload trigger was missing or preceded topology proof" >&2
        rc=93
    fi

    if [ "$cell" = rustbgpd-txn ] && [ -z "$SMOKE" ] && [ "$rc" -eq 0 ]; then
        if ! "$TXN_LIFECYCLE" "$RBGP" "unix://$run/grpc.sock" "$run/gen-a.toml" \
            "$run/gen-b.toml" "$run/config.toml" "$run" "$cdir/transactions" \
            "$daemon_pid" "$cdir/daemon.log"; then
            echo "cell $cell: abort/timeout lifecycle proof failed" >&2
            rc=91
        fi
    fi

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
    load_gate "$cell"
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
if [ "$overall" -eq 0 ]; then
    jq -n --arg fingerprint "$CAMPAIGN_FINGERPRINT" --argjson completed_at_epoch_ns "$(date +%s%N)" \
        --arg cells "$(IFS=,; echo "${CELLS[*]}")" \
        '{status:"pass",fingerprint:$fingerprint,completed_at_epoch_ns:$completed_at_epoch_ns,cells:$cells}' \
        >"$ART/COMPLETED" || exit 1
    (cd "$ART" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) \
        >"$ART/SHA256SUMS" || exit 1
    chmod -R a-w "$ART" || exit 1
    echo "sealed read-only artifact root: $ART"
fi
exit "$overall"
