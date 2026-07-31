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
#        (default: rustbgpd-sighup rustbgpd-txn bird openbgpd)
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
# Daemon-start readiness ceiling (seconds). Parsing a multi-MB IRR
# policy takes far longer than a small-config boot, so readiness is
# polled (1 s cadence, until the BGP listener is up) instead of a
# fixed sleep; this is only the hard ceiling. A harness parameter, not
# a measurement — see README "Startup and readiness windows".
START_TIMEOUT="${START_TIMEOUT:-600}"
BIRD_THREADS="${BIRD_THREADS:-8}"
ART="${ARTIFACTS_DIR:-/tmp/irrreload-artifacts}"
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB (precommitted)

CELLS=("$@")
[ ${#CELLS[@]} -eq 0 ] && CELLS=(rustbgpd-sighup rustbgpd-txn bird openbgpd)

for tool in docker jq python3 cargo ss sha256sum git awk timeout find sort; do
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
PRIOR_FINGERPRINT=$(jq -r '.fingerprint // empty' "$ART/provenance.json" 2>/dev/null)
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
    --arg cell_timeout "$CELL_TIMEOUT" --arg start_timeout "$START_TIMEOUT" \
    --arg bird_threads "$BIRD_THREADS" --arg skip_preflight "${SKIP_PREFLIGHT:-}" \
    --arg rustc "$(rustc -Vv)" --arg cargo "$(cargo -V)" \
    --arg python "$(python3 --version 2>&1)" --arg jq "$(jq --version)" \
    --arg docker "$DOCKER_VERSION" \
    --arg kernel "$(uname -srm)" \
    --arg cpu_model "$(awk -F: '/^model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)" \
    --arg bird_image "$BIRD_IMAGE" --arg bird_image_id "$BIRD_IMAGE_ID" \
    --arg openbgpd_image "$OPENBGPD_IMAGE" --arg openbgpd_image_id "$OPENBGPD_IMAGE_ID" \
    '{schema:1,git:{commit:$commit,dirty:$dirty,dirty_state_sha256:$dirty_state_sha256},scripts:{runner:$run_script_sha256,generator:$generator_sha256,rss_sampler:$sampler_sha256,txn_apply:$txn_apply_sha256},binaries:{reloadstall:$harness_sha256,rustbgpd:$daemon_sha256,rbgp:$cli_sha256,rs_config_render:$renderer_sha256},environment:{rustc:$rustc,cargo:$cargo,python:$python,jq:$jq,docker:$docker,kernel:$kernel,cpu_model:$cpu_model},inputs:{cells:$cells,smoke:$smoke,n_members:$n_members,total_prefixes:$total_prefixes,min_list:$min_list,max_list:$max_list,seed:$seed,changed_fraction:$changed_fraction,port:$port,reloads:$reloads,control_secs:$control_secs,cell_timeout:$cell_timeout,start_timeout:$start_timeout,bird_threads:$bird_threads,skip_preflight:$skip_preflight,bird_image:$bird_image,bird_image_id:$bird_image_id,openbgpd_image:$openbgpd_image,openbgpd_image_id:$openbgpd_image_id}}') || exit 1
CAMPAIGN_FINGERPRINT=$(printf '%s' "$CAMPAIGN_PROVENANCE" | sha256sum | cut -d' ' -f1) || exit 1
printf '%s\n' "$CAMPAIGN_PROVENANCE" | jq --arg fingerprint "$CAMPAIGN_FINGERPRINT" \
    '. + {fingerprint:$fingerprint}' >"$ART/provenance.json" || exit 1
ROWS_HEADER="cell,reload,peers_total,peers_changed,peers_stable,prefixes,completion_p50_s,completion_p95_s,completion_max_s,changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
if [ "$PRIOR_FINGERPRINT" != "$CAMPAIGN_FINGERPRINT" ] ||
    [ "$(head -n1 "$ART/rows.csv" 2>/dev/null)" != "$ROWS_HEADER" ]; then
    printf '%s\n' "$ROWS_HEADER" >"$ART/rows.csv"
fi

cell_receipt_matches() {
    local cdir=$1 scenario_sha actual_sha
    scenario_sha=$(jq -er --arg fingerprint "$CAMPAIGN_FINGERPRINT" \
        'select(.fingerprint == $fingerprint) | .scenario.manifest_sha256' \
        "$cdir/provenance.json" 2>/dev/null) || return 1
    [ -n "$scenario_sha" ] || return 1
    actual_sha=$(hash_file "$cdir/scenario.sha256" 2>/dev/null) || return 1
    [ "$actual_sha" = "$scenario_sha" ] || return 1
    grep -qx "pass $CAMPAIGN_FINGERPRINT $scenario_sha" "$cdir/status" 2>/dev/null
}

seal_scenario() {
    local run=$1 cdir=$2
    (
        cd "$run" || exit 1
        find . -type f -print0 | sort -z |
            while IFS= read -r -d '' path; do
                digest=$(hash_file "$path") || exit 1
                printf '%s  %s\n' "$digest" "$path"
            done
    ) >"$cdir/scenario.sha256" || return 1
    CELL_SCENARIO_SHA256=$(hash_file "$cdir/scenario.sha256") || return 1
    jq --arg scenario_sha "$CELL_SCENARIO_SHA256" \
        '. + {scenario:{manifest_sha256:$scenario_sha}}' \
        "$ART/provenance.json" >"$cdir/provenance.json"
}

cleanup() {
    # shellcheck disable=SC2317  # invoked via trap
    docker rm -f irr-bird irr-obgpd >/dev/null 2>&1
}
trap cleanup EXIT

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
    case $cell in
    rustbgpd-sighup)
        gen_scenario rustbgpd "$run" --render-bin "$RENDER" || return 1
        seal_scenario "$run" "$cdir" || return 1
        "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid # SIGHUP path: harness signals + samples this PID
        ;;
    rustbgpd-txn)
        gen_scenario rustbgpd-txn "$run" || return 1
        seal_scenario "$run" "$cdir" || return 1
        "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
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

    "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!

    local hargs=("$N_MEMBERS" "$TOTAL_PREFIXES" "$PORT" "$pid_arg"
        "$live" "$a" "$b" "$RELOADS" "$CONTROL_SECS")
    # reload_cmd is positional arg 11, so cells using it pass an explicit
    # all-changed cohort (same completion semantics as the 9-arg form).
    [ -n "$reload_cmd" ] && hargs+=("$N_MEMBERS" "$reload_cmd")

    # Background so the precommitted RSS abort criterion can kill the cell.
    timeout "$CELL_TIMEOUT" "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    local hpid=$!
    local rc=""
    while kill -0 "$hpid" 2>/dev/null; do
        if ! kill -0 "$sampler_pid" 2>/dev/null; then
            echo "cell $cell: RSS sampler exited before harness completion" >&2
            kill "$hpid" 2>/dev/null
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

    if [ -n "$container" ]; then
        docker logs "$container" >"$cdir/daemon.log" 2>&1
        docker rm -f "$container" >/dev/null 2>&1
    else
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
    fi
    local sampler_rc=0
    wait "$sampler_pid" || sampler_rc=$?
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
        if ! awk -F, -v cell="$cell" -v expected="$RELOADS" \
            'NF != 23 || $1 != cell || $2 != sprintf("%d", NR) { bad=1 } END { exit (bad || NR != expected) }' \
            "$rows_tmp"; then
            echo "cell $cell: invalid, missing, or duplicate measurement rows" >&2
            rm -f "$rows_tmp"
            rc=96
        else
            if ! sed -n '1,$p' "$rows_tmp" >>"$ART/rows.csv"; then
                echo "cell $cell: failed to retain measurement rows" >&2
                rc=96
            else
                rm -f "$rows_tmp"
                rm -rf "$run" # reproduces from the generator + manifest
            fi
        fi
    fi
    echo "cell $cell: harness rc=$rc (artifacts: $cdir)"
    return "$rc"
}

overall=0
for cell in "${CELLS[@]}"; do
    status_file="$ART/$cell/status"
    existing_rows=$(grep -c "^$cell," "$ART/rows.csv" 2>/dev/null)
    if cell_receipt_matches "$ART/$cell" &&
        [ "${existing_rows:-0}" -eq "$RELOADS" ]; then
        echo "cell $cell: matching fingerprint already passed, skipping"
        continue
    fi
    # Rows from another fingerprint can never satisfy this campaign.
    awk -F, -v cell="$cell" 'NR == 1 || $1 != cell' "$ART/rows.csv" >"$ART/rows.csv.tmp" &&
        mv "$ART/rows.csv.tmp" "$ART/rows.csv"
    load_gate
    echo "=== cell $cell start $(date -Is) ==="
    if run_cell "$cell"; then
        echo "pass $CAMPAIGN_FINGERPRINT $CELL_SCENARIO_SHA256" >"$status_file"
        echo "=== cell $cell PASS $(date -Is) ==="
    else
        echo "fail $CAMPAIGN_FINGERPRINT ${CELL_SCENARIO_SHA256:-unavailable} rc=$?" >"$status_file"
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
