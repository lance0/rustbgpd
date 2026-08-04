#!/usr/bin/env bash
# One measured streamed config transaction. The reloadstall harness has already
# copied the next generation over CANDIDATE before invoking this command.
#
# Usage: txn-apply.sh RBGP ADDR CANDIDATE CONFIG RUNTIME_DIR EVIDENCE_DIR PID DAEMON_LOG
set -u
set -o pipefail

if [ $# -ne 8 ]; then
    echo "usage: txn-apply.sh RBGP ADDR CANDIDATE CONFIG RUNTIME_DIR EVIDENCE_DIR PID DAEMON_LOG" >&2
    exit 2
fi
rbgp=$1
addr=$2
candidate=$3
config=$4
runtime_dir=$5
evidence=$6
daemon_pid=$7
daemon_log=$8
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
verify="$script_dir/verify-receipt.py"
locator="$config.commit-confirm-locator.json"
raw="$runtime_dir/commit-confirm-v3-prior.toml"
metadata="$runtime_dir/commit-confirm-v3-metadata.json"
legacy="$runtime_dir/commit-confirm-journal.json"
min_raw=$((10 * 1024 * 1024))
max_raw=$((384 * 1024 * 1024))
mkdir -p "$evidence"

die() { echo "txn-apply: $*" >&2; exit 1; }
sha() { sha256sum -- "$1" | cut -d' ' -f1; }
runtime_token_valid() { [[ $1 =~ ^kv2:[0-9a-f]{16}:8$ ]]; }
active_confirm_id=
cleanup_pending() { [ -z "$active_confirm_id" ] || "$rbgp" --addr "$addr" --json config abort "$active_confirm_id" >/dev/null 2>&1 || true; }
trap cleanup_pending EXIT
history_count() {
    "$rbgp" --addr "$addr" --json config history |
        jq -er '.entries | select(type == "array") | length'
}
history_json() {
    local entries files history_dir="$runtime_dir/config-history"
    entries=$("$rbgp" --addr "$addr" --json config history | jq -ecS '.entries') || return 1
    files=$(
        if [ -d "$history_dir" ]; then
            find "$history_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort |
                while IFS= read -r name; do
                    jq -cn --arg name "$name" --arg sha256 "$(sha "$history_dir/$name")" \
                        --argjson bytes "$(wc -c <"$history_dir/$name")" \
                        '{name:$name,bytes:$bytes,sha256:$sha256}'
                done
        fi | jq -scS '.'
    ) || return 1
    jq -cn --argjson entries "$entries" --argjson files "$files" '{entries:$entries,files:$files}'
}
warning_count() { grep -Fc 'applied config exceeds the bounded history entry size; history was left unchanged' "$daemon_log" 2>/dev/null || true; }
warning_json() {
    local before=$1 count line bytes deadline=$((SECONDS + 10))
    while :; do
        count=$(warning_count)
        [ "$count" -gt "$before" ] && break
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.1
    done
    [ "$count" -eq $((before + 1)) ] || return 1
    line=$(grep -F 'applied config exceeds the bounded history entry size; history was left unchanged' "$daemon_log" | tail -n1) || return 1
    bytes=$(printf '%s\n' "$line" | jq -er '.fields.bytes | select(type == "number")') || return 1
    [ "$bytes" -gt "$min_raw" ] || return 1
    jq -cn --argjson count_before "$before" --argjson count_after "$count" \
        --argjson bytes "$bytes" '{count_before:$count_before,count_after:$count_after,bytes:$bytes}'
}
process_json() {
    local start vmrss vmhwm
    start=$(awk '{print $22}' "/proc/$daemon_pid/stat" 2>/dev/null) || return 1
    vmrss=$(awk '$1 == "VmRSS:" {print $2}' "/proc/$daemon_pid/status") || return 1
    vmhwm=$(awk '$1 == "VmHWM:" {print $2}' "/proc/$daemon_pid/status") || return 1
    jq -cn --argjson pid "$daemon_pid" --argjson starttime "$start" \
        --argjson vmrss_kib "$vmrss" --argjson vmhwm_kib "$vmhwm" \
        '{pid:$pid,starttime:$starttime,vmrss_kib:$vmrss_kib,vmhwm_kib:$vmhwm_kib}'
}
effective_json() {
    local tmp digest bytes marker
    tmp=$(mktemp "$runtime_dir/.irr-effective.XXXXXX") || return 1
    "$rbgp" --addr "$addr" config effective >"$tmp" || { rm -f "$tmp"; return 1; }
    digest=$(sha "$tmp") || { rm -f "$tmp"; return 1; }
    bytes=$(wc -c <"$tmp") || { rm -f "$tmp"; return 1; }
    marker=$("$verify" inspect-generation "$tmp") || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    jq -cn --arg sha256 "$digest" --argjson bytes "$bytes" --arg marker "$marker" \
        '{sha256:$sha256,bytes:$bytes,marker:$marker}'
}
config_json() {
    local digest bytes marker
    digest=$(sha "$config") || return 1
    bytes=$(wc -c <"$config") || return 1
    marker=$("$verify" inspect-generation "$config") || return 1
    jq -cn --arg sha256 "$digest" --argjson bytes "$bytes" --arg marker "$marker" \
        '{sha256:$sha256,bytes:$bytes,marker:$marker}'
}
pending_json() {
    local confirm_id=$1 authority history process runtime config_state raw_bytes
    authority=$("$verify" inspect-v3 --locator "$locator" --metadata "$metadata" \
        --raw "$raw" --config "$config" --confirm-id "$confirm_id") || return 1
    raw_bytes=$(printf '%s' "$authority" | jq -er '.raw.bytes') || return 1
    [ "$raw_bytes" -gt "$min_raw" ] && [ "$raw_bytes" -le "$max_raw" ] || return 1
    [ ! -e "$legacy" ] || return 1
    history=$(history_count) || return 1
    [ "$history" -eq 0 ] || return 1
    process=$(process_json) || return 1
    runtime=$(effective_json) || return 1
    config_state=$(config_json) || return 1
    jq -cn --argjson authority "$authority" --argjson history_entries "$history" \
        --argjson process "$process" --argjson runtime "$runtime" \
        --argjson config "$config_state" \
        '{authority:$authority,legacy_absent:true,
          history_entries:$history_entries,history_outcome:"skipped_oversize",
          process:$process,config:$config,runtime:$runtime}'
}
terminal_json() {
    local history process runtime config_state
    [ ! -e "$locator" ] && [ ! -e "$locator.tmp" ] &&
        [ ! -e "$raw" ] && [ ! -e "$raw.tmp" ] &&
        [ ! -e "$metadata" ] && [ ! -e "$metadata.tmp" ] && [ ! -e "$legacy" ] || return 1
    history=$(history_count) || return 1
    [ "$history" -eq 0 ] || return 1
    process=$(process_json) || return 1
    runtime=$(effective_json) || return 1
    config_state=$(config_json) || return 1
    jq -cn --argjson history_entries "$history" --argjson process "$process" \
        --argjson runtime "$runtime" --argjson config "$config_state" \
        '{v3_absent:true,legacy_absent:true,history_entries:$history_entries,
          history_outcome:"skipped_oversize",process:$process,config:$config,runtime:$runtime}'
}

cycles="$evidence/cycles.jsonl"
candidate_bytes=$(wc -c <"$candidate") || die "cannot size candidate"
[ "$candidate_bytes" -le "$max_raw" ] || die "candidate exceeds 384 MiB"
if [ -z "${TXN_SMOKE:-}" ]; then
    [ "$candidate_bytes" -gt "$min_raw" ] || die "measured candidate is not above 10 MiB"
    cycle=$(( $(wc -l <"$cycles" 2>/dev/null || printf 0) + 1 ))
    if [ "$cycle" -lt 1 ] || [ "$cycle" -gt 4 ]; then
        die "unexpected measured cycle $cycle"
    fi
fi
candidate_sha=$(sha "$candidate") || die "cannot hash candidate"
candidate_marker=
if [ -z "${TXN_SMOKE:-}" ]; then
    candidate_marker=$("$verify" inspect-generation "$candidate") || die "cannot inspect candidate generation"
fi

plan_json=$("$rbgp" --addr "$addr" --json config plan "$candidate")
plan_rc=$?
[ "$plan_rc" -eq 2 ] || die "streamed plan exit $plan_rc, expected committable exit 2"
[ "$(printf '%s' "$plan_json" | jq -er '.status')" = committable ] || die "plan not committable"
runtime_token=$(printf '%s' "$plan_json" | jq -er '.runtime_snapshot_token | select(type == "string" and length > 0)') ||
    die "plan returned no runtime snapshot token"
runtime_token_valid "$runtime_token" || die "plan runtime snapshot token was not canonical kv2"
plan_token=$(printf '%s' "$plan_json" | jq -er '.plan_token | select(type == "string" and length > 0)') ||
    die "streamed plan returned no plan token"
[[ $plan_token =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
    die "streamed plan token was not UUID-v4"
if [ -n "${TXN_SMOKE:-}" ]; then
    apply_json=$("$rbgp" --addr "$addr" --json config apply "$candidate" \
        --expected-runtime-snapshot-token "$runtime_token" --plan-token "$plan_token") ||
        die "smoke streamed apply failed"
    [ "$(printf '%s' "$apply_json" | jq -er '.status')" = committable ] || die "smoke apply not committable"
    [ "$(printf '%s' "$apply_json" | jq -r '.confirmation')" = null ] || die "smoke apply unexpectedly confirmed"
    exit 0
fi
history_before=$(history_json) || die "cannot capture history before apply"
[ "$(printf '%s' "$history_before" | jq -er '.entries | length')" -eq 0 ] || die "history was not empty before apply"
warning_before=$(warning_count)
confirm_id="irrreload-measured-$cycle"
active_confirm_id=$confirm_id
apply_json=$("$rbgp" --addr "$addr" --json config apply "$candidate" \
    --expected-runtime-snapshot-token "$runtime_token" --plan-token "$plan_token" \
    --confirm-id "$confirm_id" --confirm-timeout 600) || die "streamed apply failed"
[ "$(printf '%s' "$apply_json" | jq -er '.status')" = committable ] || die "apply not committable"
apply_runtime=$(printf '%s' "$apply_json" | jq -er '.runtime_snapshot_token | select(type == "string")') || die "apply runtime token missing"
runtime_token_valid "$apply_runtime" || die "apply runtime snapshot token was not canonical kv2"
apply_deadline=$(printf '%s' "$apply_json" | jq -er --arg id "$confirm_id" --arg runtime "$apply_runtime" \
    '.confirmation | select(.status == "pending" and .confirm_id == $id and .timeout_seconds == 600 and
      .deadline_unix_seconds > 0 and .runtime_snapshot_token == $runtime) | .deadline_unix_seconds') ||
    die "apply confirmation metadata was incoherent"
now=$(date +%s)
if [ "$apply_deadline" -le "$now" ] || [ "$apply_deadline" -gt $((now + 605)) ]; then
    die "apply deadline was outside the requested window"
fi
status_json=$("$rbgp" --addr "$addr" --json config status) || die "pending status failed"
printf '%s' "$status_json" | jq -e --arg id "$confirm_id" --arg runtime "$apply_runtime" \
    --argjson deadline "$apply_deadline" \
    '.confirmation | select(.status == "pending" and .confirm_id == $id and .timeout_seconds == 600 and
      .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "pending status view was incoherent"
pending=$(pending_json "$confirm_id") || die "pending v3/history/process evidence failed"
authority_deadline=$(printf '%s' "$pending" | jq -er '.authority.deadline_unix_seconds') || die "v3 authority deadline missing"
[ "$authority_deadline" -lt "$apply_deadline" ] || die "v3 authority deadline did not predate the live deadline"
warning=$(warning_json "$warning_before") || die "missing oversize-history warning"

confirm_json=$("$rbgp" --addr "$addr" --json config confirm "$confirm_id") || die "confirm failed"
printf '%s' "$confirm_json" | jq -e --arg id "$confirm_id" --arg runtime "$apply_runtime" \
    --argjson deadline "$apply_deadline" \
    '.confirmation | select(.status == "confirmed" and .confirm_id == $id and .timeout_seconds == 600 and
      .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "confirm response was incoherent"
confirmed_status=$("$rbgp" --addr "$addr" --json config status) || die "confirmed status failed"
printf '%s' "$confirmed_status" | jq -e --arg id "$confirm_id" --arg runtime "$apply_runtime" \
    --argjson deadline "$apply_deadline" \
    '.confirmation | select(.status == "confirmed" and .confirm_id == $id and .timeout_seconds == 600 and
      .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "confirmed status view was incoherent"
active_confirm_id=
terminal=$(terminal_json) || die "confirmed cleanup/history/process evidence failed"
history_after=$(history_json) || die "cannot capture history after confirm"
[ "$(printf '%s' "$history_before" | jq -cS .)" = "$(printf '%s' "$history_after" | jq -cS .)" ] ||
    die "bounded history changed across oversize transaction"
[ "$(printf '%s' "$pending" | jq -r '.process.pid,.process.starttime')" = \
  "$(printf '%s' "$terminal" | jq -r '.process.pid,.process.starttime')" ] || die "daemon identity changed"

row=$(jq -cn --argjson cycle "$cycle" --arg candidate_sha256 "$candidate_sha" \
    --argjson candidate_bytes "$candidate_bytes" --arg candidate_marker "$candidate_marker" --arg confirm_id "$confirm_id" \
    --argjson apply_deadline "$apply_deadline" \
    --argjson pending "$pending" --argjson terminal "$terminal" \
    --argjson history_before "$history_before" --argjson history_after "$history_after" \
    --argjson warning "$warning" \
    '{schema:2,cycle:$cycle,candidate:{sha256:$candidate_sha256,bytes:$candidate_bytes,marker:$candidate_marker},
      plan:{transport:"streamed",status:"committable",plan_token_present:true,
            runtime_snapshot_token_present:true},
      apply:{transport:"streamed",explicit_plan_token:true,status:"committable",
             confirmation_status:"pending",confirm_id:$confirm_id,timeout_seconds:600,
             deadline_unix_seconds:$apply_deadline,
             runtime_token_coherent:true},
      history:{before:$history_before,after:$history_after,outcome:"skipped_oversize",warning:$warning},
      pending:$pending,confirmed:({status:"confirmed",status_view_verified:true} + $terminal)}') || die "cannot encode evidence"
printf '%s\n' "$row" >>"$cycles" || die "cannot retain cycle evidence"
