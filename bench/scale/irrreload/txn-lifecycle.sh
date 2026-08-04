#!/usr/bin/env bash
# After the wire harness seals and exits, exercise abort and timeout auto-revert
# against the same still-running rustbgpd process.
#
# Usage: txn-lifecycle.sh RBGP ADDR CURRENT OPPOSITE CONFIG RUNTIME_DIR EVIDENCE_DIR PID DAEMON_LOG
set -u
set -o pipefail
if [ $# -ne 9 ]; then
    echo "usage: txn-lifecycle.sh RBGP ADDR CURRENT OPPOSITE CONFIG RUNTIME_DIR EVIDENCE_DIR PID DAEMON_LOG" >&2
    exit 2
fi
rbgp=$1; addr=$2; current=$3; opposite=$4; config=$5; runtime_dir=$6; evidence=$7; daemon_pid=$8; daemon_log=$9
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
verify="$script_dir/verify-receipt.py"
locator="$config.commit-confirm-locator.json"
raw="$runtime_dir/commit-confirm-v3-prior.toml"; metadata="$runtime_dir/commit-confirm-v3-metadata.json"
legacy="$runtime_dir/commit-confirm-journal.json"; min_raw=$((10 * 1024 * 1024)); max_raw=$((384 * 1024 * 1024)); output="$evidence/lifecycle.json"; mkdir -p "$evidence"
die() { echo "txn-lifecycle: $*" >&2; exit 1; }
sha() { sha256sum -- "$1" | cut -d' ' -f1; }
runtime_token_valid() { [[ $1 =~ ^kv2:[0-9a-f]{16}:8$ ]]; }
active_confirm_id=; cleanup_pending() {
    if [ -n "$active_confirm_id" ]; then
        "$rbgp" --addr "$addr" --json config abort "$active_confirm_id" >/dev/null 2>&1 || true
    fi
}
trap cleanup_pending EXIT
history_count() { "$rbgp" --addr "$addr" --json config history | jq -er '.entries | select(type == "array") | length'; }
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
        count=$(warning_count); [ "$count" -gt "$before" ] && break
        [ "$SECONDS" -lt "$deadline" ] || return 1; sleep 0.1
    done
    [ "$count" -eq $((before + 1)) ] || return 1
    line=$(grep -F 'applied config exceeds the bounded history entry size; history was left unchanged' "$daemon_log" | tail -n1) || return 1
    bytes=$(printf '%s\n' "$line" | jq -er '.fields.bytes | select(type == "number")') || return 1
    [ "$bytes" -gt "$min_raw" ] || return 1
    jq -cn --argjson count_before "$before" --argjson count_after "$count" --argjson bytes "$bytes" \
        '{count_before:$count_before,count_after:$count_after,bytes:$bytes}'
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
content_json() {
    local path=$1 digest bytes marker
    digest=$(sha "$path") || return 1; bytes=$(wc -c <"$path") || return 1
    marker=$("$verify" inspect-generation "$path") || return 1
    jq -cn --arg sha256 "$digest" --argjson bytes "$bytes" --arg marker "$marker" \
        '{sha256:$sha256,bytes:$bytes,marker:$marker}'
}
effective_json() {
    local tmp result
    tmp=$(mktemp "$runtime_dir/.irr-effective.XXXXXX") || return 1
    "$rbgp" --addr "$addr" config effective >"$tmp" || { rm -f "$tmp"; return 1; }
    result=$(content_json "$tmp") || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"; printf '%s\n' "$result"
}
state_json() {
    local history process runtime disk
    history=$(history_count) || return 1; [ "$history" -eq 0 ] || return 1
    process=$(process_json) || return 1; runtime=$(effective_json) || return 1
    disk=$(content_json "$config") || return 1
    jq -cn --argjson history_entries "$history" --argjson process "$process" \
        --argjson runtime "$runtime" --argjson disk "$disk" \
        '{history_entries:$history_entries,history_outcome:"skipped_oversize",
          process:$process,config:$disk,runtime:$runtime}'
}
pending_json() {
    local confirm_id=$1 authority history process runtime disk raw_bytes
    authority=$("$verify" inspect-v3 --locator "$locator" --metadata "$metadata" \
        --raw "$raw" --config "$config" --confirm-id "$confirm_id") || return 1
    raw_bytes=$(printf '%s' "$authority" | jq -er '.raw.bytes') || return 1
    [ "$raw_bytes" -gt "$min_raw" ] && [ "$raw_bytes" -le "$max_raw" ] || return 1
    [ ! -e "$legacy" ] || return 1
    history=$(history_count) || return 1; [ "$history" -eq 0 ] || return 1
    process=$(process_json) || return 1; runtime=$(effective_json) || return 1
    disk=$(content_json "$config") || return 1
    jq -cn --argjson authority "$authority" --argjson history_entries "$history" \
        --argjson process "$process" --argjson runtime "$runtime" --argjson disk "$disk" \
        '{authority:$authority,legacy_absent:true,
          history_entries:$history_entries,history_outcome:"skipped_oversize",
          process:$process,config:$disk,runtime:$runtime}'
}
terminal_json() {
    local state
    [ ! -e "$locator" ] && [ ! -e "$locator.tmp" ] &&
        [ ! -e "$raw" ] && [ ! -e "$raw.tmp" ] &&
        [ ! -e "$metadata" ] && [ ! -e "$metadata.tmp" ] && [ ! -e "$legacy" ] || return 1
    state=$(state_json) || return 1
    jq -cn --argjson state "$state" '{v3_absent:true,legacy_absent:true} + $state'
}
apply_pending() {
    local id=$1 timeout=$2 plan_json plan_rc runtime_token plan_token apply_json apply_runtime status_json pending history_before warning_before warning now authority_deadline
    history_before=$(history_json) || return 1
    [ "$(printf '%s' "$history_before" | jq -er '.entries | length')" -eq 0 ] || return 1
    warning_before=$(warning_count)
    plan_json=$("$rbgp" --addr "$addr" --json config plan "$opposite"); plan_rc=$?
    [ "$plan_rc" -eq 2 ] || return 1
    [ "$(printf '%s' "$plan_json" | jq -er '.status')" = committable ] || return 1
    runtime_token=$(printf '%s' "$plan_json" | jq -er '.runtime_snapshot_token | select(length > 0)') || return 1
    runtime_token_valid "$runtime_token" || return 1
    plan_token=$(printf '%s' "$plan_json" | jq -er '.plan_token | select(length > 0)') || return 1
    [[ $plan_token =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
    active_confirm_id=$id
    apply_json=$("$rbgp" --addr "$addr" --json config apply "$opposite" \
        --expected-runtime-snapshot-token "$runtime_token" --plan-token "$plan_token" \
        --confirm-id "$id" --confirm-timeout "$timeout") || return 1
    [ "$(printf '%s' "$apply_json" | jq -er '.status')" = committable ] || return 1
    apply_runtime=$(printf '%s' "$apply_json" | jq -er '.runtime_snapshot_token | select(type == "string")') || return 1
    runtime_token_valid "$apply_runtime" || return 1
    pending_deadline=$(printf '%s' "$apply_json" | jq -er --arg id "$id" --arg runtime "$apply_runtime" \
        --argjson timeout "$timeout" \
        '.confirmation | select(.status == "pending" and .confirm_id == $id and .timeout_seconds == $timeout and
          .deadline_unix_seconds > 0 and .runtime_snapshot_token == $runtime) | .deadline_unix_seconds') || return 1
    now=$(date +%s)
    if [ "$pending_deadline" -le "$now" ] || [ "$pending_deadline" -gt $((now + timeout + 5)) ]; then
        return 1
    fi
    status_json=$("$rbgp" --addr "$addr" --json config status) || return 1
    printf '%s' "$status_json" | jq -e --arg id "$id" --arg runtime "$apply_runtime" \
        --argjson timeout "$timeout" --argjson deadline "$pending_deadline" \
        '.confirmation | select(.status == "pending" and .confirm_id == $id and .timeout_seconds == $timeout and
          .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null || return 1
    pending=$(pending_json "$id") || return 1
    authority_deadline=$(printf '%s' "$pending" | jq -er '.authority.deadline_unix_seconds') || return 1
    [ "$authority_deadline" -lt "$pending_deadline" ] || return 1
    warning=$(warning_json "$warning_before") || return 1
    pending_runtime=$apply_runtime
    pending_prefix=$(jq -cn --arg id "$id" --argjson timeout_seconds "$timeout" \
        --argjson deadline_unix_seconds "$pending_deadline" --argjson pending "$pending" \
        --argjson history_before "$history_before" --argjson warning "$warning" \
        '{candidate_role:"opposite",plan:{transport:"streamed",status:"committable",
          plan_token_present:true,runtime_snapshot_token_present:true},
          apply:{transport:"streamed",explicit_plan_token:true,status:"committable",
          confirmation_status:"pending",confirm_id:$id,timeout_seconds:$timeout_seconds,
          deadline_unix_seconds:$deadline_unix_seconds,runtime_token_coherent:true},
          history_before:$history_before,apply_history_warning:$warning,pending:$pending}'
    ) || return 1
}
[ ! -e "$output" ] || die "lifecycle evidence already exists"
[ "$(wc -l <"$evidence/cycles.jsonl" 2>/dev/null)" -eq 4 ] || die "four measured cycles are required"
current_state=$(state_json) || die "cannot capture restored-current baseline"
current_input=$(content_json "$current") || die "cannot capture current candidate"
opposite_input=$(content_json "$opposite") || die "cannot capture opposite candidate"
[ "$(printf '%s' "$current_input" | jq -r .sha256)" != "$(printf '%s' "$opposite_input" | jq -r .sha256)" ] ||
    die "current and opposite generations are identical"
apply_pending irrreload-abort 600 || die "abort pending transaction failed"
abort_prefix=$pending_prefix; abort_runtime=$pending_runtime; abort_deadline=$pending_deadline
abort_warning_before=$(warning_count)
abort_json=$("$rbgp" --addr "$addr" --json config abort irrreload-abort) || die "abort RPC failed"
abort_rollback_runtime=$(printf '%s' "$abort_json" | jq -er '.confirmation.runtime_snapshot_token | select(type == "string")') || die "abort runtime token missing"
runtime_token_valid "$abort_rollback_runtime" || die "abort runtime token was not canonical kv2"
[ "$abort_rollback_runtime" != "$abort_runtime" ] || die "abort did not rotate the runtime token"
printf '%s' "$abort_json" | jq -e --arg runtime "$abort_rollback_runtime" --argjson deadline "$abort_deadline" \
    'select(.runtime_snapshot_token == $runtime) | .confirmation |
      select(.status == "aborted" and .confirm_id == "irrreload-abort" and
      .timeout_seconds == 600 and .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "abort response was incoherent"
abort_status=$("$rbgp" --addr "$addr" --json config status) || die "abort terminal status failed"
printf '%s' "$abort_status" | jq -e --arg runtime "$abort_rollback_runtime" --argjson deadline "$abort_deadline" \
    '.confirmation | select(.status == "aborted" and .confirm_id == "irrreload-abort" and
      .timeout_seconds == 600 and .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "abort terminal status view was incoherent"
active_confirm_id=
abort_terminal=$(terminal_json) || die "abort cleanup evidence failed"
abort_warning=$(warning_json "$abort_warning_before") || die "missing abort restore history warning"
abort_history_after=$(history_json) || die "cannot capture history after abort"
[ "$(printf '%s' "$abort_prefix" | jq -cS '.history_before')" = "$(printf '%s' "$abort_history_after" | jq -cS .)" ] ||
    die "bounded history changed across abort"
[ "$(printf '%s' "$abort_terminal" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" = \
  "$(printf '%s' "$current_state" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" ] ||
    die "abort did not exactly restore disk/runtime/process identity"
abort=$(jq -cn --argjson prefix "$abort_prefix" --argjson terminal "$abort_terminal" \
    --argjson warning "$abort_warning" --argjson history_after "$abort_history_after" \
    '$prefix + {terminal:({status:"aborted",status_view_verified:true,restored_exactly:true,history_warning:$warning,
      history_after:$history_after} + $terminal)}') || die "abort receipt failed"
apply_pending irrreload-timeout 10 || die "timeout pending transaction failed"
timeout_prefix=$pending_prefix; timeout_runtime=$pending_runtime; timeout_deadline=$pending_deadline
timeout_warning_before=$(warning_count)
deadline=$((SECONDS + 60))
while :; do
    status_json=$("$rbgp" --addr "$addr" --json config status) || die "timeout status failed"
    outcome=$(printf '%s' "$status_json" | jq -er '.confirmation.status') || die "timeout status malformed"
    [ "$outcome" = pending ] || break
    [ "$SECONDS" -lt "$deadline" ] || die "timeout did not auto-revert within 60 seconds"
    sleep 0.2
done
[ "$outcome" = auto_reverted ] || die "unexpected timeout outcome $outcome"
timeout_rollback_runtime=$(printf '%s' "$status_json" | jq -er '.confirmation.runtime_snapshot_token | select(type == "string")') || die "timeout runtime token missing"
runtime_token_valid "$timeout_rollback_runtime" || die "timeout runtime token was not canonical kv2"
[ "$timeout_rollback_runtime" != "$timeout_runtime" ] || die "timeout did not rotate the runtime token"
printf '%s' "$status_json" | jq -e --arg runtime "$timeout_rollback_runtime" --argjson deadline "$timeout_deadline" \
    '.confirmation | select(.status == "auto_reverted" and .confirm_id == "irrreload-timeout" and
      .timeout_seconds == 10 and .deadline_unix_seconds == $deadline and .runtime_snapshot_token == $runtime)' >/dev/null ||
    die "timeout terminal status view was incoherent"
active_confirm_id=
timeout_terminal=$(terminal_json) || die "timeout cleanup evidence failed"
timeout_warning=$(warning_json "$timeout_warning_before") || die "missing timeout restore history warning"
timeout_history_after=$(history_json) || die "cannot capture history after timeout"
[ "$(printf '%s' "$timeout_prefix" | jq -cS '.history_before')" = "$(printf '%s' "$timeout_history_after" | jq -cS .)" ] ||
    die "bounded history changed across timeout"
[ "$(printf '%s' "$timeout_terminal" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" = \
  "$(printf '%s' "$current_state" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" ] ||
    die "timeout did not exactly restore disk/runtime/process identity"
timeout=$(jq -cn --argjson prefix "$timeout_prefix" --argjson terminal "$timeout_terminal" \
    --argjson warning "$timeout_warning" --argjson history_after "$timeout_history_after" \
    '$prefix + {terminal:({status:"auto_reverted",status_view_verified:true,restored_exactly:true,history_warning:$warning,
      history_after:$history_after} + $terminal)}') || die "timeout receipt failed"
noop_json=$("$rbgp" --addr "$addr" --json config plan "$current"); noop_rc=$?
[ "$noop_rc" -eq 0 ] || die "restored-current plan exit $noop_rc, expected NOOP exit 0"
[ "$(printf '%s' "$noop_json" | jq -er '.status')" = noop ] || die "restored-current plan not NOOP"
[ "$(printf '%s' "$noop_json" | jq -r '.plan_token')" = null ] || die "NOOP unexpectedly returned a plan token"
final_state=$(state_json) || die "cannot capture final restored state"
[ "$(printf '%s' "$final_state" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" = \
  "$(printf '%s' "$current_state" | jq -cS '.config,.runtime,.process.pid,.process.starttime')" ] ||
    die "final state differs from restored-current baseline"
tmp="$output.tmp"
jq -n --argjson baseline "$current_state" --argjson current "$current_input" \
    --argjson opposite "$opposite_input" --argjson abort "$abort" --argjson timeout "$timeout" \
    --argjson final_state "$final_state" \
    '{schema:2,generations:{current:$current,opposite:$opposite},baseline:$baseline,
      abort:$abort,timeout:$timeout,restored_current_plan:{transport:"streamed",status:"noop",
      plan_token_present:false},final_state:$final_state}' >"$tmp" || die "cannot encode lifecycle evidence"
mv "$tmp" "$output" || die "cannot publish lifecycle evidence"
