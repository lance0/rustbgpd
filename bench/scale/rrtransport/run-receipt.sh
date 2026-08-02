#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
verifier="$root/bench/scale/rrtransport/verify_receipt.py"
manifest="$root/bench/scale/rrtransport/Cargo.toml"
binary="$root/bench/scale/rrtransport/target/release/rrtransport"
rss_limit_kib=$((2 * 1024 * 1024))
sources=(
  bench/scale/rrtransport/src/main.rs
  bench/scale/rrtransport/src/rr1000.rs
  bench/scale/rrtransport/src/rr1000_support.rs
  bench/scale/rrtransport/Cargo.toml
  bench/scale/rrtransport/Cargo.lock
  bench/scale/rrtransport/run-receipt.sh
  bench/scale/rrtransport/verify_receipt.py
)

source_snapshot() {
  (cd "$root" && sha256sum "${sources[@]}")
}

classify_rss() {
  local rss=$1 output=$2
  mkdir -p "$output"
  if (( rss > rss_limit_kib )); then
    printf '{"root_failure":"rss_ceiling","observed_kib":%s,"limit_kib":%s}\n' \
      "$rss" "$rss_limit_kib" >"$output/failure.json"
    return 1
  fi
}

read_direct_rss_observation() {
  local process=$1 status
  direct_start_before=absent
  direct_state=absent
  direct_rss=absent
  direct_start_after=absent
  if child_identity "$process"; then direct_start_before=$identity_starttime; fi
  status=$(command cat -- "/proc/$process/status" 2>/dev/null || true)
  direct_state=$(awk '$1=="State:" {print substr($2,1,1)}' <<<"$status")
  [[ -n $direct_state ]] || direct_state=absent
  direct_rss=$(awk '/VmRSS:/ {print $2}' <<<"$status")
  [[ $direct_rss =~ ^[0-9]+$ ]] || direct_rss=absent
  if child_identity "$process"; then direct_start_after=$identity_starttime; fi
}

read_scripted_direct_rss_observation() {
  local _process=$1 snapshot
  snapshot=${scripted_direct_observations[$scripted_direct_index]}
  (( scripted_direct_index += 1 ))
  IFS=, read -r direct_start_before direct_state direct_rss direct_start_after <<<"$snapshot"
}

resolve_direct_rss() {
  local process=$1 expected_start=$2 attempt
  direct_rss_action=reject
  direct_rss_kib=0
  for attempt in 1 2 3; do
    "$direct_rss_observation_reader" "$process"
    if [[ $direct_start_before == absent && $direct_start_after == absent ]]; then
      direct_rss_action=exited
      return
    fi
    if [[ $direct_start_before == "$expected_start" && $direct_start_after == absent ]]; then
      direct_rss_action=exited
      return
    fi
    if [[ $direct_start_before != "$expected_start" ||
      $direct_start_after != "$expected_start" ]]; then
      return
    fi
    if [[ $direct_state == X || $direct_state == Z ]]; then
      direct_rss_action=exited
      return
    fi
    if [[ $direct_rss =~ ^[0-9]+$ ]]; then
      direct_rss_action=sample
      direct_rss_kib=$direct_rss
      return
    fi
    (( attempt < 3 )) && sleep 0.01
  done
}

sample_direct_rss() {
  local process=$1 expected_start=$2 output=$3
  resolve_direct_rss "$process" "$expected_start"
  case $direct_rss_action in
    exited) ;;
    sample)
      (( direct_rss_kib > max_rss )) && max_rss=$direct_rss_kib
      printf 'process_tree_target_rss_sample\t%s\n' "$direct_rss_kib" >>"$output/rss.tsv"
      classify_rss "$direct_rss_kib" "$output"
      ;;
    *)
      echo "tiny sampler observed live process without numeric VmRSS" >&2
      return 1
      ;;
  esac
}

classify_child_observation() {
  local executable=$1 state=$2
  if [[ $state == X || $state == Z ]]; then
    [[ $executable == expected || $executable == empty ]] && echo exited || echo reject
  elif [[ $state == absent ]]; then
    case $executable in
      expected) echo retry_expected_absent ;;
      empty) echo exited ;;
      *) echo reject ;;
    esac
  else
    case $executable in
      expected) echo sample ;;
      empty) echo retry_live_empty ;;
      *) echo reject ;;
    esac
  fi
}

classify_child_exe() {
  local expected=$1 actual=$2 state=$3 executable=foreign
  [[ $actual == "$expected" ]] && executable=expected
  [[ -z $actual ]] && executable=empty
  classify_child_observation "$executable" "$state"
}

child_identity() {
  local process=$1 stat_line stat_fields
  stat_line=$(<"/proc/$process/stat") 2>/dev/null || return 1
  stat_line=${stat_line##*) }
  read -r -a stat_fields <<<"$stat_line"
  (( ${#stat_fields[@]} >= 20 )) || return 1
  identity_ppid=${stat_fields[1]}
  identity_pgrp=${stat_fields[2]}
  identity_starttime=${stat_fields[19]}
}

read_live_sampler_observation() {
  local supervisor=$1 expected=$2 actual_exe
  mapfile -t observed_children < <(pgrep -P "$supervisor" || true)
  observed_child_count=${#observed_children[@]}
  observed_child_pid=absent
  observed_ppid_before=absent
  observed_start_before=absent
  observed_exe_kind=empty
  observed_state=absent
  observed_rss=0
  observed_ppid_after=absent
  observed_start_after=absent
  observed_supervisor_alive=false
  if kill -0 "$supervisor" 2>/dev/null; then
    observed_supervisor_alive=true
  fi
  (( observed_child_count == 1 )) || return

  observed_child_pid=${observed_children[0]}
  if child_identity "$observed_child_pid"; then
    observed_ppid_before=$identity_ppid
    observed_start_before=$identity_starttime
  fi
  actual_exe=$(readlink -f "/proc/$observed_child_pid/exe" 2>/dev/null || true)
  if [[ $actual_exe == "$expected" ]]; then
    observed_exe_kind=expected
  elif [[ -n $actual_exe ]]; then
    observed_exe_kind=foreign
  fi
  observed_state=$(awk '$1=="State:" {print substr($2,1,1)}' \
    "/proc/$observed_child_pid/status" 2>/dev/null || true)
  [[ -n $observed_state ]] || observed_state=absent
  observed_rss=$(awk '/VmRSS:/ {print $2}' \
    "/proc/$observed_child_pid/status" 2>/dev/null || echo 0)
  [[ $observed_rss =~ ^[0-9]+$ ]] || observed_rss=0
  if child_identity "$observed_child_pid"; then
    observed_ppid_after=$identity_ppid
    observed_start_after=$identity_starttime
  fi
  observed_supervisor_alive=false
  if kill -0 "$supervisor" 2>/dev/null; then
    observed_supervisor_alive=true
  fi
}

read_scripted_sampler_observation() {
  local supervisor=$1 _expected=$2 snapshot
  snapshot=${scripted_observations[$scripted_observation_index]}
  (( scripted_observation_index += 1 ))
  IFS=, read -r observed_child_count observed_child_pid observed_ppid_before \
    observed_start_before observed_exe_kind observed_state observed_rss \
    observed_ppid_after observed_start_after observed_supervisor_alive <<<"$snapshot"
  [[ $observed_ppid_before != supervisor ]] || observed_ppid_before=$supervisor
  [[ $observed_ppid_after != supervisor ]] || observed_ppid_after=$supervisor
}

sampler_diagnostic() {
  local log=$1 run=$2 observation=$3 resolution=$4 reason=$5 parent_match=$6 message
  message=$(printf 'sampler_observation run=%s observation=%s supervisor_pid=%s supervisor_alive=%s child_count=%s child_pid=%s child_starttime=%s parent_match=%s executable=%s state=%s resolution=%s reason=%s' \
    "$run" "$observation" "$sampler_supervisor" "$observed_supervisor_alive" \
    "$observed_child_count" "$observed_child_pid" "$observed_start_before" \
    "$parent_match" "$observed_exe_kind" "$observed_state" "$resolution" "$reason")
  printf '%s\n' "$message" >&2
  printf '%s\n' "$message" >>"$log"
}

resolve_sampler_child() {
  local supervisor=$1 expected=$2 log=$3 run=$4 seen_expected=$5
  local observation_attempt classification parent_match reason
  sampler_supervisor=$supervisor
  sampler_action=reject
  sampler_child=absent
  sampler_rss=0
  for observation_attempt in 1 2 3; do
    "$sampler_observation_reader" "$supervisor" "$expected"
    parent_match=false
    if (( observed_child_count > 1 )); then
      sampler_diagnostic "$log" "$run" "$observation_attempt" reject multiple_children false
      return
    fi
    if (( observed_child_count == 0 )); then
      if [[ $seen_expected == true ]]; then
        sampler_action=exited
        sampler_diagnostic "$log" "$run" "$observation_attempt" exited child_disappeared false
      else
        sampler_action=startup_wait
      fi
      return
    fi
    if [[ $observed_ppid_before == "$supervisor" &&
      $observed_ppid_after == "$supervisor" ]]; then
      parent_match=true
    fi
    if [[ $parent_match != true || $observed_start_before == absent ||
      $observed_start_before != "$observed_start_after" ]]; then
      if (( observation_attempt < 3 )); then
        sampler_diagnostic "$log" "$run" "$observation_attempt" retry identity_changed "$parent_match"
        sleep 0.01
        continue
      fi
      sampler_diagnostic "$log" "$run" "$observation_attempt" reject identity_changed "$parent_match"
      return
    fi

    classification=$(classify_child_observation "$observed_exe_kind" "$observed_state")
    case $classification in
      sample)
        sampler_action=sample
        sampler_child=$observed_child_pid
        sampler_rss=$observed_rss
        if (( observation_attempt > 1 )); then
          sampler_diagnostic "$log" "$run" "$observation_attempt" sample stable_after_retry true
        fi
        return
        ;;
      exited)
        sampler_action=exited
        reason=expected_terminal
        [[ $observed_exe_kind == empty ]] && reason=empty_terminal
        sampler_diagnostic "$log" "$run" "$observation_attempt" exited "$reason" true
        return
        ;;
      reject)
        sampler_diagnostic "$log" "$run" "$observation_attempt" reject foreign_executable true
        return
        ;;
      retry_live_empty)
        if (( observation_attempt < 3 )); then
          sampler_diagnostic "$log" "$run" "$observation_attempt" retry live_empty true
          sleep 0.01
          continue
        fi
        sampler_diagnostic "$log" "$run" "$observation_attempt" reject persistent_live_empty true
        return
        ;;
      retry_expected_absent)
        if (( observation_attempt < 3 )); then
          sampler_diagnostic "$log" "$run" "$observation_attempt" retry expected_absent true
          sleep 0.01
          continue
        fi
        sampler_diagnostic "$log" "$run" "$observation_attempt" reject persistent_expected_absent true
        return
        ;;
    esac
  done
}

launch_supervised() {
  local log=$1
  shift
  : >"$log"
  supervisor_log=$log
  setsid "$@" >>"$log" 2>&1 &
  pid=$!
}

validate_tiny_gate_identity() {
  local supervisor=$1 expected=$2 ready_pid=$3 ready_exe=$4
  local expected_exe actual_exe state start_before start_after pgrp_before pgrp_after rss
  [[ $ready_pid =~ ^[0-9]+$ && $ready_pid == "$supervisor" ]] || return 1
  kill -0 "$ready_pid" 2>/dev/null || return 1
  state=$(awk '$1=="State:" {print substr($2,1,1)}' "/proc/$ready_pid/status" 2>/dev/null || true)
  [[ -n $state && $state != X && $state != Z ]] || return 1
  child_identity "$ready_pid" || return 1
  start_before=$identity_starttime
  pgrp_before=$identity_pgrp
  expected_exe=$(readlink -f "$expected") || return 1
  actual_exe=$(readlink -f "/proc/$ready_pid/exe") || return 1
  rss=$(awk '/VmRSS:/ {print $2}' "/proc/$ready_pid/status") || return 1
  [[ $rss =~ ^[0-9]+$ ]] || return 1
  child_identity "$ready_pid" || return 1
  start_after=$identity_starttime
  pgrp_after=$identity_pgrp
  [[ $ready_exe == "$expected_exe" && $actual_exe == "$expected_exe" &&
    $start_before == "$start_after" && $pgrp_before == "$supervisor" &&
    $pgrp_after == "$supervisor" ]] || return 1
  tiny_validated_rss=$rss
  tiny_validated_starttime=$start_after
}

await_tiny_startup_gate() {
  local supervisor=$1 expected=$2 ready=$3 go=$4 receipt=$5
  local state identity_status=0 rss go_tmp
  local -a ready_fields=()
  tiny_gate_reason=startup_timeout
  tiny_gate_stop=true
  for _ in {1..1000}; do
    [[ -s $ready ]] && break
    state=$(awk '$1=="State:" {print substr($2,1,1)}' \
      "/proc/$supervisor/status" 2>/dev/null || true)
    if [[ $state == X || $state == Z ]] || ! kill -0 "$supervisor" 2>/dev/null; then
      tiny_gate_reason=pre_ready_exit
      tiny_gate_stop=false
      return 1
    fi
    sleep 0.01
  done
  [[ -s $ready ]] || return 1
  mapfile -t ready_fields <"$ready"
  if (( ${#ready_fields[@]} != 2 )); then
    tiny_gate_reason=invalid_ready_record
    return 1
  fi
  ready_pid=${ready_fields[0]}
  ready_exe=${ready_fields[1]}
  validate_tiny_gate_identity "$supervisor" "$expected" "$ready_pid" "$ready_exe" ||
    identity_status=$?
  if (( identity_status != 0 )); then
    tiny_gate_reason=identity_rejected
    return 1
  fi
  rss=$tiny_validated_rss
  (( rss > max_rss )) && max_rss=$rss
  printf 'process_tree_target_rss_sample\t%s\n' "$rss" >>"$receipt/rss.tsv"
  if ! classify_rss "$rss" "$receipt"; then
    tiny_gate_reason=rss_ceiling
    return 1
  fi
  go_tmp="$go.tmp.$$"
  printf 'go\n' >"$go_tmp"
  mv "$go_tmp" "$go"
  printf 'startup_gate resolution=release pid=%s process_group=%s initial_rss_kib=%s\n' \
    "$ready_pid" "$supervisor" "$rss" >>"$receipt/harness.log"
}

gate_tiny_supervisor() {
  tiny_gate_reason=gate_wait_failed
  tiny_gate_stop=true
  await_tiny_startup_gate "$pid" "$tiny_expected" "$tiny_ready" "$tiny_go" "$receipt"
}

stop_and_reap() {
  local stop=$1 reason=$2 state message
  if [[ $stop == true ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM -- "-$pid" 2>/dev/null || true
    for _ in {1..20}; do
      state=$(awk '$1=="State:" {print substr($2,1,1)}' "/proc/$pid/status" 2>/dev/null || true)
      [[ -z $state || $state == X || $state == Z ]] && break
      sleep 0.1
    done
    kill -KILL -- "-$pid" 2>/dev/null || true
  fi
  if wait "$pid"; then
    attempt_wait_status=0
  else
    attempt_wait_status=$?
  fi
  pid=
  message=$(printf 'sampler_reap reason=%s supervisor_status=%s' "$reason" "$attempt_wait_status")
  printf '%s\n' "$message" >&2
  printf '%s\n' "$message" >>"$supervisor_log"
}

report_tiny_startup_failure() {
  local receipt=$1 reason=$tiny_gate_reason
  stop_and_reap "$tiny_gate_stop" "startup_gate_$reason"
  printf 'startup_gate_failure reason=%s child_status=%s\n' \
    "$reason" "$attempt_wait_status" | tee -a "$receipt/harness.log" >&2
  cat "$receipt/harness.log" >&2
  return 1
}

fail_supervised_attempt() {
  local reason=$1
  stop_and_reap true "$reason"
  return 1
}

startup_gate_fixture() {
  local mode=$1 fixture_dir=$2 wrong_binary result group_pid live_members
  rm -rf "$fixture_dir"
  mkdir -p "$fixture_dir/receipt" "$fixture_dir/gate"
  receipt=$fixture_dir/receipt
  tiny_ready=$fixture_dir/gate/ready
  tiny_go=$fixture_dir/gate/go
  tiny_expected="$root/bench/scale/rrtransport/target/debug/rrtransport"
  printf 'observer\trss_kib\n' >"$receipt/rss.tsv"
  max_rss=0
  case $mode in
    delayed-expected)
      # Deliberately exceed the retired wait_exe one-second observation window.
      # shellcheck disable=SC2016 # Expanded by the fixture's bash.
      launch_supervised "$receipt/harness.log" env \
        RRTRANSPORT_STARTUP_READY="$tiny_ready" RRTRANSPORT_STARTUP_GO="$tiny_go" \
        bash -c 'sleep 1.2; exec "$1" rrtiny "$2"' bash "$tiny_expected" "$receipt"
      printf '%s\n' "$pid" >"$fixture_dir/group.pid"
      if ! gate_tiny_supervisor; then
        report_tiny_startup_failure "$receipt" || true
        return 1
      fi
      if wait "$pid"; then result=0; else result=$?; fi
      pid=
      [[ $result == 0 && -s $receipt/phase.json && -e $tiny_go ]]
      ;;
    stable-wrong)
      wrong_binary=$fixture_dir/wrong-rrtransport
      cp "$tiny_expected" "$wrong_binary"
      chmod +x "$wrong_binary"
      # shellcheck disable=SC2016 # Expanded by the fixture's bash.
      launch_supervised "$receipt/harness.log" env \
        RRTRANSPORT_STARTUP_READY="$tiny_ready" RRTRANSPORT_STARTUP_GO="$tiny_go" \
        bash -c 'sleep 1.2; exec "$1" rrtiny "$2"' bash "$wrong_binary" "$receipt"
      group_pid=$pid
      printf '%s\n' "$group_pid" >"$fixture_dir/group.pid"
      if gate_tiny_supervisor; then
        stop_and_reap true false_green_wrong_executable
        echo "stable wrong executable was released" >&2
        return 1
      fi
      report_tiny_startup_failure "$receipt" || true
      printf '%s\n' "$attempt_wait_status" >"$fixture_dir/child.status"
      [[ $tiny_gate_reason == identity_rejected && ! -e $tiny_go && -z $pid ]]
      live_members=$(ps -eo pgid=,stat= --no-headers |
        awk -v group="$group_pid" '$1 == group && $2 !~ /^[XZ]/ {print}')
      [[ -z $live_members ]]
      ;;
    pre-ready-exit)
      launch_supervised "$receipt/harness.log" bash -c \
        'sleep 0.05; printf "pre-ready fixture diagnostic\n"; exit 37'
      printf '%s\n' "$pid" >"$fixture_dir/group.pid"
      if gate_tiny_supervisor; then
        stop_and_reap true false_green_pre_ready_exit
        echo "pre-ready exit was released" >&2
        return 1
      fi
      report_tiny_startup_failure "$receipt" || true
      printf '%s\n' "$attempt_wait_status" >"$fixture_dir/child.status"
      [[ $tiny_gate_reason == pre_ready_exit && $attempt_wait_status == 37 &&
        ! -e $tiny_go && -z $pid ]]
      ;;
    *)
      return 2
      ;;
  esac
  printf '%s\tpass\n' "$mode"
}

sample_supervisor() {
  local expected=$1 receipt=$2 run=$3
  local seen_expected_child=false rss
  max_rss=0
  while kill -0 "$pid" 2>/dev/null; do
    resolve_sampler_child "$pid" "$expected" "$receipt/harness.log" "$run" "$seen_expected_child"
    [[ $sampler_action == exited ]] && break
    [[ $sampler_action != startup_wait ]] || { sleep 0.05; continue; }
    if [[ $sampler_action != sample ]]; then
      fail_supervised_attempt sampler_rejected
      return 1
    fi
    seen_expected_child=true
    rss=$sampler_rss
    (( rss > max_rss )) && max_rss=$rss
    printf 'process_tree_target_rss_sample\t%s\n' "$rss" >>"$receipt/rss.tsv"
    if ! classify_rss "$rss" "$receipt"; then
      fail_supervised_attempt rss_ceiling
      return 1
    fi
    sleep 0.2
  done
  stop_and_reap false completed
  if (( attempt_wait_status != 0 )); then
    echo "rr1000 attempt failed" >&2
    return 1
  fi
}

sampler_control_fixture() {
  local mode=$1 expected_status=$2 fixture_dir=$3 result
  mkdir -p "$fixture_dir"
  receipt=$fixture_dir
  printf 'observer\trss_kib\n' >"$receipt/rss.tsv"
  if [[ $mode == normal ]]; then
    # shellcheck disable=SC2016 # Expanded by the fixture's bash.
    launch_supervised "$receipt/harness.log" bash -c \
      'printf "harness-before\n"; sleep 0.05; exit "$1"' bash "$expected_status"
    scripted_observations=(
      "1,200,supervisor,11,expected,X,0,supervisor,11,true"
    )
  else
    # shellcheck disable=SC2016 # Expanded by the fixture's bash.
    launch_supervised "$receipt/harness.log" bash -c \
      'status=$1; trap '\''printf "harness-after\n"; exit "$status"'\'' TERM; printf "harness-before\n"; while :; do sleep 0.05; done' \
      bash "$expected_status"
    for _ in {1..100}; do
      grep -Fq harness-before "$receipt/harness.log" && break
      sleep 0.01
    done
    if [[ $mode == sampler_rejected ]]; then
      scripted_observations=(
        "1,200,supervisor,11,foreign,R,0,supervisor,11,true"
      )
    elif [[ $mode == rss_ceiling ]]; then
      scripted_observations=(
        "1,200,supervisor,11,expected,R,2097153,supervisor,11,true"
      )
    else
      return 2
    fi
  fi
  scripted_observation_index=0
  sampler_observation_reader=read_scripted_sampler_observation
  if sample_supervisor /expected "$receipt" 1; then
    result=0
  else
    result=$?
  fi
  [[ -z $pid ]]
  printf '%s\t%s\t%s\n' "$mode" "$result" "$attempt_wait_status"
}

stop_reap_fixture() {
  local reason=$1 expected_status=$2 fixture_dir=$3 result group_pid live_members signal_trace
  mkdir -p "$fixture_dir"
  # Preserve the already-dead leader proof.
  # shellcheck disable=SC2016 # Expanded by the fixture's bash.
  launch_supervised "$fixture_dir/harness.log" bash -c 'exit "$1"' bash "$expected_status"
  for _ in {1..100}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.01
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "short-lived supervisor remained live" >&2
    return 1
  fi
  signal_trace=$fixture_dir/already-dead-signals.log
  : >"$signal_trace"
  kill() {
    if [[ ${1:-} == -TERM || ${1:-} == -KILL ]]; then
      printf '%s\n' "$1" >>"$signal_trace"
    fi
    builtin kill "$@"
  }
  if fail_supervised_attempt "$reason"; then
    result=0
  else
    result=$?
  fi
  unset -f kill
  [[ $result == 1 && $attempt_wait_status == "$expected_status" && -z $pid &&
    ! -s $signal_trace ]]

  # Prove that a TERM-ignoring descendant cannot survive its leader.
  # shellcheck disable=SC2016 # Expanded by the fixture's bash.
  launch_supervised "$fixture_dir/harness.log" bash -c \
    'status=$1; descendant_file=$2; trap '\''exit "$status"'\'' TERM; bash -c '\''trap "" TERM; while :; do sleep 0.05; done'\'' & printf "%s\n" "$!" >"$descendant_file"; while :; do sleep 0.05; done' \
    bash "$expected_status" "$fixture_dir/descendant.pid"
  group_pid=$pid
  printf '%s\n' "$group_pid" >"$fixture_dir/group.pid"
  for _ in {1..100}; do
    [[ -s $fixture_dir/descendant.pid ]] && break
    sleep 0.01
  done
  [[ -s $fixture_dir/descendant.pid ]]
  if fail_supervised_attempt "$reason"; then
    result=0
  else
    result=$?
  fi
  [[ $result == 1 && $attempt_wait_status == "$expected_status" && -z $pid ]]
  for _ in {1..100}; do
    live_members=$(ps -eo pgid=,stat= --no-headers |
      awk -v group="$group_pid" '$1 == group && $2 !~ /^[XZ]/ {print}')
    [[ -z $live_members ]] && break
    sleep 0.01
  done
  if [[ -n $live_members ]]; then
    kill -KILL -- "-$group_pid" 2>/dev/null || true
    echo "live process-group member survived stop" >&2
    return 1
  fi
  printf '%s\t%s\t%s\n' "$reason" "$result" "$attempt_wait_status"
}

check_seam() {
  local script=$1 outer verify_call verify_body checksums_call checksums_body
  local direct_rss_call direct_rss_exit direct_rss_resolver
  outer="timeout -k 10 1200 \"\$scr"
  outer+="ipt\" --campaign-inner \"\$output\""
  verify_call="full_ver"
  verify_call+="ify \"\$receipt\""
  verify_body="python3 \"\$ver"
  verify_body+="ifier\" \"\$receipt\" --full | tee \"\$receipt/verifier.txt\""
  checksums_call="full_check"
  checksums_call+="sums \"\$receipt\""
  checksums_body="sha256sum -c SHA"
  checksums_body+="256SUMS --strict"
  direct_rss_call="sample_direct_rss \"\$pid\" \"\$tiny_validated_starttime\" \"\$receipt\""
  direct_rss_exit="[[ \$direct_rss_action != exited ]] || break"
  direct_rss_resolver='resolve_direct_'
  direct_rss_resolver+="rss \"\$process\" \"\$expected_start\""
  if ! grep -Fq "$outer" "$script" || ! grep -Fq "$verify_call" "$script" ||
    ! grep -Fq "$verify_body" "$script" || ! grep -Fq "$checksums_call" "$script" ||
    ! grep -Fq "$checksums_body" "$script" || ! grep -Fq "$direct_rss_call" "$script" ||
    ! grep -Fq "$direct_rss_exit" "$script" ||
    ! grep -Fq "$direct_rss_resolver" "$script"; then
    echo "runner lacks production verifier/checksum/RSS seam" >&2
    return 1
  fi
}

full_verify() {
  local receipt=$1
  python3 "$verifier" "$receipt" --full | tee "$receipt/verifier.txt"
}

run_grouped_commit_fixture() {
  RRTRANSPORT_GROUPED_COMMIT_OUTPUT="$1/grouped-commit.json" \
    RRTRANSPORT_GROUPED_COMMIT_PEERS="$2" RRTRANSPORT_GROUPED_COMMIT_PREFIXES="$3" \
    cargo test --manifest-path "$manifest" --locked \
      rr1000::tests::grouped_commit_receipt_fixture -- --exact
  [[ -s $1/grouped-commit.json ]]
}

full_checksums() {
  local receipt=$1
  (cd "$receipt" && sha256sum phase.json grouped-commit.json per-peer.tsv rss.json rss.tsv \
    provenance.json source.snapshot rrtransport.bin verifier.txt harness.log >SHA256SUMS &&
    sha256sum -c SHA256SUMS --strict)
}

host_state() {
  local prefix=$1
  mapfile -t "${prefix}_governors" < <(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
  printf -v "${prefix}_load" '%s' "$(cut -d' ' -f1 /proc/loadavg)"
  printf -v "${prefix}_pswpin" '%s' "$(awk '$1=="pswpin" {print $2}' /proc/vmstat)"
  printf -v "${prefix}_pswpout" '%s' "$(awk '$1=="pswpout" {print $2}' /proc/vmstat)"
  printf -v "${prefix}_competitors" '%s' "$(ps -eo pid=,comm= --no-headers | awk -v self="$$" '
    $1 != self && ($2 == "cargo" || $2 == "rustc" || $2 == "rustbgpd" ||
    $2 == "rrtransport" || $2 == "reloadstall" || $2 == "perf" ||
    $2 ~ /^rrharness/ || $2 ~ /^route_paging/ || $2 ~ /^rib_nlri_build/ ||
    $2 ~ /^nlri_build/ || $2 ~ /^event_history_/ || $2 ~ /^codec/ ||
    $2 ~ /^fanout/ || $2 ~ /^inbound_attrs/ || $2 ~ /^rib_ops/ ||
    $2 ~ /^policy_eval/ || $2 ~ /^explain_snapsho/ || $2 ~ /^bgperf/ ||
    $2 == "bird" || $2 == "bird6" || $2 == "bgpd" || $2 == "openbgpd" ||
    $2 == "gobgpd" || $2 == "zebra" || $2 == "frr" || $2 == "ospfd" ||
    $2 == "staticd") { print $2 }' || true)"
}

require_quiet() {
  local prefix=$1 cpus load_name competitors_name load competitors
  local -n governors_ref="${prefix}_governors"
  load_name="${prefix}_load"
  competitors_name="${prefix}_competitors"
  load=${!load_name}
  competitors=${!competitors_name}
  cpus=$(nproc)
  [[ ${governors_ref[*]} == performance ]]
  awk -v load="$load" -v cpus="$cpus" 'BEGIN {exit !(load < cpus/4)}'
  [[ -z $competitors ]]
}

cleanup() {
  if [[ -n ${pid:-} ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM -- "-$pid" 2>/dev/null || true
    for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

wait_exe() {
  local process=$1 expected=$2
  for _ in {1..100}; do
    [[ $(readlink -f "/proc/$process/exe" 2>/dev/null || true) == "$expected" ]] && return
    kill -0 "$process" 2>/dev/null || break
    sleep 0.01
  done
  echo "PID $process did not exec expected binary $expected" >&2
  return 1
}
on_int() { exit 130; }
on_term() { exit 143; }
trap cleanup EXIT
trap on_int INT
trap on_term TERM

case ${1:-} in
  --check-seam)
    [[ $# == 2 ]] || exit 2
    check_seam "$2"
    exit
    ;;
  --classify-rss)
    [[ $# == 3 ]] || exit 2
    classify_rss "$2" "$3"
    exit
    ;;
  --classify-child-exe)
    [[ $# == 4 ]] || exit 2
    classify_child_exe "$2" "$3" "$4"
    exit
    ;;
  --sample-direct-rss-observations)
    (( $# >= 4 )) || exit 2
    receipt=$2; sample_status=0
    mkdir -p "$receipt"
    printf 'checkpoint\trss_kib\n' >"$receipt/rss.tsv"
    max_rss=0
    scripted_direct_observations=("${@:4}")
    scripted_direct_index=0
    direct_rss_observation_reader=read_scripted_direct_rss_observation
    sample_direct_rss 4242 "$3" "$receipt" || sample_status=$?
    printf '%s\t%s\t%s\n' "$direct_rss_action" "$direct_rss_kib" "$max_rss"
    exit "$sample_status"
    ;;
  --resolve-child-observations)
    (( $# >= 4 )) || exit 2
    diagnostic_log=$2
    seen_expected=$3
    scripted_observations=("${@:4}")
    scripted_observation_index=0
    sampler_observation_reader=read_scripted_sampler_observation
    : >"$diagnostic_log"
    resolve_sampler_child 4242 /expected "$diagnostic_log" 1 "$seen_expected"
    printf '%s\t%s\t%s\n' "$sampler_action" "$sampler_child" "$sampler_rss"
    exit
    ;;
  --sampler-control-fixture)
    [[ $# == 4 ]] || exit 2
    sampler_control_fixture "$2" "$3" "$4"
    exit
    ;;
  --stop-reap-fixture)
    [[ $# == 4 ]] || exit 2
    stop_reap_fixture "$2" "$3" "$4"
    exit
    ;;
  --startup-gate-fixture)
    [[ $# == 3 ]] || exit 2
    cargo build --manifest-path "$manifest" --locked
    startup_gate_fixture "$2" "$3"
    exit
    ;;
  --verify-fixture)
    [[ $# == 3 ]] || exit 2
    rm -rf "$3"
    cp -a "$2" "$3"
    receipt=$3
    python3 "$verifier" "$receipt" | tee "$receipt/verifier.txt"
    (cd "$receipt" && sha256sum phase.json grouped-commit.json per-peer.tsv rss.json rss.tsv \
      provenance.json source.snapshot rrtransport.bin verifier.txt >SHA256SUMS &&
      sha256sum -c SHA256SUMS --strict)
    exit
    ;;
  --real-smoke)
    [[ $# == 2 ]] || exit 2
    cargo build --manifest-path "$manifest" --locked
    receipt=$2
    rm -rf "$receipt"
    mkdir -p "$receipt"
    tiny_binary="$root/bench/scale/rrtransport/target/debug/rrtransport"
    run_grouped_commit_fixture "$receipt" 4 100
    printf 'observer\trss_kib\n' >"$receipt/rss.tsv"
    tiny_ready=$receipt/.startup-ready
    tiny_go=$receipt/.startup-go
    tiny_expected=$tiny_binary
    launch_supervised "$receipt/harness.log" env \
      RRTRANSPORT_STARTUP_READY="$tiny_ready" RRTRANSPORT_STARTUP_GO="$tiny_go" \
      "$tiny_binary" rrtiny "$receipt"
    max_rss=0
    if ! gate_tiny_supervisor; then
      report_tiny_startup_failure "$receipt" || true
      exit 1
    fi
    direct_rss_observation_reader=read_direct_rss_observation
    while kill -0 "$pid" 2>/dev/null; do
      sample_direct_rss "$pid" "$tiny_validated_starttime" "$receipt" || exit 1
      [[ $direct_rss_action != exited ]] || break
      sleep 0.05
    done
    if ! wait "$pid"; then
      echo "tiny real-TCP harness failed" >&2
      cat "$receipt/harness.log" >&2
      pid=
      exit 1
    fi
    pid=
    rm -f "$tiny_ready" "$tiny_go"
    cp "$tiny_binary" "$receipt/rrtransport.bin"
    source_snapshot >"$receipt/source.snapshot"
    cp "$receipt/phase.json" "$receipt/phase.saved"
    python3 "$verifier" "$receipt" --write-rss "$max_rss"
    head=$(git -C "$root" rev-parse HEAD); tree=$(git -C "$root" write-tree)
    source_hash=$(sha256sum "$receipt/source.snapshot"|cut -d' ' -f1)
    binary_hash=$(sha256sum "$receipt/rrtransport.bin"|cut -d' ' -f1)
    printf '{"head_before":"%s","head_after":"%s","tree_before":"%s","tree_after":"%s","source_sha256":"%s","source_after_sha256":"%s","binary_sha256":"%s","governors":["performance"],"load_before":"fixture","load_after":"fixture","pswpin_before":0,"pswpin_after":0,"pswpout_before":0,"pswpout_after":0,"rustc":"fixture","host":"fixture","competitors":[]}\n' \
      "$head" "$head" "$tree" "$tree" "$source_hash" "$source_hash" "$binary_hash" >"$receipt/provenance.json"
    : >"$receipt/verifier.txt"
    python3 "$verifier" "$receipt" --tiny | tee "$receipt/verifier.txt"
    exit
    ;;
  --campaign-inner)
    [[ $# == 2 ]] || exit 2
    output=$2
    campaign_inner=1
    ;;
esac

if [[ -z ${campaign_inner:-} ]]; then
  [[ $# == 1 ]] || { echo "usage: $0 OUTPUT" >&2; exit 2; }
  output=$1
  script=$0
  check_seam "$script"
  timeout -k 10 1200 "$script" --campaign-inner "$output"
  exit
fi
[[ $output = /* && $output != "$root"/* ]] || { echo "output must be absolute and outside repo" >&2; exit 1; }
[[ ! -e $output ]] || { echo "output must not already exist" >&2; exit 1; }
exec 9>/tmp/rustbgpd-rrtransport-rr1000.lock
flock -n 9 || { echo "rr1000 host lock busy" >&2; exit 1; }
[[ $(ulimit -n) -ge 4096 ]] || { echo "need at least 4096 FDs" >&2; exit 1; }
available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
(( available >= 16 * 1024 * 1024 )) || { echo "need 16 GiB available" >&2; exit 1; }
[[ -z $(git -C "$root" status --porcelain) ]] || { echo "tree must be clean" >&2; exit 1; }

head_before=$(git -C "$root" rev-parse HEAD); tree_before=$(git -C "$root" write-tree)
source_before=$(source_snapshot)
timeout -k 10 300 cargo build --manifest-path "$manifest" --locked --release
mkdir -p "$output"; campaign_started=$SECONDS
run_grouped_commit_fixture "$output" 1000 100000
chmod 0444 "$output/grouped-commit.json"
before_load=''
after_load=''
before_pswpin=''
after_pswpin=''
before_pswpout=''
after_pswpout=''
for run in 1 2 3; do
  (( SECONDS - campaign_started < 1200 )) || { echo "campaign deadline" >&2; exit 1; }
  host_state before
  require_quiet before || { echo "host not quiet before attempt" >&2; exit 1; }
  receipt="$output/run-$run"; mkdir -p "$receipt"
  printf '%s\n' "$source_before" >"$receipt/source.snapshot"; cp "$binary" "$receipt/rrtransport.bin"
  cp "$output/grouped-commit.json" "$receipt/grouped-commit.json"
  printf 'observer\trss_kib\n' >"$receipt/rss.tsv"
  launch_supervised "$receipt/harness.log" timeout -k 10 300 "$binary" rr1000 "$receipt"
  wait_exe "$pid" "$(command -v timeout)"
  sampler_observation_reader=read_live_sampler_observation
  sample_supervisor "$binary" "$receipt" "$run" || exit 1
  python3 "$verifier" "$receipt" --write-rss "$max_rss"
  head_after=$(git -C "$root" rev-parse HEAD); tree_after=$(git -C "$root" write-tree)
  source_after=$(source_snapshot)
  [[ -z $(git -C "$root" status --porcelain) ]] || { echo "tree dirtied during run" >&2; exit 1; }
  source_hash=$(sha256sum "$receipt/source.snapshot"|cut -d' ' -f1)
  source_after_hash=$(printf '%s\n' "$source_after"|sha256sum|cut -d' ' -f1)
  binary_hash=$(sha256sum "$receipt/rrtransport.bin"|cut -d' ' -f1)
  host_state after
  require_quiet after || { echo "host not quiet after attempt" >&2; exit 1; }
  [[ $before_pswpin == "$after_pswpin" && $before_pswpout == "$after_pswpout" ]] || { echo "swap I/O changed" >&2; exit 1; }
  printf '{"head_before":"%s","head_after":"%s","tree_before":"%s","tree_after":"%s","source_sha256":"%s","source_after_sha256":"%s","binary_sha256":"%s","governors":["performance"],"load_before":"%s","load_after":"%s","pswpin_before":%s,"pswpin_after":%s,"pswpout_before":%s,"pswpout_after":%s,"rustc":"%s","host":"%s","competitors":[]}\n' \
    "$head_before" "$head_after" "$tree_before" "$tree_after" "$source_hash" "$source_after_hash" "$binary_hash" "$before_load" "$after_load" "$before_pswpin" "$after_pswpin" "$before_pswpout" "$after_pswpout" "$(rustc -V)" "$(uname -srvmo)" >"$receipt/provenance.json"
  [[ $source_before == "$source_after" ]] || { echo "declared sources changed" >&2; exit 1; }
  : >"$receipt/verifier.txt"
  full_verify "$receipt"
  full_checksums "$receipt"
done
