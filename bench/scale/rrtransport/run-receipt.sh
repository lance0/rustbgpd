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

classify_child_exe() {
  local expected=$1 actual=$2 state=$3
  if [[ $actual == "$expected" ]]; then
    echo sample
  elif [[ -z $actual && ($state == Z || $state == absent) ]]; then
    echo exited
  else
    echo reject
  fi
}

check_seam() {
  local script=$1 outer verify_call verify_body checksums_call checksums_body classifier_call
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
  classifier_call="classification=\$(classify_child_exe \"\$binary\" \"\$child_exe\" \"\$child_state\")"
  if ! grep -Fq "$outer" "$script" || ! grep -Fq "$verify_call" "$script" ||
    ! grep -Fq "$verify_body" "$script" || ! grep -Fq "$checksums_call" "$script" ||
    ! grep -Fq "$checksums_body" "$script" || ! grep -Fq "$classifier_call" "$script"; then
    echo "runner lacks production verifier/checksum/classifier seam" >&2
    return 1
  fi
}

full_verify() {
  local receipt=$1
  python3 "$verifier" "$receipt" --full | tee "$receipt/verifier.txt"
}

full_checksums() {
  local receipt=$1
  (cd "$receipt" && sha256sum phase.json per-peer.tsv rss.json rss.tsv provenance.json \
    source.snapshot rrtransport.bin verifier.txt harness.log >SHA256SUMS &&
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
  --verify-fixture)
    [[ $# == 3 ]] || exit 2
    rm -rf "$3"
    cp -a "$2" "$3"
    receipt=$3
    python3 "$verifier" "$receipt" | tee "$receipt/verifier.txt"
    (cd "$receipt" && sha256sum phase.json per-peer.tsv rss.json rss.tsv provenance.json \
      source.snapshot rrtransport.bin verifier.txt >SHA256SUMS && sha256sum -c SHA256SUMS)
    exit
    ;;
  --real-smoke)
    [[ $# == 2 ]] || exit 2
    cargo build --manifest-path "$manifest" --locked
    receipt=$2
    rm -rf "$receipt"
    mkdir -p "$receipt"
    tiny_binary="$root/bench/scale/rrtransport/target/debug/rrtransport"
    printf 'checkpoint\trss_kib\n' >"$receipt/rss.tsv"
    setsid "$tiny_binary" rrtiny "$receipt" >"$receipt/harness.log" 2>&1 &
    pid=$!; max_rss=0
    wait_exe "$pid" "$tiny_binary"
    while kill -0 "$pid" 2>/dev/null; do
      rss=$(awk '/VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
      (( rss > max_rss )) && max_rss=$rss
      printf 'sample\t%s\n' "$rss" >>"$receipt/rss.tsv"
      classify_rss "$rss" "$receipt" || exit 1
      sleep 0.05
    done
    if ! wait "$pid"; then
      echo "tiny real-TCP harness failed" >&2
      cat "$receipt/harness.log" >&2
      pid=
      exit 1
    fi
    pid=
    cp "$tiny_binary" "$receipt/rrtransport.bin"
    source_snapshot >"$receipt/source.snapshot"
    cp "$receipt/phase.json" "$receipt/phase.saved"
    python3 - "$receipt" "$max_rss" <<'PY'
import json,pathlib,sys
d=pathlib.Path(sys.argv[1]); p=json.loads((d/"phase.json").read_text())
with (d/"rss.tsv").open("a") as f:
 for name in ("established","staged","wire"): f.write(f"{name}\t{p[name+'_rss_kib']}\n")
(d/"rss.json").write_text(json.dumps({"established_kib":p["established_rss_kib"],
 "staged_kib":p["staged_rss_kib"],"wire_kib":p["wire_rss_kib"],
 "established_vmhwm_kib":p["established_vmhwm_kib"],"staged_vmhwm_kib":p["staged_vmhwm_kib"],
 "wire_vmhwm_kib":p["wire_vmhwm_kib"],"sampler_max_kib":int(sys.argv[2])})+"\n")
PY
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
  printf 'checkpoint\trss_kib\n' >"$receipt/rss.tsv"
  setsid timeout -k 10 300 "$binary" rr1000 "$receipt" >"$receipt/harness.log" 2>&1 &
  pid=$!; max_rss=0
  wait_exe "$pid" "$(command -v timeout)"
  while kill -0 "$pid" 2>/dev/null; do
    child=$(pgrep -P "$pid" -n || true)
    [[ -n $child ]] || { sleep 0.05; continue; }
    child_exe=$(readlink -f "/proc/$child/exe" 2>/dev/null || true)
    child_state=$(awk '$1=="State:" {print substr($2,1,1)}' "/proc/$child/status" 2>/dev/null || true)
    [[ -n $child_state ]] || child_state=absent
    classification=$(classify_child_exe "$binary" "$child_exe" "$child_state")
    [[ $classification == exited ]] && break
    [[ $classification == sample ]] || { echo "sampler child executable mismatch" >&2; exit 1; }
    rss=$(awk '/VmRSS:/ {print $2}' "/proc/$child/status" 2>/dev/null || echo 0)
    (( rss > max_rss )) && max_rss=$rss
    printf 'sample\t%s\n' "$rss" >>"$receipt/rss.tsv"
    classify_rss "$rss" "$receipt" || exit 1
    sleep 0.2
  done
  if ! wait "$pid"; then echo "rr1000 attempt failed" >&2; pid=; exit 1; fi
  pid=
  python3 - "$receipt" "$max_rss" <<'PY'
import json,pathlib,sys
d=pathlib.Path(sys.argv[1]); p=json.loads((d/"phase.json").read_text())
with (d/"rss.tsv").open("a") as f:
 for name in ("established","staged","wire"): f.write(f"{name}\t{p[name+'_rss_kib']}\n")
(d/"rss.json").write_text(json.dumps({"established_kib":p["established_rss_kib"],
 "staged_kib":p["staged_rss_kib"],"wire_kib":p["wire_rss_kib"],
 "established_vmhwm_kib":p["established_vmhwm_kib"],"staged_vmhwm_kib":p["staged_vmhwm_kib"],
 "wire_vmhwm_kib":p["wire_vmhwm_kib"],"sampler_max_kib":int(sys.argv[2])})+"\n")
PY
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
