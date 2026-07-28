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

check_seam() {
  local script=$1
  if ! grep -Fq "python3 \"\$verifier\" \"\$receipt\"" "$script" ||
    ! grep -Fq "sha256sum -c SHA256SUMS" "$script"; then
    echo "runner lacks production verifier/checksum seam" >&2
    return 1
  fi
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
trap cleanup EXIT INT TERM

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
    printf '{"head_before":"%s","head_after":"%s","tree_before":"%s","tree_after":"%s","source_sha256":"%s","source_after_sha256":"%s","binary_sha256":"%s","governors":["performance"],"load_before":"fixture","load_after":"fixture","swap_before_kib":0,"swap_after_kib":0,"rustc":"fixture","host":"fixture","competitors":[]}\n' \
      "$head" "$head" "$tree" "$tree" "$source_hash" "$source_hash" "$binary_hash" >"$receipt/provenance.json"
    : >"$receipt/verifier.txt"
    python3 "$verifier" "$receipt" --tiny | tee "$receipt/verifier.txt"
    exit
    ;;
esac

[[ $# == 1 ]] || { echo "usage: $0 OUTPUT" >&2; exit 2; }
output=$1
[[ $output = /* && $output != "$root"/* ]] || { echo "output must be absolute and outside repo" >&2; exit 1; }
[[ ! -e $output ]] || { echo "output must not already exist" >&2; exit 1; }
exec 9>/tmp/rustbgpd-rrtransport-rr1000.lock
flock -n 9 || { echo "rr1000 host lock busy" >&2; exit 1; }
check_seam "$0"
[[ $(ulimit -n) -ge 4096 ]] || { echo "need at least 4096 FDs" >&2; exit 1; }
available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
(( available >= 16 * 1024 * 1024 )) || { echo "need 16 GiB available" >&2; exit 1; }
mapfile -t governors < <(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
[[ ${#governors[@]} == 1 && ${governors[0]} == performance ]] || { echo "all CPUs must use performance governor" >&2; exit 1; }
load_before=$(cut -d' ' -f1 /proc/loadavg); cpus=$(nproc)
awk -v load="$load_before" -v cpus="$cpus" 'BEGIN {exit !(load < cpus/4)}' || { echo "host load too high" >&2; exit 1; }
! pgrep -x 'bird|bgpd|gobgpd' >/dev/null || { echo "competitor daemon running" >&2; exit 1; }
[[ -z $(git -C "$root" status --porcelain) ]] || { echo "tree must be clean" >&2; exit 1; }

head_before=$(git -C "$root" rev-parse HEAD); tree_before=$(git -C "$root" write-tree)
source_before=$(source_snapshot); swap_before=$(awk '/SwapFree:/ {print $2}' /proc/meminfo)
timeout -k 10 300 cargo build --manifest-path "$manifest" --locked --release
mkdir -p "$output"; campaign_started=$SECONDS
for run in 1 2 3; do
  (( SECONDS - campaign_started < 1200 )) || { echo "campaign deadline" >&2; exit 1; }
  receipt="$output/run-$run"; mkdir -p "$receipt"
  printf '%s\n' "$source_before" >"$receipt/source.snapshot"; cp "$binary" "$receipt/rrtransport.bin"
  printf 'checkpoint\trss_kib\n' >"$receipt/rss.tsv"
  setsid timeout -k 10 300 "$binary" rr1000 "$receipt" >"$receipt/harness.log" 2>&1 &
  pid=$!; max_rss=0
  exe=$(readlink -f "/proc/$pid/exe")
  [[ $exe == "$(command -v timeout)" ]] || { echo "sampler PID is not timeout supervisor" >&2; exit 1; }
  while kill -0 "$pid" 2>/dev/null; do
    child=$(pgrep -P "$pid" -n || true)
    [[ -n $child ]] || { sleep 0.05; continue; }
    [[ $(readlink -f "/proc/$child/exe") == "$binary" ]] || { echo "sampler child executable mismatch" >&2; exit 1; }
    rss=$(awk '/VmRSS:/ {print $2}' "/proc/$child/status" 2>/dev/null || echo 0)
    (( rss > max_rss )) && max_rss=$rss
    printf 'sample\t%s\n' "$rss" >>"$receipt/rss.tsv"
    classify_rss "$rss" "$receipt" || exit 1
    sleep 0.2
  done
  wait "$pid"; pid=
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
  source_after=$(source_snapshot); swap_after=$(awk '/SwapFree:/ {print $2}' /proc/meminfo)
  [[ -z $(git -C "$root" status --porcelain) ]] || { echo "tree dirtied during run" >&2; exit 1; }
  source_hash=$(sha256sum "$receipt/source.snapshot"|cut -d' ' -f1)
  source_after_hash=$(printf '%s\n' "$source_after"|sha256sum|cut -d' ' -f1)
  binary_hash=$(sha256sum "$receipt/rrtransport.bin"|cut -d' ' -f1)
  load_after=$(cut -d' ' -f1 /proc/loadavg)
  awk -v load="$load_after" -v cpus="$cpus" 'BEGIN {exit !(load < cpus/4)}' || { echo "post-run load too high" >&2; exit 1; }
  mapfile -t governors_after < <(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
  [[ ${governors_after[*]} == performance ]] || { echo "governor changed" >&2; exit 1; }
  ! pgrep -x 'bird|bgpd|gobgpd' >/dev/null || { echo "competitor started" >&2; exit 1; }
  [[ $swap_before == "$swap_after" ]] || { echo "swap changed" >&2; exit 1; }
  printf '{"head_before":"%s","head_after":"%s","tree_before":"%s","tree_after":"%s","source_sha256":"%s","source_after_sha256":"%s","binary_sha256":"%s","governors":["performance"],"load_before":"%s","load_after":"%s","swap_before_kib":%s,"swap_after_kib":%s,"rustc":"%s","host":"%s","competitors":[]}\n' \
    "$head_before" "$head_after" "$tree_before" "$tree_after" "$source_hash" "$source_after_hash" "$binary_hash" "$load_before" "$load_after" "$swap_before" "$swap_after" "$(rustc -V)" "$(uname -srvmo)" >"$receipt/provenance.json"
  [[ $source_before == "$source_after" ]] || { echo "declared sources changed" >&2; exit 1; }
  : >"$receipt/verifier.txt"; python3 "$verifier" "$receipt" | tee "$receipt/verifier.txt"
  (cd "$receipt" && sha256sum phase.json per-peer.tsv rss.json rss.tsv provenance.json source.snapshot rrtransport.bin verifier.txt harness.log >SHA256SUMS && sha256sum -c SHA256SUMS)
done
