#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
sampler="$repo/bench/scale/matrix/rss-sampler.sh"
matrix="$repo/bench/scale/matrix/run-matrix.sh"
tmp=$(mktemp -d)
cleanup() {
    if [ -n "${sampler_pid:-}" ]; then
        kill "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
cg="$tmp/cgroup"
mkdir "$cg"
printf '2097152\n' >"$cg/memory.current"
printf '4194304\n' >"$cg/memory.peak"
printf '0\n' >"$cg/memory.swap.max"

# Use the producer's real functions, without launching a matrix cell.
# shellcheck disable=SC1090 # The extracted function names are checked by this fixture.
source <(sed -n '/^record_scope_memory() {/,/^}/p; /^scope_stat_rows() {/,/^}/p; /^last_sample_stat_rows() {/,/^}/p' "$matrix")

write_stat() {
    printf '%s\n' "$1" >"$cg/memory.stat.next"
    mv "$cg/memory.stat.next" "$cg/memory.stat"
}
wait_for_rows() {
    local expected=$1 deadline=$((SECONDS + 5))
    while [ ! -f "$tmp/rss.csv" ] || [ "$(wc -l <"$tmp/rss.csv")" -lt "$expected" ]; do
        [ "$SECONDS" -lt "$deadline" ] || { echo 'RSS sampler did not produce the expected row' >&2; exit 1; }
        sleep 0.02
    done
}
wait_for_updated_stat() {
    local deadline=$((SECONDS + 5))
    until awk -F, 'END { exit !($5 == 6 && $6 == 5 && $7 == 4) }' "$tmp/rss.csv"; do
        [ "$SECONDS" -lt "$deadline" ] || { echo 'RSS sampler missed the updated stat' >&2; exit 1; }
        sleep 0.02
    done
}

write_stat $'file_mapped 1024\nfile 2048\nanon 3072'
"$sampler" "$$" "$tmp/rss.csv" 0.2 "$cg" &
sampler_pid=$!
wait_for_rows 2
awk -F, 'END { exit !($5 == 3 && $6 == 2 && $7 == 1) }' "$tmp/rss.csv"
write_stat $'anon 6144\nfile 5120\nfile_mapped 4096'
wait_for_updated_stat
kill "$sampler_pid"
wait "$sampler_pid" || true
sampler_pid=

last=$(last_sample_stat_rows "$tmp/rss.csv")
[ "$last" = $'cg_last_sample_anon: 6 kB\ncg_last_sample_file: 5 kB\ncg_last_sample_file_mapped: 4 kB' ]
printf '123,10,1,,,,\n' >>"$tmp/rss.csv" # Teardown read lost the cgroup.
[ "$(last_sample_stat_rows "$tmp/rss.csv")" = "$last" ]
write_stat $'anon 9216\nfile 8192\nfile_mapped 7168'
record_scope_memory "$cg" "$tmp/cgroup-memory" "$last"
rg -q '^cg_last_sample_anon: 6 kB$' "$tmp/cgroup-memory"
rg -q '^cg_teardown_anon: 9 kB$' "$tmp/cgroup-memory"
printf '124,10,1,2,3,,4\n' >>"$tmp/rss.csv"
if last_sample_stat_rows "$tmp/rss.csv" >/dev/null; then
    echo 'partial cgroup RSS row was accepted' >&2
    exit 1
fi

for bad in \
    $'anon 1024\nfile 2048' \
    $'anon 1024\nanon 2048\nfile 2048\nfile_mapped 512' \
    $'anon nope\nfile 2048\nfile_mapped 512' \
    $'anon 1024 extra\nfile 2048\nfile_mapped 512'; do
    write_stat "$bad"
    if scope_stat_rows "$cg" teardown >/dev/null; then
        echo 'malformed memory.stat was accepted by teardown producer' >&2
        exit 1
    fi
    rc=0
    timeout 4s "$sampler" "$$" "$tmp/bad.csv" 0.2 "$cg" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
        echo 'malformed memory.stat was accepted or did not stop the sampler' >&2
        exit 1
    fi
done
printf 'cgroup memory stat sampling passed\n'
