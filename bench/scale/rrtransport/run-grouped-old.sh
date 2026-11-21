#!/usr/bin/env bash
# run-grouped-old.sh BINARY NEW_OUTPUT_DIR smoke|smoke-chunked|150x37000|700x400000
# Full shapes are report-only measurements: they need the shared host lock,
# the quiet gate and a host with no compiler. Both smokes exercise correctness
# only, so a compiler seen during one is recorded and does not stop it.
set -euo pipefail
if [[ $# != 3 || ! -x $1 ]]; then
    echo "usage: $0 BINARY NEW_OUTPUT_DIR smoke|smoke-chunked|150x37000|700x400000" >&2
    exit 2
fi
case "$3" in
smoke|smoke-chunked) measured=0 ;;
150x37000|700x400000)
    measured=1
    expected_lock="$HOME/.local/state/rustbgpd-host.lock"
    if [[ $(realpath -m "${RUSTBGPD_HOST_LOCK:-$expected_lock}") != "$(realpath -m "$expected_lock")" ]]; then
        echo "full shapes require the shared host lock at $expected_lock" >&2
        exit 2
    fi
    ;;
*) echo "unknown shape $3" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
binary=$(realpath "$1")
output=$(realpath -m "$2")
# Never mix a failed or interrupted attempt with its retry.
mkdir -p "$(dirname "$output")"
mkdir "$output"
exec > >(tee -a "$output/runner.log") 2>&1
# shellcheck source=tests/soak/host-lock.sh
. "$root/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
# shellcheck source=bench/scale/host-quiet.sh
. "$here/../host-quiet.sh"
if [[ $measured == 1 ]]; then
    wait_for_rustbgpd_quiet_host "$output/quiet.tsv"
fi
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)"
unit="rrtransport-grouped-old-$(cat /proc/sys/kernel/random/uuid).scope"
sha256sum "$binary" > "$output/binary.sha256"
systemd-run --user --scope --quiet --unit="$unit" -p MemoryMax=64G -p MemorySwapMax=0 -- \
    python3 "$here/grouped_old.py" run "$binary" "$output" "$3" "$unit" ||
    { echo 'INVALID: could not complete scope supervision'; exit 2; }
python3 "$here/grouped_old.py" check "$output" "$3"
