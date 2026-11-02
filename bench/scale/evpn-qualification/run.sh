#!/usr/bin/env bash
# Run already-built cells under the shared host mutex.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(git -C "$here" rev-parse --show-toplevel)
mode=qualify.py
if [[ ${1:-} == --recovery ]]; then
    mode=recovery.py
    shift
fi
[[ $# == 1 || ( $# == 2 && $2 == --correctness-only ) ]] || {
    echo 'usage: run.sh [--recovery] CAMPAIGN [--correctness-only]' >&2
    exit 2
}
# shellcheck source=tests/soak/host-lock.sh
source "$repository/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
export RUSTBGPD_HOST_LOCK_FD
# Each measured cell checks the frozen UTC window, passes the quiet-host gate,
# and rechecks the window before launching its child. This runner installs no timer.
# Run the committed consumer from the frozen campaign, without introducing
# __pycache__ files into its verified source export.
export PYTHONDONTWRITEBYTECODE=1
exec python3 -B "$1/sources/candidate/bench/scale/evpn-qualification/$mode" run "$@"
