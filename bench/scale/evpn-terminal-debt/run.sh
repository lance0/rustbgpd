#!/usr/bin/env bash
# Run an already-built campaign, or with --compare an already-built
# parent-versus-candidate comparison, under the shared host mutex.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(git -C "$here" rev-parse --show-toplevel)
runner=sources/candidate/bench/scale/evpn-terminal-debt/terminal.py
if [[ ${1:-} == --compare ]]; then
    runner=parent/sources/candidate/bench/scale/evpn-terminal-debt/compare.py
    shift
fi
[[ $# == 1 || ( $# == 2 && $2 == --correctness-only ) ]] || {
    echo 'usage: run.sh [--compare] CAMPAIGN [--correctness-only]' >&2
    exit 2
}
# shellcheck source=tests/soak/host-lock.sh
source "$repository/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
export RUSTBGPD_HOST_LOCK_FD PYTHONDONTWRITEBYTECODE=1
exec python3 -B "$1/$runner" run "$@"
