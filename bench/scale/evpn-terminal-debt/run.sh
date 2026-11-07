#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(git -C "$here" rev-parse --show-toplevel)
[[ $# == 1 || ( $# == 2 && $2 == --correctness-only ) ]] || exit 2
# shellcheck source=tests/soak/host-lock.sh
source "$repository/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
export RUSTBGPD_HOST_LOCK_FD PYTHONDONTWRITEBYTECODE=1
exec python3 -B "$1/sources/candidate/bench/scale/evpn-terminal-debt/terminal.py" run "$@"
