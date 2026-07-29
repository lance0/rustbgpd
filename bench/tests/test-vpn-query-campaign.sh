#!/usr/bin/env bash
# shellcheck disable=SC2016 # Structural literals intentionally retain shell variables.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner=$root/bench/run-vpn-query-campaign.sh
verifier=$root/bench/verify-vpn-query-campaign.py

bash -n "$runner"
python3 -m unittest -v "$root/bench/tests/test_verify_vpn_query_campaign.py"
python3 "$verifier" --help >/dev/null
[[ $(grep -Fc '.checked_mul(' "$root/crates/api/benches/vpn_query.rs") -eq 2 && $(grep -Fc '.checked_add(' "$root/crates/api/benches/vpn_query.rs") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_$target"' "$runner") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_timing"' "$runner") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_allocation"' "$runner") -eq 1 ]]
[[ $(grep -Fc '"declared_cpu": int(cpu), "linux_affinity": affinity' "$runner") -eq 1 ]]

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
set +e
env RUSTBGPD_VPN_QUERY_FORCE_CENSOR= "$runner" "$tmp_dir/output" >/dev/null 2>&1
status=$?
set -e
[[ $status -eq 2 ]]
[[ ! -e "$tmp_dir/output" ]]
