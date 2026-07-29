#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner=$root/bench/run-vpn-query-campaign.sh
verifier=$root/bench/verify-vpn-query-campaign.py

bash -n "$runner"
python3 -m unittest -v "$root/bench/tests/test_verify_vpn_query_campaign.py"
python3 "$verifier" --help >/dev/null

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
set +e
env RUSTBGPD_VPN_QUERY_FORCE_CENSOR= "$runner" "$tmp_dir/output" >/dev/null 2>&1
status=$?
set -e
[[ $status -eq 2 ]]
[[ ! -e "$tmp_dir/output" ]]
