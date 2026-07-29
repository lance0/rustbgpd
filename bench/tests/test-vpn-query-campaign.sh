#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner=$root/bench/run-vpn-query-campaign.sh
verifier=$root/bench/verify-vpn-query-campaign.py

bash -n "$runner"
python3 -m unittest -v "$root/bench/tests/test_verify_vpn_query_campaign.py"

grep -F 'for size in 10000 100000 1000000' "$runner" >/dev/null
grep -F 'for repetition in 1 2 3 4 5 6 7 8' "$runner" >/dev/null
grep -F 'for case in U F' "$runner" >/dev/null
grep -F 'campaign must contain exactly 48 timing receipts' "$verifier" >/dev/null

mutated=$(mktemp)
trap 'rm -f "$mutated"' EXIT
sed 's/for case in U F/for case in F U/' "$runner" >"$mutated"
if grep -F 'for case in U F' "$mutated" >/dev/null; then
    echo "reordered campaign unexpectedly passed fixed-order gate" >&2
    exit 1
fi
