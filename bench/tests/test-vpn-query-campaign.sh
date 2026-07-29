#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner=$root/bench/run-vpn-query-campaign.sh
verifier=$root/bench/verify-vpn-query-campaign.py

bash -n "$runner"
python3 -m unittest -v "$root/bench/tests/test_verify_vpn_query_campaign.py"
python3 "$verifier" --help >/dev/null
