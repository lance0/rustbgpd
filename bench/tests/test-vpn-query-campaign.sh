#!/usr/bin/env bash
# shellcheck disable=SC2016 # Structural literals intentionally retain shell variables.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner=$root/bench/run-vpn-query-campaign.sh
verifier=$root/bench/verify-vpn-query-campaign.py

check_verifier_gates() {
    python3 - "$1" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
invocation = 'python3 "$root/bench/verify-vpn-query-campaign.py" "$output"'
pattern = re.compile(
    r'''set \+e\n[ \t]*python3 "\$root/bench/verify-vpn-query-campaign\.py" "\$output" \\\n'''
    r'''[ \t]*--output "\$output/classification\.json" \\\n'''
    r'''[ \t]*--fail-on-regression\n'''
    r'''[ \t]*verifier_status=\$\?\n'''
    r'''[ \t]*set -e\n'''
    r'''[ \t]*check_provenance\n'''
    r'''[ \t]*exit "\$verifier_status"'''
)
if text.count(invocation) != 3:
    raise SystemExit("expected exactly three retained verifier invocations")
if text.count("--fail-on-regression") != 3 or len(pattern.findall(text)) != 3:
    raise SystemExit("every retained verifier must gate, re-enable errexit, check provenance, and return its status")
PY
}

bash -n "$runner"
python3 -m unittest -v "$root/bench/tests/test_verify_vpn_query_campaign.py"
help=$(COLUMNS=200 python3 "$verifier" --help)
[[ $help == *"Classification is advisory unless --fail-on-regression is selected."* ]]
[[ $help == *"default: advisory exit 0"* ]]
check_verifier_gates "$runner"
[[ $(grep -Fc '.checked_mul(' "$root/crates/api/benches/vpn_query/mod.rs") -eq 2 && $(grep -Fc '.checked_add(' "$root/crates/api/benches/vpn_query/mod.rs") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_$target"' "$runner") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_timing"' "$runner") -eq 1 ]]
[[ $(grep -Fc 'taskset -c "$declared_cpu" "$output/bin/vpn_query_allocation"' "$runner") -eq 1 ]]
[[ $(grep -Fc '"declared_cpu": int(cpu), "linux_affinity": affinity' "$runner") -eq 1 ]]

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
missing_gate_runner=$tmp_dir/run-vpn-query-campaign-missing-gate.sh
cp "$runner" "$missing_gate_runner"
sed -i '0,/--fail-on-regression/{/--fail-on-regression/d;}' "$missing_gate_runner"
if check_verifier_gates "$missing_gate_runner" >/dev/null 2>&1; then
    echo "structural guard accepted a retained verifier without the gate" >&2
    exit 1
fi
set +e
env RUSTBGPD_VPN_QUERY_FORCE_CENSOR= "$runner" "$tmp_dir/output" >/dev/null 2>&1
status=$?
set -e
[[ $status -eq 2 ]]
[[ ! -e "$tmp_dir/output" ]]
