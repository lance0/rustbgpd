#!/usr/bin/env bash
# M38 smoke — Gate 8 observable DF election against a 2-PE rustbgpd
# Ethernet Segment.
#
# Asserts (see m38-evpn-df-election.clab.yml for full design notes):
#   1. PE1 reports DF=1 / NonDF=0 for (esi=...:01, vni=100) within ~30s.
#   2. PE2 reports DF=0 / NonDF=1 for the same key within ~30s.
#   3. After PE1 shuts down, PE2 promotes to DF (DF=1) and
#      `evpn_df_role_changes_total{esi=...,vni="100"}` increments.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m38-evpn-df-election.clab.yml
#   bash tests/interop/scripts/test-m38-evpn-df-election.sh
#   sudo containerlab destroy -t tests/interop/m38-evpn-df-election.clab.yml

set -eu

TOPO="m38-evpn-df-election"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
ESI="00:00:00:00:00:00:00:00:00:01"
VNI="100"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Scrape Prometheus from inside the named container at port 9179
# (configured in rustbgpd-m38-pe{1,2}.toml).
prom_scrape() {
    local container=${1:?}
    docker exec "$container" wget -qO- http://127.0.0.1:9179/metrics 2>/dev/null \
        || docker exec "$container" curl -sf http://127.0.0.1:9179/metrics 2>/dev/null \
        || true
}

# Read the current value of evpn_df_role for the given role label.
# Returns "0", "1", or "" if the metric line isn't yet emitted.
prom_df_role() {
    local container=${1:?}
    local role=${2:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" -v role="$role" '
            $0 ~ /^evpn_df_role\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") \
                && index($0, "role=\"" role "\"") {
                print $NF
                exit
            }
        '
}

prom_df_role_changes() {
    local container=${1:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" '
            $0 ~ /^evpn_df_role_changes_total\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") {
                print $NF
                exit
            }
        '
}

wait_for_role() {
    local container=${1:?}
    local role=${2:?}
    local want=${3:?}
    local timeout=${4:-30}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(prom_df_role "$container" "$role")
        if [ "$got" = "$want" ]; then return 0; fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
TOTAL=0

assert() {
    local desc=${1:?}
    local cmd=${2:?}
    TOTAL=$((TOTAL + 1))
    if eval "$cmd"; then
        echo "PASS — $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL — $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Wait for the segment orchestrator to settle. We don't have a
# direct signal here, so poll Prometheus.
echo "Waiting up to 30s for initial DF election to land..."

assert "PE1 reports DF=1 for (esi=$ESI, vni=$VNI)" \
    'wait_for_role "$PE1" df 1 30'

assert "PE1 reports NonDF=0 for the same key" \
    '[ "$(prom_df_role "$PE1" nondf)" = "0" ]'

assert "PE2 reports DF=0 for (esi=$ESI, vni=$VNI)" \
    'wait_for_role "$PE2" df 0 30'

assert "PE2 reports NonDF=1 for the same key" \
    '[ "$(prom_df_role "$PE2" nondf)" = "1" ]'

# Capture PE2's transition counter before forcing the flip.
PE2_BEFORE=$(prom_df_role_changes "$PE2")
PE2_BEFORE=${PE2_BEFORE:-0}
echo "PE2 evpn_df_role_changes_total before PE1 shutdown: $PE2_BEFORE"

# Shutdown PE1; PE2 should promote.
echo "Stopping PE1 to force DF promotion on PE2..."
docker stop -t 5 "$PE1" >/dev/null

echo "Waiting up to 30s for PE2 to promote to DF..."
assert "PE2 promotes to DF after PE1 shutdown" \
    'wait_for_role "$PE2" df 1 30'

# The transition counter should have advanced by at least 1.
PE2_AFTER=$(prom_df_role_changes "$PE2")
PE2_AFTER=${PE2_AFTER:-0}
echo "PE2 evpn_df_role_changes_total after promotion: $PE2_AFTER"
assert "PE2 evpn_df_role_changes_total advanced after promotion" \
    'awk -v b="$PE2_BEFORE" -v a="$PE2_AFTER" "BEGIN { exit !(a > b) }"'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "M38 smoke: $PASS/$TOTAL passed, $FAIL failed."
[[ $FAIL -eq 0 ]]
