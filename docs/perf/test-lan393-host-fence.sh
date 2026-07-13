#!/usr/bin/env bash
# Adversarial probes for the retained LAN-393 host-isolation helpers.
set -euo pipefail

export LAN393_LOAD_ONE_MAX=999
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$(dirname "$0")/lan393-host-fence.sh"

[[ "$LAN393_REQUIRED_LOAD_ONE_MAX" == 2.0 ]]

# Model the Linux TASK_COMM_LEN truncation used by `ps comm`, plus every
# repository benchmark family that can continue running after Cargo exits.
ps() {
    printf '%s\n' \
        '101 codec-91a /repo/target/release/deps/codec-91a --bench' \
        '102 fanout-91a /repo/target/release/deps/fanout-91a --bench' \
        '103 inbound_attrs-9 /repo/target/release/deps/inbound_attrs-91a --bench' \
        '104 rib_ops-91a /repo/target/release/deps/rib_ops-91a --bench' \
        '105 policy_eval-91a /repo/target/release/deps/policy_eval-91a --bench' \
        '106 explain_snapsho /repo/target/release/deps/explain_snapshot-91a --bench' \
        '107 validate-91a /repo/target/release/deps/validate-91a --bench' \
        '108 event_history_ /repo/target/release/deps/event_history_producer-91a --bench' \
        '109 rrharness /repo/bench/scale/rrharness/target/release/rrharness flood' \
        '110 reloadstall /repo/bench/scale/reloadstall/target/release/reloadstall' \
        '111 route_paging-9 /repo/target/release/deps/route_paging-91a --bench' \
        '112 rib_nlri_build /repo/target/release/deps/rib_nlri_build-91a --bench' \
        '113 evpn-tester /repo/bench/evpn-load/target/release/evpn-tester' \
        '114 evpn-monitor /repo/bench/evpn-load/target/release/evpn-monitor' \
        '115 python3 python3 bgperf2.py --bench-name another-run bench' \
        '116 sleep sleep 30'
}

snapshot=$(lan393_competing_process_snapshot)
[[ $(wc -l <<<"$snapshot") -eq 15 ]]
[[ "$snapshot" != *'sleep 30'* ]]

printf '%s\n' 'LAN-393 host-fence adversarial probes passed'
