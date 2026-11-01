#!/usr/bin/env python3
"""Split the workspace test binaries across CI's `core tests` shards.

Each shard runs on its own runner and builds the identical
`cargo test --locked --workspace` target set, then runs only its own
selectors. Shards never share a host: the CLI doctor tests discover live
daemon processes, and several tests own process-global signal state.

`args SHARD` prints the shard's Cargo target selectors. `check FILE` reads
the `--message-format=json` output of
`cargo test --locked --workspace --no-run` and fails unless every test
executable that command built belongs to exactly one shard, so a new test
target cannot silently drop out of CI. Doc tests run once, in DOC_SHARD.

Balanced on hosted per-binary run times: the daemon's own unit tests and the
root package's daemon-driving integration tests in shard 1; every library,
the remaining crates' integration tests and rustdoc in shard 2.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

DOC_SHARD = "2"
SHARDS = {
    "1": [
        "--bins",
        *(
            f"--test={name}"
            for name in (
                "architecture_contract",
                "atomic_aggregate_passthrough",
                "bgpkit_differential",
                "bmp_buffer_receipt_check",
                "check_strict",
                "cli_invocation",
                "commit_confirm_binary",
                "config_import_emitted_check",
                "config_migration",
                "config_persistence_lifecycle",
                "daemon_stdout_closed",
                "evpn_auto_lacp_binary",
                "evpn_core_isolation_binary",
                "evpn_dataplane_rr_only",
                "evpn_instances_binary",
                "fast_external_failover_binary",
                "global_export_reconnect",
                "grpc_failure_exit_code",
                "interface_only_check",
                "interface_only_neighbors_binary",
                "interop_policy_explain",
                "interop_tier_auth_dataplane",
                "interop_tier_auth_rr",
                "interop_topology_commands",
                "lib_module_mirror",
                "manrs_action1_example",
                "mcp_smoke",
                "mrt_real_differential",
                "outbound_prefix_limits",
                "peer_scoped_views_unknown_peer",
                "quickstart_dynamic_neighbor",
                "rbgp_mtls",
                "reloadstall_scenario_emitted_check",
                "rs_config_render_emitted_check",
                "rs_config_render_member_churn",
                "rs_config_render_multi_router_member",
                "rs_config_render_rejected_reload",
                "rs_config_render_rpki_invalid_export",
                "runtime_config_persistence_failstop",
                "runtime_config_settlement_matrix",
                "starter_configs_check_strict",
            )
        ),
    ],
    "2": [
        "--lib",
        *(
            f"--test={name}"
            for name in (
                "activation",
                "argument_errors",
                "as_path_extended_message_bound",
                "attribution_allocations",
                "birdwatcher_adapter_smoke",
                "config_import",
                "config_transaction_exit_codes",
                "daemon",
                "daemon_wide_confirmation",
                "diff_snapshots",
                "evpn_explain",
                "evpn_peer_views",
                "exit_codes",
                "export_fanout_attr_memo",
                "family_rib_pages",
                "flowspec_json",
                "flowspec_redirect_ip",
                "golden",
                "health",
                "help",
                "injection_owner",
                "inventory_contract",
                "ixp_manager",
                "ixp_manager_lifecycle",
                "label_stack_receive",
                "lifecycle",
                "listener",
                "memory_profile",
                "mutation_deadlines",
                "netns_ac_gate",
                "netns_bgp_unnumbered",
                "netns_bond_lacp",
                "netns_bum_filter",
                "netns_dataplane",
                "netns_fdb_nhg",
                "netns_flood",
                "netns_foreign_state",
                "netns_l3_install",
                "netns_link_carrier",
                "netns_managed_netdev",
                "netns_nexthop_raw",
                "netns_svd",
                "notification_registry",
                "path_attribute_layout",
                "path_attribute_registry",
                "policy_check_gate",
                "policy_coverage",
                "policy_diagnostic_color",
                "proptest_fsm",
                "proptest_roundtrip",
                "public_enum_contract",
                "read_deadlines",
                "readme_contract",
                "reconcile_actor",
                "recover",
                "replay",
                "rib_explain",
                "rib_injection_outcome",
                "route_data_sharing_profile",
                "rpki_aspa",
                "runtime_config_settlement_exit",
                "session_lifecycle",
                "shutdown_error",
                "site_local",
                "stdio_e2e",
                "stdout_closed",
                "tui_signal_restore",
                "type5_gateway_ip_self_consistency",
                "unicast_prefix_peers_memory",
                "update_group_policy_label_profile",
                "update_group_source_control_profile",
            )
        ),
    ],
}


def built_targets(lines: list[str]) -> set[tuple[str, str]]:
    """(kind, name) of every test executable in Cargo's JSON build output."""
    targets = set()
    for line in lines:
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if (
            message.get("reason") != "compiler-artifact"
            or not message.get("executable")
            or not message.get("profile", {}).get("test")
        ):
            continue
        kind = message["target"]["kind"][0]
        if kind not in {"bin", "test", "example", "bench"}:
            kind = "lib"  # lib, rlib, proc-macro, ...: all selected by --lib
        targets.add((kind, message["target"]["name"]))
    return targets


def check(targets: set[tuple[str, str]], shards: dict[str, list[str]]) -> list[str]:
    errors = []
    owners: dict[tuple[str, str], list[str]] = defaultdict(list)
    for shard, selectors in shards.items():
        for selector in selectors:
            if selector == "--lib":
                selected = {t for t in targets if t[0] == "lib"}
            elif selector == "--bins":
                selected = {t for t in targets if t[0] == "bin"}
            elif selector.startswith("--test="):
                selected = {t for t in targets if t == ("test", selector.removeprefix("--test="))}
            else:
                errors.append(f"shard {shard}: unsupported selector {selector}")
                continue
            if not selected:
                errors.append(f"shard {shard}: {selector} selects no built test target")
            for target in selected:
                owners[target].append(shard)
    for target in sorted(targets):
        found = owners.get(target, [])
        if len(found) != 1:
            where = "no shard" if not found else f"shards {', '.join(found)}"
            errors.append(f"{target[0]} target {target[1]} is in {where}")
    if not targets:
        errors.append("the build output lists no test executables")
    if DOC_SHARD not in shards:
        errors.append(f"doc-test shard {DOC_SHARD} is not a shard")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "args" and argv[1] in SHARDS:
        print(" ".join(SHARDS[argv[1]]))
        return 0
    if len(argv) == 2 and argv[0] == "check":
        with open(argv[1], encoding="utf-8") as output:
            errors = check(built_targets(output.read().splitlines()), SHARDS)
        if errors:
            print("core test shard check failed:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("core test shards cover every workspace test target exactly once")
        return 0
    print(f"usage: {sys.argv[0]} args {{{','.join(SHARDS)}}} | check CARGO_JSON", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
