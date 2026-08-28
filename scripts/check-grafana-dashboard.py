#!/usr/bin/env python3
"""Validate the shipped Grafana dashboard's load-bearing operator views."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "docs/grafana/rustbgpd-overview.json"
EVPN_DASHBOARD = ROOT / "docs/grafana/rustbgpd-evpn.json"
METRICS = ROOT / "crates/telemetry/src/metrics.rs"

# Exact registered source contract at the dashboard's Alpha boundary. The
# ticket's older family count is deliberately not trusted: any telemetry-side
# add/remove/type/label drift must update this inventory before a panel can use
# it. Scrape-added `instance`/`job` labels are validated separately.
EVPN_METRICS: dict[str, tuple[str, tuple[str, ...]]] = {
    "evpn_local_originations_total": ("counter", ("action",)),
    "evpn_local_origination_errors_total": ("counter", ("action",)),
    "evpn_local_observations_dropped_total": ("counter", ("reason",)),
    "evpn_duplicate_mac_moves_total": ("counter", ("vni", "mac")),
    "evpn_duplicate_mac_first_move_timestamp_seconds": ("gauge", ("vni", "mac")),
    "evpn_duplicate_mac_threshold_exceeded_total": (
        "counter",
        ("vni", "mac", "action"),
    ),
    "evpn_duplicate_mac_quarantine_active": ("gauge", ("vni", "mac")),
    "evpn_df_role": ("gauge", ("esi", "vni", "role")),
    "evpn_es_ac_gate": ("gauge", ("esi", "state")),
    "evpn_df_role_changes_total": ("counter", ("esi", "vni")),
    "evpn_es_drained": ("gauge", ("esi", "reason")),
    "evpn_ip_vrf_observed_routes": ("gauge", ("vrf",)),
    "evpn_ip_vrf_observed_routes_filtered_total": (
        "counter",
        ("vrf", "reason"),
    ),
    "evpn_ip_vrf_origination_suppressed_total": (
        "counter",
        ("vrf", "reason"),
    ),
    "evpn_ip_vrf_originated_routes": ("gauge", ("vrf",)),
    "evpn_ip_vrf_installed_routes": ("gauge", ("vrf",)),
    "evpn_ip_vrf_remote_prefix_drops": ("gauge", ("vrf", "reason")),
    "evpn_managed_netdev_state": (
        "gauge",
        ("class", "name", "desired", "state"),
    ),
    "evpn_fdb_nhg_drift_members_repaired_total": ("counter", ()),
    "evpn_fdb_nhg_drift_groups_replaced_total": ("counter", ()),
    "evpn_fdb_nhg_orphans_cleaned_total": ("counter", ()),
    "evpn_fdb_nhg_drift_disabled_total": ("counter", ()),
    "evpn_fdb_single_dst_adopted_total": ("counter", ()),
    "evpn_fdb_single_dst_reaped_total": ("counter", ()),
    "evpn_l3_route_adopted_total": ("counter", ()),
    "evpn_l3_route_reaped_total": ("counter", ()),
    "evpn_l3_neighbor_adopted_total": ("counter", ()),
    "evpn_l3_neighbor_reaped_total": ("counter", ()),
    "evpn_l3vxlan_fdb_adopted_total": ("counter", ()),
    "evpn_l3vxlan_fdb_reaped_total": ("counter", ()),
    "evpn_single_active_backup_swaps_total": ("counter", ()),
    "evpn_single_active_teardowns_total": ("counter", ()),
    "evpn_foreign_replaces_blocked_total": ("counter", ()),
    "evpn_foreign_deletes_skipped_total": ("counter", ()),
    "evpn_foreign_owned_relinquished_total": ("counter", ()),
    "evpn_foreign_nhid_range_conflicts_total": ("counter", ()),
    "evpn_single_active_backup_active": ("gauge", ()),
    "evpn_runtime_decomposed_fail_stops_total": ("counter", ()),
}

EVPN_VARIABLES = {
    "instance": 'label_values(bgp_rib_outbound_registered_peers, instance)',
    "vrf": 'label_values(evpn_ip_vrf_observed_routes{instance=~"$instance"}, vrf)',
}

EVPN_REQUIRED_ROWS = {
    "Type-2 / Type-3 / Type-5 and IP-VRF state",
    "DF, attachment circuits, and drain",
    "Duplicate-MAC quarantine",
    "Dataplane repair, adoption, and single-active state",
    "Ownership conflicts and fail-stops",
}

EVPN_REQUIRED_PANELS = {
    "EVPN Loc-RIB (all route types)": {"bgp_rib_loc_prefixes"},
    "Type-2 local origination actions, errors, and drops": {
        "evpn_local_originations_total",
        "evpn_local_origination_errors_total",
        "evpn_local_observations_dropped_total",
    },
    "Type-5 IP-VRF route state": {
        "evpn_ip_vrf_observed_routes",
        "evpn_ip_vrf_originated_routes",
        "evpn_ip_vrf_installed_routes",
    },
    "Type-5 filtering, suppression, and projection drops": {
        "evpn_ip_vrf_observed_routes_filtered_total",
        "evpn_ip_vrf_origination_suppressed_total",
        "evpn_ip_vrf_remote_prefix_drops",
    },
    "Active DF assignments": {"evpn_df_role"},
    "Attachment-circuit gate state": {"evpn_es_ac_gate"},
    "Ethernet-segment drain reasons": {"evpn_es_drained"},
    "DF role changes": {"evpn_df_role_changes_total"},
    "Quarantined local Type-2 keys": {"evpn_duplicate_mac_quarantine_active"},
    "Duplicate-MAC contention activity": {
        "evpn_duplicate_mac_moves_total",
        "evpn_duplicate_mac_threshold_exceeded_total",
    },
    "Time since first recorded move for active quarantines": {
        "evpn_duplicate_mac_first_move_timestamp_seconds",
        "evpn_duplicate_mac_quarantine_active",
    },
    "Managed netdev state": {"evpn_managed_netdev_state"},
    "FDB-NHG repair and cleanup": {
        "evpn_fdb_nhg_drift_members_repaired_total",
        "evpn_fdb_nhg_drift_groups_replaced_total",
        "evpn_fdb_nhg_orphans_cleaned_total",
        "evpn_fdb_nhg_drift_disabled_total",
    },
    "Startup adoption and deferred reap": {
        "evpn_fdb_single_dst_adopted_total",
        "evpn_fdb_single_dst_reaped_total",
        "evpn_l3_route_adopted_total",
        "evpn_l3_route_reaped_total",
        "evpn_l3_neighbor_adopted_total",
        "evpn_l3_neighbor_reaped_total",
        "evpn_l3vxlan_fdb_adopted_total",
        "evpn_l3vxlan_fdb_reaped_total",
    },
    "Single-active failover state": {
        "evpn_single_active_backup_active",
        "evpn_single_active_backup_swaps_total",
        "evpn_single_active_teardowns_total",
    },
    "Foreign ownership conflicts": {
        "evpn_foreign_replaces_blocked_total",
        "evpn_foreign_deletes_skipped_total",
        "evpn_foreign_owned_relinquished_total",
        "evpn_foreign_nhid_range_conflicts_total",
    },
    "Runtime decomposed fail-stops": {"evpn_runtime_decomposed_fail_stops_total"},
}

# These expressions are operator semantics, not presentation. Pinning them
# keeps comparisons, aggregation, active-state joins, and the absence of
# zero-fill fallbacks load-bearing without implementing a PromQL parser.
EVPN_TARGETS: dict[tuple[str, str], tuple[str, str]] = {
    ("EVPN Loc-RIB (all route types)", "A"): (
        'sum by (instance) (bgp_rib_loc_prefixes{instance=~"$instance",afi_safi="evpn"})',
        "{{instance}} all EVPN types",
    ),
    ("Type-2 local origination actions, errors, and drops", "A"): (
        'sum by (instance, action) (rate(evpn_local_originations_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} success {{action}}/s",
    ),
    ("Type-2 local origination actions, errors, and drops", "B"): (
        'sum by (instance, action) (rate(evpn_local_origination_errors_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} error {{action}}/s",
    ),
    ("Type-2 local origination actions, errors, and drops", "C"): (
        'sum by (instance, reason) (rate(evpn_local_observations_dropped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} observation drop {{reason}}/s",
    ),
    ("Type-5 IP-VRF route state", "A"): (
        'sum by (instance, vrf) (evpn_ip_vrf_observed_routes{instance=~"$instance",vrf=~"$vrf"})',
        "{{instance}} {{vrf}} observed",
    ),
    ("Type-5 IP-VRF route state", "B"): (
        'sum by (instance, vrf) (evpn_ip_vrf_originated_routes{instance=~"$instance",vrf=~"$vrf"})',
        "{{instance}} {{vrf}} originated",
    ),
    ("Type-5 IP-VRF route state", "C"): (
        'sum by (instance, vrf) (evpn_ip_vrf_installed_routes{instance=~"$instance",vrf=~"$vrf"})',
        "{{instance}} {{vrf}} installed",
    ),
    ("Type-5 filtering, suppression, and projection drops", "A"): (
        'sum by (instance, vrf, reason) (rate(evpn_ip_vrf_observed_routes_filtered_total{instance=~"$instance",vrf=~"$vrf"}[$__rate_interval]))',
        "{{instance}} {{vrf}} filtered {{reason}}/s",
    ),
    ("Type-5 filtering, suppression, and projection drops", "B"): (
        'sum by (instance, vrf, reason) (rate(evpn_ip_vrf_origination_suppressed_total{instance=~"$instance",vrf=~"$vrf"}[$__rate_interval]))',
        "{{instance}} {{vrf}} suppressed {{reason}}/s",
    ),
    ("Type-5 filtering, suppression, and projection drops", "C"): (
        'sum by (instance, vrf, reason) (evpn_ip_vrf_remote_prefix_drops{instance=~"$instance",vrf=~"$vrf"})',
        "{{instance}} {{vrf}} current drop {{reason}}",
    ),
    ("Active DF assignments", "A"): (
        'sum by (instance, vni) (evpn_df_role{instance=~"$instance",role="df"} == 1)',
        "{{instance}} VNI {{vni}} DF assignments",
    ),
    ("Attachment-circuit gate state", "A"): (
        'sum by (instance, state) (evpn_es_ac_gate{instance=~"$instance"} == 1)',
        "{{instance}} {{state}} segments",
    ),
    ("Ethernet-segment drain reasons", "A"): (
        'sum by (instance, reason) (evpn_es_drained{instance=~"$instance"} == 1)',
        "{{instance}} {{reason}} drains",
    ),
    ("DF role changes", "A"): (
        'sum by (instance, vni) (rate(evpn_df_role_changes_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} VNI {{vni}} changes/s",
    ),
    ("Quarantined local Type-2 keys", "A"): (
        'sum by (instance) (evpn_duplicate_mac_quarantine_active{instance=~"$instance"} == 1)',
        "{{instance}} quarantined keys",
    ),
    ("Duplicate-MAC contention activity", "A"): (
        'sum by (instance) (rate(evpn_duplicate_mac_moves_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} moves/s",
    ),
    ("Duplicate-MAC contention activity", "B"): (
        'sum by (instance, action) (rate(evpn_duplicate_mac_threshold_exceeded_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} threshold {{action}}/s",
    ),
    ("Time since first recorded move for active quarantines", "A"): (
        'max by (instance) (clamp_min(time() - evpn_duplicate_mac_first_move_timestamp_seconds{instance=~"$instance"}, 0) and on (instance, vni, mac) (evpn_duplicate_mac_quarantine_active{instance=~"$instance"} == 1))',
        "{{instance}} since first recorded move",
    ),
    ("Managed netdev state", "A"): (
        'sum by (instance, class, state) (evpn_managed_netdev_state{instance=~"$instance"} == 1)',
        "{{instance}} {{class}} {{state}}",
    ),
    ("FDB-NHG repair and cleanup", "A"): (
        'sum by (instance) (rate(evpn_fdb_nhg_drift_members_repaired_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} members repaired/s",
    ),
    ("FDB-NHG repair and cleanup", "B"): (
        'sum by (instance) (rate(evpn_fdb_nhg_drift_groups_replaced_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} groups replaced/s",
    ),
    ("FDB-NHG repair and cleanup", "C"): (
        'sum by (instance) (rate(evpn_fdb_nhg_orphans_cleaned_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} orphans cleaned/s",
    ),
    ("FDB-NHG repair and cleanup", "D"): (
        'sum by (instance) (rate(evpn_fdb_nhg_drift_disabled_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} drift disabled/s",
    ),
    ("Startup adoption and deferred reap", "A"): (
        'sum by (instance) (rate(evpn_fdb_single_dst_adopted_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} FDB adopted/s",
    ),
    ("Startup adoption and deferred reap", "B"): (
        'sum by (instance) (rate(evpn_fdb_single_dst_reaped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} FDB reaped/s",
    ),
    ("Startup adoption and deferred reap", "C"): (
        'sum by (instance) (rate(evpn_l3_route_adopted_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} routes adopted/s",
    ),
    ("Startup adoption and deferred reap", "D"): (
        'sum by (instance) (rate(evpn_l3_route_reaped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} routes reaped/s",
    ),
    ("Startup adoption and deferred reap", "E"): (
        'sum by (instance) (rate(evpn_l3_neighbor_adopted_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} neighbors adopted/s",
    ),
    ("Startup adoption and deferred reap", "F"): (
        'sum by (instance) (rate(evpn_l3_neighbor_reaped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} neighbors reaped/s",
    ),
    ("Startup adoption and deferred reap", "G"): (
        'sum by (instance) (rate(evpn_l3vxlan_fdb_adopted_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} L3VXLAN FDB adopted/s",
    ),
    ("Startup adoption and deferred reap", "H"): (
        'sum by (instance) (rate(evpn_l3vxlan_fdb_reaped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} L3VXLAN FDB reaped/s",
    ),
    ("Single-active failover state", "A"): (
        'sum by (instance) (evpn_single_active_backup_active{instance=~"$instance"})',
        "{{instance}} backup active",
    ),
    ("Single-active failover state", "B"): (
        'sum by (instance) (rate(evpn_single_active_backup_swaps_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} swaps/s",
    ),
    ("Single-active failover state", "C"): (
        'sum by (instance) (rate(evpn_single_active_teardowns_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} teardowns/s",
    ),
    ("Foreign ownership conflicts", "A"): (
        'sum by (instance) (rate(evpn_foreign_replaces_blocked_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} replace blocked/s",
    ),
    ("Foreign ownership conflicts", "B"): (
        'sum by (instance) (rate(evpn_foreign_deletes_skipped_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} delete skipped/s",
    ),
    ("Foreign ownership conflicts", "C"): (
        'sum by (instance) (rate(evpn_foreign_owned_relinquished_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} ownership relinquished/s",
    ),
    ("Foreign ownership conflicts", "D"): (
        'sum by (instance) (rate(evpn_foreign_nhid_range_conflicts_total{instance=~"$instance"}[$__rate_interval]))',
        "{{instance}} NHID conflicts/s",
    ),
    ("Runtime decomposed fail-stops", "A"): (
        'sum by (instance) (increase(evpn_runtime_decomposed_fail_stops_total{instance=~"$instance"}[15m]))',
        "{{instance}} fail-stops/15m",
    ),
}

EVPN_TARGET_DATASOURCE = {"type": "prometheus", "uid": "${datasource}"}

EVPN_DISCRETE_PANELS = {
    "Active DF assignments",
    "Attachment-circuit gate state",
    "Ethernet-segment drain reasons",
    "Quarantined local Type-2 keys",
    "Managed netdev state",
}

VARIABLES = {
    "peer": 'label_values(bgp_peer_admin_enabled{instance=~"$instance"}, peer)',
}

TARGETS = {
    ("Peer administrative / session truth", "A"): (
        'bgp_peer_admin_enabled{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Peer administrative / session truth", "B"): (
        'bgp_peer_session_established{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound queue by peer", "A"): (
        'bgp_peer_outbound_queue_depth{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Event outbox health", "A"): (
        'max(bgp_event_outbox_degraded{instance=~"$instance"})'
    ),
    ("RIB ingest pressure", "B"): (
        "sum by (peer) (rate(bgp_inbound_rib_backpressure_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval]))'
    ),
    ("RIB ingest pressure", "C"): (
        "sum by (peer) (rate(bgp_outbound_route_drops_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval]))'
    ),
    ("Slow peers", "A"): (
        'bgp_peer_slow{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Update group by peer", "A"): (
        'bgp_peer_update_group{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Policy transition in progress", "A"): (
        'bgp_rib_policy_transition_in_progress{instance=~"$instance"}'
    ),
    ("Last completed policy transition", "A"): (
        'bgp_rib_policy_transition_last_duration_milliseconds{instance=~"$instance"}'
    ),
    ("Policy-transition actor poll p99", "A"): (
        "histogram_quantile(0.99, sum by (instance, job, poll_kind, le) "
        "(rate(bgp_rib_policy_transition_actor_poll_duration_seconds_bucket"
        '{instance=~"$instance"}[15m])))'
    ),
    ("Policy-transition actor polls over 200ms", "A"): (
        "increase(bgp_rib_policy_transition_actor_poll_duration_seconds_count"
        '{instance=~"$instance"}[15m]) - ignoring(le) '
        "increase(bgp_rib_policy_transition_actor_poll_duration_seconds_bucket"
        '{instance=~"$instance",le="0.2"}[15m])'
    ),
    ("Accepted policy generation age", "A"): (
        "clamp_min(time() - bgp_policy_generation_loaded_timestamp_seconds"
        '{instance=~"$instance"}, 0)'
    ),
    ("Max-prefix usage and finite limit", "A"): (
        'bgp_max_prefix_usage{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Max-prefix usage and finite limit", "B"): (
        'bgp_max_prefix_limit{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Max-prefix remaining headroom", "A"): (
        'bgp_max_prefix_headroom{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Export rejections / malformed UPDATEs / configured discards", "A"): (
        "sum by (instance, peer, family, reason) "
        "(rate(bgp_exact_export_rejections_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval])) > 0'
    ),
    ("Export rejections / malformed UPDATEs / configured discards", "B"): (
        "sum by (instance, peer, disposition) (rate(bgp_update_malformed_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval])) > 0'
    ),
    ("Export rejections / malformed UPDATEs / configured discards", "C"): (
        "sum by (instance, peer, type_code) (rate(bgp_path_attribute_discarded_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval])) > 0'
    ),
    ("Selection-deferral state", "A"): (
        'bgp_selection_deferral_active{instance=~"$instance"}'
    ),
    ("Selection-deferral state", "B"): (
        'bgp_selection_deferral_waiters{instance=~"$instance"}'
    ),
    ("Selection-deferral exceptional events", "A"): (
        "sum by (instance, afi_safi) (rate(bgp_selection_deferral_timeouts_total"
        '{instance=~"$instance"}[$__rate_interval])) > 0'
    ),
    ("Selection-deferral exceptional events", "B"): (
        "sum by (instance, afi_safi) "
        "(rate(bgp_selection_deferral_ledger_overflows_total"
        '{instance=~"$instance"}[$__rate_interval])) > 0'
    ),
    ("RFC 8212 missing policy", "A"): (
        'bgp_rfc8212_missing_import_policy{instance=~"$instance",peer=~"$peer"}'
    ),
    ("RFC 8212 missing policy", "B"): (
        'bgp_rfc8212_missing_export_policy{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "A"): (
        'bgp_outbound_prefix_usage{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "B"): (
        'bgp_outbound_prefix_limit{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "C"): (
        'bgp_outbound_prefix_headroom{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "D"): (
        'bgp_outbound_prefix_blocking{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Dynamic-neighbor admission capacity", "A"): (
        'bgp_dynamic_neighbor_slots_used{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission capacity", "B"): (
        'bgp_dynamic_neighbor_slots_limit{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission capacity", "C"): (
        'bgp_dynamic_neighbor_slots_headroom{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission rejections", "A"): (
        "rate(bgp_dynamic_neighbor_limit_rejections_total"
        '{instance=~"$instance"}[$__rate_interval]) > 0'
    ),
    ("ORR SPF activity and topology", "A"): (
        "sum by (instance) (rate(bgp_orr_spf_runs_total"
        '{instance=~"$instance"}[$__rate_interval]))'
    ),
    ("ORR SPF activity and topology", "B"): (
        'bgp_orr_topology_nodes{instance=~"$instance"}'
    ),
    ("ORR SPF activity and topology", "C"): (
        'bgp_orr_topology_links{instance=~"$instance"}'
    ),
    ("BLACKHOLE discard activity", "A"): (
        "rate(bgp_blackhole_discard_installed_total"
        '{instance=~"$instance"}[$__rate_interval])'
    ),
    ("BLACKHOLE discard activity", "B"): (
        "rate(bgp_blackhole_discard_withdrawn_total"
        '{instance=~"$instance"}[$__rate_interval])'
    ),
    ("BLACKHOLE active rows", "A"): (
        'bgp_blackhole_discard_active{instance=~"$instance"}'
    ),
}

REQUIRED_LEGENDS = {
    ("Peer administrative / session truth", "A"): "admin {{peer}} {{interface}}",
    ("Peer administrative / session truth", "B"): "session {{peer}} {{interface}}",
    ("Export rejections / malformed UPDATEs / configured discards", "A"): (
        "exact {{instance}} {{peer}} {{family}} {{reason}}"
    ),
    ("Export rejections / malformed UPDATEs / configured discards", "B"): (
        "malformed {{instance}} {{peer}} {{disposition}}"
    ),
    ("Export rejections / malformed UPDATEs / configured discards", "C"): (
        "discard {{instance}} {{peer}} type {{type_code}}"
    ),
    ("Selection-deferral state", "A"): "{{instance}} {{afi_safi}} active",
    ("Selection-deferral state", "B"): "{{instance}} {{afi_safi}} waiters",
    ("Selection-deferral exceptional events", "A"): "{{instance}} {{afi_safi}} timeout",
    ("Selection-deferral exceptional events", "B"): (
        "{{instance}} {{afi_safi}} ledger overflow"
    ),
    ("RFC 8212 missing policy", "A"): "{{peer}} missing import",
    ("RFC 8212 missing policy", "B"): "{{peer}} missing export",
    ("Outbound prefix capacity", "A"): "{{peer}} {{family}} usage",
    ("Outbound prefix capacity", "B"): "{{peer}} {{family}} limit",
    ("Outbound prefix capacity", "C"): "{{peer}} {{family}} headroom",
    ("Outbound prefix capacity", "D"): "{{peer}} {{family}} blocking",
    ("Dynamic-neighbor admission capacity", "A"): "{{instance}} used",
    ("Dynamic-neighbor admission capacity", "B"): "{{instance}} limit",
    ("Dynamic-neighbor admission capacity", "C"): "{{instance}} headroom",
    ("Dynamic-neighbor admission rejections", "A"): "{{instance}} rejected",
    ("RIB ingest pressure", "B"): "inbound safely parked {{peer}}",
    ("RIB ingest pressure", "C"): "outbound work lost {{peer}}",
    ("ORR SPF activity and topology", "A"): "{{instance}} SPF runs/s",
    ("ORR SPF activity and topology", "B"): "{{instance}} nodes",
    ("ORR SPF activity and topology", "C"): "{{instance}} usable links",
    ("BLACKHOLE discard activity", "A"): "{{instance}} installed/s",
    ("BLACKHOLE discard activity", "B"): "{{instance}} withdrawn/s",
    ("BLACKHOLE active rows", "A"): "{{instance}} active",
}

ROUTE_SAFETY_PANELS = {
    "Export rejections / malformed UPDATEs / configured discards": 0,
    "Selection-deferral state": 8,
    "Selection-deferral exceptional events": 16,
}

CAPACITY_PANELS = {
    "RFC 8212 missing policy",
    "Outbound prefix capacity",
    "Dynamic-neighbor admission capacity",
    "Dynamic-neighbor admission rejections",
}


def fail(message: str) -> None:
    print(f"dashboard check: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalized(expression: str) -> str:
    return " ".join(expression.split())


def all_panels(panels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for panel in panels:
        flattened.append(panel)
        children = panel.get("panels", [])
        if not isinstance(children, list):
            fail(f"panel {panel.get('id')} has a non-list panels field")
        flattened.extend(all_panels(children))
    return flattened


def rust_lex(source: str) -> tuple[str, list[str]]:
    """Mask Rust comments and literals, retaining string values as opaque tokens."""
    output: list[str] = []
    strings: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            depth, end = 1, index + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            output.append(" ")
            index = end
        else:
            raw = re.match(r'(?:br|r)(?P<hashes>#{0,255})"', source[index:])
            normal = re.match(r'(?:b)?"', source[index:])
            if raw:
                marker = '"' + raw.group("hashes")
                start = index + raw.end()
                end = source.find(marker, start)
                if end < 0:
                    raise ValueError("unterminated Rust raw string")
                value, index = source[start:end], end + len(marker)
            elif normal:
                start, end = index + normal.end(), index + normal.end()
                while end < len(source):
                    if source[end] == '"':
                        slashes = 0
                        while end > start + slashes and source[end - slashes - 1] == "\\":
                            slashes += 1
                        if slashes % 2 == 0:
                            break
                    end += 2 if source[end] == "\\" else 1
                if end >= len(source):
                    raise ValueError("unterminated Rust string")
                value, index = source[start:end], end + 1
            else:
                output.append(source[index])
                index += 1
                continue
            output.append(f"__RUST_STRING_{len(strings)}__")
            strings.append(value)
    return "".join(output), strings


def dashboard_metric_references(dashboard: dict[str, Any]) -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}

    def add(expression: object, context: str) -> None:
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError(f"empty query at {context}")
        syntax = re.sub(r'"(?:\\.|[^"\\])*"', '""', expression)
        if re.search(r"[A-Za-z_:][A-Za-z0-9_:]*:[A-Za-z0-9_:]*", syntax):
            raise ValueError(f"unsupported bare/colon metric alias at {context}: {expression}")
        names = re.findall(r"(?<![$\w:])([A-Za-z_:][A-Za-z0-9_:]*)\s*(?=\{)", syntax)
        if re.search(r"(?<![\w:])\{[^}]*__name__\s*=", syntax):
            raise ValueError(f"metric-less __name__ selector at {context}")
        remainder = re.sub(r"[A-Za-z_:][\w:]*\s*\{[^}]*\}", " ", syntax)
        remainder = re.sub(r"\{[^}]*\}|\[[^]]*\]|\$\w+", " ", remainder)
        remainder = re.sub(
            r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
            " ", remainder,
        )
        remainder = re.sub(r"\b[A-Za-z_]\w*\s*(?=\()", " ", remainder)
        aliases = re.findall(r"\b[A-Za-z_:][\w:]*\b", remainder)
        if aliases:
            raise ValueError(f"unsupported bare/colon metric alias at {context}: {aliases[0]}")
        for name in names:
            references.setdefault(name, []).append(context)
        if not names and "label_values" not in expression:
            raise ValueError(f"unsupported metric-free query at {context}: {expression}")

    for variable in dashboard.get("templating", {}).get("list", []):
        if variable.get("type") != "query":
            continue
        query = variable.get("query")
        match = re.fullmatch(r"\s*label_values\(\s*([A-Za-z_:][\w:]*)\s*(?:\{[^}]*\})?\s*,[^)]+\)\s*", str(query))
        if not match:
            raise ValueError(f"unsupported template query at ${variable.get('name')}: {query}")
        references.setdefault(match.group(1), []).append(f"${variable.get('name')}")
    for panel in all_panels(dashboard.get("panels", [])):
        for target in panel.get("targets", []):
            add(target.get("expr"), f"{panel.get('title')}/{target.get('refId')}")
    if not references:
        raise ValueError("no dashboard metric references discovered")
    return references


def rust_metric_inventory(source: str) -> dict[str, str]:
    source, strings = rust_lex(source)
    source = source.split("#[cfg(test)]", 1)[0]
    constructors: dict[str, tuple[str, str]] = {}
    pattern = re.compile(
        r"let\s+(\w+)\s*=\s*(IntCounter(?:Vec)?|IntGauge(?:Vec)?|HistogramVec)::new\(\s*"
        r"(?:(?:Opts|HistogramOpts)::new\(\s*)?__RUST_STRING_(\d+)__",
        re.DOTALL,
    )
    for variable, kind, string_index in pattern.findall(source):
        if variable in constructors:
            raise ValueError(f"ambiguous metric constructor variable {variable}")
        constructors[variable] = (strings[int(string_index)], "histogram" if kind == "HistogramVec" else "ordinary")
    registered = re.findall(
        r"\.register\(\s*Box::new\(\s*(\w+)\.clone\(\)\s*,?\s*\)\s*\)", source
    )
    inventory: dict[str, str] = {}
    for variable in registered:
        if variable not in constructors:
            continue
        name, kind = constructors[variable]
        if name in inventory:
            raise ValueError(f"duplicate registered metric name {name}")
        inventory[name] = kind
    if re.search(r"register\(\s*Box::new\(\s*jemalloc_stats::JemallocCollector::new\(\)\s*\)\s*\)", source):
        fields = set(re.findall(r"\b(\w+)\s*:\s*IntGauge\b", source))
        bodies = re.findall(r"(?<!-> )\bSelf\s*\{([^}]*)\}", source)
        wired: dict[str, set[str]] = {}
        for body in bodies:
            for entry in body.split(","):
                parts = [part.strip() for part in entry.split(":", 1)]
                field, variable = (parts[0], parts[-1])
                wired.setdefault(variable, set()).add(field)
        emitted = set(re.findall(r"self\.(\w+)\.collect\(\)", source))
        for variable, (name, kind) in constructors.items():
            if name.startswith("jemalloc_") and wired.get(variable, set()) & fields & emitted:
                inventory[name] = kind
    if not inventory:
        raise ValueError("no registered Rust metrics discovered")
    return inventory


def registered_metric_definitions(
    source: str,
) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Return directly registered Prometheus kind and constructor labels."""
    source, strings = rust_lex(source)
    source = source.split("#[cfg(test)]", 1)[0]
    constructors: dict[str, tuple[str, tuple[str, ...]]] = {}
    pattern = re.compile(
        r"let\s+(\w+)\s*=\s*"
        r"(IntCounter(?:Vec)?|IntGauge(?:Vec)?|HistogramVec)::new\("
        r"(.*?)\)\s*\.expect\(",
        re.DOTALL,
    )
    for variable, rust_kind, body in pattern.findall(source):
        tokens = [int(index) for index in re.findall(r"__RUST_STRING_(\d+)__", body)]
        if len(tokens) < 2:
            raise ValueError(f"metric constructor {variable} lacks name/help strings")
        name = strings[tokens[0]]
        labels = tuple(strings[index] for index in tokens[2:]) if rust_kind.endswith("Vec") else ()
        if rust_kind.startswith("IntCounter"):
            kind = "counter"
        elif rust_kind.startswith("IntGauge"):
            kind = "gauge"
        else:
            kind = "histogram"
        constructors[variable] = (name, (kind, labels))

    definitions: dict[str, tuple[str, tuple[str, ...]]] = {}
    for variable in re.findall(
        r"\.register\(\s*Box::new\(\s*(\w+)\.clone\(\)\s*,?\s*\)\s*\)",
        source,
    ):
        constructor = constructors.get(variable)
        if constructor is None:
            continue
        name, definition = constructor
        if name in definitions:
            raise ValueError(f"duplicate registered metric name {name}")
        definitions[name] = definition
    return definitions


def expression_metric_names(expression: str) -> set[str]:
    syntax = re.sub(r'"(?:\\.|[^"\\])*"', '""', expression)
    return set(re.findall(r"(?<![$\w:])([A-Za-z_:][A-Za-z0-9_:]*)\s*(?=\{)", syntax))


def check_evpn_promql_safety(
    expression: str,
    legend: object,
    definitions: dict[str, tuple[str, tuple[str, ...]]],
    context: str,
) -> None:
    """Keep counter math correct and high-cardinality labels out of output."""
    names = expression_metric_names(expression)
    for name in names & definitions.keys():
        kind, labels = definitions[name]
        selector = re.search(rf"{re.escape(name)}\s*\{{([^}}]*)\}}", expression)
        if selector is None:
            raise ValueError(f"{context}: {name} must use an explicit selector")
        matcher_labels = set(
            re.findall(r"([A-Za-z_]\w*)\s*(?:=~|!~|!=|=)", selector.group(1))
        )
        allowed = set(labels) | {"instance", "job"}
        invalid = sorted(matcher_labels - allowed)
        if invalid:
            raise ValueError(f"{context}: {name} uses invalid labels {invalid}")

        wrapped = re.search(
            rf"(?:rate|increase)\(\s*{re.escape(name)}\s*\{{",
            expression,
        )
        if kind == "counter" and wrapped is None:
            raise ValueError(f"{context}: counter {name} must use rate/increase before aggregation")
        if kind != "counter" and wrapped is not None:
            raise ValueError(f"{context}: state gauge {name} must not use rate/increase")

        high_cardinality = {"mac", "esi", "name", "peer", "ip"} & set(labels)
        if high_cardinality:
            if not re.search(r"\b(?:sum|max|count|topk)\s*(?:by\s*\([^)]*\))?\s*\(", expression):
                raise ValueError(
                    f"{context}: {name} must aggregate away high-cardinality labels"
                )
            for grouping in re.findall(r"\bby\s*\(([^)]*)\)", expression):
                retained = {part.strip() for part in grouping.split(",")}
                unsafe = sorted(retained & high_cardinality)
                if unsafe:
                    raise ValueError(
                        f"{context}: unsafe aggregation retains labels {unsafe}"
                    )
            rendered = str(legend or "")
            unsafe_legend = sorted(
                label for label in high_cardinality if f"{{{{{label}}}}}" in rendered
            )
            if unsafe_legend:
                raise ValueError(
                    f"{context}: legend exposes high-cardinality labels {unsafe_legend}"
                )

    if "$vrf" in expression and not re.search(r'vrf\s*=~\s*"\$vrf"', expression):
        raise ValueError(f"{context}: multi-value $vrf must use the =~ matcher")


def check_evpn_dashboard(
    path: Path,
    inventory: dict[str, str],
    source: str,
) -> tuple[int, int]:
    try:
        dashboard = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        try:
            display_path = path.relative_to(ROOT)
        except ValueError:
            display_path = path
        raise ValueError(f"cannot parse {display_path}: {error}") from error

    if dashboard.get("title") != "rustbgpd EVPN Operations (Alpha)":
        raise ValueError("EVPN dashboard title must retain its explicit Alpha marker")
    description = str(dashboard.get("description", ""))
    if "Alpha" not in description or "Type 3 has no dedicated metric" not in description:
        raise ValueError(
            "EVPN dashboard must state Alpha status and the Type-3 aggregate-only boundary"
        )
    if not {"rustbgpd", "evpn", "alpha"}.issubset(set(dashboard.get("tags", []))):
        raise ValueError("EVPN dashboard tags must include rustbgpd, evpn, and alpha")

    definitions = registered_metric_definitions(source)
    actual_evpn = {
        name: definition for name, definition in definitions.items() if name.startswith("evpn_")
    }
    if actual_evpn != EVPN_METRICS:
        missing = sorted(EVPN_METRICS.keys() - actual_evpn.keys())
        extra = sorted(actual_evpn.keys() - EVPN_METRICS.keys())
        changed = sorted(
            name
            for name in EVPN_METRICS.keys() & actual_evpn.keys()
            if EVPN_METRICS[name] != actual_evpn[name]
        )
        raise ValueError(
            "EVPN telemetry inventory drifted: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )

    variables = {
        variable.get("name"): variable
        for variable in dashboard.get("templating", {}).get("list", [])
    }
    query_variables = {
        name: variable for name, variable in variables.items() if variable.get("type") == "query"
    }
    if set(query_variables) != set(EVPN_VARIABLES):
        raise ValueError(
            f"EVPN dashboard query variables must be {sorted(EVPN_VARIABLES)}"
        )
    for name, query in EVPN_VARIABLES.items():
        variable = query_variables[name]
        if variable.get("query") != query:
            raise ValueError(f"EVPN ${name} does not use its exact permitted query")
        if variable.get("multi") is not True or variable.get("includeAll") is not True:
            raise ValueError(f"EVPN ${name} must support multi-select and All")
        if variable.get("allValue") != ".*":
            raise ValueError(f"EVPN ${name} All value must be the simple regex .*")
    forbidden_variables = {"peer", "mac", "esi", "name", "ip"} & set(variables)
    if forbidden_variables:
        raise ValueError(
            f"EVPN dashboard exposes forbidden high-cardinality variables {sorted(forbidden_variables)}"
        )

    panels = all_panels(dashboard.get("panels", []))
    ids = [panel.get("id") for panel in panels]
    if any(type(panel_id) is not int for panel_id in ids):
        raise ValueError("every EVPN panel must have an integer id")
    duplicates = sorted({panel_id for panel_id in ids if ids.count(panel_id) > 1})
    if duplicates:
        raise ValueError(f"duplicate EVPN panel ids: {duplicates}")

    rows = {
        panel.get("title") for panel in panels if panel.get("type") == "row"
    }
    missing_rows = sorted(EVPN_REQUIRED_ROWS - rows)
    if missing_rows:
        raise ValueError(f"EVPN dashboard is missing required operator rows {missing_rows}")

    data_panels = [panel for panel in panels if panel.get("type") != "row"]
    data_titles = [panel.get("title") for panel in data_panels]
    panel_titles = [panel.get("title") for panel in panels]
    unexpected_titles = sorted(
        {title for title in data_titles if title not in EVPN_REQUIRED_PANELS},
        key=str,
    )
    if unexpected_titles:
        raise ValueError(f"EVPN dashboard has unexpected data panels {unexpected_titles}")
    invalid_counts = {
        title: panel_titles.count(title)
        for title in EVPN_REQUIRED_PANELS
        if panel_titles.count(title) != 1
    }
    if invalid_counts:
        raise ValueError(
            "EVPN dashboard must contain exactly one of every required data panel; "
            f"counts={invalid_counts}"
        )

    by_title = {panel.get("title"): panel for panel in data_panels}
    seen_targets: set[tuple[str, str]] = set()
    for title, required_metrics in EVPN_REQUIRED_PANELS.items():
        panel = by_title.get(title)
        if panel is None or panel.get("type") not in {"timeseries", "stat"}:
            raise ValueError(f"EVPN operator panel {title!r} is missing")
        targets = panel.get("targets", [])
        actual_metrics: set[str] = set()
        for target in targets:
            key = (title, target.get("refId"))
            if key in seen_targets:
                raise ValueError(f"duplicate EVPN target {title!r}/{key[1]}")
            seen_targets.add(key)
            expression = target.get("expr")
            if not isinstance(expression, str) or not expression:
                raise ValueError(f"EVPN panel {title!r} has an empty target")
            expected = EVPN_TARGETS.get(key)
            if expected is None:
                raise ValueError(f"unexpected EVPN target {title!r}/{key[1]}")
            expected_expression, expected_legend = expected
            if normalized(expression) != normalized(expected_expression):
                raise ValueError(
                    f"EVPN target {title!r}/{key[1]} must retain its exact expression"
                )
            if target.get("legendFormat") != expected_legend:
                raise ValueError(
                    f"EVPN target {title!r}/{key[1]} must retain legend "
                    f"{expected_legend!r}"
                )
            if target.get("datasource") != EVPN_TARGET_DATASOURCE:
                raise ValueError(
                    f"EVPN target {title!r}/{key[1]} must bind the Prometheus "
                    "${datasource} template"
                )
            actual_metrics.update(expression_metric_names(expression))
            check_evpn_promql_safety(
                expression,
                target.get("legendFormat"),
                EVPN_METRICS,
                f"{title}/{target.get('refId')}",
            )
        if actual_metrics != required_metrics:
            raise ValueError(
                f"EVPN panel {title!r} metrics must be {sorted(required_metrics)}; "
                f"got {sorted(actual_metrics)}"
            )

    if seen_targets != set(EVPN_TARGETS):
        missing = sorted(set(EVPN_TARGETS) - seen_targets)
        extra = sorted(seen_targets - set(EVPN_TARGETS))
        raise ValueError(f"EVPN target roster drifted: missing={missing}, extra={extra}")

    for title in EVPN_DISCRETE_PANELS:
        panel = by_title[title]
        defaults = panel.get("fieldConfig", {}).get("defaults", {})
        if defaults.get("decimals") != 0 or defaults.get("min") != 0:
            raise ValueError(f"EVPN discrete panel {title!r} must use whole nonnegative values")
        if defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
            raise ValueError(f"EVPN discrete panel {title!r} must use step interpolation")

    references = dashboard_metric_references(dashboard)
    check_metric_linkage(references, inventory)
    return len(panels), len(references)


def check_metric_linkage(references: dict[str, list[str]], inventory: dict[str, str]) -> None:
    unresolved: list[str] = []
    for name, contexts in sorted(references.items()):
        if name in inventory:
            continue
        base = next((name.removesuffix(suffix) for suffix in ("_bucket", "_count", "_sum") if name.endswith(suffix)), None)
        if base is None or inventory.get(base) != "histogram":
            unresolved.append(f"{name} ({', '.join(contexts)})")
    if unresolved:
        raise ValueError("unregistered dashboard metrics: " + "; ".join(unresolved))


def main() -> None:
    try:
        dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot parse {DASHBOARD.relative_to(ROOT)}: {error}")

    panels = all_panels(dashboard.get("panels", []))
    ids = [panel.get("id") for panel in panels]
    if any(type(panel_id) is not int for panel_id in ids):
        fail("every panel must have an integer id")
    duplicates = sorted({panel_id for panel_id in ids if ids.count(panel_id) > 1})
    if duplicates:
        fail(f"duplicate panel ids: {duplicates}")

    variables = {
        variable.get("name"): variable
        for variable in dashboard.get("templating", {}).get("list", [])
    }
    for name, query in VARIABLES.items():
        variable = variables.get(name)
        if variable is None:
            fail(f"missing ${name} template variable")
        if variable.get("type") != "query" or variable.get("query") != query:
            fail(f"${name} does not use its exact label_values query")
        if variable.get("multi") is not True or variable.get("includeAll") is not True:
            fail(f"${name} must support multi-select and All")
        if variable.get("allValue") != ".*":
            fail(f"${name} All value must be the regex .* ")

    # The `peer` label has one canonical format (the bare neighbor
    # address), so the dashboard must expose exactly one selector for
    # it. A second one reintroduces the split identity that made
    # `by (peer)` joins across metric families silently return empty.
    peer_selectors = sorted(
        name
        for name, variable in variables.items()
        if variable.get("type") == "query"
        and str(variable.get("query", "")).rstrip().endswith(", peer)")
    )
    if peer_selectors != ["peer"]:
        fail(f"exactly one peer selector expected, found {peer_selectors}")

    targets: dict[tuple[str, str], list[str]] = {}
    legends: dict[tuple[str, str], list[str | None]] = {}
    for panel in panels:
        title = panel.get("title")
        for target in panel.get("targets", []):
            key = (title, target.get("refId"))
            targets.setdefault(key, []).append(normalized(target.get("expr", "")))
            legends.setdefault(key, []).append(target.get("legendFormat"))

    for key, expression in TARGETS.items():
        actual = targets.get(key, [])
        expected = [normalized(expression)]
        if actual != expected:
            fail(f"target {key[0]!r}/{key[1]} must equal {expected[0]!r}; got {actual!r}")

    for key, expected in REQUIRED_LEGENDS.items():
        actual = legends.get(key, [])
        if actual != [expected]:
            fail(f"target {key[0]!r}/{key[1]} must use legend {expected!r}; got {actual!r}")

    update_group_panel = next(
        panel for panel in panels if panel.get("title") == "Update group by peer"
    )
    update_group_target = update_group_panel["targets"][0]
    if update_group_panel.get("type") != "table":
        fail("update-group IDs must use a discrete table panel")
    if update_group_panel.get("fieldConfig", {}).get("defaults", {}).get("decimals") != 0:
        fail("update-group IDs must render with zero decimal places")
    if update_group_target.get("format") != "table" or update_group_target.get("instant") is not True:
        fail("update-group target must be an instant table query")

    slow_panel = next(panel for panel in panels if panel.get("title") == "Slow peers")
    slow_defaults = slow_panel.get("fieldConfig", {}).get("defaults", {})
    if slow_defaults.get("min") != 0 or slow_defaults.get("max") != 1:
        fail("slow-peer state must be pinned to the discrete 0..1 range")
    if slow_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("slow-peer state must use step interpolation")

    truth_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Peer administrative / session truth"
    )
    if truth_panel.get("type") != "timeseries":
        fail("peer administrative/session truth must use a timeseries panel")
    truth_defaults = truth_panel.get("fieldConfig", {}).get("defaults", {})
    if (
        truth_defaults.get("decimals") != 0
        or truth_defaults.get("min") != 0
        or truth_defaults.get("max") != 1
    ):
        fail("peer administrative/session truth must be pinned to whole 0..1 values")
    if truth_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("peer administrative/session truth must use step interpolation")

    route_safety_row = next(
        (panel for panel in panels if panel.get("title") == "Route safety"), None
    )
    if route_safety_row is None or route_safety_row.get("type") != "row":
        fail("Route safety must exist as a dashboard row")
    for title in ROUTE_SAFETY_PANELS:
        panel = next((item for item in panels if item.get("title") == title), None)
        if panel is None or panel.get("type") != "timeseries":
            fail(f"{title} must exist as a timeseries panel")

    selection_panel = next(
        panel for panel in panels if panel.get("title") == "Selection-deferral state"
    )
    selection_defaults = selection_panel.get("fieldConfig", {}).get("defaults", {})
    if selection_defaults.get("decimals") != 0 or selection_defaults.get("min") != 0:
        fail("selection-deferral state must render as nonnegative whole values")
    if selection_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("selection-deferral state must use step interpolation")

    for title in CAPACITY_PANELS:
        panel = next((item for item in panels if item.get("title") == title), None)
        if panel is None or panel.get("type") != "timeseries":
            fail(f"{title} must exist as a timeseries panel")

    rfc8212_panel = next(
        panel for panel in panels if panel.get("title") == "RFC 8212 missing policy"
    )
    rfc8212_refs = [target.get("refId") for target in rfc8212_panel.get("targets", [])]
    if rfc8212_refs != ["A", "B"]:
        fail("RFC 8212 panel must contain exactly targets A and B")
    rfc8212_defaults = rfc8212_panel.get("fieldConfig", {}).get("defaults", {})
    if (
        rfc8212_defaults.get("decimals") != 0
        or rfc8212_defaults.get("min") != 0
        or rfc8212_defaults.get("max") != 1
    ):
        fail("RFC 8212 state must be pinned to whole 0..1 values")
    if rfc8212_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("RFC 8212 state must use step interpolation")
    expected_mappings = [
        {
            "type": "value",
            "options": {
                "0": {"text": "not missing", "color": "green"},
                "1": {"text": "missing", "color": "red"},
            },
        }
    ]
    if rfc8212_defaults.get("mappings") != expected_mappings:
        fail("RFC 8212 state must map 0 to not missing and 1 to missing")

    outbound_panel = next(
        panel for panel in panels if panel.get("title") == "Outbound prefix capacity"
    )
    outbound_refs = [target.get("refId") for target in outbound_panel.get("targets", [])]
    if outbound_refs != ["A", "B", "C", "D"]:
        fail("outbound capacity panel must contain exactly targets A through D")
    if any(
        "bgp_outbound_prefix_blocked_total" in target.get("expr", "")
        for target in outbound_panel.get("targets", [])
    ):
        fail("outbound capacity panel must exclude the cumulative blocked counter")
    outbound_defaults = outbound_panel.get("fieldConfig", {}).get("defaults", {})
    if outbound_defaults.get("decimals") != 0 or outbound_defaults.get("min") != 0:
        fail("outbound capacity counts must render as nonnegative whole values")
    expected_overrides = [
        {
            "matcher": {"id": "byFrameRefID", "options": "D"},
            "properties": [
                {"id": "custom.axisPlacement", "value": "right"},
                {"id": "custom.lineInterpolation", "value": "stepAfter"},
                {"id": "max", "value": 1},
            ],
        }
    ]
    if outbound_panel.get("fieldConfig", {}).get("overrides") != expected_overrides:
        fail("only outbound blocking target D must use a stepped 0..1 right axis")

    dynamic_capacity_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Dynamic-neighbor admission capacity"
    )
    dynamic_capacity_refs = [
        target.get("refId") for target in dynamic_capacity_panel.get("targets", [])
    ]
    if dynamic_capacity_refs != ["A", "B", "C"]:
        fail("dynamic-neighbor capacity panel must contain exactly targets A through C")
    dynamic_capacity_defaults = dynamic_capacity_panel.get("fieldConfig", {}).get(
        "defaults", {}
    )
    if dynamic_capacity_defaults != {"unit": "short", "decimals": 0, "min": 0}:
        fail("dynamic-neighbor capacity must render as nonnegative whole values")

    dynamic_rejections_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Dynamic-neighbor admission rejections"
    )
    dynamic_rejection_refs = [
        target.get("refId") for target in dynamic_rejections_panel.get("targets", [])
    ]
    if dynamic_rejection_refs != ["A"]:
        fail("dynamic-neighbor rejections panel must contain exactly target A")
    dynamic_rejection_defaults = dynamic_rejections_panel.get("fieldConfig", {}).get(
        "defaults", {}
    )
    if dynamic_rejection_defaults != {"unit": "ops", "min": 0}:
        fail("dynamic-neighbor rejection rate must render as nonnegative operations")

    orr_panel = next(
        panel for panel in panels if panel.get("title") == "ORR SPF activity and topology"
    )
    orr_refs = [target.get("refId") for target in orr_panel.get("targets", [])]
    if orr_panel.get("type") != "timeseries" or orr_refs != ["A", "B", "C"]:
        fail("ORR activity panel must be a timeseries with exactly targets A through C")

    blackhole_panel = next(
        (
            panel
            for panel in panels
            if panel.get("title") == "BLACKHOLE discard activity"
        ),
        None,
    )
    if blackhole_panel is None:
        fail("BLACKHOLE discard activity panel must exist")
    blackhole_refs = [target.get("refId") for target in blackhole_panel.get("targets", [])]
    if blackhole_panel.get("type") != "timeseries" or blackhole_refs != ["A", "B"]:
        fail(
            "BLACKHOLE discard activity panel must be a timeseries "
            "with exactly targets A and B"
        )
    blackhole_position = blackhole_panel.get("gridPos", {})
    if blackhole_position.get("w") != 16 or blackhole_position.get("x") != 0:
        fail("BLACKHOLE discard activity must retain its x=0, w=16 layout")
    blackhole_active = next(
        (panel for panel in panels if panel.get("title") == "BLACKHOLE active rows"),
        None,
    )
    if blackhole_active is None:
        fail("BLACKHOLE active rows panel must exist")
    active_refs = [target.get("refId") for target in blackhole_active.get("targets", [])]
    if blackhole_active.get("type") != "stat" or active_refs != ["A"]:
        fail("BLACKHOLE active rows must be a stat with exactly target A")
    active_position = blackhole_active.get("gridPos", {})
    if active_position.get("x") != 16 or active_position.get("w") != 8:
        fail("BLACKHOLE active rows must retain its x=16, w=8 layout")
    active_defaults = blackhole_active.get("fieldConfig", {}).get("defaults", {})
    if active_defaults != {"unit": "short", "min": 0, "decimals": 0}:
        fail("BLACKHOLE active rows must render as a nonnegative integer count")
    active_options = blackhole_active.get("options", {})
    expected_active_options = {
        "colorMode": "value",
        "graphMode": "area",
        "reduceOptions": {
            "calcs": ["lastNotNull"],
            "fields": "",
            "values": False,
        },
    }
    if active_options != expected_active_options:
        fail("BLACKHOLE active rows must retain its exact stat reduction options")

    try:
        references = dashboard_metric_references(dashboard)
        source = METRICS.read_text(encoding="utf-8")
        inventory = rust_metric_inventory(source)
        check_metric_linkage(references, inventory)
        evpn_panels, evpn_references = check_evpn_dashboard(
            EVPN_DASHBOARD,
            inventory,
            source,
        )
    except (OSError, ValueError) as error:
        fail(str(error))

    print(
        f"dashboard check: {len(panels)} unique panels, "
        f"{len(TARGETS)} operator targets, and {len(references)} linked metrics; "
        f"EVPN Alpha {evpn_panels} panels and {evpn_references} linked metrics"
    )


if __name__ == "__main__":
    main()
