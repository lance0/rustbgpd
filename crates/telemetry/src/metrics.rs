//! Prometheus metrics for session, RIB, policy, EVPN, GR, and RPKI counters/gauges.

use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

/// Prometheus metrics for the BGP daemon.
///
/// All metrics are registered against an explicit [`Registry`], not the
/// global default. This keeps tests isolated and gives the caller full
/// control over metric lifetime and exposition.
///
/// Label values are plain strings — this crate has no dependency on
/// `rustbgpd-fsm` or `rustbgpd-wire`.  Callers pass `state.as_str()`,
/// `"keepalive"`, etc.
///
/// **Adding a `peer`-labeled Vec metric?** Add it to the reap list in
/// [`Self::reap_peer_series`] too, so the series are removed when the
/// peer is deleted. Families without a `peer` label are process-global
/// (or keyed by another identity such as VNI, VRF, or BMP collector)
/// and are intentionally not reaped.
#[derive(Debug, Clone)]
pub struct BgpMetrics {
    registry: Registry,

    // ── Session ────────────────────────────────────────────────────
    state_transitions: IntCounterVec,
    session_flaps: IntCounterVec,
    session_established: IntCounterVec,
    stale_timer_events: IntCounterVec,

    // ── BFD (RFC 5880, ADR-0067) ───────────────────────────────────
    bfd_session_up: IntGaugeVec,
    bfd_session_flaps_total: IntCounterVec,

    // ── Notifications ──────────────────────────────────────────────
    notifications_sent: IntCounterVec,
    notifications_received: IntCounterVec,

    // ── Messages ───────────────────────────────────────────────────
    messages_sent: IntCounterVec,
    messages_received: IntCounterVec,

    // ── RIB ──────────────────────────────────────────────────────
    rib_prefixes: IntGaugeVec,
    rib_adj_out_prefixes: IntGaugeVec,
    rib_loc_prefixes: IntGaugeVec,
    route_event_history_depth: IntGauge,
    route_event_history_capacity: IntGauge,

    // ── Event streams ───────────────────────────────────────────
    event_stream_lagged: IntCounterVec,
    event_stream_subscribers: IntGaugeVec,
    grpc_authz_decisions: IntCounterVec,
    config_transaction_lifecycle: IntCounterVec,

    // ── Policy ──────────────────────────────────────────────────
    max_prefix_exceeded: IntCounterVec,

    // ── RIB drops ───────────────────────────────────────────────
    outbound_route_drops: IntCounterVec,
    inbound_rib_backpressure: IntCounterVec,
    hold_timer_rearmed_pending_input: IntCounterVec,
    blackhole_discard_installed: IntCounter,
    blackhole_discard_withdrawn: IntCounter,
    blackhole_discard_adopted: IntCounter,
    blackhole_discard_reaped: IntCounter,
    blackhole_discard_rejected: IntCounterVec,
    blackhole_discard_kernel_failures: IntCounterVec,
    fib_routes_installed: IntCounter,
    fib_routes_withdrawn: IntCounter,
    fib_routes_rejected: IntCounterVec,
    fib_kernel_failures: IntCounterVec,

    // ── Loop detection ─────────────────────────────────────────
    as_path_loop_detected: IntCounterVec,
    rr_loop_detected: IntCounterVec,
    otc_routes_blocked: IntCounterVec,
    role_mismatch: IntCounterVec,

    // ── Policy chain evaluation ────────────────────────────────
    policy_routes: IntCounterVec,

    // ── Graceful Restart ──────────────────────────────────────
    gr_active_peers: IntGaugeVec,
    gr_stale_routes: IntGaugeVec,
    gr_timer_expired: IntCounterVec,

    // ── RPKI ───────────────────────────────────────────────────
    rpki_vrp_count: IntGaugeVec,

    // ── ASPA ───────────────────────────────────────────────────
    aspa_records_total: IntGauge,

    // ── Validation-cache import refresh ───────────────────────
    validation_import_refreshes: IntCounterVec,

    // ── Enhanced Route Refresh ────────────────────────────────
    route_refresh_in_progress: IntGaugeVec,
    route_refresh_stale_entries: IntGaugeVec,

    // ── EVPN ───────────────────────────────────────────────────
    evpn_local_originations: IntCounterVec,
    evpn_local_origination_errors: IntCounterVec,
    evpn_local_observations_dropped: IntCounterVec,
    evpn_duplicate_mac_moves: IntCounterVec,
    evpn_duplicate_mac_first_move_timestamp: IntGaugeVec,
    evpn_duplicate_mac_threshold_exceeded: IntCounterVec,
    evpn_duplicate_mac_quarantine_active: IntGaugeVec,
    evpn_df_role: IntGaugeVec,
    evpn_df_role_changes: IntCounterVec,
    evpn_ip_vrf_observed_routes: IntGaugeVec,
    evpn_ip_vrf_observed_routes_filtered: IntCounterVec,
    evpn_ip_vrf_origination_suppressed: IntCounterVec,
    evpn_ip_vrf_originated_routes: IntGaugeVec,
    evpn_ip_vrf_installed_routes: IntGaugeVec,
    evpn_ip_vrf_remote_prefix_drops: IntGaugeVec,
    evpn_fdb_nhg_drift_members_repaired: IntCounter,
    evpn_fdb_nhg_drift_groups_replaced: IntCounter,
    evpn_fdb_nhg_orphans_cleaned: IntCounter,
    evpn_fdb_nhg_drift_disabled: IntCounter,
    evpn_fdb_single_dst_adopted: IntCounter,
    evpn_fdb_single_dst_reaped: IntCounter,
    evpn_l3_route_adopted: IntCounter,
    evpn_l3_route_reaped: IntCounter,
    evpn_l3_neighbor_adopted: IntCounter,
    evpn_l3_neighbor_reaped: IntCounter,
    evpn_l3vxlan_fdb_adopted: IntCounter,
    evpn_l3vxlan_fdb_reaped: IntCounter,

    // ── BMP exporter ───────────────────────────────────────────
    bmp_source_drops: IntCounterVec,
    bmp_collector_drops: IntCounterVec,
    bmp_replay_attempts: IntCounterVec,
    bmp_control_event_drops: IntCounterVec,

    // ── Event history outbox (ADR-0072) ───────────────────────
    event_outbox_committed: IntCounterVec,
    event_outbox_dropped: IntCounterVec,
    event_outbox_queue_depth: IntGaugeVec,
    event_outbox_db_size_bytes: IntGauge,
    event_outbox_retention_evicted: IntCounterVec,
    event_outbox_latest_event_id: IntGauge,
    event_outbox_open_failures: IntCounter,
    event_outbox_degraded: IntGauge,
    /// Number of `SubscribeFromEvent` requests that emitted a
    /// leading `StreamLagEvent` because the client cursor was
    /// older than the retained floor. Operator signal that
    /// `[event_history].max_events` / `max_bytes` is undersized
    /// for the collector reconnect SLA (ADR-0072 PR5).
    event_outbox_cursor_gap: IntCounter,
}

impl BgpMetrics {
    /// Create a new metrics instance with a fresh [`Registry`].
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails (programming error, not runtime).
    #[must_use]
    pub fn new() -> Self {
        Self::with_registry(Registry::new())
    }

    /// Create a new metrics instance registered against the given
    /// [`Registry`].
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails.
    #[must_use]
    #[expect(clippy::too_many_lines)]
    pub fn with_registry(registry: Registry) -> Self {
        let state_transitions = IntCounterVec::new(
            Opts::new(
                "bgp_session_state_transitions_total",
                "Total BGP session state transitions",
            ),
            &["peer", "from", "to"],
        )
        .expect("valid metric definition");

        let session_flaps = IntCounterVec::new(
            Opts::new(
                "bgp_session_flaps_total",
                "Total BGP session flaps (transitions out of Established)",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let session_established = IntCounterVec::new(
            Opts::new(
                "bgp_session_established_total",
                "Total times a BGP session reached Established",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let bfd_session_up = IntGaugeVec::new(
            Opts::new(
                "bfd_session_up",
                "BFD session state per peer (1 = Up, 0 = not Up)",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let bfd_session_flaps_total = IntCounterVec::new(
            Opts::new(
                "bfd_session_flaps_total",
                "Total BFD session flaps (transitions out of Up)",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let stale_timer_events = IntCounterVec::new(
            Opts::new(
                "bgp_fsm_stale_timer_events_total",
                "FSM timer-expired events that arrived in a state where the corresponding timer should not be running. Non-zero values point at a daemon-side timer-management bug; the FSM ignores these events rather than tearing the session down.",
            ),
            &["peer", "state", "timer"],
        )
        .expect("valid metric definition");

        let notifications_sent = IntCounterVec::new(
            Opts::new(
                "bgp_notifications_sent_total",
                "Total BGP NOTIFICATION messages sent",
            ),
            &["peer", "code", "subcode"],
        )
        .expect("valid metric definition");

        let notifications_received = IntCounterVec::new(
            Opts::new(
                "bgp_notifications_received_total",
                "Total BGP NOTIFICATION messages received",
            ),
            &["peer", "code", "subcode"],
        )
        .expect("valid metric definition");

        let messages_sent = IntCounterVec::new(
            Opts::new("bgp_messages_sent_total", "Total BGP messages sent by type"),
            &["peer", "type"],
        )
        .expect("valid metric definition");

        let messages_received = IntCounterVec::new(
            Opts::new(
                "bgp_messages_received_total",
                "Total BGP messages received by type",
            ),
            &["peer", "type"],
        )
        .expect("valid metric definition");

        let rib_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_prefixes",
                "Number of prefixes in Adj-RIB-In per peer and AFI/SAFI",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let rib_adj_out_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_adj_out_prefixes",
                "Number of prefixes in Adj-RIB-Out per peer and AFI/SAFI",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let rib_loc_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_loc_prefixes",
                "Number of prefixes in the Loc-RIB per AFI/SAFI",
            ),
            &["afi_safi"],
        )
        .expect("valid metric definition");

        let route_event_history_depth = IntGauge::new(
            "bgp_route_event_history_depth",
            "Current number of unicast route events retained in the bounded in-memory route-event history ring.",
        )
        .expect("valid metric definition");

        let route_event_history_capacity = IntGauge::new(
            "bgp_route_event_history_capacity",
            "Configured capacity of the bounded in-memory unicast route-event history ring.",
        )
        .expect("valid metric definition");

        let event_stream_lagged = IntCounterVec::new(
            Opts::new(
                "bgp_event_stream_lagged_total",
                "Events missed by slow live event-stream subscribers by service and source.",
            ),
            &["service", "source"],
        )
        .expect("valid metric definition");

        let event_stream_subscribers = IntGaugeVec::new(
            Opts::new(
                "bgp_event_stream_subscribers",
                "Current live event-stream subscriber count by service and source.",
            ),
            &["service", "source"],
        )
        .expect("valid metric definition");

        let grpc_authz_decisions = IntCounterVec::new(
            Opts::new(
                "bgp_grpc_authz_decisions_total",
                "ADR-0064 gRPC authorization tier decisions by bounded listener and decision labels.",
            ),
            &["tier", "result", "authn", "access_mode"],
        )
        .expect("valid metric definition");

        let config_transaction_lifecycle = IntCounterVec::new(
            Opts::new(
                "bgp_config_transaction_lifecycle_total",
                "Confirmed config transaction lifecycle transitions by bounded operation and outcome labels.",
            ),
            &["operation", "outcome"],
        )
        .expect("valid metric definition");

        let max_prefix_exceeded = IntCounterVec::new(
            Opts::new(
                "bgp_max_prefix_exceeded_total",
                "Number of times a peer exceeded its max-prefix limit",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let outbound_route_drops = IntCounterVec::new(
            Opts::new(
                "bgp_outbound_route_drops_total",
                "Number of outbound route updates dropped due to full channel",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let inbound_rib_backpressure = IntCounterVec::new(
            Opts::new(
                "bgp_inbound_rib_backpressure_total",
                "Inbound route batches that found the RIB channel full and blocked: the session \
                 task parks and TCP receive-window backpressure paces the sender (ADR-0078).",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let hold_timer_rearmed_pending_input = IntCounterVec::new(
            Opts::new(
                "bgp_hold_timer_rearmed_pending_input_total",
                "Hold-timer expiries converted to re-arms because unprocessed peer input was \
                 pending — the local daemon was the bottleneck, not the peer (ADR-0078).",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let blackhole_discard_installed = IntCounter::new(
            "bgp_blackhole_discard_installed_total",
            "RFC 7999 BLACKHOLE kernel discard routes successfully installed.",
        )
        .expect("valid metric definition");

        let blackhole_discard_withdrawn = IntCounter::new(
            "bgp_blackhole_discard_withdrawn_total",
            "Daemon-owned RFC 7999 BLACKHOLE kernel discard routes successfully removed.",
        )
        .expect("valid metric definition");

        let blackhole_discard_adopted = IntCounter::new(
            "bgp_blackhole_discard_adopted_total",
            "Marker-matching RFC 7999 BLACKHOLE kernel discard routes adopted by the startup sweep (ADR-0079).",
        )
        .expect("valid metric definition");

        let blackhole_discard_reaped = IntCounter::new(
            "bgp_blackhole_discard_reaped_total",
            "Adopted-but-unclaimed RFC 7999 BLACKHOLE kernel discard routes reaped after the post-startup deferral.",
        )
        .expect("valid metric definition");

        let blackhole_discard_rejected = IntCounterVec::new(
            Opts::new(
                "bgp_blackhole_discard_rejected_total",
                "RFC 7999 BLACKHOLE routes rejected before kernel discard install by reason.",
            ),
            &["reason"],
        )
        .expect("valid metric definition");

        let blackhole_discard_kernel_failures = IntCounterVec::new(
            Opts::new(
                "bgp_blackhole_discard_kernel_failures_total",
                "Kernel failures while applying RFC 7999 BLACKHOLE discard routes by action.",
            ),
            &["action"],
        )
        .expect("valid metric definition");

        let fib_routes_installed = IntCounter::new(
            "bgp_fib_routes_installed_total",
            "General unicast FIB routes successfully installed or replaced.",
        )
        .expect("valid metric definition");

        let fib_routes_withdrawn = IntCounter::new(
            "bgp_fib_routes_withdrawn_total",
            "Daemon-owned general unicast FIB routes successfully removed.",
        )
        .expect("valid metric definition");

        let fib_routes_rejected = IntCounterVec::new(
            Opts::new(
                "bgp_fib_routes_rejected_total",
                "General unicast FIB route candidates rejected before kernel install by reason.",
            ),
            &["reason"],
        )
        .expect("valid metric definition");

        let fib_kernel_failures = IntCounterVec::new(
            Opts::new(
                "bgp_fib_kernel_failures_total",
                "Kernel failures while applying general unicast FIB routes by action.",
            ),
            &["action"],
        )
        .expect("valid metric definition");

        let as_path_loop_detected = IntCounterVec::new(
            Opts::new(
                "bgp_as_path_loop_detected_total",
                "Total prefixes rejected due to AS_PATH loop detection",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let rr_loop_detected = IntCounterVec::new(
            Opts::new(
                "bgp_rr_loop_detected_total",
                "Total updates rejected due to route reflector loop detection",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let otc_routes_blocked = IntCounterVec::new(
            Opts::new(
                "bgp_otc_routes_blocked_total",
                "RFC 9234 Only-to-Customer unicast routes blocked by bounded peer and reason labels.",
            ),
            &["peer", "reason"],
        )
        .expect("valid metric definition");

        let role_mismatch = IntCounterVec::new(
            Opts::new(
                "bgp_role_mismatch_total",
                "RFC 9234 OPEN-time Role-Mismatch rejections (NOTIFICATION 2/11). \
                 local_role + remote_role ∈ {provider, route_server, \
                 route_server_client, customer, peer, none}.",
            ),
            &["peer", "local_role", "remote_role"],
        )
        .expect("valid metric definition");

        let policy_routes = IntCounterVec::new(
            Opts::new(
                "bgp_policy_routes_total",
                "Routes evaluated through a policy chain, attributed to the \
                 terminal-decision policy. Labels: peer (bounded by neighbor \
                 count), policy (configured policy name; \"inline\" for \
                 anonymous), direction ∈ {import, export}, action ∈ {permit, \
                 deny}. Cardinality is bounded by config — no per-clause \
                 reason label in v1.",
            ),
            &["peer", "policy", "direction", "action"],
        )
        .expect("valid metric definition");

        let gr_active_peers = IntGaugeVec::new(
            Opts::new(
                "bgp_gr_active_peers",
                "Number of peers currently in graceful restart",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let gr_stale_routes = IntGaugeVec::new(
            Opts::new(
                "bgp_gr_stale_routes",
                "Number of stale routes during graceful restart",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let gr_timer_expired = IntCounterVec::new(
            Opts::new(
                "bgp_gr_timer_expired_total",
                "Number of graceful restart timer expirations",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let rpki_vrp_count = IntGaugeVec::new(
            Opts::new(
                "bgp_rpki_vrp_count",
                "Number of RPKI VRP entries by address family",
            ),
            &["af"],
        )
        .expect("valid metric definition");

        let aspa_records_total = IntGauge::new(
            "bgp_aspa_records_total",
            "Number of ASPA customer records in the merged table",
        )
        .expect("valid metric definition");

        let validation_import_refreshes = IntCounterVec::new(
            Opts::new(
                "bgp_validation_import_refreshes_total",
                "Validation-cache-triggered inbound Route Refresh work by dependency and bounded outcome.",
            ),
            &["dependency", "outcome"],
        )
        .expect("valid metric definition");

        let route_refresh_in_progress = IntGaugeVec::new(
            Opts::new(
                "bgp_route_refresh_in_progress",
                "Active inbound Enhanced Route Refresh windows by peer and AFI/SAFI (1 = active, 0 = inactive).",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let route_refresh_stale_entries = IntGaugeVec::new(
            Opts::new(
                "bgp_route_refresh_stale_entries",
                "Routes still awaiting replacement during an inbound Enhanced Route Refresh window by peer and AFI/SAFI.",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let evpn_local_originations = IntCounterVec::new(
            Opts::new(
                "evpn_local_originations_total",
                "Successful locally-originated EVPN Type 2 route actions by action (inject, withdraw)",
            ),
            &["action"],
        )
        .expect("valid metric definition");

        let evpn_local_origination_errors = IntCounterVec::new(
            Opts::new(
                "evpn_local_origination_errors_total",
                "Failed locally-originated EVPN Type 2 route actions by action (inject, withdraw)",
            ),
            &["action"],
        )
        .expect("valid metric definition");

        let evpn_local_observations_dropped = IntCounterVec::new(
            Opts::new(
                "evpn_local_observations_dropped_total",
                "Kernel local-MAC observations dropped before reaching the EVPN originator by reason",
            ),
            &["reason"],
        )
        .expect("valid metric definition");

        let evpn_duplicate_mac_moves = IntCounterVec::new(
            Opts::new(
                "evpn_duplicate_mac_moves_total",
                "EVPN MAC mobility contention events detected by VNI and MAC",
            ),
            &["vni", "mac"],
        )
        .expect("valid metric definition");

        let evpn_duplicate_mac_first_move_timestamp = IntGaugeVec::new(
            Opts::new(
                "evpn_duplicate_mac_first_move_timestamp_seconds",
                "Unix timestamp of the first EVPN MAC mobility contention event observed for a VNI and MAC",
            ),
            &["vni", "mac"],
        )
        .expect("valid metric definition");

        let evpn_duplicate_mac_threshold_exceeded = IntCounterVec::new(
            Opts::new(
                "evpn_duplicate_mac_threshold_exceeded_total",
                "EVPN duplicate-MAC M/N threshold crossings by VNI, MAC, and configured action",
            ),
            &["vni", "mac", "action"],
        )
        .expect("valid metric definition");

        let evpn_duplicate_mac_quarantine_active = IntGaugeVec::new(
            Opts::new(
                "evpn_duplicate_mac_quarantine_active",
                "1 while local Type 2 origination is suppressed for an EVPN duplicate-MAC key; 0 after recovery",
            ),
            &["vni", "mac"],
        )
        .expect("valid metric definition");

        let evpn_df_role = IntGaugeVec::new(
            Opts::new(
                "evpn_df_role",
                "EVPN Designated Forwarder role per (ESI, VNI, role): 1 indicates the active role for the local PE, 0 indicates inactive. Always two label combinations per (esi, vni) — role=df and role=nondf — exactly one of which is 1.",
            ),
            &["esi", "vni", "role"],
        )
        .expect("valid metric definition");

        let evpn_df_role_changes = IntCounterVec::new(
            Opts::new(
                "evpn_df_role_changes_total",
                "EVPN Designated Forwarder role transitions per (ESI, VNI). Bumps every time the local PE flips between DF and NonDF for that (ESI, VNI). Useful for spotting unstable elections.",
            ),
            &["esi", "vni"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_observed_routes = IntGaugeVec::new(
            Opts::new(
                "evpn_ip_vrf_observed_routes",
                "Kernel routes currently observed in each configured EVPN IP-VRF \
                 `table_id` that survive the Gate 9 slice 6a classifier (eligible for \
                 Type 5 origination). Label `vrf` is the operator-facing IP-VRF name.",
            ),
            &["vrf"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_observed_routes_filtered = IntCounterVec::new(
            Opts::new(
                "evpn_ip_vrf_observed_routes_filtered_total",
                "Kernel routes filtered by the EVPN IP-VRF observation classifier \
                 (Gate 9 slice 6a), per VRF and drop reason. `reason` ∈ \
                 {installed_by_routing_daemon, output_device_is_l3vxlan, \
                 non_forwardable_type, link_local_or_multicast, malformed}.",
            ),
            &["vrf", "reason"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_origination_suppressed = IntCounterVec::new(
            Opts::new(
                "evpn_ip_vrf_origination_suppressed_total",
                "EVPN Type 5 origination candidates suppressed (Gate 9 slice 6b), \
                 per VRF and reason. `reason` ∈ {not_ready, family_mismatch}. The \
                 `not_ready` arm bumps once per pending observation each reconcile \
                 pass while the VRF is NotReady so the operator can see why a route \
                 is not on the wire.",
            ),
            &["vrf", "reason"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_originated_routes = IntGaugeVec::new(
            Opts::new(
                "evpn_ip_vrf_originated_routes",
                "Locally-originated EVPN Type 5 routes currently advertised from \
                 each IP-VRF (Gate 9 slice 6b). Matches the L3 originator's \
                 in-flight set after each reconcile pass — same value as the \
                 gRPC `IpVrfState.originated_routes_count` field.",
            ),
            &["vrf"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_installed_routes = IntGaugeVec::new(
            Opts::new(
                "evpn_ip_vrf_installed_routes",
                "Remote EVPN Type 5 routes currently installed in each IP-VRF's \
                 kernel route table (Gate 9 slice 6c). Updated on every reconcile \
                 pass from the L3 reconciler's owned-set bookkeeping.",
            ),
            &["vrf"],
        )
        .expect("valid metric definition");

        let evpn_ip_vrf_remote_prefix_drops = IntGaugeVec::new(
            Opts::new(
                "evpn_ip_vrf_remote_prefix_drops",
                "Current remote EVPN Type 5 projection drops by IP-VRF and bounded \
                 reason. Reasons include overlay-index recursive-resolution failures, \
                 RT misses, missing Router MAC, self-originated rows, and L3VNI \
                 mismatches. The special vrf label `_unscoped` covers drops that \
                 happen before the route can be tied to a configured IP-VRF.",
            ),
            &["vrf", "reason"],
        )
        .expect("valid metric definition");

        let evpn_fdb_nhg_drift_members_repaired = IntCounter::new(
            "evpn_fdb_nhg_drift_members_repaired_total",
            "FDB-NHG per-VTEP member nexthops repaired by ADR-0059 drift recovery.",
        )
        .expect("valid metric definition");

        let evpn_fdb_nhg_drift_groups_replaced = IntCounter::new(
            "evpn_fdb_nhg_drift_groups_replaced_total",
            "FDB nexthop groups re-created or replaced by ADR-0059 drift recovery.",
        )
        .expect("valid metric definition");

        let evpn_fdb_nhg_orphans_cleaned = IntCounter::new(
            "evpn_fdb_nhg_orphans_cleaned_total",
            "Adopted / unreferenced rustbgpd-tagged FDB nexthops cleaned up by ADR-0059 GC.",
        )
        .expect("valid metric definition");

        let evpn_fdb_nhg_drift_disabled = IntCounter::new(
            "evpn_fdb_nhg_drift_disabled_total",
            "Permanent drift-dump failures that disabled ADR-0059 FDB-NHG drift recovery for this daemon instance.",
        )
        .expect("valid metric definition");

        let evpn_fdb_single_dst_adopted = IntCounter::new(
            "evpn_fdb_single_dst_adopted_total",
            "Single-dst extern_learn FDB rows adopted at startup from a previous daemon lifetime (ADR-0079).",
        )
        .expect("valid metric definition");

        let evpn_fdb_single_dst_reaped = IntCounter::new(
            "evpn_fdb_single_dst_reaped_total",
            "Adopted single-dst FDB rows reaped after the ADR-0079 deferral because no EVPN route re-claimed them.",
        )
        .expect("valid metric definition");

        let evpn_l3_route_adopted = IntCounter::new(
            "evpn_l3_route_adopted_total",
            "Proto-bgp onlink routes in configured IP-VRF tables adopted from a previous daemon lifetime (ADR-0079).",
        )
        .expect("valid metric definition");

        let evpn_l3_route_reaped = IntCounter::new(
            "evpn_l3_route_reaped_total",
            "Adopted IP-VRF routes reaped after the ADR-0079 deferral because no Type 5 re-claimed them.",
        )
        .expect("valid metric definition");

        let evpn_l3_neighbor_adopted = IntCounter::new(
            "evpn_l3_neighbor_adopted_total",
            "Permanent extern_learn L3 neighbors on managed L3VXLAN devices adopted from a previous daemon lifetime (ADR-0079).",
        )
        .expect("valid metric definition");

        let evpn_l3_neighbor_reaped = IntCounter::new(
            "evpn_l3_neighbor_reaped_total",
            "Adopted L3 neighbors reaped after the ADR-0079 deferral because no Type 5 re-claimed them.",
        )
        .expect("valid metric definition");

        let evpn_l3vxlan_fdb_adopted = IntCounter::new(
            "evpn_l3vxlan_fdb_adopted_total",
            "Extern_learn L3VXLAN FDB rows adopted from a previous daemon lifetime (ADR-0079).",
        )
        .expect("valid metric definition");

        let evpn_l3vxlan_fdb_reaped = IntCounter::new(
            "evpn_l3vxlan_fdb_reaped_total",
            "Adopted L3VXLAN FDB rows reaped after the ADR-0079 deferral because no Type 5 re-claimed them.",
        )
        .expect("valid metric definition");

        let bmp_source_drops = IntCounterVec::new(
            Opts::new(
                "bmp_source_drops_total",
                "BMP events dropped at the PeerSession→BmpManager channel by reason (channel_full, channel_closed)",
            ),
            &["peer", "reason"],
        )
        .expect("valid metric definition");

        let bmp_collector_drops = IntCounterVec::new(
            Opts::new(
                "bmp_collector_drops_total",
                "BMP messages dropped at the BmpManager→BmpClient channel per collector, by phase (fan_out, replay) and reason (channel_full, channel_closed)",
            ),
            &["collector", "phase", "reason"],
        )
        .expect("valid metric definition");

        let bmp_replay_attempts = IntCounterVec::new(
            Opts::new(
                "bmp_replay_attempts_total",
                "PeerUp-cache replay attempts triggered by a BMP collector reconnect",
            ),
            &["collector"],
        )
        .expect("valid metric definition");

        let bmp_control_event_drops = IntCounterVec::new(
            Opts::new(
                "bmp_control_event_drops_total",
                "BMP control events (collector_connected, collector_disconnected) that failed to reach the manager — surfaces silent skipped PeerUp replay when the control channel is wedged",
            ),
            &["collector", "kind", "reason"],
        )
        .expect("valid metric definition");

        // ── Event history outbox (ADR-0072) ─────────────────────
        let event_outbox_committed = IntCounterVec::new(
            Opts::new(
                "bgp_event_outbox_committed_total",
                "Events durably committed to the local event outbox (ADR-0072) by category.",
            ),
            &["category"],
        )
        .expect("valid metric definition");

        let event_outbox_dropped = IntCounterVec::new(
            Opts::new(
                "bgp_event_outbox_dropped_total",
                "Events dropped before reaching durable storage. The outbox is best-effort under overload (ADR-0072); drops are observable but lie outside the committed cursor sequence by design.",
            ),
            &["category", "reason"],
        )
        .expect("valid metric definition");

        let event_outbox_queue_depth = IntGaugeVec::new(
            Opts::new(
                "bgp_event_outbox_queue_depth",
                "Pending events in the producer queue per category. Climbs before drops start; an operator early-warning signal.",
            ),
            &["category"],
        )
        .expect("valid metric definition");

        let event_outbox_db_size_bytes = IntGauge::new(
            "bgp_event_outbox_db_size_bytes",
            "Combined size of events.db + WAL on disk. The [event_history].max_bytes setting is a retention trigger/target, not a strict filesystem cap.",
        )
        .expect("valid metric definition");

        let event_outbox_retention_evicted = IntCounterVec::new(
            Opts::new(
                "bgp_event_outbox_retention_evicted_total",
                "Events evicted by the retention pass, by reason (count_cap or byte_cap).",
            ),
            &["reason"],
        )
        .expect("valid metric definition");

        let event_outbox_latest_event_id = IntGauge::new(
            "bgp_event_outbox_latest_event_id",
            "Latest committed monotonic event_id. Operator sanity check that the daemon is making forward progress.",
        )
        .expect("valid metric definition");

        let event_outbox_open_failures = IntCounter::new(
            "bgp_event_outbox_open_failures_total",
            "Events DB open failures across the process lifetime. Typically 0 or 1; non-zero means the daemon went into recovery or pass-through (ADR-0072).",
        )
        .expect("valid metric definition");

        let event_outbox_degraded = IntGauge::new(
            "bgp_event_outbox_degraded",
            "1 = the event outbox has experienced at least one drop or open failure since process start. 0 = healthy. Does not auto-clear in v1; operator restarts to clear.",
        )
        .expect("valid metric definition");

        let event_outbox_cursor_gap = IntCounter::new(
            "bgp_event_outbox_cursor_gap_total",
            "SubscribeFromEvent requests that emitted a leading StreamLagEvent because the client cursor was older than the retained floor. Operator signal that [event_history].max_events / max_bytes is undersized for the collector reconnect SLA (ADR-0072).",
        )
        .expect("valid metric definition");

        registry
            .register(Box::new(state_transitions.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(session_flaps.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(session_established.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bfd_session_up.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bfd_session_flaps_total.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(stale_timer_events.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(notifications_sent.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(notifications_received.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(messages_sent.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(messages_received.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_adj_out_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_loc_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(route_event_history_depth.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(route_event_history_capacity.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_stream_lagged.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_stream_subscribers.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(grpc_authz_decisions.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(config_transaction_lifecycle.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(max_prefix_exceeded.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(outbound_route_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(inbound_rib_backpressure.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(hold_timer_rearmed_pending_input.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_installed.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_withdrawn.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_adopted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_reaped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_rejected.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(blackhole_discard_kernel_failures.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(fib_routes_installed.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(fib_routes_withdrawn.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(fib_routes_rejected.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(fib_kernel_failures.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(as_path_loop_detected.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rr_loop_detected.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(otc_routes_blocked.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(role_mismatch.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(policy_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_active_peers.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_stale_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_timer_expired.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rpki_vrp_count.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(aspa_records_total.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(validation_import_refreshes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(route_refresh_in_progress.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(route_refresh_stale_entries.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_local_originations.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_local_origination_errors.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_local_observations_dropped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_duplicate_mac_moves.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_duplicate_mac_first_move_timestamp.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_duplicate_mac_threshold_exceeded.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_duplicate_mac_quarantine_active.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_df_role.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_df_role_changes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_observed_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_observed_routes_filtered.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_origination_suppressed.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_originated_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_installed_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_ip_vrf_remote_prefix_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_nhg_drift_members_repaired.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_nhg_drift_groups_replaced.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_nhg_orphans_cleaned.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_nhg_drift_disabled.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_single_dst_adopted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_fdb_single_dst_reaped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3_route_adopted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3_route_reaped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3_neighbor_adopted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3_neighbor_reaped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3vxlan_fdb_adopted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(evpn_l3vxlan_fdb_reaped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bmp_source_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bmp_collector_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bmp_replay_attempts.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(bmp_control_event_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_committed.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_dropped.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_queue_depth.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_db_size_bytes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_retention_evicted.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_latest_event_id.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_open_failures.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_degraded.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(event_outbox_cursor_gap.clone()))
            .expect("metric not already registered");

        Self {
            registry,
            state_transitions,
            session_flaps,
            session_established,
            stale_timer_events,
            bfd_session_up,
            bfd_session_flaps_total,
            notifications_sent,
            notifications_received,
            messages_sent,
            messages_received,
            rib_prefixes,
            rib_adj_out_prefixes,
            rib_loc_prefixes,
            route_event_history_depth,
            route_event_history_capacity,
            event_stream_lagged,
            event_stream_subscribers,
            grpc_authz_decisions,
            config_transaction_lifecycle,
            max_prefix_exceeded,
            outbound_route_drops,
            inbound_rib_backpressure,
            hold_timer_rearmed_pending_input,
            blackhole_discard_installed,
            blackhole_discard_withdrawn,
            blackhole_discard_adopted,
            blackhole_discard_reaped,
            blackhole_discard_rejected,
            blackhole_discard_kernel_failures,
            fib_routes_installed,
            fib_routes_withdrawn,
            fib_routes_rejected,
            fib_kernel_failures,
            as_path_loop_detected,
            rr_loop_detected,
            otc_routes_blocked,
            role_mismatch,
            policy_routes,
            gr_active_peers,
            gr_stale_routes,
            gr_timer_expired,
            rpki_vrp_count,
            aspa_records_total,
            validation_import_refreshes,
            route_refresh_in_progress,
            route_refresh_stale_entries,
            evpn_local_originations,
            evpn_local_origination_errors,
            evpn_local_observations_dropped,
            evpn_duplicate_mac_moves,
            evpn_duplicate_mac_first_move_timestamp,
            evpn_duplicate_mac_threshold_exceeded,
            evpn_duplicate_mac_quarantine_active,
            evpn_df_role,
            evpn_df_role_changes,
            evpn_ip_vrf_observed_routes,
            evpn_ip_vrf_observed_routes_filtered,
            evpn_ip_vrf_origination_suppressed,
            evpn_ip_vrf_originated_routes,
            evpn_ip_vrf_installed_routes,
            evpn_ip_vrf_remote_prefix_drops,
            evpn_fdb_nhg_drift_members_repaired,
            evpn_fdb_nhg_drift_groups_replaced,
            evpn_fdb_nhg_orphans_cleaned,
            evpn_fdb_nhg_drift_disabled,
            evpn_fdb_single_dst_adopted,
            evpn_fdb_single_dst_reaped,
            evpn_l3_route_adopted,
            evpn_l3_route_reaped,
            evpn_l3_neighbor_adopted,
            evpn_l3_neighbor_reaped,
            evpn_l3vxlan_fdb_adopted,
            evpn_l3vxlan_fdb_reaped,
            bmp_source_drops,
            bmp_collector_drops,
            bmp_replay_attempts,
            bmp_control_event_drops,
            event_outbox_committed,
            event_outbox_dropped,
            event_outbox_queue_depth,
            event_outbox_db_size_bytes,
            event_outbox_retention_evicted,
            event_outbox_latest_event_id,
            event_outbox_open_failures,
            event_outbox_degraded,
            event_outbox_cursor_gap,
        }
    }

    /// The underlying Prometheus registry, for gathering metrics.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // ── Per-peer series reaping ────────────────────────────────────

    /// Remove every series whose `peer` label equals `peer`, across all
    /// peer-labeled metric families (gauges and counters alike).
    ///
    /// Call this only when a peer is **deleted** — never on a session
    /// flap or admin disable, where the peer still exists and must keep
    /// its history. Removing a label set makes Prometheus mark the
    /// series stale at the next scrape; if the same peer is later
    /// re-added, its counters restart from zero, which `rate()` /
    /// `increase()` handle as an ordinary counter reset.
    ///
    /// Matching is exact on the label string. Callers that emit the
    /// peer under more than one formatting (e.g. bare address vs
    /// address:port) must call this once per form.
    ///
    /// Reaping a peer with no live series is a no-op.
    ///
    /// REAP LIST — keep in sync with the `peer`-labeled Vec fields on
    /// [`BgpMetrics`] (see the struct doc comment).
    pub fn reap_peer_series(&self, peer: &str) {
        Self::reap_peer_series_from_vec(&self.state_transitions, peer);
        Self::reap_peer_series_from_vec(&self.session_flaps, peer);
        Self::reap_peer_series_from_vec(&self.session_established, peer);
        Self::reap_peer_series_from_vec(&self.stale_timer_events, peer);
        Self::reap_peer_series_from_vec(&self.bfd_session_up, peer);
        Self::reap_peer_series_from_vec(&self.bfd_session_flaps_total, peer);
        Self::reap_peer_series_from_vec(&self.notifications_sent, peer);
        Self::reap_peer_series_from_vec(&self.notifications_received, peer);
        Self::reap_peer_series_from_vec(&self.messages_sent, peer);
        Self::reap_peer_series_from_vec(&self.messages_received, peer);
        Self::reap_peer_series_from_vec(&self.rib_prefixes, peer);
        Self::reap_peer_series_from_vec(&self.rib_adj_out_prefixes, peer);
        Self::reap_peer_series_from_vec(&self.max_prefix_exceeded, peer);
        Self::reap_peer_series_from_vec(&self.outbound_route_drops, peer);
        Self::reap_peer_series_from_vec(&self.inbound_rib_backpressure, peer);
        Self::reap_peer_series_from_vec(&self.hold_timer_rearmed_pending_input, peer);
        Self::reap_peer_series_from_vec(&self.as_path_loop_detected, peer);
        Self::reap_peer_series_from_vec(&self.rr_loop_detected, peer);
        Self::reap_peer_series_from_vec(&self.otc_routes_blocked, peer);
        Self::reap_peer_series_from_vec(&self.role_mismatch, peer);
        Self::reap_peer_series_from_vec(&self.policy_routes, peer);
        Self::reap_peer_series_from_vec(&self.gr_active_peers, peer);
        Self::reap_peer_series_from_vec(&self.gr_stale_routes, peer);
        Self::reap_peer_series_from_vec(&self.gr_timer_expired, peer);
        Self::reap_peer_series_from_vec(&self.route_refresh_in_progress, peer);
        Self::reap_peer_series_from_vec(&self.route_refresh_stale_entries, peer);
        Self::reap_peer_series_from_vec(&self.bmp_source_drops, peer);
    }

    /// Remove every series of one Vec metric whose `peer` label equals
    /// `peer`.
    ///
    /// The prometheus crate has no wildcard removal —
    /// `remove_label_values` needs the exact, complete label-value
    /// tuple in the declared label order. So: collect the family proto,
    /// select the metrics whose `peer` label matches, rebuild each full
    /// tuple in the order of the family's declared `variable_labels`
    /// (the proto sorts label pairs by name, which may differ), and
    /// remove them one by one.
    fn reap_peer_series_from_vec<T: prometheus::core::MetricVecBuilder>(
        vec: &prometheus::core::MetricVec<T>,
        peer: &str,
    ) {
        use prometheus::core::Collector;

        let descs = vec.desc();
        let Some(desc) = descs.first() else {
            return;
        };
        for family in vec.collect() {
            for metric in family.get_metric() {
                let labels = metric.get_label();
                if !labels
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer)
                {
                    continue;
                }
                let values: Vec<&str> = desc
                    .variable_labels
                    .iter()
                    .map(|name| {
                        labels
                            .iter()
                            .find(|label| label.name() == name.as_str())
                            .map_or("", |label| label.value())
                    })
                    .collect();
                // Removal can only fail for a tuple that no longer
                // exists (e.g. removed concurrently) — ignore.
                let _ = vec.remove_label_values(&values);
            }
        }
    }

    // ── Recording methods ──────────────────────────────────────────

    /// Record a session state transition.
    ///
    /// Automatically increments the flap counter when leaving
    /// `"established"` and the established counter when entering it.
    pub fn record_state_transition(&self, peer: &str, from: &str, to: &str) {
        self.state_transitions
            .with_label_values(&[peer, from, to])
            .inc();

        if from == "established" {
            self.session_flaps.with_label_values(&[peer]).inc();
        }
        if to == "established" {
            self.session_established.with_label_values(&[peer]).inc();
        }
    }

    /// Record a BFD session state change: set the per-peer up gauge and count a
    /// flap on any transition out of Up.
    pub fn record_bfd_state(&self, peer: &str, is_up: bool, was_up: bool) {
        self.bfd_session_up
            .with_label_values(&[peer])
            .set(i64::from(is_up));
        if was_up && !is_up {
            self.bfd_session_flaps_total
                .with_label_values(&[peer])
                .inc();
        }
    }

    /// Record an FSM stale-timer event (timer-expired in a state where
    /// the corresponding timer should not be running). The FSM ignores
    /// these rather than tearing the session down; the counter exists
    /// so they don't disappear silently.
    pub fn record_stale_timer_event(&self, peer: &str, state: &str, timer: &str) {
        self.stale_timer_events
            .with_label_values(&[peer, state, timer])
            .inc();
    }

    /// Record a NOTIFICATION sent to a peer.
    pub fn record_notification_sent(&self, peer: &str, code: &str, subcode: &str) {
        self.notifications_sent
            .with_label_values(&[peer, code, subcode])
            .inc();
    }

    /// Record a NOTIFICATION received from a peer.
    pub fn record_notification_received(&self, peer: &str, code: &str, subcode: &str) {
        self.notifications_received
            .with_label_values(&[peer, code, subcode])
            .inc();
    }

    /// Record a BGP message sent to a peer.
    pub fn record_message_sent(&self, peer: &str, msg_type: &str) {
        self.messages_sent
            .with_label_values(&[peer, msg_type])
            .inc();
    }

    /// Record a BGP message received from a peer.
    pub fn record_message_received(&self, peer: &str, msg_type: &str) {
        self.messages_received
            .with_label_values(&[peer, msg_type])
            .inc();
    }

    /// Set the number of prefixes in Adj-RIB-In for a peer/AFI-SAFI.
    pub fn set_rib_prefixes(&self, peer: &str, afi_safi: &str, count: i64) {
        self.rib_prefixes
            .with_label_values(&[peer, afi_safi])
            .set(count);
    }

    /// Set the number of prefixes in Adj-RIB-Out for a peer/AFI-SAFI.
    pub fn set_adj_rib_out_prefixes(&self, peer: &str, afi_safi: &str, count: i64) {
        self.rib_adj_out_prefixes
            .with_label_values(&[peer, afi_safi])
            .set(count);
    }

    /// Set the number of prefixes in the Loc-RIB for an AFI/SAFI.
    pub fn set_loc_rib_prefixes(&self, afi_safi: &str, count: i64) {
        self.rib_loc_prefixes
            .with_label_values(&[afi_safi])
            .set(count);
    }

    /// Set the number of retained events in the bounded route-event
    /// history ring.
    pub fn set_route_event_history_depth(&self, count: i64) {
        self.route_event_history_depth.set(count);
    }

    /// Set the configured capacity of the bounded route-event history
    /// ring.
    pub fn set_route_event_history_capacity(&self, count: i64) {
        self.route_event_history_capacity.set(count);
    }

    /// Record events missed by a slow live event-stream subscriber.
    pub fn record_event_stream_lagged(&self, service: &str, source: &str, missed: u64) {
        if missed == 0 {
            return;
        }
        self.event_stream_lagged
            .with_label_values(&[service, source])
            .inc_by(missed);
    }

    /// Increment the current live event-stream subscriber gauge.
    pub fn inc_event_stream_subscriber(&self, service: &str, source: &str) {
        self.event_stream_subscribers
            .with_label_values(&[service, source])
            .inc();
    }

    /// Decrement the current live event-stream subscriber gauge.
    pub fn dec_event_stream_subscriber(&self, service: &str, source: &str) {
        self.event_stream_subscribers
            .with_label_values(&[service, source])
            .dec();
    }

    /// Create a guard that increments the live event-stream subscriber
    /// gauge and decrements it when the stream is dropped.
    #[must_use]
    pub fn event_stream_subscriber_guard(
        &self,
        service: &'static str,
        source: &'static str,
    ) -> EventStreamSubscriberGuard {
        self.inc_event_stream_subscriber(service, source);
        EventStreamSubscriberGuard {
            metrics: self.clone(),
            service,
            source,
        }
    }

    /// Record an ADR-0064 gRPC authorization decision.
    ///
    /// Labels are deliberately bounded: method path, listener address,
    /// and principal are emitted in structured logs by `rustbgpd-api`
    /// rather than as Prometheus labels.
    pub fn record_grpc_authz_decision(
        &self,
        tier: &str,
        result: &str,
        authn: &str,
        access_mode: &str,
    ) {
        self.grpc_authz_decisions
            .with_label_values(&[tier, result, authn, access_mode])
            .inc();
    }

    /// Record a confirmed config transaction lifecycle transition.
    ///
    /// Labels are deliberately bounded:
    /// - `operation`: `"confirm"`, `"abort"`, or `"auto_revert"`.
    /// - `outcome`: `"success"` or `"failure"`.
    pub fn record_config_transaction_lifecycle(&self, operation: &str, outcome: &str) {
        debug_assert!(
            matches!(operation, "confirm" | "abort" | "auto_revert"),
            "unbounded config-transaction lifecycle operation label: {operation:?}"
        );
        debug_assert!(
            matches!(outcome, "success" | "failure"),
            "unbounded config-transaction lifecycle outcome label: {outcome:?}"
        );
        self.config_transaction_lifecycle
            .with_label_values(&[operation, outcome])
            .inc();
    }

    /// Record a max-prefix-exceeded event for a peer.
    pub fn record_max_prefix_exceeded(&self, peer: &str) {
        self.max_prefix_exceeded.with_label_values(&[peer]).inc();
    }

    /// Record an outbound route update drop for a peer.
    pub fn record_outbound_route_drop(&self, peer: &str) {
        self.outbound_route_drops.with_label_values(&[peer]).inc();
    }

    /// Record an inbound route batch that blocked on a full RIB channel
    /// (ADR-0078: the session parks instead of dropping).
    pub fn record_inbound_rib_backpressure(&self, peer: &str) {
        self.inbound_rib_backpressure
            .with_label_values(&[peer])
            .inc();
    }

    /// Record a hold-timer expiry converted to a re-arm because
    /// unprocessed peer input was pending (ADR-0078).
    pub fn record_hold_timer_rearmed_pending_input(&self, peer: &str) {
        self.hold_timer_rearmed_pending_input
            .with_label_values(&[peer])
            .inc();
    }

    /// Record a successful RFC 7999 kernel discard install.
    pub fn record_blackhole_discard_installed(&self) {
        self.blackhole_discard_installed.inc();
    }

    /// Record a successful RFC 7999 kernel discard removal.
    pub fn record_blackhole_discard_withdrawn(&self) {
        self.blackhole_discard_withdrawn.inc();
    }

    /// Record a marker-matching kernel discard route adopted by the
    /// ADR-0079 startup sweep.
    pub fn record_blackhole_discard_adopted(&self) {
        self.blackhole_discard_adopted.inc();
    }

    /// Record an adopted-but-unclaimed kernel discard route reaped after
    /// the post-startup deferral.
    pub fn record_blackhole_discard_reaped(&self) {
        self.blackhole_discard_reaped.inc();
    }

    /// Record a rejected RFC 7999 kernel-discard candidate.
    ///
    /// `reason` is expected to be `broad_prefix` or `not_ebgp`.
    pub fn record_blackhole_discard_rejected(&self, reason: &str) {
        self.blackhole_discard_rejected
            .with_label_values(&[reason])
            .inc();
    }

    /// Record a kernel apply failure for RFC 7999 discard state.
    ///
    /// `action` is expected to be `setup`, `install`, `remove`,
    /// `dump`, or `unsupported_platform`.
    pub fn record_blackhole_discard_kernel_failure(&self, action: &str) {
        self.blackhole_discard_kernel_failures
            .with_label_values(&[action])
            .inc();
    }

    /// Record a successful general unicast FIB route install or replace.
    pub fn record_fib_route_installed(&self) {
        self.fib_routes_installed.inc();
    }

    /// Record a successful daemon-owned general unicast FIB route removal.
    pub fn record_fib_route_withdrawn(&self) {
        self.fib_routes_withdrawn.inc();
    }

    /// Record a rejected general unicast FIB route candidate.
    pub fn record_fib_route_rejected(&self, reason: &str) {
        self.fib_routes_rejected.with_label_values(&[reason]).inc();
    }

    /// Record a kernel apply failure for general unicast FIB state.
    ///
    /// `action` is expected to be `setup`, `dump`, `install`,
    /// `replace`, `remove`, or `unsupported_platform`.
    pub fn record_fib_kernel_failure(&self, action: &str) {
        self.fib_kernel_failures.with_label_values(&[action]).inc();
    }

    /// Record `AS_PATH` loop detection: increment by the number of rejected prefixes.
    pub fn record_as_path_loop_detected(&self, peer: &str, count: u64) {
        self.as_path_loop_detected
            .with_label_values(&[peer])
            .inc_by(count);
    }

    /// Record a route reflector loop detection event (`ORIGINATOR_ID` or `CLUSTER_LIST` loop).
    pub fn record_rr_loop_detected(&self, peer: &str) {
        self.rr_loop_detected.with_label_values(&[peer]).inc();
    }

    /// Record RFC 9234 OTC route-leak blocking by bounded reason label.
    pub fn record_otc_routes_blocked(&self, peer: &str, reason: &str, count: u64) {
        self.otc_routes_blocked
            .with_label_values(&[peer, reason])
            .inc_by(count);
    }

    /// Record RFC 9234 OPEN-time Role-Mismatch rejection.
    ///
    /// `local_role` and `remote_role` are bounded strings — one of
    /// `{provider, route_server, route_server_client, customer, peer, none}`.
    /// The label cardinality is fixed at 6×6 = 36 per peer; absent roles
    /// (peer didn't advertise, or we didn't configure) become `"none"`.
    pub fn record_role_mismatch(&self, peer: &str, local_role: &str, remote_role: &str) {
        self.role_mismatch
            .with_label_values(&[peer, local_role, remote_role])
            .inc();
    }

    /// Record a route evaluated through a policy chain, attributed to
    /// the terminal-decision policy.
    ///
    /// - `peer`: bounded by neighbor count.
    /// - `policy`: configured policy name; `"inline"` for anonymous /
    ///   inline policies.
    /// - `direction`: `"import"` or `"export"`.
    /// - `action`: `"permit"` or `"deny"`.
    ///
    /// Cardinality stays bounded by config (no free-form labels).
    pub fn record_policy_routes(&self, peer: &str, policy: &str, direction: &str, action: &str) {
        self.policy_routes
            .with_label_values(&[peer, policy, direction, action])
            .inc();
    }

    /// Set the GR active flag for a peer (1 = in GR, 0 = not).
    pub fn set_gr_active(&self, peer: &str, active: bool) {
        self.gr_active_peers
            .with_label_values(&[peer])
            .set(i64::from(active));
    }

    /// Set the number of stale routes for a GR peer.
    pub fn set_gr_stale_routes(&self, peer: &str, count: i64) {
        self.gr_stale_routes.with_label_values(&[peer]).set(count);
    }

    /// Record a GR timer expiration for a peer.
    pub fn record_gr_timer_expired(&self, peer: &str) {
        self.gr_timer_expired.with_label_values(&[peer]).inc();
    }

    /// Set RPKI VRP count by address family.
    pub fn set_rpki_vrp_count(&self, af: &str, count: i64) {
        self.rpki_vrp_count.with_label_values(&[af]).set(count);
    }

    /// Set ASPA record count.
    pub fn set_aspa_records_total(&self, count: i64) {
        self.aspa_records_total.set(count);
    }

    /// Record validation-cache-triggered inbound Route Refresh work.
    ///
    /// Labels are bounded:
    /// - `dependency`: `"rpki"` or `"aspa"`.
    /// - `outcome`: `"eligible"`, `"refreshed"`,
    ///   `"skipped_not_established"`, or `"failed"`.
    pub fn record_validation_import_refresh(&self, dependency: &str, outcome: &str, count: u64) {
        self.validation_import_refreshes
            .with_label_values(&[dependency, outcome])
            .inc_by(count);
    }

    /// Set whether an inbound Enhanced Route Refresh window is active.
    ///
    /// `afi_safi` is expected to be a bounded family label such as
    /// `"ipv4_unicast"`, `"ipv6_flowspec"`, or `"l2vpn_evpn"`.
    pub fn set_route_refresh_in_progress(&self, peer: &str, afi_safi: &str, active: bool) {
        self.route_refresh_in_progress
            .with_label_values(&[peer, afi_safi])
            .set(i64::from(active));
    }

    /// Set how many entries are still awaiting replacement in an inbound
    /// Enhanced Route Refresh window.
    pub fn set_route_refresh_stale_entries(&self, peer: &str, afi_safi: &str, count: i64) {
        self.route_refresh_stale_entries
            .with_label_values(&[peer, afi_safi])
            .set(count);
    }

    /// Record a successful locally-originated EVPN Type 2 action.
    ///
    /// `action` is expected to be `inject` or `withdraw`.
    pub fn record_evpn_local_origination(&self, action: &str) {
        self.evpn_local_originations
            .with_label_values(&[action])
            .inc();
    }

    /// Record a failed locally-originated EVPN Type 2 action.
    ///
    /// `action` is expected to be `inject` or `withdraw`.
    pub fn record_evpn_local_origination_error(&self, action: &str) {
        self.evpn_local_origination_errors
            .with_label_values(&[action])
            .inc();
    }

    /// Record a kernel local-MAC observation dropped before the
    /// originator received it.
    ///
    /// `reason` is expected to be `channel_full` or `channel_closed`.
    pub fn record_evpn_local_observation_drop(&self, reason: &str) {
        self.evpn_local_observations_dropped
            .with_label_values(&[reason])
            .inc();
    }

    /// Record a detected EVPN duplicate-MAC / mobility contention
    /// event for one `(VNI, MAC)`.
    pub fn record_evpn_duplicate_mac_move(&self, vni: u32, mac: &str) {
        let vni = vni.to_string();
        self.evpn_duplicate_mac_moves
            .with_label_values(&[vni.as_str(), mac])
            .inc();
        let first_seen = self
            .evpn_duplicate_mac_first_move_timestamp
            .with_label_values(&[vni.as_str(), mac]);
        if first_seen.get() == 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            first_seen.set(now);
        }
    }

    /// Record that a `(VNI, MAC)` exceeded the configured duplicate-MAC
    /// M/N threshold. `action` is the operator-selected action label
    /// (`detect` or `suppress_local`).
    pub fn record_evpn_duplicate_mac_threshold_exceeded(&self, vni: u32, mac: &str, action: &str) {
        let vni = vni.to_string();
        self.evpn_duplicate_mac_threshold_exceeded
            .with_label_values(&[vni.as_str(), mac, action])
            .inc();
    }

    /// Set local-origin quarantine state for a duplicate-MAC key.
    pub fn set_evpn_duplicate_mac_quarantine_active(&self, vni: u32, mac: &str, active: bool) {
        let vni = vni.to_string();
        self.evpn_duplicate_mac_quarantine_active
            .with_label_values(&[vni.as_str(), mac])
            .set(i64::from(active));
    }

    /// Set the EVPN Designated Forwarder role gauge for a
    /// `(ESI, VNI)`. Sets `role="df"` to 1 and `role="nondf"` to 0
    /// (or vice versa) so `PromQL evpn_df_role{role="df"} == 1`
    /// finds active DFs. Caller passes the canonical ESI text form
    /// (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`) and `is_df`.
    pub fn set_evpn_df_role(&self, esi: &str, vni: u32, is_df: bool) {
        let vni = vni.to_string();
        self.evpn_df_role
            .with_label_values(&[esi, vni.as_str(), "df"])
            .set(i64::from(is_df));
        self.evpn_df_role
            .with_label_values(&[esi, vni.as_str(), "nondf"])
            .set(i64::from(!is_df));
    }

    /// Record an EVPN DF role transition for `(ESI, VNI)`.
    pub fn record_evpn_df_role_change(&self, esi: &str, vni: u32) {
        let vni = vni.to_string();
        self.evpn_df_role_changes
            .with_label_values(&[esi, vni.as_str()])
            .inc();
    }

    /// Set the EVPN IP-VRF observed-routes gauge for one VRF (Gate 9
    /// slice 6a). Call from the daemon's `DataplaneReport` subscriber
    /// once per pass per VRF; the value is the latest count of routes
    /// surviving the classifier.
    pub fn set_evpn_ip_vrf_observed_routes(&self, vrf: &str, count: i64) {
        self.evpn_ip_vrf_observed_routes
            .with_label_values(&[vrf])
            .set(count);
    }

    /// Increment the EVPN IP-VRF filtered-routes counter for one
    /// `(vrf, reason)` by the given delta (Gate 9 slice 6a).
    pub fn add_evpn_ip_vrf_observed_routes_filtered(&self, vrf: &str, reason: &str, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_ip_vrf_observed_routes_filtered
            .with_label_values(&[vrf, reason])
            .inc_by(delta);
    }

    /// Increment the EVPN Type 5 origination-suppressed counter for
    /// one `(vrf, reason)` by the given delta (Gate 9 slice 6b).
    /// `reason ∈ {not_ready, family_mismatch}`.
    pub fn add_evpn_ip_vrf_origination_suppressed(&self, vrf: &str, reason: &str, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_ip_vrf_origination_suppressed
            .with_label_values(&[vrf, reason])
            .inc_by(delta);
    }

    /// Set the originated-routes gauge for one VRF (Gate 9 slice 6b).
    /// Matches the gRPC `IpVrfState.originated_routes_count` field —
    /// the count of locally-originated Type 5 routes currently
    /// advertised by the L3 originator for that VRF.
    pub fn set_evpn_ip_vrf_originated_routes(&self, vrf: &str, count: i64) {
        self.evpn_ip_vrf_originated_routes
            .with_label_values(&[vrf])
            .set(count);
    }

    /// Set the installed-routes gauge for one VRF (Gate 9 slice 6c).
    pub fn set_evpn_ip_vrf_installed_routes(&self, vrf: &str, count: i64) {
        self.evpn_ip_vrf_installed_routes
            .with_label_values(&[vrf])
            .set(count);
    }

    /// Set the current Type 5 projection-drop gauge for one bounded
    /// `(vrf, reason)` label pair.
    pub fn set_evpn_ip_vrf_remote_prefix_drops(&self, vrf: &str, reason: &str, count: i64) {
        self.evpn_ip_vrf_remote_prefix_drops
            .with_label_values(&[vrf, reason])
            .set(count);
    }

    /// Increment repaired FDB-NHG per-VTEP member counter.
    pub fn add_evpn_fdb_nhg_drift_members_repaired(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_nhg_drift_members_repaired.inc_by(delta);
    }

    /// Increment re-created / replaced FDB-NHG group counter.
    pub fn add_evpn_fdb_nhg_drift_groups_replaced(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_nhg_drift_groups_replaced.inc_by(delta);
    }

    /// Increment cleaned FDB-NHG orphan counter.
    pub fn add_evpn_fdb_nhg_orphans_cleaned(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_nhg_orphans_cleaned.inc_by(delta);
    }

    /// Increment permanent drift-disable counter.
    pub fn add_evpn_fdb_nhg_drift_disabled(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_nhg_drift_disabled.inc_by(delta);
    }

    /// Increment the ADR-0079 single-dst FDB adoption counter.
    pub fn add_evpn_fdb_single_dst_adopted(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_single_dst_adopted.inc_by(delta);
    }

    /// Increment the ADR-0079 single-dst FDB reap counter.
    pub fn add_evpn_fdb_single_dst_reaped(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_fdb_single_dst_reaped.inc_by(delta);
    }

    /// Increment the ADR-0079 adopted IP-VRF route counter.
    pub fn add_evpn_l3_route_adopted(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3_route_adopted.inc_by(delta);
    }

    /// Increment the ADR-0079 reaped IP-VRF route counter.
    pub fn add_evpn_l3_route_reaped(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3_route_reaped.inc_by(delta);
    }

    /// Increment the ADR-0079 adopted L3 neighbor counter.
    pub fn add_evpn_l3_neighbor_adopted(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3_neighbor_adopted.inc_by(delta);
    }

    /// Increment the ADR-0079 reaped L3 neighbor counter.
    pub fn add_evpn_l3_neighbor_reaped(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3_neighbor_reaped.inc_by(delta);
    }

    /// Increment the ADR-0079 adopted L3VXLAN FDB row counter.
    pub fn add_evpn_l3vxlan_fdb_adopted(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3vxlan_fdb_adopted.inc_by(delta);
    }

    /// Increment the ADR-0079 reaped L3VXLAN FDB row counter.
    pub fn add_evpn_l3vxlan_fdb_reaped(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        self.evpn_l3vxlan_fdb_reaped.inc_by(delta);
    }

    /// Record a BMP event dropped at the PeerSession→BmpManager channel.
    pub fn record_bmp_source_drop(&self, peer: &str, reason: &str) {
        self.bmp_source_drops
            .with_label_values(&[peer, reason])
            .inc();
    }

    /// Record `count` BMP messages dropped at the BmpManager→BmpClient
    /// channel. `count = 1` for fan-out drops; replay aborts pass the
    /// remaining cached-PeerUp count so an early break still surfaces
    /// every skipped message.
    pub fn record_bmp_collector_drop(
        &self,
        collector: &str,
        phase: &str,
        reason: &str,
        count: u64,
    ) {
        self.bmp_collector_drops
            .with_label_values(&[collector, phase, reason])
            .inc_by(count);
    }

    /// Record a PeerUp-cache replay attempt for a reconnected BMP collector.
    pub fn record_bmp_replay_attempt(&self, collector: &str) {
        self.bmp_replay_attempts
            .with_label_values(&[collector])
            .inc();
    }

    /// Record a BMP control event (e.g., `CollectorConnected`) that
    /// failed to reach the manager. `reason` ∈ {`channel_closed`,
    /// `channel_timeout`}. When this counter is non-zero the manager
    /// hasn't processed the corresponding event, which (for
    /// `collector_connected`) means the `PeerUp` cache replay never
    /// fires for that reconnect.
    pub fn record_bmp_control_event_drop(&self, collector: &str, kind: &str, reason: &str) {
        self.bmp_control_event_drops
            .with_label_values(&[collector, kind, reason])
            .inc();
    }

    // ── Event history outbox (ADR-0072) ─────────────────────────

    /// Record a successful durable commit. Called by EHM after each
    /// committed batch, once per event in the batch.
    pub fn record_event_outbox_committed(&self, category: &str) {
        self.event_outbox_committed
            .with_label_values(&[category])
            .inc();
    }

    /// Record an outbox drop or cursor-delivery skip. `reason` is
    /// bounded by caller: `queue_full`, `closed`, `db_error`,
    /// `decode_failure`, `opaque_codec`, or `source_lagged`. Call
    /// [`Self::mark_event_outbox_degraded`] separately when the drop
    /// represents an operator-visible outbox degradation; shutdown-time
    /// `closed` drops intentionally do not mark degraded.
    pub fn record_event_outbox_drop(&self, category: &str, reason: &str) {
        self.event_outbox_dropped
            .with_label_values(&[category, reason])
            .inc();
    }

    /// Bulk version of [`Self::record_event_outbox_drop`] for the case
    /// where a single upstream signal represents `count` lost events
    /// — e.g. a `broadcast::error::RecvError::Lagged(missed)` on the
    /// FIB or BFD bridge, where `missed` events were never seen by
    /// the bridge body and therefore never enqueued into EHM. Same
    /// bounded `reason` vocabulary as `record_event_outbox_drop`.
    pub fn record_event_outbox_drops_by(&self, category: &str, reason: &str, count: u64) {
        self.event_outbox_dropped
            .with_label_values(&[category, reason])
            .inc_by(count);
    }

    /// Update the per-category queue depth gauge. EHM calls this
    /// from the actor loop after each batch drain.
    pub fn set_event_outbox_queue_depth(&self, category: &str, depth: i64) {
        self.event_outbox_queue_depth
            .with_label_values(&[category])
            .set(depth);
    }

    pub fn set_event_outbox_db_size_bytes(&self, bytes: i64) {
        self.event_outbox_db_size_bytes.set(bytes);
    }

    pub fn record_event_outbox_retention_evicted(&self, reason: &str, count: u64) {
        self.event_outbox_retention_evicted
            .with_label_values(&[reason])
            .inc_by(count);
    }

    pub fn set_event_outbox_latest_event_id(&self, event_id: i64) {
        self.event_outbox_latest_event_id.set(event_id);
    }

    pub fn record_event_outbox_open_failure(&self) {
        self.event_outbox_open_failures.inc();
        self.event_outbox_degraded.set(1);
    }

    pub fn mark_event_outbox_degraded(&self) {
        self.event_outbox_degraded.set(1);
    }

    /// Increment the `SubscribeFromEvent` cursor-gap counter. The
    /// gRPC handler calls this whenever it emits a leading
    /// `StreamLagEvent` because the requested cursor was below the
    /// retention floor (ADR-0072 PR5).
    pub fn record_event_outbox_cursor_gap(&self) {
        self.event_outbox_cursor_gap.inc();
    }

    /// Whether the outbox is currently flagged degraded. 1 = at least
    /// one drop or open failure since process start.
    #[must_use]
    pub fn event_outbox_degraded(&self) -> bool {
        self.event_outbox_degraded.get() != 0
    }
}

impl Default for BgpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII subscriber-count guard for live event streams.
#[derive(Debug)]
pub struct EventStreamSubscriberGuard {
    metrics: BgpMetrics,
    service: &'static str,
    source: &'static str,
}

impl Drop for EventStreamSubscriberGuard {
    fn drop(&mut self) {
        self.metrics
            .dec_event_stream_subscriber(self.service, self.source);
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Encoder;

    use super::*;

    /// Helper: gather all metrics from the registry as text.
    fn gather_text(m: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = m.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn new_creates_metrics_at_zero() {
        let m = BgpMetrics::new();
        let text = gather_text(&m);
        // Metrics should be registered but no label vectors initialized yet
        // (prometheus only emits metrics once a label combination is observed)
        assert!(!text.contains("bgp_session_state_transitions_total"));
    }

    #[test]
    fn state_transition_increments_counter() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.1", "idle", "connect");

        let val = m
            .state_transitions
            .with_label_values(&["10.0.0.1", "idle", "connect"])
            .get();
        assert_eq!(val, 2);
    }

    #[test]
    fn flap_counter_increments_when_leaving_established() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "established", "idle");

        let flaps = m.session_flaps.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(flaps, 1);
    }

    #[test]
    fn blackhole_kernel_failure_counter_accepts_setup_labels() {
        let m = BgpMetrics::new();
        m.record_blackhole_discard_kernel_failure("setup");
        m.record_blackhole_discard_kernel_failure("unsupported_platform");

        assert_eq!(
            m.blackhole_discard_kernel_failures
                .with_label_values(&["setup"])
                .get(),
            1
        );
        assert_eq!(
            m.blackhole_discard_kernel_failures
                .with_label_values(&["unsupported_platform"])
                .get(),
            1
        );
    }

    #[test]
    fn fib_route_counters_register_expected_labels() {
        let m = BgpMetrics::new();
        m.record_fib_route_installed();
        m.record_fib_route_withdrawn();
        m.record_fib_route_rejected("foreign_route_exists");
        m.record_fib_kernel_failure("setup");
        m.record_fib_kernel_failure("dump");

        assert_eq!(m.fib_routes_installed.get(), 1);
        assert_eq!(m.fib_routes_withdrawn.get(), 1);
        assert_eq!(
            m.fib_routes_rejected
                .with_label_values(&["foreign_route_exists"])
                .get(),
            1
        );
        assert_eq!(m.fib_kernel_failures.with_label_values(&["setup"]).get(), 1);
        assert_eq!(m.fib_kernel_failures.with_label_values(&["dump"]).get(), 1);
    }

    #[test]
    fn event_stream_lagged_counter_accumulates_missed_events() {
        let m = BgpMetrics::new();

        m.record_event_stream_lagged("watch_events", "route", 3);
        m.record_event_stream_lagged("watch_events", "route", 2);
        m.record_event_stream_lagged("watch_events", "session", 0);

        assert_eq!(
            m.event_stream_lagged
                .with_label_values(&["watch_events", "route"])
                .get(),
            5
        );
        assert_eq!(
            m.event_stream_lagged
                .with_label_values(&["watch_events", "session"])
                .get(),
            0
        );
    }

    #[test]
    fn event_stream_subscriber_guard_tracks_lifecycle() {
        let m = BgpMetrics::new();

        {
            let _guard = m.event_stream_subscriber_guard("watch_routes", "route");
            assert_eq!(
                m.event_stream_subscribers
                    .with_label_values(&["watch_routes", "route"])
                    .get(),
                1
            );
        }

        assert_eq!(
            m.event_stream_subscribers
                .with_label_values(&["watch_routes", "route"])
                .get(),
            0
        );
    }

    #[test]
    fn grpc_authz_decision_counter_uses_bounded_labels() {
        let m = BgpMetrics::new();
        m.record_grpc_authz_decision("operator_only", "audit_forward", "mtls", "read_write");
        m.record_grpc_authz_decision("operator_only", "audit_forward", "mtls", "read_write");

        assert_eq!(
            m.grpc_authz_decisions
                .with_label_values(&["operator_only", "audit_forward", "mtls", "read_write"])
                .get(),
            2
        );

        let text = gather_text(&m);
        assert!(text.contains("bgp_grpc_authz_decisions_total"));
        assert!(!text.contains("rustbgpd.v1.ControlService"));
    }

    #[test]
    fn config_transaction_lifecycle_counter_uses_bounded_labels() {
        let m = BgpMetrics::new();
        m.record_config_transaction_lifecycle("confirm", "success");
        m.record_config_transaction_lifecycle("abort", "failure");
        m.record_config_transaction_lifecycle("auto_revert", "success");

        assert_eq!(
            m.config_transaction_lifecycle
                .with_label_values(&["confirm", "success"])
                .get(),
            1
        );
        assert_eq!(
            m.config_transaction_lifecycle
                .with_label_values(&["abort", "failure"])
                .get(),
            1
        );
        assert_eq!(
            m.config_transaction_lifecycle
                .with_label_values(&["auto_revert", "success"])
                .get(),
            1
        );

        let text = gather_text(&m);
        assert!(text.contains("bgp_config_transaction_lifecycle_total"));
        assert!(text.contains(r#"operation="confirm""#));
        assert!(text.contains(r#"outcome="failure""#));
        assert!(!text.contains("confirm_id"));
    }

    #[test]
    fn otc_routes_blocked_counter_uses_bounded_reason_label() {
        let m = BgpMetrics::new();
        m.record_otc_routes_blocked("10.0.0.2", "ingress_peer_mismatch", 2);
        m.record_otc_routes_blocked("10.0.0.2", "ingress_peer_mismatch", 3);

        assert_eq!(
            m.otc_routes_blocked
                .with_label_values(&["10.0.0.2", "ingress_peer_mismatch"])
                .get(),
            5
        );
    }

    #[test]
    fn policy_routes_counter_uses_bounded_labels() {
        let m = BgpMetrics::new();
        // Three permits + one deny against the same import policy.
        m.record_policy_routes("10.0.0.2", "ingress-filter", "import", "permit");
        m.record_policy_routes("10.0.0.2", "ingress-filter", "import", "permit");
        m.record_policy_routes("10.0.0.2", "ingress-filter", "import", "permit");
        m.record_policy_routes("10.0.0.2", "ingress-filter", "import", "deny");
        // An export policy on the same peer.
        m.record_policy_routes("10.0.0.2", "egress-clean", "export", "permit");
        // An inline policy on a different peer.
        m.record_policy_routes("10.0.0.3", "inline", "import", "deny");

        assert_eq!(
            m.policy_routes
                .with_label_values(&["10.0.0.2", "ingress-filter", "import", "permit"])
                .get(),
            3
        );
        assert_eq!(
            m.policy_routes
                .with_label_values(&["10.0.0.2", "ingress-filter", "import", "deny"])
                .get(),
            1
        );
        assert_eq!(
            m.policy_routes
                .with_label_values(&["10.0.0.3", "inline", "import", "deny"])
                .get(),
            1
        );

        let text = gather_text(&m);
        assert!(text.contains("bgp_policy_routes_total"));
        assert!(text.contains(r#"policy="ingress-filter""#));
        assert!(text.contains(r#"direction="import""#));
        assert!(text.contains(r#"action="deny""#));
    }

    #[test]
    fn validation_import_refresh_counter_uses_bounded_labels() {
        let m = BgpMetrics::new();
        m.record_validation_import_refresh("rpki", "eligible", 3);
        m.record_validation_import_refresh("rpki", "refreshed", 2);
        m.record_validation_import_refresh("rpki", "skipped_not_established", 1);
        m.record_validation_import_refresh("aspa", "failed", 1);

        assert_eq!(
            m.validation_import_refreshes
                .with_label_values(&["rpki", "eligible"])
                .get(),
            3
        );
        assert_eq!(
            m.validation_import_refreshes
                .with_label_values(&["rpki", "refreshed"])
                .get(),
            2
        );
        assert_eq!(
            m.validation_import_refreshes
                .with_label_values(&["rpki", "skipped_not_established"])
                .get(),
            1
        );
        assert_eq!(
            m.validation_import_refreshes
                .with_label_values(&["aspa", "failed"])
                .get(),
            1
        );

        let text = gather_text(&m);
        assert!(text.contains("bgp_validation_import_refreshes_total"));
        assert!(text.contains(r#"dependency="rpki""#));
        assert!(text.contains(r#"outcome="skipped_not_established""#));
    }

    #[test]
    fn route_refresh_gauges_use_peer_and_family_labels() {
        let m = BgpMetrics::new();
        m.set_route_refresh_in_progress("10.0.0.1", "ipv4_unicast", true);
        m.set_route_refresh_stale_entries("10.0.0.1", "ipv4_unicast", 42);
        m.set_route_refresh_in_progress("10.0.0.1", "ipv4_unicast", false);
        m.set_route_refresh_stale_entries("10.0.0.1", "ipv4_unicast", 0);

        assert_eq!(
            m.route_refresh_in_progress
                .with_label_values(&["10.0.0.1", "ipv4_unicast"])
                .get(),
            0
        );
        assert_eq!(
            m.route_refresh_stale_entries
                .with_label_values(&["10.0.0.1", "ipv4_unicast"])
                .get(),
            0
        );

        let text = gather_text(&m);
        assert!(text.contains("bgp_route_refresh_in_progress"));
        assert!(text.contains("bgp_route_refresh_stale_entries"));
        assert!(text.contains(r#"afi_safi="ipv4_unicast""#));
    }

    #[test]
    fn role_mismatch_counter_uses_bounded_role_labels() {
        let m = BgpMetrics::new();
        // Both Provider — incompatible (RFC 9234 Table 2 forbids).
        m.record_role_mismatch("10.0.0.7", "provider", "provider");
        m.record_role_mismatch("10.0.0.7", "provider", "provider");
        // Strict mode: we configured Customer but peer didn't advertise Role.
        m.record_role_mismatch("10.0.0.8", "customer", "none");

        assert_eq!(
            m.role_mismatch
                .with_label_values(&["10.0.0.7", "provider", "provider"])
                .get(),
            2
        );
        assert_eq!(
            m.role_mismatch
                .with_label_values(&["10.0.0.8", "customer", "none"])
                .get(),
            1
        );

        // The metric should render in the registry's text output.
        let text = gather_text(&m);
        assert!(text.contains("bgp_role_mismatch_total"));
        assert!(text.contains(r#"local_role="provider""#));
        assert!(text.contains(r#"remote_role="none""#));
    }

    #[test]
    fn route_event_history_gauges_set_depth_and_capacity() {
        let m = BgpMetrics::new();

        m.set_route_event_history_capacity(4096);
        m.set_route_event_history_depth(17);

        assert_eq!(m.route_event_history_capacity.get(), 4096);
        assert_eq!(m.route_event_history_depth.get(), 17);
    }

    #[test]
    fn flap_counter_does_not_increment_for_other_transitions() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.1", "connect", "open_sent");

        let flaps = m.session_flaps.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(flaps, 0);
    }

    #[test]
    fn established_counter_increments_when_entering_established() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "open_confirm", "established");

        let est = m.session_established.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(est, 1);
    }

    #[test]
    fn notification_sent_counter() {
        let m = BgpMetrics::new();
        m.record_notification_sent("10.0.0.1", "2", "2");
        m.record_notification_sent("10.0.0.1", "2", "2");
        m.record_notification_sent("10.0.0.1", "6", "0");

        let open_err = m
            .notifications_sent
            .with_label_values(&["10.0.0.1", "2", "2"])
            .get();
        assert_eq!(open_err, 2);

        let cease = m
            .notifications_sent
            .with_label_values(&["10.0.0.1", "6", "0"])
            .get();
        assert_eq!(cease, 1);
    }

    #[test]
    fn notification_received_counter() {
        let m = BgpMetrics::new();
        m.record_notification_received("10.0.0.2", "4", "0");

        let val = m
            .notifications_received
            .with_label_values(&["10.0.0.2", "4", "0"])
            .get();
        assert_eq!(val, 1);
    }

    #[test]
    fn message_sent_counter() {
        let m = BgpMetrics::new();
        m.record_message_sent("10.0.0.1", "open");
        m.record_message_sent("10.0.0.1", "keepalive");
        m.record_message_sent("10.0.0.1", "keepalive");

        let open = m
            .messages_sent
            .with_label_values(&["10.0.0.1", "open"])
            .get();
        assert_eq!(open, 1);

        let ka = m
            .messages_sent
            .with_label_values(&["10.0.0.1", "keepalive"])
            .get();
        assert_eq!(ka, 2);
    }

    #[test]
    fn message_received_counter() {
        let m = BgpMetrics::new();
        m.record_message_received("10.0.0.2", "update");

        let val = m
            .messages_received
            .with_label_values(&["10.0.0.2", "update"])
            .get();
        assert_eq!(val, 1);
    }

    #[test]
    fn rib_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_rib_prefixes("10.0.0.1", "ipv4_unicast", 42);

        let val = m
            .rib_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 42);

        m.set_rib_prefixes("10.0.0.1", "ipv4_unicast", 0);
        let val = m
            .rib_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 0);
    }

    #[test]
    fn per_peer_isolation() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.2", "idle", "connect");

        let p1 = m
            .state_transitions
            .with_label_values(&["10.0.0.1", "idle", "connect"])
            .get();
        let p2 = m
            .state_transitions
            .with_label_values(&["10.0.0.2", "idle", "connect"])
            .get();
        assert_eq!(p1, 1);
        assert_eq!(p2, 1);
    }

    #[test]
    fn gather_produces_valid_text() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_message_sent("10.0.0.1", "open");

        let text = gather_text(&m);
        assert!(text.contains("bgp_session_state_transitions_total"));
        assert!(text.contains("bgp_messages_sent_total"));
        assert!(text.contains("10.0.0.1"));
    }

    fn assert_duplicate_mac_metrics(m: &BgpMetrics, first_move_timestamp: i64, text: &str) {
        assert_eq!(
            m.evpn_duplicate_mac_moves
                .with_label_values(&["100", "02:aa:bb:cc:dd:01"])
                .get(),
            2
        );
        assert!(
            first_move_timestamp > 0,
            "first move timestamp should be set"
        );
        assert_eq!(
            m.evpn_duplicate_mac_first_move_timestamp
                .with_label_values(&["100", "02:aa:bb:cc:dd:01"])
                .get(),
            first_move_timestamp,
            "first move timestamp should not change on later moves"
        );
        assert_eq!(
            m.evpn_duplicate_mac_threshold_exceeded
                .with_label_values(&["100", "02:aa:bb:cc:dd:01", "detect"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_duplicate_mac_quarantine_active
                .with_label_values(&["100", "02:aa:bb:cc:dd:01"])
                .get(),
            1
        );
        assert!(
            text.contains(
                "evpn_duplicate_mac_moves_total{mac=\"02:aa:bb:cc:dd:01\",vni=\"100\"} 2"
            ) || text.contains(
                "evpn_duplicate_mac_moves_total{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\"} 2"
            )
        );
        assert!(
            text.contains(
                "evpn_duplicate_mac_first_move_timestamp_seconds{mac=\"02:aa:bb:cc:dd:01\",vni=\"100\"}"
            ) || text.contains(
                "evpn_duplicate_mac_first_move_timestamp_seconds{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\"}"
            )
        );
        assert!(
            text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{action=\"detect\",mac=\"02:aa:bb:cc:dd:01\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\",action=\"detect\"} 1"
            )
        );
        assert!(
            text.contains(
                "evpn_duplicate_mac_quarantine_active{mac=\"02:aa:bb:cc:dd:01\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_quarantine_active{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\"} 1"
            )
        );
    }

    #[test]
    fn evpn_local_origination_counters_are_exported() {
        let m = BgpMetrics::new();
        m.record_evpn_local_origination("inject");
        m.record_evpn_local_origination("withdraw");
        m.record_evpn_local_origination_error("inject");
        m.record_evpn_local_origination_error("withdraw");
        m.record_evpn_local_observation_drop("channel_full");
        m.record_evpn_local_observation_drop("channel_closed");
        m.record_evpn_duplicate_mac_move(100, "02:aa:bb:cc:dd:01");
        let first_move_timestamp = m
            .evpn_duplicate_mac_first_move_timestamp
            .with_label_values(&["100", "02:aa:bb:cc:dd:01"])
            .get();
        m.record_evpn_duplicate_mac_move(100, "02:aa:bb:cc:dd:01");
        m.record_evpn_duplicate_mac_threshold_exceeded(100, "02:aa:bb:cc:dd:01", "detect");
        m.set_evpn_duplicate_mac_quarantine_active(100, "02:aa:bb:cc:dd:01", true);

        assert_eq!(
            m.evpn_local_originations
                .with_label_values(&["inject"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_local_originations
                .with_label_values(&["withdraw"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_local_origination_errors
                .with_label_values(&["inject"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_local_origination_errors
                .with_label_values(&["withdraw"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_local_observations_dropped
                .with_label_values(&["channel_full"])
                .get(),
            1
        );
        assert_eq!(
            m.evpn_local_observations_dropped
                .with_label_values(&["channel_closed"])
                .get(),
            1
        );
        let text = gather_text(&m);
        assert!(text.contains("evpn_local_originations_total{action=\"inject\"} 1"));
        assert!(text.contains("evpn_local_originations_total{action=\"withdraw\"} 1"));
        assert!(text.contains("evpn_local_origination_errors_total{action=\"inject\"} 1"));
        assert!(text.contains("evpn_local_origination_errors_total{action=\"withdraw\"} 1"));
        assert!(text.contains("evpn_local_observations_dropped_total{reason=\"channel_full\"} 1"));
        assert!(
            text.contains("evpn_local_observations_dropped_total{reason=\"channel_closed\"} 1")
        );
        assert_duplicate_mac_metrics(&m, first_move_timestamp, &text);
    }

    #[test]
    fn evpn_fdb_nhg_drift_counters_are_exported() {
        let m = BgpMetrics::new();
        m.add_evpn_fdb_nhg_drift_members_repaired(2);
        m.add_evpn_fdb_nhg_drift_groups_replaced(3);
        m.add_evpn_fdb_nhg_orphans_cleaned(4);
        m.add_evpn_fdb_nhg_drift_disabled(1);
        m.add_evpn_fdb_single_dst_adopted(5);
        m.add_evpn_fdb_single_dst_reaped(6);

        assert_eq!(m.evpn_fdb_nhg_drift_members_repaired.get(), 2);
        assert_eq!(m.evpn_fdb_nhg_drift_groups_replaced.get(), 3);
        assert_eq!(m.evpn_fdb_nhg_orphans_cleaned.get(), 4);
        assert_eq!(m.evpn_fdb_nhg_drift_disabled.get(), 1);
        assert_eq!(m.evpn_fdb_single_dst_adopted.get(), 5);
        assert_eq!(m.evpn_fdb_single_dst_reaped.get(), 6);

        let text = gather_text(&m);
        assert!(text.contains("evpn_fdb_nhg_drift_members_repaired_total 2"));
        assert!(text.contains("evpn_fdb_nhg_drift_groups_replaced_total 3"));
        assert!(text.contains("evpn_fdb_nhg_orphans_cleaned_total 4"));
        assert!(text.contains("evpn_fdb_single_dst_adopted_total 5"));
        assert!(text.contains("evpn_fdb_single_dst_reaped_total 6"));
        assert!(text.contains("evpn_fdb_nhg_drift_disabled_total 1"));
    }

    #[test]
    fn evpn_l3_adoption_counters_are_exported() {
        let m = BgpMetrics::new();
        m.add_evpn_l3_route_adopted(1);
        m.add_evpn_l3_route_reaped(2);
        m.add_evpn_l3_neighbor_adopted(3);
        m.add_evpn_l3_neighbor_reaped(4);
        m.add_evpn_l3vxlan_fdb_adopted(5);
        m.add_evpn_l3vxlan_fdb_reaped(6);

        assert_eq!(m.evpn_l3_route_adopted.get(), 1);
        assert_eq!(m.evpn_l3_route_reaped.get(), 2);
        assert_eq!(m.evpn_l3_neighbor_adopted.get(), 3);
        assert_eq!(m.evpn_l3_neighbor_reaped.get(), 4);
        assert_eq!(m.evpn_l3vxlan_fdb_adopted.get(), 5);
        assert_eq!(m.evpn_l3vxlan_fdb_reaped.get(), 6);

        let text = gather_text(&m);
        assert!(text.contains("evpn_l3_route_adopted_total 1"));
        assert!(text.contains("evpn_l3_route_reaped_total 2"));
        assert!(text.contains("evpn_l3_neighbor_adopted_total 3"));
        assert!(text.contains("evpn_l3_neighbor_reaped_total 4"));
        assert!(text.contains("evpn_l3vxlan_fdb_adopted_total 5"));
        assert!(text.contains("evpn_l3vxlan_fdb_reaped_total 6"));
    }

    #[test]
    fn evpn_ip_vrf_remote_prefix_drop_gauge_is_exported() {
        let m = BgpMetrics::new();
        m.set_evpn_ip_vrf_remote_prefix_drops("blue", "unresolved_overlay_index_gateway", 2);
        m.set_evpn_ip_vrf_remote_prefix_drops("_unscoped", "no_matching_ip_vrf", 1);

        assert_eq!(
            m.evpn_ip_vrf_remote_prefix_drops
                .with_label_values(&["blue", "unresolved_overlay_index_gateway"])
                .get(),
            2
        );
        assert_eq!(
            m.evpn_ip_vrf_remote_prefix_drops
                .with_label_values(&["_unscoped", "no_matching_ip_vrf"])
                .get(),
            1
        );

        let text = gather_text(&m);
        assert!(
            text.contains(
                "evpn_ip_vrf_remote_prefix_drops{reason=\"unresolved_overlay_index_gateway\",vrf=\"blue\"} 2"
            ) || text.contains(
                "evpn_ip_vrf_remote_prefix_drops{vrf=\"blue\",reason=\"unresolved_overlay_index_gateway\"} 2"
            )
        );
    }

    #[test]
    fn adj_rib_out_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_adj_rib_out_prefixes("10.0.0.1", "ipv4_unicast", 5);

        let val = m
            .rib_adj_out_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 5);
    }

    #[test]
    fn loc_rib_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_loc_rib_prefixes("ipv4_unicast", 42);

        let val = m
            .rib_loc_prefixes
            .with_label_values(&["ipv4_unicast"])
            .get();
        assert_eq!(val, 42);
    }

    #[test]
    fn max_prefix_exceeded_counter() {
        let m = BgpMetrics::new();
        m.record_max_prefix_exceeded("10.0.0.1");
        m.record_max_prefix_exceeded("10.0.0.1");

        let val = m.max_prefix_exceeded.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(val, 2);
    }

    #[test]
    fn with_registry_uses_provided_registry() {
        let reg = Registry::new();
        let m = BgpMetrics::with_registry(reg);
        m.record_state_transition("10.0.0.1", "idle", "connect");

        let families = m.registry().gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn bmp_source_drop_counter() {
        let m = BgpMetrics::new();
        m.record_bmp_source_drop("10.0.0.1", "channel_full");
        m.record_bmp_source_drop("10.0.0.1", "channel_full");
        m.record_bmp_source_drop("10.0.0.2", "channel_closed");

        let full = m
            .bmp_source_drops
            .with_label_values(&["10.0.0.1", "channel_full"])
            .get();
        assert_eq!(full, 2);

        let closed = m
            .bmp_source_drops
            .with_label_values(&["10.0.0.2", "channel_closed"])
            .get();
        assert_eq!(closed, 1);
    }

    #[test]
    fn bmp_collector_drop_counter() {
        let m = BgpMetrics::new();
        m.record_bmp_collector_drop("127.0.0.1:5000", "fan_out", "channel_full", 1);
        m.record_bmp_collector_drop("127.0.0.1:5000", "fan_out", "channel_full", 1);
        // Replay abort: count every cached-PeerUp message that was
        // skipped, not just one.
        m.record_bmp_collector_drop("127.0.0.1:5000", "replay", "channel_full", 7);

        let fan_out = m
            .bmp_collector_drops
            .with_label_values(&["127.0.0.1:5000", "fan_out", "channel_full"])
            .get();
        assert_eq!(fan_out, 2);

        let replay = m
            .bmp_collector_drops
            .with_label_values(&["127.0.0.1:5000", "replay", "channel_full"])
            .get();
        assert_eq!(replay, 7);
    }

    #[test]
    fn bmp_control_event_drop_counter() {
        let m = BgpMetrics::new();
        m.record_bmp_control_event_drop("127.0.0.1:5000", "collector_connected", "channel_timeout");
        m.record_bmp_control_event_drop("127.0.0.1:5000", "collector_connected", "channel_closed");
        m.record_bmp_control_event_drop("127.0.0.1:5000", "collector_connected", "channel_timeout");

        let timeouts = m
            .bmp_control_event_drops
            .with_label_values(&["127.0.0.1:5000", "collector_connected", "channel_timeout"])
            .get();
        assert_eq!(timeouts, 2);

        let closed = m
            .bmp_control_event_drops
            .with_label_values(&["127.0.0.1:5000", "collector_connected", "channel_closed"])
            .get();
        assert_eq!(closed, 1);
    }

    /// Populate every peer-labeled family for `peer` through the public
    /// recording surface. Doubles as the sync guard for the reap list:
    /// if a future peer-labeled family is added here but not to
    /// `reap_peer_series`, `reap_peer_series_removes_every_peer_labeled_family`
    /// fails.
    fn populate_all_peer_families(m: &BgpMetrics, peer: &str) {
        // state_transitions + session_flaps + session_established
        m.record_state_transition(peer, "open_confirm", "established");
        m.record_state_transition(peer, "established", "idle");
        m.record_stale_timer_event(peer, "idle", "hold");
        m.record_bfd_state(peer, true, false);
        m.record_bfd_state(peer, false, true); // bfd flap counter
        m.record_notification_sent(peer, "6", "0");
        m.record_notification_received(peer, "4", "0");
        m.record_message_sent(peer, "keepalive");
        m.record_message_received(peer, "update");
        m.set_rib_prefixes(peer, "ipv4_unicast", 42);
        m.set_adj_rib_out_prefixes(peer, "ipv4_unicast", 7);
        m.record_max_prefix_exceeded(peer);
        m.record_outbound_route_drop(peer);
        m.record_inbound_rib_backpressure(peer);
        m.record_hold_timer_rearmed_pending_input(peer);
        m.record_as_path_loop_detected(peer, 3);
        m.record_rr_loop_detected(peer);
        m.record_otc_routes_blocked(peer, "ingress_peer_mismatch", 2);
        m.record_role_mismatch(peer, "provider", "provider");
        m.record_policy_routes(peer, "ingress-filter", "import", "permit");
        m.set_gr_active(peer, true);
        m.set_gr_stale_routes(peer, 5);
        m.record_gr_timer_expired(peer);
        m.set_route_refresh_in_progress(peer, "ipv4_unicast", true);
        m.set_route_refresh_stale_entries(peer, "ipv4_unicast", 9);
        m.record_bmp_source_drop(peer, "channel_full");
    }

    /// Series (family name + label set) in the registry whose `peer`
    /// label equals `peer`.
    fn series_for_peer(m: &BgpMetrics, peer: &str) -> Vec<String> {
        m.registry()
            .gather()
            .into_iter()
            .flat_map(|family| {
                let name = family.name().to_string();
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == "peer" && label.value() == peer)
                    })
                    .map(|_| name.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn reap_peer_series_removes_every_peer_labeled_family() {
        let m = BgpMetrics::new();
        populate_all_peer_families(&m, "10.0.0.1");
        populate_all_peer_families(&m, "10.0.0.2");
        // 27 peer-labeled families; state transitions hold two series.
        assert_eq!(series_for_peer(&m, "10.0.0.1").len(), 28);

        m.reap_peer_series("10.0.0.1");

        let leftovers = series_for_peer(&m, "10.0.0.1");
        assert!(
            leftovers.is_empty(),
            "peer-labeled families not reaped: {leftovers:?}"
        );
        // The other peer's series are untouched.
        assert_eq!(series_for_peer(&m, "10.0.0.2").len(), 28);
    }

    #[test]
    fn reap_peer_series_spares_other_peers_and_global_counters() {
        let m = BgpMetrics::new();
        // One gauge family, one counter family, one multi-label family,
        // for two peers each.
        m.set_gr_active("10.0.0.1", true);
        m.set_gr_active("10.0.0.2", true);
        m.record_max_prefix_exceeded("10.0.0.1");
        m.record_max_prefix_exceeded("10.0.0.2");
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.1", "open_confirm", "established");
        m.record_state_transition("10.0.0.2", "idle", "connect");
        // Process-global counters must be untouched.
        m.record_fib_route_installed();
        m.record_event_outbox_cursor_gap();

        m.reap_peer_series("10.0.0.1");

        let text = gather_text(&m);
        assert!(
            !text.contains("10.0.0.1"),
            "reaped peer still present in exposition:\n{text}"
        );
        assert!(text.contains(r#"bgp_gr_active_peers{peer="10.0.0.2"} 1"#));
        assert!(text.contains(r#"bgp_max_prefix_exceeded_total{peer="10.0.0.2"} 1"#));
        assert!(text.contains(r#"peer="10.0.0.2""#));
        assert!(text.contains("bgp_fib_routes_installed_total 1"));
        assert!(text.contains("bgp_event_outbox_cursor_gap_total 1"));
    }

    #[test]
    fn reap_peer_series_removes_all_label_combinations_for_peer() {
        let m = BgpMetrics::new();
        // Multi-label family with several combinations per peer.
        m.record_message_sent("10.0.0.1", "open");
        m.record_message_sent("10.0.0.1", "keepalive");
        m.record_message_sent("10.0.0.1", "update");
        m.record_message_sent("10.0.0.2", "keepalive");

        m.reap_peer_series("10.0.0.1");

        let family = m
            .registry()
            .gather()
            .into_iter()
            .find(|f| f.name() == "bgp_messages_sent_total")
            .expect("family present");
        assert_eq!(family.get_metric().len(), 1);
        assert!(
            family.get_metric()[0]
                .get_label()
                .iter()
                .any(|l| l.name() == "peer" && l.value() == "10.0.0.2")
        );
    }

    #[test]
    fn reap_peer_series_without_series_is_noop() {
        let m = BgpMetrics::new();
        // Nothing recorded at all — must not panic.
        m.reap_peer_series("192.0.2.99");
        // Series exist, but none for the reaped peer.
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.reap_peer_series("192.0.2.99");
        assert_eq!(
            m.state_transitions
                .with_label_values(&["10.0.0.1", "idle", "connect"])
                .get(),
            1
        );
        // Reaping the same peer twice is also a no-op.
        m.reap_peer_series("10.0.0.1");
        m.reap_peer_series("10.0.0.1");
        let text = gather_text(&m);
        assert!(!text.contains("10.0.0.1"));
    }

    #[test]
    fn bmp_replay_attempts_counter() {
        let m = BgpMetrics::new();
        m.record_bmp_replay_attempt("127.0.0.1:5000");
        m.record_bmp_replay_attempt("127.0.0.1:5000");
        m.record_bmp_replay_attempt("127.0.0.1:5001");

        let a = m
            .bmp_replay_attempts
            .with_label_values(&["127.0.0.1:5000"])
            .get();
        assert_eq!(a, 2);

        let b = m
            .bmp_replay_attempts
            .with_label_values(&["127.0.0.1:5001"])
            .get();
        assert_eq!(b, 1);
    }
}
