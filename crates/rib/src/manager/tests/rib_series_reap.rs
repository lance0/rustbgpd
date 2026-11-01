//! The RIB's label reap at a neighbor's deletion covers exactly what the RIB
//! writes: every series it emitted for the neighbor goes, and the series a
//! new neighbor's session and peer manager emit under the same label first
//! stay (`BgpMetrics::reap_rib_peer_series`).

use std::collections::BTreeSet;

use super::outbound_prefix_limits::{announce, apply, limit_config, prepare};
use super::*;
use crate::test_support::peer_v4;

const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Every series labelled `peer`, as family name and label set.
fn series(metrics: &BgpMetrics, peer: &str) -> BTreeSet<String> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .flat_map(|family| {
            let name = family.name().to_owned();
            family
                .get_metric()
                .iter()
                .filter(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "peer" && label.value() == peer)
                })
                .map(|metric| {
                    let labels: Vec<_> = metric
                        .get_label()
                        .iter()
                        .map(|label| format!("{}={}", label.name(), label.value()))
                        .collect();
                    format!("{name}[{}]", labels.join(","))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn families(series: &BTreeSet<String>) -> BTreeSet<&str> {
    series
        .iter()
        .map(|series| series.split('[').next().unwrap_or_default())
        .collect()
}

fn peer_up(manager: &mut RibManager, session_id: u64) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer: peer_v4(TARGET),
        peer_asn: 65_002,
        peer_router_id: TARGET,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn routes(source: Ipv4Addr, octets: impl IntoIterator<Item = u8>) -> Vec<Route> {
    octets
        .into_iter()
        .map(|octet| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
                source,
            )
        })
        .collect()
}

/// The target's session `session_id` sends routes, handled to completion.
fn receive_from_target(
    manager: &mut RibManager,
    session_id: u64,
    octets: impl IntoIterator<Item = u8>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(TARGET),
        session_id,
        announced: routes(TARGET, octets),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
}

/// What a new neighbor's session and peer manager emit under its label
/// before any of its RIB messages: none of it is the RIB's to reap.
fn seed_session_and_peer_manager_series(metrics: &BgpMetrics, peer: &str) {
    metrics.set_peer_admin_enabled(peer, "", true);
    metrics.set_peer_info(peer, "", 65_002, "replacement", "");
    metrics.set_peer_session_state(peer, "", "connect");
    metrics.set_peer_session_established(peer, "", false);
    metrics.set_max_prefix_latched(peer, "", false);
    metrics.record_state_transition(peer, "idle", "connect");
    metrics.record_message_sent(peer, "open");
    metrics.initialize_exact_export_rejection_series(peer, ["ipv4_unicast"]);
    metrics.initialize_export_family_suppressed_series(
        peer,
        "ipv6_unicast",
        rustbgpd_telemetry::reason_labels::ExactExportReason::MissingIpv6NextHop,
    );
    metrics.initialize_update_malformed_series(peer);
    metrics.set_rfc8212_missing_policy(peer, false, false);
    metrics.record_policy_routes(peer, "inline", "import", "permit");
}

/// The census. A neighbor's RIB life writes its `peer`-labelled families:
/// received and advertised prefixes, update group, export policy counts,
/// outbound prefix capacity and a blocked prefix, route refresh, stale
/// session messages and teardowns, a replaced registration, a dropped
/// outbound update, and Graceful Restart with its timer expiry. The RIB's
/// reap removes all of them and leaves every series a new neighbor's
/// session and peer manager emit under the label. Red proofs: dropping a
/// family the RIB writes from `reap_rib_peer_series` leaves its series; a
/// session or peer-manager family in the list removes the new neighbor's.
#[test]
fn the_rib_reap_covers_exactly_what_the_rib_writes() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let target = peer_v4(TARGET);
    let source = peer_v4(SOURCE);
    let label = TARGET.to_string();

    announce(&mut manager, source, routes(SOURCE, [1]));
    let first = peer_up(&mut manager, 1);
    receive_from_target(&mut manager, 1, [41, 42]);
    prepare(
        &mut manager,
        1,
        limit_config(&[(target, Some(1), None)], &[]),
    )
    .unwrap();
    apply(&mut manager, 1, true).unwrap();
    announce(&mut manager, source, routes(SOURCE, [2]));
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 1,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    // A late session's messages, then a second session replacing the first.
    receive_from_target(&mut manager, 99, [43]);
    manager.handle_update(RibUpdate::PeerDown {
        peer: target,
        session_id: 99,
    });
    drop(first);
    let second = peer_up(&mut manager, 2);
    drop(second);
    announce(&mut manager, source, routes(SOURCE, [3]));
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: target,
        session_id: 2,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let written = series(&metrics, &label);
    manager.sweep_gr_stale(target);
    let written: BTreeSet<_> = written.union(&series(&metrics, &label)).cloned().collect();
    let driven = BTreeSet::from([
        "bgp_rib_prefixes",
        "bgp_rib_adj_out_prefixes",
        "bgp_peer_update_group",
        "bgp_policy_routes_total",
        "bgp_outbound_prefix_usage",
        "bgp_outbound_prefix_limit",
        "bgp_outbound_prefix_headroom",
        "bgp_outbound_prefix_blocking",
        "bgp_outbound_prefix_blocked_total",
        "bgp_route_refresh_in_progress",
        "bgp_route_refresh_stale_entries",
        "bgp_rib_stale_session_message_ignored_total",
        "bgp_rib_stale_peer_down_ignored_total",
        "bgp_rib_outbound_registration_replaced_total",
        "bgp_outbound_route_drops_total",
        "bgp_gr_active_peers",
        "bgp_gr_stale_routes",
        "bgp_gr_timer_expired_total",
    ]);
    let written_families = families(&written);
    let missing: Vec<_> = driven.difference(&written_families).collect();
    assert!(
        missing.is_empty(),
        "the scenario no longer drives {missing:?}"
    );

    seed_session_and_peer_manager_series(&metrics, &label);
    let foreign: BTreeSet<_> = series(&metrics, &label)
        .difference(&written)
        .cloned()
        .collect();
    assert!(!foreign.is_empty());
    metrics.reap_rib_peer_series(&label);
    assert_eq!(
        series(&metrics, &label),
        foreign,
        "the RIB reap removes what the RIB wrote and nothing else"
    );
}
