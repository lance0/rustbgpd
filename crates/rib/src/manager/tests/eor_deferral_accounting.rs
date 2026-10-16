//! A deferred End-of-RIB marker is counted under
//! `bgp_outbound_eor_deferrals_total`, never as a route drop.

use super::*;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

fn eor_deferrals(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_outbound_eor_deferrals_total",
        &[("peer", "10.0.0.2")],
    )
}

/// One route and a one-slot writer queue: the initial dump takes the slot, so
/// the separate End-of-RIB send hits a full channel.
fn peer_up_with_full_queue() -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    manager.enqueue_routes_received(
        source.into(),
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            source,
        )],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        None,
    );
    while manager.process_next_route_chunk() {}
    let (outbound_tx, out_rx) = mpsc::channel(1);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: PEER,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    (manager, out_rx)
}

/// Initial-dump End-of-RIB (`peer_lifecycle`).
#[test]
fn initial_dump_eor_on_full_channel_is_counted() {
    let (manager, _out_rx) = peer_up_with_full_queue();
    assert!(manager.pending_eor[&PEER].contains(&FAMILY));
    assert!((eor_deferrals(&manager.metrics) - 1.0).abs() < f64::EPSILON);
    assert!(
        counter_metric_value(&manager.metrics, "bgp_outbound_route_drops_total", &[]).abs()
            < f64::EPSILON
    );
}

/// Deferred-marker retry (`route_refresh`): a still-full channel counts again,
/// and a drained channel delivers without counting.
#[test]
fn flush_pending_eor_on_full_channel_is_counted() {
    let (mut manager, mut out_rx) = peer_up_with_full_queue();
    manager.flush_pending_eor(PEER);
    assert!((eor_deferrals(&manager.metrics) - 2.0).abs() < f64::EPSILON);
    assert!(manager.pending_eor[&PEER].contains(&FAMILY));

    assert!(!out_rx.try_recv().unwrap().announce.is_empty());
    manager.flush_pending_eor(PEER);
    assert_eq!(out_rx.try_recv().unwrap().end_of_rib, vec![FAMILY]);
    assert!((eor_deferrals(&manager.metrics) - 2.0).abs() < f64::EPSILON);
}
