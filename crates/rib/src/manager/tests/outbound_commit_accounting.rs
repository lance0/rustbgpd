//! Every failed outbound transaction is counted under exactly one metric:
//! writer-channel loss under `bgp_outbound_route_drops_total` for every
//! family, and fail-closed refusals under `bgp_outbound_commit_refusals_total`.

use rustbgpd_telemetry::reason_labels::OutboundCommitRefusal;

use super::*;
use crate::manager::distribution::{OutboundCommitBatch, OutboundCommitFailure};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70));
const PEER_LABEL: &str = "192.0.2.70";
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn drops(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_outbound_route_drops_total",
        &[("peer", PEER_LABEL)],
    )
}

fn refusals(metrics: &BgpMetrics) -> f64 {
    OutboundCommitRefusal::ALL
        .iter()
        .map(|reason| refusals_for(metrics, *reason))
        .sum()
}

fn refusals_for(metrics: &BgpMetrics, reason: OutboundCommitRefusal) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_outbound_commit_refusals_total",
        &[("peer", PEER_LABEL), ("reason", reason.as_str())],
    )
}

/// A registered peer with an exact export encoder and a one-slot writer queue.
fn registered(manager: &mut RibManager) -> mpsc::Receiver<crate::OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(1);
    manager.outbound_peers.insert(PEER, outbound_tx);
    manager
        .peer_export_encoders
        .insert(PEER, crate::manager::permissive_test_exact_export_encoder());
    outbound_rx
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn unicast_batch() -> OutboundCommitBatch {
    OutboundCommitBatch::with_unicast(
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            SOURCE,
        )]
        .into(),
        vec![None].into(),
    )
}

fn family_batches() -> Vec<(&'static str, OutboundCommitBatch)> {
    vec![
        ("unicast", unicast_batch()),
        (
            "flowspec",
            OutboundCommitBatch {
                flowspec_announce: vec![make_flowspec_route(SOURCE)],
                ..OutboundCommitBatch::default()
            },
        ),
        (
            "evpn",
            OutboundCommitBatch {
                evpn_announce: vec![make_evpn_imet(SOURCE, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
        (
            "bgpls",
            OutboundCommitBatch {
                bgpls_announce: vec![make_bgpls_route(SOURCE, 1, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
        (
            "vpn",
            OutboundCommitBatch {
                vpn_announce: vec![make_vpn_rib_route(SOURCE, 1, 100, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
        (
            "labeled",
            OutboundCommitBatch {
                labeled_announce: vec![make_labeled_rib_route(SOURCE, 1, 100, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
        (
            "rtc",
            OutboundCommitBatch {
                rtc_announce: vec![make_rtc_rib_route(SOURCE, 1, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
    ]
}

/// A full writer queue defers every family's transaction to dirty resync,
/// and each one is counted as a drop rather than a refusal.
#[test]
fn full_writer_channel_counts_a_drop_for_every_family() {
    for (family, batch) in family_batches() {
        let mut manager = manager();
        let _outbound_rx = registered(&mut manager);
        manager.outbound_peers[&PEER]
            .try_send(crate::OutboundRouteUpdate::default())
            .unwrap();

        assert_eq!(
            manager.try_send_and_commit_outbound_update(PEER, batch),
            Err(OutboundCommitFailure::WriterUnavailable),
            "{family}"
        );
        assert!(
            (drops(&manager.metrics) - 1.0).abs() < f64::EPSILON,
            "{family}"
        );
        assert!(refusals(&manager.metrics).abs() < f64::EPSILON, "{family}");
    }
}

/// The same families commit through an open queue without counting anything,
/// so the drop above is caused by the full queue and not by the payload.
#[test]
fn open_writer_channel_commits_every_family_without_counting() {
    for (family, batch) in family_batches() {
        let mut manager = manager();
        let mut outbound_rx = registered(&mut manager);

        assert_eq!(
            manager.try_send_and_commit_outbound_update(PEER, batch),
            Ok(()),
            "{family}"
        );
        assert!(outbound_rx.try_recv().is_ok(), "{family}");
        assert!(drops(&manager.metrics).abs() < f64::EPSILON, "{family}");
        assert!(refusals(&manager.metrics).abs() < f64::EPSILON, "{family}");
    }
}

#[test]
fn closed_or_unregistered_writer_counts_a_drop() {
    let mut manager = manager();
    drop(registered(&mut manager));
    assert_eq!(
        manager.try_send_and_commit_outbound_update(PEER, unicast_batch()),
        Err(OutboundCommitFailure::WriterUnavailable)
    );
    manager.outbound_peers.remove(&PEER);
    assert_eq!(
        manager.try_send_and_commit_outbound_update(PEER, unicast_batch()),
        Err(OutboundCommitFailure::WriterUnavailable)
    );
    assert!((drops(&manager.metrics) - 2.0).abs() < f64::EPSILON);
    assert!(refusals(&manager.metrics).abs() < f64::EPSILON);
}

#[test]
fn missing_encoder_is_a_refusal_not_a_drop() {
    let mut manager = manager();
    let _outbound_rx = registered(&mut manager);
    manager.peer_export_encoders.remove(&PEER);

    assert_eq!(
        manager.try_send_and_commit_outbound_update(PEER, unicast_batch()),
        Err(OutboundCommitFailure::Refused(
            OutboundCommitRefusal::MissingEncoder
        ))
    );
    assert!(
        (refusals_for(&manager.metrics, OutboundCommitRefusal::MissingEncoder) - 1.0).abs()
            < f64::EPSILON
    );
    assert!((refusals(&manager.metrics) - 1.0).abs() < f64::EPSILON);
    assert!(drops(&manager.metrics).abs() < f64::EPSILON);
}

/// An EVPN-owning update-group member with no recovery provenance cannot
/// admit an EVPN batch; the open writer queue is never charged.
#[test]
fn evpn_recovery_admission_is_a_refusal_not_a_drop() {
    let mut manager = manager();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer: PEER,
        session_id: 7,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 70),
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while outbound_rx.try_recv().is_ok() {}
    let gid = manager.grouped_member_of(PEER).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.evpn_recovery_handle(PEER).is_none());

    assert_eq!(
        manager.try_send_and_commit_outbound_update(
            PEER,
            OutboundCommitBatch {
                evpn_announce: vec![make_evpn_imet(SOURCE, 100)],
                ..OutboundCommitBatch::default()
            },
        ),
        Err(OutboundCommitFailure::Refused(
            OutboundCommitRefusal::EvpnRecovery
        ))
    );
    assert!(outbound_rx.try_recv().is_err());
    assert!(
        (refusals_for(&manager.metrics, OutboundCommitRefusal::EvpnRecovery) - 1.0).abs()
            < f64::EPSILON
    );
    assert!((refusals(&manager.metrics) - 1.0).abs() < f64::EPSILON);
    assert!(drops(&manager.metrics).abs() < f64::EPSILON);
}

fn dirty_resync(metrics: &BgpMetrics, outcome: &str) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_rib_dirty_resync_total",
        &[("outcome", outcome)],
    )
}

fn peer_up(
    peer: IpAddr,
    router_id: Ipv4Addr,
    outbound_tx: mpsc::Sender<crate::OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65000,
        peer_router_id: router_id,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}

async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    response.await.unwrap();
}

/// A message handler that drains armed resync work (here `PeerDown`) records
/// one `cleared` outcome when the loop reaches its end-of-iteration disarm.
#[tokio::test(start_paused = true)]
async fn handler_drained_resync_records_one_cleared_outcome() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    // The target's one-slot queue is left full by its initial EoR.
    let (target_tx, _target_rx) = mpsc::channel(1);
    tx.send(peer_up(PEER, Ipv4Addr::new(192, 0, 2, 70), target_tx))
        .await
        .unwrap();
    let source = IpAddr::V4(SOURCE);
    let (source_tx, _source_rx) = mpsc::channel(64);
    tx.send(peer_up(source, SOURCE, source_tx)).await.unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            SOURCE,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    barrier(&tx).await;

    // One tick finds the queue still full, so the timer re-arms.
    tokio::time::advance(Duration::from_millis(1100)).await;
    barrier(&tx).await;
    assert!(dirty_resync(&metrics, "still_dirty") >= 1.0);
    assert!(dirty_resync(&metrics, "cleared").abs() < f64::EPSILON);

    // The session closes before the next tick; its handler drains the work.
    tx.send(RibUpdate::PeerDown {
        peer: PEER,
        session_id: 0,
    })
    .await
    .unwrap();
    barrier(&tx).await;
    assert!((dirty_resync(&metrics, "cleared") - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}
