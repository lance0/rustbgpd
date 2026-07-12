use std::any::Any;
use std::collections::HashSet;
use std::sync::{Mutex, RwLock};

use super::*;
use crate::update::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportErrorCode,
    ExactExportKey, ExactExportResult, ExactExportSnapshot,
};

#[derive(Clone)]
struct MockExportConfig {
    generation: u64,
    rejected: HashSet<ExactExportKey>,
}

struct MockExactExportEncoder {
    config: RwLock<MockExportConfig>,
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
}

impl MockExactExportEncoder {
    fn accepting(generation: u64) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(MockExportConfig {
                generation,
                rejected: HashSet::new(),
            }),
            probed: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn set_profile(&self, generation: u64, rejected: impl IntoIterator<Item = ExactExportKey>) {
        *self.config.write().unwrap() = MockExportConfig {
            generation,
            rejected: rejected.into_iter().collect(),
        };
    }

    fn probed(&self) -> Vec<ExactExportKey> {
        self.probed.lock().unwrap().clone()
    }
}

struct MockExactExportSnapshot {
    config: MockExportConfig,
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
}

impl ExactExportSnapshot for MockExactExportSnapshot {
    fn owner_id(&self) -> u64 {
        1
    }

    fn generation(&self) -> u64 {
        self.config.generation
    }

    fn probe_announcement(
        &self,
        candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        let key = candidate.key();
        self.probed.lock().unwrap().push(key.clone());
        if self.config.rejected.contains(&key) {
            return Err(ExactExportError::new(
                ExactExportErrorCode::MessageTooLong,
                "fixture route exceeds the classic message ceiling ".repeat(16),
            ));
        }
        Ok(ExactExportResult {
            encoded_len: 64,
            max_len: 65_535,
            generation: self.config.generation,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExactExportEncoder for MockExactExportEncoder {
    fn owner_id(&self) -> u64 {
        1
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(MockExactExportSnapshot {
            config: self.config.read().unwrap().clone(),
            probed: Arc::clone(&self.probed),
        })
    }
}

#[derive(Default)]
struct ExactBatch {
    announce: Vec<Route>,
    withdraw: Vec<(Prefix, u32)>,
    flowspec_announce: Vec<FlowSpecRoute>,
    flowspec_withdraw: Vec<crate::route::FlowSpecKey>,
    evpn_announce: Vec<EvpnRibRoute>,
    evpn_withdraw: Vec<rustbgpd_wire::EvpnRouteKey>,
    bgpls_announce: Vec<BgpLsRibRoute>,
    bgpls_withdraw: Vec<BgpLsRouteKey>,
    vpn_announce: Vec<VpnRibRoute>,
    vpn_withdraw: Vec<crate::route::VpnRibRouteKey>,
    labeled_announce: Vec<crate::route::LabeledRibRoute>,
    labeled_withdraw: Vec<crate::route::LabeledRibRouteKey>,
    rtc_announce: Vec<crate::route::RtcRibRoute>,
    rtc_withdraw: Vec<crate::route::RtcRibRouteKey>,
}

fn test_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn register_exact_target(
    manager: &mut RibManager,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(16);
    manager.outbound_peers.insert(peer, tx);
    manager.peer_export_encoders.insert(peer, encoder);
    rx
}

fn commit_batch(manager: &mut RibManager, peer: IpAddr, batch: ExactBatch) -> bool {
    let next_hop_override = vec![None; batch.announce.len()].into();
    manager.try_send_and_commit_outbound_update(
        peer,
        next_hop_override,
        batch.announce.into(),
        batch.withdraw,
        Vec::new(),
        Vec::new(),
        batch.flowspec_announce,
        batch.flowspec_withdraw,
        batch.evpn_announce,
        batch.evpn_withdraw,
        batch.bgpls_announce,
        batch.bgpls_withdraw,
        batch.vpn_announce,
        batch.vpn_withdraw,
        batch.labeled_announce,
        batch.labeled_withdraw,
        batch.rtc_announce,
        batch.rtc_withdraw,
    )
}

#[test]
fn exact_export_error_detail_is_bounded_by_unicode_scalars() {
    let error = ExactExportError::new(ExactExportErrorCode::Encoding, "xé".repeat(300));
    assert_eq!(error.detail().chars().count(), 256);
    assert!(error.detail().is_char_boundary(error.detail().len()));
}

#[tokio::test]
async fn private_route_rejection_withdraws_once_then_recovers() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(198, 51, 100, 1));
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let encoder = MockExactExportEncoder::accepting(11);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let accepted = rx.recv().await.unwrap();
    assert_eq!(accepted.announce.len(), 1);
    assert_eq!(accepted.announce[0].prefix, route.prefix);
    assert_eq!(accepted.announce[0].peer, route.peer);
    assert_eq!(accepted.exact_export_snapshot.unwrap().generation(), 11);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_some());

    encoder.set_profile(12, [key.clone()]);
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let rejected = rx.recv().await.unwrap();
    assert!(rejected.announce.is_empty());
    assert_eq!(rejected.withdraw, vec![(route.prefix, 0)]);
    assert_eq!(rejected.exact_export_snapshot.unwrap().generation(), 12);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());
    assert_eq!(
        manager.peer_unexportable[&peer],
        HashSet::from([key.clone()])
    );

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let repeated = rx.recv().await.unwrap();
    assert!(repeated.announce.is_empty());
    assert!(repeated.withdraw.is_empty(), "repeated rejection is quiet");
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());

    encoder.set_profile(13, []);
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let recovered = rx.recv().await.unwrap();
    assert_eq!(recovered.announce.len(), 1);
    assert_eq!(recovered.announce[0].prefix, route.prefix);
    assert_eq!(recovered.announce[0].peer, route.peer);
    assert!(recovered.withdraw.is_empty());
    assert_eq!(recovered.exact_export_snapshot.unwrap().generation(), 13);
    assert!(!manager.peer_unexportable.contains_key(&peer));
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_some());
}

#[tokio::test]
async fn every_route_family_is_probed_before_commit() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let source = Ipv4Addr::new(198, 51, 100, 2);
    let unicast = make_route(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24), source);
    let flowspec = make_flowspec_route(source);
    let evpn = make_evpn_imet(source, 101);
    let bgpls = make_bgpls_route(source, 0x41, 100);
    let vpn = make_vpn_rib_route(source, 41, 1041, 100);
    let labeled = make_labeled_rib_route(source, 42, 1042, 100);
    let rtc = make_rtc_rib_route(source, 43, 100);
    let expected = HashSet::from([
        ExactExportKey::Unicast(unicast.prefix, unicast.path_id),
        ExactExportKey::FlowSpec(flowspec.selection_key()),
        ExactExportKey::Evpn(evpn.key()),
        ExactExportKey::BgpLs(bgpls.key()),
        ExactExportKey::Vpn(vpn.key()),
        ExactExportKey::Labeled(labeled.key()),
        ExactExportKey::Rtc(rtc.key()),
    ]);
    for key in &expected {
        assert!(
            key.bounded_log_identity().len() <= 96,
            "diagnostic identity must stay bounded: {}",
            key.bounded_log_identity()
        );
    }

    let encoder = MockExactExportEncoder::accepting(21);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![unicast],
            flowspec_announce: vec![flowspec],
            evpn_announce: vec![evpn],
            bgpls_announce: vec![bgpls],
            vpn_announce: vec![vpn],
            labeled_announce: vec![labeled],
            rtc_announce: vec![rtc],
            ..ExactBatch::default()
        }
    ));

    let update = rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.evpn_announce.len(), 1);
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.labeled_announce.len(), 1);
    assert_eq!(update.rtc_announce.len(), 1);
    assert_eq!(
        encoder.probed().into_iter().collect::<HashSet<_>>(),
        expected
    );
}

#[test]
fn route_bearing_commit_without_encoder_fails_closed() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 2, 0), 24),
        Ipv4Addr::new(198, 51, 100, 3),
    );
    let mut manager = test_manager();
    let (tx, mut rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, tx);

    assert!(!commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route],
            ..ExactBatch::default()
        }
    ));
    assert!(!manager.adj_ribs_out.contains_key(&peer));
    assert!(rx.try_recv().is_err());
}

#[test]
fn missing_encoder_does_not_consume_retry_state() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 3, 0), 24),
        Ipv4Addr::new(198, 51, 100, 4),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let mut manager = test_manager();
    let (tx, _rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, tx);
    manager
        .peer_unexportable
        .insert(peer, HashSet::from([key.clone()]));
    manager
        .pending_otc_blocked
        .entry(peer)
        .or_default()
        .insert((route.prefix, route.path_id), route.clone());

    assert!(!commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            withdraw: vec![(route.prefix, route.path_id)],
            ..ExactBatch::default()
        }
    ));
    assert!(manager.peer_unexportable[&peer].contains(&key));
    assert!(manager.pending_otc_blocked[&peer].contains_key(&(route.prefix, route.path_id)));
}

#[test]
fn rejection_pruning_follows_sparse_overlay_liveness() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 4, 0), 24),
        Ipv4Addr::new(198, 51, 100, 5),
    );
    route.path_id = 42;
    // The rejected overlay records the outbound single-best identity, not
    // the source's inbound Add-Path ID.
    let key = ExactExportKey::Unicast(route.prefix, 0);
    let mut manager = test_manager();
    let mut rib = AdjRibIn::new(source);
    rib.insert(route.clone());
    manager.ribs.insert(source, rib);
    manager
        .peer_unexportable
        .insert(target, HashSet::from([key.clone()]));

    manager.prune_exact_export_rejections();
    assert!(manager.peer_unexportable[&target].contains(&key));

    manager.forget_exact_export_rejections([ExactExportKey::Unicast(route.prefix, 42)]);
    assert!(
        !manager.peer_unexportable.contains_key(&target),
        "targeted withdrawal cleanup must normalize inbound and outbound path IDs"
    );
    manager
        .peer_unexportable
        .insert(target, HashSet::from([key]));

    manager
        .ribs
        .get_mut(&source)
        .unwrap()
        .withdraw(&route.prefix, 42);
    manager.prune_exact_export_rejections();
    assert!(!manager.peer_unexportable.contains_key(&target));
}

async fn peer_up_with_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 7,
        encoder,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 7,
        peer,
        peer_asn: 65_100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn advertised_count(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> usize {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

async fn advertised_routes(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<Route> {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

async fn update_group(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> String {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario covers grouped rejection, source flip, regroup, explain, and projections"
)]
async fn grouped_classic_rejection_is_a_member_local_overlay_across_source_flip_and_regroup() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let classic = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let extended = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let source_a = Ipv4Addr::new(198, 51, 100, 10);
    let source_b = Ipv4Addr::new(198, 51, 100, 11);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route_a = make_route_with_lp(prefix, source_a, 100);
    let route_b = make_route_with_lp(prefix, source_b, 200);
    let key = ExactExportKey::Unicast(route_a.prefix, route_a.path_id);
    let classic_encoder = MockExactExportEncoder::accepting(31);
    classic_encoder.set_profile(31, [key]);
    let extended_encoder = MockExactExportEncoder::accepting(32);
    let mut classic_rx = peer_up_with_encoder(&tx, classic, classic_encoder).await;
    let mut extended_rx = peer_up_with_encoder(&tx, extended, extended_encoder).await;
    assert_eq!(update_group(&tx, classic).await, "group:0");
    assert_eq!(update_group(&tx, extended).await, "group:0");

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_a),
        announced: vec![route_a],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    let classic_first = classic_rx.recv().await.unwrap();
    let extended_first = extended_rx.recv().await.unwrap();
    assert!(classic_first.announce.is_empty());
    assert_eq!(extended_first.announce.len(), 1);
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert_eq!(advertised_count(&tx, extended).await, 1);
    assert!(advertised_routes(&tx, classic).await.is_empty());
    assert_eq!(advertised_routes(&tx, extended).await.len(), 1);
    let classic_explain = query_explain_advertised_route(&tx, classic, Prefix::V4(prefix)).await;
    assert_eq!(
        classic_explain.decision,
        crate::update::ExplainDecision::Deny
    );
    assert_eq!(
        classic_explain.gates.last().map(|gate| gate.code),
        Some("exact_export_rejected")
    );
    let extended_explain = query_explain_advertised_route(&tx, extended, Prefix::V4(prefix)).await;
    assert_eq!(
        extended_explain.decision,
        crate::update::ExplainDecision::Advertise
    );

    // Replacing the group-table winner must not erase the classic member's
    // rejection overlay just because the source peer changed.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_b),
        announced: vec![route_b],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    let classic_flip = classic_rx.recv().await.unwrap();
    let extended_flip = extended_rx.recv().await.unwrap();
    assert!(classic_flip.announce.is_empty());
    assert!(classic_flip.withdraw.is_empty());
    assert_eq!(extended_flip.announce.len(), 1);
    assert_eq!(extended_flip.announce[0].peer, IpAddr::V4(source_b));
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert_eq!(
        advertised_routes(&tx, extended).await[0].peer,
        IpAddr::V4(source_b)
    );

    // A content change moves only the classic peer to a new group. Its
    // one-shot old-view diff and its new group projection must both retain
    // the exact-export rejection rather than resurrecting the route.
    let unrelated = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 99, 0, 0), 16));
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: classic,
        export_policy: Some(deny_prefixes_chain(&[unrelated])),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    assert_ne!(
        update_group(&tx, classic).await,
        update_group(&tx, extended).await
    );
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert!(advertised_routes(&tx, classic).await.is_empty());
    assert_eq!(advertised_count(&tx, extended).await, 1);

    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdjRibOutCounts { reply })
        .await
        .unwrap();
    let counts = result.await.unwrap();
    assert!(counts[&classic].is_empty());
    assert_eq!(counts[&extended], vec![((Afi::Ipv4, Safi::Unicast), 1)]);

    drop(tx);
    handle.await.unwrap();
}
