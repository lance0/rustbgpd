use std::collections::BTreeMap;

use super::*;

const RECEIVER_SESSION: u64 = 7;
const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);

fn rtbh_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 7), 32)
}

/// A received BLACKHOLE path from `SOURCE`, with `filler`
/// further communities.
fn blackhole_path(prefix: Ipv4Prefix, path_id: u32, local_pref: u32, filler: u32) -> Route {
    let mut communities = vec![rustbgpd_wire::COMMUNITY_BLACKHOLE];
    communities.extend((0..filler).map(|n| 0xFDE8_0000 | n));
    path_with(prefix, path_id, local_pref, communities)
}

/// A received path from `SOURCE` carrying `communities`.
fn path_with(prefix: Ipv4Prefix, path_id: u32, local_pref: u32, communities: Vec<u32>) -> Route {
    let source = SOURCE;
    Route {
        prefix: Prefix::V4(prefix),
        peer: PeerId::from_addr(IpAddr::V4(source)),
        next_hop: IpAddr::V4(source),
        attributes: AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65_009])],
            }),
            PathAttribute::NextHop(source),
            PathAttribute::LocalPref(local_pref),
            PathAttribute::Communities(communities),
        ]),
        path_id,
        ..make_route(local_pref)
    }
}

async fn received(
    session: &PeerSession,
    source: Ipv4Addr,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) {
    session
        .rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: PeerId::from_addr(IpAddr::V4(source)),
            session_id: 0,
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
}

async fn next_export(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> OutboundRouteUpdate {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("RIB export")
        .expect("outbound channel remains open")
}

/// A 4 KiB Add-Path receiver (`send_max` 2, the session's real encoder) is
/// sent each `setup` batch from one source peer as its own update, then one
/// pass applies `announced` and `withdrawn`. Returns the wire after setup,
/// as key to community count, and the pass's envelope.
async fn setup_then(
    setup: Vec<Vec<Route>>,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) -> (BTreeMap<u32, usize>, OutboundRouteUpdate) {
    let (mut session, rib_rx) = make_test_session_with_metrics_and_identity(
        BgpMetrics::new(),
        SessionIdentity::primary(RECEIVER_SESSION),
    );
    let mut negotiated = negotiated_session(65_002, false);
    negotiated.peer_extended_message = false;
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Send);
    install_test_negotiated_session(&mut session, negotiated);
    assert_eq!(session.publish_export_profile().max_message_len(), 4_096);
    let (query_tx, query_rx) = mpsc::channel(8);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_task = tokio::spawn(manager.run());

    let receiver = PeerId::from_addr(session.peer_ip);
    let (outbound_tx, mut outbound) = mpsc::channel(16);
    session
        .rib_tx
        .send(RibUpdate::SetPeerExportEncoder {
            peer: receiver,
            session_id: RECEIVER_SESSION,
            encoder: session.export_encoder.clone(),
        })
        .await
        .unwrap();
    session
        .rib_tx
        .send(RibUpdate::PeerUp {
            peer: receiver,
            session_id: RECEIVER_SESSION,
            peer_asn: 65_002,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
            add_path_send_max: 2,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
    assert_ne!(next_export(&mut outbound).await.end_of_rib.len(), 0);

    let mut wire = BTreeMap::new();
    for batch in setup {
        received(&session, SOURCE, batch, vec![]).await;
        let installed = next_export(&mut outbound).await;
        for (_, path_id) in &installed.withdraw {
            wire.remove(path_id);
        }
        for route in installed.announce.iter() {
            wire.insert(route.path_id, route.communities().len());
        }
    }
    received(&session, SOURCE, announced, withdrawn).await;
    let pass = next_export(&mut outbound).await;

    drop(session);
    drop(query_tx);
    manager_task.await.unwrap();
    (wire, pass)
}

/// [`setup_then`] for a single RTBH row: its key and the pass's envelope.
async fn rtbh_then(
    first: Route,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) -> (u32, OutboundRouteUpdate) {
    let (wire, pass) = setup_then(vec![vec![first]], announced, withdrawn).await;
    assert_eq!(wire.len(), 1);
    (*wire.keys().next().unwrap(), pass)
}

/// The pass keeps the prefix blackholed between its UPDATEs: the RTBH key
/// is not withdrawn, and only the sendable blackhole path is announced, in
/// place at that key.
fn assert_replaced_in_place(rtbh_key: u32, pass: &OutboundRouteUpdate) {
    assert!(
        !pass
            .withdraw
            .contains(&(Prefix::V4(rtbh_prefix()), rtbh_key)),
        "the withdraw phase removes the RTBH key {rtbh_key} before any blackhole is announced: \
         withdraw {:?}",
        pass.withdraw
    );
    let announced: Vec<(u32, usize)> = pass
        .announce
        .iter()
        .map(|route| {
            assert!(
                route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
            );
            (route.path_id, route.communities().len())
        })
        .collect();
    assert_eq!(
        announced,
        [(rtbh_key, 1)],
        "only the sendable blackhole path is announced, in place at the RTBH key"
    );
}

/// One pass replaces the RTBH row with two blackholing paths, the
/// higher-ranked one too large for a single 4096-byte UPDATE: 1100 filler
/// communities put its exact single-route message over the ceiling. The
/// rejected path must not take the departing RTBH key, or the commit owes
/// that key's withdrawal ahead of the sendable path's announcement.
#[tokio::test]
async fn rejected_blackhole_replacement_leaves_the_rtbh_key_to_the_sendable_one() {
    let (rtbh_key, pass) = rtbh_then(
        blackhole_path(rtbh_prefix(), 1, 100, 0),
        vec![
            blackhole_path(rtbh_prefix(), 2, 300, 1_100),
            blackhole_path(rtbh_prefix(), 3, 200, 0),
        ],
        vec![(Prefix::V4(rtbh_prefix()), 1)],
    )
    .await;
    assert_replaced_in_place(rtbh_key, &pass);
}

/// The RTBH path itself grows past the ceiling while a second blackholing
/// path arrives in the same pass: the rejected path gives up its key, which
/// the sendable path takes over in place.
#[tokio::test]
async fn rtbh_grown_past_the_ceiling_hands_its_key_to_the_sendable_one() {
    let (rtbh_key, pass) = rtbh_then(
        blackhole_path(rtbh_prefix(), 2, 300, 0),
        vec![
            blackhole_path(rtbh_prefix(), 2, 300, 1_100),
            blackhole_path(rtbh_prefix(), 3, 200, 0),
        ],
        vec![],
    )
    .await;
    assert_replaced_in_place(rtbh_key, &pass);
}

/// An ordinary path at `#1` and an RTBH path at `#2` from one source peer;
/// the RTBH path then grows past the ceiling and outranks its sibling. The
/// rejected path holds no row, so the ordinary path keeps `#1`, not the
/// RTBH row's `#2` with `#1` withdrawn; the unsendable RTBH row's key is
/// withdrawn, as it would be with no planning at all.
#[tokio::test]
async fn rejected_rtbh_leaves_its_same_peer_sibling_on_its_key() {
    let (wire, pass) = setup_then(
        vec![
            vec![path_with(rtbh_prefix(), 1, 200, vec![])],
            vec![blackhole_path(rtbh_prefix(), 2, 100, 0)],
        ],
        vec![blackhole_path(rtbh_prefix(), 2, 300, 1_100)],
        vec![],
    )
    .await;
    assert_eq!(
        wire,
        BTreeMap::from([(1, 0), (2, 1)]),
        "ordinary at #1, RTBH at #2"
    );
    assert_eq!(
        pass.withdraw,
        [(Prefix::V4(rtbh_prefix()), 2)],
        "only the rejected RTBH row's key leaves"
    );
    assert_eq!(pass.announce.len(), 0, "the ordinary path stays as sent");
}
