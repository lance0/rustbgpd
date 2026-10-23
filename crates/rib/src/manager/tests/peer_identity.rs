//! Generational peer handles at the RIB boundary: stale handles, the
//! scoped tie-break through the peer table, and endpoint rebinding.

use super::*;
use crate::{PeerEndpoint, PeerId};

fn scoped(address: &str, interface: &str) -> PeerId {
    PeerId::allocate(PeerEndpoint::new(address.parse().unwrap(), Some(interface)))
}

/// A route from `peer`, equal on every attribute to any other this module
/// builds: selection falls through to the peer tie-break.
fn tied_route(peer: PeerId) -> Route {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(198, 51, 100, 1));
    route.peer = peer;
    route
}

async fn announce(tx: &mpsc::Sender<RibUpdate>, peer: PeerId, session_id: u64) {
    tx.send(RibUpdate::RoutesReceived {
        session_id,
        peer,
        announced: vec![tied_route(peer)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
}

fn spawn_manager() -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    (tx, tokio::spawn(manager.run()))
}

/// Acceptance: a message a deleted neighbor's session sent late, carrying
/// the old handle, is dropped after the neighbor is deleted and re-added
/// at the same endpoint, instead of landing on the new neighbor.
#[tokio::test]
async fn a_stale_handle_message_after_delete_and_re_add_is_dropped() {
    let (tx, actor) = spawn_manager();
    let old = scoped("fe80::1", "eth0");
    announce(&tx, old, 1).await;
    assert_eq!(query_received_routes(&tx, old).await.len(), 1);

    // Deleted for good: the peer manager's cleanup, then the release.
    tx.send(RibUpdate::PeerDeleted {
        peer: old,
        label: None,
        keep_series: false,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::ReleasePeer { peer: old }).await.unwrap();
    assert!(query_best_routes(&tx).await.is_empty());

    // Re-added at the same endpoint: a new handle.
    let new = scoped("fe80::1", "eth0");
    assert_ne!(new, old);
    announce(&tx, old, 1).await;
    assert!(
        query_received_routes(&tx, old).await.is_empty(),
        "the stale handle's announcement was installed"
    );
    assert!(query_best_routes(&tx).await.is_empty());
    announce(&tx, new, 2).await;
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, new);

    drop(tx);
    actor.await.unwrap();
}

/// Acceptance: two neighbors on one link-local address, equal on every
/// attribute, select the same winner whatever order they were configured
/// (handles allocated) or connected (routes arrived) in: the lower
/// interface name, through the peer table, never the handle order.
#[tokio::test]
async fn same_address_neighbors_select_the_same_winner_in_any_order() {
    for allocate_eth0_first in [true, false] {
        for eth0_arrives_first in [true, false] {
            let (eth0, eth1) = if allocate_eth0_first {
                let eth0 = scoped("fe80::1", "eth0");
                (eth0, scoped("fe80::1", "eth1"))
            } else {
                let eth1 = scoped("fe80::1", "eth1");
                (scoped("fe80::1", "eth0"), eth1)
            };
            let (tx, actor) = spawn_manager();
            let order = if eth0_arrives_first {
                [eth0, eth1]
            } else {
                [eth1, eth0]
            };
            for peer in order {
                announce(&tx, peer, 0).await;
            }
            let best = query_best_routes(&tx).await;
            assert_eq!(best.len(), 1);
            assert_eq!(
                best[0].peer, eth0,
                "allocated eth0 first: {allocate_eth0_first}, arrived first: {eth0_arrives_first}"
            );

            // Withdrawing the winner hands the prefix to the survivor.
            tx.send(RibUpdate::PeerDown {
                peer: eth0,
                session_id: 0,
            })
            .await
            .unwrap();
            let best = query_best_routes(&tx).await;
            assert_eq!(best.len(), 1);
            assert_eq!(best[0].peer, eth1);

            drop(tx);
            actor.await.unwrap();
            assert!(eth0.release());
            assert!(eth1.release());
        }
    }
}

/// An address change is a session down then up under the same handle.
/// Routes retained for Graceful Restart keep resolving to the endpoint
/// they were learned on until the rebind, which purges them first.
#[tokio::test]
async fn a_rebind_purges_routes_retained_from_the_previous_endpoint() {
    let (tx, actor) = spawn_manager();
    let peer = scoped("fe80::1", "swp1");
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 1,
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(198, 51, 100, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    announce(&tx, peer, 1).await;
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 1,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let retained = query_received_routes(&tx, peer).await;
    assert_eq!(retained.len(), 1);
    assert!(retained[0].is_stale);
    assert_eq!(
        retained[0].peer.addr(),
        "fe80::1".parse::<IpAddr>().unwrap()
    );

    let next = PeerEndpoint::new("fe80::2".parse().unwrap(), Some("swp1"));
    tx.send(RibUpdate::RebindPeer {
        peer,
        endpoint: next.clone(),
    })
    .await
    .unwrap();
    assert!(query_received_routes(&tx, peer).await.is_empty());
    assert!(query_best_routes(&tx).await.is_empty());
    assert_eq!(peer.endpoint(), Some(next));
    assert!(peer.is_live(), "a rebind keeps the handle");

    // The new endpoint's session registers and learns under the same handle.
    announce(&tx, peer, 2).await;
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer);
    assert_eq!(best[0].peer.addr(), "fe80::2".parse::<IpAddr>().unwrap());

    drop(tx);
    actor.await.unwrap();
    assert!(peer.release());
}

/// History keeps the endpoint each event recorded. A rebind moves the
/// handle to a new address; the events built before it, including the
/// teardown's withdrawals, still name the old address, for unicast and EVPN
/// alike, and none name the new one.
#[tokio::test]
async fn route_event_history_keeps_the_endpoint_each_event_recorded() {
    let (tx, actor) = spawn_manager();
    let old = Ipv4Addr::new(192, 0, 2, 1);
    let new: IpAddr = "192.0.2.9".parse().unwrap();
    let peer = PeerId::allocate(PeerEndpoint::new(IpAddr::V4(old), None));
    let mut imet = make_evpn_imet(old, 7);
    imet.peer = peer;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![tied_route(peer)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RebindPeer {
        peer,
        endpoint: PeerEndpoint::new(new, None),
    })
    .await
    .unwrap();

    let unicast = |address: IpAddr| {
        let tx = tx.clone();
        async move {
            let (reply, response) = oneshot::channel();
            tx.send(RibUpdate::QueryRouteEventHistory {
                peer: Some(address),
                peer_interface: None,
                afi: None,
                prefix: None,
                limit: 0,
                reply,
            })
            .await
            .unwrap();
            response.await.unwrap()
        }
    };
    let evpn = |address: IpAddr| {
        let tx = tx.clone();
        async move {
            let (reply, response) = oneshot::channel();
            tx.send(RibUpdate::QueryEvpnRouteEventHistory {
                peer: Some(address),
                route_type: None,
                rd: None,
                event_types: std::collections::BTreeSet::new(),
                limit: 0,
                reply,
            })
            .await
            .unwrap();
            response.await.unwrap()
        }
    };
    let old = IpAddr::V4(old);
    let recorded: Vec<_> = unicast(old)
        .await
        .iter()
        .map(|event| (event.event_type, event.peer, event.previous_peer))
        .collect();
    assert_eq!(
        recorded,
        [
            (RouteEventType::Added, Some(old), None),
            (RouteEventType::Withdrawn, None, Some(old)),
        ]
    );
    let recorded: Vec<_> = evpn(old)
        .await
        .iter()
        .map(|event| (event.event_type, event.peer, event.previous_peer))
        .collect();
    assert_eq!(
        recorded,
        [
            (RouteEventType::Added, Some(old), None),
            (RouteEventType::Withdrawn, None, Some(old)),
        ]
    );
    assert!(unicast(new).await.is_empty());
    assert!(evpn(new).await.is_empty());

    drop(tx);
    actor.await.unwrap();
    assert!(peer.release());
}

/// Acceptance: an MRT snapshot lists two neighbors on one link-local
/// address as two peer entries, each with the address the RIB had for it
/// in the snapshot's turn, so the encoder gives each its own index.
#[tokio::test]
async fn an_mrt_snapshot_lists_same_address_neighbors_separately() {
    let (tx, actor) = spawn_manager();
    let (eth0, eth1) = (scoped("fe80::1", "eth0"), scoped("fe80::1", "eth1"));
    announce(&tx, eth0, 1).await;
    announce(&tx, eth1, 2).await;
    let snapshot = query_mrt_snapshot(&tx).await;
    let mut peers: Vec<_> = snapshot
        .peers
        .iter()
        .map(|entry| (entry.peer, entry.peer_addr))
        .collect();
    peers.sort_unstable();
    let mut expected = vec![
        (eth0, "fe80::1".parse::<IpAddr>().unwrap()),
        (eth1, "fe80::1".parse().unwrap()),
    ];
    expected.sort_unstable();
    assert_eq!(peers, expected);
    assert_eq!(snapshot.routes.len(), 2);

    drop(tx);
    actor.await.unwrap();
}

/// Acceptance: when the interface breaks the tie between two neighbors on
/// one link-local address, explain names each neighbor's scope in the
/// human detail and keeps the machine reason `lower_peer_address`.
#[tokio::test]
async fn explain_names_the_scope_when_the_interface_breaks_the_tie() {
    let (tx, actor) = spawn_manager();
    let (eth1, eth0) = (scoped("fe80::1", "eth1"), scoped("fe80::1", "eth0"));
    announce(&tx, eth1, 1).await;
    announce(&tx, eth0, 2).await;
    let explain = query_explain_best_path(&tx, tied_route(eth0).prefix).await;
    assert_eq!(explain.best.as_ref().map(|best| best.peer), Some(eth0));
    let reason = explain.best_reason.expect("a contested prefix");
    assert_eq!(reason.code(), "lower_peer_address");
    assert_eq!(
        explain.best_reason_detail,
        "peer fe80::1%eth0 < fe80::1%eth1 (scope tie-break)"
    );
    let [loser] = explain.candidates.as_slice() else {
        panic!("one candidate expected");
    };
    assert_eq!(loser.route.peer, eth1);
    assert_eq!(loser.vs_best_reason.code(), "lower_peer_address");
    assert_eq!(
        loser.vs_best_detail,
        "peer fe80::1%eth1 > fe80::1%eth0 (scope tie-break)"
    );

    drop(tx);
    actor.await.unwrap();
}

/// Acceptance: a paged all-neighbor received listing whose page boundary
/// falls between two same-address neighbors' routes for one prefix and path
/// id returns every row exactly once. Keyed by address, both rows share one
/// cursor key and the second page skips the second neighbor.
#[tokio::test]
async fn a_page_boundary_between_same_address_neighbors_skips_no_row() {
    let (tx, actor) = spawn_manager();
    let (eth0, eth1) = (scoped("fe80::1", "eth0"), scoped("fe80::1", "eth1"));
    announce(&tx, eth0, 1).await;
    announce(&tx, eth1, 2).await;
    let page = |after, expected_version| {
        let tx = tx.clone();
        async move {
            let (reply, rx) = oneshot::channel();
            tx.send(RibUpdate::QueryRoutesPage {
                scope: RouteQueryScope::Received { peer: None },
                filter: None,
                after,
                expected_version,
                page_size: 1,
                reply,
            })
            .await
            .unwrap();
            rx.await.unwrap().unwrap()
        }
    };
    let mut seen = Vec::new();
    let mut current = page(None, None).await;
    loop {
        seen.extend(current.routes.iter().map(|route| route.peer));
        if !current.has_more {
            break;
        }
        let after = current.routes.last().map(crate::update::route_query_key);
        current = page(after, Some(current.version)).await;
    }
    seen.sort_unstable();
    let mut expected = vec![eth0, eth1];
    expected.sort_unstable();
    assert_eq!(seen, expected);

    drop(tx);
    actor.await.unwrap();
}
