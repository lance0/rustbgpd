//! Cold registration interleaved with real imports and session changes.

use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const DUAL: [(Afi, Safi); 2] = [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
type Inventory = BTreeMap<Prefix, (PeerId, u32)>;

fn receiver(n: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(198, 51, 100, n))
}

fn prefixes(i: u16) -> [Prefix; 2] {
    [
        Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(0x0a00_0000 + u32::from(i)),
            32,
        )),
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i),
            128,
        )),
    ]
}

fn route(prefix: Prefix, source: Ipv4Addr, pref: u32) -> Route {
    let mut route = make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0), source, pref);
    route.prefix = prefix;
    if matches!(prefix, Prefix::V6(_)) {
        route.next_hop = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));
    }
    route
}

fn fixture(per_family: u16) -> (RibManager, mpsc::Sender<RibUpdate>, Inventory) {
    let (tx, rx) = mpsc::channel(32);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.first_group_build_min_routes = 1;
    manager.outbound_row_credit_override = None;
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let expected: Inventory = (0..per_family)
        .flat_map(prefixes)
        .map(|prefix| (prefix, (peer_v4(SOURCE), 100)))
        .collect();
    let initial = expected
        .keys()
        .map(|&prefix| route(prefix, SOURCE, 100))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), initial));
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), expected.len());
    (manager, tx, expected)
}

fn join(
    manager: &mut RibManager,
    peer: PeerId,
    session: u64,
    families: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(32);
    let mut up = test_peer_up(peer, session, tx);
    let RibUpdate::PeerUp {
        is_ebgp,
        route_reflector_client,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *is_ebgp = false;
    *route_reflector_client = true;
    families.clone_into(sendable_families);
    manager.handle_update(up);
    rx
}

// Select already copied keys, independent of the table's hash seed or traversal order.
fn staged_keys(manager: &mut RibManager, expected: &Inventory) -> [[Prefix; 3]; 2] {
    for _ in 0..32 {
        manager.advance_pending_initial_registration();
        let mut families = [Vec::new(), Vec::new()];
        for &prefix in expected.keys() {
            let family = &mut families[usize::from(matches!(prefix, Prefix::V6(_)))];
            if family.len() < 3 && manager.first_group_contains(prefix) {
                family.push(prefix);
            }
        }
        if families.iter().all(|keys| keys.len() == 3) {
            return families.map(|keys| keys.try_into().unwrap());
        }
    }
    panic!("expected an unpublished page containing IPv4 and IPv6 routes");
}

fn finish(manager: &mut RibManager) {
    for _ in 0..64 {
        if manager.pending_initial_registrations.is_empty() && manager.first_group_build.is_none() {
            return;
        }
        manager.advance_pending_initial_registration();
    }
    panic!("registration did not settle");
}

#[tokio::test]
async fn pending_session_writer_orders_its_eor_but_later_config_allows_other_ingest() {
    let (mut manager, primary, _) = fixture(0);
    let incumbent = receiver(1);
    let _incumbent_rx = join(&mut manager, incumbent, 1, &DUAL);
    let (out, mut witness) = mpsc::channel(32);
    manager.handle_update(test_peer_up(receiver(3), 1, out));
    let slow = |slow| RibUpdate::PeerSlowState {
        peer: incumbent,
        session_id: 1,
        slow,
    };
    manager.handle_update(slow(true));
    let seed = prefixes(1)[0];
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![route(seed, SOURCE, 100)],
    ));
    drain_route_chunks(&mut manager);
    let _founder_rx = join(&mut manager, receiver(2), 1, &DUAL);
    manager.handle_update(slow(false));
    assert!(manager.first_group_pending_writer().is_some());

    let later_policy = |peer| {
        let (reply, response) = oneshot::channel();
        (
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy: None,
                reply,
            },
            response,
        )
    };
    let (first, mut reply1) = later_policy(receiver(3));
    let (second, mut reply2) = later_policy(receiver(3));
    primary.try_send(first).unwrap();
    assert!(manager.drain_ready_updates().await);
    // General-lane callers share the same intent ordering as primary callers.
    manager.serve_general_query(second);
    let marker = prefixes(2)[0];
    primary
        .try_send(test_routes_received(
            peer_v4(OTHER),
            vec![route(marker, OTHER, 100)],
        ))
        .unwrap();
    primary
        .try_send(RibUpdate::EndOfRib {
            peer: incumbent,
            session_id: 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .unwrap();
    assert!(manager.drain_ready_updates().await);
    assert!(manager.drain_ready_updates().await);
    assert!(manager.loc_rib.get(&marker).is_some());
    assert!(
        std::iter::from_fn(|| witness.try_recv().ok())
            .any(|out| out.announce.iter().any(|r| r.prefix == marker))
    );
    // The normal receiver also honors the barrier if the optional distribution
    // coalescer exhausted its elapsed-time budget before peeking at this EoR.
    assert!(!manager.drain_ready_updates().await);
    // It remains ahead of any following primary input until the older
    // slow-state change commits.
    assert!(manager.first_group_commit_frontier_reached());
    assert!(
        matches!(manager.primary_lookahead, Some(RibUpdate::EndOfRib { peer, .. }) if peer == incumbent)
    );
    assert!(manager.take_first_group_deferred_intent().is_none());
    assert!(matches!(
        reply1.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        reply2.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    for _ in 0..64 {
        if manager.first_group_pending_writer().is_none() {
            break;
        }
        manager.advance_first_group_build();
    }
    let first = manager.take_first_group_deferred_intent().unwrap();
    manager.handle_update(first);
    assert!(reply1.try_recv().is_ok());
    assert!(matches!(
        reply2.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let second = manager.take_first_group_deferred_intent().unwrap();
    manager.handle_update(second);
    assert!(reply2.try_recv().is_ok());
    assert!(
        matches!(manager.try_recv_primary(), Some(RibUpdate::EndOfRib { peer, .. }) if peer == incumbent)
    );
}

// One writer and its held peer's EoR, with two routes from a different
// peer awaiting reannouncement after a real GR restart and reconnect.
fn gr_writer_fixture(
    kept: Prefix,
    expired: Prefix,
) -> (
    RibManager,
    mpsc::Sender<RibUpdate>,
    [mpsc::Receiver<OutboundRouteUpdate>; 2],
) {
    let (mut manager, primary, _) = fixture(0);
    let incumbent = receiver(1);
    let incumbent_rx = join(&mut manager, incumbent, 1, &DUAL);
    let slow = |slow| RibUpdate::PeerSlowState {
        peer: incumbent,
        session_id: 1,
        slow,
    };
    manager.handle_update(slow(true));
    let source = peer_v4(SOURCE);
    manager.handle_update(test_routes_received(
        source,
        vec![route(kept, SOURCE, 100), route(expired, SOURCE, 100)],
    ));
    drain_route_chunks(&mut manager);
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: source,
        session_id: 0,
        restart_time: 10,
        stale_routes_time: 30,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    manager.handle_update(registering_peer_up(source, 1));
    assert!(manager.loc_rib.get(&kept).unwrap().is_stale);
    assert!(manager.loc_rib.get(&expired).unwrap().is_stale);

    let founder_rx = join(&mut manager, receiver(2), 1, &DUAL);
    manager.handle_update(slow(false));
    assert!(manager.first_group_pending_writer().is_some());
    primary
        .try_send(RibUpdate::EndOfRib {
            peer: incumbent,
            session_id: 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .unwrap();
    (manager, primary, [incumbent_rx, founder_rx])
}

#[tokio::test(start_paused = true)]
async fn held_writer_head_preserves_gr_expiry_cutoff_for_queued_refresh() {
    let source = peer_v4(SOURCE);
    let kept = prefixes(1)[0];
    let expired = prefixes(2)[0];
    let (mut manager, primary, _receivers) = gr_writer_fixture(kept, expired);
    let refresh =
        super::lifecycle::test_session_routes_received(source, 1, vec![route(kept, SOURCE, 190)]);
    primary.try_send(refresh).unwrap();

    let timer = ExpiryTimer::GrStale;
    let due = manager.gr_stale_deadlines[&source];
    tokio::time::advance(due - tokio::time::Instant::now()).await;
    let now = tokio::time::Instant::now();
    manager
        .expiry_cutoffs
        .observe(timer, Some(due), now, manager.primary_backlog());
    assert_eq!(manager.expiry_cutoffs.remaining(timer), 2);
    assert!(manager.can_receive_release_primary());
    assert!(manager.drain_before_expiry(timer).await);
    assert!(manager.first_group_commit_frontier_reached());
    assert_eq!(manager.expiry_cutoffs.remaining(timer), 2);

    for _ in 0..64 {
        if manager.first_group_pending_writer().is_none() {
            break;
        }
        manager.advance_first_group_build();
    }
    assert!(manager.first_group_pending_writer().is_none());
    let (reply, mut after_deadline) = oneshot::channel();
    primary
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    for _ in 0..8 {
        if !manager.drain_before_expiry(timer).await {
            break;
        }
    }
    assert!(manager.expiry_cutoffs.captured_at(timer).is_none());
    assert!(matches!(
        after_deadline.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    manager.sweep_gr_stale(source);
    let survivor = manager.loc_rib.get(&kept).unwrap();
    assert!(!survivor.is_stale);
    assert_eq!(survivor.local_pref(), 190);
    assert!(manager.loc_rib.get(&expired).is_none());
}

#[tokio::test(start_paused = true)]
async fn gr_expiry_during_sealed_writer_precedes_late_refresh() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let source = peer_v4(SOURCE);
    let kept = prefixes(1)[0];
    let (mut manager, primary, _receivers) = gr_writer_fixture(kept, prefixes(2)[0]);
    let deadline = manager.gr_stale_deadlines[&source];
    assert!(tokio::time::Instant::now() < deadline);
    assert!(!manager.drain_ready_updates().await);
    assert!(manager.first_group_commit_frontier_reached());
    assert_eq!(manager.primary_backlog(), 1);
    assert!(
        manager
            .expiry_cutoffs
            .captured_at(ExpiryTimer::GrStale)
            .is_none()
    );

    let mut actor = Box::pin(manager.run());
    let mut poll = || {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    };
    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    // The owner gets one real turn at the deadline with only the EoR queued.
    poll();
    let count = || {
        let (reply, rx) = oneshot::channel();
        primary
            .try_send(RibUpdate::QueryLocRibCount { reply })
            .unwrap();
        rx
    };
    let mut before_refresh = count();
    primary
        .try_send(super::lifecycle::test_session_routes_received(
            source,
            1,
            vec![route(kept, SOURCE, 190)],
        ))
        .unwrap();
    let mut after_refresh = count();
    for _ in 0..128 {
        poll();
        if let Ok(after) = after_refresh.try_recv() {
            assert_eq!(
                before_refresh.try_recv().unwrap(),
                0,
                "both stale routes must expire before late input"
            );
            assert_eq!(after, 1, "the late announcement installs a fresh route");
            return;
        }
    }
    panic!("the actor did not reach the input after expiry");
}

async fn assert_initial(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    expected: &Inventory,
    families: &[(Afi, Safi)],
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut seen = BTreeSet::new();
        let mut ends = Vec::new();
        while ends.len() < families.len() {
            let update = rx
                .recv()
                .await
                .expect("live peer must get its initial table");
            assert_eq!(update.unicast_withdrawals().count(), 0);
            for row in update
                .announce
                .iter()
                .filter(|row| update.announce_source_exclusion != Some(row.peer))
            {
                let afi = match row.prefix {
                    Prefix::V4(_) => Afi::Ipv4,
                    Prefix::V6(_) => Afi::Ipv6,
                };
                assert!(
                    !ends.contains(&(afi, Safi::Unicast)),
                    "row after family EoR"
                );
                assert!(
                    seen.insert(row.prefix),
                    "duplicate initial row {}",
                    row.prefix
                );
                assert_eq!(row.path_id, 0);
                assert_eq!(
                    expected.get(&row.prefix),
                    Some(&(row.peer, row.local_pref())),
                    "{}",
                    row.prefix
                );
            }
            for family in update.end_of_rib {
                assert!(
                    families.contains(&family) && !ends.contains(&family),
                    "unexpected EoR {family:?}"
                );
                ends.push(family);
            }
        }
        assert_eq!(seen.len(), expected.len(), "complete inventory before EoR");
    })
    .await
    .expect("initial table and EoR");
}

fn mutate_staged(manager: &mut RibManager, staged: [[Prefix; 3]; 2], expected: &mut Inventory) {
    let mut remove = test_routes_received(peer_v4(SOURCE), Vec::new());
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut remove else {
        unreachable!()
    };
    for [deleted, _, readded] in staged {
        withdrawn.extend([(deleted, 0), (readded, 0)]);
        expected.remove(&deleted);
    }
    manager.handle_update(remove);
    drain_route_chunks(manager);
    let mut announced = Vec::new();
    for [deleted, replaced, readded] in staged {
        assert!(manager.loc_rib.get(&deleted).is_none());
        assert!(manager.loc_rib.get(&readded).is_none());
        for (prefix, pref) in [(replaced, 175), (readded, 145)] {
            announced.push(route(prefix, SOURCE, pref));
            expected.insert(prefix, (peer_v4(SOURCE), pref));
        }
    }
    manager.handle_update(test_routes_received(peer_v4(SOURCE), announced));
    drain_route_chunks(manager);
    for [_, replaced, readded] in staged {
        assert_eq!(manager.loc_rib.get(&replaced).unwrap().local_pref(), 175);
        assert_eq!(manager.loc_rib.get(&readded).unwrap().local_pref(), 145);
    }
}

#[tokio::test]
async fn imports_during_unpublished_build_reach_both_joiners_before_eor() {
    let (mut manager, tx, mut expected) = fixture(2048);
    let founder = receiver(1);
    let peer = receiver(2);
    let mut first = join(&mut manager, founder, 1, &DUAL);
    let staged = staged_keys(&mut manager, &expected);
    let mut second = join(&mut manager, peer, 2, &DUAL);
    mutate_staged(&mut manager, staged, &mut expected);
    for waiter in [founder, peer] {
        assert!(manager.grouped_member_of(waiter).is_none());
        assert!(!manager.outbound_peers.contains_key(&waiter));
    }
    assert!(first.is_empty() && second.is_empty());

    // Resume the ordinary actor with a new ingress batch waiting behind the
    // partial page. Both initial dumps must include its routes before EoR.
    let mut markers = Vec::new();
    for prefix in prefixes(u16::MAX) {
        expected.insert(prefix, (peer_v4(OTHER), 190));
        markers.push(route(prefix, OTHER, 190));
    }
    tx.try_send(test_routes_received(peer_v4(OTHER), markers))
        .unwrap();
    // Primary FIFO drains the route batch before either query. These replies
    // establish that the markers reached the Loc-RIB before group publication.
    let (reply, count) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let (reply, membership) = oneshot::channel();
    tx.try_send(RibUpdate::QueryPeerUpdateGroup {
        peer: founder,
        reply,
    })
    .unwrap();
    let actor = tokio::spawn(manager.run_actor());
    assert_eq!(count.await.unwrap(), expected.len());
    assert_eq!(membership.await.unwrap(), "");
    tokio::join!(
        assert_initial(&mut first, &expected, &DUAL),
        assert_initial(&mut second, &expected, &DUAL)
    );
    drop(tx);
    let manager = actor.await.unwrap();
    let group = manager.grouped_member_of(founder).unwrap();
    assert_eq!(manager.grouped_member_of(peer), Some(group));
    for marker in prefixes(u16::MAX) {
        assert_eq!(manager.loc_rib.get(&marker).unwrap().peer, peer_v4(OTHER));
    }
    assert!(first.is_empty() && second.is_empty());
}

#[tokio::test]
async fn pending_policy_change_rechecks_previously_staged_route() {
    let (mut manager, _tx, mut expected) = fixture(2048);
    let peer = receiver(1);
    let mut rx = join(&mut manager, peer, 7, &DUAL);
    let [[denied, ..], _] = staged_keys(&mut manager, &expected);
    manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
        peer,
        session_id: 7,
        export_policy: Some(deny_prefixes_chain(&[denied])),
    });
    expected.remove(&denied);
    finish(&mut manager);
    assert_initial(&mut rx, &expected, &DUAL).await;
    assert!(rx.is_empty());
}

#[tokio::test]
async fn replacement_channel_with_reused_session_id_gets_the_current_initial_table() {
    let (mut manager, _tx, mut expected) = fixture(2048);
    let peer = receiver(1);
    let old = join(&mut manager, peer, 7, &DUAL);
    let staged = staged_keys(&mut manager, &expected);
    let mut current = join(&mut manager, peer, 7, &DUAL);
    manager.advance_pending_initial_registration();
    assert!(
        !manager.first_group_contains(staged[0][0]),
        "a new channel must retire its predecessor's private table"
    );
    mutate_staged(&mut manager, staged, &mut expected);
    finish(&mut manager);
    assert_initial(&mut current, &expected, &DUAL).await;
    assert!(old.is_empty() && current.is_empty());
}

#[tokio::test]
async fn last_waiter_down_retires_private_table_and_later_members_share_published_group() {
    let (mut manager, _tx, expected) = fixture(2048);
    let peer = receiver(1);
    let before = manager.group_ribs.len();
    let canceled = join(&mut manager, peer, 1, &DUAL);
    staged_keys(&mut manager, &expected);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    finish(&mut manager);
    assert!(canceled.is_empty());
    assert!(manager.grouped_member_of(peer).is_none());
    assert_eq!(manager.group_ribs.len(), before);

    let mut founder = join(&mut manager, peer, 2, &DUAL);
    finish(&mut manager);
    assert_initial(&mut founder, &expected, &DUAL).await;
    let group = manager.grouped_member_of(peer).unwrap();
    let other = receiver(2);
    let mut warm = join(&mut manager, other, 3, &DUAL);
    assert_eq!(manager.grouped_member_of(other), Some(group));
    assert!(manager.first_group_build.is_none());
    assert_initial(&mut warm, &expected, &DUAL).await;
}

#[test]
fn mixed_vpn_registration_replays_unicast_and_vpn_on_grouped_and_private_paths() {
    let (mut manager, _tx, expected) = fixture(4);
    let vpn = make_vpn_rib_route(SOURCE, 35, 100, 120);
    let vpn_key = vpn.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: vec![vpn],
        withdrawn: vec![],
    });
    let v4: BTreeSet<_> = expected
        .keys()
        .copied()
        .filter(|prefix| matches!(prefix, Prefix::V4(_)))
        .collect();
    let families = [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)];
    for (peer, private) in [(receiver(1), false), (receiver(2), true)] {
        let (tx, mut rx) = mpsc::channel(8);
        let mut up = test_peer_up(peer, 7, tx);
        let RibUpdate::PeerUp {
            sendable_families,
            per_client_best,
            ..
        } = &mut up
        else {
            unreachable!()
        };
        *sendable_families = families.to_vec();
        *per_client_best = private;
        manager.handle_update(up);
        assert_eq!(manager.grouped_member_of(peer).is_none(), private);
        assert!(manager.first_group_build.is_none());
        let table = rx.try_recv().expect("ordinary mixed-family table");
        assert_eq!(table.end_of_rib, []);
        assert_eq!(
            table
                .announce
                .iter()
                .map(|row| row.prefix)
                .collect::<BTreeSet<_>>(),
            v4
        );
        assert_eq!(table.vpn_announce.len(), 1);
        assert_eq!(table.vpn_announce[0].key(), vpn_key);
        assert_eq!(table.vpn_announce[0].peer, peer_v4(SOURCE));
        assert_eq!(
            rx.try_recv().expect("mixed-family EoR").end_of_rib,
            families
        );
        assert!(rx.is_empty());
    }
}

#[tokio::test]
async fn initial_eor_waits_for_last_chunk_of_an_already_admitted_update() {
    let (mut manager, tx, mut expected) = fixture(600);
    let peer = receiver(1);
    let mut rx = join(&mut manager, peer, 7, &DUAL);
    staged_keys(&mut manager, &expected);

    // The announce follows the withdrawal chunks of this same UPDATE. No
    // withdrawal changes the Loc-RIB or otherwise forces a repair on the build.
    let marker = prefixes(u16::MAX)[0];
    let absent = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut update = test_routes_received(peer_v4(OTHER), vec![route(marker, OTHER, 190)]);
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
        unreachable!()
    };
    *withdrawn = vec![(absent, 0); 4 * ROUTES_RECEIVED_CHUNK_SIZE];
    manager.handle_update(update);
    assert!(manager.process_next_route_chunk());
    assert!(!manager.pending_route_batches.is_empty());
    assert!(manager.loc_rib.get(&marker).is_none());

    let actor = tokio::spawn(manager.run_actor());
    expected.insert(marker, (peer_v4(OTHER), 190));
    assert_initial(&mut rx, &expected, &DUAL).await;
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(manager.pending_route_batches.is_empty());
    assert!(rx.is_empty());
}

#[tokio::test]
async fn busy_primary_fifo_allows_successive_cold_groups_to_start_and_finish() {
    let (mut manager, tx, mut expected) = fixture(600);
    let founder = receiver(1);
    let next = receiver(2);
    // Keep ordinary work ready before either PeerUp and beyond both builds.
    // Each FIFO query records membership at that message's turn.
    let mut replies = Vec::new();
    for peer in [founder, next].into_iter().cycle().take(24) {
        let (reply, response) = oneshot::channel();
        tx.try_send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
            .unwrap();
        replies.push(response);
    }
    let mut first = join(&mut manager, founder, 7, &DUAL);
    assert!(manager.first_group_build.is_some());
    let mut second = join(&mut manager, next, 8, &DUAL[..1]);
    let actor = tokio::spawn(manager.run_actor());
    let mut observed = Vec::new();
    for reply in replies {
        observed.push(reply.await.unwrap());
    }
    assert!(
        observed.first().unwrap().is_empty(),
        "primary served while staging"
    );
    assert!(
        !observed.last().unwrap().is_empty(),
        "the second group published before the FIFO drained"
    );
    assert_initial(&mut first, &expected, &DUAL).await;
    expected.retain(|prefix, _| matches!(prefix, Prefix::V4(_)));
    assert_initial(&mut second, &expected, &DUAL[..1]).await;
    drop(tx);
    let manager = actor.await.unwrap();
    assert_ne!(
        manager.grouped_member_of(founder).unwrap(),
        manager.grouped_member_of(next).unwrap()
    );
}

#[tokio::test]
async fn repair_overflow_retires_the_partial_table_then_replays_current_winners_to_both_waiters() {
    use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus};

    let (mut manager, _tx, mut expected) = fixture(2048);
    let founder = receiver(1);
    let next = receiver(2);
    let mut first = join(&mut manager, founder, 7, &DUAL);
    let [[staged, ..], _] = staged_keys(&mut manager, &expected);
    let mut second = join(&mut manager, next, 8, &DUAL);
    // Leave more staged rows than one retirement turn can release.
    let copied = |manager: &RibManager| {
        expected
            .keys()
            .filter(|&&prefix| manager.first_group_contains(prefix))
            .count()
    };
    for _ in 0..16 {
        if copied(&manager) > REGISTRATION_PAGE_SIZE {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(copied(&manager) > REGISTRATION_PAGE_SIZE);

    // A competing source wins every one of the 4096 existing keys, filling
    // the repair log. One further, distinct key overflows it.
    let winners = expected
        .iter_mut()
        .map(|(&prefix, winner)| {
            *winner = (peer_v4(OTHER), 200);
            route(prefix, OTHER, 200)
        })
        .collect();
    manager.handle_update(test_routes_received(peer_v4(OTHER), winners));
    drain_route_chunks(&mut manager);
    assert_eq!(
        manager.loc_rib.registration_scan_status(),
        RegistrationScanStatus::Scanning
    );
    let marker = prefixes(u16::MAX)[0];
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(marker, OTHER, 205)],
    ));
    drain_route_chunks(&mut manager);
    expected.insert(marker, (peer_v4(OTHER), 205));
    assert_eq!(
        manager.loc_rib.registration_scan_status(),
        RegistrationScanStatus::Overflow
    );
    assert_eq!(manager.loc_rib.get(&marker).unwrap().local_pref(), 205);

    manager.advance_pending_initial_registration();
    assert!(!manager.first_group_contains(staged));
    assert!(
        manager.first_group_build.is_some(),
        "retirement continues into another turn"
    );
    for _ in 0..32 {
        if manager.first_group_build.is_none() {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.first_group_build.is_none(), "retired before retry");
    for waiter in [founder, next] {
        assert!(manager.grouped_member_of(waiter).is_none());
        assert!(!manager.outbound_peers.contains_key(&waiter));
    }
    assert!(first.is_empty() && second.is_empty());

    staged_keys(&mut manager, &expected);
    finish(&mut manager);
    assert_initial(&mut first, &expected, &DUAL).await;
    assert_initial(&mut second, &expected, &DUAL).await;
    assert!(first.is_empty() && second.is_empty());
    assert_eq!(
        manager.grouped_member_of(next),
        Some(manager.grouped_member_of(founder).unwrap())
    );
}

#[tokio::test]
async fn rs_control_registration_waits_for_its_existing_plain_group_build() {
    let (mut manager, _tx, mut expected) = fixture(2400);
    expected.retain(|prefix, _| matches!(prefix, Prefix::V4(_)));
    let register = |manager: &mut RibManager, peer, session| {
        let (sender, receiver) = mpsc::channel(64);
        manager.handle_update(test_peer_up(peer, session, sender));
        receiver
    };
    let founder = receiver(1);
    let joiner = receiver(2);
    let mut first = register(&mut manager, founder, 41);
    manager.advance_first_group_build();
    assert!(
        expected
            .keys()
            .any(|prefix| manager.first_group_contains(*prefix))
    );
    // A build already owns the destination. Falling below either start threshold
    // cannot let a second, RS-control registration create its own copy inline.
    manager.first_group_build_min_routes = usize::MAX;
    manager.initial_dump_defer_min_routes = usize::MAX;
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer: joiner,
        session_id: 42,
        rs_control_asn: Some(64512),
    });
    let mut second = register(&mut manager, joiner, 42);
    assert!(manager.pending_initial_registrations.contains(&joiner));
    // Rotate past the founder so the ordinary deferred path examines the
    // RS-control peer while its uncapped initial replay would still need a build.
    manager.advance_pending_initial_registration();
    manager.advance_pending_initial_registration();
    for peer in [founder, joiner] {
        assert!(!manager.outbound_peers.contains_key(&peer));
    }
    assert!(second.is_empty());

    finish(&mut manager);
    assert_initial(&mut first, &expected, &[(Afi::Ipv4, Safi::Unicast)]).await;
    assert_initial(&mut second, &expected, &[(Afi::Ipv4, Safi::Unicast)]).await;
    assert_eq!(manager.peer_rs_control.get(&joiner), Some(&64512));
    assert_eq!(
        manager.grouped_member_of(joiner),
        Some(manager.grouped_member_of(founder).unwrap())
    );
}

// Fill the repair log without touching the staged IPv4 row we withdraw next.
// Its stale copy then survives in the discarded table with no repair-log entry.
fn overflow_with_staged_withdrawal(
    manager: &mut RibManager,
    expected: &mut Inventory,
    lost: Prefix,
) {
    use crate::loc_rib::RegistrationScanStatus;

    let winners: Vec<_> = expected
        .iter_mut()
        .filter(|(prefix, _)| matches!(prefix, Prefix::V6(_)))
        .map(|(&prefix, winner)| {
            *winner = (peer_v4(OTHER), 200);
            route(prefix, OTHER, 200)
        })
        .collect();
    assert_eq!(winners.len(), 4096);
    manager.handle_update(test_routes_received(peer_v4(OTHER), winners));
    drain_route_chunks(manager);
    assert_eq!(
        manager.loc_rib.registration_scan_status(),
        RegistrationScanStatus::Scanning
    );

    let mut removal = test_routes_received(peer_v4(SOURCE), Vec::new());
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut removal else {
        unreachable!()
    };
    withdrawn.push((lost, 0));
    manager.handle_update(removal);
    drain_route_chunks(manager);
    expected.remove(&lost).unwrap();
    assert!(manager.loc_rib.get(&lost).is_none());
    assert!(manager.first_group_contains(lost));
    assert_eq!(
        manager.loc_rib.registration_scan_status(),
        RegistrationScanStatus::Overflow
    );
}

#[tokio::test]
async fn overflow_withdrawal_stays_withdrawn_across_retirement_and_sender_replacement() {
    use crate::loc_rib::REGISTRATION_PAGE_SIZE;

    let (mut manager, _tx, mut expected) = fixture(4096);
    let mut established = join(&mut manager, receiver(3), 6, &DUAL[..1]);
    finish(&mut manager);
    let ipv4 = expected
        .iter()
        .filter(|(p, _)| matches!(p, Prefix::V4(_)))
        .map(|(&p, &winner)| (p, winner))
        .collect();
    assert_initial(&mut established, &ipv4, &DUAL[..1]).await;
    let published = manager.group_ribs.len();
    let founder = receiver(1);
    let next = receiver(2);
    let old = join(&mut manager, founder, 7, &DUAL);
    let [[lost, changed, _], _] = staged_keys(&mut manager, &expected);
    // No slots are vacant before this build sees its first change.
    let mut remaining = expected
        .keys()
        .filter(|&&p| manager.first_group_contains(p))
        .count();
    for _ in 0..32 {
        if remaining > 3 * REGISTRATION_PAGE_SIZE {
            break;
        }
        manager.advance_pending_initial_registration();
        remaining = expected
            .keys()
            .filter(|&&p| manager.first_group_contains(p))
            .count();
    }
    assert!(remaining > 3 * REGISTRATION_PAGE_SIZE);
    overflow_with_staged_withdrawal(&mut manager, &mut expected, lost);
    let withdrawal = established
        .try_recv()
        .expect("established receiver's withdrawal");
    assert_eq!(
        withdrawal
            .unicast_withdrawals()
            .copied()
            .collect::<Vec<_>>(),
        [(lost, 0)]
    );
    assert!(established.is_empty());
    for _ in 0..2 {
        manager.advance_pending_initial_registration();
        let after = manager
            .first_group_retiring_slots()
            .expect("partly retired group");
        assert!((1..=REGISTRATION_PAGE_SIZE).contains(&(remaining - after)));
        remaining = after;
    }

    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(changed, OTHER, 220)],
    ));
    drain_route_chunks(&mut manager);
    expected.insert(changed, (peer_v4(OTHER), 220));
    assert_eq!(manager.loc_rib.get(&changed).unwrap().peer, peer_v4(OTHER));
    let update = established
        .try_recv()
        .expect("established receiver's new winner");
    assert_eq!(
        update
            .announce
            .iter()
            .map(|r| (r.prefix, r.peer, r.local_pref()))
            .collect::<Vec<_>>(),
        [(changed, peer_v4(OTHER), 220)]
    );
    assert!(update.end_of_rib.is_empty() && established.is_empty());
    assert_eq!(manager.first_group_retiring_slots(), Some(remaining));

    let mut replacement = join(&mut manager, founder, 7, &DUAL);
    let mut second = join(&mut manager, next, 8, &DUAL);
    while remaining != 0 {
        assert_eq!(manager.first_group_retiring_slots(), Some(remaining));
        assert_eq!(manager.group_ribs.len(), published);
        for waiter in [founder, next] {
            assert!(manager.grouped_member_of(waiter).is_none());
            assert!(!manager.outbound_peers.contains_key(&waiter));
        }
        assert!(old.is_empty() && replacement.is_empty() && second.is_empty());
        manager.advance_pending_initial_registration();
        let after = manager.first_group_retiring_slots().unwrap_or(0);
        assert!((1..=REGISTRATION_PAGE_SIZE).contains(&(remaining - after)));
        remaining = after;
    }
    assert!(manager.first_group_build.is_none());
    assert_eq!(manager.group_ribs.len(), published);
    finish(&mut manager);
    assert_initial(&mut replacement, &expected, &DUAL).await;
    assert_initial(&mut second, &expected, &DUAL).await;
    assert!(old.is_empty() && replacement.is_empty() && second.is_empty());
    assert_eq!(
        manager.grouped_member_of(next),
        Some(manager.grouped_member_of(founder).unwrap())
    );
    assert_eq!(manager.group_ribs.len(), published + 1);
}

// A cold build caught mid-walk, with `members` registered peers whose policy
// clear needs the table under construction. Member `n` is `receiver(n)`.
fn cold_build_with_policy_members(
    per_family: u16,
    members: u8,
) -> (
    RibManager,
    mpsc::Sender<RibUpdate>,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let (mut manager, primary, expected) = fixture(per_family);
    let mut receivers = Vec::new();
    for n in 1..=members {
        let (out, rx) = mpsc::channel(32);
        let mut up = test_peer_up(receiver(n), 1, out);
        let RibUpdate::PeerUp {
            is_ebgp,
            route_reflector_client,
            sendable_families,
            export_policy,
            ..
        } = &mut up
        else {
            unreachable!()
        };
        *is_ebgp = false;
        *route_reflector_client = true;
        *sendable_families = DUAL.to_vec();
        *export_policy = Some(deny_default_prefix_chain());
        manager.handle_update(up);
        finish(&mut manager);
        receivers.push(rx);
    }
    for rx in &mut receivers {
        while rx.try_recv().is_ok() {}
    }
    receivers.push(join(&mut manager, receiver(100), 1, &DUAL));
    staged_keys(&mut manager, &expected);
    assert!(manager.first_group_build.is_some());
    (manager, primary, receivers)
}

fn clear_policy(
    manager: &mut RibManager,
    peer: PeerId,
) -> oneshot::Receiver<Result<(), crate::RibCommandError>> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: None,
        reply,
    });
    assert!(
        manager.first_group_pending_writer().is_some(),
        "the policy clear must be claimed by the cold build"
    );
    assert!(response.try_recv().is_err());
    response
}

fn other_marker() -> (Prefix, RibUpdate) {
    let marker = prefixes(u16::MAX)[0];
    (
        marker,
        test_routes_received(peer_v4(OTHER), vec![route(marker, OTHER, 190)]),
    )
}

// One owner turn per iteration, scheduled as the run loop does: admissible
// primary work first, otherwise the build. Returns the build turns spent
// before `marker` reached the Loc-RIB.
async fn build_turns_until_installed(manager: &mut RibManager, marker: Prefix) -> usize {
    let mut build_turns = 0;
    while manager.loc_rib.get(&marker).is_none() {
        if manager.drain_ready_updates().await {
            continue;
        }
        assert!(
            manager.first_group_build.is_some(),
            "no build and no admissible primary work"
        );
        manager.advance_first_group_build();
        build_turns += 1;
        assert!(build_turns < 100_000, "the marker never entered");
    }
    build_turns
}

fn commit_claimed_writer(manager: &mut RibManager) {
    for _ in 0..100_000 {
        if manager.first_group_pending_writer().is_none() {
            return;
        }
        manager.advance_first_group_build();
    }
    panic!("the claimed writer never committed");
}

#[tokio::test]
async fn unrelated_update_passes_a_session_end_that_waits_for_the_cold_build() {
    let mut waited = [0usize; 2];
    for session_ends in [false, true] {
        let (mut manager, primary, _receivers) = cold_build_with_policy_members(8192, 1);
        let incumbent = receiver(1);
        let source_group = manager.grouped_member_of(incumbent).unwrap();
        let mut policy_reply = clear_policy(&mut manager, incumbent);
        if session_ends {
            primary
                .try_send(RibUpdate::PeerDown {
                    peer: incumbent,
                    session_id: 1,
                })
                .unwrap();
        }
        let (marker, update) = other_marker();
        primary.try_send(update).unwrap();

        waited[usize::from(session_ends)] = build_turns_until_installed(&mut manager, marker).await;
        assert!(
            manager.first_group_pending_writer().is_some(),
            "an unrelated UPDATE waited {} build turns, until the writer committed",
            waited[usize::from(session_ends)]
        );
        assert!(policy_reply.try_recv().is_err());
        // The session end has not taken effect ahead of the older writer.
        assert!(manager.outbound_peers.contains_key(&incumbent));

        commit_claimed_writer(&mut manager);
        assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
        assert!(
            manager
                .grouped_member_of(incumbent)
                .is_some_and(|destination| destination != source_group),
            "the writer moved the still-registered peer"
        );
        if session_ends {
            // Newer primary input stays behind the retained session end.
            assert!(manager.try_recv_primary().is_none());
            let end = manager.take_first_group_deferred_intent().unwrap();
            assert!(matches!(end, RibUpdate::PeerDown { peer, .. } if peer == incumbent));
            manager.handle_update(end);
            assert!(!manager.outbound_peers.contains_key(&incumbent));
        }
        assert!(manager.take_first_group_deferred_intent().is_none());
    }
    assert_eq!(
        waited[1], waited[0],
        "build turns an unrelated UPDATE waited behind the session end, and the control"
    );
}

#[tokio::test]
async fn peer_up_after_a_retained_session_end_stays_behind_it() {
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 1);
    let incumbent = receiver(1);
    let mut policy_reply = clear_policy(&mut manager, incumbent);
    primary
        .try_send(RibUpdate::PeerDown {
            peer: incumbent,
            session_id: 1,
        })
        .unwrap();
    let (out, _replacement_rx) = mpsc::channel(32);
    primary.try_send(test_peer_up(incumbent, 2, out)).unwrap();
    let (marker, update) = other_marker();
    primary.try_send(update).unwrap();

    // The session end is retained. Its peer's next session holds the head.
    assert!(manager.drain_ready_updates().await);
    assert!(!manager.drain_ready_updates().await);
    assert!(matches!(
        manager.primary_lookahead,
        Some(RibUpdate::PeerUp { peer, session_id: 2, .. }) if peer == incumbent
    ));
    assert!(manager.first_group_commit_frontier_reached());
    assert_eq!(manager.outbound_session_ids.get(&incumbent), Some(&1));

    commit_claimed_writer(&mut manager);
    assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
    assert_eq!(manager.outbound_session_ids.get(&incumbent), Some(&1));
    assert!(manager.try_recv_primary().is_none());
    let end = manager.take_first_group_deferred_intent().unwrap();
    assert!(matches!(end, RibUpdate::PeerDown { session_id: 1, .. }));
    manager.handle_update(end);
    assert!(!manager.outbound_peers.contains_key(&incumbent));
    assert!(manager.loc_rib.get(&marker).is_none());

    let up = manager.try_recv_primary().unwrap();
    assert!(matches!(up, RibUpdate::PeerUp { session_id: 2, .. }));
    manager.handle_update(up);
    finish(&mut manager);
    assert_eq!(manager.outbound_session_ids.get(&incumbent), Some(&2));
    assert!(manager.drain_ready_updates().await);
    drain_route_chunks(&mut manager);
    assert!(manager.loc_rib.get(&marker).is_some());
}

#[tokio::test]
async fn two_session_ends_behind_one_writer_replay_in_admission_order() {
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(4096, 2);
    let (first, second) = (receiver(1), receiver(2));
    let source_group = manager.grouped_member_of(first).unwrap();
    assert_eq!(manager.grouped_member_of(second), Some(source_group));
    let (reply, mut policy_reply) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: [first, second]
            .map(|peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: None,
            })
            .into(),
        reply,
    });
    assert!(manager.first_group_pending_writer().is_some());
    primary
        .try_send(RibUpdate::PeerGracefulRestart {
            peer: second,
            session_id: 1,
            restart_time: 10,
            stale_routes_time: 30,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .unwrap();
    primary
        .try_send(RibUpdate::PeerDown {
            peer: first,
            session_id: 1,
        })
        .unwrap();
    let (marker, update) = other_marker();
    primary.try_send(update).unwrap();

    assert_eq!(build_turns_until_installed(&mut manager, marker).await, 0);
    assert!(manager.first_group_pending_writer().is_some());
    assert!(policy_reply.try_recv().is_err());
    for peer in [first, second] {
        assert!(manager.outbound_peers.contains_key(&peer));
    }

    commit_claimed_writer(&mut manager);
    assert_eq!(policy_reply.try_recv().unwrap(), Ok(vec![]));
    let destination = manager.grouped_member_of(first).unwrap();
    assert_ne!(destination, source_group);
    assert_eq!(manager.grouped_member_of(second), Some(destination));
    let end = manager.take_first_group_deferred_intent().unwrap();
    assert!(matches!(end, RibUpdate::PeerGracefulRestart { peer, .. } if peer == second));
    manager.handle_update(end);
    assert!(!manager.outbound_peers.contains_key(&second));
    assert!(manager.outbound_peers.contains_key(&first));
    let end = manager.take_first_group_deferred_intent().unwrap();
    assert!(matches!(end, RibUpdate::PeerDown { peer, .. } if peer == first));
    manager.handle_update(end);
    assert!(!manager.outbound_peers.contains_key(&first));
    assert!(manager.take_first_group_deferred_intent().is_none());
}

// The same order through the run loop: the marker is visible to a later
// primary read while the policy reply is pending, and the peer's channel
// closes only after that reply.
#[tokio::test]
async fn actor_installs_an_unrelated_update_before_the_writer_and_the_session_end() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let (mut manager, primary, mut receivers) = cold_build_with_policy_members(8192, 1);
    let incumbent = receiver(1);
    let mut policy_reply = clear_policy(&mut manager, incumbent);
    let routes = manager.loc_rib.len();
    primary
        .try_send(RibUpdate::PeerDown {
            peer: incumbent,
            session_id: 1,
        })
        .unwrap();
    primary.try_send(other_marker().1).unwrap();
    let (reply, mut count) = oneshot::channel();
    primary
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();

    let mut actor = Box::pin(manager.run());
    let mut founder_rx = receivers.pop().unwrap();
    let mut incumbent_rx = receivers.pop().unwrap();
    let (mut counted, mut replied) = (false, false);
    for _ in 0..100_000 {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        while founder_rx.try_recv().is_ok() {}
        if !counted && let Ok(len) = count.try_recv() {
            assert_eq!(len, routes + 1);
            assert!(
                !replied && policy_reply.try_recv().is_err(),
                "an unrelated UPDATE waited for the writer to commit"
            );
            counted = true;
        }
        if !replied && let Ok(result) = policy_reply.try_recv() {
            assert_eq!(result, Ok(()));
            replied = true;
        }
        loop {
            match incumbent_rx.try_recv() {
                Ok(_) => {}
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    assert!(
                        counted && replied,
                        "the session end preceded the unrelated UPDATE or the reply"
                    );
                    return;
                }
            }
        }
    }
    panic!("the session end never took effect");
}
