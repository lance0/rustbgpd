//! Cold registration interleaved with real imports and session changes.

use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const DUAL: [(Afi, Safi); 2] = [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
type Inventory = BTreeMap<Prefix, (PeerId, u32)>;

const MEMBER: fn(u8) -> Ipv4Addr = |n| Ipv4Addr::new(198, 51, 100, n);

fn receiver(n: u8) -> PeerId {
    peer_v4(MEMBER(n))
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
    cold_build_with_policy_members_on(fixture(per_family), members)
}

fn cold_build_with_policy_members_on(
    (mut manager, primary, expected): (RibManager, mpsc::Sender<RibUpdate>, Inventory),
    members: u8,
) -> (
    RibManager,
    mpsc::Sender<RibUpdate>,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
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
            primary.try_send(other_marker().1).unwrap();
            assert!(manager.try_recv_primary().is_none());
            assert_eq!(manager.primary_backlog(), 1);
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

// The same order through the run loop: the still-registered peer is sent the
// marker while the policy reply is pending, its channel closes only after
// that reply, and a primary-lane barrier read behind the session end is
// answered only after the close.
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
    let (marker, update) = other_marker();
    primary.try_send(update).unwrap();
    let (reply, mut barrier) = oneshot::channel();
    primary
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();

    let mut actor = Box::pin(manager.run());
    let mut founder_rx = receivers.pop().unwrap();
    let mut incumbent_rx = receivers.pop().unwrap();
    let (mut installed, mut replied, mut ended) = (false, false, false);
    for _ in 0..100_000 {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        while founder_rx.try_recv().is_ok() {}
        if let Ok(len) = barrier.try_recv() {
            assert!(
                ended,
                "the barrier read was answered before the session end"
            );
            assert_eq!(len, routes + 1);
            return;
        }
        if !replied && let Ok(result) = policy_reply.try_recv() {
            assert_eq!(result, Ok(()));
            assert!(installed, "an unrelated UPDATE waited for the writer");
            replied = true;
        }
        while !ended {
            match incumbent_rx.try_recv() {
                Ok(out) => {
                    if out.announce.iter().any(|row| row.prefix == marker) {
                        assert!(!replied, "an unrelated UPDATE waited for the writer");
                        installed = true;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    assert!(installed && replied, "the session end ran early");
                    ended = true;
                }
            }
        }
    }
    panic!("the barrier read was never answered");
}

#[tokio::test]
async fn full_window_holds_the_ninth_session_end_at_the_head() {
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 9);
    let peers: Vec<PeerId> = (1..=9).map(receiver).collect();
    let (reply, mut policy_reply) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: None,
            })
            .collect(),
        reply,
    });
    assert!(manager.first_group_pending_writer().is_some());
    for &peer in &peers {
        primary
            .try_send(RibUpdate::PeerDown {
                peer,
                session_id: 1,
            })
            .unwrap();
    }
    let (marker, update) = other_marker();
    primary.try_send(update).unwrap();
    while manager.drain_ready_updates().await {}
    assert_eq!(manager.first_group_deferred_intents.len(), 8);
    assert!(matches!(
        manager.primary_lookahead,
        Some(RibUpdate::PeerDown { peer, .. }) if peer == peers[8]
    ));
    assert!(manager.first_group_commit_frontier_reached());
    assert!(manager.loc_rib.get(&marker).is_none());
    commit_claimed_writer(&mut manager);
    assert!(policy_reply.try_recv().unwrap().is_ok());
    for &expected in &peers[..8] {
        assert!(manager.try_recv_primary().is_none());
        let end = manager.take_first_group_deferred_intent().unwrap();
        assert!(matches!(end, RibUpdate::PeerDown { peer, .. } if peer == expected));
        manager.handle_update(end);
    }
    let ninth = manager.try_recv_primary().unwrap();
    assert!(matches!(ninth, RibUpdate::PeerDown { peer, .. } if peer == peers[8]));
    manager.handle_update(ninth);
    for peer in &peers {
        assert!(!manager.outbound_peers.contains_key(peer));
    }
    assert!(manager.drain_ready_updates().await);
    drain_route_chunks(&mut manager);
    assert!(manager.loc_rib.get(&marker).is_some());
}

#[tokio::test]
async fn late_session_end_is_retained_and_replayed() {
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 1);
    let incumbent = receiver(1);
    let mut policy_reply = clear_policy(&mut manager, incumbent);
    primary
        .try_send(RibUpdate::LateSessionEnd(Box::new(RibUpdate::PeerDown {
            peer: incumbent,
            session_id: 1,
        })))
        .unwrap();
    let (marker, update) = other_marker();
    primary.try_send(update).unwrap();
    assert_eq!(build_turns_until_installed(&mut manager, marker).await, 0);
    assert!(manager.first_group_pending_writer().is_some());
    assert!(manager.outbound_peers.contains_key(&incumbent));
    commit_claimed_writer(&mut manager);
    assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
    let end = manager.take_first_group_deferred_intent().unwrap();
    assert!(matches!(end, RibUpdate::LateSessionEnd(_)));
    manager.handle_update(end);
    assert!(!manager.outbound_peers.contains_key(&incumbent));
}

// The writer names the peer but not its route input: only the retained end
// itself keeps a sibling session's routes and End-of-RIB behind it.
#[tokio::test]
async fn same_peer_routes_and_end_of_rib_stay_behind_a_retained_session_end() {
    let incumbent = receiver(1);
    let own = prefixes(u16::MAX - 1)[0];
    let later = [
        super::lifecycle::test_session_routes_received(incumbent, 1, vec![route(own, OTHER, 190)]),
        RibUpdate::EndOfRib {
            peer: incumbent,
            session_id: 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        },
    ];
    for message in later {
        let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 1);
        let _policy_reply = clear_policy(&mut manager, incumbent);
        primary
            .try_send(RibUpdate::PeerDown {
                peer: incumbent,
                session_id: 1,
            })
            .unwrap();
        primary.try_send(message).unwrap();
        while manager.drain_ready_updates().await {}
        drain_route_chunks(&mut manager);
        assert_eq!(manager.first_group_deferred_intents.len(), 1);
        assert!(
            manager
                .primary_lookahead
                .as_ref()
                .is_some_and(|head| head.session_peer() == Some(incumbent)),
            "the peer's own input passed its retained session end"
        );
        assert!(manager.first_group_commit_frontier_reached());
        assert!(manager.loc_rib.get(&own).is_none());
    }
}

#[tokio::test]
async fn session_end_of_a_peer_the_writer_does_not_name_applies_at_once() {
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 2);
    let _policy_reply = clear_policy(&mut manager, receiver(1));
    primary
        .try_send(RibUpdate::PeerDown {
            peer: receiver(2),
            session_id: 1,
        })
        .unwrap();
    assert!(manager.drain_ready_updates().await);
    assert!(manager.first_group_pending_writer().is_some());
    assert!(manager.first_group_deferred_intents.is_empty());
    assert!(!manager.outbound_peers.contains_key(&receiver(2)));
}

type Answered = Box<dyn FnMut(&RibManager) -> bool>;

// `message` reaches the primary FIFO behind a retained session end. It holds
// the head until the claimed writer has committed and the end has replayed,
// and it is the next primary message after that.
async fn assert_held_behind_a_retained_session_end(
    message: RibUpdate,
    mut answered: Option<Answered>,
) {
    let incumbent = receiver(1);
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 2);
    let mut policy_reply = clear_policy(&mut manager, incumbent);
    assert!(
        matches!(
            manager.first_group_intake(&message),
            first_group_order::Intake::Apply
        ),
        "{:?} is held by the pending writer alone",
        message.actor_turn_kind()
    );
    primary
        .try_send(RibUpdate::PeerDown {
            peer: incumbent,
            session_id: 1,
        })
        .unwrap();
    let held = std::mem::discriminant(&message);
    let kind = message.actor_turn_kind();
    primary.try_send(message).unwrap();
    while manager.drain_ready_updates().await {}
    assert_eq!(manager.first_group_deferred_intents.len(), 1);
    assert!(
        manager
            .primary_lookahead
            .as_ref()
            .is_some_and(|head| std::mem::discriminant(head) == held),
        "{kind:?} passed the retained session end"
    );
    assert!(manager.first_group_commit_frontier_reached());
    assert!(!answered.as_mut().is_some_and(|done| done(&manager)));

    let (reply, mut general) = oneshot::channel();
    manager.serve_general_query(RibUpdate::QueryLocRibCount { reply });
    assert!(general.try_recv().is_ok(), "general-lane read answers");

    commit_claimed_writer(&mut manager);
    assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
    assert!(manager.try_recv_primary().is_none());
    assert!(!answered.as_mut().is_some_and(|done| done(&manager)));
    let end = manager.take_first_group_deferred_intent().unwrap();
    manager.handle_update(end);
    assert!(!manager.outbound_peers.contains_key(&incumbent));
    let next = manager.try_recv_primary().unwrap();
    assert_eq!(std::mem::discriminant(&next), held);
    manager.handle_update(next);
    assert!(answered.as_mut().is_none_or(|done| done(&manager)));
}

// A primary-lane read can be a teardown barrier or read the ended session's
// state, and a command has no proven order against the end. One message of
// every kind that is not route input holds the head until the retained end
// has replayed. The general lane is unordered against the primary FIFO and
// still answers.
#[tokio::test]
async fn primary_reads_and_other_session_ends_wait_for_a_retained_session_end() {
    fn read<T: 'static>(
        make: impl FnOnce(oneshot::Sender<T>) -> RibUpdate,
    ) -> (RibUpdate, Option<Answered>) {
        let (reply, mut response) = oneshot::channel();
        (
            make(reply),
            Some(Box::new(move |_| response.try_recv().is_ok())),
        )
    }
    // The reply is not inspected: only the hold and the order are.
    fn command<T: 'static>(
        make: impl FnOnce(oneshot::Sender<T>) -> RibUpdate,
    ) -> (RibUpdate, Option<Answered>) {
        let (reply, response) = oneshot::channel();
        std::mem::forget(response);
        (make(reply), None)
    }
    let incumbent = receiver(1);
    let (peer, session_id) = (receiver(2), 1);
    let (out, _out_rx) = mpsc::channel(8);
    let cases: Vec<(RibUpdate, Option<Answered>)> = vec![
        read(|reply| RibUpdate::QueryLocRibCount { reply }),
        read(|reply| RibUpdate::QueryEvpnSessionsSynced { reply }),
        read(|reply| RibUpdate::QueryEvpnEsSnapshot { reply }),
        read(|reply| RibUpdate::QueryPeerRetainedStale {
            peer: incumbent,
            reply,
        }),
        read(|reply| RibUpdate::QueryPeerRetention {
            peer: incumbent,
            reply,
        }),
        read(|reply| RibUpdate::QueryPeerRetentions {
            peers: vec![incumbent],
            reply,
        }),
        (
            RibUpdate::PeerDown { peer, session_id },
            Some(Box::new(move |manager| {
                !manager.outbound_peers.contains_key(&peer)
            })),
        ),
        // One message per remaining kind, none of them named by the writer.
        (test_peer_up(receiver(9), 1, out), None),
        (
            RibUpdate::PeerSlowState {
                peer,
                session_id,
                slow: true,
            },
            None,
        ),
        command(|reply| RibUpdate::ConfirmPeerOutbound {
            peer: peer_v4(OTHER),
            session_id: 0,
            reply,
        }),
        (
            RibUpdate::BeginRouteRefresh {
                peer: peer_v4(OTHER),
                session_id: 0,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            None,
        ),
        (RibUpdate::ExpireInjectionLeases { leases: vec![] }, None),
        (
            RibUpdate::RpkiCacheUpdate {
                table: Arc::new(rustbgpd_rpki::VrpTable::new(vec![])),
                delta: None,
                admission: None,
            },
            None,
        ),
        command(|reply| RibUpdate::PublishDampeningOwners {
            publication: 1,
            owners: vec![],
            reply,
        }),
    ];
    for (message, answered) in cases {
        assert_held_behind_a_retained_session_end(message, answered).await;
    }
}

fn other_route_input(edit: impl FnOnce(&mut RibUpdate)) -> RibUpdate {
    let mut update = test_routes_received(peer_v4(OTHER), vec![]);
    edit(&mut update);
    update
}

// Another peer's End-of-RIB can complete a selection deferral that the
// retained teardown would have re-armed, so it does not pass the end.
#[tokio::test]
async fn end_of_rib_from_another_peer_waits_for_a_retained_session_end() {
    let end_of_rib = RibUpdate::EndOfRib {
        peer: peer_v4(OTHER),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    };
    assert_held_behind_a_retained_session_end(end_of_rib, None).await;
}

// A FlowSpec rule is validated against the best unicast route covering its
// destination (RFC 9117), which can still be the ended session's. Route input
// passes a retained end only as unicast, EVPN, labeled or VPN routes; BGP-LS
// and RT-Constrain input is held with the rest.
#[tokio::test]
async fn only_plain_route_input_from_another_peer_passes_a_retained_session_end() {
    let other = peer_v4(OTHER);
    let rule = crate::test_support::make_flowspec_route(OTHER);
    let key = rule.selection_key();
    let wire = other_route_input(|update| {
        let RibUpdate::RoutesReceived {
            flowspec_announced, ..
        } = update
        else {
            unreachable!()
        };
        flowspec_announced.push(rule.clone());
    });
    let held = [
        other_route_input(|update| {
            let RibUpdate::RoutesReceived {
                flowspec_announced, ..
            } = update
            else {
                unreachable!()
            };
            flowspec_announced.push(rule.clone());
        }),
        other_route_input(|update| {
            let RibUpdate::RoutesReceived {
                flowspec_withdrawn, ..
            } = update
            else {
                unreachable!()
            };
            flowspec_withdrawn.push(key);
        }),
        RibUpdate::WireRoutesReceived(crate::update::WireRoutesReceived::new(wire, 0)),
        RibUpdate::BgpLsRoutesReceived {
            peer: other,
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
        },
        RibUpdate::RtcRoutesReceived {
            peer: other,
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
        },
    ];
    for message in held {
        assert_held_behind_a_retained_session_end(message, None).await;
    }

    let (mut manager, primary, _receivers) = cold_build_with_policy_members(2048, 1);
    let _policy_reply = clear_policy(&mut manager, receiver(1));
    primary
        .try_send(RibUpdate::PeerDown {
            peer: receiver(1),
            session_id: 1,
        })
        .unwrap();
    assert!(manager.drain_ready_updates().await);
    assert!(manager.session_end_retained());
    let passing = [
        other_marker().1,
        RibUpdate::WireRoutesReceived(crate::update::WireRoutesReceived::new(other_marker().1, 0)),
        RibUpdate::VpnRoutesReceived {
            peer: other,
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
        },
        RibUpdate::LabeledRoutesReceived {
            peer: other,
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
        },
    ];
    for message in passing {
        assert!(
            matches!(
                manager.first_group_primary_intake(&message),
                first_group_order::Intake::Apply
            ),
            "plain route input was held"
        );
    }
}

// The source of each unicast prefix a receiver currently holds.
#[derive(Default)]
struct Held(BTreeMap<Prefix, PeerId>);

impl Held {
    fn drain(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv() {
            for (prefix, _) in update.unicast_withdrawals() {
                self.0.remove(prefix);
            }
            for row in update
                .announce
                .iter()
                .filter(|row| update.announce_source_exclusion != Some(row.peer))
            {
                self.0.insert(row.prefix, row.peer);
            }
        }
    }
}

// Peers A and B both announce one prefix and B's path is best. A's session
// ends behind its claimed policy writer, then B withdraws. The withdrawal
// passes the retained end, so until the writer commits the receivers hold A's
// path in place of the withdrawn one (held for the whole build, the
// withdrawal waited behind the end). A's teardown is the first unit after the
// commit and removes it: no path via A outlives the build.
#[tokio::test]
async fn withdrawal_passing_a_retained_session_end_leaves_no_path_after_the_build() {
    let (a, b) = (receiver(1), receiver(2));
    let shared = prefixes(u16::MAX - 2)[0];
    let own = prefixes(u16::MAX - 3)[0];
    let mut build_turns = [0usize; 2];
    for withdraws in [false, true] {
        let (mut manager, primary, mut receivers) = cold_build_with_policy_members(8192, 3);
        manager.handle_update(super::lifecycle::test_session_routes_received(
            a,
            1,
            vec![route(shared, MEMBER(1), 150), route(own, MEMBER(1), 150)],
        ));
        manager.handle_update(super::lifecycle::test_session_routes_received(
            b,
            1,
            vec![route(shared, MEMBER(2), 190)],
        ));
        drain_route_chunks(&mut manager);
        let mut held = [Held::default(), Held::default()];
        let mut settle = |manager: &mut RibManager, held: &mut [Held; 2]| {
            drain_route_chunks(manager);
            held[0].drain(&mut receivers[1]);
            held[1].drain(&mut receivers[2]);
            while receivers[0].try_recv().is_ok() || receivers[3].try_recv().is_ok() {}
        };
        settle(&mut manager, &mut held);
        // [B's view, the observer's view]. B is not sent its own best path.
        assert_eq!(held[0].0.get(&shared), None);
        assert_eq!(held[1].0.get(&shared), Some(&b));

        let mut policy_reply = clear_policy(&mut manager, a);
        primary
            .try_send(RibUpdate::PeerDown {
                peer: a,
                session_id: 1,
            })
            .unwrap();
        if withdraws {
            let mut withdrawal = super::lifecycle::test_session_routes_received(b, 1, vec![]);
            let RibUpdate::RoutesReceived { withdrawn, .. } = &mut withdrawal else {
                unreachable!()
            };
            withdrawn.push((shared, 0));
            primary.try_send(withdrawal).unwrap();
        }
        while manager.drain_ready_updates().await {}
        settle(&mut manager, &mut held);
        assert!(manager.first_group_pending_writer().is_some());
        assert!(manager.outbound_peers.contains_key(&a));
        let during = if withdraws { a } else { b };
        assert_eq!(manager.loc_rib.get(&shared).unwrap().peer, during);
        assert_eq!(held[1].0.get(&shared), Some(&during));
        // The withdrawing peer is sent A's path too; it held none before.
        assert_eq!(held[0].0.get(&shared), withdraws.then_some(&a));

        while manager.first_group_pending_writer().is_some() {
            manager.advance_first_group_build();
            build_turns[usize::from(withdraws)] += 1;
            assert!(build_turns[usize::from(withdraws)] < 100_000);
        }
        assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
        assert!(manager.try_recv_primary().is_none());
        let end = manager.take_first_group_deferred_intent().unwrap();
        assert!(matches!(end, RibUpdate::PeerDown { peer, .. } if peer == a));
        manager.handle_update(end);
        finish(&mut manager);
        settle(&mut manager, &mut held);
        assert!(!manager.outbound_peers.contains_key(&a));
        assert!(manager.loc_rib.get(&own).is_none());
        for view in &held {
            assert!(!view.0.contains_key(&own));
            assert!(view.0.values().all(|source| *source != a));
        }
        if withdraws {
            assert!(manager.loc_rib.get(&shared).is_none());
            assert!(held.iter().all(|view| !view.0.contains_key(&shared)));
        } else {
            assert_eq!(held[1].0.get(&shared), Some(&b));
        }
    }
    assert_eq!(
        build_turns[1], build_turns[0],
        "build turns before the teardown, with the withdrawal and without"
    );
}

/// Route input from another peer that passes a retained session end.
#[derive(Clone, Copy, Debug)]
enum Passing {
    /// A one-row message, then one message of this many new prefixes.
    Burst(u32),
    /// Repeating: one message of `.0` new prefixes, then `.1` one-row messages.
    Bursts(u32, u32),
    /// Endless messages of this many new prefixes.
    Endless(u32),
    /// Endless messages that each replace the best paths of this many
    /// prefixes of the 16,384-route table, in rotating blocks. The table
    /// keeps its size, so a founder can finish its build during the feed.
    Replacing(u32),
}

impl Passing {
    /// Rows of the feed's next message, if it has one.
    fn rows(self, message: u32) -> Option<u32> {
        match self {
            Passing::Burst(rows) => [1, rows].get(message as usize).copied(),
            Passing::Bursts(rows, quiet) if message.is_multiple_of(quiet + 1) => Some(rows),
            Passing::Bursts(..) => Some(1),
            Passing::Endless(rows) | Passing::Replacing(rows) => Some(rows),
        }
    }

    fn update(self, message: u32, from: u32, rows: u32) -> RibUpdate {
        let Passing::Replacing(_) = self else {
            return new_prefixes(from, rows);
        };
        let blocks = (16384 / rows).max(1);
        let block = message % blocks;
        let routes = (block * rows..(block + 1) * rows)
            .map(|n| {
                let pair = prefixes(u16::try_from(n / 2).unwrap());
                route(pair[(n % 2) as usize], OTHER, 150 + message / blocks % 2)
            })
            .collect();
        test_routes_received(peer_v4(OTHER), routes)
    }
}

fn new_prefixes(from: u32, rows: u32) -> RibUpdate {
    let routes = (from..from + rows)
        .map(|n| {
            let prefix = Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + n), 32);
            route(Prefix::V4(prefix), OTHER, 100)
        })
        .collect();
    test_routes_received(peer_v4(OTHER), routes)
}

#[derive(PartialEq)]
enum Ran {
    SealedChunk,
    Build,
    Other,
}

/// One owner turn in the order `run_actor` takes its branches: replay of a
/// deferred intent; the sealed owner's turn (an admitted route chunk if
/// there is one, else the build); the registration branch (one primary
/// unit, then one build turn).
async fn owner_turn(
    manager: &mut RibManager,
    sealed: bool,
    primary_due: &mut bool,
    search: &mut usize,
) -> Ran {
    if let Some(intent) = manager.take_first_group_deferred_intent() {
        manager.handle_update(intent);
    } else if sealed {
        if manager.traced_route_chunk() {
            return Ran::SealedChunk;
        }
        manager.advance_first_group_build();
        return Ran::Build;
    } else if manager.first_group_build.is_none()
        && manager.pending_initial_registrations.is_empty()
    {
        manager.drain_ready_updates().await;
    } else if !*primary_due || !manager.drain_ready_updates().await {
        *primary_due = true;
        let build = manager.first_group_build.is_some();
        if !manager.pending_route_batches.is_empty()
            || (manager.can_receive_release_primary() && manager.primary_backlog() > 0)
        {
            manager.advance_busy_first_group(search);
        } else {
            manager.advance_pending_initial_registration();
        }
        if build {
            return Ran::Build;
        }
    } else {
        *primary_due = false;
    }
    Ran::Other
}

#[derive(Debug, Default)]
struct Sealing {
    /// Owner turns on which the writer held the lane sealed.
    sealed_turns: usize,
    first_sealed_turn: Option<usize>,
    /// Route chunks run back to back by the sealed owner.
    sealed_chunk_turns: usize,
    /// Builds retired and started over.
    discards: usize,
    /// The counter on the first scan turn of each retry.
    behind_turns_after_restart: Vec<u16>,
    max_behind_turns: u16,
    /// Build turns that found the repair log more than half full.
    behind_build_turns: usize,
    marker_enqueued_turn: Option<usize>,
    marker_wait: Option<usize>,
    /// Best routes when the writer committed.
    routes: usize,
    commit_turn: Option<usize>,
    end_applied_turn: Option<usize>,
}

/// A cold build on `2 * per_family` routes that holds a policy clear, with
/// `feed` from another peer, stepped one `owner_turn` per iteration. An
/// unrelated UPDATE is enqueued at `marker_at`, or at the first sealed turn
/// if that comes first. Stops at `limit` turns, or once the writer has
/// committed and the session end has been applied.
async fn sealing(
    feed: Passing,
    per_family: u16,
    session_end: bool,
    marker_at: usize,
    limit: usize,
) -> Sealing {
    let (mut manager, primary, mut receivers) = cold_build_with_policy_members(per_family, 1);
    let incumbent = receiver(1);
    if matches!(feed, Passing::Bursts(..)) {
        // Each small UPDATE between bursts must get its own receive turn.
        // Coalescing them would make that turn count depend on the 5 ms window.
        manager.distribution_window_limits.messages = 1;
    }
    let mut policy_reply = clear_policy(&mut manager, incumbent);
    if session_end {
        primary
            .try_send(RibUpdate::PeerDown {
                peer: incumbent,
                session_id: 1,
            })
            .unwrap();
    }
    let (marker, marker_update) = other_marker();
    let mut marker_update = Some(marker_update);
    let (mut sent_rows, mut message) = (0u32, 0u32);
    let mut send = |manager: &RibManager| {
        while manager.primary_backlog() < 2 {
            let Some(rows) = feed.rows(message) else {
                break;
            };
            if primary.try_send(new_prefixes(sent_rows, rows)).is_err() {
                break;
            }
            sent_rows += rows;
            message += 1;
        }
    };
    let mut seen = Sealing::default();
    let (mut primary_due, mut search, mut retiring) = (true, 0usize, false);
    for turn in 1..=limit {
        send(&manager);
        for rx in &mut receivers {
            while rx.try_recv().is_ok() {}
        }
        let sealed = manager.first_group_commit_remaining == Some(0)
            && manager.first_group_pending_writer().is_some();
        if marker_update.is_some() && (sealed || turn == marker_at) {
            primary.try_send(marker_update.take().unwrap()).unwrap();
            seen.marker_enqueued_turn = Some(turn);
        }
        if sealed {
            seen.sealed_turns += 1;
            seen.first_sealed_turn.get_or_insert(turn);
        }
        let scanning = manager.first_group_build.is_some() && !retiring;
        let behind = scanning && manager.loc_rib.registration_scan_behind();
        let ran = owner_turn(&mut manager, sealed, &mut primary_due, &mut search).await;
        seen.sealed_chunk_turns += usize::from(ran == Ran::SealedChunk);
        seen.behind_build_turns += usize::from(behind && ran == Ran::Build);
        let behind_turns = manager.first_group_behind_turns().unwrap_or(0);
        seen.max_behind_turns = seen.max_behind_turns.max(behind_turns);
        let now_retiring = manager.first_group_retiring_slots().is_some();
        seen.discards += usize::from(now_retiring && !retiring);
        if retiring && !now_retiring && manager.first_group_build.is_some() {
            seen.behind_turns_after_restart.push(behind_turns);
        }
        retiring = now_retiring;
        if seen.marker_wait.is_none() && manager.loc_rib.get(&marker).is_some() {
            seen.marker_wait = seen.marker_enqueued_turn.map(|at| turn - at);
        }
        if seen.commit_turn.is_none() && manager.first_group_pending_writer().is_none() {
            seen.commit_turn = Some(turn);
            seen.routes = manager.loc_rib.len();
            assert_eq!(policy_reply.try_recv().unwrap(), Ok(()));
        }
        if session_end
            && seen.end_applied_turn.is_none()
            && !manager.outbound_peers.contains_key(&incumbent)
        {
            assert!(
                seen.commit_turn.is_some(),
                "the session end passed the writer"
            );
            seen.end_applied_turn = Some(turn);
        }
        if seen.commit_turn.is_some() && (seen.end_applied_turn.is_some() || !session_end) {
            break;
        }
    }
    seen
}

const SEAL_BUDGET: usize = crate::manager::first_group_build::BEHIND_TURNS_BEFORE_SEAL as usize;

// Unrelated input that passes a retained session end must not postpone the
// writer and the end without bound. Once it has kept the repair log more
// than half full on 64 build turns, the build owns every turn. The sealed
// owner first runs the chunks of the message in flight back to back. One
// chunk fits the log; three or more can overflow it, depending on where in
// the message the budget ran out. That build is then discarded and the
// retry, which starts sealed so that no input passes it, commits.
#[tokio::test]
async fn input_outrunning_the_build_behind_a_retained_session_end_seals_the_lane() {
    for (rows, discards) in [(2048, 0), (4096, 1), (16378, 1)] {
        let seen = sealing(Passing::Endless(rows), 8192, true, usize::MAX, 2_000).await;
        eprintln!("endless x{rows}: {seen:?}");
        let commit = seen.commit_turn.unwrap_or_else(|| {
            panic!("x{rows}: the writer and the session end were postponed: {seen:?}")
        });
        assert_eq!(seen.end_applied_turn, Some(commit + 1), "x{rows}: {seen:?}");
        assert!(seen.discards <= discards, "x{rows}: {seen:?}");
        assert!(
            seen.sealed_chunk_turns < rows.div_ceil(1024) as usize,
            "x{rows}: {seen:?}"
        );
        let discards = seen.discards;
        // A build turn is every second owner turn until the seal, and a feed
        // that outruns the build keeps it behind on at least every other
        // one (64 of 107 at two chunks, the slowest), so the budget is spent
        // within four owner turns per behind turn.
        let sealed_at = seen.first_sealed_turn.unwrap();
        assert!(sealed_at <= 4 * SEAL_BUDGET, "x{rows}: {seen:?}");
        // Sealed, the table has stopped growing and every turn that is not
        // a chunk of the message in flight is the build's. A page visits
        // 1,024 buckets and the map has at most 16 buckets per 7 routes,
        // so one pass is under three pages per 1,024 routes. A discarded
        // table is retired and built again: three passes.
        let pass = 3 * seen.routes.div_ceil(1024) + 16;
        assert!(
            commit <= sealed_at + seen.sealed_chunk_turns + (1 + 2 * discards) * pass,
            "x{rows}: {seen:?}"
        );
    }
}

// The seal is for input that does not stop. One UPDATE of any size, and
// large UPDATEs separated by small ones, leave the other peers' input
// flowing: a third peer's UPDATE queued behind them is installed while the
// build is still scanning.
#[tokio::test]
async fn a_burst_behind_a_retained_session_end_leaves_the_lane_open() {
    for feed in [
        Passing::Burst(4096),
        Passing::Burst(16378),
        Passing::Bursts(4096, 4),
    ] {
        let seen = sealing(feed, 8192, true, 12, 2_000).await;
        eprintln!("{feed:?}: {seen:?}");
        let commit = seen.commit_turn.expect("the writer commits");
        assert_eq!(
            seen.end_applied_turn,
            Some(commit + 1),
            "{feed:?}: {seen:?}"
        );
        assert!(
            usize::from(seen.max_behind_turns) < SEAL_BUDGET / 2,
            "{feed:?}: {seen:?}"
        );
        assert_eq!(seen.discards, 0, "{feed:?}: {seen:?}");
        // The only sealed turns are the commit's own frontier.
        assert!(
            seen.first_sealed_turn.is_none_or(|turn| turn + 2 >= commit),
            "{feed:?}: {seen:?}"
        );
        // The sixteen-chunk message is ahead of the third peer's in the FIFO.
        assert!(
            seen.marker_wait.is_some_and(|wait| wait <= 32) && commit > 12 + 32,
            "{feed:?}: {seen:?}"
        );
    }
}

// A feed the alternating scan keeps up with never fills the log past half:
// the largest sustained UPDATE of base framing (1,357 rows, two chunks).
#[tokio::test]
async fn input_the_build_keeps_up_with_spends_none_of_the_seal_budget() {
    let seen = sealing(Passing::Endless(1357), 8192, true, 12, 2_000).await;
    eprintln!("{seen:?}");
    let commit = seen.commit_turn.expect("the writer commits");
    assert_eq!((seen.max_behind_turns, seen.discards), (0, 0), "{seen:?}");
    assert!(seen.first_sealed_turn.unwrap() + 4 >= commit, "{seen:?}");
}

// Without a retained session end nothing is postponed behind the writer, so
// input that outruns the build keeps its turns.
#[tokio::test]
async fn input_outrunning_the_build_with_no_session_end_leaves_the_lane_open() {
    let seen = sealing(Passing::Endless(4096), 8192, false, 12, 600).await;
    eprintln!("{seen:?}");
    assert!(seen.behind_build_turns > 2 * SEAL_BUDGET, "{seen:?}");
    assert_eq!(
        (seen.sealed_turns, seen.max_behind_turns),
        (0, 0),
        "{seen:?}"
    );
    assert!(seen.marker_wait.is_some_and(|wait| wait <= 32), "{seen:?}");
}

// The budget belongs to one attempt of one writer. A retry starts from zero
// (it is sealed by the overflow that caused it), and so does a build whose
// writer was withdrawn.
#[tokio::test]
async fn the_seal_budget_does_not_outlive_its_attempt_or_its_writer() {
    let seen = sealing(Passing::Endless(16378), 8192, true, usize::MAX, 2_000).await;
    assert!(
        usize::from(seen.max_behind_turns) >= SEAL_BUDGET,
        "{seen:?}"
    );
    assert_eq!(seen.behind_turns_after_restart, [0], "{seen:?}");

    // A caller that gave up its command releases the claim.
    let (mut manager, primary, _receivers) = cold_build_with_policy_members(8192, 1);
    let (reply, policy_reply) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: vec![crate::update::PeerExportPolicyReplacement {
            peer: receiver(1),
            export_policy: None,
        }],
        reply,
    });
    assert!(manager.first_group_pending_writer().is_some());
    primary
        .try_send(RibUpdate::PeerDown {
            peer: receiver(1),
            session_id: 1,
        })
        .unwrap();
    let routes = (0..16378)
        .map(|n| {
            let prefix = Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + n), 32);
            route(Prefix::V4(prefix), OTHER, 100)
        })
        .collect();
    primary
        .try_send(test_routes_received(peer_v4(OTHER), routes))
        .unwrap();
    for _ in 0..12 {
        manager.drain_ready_updates().await;
        manager.advance_first_group_build();
    }
    assert!(manager.first_group_behind_turns().unwrap() > 0);
    drop(policy_reply);
    manager.advance_first_group_build();
    assert!(manager.first_group_pending_writer().is_none());
    assert_eq!(manager.first_group_behind_turns(), Some(0));
    assert!(manager.first_group_commit_remaining.is_none());
}

/// What waits for the founder's slot.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Parked {
    Nothing,
    /// One command whose caller waits for the reply.
    Live,
    /// One command whose caller drops the reply before this owner turn.
    Abandoned(usize),
    /// The same, with a live command for a third destination queued behind.
    AbandonedThenLive(usize),
}

#[derive(Debug, Default)]
struct Waiting {
    /// Owner turn on which the live waiting command ran and replied.
    replied_turn: Option<usize>,
    end_applied_turn: Option<usize>,
    founder_grouped_turn: Option<usize>,
    /// First turn after the reply on which a cold build exists again.
    restarted_turn: Option<usize>,
    /// First turn from the abandonment on which a live command holds the
    /// reservation at the head of the retained intents.
    live_reserved_turn: Option<usize>,
    sealed_turns: usize,
    /// Turns that began with the lane sealed and no owner to open it.
    ownerless_sealed_turns: usize,
    /// Founder builds retired before they published.
    discards: usize,
    max_behind_turns: u16,
    /// The largest count from the second turn after the abandonment.
    max_behind_turns_once_abandoned: u16,
}

type PolicyReply = oneshot::Receiver<Result<Vec<PeerId>, crate::RibCommandError>>;

fn other_destination(peer: PeerId, chain: u32) -> (RibUpdate, PolicyReply) {
    let (reply, response) = oneshot::channel();
    let update = RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: vec![crate::update::PeerExportPolicyReplacement {
            peer,
            export_policy: Some(super::update_groups::community_chain(chain)),
        }],
        reply,
    };
    (update, response)
}

/// A founder's cold build on 16,384 routes, `parked` policy changes that
/// each need a different, cold destination behind it, and `feed` from
/// another peer, stepped one `owner_turn` per iteration. Stops at `limit`
/// turns, or once the live command has replied, the session end has been
/// applied and the founder is grouped. Under an endless feed with a live
/// command, the founder's next build having started stands in for the last.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario read top to bottom; splitting it would hide the order of events"
)]
async fn waiting_destination(
    feed: Passing,
    parked: Parked,
    session_end: bool,
    limit: usize,
) -> Waiting {
    let members = if matches!(parked, Parked::AbandonedThenLive(_)) {
        2
    } else {
        1
    };
    let (mut manager, primary, mut receivers) = cold_build_with_policy_members(8192, members);
    let (incumbent, founder) = (receiver(1), receiver(100));
    let (mut response, mut abandoned) = (None, None);
    if parked != Parked::Nothing {
        let (update, reply) = other_destination(incumbent, 0xfde8_2415);
        manager.handle_update(update);
        assert_eq!(manager.first_group_deferred_intents.len(), 1);
        assert!(manager.first_group_build.is_some());
        match parked {
            Parked::Abandoned(turn) | Parked::AbandonedThenLive(turn) => {
                abandoned = Some((turn, reply));
            }
            _ => response = Some(reply),
        }
    }
    if matches!(parked, Parked::AbandonedThenLive(_)) {
        let (update, reply) = other_destination(receiver(2), 0xfde8_2416);
        primary.try_send(update).unwrap();
        response = Some(reply);
    }
    if session_end {
        primary
            .try_send(RibUpdate::PeerDown {
                peer: incumbent,
                session_id: 1,
            })
            .unwrap();
        // Another peer's End-of-RIB does not pass a retained session end: it
        // is held at the head, which seals the lane behind the reservation.
        if abandoned.is_some() {
            primary
                .try_send(RibUpdate::EndOfRib {
                    peer: peer_v4(OTHER),
                    session_id: 0,
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                })
                .unwrap();
        }
    }
    let abandon_turn = abandoned.as_ref().map(|(turn, _)| *turn);
    let endless = feed.rows(u32::MAX).is_some();
    let (mut sent_rows, mut message) = (0u32, 0u32);
    let mut seen = Waiting::default();
    let (mut primary_due, mut search, mut retiring) = (true, 0usize, false);
    for turn in 1..=limit {
        abandoned.take_if(|(at, _)| *at == turn);
        while manager.primary_backlog() < 2 {
            let Some(rows) = feed.rows(message) else {
                break;
            };
            if primary
                .try_send(feed.update(message, sent_rows, rows))
                .is_err()
            {
                break;
            }
            sent_rows += rows;
            message += 1;
        }
        for rx in &mut receivers {
            while rx.try_recv().is_ok() {}
        }
        let owned = manager.first_group_pending_writer().is_some()
            || manager.optional_destination_retirement_active();
        let sealed = manager.first_group_commit_remaining == Some(0)
            && manager.first_group_pending_writer().is_some();
        seen.sealed_turns += usize::from(sealed);
        seen.ownerless_sealed_turns +=
            usize::from(manager.first_group_commit_remaining == Some(0) && !owned);
        owner_turn(&mut manager, sealed, &mut primary_due, &mut search).await;
        let behind_turns = manager.first_group_behind_turns().unwrap_or(0);
        seen.max_behind_turns = seen.max_behind_turns.max(behind_turns);
        if abandon_turn.is_some_and(|at| turn > at + 1) {
            seen.max_behind_turns_once_abandoned =
                seen.max_behind_turns_once_abandoned.max(behind_turns);
        }
        let now_retiring = manager.first_group_retiring_slots().is_some();
        seen.discards += usize::from(now_retiring && !retiring);
        retiring = now_retiring;
        if abandon_turn.is_some_and(|at| turn >= at)
            && seen.live_reserved_turn.is_none()
            && matches!(
                manager.first_group_pending_writer(),
                Some(RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. })
                    if !reply.is_closed()
            )
        {
            seen.live_reserved_turn = Some(turn);
        }
        if seen.replied_turn.is_some()
            && seen.restarted_turn.is_none()
            && manager.first_group_build.is_some()
        {
            seen.restarted_turn = Some(turn);
        }
        if seen.replied_turn.is_none()
            && response
                .as_mut()
                .is_some_and(|response| response.try_recv().is_ok())
        {
            seen.replied_turn = Some(turn);
        }
        if seen.end_applied_turn.is_none() && !manager.outbound_peers.contains_key(&incumbent) {
            seen.end_applied_turn = Some(turn);
        }
        if seen.founder_grouped_turn.is_none() && manager.grouped_member_of(founder).is_some() {
            seen.founder_grouped_turn = Some(turn);
        }
        let settled = (response.is_none() || seen.replied_turn.is_some())
            && (seen.end_applied_turn.is_some() || !session_end)
            && (seen.founder_grouped_turn.is_some() || (endless && seen.restarted_turn.is_some()));
        if settled {
            break;
        }
    }
    seen
}

// A policy change that needs a different cold destination waits for the
// founder's slot, and a session end can wait behind it. Input that keeps the
// founder's repair log more than half full would keep both waiting for as
// long as it lasts. Once it has done so on 64 build turns the founder gives
// the slot up, as it did when such input overflowed the log, and the command
// runs before the founder's retry can take the slot back. No input is held.
#[tokio::test]
async fn input_outrunning_a_founder_hands_its_slot_to_the_waiting_destination() {
    for rows in [2048, 4096, 16378] {
        for session_end in [false, true] {
            let seen =
                waiting_destination(Passing::Endless(rows), Parked::Live, session_end, 1_000).await;
            eprintln!("endless x{rows}, session end {session_end}: {seen:?}");
            let replied = seen.replied_turn.unwrap_or_else(|| {
                panic!("x{rows} {session_end}: the command waited for the feed: {seen:?}")
            });
            // Four owner turns per budgeted turn, as for the seal. The
            // pages staged by then are retired one per build turn, which
            // takes at most as long again.
            assert!(replied <= 8 * SEAL_BUDGET, "x{rows}: {seen:?}");
            assert_eq!(
                (seen.discards, seen.sealed_turns),
                (1, 0),
                "x{rows} {session_end}: {seen:?}"
            );
            assert_eq!(usize::from(seen.max_behind_turns), SEAL_BUDGET);
            if session_end {
                assert!(
                    seen.end_applied_turn
                        .is_some_and(|turn| turn <= replied + 2),
                    "x{rows}: {seen:?}"
                );
            }
            // The founder's retry starts once the replay is over, within
            // the busy turns of the message then in flight.
            let message_turns = 2 * (rows.div_ceil(1024) as usize + 1);
            assert!(
                seen.restarted_turn
                    .is_some_and(|turn| turn <= replied + message_turns + 4),
                "x{rows} {session_end}: the founder's build did not start again: {seen:?}"
            );
        }
    }
}

// A caller whose deadline lapsed while its command was parked has dropped
// the reply, and the command is skipped whole when it replays. The founder
// does not spend its budget or its partial table on it: it registers at
// about the turn it does with no command.
#[tokio::test]
async fn an_abandoned_waiting_destination_costs_the_founder_nothing() {
    let feed = Passing::Replacing(4096);
    let alone = waiting_destination(feed, Parked::Nothing, false, 1_000).await;
    let seen = waiting_destination(feed, Parked::Abandoned(40), false, 1_000).await;
    eprintln!("no command: {alone:?}\nabandoned: {seen:?}");
    let alone = alone.founder_grouped_turn.expect("the founder registers");
    assert_eq!(
        (
            seen.discards,
            seen.sealed_turns,
            seen.ownerless_sealed_turns
        ),
        (0, 0, 0),
        "{seen:?}"
    );
    // The turns counted for the abandoned command are not left on the job
    // for a later writer.
    assert!(
        seen.max_behind_turns > 0 && seen.max_behind_turns_once_abandoned == 0,
        "{seen:?}"
    );
    assert!(
        seen.founder_grouped_turn
            .is_some_and(|turn| turn <= alone + 16),
        "no command: {alone}, abandoned: {seen:?}"
    );
}

// A session end retained behind the abandoned command does not wait for the
// founder's budget, and the head held behind that session end, which sealed
// the lane while the reservation stood, is admitted afterwards.
#[tokio::test]
async fn a_session_end_behind_an_abandoned_waiting_destination_is_applied_at_once() {
    const ABANDONED: usize = 8;
    let seen = waiting_destination(
        Passing::Replacing(4096),
        Parked::Abandoned(ABANDONED),
        true,
        1_000,
    )
    .await;
    eprintln!("{seen:?}");
    assert!(seen.sealed_turns > 0, "the held head sealed: {seen:?}");
    // The abandoned command, then the session end: one replay each, after
    // the build turn that noticed.
    assert!(
        seen.end_applied_turn
            .is_some_and(|turn| turn <= ABANDONED + 4),
        "{seen:?}"
    );
    assert_eq!(
        (seen.discards, seen.ownerless_sealed_turns),
        (0, 0),
        "{seen:?}"
    );
    assert!(seen.founder_grouped_turn.is_some(), "{seen:?}");
}

// A live command for a third destination queued behind the abandoned one
// takes over the reservation when it replays, in its place in the queue, and
// gets the slot as a command parked alone does.
#[tokio::test]
async fn a_live_command_behind_an_abandoned_one_still_gets_the_slot() {
    const ABANDONED: usize = 20;
    let seen = waiting_destination(
        Passing::Endless(4096),
        Parked::AbandonedThenLive(ABANDONED),
        false,
        1_000,
    )
    .await;
    eprintln!("{seen:?}");
    // The message in flight finishes, then the two replays.
    assert!(
        seen.live_reserved_turn
            .is_some_and(|turn| turn <= ABANDONED + 16),
        "{seen:?}"
    );
    let replied = seen.replied_turn.expect("the live command replies");
    assert!(replied <= ABANDONED + 8 * SEAL_BUDGET, "{seen:?}");
    assert_eq!(
        (
            seen.discards,
            seen.sealed_turns,
            seen.ownerless_sealed_turns
        ),
        (1, 0, 0),
        "{seen:?}"
    );
    assert!(seen.restarted_turn.is_some(), "{seen:?}");
}

// One UPDATE of any size is over before the budget is spent: the founder
// keeps its pages, registers, and the command runs after it.
#[tokio::test]
async fn a_burst_leaves_the_founder_its_slot_while_a_destination_waits() {
    for feed in [Passing::Burst(4096), Passing::Burst(16378)] {
        let seen = waiting_destination(feed, Parked::Live, true, 1_000).await;
        eprintln!("{feed:?}: {seen:?}");
        let founder = seen.founder_grouped_turn.expect("the founder registers");
        assert_eq!(
            (seen.discards, seen.sealed_turns),
            (0, 0),
            "{feed:?}: {seen:?}"
        );
        assert!(
            usize::from(seen.max_behind_turns) < SEAL_BUDGET / 2,
            "{feed:?}: {seen:?}"
        );
        assert!(
            seen.replied_turn.is_some_and(|turn| turn > founder),
            "{feed:?}: {seen:?}"
        );
    }
}

// The same on the real actor loop: the command replies while at least a
// quarter of the queued feed is still behind it. An overflow that makes way
// for the command satisfies this too. It fails when nothing makes way, or
// when the founder's retry takes the slot back, and the command waits for
// the feed.
#[tokio::test]
async fn actor_runs_a_waiting_destination_during_a_feed_that_outruns_the_founder() {
    const MESSAGES: u32 = 128;
    const ROWS: u32 = 4096;
    let (mut manager, _fixture_primary, mut receivers) = cold_build_with_policy_members(8192, 1);
    let (primary, rx) = mpsc::channel(MESSAGES as usize + 16);
    manager.rx = rx;
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: vec![crate::update::PeerExportPolicyReplacement {
            peer: receiver(1),
            export_policy: Some(super::update_groups::community_chain(0xfde8_2415)),
        }],
        reply,
    });
    assert_eq!(manager.first_group_deferred_intents.len(), 1);
    for message in 0..MESSAGES {
        primary
            .try_send(new_prefixes(message * ROWS, ROWS))
            .unwrap();
    }
    let actor = tokio::spawn(manager.run_actor());
    let queued = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            for rx in &mut receivers {
                while rx.try_recv().is_ok() {}
            }
            if let Ok(result) = response.try_recv() {
                assert!(result.is_ok(), "{result:?}");
                break primary.max_capacity() - primary.capacity();
            }
            assert!(!actor.is_finished());
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the command replies");
    actor.abort();
    eprintln!("{queued} of {MESSAGES} messages still queued at the reply");
    assert!(queued >= MESSAGES as usize / 4, "{queued} messages left");
}

// One stale route of a restarted, reconnected peer that has not sent
// End-of-RIB, a claimed writer, and a queued command that concerns every
// peer, so that this peer's next session end is retained behind it.
fn restarted_source_behind_a_writer(
    llgr: bool,
) -> (RibManager, mpsc::Sender<RibUpdate>, Prefix, RibUpdate) {
    let (mut manager, primary, _) = fixture(0);
    let incumbent = receiver(1);
    drop(join(&mut manager, incumbent, 1, &DUAL));
    let slow = |slow| RibUpdate::PeerSlowState {
        peer: incumbent,
        session_id: 1,
        slow,
    };
    manager.handle_update(slow(true));
    let source = peer_v4(SOURCE);
    let stale = prefixes(1)[0];
    manager.handle_update(test_routes_received(
        source,
        vec![route(stale, SOURCE, 100)],
    ));
    drain_route_chunks(&mut manager);
    let restart = |session_id| RibUpdate::PeerGracefulRestart {
        peer: source,
        session_id,
        restart_time: 10,
        stale_routes_time: 30,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: llgr,
        peer_llgr_families: if llgr {
            vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 3600,
            }]
        } else {
            vec![]
        },
        llgr_stale_time: if llgr { 3600 } else { 0 },
    };
    if llgr {
        manager.handle_update(restart(0));
        manager.handle_update(registering_peer_up(source, 1));
        assert!(manager.loc_rib.get(&stale).unwrap().is_stale);
    }
    drop(join(&mut manager, receiver(2), 1, &DUAL));
    manager.handle_update(slow(false));
    assert!(manager.first_group_pending_writer().is_some());
    let (reply, reobserved) = oneshot::channel();
    std::mem::forget(reobserved);
    primary
        .try_send(RibUpdate::ReobserveConditionalAdvertisements {
            datasets: vec![],
            changed: vec![],
            reply,
        })
        .unwrap();
    (manager, primary, stale, restart(u64::from(llgr)))
}

// The run loop's order around one due timer: a due replay, then the sealed
// owner, then the drain that precedes the expiry.
async fn drain_until_expiry_may_fire(manager: &mut RibManager, timer: ExpiryTimer) {
    for _ in 0..512 {
        if let Some(intent) = manager.take_first_group_deferred_intent() {
            manager.handle_update(intent);
        } else if manager.first_group_commit_remaining == Some(0)
            && manager.first_group_pending_writer().is_some()
        {
            manager.advance_first_group_build();
        } else if !manager.drain_before_expiry(timer).await {
            assert!(manager.expiry_cutoffs.captured_at(timer).is_none());
            return;
        }
    }
    panic!("the expiry never became eligible");
}

// A second restart before End-of-RIB deletes the routes still stale from the
// first (RFC 4724). Run after the stale timer instead, they would first be
// promoted to long-lived stale and then survive the restart.
#[tokio::test(start_paused = true)]
async fn gr_expiry_waits_for_a_retained_second_restart_end() {
    let (mut manager, primary, stale, restart) = restarted_source_behind_a_writer(true);
    let source = peer_v4(SOURCE);
    primary.try_send(restart).unwrap();
    let due = manager.gr_stale_deadlines[&source];
    tokio::time::advance(due - tokio::time::Instant::now()).await;
    let now = tokio::time::Instant::now();
    let timer = ExpiryTimer::GrStale;
    manager
        .expiry_cutoffs
        .observe(timer, Some(due), now, manager.primary_backlog());
    drain_until_expiry_may_fire(&mut manager, timer).await;
    assert!(manager.first_group_pending_writer().is_none());
    assert!(manager.first_group_deferred_intents.is_empty());
    if manager
        .gr_stale_deadlines
        .get(&source)
        .is_some_and(|deadline| *deadline <= now)
    {
        manager.sweep_gr_stale(source);
    }
    assert!(
        manager.loc_rib.get(&stale).is_none(),
        "the unrefreshed stale route outlived the second restart"
    );
}

// A restart retains the peer's routes. Run after a due refresh-window
// expiry instead, the unrefreshed route would already have been deleted.
#[tokio::test(start_paused = true)]
async fn refresh_window_expiry_waits_for_a_retained_restart_end() {
    let (mut manager, primary, kept, restart) = restarted_source_behind_a_writer(false);
    let source = peer_v4(SOURCE);
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: source,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    let due = manager
        .next_refresh_deadline()
        .expect("an open refresh window");
    primary.try_send(restart).unwrap();
    tokio::time::advance(due - tokio::time::Instant::now()).await;
    let now = tokio::time::Instant::now();
    let timer = ExpiryTimer::RefreshWindow;
    manager
        .expiry_cutoffs
        .observe(timer, Some(due), now, manager.primary_backlog());
    drain_until_expiry_may_fire(&mut manager, timer).await;
    assert!(manager.first_group_deferred_intents.is_empty());
    manager.expire_refresh_windows(now);
    assert!(
        manager
            .loc_rib
            .get(&kept)
            .is_some_and(|route| route.is_stale),
        "the restart retains the route the refresh had not replaced"
    );
}

const LABELED: [(Afi, Safi); 2] = [
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv6, Safi::LabeledUnicast),
];

fn labeled_row(source: u8, prefix: Prefix, label: u32, pref: u32) -> crate::route::LabeledRibRoute {
    let mut row = make_labeled_rib_route(MEMBER(source), 0, label, pref);
    row.nlri.prefix = prefix;
    // The fixture is no route reflector: an eBGP-learned row reaches C.
    row.origin_type = crate::route::RouteOrigin::Ebgp;
    if matches!(prefix, Prefix::V6(_)) {
        row.next_hop = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));
    }
    row
}

// Rows `(index, label)` of both labeled AFIs from member `source`, with the
// withdrawal of `withdrawn` in both.
fn labeled_input(source: u8, pref: u32, rows: &[(u16, u32)], withdrawn: &[u16]) -> RibUpdate {
    RibUpdate::LabeledRoutesReceived {
        peer: receiver(source),
        session_id: 1,
        announced: rows
            .iter()
            .flat_map(|&(i, label)| {
                prefixes(i).map(|prefix| labeled_row(source, prefix, label, pref))
            })
            .collect(),
        withdrawn: withdrawn
            .iter()
            .flat_map(|&i| prefixes(i))
            .map(|prefix| crate::route::LabeledRibRouteKey { prefix, path_id: 0 })
            .collect(),
    }
}

// The source and label stack of each labeled prefix a receiver holds.
type LabeledTable = BTreeMap<Prefix, (PeerId, String)>;

fn read_labeled(table: &mut LabeledTable, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    while let Ok(update) = rx.try_recv() {
        for key in &update.labeled_withdraw {
            assert!(
                table.remove(&key.prefix).is_some(),
                "withdrawal of {key:?}, which the receiver does not hold"
            );
        }
        for row in &update.labeled_announce {
            table.insert(
                row.nlri.prefix,
                (row.peer, format!("{:?}", row.nlri.labels)),
            );
        }
    }
}

// Tick the resync timer while it is armed; the receiver reads throughout.
fn read_until_idle(
    manager: &mut RibManager,
    table: &mut LabeledTable,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) {
    for _ in 0..100_000 {
        read_labeled(table, rx);
        if !manager.resync_tick_pending() {
            return;
        }
        manager.resync_dirty_peers_bounded();
    }
    panic!("the labeled receiver never caught up");
}

// Peer A's session ends behind its claimed policy writer while a cold build
// runs. Peer B's labeled input passes the retained end: it withdraws a prefix
// both announced, changes a label and rotates fresh rows. Labeled receiver C
// is not reading, so it comes to owe both labeled families whole and reads
// them through the row cursor. After the writer commits and the retained end
// replays, C holds exactly B's rows with their labels: none of A's, the
// shared prefix included. C resumes before the commit or after the teardown.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario read top to bottom; splitting it would hide the order of events"
)]
#[tokio::test]
async fn labeled_input_passing_a_retained_session_end_reaches_a_paused_cursor_receiver() {
    use super::super::outbound_owing::OwedFamily;

    const SHARED: u16 = 40_000;
    let (a, b, c) = (receiver(1), receiver(2), receiver(200));
    let whole = |manager: &RibManager| {
        [OwedFamily::IPV4_LABELED, OwedFamily::IPV6_LABELED]
            .iter()
            .all(|family| manager.owes_whole(c, *family))
    };
    for resumes_before_commit in [false, true] {
        let case = format!("resumes_before_commit={resumes_before_commit}");
        let (mut manager, primary, expected) = fixture(8192);
        let mut c_rx = join(&mut manager, c, 1, &LABELED);
        finish(&mut manager);
        assert!(manager.first_group_build.is_none(), "{case}");
        let (mut manager, primary, _receivers) =
            cold_build_with_policy_members_on((manager, primary, expected), 2);
        let mut held = LabeledTable::new();
        let mut b_rows: BTreeMap<u16, u32> = (0..8).map(|i| (i, 100)).collect();
        b_rows.insert(SHARED, 500);
        let offered: Vec<_> = b_rows.iter().map(|(&i, &label)| (i, label)).collect();
        manager.handle_update(labeled_input(
            1,
            150,
            &[(SHARED, 400), (30_000, 400), (30_001, 400)],
            &[],
        ));
        manager.handle_update(labeled_input(2, 190, &offered, &[]));
        drain_route_chunks(&mut manager);
        read_until_idle(&mut manager, &mut held, &mut c_rx);
        assert_eq!(held.len(), 2 * 11, "{case}: admitted");
        assert_eq!(held[&prefixes(SHARED)[0]].0, b, "{case}");
        assert_eq!(held[&prefixes(30_000)[1]].0, a, "{case}");

        // C stops reading.
        let sender = manager.outbound_peers[&c].clone();
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        drop(sender);
        let mut policy_reply = clear_policy(&mut manager, a);
        primary
            .try_send(RibUpdate::PeerDown {
                peer: a,
                session_id: 1,
            })
            .unwrap();
        let mut previous: Vec<u16> = Vec::new();
        let mut rounds_after_cursor = 0;
        for round in 0..400u16 {
            let base = 1000 + round * 64;
            let fresh: Vec<(u16, u32)> = (base..base + 64).map(|i| (i, 100)).collect();
            let mut withdrawn = previous.clone();
            let mut rows = fresh.clone();
            if rounds_after_cursor == 1 {
                // With the cursor live: the shared prefix falls to A's path
                // and a row C holds changes its label.
                withdrawn.push(SHARED);
                b_rows.remove(&SHARED);
                rows.push((0, 777));
            }
            for index in &previous {
                b_rows.remove(index);
            }
            b_rows.extend(rows.iter().copied());
            primary
                .try_send(labeled_input(2, 190, &rows, &withdrawn))
                .unwrap();
            while manager.drain_ready_updates().await {}
            drain_route_chunks(&mut manager);
            previous = (base..base + 64).collect();
            rounds_after_cursor += u32::from(whole(&manager));
            if rounds_after_cursor == 3 {
                break;
            }
        }
        assert!(
            whole(&manager),
            "{case}: C owes both labeled families whole"
        );
        assert!(!manager.dirty_peers.contains(&c), "{case}");
        assert!(
            !manager.owed_row_evicted.contains(&c),
            "{case}: cursor live"
        );
        assert!(manager.session_end_retained(), "{case}");
        assert!(manager.first_group_pending_writer().is_some(), "{case}");
        assert!(manager.outbound_peers.contains_key(&a), "{case}");
        assert!(policy_reply.try_recv().is_err(), "{case}");
        for prefix in prefixes(SHARED) {
            let during = manager
                .loc_rib
                .iter_labeled()
                .find(|r| r.nlri.prefix == prefix);
            assert_eq!(
                during.map(|r| r.peer),
                Some(a),
                "{case}: A's path until the teardown"
            );
        }
        assert_eq!(held.len(), 2 * 11, "{case}: nothing reached C");

        if resumes_before_commit {
            read_until_idle(&mut manager, &mut held, &mut c_rx);
            assert_eq!(held[&prefixes(SHARED)[0]].0, a, "{case}");
            assert!(manager.session_end_retained(), "{case}");
        }
        commit_claimed_writer(&mut manager);
        assert_eq!(policy_reply.try_recv().unwrap(), Ok(()), "{case}");
        assert!(manager.try_recv_primary().is_none(), "{case}");
        let end = manager.take_first_group_deferred_intent().unwrap();
        assert!(matches!(end, RibUpdate::PeerDown { peer, .. } if peer == a));
        manager.handle_update(end);
        finish(&mut manager);
        drain_route_chunks(&mut manager);
        assert!(!manager.outbound_peers.contains_key(&a), "{case}");
        read_until_idle(&mut manager, &mut held, &mut c_rx);

        let expected: LabeledTable = b_rows
            .iter()
            .flat_map(|(&i, &label)| {
                prefixes(i).map(|prefix| {
                    let labels = format!("{:?}", labeled_row(2, prefix, label, 190).nlri.labels);
                    (prefix, (b, labels))
                })
            })
            .collect();
        let selected: LabeledTable = manager
            .loc_rib
            .iter_labeled()
            .map(|r| (r.nlri.prefix, (r.peer, format!("{:?}", r.nlri.labels))))
            .collect();
        assert_eq!(selected, expected, "{case}: selected rows");
        assert_eq!(expected.len(), 2 * (8 + 64), "{case}");
        assert!(
            held.values().all(|(source, _)| *source != a),
            "{case}: A's rows left"
        );
        assert_eq!(held, expected, "{case}: C's exact labeled table");
        let steps = histogram_sample_counts_by_label(
            &manager.metrics,
            "bgp_rib_outbound_owed_drain_step_seconds",
            "scope",
        );
        assert!(
            steps.get("cursor").is_some_and(|n| *n > 0),
            "{case}: {steps:?}"
        );
        assert_eq!(steps.get("whole").copied().unwrap_or(0), 0, "{case}");
        assert!(manager.owing(c).is_none(), "{case}: nothing owed");
        assert!(!manager.dirty_peers.contains(&c), "{case}");
        assert!(
            manager.owed_rows.iter().all(|list| list.len() == 0),
            "{case}"
        );
    }
}

mod authoritative_metadata;
mod authoritative_order;
mod authoritative_reload;
mod authoritative_scope;
mod policy_fallback;
mod policy_oracle;
mod policy_work;
mod sustained_feed;
