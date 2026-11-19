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
