//! A receiver that is a GR helper keeps our routes stale after a clean
//! session end (RFC 4724 §4.2) and drops them only at our End-of-RIB, which
//! a selection hold defers until release. An exempt row deleted before the
//! new session re-sends it must still be withdrawn inside the hold.

use std::collections::BTreeMap;

use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter, private_policy};
use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 82);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);

/// The peer's view: each key and whether it is a stale leftover from the
/// session that ended.
type PeerRib = BTreeMap<(Prefix, u32), bool>;

/// Applies every queued update; `keep` must stay on the peer after each one.
fn apply(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rib: &mut PeerRib,
    keep: Option<(Prefix, u32)>,
) -> usize {
    let mut markers = 0;
    while let Ok(update) = rx.try_recv() {
        assert!(
            (update.withdraw.is_empty() && update.announce.is_empty())
                || update.exact_export_snapshot.is_some(),
            "the transport resets a session on a route-bearing envelope without its export snapshot"
        );
        for key in &update.withdraw {
            rib.remove(key);
        }
        for route in update.announce.iter() {
            rib.insert((route.prefix, route.path_id), false);
        }
        if update.end_of_rib.contains(&FAMILY) {
            markers += 1;
            rib.retain(|_, stale| !*stale);
        }
        assert!(
            keep.is_none_or(|key| rib.contains_key(&key)),
            "a kept row (a live RTBH or a rightly stale one) never leaves the peer, even briefly"
        );
    }
    markers
}

type Session = (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
    Vec<mpsc::OwnedPermit<OutboundRouteUpdate>>,
);

/// Registers a session; `full` occupies its writer before `PeerUp`, so the
/// initial table waits for a later resync.
fn register(manager: &mut RibManager, session_id: u64, grouped: bool, full: bool) -> Session {
    register_peer(manager, OBSERVER, session_id, grouped, full, false)
}

/// [`register`] for any receiver; `add_path` negotiates Add-Path send.
fn register_peer(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    grouped: bool,
    full: bool,
    add_path: bool,
) -> Session {
    register_with(manager, address, session_id, grouped, full, add_path, false)
}

/// [`register_peer`]; `orf` negotiates Address Prefix ORF receive, which
/// holds the initial table until the peer sends its ORF.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "each flag is one independent session property of the fixture"
)]
fn register_with(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    grouped: bool,
    full: bool,
    add_path: bool,
    orf: bool,
) -> Session {
    let observer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: observer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, rx) = mpsc::channel(64);
    let occupied: Vec<_> = if full {
        std::iter::from_fn(|| tx.clone().try_reserve_owned().ok()).collect()
    } else {
        Vec::new()
    };
    let mut up = super::lifecycle::test_peer_up(observer, session_id, tx.clone());
    if let RibUpdate::PeerUp {
        sendable_families,
        export_policy,
        per_client_best,
        add_path_send_families,
        add_path_send_max,
        negotiated_orf_recv,
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY];
        if orf {
            *negotiated_orf_recv = vec![FAMILY];
        }
        if !grouped {
            *export_policy = Some(private_policy(None));
        }
        if add_path {
            *per_client_best = true;
            *add_path_send_families = vec![FAMILY];
            *add_path_send_max = 2;
        }
    }
    manager.handle_update(up);
    // A deferred registration joins its group when the run loop completes it.
    if manager.pending_initial_registrations.contains(&observer) {
        assert!(manager.grouped_member_of(observer).is_none());
    } else {
        assert_eq!(manager.grouped_member_of(observer).is_some(), grouped);
    }
    (tx, rx, occupied)
}

fn inject_rtbh(manager: &mut RibManager, prefix: Ipv4Prefix) {
    let mut route = make_route(prefix, SOURCE);
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::Communities(vec![rustbgpd_wire::COMMUNITY_BLACKHOLE]),
    ]);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
}

fn delete(manager: &mut RibManager, prefix: Ipv4Prefix) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(result.try_recv().unwrap().unwrap().removed);
}

fn clean_end(manager: &mut RibManager, session_id: u64) {
    clean_end_of(manager, OBSERVER, session_id);
}

fn clean_end_of(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) {
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: peer_v4(address),
        session_id,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![FAMILY],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
}

/// `stuck_withdraw`: the delete happens before the session ends, behind a
/// full writer. Otherwise the new session registers behind a full writer
/// and the delete lands before its initial table is admitted. The new
/// session may reuse the ended session's id; its channel is always new.
fn assert_deleted_exempt_leaves_helper_within_hold(
    grouped: bool,
    stuck_withdraw: bool,
    new_session: u64,
    aggregate: bool,
) {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (old_tx, mut old_rx, _) = register(&mut manager, 82, grouped, false);
    let mut peer_rib = PeerRib::new();
    apply(&mut old_rx, &mut peer_rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    // A BLACKHOLE aggregate is exempt by its community, a host by length.
    let rtbh = if aggregate {
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)
    } else {
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32)
    };
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut peer_rib, None);
    let key = (Prefix::V4(rtbh), 0);
    let kept_key = (Prefix::V4(kept), 0);
    assert!(peer_rib.contains_key(&key));

    if stuck_withdraw {
        let occupied: Vec<_> =
            std::iter::from_fn(|| old_tx.clone().try_reserve_owned().ok()).collect();
        delete(&mut manager, rtbh);
        drop(occupied);
    }
    // Clean end toward a GR helper: the peer keeps every row stale.
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in peer_rib.values_mut() {
        *stale = true;
    }

    let (_new_tx, mut new_rx, occupied) =
        register(&mut manager, new_session, grouped, !stuck_withdraw);
    if !stuck_withdraw {
        delete(&mut manager, rtbh);
        drop(occupied);
        // The resync tick runs while the writer is free but the new table
        // has not been resent; nothing may be withdrawn before it is.
        assert!(manager.dirty_peers.contains(&peer_v4(OBSERVER)));
        manager.resync_dirty_peers_bounded();
        apply(&mut new_rx, &mut peer_rib, Some(kept_key));
    }
    let mut markers = 0;
    for _ in 0..4 {
        // The resync timer is the only driver while nothing else changes.
        manager.resync_dirty_peers_bounded();
        markers += apply(&mut new_rx, &mut peer_rib, Some(kept_key));
    }
    assert!(manager.selection_deferred(FAMILY), "still inside the hold");
    assert_eq!(markers, 0, "End-of-RIB stays deferred until release");
    assert!(
        !peer_rib.contains_key(&key),
        "the deleted RTBH leaves the helper inside the hold; peer {peer_rib:?}"
    );
    assert_eq!(
        peer_rib.get(&kept_key),
        Some(&false),
        "the live RTBH is re-sent and never withdrawn"
    );
    assert!(manager.helper_stale_exempt.is_empty());

    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: u64::from(WAITER.octets()[3]),
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut markers = apply(&mut new_rx, &mut peer_rib, Some(kept_key));
    for _ in 0..4 {
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        markers += apply(&mut new_rx, &mut peer_rib, Some(kept_key));
    }
    assert!(!manager.selection_deferred(FAMILY));
    assert_eq!(markers, 1, "release sends the deferred End-of-RIB once");
    assert_eq!(
        peer_rib.into_iter().collect::<Vec<_>>(),
        [(kept_key, false)],
        "the peer converges on the live table"
    );
}

#[test]
fn private_helper_drops_rtbh_deleted_behind_a_full_writer_before_the_flap() {
    assert_deleted_exempt_leaves_helper_within_hold(false, true, 182, false);
}

#[test]
fn private_helper_drops_stale_rtbh_when_the_new_session_reuses_its_id() {
    assert_deleted_exempt_leaves_helper_within_hold(false, true, 82, false);
    assert_deleted_exempt_leaves_helper_within_hold(false, false, 82, false);
}

#[test]
fn private_helper_drops_rtbh_deleted_before_the_new_table_is_admitted() {
    assert_deleted_exempt_leaves_helper_within_hold(false, false, 182, false);
}

#[test]
fn grouped_helper_drops_rtbh_deleted_behind_a_full_writer_before_the_flap() {
    assert_deleted_exempt_leaves_helper_within_hold(true, true, 182, false);
}

#[test]
fn grouped_helper_drops_rtbh_deleted_before_the_new_table_is_admitted() {
    assert_deleted_exempt_leaves_helper_within_hold(true, false, 182, false);
}

#[test]
fn helper_drops_rtbh_aggregate_deleted_behind_a_full_writer_before_the_flap() {
    for grouped in [false, true] {
        assert_deleted_exempt_leaves_helper_within_hold(grouped, true, 182, true);
        assert_deleted_exempt_leaves_helper_within_hold(grouped, false, 182, true);
    }
}

/// The resync tick hides the dirty peers it does not attempt in a slice.
/// A receiver withheld that way has not resent its table, so it must keep
/// its carried live RTBH until it has. Two receivers reconnect behind full
/// writers; the tick resends one per slice.
#[test]
fn withheld_receiver_keeps_its_live_rtbh_until_its_table_is_resent() {
    const SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 84);
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let mut ribs = [PeerRib::new(), PeerRib::new()];
    let mut old = [
        register_peer(&mut manager, OBSERVER, 82, false, false, false),
        register_peer(&mut manager, SECOND, 84, false, false, false),
    ];
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    let key = (Prefix::V4(kept), 0);
    inject_rtbh(&mut manager, kept);
    for ((_, rx, _), rib) in old.iter_mut().zip(&mut ribs) {
        apply(rx, rib, None);
        assert!(rib.contains_key(&key));
    }
    for ((address, session), rib) in [(OBSERVER, 82), (SECOND, 84)].into_iter().zip(&mut ribs) {
        clean_end_of(&mut manager, address, session);
        for stale in rib.values_mut() {
            *stale = true;
        }
    }
    drop(old);
    let mut new = [
        register_peer(&mut manager, OBSERVER, 182, false, true, false),
        register_peer(&mut manager, SECOND, 184, false, true, false),
    ];
    for (_, _, occupied) in &mut new {
        occupied.clear();
    }
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        for ((_, rx, _), rib) in new.iter_mut().zip(&mut ribs) {
            apply(rx, rib, Some(key));
        }
    }
    for rib in &ribs {
        assert_eq!(
            rib.get(&key),
            Some(&false),
            "each receiver re-sent the live RTBH"
        );
    }
}

/// A replacement session without Add-Path re-advertises the live host as
/// path ID 0, and a withdrawal carries no path ID there: the stale key of an
/// Add-Path session must be compared as path ID 0, or its withdrawal removes
/// the live host.
#[test]
fn add_path_change_across_the_flap_keeps_the_live_rtbh() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register_peer(&mut manager, OBSERVER, 82, false, false, true);
    let mut ended = PeerRib::new();
    apply(&mut old_rx, &mut ended, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut ended, None);
    assert!(
        ended.contains_key(&(Prefix::V4(kept), 1)),
        "Add-Path rank 1"
    );
    clean_end(&mut manager, 82);
    drop(old_rx);
    let (_new_tx, mut new_rx, _) = register_peer(&mut manager, OBSERVER, 182, false, false, false);
    // The new session encodes no path IDs: every key it names is the
    // prefix's one row.
    let mut live = PeerRib::new();
    let key = (Prefix::V4(kept), 0);
    let mut announced = false;
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        while let Ok(update) = new_rx.try_recv() {
            for &(prefix, _) in &update.withdraw {
                live.remove(&(prefix, 0));
            }
            for route in update.announce.iter() {
                live.insert((route.prefix, 0), false);
            }
            announced |= live.contains_key(&key);
            assert!(
                !announced || live.contains_key(&key),
                "the re-sent live host is never withdrawn"
            );
        }
    }
    assert!(announced);
}

/// The peer's permit-all Address Prefix ORF, which lifts the initial gate.
fn permit_all_orf(manager: &mut RibManager, session_id: u64) {
    use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfMatch, WhenToRefresh};
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PeerOrfUpdate {
        peer: peer_v4(OBSERVER),
        session_id,
        afi: FAMILY.0,
        safi: FAMILY.1,
        when: WhenToRefresh::Immediate,
        entries: vec![AddressPrefixOrf {
            action: OrfAction::Add,
            match_: OrfMatch::Permit,
            sequence: 1,
            min_len: 0,
            max_len: 32,
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
        }],
        reply,
    });
    response.try_recv().unwrap().unwrap();
}

/// An ORF-gated reconnect registers clean but holds its initial table until
/// the peer sends its ORF, so it keeps the carried live RTBH until then.
#[test]
fn orf_gated_reconnect_keeps_its_live_rtbh_until_the_initial_table() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) =
        register_with(&mut manager, OBSERVER, 82, false, false, false, true);
    permit_all_orf(&mut manager, 82);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    let key = (Prefix::V4(kept), 0);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    assert!(rib.contains_key(&key));
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    let (_new_tx, mut new_rx, _) =
        register_with(&mut manager, OBSERVER, 182, false, false, false, true);
    assert!(!manager.dirty_peers.contains(&peer_v4(OBSERVER)));
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        apply(&mut new_rx, &mut rib, Some(key));
    }
    assert_eq!(
        rib.get(&key),
        Some(&true),
        "still the stale row, never withdrawn"
    );
    permit_all_orf(&mut manager, 182);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        apply(&mut new_rx, &mut rib, Some(key));
    }
    assert_eq!(
        rib.get(&key),
        Some(&false),
        "the ORF lifts the gate and re-sends it"
    );
}

/// The stale RTBH `rtbh` must leave the peer inside the hold once the new
/// session `session` (on `rx`) has been driven by the resync timer, while
/// the live `kept` RTBH never leaves.
fn assert_withdrawn_inside_hold(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rib: &mut PeerRib,
    rtbh: Ipv4Prefix,
    kept: Ipv4Prefix,
) {
    let kept_key = (Prefix::V4(kept), 0);
    let mut markers = 0;
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        markers += apply(rx, rib, Some(kept_key));
    }
    assert!(manager.selection_deferred(FAMILY), "still inside the hold");
    assert_eq!(markers, 0, "End-of-RIB stays deferred until release");
    assert!(
        !rib.contains_key(&(Prefix::V4(rtbh), 0)),
        "the deleted RTBH leaves the helper inside the hold; peer {rib:?}"
    );
    assert_eq!(rib.get(&kept_key), Some(&false), "the live RTBH is re-sent");
}

/// A queued withdrawal is not a delivered one: a session that ends before
/// the peer reads its queue leaves the deleted RTBH stale at the helper,
/// while the Adj-RIB-Out no longer names it. Red proof: without the hold's
/// queued-withdrawal ledger the RTBH stays until release.
#[test]
fn queued_rtbh_withdrawal_dropped_at_session_end_is_resent() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    // The withdrawal is queued, and the session ends before the peer reads it.
    delete(&mut manager, rtbh);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    assert!(rib.contains_key(&(Prefix::V4(rtbh), 0)));
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, false, false);
    assert_withdrawn_inside_hold(&mut manager, &mut new_rx, &mut rib, rtbh, kept);
}

/// A private receiver holds an ordinary route; an RTBH over the same key is
/// committed to its Adj-RIB-Out but still queued when the session ends, so
/// the helper keeps the ordinary row stale while the RTBH key is carried.
/// The RTBH is then deleted and the ordinary route is desired again but
/// held: the stale row is the right one and stays. Red proof: without the
/// desired-prefix check the flush withdraws it.
#[test]
fn private_helper_keeps_its_stale_ordinary_row_under_a_dropped_rtbh() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let key = (Prefix::V4(prefix), 0);
    announce(&mut manager, [prefix]);
    apply(&mut old_rx, &mut rib, None);
    assert!(rib.contains_key(&key), "the ordinary row reaches the peer");
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    // Queued over the ordinary row, never read: the session ends first.
    inject_rtbh(&mut manager, prefix);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    assert!(
        manager
            .helper_stale_exempt
            .get(&peer_v4(OBSERVER))
            .is_some_and(|carried| carried.keys.contains(&key)),
        "the queued RTBH's key is carried"
    );
    delete(&mut manager, prefix);
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, false, false);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        apply(&mut new_rx, &mut rib, Some(key));
    }
    assert!(manager.selection_deferred(FAMILY), "still inside the hold");
    assert_eq!(
        rib.get(&key),
        Some(&true),
        "the helper keeps its stale ordinary row until release"
    );
}

/// The transport closes the channel before the RIB learns the session
/// ended. A grouped receiver's withdrawal then fails on the closed writer,
/// and the group table no longer names the RTBH. Red proof: without the
/// group's hold ledger the RTBH stays until release.
#[test]
fn grouped_rtbh_withdrawn_in_the_closed_channel_window_is_resent() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, true, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    clean_end(&mut manager, 82);
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, true, false);
    assert_withdrawn_inside_hold(&mut manager, &mut new_rx, &mut rib, rtbh, kept);
}

/// A replacement session can register before the RIB learns that the
/// previous one ended; that ending is then discarded as superseded. Red
/// proof: without the carry on the replacement path the RTBH stays.
#[test]
fn replacement_session_carries_the_superseded_sessions_stale_rtbh() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    let occupied: Vec<_> = std::iter::from_fn(|| old_tx.clone().try_reserve_owned().ok()).collect();
    delete(&mut manager, rtbh);
    drop(occupied);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, false, false);
    // The ended session's own teardown arrives late and is discarded.
    clean_end(&mut manager, 82);
    assert_withdrawn_inside_hold(&mut manager, &mut new_rx, &mut rib, rtbh, kept);
}

type TwoFamilyFlap = (
    RibManager,
    PeerRib,
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
    Ipv4Prefix,
    (Prefix, u32),
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
);

/// A private receiver with IPv4 and IPv6 whose IPv4 initial table an ORF
/// gate holds: a host RTBH in each family, a clean flap toward a GR helper,
/// the IPv6 RTBH deleted (and the IPv4 one when `delete_v4`), then the new
/// session session 182 driven by the resync timer.
#[expect(
    clippy::too_many_lines,
    reason = "one two-family transcript arms the hold and flaps the session"
)]
fn two_family_orf_flap(delete_v4: bool) -> TwoFamilyFlap {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY, V6],
            }],
        });
    let source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let register_both = |manager: &mut RibManager, session_id: u64| {
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: observer,
            session_id,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: vec![FAMILY, V6],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        let (tx, rx) = mpsc::channel(64);
        let mut up = super::lifecycle::test_peer_up(observer, session_id, tx.clone());
        if let RibUpdate::PeerUp {
            sendable_families,
            export_policy,
            negotiated_orf_recv,
            ..
        } = &mut up
        {
            *sendable_families = vec![FAMILY, V6];
            *export_policy = Some(private_policy(None));
            *negotiated_orf_recv = vec![FAMILY];
        }
        manager.handle_update(up);
        (tx, rx)
    };
    let (_old_tx, mut old_rx) = register_both(&mut manager, 82);
    permit_all_orf(&mut manager, 82);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    // The waiter establishes for both families, which arms the hold.
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY, V6],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (waiter_tx, waiter_rx) = mpsc::channel(64);
    let mut waiter_up = super::lifecycle::test_peer_up(peer_v4(WAITER), 83, waiter_tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut waiter_up
    {
        *sendable_families = vec![FAMILY, V6];
    }
    manager.handle_update(waiter_up);
    assert!(manager.selection_deferred(FAMILY) && manager.selection_deferred(V6));
    let v4 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let mut v6 = make_route(v4, SOURCE);
    set_peer(&mut v6, crate::PeerId::LOCAL);
    v6.origin_type = crate::route::RouteOrigin::Local;
    v6.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:1::2".parse().unwrap(), 128));
    v6.next_hop = "2001:db8::81".parse().unwrap();
    let v6_key = (v6.prefix, 0);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route: v6, reply });
    result.try_recv().unwrap().unwrap();
    inject_rtbh(&mut manager, v4);
    apply(&mut old_rx, &mut rib, None);
    assert!(rib.contains_key(&v6_key) && rib.contains_key(&(Prefix::V4(v4), 0)));
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: v6_key.0,
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(result.try_recv().unwrap().unwrap().removed);
    if delete_v4 {
        delete(&mut manager, v4);
    }
    let keep = (!delete_v4).then_some((Prefix::V4(v4), 0));
    let (new_tx, mut new_rx) = register_both(&mut manager, 182);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        apply(&mut new_rx, &mut rib, keep);
    }
    (
        manager,
        rib,
        new_tx,
        new_rx,
        v4,
        v6_key,
        vec![source, waiter_rx],
    )
}

/// An ORF gate holds only its own family's initial table: the other
/// family's carried keys are withdrawn, and the gated family's wait in the
/// carried set until the peer's ORF lifts the gate.
#[test]
fn orf_gate_holds_back_only_its_own_family() {
    let (manager, rib, _new_tx, _new_rx, v4, v6_key, _peers) = two_family_orf_flap(false);
    let observer = peer_v4(OBSERVER);
    assert!(
        !rib.contains_key(&v6_key),
        "the ungated family's deleted RTBH leaves inside the hold; peer {rib:?}"
    );
    assert_eq!(
        rib.get(&(Prefix::V4(v4), 0)),
        Some(&true),
        "the gated family's live RTBH stays stale until its table"
    );
    assert!(
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.keys.contains(&(Prefix::V4(v4), 0))),
        "the gated family's key waits in the carried set"
    );
}

fn announce(manager: &mut RibManager, prefixes: impl IntoIterator<Item = Ipv4Prefix>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: u64::from(SOURCE.octets()[3]),
        announced: prefixes
            .into_iter()
            .map(|prefix| make_route_with_lp(prefix, SOURCE, 100))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn host(block: u8, index: usize) -> Ipv4Prefix {
    let [high, low] = u16::try_from(index).unwrap().to_be_bytes();
    Ipv4Prefix::new(Ipv4Addr::new(10, block, high, low), 32)
}

/// `8 * size` deleted RTBH keys wait at a helper because each prefix still
/// has an ordinary route the hold defers; then `size` updates change other
/// prefixes. A settled set is re-checked only for the prefixes a pass
/// changed, so the flush work grows with keys plus passes, not their
/// product.
fn settled_helper_flush(size: usize) -> super::work_scaling::Work {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 4096, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    let keys = 8 * size;
    announce(&mut manager, (0..keys).map(|index| host(1, index)));
    let mut peer_rib = PeerRib::new();
    for index in 0..keys {
        inject_rtbh(&mut manager, host(1, index));
        apply(&mut old_rx, &mut peer_rib, None);
    }
    assert_eq!(peer_rib.len(), keys, "setup, size {size}");
    clean_end(&mut manager, 82);
    drop(old_rx);
    for index in 0..keys {
        delete(&mut manager, host(1, index));
    }
    let work = super::work_scaling::checkpoints_in(|| {
        let (_new_tx, mut new_rx, _) = register(&mut manager, 182, false, false);
        for index in 0..size {
            announce(&mut manager, [host(2, index)]);
            manager.resync_dirty_peers_bounded();
        }
        apply(&mut new_rx, &mut peer_rib, None);
    });
    assert!(manager.selection_deferred(FAMILY));
    assert_eq!(
        manager.helper_stale_exempt[&peer_v4(OBSERVER)].keys.len(),
        keys,
        "every key still waits for its prefix's ordinary route, size {size}"
    );
    work
}

#[test]
fn settled_helper_flush_work_is_linear() {
    super::work_scaling::assert_linear(
        "settled helper stale flush",
        &["helper_stale_exempt"],
        settled_helper_flush,
    );
}

/// Fill a session's writer; dropping the permits frees it.
fn occupy(tx: &mpsc::Sender<OutboundRouteUpdate>) -> Vec<mpsc::OwnedPermit<OutboundRouteUpdate>> {
    std::iter::from_fn(|| tx.clone().try_reserve_owned().ok()).collect()
}

fn withdraw_received(manager: &mut RibManager, prefix: Ipv4Prefix) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: u64::from(SOURCE.octets()[3]),
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// The resync timer as the actor runs it: one tick per arm, re-armed only
/// while it reports pending work. The stale RTBH `rtbh` must then be gone
/// inside the hold, with `kept` never absent.
fn assert_timer_withdraws(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rib: &mut PeerRib,
    rtbh: Ipv4Prefix,
    kept: Option<Ipv4Prefix>,
) {
    let keep = kept.map(|kept| (Prefix::V4(kept), 0));
    apply(rx, rib, keep);
    for _ in 0..8 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        apply(rx, rib, keep);
    }
    assert!(
        manager.selection_convergence_held(FAMILY),
        "our End-of-RIB is still held"
    );
    assert!(
        !rib.contains_key(&(Prefix::V4(rtbh), 0)),
        "the deleted RTBH leaves the helper inside the hold; peer {rib:?}"
    );
    if let Some(keep) = keep {
        assert_eq!(rib.get(&keep), Some(&false), "the live RTBH is re-sent");
    }
}

/// A private receiver whose carried RTBH key waits because a received
/// ordinary route the hold defers still covers its prefix; the set is
/// settled. Returns the live RTBH kept on the wire.
fn settled_waiting_key() -> (
    RibManager,
    PeerRib,
    Session,
    Ipv4Prefix,
    Ipv4Prefix,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let mut manager = manager_with_dormant_waiter();
    let source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    announce(&mut manager, [rtbh]);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let mut session = register(&mut manager, 182, false, false);
    assert_timer_withdraws_nothing(&mut manager, &mut session.1, &mut rib, kept);
    let key = (Prefix::V4(rtbh), 0);
    assert!(
        manager
            .helper_stale_exempt
            .get(&peer_v4(OBSERVER))
            .is_some_and(|carried| carried.settled && carried.keys.contains(&key)),
        "the key waits in a settled set"
    );
    assert_eq!(
        rib.get(&key),
        Some(&true),
        "the helper still holds it stale"
    );
    (manager, rib, session, rtbh, kept, vec![source, waiter])
}

fn assert_timer_withdraws_nothing(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rib: &mut PeerRib,
    kept: Ipv4Prefix,
) {
    let keep = Some((Prefix::V4(kept), 0));
    apply(rx, rib, keep);
    for _ in 0..8 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        apply(rx, rib, keep);
    }
}

/// A settled key becomes withdrawable while the writer is full. Red proof:
/// leaving the set settled on a full send strands the key until release.
#[test]
fn full_writer_unsettles_a_withdrawable_carried_key() {
    let (mut manager, mut rib, (tx, mut rx, _), rtbh, kept, _peers) = settled_waiting_key();
    let occupied = occupy(&tx);
    withdraw_received(&mut manager, rtbh);
    drop(occupied);
    assert_timer_withdraws(&mut manager, &mut rx, &mut rib, rtbh, Some(kept));
}

/// A settled key's last covering route goes while its receiver is dirty
/// and not caught up, so the flush skips it. Red proof: without unsettling
/// the skipped set, the recovered session never re-checks the key.
#[test]
fn skipped_dirty_receiver_rechecks_its_settled_key() {
    let (mut manager, mut rib, (tx, mut rx, _), rtbh, kept, _peers) = settled_waiting_key();
    let occupied = occupy(&tx);
    // A new live RTBH queues behind the full writer and leaves the
    // receiver dirty.
    let fresh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 4), 32);
    inject_rtbh(&mut manager, fresh);
    assert!(manager.dirty_peers.contains(&peer_v4(OBSERVER)));
    withdraw_received(&mut manager, rtbh);
    drop(occupied);
    assert_timer_withdraws(&mut manager, &mut rx, &mut rib, rtbh, Some(kept));
    assert_eq!(rib.get(&(Prefix::V4(fresh), 0)), Some(&false));
}

/// A reconnected session queues the helper withdrawal and ends again before
/// the peer reads it; its Adj-RIB-Out never held the row. Red proof:
/// without recording the flush's withdrawal in the hold ledger the third
/// session never withdraws it.
#[test]
fn helper_withdrawal_dropped_by_a_second_flap_is_resent() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_second_tx, second_rx, _) = register(&mut manager, 182, false, false);
    manager.resync_dirty_peers_bounded();
    assert!(
        !manager.helper_stale_exempt.contains_key(&peer_v4(OBSERVER)),
        "the second session queued the withdrawal"
    );
    // The peer never reads the second session's queue.
    clean_end(&mut manager, 182);
    drop(second_rx);
    assert!(rib.contains_key(&(Prefix::V4(rtbh), 0)));
    let (_third_tx, mut third_rx, _) = register(&mut manager, 283, false, false);
    assert_timer_withdraws(&mut manager, &mut third_rx, &mut rib, rtbh, Some(kept));
}

/// The ORF gate the last waiting key held on opens while the writer is
/// full; the resync timer catches the receiver up and must still flush.
/// Red proof: without the released ORF wait in the timer's pending check
/// the timer stops and the deleted RTBH stays until release.
#[test]
fn orf_opened_behind_a_full_writer_keeps_the_timer_armed() {
    let (mut manager, mut rib, new_tx, mut new_rx, v4, v6_key, _peers) = two_family_orf_flap(true);
    assert!(!rib.contains_key(&v6_key));
    assert!(
        manager
            .helper_stale_exempt
            .get(&peer_v4(OBSERVER))
            .is_some_and(|carried| carried.settled && !carried.orf_blocked.is_empty()),
        "the gated key waits in a settled set"
    );
    let occupied = occupy(&new_tx);
    permit_all_orf(&mut manager, 182);
    drop(occupied);
    assert_timer_withdraws(&mut manager, &mut new_rx, &mut rib, v4, None);
}

/// The transport closes a grouped receiver's channel before the RIB learns
/// its session ended, so the group's RTBH withdrawal fails on the closed
/// writer and only the group's hold ledger names it. A new export policy
/// then moves the receiver to another group before the session end
/// arrives, and the new group's table never held the row. Red proof:
/// without handing the departing group's ledger to the peer, the deleted
/// RTBH stays until release.
#[test]
fn group_ledger_follows_a_receiver_into_another_group() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, true, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let first = manager.grouped_member_of(observer);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: observer,
        export_policy: Some(super::update_groups::community_chain(0xFC00_0001)),
        reply,
    });
    response.try_recv().unwrap().unwrap();
    let second = manager.grouped_member_of(observer);
    assert!(
        second.is_some() && second != first,
        "moved to another group"
    );
    clean_end(&mut manager, 82);
    assert!(rib.contains_key(&(Prefix::V4(rtbh), 0)));
    let (_new_tx, mut new_rx, _) = register_peer(&mut manager, OBSERVER, 182, true, false, false);
    assert_timer_withdraws(&mut manager, &mut new_rx, &mut rib, rtbh, Some(kept));
}

/// Collecting the carry visits every local provenance entry of the ended
/// session's table, ordinary ones included, under a readiness checkpoint.
/// Red proof: checkpointing only the exempt entries counts none here.
#[test]
fn carry_collection_checkpoints_every_provenance_entry() {
    const AGGREGATES: usize = 48;
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    // Ordinary aggregates admitted before the hold sit in the Adj-RIB-Out
    // with local provenance; none is exempt.
    for index in 0..AGGREGATES {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 9, u8::try_from(index).unwrap(), 0), 24);
        let mut route = make_route(prefix, SOURCE);
        set_peer(&mut route, crate::PeerId::LOCAL);
        route.origin_type = crate::route::RouteOrigin::Local;
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
        apply(&mut old_rx, &mut rib, None);
    }
    assert_eq!(rib.len(), AGGREGATES);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    let work = super::work_scaling::checkpoints_in(|| clean_end(&mut manager, 82));
    assert!(
        work.get("helper_stale_carry").copied().unwrap_or(0) >= AGGREGATES,
        "every provenance entry is checkpointed: {work:?}"
    );
}

/// A full set takes no more keys, but a key it already holds never costs a
/// new one its place. Red proof: counting incoming keys against the room
/// left drops the new key behind a duplicate.
#[test]
fn bounded_insert_skips_duplicates_before_the_limit() {
    let key = |index: usize| {
        let [a, b, c, d] = u32::try_from(index).unwrap().to_be_bytes();
        (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), 32)),
            0,
        )
    };
    let limit = super::HELPER_STALE_EXEMPT_LIMIT;
    let mut set: std::collections::BTreeSet<_> = (0..limit - 1).map(key).collect();
    super::peer_lifecycle::insert_bounded(&mut set, [key(0), key(limit)], &mut || {});
    assert!(set.contains(&key(limit)), "the new key is kept");
    assert_eq!(set.len(), limit);
    super::peer_lifecycle::insert_bounded(&mut set, [key(limit + 1)], &mut || {});
    assert_eq!(set.len(), limit, "a full set takes no more");
}

/// Collision failback stages selection while the gate deferring our
/// End-of-RIB still waits for the surviving session's route refresh. A
/// reconnected helper whose writer frees then must still withdraw the
/// carried deleted RTBH. Red proof: retiring keys once selection stops
/// being deferred drops it.
#[test]
fn staged_selection_still_withdraws_a_carried_rtbh() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_new_tx, mut new_rx, occupied) = register(&mut manager, 182, false, true);
    let metrics = BgpMetrics::new();
    let waiter = peer_v4(WAITER);
    let session = u64::from(WAITER.octets()[3]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        selection.session_down(waiter, session, &metrics);
        selection
            .await_collision_failback_refresh(
                waiter,
                session,
                false,
                &std::collections::HashSet::from([FAMILY]),
                true,
                &metrics,
            )
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");
    assert!(
        !manager.selection_deferred(FAMILY) && manager.selection_convergence_held(FAMILY),
        "selection staged, End-of-RIB still held"
    );
    drop(occupied);
    assert_timer_withdraws(&mut manager, &mut new_rx, &mut rib, rtbh, Some(kept));
}

/// Before any hold arms, a helper teardown carries its exempt keys, and the
/// carry retires once the next session has sent its table, End-of-RIB
/// included, still outside a hold. Red proof: without retiring a synced
/// session's carry outside the hold it outlives the session's End-of-RIB.
#[test]
fn pre_hold_carry_retires_once_the_next_session_is_synced() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_rtbh(&mut manager, rtbh);
    apply(&mut old_rx, &mut rib, None);
    assert!(!manager.selection_deferred(FAMILY), "no hold has armed");
    clean_end(&mut manager, 82);
    drop(old_rx);
    assert!(
        manager.helper_stale_exempt.contains_key(&observer),
        "a helper teardown before the hold carries its exempt keys"
    );
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, false, false);
    let markers = apply(&mut new_rx, &mut rib, Some((Prefix::V4(rtbh), 0)));
    assert_eq!(markers, 1, "the new session's End-of-RIB is sent");
    // The resync timer, armed while it reports work.
    for _ in 0..4 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
    }
    assert!(!manager.resync_tick_pending(), "no work is left to spin on");
    assert!(
        !manager.helper_stale_exempt.contains_key(&observer),
        "the carry retires once the new session is synced"
    );
}

/// Without selection deferral no hold can defer our End-of-RIB, so a
/// helper teardown builds no carry.
#[test]
fn helper_teardown_without_selection_deferral_carries_nothing() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    inject_rtbh(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    apply(&mut old_rx, &mut rib, None);
    clean_end(&mut manager, 82);
    assert!(manager.helper_stale_exempt.is_empty());
}

/// When a GR helper flaps relative to a selection hold while replay grace
/// holds our End-of-RIB toward it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GraceFlap {
    /// Before the hold arms; the RTBH is deleted while the session is down.
    BeforeHold,
    /// Inside the hold, its new table behind a full writer until after the
    /// hold releases; the RTBH is deleted in the hold.
    InHoldReleasedEarly,
    /// After the hold released, still inside grace; the RTBH is deleted
    /// while the session is down.
    AfterRelease,
    /// [`Self::AfterRelease`], but the RTBH's withdrawal is queued before
    /// the flap and the RTBH injected again: the P1 pin for a ledger key in
    /// grace.
    AfterReleaseReinjected,
}

/// A selection hold and a replay grace window on the helper receiver,
/// whose deadline outlasts the hold. Returns the manager, the peer view,
/// the new session's receiver, the RTBH and live RTBH, the grace deadline
/// and the receivers that must stay open.
fn grace_flap(
    shape: GraceFlap,
) -> (
    RibManager,
    PeerRib,
    mpsc::Receiver<OutboundRouteUpdate>,
    Ipv4Prefix,
    Ipv4Prefix,
    tokio::time::Instant,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let (_tx, rx) = mpsc::channel(16);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(600),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        })
        .with_eor_grace(crate::EorGraceConfig {
            peers: vec![crate::EorGracePeerConfig {
                peer: peer_v4(OBSERVER).into(),
                deadline,
                families: vec![FAMILY],
            }],
            replay_owners: vec![],
        });
    let source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    let mut peers = vec![source];
    let release = |manager: &mut RibManager| {
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: u64::from(WAITER.octets()[3]),
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        assert!(
            !manager.selection_convergence_held(FAMILY),
            "the hold released"
        );
    };
    if shape != GraceFlap::BeforeHold {
        peers.push(connect(&mut manager, WAITER, 64, true, false));
    }
    if matches!(
        shape,
        GraceFlap::AfterRelease | GraceFlap::AfterReleaseReinjected
    ) {
        release(&mut manager);
    }
    if shape == GraceFlap::AfterReleaseReinjected {
        // Queued to the ending session, never read, then injected again.
        delete(&mut manager, rtbh);
        inject_rtbh(&mut manager, rtbh);
    }
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    if matches!(shape, GraceFlap::BeforeHold | GraceFlap::AfterRelease) {
        delete(&mut manager, rtbh);
    }
    let full = shape == GraceFlap::InHoldReleasedEarly;
    let (_new_tx, new_rx, occupied) = register(&mut manager, 182, false, full);
    if full {
        delete(&mut manager, rtbh);
        release(&mut manager);
        drop(occupied);
    }
    (manager, rib, new_rx, rtbh, kept, deadline, peers)
}

/// Drive the resync timer as the actor does, applying every update with
/// `keep` on the wire throughout; returns the End-of-RIB markers seen.
fn run_timer(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rib: &mut PeerRib,
    keep: Option<(Prefix, u32)>,
) -> usize {
    let mut markers = apply(rx, rib, keep);
    for _ in 0..8 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        markers += apply(rx, rib, keep);
    }
    assert!(!manager.resync_tick_pending(), "the timer goes idle");
    markers
}

/// The deleted RTBH leaves the helper while replay grace still holds our
/// End-of-RIB, and the carry retires at grace end.
fn assert_withdrawn_under_grace(shape: GraceFlap) {
    let (mut manager, mut rib, mut rx, rtbh, kept, deadline, _peers) = grace_flap(shape);
    let keep = Some((Prefix::V4(kept), 0));
    let markers = run_timer(&mut manager, &mut rx, &mut rib, keep);
    assert_eq!(markers, 0, "replay grace still holds the End-of-RIB");
    assert!(
        !rib.contains_key(&(Prefix::V4(rtbh), 0)),
        "the deleted RTBH leaves while grace holds our End-of-RIB; peer {rib:?}"
    );
    assert_eq!(rib.get(&(Prefix::V4(kept), 0)), Some(&false));
    manager.expire_eor_grace(deadline);
    assert_eq!(apply(&mut rx, &mut rib, keep), 1, "grace end sends it");
    assert!(
        manager.helper_stale_exempt.is_empty(),
        "the carry is retired"
    );
    // Ledgers outlive grace only while a selection gate can still arm.
    let selection_may_hold = manager
        .selection_deferral
        .as_ref()
        .is_some_and(super::super::selection_deferral::SelectionDeferral::may_hold);
    assert_eq!(shape == GraceFlap::BeforeHold, selection_may_hold);
    assert!(selection_may_hold || manager.hold_exempt_withdrawn.is_empty());
}

/// Before any hold arms. Red proof: withdrawing only while a selection
/// gate holds leaves the RTBH until grace ends.
#[test]
fn grace_held_end_of_rib_withdraws_a_stale_rtbh_before_any_hold() {
    assert_withdrawn_under_grace(GraceFlap::BeforeHold);
}

/// The hold releases before the new session catches up. Red proof: retiring
/// carries at selection release leaves the RTBH until grace ends.
#[test]
fn grace_outlasting_the_hold_keeps_the_carry() {
    assert_withdrawn_under_grace(GraceFlap::InHoldReleasedEarly);
}

/// A flap after the hold released, inside grace. Red proof: carrying only
/// while selection may hold builds nothing, and the RTBH stays.
#[test]
fn flap_after_release_within_grace_withdraws_a_stale_rtbh() {
    assert_withdrawn_under_grace(GraceFlap::AfterRelease);
}

/// A ledger key from before a flap in grace whose RTBH is live again stays
/// on the wire.
#[test]
fn grace_ledger_key_of_a_reinjected_rtbh_keeps_it_live() {
    let (mut manager, mut rib, mut rx, rtbh, _kept, deadline, _peers) =
        grace_flap(GraceFlap::AfterReleaseReinjected);
    let key = (Prefix::V4(rtbh), 0);
    run_timer(&mut manager, &mut rx, &mut rib, Some(key));
    assert_eq!(rib.get(&key), Some(&false), "the live RTBH is re-sent");
    manager.expire_eor_grace(deadline);
    apply(&mut rx, &mut rib, Some(key));
    assert_eq!(rib.get(&key), Some(&false));
}

/// A peer that never returns leaves its carry and ledger behind; grace end,
/// with the hold already released, retires them. Red proof: without
/// retiring at the grace release they stay.
#[test]
fn grace_expiry_retires_a_carry_whose_peer_never_returns() {
    let (_tx, rx) = mpsc::channel(16);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_eor_grace(crate::EorGraceConfig {
            peers: vec![crate::EorGracePeerConfig {
                peer: peer_v4(OBSERVER).into(),
                deadline,
                families: vec![FAMILY],
            }],
            replay_owners: vec![],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32),
    );
    apply(&mut old_rx, &mut rib, None);
    // A withdrawal queued in grace is in the receiver's ledger.
    delete(&mut manager, rtbh);
    assert!(
        !manager.hold_exempt_withdrawn.is_empty(),
        "a ledger is recorded"
    );
    clean_end(&mut manager, 82);
    assert!(manager.helper_stale_exempt.contains_key(&observer));
    manager.expire_eor_grace(deadline);
    assert!(manager.helper_stale_exempt.is_empty(), "the carry retires");
    assert!(manager.hold_exempt_withdrawn.is_empty(), "and every ledger");
}

/// With selection released and grace ended, nothing can hold our
/// End-of-RIB: a helper teardown carries nothing and never enters the
/// carry collection. Red proof: carrying while any grace was configured
/// walks the table and keeps a carry.
#[test]
fn helper_teardown_after_release_and_grace_carries_nothing() {
    let (mut manager, mut rib, mut rx, _rtbh, kept, deadline, _peers) =
        grace_flap(GraceFlap::AfterRelease);
    run_timer(&mut manager, &mut rx, &mut rib, Some((Prefix::V4(kept), 0)));
    manager.expire_eor_grace(deadline);
    apply(&mut rx, &mut rib, None);
    assert!(manager.helper_stale_exempt.is_empty());
    let work = super::work_scaling::checkpoints_in(|| clean_end(&mut manager, 182));
    assert_eq!(
        work.get("helper_stale_carry"),
        None,
        "no carry collection: {work:?}"
    );
    assert!(manager.helper_stale_exempt.is_empty());
    assert!(manager.hold_exempt_withdrawn.is_empty());
}

/// When the RTBH is deleted around a flap before the hold arms.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreHoldDelete {
    /// Inside the hold, after the flap.
    InHold,
    /// Before the flap: the withdrawal is queued and the session end drops
    /// it.
    Queued,
    /// Before the flap, after the transport closed the channel: the send
    /// fails and only the hold ledger names the row.
    ClosedChannel,
    /// Queued before the flap and then injected again, so the ledger names
    /// a key whose RTBH is live: the P1 pin for ledger keys from before the
    /// hold.
    QueuedThenReinjected,
}

/// A helper flaps before any hold arms and its next registration defers
/// behind queued actor work, the production path for a session whose
/// table is not yet sent when a waiter arms the hold. The deferred dump in
/// the hold re-sends only exempt rows, so the stale RTBH must be withdrawn
/// from the carry.
fn pre_hold_flap_into_deferred_registration(grouped: bool, deleted: PreHoldDelete) {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        });
    let observer = peer_v4(OBSERVER);
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, grouped, false);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    match deleted {
        PreHoldDelete::InHold => {}
        PreHoldDelete::Queued => delete(&mut manager, rtbh),
        PreHoldDelete::ClosedChannel => {
            old_rx.close();
            delete(&mut manager, rtbh);
        }
        PreHoldDelete::QueuedThenReinjected => {
            delete(&mut manager, rtbh);
            assert!(
                manager
                    .hold_exempt_withdrawn
                    .get(&super::super::HoldWithdrawOwner::Peer(observer))
                    .is_some_and(|ledger| ledger.contains(&(Prefix::V4(rtbh), 0))),
                "the queued withdrawal is in the ledger"
            );
            inject_rtbh(&mut manager, rtbh);
        }
    }
    assert!(!manager.selection_deferred(FAMILY), "no hold has armed");
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    // Queued actor work defers an expensive initial dump to the run loop.
    manager.initial_dump_defer_min_routes = 0;
    let (reply, _queued) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let (_new_tx, mut new_rx, _) = register(&mut manager, 182, grouped, false);
    assert!(manager.pending_initial_registrations.contains(&observer));
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(
        manager.selection_deferred(FAMILY),
        "the waiter arms the hold"
    );
    if deleted == PreHoldDelete::InHold {
        delete(&mut manager, rtbh);
    }
    for _ in 0..4 {
        if manager.pending_initial_registrations.is_empty() {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.pending_initial_registrations.is_empty());
    assert_eq!(manager.grouped_member_of(observer).is_some(), grouped);
    if deleted == PreHoldDelete::QueuedThenReinjected {
        // The live RTBH is never withdrawn, even briefly.
        let key = (Prefix::V4(rtbh), 0);
        apply(&mut new_rx, &mut rib, Some(key));
        for _ in 0..8 {
            if !manager.resync_tick_pending() {
                break;
            }
            manager.resync_dirty_peers_bounded();
            apply(&mut new_rx, &mut rib, Some(key));
        }
        assert!(manager.selection_convergence_held(FAMILY));
        assert_eq!(rib.get(&key), Some(&false), "the live RTBH is re-sent");
        return;
    }
    assert_timer_withdraws(&mut manager, &mut new_rx, &mut rib, rtbh, Some(kept));
}

/// Red proof: carrying only inside a hold leaves the RTBH stale.
#[test]
fn deferred_registration_into_the_hold_withdraws_a_pre_hold_stale_rtbh() {
    for grouped in [false, true] {
        pre_hold_flap_into_deferred_registration(grouped, PreHoldDelete::InHold);
    }
}

/// Red proof: recording queued exempt withdrawals only inside a hold drops
/// this one, and the RTBH stays stale.
#[test]
fn pre_hold_queued_rtbh_withdrawal_dropped_at_session_end_is_resent() {
    for grouped in [false, true] {
        pre_hold_flap_into_deferred_registration(grouped, PreHoldDelete::Queued);
    }
}

/// A ledger key recorded before the hold whose RTBH is injected again
/// stays on the wire.
#[test]
fn pre_hold_ledger_key_of_a_reinjected_rtbh_keeps_it_live() {
    for grouped in [false, true] {
        pre_hold_flap_into_deferred_registration(grouped, PreHoldDelete::QueuedThenReinjected);
    }
}

/// Red proof: recording a group's exempt withdrawals only inside a hold
/// drops one that failed on a closed channel before the hold armed.
#[test]
fn pre_hold_grouped_rtbh_withdrawn_in_the_closed_channel_window_is_resent() {
    pre_hold_flap_into_deferred_registration(true, PreHoldDelete::ClosedChannel);
}

/// A peer that never returns leaves its carry behind; when the deadline
/// releases families that never armed, no completion runs. Red proof:
/// without retiring after the timer's transitions, the carry stays.
#[test]
fn deadline_release_retires_a_carry_whose_peer_never_returns() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    inject_rtbh(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    apply(&mut old_rx, &mut rib, None);
    // A second receiver stays up; a withdrawal queued to it before the hold
    // is in its ledger.
    let (_other_tx, mut other_rx, _) = register_peer(
        &mut manager,
        Ipv4Addr::new(192, 0, 2, 85),
        85,
        false,
        false,
        false,
    );
    let other_rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 9), 32);
    inject_rtbh(&mut manager, other_rtbh);
    delete(&mut manager, other_rtbh);
    while other_rx.try_recv().is_ok() {}
    assert!(
        !manager.hold_exempt_withdrawn.is_empty(),
        "a ledger is recorded"
    );
    clean_end(&mut manager, 82);
    assert!(manager.helper_stale_exempt.contains_key(&observer));
    manager.expire_selection_deferral();
    assert!(
        !manager
            .selection_deferral
            .as_ref()
            .is_some_and(super::super::selection_deferral::SelectionDeferral::may_hold),
        "every family is released"
    );
    assert!(manager.helper_stale_exempt.is_empty(), "the carry retires");
    assert!(manager.hold_exempt_withdrawn.is_empty(), "and every ledger");
}

/// Once every family is released no hold can defer our End-of-RIB again,
/// so a helper teardown carries nothing and never enters the carry
/// collection. Red proof: carrying regardless of the deferral state walks
/// the table and keeps a carry.
#[test]
fn helper_teardown_after_release_carries_nothing() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx, _) = register(&mut manager, 82, false, false);
    let mut rib = PeerRib::new();
    inject_rtbh(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    apply(&mut old_rx, &mut rib, None);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: u64::from(WAITER.octets()[3]),
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(
        !manager
            .selection_deferral
            .as_ref()
            .is_some_and(super::super::selection_deferral::SelectionDeferral::may_hold),
        "every family is released"
    );
    let work = super::work_scaling::checkpoints_in(|| clean_end(&mut manager, 82));
    assert_eq!(
        work.get("helper_stale_carry"),
        None,
        "no carry collection: {work:?}"
    );
    assert!(manager.helper_stale_exempt.is_empty());
}

/// Register the private dual-stack receiver, a GR helper for both
/// families, on a writer of `capacity` envelopes.
fn register_dual_stack(
    manager: &mut RibManager,
    session_id: u64,
    capacity: usize,
) -> (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    register_dual_stack_with(manager, session_id, capacity, false, None)
}

/// [`register_dual_stack`]; `orf_v4` negotiates Address Prefix ORF receive
/// for IPv4, which holds its initial table until the peer's ORF, and
/// `export_policy` replaces the private permit-all policy.
fn register_dual_stack_with(
    manager: &mut RibManager,
    session_id: u64,
    capacity: usize,
    orf_v4: bool,
    export: Option<rustbgpd_policy::PolicyChain>,
) -> (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    let observer = peer_v4(OBSERVER);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: observer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY, V6],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, rx) = mpsc::channel(capacity);
    let mut up = super::lifecycle::test_peer_up(observer, session_id, tx.clone());
    if let RibUpdate::PeerUp {
        sendable_families,
        export_policy,
        negotiated_orf_recv,
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, V6];
        *export_policy = Some(export.unwrap_or_else(|| private_policy(None)));
        if orf_v4 {
            *negotiated_orf_recv = vec![FAMILY];
        }
    }
    manager.handle_update(up);
    (tx, rx)
}

fn inject_v6_rtbh(manager: &mut RibManager, address: &str) -> (Prefix, u32) {
    let mut route = make_route(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 9), 32), SOURCE);
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.prefix = Prefix::V6(Ipv6Prefix::new(address.parse().unwrap(), 128));
    route.next_hop = "2001:db8::81".parse().unwrap();
    let key = (route.prefix, 0);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
    key
}

/// Establish `address` as a waiter whose OPEN lists `families`.
fn connect_waiter_for(
    manager: &mut RibManager,
    address: Ipv4Addr,
    families: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let session_id = u64::from(address.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: families.to_vec(),
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = families.to_vec();
    }
    manager.handle_update(up);
    rx
}

/// A dual-stack helper flaps before any hold arms, and replay grace holds
/// its next session's IPv4 End-of-RIB. The IPv6 waiter arms its hold while
/// the IPv4 gate stays dormant, as separate per-family sessions to one
/// upstream do. Our IPv4 End-of-RIB is held, so the deleted IPv4 RTBH
/// leaves the helper now instead of waiting for either gate. Red proof:
/// retiring every key whose selection gate is not armed drops it, and it
/// stays until grace ends.
#[test]
fn grace_held_family_withdraws_while_its_gate_is_dormant() {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    const V6_WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 86);
    let (_tx, rx) = mpsc::channel(16);
    let start = tokio::time::Instant::now();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![
                SelectionDeferralWaiterConfig {
                    peer: peer_v4(WAITER),
                    families: vec![FAMILY],
                },
                SelectionDeferralWaiterConfig {
                    peer: peer_v4(V6_WAITER),
                    families: vec![V6],
                },
            ],
        })
        .with_eor_grace(crate::EorGraceConfig {
            peers: vec![crate::EorGracePeerConfig {
                peer: peer_v4(OBSERVER).into(),
                deadline: start + Duration::from_secs(300),
                families: vec![FAMILY],
            }],
            replay_owners: vec![],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let (_old_tx, mut old_rx) = register_dual_stack(&mut manager, 82, 64);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    assert!(rib.contains_key(&(Prefix::V4(rtbh), 0)));
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_new_tx, mut new_rx) = register_dual_stack(&mut manager, 182, 64);
    let _v6_waiter = connect_waiter_for(&mut manager, V6_WAITER, &[V6]);
    assert!(manager.selection_deferred(V6) && !manager.selection_deferred(FAMILY));
    let keep = Some((Prefix::V4(kept), 0));
    let mut markers = apply(&mut new_rx, &mut rib, keep);
    for _ in 0..4 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        markers += apply(&mut new_rx, &mut rib, keep);
    }
    assert_eq!(markers, 0, "replay grace still holds the IPv4 End-of-RIB");
    assert!(
        !manager.selection_deferred(FAMILY),
        "the IPv4 gate is dormant"
    );
    assert!(
        !rib.contains_key(&(Prefix::V4(rtbh), 0)),
        "the deleted IPv4 RTBH leaves while its End-of-RIB is held; peer {rib:?}"
    );
    assert_eq!(rib.get(&(Prefix::V4(kept), 0)), Some(&false));
}

/// A registered session without an exact export encoder fails closed: its
/// carried set can never be flushed, so the resync timer must not keep
/// re-arming for it. Red proof: a runnable check that ignores the encoder
/// leaves the timer pending every tick until the hold ends.
#[test]
fn fail_closed_session_leaves_the_resync_timer_idle() {
    let (mut manager, _rib, (_tx, _rx, _), rtbh, _kept, _peers) = settled_waiting_key();
    let observer = peer_v4(OBSERVER);
    assert!(manager.selection_deferred(FAMILY));
    manager.peer_export_encoders.remove(&observer);
    // The covering route goes, and the skipped set is marked to re-walk.
    withdraw_received(&mut manager, rtbh);
    assert!(
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| !carried.settled),
        "the skipped set waits for a re-walk"
    );
    assert!(
        !manager.resync_tick_pending(),
        "nothing the timer can do for a session without an encoder"
    );
}

/// A dual-stack helper flaps while only the IPv6 gate is armed; its next
/// session's IPv4 End-of-RIB goes out at once, which purges the deleted
/// IPv4 RTBH the helper kept. The IPv4 keys retire then and nothing is
/// withdrawn for them. Red proof: retiring a dormant family's keys only at
/// its release keeps them waiting for a gate that has nothing left to do.
#[test]
fn dormant_family_keys_retire_once_its_end_of_rib_is_sent() {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    const V6_WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 86);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![
                SelectionDeferralWaiterConfig {
                    peer: peer_v4(WAITER),
                    families: vec![FAMILY],
                },
                SelectionDeferralWaiterConfig {
                    peer: peer_v4(V6_WAITER),
                    families: vec![V6],
                },
            ],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx) = register_dual_stack(&mut manager, 82, 64);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let key = (Prefix::V4(rtbh), 0);
    inject_rtbh(&mut manager, rtbh);
    apply(&mut old_rx, &mut rib, None);
    let _v6_waiter = connect_waiter_for(&mut manager, V6_WAITER, &[V6]);
    assert!(manager.selection_deferred(V6) && !manager.selection_deferred(FAMILY));
    clean_end(&mut manager, 82);
    drop(old_rx);
    assert!(
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.keys.contains(&key)),
        "the IPv4 key is carried"
    );
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_new_tx, mut new_rx) = register_dual_stack(&mut manager, 182, 64);
    let mut drain = |rib: &mut PeerRib| {
        let mut markers = 0;
        while let Ok(update) = new_rx.try_recv() {
            assert!(!update.withdraw.contains(&key), "nothing is withdrawn");
            for route in update.announce.iter() {
                rib.insert((route.prefix, route.path_id), false);
            }
            if update.end_of_rib.contains(&FAMILY) {
                markers += 1;
                rib.retain(|_, stale| !*stale);
            }
        }
        markers
    };
    let mut markers = drain(&mut rib);
    for _ in 0..4 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        markers += drain(&mut rib);
    }
    assert_eq!(
        markers, 1,
        "the IPv4 End-of-RIB goes out while IPv6 is held"
    );
    assert!(!rib.contains_key(&key), "and purges the stale RTBH");
    assert!(
        !manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.keys.contains(&key)),
        "the IPv4 key retires"
    );
    assert!(manager.selection_deferred(V6), "still inside the IPv6 hold");
}

/// A dual-stack helper whose IPv4 is ORF-gated flaps before any hold. Its
/// IPv6 keys let the next session run, so its IPv4 keys wait: our IPv4
/// End-of-RIB is deferred behind the ORF table, neither held nor sent. The
/// IPv4 waiter then arms while the ORF gate is still up, and the peer's
/// ORF lifts it. The deleted IPv4 RTBH must leave inside the hold. Red
/// proof: without re-walking a waiting family once a hold covers it, the
/// ORF lift never revisits the key and the RTBH stays until release.
#[test]
fn orf_gated_family_waits_then_withdraws_once_its_hold_arms() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx) = register_dual_stack_with(&mut manager, 82, 64, true, None);
    permit_all_orf(&mut manager, 82);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_rtbh(&mut manager, rtbh);
    let v6_key = inject_v6_rtbh(&mut manager, "2001:db8:1::2");
    apply(&mut old_rx, &mut rib, None);
    let key = (Prefix::V4(rtbh), 0);
    assert!(rib.contains_key(&key) && rib.contains_key(&v6_key));
    assert!(!manager.selection_deferred(FAMILY), "no hold has armed");
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_new_tx, mut new_rx) = register_dual_stack_with(&mut manager, 182, 64, true, None);
    run_timer(&mut manager, &mut new_rx, &mut rib, None);
    let waiting = |manager: &RibManager| {
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.settled && carried.keys.contains(&key))
    };
    assert!(
        waiting(&manager),
        "the IPv4 key waits in a settled set behind the ORF-deferred End-of-RIB"
    );
    assert!(
        rib.contains_key(&key),
        "nothing withdrawn while it is not held"
    );
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    run_timer(&mut manager, &mut new_rx, &mut rib, None);
    assert!(waiting(&manager), "arming the hold does not touch the key");
    permit_all_orf(&mut manager, 182);
    run_timer(&mut manager, &mut new_rx, &mut rib, None);
    assert!(
        manager.selection_convergence_held(FAMILY),
        "still inside the hold"
    );
    assert!(
        !rib.contains_key(&key),
        "the deleted RTBH leaves inside the hold; peer {rib:?}"
    );
}

/// A session that is clean and caught up while its unicast End-of-RIB is
/// queued but not held: production reaches this for an EVPN receiver
/// whose feed is current, where a full writer at the End-of-RIB leaves the
/// peer clean (`send_initial_table_with_readiness`, `flush_pending_eor`).
/// The test reaches it with a writer that fits the table but not the
/// End-of-RIB, then clears the dirty mark the plain unicast session gets.
/// The carried key must wait for the hold, not retire as if the End-of-RIB
/// had gone out. Red proof: retiring regardless of a queued End-of-RIB
/// drops it, and the RTBH stays until release.
#[test]
fn queued_unheld_end_of_rib_keeps_the_carry_for_the_hold() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (_old_tx, mut old_rx) = register_dual_stack(&mut manager, 82, 64);
    let mut rib = PeerRib::new();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 3), 32);
    inject_rtbh(&mut manager, rtbh);
    inject_rtbh(&mut manager, kept);
    apply(&mut old_rx, &mut rib, None);
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    // Room for the table only: the End-of-RIB queues behind it.
    let (_new_tx, mut new_rx) = register_dual_stack(&mut manager, 182, 1);
    assert!(
        manager
            .pending_eor
            .get(&observer)
            .is_some_and(|families| families.contains(&FAMILY)),
        "the IPv4 End-of-RIB is queued"
    );
    // An EVPN receiver with a current feed stays clean here.
    manager.dirty_peers.remove(&observer);
    manager.flush_helper_stale_exempt(&HashSet::new());
    let key = (Prefix::V4(rtbh), 0);
    assert!(
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.keys.contains(&key)),
        "the key waits: the End-of-RIB is queued, not sent"
    );
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    assert_timer_withdraws(&mut manager, &mut new_rx, &mut rib, rtbh, Some(kept));
}

/// A carried IPv4 key waits under replay grace because its prefix still has
/// a candidate route, one this receiver's export policy denies, while an
/// unrelated IPv6 selection gate stays dormant. Grace then ends and our
/// IPv4 End-of-RIB goes out, purging the helper's stale row. The settled
/// carry must retire that key then, without a withdrawal. Red proof:
/// without re-walking a set whose family retired, the obsolete key stays
/// in the bounded carry until the IPv6 gate releases.
#[test]
fn settled_carry_retires_its_family_once_its_end_of_rib_goes_out() {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    const V6_WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 86);
    let (_tx, rx) = mpsc::channel(16);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(600),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(V6_WAITER),
                families: vec![V6],
            }],
        })
        .with_eor_grace(crate::EorGraceConfig {
            peers: vec![crate::EorGracePeerConfig {
                peer: peer_v4(OBSERVER).into(),
                deadline,
                families: vec![FAMILY],
            }],
            replay_owners: vec![],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    let key = (Prefix::V4(rtbh), 0);
    // The receiver never gets the eBGP route at the RTBH's prefix.
    let mut deny_external = deny_prefixes_chain(&[Prefix::V4(rtbh)]);
    deny_external.policies[0].policy.entries[0].match_route_type =
        Some(rustbgpd_policy::RouteType::External);
    let (_old_tx, mut old_rx) =
        register_dual_stack_with(&mut manager, 82, 64, false, Some(deny_external.clone()));
    announce(&mut manager, [rtbh]);
    inject_rtbh(&mut manager, rtbh);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib, None);
    assert!(rib.contains_key(&key));
    clean_end(&mut manager, 82);
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    delete(&mut manager, rtbh);
    let (_new_tx, mut new_rx) =
        register_dual_stack_with(&mut manager, 182, 64, false, Some(deny_external));
    assert_eq!(run_timer(&mut manager, &mut new_rx, &mut rib, None), 0);
    assert!(
        manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.settled && carried.keys.contains(&key)),
        "the key waits in a settled set: its prefix still has a candidate"
    );
    manager.expire_eor_grace(deadline);
    let mut markers = 0;
    for _ in 0..8 {
        while let Ok(update) = new_rx.try_recv() {
            assert!(!update.withdraw.contains(&key), "nothing is withdrawn");
            if update.end_of_rib.contains(&FAMILY) {
                markers += 1;
                rib.retain(|_, stale| !*stale);
            }
        }
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
    }
    assert_eq!(markers, 1, "grace end sends the IPv4 End-of-RIB");
    assert!(!rib.contains_key(&key), "which purges the stale row");
    assert!(
        manager
            .selection_deferral
            .as_ref()
            .is_some_and(super::super::selection_deferral::SelectionDeferral::may_hold),
        "the IPv6 gate can still hold"
    );
    assert!(
        !manager
            .helper_stale_exempt
            .get(&observer)
            .is_some_and(|carried| carried.keys.contains(&key)),
        "the obsolete IPv4 key retires"
    );
}

/// Releasing many grace windows at one deadline retires carries and
/// ledgers once for the batch, so the work grows with windows plus owners.
/// Red proof: a retirement per released window rescans every remaining
/// owner, a windows x owners term.
fn grace_batch_release(size: usize) -> super::work_scaling::Work {
    let (_tx, rx) = mpsc::channel(16);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let address = |index: usize| {
        let [high, low] = u16::try_from(index).unwrap().to_be_bytes();
        Ipv4Addr::new(192, 0, 3 + high, low)
    };
    // A later window keeps grace open past the batch, so the batch's
    // retirement walks the owners.
    let mut peers: Vec<_> = (0..size)
        .map(|index| crate::EorGracePeerConfig {
            peer: peer_v4(address(index)).into(),
            deadline,
            families: vec![FAMILY],
        })
        .collect();
    peers.push(crate::EorGracePeerConfig {
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 99)).into(),
        deadline: deadline + Duration::from_secs(1),
        families: vec![FAMILY],
    });
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_eor_grace(crate::EorGraceConfig {
            peers,
            replay_owners: vec![],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let mut receivers: Vec<_> = (0..size)
        .map(|index| {
            let (_tx, rx, _) = register_peer(
                &mut manager,
                address(index),
                u64::try_from(index).unwrap() + 1,
                false,
                false,
                false,
            );
            rx
        })
        .collect();
    let rtbh = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_rtbh(&mut manager, rtbh);
    // Each receiver's queued withdrawal is recorded in its own ledger.
    delete(&mut manager, rtbh);
    for rx in &mut receivers {
        while rx.try_recv().is_ok() {}
    }
    let peer_ledgers = |manager: &RibManager| {
        manager
            .hold_exempt_withdrawn
            .keys()
            .filter(|owner| matches!(owner, super::super::HoldWithdrawOwner::Peer(_)))
            .count()
    };
    assert_eq!(peer_ledgers(&manager), size, "setup, size {size}");
    let work = super::work_scaling::checkpoints_in(|| manager.expire_eor_grace(deadline));
    assert_eq!(
        peer_ledgers(&manager),
        0,
        "every released peer's ledger retires"
    );
    work
}

#[test]
fn grace_batch_release_retires_linearly() {
    super::work_scaling::assert_linear(
        "grace batch release",
        &["helper_stale_retire"],
        grace_batch_release,
    );
}

/// The carried-family shortcut reads only the first and last keys, which
/// holds while `Prefix` orders every IPv4 prefix before every IPv6 one.
/// A reordered or added variant fails here.
#[test]
fn carried_keys_sort_ipv4_before_ipv6() {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    let last_v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::BROADCAST, 32));
    let first_v6 = Prefix::V6(Ipv6Prefix::new("::".parse().unwrap(), 0));
    assert!(last_v4 < first_v6);
    let keys = std::collections::BTreeSet::from([
        (first_v6, 0),
        (Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)), 3),
        (last_v4, 7),
    ]);
    assert_eq!(
        super::peer_lifecycle::carried_families(&keys).collect::<Vec<_>>(),
        [FAMILY, V6]
    );
}
