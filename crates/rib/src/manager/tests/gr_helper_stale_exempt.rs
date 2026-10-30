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
            "a live RTBH never leaves the peer, even briefly"
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
    assert_eq!(manager.grouped_member_of(observer).is_some(), grouped);
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
