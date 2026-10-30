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

/// Registers a session; `full` occupies its writer before `PeerUp`, so the
/// initial table waits for a later resync.
fn register(
    manager: &mut RibManager,
    session_id: u64,
    grouped: bool,
    full: bool,
) -> (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
    Vec<mpsc::OwnedPermit<OutboundRouteUpdate>>,
) {
    let observer = peer_v4(OBSERVER);
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
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY];
        if !grouped {
            *export_policy = Some(private_policy(None));
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
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: peer_v4(OBSERVER),
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
