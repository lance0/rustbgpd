//! A receiver whose ended session advertised Graceful Restart may still hold
//! our routes stale and deletes them at our next End-of-RIB (RFC 4724 §4.2);
//! a GR restarter completes its route selection there (§4.1). An ORF-gated
//! family's table waits for the peer's ROUTE-REFRESH (RFC 5291 §6), so its
//! initial End-of-RIB must follow that table, not precede it, with a bounded
//! fallback for a peer that never refreshes.

use std::collections::BTreeMap;

use super::selection_deferral_dirty_rtbh::private_policy;
use super::*;
use crate::manager::ORF_EOR_HOLD_CAP;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 82);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
const WAITER_SESSION: u64 = 83;

/// The peer's view: each key and whether it is stale from an ended session.
type PeerRib = BTreeMap<(Prefix, u32), bool>;

/// The Graceful Restart capability a session's OPEN carried.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    NoGr,
    /// A capability listing no family: the peer retains our routes only.
    HelperOnly,
    /// A capability listing the family; the session's end is GR retention.
    Gr {
        restarting: bool,
    },
}

fn host() -> (Ipv4Prefix, (Prefix, u32)) {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    (prefix, (Prefix::V4(prefix), 0))
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(16);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

/// A manager inside a startup selection hold on the family, with its waiter.
fn held_manager() -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(600),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        });
    let waiter =
        super::selection_deferral_dirty_rtbh::connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_convergence_held(FAMILY));
    (manager, waiter)
}

fn context(session_id: u64, open: Open) -> RibUpdate {
    RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(OBSERVER),
        session_id,
        peer_restart_state: matches!(open, Open::Gr { restarting: true }),
        peer_gr_helper: open != Open::NoGr,
        peer_gr_families: if matches!(open, Open::Gr { .. }) {
            vec![FAMILY]
        } else {
            vec![]
        },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    }
}

/// An ORF-receive `PeerUp` on `tx`.
fn peer_up(session_id: u64, tx: mpsc::Sender<OutboundRouteUpdate>) -> RibUpdate {
    let mut up = super::lifecycle::test_peer_up(peer_v4(OBSERVER), session_id, tx);
    if let RibUpdate::PeerUp {
        sendable_families,
        export_policy,
        negotiated_orf_recv,
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY];
        *export_policy = Some(private_policy(None));
        *negotiated_orf_recv = vec![FAMILY];
    }
    up
}

fn register(
    manager: &mut RibManager,
    session_id: u64,
    open: Open,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(64);
    manager.handle_update(context(session_id, open));
    manager.handle_update(peer_up(session_id, tx));
    rx
}

fn inject_host(manager: &mut RibManager) {
    let mut route = make_route(host().0, Ipv4Addr::new(192, 0, 2, 81));
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
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

/// The peer's plain ROUTE-REFRESH, which also lifts the gate.
fn refresh(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer: peer_v4(OBSERVER),
        session_id,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
}

/// Applies every queued update as a GR helper does: `table` for an update
/// announcing the host route, then `eor` for one carrying the family's
/// End-of-RIB, which drops every row still stale.
fn apply(rx: &mut mpsc::Receiver<OutboundRouteUpdate>, rib: &mut PeerRib) -> Vec<&'static str> {
    let mut seen = Vec::new();
    while let Ok(update) = rx.try_recv() {
        for key in &update.withdraw {
            rib.remove(key);
        }
        for route in update.announce.iter() {
            rib.insert((route.prefix, route.path_id), false);
        }
        if update
            .announce
            .iter()
            .any(|route| route.prefix == host().1.0)
        {
            seen.push("table");
        }
        if update.end_of_rib.contains(&FAMILY) {
            rib.retain(|_, stale| !*stale);
            seen.push("eor");
        }
    }
    seen
}

/// The host route is on the peer when its session with `old` ends: a GR
/// retention end for `Open::Gr` (the peer becomes a restarter), otherwise
/// `PeerDown`. The peer keeps our routes stale unless `old` is `NoGr`. A new
/// ORF-gated session registers (restarting after a GR end, helper-only
/// otherwise). Returns its receiver and the peer's RIB.
fn flapped(manager: &mut RibManager, old: Open) -> (mpsc::Receiver<OutboundRouteUpdate>, PeerRib) {
    let mut old_rx = register(manager, 82, old);
    permit_all_orf(manager, 82);
    inject_host(manager);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib);
    assert_eq!(
        rib.get(&host().1),
        Some(&false),
        "the host route reached the peer"
    );
    let peer = peer_v4(OBSERVER);
    let new = if matches!(old, Open::Gr { .. }) {
        manager.handle_update(RibUpdate::PeerGracefulRestart {
            peer,
            session_id: 82,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![FAMILY],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        });
        Open::Gr { restarting: true }
    } else {
        manager.handle_update(RibUpdate::PeerDown {
            peer,
            session_id: 82,
        });
        Open::HelperOnly
    };
    drop(old_rx);
    if old == Open::NoGr {
        rib.clear();
    } else {
        for stale in rib.values_mut() {
            *stale = true;
        }
    }
    let new_rx = register(manager, 182, new);
    assert_eq!(
        manager.gr_peers.contains_key(&peer),
        matches!(old, Open::Gr { .. })
    );
    (new_rx, rib)
}

/// The ticket's shape. Red proof: keying the deferral on `gr_peers` alone
/// sends the initial End-of-RIB first and the helper drops the host route.
#[test]
fn stale_holding_helper_gets_its_orf_table_before_the_initial_eor() {
    let mut manager = manager();
    let (mut rx, mut rib) = flapped(&mut manager, Open::HelperOnly);
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    assert_eq!(
        rib.get(&host().1),
        Some(&true),
        "the helper still holds it stale"
    );
    permit_all_orf(&mut manager, 182);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_eq!(apply(&mut rx, &mut rib), vec!["table", "eor"]);
    assert_eq!(
        rib.get(&host().1),
        Some(&false),
        "re-announced, never swept"
    );
}

/// A peer that never refreshes still gets the End-of-RIB at the cap, and
/// not before it; a later ROUTE-REFRESH still gets the table.
async fn assert_eor_at_the_cap(old: Open) {
    let mut manager = manager();
    let (mut rx, mut rib) = flapped(&mut manager, old);
    let registered = tokio::time::Instant::now();
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    let deadline = manager
        .next_eor_hold_deadline()
        .expect("the hold arms a timer");
    assert_eq!(deadline, registered + ORF_EOR_HOLD_CAP);
    tokio::time::advance(ORF_EOR_HOLD_CAP.saturating_sub(Duration::from_secs(1))).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert_eq!(
        apply(&mut rx, &mut rib),
        Vec::<&str>::new(),
        "nothing before the cap"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.expire_eor_holds(deadline);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
    assert!(rib.is_empty(), "the peer deletes what we never re-sent");
    assert_eq!(manager.next_eor_hold_deadline(), None);
    permit_all_orf(&mut manager, 182);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_eq!(apply(&mut rx, &mut rib).first(), Some(&"table"));
    assert_eq!(rib.get(&host().1), Some(&false));
}

/// Red proof: dropping the hold's expiry leaves the helper waiting.
#[tokio::test(start_paused = true)]
async fn never_refreshing_helper_gets_the_eor_at_the_cap() {
    assert_eor_at_the_cap(Open::HelperOnly).await;
}

/// A GR restarter's ended session always carried GR, so its ORF-gated
/// End-of-RIB has the same cap; its own selection deferral timer would bound
/// the wait anyway (RFC 4724 §4.1). Red proof: as for the helper.
#[tokio::test(start_paused = true)]
async fn never_refreshing_restarter_gets_the_eor_at_the_cap() {
    assert_eor_at_the_cap(Open::Gr { restarting: false }).await;
}

/// A receiver whose ended session had no GR capability dropped our routes,
/// whatever its new OPEN says: it keeps today's immediate honest-empty
/// End-of-RIB. Red proof: recording every ended session as stale-holding
/// defers it.
#[test]
fn non_helper_reconnect_keeps_the_immediate_orf_eor() {
    let mut manager = manager();
    let (mut rx, mut rib) = flapped(&mut manager, Open::NoGr);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
    assert_eq!(manager.next_eor_hold_deadline(), None);
}

/// The held End-of-RIB and its timer belong to the session: a session end
/// drops both, so no cap fires into the next session, and a peer delete
/// forgets that the peer may hold our routes. Red proof: keeping the hold
/// across `clear_outbound_peer_state` leaves its deadline armed.
#[tokio::test(start_paused = true)]
async fn session_end_and_delete_drop_the_held_eor() {
    let mut manager = manager();
    let (rx, _rib) = flapped(&mut manager, Open::HelperOnly);
    let peer = peer_v4(OBSERVER);
    assert!(manager.gr_deferred_eor.contains_key(&peer));
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 182,
    });
    drop(rx);
    assert!(!manager.gr_deferred_eor.contains_key(&peer));
    assert_eq!(manager.next_eor_hold_deadline(), None);
    // The ended session was a helper too, so the next one would hold.
    assert!(manager.peer_may_hold_stale.contains(&peer));
    manager.handle_update(RibUpdate::PeerDeleted {
        peer,
        label: None,
        keep_series: false,
    });
    assert!(!manager.peer_may_hold_stale.contains(&peer));
    let mut rx = register(&mut manager, 282, Open::HelperOnly);
    assert_eq!(apply(&mut rx, &mut PeerRib::new()), vec!["eor"]);
}

/// Inside our startup selection hold the peer's refresh is deferred, and
/// the cap passes before release. Whether the refresh came before or after
/// the cap, release sends the table before the End-of-RIB, so the peer
/// never drops the stale host route.
async fn assert_held_refresh_keeps_table_first(old: Open, refresh_before_cap: bool) {
    let (mut manager, _waiter) = held_manager();
    let (mut rx, mut rib) = flapped(&mut manager, old);
    let peer = peer_v4(OBSERVER);
    assert!(manager.gr_deferred_eor[&peer].contains(&FAMILY));
    if refresh_before_cap {
        refresh(&mut manager, 182);
    }
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    if !refresh_before_cap {
        refresh(&mut manager, 182);
    }
    assert_eq!(
        apply(&mut rx, &mut rib),
        Vec::<&str>::new(),
        "nothing before release"
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: WAITER_SESSION,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_convergence_held(FAMILY));
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_eq!(apply(&mut rx, &mut rib), vec!["table", "eor"]);
    assert_eq!(rib.get(&host().1), Some(&false));
}

/// The control: no stale retention, no cap; the hold alone orders them.
#[tokio::test(start_paused = true)]
async fn held_refresh_without_retention_keeps_table_first() {
    assert_held_refresh_keeps_table_first(Open::NoGr, true).await;
}

/// Red proof: a cap that releases every deferred marker, including one
/// whose refresh the hold queued, sends `["eor", "table"]`.
#[tokio::test(start_paused = true)]
async fn helper_refresh_queued_before_the_cap_keeps_table_first() {
    assert_held_refresh_keeps_table_first(Open::HelperOnly, true).await;
}

/// Red proof: as above.
#[tokio::test(start_paused = true)]
async fn restarter_refresh_queued_before_the_cap_keeps_table_first() {
    assert_held_refresh_keeps_table_first(Open::Gr { restarting: false }, true).await;
}

/// Red proof: without the deferred refresh reclaiming the marker the cap
/// released into the hold, release sends `["eor", "table"]`.
#[tokio::test(start_paused = true)]
async fn helper_refresh_after_the_cap_keeps_table_first() {
    assert_held_refresh_keeps_table_first(Open::HelperOnly, false).await;
}

/// Red proof: as above.
#[tokio::test(start_paused = true)]
async fn restarter_refresh_after_the_cap_keeps_table_first() {
    assert_held_refresh_keeps_table_first(Open::Gr { restarting: false }, false).await;
}

/// A replacement `PeerUp` that supersedes a registration still waiting in
/// `pending_initial_registrations` records that superseded session's GR
/// capability too. Red proof: carrying only an installed outbound session id
/// loses the flag, and the replacement gets no hold.
#[tokio::test]
async fn replacement_of_a_deferred_registration_keeps_the_hold() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let (old_tx, _old_rx) = mpsc::channel(16);
    let (new_tx, _new_rx) = mpsc::channel(16);
    for update in [
        context(82, Open::HelperOnly),
        peer_up(82, old_tx),
        context(182, Open::HelperOnly),
        peer_up(182, new_tx),
    ] {
        tx.try_send(update).unwrap();
    }
    let peer = peer_v4(OBSERVER);
    for _ in 0..32 {
        let current = manager
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .map(|record| record.session_id);
        if current == Some(182) {
            break;
        }
        assert!(manager.drain_ready_updates().await);
    }
    assert!(manager.pending_initial_registrations.contains(&peer));
    assert!(manager.orf_eor_hold.contains_key(&peer));
}
