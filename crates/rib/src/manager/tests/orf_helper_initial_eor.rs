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

/// A manager inside a startup selection hold on the family, with its waiter
/// and the sender of its primary queue.
fn held_manager() -> (
    RibManager,
    mpsc::Receiver<OutboundRouteUpdate>,
    mpsc::Sender<RibUpdate>,
) {
    let (tx, rx) = mpsc::channel(16);
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
    (manager, waiter, tx)
}

fn context(session_id: u64, open: Open) -> RibUpdate {
    context_of(OBSERVER, session_id, open)
}

fn context_of(address: Ipv4Addr, session_id: u64, open: Open) -> RibUpdate {
    RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(address),
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
    peer_up_of(OBSERVER, session_id, tx)
}

fn peer_up_of(
    address: Ipv4Addr,
    session_id: u64,
    tx: mpsc::Sender<OutboundRouteUpdate>,
) -> RibUpdate {
    let mut up = super::lifecycle::test_peer_up(peer_v4(address), session_id, tx);
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
    register_of(manager, OBSERVER, session_id, open, 64).1
}

fn register_of(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    open: Open,
    capacity: usize,
) -> (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let (tx, rx) = mpsc::channel(capacity);
    manager.handle_update(context_of(address, session_id, open));
    manager.handle_update(peer_up_of(address, session_id, tx.clone()));
    (tx, rx)
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
    permit_all_orf_of(manager, OBSERVER, session_id);
}

fn permit_all_orf_of(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) {
    use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfMatch, WhenToRefresh};
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PeerOrfUpdate {
        peer: peer_v4(address),
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
    refresh_of(manager, OBSERVER, session_id);
}

fn refresh_of(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer: peer_v4(address),
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
    let (_tx, rx, rib) = flapped_of(manager, OBSERVER, old, 64);
    (rx, rib)
}

/// [`flapped`] for the peer at `address`, whose new session's channel holds
/// `capacity` updates. Also returns that channel's sender. The host route is
/// injected once, on the first call.
fn flapped_of(
    manager: &mut RibManager,
    address: Ipv4Addr,
    old: Open,
    capacity: usize,
) -> (
    mpsc::Sender<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
    PeerRib,
) {
    let (_old_tx, mut old_rx) = register_of(manager, address, 82, old, 64);
    permit_all_orf_of(manager, address, 82);
    if manager.loc_rib.get(&host().1.0).is_none() {
        inject_host(manager);
    }
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib);
    assert_eq!(
        rib.get(&host().1),
        Some(&false),
        "the host route reached the peer"
    );
    let peer = peer_v4(address);
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
    let (new_tx, new_rx) = register_of(manager, address, 182, new, capacity);
    assert_eq!(
        manager.gr_peers.contains_key(&peer),
        matches!(old, Open::Gr { .. })
    );
    (new_tx, new_rx, rib)
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
    let (mut manager, _waiter, _tx) = held_manager();
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
/// capability too, so the replacement's End-of-RIB follows its table. Red
/// proof: carrying only an installed outbound session id loses the flag,
/// and the replacement sends the End-of-RIB first.
#[tokio::test]
async fn replacement_of_a_deferred_registration_keeps_the_hold() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    inject_host(&mut manager);
    manager.initial_dump_defer_min_routes = 0;
    let (old_tx, _old_rx) = mpsc::channel(16);
    let (new_tx, mut new_rx) = mpsc::channel(16);
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
    while !manager.pending_initial_registrations.is_empty() {
        manager.advance_pending_initial_registration();
    }
    let mut rib = PeerRib::new();
    assert_eq!(apply(&mut new_rx, &mut rib), Vec::<&str>::new());
    permit_all_orf(&mut manager, 182);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_eq!(apply(&mut new_rx, &mut rib), vec!["table", "eor"]);
}

fn fill(tx: &mpsc::Sender<OutboundRouteUpdate>) {
    while tx.try_send(OutboundRouteUpdate::default()).is_ok() {}
}

fn queued(map: &HashMap<PeerId, HashSet<(Afi, Safi)>>, peer: PeerId) -> bool {
    map.get(&peer)
        .is_some_and(|families| families.contains(&FAMILY))
}

/// The refresh's response is refused by a full writer after it lifted the
/// gate, then the cap passes: the dirty resync's retry sends the table and
/// one End-of-RIB after it. Red proof: dropping both the `pending_refresh`
/// and the gate-lifted clause from the cap's partition sends
/// `["table", "eor", "table", "eor"]`; either clause alone keeps one.
#[tokio::test(start_paused = true)]
async fn refused_refresh_across_the_cap_sends_one_eor_after_the_table() {
    let mut manager = manager();
    let peer = peer_v4(OBSERVER);
    let (tx, mut rx, mut rib) = flapped_of(&mut manager, OBSERVER, Open::HelperOnly, 4);
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    fill(&tx);
    refresh(&mut manager, 182);
    assert!(manager.dirty_peers.contains(&peer));
    assert!(queued(&manager.pending_refresh, peer));
    assert!(!queued(&manager.peer_orf_pending, peer), "the gate lifted");
    assert!(queued(&manager.gr_deferred_eor, peer));
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    let mut seen = apply(&mut rx, &mut rib);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    seen.extend(apply(&mut rx, &mut rib));
    assert_eq!(seen.first(), Some(&"table"), "{seen:?}");
    assert_eq!(seen.iter().filter(|&&s| s == "eor").count(), 1, "{seen:?}");
    assert_eq!(rib.get(&host().1), Some(&false));
}

/// The refresh is deferred behind our selection hold, and the peer is dirty
/// at release, which turns the refresh into a `pending_refresh` retry with
/// the gate still up; the cap then passes before the resync. Red proof:
/// releasing a `pending_refresh` family at the cap sends
/// `["eor", "table", "eor"]`.
#[tokio::test(start_paused = true)]
async fn dirty_at_release_then_cap_keeps_table_first() {
    let (mut manager, _waiter, _tx) = held_manager();
    let peer = peer_v4(OBSERVER);
    let (tx, mut rx, mut rib) = flapped_of(&mut manager, OBSERVER, Open::HelperOnly, 4);
    assert!(queued(&manager.gr_deferred_eor, peer));
    refresh(&mut manager, 182);
    assert!(queued(&manager.selection_deferred_refresh, peer));
    fill(&tx);
    manager.mark_outbound_dirty(peer);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: WAITER_SESSION,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.dirty_peers.contains(&peer));
    assert!(queued(&manager.pending_refresh, peer));
    assert!(
        queued(&manager.peer_orf_pending, peer),
        "the gate is still up"
    );
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    let mut seen = apply(&mut rx, &mut rib);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    seen.extend(apply(&mut rx, &mut rib));
    assert_eq!(seen, vec!["table", "eor"]);
    assert_eq!(rib.get(&host().1), Some(&false));
}

/// The shared timer fires late for the earlier of two caps, past the later
/// one, while the later peer's ROUTE-REFRESH is still queued: only the due
/// cap expires, so the queued refresh drains before the later cap and its
/// table precedes its End-of-RIB. Red proof: expiring every cap up to
/// `now` sends the later peer's End-of-RIB at the earlier cap.
#[tokio::test(start_paused = true)]
async fn a_later_cap_waits_for_its_own_turn() {
    const LATER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 84);
    let mut manager = manager();
    let (_tx, mut rx, mut rib) = flapped_of(&mut manager, OBSERVER, Open::HelperOnly, 64);
    let first = manager.next_eor_hold_deadline().expect("the first cap");
    tokio::time::advance(Duration::from_secs(10)).await;
    let (_later_tx, mut later_rx, mut later_rib) =
        flapped_of(&mut manager, LATER, Open::HelperOnly, 64);
    assert_eq!(apply(&mut later_rx, &mut later_rib), Vec::<&str>::new());
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(first);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
    assert_eq!(
        apply(&mut later_rx, &mut later_rib),
        Vec::<&str>::new(),
        "the later cap waits for its own turn"
    );
    refresh_of(&mut manager, LATER, 182);
    let second = manager.next_eor_hold_deadline().expect("the later cap");
    manager.expire_eor_holds(second);
    assert_eq!(apply(&mut later_rx, &mut later_rib), vec!["table", "eor"]);
    assert_eq!(later_rib.get(&host().1), Some(&false));
}

/// A GR restarter whose registration waits in
/// `pending_initial_registrations` past the cap: the cap has nothing to
/// release yet, and the later initial dump sends the End-of-RIB at once
/// instead of holding it with no timer left. Red proof: a predicate that
/// ignores the passed cap holds it through `gr_peers` alone.
#[tokio::test(start_paused = true)]
async fn registration_deferred_past_the_cap_sends_the_eor() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(OBSERVER);
    let mut old_rx = register(&mut manager, 82, Open::Gr { restarting: false });
    permit_all_orf(&mut manager, 82);
    inject_host(&mut manager);
    let mut rib = PeerRib::new();
    apply(&mut old_rx, &mut rib);
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
    drop(old_rx);
    for stale in rib.values_mut() {
        *stale = true;
    }
    manager.initial_dump_defer_min_routes = 0;
    let (new_tx, mut new_rx) = mpsc::channel(16);
    for update in [
        context(182, Open::Gr { restarting: true }),
        peer_up(182, new_tx),
        // Queued work behind the PeerUp defers its registration.
        context(999, Open::NoGr),
    ] {
        tx.try_send(update).unwrap();
    }
    while manager.drain_ready_updates().await {}
    assert!(manager.pending_initial_registrations.contains(&peer));
    assert!(manager.gr_peers.contains_key(&peer));
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert_eq!(manager.next_eor_hold_deadline(), None);
    while !manager.pending_initial_registrations.is_empty() {
        manager.advance_pending_initial_registration();
    }
    assert_eq!(apply(&mut new_rx, &mut rib), vec!["eor"]);
}

/// Releases the startup selection hold through its waiter's End-of-RIB.
fn release_hold(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: WAITER_SESSION,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_convergence_held(FAMILY));
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
}

/// An ORF peer with no stale retention whose initial dump falls inside our
/// startup selection hold: its marker waits for the gated table, bounded by
/// the cap, so a peer that never refreshes still gets it when the hold
/// ends. Red proof: recording that marker without arming the cap leaves it
/// waiting for a refresh that never comes.
#[tokio::test(start_paused = true)]
async fn held_marker_of_a_non_retaining_peer_has_the_cap() {
    let (mut manager, _waiter, _tx) = held_manager();
    inject_host(&mut manager);
    let mut rx = register(&mut manager, 182, Open::NoGr);
    let mut rib = PeerRib::new();
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert_eq!(
        apply(&mut rx, &mut rib),
        Vec::<&str>::new(),
        "the selection hold still holds it"
    );
    release_hold(&mut manager);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
}

/// A stale-holding peer's registration waits past its cap and then dumps
/// inside our selection hold: the selection-held marker is not recorded for
/// a table after the cap, so it goes out when the hold ends. Red proof:
/// recording it into `gr_deferred_eor` regardless of the cap leaves it with
/// no timer.
#[tokio::test(start_paused = true)]
async fn selection_held_marker_after_the_cap_goes_out_at_release() {
    let (mut manager, _waiter, tx) = held_manager();
    let peer = peer_v4(OBSERVER);
    let _old_rx = register(&mut manager, 82, Open::HelperOnly);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 82,
    });
    manager.initial_dump_defer_min_routes = 0;
    let (new_tx, mut rx) = mpsc::channel(16);
    for update in [
        context(182, Open::HelperOnly),
        peer_up(182, new_tx),
        // Queued work behind the PeerUp defers its registration.
        context(999, Open::NoGr),
    ] {
        tx.try_send(update).unwrap();
    }
    while manager.drain_ready_updates().await {}
    assert!(manager.pending_initial_registrations.contains(&peer));
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    while !manager.pending_initial_registrations.is_empty() {
        manager.advance_pending_initial_registration();
    }
    let mut rib = PeerRib::new();
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    release_hold(&mut manager);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
}

/// A gated family unlocked after the cap while our selection hold still
/// holds its marker: the marker is not recorded for a table, so it goes out
/// when the hold ends. Red proof: the unlock's held branch recording it into
/// `gr_deferred_eor` regardless of the cap leaves it with no timer.
#[tokio::test(start_paused = true)]
async fn unlock_after_the_cap_under_a_hold_goes_out_at_release() {
    let (mut manager, _waiter, _tx) = held_manager();
    let peer = peer_v4(OBSERVER);
    let _old_rx = register(&mut manager, 82, Open::HelperOnly);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 82,
    });
    let (tx, mut rx) = mpsc::channel(16);
    manager.handle_update(context(182, Open::HelperOnly));
    let mut up = peer_up(182, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        sendable_families.clear();
    }
    manager.handle_update(up);
    tokio::time::advance(ORF_EOR_HOLD_CAP).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert!(manager.orf_eor_cap_passed.contains(&peer));
    manager.handle_update(RibUpdate::PeerFamilySendable {
        peer,
        session_id: 182,
        family: FAMILY,
        add_path_send_limit: None,
    });
    let mut rib = PeerRib::new();
    assert_eq!(apply(&mut rx, &mut rib), Vec::<&str>::new());
    release_hold(&mut manager);
    assert_eq!(apply(&mut rx, &mut rib), vec!["eor"]);
}
