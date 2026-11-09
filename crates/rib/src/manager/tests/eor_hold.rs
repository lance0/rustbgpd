//! The End-of-RIB hold set: an owed marker leaves only from the release
//! that empties its hold set, never from a timer or another reason's
//! release while a reason is still present.
//!
//! The exhaustive test arms every combination of the five reasons one
//! plain session can carry. The EVPN feed and owed-key reasons need their
//! own producers and are pinned in `evpn_complete_feed` and
//! `outbound_owing`.

use super::*;
use crate::manager::eor_hold::EorHold;
use crate::{
    EorGraceConfig, EorGracePeerConfig, SelectionDeferralConfig, SelectionDeferralWaiterConfig,
};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const SOURCE: PeerId = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
const TARGET: PeerId = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
const WINDOW: Duration = Duration::from_secs(10);
const REASONS: [EorHold; 5] = [
    EorHold::Selection,
    EorHold::RtMembership,
    EorHold::Grace,
    EorHold::OrfTable,
    EorHold::Resync,
];

fn connect(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    family: (Afi, Safi),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    connect_with(manager, peer, session_id, vec![family])
}

fn connect_with(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: families.clone(),
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: families,
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

/// End-of-RIB markers for `FAMILY` among everything queued on `rx`.
fn markers(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> usize {
    std::iter::from_fn(|| rx.try_recv().ok())
        .map(|update| {
            update
                .end_of_rib
                .iter()
                .filter(|family| **family == FAMILY)
                .count()
        })
        .sum()
}

/// A manager whose `TARGET` session owes `FAMILY`'s marker under exactly
/// the reasons in `held`.
fn held_by(held: &[EorHold]) -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    if held.contains(&EorHold::Selection) {
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: SOURCE.into(),
                families: vec![FAMILY],
            }],
        });
    }
    if held.contains(&EorHold::Grace) {
        manager = manager.with_eor_grace(EorGraceConfig {
            peers: vec![EorGracePeerConfig {
                peer: TARGET.into(),
                deadline: tokio::time::Instant::now() + WINDOW,
                families: vec![FAMILY],
            }],
            replay_owners: vec![],
        });
    }
    if held.contains(&EorHold::Selection) {
        // The waiter's session arms the gate; the receiver never reads.
        std::mem::forget(connect(&mut manager, SOURCE, 1, FAMILY));
    }
    let mut output = connect(&mut manager, TARGET, 2, FAMILY);
    // Without a withholding reason the initial dump sent the marker; the
    // session then owes it again, as after any later event.
    markers(&mut output);
    manager.owe_eor(TARGET, FAMILY);
    if held.contains(&EorHold::RtMembership) {
        manager.hold_eor_for_rt_membership(TARGET, tokio::time::Instant::now() + WINDOW);
    }
    if held.contains(&EorHold::OrfTable) {
        manager.owe_eor_behind_orf_table(TARGET, FAMILY);
    }
    if held.contains(&EorHold::Resync) {
        manager.dirty_peers.insert(TARGET);
    }
    (manager, output)
}

fn assert_holds(manager: &RibManager, expected: &[EorHold], case: &str) {
    let holds = manager.eor_holds(TARGET, FAMILY);
    for hold in EorHold::ALL {
        assert_eq!(
            holds.contains(hold),
            expected.contains(&hold),
            "{case}: {hold:?} in {holds:?}"
        );
    }
}

/// Everything that may offer the marker without releasing a reason of
/// this case: a bare settle, the tick's marker lane, and the release of
/// each reason that is not present.
fn poke(manager: &mut RibManager, present: &[EorHold]) {
    manager.settle_eor_now(TARGET);
    manager.retry_eor_markers_bounded();
    let timed = |reason: &EorHold| matches!(reason, EorHold::RtMembership | EorHold::Grace);
    for reason in REASONS {
        // The shared hold timer ends both deadline-backed reasons, so it
        // is poked only when neither is present.
        let timer_shared = timed(&reason) && present.iter().any(timed);
        if !present.contains(&reason) && !timer_shared {
            release(manager, reason);
        }
    }
}

/// End `reason` the way production does. The two deadline-backed reasons
/// end through the shared hold timer.
fn release(manager: &mut RibManager, reason: EorHold) {
    use crate::manager::eor_hold::EorTrigger;
    match reason {
        EorHold::Selection => manager.expire_selection_deferral(),
        EorHold::RtMembership | EorHold::Grace => {
            manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
        }
        EorHold::OrfTable => manager.release_eor_orf_table(TARGET, [FAMILY], EorTrigger::Release),
        EorHold::Resync => {
            manager.dirty_peers.remove(&TARGET);
            manager.resync_settles_eor(TARGET, None);
        }
        EorHold::EvpnFeed | EorHold::OwedKeys | EorHold::Writer => unreachable!(),
    }
}

/// Every non-empty combination of the five reasons, released one step at a
/// time in an order that varies by combination: no marker leaves while a
/// reason remains, whatever else is poked or expires, and exactly one
/// leaves with the release of the last reason.
#[tokio::test(start_paused = true)]
async fn a_marker_leaves_only_from_the_release_that_empties_its_hold_set() {
    for mask in 1_usize..(1 << REASONS.len()) {
        let held: Vec<EorHold> = REASONS
            .into_iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, reason)| reason)
            .collect();
        let case = format!("{held:?}");
        let (mut manager, mut output) = held_by(&held);
        assert_holds(&manager, &held, &case);
        // The timer step ends both deadline-backed reasons at once.
        let mut steps: Vec<Vec<EorHold>> = Vec::new();
        let timed: Vec<EorHold> = held
            .iter()
            .copied()
            .filter(|reason| matches!(reason, EorHold::RtMembership | EorHold::Grace))
            .collect();
        if !timed.is_empty() {
            steps.push(timed);
        }
        steps.extend(
            held.iter()
                .copied()
                .filter(|reason| !matches!(reason, EorHold::RtMembership | EorHold::Grace))
                .map(|reason| vec![reason]),
        );
        let turn = mask % steps.len();
        steps.rotate_left(turn);
        let mut present = held.clone();
        for step in steps {
            poke(&mut manager, &present);
            assert_eq!(
                markers(&mut output),
                0,
                "{case}: sent while {present:?} held"
            );
            assert!(manager.eor.owes(TARGET, FAMILY), "{case}: dropped unsent");
            assert_holds(&manager, &present, &case);
            release(&mut manager, step[0]);
            present.retain(|reason| !step.contains(reason));
            if present.is_empty() {
                assert_eq!(markers(&mut output), 1, "{case}: last release sends");
            }
        }
        assert!(!manager.eor.owes(TARGET, FAMILY), "{case}");
        poke(&mut manager, &[]);
        assert_eq!(markers(&mut output), 0, "{case}: sent twice");
    }
}

/// A refused send is the one state the resync tick may end: the marker
/// stays owed with only the writer reason, and the tick's marker lane
/// retries it once the writer has room.
#[tokio::test(start_paused = true)]
async fn a_refused_marker_waits_for_the_tick_with_only_the_writer_reason() {
    let (mut manager, mut output) = held_by(&[EorHold::RtMembership]);
    let sender = manager.outbound_peers[&TARGET].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    release(&mut manager, EorHold::RtMembership);
    assert_eq!(markers(&mut output), 0);
    // A refused marker of a session without a current EVPN feed also
    // resyncs; clear that to isolate the writer reason.
    manager.dirty_peers.remove(&TARGET);
    assert_holds(&manager, &[EorHold::Writer], "refused");
    manager.retry_eor_markers_bounded();
    assert_eq!(markers(&mut output), 1);
    assert!(!manager.eor.owes(TARGET, FAMILY));
}

/// The test-build check after every actor turn: a marker owed with an
/// empty hold set and a live writer was left behind by a release that did
/// not settle it.
#[test]
#[should_panic(expected = "is owed with no hold and was not sent")]
fn the_end_of_turn_check_rejects_a_ready_unsent_marker() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _output = connect(&mut manager, TARGET, 2, V4);
    manager.owe_eor(TARGET, V4);
    manager.handle_update(RibUpdate::RetireEorGraceInterface {
        interface: "swp9".into(),
    });
}

fn plain_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn v4_prefix(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

fn announce(manager: &mut RibManager, source: PeerId, session_id: u64, octet: u8) {
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    route.peer = source;
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// A marker a release found behind a pending forced resync, then that
/// resync's pass. Returns what the pass delivered, in order.
fn forced_resync_with_marker(
    manager: &mut RibManager,
    output: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> Vec<OutboundRouteUpdate> {
    while output.try_recv().is_ok() {}
    manager.owe_eor(TARGET, V4);
    manager.force_outbound_peers.insert(TARGET);
    manager.settle_eor_now(TARGET);
    assert!(output.try_recv().is_err(), "the forced resync comes first");
    assert!(manager.eor_holds(TARGET, V4).contains(EorHold::Resync));
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(!manager.force_outbound_peers.contains(&TARGET));
    assert!(!manager.eor.owes(TARGET, V4));
    assert!(!manager.resync_tick_pending());
    std::iter::from_fn(|| output.try_recv().ok()).collect()
}

/// A forced resync holds the markers a release finds behind it, and its
/// admission sends them on the slot it reserved. Before, only the resync
/// tick sent a marker left behind a force-only resync. This is the exit of
/// a resync whose view is empty.
#[test]
fn a_forced_resync_sends_the_marker_it_held() {
    let mut manager = plain_manager();
    let mut output = connect(&mut manager, TARGET, 2, V4);
    let sent = forced_resync_with_marker(&mut manager, &mut output);
    let markers: Vec<_> = sent.iter().flat_map(|update| &update.end_of_rib).collect();
    assert_eq!(markers, [&V4]);
}

/// The same through the exit that commits routes: the marker follows the
/// forced resync's re-announcement in the delivered order.
#[test]
fn a_forced_resync_sends_the_marker_behind_the_routes_it_commits() {
    let mut manager = plain_manager();
    std::mem::forget(connect(&mut manager, SOURCE, 1, V4));
    let mut output = connect(&mut manager, TARGET, 2, V4);
    announce(&mut manager, SOURCE, 1, 7);
    let sent = forced_resync_with_marker(&mut manager, &mut output);
    let routes = sent
        .iter()
        .position(|update| {
            update
                .announce
                .iter()
                .any(|route| route.prefix == v4_prefix(7))
        })
        .expect("the forced resync re-announces the route");
    let marker = sent
        .iter()
        .position(|update| update.end_of_rib.contains(&V4))
        .expect("the marker is sent in the same pass");
    assert!(routes < marker, "the marker follows the forced table");
    assert_eq!(sent.iter().flat_map(|update| &update.end_of_rib).count(), 1);
}

/// The same through the exit that finds nothing to send: the only route is
/// the receiver's own, so the forced resync is unchanged and the marker is
/// all it delivers.
#[test]
fn a_forced_resync_with_nothing_to_send_still_sends_the_marker() {
    let mut manager = plain_manager();
    let mut output = connect(&mut manager, TARGET, 2, V4);
    announce(&mut manager, TARGET, 2, 9);
    let sent = forced_resync_with_marker(&mut manager, &mut output);
    assert!(sent.iter().all(|update| update.announce.is_empty()));
    let markers: Vec<_> = sent.iter().flat_map(|update| &update.end_of_rib).collect();
    assert_eq!(markers, [&V4]);
}

/// A forced resync that runs while a selection gate defers one of the
/// peer's families keeps its force bit for that family. The bit is not a
/// pending resync for the rest: another family's marker leaves in the turn
/// its own hold ends, with no tick. The gate's release then runs the
/// deferred forced resync itself; nothing else drives a force-only peer.
#[tokio::test(start_paused = true)]
async fn a_force_bit_kept_for_a_deferred_family_holds_no_other_marker() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: SOURCE.into(),
                families: vec![V4],
            }],
        })
        .with_eor_grace(EorGraceConfig {
            peers: vec![EorGracePeerConfig {
                peer: TARGET.into(),
                deadline: tokio::time::Instant::now() + WINDOW,
                families: vec![V6],
            }],
            replay_owners: vec![],
        });
    // The receiver joins while the gate is dormant; the waiter arms it.
    let mut output = connect_with(&mut manager, TARGET, 2, vec![V4, V6]);
    std::mem::forget(connect(&mut manager, SOURCE, 1, V4));
    assert!(manager.selection_resync_held(TARGET));
    assert!(!manager.dirty_peers.contains(&TARGET));
    while output.try_recv().is_ok() {}
    assert_eq!(manager.eor_pending(TARGET), HashSet::from([V6]));

    let (reply, _response) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound {
        peer: TARGET,
        reply,
    });
    assert!(
        manager.force_outbound_peers.contains(&TARGET),
        "kept for IPv4"
    );
    assert!(manager.selection_partial_caught_up(TARGET));
    assert!(!manager.dirty_peers.contains(&TARGET));
    while output.try_recv().is_ok() {}

    // The grace window ends on a static table: no pass, no tick.
    manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
    let sent: Vec<_> = std::iter::from_fn(|| output.try_recv().ok())
        .flat_map(|update| update.end_of_rib)
        .collect();
    assert_eq!(sent, [V6], "the IPv6 marker leaves with its own release");
    assert!(manager.force_outbound_peers.contains(&TARGET));

    manager.expire_selection_deferral();
    assert!(
        !manager.force_outbound_peers.contains(&TARGET),
        "the gate's release runs the deferred forced resync"
    );
    assert!(!manager.dirty_peers.contains(&TARGET));
    assert!(!manager.resync_tick_pending());
}

/// The production fallback: a marker left owed with no hold and no refused
/// send (a release that did not send it) still leaves on the next resync
/// tick, and the tick reports it. Actor turns never reach this silently in
/// a test build; the end-of-turn check above fires first.
#[test]
fn the_tick_sends_an_unsettled_marker_and_reports_it() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut output = connect(&mut manager, TARGET, 2, V4);
    while output.try_recv().is_ok() {}
    manager.owe_eor(TARGET, V4);
    assert!(manager.resync_tick_pending());
    manager.resync_dirty_peers_bounded();
    assert_eq!(output.try_recv().unwrap().end_of_rib, [V4]);
    assert_eq!(manager.eor.unsettled_tick_sends, 1);
    assert!(!manager.eor.owes(TARGET, V4));
    assert!(!manager.resync_tick_pending());
}

/// A refused marker is the tick's ordinary retry and is not reported.
#[tokio::test(start_paused = true)]
async fn the_tick_does_not_report_a_refused_marker() {
    let (mut manager, mut output) = held_by(&[EorHold::RtMembership]);
    let sender = manager.outbound_peers[&TARGET].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    release(&mut manager, EorHold::RtMembership);
    manager.dirty_peers.remove(&TARGET);
    assert_eq!(markers(&mut output), 0);
    manager.retry_eor_markers_bounded();
    assert_eq!(markers(&mut output), 1);
    assert_eq!(manager.eor.unsettled_tick_sends, 0);
}
