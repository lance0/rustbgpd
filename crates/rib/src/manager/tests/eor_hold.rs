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
const OTHER: PeerId = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
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

/// Which exit the forced resync under the gate takes.
#[derive(Clone, Copy, Debug)]
enum ForcedExit {
    /// Nothing in the table.
    EmptyView,
    /// Only the receiver's own route: nothing to send.
    NoDiff,
    /// Another peer's route: the pass commits its re-announcement.
    Commit,
}

/// `TARGET` joins while the IPv6 gate is dormant, its IPv4 marker held by a
/// grace window; the waiter then arms the gate. IPv4 is never deferred, so
/// its routes flow.
fn kept_force_bit_fixture(exit: ForcedExit) -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: SOURCE.into(),
                families: vec![V6],
            }],
        })
        .with_eor_grace(EorGraceConfig {
            peers: vec![EorGracePeerConfig {
                peer: TARGET.into(),
                deadline: tokio::time::Instant::now() + WINDOW,
                families: vec![V4],
            }],
            replay_owners: vec![],
        });
    let mut output = connect_with(&mut manager, TARGET, 2, vec![V4, V6]);
    match exit {
        ForcedExit::EmptyView => {}
        ForcedExit::NoDiff => announce(&mut manager, TARGET, 2, 9),
        ForcedExit::Commit => {
            std::mem::forget(connect(&mut manager, OTHER, 3, V4));
            announce(&mut manager, OTHER, 3, 7);
        }
    }
    std::mem::forget(connect(&mut manager, SOURCE, 1, V6));
    assert!(manager.selection_resync_held(TARGET), "{exit:?}");
    assert!(!manager.dirty_peers.contains(&TARGET), "{exit:?}");
    while output.try_recv().is_ok() {}
    assert_eq!(manager.eor_pending(TARGET), HashSet::from([V4]), "{exit:?}");
    (manager, output)
}

/// A forced resync that runs while a selection gate defers one of the
/// peer's families keeps its force bit for that family. The bit is not a
/// pending resync for the rest: another family's marker leaves in the turn
/// its own hold ends, with no tick, whichever exit the forced pass took
/// (empty view, nothing to send, or a commit with routes). The gate's
/// release then runs the deferred forced resync itself; nothing else
/// drives a force-only peer.
#[tokio::test(start_paused = true)]
async fn a_force_bit_kept_for_a_deferred_family_holds_no_other_marker() {
    for exit in [
        ForcedExit::EmptyView,
        ForcedExit::NoDiff,
        ForcedExit::Commit,
    ] {
        let (mut manager, mut output) = kept_force_bit_fixture(exit);
        let (reply, _response) = oneshot::channel();
        manager.handle_update(RibUpdate::RefreshPeerOutbound {
            peer: TARGET,
            reply,
        });
        assert!(
            manager.force_outbound_peers.contains(&TARGET),
            "{exit:?}: kept for IPv6"
        );
        assert!(manager.selection_partial_caught_up(TARGET), "{exit:?}");
        assert!(!manager.dirty_peers.contains(&TARGET), "{exit:?}");
        let resent = std::iter::from_fn(|| output.try_recv().ok())
            .filter(|update| !update.announce.is_empty())
            .count();
        assert_eq!(
            resent,
            usize::from(matches!(exit, ForcedExit::Commit)),
            "{exit:?}"
        );

        // The grace window ends on a static table: no pass, no tick.
        manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
        assert_eq!(
            markers_of(&mut output, V4),
            1,
            "{exit:?}: leaves with its own release"
        );
        assert!(manager.force_outbound_peers.contains(&TARGET), "{exit:?}");

        manager.expire_selection_deferral();
        assert!(
            !manager.force_outbound_peers.contains(&TARGET),
            "{exit:?}: the gate's release runs the deferred forced resync"
        );
        assert!(!manager.dirty_peers.contains(&TARGET), "{exit:?}");
        assert!(!manager.resync_tick_pending(), "{exit:?}");
    }
}

/// A marker that a pending forced resync holds leaves from the exit where
/// that resync catches up under the gate, whichever exit it is, and is not
/// left for the tick.
#[tokio::test(start_paused = true)]
async fn a_forced_resync_that_catches_up_under_the_gate_sends_the_marker_it_held() {
    for exit in [
        ForcedExit::EmptyView,
        ForcedExit::NoDiff,
        ForcedExit::Commit,
    ] {
        let (mut manager, mut output) = kept_force_bit_fixture(exit);
        // A forced resync is requested and not yet run.
        manager.set_selection_partial_caught_up(TARGET, false);
        manager.force_outbound_peers.insert(TARGET);
        manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
        assert_eq!(
            markers_of(&mut output, V4),
            0,
            "{exit:?}: the forced resync comes first"
        );
        assert!(
            manager.eor_holds(TARGET, V4).contains(EorHold::Resync),
            "{exit:?}"
        );

        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        assert!(manager.selection_partial_caught_up(TARGET), "{exit:?}");
        assert!(
            manager.force_outbound_peers.contains(&TARGET),
            "{exit:?}: kept for IPv6"
        );
        let sent: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
        assert_eq!(
            sent.last().map(|update| update.end_of_rib.as_slice()),
            Some([V4].as_slice()),
            "{exit:?}: the marker follows the forced pass"
        );
        assert!(!manager.eor.owes(TARGET, V4), "{exit:?}");
    }
}

/// A receiver of [`late_armed_gate`]: peer, session and its families.
type GateReceiver<'a> = (PeerId, u64, &'a [(Afi, Safi)]);

/// A late-armed gate: each of `receivers` joins with its own families
/// while the gate for `families` is dormant, its markers held by a grace
/// window, then the waiter `SOURCE` arms the gate and sends one IPv4 route
/// under the hold. The grace windows are then ended, so only the gate holds
/// the markers.
fn late_armed_gate(
    families: &[(Afi, Safi)],
    receivers: &[GateReceiver<'_>],
) -> (RibManager, Vec<mpsc::Receiver<OutboundRouteUpdate>>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: SOURCE.into(),
                families: families.to_vec(),
            }],
        })
        .with_eor_grace(EorGraceConfig {
            peers: receivers
                .iter()
                .map(|&(peer, _, own)| EorGracePeerConfig {
                    peer: peer.into(),
                    deadline: tokio::time::Instant::now() + WINDOW,
                    families: own.to_vec(),
                })
                .collect(),
            replay_owners: vec![],
        });
    let mut outputs: Vec<_> = receivers
        .iter()
        .map(|&(peer, session, own)| connect_with(&mut manager, peer, session, own.to_vec()))
        .collect();
    std::mem::forget(connect_with(&mut manager, SOURCE, 1, families.to_vec()));
    announce(&mut manager, SOURCE, 1, 7);
    manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
    for (output, &(peer, _, _)) in outputs.iter_mut().zip(receivers) {
        assert_eq!(markers_of(output, V4), 0, "the gate holds the marker");
        assert!(manager.eor.owes(peer, V4));
        assert!(manager.selection_resync_held(peer));
    }
    (manager, outputs)
}

/// End-of-RIB markers for `family` among everything queued on `rx`.
fn markers_of(rx: &mut mpsc::Receiver<OutboundRouteUpdate>, family: (Afi, Safi)) -> usize {
    std::iter::from_fn(|| rx.try_recv().ok())
        .map(|update| update.end_of_rib.iter().filter(|f| **f == family).count())
        .sum()
}

/// Force a resync of `peer` under the gate: it runs for what the gate
/// allows and keeps its force bit for the deferred family.
fn force_under_the_gate(manager: &mut RibManager, peer: PeerId) {
    let (reply, _response) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(manager.force_outbound_peers.contains(&peer), "kept");
    assert!(!manager.dirty_peers.contains(&peer));
}

fn source_end_of_rib(manager: &mut RibManager, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer: SOURCE,
        session_id: 1,
        afi: family.0,
        safi: family.1,
    });
}

/// The released route and then the family's End-of-RIB, in that order, in
/// what `output` delivered.
fn assert_route_precedes_marker(output: &mut mpsc::Receiver<OutboundRouteUpdate>, case: &str) {
    let sent: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
    let route = sent
        .iter()
        .position(|update| {
            update
                .announce
                .iter()
                .any(|route| route.prefix == v4_prefix(7))
        })
        .unwrap_or_else(|| panic!("{case}: the released route is sent"));
    let marker = sent
        .iter()
        .position(|update| update.end_of_rib.contains(&V4))
        .unwrap_or_else(|| panic!("{case}: the End-of-RIB is sent in the release turn"));
    assert!(
        route <= marker,
        "{case}: the End-of-RIB (envelope {marker}) left before the released route (envelope {route})"
    );
    assert_eq!(
        sent.iter()
            .flat_map(|update| &update.end_of_rib)
            .filter(|family| **family == V4)
            .count(),
        1,
        "{case}: one End-of-RIB"
    );
}

/// A gate ends while a receiver keeps a deferred force bit and owes the
/// family's End-of-RIB. The deferred forced resync runs in the release
/// turn, and the marker still follows the routes the release selects: the
/// gate stays armed until they are admitted. By the timer and by the
/// waiter's End-of-RIB.
#[tokio::test(start_paused = true)]
async fn a_gate_release_sends_the_released_routes_before_the_marker_of_a_forced_peer() {
    for by_timer in [true, false] {
        let case = if by_timer { "timer" } else { "all End-of-RIB" };
        let (mut manager, mut outputs) = late_armed_gate(&[V4], &[(TARGET, 2, &[V4])]);
        let mut output = outputs.remove(0);
        force_under_the_gate(&mut manager, TARGET);
        while output.try_recv().is_ok() {}
        if by_timer {
            manager.expire_selection_deferral();
        } else {
            source_end_of_rib(&mut manager, V4);
        }
        assert!(!manager.selection_convergence_held(V4), "{case}");
        assert!(!manager.force_outbound_peers.contains(&TARGET), "{case}");
        assert_route_precedes_marker(&mut output, case);
        assert!(!manager.eor.owes(TARGET, V4), "{case}");
        assert!(!manager.resync_tick_pending(), "{case}");
    }
}

/// The same while a second family of the receiver is still deferred, so
/// its own forced resync stays deferred and only another receiver's makes
/// the release run its empty pass. The released family's marker follows
/// its routes; the other family's marker and the force bit wait for their
/// own gate.
#[tokio::test(start_paused = true)]
async fn a_gate_release_keeps_route_before_marker_while_another_family_is_deferred() {
    let (mut manager, mut outputs) =
        late_armed_gate(&[V4, V6], &[(TARGET, 2, &[V4, V6]), (OTHER, 3, &[V4])]);
    let mut other = outputs.remove(1);
    let mut output = outputs.remove(0);
    force_under_the_gate(&mut manager, TARGET);
    force_under_the_gate(&mut manager, OTHER);
    while output.try_recv().is_ok() {}
    while other.try_recv().is_ok() {}
    source_end_of_rib(&mut manager, V4);
    assert!(!manager.selection_convergence_held(V4));
    assert!(manager.selection_convergence_held(V6));
    assert_route_precedes_marker(&mut output, "second family deferred");
    assert_route_precedes_marker(&mut other, "forced peer beside it");
    assert_eq!(manager.eor_pending(TARGET), HashSet::from([V6]));
    assert!(
        manager.force_outbound_peers.contains(&TARGET),
        "kept for IPv6"
    );
    assert!(!manager.force_outbound_peers.contains(&OTHER));
}

/// The same for a dirty receiver with no force bit that the release wakes,
/// while another receiver's deferred forced resync makes the release run
/// its empty pass first.
#[tokio::test(start_paused = true)]
async fn a_gate_release_keeps_route_before_marker_for_a_woken_dirty_peer() {
    let (mut manager, mut outputs) =
        late_armed_gate(&[V4], &[(OTHER, 3, &[V4]), (TARGET, 2, &[V4])]);
    let mut forced = outputs.remove(1);
    let mut output = outputs.remove(0);
    force_under_the_gate(&mut manager, TARGET);
    manager.mark_outbound_dirty(OTHER);
    manager.resync_dirty_peers_bounded();
    assert!(
        manager.dirty_peers.contains(&OTHER),
        "dirty for the deferred family"
    );
    assert!(!manager.force_outbound_peers.contains(&OTHER));
    while output.try_recv().is_ok() {}
    while forced.try_recv().is_ok() {}
    manager.expire_selection_deferral();
    assert_route_precedes_marker(&mut output, "woken dirty peer");
    assert_route_precedes_marker(&mut forced, "forced peer");
    assert!(!manager.dirty_peers.contains(&OTHER));
}

/// A receiver that is dirty when its gate ends is resynced by the release
/// pass, under the gate, and then owes nothing but the marker the gate
/// held: no replay of the family is walked for it. Here its ordinary rows
/// are at its row credit, so that replay would be refused and the receiver
/// marked dirty again, for a second copy of its table on a later tick.
#[tokio::test(start_paused = true)]
async fn a_peer_resynced_by_the_release_pass_gets_its_marker_and_no_second_table() {
    const FEED: PeerId = peer_v4(Ipv4Addr::new(10, 0, 0, 4));
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
                families: vec![V4],
            }],
            replay_owners: vec![],
        });
    manager.outbound_row_credit_override = Some(1);
    // Add-Path send keeps the receiver out of an update group.
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: TARGET,
        session_id: 2,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![V4],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, mut output) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer: TARGET,
        session_id: 2,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![V4],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![V4],
        add_path_send_max: 2,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    assert!(manager.grouped_member_of(TARGET).is_none(), "ungrouped");
    while output.try_recv().is_ok() {}
    // One ordinary row the receiver never drains: its credit is spent.
    std::mem::forget(connect_with(&mut manager, FEED, 4, vec![V4]));
    announce(&mut manager, FEED, 4, 9);
    let undrained: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
    assert!(manager.outbound_credit_exhausted(TARGET));
    // The waiter arms the gate and announces under it; grace then ends.
    std::mem::forget(connect_with(&mut manager, SOURCE, 1, vec![V4]));
    announce(&mut manager, SOURCE, 1, 7);
    manager.expire_eor_holds(tokio::time::Instant::now() + WINDOW);
    manager.mark_outbound_dirty(TARGET);
    assert!(output.try_recv().is_err(), "the gate holds the marker");
    assert!(manager.eor.owes(TARGET, V4));

    manager.expire_selection_deferral();

    assert!(!manager.dirty_peers.contains(&TARGET), "resynced once");
    assert!(!manager.eor.owes(TARGET, V4));
    assert!(manager.outbound_credit_exhausted(TARGET), "still spent");
    assert_route_precedes_marker(&mut output, "resynced under the gate");
    // The resync's envelopes are gone; nothing asks for the table again.
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(output.try_recv().is_err(), "no second table");
    assert!(!manager.resync_tick_pending());
    drop(undrained);
}

/// The same for a group member that joined under the armed gate, so it
/// still carries the record of what its held initial table admitted: the
/// release pass resyncs it, the marker follows, and the record is retired
/// without the replay that would have checked the table against it.
#[tokio::test(start_paused = true)]
async fn a_group_member_resynced_by_the_release_pass_gets_its_marker_and_no_second_table() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: SOURCE.into(),
                families: vec![V4],
            }],
        });
    // One route is selected before the gate arms, one is held under it.
    std::mem::forget(connect_with(&mut manager, OTHER, 3, vec![V4]));
    announce(&mut manager, OTHER, 3, 9);
    std::mem::forget(connect_with(&mut manager, SOURCE, 1, vec![V4]));
    announce(&mut manager, SOURCE, 1, 7);
    let mut output = connect_with(&mut manager, TARGET, 2, vec![V4]);
    assert!(manager.grouped_member_of(TARGET).is_some(), "grouped");
    assert_eq!(markers_of(&mut output, V4), 0, "the gate holds the marker");
    manager.mark_outbound_dirty(TARGET);
    assert!(manager.pending_group_admitted.contains_key(&TARGET));

    manager.expire_selection_deferral();

    assert!(!manager.dirty_peers.contains(&TARGET), "resynced once");
    assert!(!manager.pending_group_admitted.contains_key(&TARGET));
    assert_route_precedes_marker(&mut output, "group member resynced under the gate");
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(output.try_recv().is_err(), "no second table");
    assert!(!manager.resync_tick_pending());
}

/// The same for a receiver a second deferred family keeps dirty: the
/// release pass resyncs it for the released family, whose marker follows
/// in the release turn, and it is not woken for that family again.
#[tokio::test(start_paused = true)]
async fn a_dirty_peer_held_by_another_family_gets_the_released_marker_once() {
    let (mut manager, mut outputs) = late_armed_gate(&[V4, V6], &[(TARGET, 2, &[V4, V6])]);
    let mut output = outputs.remove(0);
    manager.mark_outbound_dirty(TARGET);
    manager.resync_dirty_peers_bounded();
    assert!(manager.dirty_peers.contains(&TARGET), "held by both gates");
    while output.try_recv().is_ok() {}

    source_end_of_rib(&mut manager, V4);

    assert!(manager.selection_convergence_held(V6));
    assert_route_precedes_marker(&mut output, "dirty for IPv6");
    assert!(manager.dirty_peers.contains(&TARGET), "kept for IPv6");
    assert_eq!(manager.eor_pending(TARGET), HashSet::from([V6]));
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(output.try_recv().is_err(), "no second partial resync");
}

/// A session whose IPv4 is behind the RFC 5291 §6 gate (it negotiated ORF
/// receive and has not refreshed), with its first End-of-RIB already sent.
fn orf_gated(manager: &mut RibManager) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, mut output) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer: TARGET,
        session_id: 2,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![V4],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![V4],
        negotiated_llgr_families: vec![],
    });
    assert!(manager.peer_orf_pending[&TARGET].contains(&V4));
    assert_eq!(
        markers_of(&mut output, V4),
        1,
        "the honest-empty marker is immediate"
    );
    output
}

/// A marker of a family still behind the ORF gate, with no hold of its own
/// and no refused send, is what the tick would wait on until the peer
/// refreshes. The peer's ROUTE-REFRESH is the release: it lifts the gate,
/// and the marker follows its answer's table in that turn.
#[test]
fn a_refresh_releases_the_marker_of_an_orf_gated_family() {
    let mut manager = plain_manager();
    let mut output = orf_gated(&mut manager);
    manager.owe_eor(TARGET, V4);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: TARGET,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    assert!(
        !manager.peer_orf_pending.contains_key(&TARGET),
        "the gate lifted"
    );
    assert_eq!(markers_of(&mut output, V4), 1);
    assert!(!manager.eor.owes(TARGET, V4));
    assert!(!manager.resync_tick_pending());
}

/// The check after an actor turn is stricter than the fallback about that
/// gate: the tick waits for it, so a marker left behind it would stay
/// invisible until the peer refreshed. A release sends such a marker at
/// once, so the check rejects one that was not sent.
#[test]
#[should_panic(expected = "is owed with no hold and was not sent")]
fn the_end_of_turn_check_rejects_an_unsent_marker_behind_the_orf_gate() {
    let mut manager = plain_manager();
    let _output = orf_gated(&mut manager);
    manager.owe_eor(TARGET, V4);
    manager.handle_update(RibUpdate::RetireEorGraceInterface {
        interface: "swp9".into(),
    });
}

/// The fallback itself keeps the tick's rule: it does not send a marker
/// while its family is behind the gate.
#[test]
fn the_tick_fallback_waits_for_the_orf_gate() {
    let mut manager = plain_manager();
    let mut output = orf_gated(&mut manager);
    manager.eor.allow_unsettled = true;
    manager.owe_eor(TARGET, V4);
    manager.resync_dirty_peers_bounded();
    assert_eq!(markers_of(&mut output, V4), 0);
    assert_eq!(manager.eor.unsettled_tick_finds, 0);
    assert!(manager.eor.owes(TARGET, V4));
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
    manager.eor.allow_unsettled = true;
    manager.owe_eor(TARGET, V4);
    assert!(manager.resync_tick_pending());
    manager.resync_dirty_peers_bounded();
    assert_eq!(output.try_recv().unwrap().end_of_rib, [V4]);
    assert_eq!(manager.eor.unsettled_tick_finds, 1);
    assert!(!manager.eor.owes(TARGET, V4));
    assert!(!manager.resync_tick_pending());
}

/// Without the opt-in, a test build fails as soon as the fallback finds a
/// marker, so a test that drives ticks directly cannot pass through it.
#[test]
#[should_panic(expected = "was left to the resync tick")]
fn the_tick_fallback_fails_a_test_that_did_not_opt_in() {
    let mut manager = plain_manager();
    let _output = connect(&mut manager, TARGET, 2, V4);
    manager.owe_eor(TARGET, V4);
    manager.retry_eor_markers_bounded();
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
    assert_eq!(manager.eor.unsettled_tick_finds, 0);
}

/// The fallback reports a marker it finds whether or not the writer takes
/// it: a refused send becomes an ordinary retry, which is not reported
/// again.
#[test]
fn the_tick_reports_an_unsettled_marker_even_when_the_writer_refuses_it() {
    let mut manager = plain_manager();
    let mut output = connect(&mut manager, TARGET, 2, V4);
    while output.try_recv().is_ok() {}
    manager.eor.allow_unsettled = true;
    manager.owe_eor(TARGET, V4);
    let sender = manager.outbound_peers[&TARGET].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.retry_eor_markers_bounded();
    assert_eq!(manager.eor.unsettled_tick_finds, 1);
    assert!(manager.eor_holds(TARGET, V4).contains(EorHold::Writer));
    while output.try_recv().is_ok() {}
    manager.retry_eor_markers_bounded();
    assert_eq!(output.try_recv().unwrap().end_of_rib, [V4]);
    assert_eq!(
        manager.eor.unsettled_tick_finds, 1,
        "the retry is not reported"
    );
}
