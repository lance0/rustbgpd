//! An End-of-RIB hold release (the planned-restart grace window, the
//! RT-Constrain membership hold, the ORF cap, a pass's deferred settle)
//! stages no routes. It sends the markers whose family owes nothing; a
//! family still owed to a receiver keeps its marker for the resync tick's
//! owed-key drain, which reads the receiver's credit and sends one family
//! per step, the table and then its End-of-RIB.

use std::collections::BTreeSet;

use super::*;
use crate::manager::slice_timing::checkpoints;
use crate::update::OutboundRouteUpdate;
use crate::{EorGraceConfig, EorGracePeerConfig};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const VPN: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const RTC: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);
const FLOWSPEC: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
/// (receivers, rows owed to each).
const SHAPES: [(u8, u16); 4] = [(8, 50), (32, 50), (8, 200), (32, 200)];

fn receiver(index: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 9, 0, index + 1)
}

fn row(index: u16) -> Ipv4Prefix {
    let [high, low] = index.to_be_bytes();
    Ipv4Prefix::new(Ipv4Addr::new(10, 20 + high, low, 0), 24)
}

/// Register a GR-helper session; `private` gives it an export chain of its
/// own, so it holds its families in its own Adj-RIB-Out.
fn up(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    families: &[(Afi, Safi)],
    orf: &[(Afi, Safi)],
    private: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let export_policy = private.then(|| {
        let mut chain =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let entry = &mut chain.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![u32::MAX],
            peer_groups: vec![],
        });
        rustbgpd_policy::PolicyChain::from_named(chain.policies)
    });
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(4096);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy,
        sendable_families: families.to_vec(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: orf.to_vec(),
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

type Receivers = Vec<(PeerId, mpsc::Receiver<OutboundRouteUpdate>)>;

struct Setup {
    /// What each receiver negotiates.
    families: Vec<(Afi, Safi)>,
    /// The receivers' ORF-gated families.
    orf: Vec<(Afi, Safi)>,
    /// The families the selection hold defers.
    waiter_families: Vec<(Afi, Safi)>,
    /// A planned-restart grace window covers `FAMILY` toward each receiver.
    grace: bool,
    /// The source also sends one `FlowSpec` rule per row.
    flowspec_rules: bool,
}

impl Setup {
    fn of(families: &[(Afi, Safi)]) -> Self {
        Self {
            families: families.to_vec(),
            orf: vec![],
            waiter_families: vec![FAMILY],
            grace: false,
            flowspec_rules: false,
        }
    }
}

/// A manager inside its selection hold with `rows` unicast rows (and
/// rules) from the source and `count` private receivers that joined under
/// the hold.
fn build(setup: &Setup, count: u8, rows: u16) -> (RibManager, Receivers) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER).into(),
                families: setup.waiter_families.clone(),
            }],
        });
    if setup.grace {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        manager = manager.with_eor_grace(EorGraceConfig {
            peers: (0..count)
                .map(|index| EorGracePeerConfig {
                    peer: peer_v4(receiver(index)).into(),
                    deadline,
                    families: vec![FAMILY],
                })
                .collect(),
            replay_owners: vec!["ctl".into()],
        });
    }
    super::arm_selection_waiter(&mut manager, peer_v4(WAITER), &setup.waiter_families);
    std::mem::forget(up(
        &mut manager,
        SOURCE,
        0,
        &[FAMILY, V6, FLOWSPEC],
        &[],
        false,
    ));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: (0..rows)
            .map(|index| make_route_with_lp(row(index), SOURCE, 100))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: if setup.flowspec_rules {
            (0..rows)
                .map(|index| {
                    let mut rule = crate::test_support::make_flowspec_route(SOURCE);
                    rule.rule.components =
                        vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                            rustbgpd_wire::FlowSpecPrefix::V4(row(index)),
                        )];
                    rule
                })
                .collect()
        } else {
            vec![]
        },
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let receivers = (0..count)
        .map(|index| {
            if !setup.orf.is_empty() {
                // A helper session that ended: the peer may hold our routes
                // stale, which arms the ORF End-of-RIB cap next session.
                let old = u64::from(index) + 101;
                drop(up(
                    &mut manager,
                    receiver(index),
                    old,
                    &setup.families,
                    &setup.orf,
                    true,
                ));
                manager.handle_update(RibUpdate::PeerDown {
                    peer: peer_v4(receiver(index)),
                    session_id: old,
                });
            }
            let mut rx = up(
                &mut manager,
                receiver(index),
                u64::from(index) + 1,
                &setup.families,
                &setup.orf,
                true,
            );
            let peer = peer_v4(receiver(index));
            assert!(manager.grouped_member_of(peer).is_none(), "private");
            while rx.try_recv().is_ok() {}
            (peer, rx)
        })
        .collect();
    (manager, receivers)
}

/// The deferral timer releases `families`, in this order, in one turn. The
/// order of a real expiry comes from a hash map; here it is fixed.
fn timer_releases(manager: &mut RibManager, families: &[(Afi, Safi)]) {
    use crate::manager::selection_deferral::SelectionDeferralTransition::{Release, Stage};
    let order = |transition: &_| match transition {
        Release { family, .. } => families.iter().position(|released| released == family),
        Stage { .. } => None,
    };
    let mut transitions = manager.selection_deferral.as_ref().unwrap().expire();
    transitions.retain(|transition| order(transition).is_some());
    transitions.sort_by_key(order);
    assert_eq!(transitions.len(), families.len());
    manager.apply_selection_deferral_transitions(transitions, "Selection_Deferral_Timer expired");
    manager.settle_eor_after_pass();
}

/// [`build`], then the selection hold released: every receiver owes
/// `FAMILY` whole and nothing was sent to it.
fn released(setup: &Setup, count: u8, rows: u16) -> (RibManager, Receivers) {
    let (mut manager, mut receivers) = build(setup, count, rows);
    timer_releases(&mut manager, &setup.waiter_families);
    for (peer, rx) in &mut receivers {
        assert!(manager.owes(*peer, FAMILY), "owed at the selection release");
        assert!(
            rx.try_recv().is_err(),
            "nothing sent at the selection release"
        );
    }
    (manager, receivers)
}

/// What one receiver's session has written. Writing asserts that no route
/// of a family follows that family's End-of-RIB.
#[derive(Default)]
struct Wire {
    table: BTreeSet<Prefix>,
    rows: usize,
    rules: usize,
    markers: Vec<(Afi, Safi)>,
}

impl Wire {
    fn write(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv().map(delivered) {
            for route in update.announce.iter() {
                if matches!(route.prefix, Prefix::V4(_)) {
                    assert_eq!(self.markers(FAMILY), 0, "a route followed its End-of-RIB");
                }
                self.table.insert(route.prefix);
                self.rows += 1;
            }
            if !update.flowspec_announce.is_empty() {
                assert_eq!(self.markers(FLOWSPEC), 0, "a rule followed its End-of-RIB");
                self.rules += update.flowspec_announce.len();
            }
            self.markers.extend(update.end_of_rib.iter().copied());
        }
    }

    fn markers(&self, family: (Afi, Safi)) -> usize {
        self.markers.iter().filter(|sent| **sent == family).count()
    }
}

fn write_all(receivers: &mut Receivers, wires: &mut [Wire]) {
    for ((_, rx), wire) in receivers.iter_mut().zip(wires.iter_mut()) {
        wire.write(rx);
    }
}

/// Run resync ticks, each session writing what it was sent, until no
/// resync work is left.
fn drain(manager: &mut RibManager, receivers: &mut Receivers, wires: &mut [Wire]) {
    for _ in 0..8 * receivers.len() + 8 {
        manager.resync_dirty_peers_bounded();
        write_all(receivers, wires);
    }
    assert!(!manager.resync_tick_pending(), "the drain left work");
}

/// Every receiver holds `rows` rows, each sent once, then one End-of-RIB,
/// and owes nothing.
fn assert_delivered(
    manager: &RibManager,
    receivers: &[(PeerId, mpsc::Receiver<OutboundRouteUpdate>)],
    wires: &[Wire],
    rows: u16,
) {
    for ((peer, _), wire) in receivers.iter().zip(wires) {
        assert_eq!(wire.table.len(), usize::from(rows), "{peer}: the table");
        assert_eq!(wire.rows, usize::from(rows), "{peer}: each row once");
        assert_eq!(wire.markers(FAMILY), 1, "{peer}: one End-of-RIB");
        assert!(manager.owing(*peer).is_none(), "{peer}: nothing owed");
        assert!(!manager.eor_pending(*peer).contains(&FAMILY), "{peer}");
        assert!(!manager.dirty_peers.contains(peer), "{peer}");
    }
}

/// Spend `peer`'s row credit; the charge holds it until dropped.
fn spend(manager: &mut RibManager, peer: PeerId) -> crate::OutboundCharge {
    crate::OutboundCharge::new(
        &manager.outbound_credit_handle(peer),
        manager.outbound_row_credit(),
    )
}

/// One hold release, checked at the four shapes and with a receiver whose
/// credit is spent. `prepare` builds the state `release` runs in; the
/// release frees `FAMILY`'s End-of-RIB toward receiver 0 at least, and
/// sends it `in_turn`, the markers whose family owes nothing.
///
/// - The release turn puts no row on any receiver's channel and every
///   receiver still owes the family.
/// - The work of the release turn grows by the same number of checkpoints
///   from 8 to 32 receivers at 50 rows as at 200: nothing in it is per row.
/// - The ticks after it give every receiver its table and then one
///   End-of-RIB, and leave nothing owed or pending.
/// - A receiver with spent credit is sent nothing by the release or the
///   ticks, and is delivered once its credit returns.
fn release_leaves_owed_families_to_the_drain(
    prepare: impl Fn(u8, u16) -> (RibManager, Receivers),
    release: impl Fn(&mut RibManager, &[PeerId]),
    in_turn: &[(Afi, Safi)],
) {
    let mut work = vec![];
    for (count, rows) in SHAPES {
        let case = format!("{count} receivers, {rows} rows");
        let (mut manager, mut receivers) = prepare(count, rows);
        let peers: Vec<PeerId> = receivers.iter().map(|(peer, _)| *peer).collect();
        let mut wires: Vec<Wire> = peers.iter().map(|_| Wire::default()).collect();
        let before: usize = checkpoints().values().sum();
        release(&mut manager, &peers);
        work.push(checkpoints().values().sum::<usize>() - before);
        write_all(&mut receivers, &mut wires);
        for (peer, wire) in peers.iter().zip(&wires) {
            assert_eq!(
                wire.rows + wire.rules,
                0,
                "{case}: rows in the release turn"
            );
            assert_eq!(
                wire.markers(FAMILY),
                0,
                "{case}: End-of-RIB before its table"
            );
            assert!(manager.owes(*peer, FAMILY), "{case}: still owed");
            assert!(!manager.dirty_peers.contains(peer), "{case}");
        }
        assert_eq!(
            wires[0].markers, in_turn,
            "{case}: markers that owe nothing"
        );
        drain(&mut manager, &mut receivers, &mut wires);
        assert_delivered(&manager, &receivers, &wires, rows);
    }
    assert_eq!(
        work[1] - work[0],
        work[3] - work[2],
        "24 more receivers cost the release turn the same at 50 rows as at 200: {work:?}"
    );

    let (mut manager, mut receivers) = prepare(4, 50);
    let peers: Vec<PeerId> = receivers.iter().map(|(peer, _)| *peer).collect();
    let mut wires: Vec<Wire> = peers.iter().map(|_| Wire::default()).collect();
    let charge = spend(&mut manager, peers[0]);
    release(&mut manager, &peers);
    for _ in 0..8 {
        write_all(&mut receivers, &mut wires);
        assert_eq!(wires[0].rows, 0, "spent credit: no row");
        assert_eq!(wires[0].markers(FAMILY), 0, "spent credit: no End-of-RIB");
        manager.resync_dirty_peers_bounded();
    }
    assert!(manager.owes(peers[0], FAMILY));
    assert!(!manager.dirty_peers.contains(&peers[0]));
    drop(charge);
    drain(&mut manager, &mut receivers, &mut wires);
    assert_delivered(&manager, &receivers, &wires, 50);
}

fn grace() -> Setup {
    Setup {
        grace: true,
        ..Setup::of(&[FAMILY])
    }
}

fn replay_complete(manager: &mut RibManager) {
    let incarnation = manager.injection_leases.incarnation();
    let result = manager.mark_replay_complete("ctl", incarnation).unwrap();
    assert_eq!(result, crate::manager::eor_grace::ReplayComplete::Released);
}

/// Every grace window ends together when the listed controller signals
/// replay complete. Red when the release absorbs: the turn sends receivers
/// times rows, a spent-credit receiver included.
#[test]
fn grace_replay_complete_leaves_owed_families_to_the_drain() {
    let setup = grace();
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, _| replay_complete(manager),
        &[],
    );
}

/// Every grace window ends together at the shared deadline.
#[test]
fn grace_deadline_leaves_owed_families_to_the_drain() {
    let setup = grace();
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, _| {
            manager.expire_eor_grace(tokio::time::Instant::now() + Duration::from_secs(31));
            assert!(!manager.eor_grace_open());
        },
        &[],
    );
}

/// A grace window that ends after the drain already delivered the family
/// sends the End-of-RIB in the release turn: a marker whose family owes
/// nothing is not left for a tick.
#[test]
fn a_grace_release_sends_a_marker_whose_family_owes_nothing_at_once() {
    let (mut manager, mut receivers) = released(&grace(), 4, 50);
    let mut wires: Vec<Wire> = receivers.iter().map(|_| Wire::default()).collect();
    drain(&mut manager, &mut receivers, &mut wires);
    for ((peer, _), wire) in receivers.iter().zip(&wires) {
        assert_eq!(wire.rows, 50, "the drain delivers under the grace window");
        assert_eq!(wire.markers(FAMILY), 0, "the window holds the End-of-RIB");
        assert!(!manager.owes(*peer, FAMILY));
    }
    replay_complete(&mut manager);
    write_all(&mut receivers, &mut wires);
    assert_delivered(&manager, &receivers, &wires, 50);
}

/// A grace release's `pending_families` lists a held family whose
/// End-of-RIB stayed behind: one the selection gate still holds with
/// nothing owed, and one whose table is still owed; a family whose marker
/// left is not listed.
#[test]
fn a_grace_release_lists_held_and_owed_families_as_pending() {
    use rustbgpd_telemetry::reason_labels::GrEorGraceReleaseReason::Deadline;
    let release = |manager: &mut RibManager, peer| {
        manager
            .release_eor_grace_peer(&crate::EorGraceTarget::Peer(peer), Deadline)
            .2
    };
    let (mut manager, receivers) = build(&grace(), 1, 50);
    let peer = receivers[0].0;
    assert!(manager.owing(peer).is_none(), "nothing owed under the gate");
    assert_eq!(release(&mut manager, peer), "ipv4_unicast", "still held");

    let (mut manager, receivers) = released(&grace(), 1, 50);
    let peer = receivers[0].0;
    assert_eq!(release(&mut manager, peer), "ipv4_unicast", "still owed");

    let (mut manager, mut receivers) = released(&grace(), 1, 50);
    let mut wires = vec![Wire::default()];
    drain(&mut manager, &mut receivers, &mut wires);
    let peer = receivers[0].0;
    assert_eq!(release(&mut manager, peer), "", "the marker left");
    write_all(&mut receivers, &mut wires);
    assert_eq!(wires[0].markers(FAMILY), 1);
}

/// The RT-Constrain membership cap passes for every held receiver: the
/// VPN End-of-RIB it held leaves in that turn, the owed unicast family
/// does not.
#[test]
fn rt_membership_cap_leaves_owed_families_to_the_drain() {
    let setup = Setup::of(&[FAMILY, VPN, RTC]);
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, peers| {
            for peer in peers {
                assert!(manager.eor.rt_membership_held(*peer));
            }
            manager.expire_eor_holds(tokio::time::Instant::now() + Duration::from_secs(61));
        },
        &[VPN],
    );
}

/// One receiver's own RT-Constrain End-of-RIB ends its membership hold.
#[test]
fn rt_constrain_end_of_rib_leaves_owed_families_to_the_drain() {
    let setup = Setup::of(&[FAMILY, VPN, RTC]);
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, peers| {
            manager.handle_update(RibUpdate::EndOfRib {
                peer: peers[0],
                session_id: 1,
                afi: RTC.0,
                safi: RTC.1,
            });
        },
        &[VPN],
    );
}

/// Receivers under the RT-Constrain membership hold that sent their
/// RT-Constrain End-of-RIB while RT-Constrain selection was deferred, with
/// selection held for unicast and RT-Constrain.
fn rt_membership_complete_under_deferral(count: u8, rows: u16) -> (RibManager, Receivers) {
    let setup = Setup {
        waiter_families: vec![FAMILY, RTC],
        ..Setup::of(&[FAMILY, VPN, RTC])
    };
    let (mut manager, receivers) = build(&setup, count, rows);
    for (index, (peer, _)) in receivers.iter().enumerate() {
        assert!(manager.eor.rt_membership_held(*peer), "hold armed");
        manager.handle_update(RibUpdate::EndOfRib {
            peer: *peer,
            session_id: index as u64 + 1,
            afi: RTC.0,
            safi: RTC.1,
        });
        assert!(manager.eor.rt_membership_held(*peer), "ends at the release");
    }
    (manager, receivers)
}

/// One timer turn releases unicast and then RT-Constrain: the membership
/// holds end after the unicast family was owed. Red when the membership
/// release absorbs it.
#[test]
fn rt_membership_release_after_the_owed_family_in_one_turn() {
    release_leaves_owed_families_to_the_drain(
        rt_membership_complete_under_deferral,
        |manager, _| timer_releases(manager, &[FAMILY, RTC]),
        &[VPN],
    );
}

/// The other timer order: RT-Constrain, then unicast.
#[test]
fn rt_membership_release_before_the_owed_family_in_one_turn() {
    release_leaves_owed_families_to_the_drain(
        rt_membership_complete_under_deferral,
        |manager, _| timer_releases(manager, &[RTC, FAMILY]),
        &[VPN],
    );
}

/// Unicast is released in one turn and RT-Constrain in a later one, before
/// any drain tick ran.
#[test]
fn rt_membership_release_in_a_later_turn_leaves_owed_families_to_the_drain() {
    release_leaves_owed_families_to_the_drain(
        |count, rows| {
            let (mut manager, receivers) = rt_membership_complete_under_deferral(count, rows);
            timer_releases(&mut manager, &[FAMILY]);
            (manager, receivers)
        },
        |manager, _| timer_releases(manager, &[RTC]),
        &[VPN],
    );
}

/// The ORF cap passes for every receiver: the gated IPv6 End-of-RIB leaves
/// in that turn (its table waits for a refresh and owes nothing), the owed
/// IPv4 family does not.
#[test]
fn orf_cap_leaves_owed_families_to_the_drain() {
    let setup = Setup {
        orf: vec![V6],
        ..Setup::of(&[FAMILY, V6])
    };
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, peers| {
            for peer in peers {
                assert!(manager.orf_eor_hold.contains_key(peer), "ORF cap armed");
                assert!(manager.eor_behind_orf_table(*peer).contains(&V6));
            }
            manager.expire_eor_holds(tokio::time::Instant::now() + Duration::from_secs(61));
        },
        &[V6],
    );
}

/// The settle a pass defers to its end, for every receiver in one call.
#[test]
fn a_deferred_settle_leaves_owed_families_to_the_drain() {
    let setup = Setup::of(&[FAMILY]);
    release_leaves_owed_families_to_the_drain(
        |count, rows| released(&setup, count, rows),
        |manager, peers| {
            for peer in peers {
                manager.defer_eor_settle(*peer);
            }
            manager.settle_eor_after_pass();
        },
        &[],
    );
}

/// A receiver owed two whole families takes two drain steps, one family
/// and its End-of-RIB each, and a step reads the receiver's credit first.
/// Red when a step absorbs every owed family behind one credit read (both
/// families arrive in the first step), and when the step skips the credit
/// read (the stalled receiver is sent its families).
#[test]
fn a_drain_step_sends_one_owed_family_after_a_credit_read() {
    let setup = Setup {
        waiter_families: vec![FAMILY, FLOWSPEC],
        flowspec_rules: true,
        ..Setup::of(&[FAMILY, FLOWSPEC])
    };
    let (mut manager, mut receivers) = released(&setup, 2, 50);
    let (stalled, healthy) = (receivers[0].0, receivers[1].0);
    assert!(manager.owes(healthy, FLOWSPEC) && manager.owes(stalled, FLOWSPEC));
    // One receiver step per tick.
    manager.flush_poll_budget = Duration::ZERO;
    let charge = spend(&mut manager, stalled);
    let mut wires: Vec<Wire> = receivers.iter().map(|_| Wire::default()).collect();
    let mut steps = vec![];
    for _ in 0..6 {
        let before = (wires[1].rows, wires[1].rules, wires[1].markers.len());
        manager.resync_dirty_peers_bounded();
        write_all(&mut receivers, &mut wires);
        let step = (
            wires[1].rows - before.0,
            wires[1].rules - before.1,
            wires[1].markers.len() - before.2,
        );
        if step != (0, 0, 0) {
            steps.push(step);
        }
    }
    steps.sort_unstable();
    assert_eq!(
        steps,
        vec![(0, 50, 1), (50, 0, 1)],
        "one family and its End-of-RIB per step"
    );
    assert_eq!(wires[1].markers(FAMILY), 1);
    assert_eq!(wires[1].markers(FLOWSPEC), 1);
    assert!(manager.owing(healthy).is_none());
    assert_eq!(wires[0].rows + wires[0].rules, 0, "spent credit: nothing");
    assert_eq!(wires[0].markers, []);
    assert!(manager.owes(stalled, FAMILY) && manager.owes(stalled, FLOWSPEC));
    drop(charge);
    drain(&mut manager, &mut receivers, &mut wires);
    assert_delivered(&manager, &receivers, &wires, 50);
    assert_eq!(wires[0].rules, 50);
    assert_eq!(wires[0].markers(FLOWSPEC), 1);
}

/// The step that absorbs a family for its End-of-RIB sends nothing of the
/// receiver's other owed family, here one keyed IPv6 route, which needs no
/// operation of its own and goes out in the next step. Red when the step
/// goes on to the next family after the absorption.
#[test]
fn a_drain_step_that_absorbs_a_family_leaves_a_keyed_family_for_the_next() {
    use crate::manager::outbound_owing::OwedFamily;
    let (mut manager, mut receivers) = released(&Setup::of(&[FAMILY, V6]), 1, 50);
    manager.flush_poll_budget = Duration::ZERO;
    let peer = receivers[0].0;
    let charge = spend(&mut manager, peer);
    let mut route = crate::test_support::make_v6_route(
        Ipv6Prefix::new("2001:db8:7::".parse().unwrap(), 48),
        "2001:db8::1".parse().unwrap(),
    );
    route.peer = peer_v4(SOURCE);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(manager.owed_key_count(peer, OwedFamily::IPV6_UNICAST), 1);
    drop(charge);
    let mut wires = vec![Wire::default()];
    manager.resync_dirty_peers_bounded();
    write_all(&mut receivers, &mut wires);
    assert_eq!(wires[0].rows, 50, "the absorbed family alone");
    assert_eq!(wires[0].markers, [FAMILY]);
    assert_eq!(manager.owed_key_count(peer, OwedFamily::IPV6_UNICAST), 1);
    manager.resync_dirty_peers_bounded();
    write_all(&mut receivers, &mut wires);
    assert_eq!(wires[0].rows, 51, "the keyed route in the next step");
    assert!(manager.owing(peer).is_none());
}

/// Between a grace release and a receiver's drain step the receiver flaps,
/// is marked dirty, or refreshes the owed family: each still ends with the
/// table once and then one End-of-RIB (a refresh adds its own answer).
#[test]
fn a_receiver_that_changes_before_its_step_still_gets_table_then_end_of_rib() {
    for event in ["flap", "dirty", "refresh"] {
        let (mut manager, mut receivers) = released(&grace(), 2, 50);
        replay_complete(&mut manager);
        let peer = receivers[0].0;
        let mut wires: Vec<Wire> = receivers.iter().map(|_| Wire::default()).collect();
        match event {
            "flap" => {
                manager.handle_update(RibUpdate::PeerDown {
                    peer,
                    session_id: 1,
                });
                assert!(
                    manager.owing(peer).is_none(),
                    "the debt ends with the session"
                );
                receivers[0].1 = up(&mut manager, receiver(0), 9, &[FAMILY], &[], true);
            }
            "dirty" => {
                manager.mark_outbound_dirty(peer);
            }
            _ => {
                manager.handle_update(RibUpdate::RouteRefreshRequest {
                    queued: Arc::default(),
                    peer,
                    session_id: 1,
                    afi: FAMILY.0,
                    safi: FAMILY.1,
                });
                // The owed table and its End-of-RIB, then the answer.
                let sent: Vec<_> = std::iter::from_fn(|| receivers[0].1.try_recv().ok())
                    .map(delivered)
                    .map(|update| (update.announce.iter().count(), update.end_of_rib.clone()))
                    .collect();
                assert_eq!(sent[..2], [(50, vec![]), (0, vec![FAMILY])], "{event}");
                assert_eq!(sent[2].0, 50, "{event}: the answer");
                assert!(!manager.owes(peer, FAMILY));
            }
        }
        drain(&mut manager, &mut receivers, &mut wires);
        if event == "refresh" {
            assert!(
                wires[0].rows == 0 && wires[0].markers.is_empty(),
                "no repeat"
            );
            assert_delivered(&manager, &receivers[1..], &wires[1..], 50);
        } else {
            assert_delivered(&manager, &receivers, &wires, 50);
        }
    }
}
