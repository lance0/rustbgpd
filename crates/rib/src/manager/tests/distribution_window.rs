//! Cross-message distribution windows: already-queued unicast-only
//! `RoutesReceived` messages share one outbound pass (RFC 4271 Appendix F.1).
//!
//! Each oracle scenario runs three ways: grouped with the input queued, the
//! per-peer path (`test_force_ungrouped`) with the same queued input, and
//! grouped with a FIFO barrier after every message so no window forms. The
//! grouped and per-peer sides must agree, and the coalesced run must reach
//! the same final advertised state as the one-pass-per-message reference.

use rustbgpd_wire::{Afi, Safi};

use super::exportability::MockExactExportEncoder;
use super::update_groups_oracle::{
    NormMsg, Oracle, SESSION, Streams, deny_prefix_chain, fold, ibgp_route, pcb_peer_up, pfx,
    ranked, rs_route,
};
use super::*;
use crate::manager::distribution::DistributionWindowLimits;
use crate::update::ExactExportKey;

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const CLUSTER: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 0, 2, 1));

/// A distinct /24 per `(a, b)`: `10.(210 + b).a.0/24`. ([`pfx`] masks its
/// second argument away, so `pfx(a, 1)` and `pfx(a, 2)` are one prefix.)
fn window_pfx(a: u8, b: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 210 + b, a, 0), 24)
}

/// Window limits with every bound out of reach.
fn unbounded() -> DistributionWindowLimits {
    DistributionWindowLimits {
        messages: usize::MAX,
        routes: usize::MAX,
        affected_prefixes: usize::MAX,
        elapsed: Duration::MAX,
    }
}

/// Take the wall-clock bound out of play so a test's window shape never
/// depends on how long the host takes to run it. Only the elapsed-bound
/// case of [`each_window_bound_splits_queued_input`] exercises that bound,
/// with a zero limit that always fires.
pub(super) fn untimed_window(manager: &mut RibManager) {
    manager.distribution_window_limits.elapsed = Duration::MAX;
}

fn routes(from: Ipv4Addr, announced: Vec<Route>, withdrawn: Vec<Ipv4Prefix>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: SESSION,
        peer: IpAddr::V4(from),
        announced,
        withdrawn: withdrawn
            .into_iter()
            .map(|prefix| (Prefix::V4(prefix), 0))
            .collect(),
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    }
}

/// Grouped-queued, per-peer-queued and grouped-sequential streams.
async fn run_three<S>(cluster_id: Option<Ipv4Addr>, scenario: S) -> (Streams, Streams, Streams)
where
    S: AsyncFn(&mut Oracle),
{
    let mut queued = Oracle::spawn_configured(false, cluster_id, untimed_window);
    scenario(&mut queued).await;
    let queued = queued.finish().await;
    let mut ungrouped = Oracle::spawn_configured(true, cluster_id, untimed_window);
    scenario(&mut ungrouped).await;
    let ungrouped = ungrouped.finish().await;
    let mut sequential = Oracle::spawn_configured(false, cluster_id, untimed_window).sequential();
    scenario(&mut sequential).await;
    let sequential = sequential.finish().await;
    (queued, ungrouped, sequential)
}

/// A member's route-bearing messages (setup `EoR` markers excluded).
fn route_messages(streams: &Streams, member: Ipv4Addr) -> Vec<&NormMsg> {
    streams[&IpAddr::V4(member)]
        .iter()
        .filter(|msg| !msg.announce.is_empty() || !msg.withdraw.is_empty())
        .collect()
}

fn route_message_count(streams: &Streams) -> usize {
    streams
        .keys()
        .map(|peer| match peer {
            IpAddr::V4(peer) => route_messages(streams, *peer).len(),
            IpAddr::V6(_) => unreachable!("oracle members are IPv4"),
        })
        .sum()
}

fn announced(msg: &NormMsg) -> BTreeSet<Prefix> {
    msg.announce.iter().map(|entry| entry.0).collect()
}

fn assert_coalesced_equivalence(queued: &Streams, ungrouped: &Streams, sequential: &Streams) {
    assert_eq!(
        fold(queued),
        fold(ungrouped),
        "grouped and per-peer paths must agree on coalesced input"
    );
    assert_eq!(
        fold(queued),
        fold(sequential),
        "a coalesced window must reach the one-pass-per-message final state"
    );
    assert!(
        route_message_count(queued) < route_message_count(sequential),
        "queued input must share distribution passes"
    );
}

/// Announce, withdraw and re-announce of one prefix across queued messages
/// collapses to its final state: each member sees ONE route message with
/// the final attributes and no transient withdrawal.
#[tokio::test]
async fn queued_announce_withdraw_announce_distributes_final_state_once() {
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 64).await;
        o.queue(vec![
            routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![]),
            routes(A, vec![], vec![pfx(1, 0)]),
            routes(A, vec![ibgp_route(pfx(1, 0), A, 150, vec![])], vec![]),
            routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![]),
        ])
        .await;
    };
    let (queued, ungrouped, sequential) = run_three(CLUSTER, scenario).await;
    assert_eq!(queued, ungrouped, "grouped and per-peer streams must match");
    assert_coalesced_equivalence(&queued, &ungrouped, &sequential);
    for member in [B, C] {
        let messages = route_messages(&queued, member);
        assert_eq!(messages.len(), 1, "one window, one message to {member}");
        assert!(messages[0].withdraw.is_empty(), "no transient withdrawal");
        assert_eq!(
            announced(messages[0]),
            BTreeSet::from([Prefix::V4(pfx(1, 0)), Prefix::V4(pfx(2, 0))])
        );
        let p1 = messages[0]
            .announce
            .iter()
            .find(|entry| entry.0 == Prefix::V4(pfx(1, 0)))
            .unwrap();
        assert!(p1.4.contains(&PathAttribute::LocalPref(150)));
        assert_eq!(route_messages(&sequential, member).len(), 4);
    }
}

/// Several sources displace each other's best inside one window on a
/// per-client-best group: a promotion (source flip) and a flip back.
#[tokio::test]
async fn queued_source_flips_on_per_client_best_group_match_oracle() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        o.queue(vec![
            routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]),
            routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]),
            routes(C, vec![ranked(pfx(2, 0), C, 2)], vec![]),
            // Promotion: A's best withdraws, B's runner-up takes over.
            routes(A, vec![], vec![pfx(1, 0)]),
            // B displaces C on p2.
            routes(B, vec![ranked(pfx(2, 0), B, 1)], vec![]),
            // Flip back to A on p1.
            routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]),
        ])
        .await;
    };
    let (queued, ungrouped, sequential) = run_three(None, scenario).await;
    assert_coalesced_equivalence(&queued, &ungrouped, &sequential);
}

/// A window mixing untagged routes with an RFC 7947 control-tagged route
/// and a tag-only transition is one tagged pass for the rs-control members:
/// the steered-away targets never receive the tagged route.
#[tokio::test]
async fn queued_tagged_rs_control_window_matches_oracle() {
    // Oracle eBGP members all have ASN 65010; `0:65010` means "do not
    // announce to 65010".
    const RS_AS: u32 = 65000;
    let steer = 65_010;
    let scenario = async |o: &mut Oracle| {
        o.set_rs_control(A, RS_AS).await;
        o.peer_up(A, true, false, None, 64).await;
        o.set_rs_control(B, RS_AS).await;
        o.peer_up(B, true, false, None, 64).await;
        o.peer_up(C, true, false, None, 64).await;
        o.queue(vec![
            routes(C, vec![rs_route(pfx(1, 0), C, vec![65010], vec![])], vec![]),
            routes(
                C,
                vec![rs_route(pfx(2, 0), C, vec![65010], vec![steer])],
                vec![],
            ),
            routes(C, vec![rs_route(pfx(3, 0), C, vec![65010], vec![])], vec![]),
            // Tag-only transitions: p2 loses its tag, p1 gains one.
            routes(C, vec![rs_route(pfx(2, 0), C, vec![65010], vec![])], vec![]),
            routes(
                C,
                vec![rs_route(pfx(1, 0), C, vec![65010], vec![steer])],
                vec![],
            ),
        ])
        .await;
    };
    let (queued, ungrouped, sequential) = run_three(None, scenario).await;
    assert_eq!(queued, ungrouped, "grouped and per-peer streams must match");
    assert_coalesced_equivalence(&queued, &ungrouped, &sequential);
    let folded = fold(&queued);
    for member in [A, B] {
        let table = &folded[&IpAddr::V4(member)];
        assert!(!table.contains_key(&(Prefix::V4(pfx(1, 0)), 0)));
        assert!(table.contains_key(&(Prefix::V4(pfx(2, 0)), 0)));
        assert!(table.contains_key(&(Prefix::V4(pfx(3, 0)), 0)));
    }
}

/// Any other update queued behind the window's route messages settles the
/// window first: a bystander sees the window's routes in their own message
/// before the barrier's effect, and later routes in a later message.
#[tokio::test]
async fn barrier_update_settles_window_before_it_applies() {
    type Barrier = fn() -> RibUpdate;
    let barriers: [(&str, Barrier); 5] = [
        ("end_of_rib", || RibUpdate::EndOfRib {
            peer: IpAddr::V4(A),
            session_id: SESSION,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        }),
        ("route_refresh", || RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            peer: IpAddr::V4(B),
            session_id: SESSION,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        }),
        ("peer_down", || RibUpdate::PeerDown {
            peer: IpAddr::V4(A),
            session_id: SESSION,
        }),
        ("export_policy", || RibUpdate::ReplacePeerExportPolicy {
            peer: IpAddr::V4(B),
            export_policy: Some(deny_prefix_chain(pfx(2, 0))),
            reply: oneshot::channel().0,
        }),
        ("primary_query", || RibUpdate::QueryBestRoutes {
            deadline: full_snapshot_query_deadline(),
            reply: oneshot::channel().0,
        }),
    ];
    for (label, barrier) in barriers {
        let mut o = Oracle::spawn_configured(false, CLUSTER, untimed_window);
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 64).await;
        o.drain_peer_available(C).await;
        o.queue(vec![
            routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![]),
            routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![]),
            barrier(),
            routes(B, vec![ibgp_route(pfx(3, 0), B, 100, vec![])], vec![]),
        ])
        .await;
        let messages = o.drain_peer_available(C).await;
        let routed = messages
            .iter()
            .filter(|msg| !msg.announce.is_empty() || !msg.withdraw.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(
            announced(routed[0]),
            BTreeSet::from([Prefix::V4(pfx(1, 0)), Prefix::V4(pfx(2, 0))]),
            "{label}: the window settles before the barrier"
        );
        let last = routed.last().unwrap();
        assert_eq!(
            announced(last),
            BTreeSet::from([Prefix::V4(pfx(3, 0))]),
            "{label}: input behind the barrier opens a new window"
        );
        if label == "peer_down" {
            assert_eq!(routed.len(), 3, "{label}: announce, withdraw, announce");
            assert_eq!(
                routed[1]
                    .withdraw
                    .iter()
                    .map(|w| w.0)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([Prefix::V4(pfx(1, 0)), Prefix::V4(pfx(2, 0))])
            );
        } else {
            assert_eq!(routed.len(), 2, "{label}: exactly two windows");
        }
        let _ = o.finish().await;
    }
}

/// Synchronous actor turns: finish the queued route batch chunk by chunk and
/// admit the next primary update only when none remains.
fn drain_primary(manager: &mut RibManager) {
    loop {
        if manager.process_next_route_chunk() {
            continue;
        }
        let Some(update) = manager.try_recv_primary() else {
            return;
        };
        manager.handle_update(update);
    }
}

fn source() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 7)
}

fn unregistered_routes(announced: Vec<Route>, withdrawn: Vec<Ipv4Prefix>) -> RibUpdate {
    let RibUpdate::RoutesReceived {
        peer,
        announced,
        withdrawn,
        flowspec_announced,
        flowspec_withdrawn,
        evpn_announced,
        evpn_withdrawn,
        ..
    } = routes(source(), announced, withdrawn)
    else {
        unreachable!()
    };
    RibUpdate::RoutesReceived {
        peer,
        session_id: 0,
        announced,
        withdrawn,
        flowspec_announced,
        flowspec_withdrawn,
        evpn_announced,
        evpn_withdrawn,
    }
}

fn member_up(peer: IpAddr, session_id: u64) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let update = RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65_010,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    };
    (update, outbound_rx)
}

fn route_envelopes(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    let mut envelopes = Vec::new();
    while let Ok(update) = rx.try_recv() {
        if !update.announce.is_empty() || !update.withdraw.is_empty() {
            envelopes.push(update);
        }
    }
    envelopes
}

/// Two grouped members, `target` rejecting `p` through its exact encoder.
struct RejectionFixture {
    tx: mpsc::Sender<RibUpdate>,
    manager: RibManager,
    target: IpAddr,
    /// `[target, other]` outbound receivers.
    receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    p: Ipv4Prefix,
    q: Ipv4Prefix,
    key_p: ExactExportKey,
}

fn rejection_fixture() -> RejectionFixture {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    untimed_window(&mut manager);
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 2));
    let p = pfx(7, 0);
    let key_p = ExactExportKey::Unicast(Prefix::V4(p), 0);
    let rejecting = MockExactExportEncoder::accepting(1);
    rejecting.set_profile(1, [key_p.clone()]);
    let mut receivers = Vec::new();
    for (peer, encoder) in [
        (target, rejecting),
        (other, MockExactExportEncoder::accepting(1)),
    ] {
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 1,
            encoder,
        });
        let (up, mut out) = member_up(peer, 1);
        manager.handle_update(up);
        let _ = route_envelopes(&mut out);
        receivers.push(out);
    }
    RejectionFixture {
        tx,
        manager,
        target,
        receivers,
        p,
        q: pfx(8, 0),
        key_p,
    }
}

/// Exact-export rejections retire only after the window's single pass: the
/// rejected target never receives a withdrawal for a route it never held,
/// and a rejection whose route is live again at the end of the window stays.
#[tokio::test]
async fn exact_export_rejection_retires_after_window_distribution() {
    let RejectionFixture {
        tx,
        mut manager,
        target,
        mut receivers,
        p,
        q,
        key_p,
    } = rejection_fixture();
    let route = |prefix| make_route(prefix, source());

    tx.try_send(unregistered_routes(vec![route(p)], vec![]))
        .unwrap();
    drain_primary(&mut manager);
    assert!(route_envelopes(&mut receivers[0]).is_empty());
    assert_eq!(route_envelopes(&mut receivers[1]).len(), 1);
    assert_eq!(
        manager.peer_unexportable[&target],
        HashSet::from([key_p.clone()])
    );

    // Withdraw the rejected route and announce another in one window.
    tx.try_send(unregistered_routes(vec![], vec![p])).unwrap();
    tx.try_send(unregistered_routes(vec![route(q)], vec![]))
        .unwrap();
    drain_primary(&mut manager);
    let to_target = route_envelopes(&mut receivers[0]);
    assert_eq!(to_target.len(), 1, "one window, one envelope");
    assert!(
        to_target[0].withdraw.is_empty(),
        "no withdrawal for a route the target never received"
    );
    assert_eq!(to_target[0].announce[0].prefix, Prefix::V4(q));
    let to_other = route_envelopes(&mut receivers[1]);
    assert_eq!(to_other.len(), 1);
    assert_eq!(to_other[0].withdraw, vec![(Prefix::V4(p), 0)]);
    assert!(!manager.peer_unexportable.contains_key(&target));

    // Announce, withdraw and re-announce the rejected route in one window:
    // it is live when the window settles, so the rejection survives.
    tx.try_send(unregistered_routes(vec![route(p)], vec![]))
        .unwrap();
    tx.try_send(unregistered_routes(vec![], vec![p])).unwrap();
    tx.try_send(unregistered_routes(vec![route(p)], vec![]))
        .unwrap();
    drain_primary(&mut manager);
    assert!(route_envelopes(&mut receivers[0]).is_empty());
    assert_eq!(route_envelopes(&mut receivers[1]).len(), 1);
    assert_eq!(manager.peer_unexportable[&target], HashSet::from([key_p]));
}

/// Deliver `messages` through the synchronous actor turns with `limits` and
/// return the route envelopes one member received (one per window).
fn windows_for(
    limits: DistributionWindowLimits,
    messages: Vec<RibUpdate>,
) -> Vec<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.distribution_window_limits = limits;
    let (up, mut out) = member_up(IpAddr::V4(Ipv4Addr::new(10, 0, 8, 1)), 1);
    manager.handle_update(up);
    let _ = route_envelopes(&mut out);
    for message in messages {
        tx.try_send(message).unwrap();
    }
    drain_primary(&mut manager);
    route_envelopes(&mut out)
}

/// Distinct prefixes announced per window.
fn prefixes_per_window(limits: DistributionWindowLimits, messages: Vec<RibUpdate>) -> Vec<usize> {
    windows_for(limits, messages)
        .iter()
        .map(|update| update.announce.len())
        .collect()
}

/// The MED of the last churn message each window absorbed (message `i`
/// carries MED `i`), which pins exactly where every window closed.
fn churn_window_ends(limits: DistributionWindowLimits, count: u32) -> Vec<u32> {
    windows_for(limits, churn_messages(count))
        .iter()
        .map(|update| {
            assert_eq!(update.announce.len(), 1);
            update.announce[0]
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    PathAttribute::Med(med) => Some(*med),
                    _ => None,
                })
                .expect("churn routes carry a MED")
        })
        .collect()
}

fn distinct_messages(count: u8, prefixes_each: u8) -> Vec<RibUpdate> {
    (0..count)
        .map(|message| {
            unregistered_routes(
                (0..prefixes_each)
                    .map(|index| make_route(window_pfx(message, index), source()))
                    .collect(),
                vec![],
            )
        })
        .collect()
}

fn churn_messages(count: u32) -> Vec<RibUpdate> {
    (0..count)
        .map(|med| {
            let mut route = make_route(pfx(30, 0), source());
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::Med(med));
            });
            unregistered_routes(vec![route], vec![])
        })
        .collect()
}

/// Every bound closes the window on its own. Each case enables only the
/// bound under test (all others unreachable, including the wall-clock one),
/// so the window shape proves which bound fired.
#[tokio::test]
async fn each_window_bound_splits_queued_input() {
    let defaults = DistributionWindowLimits::default();
    assert_eq!(
        (
            defaults.messages,
            defaults.routes,
            defaults.affected_prefixes,
            defaults.elapsed
        ),
        (256, 4_096, 1_024, Duration::from_millis(5)),
        "the documented default bounds"
    );
    assert_eq!(
        prefixes_per_window(unbounded(), distinct_messages(10, 1)),
        [10],
        "no bound reached: one window"
    );
    assert_eq!(
        prefixes_per_window(
            DistributionWindowLimits {
                messages: 4,
                ..unbounded()
            },
            distinct_messages(10, 1)
        ),
        [4, 4, 2],
        "message bound: four messages per window"
    );
    assert_eq!(
        prefixes_per_window(
            DistributionWindowLimits {
                routes: 3,
                ..unbounded()
            },
            distinct_messages(10, 2)
        ),
        [4, 4, 4, 4, 4],
        "input-route bound: closes at the first message reaching three routes"
    );
    assert_eq!(
        prefixes_per_window(
            DistributionWindowLimits {
                affected_prefixes: 3,
                ..unbounded()
            },
            distinct_messages(10, 1)
        ),
        [3, 3, 3, 1],
        "affected-prefix bound: three changed prefixes per window"
    );
    // A zero limit has always elapsed once the window's first chunk ran, so
    // this case is deterministic without a clock.
    assert_eq!(
        prefixes_per_window(
            DistributionWindowLimits {
                elapsed: Duration::ZERO,
                ..unbounded()
            },
            distinct_messages(10, 1)
        ),
        [1; 10],
        "elapsed bound: every message its own window"
    );
}

/// Repeated churn of one prefix never grows the affected set, so the
/// input-route and message bounds are what cap it.
#[tokio::test]
async fn same_prefix_churn_is_capped_by_the_input_bounds() {
    assert_eq!(
        churn_window_ends(
            DistributionWindowLimits {
                affected_prefixes: 1,
                ..unbounded()
            },
            10
        ),
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        "an affected-prefix bound of one closes every churn window"
    );
    assert_eq!(
        churn_window_ends(
            DistributionWindowLimits {
                affected_prefixes: 2,
                ..unbounded()
            },
            10
        ),
        [9],
        "churn of one prefix never reaches an affected-prefix bound above one"
    );
    assert_eq!(
        churn_window_ends(
            DistributionWindowLimits {
                routes: 4,
                ..unbounded()
            },
            10
        ),
        [3, 7, 9],
        "the input-route bound caps same-prefix churn"
    );
    assert_eq!(
        churn_window_ends(
            DistributionWindowLimits {
                messages: 4,
                ..unbounded()
            },
            10
        ),
        [3, 7, 9],
        "the message bound caps same-prefix churn"
    );
}

/// No waiting: an isolated message distributes in the actor turn that
/// ingests it, and a window admits one queued message per actor turn so
/// readiness and query seams still run between messages.
#[tokio::test]
async fn window_never_waits_and_admits_one_message_per_turn() {
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    untimed_window(&mut manager);
    let (up, mut out) = member_up(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1)), 1);
    manager.handle_update(up);
    let _ = route_envelopes(&mut out);

    manager.handle_update(unregistered_routes(
        vec![make_route(pfx(40, 0), source())],
        vec![],
    ));
    assert!(manager.process_next_route_chunk());
    assert_eq!(
        route_envelopes(&mut out).len(),
        1,
        "an isolated message distributes in its own turn"
    );
    assert!(!manager.process_next_route_chunk());

    for message in distinct_messages(3, 1) {
        tx.try_send(message).unwrap();
    }
    let first = manager.try_recv_primary().unwrap();
    manager.handle_update(first);
    assert!(manager.process_next_route_chunk());
    assert!(route_envelopes(&mut out).is_empty(), "window still open");
    assert_eq!(manager.primary_backlog(), 1, "one queued message admitted");
    assert!(manager.process_next_route_chunk());
    assert_eq!(manager.primary_backlog(), 0);
    assert!(route_envelopes(&mut out).is_empty());
    assert!(manager.process_next_route_chunk());
    assert_eq!(route_envelopes(&mut out).len(), 1, "settled once drained");
    assert!(!manager.process_next_route_chunk());
}

/// Dirty-peer resync can run between the chunks of an open window (its due
/// timer is checked before route chunks): it settles the window first,
/// distributing the accumulated changes and retiring the window's
/// exact-export withdrawals before it reads advertised state.
#[tokio::test]
async fn dirty_resync_settles_an_open_window_first() {
    let RejectionFixture {
        tx,
        mut manager,
        target,
        mut receivers,
        p,
        q,
        key_p,
    } = rejection_fixture();
    let route = |prefix| make_route(prefix, source());
    tx.try_send(unregistered_routes(vec![route(p)], vec![]))
        .unwrap();
    drain_primary(&mut manager);
    let _ = route_envelopes(&mut receivers[1]);
    assert_eq!(manager.peer_unexportable[&target], HashSet::from([key_p]));

    // Window: withdraw p, then q already queued. One turn ingests the
    // withdrawal and admits q; the window is open.
    tx.try_send(unregistered_routes(vec![], vec![p])).unwrap();
    tx.try_send(unregistered_routes(vec![route(q)], vec![]))
        .unwrap();
    let first = manager.try_recv_primary().unwrap();
    manager.handle_update(first);
    assert!(manager.process_next_route_chunk());
    assert!(
        !manager.pending_distribute_affected.is_empty(),
        "window open"
    );
    assert!(route_envelopes(&mut receivers[1]).is_empty());

    let _ = manager.resync_dirty_peers_bounded();
    assert!(manager.pending_distribute_affected.is_empty());
    assert!(manager.pending_exact_export_withdrawals.is_empty());
    assert!(
        !manager.peer_unexportable.contains_key(&target),
        "the window's withdrawal retires the rejection"
    );
    assert!(route_envelopes(&mut receivers[0]).is_empty());
    let settled = route_envelopes(&mut receivers[1]);
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].withdraw, vec![(Prefix::V4(p), 0)]);

    // The admitted message continues as a new window.
    drain_primary(&mut manager);
    for receiver in &mut receivers {
        let later = route_envelopes(receiver);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].announce[0].prefix, Prefix::V4(q));
    }
}

/// A window admits at most one queued message per actor turn, including a
/// stale-session message it drops: a backlog of stale messages cannot drain
/// in one turn and skip the readiness and query seams between messages.
#[tokio::test]
async fn window_dequeues_at_most_one_message_per_turn_including_stale() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    untimed_window(&mut manager);
    let member = IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1));
    let (up, mut out) = member_up(member, 1);
    manager.handle_update(up);
    let _ = route_envelopes(&mut out);
    let IpAddr::V4(member_v4) = member else {
        unreachable!()
    };
    let stale = |prefix| {
        let RibUpdate::RoutesReceived {
            peer,
            announced,
            withdrawn,
            flowspec_announced,
            flowspec_withdrawn,
            evpn_announced,
            evpn_withdrawn,
            ..
        } = routes(member_v4, vec![make_route(prefix, member_v4)], vec![])
        else {
            unreachable!()
        };
        RibUpdate::RoutesReceived {
            peer,
            session_id: 9,
            announced,
            withdrawn,
            flowspec_announced,
            flowspec_withdrawn,
            evpn_announced,
            evpn_withdrawn,
        }
    };
    let (query_reply, mut query_response) = oneshot::channel();
    let queued = vec![
        stale(window_pfx(50, 1)),
        stale(window_pfx(50, 2)),
        RibUpdate::QueryBestRoutes {
            deadline: full_snapshot_query_deadline(),
            reply: query_reply,
        },
        stale(window_pfx(50, 3)),
        stale(window_pfx(50, 4)),
        unregistered_routes(vec![make_route(window_pfx(50, 5), source())], vec![]),
    ];
    let total = queued.len();
    manager.handle_update(unregistered_routes(
        vec![make_route(window_pfx(50, 0), source())],
        vec![],
    ));
    for update in queued {
        tx.try_send(update).unwrap();
    }

    // Actor turns: one route chunk (which may admit one queued message), or
    // one ordinary receive.
    let mut turns = 0;
    let mut query_answered_at = None;
    loop {
        let before = manager.primary_backlog();
        if !manager.process_next_route_chunk() {
            let Some(update) = manager.try_recv_primary() else {
                break;
            };
            manager.handle_update(update);
        }
        turns += 1;
        assert!(
            before - manager.primary_backlog() <= 1,
            "turn {turns} dequeued more than one message"
        );
        if query_answered_at.is_none() && query_response.try_recv().is_ok() {
            query_answered_at = Some(turns);
        }
    }
    assert!(turns > total, "every queued message took its own turn");
    assert!(query_answered_at.is_some());
    let delivered = route_envelopes(&mut out)
        .iter()
        .flat_map(|update| update.announce.iter().map(|route| route.prefix))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        delivered,
        BTreeSet::from([Prefix::V4(window_pfx(50, 0)), Prefix::V4(window_pfx(50, 5))]),
        "stale messages are dropped, fresh ones distributed"
    );
}
