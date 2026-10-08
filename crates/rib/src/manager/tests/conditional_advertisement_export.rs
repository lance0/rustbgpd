//! ADR-0137 slice 3: the conditional-advertisement export gate through the
//! real export path. Every test drives the actor's own handlers — route
//! ingestion, the settle timer, the bounded dirty resync — under a paused
//! clock and observes the target's outbound UPDATE stream and Adj-RIB-Out.

use std::collections::BTreeSet;
use std::time::Duration;

use rustbgpd_policy::PolicyChain;
use rustbgpd_policy::rpol::RpolFile;
use rustbgpd_policy::sets::SetStore;
use tokio::time::advance;

use super::*;
use crate::update::{ExplainAdvertisedRoute, ExplainDecision};
use crate::{ConditionalAdvertiseIf, ConditionalAdvertisement, ConditionalAdvertisementSet};

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SOURCE2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const BYSTANDER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const NAME: &str = "backup";
const SETTLE: Duration = Duration::from_secs(5);
const JUST_BEFORE_SETTLE: Duration = Duration::from_millis(4_999);
/// 65000:100 marks a route the tagged advertise policy controls.
const TAG: u32 = 0xFDE8_0064;

fn controlled() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)
}
fn other() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)
}
fn condition() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32)
}
fn v4(prefix: Ipv4Prefix) -> Prefix {
    Prefix::V4(prefix)
}
fn ip(addr: Ipv4Addr) -> IpAddr {
    IpAddr::V4(addr)
}

fn rpol(source: &str, name: &str) -> PolicyChain {
    let compiled = RpolFile::parse(source)
        .expect("clean rpol")
        .compile_policy(name, &[], &mut SetStore::new())
        .expect("policy exists");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        name.to_string(),
        Arc::new(compiled),
    )])
}

/// Selects exactly the controlled prefix.
fn prefix_predicate() -> PolicyChain {
    rpol(
        "policy ctl { term t { if route.prefix == 203.0.113.0/24 { accept } } term rest { reject } }",
        "ctl",
    )
}

/// Selects routes tagged 65000:100.
fn tagged_predicate() -> PolicyChain {
    rpol(
        "policy tagged { term t { if route.communities has 65000:100 { accept } } term rest { reject } }",
        "tagged",
    )
}

/// Selects MED 0, rejects any other MED, and errors on MED `u32::MAX`.
fn med_predicate() -> PolicyChain {
    rpol(
        "policy guard { term t3 { if route.med + 1 == 1 { accept } } term rest { reject } }",
        "guard",
    )
}

fn definition(
    advertise_policy: PolicyChain,
    advertise_if: ConditionalAdvertiseIf,
) -> ConditionalAdvertisement {
    ConditionalAdvertisement {
        name: Arc::from(NAME),
        advertise_policy,
        advertise_if,
        condition_prefixes: vec![v4(condition())],
        condition_policy: None,
        settle_time: SETTLE,
    }
}

fn install_set(
    definition: ConditionalAdvertisement,
    peers: &[Ipv4Addr],
) -> ConditionalAdvertisementSet {
    ConditionalAdvertisementSet {
        definitions: vec![definition],
        attachments: peers
            .iter()
            .map(|peer| (ip(*peer), vec![Arc::from(NAME)]))
            .collect(),
    }
}

fn manager_with(set: ConditionalAdvertisementSet) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_conditional_advertisements(set)
}

#[derive(Clone, Copy, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent peer-shape switches of the fixture"
)]
struct Shape {
    ibgp: bool,
    rr_client: bool,
    per_client_best: bool,
    add_path: bool,
}

fn peer_up(
    manager: &mut RibManager,
    peer: Ipv4Addr,
    shape: Shape,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    manager.handle_update(RibUpdate::PeerUp {
        peer: ip(peer),
        session_id: 0,
        peer_asn: if shape.ibgp { 65001 } else { 65100 },
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: !shape.ibgp,
        route_reflector_client: shape.rr_client,
        orr_vantage: None,
        per_client_best: shape.per_client_best,
        interpret_rfc1997: true,
        add_path_send_families: if shape.add_path {
            ipv4_sendable()
        } else {
            Vec::new()
        },
        add_path_send_max: if shape.add_path { 8 } else { 0 },
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    outbound_rx
}

fn route(prefix: Ipv4Prefix, source: Ipv4Addr, local_pref: u32, tagged: bool) -> Route {
    let mut route = make_multipath_route(prefix, source, vec![65100], local_pref);
    if tagged {
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(vec![TAG]));
        });
    }
    route
}

fn announce(manager: &mut RibManager, source: Ipv4Addr, routes: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: ip(source),
        session_id: 0,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn withdraw(manager: &mut RibManager, source: Ipv4Addr, prefix: Ipv4Prefix) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: ip(source),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![(v4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// The bounded resync tick, as the run loop drives it.
fn resync(manager: &mut RibManager) {
    while manager.resync_dirty_peers_bounded() {}
}

/// Let `by` elapse, fire due settle timers (which mark the attached peers
/// dirty), and run the resync tick.
async fn elapse(manager: &mut RibManager, by: Duration) {
    advance(by).await;
    let _ = manager.fire_conditional_advertisement_timers();
    resync(manager);
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Wire {
    announced: BTreeSet<(Prefix, u32)>,
    withdrawn: BTreeSet<(Prefix, u32)>,
}

fn drain(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Wire {
    let mut wire = Wire::default();
    while let Ok(update) = rx.try_recv() {
        wire.announced.extend(
            update
                .announce
                .iter()
                .map(|route| (route.prefix, route.path_id)),
        );
        wire.withdrawn.extend(update.withdraw.iter().copied());
    }
    wire
}

fn wire(announced: &[(Ipv4Prefix, u32)], withdrawn: &[(Ipv4Prefix, u32)]) -> Wire {
    Wire {
        announced: announced.iter().map(|(p, id)| (v4(*p), *id)).collect(),
        withdrawn: withdrawn.iter().map(|(p, id)| (v4(*p), *id)).collect(),
    }
}

/// Advertised `(prefix, path id) -> source peer`.
fn advertised(manager: &RibManager, peer: Ipv4Addr) -> BTreeMap<(Prefix, u32), IpAddr> {
    manager
        .adj_ribs_out
        .get(&ip(peer))
        .map(|rib| {
            rib.iter()
                .map(|route| ((route.prefix, route.path_id), route.peer))
                .collect()
        })
        .unwrap_or_default()
}

fn has(manager: &RibManager, peer: Ipv4Addr, prefix: Ipv4Prefix) -> bool {
    advertised(manager, peer)
        .keys()
        .any(|(advertised, _)| *advertised == v4(prefix))
}

fn explain(manager: &mut RibManager, peer: Ipv4Addr, prefix: Ipv4Prefix) -> ExplainAdvertisedRoute {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
        peer: ip(peer),
        prefix: v4(prefix),
        rd: None,
        labeled: false,
        source: None,
        reply,
    });
    response
        .try_recv()
        .expect("explain answers synchronously")
        .expect("explain succeeds")
}

fn first_stop(explanation: &ExplainAdvertisedRoute) -> Option<&'static str> {
    explanation
        .gates
        .iter()
        .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
        .map(|step| step.code)
}

fn conditional_step(explanation: &ExplainAdvertisedRoute) -> &crate::update::ExportGateStep {
    explanation
        .gates
        .iter()
        .find(|step| step.gate == "conditional_advertisement")
        .expect("conditional advertisement step in the ladder")
}

/// `advertise_if = "present"`: the controlled route follows the condition with
/// exact withdrawals and re-advertisements after each settle window; other
/// routes never move.
#[tokio::test(start_paused = true)]
async fn present_absent_present_withdraws_and_readvertises_exactly() {
    let mut manager = manager_with(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(other(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());

    // Startup is `pending`: the initial dump withholds the controlled route.
    assert_eq!(drain(&mut rx), wire(&[(other(), 0), (condition(), 0)], &[]),);
    assert!(!has(&manager, TARGET, controlled()));

    // Present for a full settle window: advertised, nothing else re-sent.
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[(controlled(), 0)], &[]));

    // Absent: still advertised until the window closes, then one withdraw.
    withdraw(&mut manager, SOURCE, condition());
    assert_eq!(drain(&mut rx), wire(&[], &[(condition(), 0)]));
    elapse(&mut manager, JUST_BEFORE_SETTLE).await;
    assert_eq!(drain(&mut rx), Wire::default());
    assert!(has(&manager, TARGET, controlled()));
    elapse(&mut manager, Duration::from_millis(1)).await;
    assert_eq!(drain(&mut rx), wire(&[], &[(controlled(), 0)]));
    assert!(!has(&manager, TARGET, controlled()));

    // Churn on a controlled route while suppressed stays off the wire.
    announce(
        &mut manager,
        SOURCE,
        vec![route(controlled(), SOURCE, 200, false)],
    );
    assert_eq!(drain(&mut rx), Wire::default());

    // Present again: one re-advertisement after the window.
    announce(
        &mut manager,
        SOURCE,
        vec![route(condition(), SOURCE, 100, false)],
    );
    assert_eq!(drain(&mut rx), wire(&[(condition(), 0)], &[]));
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[(controlled(), 0)], &[]));
    assert!(has(&manager, TARGET, other()));
}

/// `advertise_if = "absent"` (the backup edge): the backup prefix is announced
/// only while the primary's condition route is gone. A peer without the
/// attachment always receives it.
#[tokio::test(start_paused = true)]
async fn absent_mode_announces_the_backup_only_while_the_condition_is_gone() {
    let mut manager = manager_with(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Absent),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    let mut bystander = peer_up(&mut manager, BYSTANDER, Shape::default());
    let _ = drain(&mut rx);
    assert!(
        drain(&mut bystander)
            .announced
            .contains(&(v4(controlled()), 0))
    );

    elapse(&mut manager, SETTLE).await;
    assert!(
        !has(&manager, TARGET, controlled()),
        "primary present: backup held"
    );

    withdraw(&mut manager, SOURCE, condition());
    let _ = drain(&mut rx);
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[(controlled(), 0)], &[]));

    announce(
        &mut manager,
        SOURCE,
        vec![route(condition(), SOURCE, 100, false)],
    );
    let _ = drain(&mut rx);
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[], &[(controlled(), 0)]));
    assert!(
        !drain(&mut bystander)
            .withdrawn
            .contains(&(v4(controlled()), 0)),
        "an unattached peer is never gated"
    );
}

/// Add-Path: each suppressed candidate leaves the walk on its own, and the
/// Adj-RIB-Out diff withdraws exactly the path IDs no longer staged.
#[tokio::test(start_paused = true)]
async fn add_path_withdraws_per_path_id() {
    let mut manager = manager_with(install_set(
        definition(tagged_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![route(controlled(), SOURCE, 200, true)],
    );
    announce(
        &mut manager,
        SOURCE2,
        vec![
            route(controlled(), SOURCE2, 100, false),
            route(condition(), SOURCE2, 100, false),
        ],
    );
    let mut rx = peer_up(
        &mut manager,
        TARGET,
        Shape {
            add_path: true,
            ..Shape::default()
        },
    );
    let _ = drain(&mut rx);
    // Pending: only the untagged path is staged, at rank 1.
    assert_eq!(
        advertised(&manager, TARGET).get(&(v4(controlled()), 1)),
        Some(&ip(SOURCE2))
    );
    elapse(&mut manager, SETTLE).await;
    let both = advertised(&manager, TARGET);
    assert_eq!(both.get(&(v4(controlled()), 1)), Some(&ip(SOURCE)));
    assert_eq!(both.get(&(v4(controlled()), 2)), Some(&ip(SOURCE2)));
    let _ = drain(&mut rx);

    withdraw(&mut manager, SOURCE2, condition());
    let _ = drain(&mut rx);
    elapse(&mut manager, SETTLE).await;
    // The tagged path left; the untagged one now holds path ID 1 and the
    // second ID is withdrawn.
    assert_eq!(
        drain(&mut rx),
        wire(&[(controlled(), 1)], &[(controlled(), 2)])
    );
    let after = advertised(&manager, TARGET);
    assert_eq!(after.get(&(v4(controlled()), 1)), Some(&ip(SOURCE2)));
    assert!(!after.contains_key(&(v4(controlled()), 2)));
}

/// `per_client_best`: a suppressed best candidate works like an export
/// denial in the first-permitted walk, so the next candidate is staged.
#[tokio::test(start_paused = true)]
async fn per_client_best_moves_to_the_next_permitted_candidate() {
    let mut manager = manager_with(install_set(
        definition(tagged_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![route(controlled(), SOURCE, 200, true)],
    );
    announce(
        &mut manager,
        SOURCE2,
        vec![route(controlled(), SOURCE2, 100, false)],
    );
    let mut rx = peer_up(
        &mut manager,
        TARGET,
        Shape {
            per_client_best: true,
            ..Shape::default()
        },
    );
    let _ = drain(&mut rx);
    assert_eq!(
        advertised(&manager, TARGET).get(&(v4(controlled()), 0)),
        Some(&ip(SOURCE2)),
        "pending suppresses the tagged best; the runner-up is advertised"
    );
    let explanation = explain(&mut manager, TARGET, controlled());
    let suppressed = explanation
        .reasons
        .iter()
        .find(|reason| reason.code == "conditional_advertisement_suppressed")
        .expect("explain records the suppressed candidate with the conditional code");
    assert!(
        suppressed
            .message
            .starts_with("candidate 1 of 2 (from 10.0.0.1"),
        "{}",
        suppressed.message
    );
    assert_eq!(explanation.route_peer, Some(ip(SOURCE2)));

    // The condition arrives: the tagged best is staged at path 0 in place.
    announce(
        &mut manager,
        SOURCE2,
        vec![route(condition(), SOURCE2, 100, false)],
    );
    let _ = drain(&mut rx);
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[(controlled(), 0)], &[]));
    assert_eq!(
        advertised(&manager, TARGET).get(&(v4(controlled()), 0)),
        Some(&ip(SOURCE))
    );
}

/// The gate runs after RFC 4456: it never makes a route reflectable, and a
/// reflected route toward a client is gated like any other.
#[tokio::test(start_paused = true)]
async fn route_reflection_rules_run_before_the_gate() {
    let mut manager = RibManager::new(
        mpsc::channel(8).1,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)),
        BgpMetrics::new(),
    )
    .with_conditional_advertisements(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET, BYSTANDER],
    ));
    let ibgp = Shape {
        ibgp: true,
        ..Shape::default()
    };
    let mut source_rx = peer_up(&mut manager, SOURCE, ibgp);
    let mut client = peer_up(
        &mut manager,
        TARGET,
        Shape {
            ibgp: true,
            rr_client: true,
            ..Shape::default()
        },
    );
    let mut non_client = peer_up(&mut manager, BYSTANDER, ibgp);
    let mut ibgp_route = route(controlled(), SOURCE, 100, false);
    ibgp_route.origin_type = crate::route::RouteOrigin::Ibgp;
    let mut ibgp_condition = route(condition(), SOURCE, 100, false);
    ibgp_condition.origin_type = crate::route::RouteOrigin::Ibgp;
    announce(&mut manager, SOURCE, vec![ibgp_route, ibgp_condition]);
    let _ = (
        drain(&mut source_rx),
        drain(&mut client),
        drain(&mut non_client),
    );

    // Pending suppresses toward the client; non-client to non-client is
    // stopped first by reflection, exactly as without the attachment.
    assert!(!has(&manager, TARGET, controlled()));
    assert_eq!(
        first_stop(&explain(&mut manager, TARGET, controlled())),
        Some("conditional_advertisement_suppressed")
    );
    assert_eq!(
        first_stop(&explain(&mut manager, BYSTANDER, controlled())),
        Some("rr_non_client_to_non_client")
    );

    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut client), wire(&[(controlled(), 0)], &[]));
    assert_eq!(
        drain(&mut non_client),
        Wire::default(),
        "advertising does not make a route reflectable"
    );
}

/// For every unicast body, a route an earlier gate stops reports the same
/// first denial, live and in both explain paths, whether or not an active
/// suppression would also stop it.
#[tokio::test(start_paused = true)]
async fn first_denial_is_unchanged_in_every_body() {
    let shapes = [
        ("single_best", Shape::default()),
        (
            "add_path",
            Shape {
                add_path: true,
                ..Shape::default()
            },
        ),
        (
            "per_client_best",
            Shape {
                per_client_best: true,
                ..Shape::default()
            },
        ),
    ];
    for (label, shape) in shapes {
        let mut outcomes = Vec::new();
        for attached in [false, true] {
            let peers: &[Ipv4Addr] = if attached { &[TARGET] } else { &[] };
            let mut manager = manager_with(install_set(
                definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
                peers,
            ));
            let mut no_advertise = route(controlled(), SOURCE, 100, false);
            AttrSet::edit(&mut no_advertise.attributes, |attrs| {
                attrs.push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
                ]));
            });
            announce(&mut manager, SOURCE, vec![no_advertise]);
            let mut rx = peer_up(&mut manager, TARGET, shape);
            let live = drain(&mut rx);
            let explanation = explain(&mut manager, TARGET, controlled());
            assert!(
                !explanation
                    .gates
                    .iter()
                    .any(|step| step.code.starts_with("conditional_advertisement_")),
                "{label}: the gate ran ahead of an earlier stop"
            );
            outcomes.push((
                live,
                advertised(&manager, TARGET),
                explanation.decision,
                first_stop(&explanation),
                manager.export_policy_stats.get(&ip(TARGET)).copied(),
            ));
        }
        assert_eq!(outcomes[0], outcomes[1], "{label}: first denial changed");
        assert!(
            outcomes[0].3.is_some(),
            "{label}: an earlier gate must stop the route"
        );
    }
}

/// An `advertise_policy` evaluation error while suppressing fails closed
/// with its own explain code; a clean rejection reaches the export chain.
#[tokio::test(start_paused = true)]
async fn evaluation_error_fails_closed_and_differs_from_a_clean_reject() {
    let mut manager = manager_with(install_set(
        definition(med_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    let med = |prefix, value| {
        let mut route = route(prefix, SOURCE, 100, false);
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::Med(value));
        });
        route
    };
    announce(
        &mut manager,
        SOURCE,
        vec![med(controlled(), u32::MAX), med(other(), 5)],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    assert_eq!(drain(&mut rx), wire(&[(other(), 0)], &[]));

    let error = explain(&mut manager, TARGET, controlled());
    assert_eq!(error.decision, ExplainDecision::Deny);
    let step = conditional_step(&error);
    assert_eq!(step.code, "conditional_advertisement_eval_error");
    assert!(
        step.detail.contains(
            "advertise_policy guard failed in term t3 (evaluation error); failing closed"
        ),
        "{}",
        step.detail
    );
    let clean = explain(&mut manager, TARGET, other());
    assert_eq!(clean.decision, ExplainDecision::Advertise);
    let step = conditional_step(&clean);
    assert_eq!(step.code, "conditional_advertisement");
    assert_eq!(
        step.verdict,
        crate::update::ExportGateVerdict::NotApplicable
    );
    assert_eq!(
        step.detail,
        "route not selected by any attached advertise policy"
    );
}

/// Explain reports the suppression with the definition, condition, and
/// state; the pass names the advertising definition.
#[tokio::test(start_paused = true)]
async fn explain_names_the_definition_condition_and_state() {
    let mut manager = manager_with(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Absent),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let _rx = peer_up(&mut manager, TARGET, Shape::default());
    let _bystander = peer_up(&mut manager, BYSTANDER, Shape::default());

    assert_eq!(
        conditional_step(&explain(&mut manager, TARGET, controlled())).detail,
        "suppressed by conditional advertisement backup: pending initial evaluation; \
         observed present for 0s, applies after settle_time 5s"
    );
    elapse(&mut manager, SETTLE).await;
    let step = conditional_step(&explain(&mut manager, TARGET, controlled())).clone();
    assert_eq!(step.code, "conditional_advertisement_suppressed");
    assert_eq!(
        step.detail,
        "suppressed by conditional advertisement backup: condition prefix 198.51.100.1/32 \
         present (advertise if absent)"
    );
    withdraw(&mut manager, SOURCE, condition());
    elapse(&mut manager, SETTLE).await;
    let step = conditional_step(&explain(&mut manager, TARGET, controlled())).clone();
    assert_eq!(step.verdict, crate::update::ExportGateVerdict::Pass);
    assert_eq!(
        step.detail,
        "conditional advertisement backup permits: condition prefix 198.51.100.1/32 absent \
         (advertise if absent)"
    );
    let unattached = explain(&mut manager, BYSTANDER, controlled());
    assert_eq!(
        conditional_step(&unattached).detail,
        "no conditional advertisement attached"
    );
}

/// An attached peer takes the per-peer path with the visible
/// `conditional_advertisement` reason; detaching restores grouping.
#[tokio::test(start_paused = true)]
async fn attachment_selects_the_fallback_reason_and_detach_regroups() {
    let mut manager = manager_with(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    let _target = peer_up(&mut manager, TARGET, Shape::default());
    let _bystander = peer_up(&mut manager, BYSTANDER, Shape::default());
    let label = |manager: &RibManager, peer| manager.update_groups.members[&ip(peer)].label();
    assert_eq!(label(&manager, TARGET), "conditional_advertisement");
    assert!(label(&manager, BYSTANDER).starts_with("group:"));

    let _ =
        manager.handle_install_conditional_advertisements(ConditionalAdvertisementSet::default());
    assert_eq!(label(&manager, TARGET), label(&manager, BYSTANDER));

    let _ = manager.handle_install_conditional_advertisements(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    assert_eq!(label(&manager, TARGET), "conditional_advertisement");
}

/// Reinstalling identical content keeps the tracker state and resyncs
/// nothing; changed content is evaluated immediately and resyncs.
#[tokio::test(start_paused = true)]
async fn reload_content_identity() {
    let installed = || {
        install_set(
            definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
            &[TARGET],
        )
    };
    let mut manager = manager_with(installed());
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    elapse(&mut manager, SETTLE).await;
    let _ = drain(&mut rx);
    withdraw(&mut manager, SOURCE, condition());
    let _ = drain(&mut rx);
    let deadline = manager.next_conditional_advertisement_deadline();
    assert!(deadline.is_some(), "absent observation is settling");

    let _ = manager.handle_install_conditional_advertisements(installed());
    assert!(
        manager.dirty_peers.is_empty(),
        "identical content resyncs nothing"
    );
    assert_eq!(manager.next_conditional_advertisement_deadline(), deadline);
    resync(&mut manager);
    assert_eq!(drain(&mut rx), Wire::default());

    // A changed advertise mode applies at once: absent now advertises.
    let _ = manager.handle_install_conditional_advertisements(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Absent),
        &[TARGET],
    ));
    assert!(manager.dirty_peers.contains(&ip(TARGET)));
    assert_eq!(manager.next_conditional_advertisement_deadline(), None);
    resync(&mut manager);
    assert_eq!(
        drain(&mut rx),
        Wire::default(),
        "still advertised under the new definition"
    );
    assert!(has(&manager, TARGET, controlled()));
}

/// Compensation during an active settle window reinstates the prior
/// applied state, its deadline, and its wire effect without re-evaluating.
#[tokio::test(start_paused = true)]
async fn restore_during_a_settle_window_reinstates_state_and_wire() {
    let mut manager = manager_with(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    elapse(&mut manager, SETTLE).await;
    withdraw(&mut manager, SOURCE, condition());
    let _ = drain(&mut rx);
    advance(Duration::from_secs(2)).await;
    let deadline = manager.next_conditional_advertisement_deadline();

    // A failed generation detaches the peer, then compensates.
    let capture =
        manager.handle_install_conditional_advertisements(ConditionalAdvertisementSet::default());
    resync(&mut manager);
    assert_eq!(manager.next_conditional_advertisement_deadline(), None);
    manager.handle_restore_conditional_advertisements(capture);
    resync(&mut manager);
    assert_eq!(
        manager.next_conditional_advertisement_deadline(),
        deadline,
        "restored, not re-evaluated: the original settle deadline stands"
    );
    assert!(
        has(&manager, TARGET, controlled()),
        "prior applied advertise state restored"
    );
    assert_eq!(
        manager.update_groups.members[&ip(TARGET)].label(),
        "conditional_advertisement"
    );

    elapse(&mut manager, Duration::from_secs(3)).await;
    assert_eq!(
        drain(&mut rx).withdrawn,
        BTreeSet::from([(v4(controlled()), 0)])
    );
}

/// A dataset swap reaches both predicates: `ReevaluatePeerExportPolicies`
/// re-gates an attached peer's `advertise_policy`, and a re-observation
/// moves a `condition_policy` under the debounce.
#[tokio::test(start_paused = true)]
async fn dataset_swap_reaches_both_predicates() {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry};

    let data = |prefix: Option<Ipv4Prefix>| {
        DatasetData::Prefix(PrefixSet::new(prefix.map(|prefix| PrefixSetEntry {
            prefix: v4(prefix),
            ge: None,
            le: None,
        })))
    };
    let dataset_policy = |name: &str, handle: &Arc<DatasetHandle>| {
        let mut bindings = DatasetBindings::new();
        bindings.insert(Arc::clone(handle));
        let compiled = RpolFile::parse(&format!(
            "dataset prefix-set {name}\npolicy p {{ term t {{ if route.prefix in {name} {{ accept }} reject }} }}"
        ))
        .unwrap()
        .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
        .unwrap()
        .unwrap();
        PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
            "p".to_string(),
            Arc::new(compiled),
        )])
    };
    let advertised_set = Arc::new(DatasetHandle::new(
        "controlled",
        DatasetKind::Prefix,
        data(None),
    ));
    let condition_set = Arc::new(DatasetHandle::new(
        "primary",
        DatasetKind::Prefix,
        data(Some(condition())),
    ));
    let mut definition = definition(
        dataset_policy("controlled", &advertised_set),
        ConditionalAdvertiseIf::Present,
    );
    definition.condition_policy = Some(dataset_policy("primary", &condition_set));
    let mut manager = manager_with(install_set(definition, &[TARGET]));
    announce(
        &mut manager,
        SOURCE,
        vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    // Pending, but the predicate selects nothing yet: advertised.
    assert!(has(&manager, TARGET, controlled()));
    elapse(&mut manager, SETTLE).await;
    let _ = drain(&mut rx);

    // condition_policy dataset drops the condition: re-observed, debounced.
    condition_set.refresh(data(None));
    manager.handle_reobserve_conditional_advertisement_datasets(&["primary".to_string()]);
    assert!(manager.next_conditional_advertisement_deadline().is_some());
    // advertise_policy dataset now selects the controlled prefix, and the
    // export re-evaluation the peer manager sends for it re-gates.
    advertised_set.refresh(data(Some(controlled())));
    let (reply, _result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![ip(TARGET)],
        reply,
    });
    resync(&mut manager);
    assert!(
        has(&manager, TARGET, controlled()),
        "still advertising until the window closes"
    );
    elapse(&mut manager, SETTLE).await;
    assert_eq!(drain(&mut rx), wire(&[], &[(controlled(), 0)]));
}

/// The actor's own run loop: the settle timer fires, the transition marks
/// the peer dirty, and the bounded resync tick withdraws on the wire.
#[tokio::test(start_paused = true)]
async fn run_loop_withdraws_after_the_settle_window() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_conditional_advertisements(install_set(
            definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
            &[TARGET],
        ));
    let handle = tokio::spawn(manager.run());
    let send = |update| {
        let tx = tx.clone();
        async move { tx.send(update).await.unwrap() }
    };
    send(RibUpdate::RoutesReceived {
        peer: ip(SOURCE),
        session_id: 0,
        announced: vec![
            route(controlled(), SOURCE, 100, false),
            route(condition(), SOURCE, 100, false),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await;
    let (outbound_tx, mut out_rx) = mpsc::channel(64);
    send(RibUpdate::PeerUp {
        peer: ip(TARGET),
        session_id: 0,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await;
    let started = tokio::time::Instant::now();
    let announced_at = tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            let update = out_rx.recv().await.unwrap();
            if update
                .announce
                .iter()
                .any(|route| route.prefix == v4(controlled()))
            {
                break tokio::time::Instant::now();
            }
        }
    })
    .await
    .expect("the settle timer advertises the controlled route");
    assert!(
        announced_at >= started + SETTLE,
        "advertised only after the window"
    );

    send(RibUpdate::RoutesReceived {
        peer: ip(SOURCE),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![(v4(condition()), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await;
    let lost = tokio::time::Instant::now();
    let withdrawn_at = tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            let update = out_rx.recv().await.unwrap();
            if update.withdraw.contains(&(v4(controlled()), 0)) {
                break tokio::time::Instant::now();
            }
        }
    })
    .await
    .expect("the settle timer withdraws the controlled route");
    assert!(withdrawn_at >= lost + SETTLE);
    drop(tx);
    handle.await.unwrap();
}

/// A peer that registered before the install that attaches it is regrouped
/// and resynced by that install, so it cannot keep exporting ungated.
#[tokio::test(start_paused = true)]
async fn install_gates_a_peer_registered_before_it() {
    let mut manager = manager_with(ConditionalAdvertisementSet::default());
    announce(
        &mut manager,
        SOURCE,
        vec![route(controlled(), SOURCE, 100, false)],
    );
    let mut rx = peer_up(&mut manager, TARGET, Shape::default());
    let _bystander = peer_up(&mut manager, BYSTANDER, Shape::default());
    assert!(drain(&mut rx).announced.contains(&(v4(controlled()), 0)));

    // Warm install of a changed definition: evaluated at once (absent, so
    // advertise-if-present suppresses) and the attached peer is resynced.
    let _ = manager.handle_install_conditional_advertisements(install_set(
        definition(prefix_predicate(), ConditionalAdvertiseIf::Present),
        &[TARGET],
    ));
    assert_eq!(
        manager.update_groups.members[&ip(TARGET)].label(),
        "conditional_advertisement"
    );
    resync(&mut manager);
    assert_eq!(drain(&mut rx), wire(&[], &[(controlled(), 0)]));
}
