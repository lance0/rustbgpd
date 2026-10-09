//! ADR-0137 slice 2: condition-tracker state machine under a paused clock.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_policy::PolicyChain;
use rustbgpd_policy::rpol::RpolFile;
use rustbgpd_policy::sets::{PrefixSetEntry, SetStore};
use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, Safi};
use tokio::time::{Instant, advance};

use super::super::helpers::LOCAL_PEER;

use super::super::conditional_advertisement::{AppliedConditionalState, ConditionObservation};
use super::*;
use crate::attr_set::AttrSet;
use crate::{
    ConditionalAdvertiseIf, ConditionalAdvertisement, SelectionDeferralConfig,
    SelectionDeferralWaiterConfig,
};

const NAME: &str = "backup";
const SETTLE: Duration = Duration::from_secs(5);
const JUST_BEFORE_SETTLE: Duration = Duration::from_millis(4_999);

fn prefix(octet: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, octet), 32)
}

fn condition() -> Prefix {
    Prefix::V4(prefix(1))
}

fn peer(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

fn manager_with(metrics: &BgpMetrics) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
}

fn manager() -> RibManager {
    manager_with(&BgpMetrics::new())
}

fn rpol_chain(source: &str, name: &str) -> PolicyChain {
    let compiled = RpolFile::parse(source)
        .expect("clean rpol")
        .compile_policy(name, &[], &mut SetStore::new())
        .expect("policy exists");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        name.to_string(),
        Arc::new(compiled),
    )])
}

/// Matches MED 0, misses any other MED, and errors on MED `u32::MAX`
/// (checked-arithmetic overflow).
fn med_guard() -> PolicyChain {
    rpol_chain(
        "policy guard { term t { if route.med + 1 == 1 { accept } } term rest { reject } }",
        "guard",
    )
}

fn definition(
    advertise_if: ConditionalAdvertiseIf,
    condition_policy: Option<PolicyChain>,
    settle_time: Duration,
) -> ConditionalAdvertisement {
    ConditionalAdvertisement {
        name: Arc::from(NAME),
        advertise_policy: PolicyChain::default(),
        advertise_if,
        condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(condition())],
        condition_policy,
        settle_time,
    }
}

fn absent_if(settle: Duration) -> ConditionalAdvertisement {
    definition(ConditionalAdvertiseIf::Absent, None, settle)
}

fn state(
    manager: &RibManager,
) -> (
    ConditionObservation,
    AppliedConditionalState,
    Option<Instant>,
) {
    manager.conditional_advertisement_state(NAME).unwrap()
}

fn applied(manager: &RibManager) -> AppliedConditionalState {
    state(manager).1
}

fn route_with_med(source: IpAddr, p: Ipv4Prefix, med: Option<u32>) -> Route {
    let IpAddr::V4(source) = source else {
        unreachable!()
    };
    let mut route = make_route(p, source);
    if let Some(med) = med {
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(rustbgpd_wire::PathAttribute::Med(med));
        });
    }
    route
}

fn inject(manager: &mut RibManager, p: Ipv4Prefix, med: Option<u32>) {
    let mut route = route_with_med(peer(254), p, med);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    let (reply, _rx) = oneshot::channel();
    manager.handle_inject_route(route, reply);
}

fn withdraw_injected(manager: &mut RibManager, p: Ipv4Prefix) {
    let (reply, _rx) = oneshot::channel();
    manager.handle_withdraw_injected(Prefix::V4(p), 0, reply);
}

fn peer_up(manager: &mut RibManager, source: IpAddr, session_id: u64) {
    manager.handle_update(peer_up_update(source, session_id, 65001));
}

fn peer_up_update(source: IpAddr, session_id: u64, peer_asn: u32) -> RibUpdate {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    RibUpdate::PeerUp {
        peer: source,
        session_id,
        peer_asn,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 254),
        outbound_tx,
        export_policy: None,
        sendable_families: Vec::new(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

fn routes_received(
    source: IpAddr,
    session_id: u64,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: source,
        session_id,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// Round-trip one primary message through a running actor: every message
/// queued before it has been applied once its reply arrives.
async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    let mut route = route_with_med(
        peer(254),
        Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
        None,
    );
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute { route, reply })
        .await
        .unwrap();
    response.await.unwrap().unwrap();
}

fn received(
    manager: &mut RibManager,
    source: IpAddr,
    session_id: u64,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

async fn settle(manager: &mut RibManager, by: Duration) {
    advance(by).await;
    let _ = manager.fire_conditional_advertisement_timers();
}

fn condition_gauge(metrics: &BgpMetrics, state: &str) -> f64 {
    gauge_metric_value(
        metrics,
        "bgp_conditional_advertisement_condition",
        &[("name", NAME), ("state", state)],
    )
}

fn permitted_gauge(metrics: &BgpMetrics) -> f64 {
    gauge_metric_value(
        metrics,
        "bgp_conditional_advertisement_permitted",
        &[("name", NAME), ("advertise_if", "absent")],
    )
}

fn transitions(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_conditional_advertisement_transitions_total",
        &[("name", NAME)],
    )
}

/// A startup install is `pending` until the observation has been stable for
/// `settle_time`; every later change waits the full interval again.
#[tokio::test(start_paused = true)]
async fn settle_applies_only_after_a_stable_interval() {
    let metrics = BgpMetrics::new();
    let mut manager = manager_with(&metrics);
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let (observed, applied_state, deadline) = state(&manager);
    assert_eq!(observed, ConditionObservation::Absent);
    assert_eq!(applied_state, AppliedConditionalState::Pending);
    assert_eq!(deadline, Some(Instant::now() + SETTLE));
    assert_eq!(manager.next_conditional_advertisement_deadline(), deadline);

    settle(&mut manager, JUST_BEFORE_SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Pending);
    assert!(permitted_gauge(&metrics) < 0.5);
    settle(&mut manager, Duration::from_millis(1)).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
    assert!((permitted_gauge(&metrics) - 1.0).abs() < f64::EPSILON);
    assert!((condition_gauge(&metrics, "absent") - 1.0).abs() < f64::EPSILON);

    inject(&mut manager, prefix(1), None);
    let (observed, applied_state, deadline) = state(&manager);
    assert_eq!(observed, ConditionObservation::Present);
    assert_eq!(applied_state, AppliedConditionalState::Advertise);
    assert_eq!(deadline, Some(Instant::now() + SETTLE));
    assert!((condition_gauge(&metrics, "present") - 1.0).abs() < f64::EPSILON);
    assert!(condition_gauge(&metrics, "absent") < 0.5);

    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Suppress);
    assert!(permitted_gauge(&metrics) < 0.5);
    assert!((transitions(&metrics) - 2.0).abs() < f64::EPSILON);
}

/// A condition that flips back inside the settle window never changes the
/// applied state, however long it keeps flapping.
#[tokio::test(start_paused = true)]
async fn flapping_inside_the_window_keeps_the_applied_state() {
    let metrics = BgpMetrics::new();
    let mut manager = manager_with(&metrics);
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);

    for _ in 0..10 {
        inject(&mut manager, prefix(1), None);
        settle(&mut manager, Duration::from_secs(2)).await;
        withdraw_injected(&mut manager, prefix(1));
        settle(&mut manager, Duration::from_secs(2)).await;
        assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
    }
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
    assert!((transitions(&metrics) - 1.0).abs() < f64::EPSILON);
}

/// `unknown` cancels the timer and holds the applied state; a known
/// observation returning after it arms the full interval again, even when it
/// matches the observation before the error.
#[tokio::test(start_paused = true)]
async fn unknown_cancels_and_a_returning_observation_rearms_in_full() {
    let metrics = BgpMetrics::new();
    let mut manager = manager_with(&metrics);
    let started = Instant::now();
    let _ = manager.install_conditional_advertisements(vec![definition(
        ConditionalAdvertiseIf::Absent,
        Some(med_guard()),
        SETTLE,
    )]);
    assert_eq!(state(&manager).2, Some(started + SETTLE));

    advance(Duration::from_secs(2)).await;
    inject(&mut manager, prefix(1), Some(u32::MAX));
    let (observed, applied_state, deadline) = state(&manager);
    assert_eq!(observed, ConditionObservation::Unknown);
    assert_eq!(applied_state, AppliedConditionalState::Pending);
    assert_eq!(deadline, None);
    assert!((condition_gauge(&metrics, "unknown") - 1.0).abs() < f64::EPSILON);
    assert!(
        counter_metric_value(
            &metrics,
            "bgp_policy_eval_errors_total",
            &[("direction", "condition"), ("kind", "overflow")],
        ) >= 1.0
    );

    advance(Duration::from_secs(1)).await;
    let returned = Instant::now();
    withdraw_injected(&mut manager, prefix(1));
    assert_eq!(state(&manager).0, ConditionObservation::Absent);
    assert_eq!(state(&manager).2, Some(returned + SETTLE));

    // The original deadline (started + 5s) passes without effect.
    settle(&mut manager, JUST_BEFORE_SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Pending);
    settle(&mut manager, Duration::from_millis(1)).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);

    // A failing candidate holds the applied state indefinitely.
    inject(&mut manager, prefix(1), Some(u32::MAX));
    settle(&mut manager, SETTLE * 10).await;
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Unknown,
            AppliedConditionalState::Advertise,
            None
        )
    );
}

/// A clean match beats an erroring candidate, and a clean rejection is a
/// miss rather than an error.
#[tokio::test(start_paused = true)]
async fn clean_match_beats_error_and_rejection_is_a_miss() {
    let mut manager = manager();
    let source = peer(1);
    peer_up(&mut manager, source, 1);
    let _ = manager.install_conditional_advertisements(vec![definition(
        ConditionalAdvertiseIf::Absent,
        Some(med_guard()),
        SETTLE,
    )]);
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, prefix(1), Some(5))],
        vec![],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    inject(&mut manager, prefix(1), Some(u32::MAX));
    assert_eq!(state(&manager).0, ConditionObservation::Unknown);

    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, prefix(1), Some(0))],
        vec![],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Present);
}

/// A locally injected candidate has no peer context: a peer-address match
/// and its negation both miss it, while a route-type `local` match selects
/// it. A received candidate carries its source peer's address.
#[tokio::test(start_paused = true)]
async fn local_candidates_have_absent_peer_context() {
    let observe = |policy: PolicyChain, received_from: Option<IpAddr>| {
        let mut manager = manager();
        let _ = manager.install_conditional_advertisements(vec![definition(
            ConditionalAdvertiseIf::Present,
            Some(policy),
            SETTLE,
        )]);
        if let Some(source) = received_from {
            peer_up(&mut manager, source, 1);
            received(
                &mut manager,
                source,
                1,
                vec![route_with_med(source, prefix(1), None)],
                vec![],
            );
        } else {
            inject(&mut manager, prefix(1), None);
        }
        state(&manager).0
    };
    let equals = || {
        rpol_chain(
            "policy p { term t { if peer.address == 10.0.0.2 { accept } } term r { reject } }",
            "p",
        )
    };
    let differs = || {
        rpol_chain(
            "policy p { term t { if peer.address != 10.0.0.2 { accept } } term r { reject } }",
            "p",
        )
    };
    let local = rpol_chain(
        "policy p { term t { if route.route-type == local { accept } } term r { reject } }",
        "p",
    );
    assert_eq!(observe(equals(), None), ConditionObservation::Absent);
    assert_eq!(observe(differs(), None), ConditionObservation::Absent);
    assert_eq!(observe(local, None), ConditionObservation::Present);
    assert_eq!(
        observe(equals(), Some(peer(2))),
        ConditionObservation::Present
    );
    assert_eq!(
        observe(differs(), Some(peer(3))),
        ConditionObservation::Present
    );
    assert_eq!(
        observe(differs(), Some(peer(2))),
        ConditionObservation::Absent
    );
}

/// Route churn outside the condition prefixes visits no condition candidate:
/// the observation is driven by the prefix index, not a table walk. The
/// condition prefix holds a candidate throughout, so any re-observation of
/// the definition would be counted.
#[tokio::test(start_paused = true)]
async fn observation_is_indexed_and_never_walks_the_table() {
    let mut manager = manager();
    let source = peer(1);
    peer_up(&mut manager, source, 1);
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    inject(&mut manager, prefix(1), None);
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    let baseline = manager.conditional_advertisement_candidate_visits();

    let others: Vec<_> = (2..=200)
        .map(|octet| route_with_med(source, prefix(octet), None))
        .collect();
    received(&mut manager, source, 1, others, vec![]);
    let withdrawn: Vec<_> = (2..=200)
        .map(|octet| (Prefix::V4(prefix(octet)), 0))
        .collect();
    received(&mut manager, source, 1, vec![], withdrawn);
    assert_eq!(
        manager.conditional_advertisement_candidate_visits(),
        baseline
    );

    // A second candidate on the condition prefix is observed (both are
    // candidates; the first one visited already decides presence).
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    );
    assert!(manager.conditional_advertisement_candidate_visits() > baseline);

    // Losing every candidate (withdrawal plus peer teardown) is absence.
    withdraw_injected(&mut manager, prefix(1));
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    manager.handle_update(RibUpdate::PeerDown {
        peer: source,
        session_id: 1,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(state(&manager).0, ConditionObservation::Absent);
}

/// RFC 4724 selection deferral holds a definition `pending` with no armed
/// timer; the release arms a fresh interval from the release time.
#[tokio::test(start_paused = true)]
async fn selection_deferral_holds_pending_until_release() {
    let waiter = peer(9);
    let mut manager = manager().with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(30),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        }],
    });
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            None
        )
    );
    inject(&mut manager, prefix(1), None);
    withdraw_injected(&mut manager, prefix(1));
    settle(&mut manager, Duration::from_secs(29)).await;
    assert_eq!(state(&manager).2, None);
    assert_eq!(applied(&manager), AppliedConditionalState::Pending);
    let held = &manager.conditional_advertisement_status()[0];
    assert!(held.selection_deferred);
    assert_eq!((held.applied, held.settle_remaining), ("pending", None));

    advance(Duration::from_secs(1)).await;
    manager.expire_selection_deferral();
    let released = Instant::now();
    assert_eq!(state(&manager).2, Some(released + SETTLE));
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
}

/// A later install keeps unchanged definitions' state and applies a changed
/// definition immediately. Compensation restores the prior applied state and
/// deadline without evaluating again; a RIB change during the failed
/// generation restarts the debounce from the restore time.
#[tokio::test(start_paused = true)]
async fn install_and_rollback_preserve_the_debounce() {
    let metrics = BgpMetrics::new();
    let mut manager = manager_with(&metrics);
    let started = Instant::now();
    let _ = manager.install_conditional_advertisements(vec![absent_if(Duration::from_secs(10))]);
    advance(Duration::from_secs(3)).await;

    // Unchanged content: same state, same deadline.
    let (_, transitions) =
        manager.install_conditional_advertisements(vec![absent_if(Duration::from_secs(10))]);
    assert_eq!(transitions, Vec::<Arc<str>>::new());
    assert_eq!(state(&manager).2, Some(started + Duration::from_secs(10)));

    // Changed content applies at once, then compensation restores.
    let (capture, transitions) =
        manager.install_conditional_advertisements(vec![absent_if(Duration::from_secs(20))]);
    assert_eq!(transitions, vec![Arc::from(NAME)]);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Advertise,
            None
        )
    );
    assert!((self::transitions(&metrics) - 1.0).abs() < f64::EPSILON);
    let transitions = manager.restore_conditional_advertisements(capture.clone());
    assert_eq!(transitions, vec![Arc::from(NAME)]);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            Some(started + Duration::from_secs(10))
        )
    );
    // Restoring a different applied state is itself a counted transition.
    assert!((self::transitions(&metrics) - 2.0).abs() < f64::EPSILON);
    assert!(permitted_gauge(&metrics) < 0.5);
    settle(&mut manager, Duration::from_secs(7)).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
    assert!((self::transitions(&metrics) - 3.0).abs() < f64::EPSILON);

    // Rollback while the RIB moved during the failed generation.
    let mut manager = self::manager();
    let started = Instant::now();
    let _ = manager.install_conditional_advertisements(vec![absent_if(Duration::from_secs(10))]);
    advance(Duration::from_secs(3)).await;
    let (capture, _) =
        manager.install_conditional_advertisements(vec![absent_if(Duration::from_secs(20))]);
    advance(Duration::from_secs(1)).await;
    inject(&mut manager, prefix(1), None);
    advance(Duration::from_secs(1)).await;
    let restored_at = Instant::now();
    let _ = manager.restore_conditional_advertisements(capture);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Present,
            AppliedConditionalState::Pending,
            Some(restored_at + Duration::from_secs(10))
        )
    );
    assert_ne!(restored_at, started + Duration::from_secs(10));
}

/// A dataset swap re-observes only the definitions whose `condition_policy`
/// references the swapped dataset, under the ordinary debounce.
#[tokio::test(start_paused = true)]
async fn dataset_swap_reobserves_only_dependent_definitions() {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry};

    let data = |listed: bool| {
        DatasetData::Prefix(PrefixSet::new(listed.then_some(PrefixSetEntry {
            prefix: condition(),
            ge: None,
            le: None,
        })))
    };
    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        data(false),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled = RpolFile::parse(
        "dataset prefix-set allowed\npolicy p { term t { if route.prefix in allowed { accept } reject } }",
    )
    .unwrap()
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .unwrap()
    .unwrap();
    let policy = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);

    let mut manager = manager();
    let _ = manager.install_conditional_advertisements(vec![definition(
        ConditionalAdvertiseIf::Present,
        Some(policy),
        SETTLE,
    )]);
    inject(&mut manager, prefix(1), None);
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    handle.refresh(data(true));
    let visits = manager.conditional_advertisement_candidate_visits();
    let _ = manager.reevaluate_conditional_advertisement_datasets(&["unrelated".to_string()]);
    assert_eq!(manager.conditional_advertisement_candidate_visits(), visits);
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    let swapped = Instant::now();
    let _ = manager.reevaluate_conditional_advertisement_datasets(&["allowed".to_string()]);
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    assert_eq!(state(&manager).2, Some(swapped + SETTLE));
}

/// The actor's run loop arms and fires the settle timer itself.
#[tokio::test(start_paused = true)]
async fn run_loop_fires_the_settle_timer() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let handle = tokio::spawn(manager.run());

    tokio::time::sleep(JUST_BEFORE_SETTLE).await;
    assert!(permitted_gauge(&metrics) < 0.5);
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert!((permitted_gauge(&metrics) - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// A capture taken during selection deferral has no deadline. When the
/// release happens while the failed generation is installed, the restore
/// must arm the restored definition, or it stays `pending` for good.
#[tokio::test(start_paused = true)]
async fn rollback_after_deferral_release_arms_the_restored_definition() {
    let waiter = peer(9);
    let metrics = BgpMetrics::new();
    let mut manager = manager_with(&metrics).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(30),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        }],
    });
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let (capture, _) = manager.install_conditional_advertisements(vec![absent_if(SETTLE * 2)]);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            None
        )
    );

    advance(Duration::from_secs(30)).await;
    manager.expire_selection_deferral();
    assert!(state(&manager).2.is_some());

    advance(Duration::from_secs(1)).await;
    let restored_at = Instant::now();
    let _ = manager.restore_conditional_advertisements(capture);
    assert_eq!(
        state(&manager),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            Some(restored_at + SETTLE)
        )
    );
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
}

/// A candidate retained in Adj-RIB-In but skipped by selection (an invalid
/// `SRv6` service SID structure) is still an accepted condition candidate.
#[tokio::test(start_paused = true)]
async fn selection_ineligible_candidate_still_counts() {
    use crate::srv6::tests::service_attribute;

    let mut manager = manager();
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let mut route = route_with_med(peer(254), prefix(1), None);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(service_attribute(
            5,
            "2001:db8:111:1::".parse().unwrap(),
            19,
            Some([100, 24, 16, 0, 0, 0]),
        ));
    });
    let (reply, _rx) = oneshot::channel();
    manager.handle_inject_route(route, reply);
    assert!(manager.loc_rib.get(&condition()).is_none());
    assert_eq!(state(&manager).0, ConditionObservation::Present);
}

/// A `condition_policy` that reads the source peer's group re-observes when
/// that membership changes, with no route churn at all.
#[tokio::test(start_paused = true)]
async fn source_peer_group_change_reobserves_without_route_churn() {
    let source = peer(1);
    let mut manager = manager();
    peer_up(&mut manager, source, 1);
    let _ = manager.install_conditional_advertisements(vec![definition(
        ConditionalAdvertiseIf::Present,
        Some(rpol_chain(
            r#"policy p { term t { if peer.group == "transit" { accept } } term r { reject } }"#,
            "p",
        )),
        SETTLE,
    )]);
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    let joined = Instant::now();
    manager.handle_set_peer_policy_context(source, Some("transit".to_string()));
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    assert_eq!(state(&manager).2, Some(joined + SETTLE));

    advance(Duration::from_secs(1)).await;
    manager.handle_set_peer_policy_context(source, None);
    assert_eq!(state(&manager).0, ConditionObservation::Absent);
}

/// A settle deadline that passes while a route batch is queued applies the
/// observation of the finished batch, not the one the batch made obsolete,
/// whichever of the timer and the ready update the actor sees first.
#[tokio::test(start_paused = true)]
async fn expiry_during_an_open_batch_waits_for_its_observation() {
    let metrics = BgpMetrics::new();
    let source = peer(1);
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let handle = tokio::spawn(manager.run());

    tx.send(peer_up_update(source, 1, 65001)).await.unwrap();
    tokio::time::sleep(JUST_BEFORE_SETTLE).await;
    assert!(condition_gauge(&metrics, "absent") > 0.5);

    // The condition arrives first in a multi-chunk batch queued just before
    // the deadline; the deadline passes before the actor runs again.
    let mut announced = vec![route_with_med(source, prefix(1), None)];
    announced.extend((0..2_048_u32).map(|index| {
        let [_, _, high, low] = index.to_be_bytes();
        route_with_med(
            source,
            Ipv4Prefix::new(Ipv4Addr::new(203, high, low, 0), 24),
            None,
        )
    }));
    tx.send(routes_received(source, 1, announced, vec![]))
        .await
        .unwrap();
    advance(Duration::from_millis(2)).await;
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert!((condition_gauge(&metrics, "present") - 1.0).abs() < f64::EPSILON);
    assert!(permitted_gauge(&metrics) < 0.5);
    assert!(transitions(&metrics) < 0.5);

    tokio::time::sleep(SETTLE).await;
    assert!(permitted_gauge(&metrics) < 0.5);
    assert!((transitions(&metrics) - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// A GR-retained candidate outlives its session; a reconnect that changes
/// the source peer's ASN re-observes a `condition_policy` that reads it.
#[tokio::test(start_paused = true)]
async fn retained_route_reconnect_with_a_new_asn_reobserves() {
    let source = peer(1);
    let mut manager = manager();
    manager.handle_update(peer_up_update(source, 1, 65001));
    let _ = manager.install_conditional_advertisements(vec![definition(
        ConditionalAdvertiseIf::Present,
        Some(rpol_chain(
            "policy p { term t { if peer.asn == 65002 { accept } } term r { reject } }",
            "p",
        )),
        SETTLE,
    )]);
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: source,
        session_id: 1,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    drain_route_chunks(&mut manager);
    assert!(
        manager.ribs[&source]
            .iter_prefix(&condition())
            .next()
            .is_some()
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    let reconnected = Instant::now();
    manager.handle_update(peer_up_update(source, 2, 65002));
    assert!(
        manager.ribs[&source]
            .iter_prefix(&condition())
            .next()
            .is_some()
    );
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    assert_eq!(state(&manager).2, Some(reconnected + SETTLE));
}

/// Sustained unrelated traffic while another timer (a GR stale deadline)
/// is overdue cannot starve a due settle deadline: the channel stays full
/// because each send waits for the actor to free a slot.
#[tokio::test(start_paused = true)]
async fn settle_expiry_is_served_beside_an_overdue_timer_under_traffic() {
    let metrics = BgpMetrics::new();
    let (source, restarting) = (peer(1), peer(2));
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let handle = tokio::spawn(manager.run());

    tx.send(peer_up_update(source, 1, 65001)).await.unwrap();
    tx.send(peer_up_update(restarting, 1, 65002)).await.unwrap();
    tx.send(routes_received(
        restarting,
        1,
        vec![route_with_med(restarting, prefix(9), None)],
        vec![],
    ))
    .await
    .unwrap();
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: restarting,
        session_id: 1,
        restart_time: 1,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    barrier(&tx).await;

    let unrelated = || {
        routes_received(
            source,
            1,
            vec![route_with_med(source, prefix(7), None)],
            vec![],
        )
    };
    for _ in 0..8 {
        tx.send(unrelated()).await.unwrap();
    }
    // Both deadlines are now overdue, with the mailbox full.
    advance(SETTLE + Duration::from_millis(1)).await;
    let mut sent = 0;
    while permitted_gauge(&metrics) < 0.5 {
        assert!(
            sent < 1_000,
            "settle expiry starved behind unrelated updates"
        );
        tx.send(unrelated()).await.unwrap();
        sent += 1;
    }
    assert!((transitions(&metrics) - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

fn unrelated_two_chunk(source: IpAddr, octet: u8) -> RibUpdate {
    routes_received(
        source,
        1,
        vec![route_with_med(source, prefix(octet), None)],
        vec![(Prefix::V4(prefix(octet.wrapping_add(100))), 0)],
    )
}

async fn spawn_with_source(
    metrics: &BgpMetrics,
    source: IpAddr,
) -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    // Coalescing must not depend on wall-clock speed under test load.
    manager.distribution_window_limits.elapsed = Duration::from_secs(3_600);
    let _ = manager.install_conditional_advertisements(vec![absent_if(SETTLE)]);
    let handle = tokio::spawn(manager.run());
    tx.send(peer_up_update(source, 1, 65001)).await.unwrap();
    barrier(&tx).await;
    (tx, handle)
}

/// A batch already open when the deadline falls due finishes first, but its
/// distribution window must not coalesce a message that arrived after the
/// cutoff: that later condition change cannot cancel the due expiry.
#[tokio::test(start_paused = true)]
async fn expiry_cutoff_stops_an_open_batch_window_from_extending() {
    let metrics = BgpMetrics::new();
    let source = peer(1);
    let (tx, handle) = spawn_with_source(&metrics, source).await;

    advance(JUST_BEFORE_SETTLE).await;
    // Three chunks: two withdrawal chunks and one announcement.
    let withdrawn: Vec<_> = (0..1_025_u32)
        .map(|index| {
            let [_, _, high, low] = index.to_be_bytes();
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, high, low, 0), 24)),
                0,
            )
        })
        .collect();
    tx.send(routes_received(
        source,
        1,
        vec![route_with_med(source, prefix(7), None)],
        withdrawn,
    ))
    .await
    .unwrap();
    // The actor receives the batch and runs its first chunk.
    tokio::task::yield_now().await;
    advance(Duration::from_millis(2)).await;
    // The actor saw the deadline due with the batch open; this message is
    // after the cutoff.
    tx.send(routes_received(
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    ))
    .await
    .unwrap();
    barrier(&tx).await;

    assert!((transitions(&metrics) - 1.0).abs() < f64::EPSILON);
    assert!((condition_gauge(&metrics, "present") - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// Messages queued when the deadline falls due are admitted before it fires,
/// coalesced or not, and each admission is charged: a condition change
/// queued after them, even one a window could coalesce, waits for expiry.
#[tokio::test(start_paused = true)]
async fn expiry_cutoff_charges_coalesced_queued_messages() {
    let metrics = BgpMetrics::new();
    let source = peer(1);
    let (tx, handle) = spawn_with_source(&metrics, source).await;

    for octet in [7, 8, 9] {
        tx.send(unrelated_two_chunk(source, octet)).await.unwrap();
    }
    advance(SETTLE + Duration::from_millis(1)).await;
    tx.send(routes_received(
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    ))
    .await
    .unwrap();
    barrier(&tx).await;
    assert!((transitions(&metrics) - 1.0).abs() < f64::EPSILON);
    assert!((condition_gauge(&metrics, "present") - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();

    // The same condition change queued before the deadline does cancel it.
    let metrics = BgpMetrics::new();
    let (tx, handle_2) = spawn_with_source(&metrics, source).await;
    for octet in [7, 8] {
        tx.send(unrelated_two_chunk(source, octet)).await.unwrap();
    }
    tx.send(routes_received(
        source,
        1,
        vec![route_with_med(source, prefix(1), None)],
        vec![],
    ))
    .await
    .unwrap();
    advance(SETTLE + Duration::from_millis(1)).await;
    barrier(&tx).await;
    assert!(transitions(&metrics) < 0.5);
    assert!((condition_gauge(&metrics, "present") - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle_2.await.unwrap();
}

/// `(entry, state)` per condition entry of a status row.
fn condition_states(status: &crate::ConditionalAdvertisementStatus) -> Vec<(String, &'static str)> {
    status
        .conditions
        .iter()
        .map(|condition| (condition.entry.to_string(), condition.state))
        .collect()
}

fn status(manager: &RibManager, name: &str) -> crate::ConditionalAdvertisementStatus {
    manager
        .conditional_advertisement_status()
        .into_iter()
        .find(|status| &*status.name == name)
        .unwrap()
}

/// The status view: definitions in name order with their attached peers,
/// each condition prefix's own observation (present, absent, or unknown
/// beside a clean match), the applied state, and the settle timer pending
/// with its remaining time or settled.
#[tokio::test(start_paused = true)]
async fn status_reports_conditions_applied_state_settle_and_attachments() {
    let mut manager = manager();
    let core = ConditionalAdvertisement {
        name: Arc::from("core"),
        advertise_policy: PolicyChain::default(),
        advertise_if: ConditionalAdvertiseIf::Present,
        condition_prefixes: vec![
            rustbgpd_policy::sets::PrefixSetEntry::exact(Prefix::V4(prefix(2))),
            rustbgpd_policy::sets::PrefixSetEntry::exact(Prefix::V4(prefix(3))),
        ],
        condition_policy: Some(med_guard()),
        settle_time: Duration::ZERO,
    };
    let _ = manager.handle_install_conditional_advertisements(crate::ConditionalAdvertisementSet {
        definitions: vec![core, absent_if(SETTLE)],
        attachments: [
            (peer(1), vec![Arc::from(NAME)]),
            (peer(2), vec![Arc::from(NAME), Arc::from("core")]),
        ]
        .into_iter()
        .collect(),
    });
    let names: Vec<String> = manager
        .conditional_advertisement_status()
        .iter()
        .map(|status| status.name.to_string())
        .collect();
    assert_eq!(names, [NAME, "core"]);

    // Startup: pending behind an armed settle timer.
    let backup = status(&manager, NAME);
    assert_eq!(backup.advertise_if, ConditionalAdvertiseIf::Absent);
    assert_eq!(
        condition_states(&backup),
        [(condition().to_string(), "absent")]
    );
    assert_eq!((backup.observed, backup.applied), ("absent", "pending"));
    assert_eq!(backup.settle_time, SETTLE);
    assert_eq!(backup.settle_remaining, Some(SETTLE));
    assert!(!backup.selection_deferred);
    assert_eq!(backup.attached_peers, [peer(1), peer(2)]);
    // settle_time 0 applies at install: settled, nothing armed.
    let core = status(&manager, "core");
    assert_eq!((core.observed, core.applied), ("absent", "suppress"));
    assert_eq!(core.settle_remaining, None);
    assert_eq!(core.attached_peers, [peer(2)]);

    // A changed observation restarts the timer; time shows on both clocks.
    advance(Duration::from_secs(2)).await;
    inject(&mut manager, prefix(1), None);
    advance(Duration::from_secs(2)).await;
    let backup = status(&manager, NAME);
    assert_eq!(
        condition_states(&backup),
        [(condition().to_string(), "present")]
    );
    assert_eq!((backup.observed, backup.applied), ("present", "pending"));
    assert_eq!(backup.observed_for, Duration::from_secs(2));
    assert_eq!(backup.settle_remaining, Some(Duration::from_secs(3)));
    settle(&mut manager, Duration::from_secs(3)).await;
    let backup = status(&manager, NAME);
    assert_eq!(
        (backup.applied, backup.settle_remaining),
        ("suppress", None)
    );

    // Per-prefix observations: a clean match on one prefix and an
    // evaluation error on the other leave the whole condition present.
    inject(&mut manager, prefix(2), Some(0));
    inject(&mut manager, prefix(3), Some(u32::MAX));
    let core = status(&manager, "core");
    assert_eq!(
        condition_states(&core),
        [
            (prefix(2).to_string(), "present"),
            (prefix(3).to_string(), "unknown")
        ]
    );
    assert_eq!((core.observed, core.applied), ("present", "advertise"));
    // Without the match, the error makes the whole condition unknown and
    // the applied state holds.
    withdraw_injected(&mut manager, prefix(2));
    let core = status(&manager, "core");
    assert_eq!(
        condition_states(&core),
        [
            (prefix(2).to_string(), "absent"),
            (prefix(3).to_string(), "unknown")
        ]
    );
    assert_eq!((core.observed, core.applied), ("unknown", "advertise"));
}

/// The query is served through the actor's channel like any RIB read.
#[tokio::test(start_paused = true)]
async fn status_query_is_served_by_the_running_actor() {
    let (tx, rx) = mpsc::channel(8);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_conditional_advertisements(crate::ConditionalAdvertisementSet {
            definitions: vec![absent_if(SETTLE)],
            attachments: [(peer(1), vec![Arc::from(NAME)])].into_iter().collect(),
        });
    let actor = tokio::spawn(manager.run());
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryConditionalAdvertisements { reply })
        .await
        .unwrap();
    let statuses = response.await.unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(&*statuses[0].name, NAME);
    assert_eq!(statuses[0].attached_peers, [peer(1)]);
    drop(tx);
    actor.await.unwrap();
}

fn v4(a: u8, b: u8, c: u8, len: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, a, b, c), len)
}

fn range(base: Ipv4Prefix, ge: Option<u8>, le: Option<u8>) -> PrefixSetEntry {
    PrefixSetEntry {
        prefix: Prefix::V4(base),
        ge,
        le,
    }
}

fn ranged(name: &str, entries: Vec<PrefixSetEntry>, settle: Duration) -> ConditionalAdvertisement {
    ConditionalAdvertisement {
        name: Arc::from(name),
        advertise_policy: PolicyChain::default(),
        advertise_if: ConditionalAdvertiseIf::Absent,
        condition_prefixes: entries,
        condition_policy: None,
        settle_time: settle,
    }
}

fn observed(manager: &RibManager, name: &str) -> ConditionObservation {
    manager.conditional_advertisement_state(name).unwrap().0
}

/// A range condition (`10.0.0.0/8 le 24`) through the real RIB path: a
/// prefix already held at install counts (the full rescan), a received or
/// injected prefix inside the range makes it present under the ordinary
/// debounce, the condition stays present until the last in-range prefix
/// goes, and prefixes outside the range never count.
#[tokio::test(start_paused = true)]
async fn range_condition_appears_and_disappears() {
    let mut manager = manager();
    let source = peer(1);
    peer_up(&mut manager, source, 1);
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, v4(9, 0, 0, 16), None)],
        vec![],
    );
    let _ = manager.install_conditional_advertisements(vec![ranged(
        NAME,
        vec![range(v4(0, 0, 0, 8), None, Some(24))],
        SETTLE,
    )]);
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    received(
        &mut manager,
        source,
        1,
        vec![],
        vec![(Prefix::V4(v4(9, 0, 0, 16)), 0)],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);

    // Outside the range: a longer prefix than `le`, and another /8.
    inject(&mut manager, v4(3, 3, 0, 25), None);
    inject(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(11, 1, 0, 0), 16),
        None,
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);

    inject(&mut manager, v4(1, 0, 0, 16), None);
    let (observed_now, applied_now, deadline) = state(&manager);
    assert_eq!(observed_now, ConditionObservation::Present);
    assert_eq!(applied_now, AppliedConditionalState::Advertise);
    assert_eq!(deadline, Some(Instant::now() + SETTLE));
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Suppress);

    // Two in-range prefixes: losing one keeps the condition present.
    received(
        &mut manager,
        source,
        1,
        vec![route_with_med(source, v4(2, 0, 0, 24), None)],
        vec![],
    );
    withdraw_injected(&mut manager, v4(1, 0, 0, 16));
    assert_eq!(state(&manager).0, ConditionObservation::Present);
    received(
        &mut manager,
        source,
        1,
        vec![],
        vec![(Prefix::V4(v4(2, 0, 0, 24)), 0)],
    );
    assert_eq!(state(&manager).0, ConditionObservation::Absent);
    settle(&mut manager, SETTLE).await;
    assert_eq!(applied(&manager), AppliedConditionalState::Advertise);
}

/// Overlapping ranges in two definitions: one prefix inside both drives
/// both; a prefix inside only the wider range drives only that one.
#[tokio::test(start_paused = true)]
async fn overlapping_ranges_across_definitions_track_independently() {
    let mut manager = manager();
    let _ = manager.install_conditional_advertisements(vec![
        ranged("wide", vec![range(v4(0, 0, 0, 8), None, Some(24))], SETTLE),
        ranged(
            "narrow",
            vec![range(v4(1, 0, 0, 16), Some(24), Some(24))],
            SETTLE,
        ),
    ]);
    inject(&mut manager, v4(1, 2, 0, 24), None);
    assert_eq!(observed(&manager, "wide"), ConditionObservation::Present);
    assert_eq!(observed(&manager, "narrow"), ConditionObservation::Present);

    inject(&mut manager, v4(2, 0, 0, 16), None);
    withdraw_injected(&mut manager, v4(1, 2, 0, 24));
    assert_eq!(observed(&manager, "wide"), ConditionObservation::Present);
    assert_eq!(observed(&manager, "narrow"), ConditionObservation::Absent);

    withdraw_injected(&mut manager, v4(2, 0, 0, 16));
    assert_eq!(observed(&manager, "wide"), ConditionObservation::Absent);
}

/// `ge`/`le` bounds are inclusive: a prefix one bit outside either bound
/// misses, and one on each bound matches.
#[tokio::test(start_paused = true)]
async fn range_bounds_match_inclusively_and_miss_one_bit_outside() {
    let mut manager = manager();
    let _ = manager.install_conditional_advertisements(vec![ranged(
        NAME,
        vec![range(v4(0, 0, 0, 8), Some(16), Some(24))],
        SETTLE,
    )]);
    for outside in [v4(0, 0, 0, 15), v4(0, 0, 0, 25), v4(0, 0, 0, 8)] {
        inject(&mut manager, outside, None);
        assert_eq!(
            state(&manager).0,
            ConditionObservation::Absent,
            "{outside} is outside ge 16 le 24"
        );
        withdraw_injected(&mut manager, outside);
    }
    for inside in [v4(0, 0, 0, 16), v4(0, 0, 0, 24)] {
        inject(&mut manager, inside, None);
        assert_eq!(
            state(&manager).0,
            ConditionObservation::Present,
            "{inside} is on a bound of ge 16 le 24"
        );
        withdraw_injected(&mut manager, inside);
        assert_eq!(state(&manager).0, ConditionObservation::Absent);
    }
}

/// The status view of a range entry: its bounds, its own state, the count of
/// present in-range prefixes, and at most eight of them in address order.
/// An entry with only evaluation errors in range reports `unknown`.
#[tokio::test(start_paused = true)]
async fn status_reports_range_counts_with_a_bounded_sample() {
    let mut manager = manager();
    let mut definition = ranged(
        NAME,
        vec![
            range(v4(0, 0, 0, 8), None, Some(24)),
            range(v4(200, 0, 0, 16), Some(24), None),
            PrefixSetEntry::exact(condition()),
        ],
        SETTLE,
    );
    definition.condition_policy = Some(med_guard());
    let _ = manager.install_conditional_advertisements(vec![definition]);
    for octet in (1..=10).rev() {
        inject(&mut manager, v4(octet, 0, 0, 16), Some(0));
    }
    inject(&mut manager, v4(200, 0, 7, 24), Some(u32::MAX));

    let row = status(&manager, NAME);
    assert_eq!(
        condition_states(&row),
        [
            ("10.0.0.0/8 le 24".to_string(), "present"),
            ("10.200.0.0/16 ge 24".to_string(), "unknown"),
            (condition().to_string(), "absent"),
        ]
    );
    let wide = &row.conditions[0];
    assert_eq!(wide.present_count, 10);
    assert_eq!(
        wide.present_sample,
        (1..=8)
            .map(|octet| Prefix::V4(v4(octet, 0, 0, 16)))
            .collect::<Vec<_>>()
    );
    assert_eq!(row.conditions[1].present_count, 0);
    assert_eq!(row.conditions[1].present_sample, Vec::<Prefix>::new());
    assert_eq!(row.observed, "present");
}
