//! ADR-0137 slice 2: condition-tracker state machine under a paused clock.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_policy::PolicyChain;
use rustbgpd_policy::rpol::RpolFile;
use rustbgpd_policy::sets::SetStore;
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
        condition_prefixes: vec![condition()],
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
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer: source,
        session_id,
        peer_asn: 65001,
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
    });
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

    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 1,
        peer_asn: 65001,
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
    })
    .await
    .unwrap();
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
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 1,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
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
