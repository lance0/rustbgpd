use super::super::conditional_advertisement::{AppliedConditionalState, ConditionObservation};
use super::*;
use crate::{ConditionalAdvertiseIf, ConditionalAdvertisement, ConditionalAdvertisementSet};
use tokio::time::{Instant, advance};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 91);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 92);
const NAME: &str = "dormant-backup";
const SETTLE: Duration = Duration::from_secs(10);

fn definition(name: &str, condition: Prefix, settle_time: Duration) -> ConditionalAdvertisement {
    ConditionalAdvertisement {
        name: Arc::from(name),
        advertise_policy: rustbgpd_policy::PolicyChain::default(),
        advertise_if: ConditionalAdvertiseIf::Absent,
        condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(condition)],
        condition_policy: None,
        settle_time,
        retiring: false,
    }
}

fn manager(definitions: Vec<ConditionalAdvertisement>) -> RibManager {
    let (_tx, rx) = mpsc::channel(16);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        })
        .with_conditional_advertisements(ConditionalAdvertisementSet {
            definitions,
            attachments: BTreeMap::from([(peer_v4(OBSERVER).addr().into(), vec![Arc::from(NAME)])]),
        })
}

fn release(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: u64::from(WAITER.octets()[3]),
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_deferred(FAMILY));
}

fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    waiter: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let session_id = u64::from(address.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { vec![FAMILY] } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(32);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
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

fn announcements(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<(Prefix, u32)> {
    let mut routes = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        routes.extend(
            update
                .announce
                .iter()
                .map(|route| (route.prefix, route.path_id)),
        );
    }
    routes
}

async fn fire_and_resync(manager: &mut RibManager, elapsed: Duration) {
    advance(elapsed).await;
    let _ = manager.fire_conditional_advertisement_timers();
    while manager.resync_dirty_peers_bounded() {}
}

#[tokio::test(start_paused = true)]
async fn dormant_conditional_timer_cannot_release_rtbh_during_a_new_gr_hold() {
    let condition = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 91), 32);
    let mut manager = manager(vec![definition(NAME, condition, SETTLE)]);
    let original_deadline = Instant::now() + SETTLE;
    assert!(!manager.selection_deferred(FAMILY));
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            Some(original_deadline),
        )
    );
    let mut observer_rx = connect(&mut manager, OBSERVER, false);
    let initial = observer_rx.try_recv().unwrap();
    assert_eq!(initial.end_of_rib, [FAMILY]);
    assert_eq!(initial.announce.len(), 0);

    let mut route = make_route(host, WAITER);
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ]);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(host)).unwrap().peer,
        crate::PeerId::LOCAL
    );
    assert_eq!(announcements(&mut observer_rx), [] as [(Prefix, u32); 0]);

    advance(Duration::from_secs(3)).await;
    let _waiter_rx = connect(&mut manager, WAITER, true);
    assert!(manager.selection_deferred(FAMILY));
    assert_eq!(manager.next_conditional_advertisement_deadline(), None);
    assert_eq!(announcements(&mut observer_rx), [] as [(Prefix, u32); 0]);
    fire_and_resync(&mut manager, Duration::from_secs(7)).await;
    assert_eq!(Instant::now(), original_deadline);
    assert!(manager.selection_deferred(FAMILY));
    let held = manager.conditional_advertisement_state(NAME).unwrap();
    let escaped = announcements(&mut observer_rx);
    assert_eq!(
        (held.1, escaped),
        (
            AppliedConditionalState::Pending,
            Vec::<(Prefix, u32)>::new()
        ),
        "the old dormant deadline must not permit or announce RTBH while the current waiter owes EoR"
    );
    assert_eq!(held.2, None);

    release(&mut manager);
    let released = Instant::now();
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            Some(released + SETTLE),
        )
    );
    assert_eq!(announcements(&mut observer_rx), [] as [(Prefix, u32); 0]);
    fire_and_resync(
        &mut manager,
        SETTLE.checked_sub(Duration::from_millis(1)).unwrap(),
    )
    .await;
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Pending
    );
    assert_eq!(announcements(&mut observer_rx), [] as [(Prefix, u32); 0]);
    fire_and_resync(&mut manager, Duration::from_millis(1)).await;
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Advertise,
            None,
        )
    );
    assert_eq!(announcements(&mut observer_rx), [(Prefix::V4(host), 0)]);
}

#[tokio::test(start_paused = true)]
async fn restoring_a_dormant_capture_cannot_rearm_a_timer_during_selection_hold() {
    let condition = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let mut manager = manager(vec![definition(NAME, condition, SETTLE)]);
    let original_deadline = manager.next_conditional_advertisement_deadline().unwrap();
    let capture = manager
        .handle_install_conditional_advertisements(ConditionalAdvertisementSet::default(), &[]);
    advance(Duration::from_secs(3)).await;
    let _waiter_rx = connect(&mut manager, WAITER, true);
    assert!(manager.selection_deferred(FAMILY));
    manager.handle_restore_conditional_advertisements(capture);
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            None,
        )
    );
    assert_eq!(manager.next_conditional_advertisement_deadline(), None);
    fire_and_resync(&mut manager, Duration::from_secs(7)).await;
    assert_eq!(Instant::now(), original_deadline);
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Pending
    );
    release(&mut manager);
    assert_eq!(
        manager.next_conditional_advertisement_deadline(),
        Some(Instant::now() + SETTLE)
    );
    fire_and_resync(&mut manager, SETTLE).await;
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Advertise
    );
}

#[tokio::test(start_paused = true)]
async fn restoring_a_dormant_capture_after_release_restarts_the_full_settle_interval() {
    let condition = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let mut manager = manager(vec![definition(NAME, condition, SETTLE)]);
    let original_deadline = manager.next_conditional_advertisement_deadline().unwrap();
    let capture = manager
        .handle_install_conditional_advertisements(ConditionalAdvertisementSet::default(), &[]);
    advance(Duration::from_secs(3)).await;
    let _waiter_rx = connect(&mut manager, WAITER, true);
    assert!(manager.selection_deferred(FAMILY));
    advance(Duration::from_secs(5)).await;
    release(&mut manager);
    manager.handle_restore_conditional_advertisements(capture);
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Pending,
            Some(Instant::now() + SETTLE),
        )
    );
    fire_and_resync(&mut manager, Duration::from_secs(2)).await;
    assert_eq!(Instant::now(), original_deadline);
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Pending
    );
    fire_and_resync(&mut manager, Duration::from_secs(8)).await;
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Advertise
    );
}

#[tokio::test(start_paused = true)]
async fn selection_activation_preserves_applied_zero_settle_and_other_family_timer() {
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64));
    let mut suppressed = definition("suppressed", v4, Duration::ZERO);
    suppressed.advertise_if = ConditionalAdvertiseIf::Present;
    let mut manager = manager(vec![
        definition(NAME, v4, Duration::ZERO),
        suppressed,
        definition("v6", v6, SETTLE),
    ]);
    let original_deadline = Instant::now() + SETTLE;
    let _waiter_rx = connect(&mut manager, WAITER, true);
    assert!(manager.selection_deferred(FAMILY));
    assert_eq!(
        manager.next_conditional_advertisement_deadline(),
        Some(original_deadline)
    );
    for (name, applied) in [
        (NAME, AppliedConditionalState::Advertise),
        ("suppressed", AppliedConditionalState::Suppress),
    ] {
        assert_eq!(
            manager.conditional_advertisement_state(name).unwrap(),
            (ConditionObservation::Absent, applied, None)
        );
    }
    fire_and_resync(&mut manager, SETTLE).await;
    assert!(manager.selection_deferred(FAMILY));
    assert_eq!(
        manager.conditional_advertisement_state("v6").unwrap(),
        (
            ConditionObservation::Absent,
            AppliedConditionalState::Advertise,
            None,
        )
    );
    release(&mut manager);
    assert_eq!(manager.next_conditional_advertisement_deadline(), None);
    assert_eq!(
        manager.conditional_advertisement_state(NAME).unwrap().1,
        AppliedConditionalState::Advertise
    );
    assert_eq!(
        manager
            .conditional_advertisement_state("suppressed")
            .unwrap()
            .1,
        AppliedConditionalState::Suppress
    );
}

fn readiness_visits(
    manager: &mut RibManager,
    work: impl FnOnce(&mut RibManager),
) -> BTreeMap<&'static str, usize> {
    use std::sync::Mutex;

    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    manager.readiness_rx = Some(readiness_rx);
    manager.flush_poll_budget = Duration::ZERO;
    let pending = Arc::new(Mutex::new(
        None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>,
    ));
    let visits = Arc::new(Mutex::new(BTreeMap::new()));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let pending = Arc::clone(&pending);
        let visits = Arc::clone(&visits);
        move |stage| {
            if !matches!(
                stage,
                "conditional_suspend_family"
                    | "conditional_suspend_definition"
                    | "conditional_suspend_condition"
                    | "conditional_restore_definition"
                    | "conditional_restore_condition"
            ) {
                return;
            }
            if let Some(mut response) = pending.lock().unwrap().take() {
                assert_eq!(response.try_recv().unwrap(), Ok(0));
            }
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some(response);
            *visits.lock().unwrap().entry(stage).or_default() += 1;
        }
    }));
    assert!(manager.replacement_readiness.is_none());
    work(manager);
    assert!(manager.replacement_readiness.is_none());
    manager.replacement_readiness_test_hook = None;
    assert_eq!(
        pending
            .lock()
            .unwrap()
            .take()
            .expect("the actual caller must service interior conditional readiness")
            .try_recv()
            .unwrap(),
        Ok(0)
    );
    Arc::try_unwrap(visits).unwrap().into_inner().unwrap()
}

#[test]
fn actual_conditional_activation_and_restore_service_matching_and_unmatched_entries() {
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64));
    let other_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64));
    let mut mixed = definition(NAME, v4, SETTLE);
    mixed
        .condition_prefixes
        .insert(0, rustbgpd_policy::sets::PrefixSetEntry::exact(v6));
    let mut unmatched = definition("unmatched", v6, SETTLE);
    unmatched
        .condition_prefixes
        .push(rustbgpd_policy::sets::PrefixSetEntry::exact(other_v6));
    let definitions = vec![mixed, unmatched, definition("v6", v6, SETTLE)];
    let mut manager = manager(definitions.clone());
    let (capture, _) = manager.install_conditional_advertisements(definitions);
    let activation = readiness_visits(&mut manager, |manager| {
        let _outbound_rx = connect(manager, WAITER, true);
    });
    assert_eq!(
        activation,
        BTreeMap::from([
            ("conditional_suspend_family", 1),
            ("conditional_suspend_definition", 3),
            ("conditional_suspend_condition", 5),
        ])
    );
    assert!(manager.selection_deferred(FAMILY));
    assert_eq!(
        readiness_visits(&mut manager, |manager| {
            manager.handle_restore_conditional_advertisements(capture);
        }),
        BTreeMap::from([
            ("conditional_restore_definition", 3),
            ("conditional_restore_condition", 5),
        ])
    );
    assert!(manager.selection_deferred(FAMILY));
}
