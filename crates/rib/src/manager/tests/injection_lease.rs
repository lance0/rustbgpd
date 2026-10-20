//! ADR-0141 owner-scoped leases through a running RIB manager, on a paused
//! clock.

use super::*;
use crate::injection_lease::{
    InjectionLeases, LeaseGeneration, MAX_KEYS_PER_OWNER, MAX_LIVE_OWNERS,
};
use crate::update::{InjectOutcome, RibCommandError};

const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70));

struct Harness {
    tx: mpsc::Sender<RibUpdate>,
    out_rx: mpsc::Receiver<OutboundRouteUpdate>,
    leases: Arc<InjectionLeases>,
    metrics: BgpMetrics,
    cancel: Option<oneshot::Sender<()>>,
    expiry: tokio::task::JoinHandle<()>,
    manager: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let (tx, rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        let leases = manager.injection_leases();
        let (cancel, cancel_rx) = oneshot::channel();
        let expiry = tokio::spawn(Arc::clone(&leases).run_expiry(tx.clone(), cancel_rx));
        let manager = tokio::spawn(manager.run());
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer: TARGET,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::FlowSpec)],
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        Self {
            tx,
            out_rx,
            leases,
            metrics,
            cancel: Some(cancel),
            expiry,
            manager,
        }
    }

    async fn stop(mut self) {
        let _ = self.cancel.take().unwrap().send(());
        self.expiry.await.unwrap();
        drop(self.tx);
        self.manager.await.unwrap();
    }

    /// Let the expiry task observe the clock, then round-trip the RIB so
    /// any batch it sent has been applied.
    async fn settle(&self) {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let _ = query_best_routes(&self.tx).await;
    }

    fn drain(&mut self) -> Vec<OutboundRouteUpdate> {
        let mut updates = Vec::new();
        while let Ok(update) = self.out_rx.try_recv() {
            updates.push(update);
        }
        updates
    }
}

fn host(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

fn local_route(octet: u8) -> Route {
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
        Ipv4Addr::UNSPECIFIED,
    );
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.peer_router_id = Ipv4Addr::UNSPECIFIED;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
        PathAttribute::Communities(vec![0xFFFF_029A]),
    ]);
    route
}

fn local_rule() -> FlowSpecRoute {
    let mut route = make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.peer_router_id = Ipv4Addr::UNSPECIFIED;
    route.attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ];
    route
}

async fn leased_route(
    tx: &mpsc::Sender<RibUpdate>,
    route: Route,
    owner: &str,
    lease_seconds: u32,
) -> Result<(InjectOutcome, LeaseGeneration), RibCommandError> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectLeasedRoute {
        route,
        owner: owner.to_string(),
        lease_seconds,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

async fn leased_rule(
    tx: &mpsc::Sender<RibUpdate>,
    route: FlowSpecRoute,
    owner: &str,
    lease_seconds: u32,
) -> Result<(InjectOutcome, LeaseGeneration), RibCommandError> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectLeasedFlowSpec {
        route,
        owner: owner.to_string(),
        lease_seconds,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

async fn unowned_route(
    tx: &mpsc::Sender<RibUpdate>,
    route: Route,
) -> Result<InjectOutcome, RibCommandError> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute { route, reply })
        .await
        .unwrap();
    rx.await.unwrap()
}

async fn delete_route(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
    override_owner: bool,
) -> Result<bool, RibCommandError> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawInjected {
        prefix: host(octet),
        path_id: 0,
        allow_missing: false,
        owner: owner.to_string(),
        override_owner,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

async fn local_prefixes(tx: &mpsc::Sender<RibUpdate>) -> Vec<Prefix> {
    let mut prefixes: Vec<Prefix> = query_received_routes(tx, LOCAL_PEER)
        .await
        .into_iter()
        .map(|route| route.prefix)
        .collect();
    prefixes.sort_unstable();
    prefixes
}

/// Expiry withdraws an owner's unicast route and `FlowSpec` rule in one RIB
/// turn, the withdrawal reaches the peer's outbound, it is counted and
/// gauged, and an unowned route stays permanent.
///
/// Break-to-red: without the expiry task's send, or without the RIB
/// withdrawing the expired keys, the peer never sees the withdrawal.
#[tokio::test(start_paused = true)]
async fn expiry_withdraws_both_families_and_reaches_the_peer() {
    let mut h = Harness::start().await;
    let (_, g) = leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    let (_, g_rule) = leased_rule(&h.tx, local_rule(), "ctl", 10).await.unwrap();
    assert_eq!(g, g_rule, "one lease per owner");
    assert_eq!(
        unowned_route(&h.tx, local_route(2)).await.unwrap(),
        InjectOutcome::Created
    );
    h.settle().await;
    let announced = h.drain();
    assert!(announced.iter().any(|u| u.announce.len() == 1));
    assert!(announced.iter().any(|u| u.flowspec_announce.len() == 1));

    tokio::time::advance(Duration::from_millis(9_999)).await;
    h.settle().await;
    assert!(h.drain().is_empty(), "nothing expires before the deadline");

    tokio::time::advance(Duration::from_millis(1)).await;
    h.settle().await;
    let withdrawn = h.drain();
    assert_eq!(
        withdrawn
            .iter()
            .flat_map(|u| u.withdraw.iter())
            .collect::<Vec<_>>(),
        vec![&(host(1), 0)]
    );
    assert_eq!(
        withdrawn
            .iter()
            .map(|u| u.flowspec_withdraw.len())
            .sum::<usize>(),
        1
    );
    assert_eq!(local_prefixes(&h.tx).await, vec![host(2)]);
    assert_eq!(
        counter_metric_value(
            &h.metrics,
            "bgp_injection_lease_expiries_total",
            &[("owner", "ctl")]
        ),
        1.0
    );
    assert_eq!(
        gauge_metric_value(&h.metrics, "bgp_injection_leases", &[]),
        0.0
    );
    assert_eq!(h.leases.renew("ctl", g, 10), None);

    tokio::time::advance(Duration::from_secs(100_000)).await;
    h.settle().await;
    assert!(h.drain().is_empty());
    assert_eq!(
        local_prefixes(&h.tx).await,
        vec![host(2)],
        "unowned is permanent"
    );
    h.stop().await;
}

/// A renewal before the deadline moves it; the route survives the old
/// deadline and expires at the renewed one. A leased add with a shorter
/// lease never pulls the deadline in.
#[tokio::test(start_paused = true)]
async fn renewal_prevents_expiry_and_adds_never_shorten() {
    let mut h = Harness::start().await;
    let (_, g) = leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(8)).await;
    assert_eq!(h.leases.renew("ctl", g, 10), Some(Duration::from_secs(10)));
    // Joins at t=8 with 5 s: max(18, 13) keeps 18.
    let (_, joined) = leased_route(&h.tx, local_route(3), "ctl", 5).await.unwrap();
    assert_eq!(joined, g);
    h.settle().await;
    h.drain();

    tokio::time::advance(Duration::from_secs(9)).await;
    h.settle().await;
    assert!(h.drain().is_empty(), "renewed past the original deadline");
    assert_eq!(local_prefixes(&h.tx).await, vec![host(1), host(3)]);

    tokio::time::advance(Duration::from_secs(1)).await;
    h.settle().await;
    let withdrawn: usize = h.drain().iter().map(|u| u.withdraw.len()).sum();
    assert_eq!(withdrawn, 2);
    assert_eq!(local_prefixes(&h.tx).await, Vec::<Prefix>::new());
    h.stop().await;
}

/// An expired generation cannot be renewed or resurrected; the next leased
/// add starts a new generation, and the old one stays dead.
#[tokio::test(start_paused = true)]
async fn expired_renewal_fails_and_readd_starts_a_new_generation() {
    let mut h = Harness::start().await;
    let (_, g1) = leased_route(&h.tx, local_route(1), "ctl", 5).await.unwrap();
    tokio::time::advance(Duration::from_secs(5)).await;
    h.settle().await;
    assert_eq!(h.drain().iter().map(|u| u.withdraw.len()).sum::<usize>(), 1);
    assert_eq!(h.leases.renew("ctl", g1, 5), None);

    let (outcome, g2) = leased_route(&h.tx, local_route(1), "ctl", 5).await.unwrap();
    assert_eq!(outcome, InjectOutcome::Created);
    assert_ne!(g2, g1);
    assert_eq!(g2.incarnation, g1.incarnation);
    assert_eq!(h.leases.renew("ctl", g1, 5), None);
    assert!(h.leases.renew("ctl", g2, 5).is_some());
    h.stop().await;
}

/// An identical leased re-add that commits after generation g died but
/// before its expiry batch is applied starts g+1, retags the key and causes
/// no wire churn; the late `Expire(g)` then skips the retagged key.
#[tokio::test(start_paused = true)]
async fn late_expiry_of_an_old_generation_spares_a_retagged_key() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let leases = manager.injection_leases();
    let manager = tokio::spawn(manager.run());
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: TARGET,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let (_, g) = leased_route(&tx, local_route(1), "ctl", 5).await.unwrap();
    let _ = query_best_routes(&tx).await;
    while out_rx.try_recv().is_ok() {}
    // No expiry task: generation g dies but is not reaped yet.
    tokio::time::advance(Duration::from_secs(6)).await;
    let (outcome, g_next) = leased_route(&tx, local_route(1), "ctl", 5).await.unwrap();
    assert_eq!(outcome, InjectOutcome::Unchanged);
    assert_ne!(g_next, g);

    let (expired, _) = leases.take_expired();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].generation, g);
    tx.send(RibUpdate::ExpireInjectionLeases { leases: expired })
        .await
        .unwrap();
    let _ = query_best_routes(&tx).await;
    assert!(out_rx.try_recv().is_err(), "no wire churn");
    assert_eq!(local_prefixes(&tx).await, vec![host(1)]);
    assert!(leases.renew("ctl", g_next, 5).is_some());

    drop(tx);
    manager.await.unwrap();
}

/// Ownership mismatches are refused with no change: a leased add onto an
/// unowned key (convert by delete-then-add), onto another owner's key, an
/// unowned add onto an owned key, and deletes with the wrong owner or `""`.
/// `override_owner` deletes regardless.
#[tokio::test(start_paused = true)]
async fn ownership_mismatches_are_failed_precondition_and_change_nothing() {
    let mut h = Harness::start().await;
    unowned_route(&h.tx, local_route(1)).await.unwrap();
    leased_route(&h.tx, local_route(2), "a", 30).await.unwrap();
    h.settle().await;
    h.drain();

    let mut changed = local_route(1);
    changed.attributes = AttrSet::new(vec![PathAttribute::Origin(Origin::Egp)]);
    assert!(matches!(
        leased_route(&h.tx, changed.clone(), "a", 30).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    let mut changed_owned = local_route(2);
    changed_owned.attributes = AttrSet::new(vec![PathAttribute::Origin(Origin::Egp)]);
    assert!(matches!(
        leased_route(&h.tx, changed_owned.clone(), "b", 30).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    assert!(matches!(
        unowned_route(&h.tx, changed_owned).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    assert!(matches!(
        delete_route(&h.tx, 2, "", false).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    assert!(matches!(
        delete_route(&h.tx, 2, "b", false).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    assert!(matches!(
        delete_route(&h.tx, 1, "a", false).await,
        Err(RibCommandError::FailedPrecondition(_))
    ));
    assert_eq!(h.leases.list(Some("b")), Vec::new());
    h.settle().await;
    assert!(
        h.drain().is_empty(),
        "rejections change nothing on the wire"
    );
    assert_eq!(local_prefixes(&h.tx).await, vec![host(1), host(2)]);

    // Delete-then-add converts the unowned key; override removes an owned one.
    assert_eq!(delete_route(&h.tx, 1, "", false).await, Ok(true));
    leased_route(&h.tx, changed, "a", 30).await.unwrap();
    assert_eq!(delete_route(&h.tx, 2, "", true).await, Ok(true));
    assert_eq!(delete_route(&h.tx, 1, "a", false).await, Ok(true));
    assert_eq!(local_prefixes(&h.tx).await, Vec::<Prefix>::new());
    h.stop().await;
}

/// The 65th live owner is refused and its route is not inserted.
#[tokio::test(start_paused = true)]
async fn owner_cap_is_resource_exhausted() {
    let h = Harness::start().await;
    for i in 0..MAX_LIVE_OWNERS {
        let octet = u8::try_from(i).unwrap();
        leased_route(&h.tx, local_route(octet), &format!("o{i}"), 30)
            .await
            .unwrap();
    }
    assert!(matches!(
        leased_route(&h.tx, local_route(200), "late", 30).await,
        Err(RibCommandError::ResourceExhausted(_))
    ));
    assert!(!local_prefixes(&h.tx).await.contains(&host(200)));
    h.stop().await;
}

/// Shutdown cancels the expiry task out of a blocked RIB send and out of an
/// idle wait; nothing is delivered after cancellation.
#[tokio::test(start_paused = true)]
async fn expiry_task_cancels_out_of_a_blocked_send_and_an_idle_wait() {
    let leases = Arc::new(InjectionLeases::new());
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(RibUpdate::ExpireInjectionLeases { leases: vec![] })
        .await
        .unwrap();
    leases.admit("ctl", 5).unwrap();
    let (cancel, cancel_rx) = oneshot::channel();
    let task = tokio::spawn(Arc::clone(&leases).run_expiry(tx.clone(), cancel_rx));
    tokio::time::advance(Duration::from_secs(6)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished(), "parked on the full RIB channel");
    cancel.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("cancelled out of the send")
        .unwrap();
    assert!(matches!(
        rx.try_recv(),
        Ok(RibUpdate::ExpireInjectionLeases { leases }) if leases.is_empty()
    ));
    assert!(rx.try_recv().is_err(), "the expired batch was never sent");

    let (cancel, cancel_rx) = oneshot::channel();
    let idle = tokio::spawn(Arc::new(InjectionLeases::new()).run_expiry(tx, cancel_rx));
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    cancel.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), idle)
        .await
        .expect("cancelled out of the idle wait")
        .unwrap();
}

/// The ownership sweep of an expired owner runs in the RIB actor without the
/// lease table's lock: at every key it withdraws, another owner's renewal is
/// served at once.
///
/// Break-to-red: holding the lease lock across the sweep fails the
/// `is_unlocked` check at the first key.
#[tokio::test(start_paused = true)]
async fn an_expiry_sweep_never_holds_the_lease_lock() {
    let h = Harness::start().await;
    let (_, keep) = leased_route(&h.tx, local_route(250), "b", 3_600)
        .await
        .unwrap();
    for octet in 0..200 {
        leased_route(&h.tx, local_route(octet), "a", 5)
            .await
            .unwrap();
    }
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (leases, record) = (Arc::clone(&h.leases), Arc::clone(&seen));
    crate::manager::lease_expiry::EXPIRY_SWEEP_PROBE.with(|probe| {
        *probe.borrow_mut() = Some(Box::new(move || {
            let renewed = leases.is_unlocked() && leases.renew("b", keep, 3_600).is_some();
            record.lock().unwrap().push(renewed);
        }));
    });
    tokio::time::advance(Duration::from_secs(5)).await;
    h.settle().await;
    crate::manager::lease_expiry::EXPIRY_SWEEP_PROBE.with(|probe| probe.borrow_mut().take());
    let seen = std::mem::take(&mut *seen.lock().unwrap());
    assert_eq!(seen.len(), 200, "the sweep visited every key of owner a");
    assert!(seen.iter().all(|renewed| *renewed));
    assert_eq!(local_prefixes(&h.tx).await, vec![host(250)]);
    h.stop().await;
}

/// A refused leased add interns nothing: ownership and capacity are decided
/// before the attributes enter the intern table.
///
/// Break-to-red: interning before admission grows the table by one set per
/// refused add.
#[tokio::test(start_paused = true)]
async fn refused_leased_adds_leave_the_intern_table_alone() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager
        .inject_local_route(local_route(1), Some(("a", 30)))
        .unwrap();
    for i in 1..MAX_LIVE_OWNERS {
        let octet = u8::try_from(i + 1).unwrap();
        manager
            .inject_local_route(local_route(octet), Some((&format!("o{i}"), 30)))
            .unwrap();
    }
    let interned = manager.attr_intern.len();
    for med in 0..100 {
        let mut route = local_route(1);
        route.attributes = AttrSet::new(vec![PathAttribute::Med(med)]);
        assert!(matches!(
            manager.inject_local_route(route, Some(("b", 30))),
            Err(RibCommandError::FailedPrecondition(_))
        ));
        let mut route = local_route(200);
        route.attributes = AttrSet::new(vec![PathAttribute::Med(med)]);
        assert!(matches!(
            manager.inject_local_route(route, Some(("late", 30))),
            Err(RibCommandError::ResourceExhausted(_))
        ));
    }
    assert_eq!(manager.attr_intern.len(), interned);
}

/// A route page and the received `FlowSpec` view carry the owner and
/// generation each local row had in the RIB turn that read it; unowned rows
/// carry none.
///
/// Break-to-red: without the capture the read-back has no tag to report.
#[tokio::test(start_paused = true)]
async fn read_back_captures_tags_with_the_snapshot() {
    let h = Harness::start().await;
    let (_, g) = leased_route(&h.tx, local_route(1), "ctl", 30)
        .await
        .unwrap();
    unowned_route(&h.tx, local_route(2)).await.unwrap();
    leased_rule(&h.tx, local_rule(), "ctl", 30).await.unwrap();

    let (reply, rx) = oneshot::channel();
    h.tx.send(RibUpdate::QueryRoutesPage {
        scope: RouteQueryScope::Received {
            peer: Some(LOCAL_PEER),
        },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 10,
        reply,
    })
    .await
    .unwrap();
    let page = rx.await.unwrap().unwrap();
    let tags: Vec<_> = page
        .routes
        .iter()
        .zip(&page.injection)
        .map(|(route, tag)| {
            (
                route.prefix,
                tag.as_ref().map(|t| (&*t.owner, t.generation)),
            )
        })
        .collect();
    assert_eq!(tags, vec![(host(1), Some(("ctl", g))), (host(2), None)]);

    let (reply, rx) = oneshot::channel();
    h.tx.send(RibUpdate::QueryReceivedFlowSpecRoutes {
        peer: LOCAL_PEER,
        filter: None,
        reply,
    })
    .await
    .unwrap();
    let rows = rx.await.unwrap();
    assert_eq!(rows.len(), 1);
    let tag = rows[0].injection.as_ref().expect("owned rule is tagged");
    assert_eq!((&*tag.owner, tag.generation), ("ctl", g));
    h.stop().await;
}

/// One owner holds at most `MAX_KEYS_PER_OWNER` keys, which bounds the
/// work of its expiry batch. A new key past the cap is refused with nothing
/// changed; replacing a held key, deleting one to make room, and other
/// owners are unaffected.
///
/// Break-to-red: without the cap the extra key is admitted.
#[tokio::test(start_paused = true)]
async fn an_owner_holds_at_most_the_key_cap() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let route = |index: usize| {
        let mut route = local_route(0);
        let index = u32::try_from(index).unwrap();
        route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 | index), 32));
        route
    };
    for index in 0..MAX_KEYS_PER_OWNER {
        manager
            .inject_local_route(route(index), Some(("a", 30)))
            .unwrap();
    }
    let held = manager.ribs[&LOCAL_PEER].len();
    let extra = route(MAX_KEYS_PER_OWNER);
    assert!(matches!(
        manager.inject_local_route(extra.clone(), Some(("a", 30))),
        Err(RibCommandError::ResourceExhausted(_))
    ));
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), held);

    let mut replaced = route(0);
    replaced.attributes = AttrSet::new(vec![PathAttribute::Med(7)]);
    manager
        .inject_local_route(replaced, Some(("a", 30)))
        .unwrap();
    manager
        .inject_local_route(extra.clone(), Some(("b", 30)))
        .unwrap();
    let (reply, mut deleted) = oneshot::channel();
    manager.handle_withdraw_injected(route(1).prefix, 0, false, "a", false, reply);
    assert_eq!(deleted.try_recv().unwrap(), Ok(true));
    assert!(
        manager
            .inject_local_route(route(MAX_KEYS_PER_OWNER + 1), Some(("a", 30)))
            .is_ok()
    );
}
