//! ADR-0141 owner-scoped leases through a running RIB manager, on a paused
//! clock.

use std::num::NonZeroU64;

use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix};

use super::*;
use crate::PeerId;
use crate::injection_lease::{
    ExpiryExit, GuardedFence, InjectedKey, InjectionLeases, LeaseConflict, LeaseGeneration,
    LeasedKeysPage, LeasedKeysResume, MAX_KEYS_PER_OWNER, MAX_LIVE_OWNERS, MutationWindowId,
    guarded_owner,
};
use crate::route::FlowSpecKey;
use crate::test_support::peer_v4;
use crate::update::{InjectOutcome, RibCommandError, RoutePage};

const TARGET: PeerId = peer_v4(Ipv4Addr::new(192, 0, 2, 70));

struct Harness {
    tx: mpsc::Sender<RibUpdate>,
    out_rx: mpsc::Receiver<OutboundRouteUpdate>,
    leases: Arc<InjectionLeases>,
    metrics: BgpMetrics,
    cancel: Option<oneshot::Sender<()>>,
    expiry: tokio::task::JoinHandle<ExpiryExit>,
    manager: tokio::task::JoinHandle<()>,
}

type StageObserver = Arc<dyn Fn(&'static str) + Send + Sync>;

impl Harness {
    async fn start() -> Self {
        Self::start_with_ingest_stall(None).await
    }

    /// Start with the ADR-0078 ingest stall set, so a `RoutesReceived`
    /// batch holds the RIB actor for `stall` while later messages queue.
    async fn start_with_ingest_stall(stall: Option<Duration>) -> Self {
        Self::start_with(stall, None).await
    }

    /// Start with an ingest stall and a readiness-stage observer.
    async fn start_with(stall: Option<Duration>, observer: Option<StageObserver>) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        manager.test_ingest_stall = stall;
        manager.replacement_readiness_test_hook = observer;
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
        assert_eq!(self.expiry.await.unwrap(), ExpiryExit::Cancelled);
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

    /// Hold the RIB actor in the ingest stall: queue an empty
    /// `RoutesReceived` batch and let the actor pop it.
    async fn stall_rib(&self) {
        self.tx
            .send(RibUpdate::RoutesReceived {
                session_id: 0,
                peer: TARGET,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            })
            .await
            .unwrap();
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
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
    rx.await.unwrap().map(|removal| removal.removed)
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

/// Expiry removes the expired owner's local intent and nothing else:
/// another owner's route and rule, and an unowned route, stay, and the
/// other owner's lease still renews.
///
/// Break-to-red: an expiry sweep that takes every owned key instead of the
/// expired owner's withdraws `b`'s entries here.
#[tokio::test(start_paused = true)]
async fn expiry_spares_other_owners_and_unowned_intent() {
    let mut h = Harness::start().await;
    let (_, g_a) = leased_route(&h.tx, local_route(1), "a", 5).await.unwrap();
    let (_, g_b) = leased_route(&h.tx, local_route(3), "b", 30).await.unwrap();
    leased_rule(&h.tx, local_rule(), "b", 30).await.unwrap();
    unowned_route(&h.tx, local_route(2)).await.unwrap();
    h.settle().await;
    h.drain();

    tokio::time::advance(Duration::from_secs(5)).await;
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
        0,
        "b's rule stays"
    );
    assert_eq!(local_prefixes(&h.tx).await, vec![host(2), host(3)]);
    assert_eq!(h.leases.renew("a", g_a, 30), None);
    assert!(h.leases.renew("b", g_b, 30).is_some());
    h.stop().await;
}

/// A daemon restart invalidates every generation: the new process's lease
/// table refuses the old generation even at the same sequence, and the
/// controller's re-add starts a new generation on a key the restart dropped.
///
/// Break-to-red: an incarnation that does not change per process (for
/// example a constant) lets the restarted table renew the old generation.
#[tokio::test]
async fn a_restart_invalidates_every_generation() {
    let first = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    let (_, before) = {
        let mut first = first;
        first
            .inject_local_route(local_route(1), Some(("ctl", 30)))
            .unwrap()
    };
    let before = before.unwrap();

    let mut restarted = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    assert_eq!(restarted.injection_leases().renew("ctl", before, 30), None);
    let (outcome, after) = restarted
        .inject_local_route(local_route(1), Some(("ctl", 30)))
        .unwrap();
    let after = after.unwrap();
    assert_eq!(
        outcome,
        InjectOutcome::Created,
        "a restart drops injected state"
    );
    assert_eq!(after.sequence, before.sequence);
    assert_ne!(after, before);
    assert_eq!(restarted.injection_leases().renew("ctl", before, 30), None);
}

fn sync_leased(
    manager: &mut RibManager,
    octet: u8,
    owner: &str,
    lease_seconds: u32,
) -> LeaseGeneration {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectLeasedRoute {
        route: local_route(octet),
        owner: owner.to_string(),
        lease_seconds,
        reply,
    });
    rx.try_recv().unwrap().unwrap().1
}

fn sync_leased_rule(manager: &mut RibManager, owner: &str) -> LeaseGeneration {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectLeasedFlowSpec {
        route: local_rule(),
        owner: owner.to_string(),
        lease_seconds: 30,
        reply,
    });
    rx.try_recv().unwrap().unwrap().1
}

fn try_leased_keys(
    manager: &mut RibManager,
    owner: &str,
    resume: Option<LeasedKeysResume>,
    page_size: usize,
) -> Option<LeasedKeysPage> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLeasedKeys {
        owner: owner.to_string(),
        resume,
        page_size,
        reply,
    });
    rx.try_recv().unwrap()
}

/// A first page.
fn leased_keys(manager: &mut RibManager, owner: &str, page_size: usize) -> LeasedKeysPage {
    try_leased_keys(manager, owner, None, page_size).unwrap()
}

/// The continuation a walk's token names after `page`.
fn resume_after(page: &LeasedKeysPage) -> LeasedKeysResume {
    LeasedKeysResume {
        incarnation: page.incarnation,
        generation: page.generation,
        watermark: page.watermark,
        after: page.rows.last().unwrap().cursor.clone(),
    }
}

fn listed(page: &LeasedKeysPage) -> Vec<InjectedKey> {
    page.rows.iter().map(|row| row.key.clone()).collect()
}

/// An owner's listing holds that owner's keys only, unicast in (prefix,
/// path ID) order then `FlowSpec`, each with its generation and remaining
/// lease; another owner's and unowned entries never appear.
///
/// Break-to-red: a listing that walks every tagged key instead of the
/// owner's lists `b`'s route under `a`.
#[tokio::test(start_paused = true)]
async fn leased_keys_list_only_the_owners_keys_in_order() {
    let mut manager = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    let g_a = sync_leased(&mut manager, 3, "a", 30);
    sync_leased(&mut manager, 1, "a", 30);
    sync_leased_rule(&mut manager, "a");
    let g_b = sync_leased(&mut manager, 2, "b", 30);
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: local_route(4),
        reply,
    });
    rx.try_recv().unwrap().unwrap();

    let page = leased_keys(&mut manager, "a", 10);
    assert!(!page.more);
    let rule = local_rule();
    assert_eq!(
        listed(&page),
        vec![
            InjectedKey::Unicast(host(1), 0),
            InjectedKey::Unicast(host(3), 0),
            InjectedKey::FlowSpec(crate::route::FlowSpecKey {
                afi: rule.afi,
                rule: rule.rule,
            }),
        ]
    );
    assert!(page.rows.iter().all(|row| row.generation == g_a));
    assert!(
        page.rows
            .iter()
            .all(|row| row.remaining == Duration::from_secs(30))
    );
    let page = leased_keys(&mut manager, "b", 10);
    assert_eq!(listed(&page), vec![InjectedKey::Unicast(host(2), 0)]);
    assert_eq!(page.rows[0].generation, g_b);
    assert_eq!(leased_keys(&mut manager, "nobody", 10).rows, []);

    // Past the deadline but not yet reaped: listed, with nothing remaining.
    tokio::time::advance(Duration::from_secs(31)).await;
    let page = leased_keys(&mut manager, "b", 10);
    assert_eq!(page.rows[0].remaining, Duration::ZERO);
}

/// Pages hold at most `page_size` keys in the listing order and resume
/// strictly after the last key returned, even when a key ahead of the
/// cursor is added between pages.
#[tokio::test]
async fn leased_keys_page_within_the_bound() {
    let mut manager = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    for octet in [5, 1, 4, 2, 3] {
        sync_leased(&mut manager, octet, "a", 30);
    }
    let first = leased_keys(&mut manager, "a", 2);
    assert_eq!(
        listed(&first),
        vec![
            InjectedKey::Unicast(host(1), 0),
            InjectedKey::Unicast(host(2), 0)
        ]
    );
    assert!(first.more);
    // Adding a key ahead of the cursor and deleting one behind it keep the
    // lease and its generation, so the walk continues.
    sync_leased(&mut manager, 0, "a", 30);
    sync_delete(&mut manager, 1, "a");
    let second = try_leased_keys(&mut manager, "a", Some(resume_after(&first)), 2).unwrap();
    assert_eq!(
        listed(&second),
        vec![
            InjectedKey::Unicast(host(3), 0),
            InjectedKey::Unicast(host(4), 0)
        ]
    );
    assert!(second.more);
    let last = try_leased_keys(&mut manager, "a", Some(resume_after(&second)), 2).unwrap();
    assert_eq!(listed(&last), vec![InjectedKey::Unicast(host(5), 0)]);
    assert!(!last.more);
    assert_eq!(leased_keys(&mut manager, "a", 0).rows.len(), 1);
    assert_eq!(leased_keys(&mut manager, "a", usize::MAX).rows.len(), 5);
}

fn sync_delete(manager: &mut RibManager, octet: u8, owner: &str) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: host(octet),
        path_id: 0,
        allow_missing: false,
        owner: owner.to_string(),
        override_owner: false,
        reply,
    });
    assert!(rx.try_recv().unwrap().unwrap().removed);
}

fn manager_for_keys() -> RibManager {
    RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    )
}

/// Every page names the owner's live generation: absent without a live
/// lease, present with the keys it holds, and present with none once the
/// owner deleted every key while its lease lives.
#[tokio::test]
async fn leased_key_pages_report_the_walks_generation() {
    let mut manager = manager_for_keys();
    let page = leased_keys(&mut manager, "ctl", 10);
    assert_eq!((page.rows.len(), page.generation), (0, None));

    let generation = sync_leased(&mut manager, 1, "ctl", 30);
    let page = leased_keys(&mut manager, "ctl", 10);
    assert_eq!((page.rows.len(), page.generation), (1, Some(generation)));
    assert_eq!(page.incarnation, manager.injection_leases().incarnation());

    sync_delete(&mut manager, 1, "ctl");
    let page = leased_keys(&mut manager, "ctl", 10);
    assert_eq!((page.rows.len(), page.generation), (0, Some(generation)));
}

/// A walk never continues into a restarted daemon: a later page is
/// refused whether or not the owner held a live lease, so a truncated walk
/// cannot end in an empty page that reads as complete.
///
/// Break-to-red: without the incarnation check, the no-lease walk resumes
/// into the restarted process and returns an empty final page.
#[tokio::test(start_paused = true)]
async fn a_leased_key_walk_refuses_a_restarted_daemon() {
    let mut first = manager_for_keys();
    sync_leased(&mut first, 1, "ctl", 30);
    sync_leased(&mut first, 2, "ctl", 30);
    let live = leased_keys(&mut first, "ctl", 1);
    assert!(live.more && live.generation.is_some());

    let mut restarted = manager_for_keys();
    sync_leased(&mut restarted, 1, "ctl", 30);
    sync_leased(&mut restarted, 2, "ctl", 30);
    assert_eq!(
        try_leased_keys(&mut restarted, "ctl", Some(resume_after(&live)), 1),
        None
    );

    // The owner's lease lapsed before the walk began: keys awaiting
    // withdrawal, no live generation.
    let mut lapsed = manager_for_keys();
    sync_leased(&mut lapsed, 1, "ctl", 5);
    sync_leased(&mut lapsed, 2, "ctl", 5);
    tokio::time::advance(Duration::from_secs(6)).await;
    let walk = leased_keys(&mut lapsed, "ctl", 1);
    assert!(walk.more && walk.generation.is_none());
    let mut restarted = manager_for_keys();
    assert_eq!(
        try_leased_keys(&mut restarted, "ctl", Some(resume_after(&walk)), 1),
        None
    );
}

/// A walk that began without a live lease refuses a continuation after a
/// generation started and expired again in between, though neither page
/// sees a live lease.
///
/// Break-to-red: comparing only the live generations lets the walk resume.
#[tokio::test(start_paused = true)]
async fn a_leased_key_walk_refuses_a_generation_that_came_and_went() {
    let mut manager = manager_for_keys();
    sync_leased(&mut manager, 1, "ctl", 5);
    sync_leased(&mut manager, 2, "ctl", 5);
    tokio::time::advance(Duration::from_secs(6)).await;
    let walk = leased_keys(&mut manager, "ctl", 1);
    assert!(walk.more && walk.generation.is_none());

    sync_leased(&mut manager, 3, "ctl", 5);
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(manager.injection_leases().live_generation("ctl").0, None);
    assert_eq!(
        try_leased_keys(&mut manager, "ctl", Some(resume_after(&walk)), 1),
        None
    );
}

/// A walk never continues into a new generation: after the owner's lease
/// expired and the owner added again, a later page is refused.
///
/// Break-to-red: without the generation check, the walk resumes into the
/// new generation's keys.
#[tokio::test(start_paused = true)]
async fn a_leased_key_walk_refuses_a_new_generation() {
    let mut manager = manager_for_keys();
    sync_leased(&mut manager, 1, "ctl", 5);
    sync_leased(&mut manager, 2, "ctl", 5);
    let walk = leased_keys(&mut manager, "ctl", 1);
    assert!(walk.more);

    tokio::time::advance(Duration::from_secs(6)).await;
    let (expired, _) = manager.injection_leases().take_expired();
    manager.handle_update(RibUpdate::ExpireInjectionLeases { leases: expired });
    let renewed = sync_leased(&mut manager, 1, "ctl", 5);
    sync_leased(&mut manager, 2, "ctl", 5);
    assert_ne!(Some(renewed), walk.generation);
    assert_eq!(
        try_leased_keys(&mut manager, "ctl", Some(resume_after(&walk)), 1),
        None
    );
}

/// After a daemon restart an owner holds no keys, and the keys it adds
/// again carry the new process's incarnation.
#[tokio::test]
async fn leased_keys_after_a_restart_carry_the_new_incarnation() {
    let mut first = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    let before = sync_leased(&mut first, 1, "ctl", 30);
    assert_eq!(leased_keys(&mut first, "ctl", 10).rows.len(), 1);

    let mut restarted = RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    );
    assert_eq!(leased_keys(&mut restarted, "ctl", 10).rows, []);
    sync_leased(&mut restarted, 1, "ctl", 30);
    let page = leased_keys(&mut restarted, "ctl", 10);
    assert_eq!(
        page.rows[0].generation.incarnation,
        restarted.injection_leases().incarnation()
    );
    assert_ne!(page.rows[0].generation.incarnation, before.incarnation);
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
/// Each carries the conflict the API reports as its `ErrorInfo` reason.
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
    let conflict = |result: Result<(), RibCommandError>| match result {
        Err(RibCommandError::FailedPrecondition(conflict, _)) => Some(conflict),
        _ => None,
    };
    assert_eq!(
        conflict(
            leased_route(&h.tx, changed.clone(), "a", 30)
                .await
                .map(drop)
        ),
        Some(LeaseConflict::KeyUnowned)
    );
    let mut changed_owned = local_route(2);
    changed_owned.attributes = AttrSet::new(vec![PathAttribute::Origin(Origin::Egp)]);
    assert_eq!(
        conflict(
            leased_route(&h.tx, changed_owned.clone(), "b", 30)
                .await
                .map(drop)
        ),
        Some(LeaseConflict::OwnerMismatch)
    );
    assert_eq!(
        conflict(unowned_route(&h.tx, changed_owned).await.map(drop)),
        Some(LeaseConflict::OwnerMismatch)
    );
    assert_eq!(
        conflict(delete_route(&h.tx, 2, "", false).await.map(drop)),
        Some(LeaseConflict::OwnerMismatch)
    );
    assert_eq!(
        conflict(delete_route(&h.tx, 2, "b", false).await.map(drop)),
        Some(LeaseConflict::OwnerMismatch)
    );
    assert_eq!(
        conflict(delete_route(&h.tx, 1, "a", false).await.map(drop)),
        Some(LeaseConflict::KeyUnowned)
    );
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
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancelled out of the send")
            .unwrap(),
        ExpiryExit::Cancelled
    );
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
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), idle)
            .await
            .expect("cancelled out of the idle wait")
            .unwrap(),
        ExpiryExit::Cancelled
    );
}

/// An expiry batch that finds the RIB's receiver gone ends the task with
/// `RibChannelClosed`, so supervision reports the RIB's own failure rather
/// than an expiry failure.
///
/// Break-to-red: reporting a failed send as `Cancelled` fails the match.
#[tokio::test(start_paused = true)]
async fn expiry_reports_a_closed_rib_channel() {
    let leases = Arc::new(InjectionLeases::new());
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    leases.admit("ctl", 5).unwrap();
    let (_cancel, cancel_rx) = oneshot::channel();
    let task = tokio::spawn(Arc::clone(&leases).run_expiry(tx, cancel_rx));
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the failed send ends the task")
            .unwrap(),
        ExpiryExit::RibChannelClosed
    );
}

/// The ownership sweep of an expired owner runs in the RIB actor without the
/// lease table's lock: at every key it withdraws, another owner's renewal is
/// served at once.
///
/// Break-to-red: holding the lease lock across the sweep fails the
/// `is_unlocked` check at the first key.
#[tokio::test(start_paused = true)]
async fn an_expiry_sweep_never_holds_the_lease_lock() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let probe = Arc::new(std::sync::Mutex::new(
        None::<(Arc<InjectionLeases>, LeaseGeneration)>,
    ));
    let observer: StageObserver = {
        let (probe, record) = (Arc::clone(&probe), Arc::clone(&seen));
        Arc::new(move |stage| {
            if stage != "lease_expiry_sweep" {
                return;
            }
            if let Some((leases, keep)) = &*probe.lock().unwrap() {
                let renewed = leases.is_unlocked() && leases.renew("b", *keep, 3_600).is_some();
                record.lock().unwrap().push(renewed);
            }
        })
    };
    let h = Harness::start_with(None, Some(observer)).await;
    let (_, keep) = leased_route(&h.tx, local_route(250), "b", 3_600)
        .await
        .unwrap();
    for octet in 0..200 {
        leased_route(&h.tx, local_route(octet), "a", 5)
            .await
            .unwrap();
    }
    *probe.lock().unwrap() = Some((Arc::clone(&h.leases), keep));
    tokio::time::advance(Duration::from_secs(5)).await;
    h.settle().await;
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
            Err(RibCommandError::FailedPrecondition(
                LeaseConflict::OwnerMismatch,
                _
            ))
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
    assert!(deleted.try_recv().unwrap().unwrap().removed);
    assert!(
        manager
            .inject_local_route(route(MAX_KEYS_PER_OWNER + 1), Some(("a", 30)))
            .is_ok()
    );
}

/// Expiry removes only the local intent: a learned route for the same
/// prefix, out-selected while the leased route lived, becomes best and is
/// advertised to the peer in place of the local one.
///
/// Break-to-red: an expiry that skips the selection pass leaves the learned
/// route unadvertised.
#[tokio::test(start_paused = true)]
async fn expiry_hands_the_prefix_to_a_learned_route() {
    const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);
    let mut h = Harness::start().await;
    let (source_tx, _source_rx) = mpsc::channel(64);
    h.tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(SOURCE),
        peer_asn: 65200,
        peer_router_id: SOURCE,
        outbound_tx: source_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
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
    leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    let mut learned = make_route(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32), SOURCE);
    learned.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65200])],
        }),
        PathAttribute::NextHop(SOURCE),
    ]);
    h.tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![learned],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    h.settle().await;
    let best = |routes: Vec<Route>| {
        routes
            .into_iter()
            .filter(|route| route.prefix == host(1))
            .map(|route| route.peer)
            .collect::<Vec<_>>()
    };
    assert_eq!(best(query_best_routes(&h.tx).await), vec![LOCAL_PEER]);
    h.drain();

    tokio::time::advance(Duration::from_secs(10)).await;
    h.settle().await;
    assert_eq!(best(query_best_routes(&h.tx).await), vec![peer_v4(SOURCE)]);
    let advertised: Vec<PeerId> = h
        .drain()
        .iter()
        .flat_map(|update| update.announce.iter())
        .filter(|route| route.prefix == host(1))
        .map(|route| route.peer)
        .collect();
    assert_eq!(advertised, vec![peer_v4(SOURCE)]);
    h.stop().await;
}

/// Every queued RIB message is as large as the largest variant, so a lease
/// variant must not set that size. Its payloads (a route or rule, an owner
/// and a reply) stay below the largest existing variant.
///
/// Break-to-red: growing any variant past 248 bytes fails the bound; box
/// the payload instead.
#[test]
fn lease_variants_do_not_grow_rib_update() {
    type Reply = oneshot::Sender<Result<(InjectOutcome, LeaseGeneration), RibCommandError>>;
    assert!(size_of::<RibUpdate>() <= 248, "{}", size_of::<RibUpdate>());
    assert!(size_of::<(Route, String, u32, Reply)>() < size_of::<RibUpdate>());
    assert!(size_of::<(FlowSpecRoute, String, u32, Reply)>() < size_of::<RibUpdate>());
    assert!(
        size_of::<(FlowSpecRoute, String, u32, GuardedFence, Reply)>() < size_of::<RibUpdate>()
    );
}

async fn route_page(tx: &mpsc::Sender<RibUpdate>, scope: RouteQueryScope) -> RoutePage {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope,
        filter: None,
        after: None,
        expected_version: None,
        page_size: 10,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap().unwrap()
}

/// Lease tags follow source path IDs. Two owners inject one prefix under
/// path IDs 0 and 42: the received and best rows name each path's own
/// owner, and the advertised page, whose rows carry an outbound path ID,
/// names none rather than a wrong one.
///
/// Break-to-red: tagging advertised rows by their outbound path ID 0 names
/// owner `b` for whichever path was exported.
#[tokio::test(start_paused = true)]
async fn lease_tags_follow_source_path_ids_and_skip_advertised_rows() {
    let h = Harness::start().await;
    let mut path_42 = local_route(1);
    path_42.path_id = 42;
    let (_, g_a) = leased_route(&h.tx, path_42, "a", 30).await.unwrap();
    let (_, g_b) = leased_route(&h.tx, local_route(1), "b", 30).await.unwrap();
    h.settle().await;

    let owners = |page: &RoutePage| {
        page.routes
            .iter()
            .zip(
                page.injection
                    .iter()
                    .map(Some)
                    .chain(std::iter::repeat(None)),
            )
            .map(|(route, tag)| {
                (
                    route.path_id,
                    tag.and_then(Option::as_ref)
                        .map(|tag| (tag.owner.to_string(), tag.generation)),
                )
            })
            .collect::<Vec<_>>()
    };
    let received = route_page(
        &h.tx,
        RouteQueryScope::Received {
            peer: Some(LOCAL_PEER),
        },
    )
    .await;
    let mut received = owners(&received);
    received.sort_unstable_by_key(|row| row.0);
    assert_eq!(
        received,
        vec![
            (0, Some(("b".to_string(), g_b))),
            (42, Some(("a".to_string(), g_a)))
        ]
    );
    let best = owners(&route_page(&h.tx, RouteQueryScope::Best).await);
    assert_eq!(best.len(), 1);
    let expected = if best[0].0 == 42 {
        ("a".to_string(), g_a)
    } else {
        ("b".to_string(), g_b)
    };
    assert_eq!(best[0].1, Some(expected));
    let advertised = owners(&route_page(&h.tx, RouteQueryScope::Advertised { peer: TARGET }).await);
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].1, None, "advertised rows are not tagged");
    h.stop().await;
}

/// Queue a leased add without waiting for its reply.
async fn queue_leased_route(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
) -> oneshot::Receiver<Result<(InjectOutcome, LeaseGeneration), RibCommandError>> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectLeasedRoute {
        route: local_route(octet),
        owner: owner.to_string(),
        lease_seconds: 10,
        reply,
    })
    .await
    .unwrap();
    rx
}

/// Queue an owner's delete without waiting for its reply.
async fn queue_delete(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
) -> oneshot::Receiver<Result<crate::update::InjectedRemoval, RibCommandError>> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawInjected {
        prefix: host(octet),
        path_id: 0,
        allow_missing: false,
        owner: owner.to_string(),
        override_owner: false,
        reply,
    })
    .await
    .unwrap();
    rx
}

fn withdrawn_hosts(updates: &[OutboundRouteUpdate]) -> Vec<Prefix> {
    let mut hosts: Vec<Prefix> = updates
        .iter()
        .flat_map(|update| update.withdraw.iter().map(|(prefix, _)| *prefix))
        .collect();
    hosts.sort_unstable();
    hosts
}

/// ADR-0141 §12 race: a leased add queued behind a stalled RIB before the
/// deadline is applied after it, by which time the expiry task has reaped g
/// and queued `Expire(g)` behind the add. The add starts generation g+1, and
/// `Expire(g)` withdraws only keys still tagged g: the re-added key and the
/// new key survive, an untouched g key goes. (An add applied after the
/// deadline but before the reap is pinned by
/// `late_expiry_of_an_old_generation_spares_a_retagged_key`.)
///
/// Break-to-red: withdrawing every key of the owner takes the re-added and
/// new keys too.
#[tokio::test(start_paused = true)]
async fn an_add_queued_across_the_deadline_starts_a_new_generation() {
    let mut h = Harness::start_with_ingest_stall(Some(Duration::from_secs(20))).await;
    let (_, g) = leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    leased_route(&h.tx, local_route(3), "ctl", 10)
        .await
        .unwrap();
    h.settle().await;
    h.drain();

    h.stall_rib().await;
    let readd = queue_leased_route(&h.tx, 1, "ctl").await;
    let new_key = queue_leased_route(&h.tx, 2, "ctl").await;
    // The deadline passes while the RIB is stalled; the expiry task queues
    // Expire(g) behind the two adds.
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(10)).await;

    let (outcome, g_readd) = readd.await.unwrap().unwrap();
    assert_eq!(outcome, InjectOutcome::Unchanged);
    let (_, g_new) = new_key.await.unwrap().unwrap();
    assert_ne!(g_readd, g);
    assert_eq!(g_readd, g_new);
    h.settle().await;
    assert_eq!(withdrawn_hosts(&h.drain()), vec![host(3)]);
    assert_eq!(local_prefixes(&h.tx).await, vec![host(1), host(2)]);
    assert!(h.leases.renew("ctl", g_new, 10).is_some());
    h.stop().await;
}

/// ADR-0141 §12 expiry vs delete, delete first: the owner's delete, applied
/// after the deadline but ahead of `Expire(g)`, still matches its owner and
/// removes its key, and the expiry withdraws the owner's remaining key. Each
/// key is withdrawn once.
///
/// Break-to-red: judging the delete by lease liveness instead of the key's
/// tag refuses it once the deadline has passed.
#[tokio::test(start_paused = true)]
async fn a_delete_ahead_of_expiry_is_withdrawn_once() {
    let mut h = Harness::start_with_ingest_stall(Some(Duration::from_secs(20))).await;
    leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    leased_route(&h.tx, local_route(2), "ctl", 10)
        .await
        .unwrap();
    h.settle().await;
    h.drain();

    h.stall_rib().await;
    let deleted = queue_delete(&h.tx, 1, "ctl").await;
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(deleted.await.unwrap().unwrap().removed);
    h.settle().await;
    assert_eq!(withdrawn_hosts(&h.drain()), vec![host(1), host(2)]);
    assert_eq!(local_prefixes(&h.tx).await, Vec::<Prefix>::new());
    let (_, g) = leased_route(&h.tx, local_route(3), "ctl", 10)
        .await
        .unwrap();
    assert_eq!(
        h.leases.list(Some("ctl"))[0].generation,
        g,
        "the expired generation left nothing behind"
    );
    h.stop().await;
}

/// ADR-0141 §12 expiry vs delete, expiry first: `Expire(g)` queued ahead of
/// the owner's delete withdraws the key, and the delete then reports it
/// missing without a second withdrawal.
///
/// Break-to-red: an expiry that leaves the key in the RIB lets the delete
/// succeed.
#[tokio::test(start_paused = true)]
async fn a_delete_behind_expiry_finds_the_key_gone() {
    let mut h = Harness::start_with_ingest_stall(Some(Duration::from_secs(20))).await;
    leased_route(&h.tx, local_route(1), "ctl", 10)
        .await
        .unwrap();
    h.settle().await;
    h.drain();

    h.stall_rib().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let deleted = queue_delete(&h.tx, 1, "ctl").await;
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(matches!(
        deleted.await.unwrap(),
        Err(RibCommandError::NotFound(_))
    ));
    h.settle().await;
    assert_eq!(withdrawn_hosts(&h.drain()), vec![host(1)]);
    assert_eq!(local_prefixes(&h.tx).await, Vec::<Prefix>::new());
    h.stop().await;
}

/// With no lease, the expiry task costs nothing: after its first pass it
/// parks without a timer, so a day passes with no further pass and no RIB
/// send. A lease wakes it, and once that lease is gone it parks again.
///
/// Break-to-red: an idle wait on a periodic tick makes a pass per tick.
#[tokio::test(start_paused = true)]
async fn an_idle_expiry_task_never_wakes() {
    let leases = Arc::new(InjectionLeases::new());
    let (tx, mut rx) = mpsc::channel(8);
    let (cancel, cancel_rx) = oneshot::channel();
    let task = tokio::spawn(Arc::clone(&leases).run_expiry(tx, cancel_rx));
    let settle = || async {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    };
    settle().await;
    assert_eq!(leases.expiry_passes(), 1);
    tokio::time::advance(Duration::from_hours(24)).await;
    settle().await;
    assert_eq!(leases.expiry_passes(), 1, "no pass while idle");
    assert!(rx.try_recv().is_err(), "no RIB send while idle");

    leases.admit("ctl", 5).unwrap();
    settle().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    settle().await;
    assert!(matches!(
        rx.try_recv(),
        Ok(RibUpdate::ExpireInjectionLeases { leases }) if leases.len() == 1
    ));
    let parked = leases.expiry_passes();
    tokio::time::advance(Duration::from_hours(24)).await;
    settle().await;
    assert_eq!(leases.expiry_passes(), parked, "parked again once empty");
    assert!(rx.try_recv().is_err());

    cancel.send(()).unwrap();
    assert_eq!(task.await.unwrap(), ExpiryExit::Cancelled);
}

/// Measures one expiry batch's RIB turn: `RUSTBGPD_LEASE_EXPIRY_OWNERS`
/// owners (default 1), each at the per-owner key cap, expire together with
/// one eBGP peer attached. A learned update queued at the batch's start
/// waits the whole turn. Run in release:
/// `cargo test --release -p rustbgpd-rib --lib -- --ignored --nocapture
/// expiry_batch_turn`.
#[tokio::test(start_paused = true)]
#[ignore = "measurement; run explicitly in release"]
async fn expiry_batch_turn() {
    let owners: usize = std::env::var("RUSTBGPD_LEASE_EXPIRY_OWNERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (out_tx, mut out_rx) = mpsc::channel(1 << 16);
    manager.handle_update(RibUpdate::PeerUp {
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
    });
    let leases = manager.injection_leases();
    let mut index = 0u32;
    for owner in 0..owners {
        let owner = format!("o{owner}");
        for _ in 0..MAX_KEYS_PER_OWNER {
            let mut route = local_route(0);
            route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 | index), 32));
            index += 1;
            manager
                .inject_local_route(route, Some((&owner, 5)))
                .unwrap();
        }
        while out_rx.try_recv().is_ok() {}
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    let (expired, _) = leases.take_expired();
    assert_eq!(expired.len(), owners);
    let started = std::time::Instant::now();
    manager.handle_expire_injection_leases(&expired);
    let turn = started.elapsed();
    let mut withdrawn = 0;
    while let Ok(update) = out_rx.try_recv() {
        withdrawn += update.withdraw.len();
    }
    assert_eq!(withdrawn, owners * MAX_KEYS_PER_OWNER);
    eprintln!(
        "expiry batch: owners={owners} keys={} turn_ms={:.1}",
        owners * MAX_KEYS_PER_OWNER,
        turn.as_secs_f64() * 1000.0
    );
}

/// The peer-down comparison for [`expiry_batch_turn`]: one eBGP peer's
/// session ends holding as many learned routes as the expiry batch
/// withdraws, with the same receiving peer attached.
#[tokio::test(start_paused = true)]
#[ignore = "measurement; run explicitly in release"]
async fn peer_down_turn() {
    const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
    let owners: usize = std::env::var("RUSTBGPD_LEASE_EXPIRY_OWNERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_up = |peer: PeerId, asn: u32, outbound_tx| RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: asn,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    };
    let (out_tx, mut out_rx) = mpsc::channel(1 << 16);
    manager.handle_update(peer_up(TARGET, 65100, out_tx));
    let (source_tx, _source_rx) = mpsc::channel(1 << 16);
    manager.handle_update(peer_up(peer_v4(SOURCE), 65200, source_tx));
    let total = owners * MAX_KEYS_PER_OWNER;
    let mut index = 0u32;
    while (index as usize) < total {
        let announced = (0..4096)
            .map(|_| {
                let mut route = make_route(
                    Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 | index), 32),
                    SOURCE,
                );
                index += 1;
                route.attributes = AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65200])],
                    }),
                    PathAttribute::NextHop(SOURCE),
                ]);
                route
            })
            .collect();
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: peer_v4(SOURCE),
            announced,
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
        while out_rx.try_recv().is_ok() {}
    }
    let started = std::time::Instant::now();
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer_v4(SOURCE),
        session_id: 0,
    });
    while manager.process_next_route_chunk() {}
    let turn = started.elapsed();
    let mut withdrawn = 0;
    while let Ok(update) = out_rx.try_recv() {
        withdrawn += update.withdraw.len();
    }
    assert_eq!(withdrawn, total);
    eprintln!(
        "peer down: routes={total} turn_ms={:.1}",
        turn.as_secs_f64() * 1000.0
    );
}

async fn next_entry(rx: &mut mpsc::UnboundedReceiver<usize>) -> Option<usize> {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
}

/// A multi-owner expiry batch runs under the source peer-down readiness
/// owner: a readiness query queued while the sweep is inside the batch is
/// answered at the next key, with the count published before the batch,
/// and the batch still withdraws every key of every owner.
///
/// Break-to-red: without the owner, the sweep's checkpoints service nothing
/// and the query waits until the whole batch has finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_owner_expiry_batch_keeps_answering_readiness() {
    const KEYS: u8 = 4;
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Service a queued query at every checkpoint rather than once per budget.
    manager.flush_poll_budget = Duration::ZERO;
    let (out_tx, mut out_rx) = mpsc::channel(64);
    manager.handle_update(super::update_groups_recovery::peer_up(TARGET, out_tx, None));
    let mut expired = Vec::new();
    for (owner, base) in [("a", 0), ("b", KEYS)] {
        let mut generation = None;
        for octet in base..base + KEYS {
            let (_, g) = manager
                .inject_local_route(local_route(octet), Some((owner, 30)))
                .unwrap();
            generation = g;
        }
        expired.push(crate::injection_lease::ExpiredLease {
            owner: Arc::from(owner),
            generation: generation.unwrap(),
            deadline: tokio::time::Instant::now(),
        });
    }
    while out_rx.try_recv().is_ok() {}
    let before = manager.loc_rib.len();
    assert_eq!(before, usize::from(2 * KEYS));

    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    manager.readiness_rx = Some(readiness_rx);
    manager.replacement_readiness_receipts.clear();
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    manager.replacement_readiness_test_hook = Some(Arc::new(move |stage| {
        if stage != "lease_expiry_sweep" {
            return;
        }
        let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if call < 2 {
            entered_tx.send(call).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        }
    }));
    let actor = tokio::spawn(async move {
        let update = manager.rx.recv().await.unwrap();
        manager.handle_update(update);
        manager
    });
    tx.send(RibUpdate::ExpireInjectionLeases { leases: expired })
        .await
        .unwrap();

    assert_eq!(
        next_entry(&mut entered_rx).await,
        Some(0),
        "the sweep reached its first key"
    );
    let (reply, mut response) = oneshot::channel();
    readiness_tx
        .try_send(crate::update::RibReadinessQuery::LocRibCount {
            reply,
            enqueued: std::time::Instant::now(),
        })
        .unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        next_entry(&mut entered_rx).await,
        Some(1),
        "the sweep reached its next key"
    );
    let answered = response.try_recv();
    release_tx.send(()).unwrap();
    let manager = actor.await.unwrap();

    assert_eq!(
        answered,
        Ok(Ok(before)),
        "the query is answered inside the batch, not after it"
    );
    assert_eq!(manager.loc_rib.len(), 0);
    let mut withdrawn: Vec<Prefix> = Vec::new();
    while let Ok(update) = out_rx.try_recv() {
        withdrawn.extend(update.withdraw.iter().map(|(prefix, _)| *prefix));
    }
    withdrawn.sort_unstable();
    assert_eq!(withdrawn, (0..2 * KEYS).map(host).collect::<Vec<_>>());
    assert_eq!(
        manager
            .replacement_readiness_receipts
            .iter()
            .map(|receipt| receipt.kind)
            .collect::<Vec<_>>(),
        [super::super::ReadinessOwnerKind::PeerTeardown],
        "the batch ran under the source teardown owner"
    );
}

// ADR-0144 guarded FlowSpec mutations: windows, revisions and the guarded
// owner namespace, through a running RIB manager on a paused clock.

/// A local rule for `203.0.113.<octet>/32` whose payload is set by
/// `community`.
fn guarded_rule(octet: u8, community: u32) -> FlowSpecRoute {
    let mut route = local_rule();
    route.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
    ))];
    route
        .attributes
        .push(PathAttribute::Communities(vec![community]));
    route
}

fn rule_key(octet: u8) -> FlowSpecKey {
    guarded_rule(octet, 0).selection_key()
}

type AddReply = oneshot::Receiver<Result<(InjectOutcome, LeaseGeneration), RibCommandError>>;
type DeleteReply = oneshot::Receiver<Result<crate::update::InjectedRemoval, RibCommandError>>;

/// Queue a guarded add with a 60 s lease without waiting for its reply.
async fn queue_guarded_add(
    tx: &mpsc::Sender<RibUpdate>,
    route: FlowSpecRoute,
    owner: &str,
    window: MutationWindowId,
    revision: u64,
) -> AddReply {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectGuardedFlowSpec {
        route,
        owner: owner.to_string(),
        lease_seconds: 60,
        fence: GuardedFence {
            window,
            revision: NonZeroU64::new(revision).unwrap(),
        },
        reply,
    })
    .await
    .unwrap();
    rx
}

async fn guarded_add(
    tx: &mpsc::Sender<RibUpdate>,
    route: FlowSpecRoute,
    owner: &str,
    window: MutationWindowId,
    revision: u64,
) -> Result<(InjectOutcome, LeaseGeneration), RibCommandError> {
    queue_guarded_add(tx, route, owner, window, revision)
        .await
        .await
        .unwrap()
}

/// Queue a guarded delete without waiting for its reply.
async fn queue_guarded_delete(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
    revision: u64,
) -> DeleteReply {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawGuardedFlowSpec {
        key: rule_key(octet),
        owner: owner.to_string(),
        revision: NonZeroU64::new(revision).unwrap(),
        reply,
    })
    .await
    .unwrap();
    rx
}

async fn guarded_delete(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
    revision: u64,
) -> Result<crate::update::InjectedRemoval, RibCommandError> {
    queue_guarded_delete(tx, octet, owner, revision)
        .await
        .await
        .unwrap()
}

/// A legacy owner-scoped `FlowSpec` delete.
async fn legacy_delete_rule(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    owner: &str,
    override_owner: bool,
) -> Result<crate::update::InjectedRemoval, RibCommandError> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawFlowSpec {
        key: rule_key(octet),
        allow_missing: false,
        owner: owner.to_string(),
        override_owner,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

#[track_caller]
fn assert_conflict<T: std::fmt::Debug>(
    result: Result<T, RibCommandError>,
    expected: LeaseConflict,
) {
    match result {
        Err(RibCommandError::FailedPrecondition(conflict, _)) => assert_eq!(conflict, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

/// The local rules' destination octets with their payloads, sorted.
async fn local_rules(tx: &mpsc::Sender<RibUpdate>) -> Vec<(u8, Vec<PathAttribute>)> {
    let mut rules: Vec<(u8, Vec<PathAttribute>)> = query_flowspec_routes(tx)
        .await
        .into_iter()
        .filter(|route| route.peer == LOCAL_PEER)
        .map(|route| {
            let octet = (1..=u8::MAX)
                .find(|octet| route.selection_key() == rule_key(*octet))
                .expect("a guarded test rule");
            (octet, route.attributes.clone())
        })
        .collect();
    rules.sort_by_key(|(octet, _)| *octet);
    rules
}

fn guarded_lease(h: &Harness, owner: &str) -> Vec<crate::injection_lease::LeaseRow> {
    h.leases.list(Some(&guarded_owner(owner)))
}

fn flowspec_changes(updates: &[OutboundRouteUpdate]) -> usize {
    updates
        .iter()
        .map(|update| update.flowspec_announce.len() + update.flowspec_withdraw.len())
        .sum()
}

/// A guarded add queued behind a stalled RIB inside its window, and applied
/// after the window expired, is refused at commit: it starts no lease for a
/// new owner, leaves a live sibling and its lease untouched, and reaches
/// neither the RIB nor the wire.
///
/// Break-to-red: without the window check in the lease table's admission,
/// both adds commit and the new owner starts a lease.
#[tokio::test(start_paused = true)]
async fn a_guarded_add_stalled_past_its_window_starts_no_lease() {
    let mut h = Harness::start_with_ingest_stall(Some(Duration::from_secs(20))).await;
    let (long, _) = h.leases.issue_window("ctl", 120).unwrap();
    guarded_add(&h.tx, guarded_rule(1, 1), "ctl", long, 1)
        .await
        .unwrap();
    h.settle().await;
    h.drain();
    let sibling_lease = guarded_lease(&h, "ctl");

    let (short_ctl, _) = h.leases.issue_window("ctl", 5).unwrap();
    let (short_solo, _) = h.leases.issue_window("solo", 5).unwrap();
    h.stall_rib().await;
    let sibling = queue_guarded_add(&h.tx, guarded_rule(2, 1), "ctl", short_ctl, 1).await;
    let fresh = queue_guarded_add(&h.tx, guarded_rule(3, 1), "solo", short_solo, 1).await;
    tokio::time::advance(Duration::from_secs(20)).await;

    assert_conflict(sibling.await.unwrap(), LeaseConflict::WindowNotLive);
    assert_conflict(fresh.await.unwrap(), LeaseConflict::WindowNotLive);
    h.settle().await;
    assert_eq!(flowspec_changes(&h.drain()), 0, "nothing reached the wire");
    assert_eq!(guarded_lease(&h, "solo"), Vec::new(), "no lease started");
    let lease = guarded_lease(&h, "ctl");
    assert_eq!(lease[0].generation, sibling_lease[0].generation);
    assert_eq!(
        lease[0].remaining,
        sibling_lease[0]
            .remaining
            .checked_sub(Duration::from_secs(20))
            .unwrap(),
        "the refusal did not move the sibling's deadline"
    );
    let rules = local_rules(&h.tx).await;
    assert_eq!(
        rules.iter().map(|(octet, _)| *octet).collect::<Vec<_>>(),
        [1]
    );
    h.stop().await;
}

/// A guarded add with an older window does not shorten a later deadline,
/// and never extends past its own window. An unchanged re-add through a
/// short window stops at that window's expiry; after a renewal through a
/// longer window, the same re-add keeps the later deadline, so a delayed add
/// cannot expire live sibling keys early. A renewal still sets the deadline
/// exactly, capped by its window.
///
/// Break-to-red: capping after taking the maximum lets the late re-add pull
/// the renewed deadline back to the short window's expiry.
#[tokio::test(start_paused = true)]
async fn a_guarded_add_never_shortens_and_never_passes_its_window() {
    let h = Harness::start().await;
    let (short, _) = h.leases.issue_window("ctl", 30).unwrap();
    let (outcome, g) = guarded_add(&h.tx, guarded_rule(1, 1), "ctl", short, 1)
        .await
        .unwrap();
    assert_eq!(outcome, InjectOutcome::Created);
    assert_eq!(
        guarded_lease(&h, "ctl")[0].remaining,
        Duration::from_secs(30)
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        guarded_add(&h.tx, guarded_rule(1, 1), "ctl", short, 1)
            .await
            .unwrap(),
        (InjectOutcome::Unchanged, g)
    );
    assert_eq!(
        guarded_lease(&h, "ctl")[0].remaining,
        Duration::from_secs(20),
        "the re-add stops at its own window's expiry"
    );

    let (long, _) = h.leases.issue_window("ctl", 120).unwrap();
    assert_eq!(
        h.leases.renew_guarded("ctl", g, 60, long),
        Ok(Duration::from_secs(60))
    );
    assert_eq!(
        guarded_add(&h.tx, guarded_rule(1, 1), "ctl", short, 1)
            .await
            .unwrap(),
        (InjectOutcome::Unchanged, g)
    );
    assert_eq!(
        guarded_lease(&h, "ctl")[0].remaining,
        Duration::from_secs(60),
        "the older window does not pull the deadline back"
    );
    assert_eq!(
        h.leases.renew_guarded("ctl", g, 60, short),
        Ok(Duration::from_secs(20))
    );
    assert_eq!(
        guarded_lease(&h, "ctl")[0].remaining,
        Duration::from_secs(20)
    );
    h.stop().await;
}

/// A lease shortened through `renew_guarded` expires at the shortened
/// deadline: its keys leave the RIB and the wire then, not at the deadline
/// the add set.
///
/// Break-to-red: an expiry task that keeps sleeping to the old deadline
/// leaves the rule in place past the shortened one.
#[tokio::test(start_paused = true)]
async fn a_shortened_guarded_lease_expires_at_the_new_deadline() {
    let mut h = Harness::start().await;
    let (window, _) = h.leases.issue_window("ctl", 120).unwrap();
    let (_, g) = guarded_add(&h.tx, guarded_rule(1, 1), "ctl", window, 1)
        .await
        .unwrap();
    h.settle().await;
    h.drain();
    assert_eq!(
        guarded_lease(&h, "ctl")[0].remaining,
        Duration::from_secs(60)
    );
    assert_eq!(
        h.leases.renew_guarded("ctl", g, 10, window),
        Ok(Duration::from_secs(10))
    );
    h.settle().await;

    tokio::time::advance(Duration::from_secs(9)).await;
    h.settle().await;
    assert_eq!(flowspec_changes(&h.drain()), 0);
    assert_eq!(local_rules(&h.tx).await.len(), 1);

    tokio::time::advance(Duration::from_secs(1)).await;
    h.settle().await;
    let withdrawn: usize = h
        .drain()
        .iter()
        .map(|update| update.flowspec_withdraw.len())
        .sum();
    assert_eq!(withdrawn, 1, "withdrawn on the wire at the new deadline");
    assert_eq!(local_rules(&h.tx).await, Vec::new());
    assert_eq!(guarded_lease(&h, "ctl"), Vec::new());
    h.stop().await;
}

/// A guarded add with a nonzero path ID is refused before admission: the
/// local rule key, the ownership index and the withdraw path all assume
/// path ID 0. Nothing changes: no lease, no rule, nothing on the wire.
///
/// Break-to-red: without the check, the add is admitted under a key the
/// guarded delete cannot reach.
#[tokio::test(start_paused = true)]
async fn a_guarded_add_with_a_path_id_is_refused() {
    let mut h = Harness::start().await;
    let (window, _) = h.leases.issue_window("ctl", 120).unwrap();
    let mut route = guarded_rule(1, 1);
    route.path_id = 7;
    let result = guarded_add(&h.tx, route, "ctl", window, 1).await;
    assert!(
        matches!(result, Err(RibCommandError::Internal(_))),
        "{result:?}"
    );
    h.settle().await;
    assert_eq!(flowspec_changes(&h.drain()), 0);
    assert_eq!(local_rules(&h.tx).await, Vec::new());
    assert_eq!(guarded_lease(&h, "ctl"), Vec::new());
    h.stop().await;
}

/// Only a guarded delete that removes a rule retires the key's exact-export
/// rejections. A refused delete (another revision) runs no retirement, and
/// an absent key's recorded rejection stays; the delete that removes a rule
/// retires its key and no other.
///
/// Break-to-red: retiring unconditionally runs the retirement for the
/// refusal and drops the absent key's rejection.
#[tokio::test(start_paused = true)]
async fn only_a_removing_guarded_delete_retires_export_rejections() {
    let mut manager = manager_for_keys();
    let (window, _) = manager.injection_leases().issue_window("ctl", 120).unwrap();
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectGuardedFlowSpec {
        route: guarded_rule(1, 1),
        owner: "ctl".to_string(),
        lease_seconds: 60,
        fence: GuardedFence {
            window,
            revision: NonZeroU64::new(1).unwrap(),
        },
        reply,
    });
    rx.try_recv().unwrap().unwrap();
    let rejected = |octet| ExactExportKey::FlowSpec(rule_key(octet));
    manager
        .peer_unexportable
        .insert(TARGET, HashSet::from([rejected(1), rejected(2)]));
    let retirements = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let retirements = Arc::clone(&retirements);
        move |seam| {
            if seam == "exact_rejection_retirement" {
                retirements.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }));
    let delete = |manager: &mut RibManager, octet: u8, revision: u64| {
        let (reply, mut rx) = oneshot::channel();
        manager.with_replacement_readiness(|manager| {
            manager.handle_update(RibUpdate::WithdrawGuardedFlowSpec {
                key: rule_key(octet),
                owner: "ctl".to_string(),
                revision: NonZeroU64::new(revision).unwrap(),
                reply,
            });
        });
        rx.try_recv().unwrap()
    };

    assert_conflict(delete(&mut manager, 1, 2), LeaseConflict::RevisionMismatch);
    assert!(!delete(&mut manager, 2, 1).unwrap().removed);
    assert_eq!(
        retirements.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no retirement for a refused or absent delete"
    );
    assert_eq!(
        manager.peer_unexportable[&TARGET],
        HashSet::from([rejected(1), rejected(2)])
    );

    assert!(delete(&mut manager, 1, 1).unwrap().removed);
    assert_eq!(
        manager.peer_unexportable[&TARGET],
        HashSet::from([rejected(2)]),
        "the removed key's rejection is retired, the absent key's is not"
    );
}

/// A delete of an older revision delayed behind a delete and a newer add of
/// the same key is refused, and the newer admission stays in the RIB and on
/// the wire. Its own revision reads back through the removal tag, and a
/// repeat delete reports the key absent.
///
/// Break-to-red: without the revision check on the withdraw path, the late
/// delete removes the newer admission.
#[tokio::test(start_paused = true)]
async fn a_delayed_delete_spares_a_newer_admission() {
    let mut h = Harness::start_with_ingest_stall(Some(Duration::from_secs(20))).await;
    let (window, _) = h.leases.issue_window("ctl", 120).unwrap();
    guarded_add(&h.tx, guarded_rule(1, 1), "ctl", window, 1)
        .await
        .unwrap();
    guarded_add(&h.tx, guarded_rule(2, 1), "ctl", window, 1)
        .await
        .unwrap();
    h.settle().await;
    h.drain();

    h.stall_rib().await;
    let first = queue_guarded_delete(&h.tx, 1, "ctl", 1).await;
    let newer = queue_guarded_add(&h.tx, guarded_rule(1, 2), "ctl", window, 2).await;
    let late = queue_guarded_delete(&h.tx, 1, "ctl", 1).await;
    tokio::time::advance(Duration::from_secs(20)).await;

    let removal = first.await.unwrap().unwrap();
    assert!(removal.removed);
    assert_eq!(removal.tag.unwrap().revision, NonZeroU64::new(1));
    assert_eq!(newer.await.unwrap().unwrap().0, InjectOutcome::Created);
    assert_conflict(late.await.unwrap(), LeaseConflict::RevisionMismatch);
    h.settle().await;
    let updates = h.drain();
    let last = updates
        .iter()
        .rev()
        .find(|update| flowspec_changes(std::slice::from_ref(update)) > 0)
        .unwrap();
    assert_eq!(
        last.flowspec_announce.len(),
        1,
        "the newer admission is announced last"
    );
    assert_eq!(
        local_rules(&h.tx).await,
        vec![
            (1, guarded_rule(1, 2).attributes),
            (2, guarded_rule(2, 1).attributes)
        ]
    );

    let (reply, rx) = oneshot::channel();
    h.tx.send(RibUpdate::QueryLeasedKeys {
        owner: guarded_owner("ctl"),
        resume: None,
        page_size: 10,
        reply,
    })
    .await
    .unwrap();
    let revisions: Vec<_> = rx
        .await
        .unwrap()
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.key, row.revision))
        .collect();
    assert_eq!(
        revisions,
        [
            (InjectedKey::FlowSpec(rule_key(1)), NonZeroU64::new(2)),
            (InjectedKey::FlowSpec(rule_key(2)), NonZeroU64::new(1)),
        ],
        "read-back reports each key's admission revision"
    );

    assert_conflict(
        guarded_delete(&h.tx, 2, "other", 1).await,
        LeaseConflict::OwnerMismatch,
    );
    let removal = guarded_delete(&h.tx, 1, "ctl", 2).await.unwrap();
    assert!(removal.removed);
    assert_eq!(removal.tag.unwrap().revision, NonZeroU64::new(2));
    let absent = guarded_delete(&h.tx, 1, "ctl", 2).await.unwrap();
    assert!(!absent.removed, "an absent key is NOT_PRESENT");
    assert_eq!(local_rules(&h.tx).await.len(), 1);
    h.stop().await;
}

/// A present key refuses another revision, and its own revision with a
/// different payload, changing nothing: the payload, the sibling key, the
/// lease deadline and the wire stay as they were. Its own revision with the
/// same payload is an idempotent retry.
///
/// Break-to-red: without the revision checks on the add path, the second
/// payload replaces the first.
#[tokio::test(start_paused = true)]
async fn a_present_key_refuses_another_revision_or_payload() {
    let mut h = Harness::start().await;
    let (window, _) = h.leases.issue_window("ctl", 120).unwrap();
    let (_, g) = guarded_add(&h.tx, guarded_rule(1, 1), "ctl", window, 1)
        .await
        .unwrap();
    guarded_add(&h.tx, guarded_rule(2, 1), "ctl", window, 1)
        .await
        .unwrap();
    h.settle().await;
    h.drain();
    let before = guarded_lease(&h, "ctl");
    let rules = local_rules(&h.tx).await;
    tokio::time::advance(Duration::from_secs(5)).await;

    for (community, revision) in [(2, 1), (1, 2), (2, 2)] {
        assert_conflict(
            guarded_add(&h.tx, guarded_rule(1, community), "ctl", window, revision).await,
            LeaseConflict::RevisionMismatch,
        );
    }
    h.settle().await;
    assert_eq!(flowspec_changes(&h.drain()), 0);
    assert_eq!(local_rules(&h.tx).await, rules);
    let after = guarded_lease(&h, "ctl");
    assert_eq!(after[0].generation, g);
    assert_eq!(
        after[0].remaining,
        before[0]
            .remaining
            .checked_sub(Duration::from_secs(5))
            .unwrap()
    );
    assert_eq!(
        guarded_add(&h.tx, guarded_rule(1, 1), "ctl", window, 1)
            .await
            .unwrap(),
        (InjectOutcome::Unchanged, g)
    );
    h.stop().await;
}

/// Legacy entry points cannot reach a guarded owner's key or lease: a
/// leased add, an unowned add and an owner-scoped delete of the bare name
/// are refused; a legacy renewal of the guarded generation fails; and a
/// legacy add of a new key starts a separate lease that leaves the guarded
/// deadline alone. Guarded calls cannot reach the legacy key either, and
/// `override_owner` stays as break-glass.
///
/// Break-to-red: without the namespace, the legacy add joins the guarded
/// owner's key.
#[tokio::test(start_paused = true)]
async fn legacy_entry_points_cannot_reach_a_guarded_owner() {
    let h = Harness::start().await;
    let (window, _) = h.leases.issue_window("ctl", 120).unwrap();
    let (_, g) = guarded_add(&h.tx, guarded_rule(1, 1), "ctl", window, 1)
        .await
        .unwrap();
    let before = guarded_lease(&h, "ctl");

    assert_conflict(
        leased_rule(&h.tx, guarded_rule(1, 1), "ctl", 3600).await,
        LeaseConflict::OwnerMismatch,
    );
    let (reply, rx) = oneshot::channel();
    h.tx.send(RibUpdate::InjectFlowSpec {
        route: guarded_rule(1, 1),
        reply,
    })
    .await
    .unwrap();
    assert_conflict(rx.await.unwrap(), LeaseConflict::OwnerMismatch);
    for owner in ["ctl", ""] {
        assert_conflict(
            legacy_delete_rule(&h.tx, 1, owner, false).await,
            LeaseConflict::OwnerMismatch,
        );
    }
    assert_eq!(h.leases.renew("ctl", g, 3600), None);
    let (_, legacy) = leased_rule(&h.tx, guarded_rule(2, 1), "ctl", 3600)
        .await
        .unwrap();
    assert_ne!(legacy, g, "a separate legacy lease");
    assert_eq!(guarded_lease(&h, "ctl"), before);

    assert_conflict(
        guarded_add(&h.tx, guarded_rule(2, 1), "ctl", window, 1).await,
        LeaseConflict::OwnerMismatch,
    );
    assert_conflict(
        guarded_delete(&h.tx, 2, "ctl", 1).await,
        LeaseConflict::OwnerMismatch,
    );
    assert_eq!(local_rules(&h.tx).await.len(), 2);

    let removal = legacy_delete_rule(&h.tx, 1, "", true).await.unwrap();
    assert!(removal.removed);
    assert_eq!(&*removal.tag.unwrap().owner, guarded_owner("ctl"));
    h.stop().await;
}
