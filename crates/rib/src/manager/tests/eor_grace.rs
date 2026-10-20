//! Planned-restart End-of-RIB grace window, on a paused clock.
//!
//! The upstream is modeled as an RFC 4724 §4.2 helper: it retains the
//! previous session's routes as stale, refreshes them on re-advertisement,
//! drops them on withdrawal, and removes every remaining stale route of a
//! family at that family's End-of-RIB. The model is updated after every
//! outbound message, so a transient gap is seen even when the final table
//! looks right.

use std::collections::HashSet;

use rustbgpd_bmp::BmpReplay;
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::mpsc;

use super::*;
use crate::update::{InjectOutcome, RibCommandError};
use crate::{
    EorGraceConfig, EorGracePeerConfig, SelectionDeferralConfig, SelectionDeferralWaiterConfig,
};

const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const WINDOW: Duration = Duration::from_secs(10);
const UPSTREAM: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
/// Banned before the restart and re-injected by the controller after it.
const KEPT: u8 = 7;
/// Banned before the restart and unbanned while the daemon was down: the
/// restarted daemon never learns it again.
const UNBANNED: u8 = 8;
const MS: Duration = Duration::from_millis(1);

fn host(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

fn local_route(octet: u8) -> Route {
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
        Ipv4Addr::UNSPECIFIED,
    );
    route.peer = super::super::helpers::LOCAL_PEER;
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

fn grace(peers: &[IpAddr]) -> EorGraceConfig {
    let start = tokio::time::Instant::now();
    EorGraceConfig {
        peers: peers
            .iter()
            .map(|&peer| EorGracePeerConfig {
                peer,
                deadline: start + WINDOW,
                families: vec![V4, V6],
            })
            .collect(),
    }
}

/// The daemon builds the selection-deferral roster from the same static GR
/// peers. A helper-only upstream (FRR's default) is excluded from it, so the
/// gate releases at once and only the grace window can hold End-of-RIB.
fn deferral(peers: &[IpAddr]) -> SelectionDeferralConfig {
    SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: peers
            .iter()
            .map(|&peer| SelectionDeferralWaiterConfig {
                peer,
                families: vec![V4, V6],
            })
            .collect(),
    }
}

/// `None` is a cold boot; `Some(peers)` a planned restart with a grace
/// window for `peers` (possibly none).
fn manager(grace_peers: Option<&[IpAddr]>, metrics: &BgpMetrics) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    with_grace(
        RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()),
        grace_peers,
    )
}

fn with_grace(manager: RibManager, grace_peers: Option<&[IpAddr]>) -> RibManager {
    match grace_peers {
        Some(peers) => manager
            .with_selection_deferral(deferral(&[UPSTREAM]))
            .with_eor_grace(grace(peers)),
        None => manager,
    }
}

#[derive(Clone, Copy)]
struct Session {
    helper: bool,
    restarting: bool,
}

const HELPER: Session = Session {
    helper: true,
    restarting: false,
};

fn session_messages(
    peer: IpAddr,
    session_id: u64,
    session: Session,
    families: Vec<(Afi, Safi)>,
    capacity: usize,
) -> ([RibUpdate; 2], mpsc::Receiver<OutboundRouteUpdate>) {
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    (
        [
            RibUpdate::SetPeerGracefulRestartContext {
                peer,
                session_id,
                peer_restart_state: session.restarting,
                peer_gr_helper: session.helper,
                // Helper-only: the capability lists no family.
                peer_gr_families: vec![],
                peer_enhanced_refresh: true,
                peer_llgr_families: vec![],
                local_llgr_stale_time: 0,
            },
            RibUpdate::PeerUp {
                peer,
                session_id,
                peer_asn: 65_002,
                peer_router_id: Ipv4Addr::new(10, 0, 0, 254),
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
            },
        ],
        outbound_rx,
    )
}

fn connect(
    manager: &mut RibManager,
    peer: IpAddr,
    session: Session,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (messages, rx) = session_messages(peer, 1, session, vec![V4], 64);
    for message in messages {
        manager.handle_update(message);
    }
    rx
}

fn inject(manager: &mut RibManager, octet: u8) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: local_route(octet),
        reply,
    });
    drain_route_chunks(manager);
    assert!(rx.try_recv().unwrap().is_ok());
}

/// RFC 4724 §4.2 helper retaining the previous session's routes.
struct Helper {
    routes: HashSet<Prefix>,
    stale: HashSet<Prefix>,
    eor: Vec<(Afi, Safi)>,
    /// Every message in arrival order, reduced to what ordering checks need.
    log: Vec<String>,
}

impl Helper {
    fn retaining(octets: &[u8]) -> Self {
        let stale: HashSet<Prefix> = octets.iter().map(|&octet| host(octet)).collect();
        Self {
            routes: stale.clone(),
            stale,
            eor: vec![],
            log: vec![],
        }
    }

    fn apply(&mut self, update: &OutboundRouteUpdate) {
        for route in update.announce.iter() {
            self.stale.remove(&route.prefix);
            self.routes.insert(route.prefix);
            self.log.push(format!("announce {}", route.prefix));
        }
        for (prefix, _) in &update.withdraw {
            self.stale.remove(prefix);
            self.routes.remove(prefix);
            self.log.push(format!("withdraw {prefix}"));
        }
        if update.end_of_rib.contains(&V4) {
            for prefix in self.stale.drain() {
                self.routes.remove(&prefix);
            }
            self.log.push("eor".into());
        }
        self.eor.extend(update.end_of_rib.iter().copied());
        assert!(
            update.refresh_markers.is_empty() || !self.eor.is_empty(),
            "a refresh marker preceded the initial End-of-RIB"
        );
    }

    /// Apply every queued message, checking `invariant` after each one.
    fn observe(
        &mut self,
        rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
        mut invariant: impl FnMut(&Self) -> bool,
    ) -> bool {
        let mut held = true;
        while let Ok(update) = rx.try_recv() {
            self.apply(&update);
            held &= invariant(self);
        }
        held
    }

    fn has(&self, octet: u8) -> bool {
        self.routes.contains(&host(octet))
    }
}

fn eor_count(metrics: &BgpMetrics, peer: IpAddr) -> f64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_gr_eor_grace_expired_total")
        .and_then(|family| {
            family
                .get_metric()
                .iter()
                .find(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "peer" && label.value() == peer.to_string())
                })
                .map(|metric| metric.get_counter().get_value())
        })
        .unwrap_or(0.0)
}

struct ReplayRun {
    /// The re-injected ban was absent at the upstream after some message.
    gap: bool,
    /// When End-of-RIB reached the upstream, relative to process start.
    eor_at: Option<Duration>,
    log: Vec<String>,
}

struct Observer {
    helper: Helper,
    start: tokio::time::Instant,
    gap: bool,
    eor_at: Option<Duration>,
}

impl Observer {
    fn apply(&mut self, update: &OutboundRouteUpdate) {
        self.helper.apply(update);
        self.gap |= !self.helper.has(KEPT);
        if self.eor_at.is_none() && !self.helper.eor.is_empty() {
            self.eor_at = Some(self.start.elapsed());
        }
    }

    fn drain(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv() {
            self.apply(&update);
        }
    }
}

/// One primary round trip: every earlier message has been applied.
async fn sync(tx: &mpsc::Sender<RibUpdate>) {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount {
        peer: UPSTREAM,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap();
}

/// One planned restart through the running actor: the upstream reconnects
/// at once, the controller re-injects one ban after `replay_after`, and the
/// upstream is observed after every message until `WINDOW + 1 s`.
async fn delayed_replay(grace_on: bool, replay_after: Duration) -> ReplayRun {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let grace_peers: &[IpAddr] = if grace_on { &[UPSTREAM] } else { &[] };
    let manager = with_grace(
        RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()),
        Some(grace_peers),
    );
    let mut observer = Observer {
        helper: Helper::retaining(&[KEPT, UNBANNED]),
        start: tokio::time::Instant::now(),
        gap: false,
        eor_at: None,
    };
    let handle = tokio::spawn(manager.run());
    let (messages, mut out_rx) = session_messages(UPSTREAM, 1, HELPER, vec![V4], 64);
    for message in messages {
        tx.send(message).await.unwrap();
    }
    sync(&tx).await;
    observer.drain(&mut out_rx);

    tokio::time::advance(replay_after).await;
    let (reply, injected) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route: local_route(KEPT),
        reply,
    })
    .await
    .unwrap();
    let outcome: Result<InjectOutcome, RibCommandError> = injected.await.unwrap();
    outcome.unwrap();
    sync(&tx).await;
    observer.drain(&mut out_rx);

    // Just before the deadline nothing may release End-of-RIB.
    tokio::time::advance(WINDOW.saturating_sub(replay_after + MS)).await;
    sync(&tx).await;
    observer.drain(&mut out_rx);
    if grace_on {
        assert!(
            observer.helper.eor.is_empty(),
            "End-of-RIB left before the deadline"
        );
        assert!(eor_count(&metrics, UPSTREAM) < 0.5);
        tokio::time::advance(MS).await;
        // The run loop's own timer releases the marker.
        let update = out_rx.recv().await.unwrap();
        observer.apply(&update);
        assert!((eor_count(&metrics, UPSTREAM) - 1.0).abs() < f64::EPSILON);
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    sync(&tx).await;
    observer.drain(&mut out_rx);
    assert!(
        observer.helper.has(KEPT),
        "the re-injected ban is missing at the end"
    );
    assert!(
        !observer.helper.has(UNBANNED),
        "the unbanned route outlived End-of-RIB"
    );

    drop(tx);
    handle.await.unwrap();
    ReplayRun {
        gap: observer.gap,
        eor_at: observer.eor_at,
        log: observer.helper.log,
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_replay_inside_the_window_never_leaves_a_gap() {
    let run = delayed_replay(true, Duration::from_secs(4)).await;
    assert!(
        !run.gap,
        "re-injected ban was absent at the upstream: {:?}",
        run.log
    );
    assert_eq!(run.eor_at, Some(WINDOW));
    // The replayed announcement precedes the released marker.
    let announce = run
        .log
        .iter()
        .position(|e| e == &format!("announce {}", host(KEPT)));
    let eor = run.log.iter().position(|e| e == "eor");
    assert!(announce.unwrap() < eor.unwrap(), "{:?}", run.log);
}

/// Control: the same restart without the window. End-of-RIB leaves with the
/// initial table and the upstream drops the ban until replay re-adds it.
#[tokio::test(start_paused = true)]
async fn control_without_the_window_shows_the_gap() {
    let run = delayed_replay(false, Duration::from_secs(4)).await;
    assert!(run.gap, "the control must observe the gap: {:?}", run.log);
    assert_eq!(run.eor_at, Some(Duration::ZERO));
    assert_eq!(run.log.first().map(String::as_str), Some("eor"));
}

/// No replay at all: the deadline alone releases End-of-RIB, counted in the
/// expiry metric, and the upstream then drops every unreplayed stale ban.
#[tokio::test(start_paused = true)]
async fn absent_replay_is_released_by_the_deadline() {
    let metrics = BgpMetrics::new();
    let mut manager = manager(Some(&[UPSTREAM]), &metrics);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    let mut helper = Helper::retaining(&[KEPT, UNBANNED]);
    assert!(helper.observe(&mut rx, |helper| helper.has(KEPT) && helper.has(UNBANNED)));
    assert_eq!(helper.eor, []);

    tokio::time::advance(WINDOW.saturating_sub(MS)).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert!(helper.observe(&mut rx, |helper| helper.has(KEPT)));
    assert_eq!(helper.eor, []);
    assert!(eor_count(&metrics, UPSTREAM) < 0.5);

    tokio::time::advance(MS).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    helper.observe(&mut rx, |_| true);
    assert_eq!(helper.eor, vec![V4]);
    assert!(!helper.has(KEPT) && !helper.has(UNBANNED));
    assert!((eor_count(&metrics, UPSTREAM) - 1.0).abs() < f64::EPSILON);
    // The window is spent: a later reconnect sends End-of-RIB at once.
    manager.handle_update(RibUpdate::PeerDown {
        peer: UPSTREAM,
        session_id: 1,
    });
    let (messages, mut rx) = session_messages(UPSTREAM, 2, HELPER, vec![V4], 64);
    for message in messages {
        manager.handle_update(message);
    }
    assert!(rx.try_recv().unwrap().end_of_rib.contains(&V4));
}

/// Partial replay plus a ban lifted during the outage: the replayed ban is
/// fresh, the lifted one stays stale until the release removes it, and a
/// controller withdrawal during the hold flows at once.
#[tokio::test(start_paused = true)]
async fn unban_during_downtime_is_retained_until_release() {
    const LATER: u8 = 9;
    let metrics = BgpMetrics::new();
    let mut manager = manager(Some(&[UPSTREAM]), &metrics);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    let mut helper = Helper::retaining(&[KEPT, UNBANNED]);
    let both = |helper: &Helper| helper.has(KEPT) && helper.has(UNBANNED);
    assert!(helper.observe(&mut rx, both));

    tokio::time::advance(Duration::from_secs(3)).await;
    inject(&mut manager, KEPT);
    assert!(helper.observe(&mut rx, both));
    assert!(!helper.stale.contains(&host(KEPT)));
    assert!(helper.stale.contains(&host(UNBANNED)));

    // A ban added and lifted inside the hold reaches the upstream both ways.
    inject(&mut manager, LATER);
    assert!(helper.observe(&mut rx, both));
    assert!(helper.has(LATER));
    let (reply, mut removed) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: host(LATER),
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    drain_route_chunks(&mut manager);
    assert!(removed.try_recv().unwrap().unwrap().removed);
    assert!(helper.observe(&mut rx, both));
    assert!(!helper.has(LATER), "withdrawal waited for the hold");
    assert_eq!(helper.eor, []);

    tokio::time::advance(WINDOW).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert!(helper.observe(&mut rx, |helper| helper.has(KEPT)));
    assert!(!helper.has(UNBANNED), "the lifted ban outlived the release");
}

/// The deadline is fixed at process start: a reconnect inside the window
/// holds End-of-RIB again but only until the original deadline.
#[tokio::test(start_paused = true)]
async fn reconnect_does_not_extend_the_deadline() {
    let metrics = BgpMetrics::new();
    let mut manager = manager(Some(&[UPSTREAM]), &metrics);
    let mut first = connect(&mut manager, UPSTREAM, HELPER);
    tokio::time::advance(Duration::from_secs(6)).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    while let Ok(update) = first.try_recv() {
        assert_eq!(update.end_of_rib, []);
    }
    manager.handle_update(RibUpdate::PeerDown {
        peer: UPSTREAM,
        session_id: 1,
    });
    let (messages, mut second) = session_messages(UPSTREAM, 2, HELPER, vec![V4], 64);
    for message in messages {
        manager.handle_update(message);
    }
    tokio::time::advance(Duration::from_secs(4).saturating_sub(MS)).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    while let Ok(update) = second.try_recv() {
        assert!(update.end_of_rib.is_empty(), "released before the deadline");
    }
    tokio::time::advance(MS).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
    assert_eq!(second.try_recv().unwrap().end_of_rib, vec![V4]);
}

/// A cold boot builds no window, and in a planned restart a peer without the
/// setting, a non-helper session, or a restarting peer keep today's
/// immediate End-of-RIB (RFC 4724 §4.1).
#[tokio::test(start_paused = true)]
async fn cold_boot_and_ineligible_sessions_get_end_of_rib_at_once() {
    let metrics = BgpMetrics::new();

    let mut cold = manager(None, &metrics);
    let mut rx = connect(&mut cold, UPSTREAM, HELPER);
    assert_eq!(rx.try_recv().unwrap().end_of_rib, vec![V4]);

    // RFC 4724 §4.2: an unconfigured peer (here a reflector client) in the
    // same restart is not delayed by the configured peer's window.
    let mut planned = manager(Some(&[UPSTREAM]), &metrics);
    let mut held = connect(&mut planned, UPSTREAM, HELPER);
    let mut client = connect(&mut planned, CLIENT, HELPER);
    assert_eq!(client.try_recv().unwrap().end_of_rib, vec![V4]);
    assert_no_eor(&mut held, "configured upstream");

    for session in [
        Session {
            helper: false,
            restarting: false,
        },
        Session {
            helper: true,
            restarting: true,
        },
    ] {
        let mut planned = manager(Some(&[UPSTREAM]), &metrics);
        let mut rx = connect(&mut planned, UPSTREAM, session);
        assert_eq!(rx.try_recv().unwrap().end_of_rib, vec![V4]);
    }
}

fn assert_no_eor(rx: &mut mpsc::Receiver<OutboundRouteUpdate>, path: &str) {
    while let Ok(update) = rx.try_recv() {
        assert!(update.end_of_rib.is_empty(), "{path} sent End-of-RIB");
        assert!(
            update.refresh_markers.is_empty(),
            "{path} sent a refresh marker before the initial End-of-RIB"
        );
    }
}

async fn release(manager: &mut RibManager) {
    tokio::time::advance(WINDOW).await;
    manager.expire_eor_holds(tokio::time::Instant::now());
}

/// Every alternate End-of-RIB writer respects the hold, and the released
/// marker follows the routes those paths sent.
#[tokio::test(start_paused = true)]
async fn refresh_and_operator_replay_respect_the_hold() {
    let metrics = BgpMetrics::new();

    // Peer ROUTE-REFRESH: routes flow, End-of-RIB and BoRR/EoRR wait.
    let mut manager = manager(Some(&[UPSTREAM]), &metrics);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    inject(&mut manager, KEPT);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: UPSTREAM,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        queued: Arc::default(),
    });
    let mut helper = Helper::retaining(&[KEPT]);
    helper.observe(&mut rx, |_| true);
    assert!(helper.eor.is_empty(), "route refresh sent End-of-RIB");
    assert!(helper.has(KEPT));
    release(&mut manager).await;
    helper.observe(&mut rx, |_| true);
    assert_eq!(helper.eor, vec![V4]);

    // Operator outbound replay ends in a wire End-of-RIB: refused while held.
    let mut manager = manager_with(&metrics);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    let replay = |manager: &mut RibManager| {
        let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplayPeerOutbound {
            peer: UPSTREAM,
            session_id: 1,
            families: vec![V4],
            replay: token,
            reply,
        });
        response.try_recv().unwrap()
    };
    assert!(replay(&mut manager).is_err());
    assert_no_eor(&mut rx, "operator replay");
    release(&mut manager).await;
    assert_eq!(rx.try_recv().unwrap().end_of_rib, vec![V4]);
    assert!(replay(&mut manager).is_ok());
}

#[tokio::test(start_paused = true)]
async fn dirty_resync_respects_the_hold() {
    let metrics = BgpMetrics::new();
    // Dirty-peer resync (also the regroup path) carries no held marker; a
    // release while dirty leaves the marker to the resync, after its routes.
    let mut manager = manager_with(&metrics);
    let (messages, mut rx) = session_messages(UPSTREAM, 1, HELPER, vec![V4], 1);
    for message in messages {
        manager.handle_update(message);
    }
    let mut helper = Helper::retaining(&[KEPT]);
    let kept = |helper: &Helper| helper.has(KEPT);
    let _ = manager.mark_outbound_dirty(UPSTREAM);
    let _ = manager.resync_dirty_peers_bounded();
    assert!(helper.observe(&mut rx, kept));
    assert!(helper.eor.is_empty(), "dirty resync sent End-of-RIB");
    // A full one-slot queue makes the second announcement mark the peer dirty.
    inject(&mut manager, 9);
    inject(&mut manager, KEPT);
    assert!(manager.dirty_peers.contains(&UPSTREAM));
    release(&mut manager).await;
    assert!(helper.observe(&mut rx, kept));
    assert!(helper.eor.is_empty(), "release flushed past a dirty resync");
    assert!(
        !helper.stale.is_empty(),
        "the held route arrived before the resync"
    );
    let _ = manager.resync_dirty_peers_bounded();
    assert!(helper.observe(&mut rx, kept));
    assert_eq!(helper.eor, vec![V4]);
    assert_eq!(helper.log.last().map(String::as_str), Some("eor"));
}

#[tokio::test(start_paused = true)]
async fn late_family_marker_retry_and_selection_release_respect_the_hold() {
    let metrics = BgpMetrics::new();
    // A family that becomes sendable mid-session, and the EVPN marker retry
    // sweep over pending markers.
    let mut manager = manager_with(&metrics);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    manager.handle_update(RibUpdate::PeerFamilySendable {
        peer: UPSTREAM,
        session_id: 1,
        family: V6,
        add_path_send_limit: None,
    });
    manager.retry_evpn_feed_markers_bounded();
    assert_no_eor(&mut rx, "family-sendable / marker retry");
    release(&mut manager).await;
    let mut released = HashSet::new();
    while let Ok(update) = rx.try_recv() {
        released.extend(update.end_of_rib);
    }
    assert_eq!(released, HashSet::from([V4, V6]));

    // A GR-capable waiter's End-of-RIB releases selection deferral, whose
    // flush must still leave the grace hold in place.
    let mut manager = manager_with(&metrics);
    let (messages, mut rx) = {
        let (mut messages, rx) = session_messages(UPSTREAM, 1, HELPER, vec![V4], 64);
        if let RibUpdate::SetPeerGracefulRestartContext {
            peer_gr_families, ..
        } = &mut messages[0]
        {
            *peer_gr_families = vec![V4];
        }
        (messages, rx)
    };
    for message in messages {
        manager.handle_update(message);
    }
    assert!(manager.selection_convergence_held(V4));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: UPSTREAM,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert!(!manager.selection_convergence_held(V4));
    assert_no_eor(&mut rx, "selection-deferral release");
    release(&mut manager).await;
    let mut released = vec![];
    while let Ok(update) = rx.try_recv() {
        released.extend(update.end_of_rib);
    }
    assert_eq!(released, vec![V4]);
}

fn manager_with(metrics: &BgpMetrics) -> RibManager {
    manager(Some(&[UPSTREAM]), metrics)
}

/// The run loop probes the nearest hold deadline every turn. Grace deadlines
/// sit in a `DeadlineMap`, so that probe reads a cached minimum instead of
/// scanning the configured peers, and deleting the earliest peer moves it.
#[tokio::test(start_paused = true)]
async fn grace_deadlines_use_the_cached_deadline_map() {
    let metrics = BgpMetrics::new();
    let mut config = grace(&[UPSTREAM, CLIENT]);
    config.peers[1].deadline += WINDOW;
    let (_tx, rx) = mpsc::channel(8);
    let mut manager =
        RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()).with_eor_grace(config);
    let start = tokio::time::Instant::now();
    assert!(!manager.eor_grace_deadlines.is_stale());
    assert_eq!(manager.next_eor_hold_deadline(), Some(start + WINDOW));
    manager.handle_update(RibUpdate::PeerDeleted { peer: UPSTREAM });
    assert!(manager.eor_grace_deadlines.is_stale());
    assert_eq!(manager.next_eor_hold_deadline(), Some(start + WINDOW * 2));
    assert!(!manager.eor_grace_deadlines.is_stale());
}

/// Two windows of different lengths behind the one shared timer. The timer
/// fires for the shorter window; by the time its backlog has drained, the
/// longer window has passed too, while a replay for that peer queued between
/// the two deadlines still waits in the actor queue. Only the window that
/// fell due is released, so the replay reaches the later peer before its
/// End-of-RIB.
#[tokio::test(start_paused = true)]
async fn later_window_waits_for_its_own_turn() {
    let metrics = BgpMetrics::new();
    let mut config = grace(&[UPSTREAM, CLIENT]);
    config.peers[1].deadline += Duration::from_secs(1);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager =
        RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()).with_eor_grace(config);
    let start = tokio::time::Instant::now();
    let mut first = connect(&mut manager, UPSTREAM, HELPER);
    let mut later = connect(&mut manager, CLIENT, HELPER);

    // A's deadline falls due; its admitted backlog takes until after B's.
    tokio::time::advance(WINDOW + Duration::from_secs(2)).await;
    manager.expire_eor_holds(start + WINDOW);
    assert_eq!(first.try_recv().unwrap().end_of_rib, vec![V4]);
    assert_no_eor(
        &mut later,
        "the later window, released with the earlier one",
    );

    // The replay queued at 10.5 s is applied before B's own expiry turn.
    inject(&mut manager, KEPT);
    manager.expire_eor_holds(start + WINDOW + Duration::from_secs(1));
    let mut helper = Helper::retaining(&[KEPT]);
    assert!(helper.observe(&mut later, |helper| helper.has(KEPT)));
    assert_eq!(helper.eor, vec![V4]);
    assert_eq!(helper.log.last().map(String::as_str), Some("eor"));
}

/// Startup work can run past the window. The deadline was fixed at daemon
/// start, so End-of-RIB leaves on the first registration after it instead of
/// a full window later.
#[tokio::test(start_paused = true)]
async fn deadline_counts_from_daemon_start_not_install() {
    let metrics = BgpMetrics::new();
    let start = tokio::time::Instant::now();
    let config = grace(&[UPSTREAM]);
    tokio::time::advance(WINDOW + Duration::from_secs(5)).await;
    let mut manager = manager_from(config, &metrics);
    let due = manager.next_eor_hold_deadline().unwrap();
    assert_eq!(due, start + WINDOW);
    let mut rx = connect(&mut manager, UPSTREAM, HELPER);
    assert_no_eor(&mut rx, "the held session before the timer turn");
    manager.expire_eor_holds(due);
    assert_eq!(rx.try_recv().unwrap().end_of_rib, vec![V4]);
}

fn manager_from(config: EorGraceConfig, metrics: &BgpMetrics) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()).with_eor_grace(config)
}
