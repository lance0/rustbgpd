//! ADR-0140 planner, discovery and controller tests. The `netns` module
//! drives the real controller against kernel bonds and veths.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_evpn_linux::AdminLinkState;
use rustbgpd_rib::EvpnSessionsSync;
use tokio::time::Instant;

use super::receipt::{HostIdentity, LinkIdentity, NetnsId, OwnedLink};
use super::*;
use crate::config::{CoreIsolationBinding, CoreIsolationSnapshot, EvpnCoreIsolationConfig};

fn settings(hold: u64, backstop: u64) -> EvpnCoreIsolationConfig {
    EvpnCoreIsolationConfig {
        enabled: true,
        uplinks: Vec::new(),
        hold_after_sync_seconds: hold,
        backstop_seconds: backstop,
    }
}

fn bindings(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// Sessions up and synced, with `bond0`'s remote ES peers.
fn core_up(synced: bool, peers: &[&str]) -> Observation {
    Observation {
        sessions: EvpnSessionsSync {
            established: 1,
            stale: 0,
            synced,
        },
        uplinks_down: false,
        peers: Some(BTreeMap::from([(
            "bond0".to_string(),
            peers.iter().map(|p| ip(p)).collect(),
        )])),
    }
}

/// Every EVPN session down and nothing GR-retained.
fn core_lost() -> Observation {
    Observation::default()
}

fn hold(planner: &HoldPlanner) -> bool {
    matches!(planner.decision("bond0"), HoldDecision::Hold(_))
}

/// A released planner whose core is up with one remote ES peer latched.
fn steady(hold_secs: u64, backstop: u64) -> HoldPlanner {
    let mut planner = HoldPlanner::released(&settings(hold_secs, backstop));
    planner.observe(
        &bindings(&["bond0"]),
        &core_up(true, &["10.0.0.2"]),
        Instant::now(),
    );
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));
    planner
}

#[tokio::test(start_paused = true)]
async fn boot_hold_holds_every_binding_until_sync_settles() {
    let b = bindings(&["bond0", "bond1"]);
    let mut planner = HoldPlanner::startup(&settings(10, 180), Instant::now());
    planner.expire(&b, Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Hold("startup_hold")
    );
    assert_eq!(
        planner.decision("bond1"),
        HoldDecision::Hold("startup_hold")
    );

    // Sessions come up but have not sent End-of-RIB: still held.
    tokio::time::advance(Duration::from_secs(20)).await;
    planner.observe(&b, &core_up(false, &[]), Instant::now());
    assert!(hold(&planner));
    // Synced: the settle hold starts, and the link stays down for it.
    planner.observe(&b, &core_up(true, &[]), Instant::now());
    tokio::time::advance(Duration::from_secs(9)).await;
    planner.observe(&b, &core_up(true, &[]), Instant::now());
    assert!(hold(&planner), "released before the settle hold elapsed");
    tokio::time::advance(Duration::from_secs(1)).await;
    let events = planner.observe(&b, &core_up(true, &[]), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));
    assert_eq!(events[0].0, "released");
}

/// Before the first EVPN sync no peer can be latched, so a core lost then
/// stays under the startup hold instead of becoming a peerless (and so
/// released) isolation. After a sync it becomes an isolation hold.
#[tokio::test(start_paused = true)]
async fn core_lost_before_first_sync_keeps_the_startup_hold() {
    let b = bindings(&["bond0"]);
    let mut planner = HoldPlanner::startup(&settings(10, 180), Instant::now());
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Hold("startup_hold")
    );

    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
}

#[tokio::test(start_paused = true)]
async fn isolation_holds_a_segment_whose_peer_was_seen_while_the_core_was_up() {
    let b = bindings(&["bond0"]);
    let mut planner = steady(10, 180);
    let events = planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
    assert_eq!(events[0].0, "isolated");
}

#[tokio::test(start_paused = true)]
async fn recovery_waits_for_sync_and_the_settle_hold_before_release() {
    let b = bindings(&["bond0"]);
    let mut planner = steady(10, 180);
    planner.observe(&b, &core_lost(), Instant::now());

    // Core back but not synced: recovering, held.
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("recovering"));
    tokio::time::advance(Duration::from_secs(60)).await;
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    assert!(hold(&planner));
    // Synced: held for exactly the settle time.
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    tokio::time::advance(Duration::from_secs(5)).await;
    // A sync blip restarts the settle hold.
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    tokio::time::advance(Duration::from_secs(9)).await;
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    assert!(hold(&planner));
    tokio::time::advance(Duration::from_secs(1)).await;
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));
}

#[tokio::test(start_paused = true)]
async fn backstop_releases_before_sync_with_a_warning_state() {
    let b = bindings(&["bond0"]);
    let mut planner = steady(10, 180);
    planner.observe(&b, &core_lost(), Instant::now());
    tokio::time::advance(Duration::from_secs(600)).await;
    // The backstop clock starts at the core-up edge, not at isolation.
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    tokio::time::advance(Duration::from_secs(179)).await;
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    assert!(hold(&planner));
    tokio::time::advance(Duration::from_secs(1)).await;
    let events = planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    assert_eq!(events[0].0, "backstop_unsynced");
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("backstop_released")
    );
    // The warning state holds until a sync is observed.
    planner.observe(&b, &core_up(false, &["10.0.0.2"]), Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("backstop_released")
    );
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));

    // The startup backstop runs from daemon start, also with a RIB that
    // never answers.
    let start = Instant::now();
    let mut boot = HoldPlanner::startup(&settings(10, 180), start);
    tokio::time::advance(Duration::from_secs(180)).await;
    assert_eq!(boot.expire(&b, Instant::now())[0].0, "backstop_unsynced");
    assert_eq!(
        boot.decision("bond0"),
        HoldDecision::Release("backstop_released")
    );
}

#[tokio::test(start_paused = true)]
async fn gr_stale_retention_is_not_isolation() {
    let b = bindings(&["bond0"]);
    let mut planner = steady(10, 180);
    let stale = Observation {
        sessions: EvpnSessionsSync {
            established: 0,
            stale: 1,
            synced: false,
        },
        ..Observation::default()
    };
    planner.observe(&b, &stale, Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));
    // Once retention ends with no session back, the PE is isolated.
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
}

#[tokio::test(start_paused = true)]
async fn peer_latch_survives_the_last_session_down_flush_but_not_a_withdrawal() {
    let b = bindings(&["bond0"]);
    // The flush empties the Type 4 set in the same read that shows no
    // session: that read must not clear the latch.
    let mut planner = steady(10, 180);
    let flushed = Observation {
        peers: Some(BTreeMap::from([("bond0".to_string(), BTreeSet::new())])),
        ..core_lost()
    };
    planner.observe(&b, &flushed, Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));

    // A peer that withdrew while the core was up leaves no other member:
    // isolation is suppressed and the CE keeps this PE.
    let mut planner = steady(10, 180);
    planner.observe(&b, &core_up(true, &[]), Instant::now());
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("suppressed_no_peer")
    );
}

/// The controller reads sessions and Type 4 rows in one RIB turn through
/// the O(Type 4) snapshot, never a filtered walk of the EVPN Loc-RIB, and
/// latches peers only while EVPN is synced.
#[tokio::test]
async fn rib_poll_uses_one_indexed_snapshot_and_latches_only_when_synced() {
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: BgpMetrics::new(),
        directory: None,
        start: Instant::now(),
    });
    controller.snapshot = Arc::new(snapshot("bond0", Some(esi(1))));
    let rib = tokio::spawn(async move {
        let mut synced = true;
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::QueryEvpnEsSnapshot { reply } => {
                    let _ = reply.send(rustbgpd_rib::EvpnEsSnapshot {
                        sessions: EvpnSessionsSync {
                            established: 1,
                            stale: 0,
                            synced,
                        },
                        es_routes: vec![remote_type4(esi(1), "10.0.0.2")],
                    });
                    synced = false;
                }
                RibUpdate::QueryEvpnRoutes { .. } => {
                    panic!("the poll must not walk the EVPN Loc-RIB")
                }
                _ => panic!("unexpected RIB query"),
            }
        }
    });
    let peers = controller
        .poll_rib()
        .await
        .expect("synced snapshot latches");
    assert_eq!(peers["bond0"], BTreeSet::from([ip("10.0.0.2")]));
    assert!(
        controller.poll_rib().await.is_none(),
        "an unsynced session cannot present its partial Type 4 set"
    );
    assert_eq!(controller.last_sessions.map(|s| s.established), Some(1));
    drop(controller);
    rib.await.unwrap();
}

fn snapshot_with(
    esi_text: &str,
    id: Option<rustbgpd_wire::EthernetSegmentIdentifier>,
    originator: &str,
) -> Arc<CoreIsolationSnapshot> {
    let mut snap = snapshot("bond0", id);
    let binding = snap.bindings.get_mut("bond0").unwrap();
    binding.esi_text = esi_text.to_string();
    binding.originator_ip = Some(ip(originator));
    Arc::new(snap)
}

/// An isolated binding whose segment identity changes on a live reload
/// loses its latch and its hold: its members go back up through the
/// guarded release, and it is not held again until a Type 4 is seen for
/// the new identity. An `auto-lacp` ESI that only goes unresolved (its
/// own members are held down) keeps the hold.
#[tokio::test(start_paused = true)]
async fn identity_change_drops_the_peer_latch_and_the_hold() {
    let isolated = |steps: Vec<Arc<CoreIsolationSnapshot>>| {
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mut controller = Controller::new(CoreIsolationDeps {
            rib_tx,
            metrics: BgpMetrics::new(),
            directory: None,
            start: Instant::now(),
        });
        controller.startup = false;
        controller.apply_config(snapshot_with("auto-lacp", Some(esi(1)), "10.0.0.1"));
        let b = bindings(&["bond0"]);
        let planner = controller.planner.as_mut().unwrap();
        planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
        planner.observe(&b, &core_lost(), Instant::now());
        assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
        for next in steps {
            controller.apply_config(next);
        }
        let planner = controller.planner.as_mut().unwrap();
        let decision = planner.decision("bond0");
        // Still isolated: without a fresh Type 4 it is never re-held.
        planner.observe(&b, &core_lost(), Instant::now());
        assert_eq!(planner.decision("bond0"), decision);
        decision
    };
    let unresolved = || snapshot_with("auto-lacp", None, "10.0.0.1");
    for steps in [
        vec![snapshot_with(
            "00:00:00:00:00:00:00:00:00:07",
            Some(esi(7)),
            "10.0.0.1",
        )],
        vec![snapshot_with("auto-lacp", Some(esi(9)), "10.0.0.1")],
        vec![snapshot_with("auto-lacp", Some(esi(1)), "10.0.0.5")],
        // A CE replaced behind the bond: unresolved, then a different ESI.
        vec![
            unresolved(),
            snapshot_with("auto-lacp", Some(esi(9)), "10.0.0.1"),
        ],
    ] {
        assert_eq!(
            isolated(steps),
            HoldDecision::Release("suppressed_no_peer"),
            "a new segment identity must not inherit the old peer latch"
        );
    }
    for steps in [
        vec![unresolved()],
        vec![
            unresolved(),
            snapshot_with("auto-lacp", Some(esi(1)), "10.0.0.1"),
        ],
    ] {
        assert_eq!(
            isolated(steps),
            HoldDecision::Hold("isolated"),
            "an auto-lacp ESI lost to our own hold, or regained unchanged, is the same segment"
        );
    }
}

/// A peer counts only if seen while the core was up by both signals.
/// Synced sessions behind dead uplinks latch nothing, so after the startup
/// backstop the next isolation does not take the links down again. A later
/// legitimate hold is not suppressed by the backstop.
#[tokio::test(start_paused = true)]
async fn uplink_isolation_latches_no_peer_across_the_startup_backstop() {
    let b = bindings(&["bond0"]);
    let uplinks_dead = Observation {
        uplinks_down: true,
        ..core_up(true, &["10.0.0.2"])
    };
    let mut planner = HoldPlanner::startup(&settings(10, 180), Instant::now());
    planner.observe(&b, &uplinks_dead, Instant::now());
    tokio::time::advance(Duration::from_secs(180)).await;
    planner.observe(&b, &uplinks_dead, Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("backstop_released")
    );
    planner.observe(&b, &uplinks_dead, Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("suppressed_no_peer"),
        "a peer seen behind dead uplinks must not re-hold the links after the backstop"
    );

    // Uplinks back and synced: the peer latches; losing the uplinks again
    // is a real isolation and holds.
    planner.observe(&b, &core_up(true, &["10.0.0.2"]), Instant::now());
    planner.observe(&b, &uplinks_dead, Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
}

/// Failures outrank `disabled`: a release that fails after the table is
/// disabled, or after the binding is removed, stays visible.
#[test]
fn release_failure_after_disable_is_reported_not_disabled() {
    let metrics = BgpMetrics::with_registry(prometheus::Registry::new());
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: metrics.clone(),
        directory: None,
        start: Instant::now(),
    });
    let active = |interface: &str| -> Vec<String> {
        metrics
            .registry()
            .gather()
            .iter()
            .filter(|f| f.name() == "evpn_es_core_isolation_state")
            .flat_map(|f| f.get_metric().to_vec())
            .filter(|m| {
                (m.get_gauge().get_value() - 1.0).abs() < f64::EPSILON
                    && m.get_label()
                        .iter()
                        .any(|l| l.name() == "interface" && l.value() == interface)
            })
            .flat_map(|m| {
                m.get_label()
                    .iter()
                    .filter(|l| l.name() == "state")
                    .map(|l| l.value().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut disabled = snapshot("bond0", Some(esi(1)));
    disabled.settings.as_mut().unwrap().enabled = false;
    controller.apply_config(Arc::new(disabled.clone()));
    controller.publish_states();
    assert_eq!(active("bond0"), ["disabled"]);

    controller.runtime.get_mut("bond0").unwrap().action_failed = true;
    controller.publish_states();
    assert_eq!(active("bond0"), ["action_failed"]);

    // The binding leaves the config while one of its releases fails.
    let mut unbound = disabled;
    unbound.bindings.clear();
    controller.apply_config(Arc::new(unbound));
    controller
        .runtime
        .entry("bond0".to_string())
        .or_default()
        .action_failed = true;
    controller.publish_states();
    assert_eq!(active("bond0"), ["action_failed"]);
    controller.runtime.get_mut("bond0").unwrap().action_failed = false;
    controller.publish_states();
    assert!(active("bond0").is_empty(), "series go once nothing fails");
}

/// Disabling or removing the table clears the signal gauge, and an
/// unbound interface loses its state series.
#[test]
fn disable_and_unbind_leave_no_stale_series() {
    let metrics = BgpMetrics::with_registry(prometheus::Registry::new());
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: metrics.clone(),
        directory: None,
        start: Instant::now(),
    });
    let series = |family: &str| -> usize {
        metrics
            .registry()
            .gather()
            .iter()
            .filter(|f| f.name() == family)
            .map(|f| f.get_metric().len())
            .sum()
    };
    controller.apply_config(Arc::new(snapshot("bond0", Some(esi(1)))));
    controller.publish_states();
    metrics.set_evpn_core_isolated(true, false);
    assert!(series("evpn_es_core_isolation_state") > 0);
    assert_eq!(series("evpn_core_isolated"), 2);

    // Disabled in place: the binding reports `disabled`, the signals go.
    let mut disabled = snapshot("bond0", Some(esi(1)));
    disabled.settings.as_mut().unwrap().enabled = false;
    controller.apply_config(Arc::new(disabled));
    controller.publish_states();
    assert_eq!(series("evpn_core_isolated"), 0);

    // Unbound: the interface's state series are removed.
    let mut unbound = snapshot("bond0", Some(esi(1)));
    unbound.bindings.clear();
    controller.apply_config(Arc::new(unbound));
    controller.publish_states();
    assert_eq!(series("evpn_es_core_isolation_state"), 0);

    // Removed table with a binding left: no series either.
    metrics.set_evpn_core_isolated(true, true);
    let mut removed = snapshot("bond0", Some(esi(1)));
    removed.settings = None;
    controller.apply_config(Arc::new(removed));
    controller.publish_states();
    assert_eq!(series("evpn_es_core_isolation_state"), 0);
    assert_eq!(series("evpn_core_isolated"), 0);
}

fn esi(seed: u8) -> rustbgpd_wire::EthernetSegmentIdentifier {
    rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, seed])
}

fn remote_type4(
    id: rustbgpd_wire::EthernetSegmentIdentifier,
    originator: &str,
) -> rustbgpd_rib::route::EvpnRibRoute {
    use rustbgpd_wire::{EvpnEs, ExtendedCommunity, PathAttribute};
    rustbgpd_rib::route::EvpnRibRoute {
        route: EvpnRoute::Es(EvpnEs {
            rd: crate::test_support::rd(65000, 100),
            esi: id,
            originator_ip: ip(originator),
        }),
        next_hop: ip(originator),
        link_local_next_hop: None,
        peer: ip(originator),
        attributes: rustbgpd_rib::AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::es_import_rt(crate::evpn_segment::es_import_rt_from_esi(id)),
        ])]),
        received_at: std::time::Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Ibgp,
        peer_router_id: "192.0.2.1".parse().unwrap(),
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn snapshot(
    interface: &str,
    id: Option<rustbgpd_wire::EthernetSegmentIdentifier>,
) -> CoreIsolationSnapshot {
    CoreIsolationSnapshot {
        settings: Some(settings(10, 180)),
        bindings: BTreeMap::from([(
            interface.to_string(),
            CoreIsolationBinding {
                esi_text: "00:00:00:00:00:00:00:00:00:01".to_string(),
                esi: id,
                originator_ip: Some(ip("10.0.0.1")),
            },
        )]),
    }
}

#[test]
fn peers_count_only_other_originators_with_the_es_import_rt() {
    let bindings = snapshot("bond0", Some(esi(1))).bindings;
    let mut no_rt = remote_type4(esi(1), "10.0.0.3");
    no_rt.attributes = rustbgpd_rib::AttrSet::new(Vec::new());
    let routes = vec![
        remote_type4(esi(1), "10.0.0.2"),
        remote_type4(esi(1), "10.0.0.1"),
        remote_type4(esi(2), "10.0.0.4"),
        no_rt,
    ];
    assert_eq!(
        peers_by_binding(&bindings, &routes)["bond0"],
        BTreeSet::from([ip("10.0.0.2")])
    );
    // An `auto-lacp` binding with no ready ESI keeps its latch.
    assert!(peers_by_binding(&snapshot("bond0", None).bindings, &routes).is_empty());
}

fn link(ifindex: u32, name: &str, master: Option<u32>, admin_up: bool) -> AdminLinkState {
    AdminLinkState {
        ifindex,
        name: name.into(),
        admin_up,
        carrier: admin_up,
        is_bond: name.starts_with("bond"),
        master,
        lower: None,
        address: Some(vec![2, 0, 0, 0, 0, 1]),
        perm_address: None,
        bond_perm_hwaddr: master.map(|_| vec![2, 0, 0, 0, 1, u8::try_from(ifindex).unwrap()]),
    }
}

fn host() -> HostIdentity {
    HostIdentity {
        boot_id: "boot".into(),
        netns: NetnsId { dev: 1, ino: 2 },
    }
}

#[test]
fn uplink_under_a_bound_bond_is_excluded_so_isolation_can_release() {
    let snap = snapshot("bond0", Some(esi(1)));
    // eth1 was enslaved under the bound bond at runtime; the hold took it
    // down, so it has no carrier.
    let links = vec![
        link(3, "bond0", None, true),
        link(4, "eth1", Some(3), false),
        link(5, "eth2", None, false),
    ];
    let (down, overlaps) = uplink_signal(&["eth1".to_string()], &snap, &links, &[]);
    assert!(!down, "an excluded uplink cannot hold the PE isolated");
    assert_eq!(overlaps, vec![("eth1".to_string(), "bond0".to_string())]);

    // With it excluded, recovery releases the hold.
    let b = bindings(&["bond0"]);
    let mut planner = steady(0, 180);
    planner.observe(
        &b,
        &Observation {
            uplinks_down: true,
            ..core_up(true, &["10.0.0.2"])
        },
        Instant::now(),
    );
    assert!(hold(&planner));
    planner.observe(
        &b,
        &Observation {
            uplinks_down: down,
            ..core_up(true, &["10.0.0.2"])
        },
        Instant::now(),
    );
    planner.observe(
        &b,
        &Observation {
            uplinks_down: down,
            ..core_up(true, &["10.0.0.2"])
        },
        Instant::now(),
    );
    assert_eq!(planner.decision("bond0"), HoldDecision::Release("released"));

    // One redundant uplink with carrier keeps the PE connected; all
    // down isolates; a missing uplink counts as down.
    let uplinks = ["eth2".to_string(), "eth9".to_string()];
    assert!(uplink_signal(&uplinks, &snap, &links, &[]).0);
    let mut up = links.clone();
    up[2].carrier = true;
    assert!(!uplink_signal(&uplinks, &snap, &up, &[]).0);
}

/// `link` stacked on `lower` (`IFLA_LINK`), such as a VLAN.
fn stacked(ifindex: u32, name: &str, lower: u32) -> AdminLinkState {
    AdminLinkState {
        lower: Some(lower),
        ..link(ifindex, name, None, false)
    }
}

#[test]
fn uplink_stacked_on_a_bound_bond_is_excluded_so_isolation_can_release() {
    let snap = snapshot("bond0", Some(esi(1)));
    // The hold took bond0's members down, so bond0 and every VLAN on it
    // lost carrier.
    let mut links = vec![
        link(3, "bond0", None, false),
        link(7, "m0", Some(3), false),
        stacked(20, "bond0.100", 3),
        // QinQ: two hops down to the bound bond.
        stacked(21, "bond0.100.5", 20),
        // On a member of the bound bond: excluded through its master.
        stacked(22, "m0.200", 7),
        // A lower device that is gone, and a veth pair's IFLA_LINK cycle.
        stacked(23, "gone.300", 99),
        stacked(30, "v0", 31),
        stacked(31, "v1", 30),
    ];
    let (down, overlaps) = uplink_signal(&["bond0.100".to_string()], &snap, &links, &[]);
    assert!(!down, "our own hold must not keep the PE isolated");
    assert_eq!(
        overlaps,
        vec![("bond0.100".to_string(), "bond0".to_string())]
    );
    for uplink in ["bond0.100.5", "m0.200"] {
        let (_, overlaps) = uplink_signal(&[uplink.to_string()], &snap, &links, &[]);
        assert_eq!(overlaps, vec![(uplink.to_string(), "bond0".to_string())]);
    }

    // A broken or cyclic chain is not an overlap: the uplink stays in the
    // signal with its own carrier.
    let uplinks = ["gone.300".to_string(), "v0".to_string()];
    let (down, overlaps) = uplink_signal(&uplinks, &snap, &links, &[]);
    assert!(down && overlaps.is_empty());
    links[6].carrier = true;
    assert!(!uplink_signal(&uplinks, &snap, &links, &[]).0);
}

#[test]
fn discovery_downs_new_members_and_never_re_downs_an_override() {
    let binding = snapshot("bond0", Some(esi(1))).bindings["bond0"].clone();
    let links = vec![
        link(3, "bond0", None, true),
        link(7, "m0", Some(3), true),
        link(8, "m1", Some(3), true),
        link(9, "m2", Some(3), false),
        link(10, "other", None, true),
    ];
    let owned_m0 = OwnedLink {
        boot_id: host().boot_id,
        netns: host().netns,
        esi: binding.esi_text.clone(),
        binding: "bond0".into(),
        link: LinkIdentity::in_dump(&links[1], &links),
    };
    let actions = discover(
        "bond0",
        &binding,
        &links,
        std::slice::from_ref(&owned_m0),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &host(),
    );
    assert_eq!(actions.len(), 2, "{actions:?}");
    assert!(matches!(&actions[0], MemberAction::Overridden { entry, .. } if *entry == owned_m0));
    assert!(matches!(&actions[1], MemberAction::TakeDown(e) if e.link.name == "m1"));

    // After the override is recorded, discovery does not treat m0 as new.
    let overridden = BTreeSet::from([(7, "m0".to_string())]);
    let actions = discover(
        "bond0",
        &binding,
        &links,
        &[],
        &overridden,
        &BTreeSet::new(),
        &host(),
    );
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert!(matches!(&actions[0], MemberAction::TakeDown(e) if e.link.name == "m1"));

    // A link bound directly (not a bond) is its own member.
    let actions = discover(
        "other",
        &binding,
        &links,
        &[],
        &BTreeSet::new(),
        &BTreeSet::new(),
        &host(),
    );
    assert!(matches!(&actions[..], [MemberAction::TakeDown(e)] if e.link.name == "other"));

    // An owned member seen outside the bond during this hold and enslaved
    // again comes back admin-up: it is taken down again, not overridden.
    let left_bond = BTreeSet::from([(7, "m0".to_string())]);
    let actions = discover(
        "bond0",
        &binding,
        &links,
        std::slice::from_ref(&owned_m0),
        &BTreeSet::new(),
        &left_bond,
        &host(),
    );
    assert!(matches!(&actions[0], MemberAction::Redown { entry, .. } if *entry == owned_m0));
}

/// An `auto-lacp` binding the startup hold left unresolved cannot latch a
/// peer. A core lost after the first sync must keep the startup hold for
/// it, not suppress it as peerless and raise its members while isolated.
#[tokio::test(start_paused = true)]
async fn unlatched_binding_keeps_the_startup_hold_when_the_core_is_lost() {
    let b = bindings(&["bond0"]);
    let mut planner = HoldPlanner::startup(&settings(10, 180), Instant::now());
    tokio::time::advance(Duration::from_secs(20)).await;
    let unresolved = Observation {
        sessions: EvpnSessionsSync {
            established: 1,
            stale: 0,
            synced: true,
        },
        uplinks_down: false,
        // `peers_by_binding` omits a binding with no resolved ESI.
        peers: Some(BTreeMap::new()),
    };
    planner.observe(&b, &unresolved, Instant::now());
    tokio::time::advance(Duration::from_secs(5)).await;
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Hold("startup_hold")
    );

    // An explicit binding that latched, even empty, is a peer record: the
    // startup hold becomes an isolation hold for it.
    let mut planner = HoldPlanner::startup(&settings(10, 180), Instant::now());
    planner.observe(&b, &core_up(true, &[]), Instant::now());
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("suppressed_no_peer")
    );
}

/// A RIB that stops answering is no reading: nothing is decided on the
/// last one, and an isolation hold is released after `backstop_seconds`
/// without an answer, so a stall never pins links down.
#[tokio::test(start_paused = true)]
async fn stalled_rib_is_no_reading_and_cannot_pin_an_isolation_hold() {
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: BgpMetrics::new(),
        directory: None,
        start: Instant::now(),
    });
    controller.snapshot = Arc::new(snapshot("bond0", Some(esi(1))));
    controller.last_sessions = Some(EvpnSessionsSync::default());
    // Hold every query unanswered.
    let rib = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            held.push(update);
        }
    });
    let started = Instant::now();
    assert!(controller.poll_rib().await.is_none());
    assert!(
        started.elapsed() < POLL_INTERVAL,
        "a stalled poll must not block the loop for a whole poll interval"
    );
    assert_eq!(
        controller.last_sessions, None,
        "a timed-out poll must not replay the last reading"
    );
    drop(controller);
    rib.await.unwrap();

    let b = bindings(&["bond0"]);
    let mut planner = steady(10, 180);
    planner.observe(&b, &core_lost(), Instant::now());
    assert_eq!(planner.decision("bond0"), HoldDecision::Hold("isolated"));
    planner.expire(&b, Instant::now());
    tokio::time::advance(Duration::from_secs(179)).await;
    planner.expire(&b, Instant::now());
    assert!(hold(&planner));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(planner.expire(&b, Instant::now())[0].0, "backstop_unsynced");
    assert_eq!(
        planner.decision("bond0"),
        HoldDecision::Release("backstop_released")
    );
}

/// Startup reconcile drops an ambiguous entry once nothing is left to
/// own (its link is gone, or the operator raised it) and keeps one whose
/// link is still down. Dropping never raises a link.
#[test]
fn startup_reconcile_drops_ambiguous_entries_with_nothing_left_down() {
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: BgpMetrics::new(),
        directory: None,
        start: Instant::now(),
    });
    controller.host = Some(host());
    let recorded = vec![
        link(3, "bond0", None, true),
        link(7, "m0", Some(3), false),
        link(8, "m1", Some(3), false),
        link(9, "m2", Some(3), false),
    ];
    let entry = |i: usize| OwnedLink {
        boot_id: host().boot_id,
        netns: host().netns,
        esi: "auto-lacp".into(),
        binding: "bond0".into(),
        link: LinkIdentity::in_dump(&recorded[i], &recorded),
    };
    controller.receipt = vec![entry(1), entry(2), entry(3)];
    // m0 renamed and still down; m1 renamed and raised by the operator;
    // m2 deleted.
    let now = vec![
        link(3, "bond0", None, true),
        link(7, "m0x", Some(3), false),
        link(8, "m1x", Some(3), true),
    ];
    controller.reconcile_at_start(&now);
    let names: Vec<&str> = controller
        .receipt
        .iter()
        .map(|e| e.link.name.as_str())
        .collect();
    assert_eq!(names, ["m0"]);
}

#[test]
fn ambiguous_entry_is_stale_only_with_nothing_left_down() {
    use super::receipt::ambiguous_entry_is_stale as stale;
    let recorded = vec![link(3, "bond0", None, true), link(7, "m0", Some(3), false)];
    let entry = OwnedLink {
        boot_id: host().boot_id,
        netns: host().netns,
        esi: "auto-lacp".into(),
        binding: "bond0".into(),
        link: LinkIdentity::in_dump(&recorded[1], &recorded),
    };
    assert!(stale(&entry, &recorded[..1]), "link gone");
    assert!(stale(&entry, &[link(7, "m0x", None, true)]), "raised");
    assert!(!stale(&entry, &[link(7, "m0x", None, false)]), "still down");
    assert!(
        !stale(
            &entry,
            &[link(7, "m0x", None, true), link(9, "m0", None, false)]
        ),
        "a down candidate by name keeps it"
    );
}

/// A receipt that is unreadable on one pass and repaired before the next
/// clears the read error: bindings do not stay at `action_failed`.
#[test]
fn repaired_receipt_clears_the_read_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let receipt_path = dir.path().join(receipt::RECEIPT_FILE);
    std::fs::write(&receipt_path, b"not json").unwrap();
    std::fs::set_permissions(
        &receipt_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();

    let metrics = BgpMetrics::with_registry(prometheus::Registry::new());
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mut controller = Controller::new(CoreIsolationDeps {
        rib_tx,
        metrics: metrics.clone(),
        directory: None,
        start: Instant::now(),
    });
    controller.store =
        Some(receipt::ReceiptStore::lock(std::fs::File::open(dir.path()).unwrap()).unwrap());
    controller.apply_config(Arc::new(snapshot("bond0", Some(esi(1)))));
    let state = || -> Vec<String> {
        metrics
            .registry()
            .gather()
            .iter()
            .filter(|f| f.name() == "evpn_es_core_isolation_state")
            .flat_map(|f| f.get_metric().to_vec())
            .filter(|m| (m.get_gauge().get_value() - 1.0).abs() < f64::EPSILON)
            .flat_map(|m| {
                m.get_label()
                    .iter()
                    .filter(|l| l.name() == "state")
                    .map(|l| l.value().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    assert!(!controller.load_receipt());
    controller.publish_states();
    assert_eq!(state(), ["action_failed"]);

    std::fs::remove_file(&receipt_path).unwrap();
    assert!(controller.load_receipt());
    controller.publish_states();
    assert_eq!(
        state(),
        ["startup_hold"],
        "a repaired receipt must not leave the binding at action_failed"
    );
}

#[cfg(target_os = "linux")]
mod netns;
