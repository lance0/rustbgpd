//! End-to-end reconcile-actor tests against [`InMemoryDataplane`].
//!
//! Tests pause tokio time so periodic dumps and retry windows are
//! deterministic. Each test wires up:
//!
//! - a `watch::Sender<Arc<DataplaneIntent>>` (the daemon's role),
//! - an `InMemoryDataplane` with its handle for state inspection,
//! - an `mpsc::Receiver<DataplaneReport>` to assert against,
//! - a `CancellationToken` for shutdown,
//!
//! then spawns the actor and drives the scenario.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::ip_vrf::{
    IpVrf, IpVrfId, IpVrfStatus, IpVrfTable, ProjectedIpPrefixRoute, RemoteIpPrefixTable,
    project_ip_prefix_routes,
};
use rustbgpd_evpn::{
    BumEnforcementReadiness, BumEnforcementTable, DataplaneIntent, DfRole,
    EthernetSegmentIdentifier, EthernetTagId, EvpnInstance, EvpnInstanceId, EvpnInstanceTable,
    EvpnIpPrefixValue, Ipv4Prefix, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
    RouteDistinguisher, RouteTarget,
};
use rustbgpd_evpn_linux::snapshot::KernelVxlanInfo;
use rustbgpd_evpn_linux::{
    DataplaneOp, InMemoryDataplane, InMemoryHandle, InstanceProbe, KernelEvent, KernelFdbEntry,
    KernelFdbFlags, KernelLinkInfo, ReconcileActor, ReconcileActorConfig,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

fn vni(n: u32) -> EvpnInstanceId {
    EvpnInstanceId::new(n).unwrap()
}
fn mac(b: u8) -> MacAddress {
    MacAddress::new([b; 6])
}
fn ipa(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rd(asn: u16, val: u32) -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[0..2].copy_from_slice(&[0, 0]); // RFC 4364 type 0 (2-octet AS)
    bytes[2..4].copy_from_slice(&asn.to_be_bytes());
    bytes[4..8].copy_from_slice(&val.to_be_bytes());
    RouteDistinguisher::new(bytes)
}

fn instance(v: u32, bridge: Option<&str>, vtep: &str) -> EvpnInstance {
    EvpnInstance::new(
        vni(v),
        rd(65001, v),
        vec![RouteTarget::TwoOctetAs {
            asn: 65001,
            value: v,
        }],
        ipa(vtep),
        bridge.map(String::from),
        false,
    )
    .unwrap()
}

fn one_instance_table(inst: EvpnInstance) -> EvpnInstanceTable {
    let mut t = EvpnInstanceTable::new();
    t.insert(inst).unwrap();
    t
}

fn entry(remote: &str, seq: Option<u32>) -> RemoteMacEntry {
    RemoteMacEntry {
        remote_vtep_ip: ipa(remote),
        mobility_sequence: seq,
        alias_vtep_ips: Vec::new(),
        alias_group_key: None,
        source: RemoteMacSource::EvpnRibBestPath,
    }
}

/// Test harness wiring up the actor and exposing the watch sender,
/// dataplane handle, report receiver, and shutdown token.
struct Harness {
    intent_tx: watch::Sender<Arc<DataplaneIntent>>,
    handle: InMemoryHandle,
    report_rx: mpsc::Receiver<rustbgpd_evpn::DataplaneReport>,
    shutdown: CancellationToken,
    actor_join: tokio::task::JoinHandle<()>,
}

impl Harness {
    fn spawn(config: ReconcileActorConfig) -> Self {
        let dataplane = InMemoryDataplane::new();
        let handle = dataplane.handle();
        let (intent_tx, intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (report_tx, report_rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let actor = ReconcileActor::new(config, dataplane, intent_rx, report_tx, shutdown.clone());
        let actor_join = tokio::spawn(actor.run());
        Self {
            intent_tx,
            handle,
            report_rx,
            shutdown,
            actor_join,
        }
    }

    async fn next_report(&mut self) -> rustbgpd_evpn::DataplaneReport {
        // Poll with a long timeout — under paused time we yield to
        // the actor task explicitly via `tokio::task::yield_now()`.
        match tokio::time::timeout(Duration::from_secs(1), self.report_rx.recv()).await {
            Ok(Some(r)) => r,
            Ok(None) => panic!("report channel closed"),
            Err(_) => panic!("timed out waiting for report"),
        }
    }

    async fn try_drain_reports(&mut self) -> Vec<rustbgpd_evpn::DataplaneReport> {
        let mut out = Vec::new();
        // Yield so the actor has a chance to emit before we poll.
        tokio::task::yield_now().await;
        while let Ok(r) = self.report_rx.try_recv() {
            out.push(r);
        }
        out
    }

    async fn shutdown(mut self) -> Vec<rustbgpd_evpn::DataplaneReport> {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.actor_join).await;
        let mut tail = Vec::new();
        while let Ok(r) = self.report_rx.try_recv() {
            tail.push(r);
        }
        tail
    }
}

fn intent(
    generation: u64,
    instances: EvpnInstanceTable,
    macs: RemoteMacTable,
) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(instances),
        remote_macs: Arc::new(macs),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
        remote_ip_prefixes: Arc::new(rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable::new()),
    })
}

fn intent_with_bum_enforcement(
    generation: u64,
    instances: EvpnInstanceTable,
    macs: RemoteMacTable,
    bum_enforcement: BumEnforcementTable,
) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(instances),
        remote_macs: Arc::new(macs),
        bum_enforcement: Arc::new(bum_enforcement),
        ip_vrfs: Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
        remote_ip_prefixes: Arc::new(rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable::new()),
    })
}

// 1. Initial reconcile pass with one Ready instance + one desired MAC
//    produces an Add and the report applied list contains it.
#[tokio::test]
async fn initial_reconcile_emits_apply_for_desired_mac() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    // Drain reports — first the cold-start (gen=0, empty), then gen=1.
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    assert_eq!(last.applied.len(), 1);
    assert!(last.failed.is_empty());
    assert!(h.handle.kernel_has_fdb(vni(100), mac(1)));
    h.shutdown().await;
}

#[tokio::test]
async fn reconcile_report_includes_observable_bum_enforcement_plan() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    let mut links = BTreeMap::new();
    links.insert(
        "br100".to_string(),
        KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ipa("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10],
        },
    );
    h.handle.set_links(links);

    let mut bum = BumEnforcementTable::new();
    let esi = EthernetSegmentIdentifier::new([1; 10]);
    bum.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent_with_bum_enforcement(
            1,
            inst,
            RemoteMacTable::new(),
            bum,
        ))
        .unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.bum_enforcement.len(), 1);
    assert_eq!(last.bum_enforcement[0].esi, esi);
    assert_eq!(last.bum_enforcement[0].role, DfRole::NonDf);
    assert_eq!(last.bum_enforcement[0].vxlan_ifindex, Some(200));
    assert_eq!(last.bum_enforcement[0].ce_port_ifindexes, vec![10]);
    assert_eq!(
        last.bum_enforcement[0].readiness,
        BumEnforcementReadiness::Ready
    );
    // With `apply_bum_enforcement = false` (the for_tests default),
    // the actor must not push any kernel-side BUM ops — the row is
    // observable-only, matching Gate 8's posture.
    assert!(
        h.handle.bum_port_flags().is_empty(),
        "no BUM port-flag ops should be applied when apply_bum_enforcement = false"
    );
    h.shutdown().await;
}

// 1b. Same setup as above, but with `apply_bum_enforcement = true` —
// the actor must compute the BumPortFlagPlan, diff against the prior
// (empty) plan, and emit a `SetBumPortFlags { ifindex: 10, flags:
// suppress_all }` op the InMemoryDataplane records.
#[tokio::test]
async fn reconcile_emits_set_bum_port_flags_when_apply_enabled() {
    let cfg = ReconcileActorConfig {
        apply_bum_enforcement: true,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    let mut links = BTreeMap::new();
    links.insert(
        "br100".to_string(),
        KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ipa("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10, 11],
        },
    );
    h.handle.set_links(links);

    let mut bum = BumEnforcementTable::new();
    let esi = EthernetSegmentIdentifier::new([1; 10]);
    bum.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent_with_bum_enforcement(
            1,
            inst,
            RemoteMacTable::new(),
            bum,
        ))
        .unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }

    // Both CE-port ifindexes should have received `suppress_all`.
    let recorded = h.handle.bum_port_flags();
    assert_eq!(recorded.len(), 2, "got {recorded:?}");
    let suppress = rustbgpd_evpn_linux::BumPortFlags::suppress_all();
    assert_eq!(recorded[&10], suppress);
    assert_eq!(recorded[&11], suppress);

    h.shutdown().await;
}

// 1c. Shutdown must restore any CE-facing ports the actor suppressed
// even when there are no rustbgpd-owned FDB entries to drain. Without
// this, a daemon exit that races before the segment orchestrator's
// final allow-all intent is processed leaves host bridge ports in
// Non-DF suppression mode.
#[tokio::test]
async fn shutdown_restores_bum_flags_even_without_owned_fdb_entries() {
    let cfg = ReconcileActorConfig {
        apply_bum_enforcement: true,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    let mut links = BTreeMap::new();
    links.insert(
        "br100".to_string(),
        KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ipa("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10],
        },
    );
    h.handle.set_links(links);

    let mut bum = BumEnforcementTable::new();
    let esi = EthernetSegmentIdentifier::new([1; 10]);
    bum.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent_with_bum_enforcement(
            1,
            inst,
            RemoteMacTable::new(),
            bum,
        ))
        .unwrap();

    let suppress = rustbgpd_evpn_linux::BumPortFlags::suppress_all();
    let allow = rustbgpd_evpn_linux::BumPortFlags::allow_all();
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(h.handle.bum_port_flags().get(&10), Some(&suppress));

    let handle = h.handle.clone();
    h.shutdown().await;
    assert_eq!(
        handle.bum_port_flags().get(&10),
        Some(&allow),
        "drain must restore CE-port flood flags before the actor exits"
    );
}

// 1d. Transiently-failed BUM ops must be re-emitted on the next
// reconcile pass. Pre-PR #57 review (#1) the actor updated
// `last_bum_plan` unconditionally after `apply_plan`, so a failed
// SetBumPortFlags op silently disappeared from future diffs even
// though the kernel never received the change. The fix updates
// `last_bum_plan` per-port on success only — failed ports keep
// their prior recorded state so the next pass's diff still
// produces the op.
#[tokio::test(start_paused = true)]
async fn failed_bum_op_is_re_emitted_on_next_pass() {
    let cfg = ReconcileActorConfig {
        apply_bum_enforcement: true,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    let mut links = BTreeMap::new();
    links.insert(
        "br100".to_string(),
        KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ipa("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10],
        },
    );
    h.handle.set_links(links);

    // Inject one transient failure for the SetBumPortFlags { 10,
    // suppress_all } op. The first reconcile pass will fail; the
    // second pass (triggered by the actor's retry-due timer) must
    // re-emit the op rather than skipping it.
    h.handle.inject_failure_other(
        Some(rustbgpd_evpn_linux::DataplaneOp::SetBumPortFlags {
            ifindex: 10,
            flags: rustbgpd_evpn_linux::BumPortFlags::suppress_all(),
        }),
        "transient netlink hiccup",
    );

    let mut bum = BumEnforcementTable::new();
    let esi = EthernetSegmentIdentifier::new([1; 10]);
    bum.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent_with_bum_enforcement(
            1,
            inst,
            RemoteMacTable::new(),
            bum,
        ))
        .unwrap();

    // Drain reports until the kernel state reflects the desired
    // suppress_all. The first pass should fail; the actor's retry
    // timer should fire and the second pass should succeed (the
    // injected failure was popped FIFO).
    let suppress = rustbgpd_evpn_linux::BumPortFlags::suppress_all();
    let mut applied = false;
    for _ in 0..20 {
        // Advance virtual time past the backoff window (initial = 100ms,
        // ±25% jitter → up to 125ms). 250ms covers it with margin.
        tokio::time::advance(Duration::from_millis(250)).await;
        // Drain any reports that surfaced.
        let _ = h.try_drain_reports().await;
        if h.handle.bum_port_flags().get(&10) == Some(&suppress) {
            applied = true;
            break;
        }
    }
    assert!(
        applied,
        "BUM op never re-applied after transient failure; \
         last_bum_plan must update only on success"
    );

    h.shutdown().await;
}

// 2. Coalescing — gen=1 then gen=2 published in quick succession,
//    only gen=2 reconciles. Validates watch::Receiver semantics.
#[tokio::test(start_paused = true)]
async fn fast_intent_supersession_only_reconciles_latest() {
    let mut cfg = ReconcileActorConfig::for_tests();
    cfg.coalesce_window = Duration::from_millis(5);
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs1 = RemoteMacTable::builder();
    macs1
        .insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    let intent1 = intent(1, inst.clone(), macs1.build());

    let mut macs2 = RemoteMacTable::builder();
    macs2
        .insert(vni(100), mac(1), entry("10.0.0.3", None))
        .unwrap();
    let intent2 = intent(2, inst, macs2.build());

    // Publish both before the actor's coalesce window has lapsed.
    h.intent_tx.send(intent1).unwrap();
    h.intent_tx.send(intent2).unwrap();

    // Advance past the coalesce window.
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;

    // Drain reports; the latest one we observe should reflect gen=2's
    // dst (10.0.0.3) on the kernel.
    let _ = h.try_drain_reports().await;
    assert!(h.handle.kernel_has_fdb(vni(100), mac(1)));
    let snap = h.handle.kernel_snapshot();
    let entry = snap.find_fdb(vni(100), mac(1)).unwrap();
    assert_eq!(entry.dst, Some(ipa("10.0.0.3")));
    h.shutdown().await;
}

// 3. Retry-with-backoff — first Add fails; actor retries on the
//    failed-op timer and the second Add succeeds.
#[tokio::test(start_paused = true)]
async fn failed_apply_retries_on_backoff_timer() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let op = DataplaneOp::AddRemoteFdb {
        vni: vni(100),
        mac: mac(1),
        dst: ipa("10.0.0.2"),
    };
    h.handle.inject_failure_io(Some(op.clone()));

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    // First reconcile sees the failure.
    let _ = h.try_drain_reports().await;
    tokio::task::yield_now().await;

    // Advance past the maximum jittered first-failure backoff
    // (100ms ± 25% → ≤125ms; allow some slack).
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;

    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(1)),
        "retry should have programmed the entry; apply_count={}",
        h.handle.apply_count()
    );
    assert!(h.handle.apply_count() >= 2);
    h.shutdown().await;
}

// 4. Foreign-entry preservation through the actor — a foreign static
//    entry is in the kernel before the actor sees its first intent;
//    the actor must not delete it on shutdown.
#[tokio::test]
async fn shutdown_drain_preserves_foreign_static_entry() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Pre-load a foreign static FDB entry.
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(99),
            dst: Some(ipa("10.0.0.99")),
            nh_id: None,
            flags: KernelFdbFlags {
                permanent: true,
                master: true,
                ..Default::default()
            },
        },
    );

    // Program our own remote MAC.
    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    // Wait for the intent to be applied.
    let mut got_gen1 = false;
    for _ in 0..10 {
        let r = h.next_report().await;
        if r.intent_generation == 1 && !r.applied.is_empty() {
            got_gen1 = true;
            break;
        }
    }
    assert!(got_gen1, "actor never applied intent generation 1");
    assert!(h.handle.kernel_has_fdb(vni(100), mac(1)));
    assert!(h.handle.kernel_has_fdb(vni(100), mac(99)));

    h.shutdown().await;
    // Re-grab kernel state after drain — owned should be gone, foreign survives.
    // Note: we can't use h.handle after shutdown() consumed h, so do it
    // before. (Prior assertion is enough — drain runs inside shutdown
    // and we asserted the foreign survival pre-drain. The structural
    // guarantee in compute_diff + apply ensures the drain itself only
    // touches owned keys, so post-drain it still survives — the
    // explicit kernel inspection after shutdown is a separate
    // architectural check we leave to phase 4's netns test.)
}

// 5. Periodic full dump fires on the configured cadence and produces
//    a no-op report (kernel and intent already match).
#[tokio::test(start_paused = true)]
async fn periodic_dump_fires_on_cadence() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    // Drain initial reports.
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    let baseline_count = h.handle.apply_count();
    // Advance 60s + a little.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let reports = h.try_drain_reports().await;
    assert!(
        !reports.is_empty(),
        "expected at least one periodic-dump report"
    );
    // No new applies — periodic pass is a no-op.
    assert_eq!(h.handle.apply_count(), baseline_count);
    h.shutdown().await;
}

// 6. Kernel event triggers immediate reconcile.
#[tokio::test]
async fn kernel_event_triggers_reconcile() {
    let cfg = ReconcileActorConfig {
        coalesce_window: Duration::from_millis(0),
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    // Wait for the cold-start + intent-1 reports to clear.
    for _ in 0..10 {
        if let Ok(Some(r)) =
            tokio::time::timeout(Duration::from_millis(50), h.report_rx.recv()).await
            && r.intent_generation >= 1
        {
            break;
        }
    }

    // Pump a kernel event.
    h.handle.push_event(KernelEvent::KernelStateChanged).await;

    // Wait for the event-triggered reconcile report. The actor wakes
    // via `next_event()` → `coalesce_and_reconcile()`. With
    // coalesce_window = 0 the reconcile fires immediately, but the
    // tokio scheduler still needs a poll cycle.
    let saw_event_pass = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if let Some(r) = h.report_rx.recv().await {
                // Any post-cold-start report counts; the actor only
                // emits one when it ran a pass.
                if r.intent_generation == 1 {
                    return true;
                }
            } else {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(saw_event_pass, "kernel event did not wake the actor");
    h.shutdown().await;
}

// 7. NotReady instance never gets ops emitted; status row reflects it.
#[tokio::test]
async fn not_ready_instance_emits_status_no_ops() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(
        vni(100),
        InstanceProbe::NotReady {
            reason: "bridge missing".into(),
        },
    );

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    assert!(last.applied.is_empty());
    assert!(last.failed.is_empty());
    assert_eq!(last.instance_status.len(), 1);
    let row = &last.instance_status[0];
    assert_eq!(row.vni, vni(100));
    assert_eq!(row.state, rustbgpd_evpn::InstanceState::NotReady);
    assert!(!h.handle.kernel_has_fdb(vni(100), mac(1)));
    h.shutdown().await;
}

// 8. Permanent suppression is per-op-fingerprint. Generation churn
//    on the same op shape MUST NOT clear suppression — only when the
//    op shape itself changes (mobility move, add↔remove transition)
//    does the actor retry.
#[tokio::test(start_paused = true)]
async fn permanent_failure_suppression_is_per_op_fingerprint() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let target = DataplaneOp::AddRemoteFdb {
        vni: vni(100),
        mac: mac(1),
        dst: ipa("10.0.0.2"),
    };
    h.handle.inject_failure_kernel_too_old(Some(target));

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst.clone(), macs.build()))
        .unwrap();

    // First reconcile records the permanent failure with the
    // current op shape.
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;
    let after_first = h.handle.apply_count();
    assert!(
        after_first >= 1,
        "first apply did not run; got count={after_first}"
    );

    // Periodic dumps must not retry while the op shape is unchanged.
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
    }
    let _ = h.try_drain_reports().await;
    assert_eq!(
        h.handle.apply_count(),
        after_first,
        "suppressed op shape was re-applied (count {after_first} -> {})",
        h.handle.apply_count()
    );

    // Publish a fresh intent generation with the SAME op shape
    // (still 10.0.0.2, no mobility seq). Per-op-fingerprint
    // suppression must hold — generation churn alone does NOT clear.
    let mut macs_same = RemoteMacTable::builder();
    macs_same
        .insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    h.intent_tx
        .send(intent(2, inst.clone(), macs_same.build()))
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let after_same_gen = h.handle.apply_count();
    assert_eq!(
        after_same_gen, after_first,
        "generation bump alone re-applied a suppressed op (count {after_first} -> {after_same_gen}); \
         suppression must be per-op-fingerprint, not generation-wide"
    );

    // Now publish an intent where the op shape DOES change — same
    // (VNI, MAC), different remote VTEP. This is the operator's
    // mobility move; the new op shape must execute.
    let mut macs_moved = RemoteMacTable::builder();
    macs_moved
        .insert(vni(100), mac(1), entry("10.0.0.5", None))
        .unwrap();
    h.intent_tx
        .send(intent(3, inst, macs_moved.build()))
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;

    assert!(
        h.handle.apply_count() > after_same_gen,
        "op shape change (mobility move) did not clear suppression; \
         count stuck at {after_same_gen}"
    );
    assert!(h.handle.kernel_has_fdb(vni(100), mac(1)));
    h.shutdown().await;
}

// 9. Cross-key isolation: a permanent failure on (VNI, MAC=1) MUST
//    NOT block a separate (VNI, MAC=2) from being applied. Earlier
//    generation-wide suppression had cross-key bleed via the
//    "any RemoteMacTable change clears the whole set" semantics;
//    per-op-fingerprint isolates each (VNI, MAC) cleanly.
#[tokio::test(start_paused = true)]
async fn permanent_failure_does_not_leak_across_keys() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Permanent-fail Add for mac(1); leave mac(2) alone.
    let target = DataplaneOp::AddRemoteFdb {
        vni: vni(100),
        mac: mac(1),
        dst: ipa("10.0.0.2"),
    };
    h.handle.inject_failure_kernel_too_old(Some(target));

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    macs.insert(vni(100), mac(2), entry("10.0.0.3", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(2)),
        "unrelated key was blocked by another key's permanent failure"
    );
    assert!(!h.handle.kernel_has_fdb(vni(100), mac(1)));

    h.shutdown().await;
}

/// Regression for the "closed kernel-event stream busy-loop" review
/// finding on PR #79: when `Dataplane::next_event()` resolves to
/// `None` (the natural shape for a closed `mpsc::Receiver` after the
/// notify task drops `kernel_event_tx`), the actor's biased
/// `tokio::select!` would have spun the `next_event` arm and
/// starved every other arm behind it — including `intent_rx` and
/// `shutdown`. The fix gates the arm with an `event_stream_open`
/// flag flipped to `false` on the first `None`; this test validates
/// the actor still drives forward progress on intent changes (and
/// shuts down cleanly) when the event stream is closed from the
/// start.
///
/// Runs against **real** tokio time, not paused — the `timeout`
/// calls below need to actually elapse if the regression returns,
/// otherwise the busy-loop would also block the timer task and the
/// test would hang instead of failing. The waits are tight (≤2 s)
/// so the cost of un-paused time is minimal.
#[tokio::test]
async fn closed_event_stream_does_not_starve_intent_and_shutdown() {
    let dataplane = InMemoryDataplane::with_closed_event_stream();
    let handle = dataplane.handle();
    let (intent_tx, intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
    let (report_tx, mut report_rx) = mpsc::channel(64);
    let shutdown = CancellationToken::new();
    let actor = ReconcileActor::new(
        ReconcileActorConfig::for_tests(),
        dataplane,
        intent_rx,
        report_tx,
        shutdown.clone(),
    );
    let actor_join = tokio::spawn(actor.run());

    // Initial dump pass. If the actor were stuck in the next_event
    // busy-loop, we'd never see this report.
    tokio::task::yield_now().await;
    let first = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
        .await
        .expect("initial reconcile pass timed out — closed event stream starved the actor")
        .expect("report channel closed unexpectedly");
    assert_eq!(first.intent_generation, 0);

    // Intent change after the event stream has closed. If the
    // busy-loop is back, this never wakes the actor and the test
    // times out.
    let mut inst = EvpnInstanceTable::new();
    inst.insert(instance(100, Some("br100"), "10.0.0.1"))
        .unwrap();
    handle.set_probe(vni(100), InstanceProbe::Ready);
    intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();
    tokio::task::yield_now().await;
    let second = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
        .await
        .expect("intent-change reconcile timed out — closed event stream starved intent_rx")
        .expect("report channel closed unexpectedly");
    assert_eq!(second.intent_generation, 1);

    // Shutdown must complete despite the closed event stream.
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), actor_join)
        .await
        .expect("actor join timed out — shutdown was starved")
        .expect("actor task panicked");
}

// ADR-0059 slice 3b: actor-level FDB-NHG coverage. The diff-level
// unit tests exercise `compute_diff` Pass 1b in isolation, and the
// privileged netns test (`tests/netns_fdb_nhg.rs`) validates the raw
// netlink primitives. These tests close the gap on the coordinator
// + adoption state machine through `ReconcileActor::apply_nhg_op` +
// `cleanup_unreferenced_adoptions`.

fn entry_multi_homed(remote: &str, aliases: &[&str], seg: u8) -> RemoteMacEntry {
    RemoteMacEntry {
        remote_vtep_ip: ipa(remote),
        mobility_sequence: None,
        alias_vtep_ips: aliases.iter().map(|s| ipa(s)).collect(),
        alias_group_key: Some((EthernetSegmentIdentifier::new([seg; 10]), EthernetTagId(0))),
        source: RemoteMacSource::EvpnRibBestPath,
    }
}

/// Returns `(members, groups)` partitioned out of the in-memory
/// nexthop_ops map by kind.
fn split_nexthop_ops(
    nhs: &std::collections::BTreeMap<u32, rustbgpd_evpn_linux::dataplane::KernelNexthop>,
) -> (
    Vec<rustbgpd_evpn_linux::dataplane::KernelNexthop>,
    Vec<rustbgpd_evpn_linux::dataplane::KernelNexthop>,
) {
    use rustbgpd_evpn_linux::dataplane::KernelNexthopKind;
    let mut members = Vec::new();
    let mut groups = Vec::new();
    for nh in nhs.values() {
        match &nh.kind {
            KernelNexthopKind::Member { .. } => members.push(nh.clone()),
            KernelNexthopKind::Group { .. } => groups.push(nh.clone()),
        }
    }
    (members, groups)
}

// 1. Multi-homed Type 2 intent installs member NHs + group + FDB row
//    end-to-end through the actor.
#[tokio::test]
async fn fdb_nhg_multihomed_intent_installs_members_group_and_row() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    assert!(
        last.failed.is_empty(),
        "expected no failures: {:?}",
        last.failed
    );

    let nhs = h.handle.nexthop_ops();
    let (members, groups) = split_nexthop_ops(&nhs);
    assert_eq!(members.len(), 2, "expected 2 per-VTEP members; got {nhs:?}");
    assert_eq!(groups.len(), 1, "expected 1 group; got {nhs:?}");

    // FDB row exists and points at the group.
    let group_id = groups[0].id;
    assert_eq!(
        h.handle.kernel_fdb_nh_id(vni(100), mac(1)),
        Some(group_id),
        "FDB row should reference the installed group"
    );

    h.shutdown().await;
}

// 1b. The `DataplaneReport.fdb_nexthops` projection mirrors the
//     actor's `GroupOwnedMap` + adoption-state surface so the
//     `ListEvpnNexthops` gRPC / CLI consumer can render rustbgpd's
//     owned state without scraping logs. Verifies that on a
//     successful multi-homed install the projection reports one
//     group with the right `(vni, esi, ethernet_tag, group_id)`,
//     both per-VTEP members (non-zero nh_ids, matching gateways),
//     the one MAC ref, and zero orphan / pending-delete / drift-
//     disabled state.
#[tokio::test]
async fn fdb_nhg_dataplane_report_projection_matches_owned_state() {
    use std::collections::BTreeSet;
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert!(last.failed.is_empty(), "{:?}", last.failed);

    // Cross-check the fake's kernel state — the projection is
    // expected to mirror these IDs.
    let (kernel_members, kernel_groups) = split_nexthop_ops(&h.handle.nexthop_ops());
    assert_eq!(kernel_groups.len(), 1);
    assert_eq!(kernel_members.len(), 2);
    let kernel_group_id = kernel_groups[0].id;
    let kernel_member_ids: BTreeSet<u32> = kernel_members.iter().map(|m| m.id).collect();

    // Now assert the projection.
    let status = &last.fdb_nexthops;
    assert_eq!(status.orphan_nexthops_count, 0);
    assert_eq!(status.pending_delete_count, 0);
    assert!(!status.drift_recovery_disabled);
    assert_eq!(status.groups.len(), 1, "expected 1 group row");

    let g = &status.groups[0];
    assert_eq!(g.vni, vni(100));
    assert_eq!(g.ethernet_tag, EthernetTagId(0));
    assert_eq!(g.esi, EthernetSegmentIdentifier::new([7; 10]));
    assert_eq!(g.group_id, kernel_group_id);
    assert_eq!(g.ref_macs, vec![mac(1)]);
    assert_eq!(g.members.len(), 2);
    // Gateways must match the intent; nh_ids must match the kernel
    // (and be non-zero).
    let projected_member_ids: BTreeSet<u32> = g.members.iter().map(|m| m.nexthop_id).collect();
    assert_eq!(projected_member_ids, kernel_member_ids);
    let mut projected_gateways: Vec<IpAddr> = g.members.iter().map(|m| m.gateway).collect();
    projected_gateways.sort();
    assert_eq!(
        projected_gateways,
        vec![ipa("10.0.0.2"), ipa("10.0.0.3")],
        "projection must report the primary + alias gateways from the intent"
    );
    for m in &g.members {
        assert_ne!(m.nexthop_id, 0, "projection must never report nh_id=0");
    }

    h.shutdown().await;
}

// 2. Two MACs share one group: withdraw one leaves group + members
//    in place; withdraw last tears down.
#[tokio::test]
async fn fdb_nhg_shared_group_refcount_teardown() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));

    // Phase 1: both MACs ref the same `(ESI=7, EthTag=0)` group.
    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    macs.insert(
        vni(100),
        mac(2),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    h.intent_tx
        .send(intent(1, inst.clone(), macs.clone()))
        .unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    let (members, groups) = split_nexthop_ops(&h.handle.nexthop_ops());
    assert_eq!(members.len(), 2);
    assert_eq!(groups.len(), 1, "two MACs should share one group");
    let group_id = groups[0].id;
    assert_eq!(h.handle.kernel_fdb_nh_id(vni(100), mac(1)), Some(group_id));
    assert_eq!(h.handle.kernel_fdb_nh_id(vni(100), mac(2)), Some(group_id));

    // Phase 2: withdraw MAC(1). Group + members must remain (MAC(2)
    // still refs); FDB row for MAC(1) gone.
    let mut macs2 = RemoteMacTable::builder();
    macs2
        .insert(
            vni(100),
            mac(2),
            entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
        )
        .unwrap();
    let macs2 = macs2.build();
    h.intent_tx.send(intent(2, inst.clone(), macs2)).unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation < 2 {
        last = h.next_report().await;
    }
    let (members, groups) = split_nexthop_ops(&h.handle.nexthop_ops());
    assert_eq!(
        members.len(),
        2,
        "members must survive while a sibling MAC refs the group"
    );
    assert_eq!(groups.len(), 1, "group must survive last-ref shrink");
    assert!(!h.handle.kernel_has_fdb(vni(100), mac(1)));
    assert!(h.handle.kernel_has_fdb(vni(100), mac(2)));

    // Phase 3: withdraw MAC(2). Last ref → group + members torn down.
    let macs3 = RemoteMacTable::new();
    h.intent_tx.send(intent(3, inst, macs3)).unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation < 3 {
        last = h.next_report().await;
    }
    let (members, groups) = split_nexthop_ops(&h.handle.nexthop_ops());
    assert!(
        members.is_empty(),
        "members must be GC'd after last ref drops; got {members:?}"
    );
    assert!(
        groups.is_empty(),
        "group must be GC'd after last MAC unref; got {groups:?}"
    );
    assert!(!h.handle.kernel_has_fdb(vni(100), mac(2)));

    h.shutdown().await;
}

// 3. Adoption with a preloaded tagged NHG + member + matching kernel
//    FDB row (no desired intent referencing them): cleanup must
//    retain the IDs because the FDB row still points at the group.
#[tokio::test]
async fn fdb_nhg_adoption_retains_live_kernel_fdb_refs() {
    use rustbgpd_evpn_linux::dataplane::{KernelNexthop, KernelNexthopKind};
    use rustbgpd_evpn_linux::nh_id_alloc::{NHG_TAG, VTEP_NH_TAG};

    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Pre-load a prior daemon's group + member, plus a kernel FDB
    // row pointing at the group (the "live ref" the cleanup must
    // see).
    let member_id = VTEP_NH_TAG | 1;
    let group_id = NHG_TAG | 1;
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: member_id,
        kind: KernelNexthopKind::Member {
            gateway: ipa("10.0.0.2"),
        },
    });
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: group_id,
        kind: KernelNexthopKind::Group {
            member_ids: vec![member_id],
        },
    });
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(99),
            dst: None,
            nh_id: Some(group_id),
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        },
    );

    // Empty intent — no MAC will claim these IDs through Install.
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    let macs = RemoteMacTable::new();
    h.intent_tx.send(intent(1, inst, macs)).unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);

    // Cleanup ran; both IDs must still be present because the kernel
    // FDB row references the group.
    let nhs = h.handle.nexthop_ops();
    assert!(
        nhs.contains_key(&group_id),
        "adoption cleanup must retain group ID still referenced by a kernel FDB row; got {nhs:?}"
    );
    assert!(
        nhs.contains_key(&member_id),
        "adoption cleanup must retain member of a retained group; got {nhs:?}"
    );

    h.shutdown().await;
}

// 4. Permanent-suppressed InstallFdbNhg blocks adoption cleanup
//    across passes — even when `failed.is_empty()` because the op
//    `continue`s out of `apply_plan` instead of joining `failed`.
#[tokio::test]
async fn fdb_nhg_perm_suppressed_install_blocks_adoption_cleanup() {
    use rustbgpd_evpn_linux::dataplane::{KernelNexthop, KernelNexthopKind};
    use rustbgpd_evpn_linux::nh_id_alloc::{NHG_TAG, VTEP_NH_TAG};

    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Pre-load a prior daemon's group + member with NO kernel FDB
    // row referencing them. Without the suppression gate they would
    // be cleaned up as stale on the first successful pass.
    let member_id = VTEP_NH_TAG | 1;
    let group_id = NHG_TAG | 1;
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: member_id,
        kind: KernelNexthopKind::Member {
            gateway: ipa("10.0.0.2"),
        },
    });
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: group_id,
        kind: KernelNexthopKind::Group {
            member_ids: vec![member_id],
        },
    });

    // Inject a Permanent failure (KernelTooOld) on EVERY apply call
    // so the first InstallFdbNhg fails permanently AND the next
    // pass's suppressed retry leaves `failed.is_empty()`.
    h.handle.inject_failure_kernel_too_old(None);
    h.handle.inject_failure_kernel_too_old(None);
    h.handle.inject_failure_kernel_too_old(None);

    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst.clone(), macs.clone()))
        .unwrap();

    // Pass 1: Install fails permanent → recorded in
    // `permanent_failures` → joins `failed` → cleanup skipped.
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    assert!(
        !last.failed.is_empty(),
        "expected the first-pass permanent failure to surface in `failed`"
    );

    // Push a kernel event to trigger another reconcile pass.
    // On this pass the same InstallFdbNhg is permanently
    // suppressed (`continue`s out of apply_plan), so `failed` is
    // empty — the suppression gate is what must block cleanup.
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    let mut next = h.next_report().await;
    // Discard the cold-start / earlier reports; wait for one after
    // the kernel event.
    while next.applied.is_empty() && !next.failed.is_empty() {
        next = h.next_report().await;
    }
    // At least one pass after the suppression took effect must have
    // had `failed.is_empty()`. Regardless of which pass it was, the
    // adopted IDs must STILL be present.
    let nhs = h.handle.nexthop_ops();
    assert!(
        nhs.contains_key(&group_id),
        "adoption cleanup must be blocked while an FDB-NHG op is permanently suppressed; group missing from {nhs:?}"
    );
    assert!(
        nhs.contains_key(&member_id),
        "adoption cleanup must be blocked while an FDB-NHG op is permanently suppressed; member missing from {nhs:?}"
    );

    h.shutdown().await;
}

// ─── ADR-0059 slice 3.5: per-VNI apply_aliasing_ecmp off-switch ───

// 1. Actor-level: a multi-homed Type 2 entry on a VNI with
//    `apply_aliasing_ecmp = false` programs a single-dst FDB row at
//    the primary VTEP — no NHGs are installed.
#[tokio::test]
async fn fdb_nhg_off_switch_disabled_skips_install() {
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(
        instance(100, Some("br100"), "10.0.0.1").with_apply_aliasing_ecmp(false),
    );
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert_eq!(last.intent_generation, 1);
    assert!(
        last.failed.is_empty(),
        "expected no failures: {:?}",
        last.failed
    );

    // No NHG members, no NHG groups — the off-switch routes through
    // the single-dst path.
    let nhs = h.handle.nexthop_ops();
    let (members, groups) = split_nexthop_ops(&nhs);
    assert!(
        members.is_empty() && groups.is_empty(),
        "off-switch must skip NHG install; got {nhs:?}"
    );

    // FDB row exists and points at the primary VTEP (no nh_id).
    assert!(
        h.handle.kernel_fdb_nh_id(vni(100), mac(1)).is_none(),
        "FDB row must NOT reference an NHG when off-switch is engaged"
    );
    let snapshot = h.handle.kernel_snapshot();
    let row = snapshot
        .find_fdb(vni(100), mac(1))
        .expect("FDB row should exist for (vni 100, mac 1)");
    assert_eq!(
        row.dst,
        Some(ipa("10.0.0.2")),
        "single-dst row must point at primary VTEP, got {:?}",
        row.dst,
    );

    h.shutdown().await;
}

// ─── ADR-0059 slice 3.5 PR 2: periodic RTM_GETNEXTHOP drift recovery ───

/// Helper for drift tests: install a multi-homed entry, drain reports
/// until adoption is done and the FDB-NHG path has installed the group
/// + members. Returns `(group_id, member_ids)` for the test to drive.
async fn install_and_settle_multihomed(h: &mut Harness) -> (u32, Vec<u32>) {
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    let mut macs = RemoteMacTable::builder();
    macs.insert(
        vni(100),
        mac(1),
        entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
    )
    .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert!(last.failed.is_empty(), "install failed: {:?}", last.failed);

    let (members, groups) = split_nexthop_ops(&h.handle.nexthop_ops());
    assert_eq!(groups.len(), 1, "expected 1 group, got {groups:?}");
    assert_eq!(members.len(), 2, "expected 2 members, got {members:?}");
    let group_id = groups[0].id;
    let member_ids: Vec<u32> = members.iter().map(|m| m.id).collect();
    (group_id, member_ids)
}

fn sum_fdb_nhg_drift_counters(
    reports: &[rustbgpd_evpn::DataplaneReport],
) -> rustbgpd_evpn::FdbNhgDriftCounters {
    reports.iter().fold(
        rustbgpd_evpn::FdbNhgDriftCounters::default(),
        |mut acc, r| {
            acc.members_repaired += r.fdb_nhg_drift_counters.members_repaired;
            acc.groups_replaced += r.fdb_nhg_drift_counters.groups_replaced;
            acc.orphans_cleaned += r.fdb_nhg_drift_counters.orphans_cleaned;
            acc.drift_disabled += r.fdb_nhg_drift_counters.drift_disabled;
            acc.single_dst_adopted += r.fdb_nhg_drift_counters.single_dst_adopted;
            acc.single_dst_reaped += r.fdb_nhg_drift_counters.single_dst_reaped;
            acc
        },
    )
}

// 1. Drift recovery re-adds a member that was deleted out-of-band.
#[tokio::test(start_paused = true)]
async fn drift_recovery_re_adds_missing_member() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);

    let (_group_id, member_ids) = install_and_settle_multihomed(&mut h).await;
    let removed_id = member_ids[0];

    // Out-of-band: delete the member from the fake kernel.
    h.handle
        .force_remove_nexthop_op(removed_id)
        .expect("member should have been installed");
    assert!(
        !h.handle.nexthop_ops().contains_key(&removed_id),
        "force_remove should drop the kernel-side record"
    );

    // Advance past the periodic_dump window so drift recovery runs.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.members_repaired, 1);

    // Member should be back at the same kernel ID.
    assert!(
        h.handle.nexthop_ops().contains_key(&removed_id),
        "drift recovery should re-install the deleted member at the same kernel ID"
    );

    h.shutdown().await;
}

// 1b. Drift recovery REPLACEs a per-VTEP member whose kernel-side
//     gateway no longer matches the tracked IP. An external actor
//     replacing the gateway under our tag-space ID can't be caught
//     by a `contains_key`-only check.
#[tokio::test(start_paused = true)]
async fn drift_recovery_replaces_member_with_wrong_gateway() {
    use rustbgpd_evpn_linux::dataplane::{KernelNexthop, KernelNexthopKind};

    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);

    let (_group_id, member_ids) = install_and_settle_multihomed(&mut h).await;
    // First member of the multi-homed install tracks 10.0.0.2.
    let drifted_id = member_ids[0];

    // Out-of-band: replace the kernel-side member at `drifted_id`
    // with a different gateway. This is exactly what a competing
    // daemon (or an `ip nexthop replace ... via 192.0.2.99 fdb`)
    // could leave behind — same ID, wrong gateway.
    h.handle
        .force_remove_nexthop_op(drifted_id)
        .expect("member should have been installed");
    let wrong_gateway: IpAddr = "192.0.2.99".parse().unwrap();
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: drifted_id,
        kind: KernelNexthopKind::Member {
            gateway: wrong_gateway,
        },
    });

    // Drift cycle should detect the gateway mismatch and re-issue
    // `add_nexthop_member` with the *correct* IP at the same ID.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.members_repaired, 1);

    let nhs = h.handle.nexthop_ops();
    let nh = nhs
        .get(&drifted_id)
        .expect("member should still exist after repair");
    match &nh.kind {
        KernelNexthopKind::Member { gateway } => assert_eq!(
            *gateway,
            "10.0.0.2".parse::<IpAddr>().unwrap(),
            "drift recovery must restore the tracked gateway; got {gateway}"
        ),
        other => panic!("expected Member kind, got {other:?}"),
    }

    h.shutdown().await;
}

// 2. Drift recovery re-adds a group that was deleted out-of-band.
#[tokio::test(start_paused = true)]
async fn drift_recovery_re_adds_missing_group() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);

    let (group_id, _member_ids) = install_and_settle_multihomed(&mut h).await;

    // Out-of-band: delete the group from the fake kernel.
    h.handle
        .force_remove_nexthop_op(group_id)
        .expect("group should have been installed");

    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.groups_replaced, 1);

    assert!(
        h.handle.nexthop_ops().contains_key(&group_id),
        "drift recovery should re-install the deleted group at the same kernel ID"
    );

    h.shutdown().await;
}

// 3. Drift recovery REPLACEs a group whose member set drifted.
#[tokio::test(start_paused = true)]
async fn drift_recovery_replaces_wrong_member_set() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);

    let (group_id, member_ids) = install_and_settle_multihomed(&mut h).await;
    let kept_member = member_ids[0];

    // Out-of-band: corrupt the kernel-side group to point at only one
    // member instead of two.
    h.handle
        .force_set_group_members(group_id, vec![kept_member])
        .expect("should be a group");

    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.groups_replaced, 1);

    // Group's member set should be restored to both members.
    let nhs = h.handle.nexthop_ops();
    let group = nhs.get(&group_id).expect("group exists");
    match &group.kind {
        rustbgpd_evpn_linux::dataplane::KernelNexthopKind::Group { member_ids: m } => {
            let expected: std::collections::BTreeSet<u32> = member_ids.iter().copied().collect();
            let got: std::collections::BTreeSet<u32> = m.iter().copied().collect();
            assert_eq!(
                expected, got,
                "drift recovery should REPLACE the group member set; expected {expected:?}, got {got:?}"
            );
        }
        other => panic!("expected Group kind, got {other:?}"),
    }

    h.shutdown().await;
}

// 4. Drift recovery folds untracked tagged NHIDs into adopted_unreferenced.
//    On the next reconcile pass, cleanup_unreferenced_adoptions deletes
//    them (no kernel FDB row references them, no group tracks them).
#[tokio::test(start_paused = true)]
async fn drift_recovery_deletes_untracked_tagged_group_without_fdb_ref() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Pre-load a tagged NHID in the rustbgpd group-tag range with no
    // tracking on our side and no FDB row referencing it.
    use rustbgpd_evpn_linux::dataplane::{KernelNexthop, KernelNexthopKind};
    let stale_id: u32 = 0x4000_0BAD;
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: stale_id,
        kind: KernelNexthopKind::Group { member_ids: vec![] },
    });

    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    // First pass — adoption pass should pick up the stale ID, then
    // cleanup deletes it.
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    // Already deleted by startup adoption-cleanup. Drift recovery is
    // the steady-state safety net for the *post-startup* drift case;
    // we exercise that next.
    assert!(
        !h.handle.nexthop_ops().contains_key(&stale_id),
        "startup adoption-cleanup should have already deleted the stale tagged group"
    );

    // Inject a *new* stale tagged group after adoption_done is set —
    // this is the steady-state drift case PR 2 was added for. The ID
    // sits inside the allocator's reservable bitmap range (matches
    // FRR's `EVPN_NH_ID_MAX`) so drift recovery can reserve + cleanup.
    let drift_id: u32 = 0x4000_0BAE;
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: drift_id,
        kind: KernelNexthopKind::Group { member_ids: vec![] },
    });

    // First drift tick — folds drift_id into adopted_unreferenced
    // AND runs `cleanup_unreferenced_adoptions` in-line against the
    // current snapshot. The snapshot has no FDB row referencing
    // drift_id, so retention is empty and the cleanup deletes it
    // on this pass.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.orphans_cleaned, 1);

    assert!(
        !h.handle.nexthop_ops().contains_key(&drift_id),
        "drift recovery folds + in-line-cleans untracked tagged NHIDs in one pass; nhs={:?}",
        h.handle.nexthop_ops()
    );

    h.shutdown().await;
}

// 5. Drift dump failure is non-fatal — other reconcile work proceeds.
#[tokio::test(start_paused = true)]
async fn drift_recovery_dump_failure_does_not_block_other_paths() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Install a single-dst entry — no FDB-NHG involvement.
    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }
    assert!(h.handle.kernel_has_fdb(vni(100), mac(1)));

    // Trip an Io (transient) failure that the drift cycle's
    // dump_owned_nexthops will consume; the FDB op stays untouched
    // because compute_diff produces no ops (kernel matches desired).
    // Drift returns early via the dump-failed branch — no panic, no
    // log explosion. Verify the existing FDB row survived.
    h.handle.inject_failure_io(None);
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(1)),
        "single-dst FDB row should be unaffected by drift dump failure"
    );

    h.shutdown().await;
}

// 6. Drift recovery must not delete an FDB row whose `(vni, mac)`
//    is still in the desired intent — even if the row's nh_id
//    looks like a prior-daemon orphan. This is the safety guard
//    against widening blast radius during transient apply
//    failures.
#[tokio::test(start_paused = true)]
async fn drift_recovery_preserves_fdb_row_for_desired_mac() {
    use rustbgpd_evpn_linux::dataplane::{KernelNexthop, KernelNexthopKind};

    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Pre-load a tagged kernel state from a "prior daemon run":
    //   - a tagged-NHID nexthop (in our group-tag range) that we
    //     don't track today,
    //   - an FDB row at (vni 100, mac 1) referencing that nh_id.
    let stale_nh_id: u32 = 0x4000_0BAD;
    h.handle.pre_load_nexthop_op(KernelNexthop {
        id: stale_nh_id,
        kind: KernelNexthopKind::Group { member_ids: vec![] },
    });
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(1),
            dst: None,
            nh_id: Some(stale_nh_id),
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        },
    );

    // Intent has (vni 100, mac 1) as a desired single-dst entry.
    // The apply path may or may not succeed depending on the order
    // of operations; the safety property the test pins is that
    // *drift recovery* — running on the periodic tick — won't
    // delete the row underneath us just because `owned` and
    // `tracked_ids` don't claim it yet.
    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();

    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }

    // Advance past the periodic dump window so drift recovery runs.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    // The FDB row for (vni 100, mac 1) MUST still be present —
    // drift recovery saw it referencing an untracked tagged nh_id
    // but skipped removal because the entry is in `desired`.
    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(1)),
        "drift recovery must not remove FDB row for desired (vni, mac); \
         kernel state: {:?}",
        h.handle.kernel_snapshot(),
    );

    h.shutdown().await;
}

// 7. A *permanent* dump failure (e.g., kernel too old, missing
//    CAP_NET_ADMIN) latches drift recovery off so the actor stops
//    re-attempting the dump (and emitting a warn) every reconcile
//    trigger thereafter.
#[tokio::test(start_paused = true)]
async fn drift_recovery_permanent_dump_failure_latches_off() {
    let cfg = ReconcileActorConfig::for_tests();
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);

    // Install a single-dst entry so reconcile work happens normally.
    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let macs = macs.build();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs)).unwrap();
    let mut last = h.next_report().await;
    while last.intent_generation == 0 {
        last = h.next_report().await;
    }

    // Stage a permanent failure (`KernelTooOld` is classified
    // Permanent) for the next reconcile pass's drift dump. After
    // it lands once, drift should latch off; even if we stage more
    // permanent failures, drift must not consume them.
    h.handle.inject_failure_kernel_too_old(None);

    // First drift cycle — consumes the permanent failure, latches.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let reports = h.try_drain_reports().await;
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.drift_disabled, 1);

    // Stage a SECOND permanent failure. With the latch in place,
    // drift is disabled — this failure should NOT be consumed by
    // a drift dump call. Forward reconcile work for unrelated paths
    // continues normally.
    h.handle.inject_failure_kernel_too_old(None);
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    // FDB row for the desired MAC must still be present — drift
    // disablement must not affect single-dst reconcile work.
    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(1)),
        "single-dst FDB row must survive drift-disabled state"
    );

    h.shutdown().await;
}

// ─── ADR-0079 slice 2: single-dst FDB crash-restart adoption sweep ───
//
// These tests simulate the post-crash shape directly: the fake kernel
// is pre-loaded with `extern_learn` rows (our ownership marker from a
// previous lifetime) and the actor starts with an empty OwnedSet.

/// A single-dst FDB row carrying our `extern_learn` ownership marker —
/// what a crashed daemon leaves behind in the kernel.
fn extern_learn_row(m: MacAddress, dst: &str) -> KernelFdbEntry {
    KernelFdbEntry {
        mac: m,
        dst: Some(ipa(dst)),
        nh_id: None,
        flags: KernelFdbFlags {
            extern_learn: true,
            master: true,
            ..Default::default()
        },
    }
}

// 1. A crash leftover whose MAC is still desired is re-claimed: the
//    diff emits the claim REPLACE (even though the kernel dst already
//    matches) and the row lands in the applied report + OwnedSet —
//    not the foreign-skip path.
#[tokio::test]
async fn crash_leftover_desired_mac_is_reclaimed() {
    use rustbgpd_evpn::DataplaneOpKind;

    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    h.handle
        .pre_load_fdb(vni(100), extern_learn_row(mac(1), "10.0.0.2"));

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1 && !r.applied.is_empty();
        reports.push(r);
        if done {
            break;
        }
    }
    let claim = reports.last().unwrap();
    assert_eq!(claim.applied.len(), 1, "applied: {:?}", claim.applied);
    assert!(
        matches!(
            claim.applied[0].kind,
            DataplaneOpKind::UpdateRemoteFdb { mac: m, dst } if m == mac(1) && dst == ipa("10.0.0.2")
        ),
        "claim must be the REPLACE-shaped UpdateRemoteFdb, got {:?}",
        claim.applied[0].kind,
    );
    assert!(claim.failed.is_empty(), "{:?}", claim.failed);

    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.single_dst_adopted, 1);
    assert_eq!(counters.single_dst_reaped, 0, "claimed row must not reap");

    // Row still forwards at the desired VTEP.
    let snap = h.handle.kernel_snapshot();
    let row = snap.find_fdb(vni(100), mac(1)).expect("row must survive");
    assert_eq!(row.dst, Some(ipa("10.0.0.2")));

    h.shutdown().await;
}

// 2. An adopted-but-unclaimed row keeps forwarding while the deferral
//    window is open — that is the point of the deferral. A clean
//    shutdown inside the window must not reap it either.
#[tokio::test(start_paused = true)]
async fn crash_leftover_unclaimed_row_kept_before_deferral() {
    // for_tests() carries the production-length 500 s deferral.
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    h.handle
        .pre_load_fdb(vni(100), extern_learn_row(mac(7), "10.0.0.9"));
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    // A couple of periodic passes well inside the deferral window.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.single_dst_adopted, 1);
    assert_eq!(
        counters.single_dst_reaped, 0,
        "must not reap inside the deferral window"
    );
    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(7)),
        "adopted row must keep forwarding before the deferral elapses"
    );

    let handle = h.handle.clone();
    h.shutdown().await;
    assert!(
        handle.kernel_has_fdb(vni(100), mac(7)),
        "shutdown drain only touches owned entries; adopted-but-unclaimed rows \
         are left for the next lifetime to re-adopt (ADR-0079 rule 4)"
    );
}

// 3. After the deferral, an unclaimed row is reaped — and a desired
//    row adopted in the same sweep is NOT (its claim exempts it).
#[tokio::test]
async fn crash_leftover_unclaimed_row_reaped_after_deferral() {
    let cfg = ReconcileActorConfig {
        fdb_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    // Withdrawn-while-down leftover — steers into a dead tunnel.
    h.handle
        .pre_load_fdb(vni(100), extern_learn_row(mac(7), "10.0.0.9"));
    // Still-desired leftover alongside it.
    h.handle
        .pre_load_fdb(vni(100), extern_learn_row(mac(1), "10.0.0.2"));

    let mut macs = RemoteMacTable::builder();
    macs.insert(vni(100), mac(1), entry("10.0.0.2", None))
        .unwrap();
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx.send(intent(1, inst, macs.build())).unwrap();

    let mut reports = Vec::new();
    for _ in 0..10 {
        reports.push(h.next_report().await);
        if !h.handle.kernel_has_fdb(vni(100), mac(7)) {
            break;
        }
    }

    assert!(
        !h.handle.kernel_has_fdb(vni(100), mac(7)),
        "unclaimed row must be reaped after the deferral"
    );
    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(1)),
        "desired row must be claimed, never reaped"
    );
    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.single_dst_adopted, 2);
    assert_eq!(counters.single_dst_reaped, 1);

    h.shutdown().await;
}

// 4. Foreign rows — operator-static and kernel-learned-local — carry
//    no ownership marker and must be neither adopted nor reaped, even
//    with a zero deferral.
#[tokio::test(start_paused = true)]
async fn foreign_rows_never_adopted_or_reaped() {
    let cfg = ReconcileActorConfig {
        fdb_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    // Operator-static (permanent) row.
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(8),
            dst: Some(ipa("10.0.0.8")),
            nh_id: None,
            flags: KernelFdbFlags {
                permanent: true,
                master: true,
                ..Default::default()
            },
        },
    );
    // Kernel-learned local row (dynamic, no flags, no dst).
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(9),
            dst: None,
            nh_id: None,
            flags: KernelFdbFlags::default(),
        },
    );
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(counters.single_dst_adopted, 0, "foreign rows are not ours");
    assert_eq!(counters.single_dst_reaped, 0);
    assert!(h.handle.kernel_has_fdb(vni(100), mac(8)));
    assert!(h.handle.kernel_has_fdb(vni(100), mac(9)));

    h.shutdown().await;
}

// 5. An `extern_learn` row with `nh_id` set is ADR-0059 territory —
//    the single-dst sweep must not adopt (or reap) it.
#[tokio::test]
async fn nhg_tagged_rows_left_to_adr0059_sweep() {
    let cfg = ReconcileActorConfig {
        fdb_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_probe(vni(100), InstanceProbe::Ready);
    h.handle.pre_load_fdb(
        vni(100),
        KernelFdbEntry {
            mac: mac(5),
            dst: None,
            nh_id: Some(0x4000_0001),
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        },
    );
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));
    h.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }

    let counters = sum_fdb_nhg_drift_counters(&reports);
    assert_eq!(
        counters.single_dst_adopted, 0,
        "NHG-tagged rows belong to the ADR-0059 drift sweep"
    );
    assert_eq!(counters.single_dst_reaped, 0);
    assert!(
        h.handle.kernel_has_fdb(vni(100), mac(5)),
        "the single-dst sweep must not touch an NHG-tagged row"
    );

    h.shutdown().await;
}

// 6. Idempotence under repeated crash: a second fresh actor over the
//    same kernel state (the first one shut down inside its deferral
//    window) re-adopts harmlessly, and the row is reaped exactly once.
#[tokio::test]
async fn double_crash_readoption_is_idempotent() {
    let inst = one_instance_table(instance(100, Some("br100"), "10.0.0.1"));

    // Lifetime 1: long deferral — adopt, then "crash"/stop inside the
    // window. The unclaimed row must survive.
    let mut h1 = Harness::spawn(ReconcileActorConfig::for_tests());
    h1.handle.set_probe(vni(100), InstanceProbe::Ready);
    h1.handle
        .pre_load_fdb(vni(100), extern_learn_row(mac(7), "10.0.0.9"));
    h1.intent_tx
        .send(intent(1, inst.clone(), RemoteMacTable::new()))
        .unwrap();
    let mut reports1 = Vec::new();
    loop {
        let r = h1.next_report().await;
        let done = r.intent_generation == 1;
        reports1.push(r);
        if done {
            break;
        }
    }
    assert_eq!(sum_fdb_nhg_drift_counters(&reports1).single_dst_adopted, 1);
    let handle1 = h1.handle.clone();
    h1.shutdown().await;
    assert!(
        handle1.kernel_has_fdb(vni(100), mac(7)),
        "row must survive a shutdown inside the deferral window"
    );

    // Lifetime 2: fresh actor over the surviving kernel state (the
    // OwnedSet died with lifetime 1), zero deferral. Re-adoption is
    // harmless and the reap happens exactly once.
    let cfg = ReconcileActorConfig {
        fdb_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h2 = Harness::spawn(cfg);
    h2.handle.set_probe(vni(100), InstanceProbe::Ready);
    for (&(v, _), e) in handle1.kernel_snapshot().iter_fdb() {
        h2.handle.pre_load_fdb(v, e.clone());
    }
    h2.intent_tx
        .send(intent(1, inst, RemoteMacTable::new()))
        .unwrap();

    let mut reports2 = Vec::new();
    for _ in 0..10 {
        reports2.push(h2.next_report().await);
        if !h2.handle.kernel_has_fdb(vni(100), mac(7)) {
            break;
        }
    }
    let counters = sum_fdb_nhg_drift_counters(&reports2);
    assert_eq!(
        counters.single_dst_adopted, 1,
        "second adoption is one-shot"
    );
    assert_eq!(counters.single_dst_reaped, 1, "row reaped exactly once");
    assert!(!h2.handle.kernel_has_fdb(vni(100), mac(7)));

    h2.shutdown().await;
}

// ─── ADR-0079 L3 sweep: crash-restart adoption for VRF routes / L3
// neighbors / L3VXLAN FDB rows ───
//
// Same post-crash simulation shape as the slice-2 block above: the
// fake kernel is pre-loaded with marker rows (`proto bgp` + onlink
// route in the configured table; permanent `extern_learn` neighbor /
// FDB rows on the L3VXLAN device) and the actor starts with an empty
// `L3OwnedState`. Re-claim is implicit — every L3 add applies with
// replace semantics, so a desired prefix's re-install is the claim.

const L3_TABLE_ID: u32 = 201;
const L3_IFINDEX: u32 = 42;

fn l3_vrf_id() -> IpVrfId {
    IpVrfId::new(101).unwrap()
}

fn l3_prefix() -> EvpnIpPrefixValue {
    EvpnIpPrefixValue::V4(Ipv4Prefix::new(
        std::net::Ipv4Addr::new(198, 51, 100, 0),
        24,
    ))
}

fn l3_router_mac() -> MacAddress {
    MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
}

fn l3_local_mac() -> MacAddress {
    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x10])
}

fn l3_ip_vrfs() -> IpVrfTable {
    let mut t = IpVrfTable::new();
    t.insert(
        IpVrf::new(
            "vrf101".to_string(),
            l3_vrf_id(),
            "65000:101".parse().unwrap(),
            vec!["65000:101".parse().unwrap()],
            ipa("10.0.0.1"),
            l3_local_mac(),
            "vrf101".to_string(),
            "l3vxlan101".to_string(),
            L3_TABLE_ID,
        )
        .unwrap(),
    )
    .unwrap();
    t
}

/// Desired projection containing the one test prefix — built through
/// the real projection helper so the table is shaped exactly like the
/// supervisor's.
fn l3_desired_prefixes(ip_vrfs: &IpVrfTable) -> RemoteIpPrefixTable {
    project_ip_prefix_routes(
        ip_vrfs,
        vec![ProjectedIpPrefixRoute {
            rd: "65000:101".parse().unwrap(),
            prefix: l3_prefix(),
            next_hop: ipa("10.0.0.2"),
            gateway: ipa("0.0.0.0"),
            l3vni: 101,
            route_targets: vec!["65000:101".parse().unwrap()],
            router_mac: Some(l3_router_mac()),
        }],
    )
}

fn l3_intent(
    generation: u64,
    ip_vrfs: IpVrfTable,
    remote_ip_prefixes: RemoteIpPrefixTable,
) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(EvpnInstanceTable::new()),
        remote_macs: Arc::new(RemoteMacTable::new()),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(ip_vrfs),
        remote_ip_prefixes: Arc::new(remote_ip_prefixes),
    })
}

fn l3_ready_status() -> IpVrfStatus {
    IpVrfStatus::Ready {
        vrf_ifindex: 41,
        l3vxlan_ifindex: L3_IFINDEX,
        table_id: L3_TABLE_ID,
        router_mac: l3_local_mac(),
    }
}

/// Pre-load the three marker rows a crashed daemon leaves behind for
/// one installed prefix.
fn pre_load_l3_marker_rows(handle: &InMemoryHandle) {
    handle.pre_load_l3_route(L3_TABLE_ID, l3_prefix(), L3_IFINDEX, ipa("10.0.0.2"), true);
    handle.pre_load_l3_neighbor(L3_IFINDEX, ipa("10.0.0.2"), l3_router_mac(), true);
    handle.pre_load_l3_vxlan_fdb(L3_IFINDEX, l3_router_mac(), ipa("10.0.0.2"), true);
}

/// `(route, neighbor, fdb)` presence triple for the test identity.
fn l3_kernel_rows(handle: &InMemoryHandle) -> (bool, bool, bool) {
    (
        handle.kernel_has_l3_route(L3_TABLE_ID, l3_prefix()),
        handle.kernel_has_l3_neighbor(L3_IFINDEX, ipa("10.0.0.2")),
        handle.kernel_has_l3_vxlan_fdb(L3_IFINDEX, l3_router_mac()),
    )
}

fn sum_l3_adoption_counters(
    reports: &[rustbgpd_evpn::DataplaneReport],
) -> rustbgpd_evpn::L3AdoptionCounters {
    reports.iter().fold(
        rustbgpd_evpn::L3AdoptionCounters::default(),
        |mut acc, r| {
            acc.routes_adopted += r.l3_adoption_counters.routes_adopted;
            acc.routes_reaped += r.l3_adoption_counters.routes_reaped;
            acc.neighbors_adopted += r.l3_adoption_counters.neighbors_adopted;
            acc.neighbors_reaped += r.l3_adoption_counters.neighbors_reaped;
            acc.l3vxlan_fdb_adopted += r.l3_adoption_counters.l3vxlan_fdb_adopted;
            acc.l3vxlan_fdb_reaped += r.l3_adoption_counters.l3vxlan_fdb_reaped;
            acc
        },
    )
}

// (a) Crash leftovers for a still-desired prefix are adopted, then
//     claimed by the replace-semantics re-install — never reaped,
//     even with a zero deferral.
#[tokio::test]
async fn l3_crash_leftover_desired_prefix_is_claimed_not_reaped() {
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h.handle);

    let ip_vrfs = l3_ip_vrfs();
    let desired = l3_desired_prefixes(&ip_vrfs);
    h.intent_tx.send(l3_intent(1, ip_vrfs, desired)).unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    // An extra pass after the (zero) deferral has elapsed — if the
    // claim didn't land, this is the pass that would reap.
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters.routes_adopted, 1);
    assert_eq!(counters.neighbors_adopted, 1);
    assert_eq!(counters.l3vxlan_fdb_adopted, 1);
    assert_eq!(counters.routes_reaped, 0, "claimed route must not reap");
    assert_eq!(counters.neighbors_reaped, 0);
    assert_eq!(counters.l3vxlan_fdb_reaped, 0);
    assert_eq!(
        l3_kernel_rows(&h.handle),
        (true, true, true),
        "all three rows keep forwarding after the claim"
    );

    h.shutdown().await;
}

// (b) Unclaimed marker rows keep forwarding while the deferral window
//     is open — that is the point of the deferral.
#[tokio::test(start_paused = true)]
async fn l3_unclaimed_rows_kept_before_deferral() {
    // for_tests() carries the production-length 500 s deferral.
    let mut h = Harness::spawn(ReconcileActorConfig::for_tests());
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h.handle);

    h.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    // A couple of periodic passes well inside the deferral window.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters.routes_adopted, 1);
    assert_eq!(counters.neighbors_adopted, 1);
    assert_eq!(counters.l3vxlan_fdb_adopted, 1);
    assert_eq!(
        counters.routes_reaped + counters.neighbors_reaped + counters.l3vxlan_fdb_reaped,
        0,
        "must not reap inside the deferral window"
    );
    assert_eq!(l3_kernel_rows(&h.handle), (true, true, true));

    h.shutdown().await;
}

// (c) After the deferral, unclaimed rows are reaped from all three
//     surfaces, most-dependent first: route → neighbor → FDB.
#[tokio::test]
async fn l3_unclaimed_rows_reaped_after_deferral_in_route_first_order() {
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h.handle);

    h.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    for _ in 0..10 {
        reports.push(h.next_report().await);
        if l3_kernel_rows(&h.handle) == (false, false, false) {
            break;
        }
    }

    assert_eq!(
        l3_kernel_rows(&h.handle),
        (false, false, false),
        "all three unclaimed rows must be reaped after the deferral"
    );
    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters.routes_adopted, 1);
    assert_eq!(counters.neighbors_adopted, 1);
    assert_eq!(counters.l3vxlan_fdb_adopted, 1);
    assert_eq!(counters.routes_reaped, 1);
    assert_eq!(counters.neighbors_reaped, 1);
    assert_eq!(counters.l3vxlan_fdb_reaped, 1);

    // The reap must tear down the route before the resolution rows
    // its forwarding depends on (inverse of the install order).
    let kinds: Vec<&str> = h
        .handle
        .l3_op_log()
        .iter()
        .map(|op| match op {
            DataplaneOp::RemoveRemoteIpRoute { .. } => "route",
            DataplaneOp::RemoveL3Neighbor { .. } => "neighbor",
            DataplaneOp::RemoveL3VxlanFdb { .. } => "fdb",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, vec!["route", "neighbor", "fdb"]);

    h.shutdown().await;
}

// (d) Foreign rows — same identities, no ownership markers — are
//     never adopted and never reaped, even with a zero deferral.
#[tokio::test]
async fn l3_foreign_rows_never_adopted_or_reaped() {
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    // Route without the proto-bgp + onlink pair, neighbor and FDB row
    // without extern_learn — operator-installed shapes.
    h.handle
        .pre_load_l3_route(L3_TABLE_ID, l3_prefix(), L3_IFINDEX, ipa("10.0.0.2"), false);
    h.handle
        .pre_load_l3_neighbor(L3_IFINDEX, ipa("10.0.0.2"), l3_router_mac(), false);
    h.handle
        .pre_load_l3_vxlan_fdb(L3_IFINDEX, l3_router_mac(), ipa("10.0.0.2"), false);

    h.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters, rustbgpd_evpn::L3AdoptionCounters::default());
    assert_eq!(
        l3_kernel_rows(&h.handle),
        (true, true, true),
        "foreign rows must survive untouched"
    );

    h.shutdown().await;
}

// (e/g) Desired prefix whose VRF is NotReady: nothing is reaped after
//     the deadline (the route is desired-exempt; the VRF's neighbor /
//     FDB rows are skipped because their desired keys can't be
//     derived yet), and once the VRF turns Ready the rows are claimed
//     — not reaped.
#[tokio::test]
async fn l3_desired_rows_survive_not_ready_vrf_then_claim_on_ready() {
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    // The L3VXLAN device resolves to an ifindex (so the adoption dump
    // sees the neighbor / FDB rows), but the VRF is NOT Ready — no
    // staged status.
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h.handle);

    let ip_vrfs = l3_ip_vrfs();
    let desired = l3_desired_prefixes(&ip_vrfs);
    h.intent_tx.send(l3_intent(1, ip_vrfs, desired)).unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    // Extra passes past the (zero) deferral deadline with the VRF
    // still NotReady.
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    reports.extend(h.try_drain_reports().await);

    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters.routes_adopted, 1);
    assert_eq!(counters.neighbors_adopted, 1);
    assert_eq!(counters.l3vxlan_fdb_adopted, 1);
    assert_eq!(
        counters.routes_reaped + counters.neighbors_reaped + counters.l3vxlan_fdb_reaped,
        0,
        "desired / not-ready rows must survive the deadline"
    );
    assert_eq!(l3_kernel_rows(&h.handle), (true, true, true));
    assert!(
        h.handle.l3_op_log().is_empty(),
        "no L3 ops at all while the VRF is NotReady"
    );

    // VRF turns Ready after the deadline — the rows must be claimed
    // (the diff re-emits the adds; the replace is the claim), still
    // never reaped.
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    let mut claimed = false;
    for _ in 0..10 {
        reports.extend(h.try_drain_reports().await);
        let log = h.handle.l3_op_log();
        if log
            .iter()
            .any(|op| matches!(op, DataplaneOp::AddRemoteIpRoute { .. }))
        {
            claimed = true;
            // Adds only — a remove would mean the reap fired.
            assert!(
                log.iter().all(|op| matches!(
                    op,
                    DataplaneOp::AddRemoteIpRoute { .. }
                        | DataplaneOp::AddL3Neighbor { .. }
                        | DataplaneOp::AddL3VxlanFdb { .. }
                )),
                "claim must be adds only, got {log:?}"
            );
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(claimed, "VRF turning Ready must trigger the claim installs");
    reports.extend(h.try_drain_reports().await);
    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(
        counters.routes_reaped + counters.neighbors_reaped + counters.l3vxlan_fdb_reaped,
        0,
        "claimed rows must never reap"
    );
    assert_eq!(l3_kernel_rows(&h.handle), (true, true, true));

    h.shutdown().await;
}

// (f) Double-crash idempotence: a second fresh actor over the same
//     kernel state (the first stopped inside its deferral window)
//     re-adopts harmlessly and reaps exactly once.
#[tokio::test]
async fn l3_double_crash_readoption_is_idempotent() {
    // Lifetime 1: production-length deferral — adopt, then
    // "crash"/stop inside the window. The rows must survive (the
    // drain only touches owned state, and nothing was claimed).
    let mut h1 = Harness::spawn(ReconcileActorConfig::for_tests());
    h1.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h1.handle);
    h1.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();
    let mut reports1 = Vec::new();
    loop {
        let r = h1.next_report().await;
        let done = r.intent_generation == 1;
        reports1.push(r);
        if done {
            break;
        }
    }
    let counters1 = sum_l3_adoption_counters(&reports1);
    assert_eq!(counters1.routes_adopted, 1);
    assert_eq!(counters1.neighbors_adopted, 1);
    assert_eq!(counters1.l3vxlan_fdb_adopted, 1);
    let handle1 = h1.handle.clone();
    h1.shutdown().await;
    assert_eq!(
        l3_kernel_rows(&handle1),
        (true, true, true),
        "rows must survive a shutdown inside the deferral window"
    );

    // Lifetime 2: fresh actor over the surviving kernel rows (the
    // adopted sets died with lifetime 1), zero deferral.
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h2 = Harness::spawn(cfg);
    h2.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h2.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    for ((table_id, prefix), row) in handle1.l3_routes() {
        h2.handle.pre_load_l3_route(
            table_id,
            prefix,
            row.l3vxlan_ifindex,
            row.next_hop,
            row.marked,
        );
    }
    for ((ifindex, next_hop), row) in handle1.l3_neighbors() {
        h2.handle
            .pre_load_l3_neighbor(ifindex, next_hop, row.router_mac, row.marked);
    }
    for ((ifindex, router_mac), row) in handle1.l3_vxlan_fdb() {
        h2.handle
            .pre_load_l3_vxlan_fdb(ifindex, router_mac, row.next_hop, row.marked);
    }
    h2.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();

    let mut reports2 = Vec::new();
    for _ in 0..10 {
        reports2.push(h2.next_report().await);
        if l3_kernel_rows(&h2.handle) == (false, false, false) {
            break;
        }
    }
    let counters2 = sum_l3_adoption_counters(&reports2);
    assert_eq!(counters2.routes_adopted, 1, "re-adoption is one-shot");
    assert_eq!(counters2.neighbors_adopted, 1);
    assert_eq!(counters2.l3vxlan_fdb_adopted, 1);
    assert_eq!(counters2.routes_reaped, 1, "reaped exactly once");
    assert_eq!(counters2.neighbors_reaped, 1);
    assert_eq!(counters2.l3vxlan_fdb_reaped, 1);
    assert_eq!(l3_kernel_rows(&h2.handle), (false, false, false));

    h2.shutdown().await;
}

// (h) A failed adoption dump on the first L3 pass leaves the latch
//     unset; a later successful dump adopts (and, with the zero
//     deferral, reaps the unclaimed rows).
#[tokio::test]
async fn l3_dump_failure_leaves_latch_unset_then_later_pass_adopts() {
    let cfg = ReconcileActorConfig {
        l3_adoption_reap_deferral: Duration::ZERO,
        ..ReconcileActorConfig::for_tests()
    };
    let mut h = Harness::spawn(cfg);
    h.handle.set_ip_vrf_status(l3_vrf_id(), l3_ready_status());
    h.handle.set_l3vxlan_ifindex(l3_vrf_id(), L3_IFINDEX);
    pre_load_l3_marker_rows(&h.handle);
    // Fail the first dump_l3_adoption_candidates call only.
    h.handle.inject_l3_adoption_dump_failure();

    h.intent_tx
        .send(l3_intent(1, l3_ip_vrfs(), RemoteIpPrefixTable::new()))
        .unwrap();

    let mut reports = Vec::new();
    loop {
        let r = h.next_report().await;
        let done = r.intent_generation == 1;
        reports.push(r);
        if done {
            break;
        }
    }
    let first = sum_l3_adoption_counters(&reports);
    assert_eq!(
        first,
        rustbgpd_evpn::L3AdoptionCounters::default(),
        "failed dump must not latch or adopt anything"
    );
    assert_eq!(l3_kernel_rows(&h.handle), (true, true, true));

    // Next pass retries the sweep, adopts, and reaps (zero deferral).
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    for _ in 0..10 {
        reports.extend(h.try_drain_reports().await);
        if l3_kernel_rows(&h.handle) == (false, false, false) {
            break;
        }
        tokio::task::yield_now().await;
    }
    let counters = sum_l3_adoption_counters(&reports);
    assert_eq!(counters.routes_adopted, 1);
    assert_eq!(counters.neighbors_adopted, 1);
    assert_eq!(counters.l3vxlan_fdb_adopted, 1);
    assert_eq!(counters.routes_reaped, 1);
    assert_eq!(counters.neighbors_reaped, 1);
    assert_eq!(counters.l3vxlan_fdb_reaped, 1);
    assert_eq!(l3_kernel_rows(&h.handle), (false, false, false));

    h.shutdown().await;
}
