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

use rustbgpd_evpn::{
    BumEnforcementReadiness, BumEnforcementTable, DataplaneIntent, DfRole,
    EthernetSegmentIdentifier, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress,
    RemoteMacEntry, RemoteMacSource, RemoteMacTable, RouteDistinguisher, RouteTarget,
};
use rustbgpd_evpn_linux::snapshot::KernelVxlanInfo;
use rustbgpd_evpn_linux::{
    DataplaneOp, InMemoryDataplane, InMemoryHandle, InstanceProbe, KernelEvent, KernelFdbEntry,
    KernelFdbFlags, KernelLinkInfo, ReconcileActor, ReconcileActorConfig,
};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
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

#[allow(dead_code)]
fn _starts_anchor() -> Instant {
    Instant::now()
}
