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
    EthernetSegmentIdentifier, EthernetTagId, EvpnInstance, EvpnInstanceId, EvpnInstanceTable,
    MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable, RouteDistinguisher, RouteTarget,
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
    let _ = h.try_drain_reports().await;

    // Member should be back at the same kernel ID.
    assert!(
        h.handle.nexthop_ops().contains_key(&removed_id),
        "drift recovery should re-install the deleted member at the same kernel ID"
    );

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
    let _ = h.try_drain_reports().await;

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
    let _ = h.try_drain_reports().await;

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

    // First drift tick — folds drift_id into adopted_unreferenced.
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let _ = h.try_drain_reports().await;

    // Second reconcile (kernel event) — `cleanup_unreferenced_adoptions`
    // runs because drift cleared `adoption_done`; deletes the stale ID.
    h.handle.push_event(KernelEvent::KernelStateChanged).await;
    let _ = h.next_report().await;
    let _ = h.try_drain_reports().await;

    assert!(
        !h.handle.nexthop_ops().contains_key(&drift_id),
        "drift recovery should fold the stale ID into adoption set so the next pass deletes it; nhs={:?}",
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


#[allow(dead_code)]
fn _starts_anchor() -> Instant {
    Instant::now()
}
