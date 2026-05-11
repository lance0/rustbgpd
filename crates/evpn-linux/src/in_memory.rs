//! [`InMemoryDataplane`] — the test fake.
//!
//! Implements [`Dataplane`] without touching netlink. Phase 3's
//! reconcile actor tests drive this implementation end-to-end:
//!
//! - kernel state lives in a `Mutex<KernelSnapshot>` the test can
//!   pre-load with foreign entries before the actor starts;
//! - probes are static — set per-VNI in the constructor;
//! - apply writes to the snapshot if a matching `inject_failure` rule
//!   doesn't intercept;
//! - kernel events are pumped through an mpsc the test owns.
//!
//! This is the fake the `compute_diff` tests don't need (those are
//! pure), but Phase 3 will need to drive a complete actor lifecycle.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, LocalMacObservation, MacAddress};
use tokio::sync::mpsc;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{
    InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelLinkInfo, KernelSnapshot,
};

/// Test fake of [`Dataplane`].
///
/// All shared state lives behind one `Mutex` because the actor calls
/// trait methods serially — the lock is uncontended in the actor's
/// happy path. Tests drive concurrent state by holding their own
/// reference (via [`InMemoryDataplane::handle`]) and mutating
/// independently.
#[derive(Debug)]
pub struct InMemoryDataplane {
    state: Arc<Mutex<State>>,
    events_rx: mpsc::Receiver<KernelEvent>,
    events_tx: mpsc::Sender<KernelEvent>,
    /// Upward `LocalMacObservation` channel — handed to the daemon's
    /// originator via [`Dataplane::take_local_mac_rx`]. Held as
    /// `Option` so the take-once semantic surfaces cleanly: returns
    /// `Some(rx)` on the first call, `None` thereafter.
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    /// Sender side — kept alive on the dataplane so the test handle's
    /// `inject_local_mac_observation` can publish even after the
    /// originator has taken the receiver.
    local_mac_tx: mpsc::Sender<LocalMacObservation>,
}

#[derive(Debug)]
struct State {
    kernel: KernelSnapshot,
    probes: InstanceProbes,
    /// Failure injection — popped FIFO. Each entry is consumed once
    /// per matching `apply` call; once the queue empties, applies
    /// succeed normally. Tests use this to validate the actor's
    /// retry-with-backoff path.
    failures: VecDeque<InjectedFailure>,
    /// Counter — total apply calls (including failed ones). Tests
    /// assert this against expectations.
    apply_count: usize,
    /// Recorded `SetBumPortFlags` calls keyed by ifindex. Tests use
    /// this to assert the reconciler issued the expected per-port
    /// flag triplet — the in-memory backend doesn't have a real
    /// kernel to inspect.
    bum_port_flags: std::collections::BTreeMap<u32, crate::bum_filter::BumPortFlags>,
}

#[derive(Debug, Clone)]
struct InjectedFailure {
    /// If `None`, fails the next apply regardless of op shape. If
    /// `Some`, fails only when applying matching ops.
    target: Option<DataplaneOp>,
    error: ErrorTemplate,
}

#[derive(Debug, Clone)]
enum ErrorTemplate {
    Io,
    Other(String),
    KernelTooOld,
}

impl ErrorTemplate {
    fn realize(&self) -> DataplaneError {
        match self {
            Self::Io => DataplaneError::Io(std::io::Error::other("injected I/O failure")),
            Self::Other(s) => DataplaneError::Other(s.clone()),
            Self::KernelTooOld => DataplaneError::KernelTooOld {
                feature: "injected feature".to_string(),
            },
        }
    }
}

impl InMemoryDataplane {
    /// Construct a fake with empty kernel state and no probes set.
    /// All instances default to `NotReady` until
    /// [`InMemoryHandle::set_probe`] records an explicit result.
    #[must_use]
    pub fn new() -> Self {
        let (events_tx, events_rx) = mpsc::channel(64);
        // 1024-slot upward observation buffer matches the bound the
        // originator advertises (see `src/evpn_originator.rs`); tests
        // can fill it to exercise overflow handling.
        let (local_mac_tx, local_mac_rx) = mpsc::channel(1024);
        Self {
            state: Arc::new(Mutex::new(State {
                kernel: KernelSnapshot::new(),
                probes: InstanceProbes::new(),
                failures: VecDeque::new(),
                apply_count: 0,
                bum_port_flags: std::collections::BTreeMap::new(),
            })),
            events_rx,
            events_tx,
            local_mac_rx: Some(local_mac_rx),
            local_mac_tx,
        }
    }

    /// Cloneable test handle for in-process state inspection /
    /// mutation. Tests typically grab a handle before the actor
    /// starts, then use it to pre-load kernel entries, set probes,
    /// inject failures, and assert apply counts.
    #[must_use]
    pub fn handle(&self) -> InMemoryHandle {
        InMemoryHandle {
            state: Arc::clone(&self.state),
            events_tx: self.events_tx.clone(),
            local_mac_tx: self.local_mac_tx.clone(),
        }
    }
}

impl Default for InMemoryDataplane {
    fn default() -> Self {
        Self::new()
    }
}

impl Dataplane for InMemoryDataplane {
    fn probe(
        &mut self,
        _instances: &EvpnInstanceTable,
    ) -> impl Future<Output = InstanceProbes> + Send {
        let probes = self.state.lock().expect("poisoned").probes.clone();
        async move { probes }
    }

    fn dump_snapshot(
        &mut self,
    ) -> impl Future<Output = Result<KernelSnapshot, DataplaneError>> + Send {
        let snap = self.state.lock().expect("poisoned").kernel.clone();
        async move { Ok(snap) }
    }

    fn apply(
        &mut self,
        op: &DataplaneOp,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        let result = self.apply_inner(op);
        async move { result }
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // The receiver lifetime is tied to &mut self for the duration
        // of the await. tokio::sync::mpsc::Receiver::recv takes &mut
        // self so this is exactly the borrow shape we want.
        self.events_rx.recv()
    }

    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        self.local_mac_rx.take()
    }
}

impl InMemoryDataplane {
    /// Synchronous half of `apply` — does the fail-injection lookup
    /// and the kernel-state mutation under the same lock so the test
    /// can't observe a partially-applied op.
    fn apply_inner(&self, op: &DataplaneOp) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        state.apply_count += 1;

        // Look for a matching failure injection. Pop on match.
        if let Some(idx) = state.failures.iter().position(|f| match &f.target {
            None => true,
            Some(target) => target == op,
        }) {
            let failure = state.failures.remove(idx).unwrap();
            return Err(failure.error.realize());
        }

        match op {
            DataplaneOp::AddRemoteFdb { vni, mac, dst }
            | DataplaneOp::UpdateRemoteFdb { vni, mac, dst } => {
                state.kernel.insert_fdb(
                    *vni,
                    KernelFdbEntry {
                        mac: *mac,
                        dst: Some(*dst),
                        flags: KernelFdbFlags {
                            extern_learn: true,
                            master: true,
                            ..Default::default()
                        },
                    },
                );
            }
            DataplaneOp::RemoveRemoteFdb { vni, mac } => {
                state.kernel.remove_fdb(*vni, *mac);
            }
            DataplaneOp::SetBumPortFlags { ifindex, flags } => {
                state.bum_port_flags.insert(*ifindex, *flags);
            }
            // Gate 9 slice 6c L3 ops are out of scope for the
            // in-memory fake — the L3 install path's logic is unit-
            // tested directly via `linux::l3` build helpers, and the
            // netns integration test (`EVPN_LINUX_NETNS=1`) exercises
            // the real kernel apply path. The L3 reconciler diff loop
            // doesn't route ops through this fake.
            DataplaneOp::AddRemoteIpRoute { .. }
            | DataplaneOp::RemoveRemoteIpRoute { .. }
            | DataplaneOp::AddL3Neighbor { .. }
            | DataplaneOp::RemoveL3Neighbor { .. }
            | DataplaneOp::AddL3VxlanFdb { .. }
            | DataplaneOp::RemoveL3VxlanFdb { .. } => {}
        }
        Ok(())
    }
}

/// Test-side handle for inspecting / mutating fake state.
#[derive(Debug, Clone)]
pub struct InMemoryHandle {
    state: Arc<Mutex<State>>,
    events_tx: mpsc::Sender<KernelEvent>,
    local_mac_tx: mpsc::Sender<LocalMacObservation>,
}

// Every method panics only on Mutex lock-poisoning, which is
// unrecoverable in this test fake. Documenting `# Panics` on each
// would be noise; suppress at the impl level.
#[allow(clippy::missing_panics_doc)]
impl InMemoryHandle {
    /// Pre-load a foreign FDB entry the actor must preserve.
    pub fn pre_load_fdb(&self, vni: EvpnInstanceId, entry: KernelFdbEntry) {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .insert_fdb(vni, entry);
    }

    /// Replace the fake link inventory wholesale.
    pub fn set_links(&self, links: BTreeMap<String, KernelLinkInfo>) {
        self.state.lock().expect("poisoned").kernel.set_links(links);
    }

    /// Set the probe outcome for one instance.
    pub fn set_probe(&self, vni: EvpnInstanceId, probe: InstanceProbe) {
        self.state
            .lock()
            .expect("poisoned")
            .probes
            .insert(vni, probe);
    }

    /// Inject a failure for the next matching apply call. `target =
    /// None` matches any op.
    pub fn inject_failure_io(&self, target: Option<DataplaneOp>) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::Io,
            });
    }

    /// Inject an `Other` failure with a fixed message.
    pub fn inject_failure_other(&self, target: Option<DataplaneOp>, msg: &str) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::Other(msg.to_owned()),
            });
    }

    /// Inject a `KernelTooOld` failure (permanent, unretryable).
    pub fn inject_failure_kernel_too_old(&self, target: Option<DataplaneOp>) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::KernelTooOld,
            });
    }

    /// Push a kernel event to wake the actor's select! loop.
    pub async fn push_event(&self, event: KernelEvent) {
        // Sending to a closed channel just means the actor already
        // tore down; tests treat that as harmless.
        let _ = self.events_tx.send(event).await;
    }

    /// Inject an upward `LocalMacObservation` for the daemon-side
    /// originator to consume.
    ///
    /// Tests typically:
    /// 1. Call `Dataplane::take_local_mac_rx` to hand the receiver to
    ///    the originator under test;
    /// 2. Call this method to push synthetic Learn / Aged events.
    pub async fn inject_local_mac_observation(&self, obs: LocalMacObservation) {
        let _ = self.local_mac_tx.send(obs).await;
    }

    /// Synchronous, non-async variant — `try_send` returns
    /// `Err(TrySendError::Full)` if the buffer is full. Used by the
    /// overflow-handling tests.
    ///
    /// # Errors
    /// Forwards the underlying [`mpsc::error::TrySendError`].
    pub fn try_inject_local_mac_observation(
        &self,
        obs: LocalMacObservation,
    ) -> Result<(), mpsc::error::TrySendError<LocalMacObservation>> {
        self.local_mac_tx.try_send(obs)
    }

    /// Total apply attempts recorded so far.
    #[must_use]
    pub fn apply_count(&self) -> usize {
        self.state.lock().expect("poisoned").apply_count
    }

    /// Snapshot the kernel state for assertion.
    #[must_use]
    pub fn kernel_snapshot(&self) -> KernelSnapshot {
        self.state.lock().expect("poisoned").kernel.clone()
    }

    /// `true` if the kernel snapshot contains an FDB entry for
    /// `(vni, mac)`.
    #[must_use]
    pub fn kernel_has_fdb(&self, vni: EvpnInstanceId, mac: MacAddress) -> bool {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .find_fdb(vni, mac)
            .is_some()
    }

    /// Snapshot the recorded `SetBumPortFlags` state by ifindex.
    /// Tests use this to assert the reconciler issued the expected
    /// per-port flag triplet.
    #[must_use]
    pub fn bum_port_flags(
        &self,
    ) -> std::collections::BTreeMap<u32, crate::bum_filter::BumPortFlags> {
        self.state.lock().expect("poisoned").bum_port_flags.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn apply_round_trip_program_then_remove() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let op_add = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            dst: ip("10.0.0.2"),
        };
        dp.apply(&op_add).await.unwrap();
        assert!(h.kernel_has_fdb(vni(100), mac(1)));

        let op_rem = DataplaneOp::RemoveRemoteFdb {
            vni: vni(100),
            mac: mac(1),
        };
        dp.apply(&op_rem).await.unwrap();
        assert!(!h.kernel_has_fdb(vni(100), mac(1)));
        assert_eq!(h.apply_count(), 2);
    }

    #[tokio::test]
    async fn injected_io_failure_surfaces_through_apply() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let op = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            dst: ip("10.0.0.2"),
        };
        h.inject_failure_io(Some(op.clone()));
        let err = dp.apply(&op).await.unwrap_err();
        assert!(matches!(err, DataplaneError::Io(_)));
        // Subsequent apply with the same op now succeeds (the
        // injection was popped).
        dp.apply(&op).await.unwrap();
    }

    #[tokio::test]
    async fn set_bum_port_flags_records_per_ifindex_state() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();

        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 10,
            flags: crate::bum_filter::BumPortFlags::suppress_all(),
        })
        .await
        .unwrap();
        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 11,
            flags: crate::bum_filter::BumPortFlags::allow_all(),
        })
        .await
        .unwrap();

        let recorded = h.bum_port_flags();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[&10],
            crate::bum_filter::BumPortFlags::suppress_all()
        );
        assert_eq!(recorded[&11], crate::bum_filter::BumPortFlags::allow_all());

        // Reapply with new flags overwrites — idempotent at the
        // ifindex granularity.
        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 10,
            flags: crate::bum_filter::BumPortFlags::allow_all(),
        })
        .await
        .unwrap();
        let recorded = h.bum_port_flags();
        assert_eq!(recorded[&10], crate::bum_filter::BumPortFlags::allow_all());
        assert_eq!(recorded.len(), 2, "ifindex 11 still present");
    }

    #[tokio::test]
    async fn injected_failure_with_no_target_matches_any_op() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.inject_failure_other(None, "boom");
        let op = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            dst: ip("10.0.0.2"),
        };
        assert!(dp.apply(&op).await.is_err());
    }

    #[tokio::test]
    async fn probe_returns_recorded_outcomes() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.set_probe(vni(100), InstanceProbe::Ready);
        h.set_probe(vni(200), InstanceProbe::NotReady { reason: "x".into() });
        let probes = dp.probe(&EvpnInstanceTable::new()).await;
        assert!(probes.is_ready(vni(100)));
        assert!(!probes.is_ready(vni(200)));
    }

    #[tokio::test]
    async fn pushed_kernel_event_arrives_via_next_event() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.push_event(KernelEvent::KernelStateChanged).await;
        let evt = dp.next_event().await;
        assert_eq!(evt, Some(KernelEvent::KernelStateChanged));
    }

    #[tokio::test]
    async fn pre_loaded_fdb_visible_in_dump() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.pre_load_fdb(
            vni(100),
            KernelFdbEntry {
                mac: mac(9),
                dst: None,
                flags: KernelFdbFlags::default(),
            },
        );
        let snap = dp.dump_snapshot().await.unwrap();
        assert!(snap.find_fdb(vni(100), mac(9)).is_some());
    }

    #[tokio::test]
    async fn local_mac_observation_round_trip() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let mut rx = dp
            .take_local_mac_rx()
            .expect("first take returns the receiver");
        // Subsequent take returns None (single-take semantic).
        assert!(dp.take_local_mac_rx().is_none());

        h.inject_local_mac_observation(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(1),
            ifindex: 42,
        })
        .await;
        h.inject_local_mac_observation(LocalMacObservation::Aged {
            vni: vni(100),
            mac: mac(1),
        })
        .await;

        let learned = rx.recv().await.unwrap();
        assert!(matches!(learned, LocalMacObservation::Learned { .. }));
        let aged = rx.recv().await.unwrap();
        assert!(matches!(aged, LocalMacObservation::Aged { .. }));
    }

    #[tokio::test]
    async fn local_mac_observation_buffer_overflow_surfaces_full() {
        // Channel capacity is 1024 — fill it without draining and the
        // next try_send must surface `Full`.
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        // Holding the rx alive without recv'ing keeps the buffer full.
        let _rx = dp.take_local_mac_rx().expect("rx");

        for i in 0..1024u32 {
            h.try_inject_local_mac_observation(LocalMacObservation::Learned {
                vni: vni(100),
                mac: MacAddress::new([(i & 0xff) as u8; 6]),
                ifindex: i,
            })
            .expect("buffer not yet full");
        }
        // Slot 1025 must error.
        let err = h
            .try_inject_local_mac_observation(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xff),
                ifindex: 9999,
            })
            .expect_err("buffer should be full");
        assert!(matches!(err, mpsc::error::TrySendError::Full(_)));
    }
}
