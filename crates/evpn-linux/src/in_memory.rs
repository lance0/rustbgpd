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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, MacAddress};
use tokio::sync::mpsc;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{
    InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelSnapshot,
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
            Self::KernelTooOld => DataplaneError::KernelTooOld,
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
        Self {
            state: Arc::new(Mutex::new(State {
                kernel: KernelSnapshot::new(),
                probes: InstanceProbes::new(),
                failures: VecDeque::new(),
                apply_count: 0,
            })),
            events_rx,
            events_tx,
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
        }
        Ok(())
    }
}

/// Test-side handle for inspecting / mutating fake state.
#[derive(Debug, Clone)]
pub struct InMemoryHandle {
    state: Arc<Mutex<State>>,
    events_tx: mpsc::Sender<KernelEvent>,
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
}
