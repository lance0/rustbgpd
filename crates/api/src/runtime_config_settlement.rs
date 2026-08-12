//! Process-independent settlement watchdog for owned runtime-config mutations.
//!
//! This module supplies the fail-stop ownership kernel. Call sites arm it only
//! after acquiring [`RuntimeConfigCoordinatorPermit`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::health_probe::DaemonGate;
use crate::server::{RuntimeConfigCoordinator, RuntimeConfigCoordinatorPermit};

/// Fixed maximum time from coordinator ownership to proved settlement.
pub const OWNED_SETTLEMENT_BUDGET: Duration = Duration::from_mins(30);
/// Fixed propagation interval between fencing and fail-stop.
pub const AMBIGUITY_FENCE_GRACE: Duration = Duration::from_secs(5);
/// Process exit status used after an ambiguous runtime-config mutation.
pub const AMBIGUOUS_CONFIG_EXIT_STATUS: i32 = 70;

/// Closed roster of runtime-config operations that can own the coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigOperationKind {
    Apply,
    Rollback,
    Confirm,
    Abort,
    AutoRevert,
    GnmiSet,
    Sighup,
    NeighborAdd,
    NeighborDelete,
    DynamicNeighborAdd,
    DynamicNeighborDelete,
    FibTableSet,
    FibTableDelete,
    PeerGroupSet,
    PeerGroupDelete,
    PeerGroupSetNeighbor,
    PeerGroupClearNeighbor,
    PolicySet,
    PolicyDelete,
    PolicyNeighborSet,
    PolicyNeighborSetDelete,
    PolicyGlobalImportSet,
    PolicyGlobalExportSet,
    PolicyGlobalImportClear,
    PolicyGlobalExportClear,
    PolicyNeighborImportSet,
    PolicyNeighborExportSet,
    PolicyNeighborImportClear,
    PolicyNeighborExportClear,
}

/// Monotonic nonterminal phase of an owned mutation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimeConfigSettlementPhase {
    OwnedPreflight,
    Mutating,
    SettlingRollback,
}

/// Immutable terminal state of an owned mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigSettlementTerminal {
    Owned,
    Settled,
    AmbiguousFenced,
}

/// Cause of an ambiguity fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigFenceReason {
    BudgetExpired,
    ExecutorLost,
}

const TERMINAL_OWNED: u8 = 0;
const TERMINAL_SETTLED: u8 = 1;
const TERMINAL_AMBIGUOUS: u8 = 2;
const PHASE_PREFLIGHT: u8 = 0;
const PHASE_MUTATING: u8 = 1;
const PHASE_SETTLING: u8 = 2;
const AMBIGUITY_REASON_NONE: u8 = 0;
const AMBIGUITY_REASON_BUDGET: u8 = 1;
const AMBIGUITY_REASON_EXECUTOR: u8 = 2;
const AMBIGUITY_NOT_READY: &str = "runtime config settlement is ambiguous";

#[derive(Debug)]
struct OwnedResources {
    _coordinator_permit: RuntimeConfigCoordinatorPermit,
    _stream_permit: Option<OwnedSemaphorePermit>,
    stream_admission: Option<Arc<Semaphore>>,
}

struct OperationInner {
    id: u64,
    kind: RuntimeConfigOperationKind,
    deadline: Instant,
    phase: AtomicU8,
    terminal: AtomicU8,
    fence_reason: AtomicU8,
    response_attached: AtomicBool,
    coordinator: RuntimeConfigCoordinator,
    daemon_gate: DaemonGate,
    resources: Mutex<Option<OwnedResources>>,
    registry: Arc<Registry>,
}

impl std::fmt::Debug for OperationInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationInner")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Registration {
    operation: Arc<OperationInner>,
    terminal_at: Instant,
}

struct RegistryState {
    registrations: HashMap<u64, Registration>,
    stopping: bool,
}

enum TerminalAction {
    Exit(fn(i32) -> !),
    #[cfg(test)]
    Notify(std::sync::mpsc::Sender<i32>),
}

struct Registry {
    state: Mutex<RegistryState>,
    wake: Condvar,
    next_id: AtomicU64,
    budget: Duration,
    grace: Duration,
    terminal: TerminalAction,
    thread_id: Mutex<Option<thread::ThreadId>>,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn unregister(&self, id: u64) {
        self.lock().registrations.remove(&id);
        self.wake.notify_one();
    }

    fn advance_terminal(&self, id: u64, when: Instant) {
        if let Some(registration) = self.lock().registrations.get_mut(&id) {
            registration.terminal_at = when;
        }
        self.wake.notify_one();
    }
}

/// Cloneable owner of one OS-thread clock multiplexer.
#[derive(Clone)]
pub struct RuntimeConfigSettlementWatchdog {
    registry: Arc<Registry>,
}

impl std::fmt::Debug for RuntimeConfigSettlementWatchdog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeConfigSettlementWatchdog")
            .finish_non_exhaustive()
    }
}

impl RuntimeConfigSettlementWatchdog {
    /// Start the process watchdog using fixed production durations.
    #[must_use]
    pub fn new(exit: fn(i32) -> !) -> Self {
        Self::start(
            OWNED_SETTLEMENT_BUDGET,
            AMBIGUITY_FENCE_GRACE,
            TerminalAction::Exit(exit),
        )
    }

    fn start(budget: Duration, grace: Duration, terminal: TerminalAction) -> Self {
        let registry = Arc::new(Registry {
            state: Mutex::new(RegistryState {
                registrations: HashMap::new(),
                stopping: false,
            }),
            wake: Condvar::new(),
            next_id: AtomicU64::new(1),
            budget,
            grace,
            terminal,
            thread_id: Mutex::new(None),
        });
        let thread_registry = Arc::clone(&registry);
        thread::Builder::new()
            .name("config-settlement-watchdog".into())
            .spawn(move || watchdog_loop(&thread_registry))
            .expect("config settlement watchdog OS thread must start");
        Self { registry }
    }

    /// Register resources after physical coordinator ownership is acquired.
    pub fn register_owned(
        &self,
        kind: RuntimeConfigOperationKind,
        coordinator: RuntimeConfigCoordinator,
        coordinator_permit: RuntimeConfigCoordinatorPermit,
        daemon_gate: DaemonGate,
        stream_permit: Option<OwnedSemaphorePermit>,
        stream_admission: Option<Arc<Semaphore>>,
    ) -> (OwnedRuntimeConfigOperation, RuntimeConfigExecutorGuard) {
        let deadline = Instant::now() + self.registry.budget;
        let id = self.registry.next_id.fetch_add(1, Ordering::Relaxed);
        let operation = Arc::new(OperationInner {
            id,
            kind,
            deadline,
            phase: AtomicU8::new(PHASE_PREFLIGHT),
            terminal: AtomicU8::new(TERMINAL_OWNED),
            fence_reason: AtomicU8::new(AMBIGUITY_REASON_NONE),
            response_attached: AtomicBool::new(true),
            coordinator,
            daemon_gate,
            resources: Mutex::new(Some(OwnedResources {
                _coordinator_permit: coordinator_permit,
                _stream_permit: stream_permit,
                stream_admission,
            })),
            registry: Arc::clone(&self.registry),
        });
        self.registry.lock().registrations.insert(
            id,
            Registration {
                operation: Arc::clone(&operation),
                terminal_at: deadline + self.registry.grace,
            },
        );
        self.registry.wake.notify_one();
        (
            OwnedRuntimeConfigOperation {
                inner: Arc::clone(&operation),
            },
            RuntimeConfigExecutorGuard {
                inner: Some(operation),
            },
        )
    }
}

/// Handle used by the daemon-owned operation to report progress and settlement.
#[derive(Clone, Debug)]
pub struct OwnedRuntimeConfigOperation {
    inner: Arc<OperationInner>,
}

impl OwnedRuntimeConfigOperation {
    #[must_use]
    pub fn kind(&self) -> RuntimeConfigOperationKind {
        self.inner.kind
    }

    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.inner.deadline
    }

    #[must_use]
    pub fn phase(&self) -> RuntimeConfigSettlementPhase {
        match self.inner.phase.load(Ordering::Acquire) {
            PHASE_PREFLIGHT => RuntimeConfigSettlementPhase::OwnedPreflight,
            PHASE_MUTATING => RuntimeConfigSettlementPhase::Mutating,
            _ => RuntimeConfigSettlementPhase::SettlingRollback,
        }
    }

    /// Advance the phase monotonically. Regressions are ignored.
    pub fn advance_phase(&self, phase: RuntimeConfigSettlementPhase) {
        let desired = match phase {
            RuntimeConfigSettlementPhase::OwnedPreflight => PHASE_PREFLIGHT,
            RuntimeConfigSettlementPhase::Mutating => PHASE_MUTATING,
            RuntimeConfigSettlementPhase::SettlingRollback => PHASE_SETTLING,
        };
        self.inner.phase.fetch_max(desired, Ordering::AcqRel);
    }

    #[must_use]
    pub fn terminal(&self) -> RuntimeConfigSettlementTerminal {
        match self.inner.terminal.load(Ordering::Acquire) {
            TERMINAL_OWNED => RuntimeConfigSettlementTerminal::Owned,
            TERMINAL_SETTLED => RuntimeConfigSettlementTerminal::Settled,
            _ => RuntimeConfigSettlementTerminal::AmbiguousFenced,
        }
    }

    #[must_use]
    pub fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        match self.inner.fence_reason.load(Ordering::Acquire) {
            AMBIGUITY_REASON_BUDGET => Some(RuntimeConfigFenceReason::BudgetExpired),
            AMBIGUITY_REASON_EXECUTOR => Some(RuntimeConfigFenceReason::ExecutorLost),
            _ => None,
        }
    }

    /// Mark whether a transport is still waiting; this never changes ownership.
    pub fn set_response_attached(&self, attached: bool) {
        self.inner
            .response_attached
            .store(attached, Ordering::Release);
    }

    #[must_use]
    pub fn response_attached(&self) -> bool {
        self.inner.response_attached.load(Ordering::Acquire)
    }

    /// Prove settlement and release physical ownership. Returns false after fencing.
    pub fn try_settle(&self) -> bool {
        if self
            .inner
            .terminal
            .compare_exchange(
                TERMINAL_OWNED,
                TERMINAL_SETTLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.inner.registry.unregister(self.inner.id);
        let resources = self
            .inner
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(resources);
        true
    }
}

/// Drop sentinel for loss of the daemon-owned executor after ownership.
#[must_use = "keep the executor guard alive until settlement is proved"]
#[derive(Debug)]
pub struct RuntimeConfigExecutorGuard {
    inner: Option<Arc<OperationInner>>,
}

impl Drop for RuntimeConfigExecutorGuard {
    fn drop(&mut self) {
        let Some(operation) = self.inner.take() else {
            return;
        };
        fence(&operation, RuntimeConfigFenceReason::ExecutorLost);
    }
}

fn fence(operation: &Arc<OperationInner>, reason: RuntimeConfigFenceReason) -> bool {
    if operation
        .terminal
        .compare_exchange(
            TERMINAL_OWNED,
            TERMINAL_AMBIGUOUS,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }
    let reason_value = match reason {
        RuntimeConfigFenceReason::BudgetExpired => AMBIGUITY_REASON_BUDGET,
        RuntimeConfigFenceReason::ExecutorLost => AMBIGUITY_REASON_EXECUTOR,
    };
    operation
        .fence_reason
        .store(reason_value, Ordering::Release);
    operation.daemon_gate.mark_not_ready(AMBIGUITY_NOT_READY);
    operation.daemon_gate.begin_shutdown();
    operation.coordinator.close();
    if let Some(admission) = operation
        .resources
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|resources| resources.stream_admission.as_ref())
    {
        admission.close();
    }
    operation
        .registry
        .advance_terminal(operation.id, Instant::now() + operation.registry.grace);
    true
}

fn watchdog_loop(registry: &Arc<Registry>) {
    *registry
        .thread_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(thread::current().id());
    loop {
        let now = Instant::now();
        let (expired, terminal, wait) = {
            let state = registry.lock();
            if state.stopping {
                return;
            }
            let expired = state
                .registrations
                .values()
                .filter(|entry| {
                    entry.operation.terminal.load(Ordering::Acquire) == TERMINAL_OWNED
                        && entry.operation.deadline <= now
                })
                .map(|entry| Arc::clone(&entry.operation))
                .collect::<Vec<_>>();
            let terminal = state
                .registrations
                .values()
                .find(|entry| {
                    entry.operation.terminal.load(Ordering::Acquire) == TERMINAL_AMBIGUOUS
                        && entry.terminal_at <= now
                })
                .map(|entry| Arc::clone(&entry.operation));
            let wait = state
                .registrations
                .values()
                .map(|entry| {
                    if entry.operation.terminal.load(Ordering::Acquire) == TERMINAL_OWNED {
                        entry.operation.deadline
                    } else {
                        entry.terminal_at
                    }
                })
                .min()
                .map_or(registry.budget, |next| next.saturating_duration_since(now));
            (expired, terminal, wait)
        };
        for operation in expired {
            fence(&operation, RuntimeConfigFenceReason::BudgetExpired);
        }
        if let Some(operation) = terminal {
            run_terminal_action(registry, &operation);
        }
        let state = registry.lock();
        drop(
            registry
                .wake
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }
}

#[cfg(not(test))]
fn run_terminal_action(registry: &Registry, _operation: &OperationInner) -> ! {
    match registry.terminal {
        TerminalAction::Exit(exit) => exit(AMBIGUOUS_CONFIG_EXIT_STATUS),
    }
}

#[cfg(test)]
fn run_terminal_action(registry: &Registry, operation: &OperationInner) {
    match &registry.terminal {
        TerminalAction::Exit(exit) => exit(AMBIGUOUS_CONFIG_EXIT_STATUS),
        TerminalAction::Notify(sender) => {
            let _ = sender.send(AMBIGUOUS_CONFIG_EXIT_STATUS);
            registry.unregister(operation.id);
            operation
                .resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_watchdog(
        budget: Duration,
        grace: Duration,
    ) -> (
        RuntimeConfigSettlementWatchdog,
        std::sync::mpsc::Receiver<i32>,
    ) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (
            RuntimeConfigSettlementWatchdog::start(budget, grace, TerminalAction::Notify(sender)),
            receiver,
        )
    }

    async fn operation(
        watchdog: &RuntimeConfigSettlementWatchdog,
        stream: bool,
    ) -> (
        OwnedRuntimeConfigOperation,
        RuntimeConfigExecutorGuard,
        RuntimeConfigCoordinator,
        Option<Arc<Semaphore>>,
    ) {
        let coordinator = RuntimeConfigCoordinator::new();
        let permit = coordinator.acquire().await.unwrap();
        let admission = stream.then(|| Arc::new(Semaphore::new(1)));
        let stream_permit = match &admission {
            Some(value) => Some(value.clone().acquire_owned().await.unwrap()),
            None => None,
        };
        let (operation, guard) = watchdog.register_owned(
            RuntimeConfigOperationKind::Apply,
            coordinator.clone(),
            permit,
            DaemonGate::new(),
            stream_permit,
            admission.clone(),
        );
        (operation, guard, coordinator, admission)
    }

    #[test]
    fn constants_and_closed_states_are_exact() {
        assert_eq!(OWNED_SETTLEMENT_BUDGET, Duration::from_mins(30));
        assert_eq!(AMBIGUITY_FENCE_GRACE, Duration::from_secs(5));
        assert_eq!(AMBIGUOUS_CONFIG_EXIT_STATUS, 70);
        assert_eq!(RuntimeConfigSettlementTerminal::Owned as u8, 0);
        assert_eq!(RuntimeConfigFenceReason::BudgetExpired as u8, 0);
    }

    #[tokio::test]
    async fn phase_is_monotonic_and_deadline_is_fixed() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let deadline = operation.deadline();
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        operation.advance_phase(RuntimeConfigSettlementPhase::OwnedPreflight);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::SettlingRollback
        );
        assert_eq!(operation.deadline(), deadline);
        assert!(operation.try_settle());
        drop(guard);
    }

    #[tokio::test]
    async fn settlement_releases_both_permits() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        let coordinator_waiter = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.acquire().await }
        });
        let admission_waiter = tokio::spawn(admission.unwrap().acquire_owned());
        assert!(operation.try_settle());
        drop(guard);
        assert!(coordinator_waiter.await.unwrap().is_ok());
        assert!(admission_waiter.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn executor_loss_fences_before_resources_release() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        drop(guard);
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::AmbiguousFenced
        );
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::ExecutorLost)
        );
        assert!(coordinator.is_closed());
        assert!(admission.unwrap().is_closed());
        assert!(!operation.try_settle());
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
    }

    #[tokio::test(start_paused = true)]
    async fn std_thread_deadline_ignores_paused_tokio_clock_and_detach() {
        let (watchdog, receiver) =
            test_watchdog(Duration::from_millis(40), Duration::from_millis(20));
        let (operation, guard, coordinator, _) = operation(&watchdog, false).await;
        operation.set_response_attached(false);
        assert!(!operation.response_attached());
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        assert!(coordinator.is_closed());
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::BudgetExpired)
        );
        drop(guard);
    }

    #[tokio::test]
    async fn many_settlements_leave_no_registrations_and_share_thread() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let thread_id = loop {
            if let Some(thread_id) = *watchdog.registry.thread_id.lock().unwrap() {
                break thread_id;
            }
            thread::yield_now();
        };
        for _ in 0..32 {
            let (operation, guard, _, _) = operation(&watchdog, false).await;
            assert!(operation.try_settle());
            drop(guard);
        }
        assert!(watchdog.registry.lock().registrations.is_empty());
        assert_eq!(
            *watchdog.registry.thread_id.lock().unwrap(),
            Some(thread_id)
        );
    }

    #[tokio::test]
    async fn settlement_and_executor_loss_have_exactly_one_winner() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let settle = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.try_settle()
            })
        };
        let lose = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                drop(guard);
            })
        };
        barrier.wait();
        let settled = settle.join().unwrap();
        lose.join().unwrap();
        assert_eq!(
            settled,
            operation.terminal() == RuntimeConfigSettlementTerminal::Settled
        );
        if settled {
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        } else {
            assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        }
    }

    #[tokio::test]
    async fn settlement_and_deadline_have_exactly_one_winner() {
        let (watchdog, receiver) =
            test_watchdog(Duration::from_millis(2), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        thread::sleep(Duration::from_millis(2));
        let settled = operation.try_settle();
        assert_eq!(
            settled,
            operation.terminal() == RuntimeConfigSettlementTerminal::Settled
        );
        if settled {
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        } else {
            assert_eq!(
                operation.fence_reason(),
                Some(RuntimeConfigFenceReason::BudgetExpired)
            );
            assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        }
        drop(guard);
    }
}
