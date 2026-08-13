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

pub const OWNED_SETTLEMENT_BUDGET: Duration = Duration::from_mins(30);
pub const AMBIGUITY_FENCE_GRACE: Duration = Duration::from_secs(5);
pub const AMBIGUOUS_CONFIG_EXIT_STATUS: i32 = 70;

/// Closed roster of runtime-config operations wired into settlement ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigOperationKind {
    Sighup,
    Apply,
    GnmiSet,
    Confirm,
    Abort,
    Rollback,
    AutoRevert,
    NeighborAdd,
    NeighborDelete,
    DynamicNeighborAdd,
    DynamicNeighborDelete,
    FibSet,
    FibDelete,
    PeerGroupSet,
    PeerGroupDelete,
    NeighborPeerGroupSet,
    NeighborPeerGroupClear,
    PolicySet,
    PolicyDelete,
    NeighborSetSet,
    NeighborSetDelete,
    GlobalImportChainSet,
    GlobalExportChainSet,
    GlobalImportChainClear,
    GlobalExportChainClear,
    NeighborImportChainSet,
    NeighborExportChainSet,
    NeighborImportChainClear,
    NeighborExportChainClear,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimeConfigSettlementPhase {
    OwnedPreflight,
    Mutating,
    SettlingRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigSettlementTerminal {
    Owned,
    Settled,
    RecoveryFenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigFenceReason {
    BudgetExpired,
    ExecutorLost,
    KnownDivergence,
    PublicationAmbiguous,
    AcknowledgementLost,
}

const PHASE_PREFLIGHT: u8 = 0;
const PHASE_MUTATING: u8 = 1;
const PHASE_SETTLING: u8 = 2;
const PHASE_MASK: u8 = 0b11;
const TERMINAL_OWNED: u8 = 0;
const TERMINAL_SETTLED: u8 = 1 << 2;
const TERMINAL_AMBIGUOUS: u8 = 2 << 2;
const TERMINAL_MASK: u8 = 0b11 << 2;
const AMBIGUITY_REASON_NONE: u8 = 0;
const AMBIGUITY_REASON_BUDGET: u8 = 1;
const AMBIGUITY_REASON_EXECUTOR: u8 = 2;
const FENCE_REASON_DIVERGENCE: u8 = 3;
const FENCE_REASON_PUBLICATION: u8 = 4;
const FENCE_REASON_ACKNOWLEDGEMENT: u8 = 5;
const RECOVERY_NOT_READY: &str = "runtime config settlement requires supervised recovery";

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
    state: AtomicU8,
    fence_reason: AtomicU8,
    response_attached: Arc<AtomicBool>,
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

struct Registry {
    state: Mutex<RegistryState>,
    wake: Condvar,
    next_id: AtomicU64,
    budget: Duration,
    grace: Duration,
    thread_id: Mutex<Option<thread::ThreadId>>,
    #[cfg(test)]
    terminal: std::sync::mpsc::Sender<i32>,
    #[cfg(test)]
    pre_wait_hook: Mutex<Option<PreWaitHook>>,
}

#[cfg(test)]
struct PreWaitHook {
    reached: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn unregister(&self, id: u64) {
        self.lock().registrations.remove(&id);
        self.wake.notify_all();
    }

    fn advance_terminal(&self, id: u64, when: Instant) {
        if let Some(registration) = self.lock().registrations.get_mut(&id) {
            registration.terminal_at = when;
        }
        self.wake.notify_one();
    }
}

#[derive(Clone)]
pub struct RuntimeConfigSettlementWatchdog {
    registry: Arc<Registry>,
    #[cfg(test)]
    thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
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
    #[cfg(not(test))]
    #[allow(
        clippy::new_without_default,
        reason = "construction starts the process watchdog thread, so Default would hide lifecycle side effects"
    )]
    pub fn new() -> Self {
        Self::start(OWNED_SETTLEMENT_BUDGET, AMBIGUITY_FENCE_GRACE)
    }

    #[cfg(not(test))]
    fn start(budget: Duration, grace: Duration) -> Self {
        let registry = Arc::new(Registry {
            state: Mutex::new(RegistryState {
                registrations: HashMap::new(),
                stopping: false,
            }),
            wake: Condvar::new(),
            next_id: AtomicU64::new(1),
            budget,
            grace,
            thread_id: Mutex::new(None),
        });
        let thread_registry = Arc::clone(&registry);
        thread::Builder::new()
            .name("config-settlement-watchdog".into())
            .spawn(move || watchdog_loop(&thread_registry))
            .expect("config settlement watchdog OS thread must start");
        Self { registry }
    }

    #[cfg(test)]
    fn start(budget: Duration, grace: Duration, terminal: std::sync::mpsc::Sender<i32>) -> Self {
        let registry = Arc::new(Registry {
            state: Mutex::new(RegistryState {
                registrations: HashMap::new(),
                stopping: false,
            }),
            wake: Condvar::new(),
            next_id: AtomicU64::new(1),
            budget,
            grace,
            thread_id: Mutex::new(None),
            terminal,
            pre_wait_hook: Mutex::new(None),
        });
        let thread_registry = Arc::clone(&registry);
        let thread = thread::Builder::new()
            .name("config-settlement-watchdog".into())
            .spawn(move || watchdog_loop(&thread_registry))
            .expect("config settlement watchdog OS thread must start");
        Self {
            registry,
            thread: Arc::new(Mutex::new(Some(thread))),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the closed ownership registration lists every retained fail-stop resource explicitly"
    )]
    pub fn register_owned(
        &self,
        kind: RuntimeConfigOperationKind,
        coordinator: RuntimeConfigCoordinator,
        coordinator_permit: RuntimeConfigCoordinatorPermit,
        daemon_gate: DaemonGate,
        stream_permit: Option<OwnedSemaphorePermit>,
        stream_admission: Option<Arc<Semaphore>>,
        response_attached: Arc<AtomicBool>,
    ) -> (OwnedRuntimeConfigOperation, RuntimeConfigExecutorGuard) {
        let deadline = Instant::now() + self.registry.budget;
        let id = self.registry.next_id.fetch_add(1, Ordering::Relaxed);
        let operation = Arc::new(OperationInner {
            id,
            kind,
            deadline,
            state: AtomicU8::new(TERMINAL_OWNED | PHASE_PREFLIGHT),
            fence_reason: AtomicU8::new(AMBIGUITY_REASON_NONE),
            response_attached,
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

    /// Run one detached, owned mutation from coordinator acquisition through
    /// typed settlement. Registration is the first post-acquire operation.
    /// Caller cancellation detaches only the response; typed ambiguity,
    /// deadline, or executor loss fences and parks the retained owner.
    ///
    /// # Errors
    ///
    /// Returns only the error carried by a typed clean outcome or coordinator
    /// acquisition before ownership. Ambiguous owned outcomes never return.
    pub async fn execute_owned<T, E, F, Fut>(
        &self,
        kind: RuntimeConfigOperationKind,
        coordinator: RuntimeConfigCoordinator,
        daemon_gate: DaemonGate,
        response_attached: Arc<AtomicBool>,
        body: F,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<crate::server::RuntimeConfigCoordinatorClosed> + Send + 'static,
        F: FnOnce(OwnedRuntimeConfigOperation) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = OwnedRuntimeConfigOutcome<T, E>> + Send + 'static,
    {
        let watchdog = self.clone();
        let join = tokio::spawn(async move {
            let coordinator_permit = coordinator.acquire().await?;
            let (operation, executor_guard) = watchdog.register_owned(
                kind,
                coordinator,
                coordinator_permit,
                daemon_gate,
                None,
                None,
                response_attached,
            );
            let outcome = body(operation.clone()).await;
            match outcome {
                OwnedRuntimeConfigOutcome::CleanNoEffect(result) => {
                    if !operation.try_settle() {
                        std::future::pending::<()>().await;
                    }
                    drop(executor_guard);
                    result
                }
                OwnedRuntimeConfigOutcome::PublishedDurable(value)
                | OwnedRuntimeConfigOutcome::AcknowledgedAuthority(value) => {
                    if !operation.try_settle() {
                        std::future::pending::<()>().await;
                    }
                    drop(executor_guard);
                    Ok(value)
                }
                OwnedRuntimeConfigOutcome::Fenced { error, reason } => {
                    let _ = error;
                    let _ = operation.fence_recovery(reason);
                    std::future::pending().await
                }
            }
        });
        match join.await {
            Ok(result) => result,
            Err(_) => std::future::pending().await,
        }
    }

    /// Block the calling OS thread until every clean registration settles.
    /// Ambiguous ownership deliberately never unregisters; its fail-stop wins.
    pub fn wait_until_idle(&self) {
        let mut state = self.registry.lock();
        while !state.registrations.is_empty() {
            state = self
                .registry
                .wake
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Typed result from an owned body; never inferred from transport status.
pub enum OwnedRuntimeConfigOutcome<T, E> {
    /// Success or a proven no-effect or fully-compensated failure.
    CleanNoEffect(Result<T, E>),
    /// The requested candidate is fully applied and durable.
    PublishedDurable(T),
    /// A non-publication operation whose authority was acknowledged by every
    /// runtime consumer.
    AcknowledgedAuthority(T),
    /// An accepted effect whose final state cannot be proved.
    /// Ownership must be retained until supervised recovery.
    Fenced {
        error: E,
        reason: RuntimeConfigFenceReason,
    },
}

/// Response attachment shared with a detached owned executor.
pub struct OwnedRuntimeConfigRequestContext {
    response_attached: Arc<AtomicBool>,
}

impl OwnedRuntimeConfigRequestContext {
    /// Create a unary response attachment owned by the outer RPC future.
    #[must_use]
    pub fn unary() -> (Self, OwnedRuntimeConfigResponseAttachment) {
        let attached = Arc::new(AtomicBool::new(true));
        (
            Self {
                response_attached: Arc::clone(&attached),
            },
            OwnedRuntimeConfigResponseAttachment(attached),
        )
    }

    /// Create a daemon-owned request with no response transport attached.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            response_attached: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Transfer the shared attachment sentinel to the detached executor.
    #[must_use]
    pub fn response_attached(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.response_attached)
    }
}

/// Outer-RPC sentinel; dropping it records cancellation without releasing ownership.
pub struct OwnedRuntimeConfigResponseAttachment(Arc<AtomicBool>);

impl Drop for OwnedRuntimeConfigResponseAttachment {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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
        match self.inner.state.load(Ordering::Acquire) & PHASE_MASK {
            PHASE_PREFLIGHT => RuntimeConfigSettlementPhase::OwnedPreflight,
            PHASE_MUTATING => RuntimeConfigSettlementPhase::Mutating,
            _ => RuntimeConfigSettlementPhase::SettlingRollback,
        }
    }

    /// Advance the phase monotonically while ownership is live.
    /// Settlement and recovery fencing atomically freeze the last phase.
    pub fn advance_phase(&self, phase: RuntimeConfigSettlementPhase) {
        let desired = match phase {
            RuntimeConfigSettlementPhase::OwnedPreflight => PHASE_PREFLIGHT,
            RuntimeConfigSettlementPhase::Mutating => PHASE_MUTATING,
            RuntimeConfigSettlementPhase::SettlingRollback => PHASE_SETTLING,
        };
        let mut observed = self.inner.state.load(Ordering::Acquire);
        loop {
            if observed & TERMINAL_MASK != TERMINAL_OWNED || observed & PHASE_MASK >= desired {
                return;
            }
            let next = (observed & !PHASE_MASK) | desired;
            match self.inner.state.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => observed = actual,
            }
        }
    }

    #[must_use]
    pub fn terminal(&self) -> RuntimeConfigSettlementTerminal {
        match self.inner.state.load(Ordering::Acquire) & TERMINAL_MASK {
            TERMINAL_OWNED => RuntimeConfigSettlementTerminal::Owned,
            TERMINAL_SETTLED => RuntimeConfigSettlementTerminal::Settled,
            _ => RuntimeConfigSettlementTerminal::RecoveryFenced,
        }
    }

    #[must_use]
    pub fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        match self.inner.fence_reason.load(Ordering::Acquire) {
            AMBIGUITY_REASON_BUDGET => Some(RuntimeConfigFenceReason::BudgetExpired),
            AMBIGUITY_REASON_EXECUTOR => Some(RuntimeConfigFenceReason::ExecutorLost),
            FENCE_REASON_DIVERGENCE => Some(RuntimeConfigFenceReason::KnownDivergence),
            FENCE_REASON_PUBLICATION => Some(RuntimeConfigFenceReason::PublicationAmbiguous),
            FENCE_REASON_ACKNOWLEDGEMENT => Some(RuntimeConfigFenceReason::AcknowledgementLost),
            _ => None,
        }
    }

    /// Fence a typed recovery result before any response can be published.
    #[must_use]
    pub fn fence_recovery(&self, reason: RuntimeConfigFenceReason) -> bool {
        fence(self.inner.as_ref(), reason)
    }

    #[must_use]
    pub fn response_attached(&self) -> bool {
        self.inner.response_attached.load(Ordering::Acquire)
    }

    /// Prove settlement and release physical ownership. Returns false after fencing.
    pub fn try_settle(&self) -> bool {
        let mut observed = self.inner.state.load(Ordering::Acquire);
        loop {
            if observed & TERMINAL_MASK != TERMINAL_OWNED {
                return false;
            }
            let settled = (observed & PHASE_MASK) | TERMINAL_SETTLED;
            match self.inner.state.compare_exchange_weak(
                observed,
                settled,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
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

fn fence(operation: &OperationInner, reason: RuntimeConfigFenceReason) -> bool {
    let mut observed = operation.state.load(Ordering::Acquire);
    loop {
        if observed & TERMINAL_MASK != TERMINAL_OWNED {
            return false;
        }
        let fenced = (observed & PHASE_MASK) | TERMINAL_AMBIGUOUS;
        match operation.state.compare_exchange_weak(
            observed,
            fenced,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => observed = actual,
        }
    }
    let reason_value = match reason {
        RuntimeConfigFenceReason::BudgetExpired => AMBIGUITY_REASON_BUDGET,
        RuntimeConfigFenceReason::ExecutorLost => AMBIGUITY_REASON_EXECUTOR,
        RuntimeConfigFenceReason::KnownDivergence => FENCE_REASON_DIVERGENCE,
        RuntimeConfigFenceReason::PublicationAmbiguous => FENCE_REASON_PUBLICATION,
        RuntimeConfigFenceReason::AcknowledgementLost => FENCE_REASON_ACKNOWLEDGEMENT,
    };
    operation
        .fence_reason
        .store(reason_value, Ordering::Release);
    operation.daemon_gate.mark_not_ready(RECOVERY_NOT_READY);
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
    'watchdog: loop {
        let mut state = registry.lock();
        loop {
            if state.stopping {
                break 'watchdog;
            }
            let now = Instant::now();
            let expired = state
                .registrations
                .values()
                .filter(|entry| {
                    entry.operation.state.load(Ordering::Acquire) & TERMINAL_MASK == TERMINAL_OWNED
                        && entry.operation.deadline <= now
                })
                .map(|entry| Arc::clone(&entry.operation))
                .collect::<Vec<_>>();
            let terminal = state
                .registrations
                .values()
                .find(|entry| {
                    entry.operation.state.load(Ordering::Acquire) & TERMINAL_MASK
                        == TERMINAL_AMBIGUOUS
                        && entry.terminal_at <= now
                })
                .map(|entry| Arc::clone(&entry.operation));
            let wait = state
                .registrations
                .values()
                .map(|entry| {
                    if entry.operation.state.load(Ordering::Acquire) & TERMINAL_MASK
                        == TERMINAL_OWNED
                    {
                        entry.operation.deadline
                    } else {
                        entry.terminal_at
                    }
                })
                .min()
                .map_or(registry.budget, |next| next.saturating_duration_since(now));
            if !expired.is_empty() || terminal.is_some() {
                drop(state);
                for operation in expired {
                    fence(&operation, RuntimeConfigFenceReason::BudgetExpired);
                }
                if let Some(operation) = terminal {
                    run_terminal_action(registry, &operation);
                }
                continue 'watchdog;
            }
            #[cfg(test)]
            if let Some(hook) = registry
                .pre_wait_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = hook.reached.send(());
                let _ = hook.resume.recv();
            }
            (state, _) = registry
                .wake
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    *registry
        .thread_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    registry.wake.notify_all();
}

#[cfg(not(test))]
#[allow(unsafe_code)]
fn run_terminal_action(_registry: &Registry, _operation: &OperationInner) -> ! {
    // SAFETY: `_exit` is the fail-stop contract and must skip cleanup.
    unsafe { libc::_exit(AMBIGUOUS_CONFIG_EXIT_STATUS) }
}

#[cfg(test)]
fn run_terminal_action(registry: &Registry, operation: &OperationInner) {
    let _ = registry.terminal.send(AMBIGUOUS_CONFIG_EXIT_STATUS);
    registry.unregister(operation.id);
    operation
        .resources
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestWatchdog(RuntimeConfigSettlementWatchdog);

    impl std::ops::Deref for TestWatchdog {
        type Target = RuntimeConfigSettlementWatchdog;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TestWatchdog {
        fn drop(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut state = self.registry.lock();
            while !state.registrations.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "watchdog cleanup refused owned registrations"
                );
                (state, _) = self
                    .registry
                    .wake
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            state.stopping = true;
            self.registry.wake.notify_all();
            drop(state);
            if let Some(thread) = self.0.thread.lock().unwrap().take() {
                thread
                    .join()
                    .expect("watchdog test thread must stop cleanly");
            }
            assert!(self.registry.thread_id.lock().unwrap().is_none());
        }
    }

    fn test_watchdog(
        budget: Duration,
        grace: Duration,
    ) -> (TestWatchdog, std::sync::mpsc::Receiver<i32>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (
            TestWatchdog(RuntimeConfigSettlementWatchdog::start(
                budget, grace, sender,
            )),
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
            Arc::new(AtomicBool::new(true)),
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
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::SettlingRollback
        );
        drop(guard);
    }

    #[tokio::test]
    async fn terminal_transition_freezes_phase_against_concurrent_advance() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let advance = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
            })
        };
        let settle = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.try_settle()
            })
        };
        barrier.wait();
        advance.join().unwrap();
        assert!(settle.join().unwrap());
        let frozen = operation.phase();
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(operation.phase(), frozen);
        drop(guard);
    }

    #[tokio::test]
    async fn recovery_fence_freezes_last_owned_phase() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::KnownDivergence));
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(operation.phase(), RuntimeConfigSettlementPhase::Mutating);
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
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
    async fn clean_settlement_freezes_preflight_phase() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        assert!(operation.try_settle());
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::OwnedPreflight
        );
        drop(guard);
    }

    #[tokio::test]
    async fn executor_loss_fences_before_resources_release() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        drop(guard);
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::RecoveryFenced
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

    #[tokio::test]
    async fn detected_ambiguity_closes_both_admission_resources() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::PublicationAmbiguous));
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::PublicationAmbiguous)
        );
        assert!(coordinator.is_closed());
        assert!(admission.unwrap().is_closed());
        assert!(!operation.try_settle());
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        drop(guard);
    }

    #[tokio::test]
    async fn wait_until_idle_returns_only_after_clean_settlement() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let waiter = {
            let watchdog = watchdog.clone();
            thread::spawn(move || watchdog.wait_until_idle())
        };
        thread::sleep(Duration::from_millis(10));
        assert!(!waiter.is_finished());
        assert!(operation.try_settle());
        drop(guard);
        waiter.join().unwrap();
    }

    #[tokio::test]
    async fn shared_executor_outlives_rpc_cancellation_and_settles_cleanly() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let coordinator = RuntimeConfigCoordinator::new();
        let gate = DaemonGate::new();
        let (context, attachment) = OwnedRuntimeConfigRequestContext::unary();
        let (operation_tx, operation_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let executor = tokio::spawn({
            let watchdog = watchdog.clone();
            let coordinator = coordinator.clone();
            async move {
                watchdog
                    .execute_owned(
                        RuntimeConfigOperationKind::Sighup,
                        coordinator,
                        gate,
                        context.response_attached(),
                        move |operation| async move {
                            let _ = operation_tx.send(operation);
                            let _ = release_rx.await;
                            OwnedRuntimeConfigOutcome::<(), tonic::Status>::AcknowledgedAuthority(())
                        },
                    )
                    .await
            }
        });
        let operation = operation_rx.await.unwrap();
        executor.abort();
        let _ = executor.await;
        drop(attachment);
        assert!(!operation.response_attached());
        assert_eq!(operation.terminal(), RuntimeConfigSettlementTerminal::Owned);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), coordinator.acquire())
                .await
                .is_err(),
            "caller cancellation must not release coordinator ownership"
        );
        release_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
                .await
                .unwrap()
                .is_ok()
        );
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::Settled
        );
    }

    #[tokio::test]
    async fn shared_executor_ambiguity_fences_queued_and_future_owners() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let coordinator = RuntimeConfigCoordinator::new();
        let gate = DaemonGate::new();
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        let (operation_tx, operation_rx) = tokio::sync::oneshot::channel();
        let (ambiguous_tx, ambiguous_rx) = tokio::sync::oneshot::channel();
        let executor = tokio::spawn({
            let watchdog = watchdog.clone();
            let coordinator = coordinator.clone();
            let gate = gate.clone();
            async move {
                watchdog
                    .execute_owned(
                        RuntimeConfigOperationKind::FibDelete,
                        coordinator,
                        gate,
                        context.response_attached(),
                        move |operation| async move {
                            let _ = operation_tx.send(operation);
                            let _ = ambiguous_rx.await;
                            OwnedRuntimeConfigOutcome::<(), tonic::Status>::Fenced {
                                error: tonic::Status::internal("typed recovery test outcome"),
                                reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                            }
                        },
                    )
                    .await
            }
        });
        let operation = operation_rx.await.unwrap();
        let queued = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.acquire().await }
        });
        ambiguous_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while operation.terminal() == RuntimeConfigSettlementTerminal::Owned {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::RecoveryFenced
        );
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::PublicationAmbiguous)
        );
        assert!(gate.is_shutting_down());
        assert!(queued.await.unwrap().is_err());
        assert!(coordinator.acquire().await.is_err());
        assert!(
            !executor.is_finished(),
            "ambiguous outcome must never return"
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        executor.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn std_thread_deadline_ignores_paused_tokio_clock_and_detach() {
        let (watchdog, receiver) =
            test_watchdog(Duration::from_millis(40), Duration::from_millis(20));
        let coordinator = RuntimeConfigCoordinator::new();
        let permit = coordinator.acquire().await.unwrap();
        let context = OwnedRuntimeConfigRequestContext::detached();
        let (operation, guard) = watchdog.register_owned(
            RuntimeConfigOperationKind::Sighup,
            coordinator.clone(),
            permit,
            DaemonGate::new(),
            None,
            None,
            context.response_attached(),
        );
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
        let start_deadline = Instant::now() + Duration::from_secs(5);
        let thread_id = loop {
            if let Some(thread_id) = *watchdog.registry.thread_id.lock().unwrap() {
                break thread_id;
            }
            assert!(
                Instant::now() < start_deadline,
                "watchdog thread failed to start"
            );
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

    #[tokio::test]
    async fn executor_loss_at_pre_wait_boundary_terminates_by_grace() {
        let old_deadline = Duration::from_secs(4);
        let grace = Duration::from_millis(20);
        let (watchdog, receiver) = test_watchdog(old_deadline, grace);
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let (reached_sender, reached_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        *watchdog.registry.pre_wait_hook.lock().unwrap() = Some(PreWaitHook {
            reached: reached_sender,
            resume: resume_receiver,
        });
        watchdog.registry.wake.notify_one();
        reached_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let (dropping_sender, dropping_receiver) = std::sync::mpsc::channel();
        let losing_executor = thread::spawn(move || {
            dropping_sender.send(()).unwrap();
            drop(guard);
        });
        dropping_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let started = Instant::now();
        resume_sender.send(()).unwrap();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 70);
        assert!(started.elapsed() < old_deadline);
        losing_executor.join().unwrap();
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::ExecutorLost)
        );
    }
}
