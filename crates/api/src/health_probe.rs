//! Shared control-plane health/readiness probes.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::peer_types::{PeerInfo, PeerManagerCommand};
use rustbgpd_rib::RibUpdate;

/// Total deadline for the core actor readiness probe.
pub const CORE_READINESS_DEADLINE: Duration = Duration::from_millis(200);

/// Process-wide daemon availability gate.
///
/// Two one-way transitions, both set from `main.rs` and observed by the
/// readiness surface:
///
/// - **not-ready**: a fatal availability fault (BGP listener failed to
///   bind, coordinated shutdown started). `/readyz` reports 503 with the
///   first recorded reason until the process restarts.
/// - **shutting-down**: coordinated shutdown has begun; admission paths
///   (inbound BGP connections, persisted config mutations) reject new
///   work instead of racing the teardown.
#[derive(Clone, Debug, Default)]
pub struct DaemonGate {
    inner: Arc<DaemonGateInner>,
}

#[derive(Debug, Default)]
struct DaemonGateInner {
    not_ready: OnceLock<&'static str>,
    shutting_down: AtomicBool,
}

impl DaemonGate {
    /// Create a gate in the ready, not-shutting-down state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fatal availability fault. First reason wins; later calls
    /// are no-ops so the root cause stays visible.
    pub fn mark_not_ready(&self, reason: &'static str) {
        let _ = self.inner.not_ready.set(reason);
    }

    /// Enter coordinated shutdown: readiness goes red and admission
    /// paths stop accepting new work.
    pub fn begin_shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Relaxed);
        self.mark_not_ready("daemon is shutting down");
    }

    /// The not-ready reason, if any fault has been recorded.
    #[must_use]
    pub fn not_ready_reason(&self) -> Option<&'static str> {
        self.inner.not_ready.get().copied()
    }

    /// Whether coordinated shutdown has begun.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Relaxed)
    }
}

/// Snapshot returned by a successful core actor probe.
#[derive(Debug)]
pub struct CoreHealthSnapshot {
    /// Peer snapshots returned by the peer manager.
    pub peers: Vec<PeerInfo>,
    /// Current Loc-RIB best-path count.
    pub total_routes: usize,
}

/// A bounded readiness probe for the two core control-plane actors.
#[derive(Clone)]
pub struct CoreReadinessProbe {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
    gate: Option<DaemonGate>,
}

impl CoreReadinessProbe {
    /// Create a new core readiness probe.
    #[must_use]
    pub fn new(
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
    ) -> Self {
        Self {
            peer_mgr_tx,
            rib_tx,
            gate: None,
        }
    }

    /// Attach the process-wide [`DaemonGate`]: a recorded fault (bind
    /// failure, shutdown) makes the probe fail before touching the
    /// core actors.
    #[must_use]
    pub fn with_gate(mut self, gate: DaemonGate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Probe `PeerManager` and RIB responsiveness.
    ///
    /// This deliberately checks actor responsiveness only. A daemon with zero
    /// configured peers or zero routes can still be ready.
    ///
    /// # Errors
    ///
    /// Returns [`CoreReadinessError`] when either core actor is unavailable,
    /// drops its reply channel, or does not respond before the readiness
    /// deadline.
    pub async fn check(&self) -> Result<(), CoreReadinessError> {
        self.snapshot().await.map(|_| ())
    }

    /// Return the same core actor snapshot used by `GetHealth`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreReadinessError`] when either core actor is unavailable,
    /// drops its reply channel, or does not respond before the readiness
    /// deadline.
    pub async fn snapshot(&self) -> Result<CoreHealthSnapshot, CoreReadinessError> {
        if let Some(reason) = self.gate.as_ref().and_then(DaemonGate::not_ready_reason) {
            return Err(CoreReadinessError::DaemonUnavailable(reason));
        }
        let deadline = Instant::now() + CORE_READINESS_DEADLINE;
        let peers = self.query_peer_manager(deadline).await?;
        let total_routes = self.query_rib(deadline).await?;
        Ok(CoreHealthSnapshot {
            peers,
            total_routes,
        })
    }

    async fn query_peer_manager(
        &self,
        deadline: Instant,
    ) -> Result<Vec<PeerInfo>, CoreReadinessError> {
        timeout_until(deadline, CoreReadinessError::PeerManagerTimedOut, async {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.peer_mgr_tx
                .send(PeerManagerCommand::ListPeers { reply: reply_tx })
                .await
                .map_err(|_| CoreReadinessError::PeerManagerUnavailable)?;
            reply_rx
                .await
                .map_err(|_| CoreReadinessError::PeerManagerDroppedReply)
        })
        .await
    }

    async fn query_rib(&self, deadline: Instant) -> Result<usize, CoreReadinessError> {
        timeout_until(deadline, CoreReadinessError::RibTimedOut, async {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.rib_tx
                .send(RibUpdate::QueryLocRibCount { reply: reply_tx })
                .await
                .map_err(|_| CoreReadinessError::RibUnavailable)?;
            reply_rx
                .await
                .map_err(|_| CoreReadinessError::RibDroppedReply)
        })
        .await
    }
}

async fn timeout_until<T, Fut>(
    deadline: Instant,
    timeout_error: CoreReadinessError,
    future: Fut,
) -> Result<T, CoreReadinessError>
where
    Fut: std::future::Future<Output = Result<T, CoreReadinessError>>,
{
    let now = Instant::now();
    if deadline <= now {
        return Err(timeout_error);
    }
    tokio::time::timeout(deadline - now, future)
        .await
        .map_err(|_| timeout_error)?
}

/// Core readiness failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReadinessError {
    /// `PeerManager` command channel is closed.
    PeerManagerUnavailable,
    /// `PeerManager` did not answer before the readiness deadline.
    PeerManagerTimedOut,
    /// `PeerManager` dropped the reply channel.
    PeerManagerDroppedReply,
    /// RIB command channel is closed.
    RibUnavailable,
    /// RIB did not answer before the readiness deadline.
    RibTimedOut,
    /// RIB dropped the reply channel.
    RibDroppedReply,
    /// The daemon recorded a fatal availability fault ([`DaemonGate`]):
    /// BGP listener bind failure or coordinated shutdown in progress.
    DaemonUnavailable(&'static str),
}

impl fmt::Display for CoreReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deadline_ms = CORE_READINESS_DEADLINE.as_millis();
        match self {
            Self::PeerManagerUnavailable => f.write_str("peer manager unavailable"),
            Self::PeerManagerTimedOut => {
                write!(f, "peer manager probe timed out ({deadline_ms}ms deadline)")
            }
            Self::PeerManagerDroppedReply => f.write_str("peer manager dropped reply"),
            Self::RibUnavailable => f.write_str("RIB manager unavailable"),
            Self::RibTimedOut => {
                write!(f, "RIB manager probe timed out ({deadline_ms}ms deadline)")
            }
            Self::RibDroppedReply => f.write_str("RIB manager dropped reply"),
            Self::DaemonUnavailable(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for CoreReadinessError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with_closed_peer_manager() -> CoreReadinessProbe {
        let (peer_tx, peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        drop(peer_rx);
        CoreReadinessProbe::new(peer_tx, rib_tx)
    }

    fn probe_with_closed_rib() -> (CoreReadinessProbe, mpsc::Receiver<PeerManagerCommand>) {
        let (peer_tx, peer_rx) = mpsc::channel(1);
        let (rib_tx, rib_rx) = mpsc::channel(1);
        drop(rib_rx);
        (CoreReadinessProbe::new(peer_tx, rib_tx), peer_rx)
    }

    async fn reply_to_peer_manager(
        peer_rx: &mut mpsc::Receiver<PeerManagerCommand>,
        peers: Vec<PeerInfo>,
    ) {
        let command = peer_rx.recv().await.expect("peer manager command");
        let PeerManagerCommand::ListPeers { reply } = command else {
            panic!("expected ListPeers command");
        };
        reply.send(peers).expect("peer reply receiver is alive");
    }

    async fn reply_to_rib(rib_rx: &mut mpsc::Receiver<RibUpdate>, total_routes: usize) {
        let command = rib_rx.recv().await.expect("RIB command");
        let RibUpdate::QueryLocRibCount { reply } = command else {
            panic!("expected QueryLocRibCount command");
        };
        reply
            .send(total_routes)
            .expect("RIB reply receiver is alive");
    }

    async fn reply_to_core_probe(
        peer_rx: &mut mpsc::Receiver<PeerManagerCommand>,
        peers: Vec<PeerInfo>,
        rib_rx: &mut mpsc::Receiver<RibUpdate>,
        total_routes: usize,
    ) {
        tokio::join!(
            reply_to_peer_manager(peer_rx, peers),
            reply_to_rib(rib_rx, total_routes)
        );
    }

    #[test]
    fn display_uses_stable_operator_text() {
        assert_eq!(
            CoreReadinessError::PeerManagerUnavailable.to_string(),
            "peer manager unavailable"
        );
        assert_eq!(
            CoreReadinessError::PeerManagerTimedOut.to_string(),
            "peer manager probe timed out (200ms deadline)"
        );
        assert_eq!(
            CoreReadinessError::PeerManagerDroppedReply.to_string(),
            "peer manager dropped reply"
        );
        assert_eq!(
            CoreReadinessError::RibUnavailable.to_string(),
            "RIB manager unavailable"
        );
        assert_eq!(
            CoreReadinessError::RibTimedOut.to_string(),
            "RIB manager probe timed out (200ms deadline)"
        );
        assert_eq!(
            CoreReadinessError::RibDroppedReply.to_string(),
            "RIB manager dropped reply"
        );
    }

    #[test]
    fn core_readiness_deadline_is_200ms() {
        assert_eq!(CORE_READINESS_DEADLINE, Duration::from_millis(200));
    }

    #[tokio::test]
    async fn snapshot_returns_core_actor_data_when_both_respond() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let snapshot = tokio::join!(
            probe.snapshot(),
            reply_to_core_probe(&mut peer_rx, Vec::new(), &mut rib_rx, 17)
        )
        .0
        .expect("probe should succeed");

        assert!(snapshot.peers.is_empty());
        assert_eq!(snapshot.total_routes, 17);
    }

    #[tokio::test]
    async fn check_succeeds_when_snapshot_succeeds() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(
            probe.check(),
            reply_to_core_probe(&mut peer_rx, Vec::new(), &mut rib_rx, 0)
        );

        result.expect("check should succeed");
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_sender_is_closed() {
        let err = probe_with_closed_peer_manager()
            .snapshot()
            .await
            .expect_err("closed peer manager channel should fail");

        assert_eq!(err, CoreReadinessError::PeerManagerUnavailable);
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_sender_is_closed() {
        let (probe, mut peer_rx) = probe_with_closed_rib();

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
        });

        assert_eq!(
            result.expect_err("closed RIB channel should fail"),
            CoreReadinessError::RibUnavailable
        );
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_drops_reply() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            let command = peer_rx.recv().await.expect("peer manager command");
            let PeerManagerCommand::ListPeers { reply } = command else {
                panic!("expected ListPeers command");
            };
            drop(reply);
        });

        assert_eq!(
            result.expect_err("dropped peer reply should fail"),
            CoreReadinessError::PeerManagerDroppedReply
        );
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_drops_reply() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
            let command = rib_rx.recv().await.expect("RIB command");
            let RibUpdate::QueryLocRibCount { reply } = command else {
                panic!("expected QueryLocRibCount command");
            };
            drop(reply);
        });

        assert_eq!(
            result.expect_err("dropped RIB reply should fail"),
            CoreReadinessError::RibDroppedReply
        );
    }

    #[tokio::test]
    async fn gated_probe_fails_without_touching_core_actors() {
        // BGP-listener bind failure: readiness must go red even though
        // both core actors would answer (nothing replies here and the
        // probe must not need them to).
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let gate = DaemonGate::new();
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx).with_gate(gate.clone());

        gate.mark_not_ready("BGP listener failed to bind");

        let err = probe
            .check()
            .await
            .expect_err("tripped gate must fail readiness");
        assert_eq!(
            err,
            CoreReadinessError::DaemonUnavailable("BGP listener failed to bind")
        );
        assert_eq!(err.to_string(), "BGP listener failed to bind");
        assert!(
            !gate.is_shutting_down(),
            "a bind fault must not flip the shutdown admission gate"
        );
    }

    #[tokio::test]
    async fn begin_shutdown_turns_readiness_red_and_stops_admission() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let gate = DaemonGate::new();
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx).with_gate(gate.clone());

        assert!(!gate.is_shutting_down());
        gate.begin_shutdown();

        assert!(gate.is_shutting_down());
        assert_eq!(
            probe.check().await,
            Err(CoreReadinessError::DaemonUnavailable(
                "daemon is shutting down"
            ))
        );
    }

    #[test]
    fn first_not_ready_reason_wins() {
        let gate = DaemonGate::new();
        gate.mark_not_ready("BGP listener failed to bind");
        gate.begin_shutdown();
        assert_eq!(
            gate.not_ready_reason(),
            Some("BGP listener failed to bind"),
            "the root-cause fault must stay visible across later transitions"
        );
    }

    #[tokio::test]
    async fn ungated_probe_still_probes_core_actors() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx).with_gate(DaemonGate::new());

        let (result, ()) = tokio::join!(
            probe.check(),
            reply_to_core_probe(&mut peer_rx, Vec::new(), &mut rib_rx, 0)
        );

        result.expect("untripped gate must not affect readiness");
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_times_out() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let err = probe
            .snapshot()
            .await
            .expect_err("unresponsive peer manager should time out");

        assert_eq!(err, CoreReadinessError::PeerManagerTimedOut);
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_times_out() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
        });

        assert_eq!(
            result.expect_err("unresponsive RIB should time out"),
            CoreReadinessError::RibTimedOut
        );
    }
}
