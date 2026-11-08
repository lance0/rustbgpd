use std::collections::VecDeque;
use std::fs;

use anyhow::{ensure, Context, Result};
use rustbgpd_evpn_load::{PeerError, PeerHandle as StubHandle};
use rustbgpd_fsm::SessionState;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::{Message, UpdateMessage};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
pub struct Checkpoint {
    pub direct_pid_vmrss_kib: u64,
    pub direct_pid_vmhwm_kib: u64,
    pub jemalloc_allocated_bytes: u64,
    pub jemalloc_active_bytes: u64,
    pub jemalloc_resident_bytes: u64,
    pub jemalloc_mapped_bytes: u64,
}

pub fn checkpoint(metrics: &BgpMetrics) -> Result<Checkpoint> {
    let gathered = metrics.registry().gather();
    let integer_gauge = |name: &str| -> Result<u64> {
        let family = gathered
            .iter()
            .find(|family| family.name() == name)
            .with_context(|| format!("missing allocator metric {name}"))?;
        ensure!(
            family.get_metric().len() == 1,
            "allocator metric {name} has unexpected cardinality"
        );
        let value = family.get_metric()[0].get_gauge().get_value();
        ensure!(
            value.is_finite() && value > 0.0 && value.fract() == 0.0,
            "allocator metric {name} is not a positive integer"
        );
        value
            .to_string()
            .parse()
            .with_context(|| format!("allocator metric {name} is outside u64"))
    };
    let allocated = integer_gauge("jemalloc_allocated_bytes")?;
    let active = integer_gauge("jemalloc_active_bytes")?;
    ensure!(
        allocated <= active,
        "jemalloc allocated bytes exceed active bytes"
    );
    let (vmrss, vmhwm) = rss_kib()?;
    Ok(Checkpoint {
        direct_pid_vmrss_kib: vmrss,
        direct_pid_vmhwm_kib: vmhwm,
        jemalloc_allocated_bytes: allocated,
        jemalloc_active_bytes: active,
        jemalloc_resident_bytes: integer_gauge("jemalloc_resident_bytes")?,
        jemalloc_mapped_bytes: integer_gauge("jemalloc_mapped_bytes")?,
    })
}

pub fn runtime(workers: usize) -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?)
}

pub fn is_eor(update: &UpdateMessage) -> bool {
    update.withdrawn_routes.is_empty()
        && update.path_attributes.is_empty()
        && update.nlri.is_empty()
}

pub async fn send_before<T>(
    sender: &mpsc::Sender<T>,
    update: T,
    deadline: tokio::time::Instant,
) -> Result<()> {
    tokio::time::timeout_at(deadline, sender.send(update))
        .await?
        .map_err(|_| anyhow::anyhow!("injection channel closed"))?;
    Ok(())
}

pub async fn start_after_keepalives(
    receiver: &mut mpsc::Receiver<Message>,
    arm: oneshot::Receiver<()>,
    armed: oneshot::Sender<()>,
    start: oneshot::Receiver<std::time::Instant>,
    deadline: tokio::time::Instant,
) -> Result<std::time::Instant> {
    tokio::time::timeout_at(deadline, arm).await??;
    loop {
        match receiver.try_recv() {
            Ok(Message::Keepalive) => {}
            Err(mpsc::error::TryRecvError::Empty) => break,
            Ok(_) | Err(mpsc::error::TryRecvError::Disconnected) => {
                ensure!(false, "non-KEEPALIVE message queued before T0")
            }
        }
    }
    armed
        .send(())
        .map_err(|_| anyhow::anyhow!("armed dropped"))?;
    Ok(tokio::time::timeout_at(deadline, start).await??)
}

pub fn rss_kib() -> Result<(u64, u64)> {
    let status = fs::read_to_string("/proc/self/status")?;
    let field = |name: &str| -> Result<u64> {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .context("missing process RSS field")?
            .parse()
            .context("invalid process RSS field")
    };
    Ok((field("VmRSS:")?, field("VmHWM:")?))
}

pub async fn assert_established(
    sessions: &[PeerHandle],
    deadline: tokio::time::Instant,
) -> Result<()> {
    for session in sessions {
        loop {
            let state = tokio::time::timeout_at(deadline, session.query_state())
                .await?
                .context("session closed before Established")?;
            if state.fsm_state == SessionState::Established {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

/// Tasks and channels owned by one harness run, including setup failures.
pub struct HarnessTasks<T> {
    pub sessions: Vec<PeerHandle>,
    pub handshakes: VecDeque<JoinHandle<Result<StubHandle, PeerError>>>,
    pub collectors: VecDeque<JoinHandle<Result<T>>>,
    pub background: Vec<JoinHandle<()>>,
    pub stub_senders: Vec<mpsc::Sender<Message>>,
}

impl<T> HarnessTasks<T> {
    pub fn new(manager: JoinHandle<()>) -> Self {
        Self {
            sessions: Vec::new(),
            handshakes: VecDeque::new(),
            collectors: VecDeque::new(),
            background: vec![manager],
            stub_senders: Vec::new(),
        }
    }

    pub async fn settle(mut self, deadline: tokio::time::Instant) -> Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = shutdown(self.sessions, deadline).await {
            errors.push(error);
        }
        for handshake in &self.handshakes {
            handshake.abort();
        }
        for handshake in self.handshakes {
            match handshake.await {
                // A completed handshake still owns its reader and writer.
                Ok(Ok(stub)) => self.background.extend(stub.tasks),
                Ok(Err(error)) => errors.push(error.into()),
                Err(error) if error.is_cancelled() => {}
                Err(error) => errors.push(error.into()),
            }
        }
        drop(self.stub_senders);
        for collector in &self.collectors {
            collector.abort();
        }
        for collector in self.collectors {
            match collector.await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => errors.push(error),
                Err(error) if error.is_cancelled() => {}
                Err(error) => errors.push(error.into()),
            }
        }
        if let Err(error) = abort_and_join(self.background).await {
            errors.push(error);
        }
        ensure!(errors.is_empty(), "harness cleanup failed: {errors:?}");
        Ok(())
    }
}

/// Keep the handle owned on timeout; completed handles are removed before errors propagate.
pub async fn next_task<T>(
    tasks: &mut VecDeque<JoinHandle<T>>,
    deadline: tokio::time::Instant,
) -> Result<T> {
    let task = tasks.front_mut().context("no remaining harness task")?;
    let result = tokio::time::timeout_at(deadline, task).await?;
    tasks.pop_front();
    Ok(result?)
}

pub async fn abort_and_join(tasks: impl IntoIterator<Item = JoinHandle<()>>) -> Result<()> {
    let tasks = tasks.into_iter().collect::<Vec<_>>();
    for task in &tasks {
        task.abort();
    }
    let mut errors = Vec::new();
    for task in tasks {
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                errors.push(error);
            }
        }
    }
    ensure!(errors.is_empty(), "harness task failed: {errors:?}");
    Ok(())
}

pub async fn shutdown(sessions: Vec<PeerHandle>, deadline: tokio::time::Instant) -> Result<()> {
    let tasks = sessions
        .into_iter()
        .map(|session| {
            tokio::spawn(async move {
                session
                    .shutdown_timeout(
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await??;
                Ok::<_, anyhow::Error>(())
            })
        })
        .collect::<Vec<_>>();
    let mut errors = Vec::new();
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error),
            Err(error) => errors.push(error.into()),
        }
    }
    ensure!(errors.is_empty(), "transport shutdown failed: {errors:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::RouteRefreshMessage;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let mut context = Context::from_waker(Waker::noop());
        future.poll(&mut context)
    }

    #[tokio::test]
    async fn full_injection_channel_obeys_absolute_deadline() {
        let (sender, _receiver) = mpsc::channel(1);
        sender.send(1_u8).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            send_before(&sender, 2_u8, deadline),
        )
        .await
        .expect("injection helper ignored its deadline");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn collector_arms_after_keepalive_drain_and_waits_for_t0() {
        let (sender, mut receiver) = mpsc::channel(2);
        sender.send(Message::Keepalive).await.unwrap();
        let (arm_tx, arm_rx) = oneshot::channel();
        let (armed_tx, mut armed_rx) = oneshot::channel();
        let (start_tx, start_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut collector = Box::pin(start_after_keepalives(
            &mut receiver,
            arm_rx,
            armed_tx,
            start_rx,
            deadline,
        ));

        assert!(poll_once(collector.as_mut()).is_pending());
        assert!(poll_once(Pin::new(&mut armed_rx)).is_pending());
        arm_tx.send(()).unwrap();
        assert!(poll_once(collector.as_mut()).is_pending());
        assert!(matches!(
            poll_once(Pin::new(&mut armed_rx)),
            Poll::Ready(Ok(()))
        ));
        assert!(poll_once(collector.as_mut()).is_pending());
        let t0 = std::time::Instant::now();
        start_tx.send(t0).unwrap();
        assert!(matches!(poll_once(collector.as_mut()), Poll::Ready(Ok(value)) if value == t0));
    }

    #[tokio::test]
    async fn collector_does_not_arm_with_pre_t0_non_keepalive() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(Message::RouteRefresh(RouteRefreshMessage::new(
                rustbgpd_wire::Afi::Ipv4,
                rustbgpd_wire::Safi::Unicast,
            )))
            .await
            .unwrap();
        let (arm_tx, arm_rx) = oneshot::channel();
        let (armed_tx, mut armed_rx) = oneshot::channel();
        let (_start_tx, start_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut collector = Box::pin(start_after_keepalives(
            &mut receiver,
            arm_rx,
            armed_tx,
            start_rx,
            deadline,
        ));

        arm_tx.send(()).unwrap();
        assert!(matches!(poll_once(collector.as_mut()), Poll::Ready(Err(_))));
        assert!(matches!(
            poll_once(Pin::new(&mut armed_rx)),
            Poll::Ready(Err(_))
        ));
    }
    struct NotifyOnDrop(Option<oneshot::Sender<()>>);

    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    struct HeldEncoder {
        inner: std::sync::Arc<dyn rustbgpd_rib::update::ExactExportEncoder>,
        entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        _dropped: NotifyOnDrop,
    }

    impl rustbgpd_rib::update::ExactExportEncoder for HeldEncoder {
        fn owner_id(&self) -> u64 {
            self.inner.owner_id()
        }

        fn snapshot(&self) -> std::sync::Arc<dyn rustbgpd_rib::update::ExactExportSnapshot> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
                // Dropping the release sender also unblocks a failed test.
                assert_ne!(
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(10)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                    "test failed to release the real RIB replay",
                );
            }
            self.inner.snapshot()
        }
    }

    struct HeldManager {
        task: JoinHandle<()>,
        release: std::sync::mpsc::Sender<()>,
        dropped: oneshot::Receiver<()>,
        _rib: mpsc::Sender<rustbgpd_rib::update::RibUpdate>,
        _query: mpsc::Sender<rustbgpd_rib::update::RibUpdate>,
        _outbound: mpsc::Receiver<rustbgpd_rib::update::OutboundRouteUpdate>,
    }

    async fn held_manager() -> HeldManager {
        use rustbgpd_rib::{update::RibUpdate, PeerId, RibManager};
        use rustbgpd_wire::{Afi, Safi};
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};
        let (rib, rib_rx) = mpsc::channel(16);
        let (query, query_rx) = mpsc::channel(4);
        let manager = RibManager::new(
            rib_rx,
            query_rx,
            None,
            Some(Ipv4Addr::new(127, 255, 0, 1)),
            BgpMetrics::new(),
        );
        let task = tokio::spawn(manager.run());
        let source = Ipv4Addr::new(127, 0, 2, 1);
        rib.send(super::super::source_peer_up(source))
            .await
            .unwrap();
        rib.send(RibUpdate::RoutesReceived {
            peer: PeerId::from_ipv4(source),
            session_id: 0,
            announced: vec![super::super::route(super::super::prefix(0), source)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
        let (reply, count) = oneshot::channel();
        rib.send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        assert_eq!(count.await.unwrap(), 1);
        let destination = Ipv4Addr::new(127, 0, 2, 2);
        let (entered, wait_entered) = oneshot::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let (dropped, wait_dropped) = oneshot::channel();
        rib.send(RibUpdate::SetPeerExportEncoder {
            peer: PeerId::from_ipv4(destination),
            session_id: 0,
            encoder: Arc::new(HeldEncoder {
                inner: rustbgpd_transport::fanout_bench_export_encoder(),
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(wait_release),
                _dropped: NotifyOnDrop(Some(dropped)),
            }),
        })
        .await
        .unwrap();
        let (outbound, receive) = mpsc::channel(8);
        let mut registration = super::super::source_peer_up(destination);
        if let RibUpdate::PeerUp {
            outbound_tx,
            sendable_families,
            route_reflector_client,
            ..
        } = &mut registration
        {
            *outbound_tx = outbound;
            *sendable_families = vec![(Afi::Ipv4, Safi::Unicast)];
            *route_reflector_client = true;
        }
        rib.send(registration).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), wait_entered)
            .await
            .unwrap()
            .unwrap();
        HeldManager {
            task,
            release,
            dropped: wait_dropped,
            _rib: rib,
            _query: query,
            _outbound: receive,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_waits_for_real_rib_initial_replay() {
        let held = held_manager().await;
        let mut cleanup = Box::pin(abort_and_join([held.task]));
        let first = poll_once(cleanup.as_mut());
        let was_pending = first.is_pending();
        held.release.send(()).unwrap();
        match first {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => cleanup.await.unwrap(),
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), held.dropped)
            .await
            .unwrap()
            .unwrap();
        assert!(
            was_pending,
            "cleanup returned while the real RIB replay was still held"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_reports_panic_and_still_joins_real_rib() {
        let (dropped, wait_dropped) = oneshot::channel();
        let failed = tokio::spawn(async move {
            let _dropped = NotifyOnDrop(Some(dropped));
            panic!("intentional owned-task failure");
        });
        wait_dropped.await.unwrap();
        while !failed.is_finished() {
            tokio::task::yield_now().await;
        }
        let held = held_manager().await;
        let mut cleanup = Box::pin(abort_and_join([failed, held.task]));
        let first = poll_once(cleanup.as_mut());
        let was_pending = first.is_pending();
        held.release.send(()).unwrap();
        let result = match first {
            Poll::Ready(result) => result,
            Poll::Pending => cleanup.await,
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), held.dropped)
            .await
            .unwrap()
            .unwrap();
        assert!(was_pending, "a failed task skipped the remaining RIB join");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("intentional owned-task failure"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_retains_collector_error_and_still_joins_real_rib() {
        let held = held_manager().await;
        let mut tasks = HarnessTasks::<()>::new(held.task);
        tasks.collectors.push_back(tokio::spawn(async {
            Err(anyhow::anyhow!("intentional collector failure"))
        }));
        while !tasks.collectors[0].is_finished() {
            tokio::task::yield_now().await;
        }
        let mut cleanup =
            Box::pin(tasks.settle(tokio::time::Instant::now() + std::time::Duration::from_secs(5)));
        let first = poll_once(cleanup.as_mut());
        let was_pending = first.is_pending();
        held.release.send(()).unwrap();
        let result = match first {
            Poll::Ready(result) => result,
            Poll::Pending => cleanup.await,
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), held.dropped)
            .await
            .unwrap()
            .unwrap();
        assert!(
            was_pending,
            "collector failure skipped the remaining RIB join"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("intentional collector failure"));
    }

    #[tokio::test]
    async fn cleanup_accepts_deliberate_cancellation_after_task_drop() {
        let (entered, wait_entered) = oneshot::channel();
        let (dropped, mut wait_dropped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _dropped = NotifyOnDrop(Some(dropped));
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        wait_entered.await.unwrap();
        abort_and_join([task]).await.unwrap();
        assert!(wait_dropped.try_recv().is_ok());
    }

    #[tokio::test]
    async fn task_timeout_retains_handle_for_cleanup() {
        let task = tokio::spawn(std::future::pending::<()>());
        let observer = task.abort_handle();
        let mut tasks = VecDeque::from([task]);
        assert!(next_task(&mut tasks, tokio::time::Instant::now())
            .await
            .is_err());
        assert_eq!(tasks.len(), 1);
        assert!(!observer.is_finished());
        abort_and_join(tasks).await.unwrap();
        assert!(observer.is_finished());
    }

    #[tokio::test]
    async fn failed_setup_still_settles_completed_tcp_handshake_children() {
        use rustbgpd_evpn_load::{establish_on, establish_stream, PeerConfig, PeerError};
        use rustbgpd_wire::{Afi, Safi};
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::net::{TcpListener, TcpStream};
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let listener = TcpListener::bind(listen).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = || PeerConfig {
            listen,
            local_as: 64512,
            router_id: Ipv4Addr::LOCALHOST,
            hold_time: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        };
        let (accepted, connected) = tokio::join!(establish_on(listener, config()), async {
            establish_stream(TcpStream::connect(address).await.unwrap(), config()).await
        },);
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        let observers = accepted
            .tasks
            .iter()
            .chain(&connected.tasks)
            .map(JoinHandle::abort_handle)
            .collect::<Vec<_>>();
        let mut tasks = HarnessTasks::<()>::new(tokio::spawn(std::future::pending()));
        tasks.background.extend(connected.tasks);
        tasks.stub_senders.push(connected.tx);
        tasks
            .handshakes
            .push_back(tokio::spawn(async { Err(PeerError::PrematureClose) }));
        tasks
            .handshakes
            .push_back(tokio::spawn(async { Ok(accepted) }));
        while tasks.handshakes.iter().any(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
        let result = tasks
            .settle(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
            .await;
        assert!(result.is_err(), "setup failure was swallowed");
        assert!(
            observers.iter().all(tokio::task::AbortHandle::is_finished),
            "a completed handshake lost its reader/writer tasks"
        );
    }
}
