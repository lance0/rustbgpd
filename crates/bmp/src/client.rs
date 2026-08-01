//! Per-collector async TCP client.
//!
//! Maintains a persistent connection to a single BMP collector.
//! Reconnects with backoff on failure. Sends pre-encoded BMP
//! messages received via an mpsc channel.

use std::time::Duration;

#[cfg(test)]
use bytes::Bytes;
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use crate::codec;
use crate::types::{BmpClientConfig, BmpControlEvent};

/// Write timeout for BMP collector TCP writes.
const BMP_WRITE_TIMEOUT_SECS: u64 = 5;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const COLLECTOR_CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostConnectWriteOutcome {
    Sent,
    Retry,
    Shutdown,
}

/// Per-collector BMP client.
///
/// Connects to a single collector, sends an Initiation message, then
/// streams pre-encoded BMP messages from its channel. Reconnects on
/// connection failure with capped exponential backoff.
pub struct BmpClient {
    config: BmpClientConfig,
    sys_name: String,
    sys_descr: String,
    control_tx: mpsc::Sender<BmpControlEvent>,
    metrics: BgpMetrics,
    reconnect_shutdown: Option<watch::Receiver<bool>>,
}

impl BmpClient {
    fn notify_disconnected(
        &self,
        collector_id: usize,
        collector_addr: std::net::SocketAddr,
        generation: u64,
    ) {
        if let Err(send_err) = self
            .control_tx
            .try_send(BmpControlEvent::CollectorDisconnected {
                collector_id,
                collector_addr,
                generation,
            })
        {
            let reason = match send_err {
                mpsc::error::TrySendError::Full(_) => "channel_full",
                mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            self.metrics.record_bmp_control_event_drop(
                &collector_addr.to_string(),
                "collector_disconnected",
                reason,
            );
        }
    }

    async fn write_all_with_timeout<W>(stream: &mut W, msg: &[u8]) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(
            Duration::from_secs(BMP_WRITE_TIMEOUT_SECS),
            stream.write_all(msg),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "BMP collector write timed out",
            )),
        }
    }

    async fn flush_with_timeout<W>(stream: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(Duration::from_secs(BMP_WRITE_TIMEOUT_SECS), stream.flush())
            .await
        {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "BMP collector flush timed out",
            )),
        }
    }

    async fn send_termination<W>(&self, stream: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let term = codec::encode_termination(0, "daemon shutting down", self.config.version);
        let _ = Self::write_all_with_timeout(stream, &term).await;
        let _ = Self::flush_with_timeout(stream).await;
    }

    async fn wait_post_connect_retry_or_terminate<W>(
        &self,
        stream: &mut W,
        shutdown: &mut watch::Receiver<bool>,
        backoff: &mut Duration,
        max_backoff: Duration,
    ) -> bool
    where
        W: AsyncWrite + Unpin,
    {
        if reconnect_shutdown_requested(shutdown) {
            self.send_termination(stream).await;
            return true;
        }
        wait_post_connect_retry(shutdown, backoff, max_backoff).await;
        if reconnect_shutdown_requested(shutdown) {
            self.send_termination(stream).await;
            return true;
        }
        false
    }

    async fn send_initiation_or_retry<W>(
        &self,
        stream: &mut W,
        message: &[u8],
        shutdown: &mut watch::Receiver<bool>,
        backoff: &mut Duration,
        max_backoff: Duration,
    ) -> PostConnectWriteOutcome
    where
        W: AsyncWrite + Unpin,
    {
        if let Err(error) = Self::write_all_with_timeout(stream, message).await {
            warn!(collector = %self.config.collector_addr, %error, "failed to send BMP Initiation");
            return if self
                .wait_post_connect_retry_or_terminate(stream, shutdown, backoff, max_backoff)
                .await
            {
                PostConnectWriteOutcome::Shutdown
            } else {
                PostConnectWriteOutcome::Retry
            };
        }
        PostConnectWriteOutcome::Sent
    }

    async fn send_live_or_retry<W>(
        &self,
        stream: &mut W,
        message: &[u8],
        generation: u64,
        shutdown: &mut watch::Receiver<bool>,
        backoff: &mut Duration,
        max_backoff: Duration,
    ) -> PostConnectWriteOutcome
    where
        W: AsyncWrite + Unpin,
    {
        if let Err(error) = Self::write_all_with_timeout(stream, message).await {
            warn!(collector = %self.config.collector_addr, %error, "BMP write failed, reconnecting");
            self.notify_disconnected(
                self.config.collector_id,
                self.config.collector_addr,
                generation,
            );
            return if self
                .wait_post_connect_retry_or_terminate(stream, shutdown, backoff, max_backoff)
                .await
            {
                PostConnectWriteOutcome::Shutdown
            } else {
                PostConnectWriteOutcome::Retry
            };
        }
        PostConnectWriteOutcome::Sent
    }

    /// Create a new BMP client for the given collector.
    #[must_use]
    pub fn new(
        config: BmpClientConfig,
        sys_name: String,
        sys_descr: String,
        control_tx: mpsc::Sender<BmpControlEvent>,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            config,
            sys_name,
            sys_descr,
            control_tx,
            metrics,
            reconnect_shutdown: None,
        }
    }

    /// Stop retrying a disconnected collector when daemon shutdown begins.
    ///
    /// The signal interrupts connection and bootstrap retries. Once a
    /// generation is live, the client waits for the manager to close its
    /// sender, drains the accepted queue, and sends Termination last.
    #[must_use]
    pub fn with_reconnect_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.reconnect_shutdown = Some(shutdown);
        self
    }

    /// Run the client loop. Connects, sends Initiation, streams messages.
    /// Returns when coordinated daemon shutdown closes the active generation.
    #[expect(
        clippy::too_many_lines,
        reason = "the ordered TCP generation lifecycle is kept in one state-machine loop"
    )]
    pub async fn run(mut self) {
        let addr = self.config.collector_addr;
        let id = self.config.collector_id;
        let max_backoff = Duration::from_secs(self.config.reconnect_interval.max(1));
        let mut post_connect_backoff = Duration::from_secs(1).min(max_backoff);

        // Keep the fallback sender alive for callers that do not install a
        // daemon shutdown signal. A closed watch channel is treated as a stop
        // request by the reconnect loop.
        let (_fallback_shutdown_tx, fallback_shutdown_rx) = watch::channel(false);
        let mut reconnect_shutdown = self
            .reconnect_shutdown
            .take()
            .unwrap_or(fallback_shutdown_rx);

        loop {
            let Some(mut stream) = connect_with_reconnect_shutdown(
                addr,
                max_backoff,
                &mut reconnect_shutdown,
                TcpStream::connect,
            )
            .await
            else {
                info!(collector = %addr, "BMP reconnect loop shutting down");
                return;
            };

            // Send Initiation message (framed at this collector's
            // configured BMP version)
            let init_msg =
                codec::encode_initiation(&self.sys_name, &self.sys_descr, self.config.version);
            match self
                .send_initiation_or_retry(
                    &mut stream,
                    &init_msg,
                    &mut reconnect_shutdown,
                    &mut post_connect_backoff,
                    max_backoff,
                )
                .await
            {
                PostConnectWriteOutcome::Sent => {}
                PostConnectWriteOutcome::Retry => continue,
                PostConnectWriteOutcome::Shutdown => return,
            }

            let (sender, mut rx) = mpsc::channel(COLLECTOR_CHANNEL_CAPACITY);
            let (bootstrap_tx, bootstrap_rx) = oneshot::channel();
            let event = BmpControlEvent::CollectorConnected {
                collector_id: id,
                collector_addr: addr,
                sender,
                bootstrap: bootstrap_tx,
            };
            let bootstrap = match tokio::time::timeout(CONTROL_TIMEOUT, self.control_tx.send(event))
                .await
            {
                Ok(Ok(())) => match tokio::time::timeout(CONTROL_TIMEOUT, bootstrap_rx).await {
                    Ok(Ok(bootstrap)) => bootstrap,
                    Ok(Err(_)) => {
                        self.metrics.record_bmp_control_event_drop(
                            &addr.to_string(),
                            "collector_connected",
                            "channel_closed",
                        );
                        warn!(collector = %addr, "BMP manager dropped bootstrap acknowledgement");
                        if self
                            .wait_post_connect_retry_or_terminate(
                                &mut stream,
                                &mut reconnect_shutdown,
                                &mut post_connect_backoff,
                                max_backoff,
                            )
                            .await
                        {
                            return;
                        }
                        continue;
                    }
                    Err(_) => {
                        self.metrics.record_bmp_control_event_drop(
                            &addr.to_string(),
                            "collector_connected",
                            "channel_timeout",
                        );
                        warn!(collector = %addr, "BMP manager bootstrap acknowledgement timed out");
                        if self
                            .wait_post_connect_retry_or_terminate(
                                &mut stream,
                                &mut reconnect_shutdown,
                                &mut post_connect_backoff,
                                max_backoff,
                            )
                            .await
                        {
                            return;
                        }
                        continue;
                    }
                },
                Ok(Err(_)) => {
                    self.metrics.record_bmp_control_event_drop(
                        &addr.to_string(),
                        "collector_connected",
                        "channel_closed",
                    );
                    if self
                        .wait_post_connect_retry_or_terminate(
                            &mut stream,
                            &mut reconnect_shutdown,
                            &mut post_connect_backoff,
                            max_backoff,
                        )
                        .await
                    {
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    self.metrics.record_bmp_control_event_drop(
                        &addr.to_string(),
                        "collector_connected",
                        "channel_timeout",
                    );
                    warn!(collector = %addr, "BMP control channel send timed out");
                    if self
                        .wait_post_connect_retry_or_terminate(
                            &mut stream,
                            &mut reconnect_shutdown,
                            &mut post_connect_backoff,
                            max_backoff,
                        )
                        .await
                    {
                        return;
                    }
                    continue;
                }
            };
            let mut bootstrap_failed = false;
            for message in bootstrap.messages {
                if let Err(e) = Self::write_all_with_timeout(&mut stream, &message).await {
                    warn!(collector = %addr, error = %e, "failed to write BMP bootstrap");
                    bootstrap_failed = true;
                    break;
                }
            }
            if bootstrap_failed {
                self.notify_disconnected(id, addr, bootstrap.generation);
                if self
                    .wait_post_connect_retry_or_terminate(
                        &mut stream,
                        &mut reconnect_shutdown,
                        &mut post_connect_backoff,
                        max_backoff,
                    )
                    .await
                {
                    return;
                }
                continue;
            }

            match tokio::time::timeout(
                CONTROL_TIMEOUT,
                self.control_tx
                    .send(BmpControlEvent::CollectorBootstrapComplete {
                        collector_id: id,
                        generation: bootstrap.generation,
                    }),
            )
            .await
            {
                Ok(Ok(())) => {
                    post_connect_backoff = Duration::from_secs(1).min(max_backoff);
                }
                Ok(Err(_)) => {
                    self.metrics.record_bmp_control_event_drop(
                        &addr.to_string(),
                        "collector_bootstrap_complete",
                        "channel_closed",
                    );
                    self.notify_disconnected(id, addr, bootstrap.generation);
                    if self
                        .wait_post_connect_retry_or_terminate(
                            &mut stream,
                            &mut reconnect_shutdown,
                            &mut post_connect_backoff,
                            max_backoff,
                        )
                        .await
                    {
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    self.metrics.record_bmp_control_event_drop(
                        &addr.to_string(),
                        "collector_bootstrap_complete",
                        "channel_timeout",
                    );
                    self.notify_disconnected(id, addr, bootstrap.generation);
                    if self
                        .wait_post_connect_retry_or_terminate(
                            &mut stream,
                            &mut reconnect_shutdown,
                            &mut post_connect_backoff,
                            max_backoff,
                        )
                        .await
                    {
                        return;
                    }
                    continue;
                }
            }

            // Stream messages until error or channel close
            loop {
                let Some(msg) = rx.recv().await else {
                    if reconnect_shutdown_requested(&reconnect_shutdown) {
                        // Coordinated shutdown closes the generation sender
                        // only after the manager's final messages are queued.
                        self.send_termination(&mut stream).await;
                        info!(collector = %addr, "BMP client shutting down");
                        return;
                    }
                    self.notify_disconnected(id, addr, bootstrap.generation);
                    if self
                        .wait_post_connect_retry_or_terminate(
                            &mut stream,
                            &mut reconnect_shutdown,
                            &mut post_connect_backoff,
                            max_backoff,
                        )
                        .await
                    {
                        info!(collector = %addr, "BMP client shutting down");
                        return;
                    }
                    break;
                };

                match self
                    .send_live_or_retry(
                        &mut stream,
                        &msg,
                        bootstrap.generation,
                        &mut reconnect_shutdown,
                        &mut post_connect_backoff,
                        max_backoff,
                    )
                    .await
                {
                    PostConnectWriteOutcome::Sent => {}
                    PostConnectWriteOutcome::Retry => break,
                    PostConnectWriteOutcome::Shutdown => return,
                }
            }
        }
    }
}

fn reconnect_shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

/// Wait between failed post-connect handshakes without delaying shutdown.
async fn wait_reconnect_backoff(shutdown: &mut watch::Receiver<bool>, delay: Duration) {
    if reconnect_shutdown_requested(shutdown) {
        return;
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => {}
        () = tokio::time::sleep(delay) => {}
    }
}

async fn wait_post_connect_retry(
    shutdown: &mut watch::Receiver<bool>,
    backoff: &mut Duration,
    max_backoff: Duration,
) {
    wait_reconnect_backoff(shutdown, *backoff).await;
    *backoff = backoff.saturating_mul(2).min(max_backoff);
}

async fn connect_with_reconnect_shutdown<F, Fut>(
    addr: std::net::SocketAddr,
    max_backoff: Duration,
    shutdown: &mut watch::Receiver<bool>,
    mut connect: F,
) -> Option<TcpStream>
where
    F: FnMut(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    let mut backoff = Duration::from_secs(1);

    loop {
        if reconnect_shutdown_requested(shutdown) {
            return None;
        }

        let connect_result = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || reconnect_shutdown_requested(shutdown) {
                    return None;
                }
                continue;
            }
            result = connect(addr) => result,
        };

        match connect_result {
            Ok(stream) => {
                info!(collector = %addr, "connected to BMP collector");
                return Some(stream);
            }
            Err(e) => {
                debug!(collector = %addr, error = %e, backoff_secs = backoff.as_secs(), "BMP connect failed");
            }
        }

        if reconnect_shutdown_requested(shutdown) {
            return None;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || reconnect_shutdown_requested(shutdown) {
                    return None;
                }
            }
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use super::*;
    use crate::types::BmpVersion;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    struct BrokenWriter;

    impl AsyncWrite for BrokenWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected initiation failure",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Load-bearing proof: replacing the connect select with a plain await
    /// trips the pending-connect assertion; replacing the backoff select with
    /// a plain sleep trips the reconnect-sleep assertion; deleting only the
    /// pre-connect state check leaves a receiver subscribed after shutdown in
    /// its pending connector and trips the already-signaled assertion.
    #[tokio::test(start_paused = true)]
    async fn reconnect_shutdown_interrupts_connect_and_backoff() {
        let addr = "127.0.0.1:9".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mut connect_shutdown = shutdown_rx.clone();
        let connect_task = tokio::spawn(async move {
            connect_with_reconnect_shutdown(
                addr,
                Duration::from_secs(30),
                &mut connect_shutdown,
                |_| std::future::pending::<std::io::Result<TcpStream>>(),
            )
            .await
        });

        let attempts = Arc::new(AtomicUsize::new(0));
        let backoff_attempts = Arc::clone(&attempts);
        let mut backoff_shutdown = shutdown_rx.clone();
        let backoff_task = tokio::spawn(async move {
            connect_with_reconnect_shutdown(
                addr,
                Duration::from_secs(30),
                &mut backoff_shutdown,
                move |_| {
                    backoff_attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "test refusal",
                    )))
                },
            )
            .await
        });

        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        shutdown_tx.send(true).unwrap();
        tokio::task::yield_now().await;
        assert!(
            connect_task.is_finished(),
            "pending connect ignored shutdown"
        );
        assert!(
            backoff_task.is_finished(),
            "reconnect sleep ignored shutdown"
        );
        assert!(connect_task.await.unwrap().is_none());
        assert!(backoff_task.await.unwrap().is_none());

        let mut already_signaled = shutdown_tx.subscribe();
        let already_signaled_task = tokio::spawn(async move {
            connect_with_reconnect_shutdown(
                addr,
                Duration::from_secs(30),
                &mut already_signaled,
                |_| std::future::pending::<std::io::Result<TcpStream>>(),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            already_signaled_task.is_finished(),
            "receiver subscribed after shutdown attempted a connection"
        );
        assert!(already_signaled_task.await.unwrap().is_none());
    }

    /// Load-bearing proof: adding an eager post-Initiation shutdown select
    /// drops the queued payload and Termination; deleting only the
    /// channel-close Termination encode, write, and flush retains the payload
    /// but makes the exact Termination suffix assertion red.
    #[tokio::test]
    async fn connected_shutdown_drains_payload_then_sends_exact_termination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let payload = Bytes::from_static(b"queued-before-shutdown");

        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        )
        .with_reconnect_shutdown(shutdown_rx);
        let handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed_initiation = vec![0; initiation.len()];
        stream.read_exact(&mut observed_initiation).await.unwrap();
        assert_eq!(observed_initiation, initiation);
        let BmpControlEvent::CollectorConnected {
            sender, bootstrap, ..
        } = control_rx.recv().await.unwrap()
        else {
            panic!("expected connected");
        };
        bootstrap
            .send(crate::types::BmpCollectorBootstrap {
                generation: 42,
                messages: vec![],
            })
            .unwrap();
        assert!(matches!(
            control_rx.recv().await,
            Some(BmpControlEvent::CollectorBootstrapComplete { generation: 42, .. })
        ));
        sender.send(payload.clone()).await.unwrap();
        shutdown_tx.send(true).unwrap();
        drop(sender);

        let termination = codec::encode_termination(0, "daemon shutting down", BmpVersion::V3);
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        let mut expected = payload.to_vec();
        expected.extend_from_slice(&termination);
        assert_eq!(tail, expected);
        handle.await.unwrap();
    }

    /// Load-bearing proof: dropping the pre-live shutdown termination path
    /// leaves an empty TCP tail when the manager closes the bootstrap
    /// acknowledgement during coordinated shutdown.
    #[tokio::test]
    async fn shutdown_during_bootstrap_sends_termination_last() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 30,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        )
        .with_reconnect_shutdown(shutdown_rx);
        let handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed = vec![0; initiation.len()];
        stream.read_exact(&mut observed).await.unwrap();
        let BmpControlEvent::CollectorConnected { bootstrap, .. } =
            control_rx.recv().await.unwrap()
        else {
            panic!("expected connected");
        };
        shutdown_tx.send(true).unwrap();
        drop(bootstrap);

        let termination = codec::encode_termination(0, "daemon shutting down", BmpVersion::V3);
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, termination.to_vec());
        handle.await.unwrap();
    }

    /// Load-bearing proof: treating every generation-channel close as daemon
    /// shutdown emits a Termination and exits instead of establishing the
    /// second TCP connection.
    #[tokio::test]
    async fn generation_channel_close_reconnects_without_termination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(client.run());

        let (mut first, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed = vec![0; initiation.len()];
        first.read_exact(&mut observed).await.unwrap();
        let BmpControlEvent::CollectorConnected {
            sender, bootstrap, ..
        } = control_rx.recv().await.unwrap()
        else {
            panic!("expected connected");
        };
        bootstrap
            .send(crate::types::BmpCollectorBootstrap {
                generation: 1,
                messages: vec![],
            })
            .unwrap();
        assert!(matches!(
            control_rx.recv().await,
            Some(BmpControlEvent::CollectorBootstrapComplete { generation: 1, .. })
        ));
        drop(sender);

        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert!(
            tail.is_empty(),
            "ordinary generation reset emitted Termination"
        );
        let _second = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("client did not reconnect after generation channel closed")
            .unwrap();
        handle.abort();
    }

    /// Load-bearing call-site proof: removing the bounded retry from the
    /// Initiation failure handler makes this task finish before one second.
    /// The injected writer makes the real Initiation write path fail without
    /// relying on TCP reset timing.
    #[tokio::test(start_paused = true)]
    async fn initiation_write_failure_waits_before_retry() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: "127.0.0.1:11019".parse().unwrap(),
                reconnect_interval: 4,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        );
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut writer = BrokenWriter;
            let mut backoff = Duration::from_secs(1);
            let outcome = client
                .send_initiation_or_retry(
                    &mut writer,
                    b"initiation",
                    &mut shutdown_rx,
                    &mut backoff,
                    Duration::from_secs(4),
                )
                .await;
            (outcome, backoff)
        });

        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "Initiation failure skipped retry delay"
        );
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!task.is_finished(), "Initiation retry fired too early");
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            task.await.unwrap(),
            (PostConnectWriteOutcome::Retry, Duration::from_secs(2))
        );
    }

    /// Load-bearing call-site proof: removing the bounded retry from the live
    /// write failure handler makes this task finish before one second. The
    /// injected writer avoids relying on TCP reset timing.
    #[tokio::test(start_paused = true)]
    async fn live_write_failure_waits_before_reconnect() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: "127.0.0.1:11020".parse().unwrap(),
                reconnect_interval: 4,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        );
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut writer = BrokenWriter;
            let mut backoff = Duration::from_secs(1);
            let outcome = client
                .send_live_or_retry(
                    &mut writer,
                    b"live",
                    42,
                    &mut shutdown_rx,
                    &mut backoff,
                    Duration::from_secs(4),
                )
                .await;
            (outcome, backoff)
        });

        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "live write failure skipped retry delay"
        );
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!task.is_finished(), "live retry fired too early");
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            task.await.unwrap(),
            (PostConnectWriteOutcome::Retry, Duration::from_secs(2))
        );
        assert!(matches!(
            control_rx.recv().await,
            Some(BmpControlEvent::CollectorDisconnected { generation: 42, .. })
        ));
    }

    /// Load-bearing proof: draining the live receiver before writing the
    /// bootstrap reverses the two sentinels; sending `BootstrapComplete` before
    /// the bootstrap write lets the assertion observe completion too early.
    #[tokio::test]
    async fn writes_bootstrap_before_completion_and_live_queue() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (control_tx, mut control_rx) = mpsc::channel(8);
        let bootstrap_message = Bytes::from_static(b"bootstrap-before-live");
        let live_message = Bytes::from_static(b"live-after-bootstrap");

        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(client.run());

        // Initiation is always the first BMP message on a connection.
        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed_initiation = vec![0; initiation.len()];
        stream.read_exact(&mut observed_initiation).await.unwrap();
        assert_eq!(observed_initiation, initiation);

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), control_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match ev {
            BmpControlEvent::CollectorConnected {
                collector_id,
                collector_addr,
                sender,
                bootstrap,
            } => {
                assert_eq!(collector_id, 7);
                assert_eq!(collector_addr, addr);
                sender.send(live_message.clone()).await.unwrap();
                bootstrap
                    .send(crate::types::BmpCollectorBootstrap {
                        generation: 1,
                        messages: vec![bootstrap_message.clone()],
                    })
                    .unwrap();
            }
            other => panic!("expected CollectorConnected, got {other:?}"),
        }

        assert!(matches!(
            control_rx.recv().await,
            Some(BmpControlEvent::CollectorBootstrapComplete {
                collector_id: 7,
                generation: 1
            })
        ));
        let mut ordered = vec![0; bootstrap_message.len() + live_message.len()];
        stream.read_exact(&mut ordered).await.unwrap();
        let mut expected = bootstrap_message.to_vec();
        expected.extend_from_slice(&live_message);
        assert_eq!(ordered, expected);

        handle.abort();
    }

    /// Load-bearing proof: removing the completion send timeout hangs this
    /// test; entering the live loop after the timeout writes the queued live
    /// sentinel and makes the empty-wire assertion red.
    #[tokio::test]
    async fn bootstrap_completion_timeout_never_enters_live_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let control_fill_tx = control_tx.clone();
        let metrics = BgpMetrics::new();
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            metrics.clone(),
        );
        let handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed_initiation = vec![0; initiation.len()];
        stream.read_exact(&mut observed_initiation).await.unwrap();
        let BmpControlEvent::CollectorConnected {
            sender, bootstrap, ..
        } = control_rx.recv().await.unwrap()
        else {
            panic!("expected connected");
        };
        sender
            .send(Bytes::from_static(b"must-not-reach-wire"))
            .await
            .unwrap();
        control_fill_tx
            .send(BmpControlEvent::Shutdown)
            .await
            .unwrap();
        bootstrap
            .send(crate::types::BmpCollectorBootstrap {
                generation: 9,
                messages: vec![],
            })
            .unwrap();

        tokio::time::sleep(CONTROL_TIMEOUT + Duration::from_millis(100)).await;
        let mut sentinel = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut sentinel))
                .await
                .is_err(),
            "live queue drained after BootstrapComplete timed out"
        );
        let drops = metrics
            .registry()
            .gather()
            .iter()
            .find(|family| family.name() == "bmp_control_event_drops_total")
            .into_iter()
            .flat_map(|family| &family.metric)
            .filter(|metric| {
                metric.label.iter().any(|label| {
                    label.name() == "kind" && label.value() == "collector_bootstrap_complete"
                }) && metric
                    .label
                    .iter()
                    .any(|label| label.name() == "reason" && label.value() == "channel_timeout")
            })
            .map(|metric| metric.counter.value())
            .sum::<f64>();
        assert!((drops - 1.0).abs() < f64::EPSILON);
        handle.abort();
    }

    /// Load-bearing proof: removing the delay makes the task finish before
    /// one second; removing the doubling leaves the returned delay at one
    /// second; ignoring shutdown leaves the final task pending.
    #[tokio::test(start_paused = true)]
    async fn post_connect_retry_is_delayed_capped_and_shutdown_aware() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut delayed_shutdown = shutdown_rx.clone();
        let delayed = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            wait_post_connect_retry(&mut delayed_shutdown, &mut backoff, Duration::from_secs(4))
                .await;
            backoff
        });
        tokio::task::yield_now().await;
        assert!(!delayed.is_finished());
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!delayed.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(delayed.await.unwrap(), Duration::from_secs(2));

        let mut interrupted_shutdown = shutdown_rx;
        let interrupted = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(4);
            wait_post_connect_retry(
                &mut interrupted_shutdown,
                &mut backoff,
                Duration::from_secs(4),
            )
            .await;
        });
        tokio::task::yield_now().await;
        assert!(!interrupted.is_finished());
        shutdown_tx.send(true).unwrap();
        tokio::task::yield_now().await;
        assert!(interrupted.is_finished());
    }

    /// Load-bearing proof: removing the Connected send timeout hangs the test;
    /// failing open into the live stream would make the connection persist
    /// without a manager-owned generation. The timeout is surfaced via
    /// `bmp_control_event_drops_total{kind=collector_connected,
    /// reason=channel_timeout}`.
    #[tokio::test]
    async fn collector_connected_send_timeout_increments_control_drop_counter() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 1-deep + pre-fill = next send blocks until pre-fill is drained.
        // The manager-side receiver here is never read, so the send
        // hits the 1 s timeout in the client.
        let (control_tx, _control_rx) = mpsc::channel::<BmpControlEvent>(1);
        control_tx
            .try_send(BmpControlEvent::CollectorDisconnected {
                collector_id: 0,
                collector_addr: addr,
                generation: 0,
            })
            .unwrap();

        let metrics = BgpMetrics::new();
        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            "rustbgpd".to_string(),
            "test".to_string(),
            control_tx,
            metrics.clone(),
        );
        let handle = tokio::spawn(client.run());

        // Accept and drain so the Initiation write completes — the
        // failure mode we want to exercise is post-Initiation.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();

        // Wait long enough for the 1 s control_tx.send timeout to elapse
        // and the metric to be incremented.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
        )]
        let drops = metrics
            .registry()
            .gather()
            .iter()
            .find(|f| f.name() == "bmp_control_event_drops_total")
            .map_or(0, |f| {
                f.metric
                    .iter()
                    .filter(|m| {
                        m.label
                            .iter()
                            .any(|l| l.name() == "kind" && l.value() == "collector_connected")
                            && m.label
                                .iter()
                                .any(|l| l.name() == "reason" && l.value() == "channel_timeout")
                    })
                    .map(|m| m.counter.value() as u64)
                    .sum::<u64>()
            });
        assert!(
            drops >= 1,
            "wedged control channel should bump bmp_control_event_drops_total \
             {{kind=collector_connected, reason=channel_timeout}} (got {drops})"
        );

        handle.abort();
    }
}
