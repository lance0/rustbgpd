//! Per-collector async TCP client.
//!
//! Maintains a persistent connection to a single BMP collector.
//! Reconnects with backoff on failure. Sends pre-encoded BMP
//! messages received via an mpsc channel.

use std::time::Duration;

use bytes::Bytes;
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::codec;
use crate::types::{BmpClientConfig, BmpControlEvent};

/// Write timeout for BMP collector TCP writes.
const BMP_WRITE_TIMEOUT_SECS: u64 = 5;

/// Per-collector BMP client.
///
/// Connects to a single collector, sends an Initiation message, then
/// streams pre-encoded BMP messages from its channel. Reconnects on
/// connection failure with capped exponential backoff.
pub struct BmpClient {
    config: BmpClientConfig,
    rx: mpsc::Receiver<Bytes>,
    sys_name: String,
    sys_descr: String,
    control_tx: Option<mpsc::Sender<BmpControlEvent>>,
    metrics: BgpMetrics,
    reconnect_shutdown: Option<watch::Receiver<bool>>,
}

impl BmpClient {
    async fn write_all_with_timeout(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
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

    async fn flush_with_timeout(stream: &mut TcpStream) -> std::io::Result<()> {
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

    /// Create a new BMP client for the given collector.
    #[must_use]
    pub fn new(
        config: BmpClientConfig,
        rx: mpsc::Receiver<Bytes>,
        sys_name: String,
        sys_descr: String,
        control_tx: Option<mpsc::Sender<BmpControlEvent>>,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            config,
            rx,
            sys_name,
            sys_descr,
            control_tx,
            metrics,
            reconnect_shutdown: None,
        }
    }

    /// Stop retrying a disconnected collector when daemon shutdown begins.
    ///
    /// The signal is intentionally observed only while connecting or waiting
    /// to reconnect. Once Initiation has been sent, the client drains the
    /// manager queue before sending Termination.
    #[must_use]
    pub fn with_reconnect_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.reconnect_shutdown = Some(shutdown);
        self
    }

    /// Run the client loop. Connects, sends Initiation, streams messages.
    /// Returns when the mpsc channel is closed (daemon shutdown).
    pub async fn run(mut self) {
        let addr = self.config.collector_addr;
        let id = self.config.collector_id;
        let max_backoff = Duration::from_secs(self.config.reconnect_interval.max(1));

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
            if let Err(e) = Self::write_all_with_timeout(&mut stream, &init_msg).await {
                warn!(collector = %addr, error = %e, "failed to send BMP Initiation");
                continue; // reconnect
            }

            // Collector is now ready to receive BMP messages. Surface
            // a back-pressure or closed-channel failure here loudly:
            // dropping this event silently means the manager never
            // replays the PeerUp cache to a freshly reconnected
            // collector, even though the collector is connected and
            // looks healthy from the client side. Use a 1 s timed
            // send so a wedged manager doesn't block reconnect
            // forever — and bump bmp_control_event_drops_total on
            // either failure mode so operators can alert on the
            // skipped replay rather than tail logs.
            if let Some(ref control_tx) = self.control_tx {
                let event = BmpControlEvent::CollectorConnected {
                    collector_id: id,
                    collector_addr: addr,
                };
                match tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    control_tx.send(event),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        self.metrics.record_bmp_control_event_drop(
                            &addr.to_string(),
                            "collector_connected",
                            "channel_closed",
                        );
                        warn!(
                            collector = %addr,
                            "BMP control channel closed; PeerUp replay will not fire"
                        );
                    }
                    Err(_) => {
                        self.metrics.record_bmp_control_event_drop(
                            &addr.to_string(),
                            "collector_connected",
                            "channel_timeout",
                        );
                        warn!(
                            collector = %addr,
                            "BMP control channel send timed out; PeerUp replay will not fire"
                        );
                    }
                }
            }

            // Stream messages until error or channel close
            loop {
                let Some(msg) = self.rx.recv().await else {
                    // Channel closed — send Termination and exit
                    let term =
                        codec::encode_termination(0, "daemon shutting down", self.config.version);
                    let _ = Self::write_all_with_timeout(&mut stream, &term).await;
                    let _ = Self::flush_with_timeout(&mut stream).await;
                    info!(collector = %addr, "BMP client shutting down");
                    return;
                };

                if let Err(e) = Self::write_all_with_timeout(&mut stream, &msg).await {
                    warn!(collector = %addr, error = %e, "BMP write failed, reconnecting");
                    if let Some(ref control_tx) = self.control_tx {
                        // CollectorDisconnected is best-effort but
                        // still observable: a dropped Disconnected
                        // means the manager won't see the gap until
                        // the next reconnect's Connected — count it
                        // so operators can spot stuck disconnected
                        // states.
                        if let Err(send_err) =
                            control_tx.try_send(BmpControlEvent::CollectorDisconnected {
                                collector_id: id,
                                collector_addr: addr,
                            })
                        {
                            let reason = match send_err {
                                mpsc::error::TrySendError::Full(_) => "channel_full",
                                mpsc::error::TrySendError::Closed(_) => "channel_closed",
                            };
                            self.metrics.record_bmp_control_event_drop(
                                &addr.to_string(),
                                "collector_disconnected",
                                reason,
                            );
                        }
                    }
                    break; // reconnect
                }
            }
        }
    }
}

fn reconnect_shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::types::BmpVersion;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

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
        let (msg_tx, msg_rx) = mpsc::channel(8);
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
            msg_rx,
            "rustbgpd".to_string(),
            "test".to_string(),
            Some(control_tx),
            BgpMetrics::new(),
        )
        .with_reconnect_shutdown(shutdown_rx);
        let handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = codec::encode_initiation("rustbgpd", "test", BmpVersion::V3);
        let mut observed_initiation = vec![0; initiation.len()];
        stream.read_exact(&mut observed_initiation).await.unwrap();
        assert_eq!(observed_initiation, initiation);
        assert!(matches!(
            control_rx.recv().await,
            Some(BmpControlEvent::CollectorConnected { .. })
        ));

        msg_tx.send(payload.clone()).await.unwrap();
        shutdown_tx.send(true).unwrap();
        drop(msg_tx);

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

    #[tokio::test]
    async fn emits_collector_connected_after_initiation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_msg_tx, msg_rx) = mpsc::channel(8);
        let (control_tx, mut control_rx) = mpsc::channel(8);

        let client = BmpClient::new(
            BmpClientConfig {
                collector_id: 7,
                collector_addr: addr,
                reconnect_interval: 1,
                version: BmpVersion::V3,
            },
            msg_rx,
            "rustbgpd".to_string(),
            "test".to_string(),
            Some(control_tx),
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(client.run());

        // Accept TCP connection and read a little data so initiation write path runs.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), control_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match ev {
            BmpControlEvent::CollectorConnected {
                collector_id,
                collector_addr,
            } => {
                assert_eq!(collector_id, 7);
                assert_eq!(collector_addr, addr);
            }
            other => panic!("expected CollectorConnected, got {other:?}"),
        }

        handle.abort();
    }

    /// When the manager's control channel is wedged (saturated and
    /// not draining), `CollectorConnected` send times out — but the
    /// collector stays connected and the rest of the BMP stream
    /// continues. We must surface the silent skipped replay via
    /// `bmp_control_event_drops_total{kind=collector_connected,
    /// reason=channel_timeout}`.
    #[tokio::test]
    async fn collector_connected_send_timeout_increments_control_drop_counter() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_msg_tx, msg_rx) = mpsc::channel(8);
        // 1-deep + pre-fill = next send blocks until pre-fill is drained.
        // The manager-side receiver here is never read, so the send
        // hits the 1 s timeout in the client.
        let (control_tx, _control_rx) = mpsc::channel::<BmpControlEvent>(1);
        control_tx
            .try_send(BmpControlEvent::CollectorDisconnected {
                collector_id: 0,
                collector_addr: addr,
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
            msg_rx,
            "rustbgpd".to_string(),
            "test".to_string(),
            Some(control_tx),
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
