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
use tokio::sync::mpsc;
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
        }
    }

    /// Run the client loop. Connects, sends Initiation, streams messages.
    /// Returns when the mpsc channel is closed (daemon shutdown).
    pub async fn run(mut self) {
        let addr = self.config.collector_addr;
        let id = self.config.collector_id;
        let max_backoff = Duration::from_secs(self.config.reconnect_interval.max(1));

        loop {
            let mut backoff = Duration::from_secs(1);

            // Connect with backoff
            let mut stream = loop {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        info!(collector = %addr, "connected to BMP collector");
                        break stream;
                    }
                    Err(e) => {
                        debug!(collector = %addr, error = %e, backoff_secs = backoff.as_secs(), "BMP connect failed");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BmpVersion;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

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
