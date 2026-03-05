//! Per-collector async TCP client.
//!
//! Maintains a persistent connection to a single BMP collector.
//! Reconnects with backoff on failure. Sends pre-encoded BMP
//! messages received via an mpsc channel.

use std::time::Duration;

use bytes::Bytes;
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

    #[must_use]
    pub fn new(
        config: BmpClientConfig,
        rx: mpsc::Receiver<Bytes>,
        sys_name: String,
        sys_descr: String,
        control_tx: Option<mpsc::Sender<BmpControlEvent>>,
    ) -> Self {
        Self {
            config,
            rx,
            sys_name,
            sys_descr,
            control_tx,
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

            // Send Initiation message
            let init_msg = codec::encode_initiation(&self.sys_name, &self.sys_descr);
            if let Err(e) = Self::write_all_with_timeout(&mut stream, &init_msg).await {
                warn!(collector = %addr, error = %e, "failed to send BMP Initiation");
                continue; // reconnect
            }

            // Collector is now ready to receive BMP messages.
            if let Some(ref control_tx) = self.control_tx {
                let _ = control_tx.try_send(BmpControlEvent::CollectorConnected {
                    collector_id: id,
                    collector_addr: addr,
                });
            }

            // Stream messages until error or channel close
            loop {
                let Some(msg) = self.rx.recv().await else {
                    // Channel closed — send Termination and exit
                    let term = codec::encode_termination(0, "daemon shutting down");
                    let _ = Self::write_all_with_timeout(&mut stream, &term).await;
                    let _ = Self::flush_with_timeout(&mut stream).await;
                    info!(collector = %addr, "BMP client shutting down");
                    return;
                };

                if let Err(e) = Self::write_all_with_timeout(&mut stream, &msg).await {
                    warn!(collector = %addr, error = %e, "BMP write failed, reconnecting");
                    if let Some(ref control_tx) = self.control_tx {
                        let _ = control_tx.try_send(BmpControlEvent::CollectorDisconnected {
                            collector_id: id,
                            collector_addr: addr,
                        });
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
            },
            msg_rx,
            "rustbgpd".to_string(),
            "test".to_string(),
            Some(control_tx),
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
}
