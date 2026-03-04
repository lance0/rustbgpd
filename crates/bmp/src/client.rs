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
use crate::types::BmpClientConfig;

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
}

impl BmpClient {
    #[must_use]
    pub fn new(
        config: BmpClientConfig,
        rx: mpsc::Receiver<Bytes>,
        sys_name: String,
        sys_descr: String,
    ) -> Self {
        Self {
            config,
            rx,
            sys_name,
            sys_descr,
        }
    }

    /// Run the client loop. Connects, sends Initiation, streams messages.
    /// Returns when the mpsc channel is closed (daemon shutdown).
    pub async fn run(mut self) {
        let addr = self.config.collector_addr;
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
            if let Err(e) = stream.write_all(&init_msg).await {
                warn!(collector = %addr, error = %e, "failed to send BMP Initiation");
                continue; // reconnect
            }

            // Stream messages until error or channel close
            loop {
                let Some(msg) = self.rx.recv().await else {
                    // Channel closed — send Termination and exit
                    let term = codec::encode_termination(0, "daemon shutting down");
                    let _ = stream.write_all(&term).await;
                    let _ = stream.flush().await;
                    info!(collector = %addr, "BMP client shutting down");
                    return;
                };

                if let Err(e) = stream.write_all(&msg).await {
                    warn!(collector = %addr, error = %e, "BMP write failed, reconnecting");
                    break; // reconnect
                }
            }
        }
    }
}
