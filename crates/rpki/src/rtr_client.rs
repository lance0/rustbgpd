//! Async RTR client — one tokio task per configured RPKI cache server.
//!
//! Connects via TCP, speaks RTR protocol version 1 (RFC 8210), and sends
//! VRP updates to the [`VrpManager`](super::vrp_manager::VrpManager).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::rtr_codec::{RtrDecodeError, RtrPdu};
use crate::vrp::VrpEntry;

/// Maximum read buffer size (256 KiB).
const MAX_READ_BUF: usize = 256 * 1024;

/// Update messages sent from an RTR client to the VRP manager.
#[derive(Debug)]
pub enum VrpUpdate {
    /// Full table replacement from a Reset Query response.
    FullTable {
        server: SocketAddr,
        entries: Vec<VrpEntry>,
    },
    /// Incremental delta from a Serial Query response.
    IncrementalUpdate {
        server: SocketAddr,
        announced: Vec<VrpEntry>,
        withdrawn: Vec<VrpEntry>,
    },
    /// Server connection lost — its entries should be expired.
    ServerDown { server: SocketAddr },
}

/// Configuration for a single RTR cache server connection.
#[derive(Debug, Clone)]
pub struct RtrClientConfig {
    pub server_addr: SocketAddr,
    pub refresh_interval: u64,
    pub retry_interval: u64,
    pub expire_interval: u64,
}

/// Per-cache-server RTR client.
///
/// Runs as a single tokio task: connects, exchanges RTR PDUs, sends VRP
/// updates to the manager, and reconnects on failure.
pub struct RtrClient {
    config: RtrClientConfig,
    session_id: Option<u16>,
    serial: Option<u32>,
    vrp_tx: mpsc::Sender<VrpUpdate>,
    refresh_interval: Duration,
    retry_interval: Duration,
}

impl RtrClient {
    /// Create a new RTR client.
    #[must_use]
    pub fn new(config: RtrClientConfig, vrp_tx: mpsc::Sender<VrpUpdate>) -> Self {
        Self {
            refresh_interval: Duration::from_secs(config.refresh_interval),
            retry_interval: Duration::from_secs(config.retry_interval),
            vrp_tx,
            config,
            session_id: None,
            serial: None,
        }
    }

    /// Main event loop — connects, fetches VRPs, sleeps, repeats.
    pub async fn run(mut self) {
        loop {
            match self.connect_and_fetch().await {
                Ok(()) => {
                    // Successful cycle — wait for refresh_interval before next Serial Query
                    debug!(
                        server = %self.config.server_addr,
                        interval = ?self.refresh_interval,
                        "RTR refresh cycle complete, sleeping"
                    );
                    tokio::time::sleep(self.refresh_interval).await;
                }
                Err(e) => {
                    warn!(
                        server = %self.config.server_addr,
                        error = %e,
                        "RTR connection failed"
                    );
                    let _ = self
                        .vrp_tx
                        .send(VrpUpdate::ServerDown {
                            server: self.config.server_addr,
                        })
                        .await;
                    tokio::time::sleep(self.retry_interval).await;
                }
            }
        }
    }

    /// Single connect-fetch cycle.
    #[expect(clippy::too_many_lines)]
    async fn connect_and_fetch(&mut self) -> Result<(), RtrError> {
        let mut stream = TcpStream::connect(self.config.server_addr)
            .await
            .map_err(RtrError::Io)?;

        info!(server = %self.config.server_addr, "RTR connected");

        // Send initial query
        let query = if let (Some(session_id), Some(serial)) = (self.session_id, self.serial) {
            RtrPdu::SerialQuery { session_id, serial }
        } else {
            RtrPdu::ResetQuery
        };

        let mut send_buf = Vec::new();
        query.encode(&mut send_buf);
        stream.write_all(&send_buf).await.map_err(RtrError::Io)?;

        // Read response
        let mut read_buf = vec![0u8; 8192];
        let mut parse_buf = Vec::new();
        let mut collecting = false;
        let mut is_reset = !matches!(query, RtrPdu::SerialQuery { .. });
        let mut announced = Vec::new();
        let mut withdrawn = Vec::new();

        loop {
            let n = stream.read(&mut read_buf).await.map_err(RtrError::Io)?;
            if n == 0 {
                return Err(RtrError::ConnectionClosed);
            }
            parse_buf.extend_from_slice(&read_buf[..n]);

            if parse_buf.len() > MAX_READ_BUF {
                return Err(RtrError::BufferOverflow);
            }

            // Parse as many PDUs as available
            loop {
                if parse_buf.len() < 8 {
                    break;
                }
                let Some(pdu_len) = RtrPdu::peek_length(&parse_buf) else {
                    break;
                };
                if parse_buf.len() < pdu_len as usize {
                    break;
                }
                let (pdu, consumed) = RtrPdu::decode(&parse_buf).map_err(RtrError::Decode)?;
                parse_buf.drain(..consumed);

                match pdu {
                    RtrPdu::CacheResponse { session_id } => {
                        self.session_id = Some(session_id);
                        collecting = true;
                        announced.clear();
                        withdrawn.clear();
                    }
                    RtrPdu::Ipv4Prefix {
                        flags,
                        prefix_len,
                        max_len,
                        prefix,
                        asn,
                    } if collecting => {
                        let entry = VrpEntry {
                            prefix: std::net::IpAddr::V4(prefix),
                            prefix_len,
                            max_len,
                            origin_asn: asn,
                        };
                        if flags & 1 == 1 {
                            announced.push(entry);
                        } else {
                            withdrawn.push(entry);
                        }
                    }
                    RtrPdu::Ipv6Prefix {
                        flags,
                        prefix_len,
                        max_len,
                        prefix,
                        asn,
                    } if collecting => {
                        let entry = VrpEntry {
                            prefix: std::net::IpAddr::V6(prefix),
                            prefix_len,
                            max_len,
                            origin_asn: asn,
                        };
                        if flags & 1 == 1 {
                            announced.push(entry);
                        } else {
                            withdrawn.push(entry);
                        }
                    }
                    RtrPdu::EndOfData {
                        session_id,
                        serial,
                        refresh,
                        retry,
                        expire: _,
                    } => {
                        self.session_id = Some(session_id);
                        self.serial = Some(serial);
                        // Update timers from server hints
                        if refresh > 0 {
                            self.refresh_interval = Duration::from_secs(u64::from(refresh));
                        }
                        if retry > 0 {
                            self.retry_interval = Duration::from_secs(u64::from(retry));
                        }

                        let update = if is_reset {
                            info!(
                                server = %self.config.server_addr,
                                serial,
                                entries = announced.len(),
                                "RTR full table received"
                            );
                            VrpUpdate::FullTable {
                                server: self.config.server_addr,
                                entries: std::mem::take(&mut announced),
                            }
                        } else {
                            info!(
                                server = %self.config.server_addr,
                                serial,
                                announced = announced.len(),
                                withdrawn = withdrawn.len(),
                                "RTR incremental update received"
                            );
                            VrpUpdate::IncrementalUpdate {
                                server: self.config.server_addr,
                                announced: std::mem::take(&mut announced),
                                withdrawn: std::mem::take(&mut withdrawn),
                            }
                        };

                        let _ = self.vrp_tx.send(update).await;
                        return Ok(());
                    }
                    RtrPdu::CacheReset => {
                        // Server says do a full reset
                        info!(
                            server = %self.config.server_addr,
                            "RTR cache reset received, sending Reset Query"
                        );
                        // A Cache Reset invalidates all data previously learned
                        // from this server. Clear its contribution immediately
                        // so stale VRPs are not retained until the replacement
                        // full table arrives.
                        let _ = self
                            .vrp_tx
                            .send(VrpUpdate::FullTable {
                                server: self.config.server_addr,
                                entries: vec![],
                            })
                            .await;
                        self.session_id = None;
                        self.serial = None;
                        is_reset = true;
                        collecting = false;
                        announced.clear();
                        withdrawn.clear();

                        send_buf.clear();
                        RtrPdu::ResetQuery.encode(&mut send_buf);
                        stream.write_all(&send_buf).await.map_err(RtrError::Io)?;
                    }
                    RtrPdu::SerialNotify { .. } => {
                        // Ignore during data exchange — we're already fetching
                        debug!(
                            server = %self.config.server_addr,
                            "RTR Serial Notify received during fetch (ignored)"
                        );
                    }
                    RtrPdu::ErrorReport { code, text, .. } => {
                        warn!(
                            server = %self.config.server_addr,
                            code,
                            text = %text,
                            "RTR error report received"
                        );
                        return Err(RtrError::ServerError { code, text });
                    }
                    _ => {
                        // Unexpected PDU type during collection — ignore
                        debug!(
                            server = %self.config.server_addr,
                            ?pdu,
                            "unexpected RTR PDU (ignored)"
                        );
                    }
                }
            }
        }
    }
}

/// Errors from the RTR client.
#[derive(Debug, thiserror::Error)]
pub enum RtrError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RTR decode error: {0}")]
    Decode(#[from] RtrDecodeError),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("read buffer overflow")]
    BufferOverflow,
    #[error("server error (code {code}): {text}")]
    ServerError { code: u16, text: String },
}
