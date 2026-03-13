//! Async RTR client — one tokio task per configured RPKI cache server.
//!
//! Connects via TCP, speaks RTR protocol version 1 (RFC 8210), and sends
//! VRP updates to the [`VrpManager`](super::vrp_manager::VrpManager).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant as TokioInstant;
use tracing::{debug, info, warn};

use crate::aspa::AspaRecord;
use crate::rtr_codec::{RtrDecodeError, RtrPdu};
use crate::vrp::VrpEntry;

/// Maximum read buffer size (256 KiB).
const MAX_READ_BUF: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Reset,
    Serial,
}

/// Update messages sent from an RTR client to the VRP manager.
#[derive(Debug, PartialEq, Eq)]
pub enum VrpUpdate {
    /// Full table replacement from a Reset Query response.
    FullTable {
        /// The cache server that sent this table.
        server: SocketAddr,
        /// All VRP entries from the full reset.
        entries: Vec<VrpEntry>,
        /// All ASPA records from the full reset (RTR v2 only).
        aspa_records: Vec<AspaRecord>,
    },
    /// Incremental delta from a Serial Query response.
    IncrementalUpdate {
        /// The cache server that sent this delta.
        server: SocketAddr,
        /// Newly announced VRP entries.
        announced: Vec<VrpEntry>,
        /// Withdrawn VRP entries.
        withdrawn: Vec<VrpEntry>,
        /// Newly announced ASPA records (RTR v2 only).
        aspa_announced: Vec<AspaRecord>,
        /// Withdrawn ASPA records (RTR v2 only).
        aspa_withdrawn: Vec<AspaRecord>,
    },
    /// Server connection lost — its entries should be expired.
    ServerDown {
        /// The cache server that went down.
        server: SocketAddr,
    },
}

/// Configuration for a single RTR cache server connection.
#[derive(Debug, Clone)]
pub struct RtrClientConfig {
    /// TCP address of the RTR cache server.
    pub server_addr: SocketAddr,
    /// Seconds between Serial Query polls.
    pub refresh_interval: u64,
    /// Seconds before retrying after a failed connection.
    pub retry_interval: u64,
    /// Seconds after which cached VRPs are considered stale.
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
    expire_interval: Duration,
    last_end_of_data_at: Option<TokioInstant>,
    data_expires_at: Option<TokioInstant>,
}

impl RtrClient {
    /// Create a new RTR client.
    #[must_use]
    pub fn new(config: RtrClientConfig, vrp_tx: mpsc::Sender<VrpUpdate>) -> Self {
        Self {
            refresh_interval: Duration::from_secs(config.refresh_interval),
            retry_interval: Duration::from_secs(config.retry_interval),
            expire_interval: Duration::from_secs(config.expire_interval),
            last_end_of_data_at: None,
            data_expires_at: None,
            vrp_tx,
            config,
            session_id: None,
            serial: None,
        }
    }

    /// Main event loop — connects, keeps the RTR session open, and reconnects
    /// on failure.
    pub async fn run(mut self) {
        loop {
            match TcpStream::connect(self.config.server_addr).await {
                Ok(stream) => {
                    info!(server = %self.config.server_addr, "RTR connected");
                    if let Err(e) = self.run_session(stream).await {
                        warn!(
                            server = %self.config.server_addr,
                            error = %e,
                            "RTR session ended"
                        );
                        let _ = self
                            .vrp_tx
                            .send(VrpUpdate::ServerDown {
                                server: self.config.server_addr,
                            })
                            .await;
                        self.last_end_of_data_at = None;
                        self.data_expires_at = None;
                        if matches!(e, RtrError::Expired) {
                            self.session_id = None;
                            self.serial = None;
                        }
                        tokio::time::sleep(self.retry_interval).await;
                    }
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
                    self.last_end_of_data_at = None;
                    self.data_expires_at = None;
                    tokio::time::sleep(self.retry_interval).await;
                }
            }
        }
    }

    fn current_query_kind(&self) -> QueryKind {
        if self.session_id.is_some() && self.serial.is_some() {
            QueryKind::Serial
        } else {
            QueryKind::Reset
        }
    }

    fn build_query_pdu(&self, query: QueryKind) -> RtrPdu {
        match (query, self.session_id, self.serial) {
            (QueryKind::Serial, Some(session_id), Some(serial)) => {
                RtrPdu::SerialQuery { session_id, serial }
            }
            _ => RtrPdu::ResetQuery,
        }
    }

    async fn send_query(&self, stream: &mut TcpStream, query: QueryKind) -> Result<bool, RtrError> {
        let query_pdu = self.build_query_pdu(query);
        let is_reset = matches!(query_pdu, RtrPdu::ResetQuery);
        let mut send_buf = Vec::new();
        query_pdu.encode(&mut send_buf);
        stream.write_all(&send_buf).await.map_err(RtrError::Io)?;
        Ok(is_reset)
    }

    async fn run_session(&mut self, mut stream: TcpStream) -> Result<(), RtrError> {
        let mut read_buf = vec![0u8; 8192];
        let mut parse_buf = Vec::new();
        let mut next_query = self.current_query_kind();

        loop {
            self.fetch_until_end_of_data(&mut stream, &mut read_buf, &mut parse_buf, next_query)
                .await?;
            next_query = self
                .wait_for_next_query(&mut stream, &mut read_buf, &mut parse_buf)
                .await?;
        }
    }

    async fn handle_idle_pdus(
        &mut self,
        parse_buf: &mut Vec<u8>,
    ) -> Result<Option<QueryKind>, RtrError> {
        let mut next_query = None;

        loop {
            if parse_buf.len() < 8 {
                break;
            }
            let Some(pdu_len) = RtrPdu::peek_length(parse_buf) else {
                break;
            };
            if parse_buf.len() < pdu_len as usize {
                break;
            }

            let (pdu, consumed) = RtrPdu::decode(parse_buf).map_err(RtrError::Decode)?;
            parse_buf.drain(..consumed);

            match pdu {
                RtrPdu::SerialNotify { session_id, serial } => {
                    debug!(
                        server = %self.config.server_addr,
                        session_id,
                        serial,
                        "RTR Serial Notify received"
                    );
                    let query = if self.session_id == Some(session_id) && self.serial.is_some() {
                        QueryKind::Serial
                    } else {
                        QueryKind::Reset
                    };
                    if !matches!(next_query, Some(QueryKind::Reset)) {
                        next_query = Some(query);
                    }
                }
                RtrPdu::CacheReset => {
                    info!(
                        server = %self.config.server_addr,
                        "RTR cache reset received while idle, sending Reset Query"
                    );
                    let _ = self
                        .vrp_tx
                        .send(VrpUpdate::FullTable {
                            server: self.config.server_addr,
                            entries: vec![],
                            aspa_records: vec![],
                        })
                        .await;
                    self.session_id = None;
                    self.serial = None;
                    self.last_end_of_data_at = None;
                    self.data_expires_at = None;
                    next_query = Some(QueryKind::Reset);
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
                    debug!(
                        server = %self.config.server_addr,
                        ?pdu,
                        "unexpected RTR PDU while idle (ignored)"
                    );
                }
            }
        }

        Ok(next_query)
    }

    async fn wait_for_next_query(
        &mut self,
        stream: &mut TcpStream,
        read_buf: &mut [u8],
        parse_buf: &mut Vec<u8>,
    ) -> Result<QueryKind, RtrError> {
        let refresh_deadline = TokioInstant::now() + self.refresh_interval;
        let mut refresh_sleep = Box::pin(tokio::time::sleep_until(refresh_deadline));
        let has_expiry = self.data_expires_at.is_some();
        let fallback_expiry = refresh_deadline + Duration::from_secs(365 * 24 * 60 * 60);
        let mut expire_sleep = Box::pin(tokio::time::sleep_until(
            self.data_expires_at.unwrap_or(fallback_expiry),
        ));

        loop {
            if let Some(query) = self.handle_idle_pdus(parse_buf).await? {
                return Ok(query);
            }

            tokio::select! {
                read = stream.read(read_buf) => {
                    let n = read.map_err(RtrError::Io)?;
                    if n == 0 {
                        return Err(RtrError::ConnectionClosed);
                    }
                    parse_buf.extend_from_slice(&read_buf[..n]);
                    if parse_buf.len() > MAX_READ_BUF {
                        return Err(RtrError::BufferOverflow);
                    }
                }
                () = refresh_sleep.as_mut() => {
                    debug!(
                        server = %self.config.server_addr,
                        interval = ?self.refresh_interval,
                        "RTR refresh timer fired, requesting update"
                    );
                    return Ok(self.current_query_kind());
                }
                () = expire_sleep.as_mut(), if has_expiry => {
                    return Err(RtrError::Expired);
                }
            }
        }
    }

    /// Fetch VRPs until `EndOfData`, then publish the resulting update.
    #[expect(clippy::too_many_lines)]
    async fn fetch_until_end_of_data(
        &mut self,
        stream: &mut TcpStream,
        read_buf: &mut [u8],
        parse_buf: &mut Vec<u8>,
        mut query: QueryKind,
    ) -> Result<(), RtrError> {
        'fetch: loop {
            let mut collecting = false;
            let mut announced = Vec::new();
            let mut withdrawn = Vec::new();
            let mut aspa_announced: Vec<AspaRecord> = Vec::new();
            let mut aspa_withdrawn: Vec<AspaRecord> = Vec::new();
            let is_reset = self.send_query(stream, query).await?;

            loop {
                while parse_buf.len() >= 8 {
                    let Some(pdu_len) = RtrPdu::peek_length(parse_buf) else {
                        break;
                    };
                    if parse_buf.len() < pdu_len as usize {
                        break;
                    }

                    let (pdu, consumed) = RtrPdu::decode(parse_buf).map_err(RtrError::Decode)?;
                    parse_buf.drain(..consumed);

                    match pdu {
                        RtrPdu::CacheResponse { session_id } => {
                            self.session_id = Some(session_id);
                            collecting = true;
                            announced.clear();
                            withdrawn.clear();
                            aspa_announced.clear();
                            aspa_withdrawn.clear();
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
                        RtrPdu::Aspa {
                            flags,
                            customer_asn,
                            provider_asns,
                        } if collecting => {
                            let record = AspaRecord {
                                customer_asn,
                                provider_asns,
                            };
                            if flags & 1 == 1 {
                                aspa_announced.push(record);
                            } else {
                                aspa_withdrawn.push(record);
                            }
                        }
                        RtrPdu::EndOfData {
                            session_id,
                            serial,
                            refresh,
                            retry,
                            expire,
                        } => {
                            self.session_id = Some(session_id);
                            self.serial = Some(serial);
                            if refresh > 0 {
                                self.refresh_interval = Duration::from_secs(u64::from(refresh));
                            }
                            if retry > 0 {
                                self.retry_interval = Duration::from_secs(u64::from(retry));
                            }
                            if expire > 0 {
                                self.expire_interval = Duration::from_secs(u64::from(expire));
                            }
                            let now = TokioInstant::now();
                            self.last_end_of_data_at = Some(now);
                            self.data_expires_at = Some(now + self.expire_interval);

                            let aspa_count = aspa_announced.len() + aspa_withdrawn.len();
                            let update = if is_reset {
                                info!(
                                    server = %self.config.server_addr,
                                    serial,
                                    vrps = announced.len(),
                                    aspa_records = aspa_announced.len(),
                                    "RTR full table received"
                                );
                                VrpUpdate::FullTable {
                                    server: self.config.server_addr,
                                    entries: std::mem::take(&mut announced),
                                    aspa_records: std::mem::take(&mut aspa_announced),
                                }
                            } else {
                                info!(
                                    server = %self.config.server_addr,
                                    serial,
                                    vrps_announced = announced.len(),
                                    vrps_withdrawn = withdrawn.len(),
                                    aspa_announced = aspa_announced.len(),
                                    aspa_withdrawn = aspa_withdrawn.len(),
                                    "RTR incremental update received"
                                );
                                VrpUpdate::IncrementalUpdate {
                                    server: self.config.server_addr,
                                    announced: std::mem::take(&mut announced),
                                    withdrawn: std::mem::take(&mut withdrawn),
                                    aspa_announced: std::mem::take(&mut aspa_announced),
                                    aspa_withdrawn: std::mem::take(&mut aspa_withdrawn),
                                }
                            };
                            if aspa_count > 0 {
                                debug!(
                                    server = %self.config.server_addr,
                                    "RTR v2 ASPA records received"
                                );
                            }

                            let _ = self.vrp_tx.send(update).await;
                            return Ok(());
                        }
                        RtrPdu::CacheReset => {
                            info!(
                                server = %self.config.server_addr,
                                "RTR cache reset received, sending Reset Query"
                            );
                            let _ = self
                                .vrp_tx
                                .send(VrpUpdate::FullTable {
                                    server: self.config.server_addr,
                                    entries: vec![],
                                    aspa_records: vec![],
                                })
                                .await;
                            self.session_id = None;
                            self.serial = None;
                            self.last_end_of_data_at = None;
                            self.data_expires_at = None;
                            query = QueryKind::Reset;
                            continue 'fetch;
                        }
                        RtrPdu::SerialNotify { .. } => {
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
                            debug!(
                                server = %self.config.server_addr,
                                ?pdu,
                                "unexpected RTR PDU during fetch (ignored)"
                            );
                        }
                    }
                }

                let n = stream.read(read_buf).await.map_err(RtrError::Io)?;
                if n == 0 {
                    return Err(RtrError::ConnectionClosed);
                }
                parse_buf.extend_from_slice(&read_buf[..n]);
                if parse_buf.len() > MAX_READ_BUF {
                    return Err(RtrError::BufferOverflow);
                }
            }
        }
    }
}

/// Errors from the RTR client.
#[derive(Debug, thiserror::Error)]
pub enum RtrError {
    /// TCP or socket I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// RTR PDU decoding failure.
    #[error("RTR decode error: {0}")]
    Decode(#[from] RtrDecodeError),
    /// The remote end closed the connection.
    #[error("connection closed")]
    ConnectionClosed,
    /// Inbound data exceeded the read buffer limit.
    #[error("read buffer overflow")]
    BufferOverflow,
    /// Cache data expired without a fresh `EndOfData`.
    #[error("cache data expired")]
    Expired,
    /// Cache server sent an Error Report PDU.
    #[error("server error (code {code}): {text}")]
    ServerError {
        /// Error code from the cache server.
        code: u16,
        /// Human-readable error text.
        text: String,
    },
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;
    use tokio::time::{advance, timeout};

    use super::*;

    fn test_config(
        server_addr: SocketAddr,
        refresh: u64,
        retry: u64,
        expire: u64,
    ) -> RtrClientConfig {
        RtrClientConfig {
            server_addr,
            refresh_interval: refresh,
            retry_interval: retry,
            expire_interval: expire,
        }
    }

    fn entry(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: std::net::IpAddr::V4(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    async fn read_pdu(stream: &mut TcpStream) -> RtrPdu {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let mut buf = header.to_vec();
        if len > header.len() {
            let mut body = vec![0u8; len - header.len()];
            stream.read_exact(&mut body).await.unwrap();
            buf.extend_from_slice(&body);
        }
        let (pdu, consumed) = RtrPdu::decode(&buf).unwrap();
        assert_eq!(consumed, len);
        pdu
    }

    async fn write_pdu(stream: &mut TcpStream, pdu: RtrPdu) {
        let mut buf = Vec::new();
        pdu.encode(&mut buf);
        stream.write_all(&buf).await.unwrap();
    }

    #[tokio::test]
    async fn serial_notify_triggers_incremental_refresh_without_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 65001)],
                aspa_records: vec![],
            }
        );

        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 114, 0),
                asn: 65002,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 101,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refresh_uses_serial_query_on_existing_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 10, 5, 30), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 10,
                retry: 5,
                expire: 30,
            },
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 101,
                refresh: 10,
                retry: 5,
                expire: 30,
            },
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn expire_interval_clears_server_entries_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 2, 10), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream1, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream1).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream1, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream1,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream1,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 2,
                expire: 10,
            },
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });

        advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;

        drop(stream1);
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn cache_reset_clears_entries_and_refetches_on_same_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        write_pdu(&mut stream, RtrPdu::CacheReset).await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![],
                aspa_records: vec![],
            }
        );

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 8 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 114, 0),
                asn: 65002,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 8,
                serial: 200,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn unexpected_serial_notify_during_fetch_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let _ = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), read_pdu(&mut stream))
                .await
                .is_err()
        );

        client_handle.abort();
        let _ = client_handle.await;
    }
}
