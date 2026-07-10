//! Async RTR client — one tokio task per configured RPKI cache server.
//!
//! Connects via TCP, prefers RTR protocol version 2 for ASPA support, falls
//! back to version 1 on explicit server rejection, and sends VRP updates to
//! the [`VrpManager`](super::vrp_manager::VrpManager).
//!
//! Cache state is modeled as one per-cache epoch — the
//! `(protocol version, session ID, serial)` triple — advanced only as a
//! unit at a validated End of Data. Any identity mismatch mid-stream
//! triggers a full resynchronization (Reset Query), never a splice.
//! Validated data is retained through reconnects and Cache Reset until a
//! full replacement completes or the expire interval passes. Each
//! transaction is bounded by a deadline and record/byte budgets. See the
//! crate-level docs for the supported RFC 8210 / 8210bis subset.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant as TokioInstant;
use tracing::{debug, info, warn};

use crate::aspa::AspaRecord;
use crate::rtr_codec::{RtrDecodeError, RtrEncodeError, RtrPdu};
use crate::vrp::VrpEntry;

/// Maximum read buffer size (256 KiB).
const MAX_READ_BUF: usize = 256 * 1024;

/// Wall-clock budget for one RTR transaction (query → End of Data).
/// A full production table transfers in seconds; a cache that cannot
/// complete within this window is broken or hostile.
const TRANSACTION_DEADLINE: Duration = Duration::from_mins(5);

/// Record budget for one RTR transaction (VRPs + ASPAs, announce +
/// withdraw). The global VRP set is well under 1M; 4M leaves years of
/// headroom while bounding worst-case collection memory.
const MAX_TRANSACTION_RECORDS: usize = 4_000_000;

/// Wire-byte budget for one RTR transaction.
const MAX_TRANSACTION_BYTES: usize = 256 * 1024 * 1024;

/// Maximum in-transaction restarts (identity mismatch, Cache Reset)
/// before the connection is dropped and retries are paced by
/// `retry_interval`.
const MAX_TRANSACTION_RESTARTS: u8 = 2;

/// RFC 1982 serial-number order: `new` is the same as or after `old`.
fn serial_not_before(old: u32, new: u32) -> bool {
    new.wrapping_sub(old) < (1 << 31)
}

/// One cache epoch: the `(protocol version, session ID, serial)` triple
/// identifying a coherent cache state.
///
/// The three values advance together and are only ever set as a unit, at a
/// validated End of Data. Incremental (Serial Query) data may only be
/// spliced onto a table whose epoch matches the response identity; any
/// mismatch forces a full resynchronization via Reset Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheEpoch {
    version: u8,
    session_id: u16,
    serial: u32,
}

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
    /// The cache epoch backing the currently held data, if any.
    epoch: Option<CacheEpoch>,
    vrp_tx: mpsc::Sender<VrpUpdate>,
    refresh_interval: Duration,
    retry_interval: Duration,
    expire_interval: Duration,
    last_end_of_data_at: Option<TokioInstant>,
    data_expires_at: Option<TokioInstant>,
    /// Protocol version used for the current connection attempt
    /// (2 = ASPA capable, 1 = VRP only).
    negotiated_version: u8,
    /// Per-transaction budgets (consts in production; shrunk in tests).
    transaction_deadline: Duration,
    max_transaction_records: usize,
    max_transaction_bytes: usize,
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
            epoch: None,
            negotiated_version: crate::rtr_codec::RTR_VERSION_2,
            transaction_deadline: TRANSACTION_DEADLINE,
            max_transaction_records: MAX_TRANSACTION_RECORDS,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
        }
    }

    /// Main event loop — connects, keeps the RTR session open, and reconnects
    /// on failure.
    pub async fn run(mut self) {
        loop {
            self.prepare_fresh_connection_attempt();
            if let Err(e) = self.connect_and_run().await {
                warn!(
                    server = %self.config.server_addr,
                    error = %e,
                    "RTR connection failed"
                );
                self.handle_disconnected_session(false).await;
            }
        }
    }

    fn prepare_fresh_connection_attempt(&mut self) {
        // Reconnect at the version the held data was validated under.
        // Re-probing v2 while holding a v1 epoch wedges against v1-only
        // caches (StayRTR, GoRTR): they answer the v2 query with a
        // version-0 Error Report, which fails the version check as a
        // decode-level mismatch, and with data held no fallback signal
        // fires — the client would loop until the data expired and
        // validation flapped. A downgraded cache that merely restarted
        // must instead re-land its v1 session within one retry, with
        // full retention.
        //
        // v2 upgrade policy: the preferred version is deliberately
        // re-probed only at the epoch-less points — initial start and
        // after data expiry (see `handle_disconnected_session`) — so a
        // cache that later gains v2 support is still discovered without
        // risking held data. With no epoch, keep the current (possibly
        // downgraded) version so the v1 fallback sticks across retries.
        if let Some(epoch) = self.epoch {
            self.negotiated_version = epoch.version;
        }
    }

    async fn connect_and_run(&mut self) -> Result<(), std::io::Error> {
        let stream = TcpStream::connect(self.config.server_addr).await?;
        info!(
            server = %self.config.server_addr,
            rtr_version = self.negotiated_version,
            "RTR connected"
        );

        if let Err(error) = self.run_session(stream).await {
            if self.should_fallback_to_v1(&error) {
                self.run_v1_fallback_session().await;
                return Ok(());
            }

            warn!(
                server = %self.config.server_addr,
                error = %error,
                "RTR session ended"
            );
            self.handle_disconnected_session(matches!(error, RtrError::Expired))
                .await;
        }

        Ok(())
    }

    fn should_fallback_to_v1(&self, error: &RtrError) -> bool {
        if self.negotiated_version != crate::rtr_codec::RTR_VERSION_2 {
            return false;
        }
        // Explicit "Unsupported Protocol Version" error (code 4).
        if matches!(error, RtrError::ServerError { code: 4, .. }) {
            return true;
        }
        // Server closed the connection, answered with a lower version
        // byte, or sent garbage without ever completing a transaction
        // (no epoch established). Real-world caches like GoRTR and
        // StayRTR disconnect on unsupported versions instead of sending
        // error code 4.
        self.epoch.is_none()
            && matches!(
                error,
                RtrError::Io(_)
                    | RtrError::ConnectionClosed
                    | RtrError::Decode(_)
                    | RtrError::VersionMismatch { .. }
            )
    }

    async fn run_v1_fallback_session(&mut self) {
        info!(
            server = %self.config.server_addr,
            "RTR server does not support v2, falling back to v1 (no ASPA)"
        );
        self.negotiated_version = crate::rtr_codec::RTR_VERSION;
        // The v2 epoch is no longer valid at v1, so the next query is a
        // full Reset Query. Held data and its expiry are retained until
        // the v1 full table replaces them or the expire interval passes.
        self.epoch = None;

        match TcpStream::connect(self.config.server_addr).await {
            Ok(stream) => {
                info!(
                    server = %self.config.server_addr,
                    rtr_version = self.negotiated_version,
                    "RTR reconnected with fallback version"
                );
                if let Err(error) = self.run_session(stream).await {
                    warn!(
                        server = %self.config.server_addr,
                        error = %error,
                        "RTR session ended after v1 fallback"
                    );
                    self.handle_disconnected_session(matches!(error, RtrError::Expired))
                        .await;
                }
            }
            Err(error) => {
                warn!(
                    server = %self.config.server_addr,
                    error = %error,
                    "RTR reconnection for v1 fallback failed"
                );
                self.handle_disconnected_session(false).await;
            }
        }
    }

    /// Handle a lost or failed session.
    ///
    /// Validated data is RETAINED through reconnect: `ServerDown` (which
    /// drops the cache's entries from the merged tables) is only sent once
    /// the expire interval passes without a fresh End of Data — either
    /// signalled by the session (`expired_now`) or detected here while
    /// retrying. A mere disconnect must not flap route validation.
    async fn handle_disconnected_session(&mut self, expired_now: bool) {
        let now = TokioInstant::now();
        let expired = expired_now || self.data_expires_at.is_some_and(|at| now >= at);
        if expired {
            let _ = self
                .vrp_tx
                .send(VrpUpdate::ServerDown {
                    server: self.config.server_addr,
                })
                .await;
            self.epoch = None;
            self.last_end_of_data_at = None;
            self.data_expires_at = None;
            // Data expiry is the deliberate v2 re-probe point: with
            // nothing held there is no retention to protect, so try the
            // preferred version again in case the cache gained v2
            // support. A still-v1-only cache answers the probe with a
            // rejection, and the epoch-less fallback path re-lands v1.
            self.negotiated_version = crate::rtr_codec::RTR_VERSION_2;
        }
        // Wake at expiry if it lands inside the retry window, so retained
        // data cannot outlive its expire interval across failed retries.
        let sleep_for = self.data_expires_at.map_or(self.retry_interval, |at| {
            self.retry_interval.min(at.saturating_duration_since(now))
        });
        tokio::time::sleep(sleep_for).await;
    }

    fn current_query_kind(&self) -> QueryKind {
        // An epoch is only usable for incremental queries at the version
        // it was established under; after a version change the next query
        // must be a full Reset Query.
        match self.epoch {
            Some(epoch) if epoch.version == self.negotiated_version => QueryKind::Serial,
            _ => QueryKind::Reset,
        }
    }

    fn build_query_pdu(&self, query: QueryKind) -> RtrPdu {
        match (query, self.epoch) {
            (QueryKind::Serial, Some(epoch)) => RtrPdu::SerialQuery {
                session_id: epoch.session_id,
                serial: epoch.serial,
            },
            _ => RtrPdu::ResetQuery,
        }
    }

    /// Pop the next complete PDU off `parse_buf`, enforcing that its
    /// version byte matches the negotiated connection version so records
    /// from different protocol versions can never mix in one session.
    fn next_pdu(&self, parse_buf: &mut Vec<u8>) -> Result<Option<RtrPdu>, RtrError> {
        if parse_buf.len() < 8 {
            return Ok(None);
        }
        let Some(pdu_len) = RtrPdu::peek_length(parse_buf) else {
            return Ok(None);
        };
        if parse_buf.len() < pdu_len as usize {
            return Ok(None);
        }
        let got = parse_buf[0];
        if got != self.negotiated_version {
            return Err(RtrError::VersionMismatch {
                expected: self.negotiated_version,
                got,
            });
        }
        let (pdu, consumed) = RtrPdu::decode(parse_buf).map_err(RtrError::Decode)?;
        parse_buf.drain(..consumed);
        Ok(Some(pdu))
    }

    async fn send_query(&self, stream: &mut TcpStream, query: QueryKind) -> Result<bool, RtrError> {
        let query_pdu = self.build_query_pdu(query);
        let is_reset = matches!(query_pdu, RtrPdu::ResetQuery);
        let mut send_buf = Vec::new();
        query_pdu.encode_with_version(&mut send_buf, self.negotiated_version)?;
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

    fn handle_idle_pdus(&mut self, parse_buf: &mut Vec<u8>) -> Result<Option<QueryKind>, RtrError> {
        let mut next_query = None;

        while let Some(pdu) = self.next_pdu(parse_buf)? {
            match pdu {
                RtrPdu::SerialNotify { session_id, serial } => {
                    debug!(
                        server = %self.config.server_addr,
                        session_id,
                        serial,
                        "RTR Serial Notify received"
                    );
                    let query = if self.epoch.map(|e| e.session_id) == Some(session_id) {
                        self.current_query_kind()
                    } else {
                        QueryKind::Reset
                    };
                    if !matches!(next_query, Some(QueryKind::Reset)) {
                        next_query = Some(query);
                    }
                }
                RtrPdu::CacheReset => {
                    // The epoch is gone but the data is still the most
                    // recent validated state — retain it (and its expiry)
                    // until the Reset Query's full table replaces it.
                    info!(
                        server = %self.config.server_addr,
                        "RTR cache reset received while idle, resynchronizing with Reset Query"
                    );
                    self.epoch = None;
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
        let fallback_expiry = refresh_deadline + Duration::from_hours(24 * 365);
        let mut expire_sleep = Box::pin(tokio::time::sleep_until(
            self.data_expires_at.unwrap_or(fallback_expiry),
        ));

        loop {
            if let Some(query) = self.handle_idle_pdus(parse_buf)? {
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
    ///
    /// One call is one bounded RTR transaction: it is limited by a
    /// wall-clock deadline and record/byte budgets, and every response's
    /// identity (session ID, serial progression) is validated against the
    /// held [`CacheEpoch`] before its records may replace or extend the
    /// table. On any identity mismatch the response is discarded and the
    /// client resynchronizes with a full Reset Query — it never splices.
    #[expect(
        clippy::too_many_lines,
        reason = "RTR transaction keeps identity checks, collection, budgets, and publish ordering together"
    )]
    async fn fetch_until_end_of_data(
        &mut self,
        stream: &mut TcpStream,
        read_buf: &mut [u8],
        parse_buf: &mut Vec<u8>,
        mut query: QueryKind,
    ) -> Result<(), RtrError> {
        let deadline = TokioInstant::now() + self.transaction_deadline;
        let mut bytes: usize = 0;
        let mut restarts: u8 = 0;

        // Bump the restart counter, failing the transaction once a broken
        // cache keeps forcing resynchronization.
        macro_rules! restart {
            () => {{
                restarts += 1;
                if restarts > MAX_TRANSACTION_RESTARTS {
                    return Err(RtrError::ProtocolViolation(
                        "too many restarts in one transaction",
                    ));
                }
            }};
        }

        'transaction: loop {
            // Session identity expected for an incremental response, and
            // the serial it must not regress behind.
            let expected_session = match query {
                QueryKind::Serial => self.epoch.map(|e| e.session_id),
                QueryKind::Reset => None,
            };
            let prior_serial = self.epoch.map(|e| e.serial);
            // Session ID from this transaction's Cache Response; records
            // are only collected once it is set.
            let mut pending_session: Option<u16> = None;
            // Identity mismatch seen: drain the rest of the response
            // without collecting, then resync with a Reset Query.
            let mut discarding = false;
            let mut records: usize = 0;
            let mut announced = Vec::new();
            let mut withdrawn = Vec::new();
            let mut aspa_announced: Vec<AspaRecord> = Vec::new();
            let mut aspa_withdrawn: Vec<AspaRecord> = Vec::new();
            let is_reset = self.send_query(stream, query).await?;

            loop {
                while let Some(pdu) = self.next_pdu(parse_buf)? {
                    match pdu {
                        RtrPdu::CacheResponse { session_id } => {
                            if expected_session.is_some_and(|expected| expected != session_id) {
                                // The cache is answering from a different
                                // session than the one our data belongs to.
                                // Never splice: discard this response and
                                // resynchronize with a full Reset Query.
                                warn!(
                                    server = %self.config.server_addr,
                                    expected = expected_session,
                                    got = session_id,
                                    "RTR Cache Response session mismatch — resynchronizing"
                                );
                                restart!();
                                self.epoch = None;
                                discarding = true;
                                continue;
                            }
                            pending_session = Some(session_id);
                            records = 0;
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
                        } if pending_session.is_some() => {
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
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::Ipv6Prefix {
                            flags,
                            prefix_len,
                            max_len,
                            prefix,
                            asn,
                        } if pending_session.is_some() => {
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
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::Aspa {
                            flags,
                            customer_asn,
                            provider_asns,
                        } if pending_session.is_some() => {
                            // 8210bis §5.12: an ASPA announcement MUST carry
                            // at least one Provider ASN, and one carrying
                            // multiple Provider ASNs MUST NOT contain AS 0
                            // ("ASPA Provider List Error"). Accepting an
                            // empty announcement would fabricate an
                            // all-invalidating attestation for the customer.
                            if flags & 1 == 1
                                && (provider_asns.is_empty()
                                    || (provider_asns.len() > 1 && provider_asns.contains(&0)))
                            {
                                warn!(
                                    server = %self.config.server_addr,
                                    customer_asn,
                                    providers = provider_asns.len(),
                                    "RTR ASPA announcement with invalid provider list"
                                );
                                return Err(RtrError::ProtocolViolation(
                                    "ASPA provider list error",
                                ));
                            }
                            let record = AspaRecord {
                                customer_asn,
                                provider_asns,
                            };
                            if flags & 1 == 1 {
                                aspa_announced.push(record);
                            } else {
                                aspa_withdrawn.push(record);
                            }
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::EndOfData {
                            session_id,
                            serial,
                            refresh,
                            retry,
                            expire,
                        } => {
                            if discarding {
                                // Mismatched response fully drained;
                                // resynchronize from scratch.
                                query = QueryKind::Reset;
                                continue 'transaction;
                            }
                            let serial_sane = is_reset
                                || prior_serial.is_none_or(|old| serial_not_before(old, serial));
                            if pending_session != Some(session_id) || !serial_sane {
                                // End of Data identity does not match the
                                // Cache Response (or was never preceded by
                                // one), or the serial went backwards: the
                                // response cannot be trusted as one
                                // coherent cache state.
                                warn!(
                                    server = %self.config.server_addr,
                                    expected = pending_session,
                                    got = session_id,
                                    serial,
                                    "RTR End of Data identity mismatch — resynchronizing"
                                );
                                restart!();
                                self.epoch = None;
                                query = QueryKind::Reset;
                                continue 'transaction;
                            }
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
                            // The transaction is complete and validated:
                            // advance the epoch as one unit.
                            self.epoch = Some(CacheEpoch {
                                version: self.negotiated_version,
                                session_id,
                                serial,
                            });

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
                            // Retain held data (and its expiry) until the
                            // Reset Query's full table replaces it.
                            info!(
                                server = %self.config.server_addr,
                                "RTR cache reset received, resynchronizing with Reset Query"
                            );
                            restart!();
                            self.epoch = None;
                            query = QueryKind::Reset;
                            continue 'transaction;
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
                            // An Error Report is fatal to the session, and
                            // one answering our Serial Query means the
                            // incremental path is dead too: a restarted
                            // cache that no longer knows our session may
                            // reject the query outright (StayRTR sends
                            // "Session ID mismatch" error code 0 instead of
                            // a Cache Reset). Drop the epoch — retaining
                            // the data and its expiry — so the reconnect
                            // resynchronizes with a full Reset Query
                            // instead of retrying the same rejected query
                            // until the data expires.
                            if matches!(query, QueryKind::Serial) {
                                self.epoch = None;
                            }
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

                let n = tokio::time::timeout_at(deadline, stream.read(read_buf))
                    .await
                    .map_err(|_| RtrError::TransactionTimeout)?
                    .map_err(RtrError::Io)?;
                if n == 0 {
                    return Err(RtrError::ConnectionClosed);
                }
                bytes += n;
                if bytes > self.max_transaction_bytes {
                    return Err(RtrError::TransactionLimit("byte budget exceeded"));
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
    /// RTR PDU encoding failure.
    #[error("RTR encode error: {0}")]
    Encode(#[from] RtrEncodeError),
    /// The remote end closed the connection.
    #[error("connection closed")]
    ConnectionClosed,
    /// Inbound data exceeded the read buffer limit.
    #[error("read buffer overflow")]
    BufferOverflow,
    /// A PDU arrived with a version byte different from the negotiated
    /// session version.
    #[error("RTR version mismatch: negotiated {expected}, received {got}")]
    VersionMismatch {
        /// Version negotiated for this session.
        expected: u8,
        /// Version byte carried by the offending PDU.
        got: u8,
    },
    /// An RTR transaction exceeded its wall-clock deadline.
    #[error("RTR transaction deadline exceeded")]
    TransactionTimeout,
    /// An RTR transaction exceeded a record or byte budget.
    #[error("RTR transaction limit: {0}")]
    TransactionLimit(&'static str),
    /// The cache repeatedly violated session identity within one
    /// transaction.
    #[error("RTR protocol violation: {0}")]
    ProtocolViolation(&'static str),
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
        read_pdu_with_version(stream).await.1
    }

    async fn read_pdu_with_version(stream: &mut TcpStream) -> (u8, RtrPdu) {
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
        (header[0], pdu)
    }

    async fn write_pdu_version(stream: &mut TcpStream, pdu: RtrPdu, version: u8) {
        let mut buf = Vec::new();
        pdu.encode_with_version(&mut buf, version).unwrap();
        stream.write_all(&buf).await.unwrap();
    }

    /// Write a PDU at v2 — the version the client negotiates by default
    /// and now enforces on every received PDU.
    async fn write_pdu(stream: &mut TcpStream, pdu: RtrPdu) {
        write_pdu_version(stream, pdu, crate::rtr_codec::RTR_VERSION_2).await;
    }

    /// Write a whole response as ONE write. Required in `start_paused`
    /// tests: if the client parks between two writes while its
    /// transaction-deadline timer is pending, tokio's paused clock
    /// auto-advances to that timer and the transaction times out.
    async fn write_pdus(stream: &mut TcpStream, pdus: &[RtrPdu]) {
        write_pdus_version(stream, pdus, crate::rtr_codec::RTR_VERSION_2).await;
    }

    async fn write_pdus_version(stream: &mut TcpStream, pdus: &[RtrPdu], version: u8) {
        let mut buf = Vec::new();
        for pdu in pdus {
            pdu.encode_with_version(&mut buf, version).unwrap();
        }
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

        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 10,
                    retry: 5,
                    expire: 30,
                },
            ],
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

        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 101,
                    refresh: 10,
                    retry: 5,
                    expire: 30,
                },
            ],
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

        write_pdus(
            &mut stream1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 2,
                    expire: 10,
                },
            ],
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
    async fn cache_reset_retains_entries_until_replacement_full_table() {
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

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        // No update between Cache Reset and the replacement full table:
        // the previous data stays valid until it is replaced.
        assert!(vrp_rx.try_recv().is_err());

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
    async fn unsupported_v2_falls_back_to_v1_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream_v2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);

        write_pdu(
            &mut stream_v2,
            RtrPdu::ErrorReport {
                code: 4,
                pdu: vec![],
                text: "Unsupported Protocol Version".to_string(),
            },
        )
        .await;
        drop(stream_v2);

        let (mut stream_v1, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v1).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(pdu, RtrPdu::ResetQuery);

        write_pdu_version(
            &mut stream_v1,
            RtrPdu::CacheResponse { session_id: 7 },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        write_pdu_version(
            &mut stream_v1,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        write_pdu_version(
            &mut stream_v1,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
            crate::rtr_codec::RTR_VERSION,
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

    /// Establish an epoch (session 7, serial 100) on `stream` with one
    /// IPv4 prefix and consume the resulting `FullTable` update.
    async fn establish_epoch(stream: &mut TcpStream, vrp_rx: &mut mpsc::Receiver<VrpUpdate>) {
        assert_eq!(read_pdu(stream).await, RtrPdu::ResetQuery);
        write_pdus(
            stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;
        let _ = vrp_rx.recv().await.unwrap();
    }

    #[tokio::test]
    async fn cache_response_session_mismatch_resyncs_instead_of_splicing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

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

        // The cache answers the Serial Query from a DIFFERENT session:
        // this delta belongs to another cache state and must not be
        // spliced onto ours.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 9 }).await;
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
                session_id: 9,
                serial: 200,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        // The client drains the mismatched response, publishes nothing,
        // and resynchronizes with a full Reset Query.
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 9 }).await;
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
                session_id: 9,
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
        // Full replacement, never an incremental splice.
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
    async fn end_of_data_session_mismatch_triggers_full_requery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        // End of Data carries a session ID that does not match the Cache
        // Response: the response is not one coherent cache state.
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
                session_id: 8,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 8 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 8,
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
                entries: vec![],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn serial_regression_triggers_full_requery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

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

        // Incremental response whose serial went backwards (RFC 1982).
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 50,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_retains_data_and_resumes_with_serial_query() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

        // Connection drops. The retained data must NOT be flushed: no
        // ServerDown, and the client resumes the same epoch with a Serial
        // Query on reconnect.
        drop(stream);
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_pdu(&mut stream2).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn version_mismatch_mid_session_reconnects_and_retains_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

        // A PDU with a different version byte mid-session: records from
        // different protocol versions must never mix in one epoch.
        write_pdu_version(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        // The client drops the session but retains data and epoch.
        let (mut stream2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Drive the client through the code-4 v2 rejection into a v1
    /// session and establish a v1 epoch (session 7, serial 100) with one
    /// prefix, serving the given expire interval. Consumes the resulting
    /// `FullTable` update and returns the live v1 stream.
    async fn establish_v1_epoch(
        listener: &TcpListener,
        vrp_rx: &mut mpsc::Receiver<VrpUpdate>,
        expire: u32,
    ) -> TcpStream {
        let (mut stream_v2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdu(
            &mut stream_v2,
            RtrPdu::ErrorReport {
                code: 4,
                pdu: vec![],
                text: "Unsupported Protocol Version".to_string(),
            },
        )
        .await;
        drop(stream_v2);

        let (mut stream_v1, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v1).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdus_version(
            &mut stream_v1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let update = vrp_rx.recv().await.unwrap();
        assert!(matches!(update, VrpUpdate::FullTable { .. }));
        stream_v1
    }

    /// LAN-312: a v1-only cache (`StayRTR`) restarting while data is held
    /// must not wedge the client. The client must reconnect at v1 —
    /// never re-probing v2 with held v1 data, since the cache can only
    /// answer that with a version-0 Error Report the version check
    /// rejects before any fallback signal fires — and re-land the v1
    /// session within one retry interval with full retention.
    #[tokio::test(start_paused = true)]
    async fn v1_cache_restart_relands_v1_within_one_retry_with_retention() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        // Large expire interval: the paused clock auto-advances past idle
        // timers, and expiry must stay out of reach so the only way this
        // test passes is an immediate v1 re-land — never the
        // expiry-then-recover blackout this fix removes.
        let client = RtrClient::new(test_config(addr, 60, 5, 3600), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let stream_v1 = establish_v1_epoch(&listener, &mut vrp_rx, 3600).await;

        // The cache restarts: connection drops.
        drop(stream_v1);

        // StayRTR-like restarted cache: any v2 query is answered with a
        // version-0 Error Report and a close. The fixed client never
        // sends one — it reconnects straight at v1.
        let mut relanded = None;
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (version, pdu) = read_pdu_with_version(&mut stream).await;
            if version == crate::rtr_codec::RTR_VERSION_2 {
                write_pdu_version(
                    &mut stream,
                    RtrPdu::ErrorReport {
                        code: 8,
                        pdu: vec![],
                        text: "Bad protocol version".to_string(),
                    },
                    0,
                )
                .await;
                drop(stream);
                continue;
            }
            relanded = Some((stream, pdu));
            break;
        }
        let (mut stream, pdu) = relanded.expect(
            "client wedged: kept re-probing v2 while holding v1 data instead of re-landing v1",
        );
        // Same epoch resumed at its own version — an incremental query.
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        // Retention held throughout: no ServerDown, no validation flap.
        assert!(vrp_rx.try_recv().is_err());

        // The restarted cache no longer knows the session: StayRTR
        // answers the old-session Serial Query with a "Session ID
        // mismatch" Error Report (code 0) and closes — NOT a Cache
        // Reset. The client must drop the dead epoch (keeping the data)
        // and resynchronize with a full Reset Query on the next retry,
        // never re-sending the same rejected Serial Query.
        write_pdus_version(
            &mut stream,
            &[RtrPdu::ErrorReport {
                code: 0,
                pdu: vec![],
                text: "Session ID mismatch: client is desynchronized".to_string(),
            }],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        drop(stream);

        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(
            pdu,
            RtrPdu::ResetQuery,
            "client kept retrying the rejected Serial Query instead of resynchronizing"
        );
        assert!(vrp_rx.try_recv().is_err());
        write_pdus_version(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 9 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 114, 0),
                    asn: 65002,
                },
                RtrPdu::EndOfData {
                    session_id: 9,
                    serial: 1,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
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

    /// The deliberate v2 re-probe point: once held v1 data expires
    /// (nothing left to protect), the client probes the preferred
    /// version again and can upgrade to a cache that gained v2 support.
    #[tokio::test(start_paused = true)]
    async fn data_expiry_reprobes_v2_for_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        // v1 epoch whose data expires before the next refresh.
        let _stream_v1 = establish_v1_epoch(&listener, &mut vrp_rx, 30).await;

        // The cache never speaks again; the expire interval passes and
        // the held entries are dropped.
        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });

        // Epoch-less again: the client re-probes v2 and upgrades.
        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 11 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 115, 0),
                    asn: 65003,
                },
                RtrPdu::EndOfData {
                    session_id: 11,
                    serial: 1,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 115, 0), 24, 24, 65003)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn record_budget_exceeded_drops_connection_without_publishing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.max_transaction_records = 2;
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        let mut pdus = vec![RtrPdu::CacheResponse { session_id: 7 }];
        for i in 0..3u8 {
            pdus.push(RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, i),
                asn: 65001,
            });
        }
        write_pdus(&mut stream, &pdus).await;

        // Budget exceeded: the client drops the connection (bounded
        // error, no wedge/OOM) and publishes nothing.
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn byte_budget_exceeded_drops_connection_without_publishing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.max_transaction_bytes = 4;
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_deadline_drops_stalled_transfer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.transaction_deadline = Duration::from_secs(30);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        // Cache Response and then… nothing. The transaction must not
        // wedge: the deadline fires (paused clock auto-advances) and the
        // client reconnects.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Drive one transaction whose payload contains `aspa`, and assert the
    /// client rejects the response (8210bis §5.12 "ASPA Provider List
    /// Error"): the connection is dropped without publishing and the
    /// reconnect starts over with a Reset Query.
    async fn assert_aspa_announcement_rejected(aspa: RtrPdu) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                aspa,
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_announcement_without_providers_is_rejected() {
        // 8210bis §5.12: an announcement MUST contain at least one
        // Provider ASN (an empty set is only valid on a withdrawal).
        assert_aspa_announcement_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![],
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_announcement_with_as0_among_multiple_providers_is_rejected() {
        // 8210bis §5.12: a multi-provider announcement MUST NOT contain
        // AS 0. (A single-provider AS 0 announcement is the legal
        // "no providers" attestation and stays accepted.)
        assert_aspa_announcement_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![0, 65002],
        })
        .await;
    }

    #[tokio::test]
    async fn aspa_as0_only_announcement_is_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: 65001,
                    provider_asns: vec![0],
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
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
                entries: vec![],
                aspa_records: vec![AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![0],
                }],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[test]
    fn serial_not_before_rfc1982_boundaries() {
        // Same serial: not a regression.
        assert!(serial_not_before(100, 100));
        // Forward step, including across the u32 wrap.
        assert!(serial_not_before(100, 101));
        assert!(serial_not_before(u32::MAX, 0));
        assert!(serial_not_before(u32::MAX, (1 << 31) - 2));
        // Backward step, including across the wrap, is a regression.
        assert!(!serial_not_before(101, 100));
        assert!(!serial_not_before(0, u32::MAX));
        // Exactly half the number space away is undefined in RFC 1982;
        // treated as a regression (the conservative reading).
        assert!(!serial_not_before(0, 1 << 31));
    }
}
