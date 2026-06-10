//! Per-peer outbound TCP writer task.
//!
//! Owns the [`OwnedWriteHalf`] of a peer's TCP stream plus two inbound
//! channels (bounded "bulk" + unbounded "priority") and runs a biased
//! `tokio::select!` so priority traffic preempts bulk. The session task
//! encodes BGP messages and enqueues their bytes; this task is a dumb
//! pipe that does `write_all + flush` — with one exception: it owns the
//! periodic KEEPALIVE cadence (ADR-0078).
//!
//! Splitting the writer out of the session task is the architectural
//! fix tracked by ADR-0051. With the write half in its own task, TCP
//! receive-buffer back-pressure can no longer park the session's
//! `tokio::select!` and starve its `commands.recv()` / `read_tcp` /
//! timer arms — which is the root cause of the `GetHealth` wedge that
//! the 0735dd9 timeouts could only contain.
//!
//! KEEPALIVE cadence lives here, not in the session task, for the same
//! reason in the opposite direction (ADR-0078): with inbound RIB
//! delivery now blocking, a session task parked on a full RIB channel
//! must keep feeding the peer's hold timer. The session drives the
//! cadence over a watch channel (`Some(interval)` on negotiation,
//! `None`/sender-drop to stop); the writer emits the constant 19-byte
//! KEEPALIVE frame on each deadline. This is FRR's dedicated
//! keepalive-thread invariant in our two-task shape.
//!
//! Saturation policy lives in the session task, not here:
//! `bulk_tx.try_send` failing with `Full` means the peer hasn't drained
//! 4096 BGP messages, the session emits a `Cease/8` (Out of Resources,
//! RFC 4486 §4 subcode 8) through `priority_tx`, then drops both
//! senders so this task exits cleanly. Wiring lives in
//! `PeerSession::trigger_outbound_saturation_teardown`; this module
//! just provides the channels and the pipe.

use std::time::Duration;

use bytes::Bytes;
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Channel handles + a [`JoinHandle`] held by the session task.
///
/// Drop `bulk_tx`, `priority_tx`, and `keepalive_tx` to signal the
/// writer to exit cleanly — its `recv` calls return `None`, the cadence
/// stops, the task returns `Ok(())` and `join` resolves. A TCP write or
/// flush failure ends the task with `Err(io::Error)` instead.
pub(super) struct WriterHandle {
    /// Bounded channel — `UPDATE`s, `RouteRefresh` `BoRR`/`EoRR`, `EoR` markers.
    /// `try_send` returning `Full` is the saturation signal that
    /// triggers session teardown.
    pub(super) bulk_tx: mpsc::Sender<Bytes>,
    /// Unbounded channel — `OPEN`, `KEEPALIVE`, `NOTIFICATION`, operator
    /// `ROUTE-REFRESH` commands, collision `Cease`. Unbounded is safe
    /// because each of these is bounded by session lifetime or timer
    /// cadence, not by route volume.
    pub(super) priority_tx: mpsc::UnboundedSender<Bytes>,
    /// KEEPALIVE cadence control (ADR-0078): `Some(interval)` starts or
    /// retimes the writer-owned periodic KEEPALIVE, `None` stops it.
    /// Dropping the sender also stops it.
    pub(super) keepalive_tx: watch::Sender<Option<Duration>>,
    /// Resolves when the writer exits: `Ok(())` on clean shutdown,
    /// `Err(io::Error)` on TCP write/flush failure.
    pub(super) join: JoinHandle<std::io::Result<()>>,
}

/// The constant KEEPALIVE PDU: 16-byte all-ones marker, length 19,
/// type 4 (RFC 4271 §4.4 — no body).
const KEEPALIVE_FRAME: [u8; 19] = {
    let mut frame = [0xFFu8; 19];
    frame[16] = 0;
    frame[17] = 19;
    frame[18] = 4;
    frame
};

/// Spawn a writer task for the given TCP write half. `bulk_buffer` sets
/// the bounded channel depth — production callers pass `OUTBOUND_BUFFER`
/// (defined in `session/mod.rs`); tests can pass a smaller value to
/// exercise saturation paths quickly.
pub(super) fn spawn(
    write_half: OwnedWriteHalf,
    bulk_buffer: usize,
    metrics: BgpMetrics,
    peer_label: String,
) -> WriterHandle {
    let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(bulk_buffer);
    let (priority_tx, priority_rx) = mpsc::unbounded_channel::<Bytes>();
    let (keepalive_tx, keepalive_rx) = watch::channel(None);
    let task = WriterTask {
        write_half,
        bulk_rx,
        priority_rx,
        keepalive_rx,
        metrics,
        peer_label,
    };
    let join = tokio::spawn(task.run());
    WriterHandle {
        bulk_tx,
        priority_tx,
        keepalive_tx,
        join,
    }
}

struct WriterTask {
    write_half: OwnedWriteHalf,
    bulk_rx: mpsc::Receiver<Bytes>,
    priority_rx: mpsc::UnboundedReceiver<Bytes>,
    keepalive_rx: watch::Receiver<Option<Duration>>,
    metrics: BgpMetrics,
    peer_label: String,
}

impl WriterTask {
    async fn run(mut self) -> std::io::Result<()> {
        let mut bulk_open = true;
        let mut priority_open = true;
        let mut cadence_open = true;
        let mut cadence: Option<Duration> = *self.keepalive_rx.borrow();
        let mut next_keepalive = cadence.map(|interval| tokio::time::Instant::now() + interval);
        loop {
            // Exit only when both message channels have closed — the
            // cadence alone must not keep a writer alive for a session
            // that already tore down its senders.
            if !bulk_open && !priority_open {
                debug!("writer: both senders dropped, exiting cleanly");
                return Ok(());
            }
            // `biased` keeps NOTIFICATIONs and KEEPALIVEs from starving
            // behind a backlog of UPDATEs, and ensures the saturation
            // `Cease/8` reaches the wire before any further bulk work.
            let bytes = tokio::select! {
                biased;
                changed = self.keepalive_rx.changed(), if cadence_open => {
                    if changed.is_ok() {
                        cadence = *self.keepalive_rx.borrow();
                    } else {
                        cadence_open = false;
                        cadence = None;
                    }
                    next_keepalive =
                        cadence.map(|interval| tokio::time::Instant::now() + interval);
                    continue;
                }
                msg = self.priority_rx.recv(), if priority_open => {
                    if let Some(b) = msg {
                        b
                    } else {
                        priority_open = false;
                        continue;
                    }
                }
                () = async {
                    if let Some(deadline) = next_keepalive {
                        tokio::time::sleep_until(deadline).await;
                    }
                }, if next_keepalive.is_some() => {
                    if let Some(interval) = cadence {
                        next_keepalive = Some(tokio::time::Instant::now() + interval);
                    }
                    self.metrics
                        .record_message_sent(&self.peer_label, "keepalive");
                    Bytes::from_static(&KEEPALIVE_FRAME)
                }
                msg = self.bulk_rx.recv(), if bulk_open => {
                    if let Some(b) = msg {
                        b
                    } else {
                        bulk_open = false;
                        continue;
                    }
                }
            };

            if let Err(e) = self.write_half.write_all(&bytes).await {
                warn!(error = %e, "writer: write_all failed");
                return Err(e);
            }
            if let Err(e) = self.write_half.flush().await {
                warn!(error = %e, "writer: flush failed");
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Establish a real connected TCP pair on loopback. Returns
    /// `(server_side, client_side)` — the test owns both ends so it can
    /// hand one half to the writer and read from the other.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap();
        (server, client)
    }

    /// Bulk messages preserve FIFO order over the wire.
    #[tokio::test]
    async fn bulk_messages_preserve_order() {
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
        );

        for i in 0u8..5 {
            handle.bulk_tx.send(Bytes::from(vec![i])).await.unwrap();
        }
        // Drop senders so writer drains and exits.
        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0, 1, 2, 3, 4]);

        let result = join.await.unwrap();
        assert!(result.is_ok(), "writer exited with error: {result:?}");
    }

    /// Priority preempts bulk: with biased select, a priority byte
    /// pushed while `bulk_rx` has a backlog must reach the wire within
    /// the next two write iterations (one in-flight bulk write may
    /// already be parked in `write_all`; the next select! pick must
    /// be the priority byte).
    #[tokio::test]
    async fn priority_preempts_bulk() {
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
        );

        // Pre-load several bulk messages.
        for i in 0u8..4 {
            handle
                .bulk_tx
                .send(Bytes::from(vec![0xB0 + i]))
                .await
                .unwrap();
        }
        // Push priority while bulk_rx still has items queued.
        handle.priority_tx.send(Bytes::from(vec![0xFF])).unwrap();

        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let mut buf = vec![0u8; 5];
        client.read_exact(&mut buf).await.unwrap();

        // Worst case: writer was already inside `write_all` for one
        // bulk byte when priority arrived, so 0xFF lands at index 1
        // rather than 0. That's still preemption (4 queued bulks did
        // not all drain first).
        let ff_pos = buf
            .iter()
            .position(|&b| b == 0xFF)
            .expect("priority byte missing from output");
        assert!(
            ff_pos < 2,
            "priority byte at index {ff_pos}, expected < 2 for biased select preemption; buf = {buf:?}"
        );

        let result = join.await.unwrap();
        assert!(result.is_ok(), "writer exited with error: {result:?}");
    }

    /// Dropping both senders is the clean shutdown signal.
    #[tokio::test]
    async fn drop_both_senders_exits_cleanly() {
        let (server, _client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
        );

        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let result = join.await.unwrap();
        assert!(
            result.is_ok(),
            "writer should exit Ok on dropped senders, got: {result:?}"
        );
    }
}

#[cfg(test)]
mod keepalive_cadence_tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap();
        (server, client)
    }

    /// ADR-0078 rule 2: the writer emits KEEPALIVE frames on its own
    /// cadence with zero involvement from the session task — the
    /// invariant that keeps the peer's hold timer fed while the session
    /// is parked on a blocking RIB delivery.
    #[tokio::test]
    async fn writer_emits_keepalives_on_cadence_without_session_involvement() {
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
        );
        handle
            .keepalive_tx
            .send(Some(Duration::from_millis(50)))
            .unwrap();

        let mut frame = [0u8; 19];
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut frame))
                .await
                .expect("keepalive must arrive on cadence")
                .unwrap();
            assert_eq!(frame, KEEPALIVE_FRAME);
        }

        // Stopping the cadence stops the frames (tolerate one frame
        // already in flight when the stop lands).
        handle.keepalive_tx.send(None).unwrap();
        let in_flight =
            tokio::time::timeout(Duration::from_millis(150), client.read_exact(&mut frame)).await;
        if in_flight.is_ok() {
            let after_stop =
                tokio::time::timeout(Duration::from_millis(200), client.read_exact(&mut frame))
                    .await;
            assert!(after_stop.is_err(), "cadence must stop after None");
        }

        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);
        drop(handle.keepalive_tx);
        join.await.unwrap().unwrap();
    }

    /// The emitted frame is a well-formed KEEPALIVE PDU.
    #[test]
    fn keepalive_frame_is_valid_pdu() {
        let mut buf = bytes::Bytes::copy_from_slice(&KEEPALIVE_FRAME);
        let msg = rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap();
        assert!(matches!(msg, rustbgpd_wire::Message::Keepalive));
    }
}
