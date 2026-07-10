//! Per-peer outbound TCP writer task.
//!
//! Owns the [`OwnedWriteHalf`] of a peer's TCP stream plus two inbound
//! channels (bounded "bulk" + unbounded "priority") and runs a biased
//! `tokio::select!` so priority traffic preempts bulk. The session task
//! encodes BGP messages and enqueues their bytes; this task is a dumb
//! pipe that does `write_all + flush` — coalescing queued bulk frames
//! into one write per drain (see [`coalesce_bulk`]) — with one
//! exception: it owns the periodic KEEPALIVE cadence (ADR-0078).
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
//! RFC 4486 §4 subcode 8) through `priority_tx`, signals `teardown_tx`,
//! and drops the senders. The teardown signal makes this task **discard
//! the queued bulk backlog instead of draining it** — the Cease must be
//! the final frame the peer sees, and flushing a saturated queue would
//! delay the close indefinitely — flush the already-enqueued priority
//! frames best-effort within [`TEARDOWN_LINGER`], and exit with
//! [`WriterExit::TornDown`] so the session's writer-exit arm drives
//! `TcpConnectionFails` + FSM/RIB cleanup exactly like a real TCP
//! failure. Wiring lives in
//! `PeerSession::trigger_outbound_saturation_teardown`; this module
//! owns the discard/flush/close mechanics.
//!
//! # Bulk write coalescing (LAN-332)
//!
//! Per-message `write_all + flush` made writer+syscalls the largest
//! CPU bucket at 1000-peer scale (31.8% of RR CPU under churn,
//! `docs/perf/scale-receipt-2026-07.md`). Each drain of the bulk
//! channel therefore coalesces up to [`MAX_BATCH_FRAMES`] /
//! [`MAX_BATCH_BYTES`] of already-queued WHOLE frames into one
//! contiguous buffer and issues a single `write_all + flush` — the
//! same shape as FRR's packed subgroup streams. Only bulk frames
//! coalesce: priority frames (OPEN, KEEPALIVE, NOTIFICATION, Cease)
//! always write alone, so the saturation-teardown guarantee that the
//! `Cease/8` is the final frame on the wire cannot be violated by a
//! batch that pulled the Cease and then appended bulk behind it, and
//! biased priority preemption keeps single-frame granularity on the
//! priority side (bulk backlog can delay a priority frame by at most
//! one in-flight batch instead of one in-flight frame).
//!
//! # Send hold timer (RFC 9687)
//!
//! The writer also owns `SendHoldTime` enforcement: each
//! `write_all + flush` (one frame or one coalesced batch) is wrapped
//! in a timeout of the configured
//! `SendHoldTime`, and hitting it ends the task with
//! [`WriterExit::SendHoldExpired`] — the session tears down through the
//! TCP-failure path *without* sending a NOTIFICATION (§4.3 makes the
//! NOTIFICATION optional and only "if … doing so will not delay" the
//! teardown; our socket is by definition not draining, and a
//! `write_all` cancelled mid-frame may have left a partial PDU on the
//! wire, so injecting one could corrupt framing).
//!
//! Deviation from the letter of §4.3: the RFC models a free-running
//! timer restarted on every sent message; we run a per-write deadline
//! that only ticks while a write is pending. The trigger condition is
//! equivalent — a peer that stops draining wedges the pending write,
//! which then times out — but our variant cannot fire on an idle
//! session, so we do not need the RFC's "stop the timer when the
//! negotiated `HoldTime` is zero" rule and keep protection active even
//! with keepalives disabled. Like every implementation of this
//! mechanism (FRR measures `SendQ` progress the same way), detection
//! starts only once the kernel send buffer stops accepting bytes.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Why the writer task ended, beyond a clean both-senders-dropped exit.
#[derive(Debug)]
pub(super) enum WriterExit {
    /// TCP write or flush failed.
    Io(std::io::Error),
    /// RFC 9687 send hold timer expired: a single `write_all + flush`
    /// (one frame or one coalesced batch, ≤ [`MAX_BATCH_BYTES`] plus
    /// one frame) could not complete within the configured
    /// `SendHoldTime` because the peer stopped draining its socket.
    SendHoldExpired {
        /// The configured `SendHoldTime` that elapsed.
        limit: Duration,
    },
    /// Session-requested hard close (outbound saturation `Cease/8`):
    /// the queued bulk backlog was discarded — never drained — the
    /// Cease was flushed best-effort within [`TEARDOWN_LINGER`], and
    /// the socket closed. The session's writer-exit arm maps this to
    /// `TcpConnectionFails` so FSM/RIB cleanup runs from the run loop.
    TornDown,
}

/// Best-effort bound on teardown writes: how long the writer will wait
/// for an in-flight frame to reach a frame boundary and for the Cease
/// NOTIFICATION to reach the wire before hard-closing anyway. A
/// saturated TCP window may never accept the Cease; the close must not
/// wait on it.
const TEARDOWN_LINGER: Duration = Duration::from_secs(2);

/// Maximum frames coalesced into one bulk write. 64 standard
/// maximum-size PDUs (4096 B, RFC 4271) is exactly
/// [`MAX_BATCH_BYTES`], so the two caps agree at the worst-case
/// standard frame size; typical UPDATEs are far smaller and hit the
/// frame cap first, still cutting write syscalls by up to 64×.
const MAX_BATCH_FRAMES: usize = 64;

/// Byte threshold that stops batch growth. WHOLE FRAMES ONLY: the cap
/// is checked before pulling the next frame, so a batch may overshoot
/// by at most one frame (≤ 64 KiB under RFC 8654 extended messages).
/// 256 KiB keeps a single coalesced write small enough that the
/// send-hold deadline and the teardown linger bound roughly the same
/// wire time as before, while amortizing the syscall + flush cost.
const MAX_BATCH_BYTES: usize = 256 * 1024;

/// Coalesce already-queued bulk frames behind `first` into one
/// contiguous buffer, up to [`MAX_BATCH_FRAMES`] / [`MAX_BATCH_BYTES`].
/// Non-blocking: only frames already sitting in the channel join the
/// batch. Returns `first` untouched (zero copy) when the queue is
/// empty — the idle/trickle path is unchanged. Frames keep their
/// queue order; frames are never split.
fn coalesce_bulk(first: Bytes, bulk_rx: &mut mpsc::Receiver<Bytes>) -> Bytes {
    let Ok(second) = bulk_rx.try_recv() else {
        return first;
    };
    let mut batch = BytesMut::with_capacity(first.len() + second.len());
    batch.extend_from_slice(&first);
    batch.extend_from_slice(&second);
    let mut frames = 2;
    while frames < MAX_BATCH_FRAMES && batch.len() < MAX_BATCH_BYTES {
        // `Empty` and `Disconnected` both just end the batch; the run
        // loop's `bulk_rx.recv()` arm observes closure and flips
        // `bulk_open` on its own.
        let Ok(next) = bulk_rx.try_recv() else { break };
        batch.extend_from_slice(&next);
        frames += 1;
    }
    batch.freeze()
}

/// Channel handles + a [`JoinHandle`] held by the session task.
///
/// Drop `bulk_tx` and `priority_tx` to signal the writer to exit
/// cleanly — its message `recv` calls return `None`, the task returns
/// `Ok(())`, and `join` resolves. Dropping `keepalive_tx` only stops the
/// cadence; it is not part of the exit condition. A TCP write/flush
/// failure or a send-hold expiry (RFC 9687) ends the task with
/// `Err(WriterExit)` instead.
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
    /// Hard-teardown signal (saturation `Cease/8`): sending `true`
    /// makes the writer discard the bulk backlog, flush pending
    /// priority frames within [`TEARDOWN_LINGER`], and exit with
    /// [`WriterExit::TornDown`]. Racing an in-flight write is part of
    /// the contract — a writer wedged in `write_all` observes the
    /// signal without waiting for the write to complete. Dropping the
    /// sender without signalling is the ordinary close path and keeps
    /// today's drain semantics.
    pub(super) teardown_tx: watch::Sender<bool>,
    /// Resolves when the writer exits: `Ok(())` on clean shutdown,
    /// `Err(WriterExit)` on TCP write/flush failure or send-hold expiry.
    pub(super) join: JoinHandle<Result<(), WriterExit>>,
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
/// exercise saturation paths quickly. `send_hold_time` is the RFC 9687
/// `SendHoldTime` (`None` = disabled): a single write/flush that cannot
/// complete within it ends the task with [`WriterExit::SendHoldExpired`].
pub(super) fn spawn(
    write_half: OwnedWriteHalf,
    bulk_buffer: usize,
    metrics: BgpMetrics,
    peer_label: String,
    send_hold_time: Option<Duration>,
) -> WriterHandle {
    let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(bulk_buffer);
    let (priority_tx, priority_rx) = mpsc::unbounded_channel::<Bytes>();
    let (keepalive_tx, keepalive_rx) = watch::channel(None);
    let (teardown_tx, teardown_rx) = watch::channel(false);
    let task = WriterTask {
        write_half,
        bulk_rx,
        priority_rx,
        keepalive_rx,
        teardown_rx,
        metrics,
        peer_label,
        send_hold_time,
    };
    let join = tokio::spawn(task.run());
    WriterHandle {
        bulk_tx,
        priority_tx,
        keepalive_tx,
        teardown_tx,
        join,
    }
}

struct WriterTask {
    write_half: OwnedWriteHalf,
    bulk_rx: mpsc::Receiver<Bytes>,
    priority_rx: mpsc::UnboundedReceiver<Bytes>,
    keepalive_rx: watch::Receiver<Option<Duration>>,
    teardown_rx: watch::Receiver<bool>,
    metrics: BgpMetrics,
    peer_label: String,
    send_hold_time: Option<Duration>,
}

/// Resolve once the session has signalled hard teardown. Pends forever
/// otherwise — including when the sender is dropped *without*
/// signalling, which is the ordinary (non-saturation) close path and
/// must keep the writer's drain-then-exit semantics.
async fn teardown_requested(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Apply the RFC 9687 send-hold bound to a write when configured.
/// `Err(limit)` means the timer expired.
async fn with_send_hold(
    write: impl Future<Output = std::io::Result<()>>,
    send_hold_time: Option<Duration>,
) -> Result<std::io::Result<()>, Duration> {
    match send_hold_time {
        Some(limit) => tokio::time::timeout(limit, write).await.map_err(|_| limit),
        None => Ok(write.await),
    }
}

impl WriterTask {
    async fn run(mut self) -> Result<(), WriterExit> {
        let mut bulk_open = true;
        let mut priority_open = true;
        let mut cadence_open = true;
        let mut teardown_open = true;
        let mut cadence: Option<Duration> = *self.keepalive_rx.borrow();
        let mut next_keepalive = cadence.map(|interval| tokio::time::Instant::now() + interval);
        loop {
            // Hard teardown (saturation Cease/8): discard the bulk
            // backlog, flush the pending priority frames best-effort,
            // close. Checked at the top of every iteration so no bulk
            // frame can slip out between the signal and the close.
            if *self.teardown_rx.borrow() {
                return self.teardown_close().await;
            }
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
            // The bool marks bulk-arm frames as coalescible; priority
            // and cadence frames always write alone (module docs,
            // "Bulk write coalescing").
            let (bytes, from_bulk) = tokio::select! {
                biased;
                changed = self.teardown_rx.changed(), if teardown_open => {
                    if changed.is_err() {
                        // Sender dropped without signalling: ordinary
                        // close path, keep drain semantics and never
                        // poll this arm again.
                        teardown_open = false;
                    }
                    continue;
                }
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
                        (b, false)
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
                    (Bytes::from_static(&KEEPALIVE_FRAME), false)
                }
                msg = self.bulk_rx.recv(), if bulk_open => {
                    if let Some(b) = msg {
                        (b, true)
                    } else {
                        bulk_open = false;
                        continue;
                    }
                }
            };

            let bytes = if from_bulk {
                coalesce_bulk(bytes, &mut self.bulk_rx)
            } else {
                bytes
            };
            self.write_message(&bytes).await?;
        }
    }

    /// `write_all + flush` one message (or one coalesced batch of
    /// whole bulk frames), bounded by the RFC 9687 send hold timer
    /// when configured, and raced against the session's hard-teardown
    /// signal — a writer wedged mid-write on a saturated TCP window
    /// must not delay the teardown indefinitely.
    async fn write_message(&mut self, bytes: &Bytes) -> Result<(), WriterExit> {
        let Self {
            write_half,
            teardown_rx,
            send_hold_time,
            peer_label,
            ..
        } = self;
        let write = async {
            write_half.write_all(bytes).await?;
            write_half.flush().await
        };
        tokio::pin!(write);
        let outcome = tokio::select! {
            biased;
            result = with_send_hold(write.as_mut(), *send_hold_time) => Some(result),
            () = teardown_requested(teardown_rx) => None,
        };
        let result = match outcome {
            Some(Ok(result)) => result,
            Some(Err(limit)) => {
                warn!(
                    peer = %peer_label,
                    send_hold_time = ?limit,
                    "send hold timer expired: peer stopped draining our TCP output \
                     (RFC 9687); terminating session without NOTIFICATION"
                );
                return Err(WriterExit::SendHoldExpired { limit });
            }
            None => {
                // Hard teardown while this frame/batch is in flight:
                // give the write a short linger to reach a frame
                // boundary — batches hold only whole frames, so a
                // completed write always ends on one (and the Cease
                // can still follow it intact) — then abandon: a
                // `write_all` cancelled mid-frame may have left a
                // partial PDU on the wire, so nothing (not even the
                // Cease) may be written after an abandoned write. On
                // completion the run loop's top-of-iteration check
                // routes into `teardown_close`.
                match tokio::time::timeout(TEARDOWN_LINGER, write.as_mut()).await {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        debug!(
                            peer = %peer_label,
                            "teardown: abandoned in-flight write after linger; hard close"
                        );
                        return Err(WriterExit::TornDown);
                    }
                }
            }
        };
        result.map_err(|e| {
            warn!(error = %e, "writer: write/flush failed");
            WriterExit::Io(e)
        })
    }

    /// Session-requested hard close: drop the queued bulk backlog on
    /// the floor — the `Cease/8` already enqueued on the priority
    /// channel must be the FINAL frame the peer sees, and draining a
    /// saturated queue could take unbounded time — then flush the
    /// pending priority frames best-effort within [`TEARDOWN_LINGER`]
    /// and exit. Returning drops the write half, which closes the
    /// socket without draining.
    async fn teardown_close(mut self) -> Result<(), WriterExit> {
        let deadline = tokio::time::Instant::now() + TEARDOWN_LINGER;
        // The session enqueues the Cease before signalling teardown and
        // then drops its senders, so `try_recv` yields exactly the
        // still-buffered priority frames (normally just the Cease/8).
        while let Ok(bytes) = self.priority_rx.try_recv() {
            let write = async {
                self.write_half.write_all(&bytes).await?;
                self.write_half.flush().await
            };
            match tokio::time::timeout_at(deadline, write).await {
                Ok(Ok(())) => {}
                // Best-effort: a saturated TCP window may never accept
                // the Cease. Do not delay the close for it.
                Ok(Err(_)) | Err(_) => break,
            }
        }
        debug!(peer = %self.peer_label, "writer: hard close after saturation teardown");
        Err(WriterExit::TornDown)
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
            None,
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
            None,
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

    /// RFC 9687 wedge test: a peer that accepts the TCP connection but
    /// never reads must trip the send hold timer at ~the configured
    /// value once our kernel send buffer stops accepting bytes, ending
    /// the writer with `WriterExit::SendHoldExpired` — and without
    /// putting a NOTIFICATION on the wire (nothing is written after the
    /// expiry; the session layer never enqueues one on this path).
    #[tokio::test]
    async fn send_hold_expiry_on_wedged_peer() {
        const SEND_HOLD: Duration = Duration::from_secs(1);
        // Shrink both socket buffers so the wedge happens with little
        // data: SO_RCVBUF must be set before connect to size the
        // window; SO_SNDBUF on the writer side caps what the kernel
        // absorbs after the peer stops draining.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(4096).unwrap();
            socket.connect(addr).await.unwrap()
        });
        let (server, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&server)
            .set_send_buffer_size(4096)
            .unwrap();
        // Keep the peer socket alive but never read from it.
        let wedged_peer = connect.await.unwrap();

        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
            Some(SEND_HOLD),
        );

        // Flood enough bytes to fill both kernel buffers (priority is
        // unbounded, so enqueueing never blocks the test).
        let start = tokio::time::Instant::now();
        for _ in 0..64 {
            handle
                .priority_tx
                .send(Bytes::from(vec![0u8; 64 * 1024]))
                .unwrap();
        }

        let result = tokio::time::timeout(Duration::from_secs(10), handle.join)
            .await
            .expect("writer must exit once the send hold timer fires")
            .expect("writer task must not panic");
        let elapsed = start.elapsed();

        match result {
            Err(WriterExit::SendHoldExpired { limit }) => assert_eq!(limit, SEND_HOLD),
            other => panic!("expected SendHoldExpired, got {other:?}"),
        }
        eprintln!("send-hold wedge: teardown after {elapsed:?} (timer {SEND_HOLD:?})");
        // Teardown at ~the configured timer: at least the full
        // SendHoldTime after the flood began, and well before the
        // second timer interval would have elapsed (generous slack for
        // CI schedulers).
        assert!(
            elapsed >= SEND_HOLD,
            "expired early: {elapsed:?} < {SEND_HOLD:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "expired far too late: {elapsed:?}"
        );
        drop(wedged_peer);
    }

    /// A draining peer must NOT trip the send hold timer even when the
    /// transfer takes longer than the timer: the deadline is per
    /// write, not per connection.
    #[tokio::test]
    async fn send_hold_timer_spares_draining_peer() {
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            8,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
            Some(Duration::from_millis(200)),
        );

        // Reader that trickles: consumes everything, slowly.
        let reader = tokio::spawn(async move {
            let mut total = 0usize;
            let mut buf = [0u8; 4096];
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
            }
            total
        });

        let payload = 32 * 1024;
        for _ in 0..8 {
            handle
                .bulk_tx
                .send(Bytes::from(vec![0u8; payload]))
                .await
                .unwrap();
        }
        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let result = tokio::time::timeout(Duration::from_secs(10), join)
            .await
            .expect("writer must finish")
            .unwrap();
        assert!(
            result.is_ok(),
            "draining peer tripped the timer: {result:?}"
        );
        assert_eq!(reader.await.unwrap(), 8 * payload);
    }

    /// Batch cap: exactly [`MAX_BATCH_FRAMES`] whole frames coalesce;
    /// the rest stay queued, in order.
    #[test]
    fn coalesce_respects_frame_cap() {
        let (tx, mut rx) = mpsc::channel(256);
        for i in 0..100u8 {
            tx.try_send(Bytes::from(vec![i; 10])).unwrap();
        }
        let batch = coalesce_bulk(Bytes::from(vec![0xAA; 10]), &mut rx);
        // `first` + 63 drained frames = MAX_BATCH_FRAMES.
        assert_eq!(batch.len(), MAX_BATCH_FRAMES * 10);
        assert_eq!(&batch[..10], &[0xAA; 10]);
        assert_eq!(&batch[10..20], &[0u8; 10]);
        // Frame 63 is the first one left behind — whole and in order.
        assert_eq!(rx.try_recv().unwrap(), Bytes::from(vec![63u8; 10]));
    }

    /// Byte cap: growth stops once the batch crosses
    /// [`MAX_BATCH_BYTES`] — checked before each pull, so the batch
    /// overshoots by at most one whole frame and never splits one.
    #[test]
    fn coalesce_respects_byte_cap_whole_frames_only() {
        const FRAME: usize = 100 * 1024;
        let (tx, mut rx) = mpsc::channel(8);
        for _ in 0..5 {
            tx.try_send(Bytes::from(vec![0u8; FRAME])).unwrap();
        }
        let batch = coalesce_bulk(Bytes::from(vec![0u8; FRAME]), &mut rx);
        // 100K + 100K = 200K < 256K -> pull one more whole frame ->
        // 300K >= 256K -> stop.
        assert_eq!(batch.len(), 3 * FRAME);
        // Three frames remain queued, whole.
        for _ in 0..3 {
            assert_eq!(rx.try_recv().unwrap().len(), FRAME);
        }
        assert!(rx.try_recv().is_err());
    }

    /// An empty queue returns `first` without copying it — the
    /// idle/trickle single-frame path is unchanged.
    #[test]
    fn coalesce_empty_queue_is_zero_copy() {
        let (_tx, mut rx) = mpsc::channel::<Bytes>(8);
        let first = Bytes::from(vec![7u8; 32]);
        let ptr = first.as_ptr();
        let out = coalesce_bulk(first, &mut rx);
        assert_eq!(out.as_ptr(), ptr, "single frame must not be copied");
    }

    /// Whole-frame integrity + FIFO order across many coalesced
    /// batches: a flood far larger than one batch arrives on the wire
    /// as the exact concatenation of the frames as enqueued.
    #[tokio::test]
    async fn bulk_flood_frames_intact_and_ordered_across_batches() {
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            512,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
            None,
        );

        // 300 frames of varying size (1..=600 bytes) and distinct
        // content: > 4 full frame-cap batches.
        let mut expected = Vec::new();
        for i in 0..300usize {
            let frame = vec![u8::try_from(i % 251).unwrap(); (i * 2) % 600 + 1];
            expected.extend_from_slice(&frame);
            handle.bulk_tx.send(Bytes::from(frame)).await.unwrap();
        }
        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let mut got = vec![0u8; expected.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got, expected,
            "coalesced stream must equal frame concatenation"
        );
        join.await.unwrap().unwrap();
    }

    /// Forced short writes: tiny kernel buffers make every coalesced
    /// batch complete through multiple partial `write_all` iterations;
    /// the stream must still be the exact frame concatenation.
    #[tokio::test]
    async fn short_writes_keep_frames_intact() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(4096).unwrap();
            socket.connect(addr).await.unwrap()
        });
        let (server, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&server)
            .set_send_buffer_size(4096)
            .unwrap();
        let mut client = connect.await.unwrap();

        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            256,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
            None,
        );

        // One full byte-cap batch worth of max-size standard PDUs:
        // 64 x 4096 B, far beyond the 4 KiB kernel buffers.
        let mut expected = Vec::new();
        for i in 0..64usize {
            let frame = vec![u8::try_from(i).unwrap(); 4096];
            expected.extend_from_slice(&frame);
            handle.bulk_tx.send(Bytes::from(frame)).await.unwrap();
        }
        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);

        let mut got = vec![0u8; expected.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected, "short writes must not tear frames");
        join.await.unwrap().unwrap();
    }

    /// Teardown while coalesced batches are in flight on a healthy
    /// socket: the linger lets the in-flight write finish, so the
    /// bytes on the wire are a frame-aligned prefix of the enqueued
    /// stream — no partial frame emitted.
    #[tokio::test]
    async fn teardown_mid_batch_ends_on_frame_boundary() {
        const FRAME: usize = 1000;
        let (server, mut client) = tcp_pair().await;
        let (_read, write) = server.into_split();
        let handle = spawn(
            write,
            512,
            BgpMetrics::with_registry(prometheus::Registry::new()),
            "test-peer".to_string(),
            None,
        );

        let mut sent = Vec::new();
        for i in 0..256usize {
            let frame = vec![u8::try_from(i % 251).unwrap(); FRAME];
            sent.extend_from_slice(&frame);
            handle.bulk_tx.send(Bytes::from(frame)).await.unwrap();
        }
        // Observe some bytes on the wire, then signal hard teardown
        // while later batches are still queued/in flight.
        let mut head = [0u8; 2 * FRAME];
        client.read_exact(&mut head).await.unwrap();
        handle.teardown_tx.send(true).unwrap();

        let join = handle.join;
        drop(handle.bulk_tx);
        drop(handle.priority_tx);
        let result = tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .expect("writer must exit after teardown")
            .unwrap();
        assert!(
            matches!(result, Err(WriterExit::TornDown)),
            "expected TornDown, got {result:?}"
        );

        // Drain to EOF (writer dropped the socket on exit).
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        let mut got = head.to_vec();
        got.extend_from_slice(&rest);
        assert_eq!(
            got.len() % FRAME,
            0,
            "teardown emitted a partial frame ({} bytes)",
            got.len()
        );
        assert_eq!(
            got,
            sent[..got.len()],
            "wire bytes must be a prefix of the enqueued frame stream"
        );
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
            None,
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
            None,
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
