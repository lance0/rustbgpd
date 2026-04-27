//! Per-peer outbound TCP writer task.
//!
//! Owns the [`OwnedWriteHalf`] of a peer's TCP stream plus two inbound
//! channels (bounded "bulk" + unbounded "priority") and runs a biased
//! `tokio::select!` so priority traffic preempts bulk. The session task
//! encodes BGP messages and enqueues their bytes; this task is a dumb
//! pipe that does `write_all + flush`.
//!
//! Splitting the writer out of the session task is the architectural
//! fix tracked by ADR-0051. With the write half in its own task, TCP
//! receive-buffer back-pressure can no longer park the session's
//! `tokio::select!` and starve its `commands.recv()` / `read_tcp` /
//! timer arms — which is the root cause of the `GetHealth` wedge that
//! the 0735dd9 timeouts could only contain.
//!
//! Saturation policy lives in the session task, not here:
//! `bulk_tx.try_send` failing with `Full` means the peer hasn't drained
//! 4096 BGP messages, the session emits a `Cease/9` (Out of Resources)
//! through `priority_tx`, then drops both senders so this task exits
//! cleanly. Wiring of that policy is in commit 2/3; this module just
//! provides the channels and the pipe.

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Channel handles + a [`JoinHandle`] held by the session task.
///
/// Drop both `bulk_tx` and `priority_tx` to signal the writer to exit
/// cleanly — its `recv` calls return `None`, the biased select's `else`
/// arm fires, the task returns `Ok(())` and `join` resolves. A TCP
/// write or flush failure ends the task with `Err(io::Error)` instead.
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
    /// Resolves when the writer exits: `Ok(())` on clean shutdown,
    /// `Err(io::Error)` on TCP write/flush failure.
    pub(super) join: JoinHandle<std::io::Result<()>>,
}

/// Spawn a writer task for the given TCP write half. `bulk_buffer` sets
/// the bounded channel depth — production callers pass `OUTBOUND_BUFFER`
/// (defined in `session/mod.rs`); tests can pass a smaller value to
/// exercise saturation paths quickly.
pub(super) fn spawn(write_half: OwnedWriteHalf, bulk_buffer: usize) -> WriterHandle {
    let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(bulk_buffer);
    let (priority_tx, priority_rx) = mpsc::unbounded_channel::<Bytes>();
    let task = WriterTask {
        write_half,
        bulk_rx,
        priority_rx,
    };
    let join = tokio::spawn(task.run());
    WriterHandle {
        bulk_tx,
        priority_tx,
        join,
    }
}

struct WriterTask {
    write_half: OwnedWriteHalf,
    bulk_rx: mpsc::Receiver<Bytes>,
    priority_rx: mpsc::UnboundedReceiver<Bytes>,
}

impl WriterTask {
    async fn run(mut self) -> std::io::Result<()> {
        loop {
            // `biased` keeps NOTIFICATIONs and KEEPALIVEs from starving
            // behind a backlog of UPDATEs, and ensures the saturation
            // `Cease/9` reaches the wire before any further bulk work.
            // The `else` arm fires when both receivers have closed (all
            // senders dropped + buffers drained), giving us a clean
            // shutdown path with no extra signalling channel.
            let bytes = tokio::select! {
                biased;
                Some(b) = self.priority_rx.recv() => b,
                Some(b) = self.bulk_rx.recv()     => b,
                else => {
                    debug!("writer: both senders dropped, exiting cleanly");
                    return Ok(());
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
        let handle = spawn(write, 8);

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
        let handle = spawn(write, 8);

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
        let handle = spawn(write, 8);

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
