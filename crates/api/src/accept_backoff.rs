//! Accept-error backoff for the management-plane listeners (gRPC TCP, gRPC
//! UDS, metrics).
//!
//! Tokio clears a listener's readiness only on `WouldBlock`, so after
//! EMFILE/ENFILE the listener stays readable and every poll fails at once.
//! Tonic's serve loop drops accept errors and polls again, which spins a
//! runtime worker. [`AcceptBackoff`] wraps the accepted-connection stream
//! and, after a resource-exhaustion error, delays the next poll with the BGP
//! listener's backoff (100 ms doubling to a 1 s cap, reset on success). A
//! fatal error (the listening socket itself is unusable) ends the stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures::Stream;
use rustbgpd_transport::listener::{
    ACCEPT_BACKOFF_CAP, ACCEPT_BACKOFF_INITIAL, AcceptErrorClass, accept_error_class,
};
use tokio::time::Sleep;
use tracing::{debug, error, info};

/// Consecutive failures between repeated error logs once the backoff sits
/// at its cap: about one line per minute while exhaustion persists.
const LOG_EVERY_FAILURES: u64 = 60;

/// Stream adapter that backs off after resource-exhaustion accept errors.
///
/// Errors are still yielded so the caller sees them; the adapter only
/// delays the poll that follows one. A fatal error ends the stream
/// instead, since no later accept on that socket can succeed. It logs the first failure of an
/// episode, then about one line a minute while it persists, and a
/// recovery line on the next accepted connection.
pub struct AcceptBackoff<S> {
    inner: S,
    listener: String,
    delay: Option<Pin<Box<Sleep>>>,
    next_backoff: Duration,
    failures: u64,
}

impl<S> AcceptBackoff<S> {
    /// Wrap `inner`; `listener` names it in log records.
    pub fn new(inner: S, listener: impl Into<String>) -> Self {
        Self {
            inner,
            listener: listener.into(),
            delay: None,
            next_backoff: ACCEPT_BACKOFF_INITIAL,
            failures: 0,
        }
    }
}

impl<S, T> Stream for AcceptBackoff<S>
where
    S: Stream<Item = io::Result<T>> + Unpin,
{
    type Item = io::Result<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(delay) = this.delay.as_mut() {
            ready!(delay.as_mut().poll(cx));
            this.delay = None;
        }
        let item = ready!(Pin::new(&mut this.inner).poll_next(cx));
        match &item {
            Some(Ok(_)) => {
                if this.failures > 0 {
                    info!(
                        listener = %this.listener,
                        failures = this.failures,
                        "listener accept recovered"
                    );
                }
                this.failures = 0;
                this.next_backoff = ACCEPT_BACKOFF_INITIAL;
            }
            Some(Err(e)) => match accept_error_class(e) {
                AcceptErrorClass::Transient => {
                    debug!(listener = %this.listener, error = %e, "listener accept error");
                }
                AcceptErrorClass::Fatal => {
                    // The listening socket itself is unusable; no later accept
                    // can succeed. End the stream, as the BGP listener drops
                    // such a socket. Tonic's serve returns and the gRPC
                    // supervisor fail-stops the daemon; the metrics task ends
                    // and its supervisor does the same.
                    error!(
                        listener = %this.listener,
                        error = %e,
                        "listener socket unusable; stopping its accept loop"
                    );
                    return Poll::Ready(None);
                }
                AcceptErrorClass::ResourceExhausted => {
                    this.failures += 1;
                    if this.failures == 1 || this.failures.is_multiple_of(LOG_EVERY_FAILURES) {
                        error!(
                            listener = %this.listener,
                            error = %e,
                            failures = this.failures,
                            backoff_ms = u64::try_from(this.next_backoff.as_millis()).unwrap_or(u64::MAX),
                            "listener accept failing; backing off"
                        );
                    }
                    this.delay = Some(Box::pin(tokio::time::sleep(this.next_backoff)));
                    this.next_backoff = (this.next_backoff * 2).min(ACCEPT_BACKOFF_CAP);
                }
            },
            None => {}
        }
        Poll::Ready(item)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::StreamExt;
    use tokio::time::Instant;

    use super::*;

    /// Yields `Err(errno)` on every poll, like a listener stuck at EMFILE,
    /// and ends after `limit` polls so a missing backoff fails the test
    /// instead of hanging it.
    fn failing_stream(
        errno: i32,
        polls: Arc<AtomicUsize>,
        limit: usize,
    ) -> impl Stream<Item = io::Result<()>> + Unpin {
        futures::stream::poll_fn(move |_| {
            if polls.fetch_add(1, Ordering::SeqCst) >= limit {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Err(io::Error::from_raw_os_error(errno))))
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_emfile_polls_at_most_once_per_backoff_step() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut incoming =
            AcceptBackoff::new(failing_stream(libc::EMFILE, polls.clone(), 1000), "test");
        let drained = tokio::time::timeout(Duration::from_secs(10), async {
            while incoming.next().await.is_some() {}
        })
        .await;
        assert!(drained.is_err(), "backoff must keep the stream pending");
        // 0, 100, 300, 700, 1500 ms, then once per second up to 9500 ms.
        assert_eq!(polls.load(Ordering::SeqCst), 13);
    }

    #[tokio::test(start_paused = true)]
    async fn fatal_error_ends_the_stream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut incoming =
            AcceptBackoff::new(failing_stream(libc::EBADF, polls.clone(), 1000), "test");
        let start = Instant::now();
        assert!(incoming.next().await.is_none());
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_backoff_and_transient_errors_do_not_delay() {
        let mut script = vec![
            Err(io::Error::from_raw_os_error(libc::EMFILE)),
            Err(io::Error::from_raw_os_error(libc::EMFILE)),
            Ok(()),
            Err(io::Error::from_raw_os_error(libc::ECONNABORTED)),
            Err(io::Error::from_raw_os_error(libc::ENFILE)),
            Ok(()),
        ]
        .into_iter();
        let mut incoming = AcceptBackoff::new(
            futures::stream::poll_fn(|_| Poll::Ready(script.next())),
            "test",
        );
        let start = Instant::now();
        let mut at = Vec::new();
        while incoming.next().await.is_some() {
            at.push(start.elapsed().as_millis());
        }
        // EMFILE at 0, EMFILE after 100 ms, success after 200 ms more, the
        // transient error immediately, ENFILE immediately (no delay armed),
        // and the final success after the reset 100 ms step.
        assert_eq!(at, [0, 100, 300, 300, 300, 400]);
    }
}
