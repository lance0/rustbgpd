//! Prometheus text rendering shared by the HTTP `/metrics` endpoint and the
//! `GetMetrics` RPC.

use std::time::Duration;

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::Semaphore;

/// Bounds how long one caller waits: for the slot plus the render itself. On
/// expiry the render keeps running and holds the slot until it finishes. Far
/// above a normal render, below Prometheus's default 10 s scrape timeout.
pub const RENDER_DEADLINE: Duration = Duration::from_secs(5);

/// One whole-registry render in flight per process; later callers wait for
/// the slot instead of each occupying a blocking-pool thread. A daemon has
/// one registry, so a process-wide slot is also a per-registry slot.
pub(crate) static RENDER_SLOT: Semaphore = Semaphore::const_new(1);

/// Gather and encode the whole registry as Prometheus text.
///
/// The render scales with peer count (tens of milliseconds and several MiB
/// at 1000 peers), so it runs on the blocking pool rather than stalling an
/// async worker and every task queued behind it.
///
/// # Errors
///
/// Returns an error if encoding fails, the output is not UTF-8, or the
/// blocking render task panics. Returns [`std::io::ErrorKind::TimedOut`] when
/// the slot wait and render together exceed [`RENDER_DEADLINE`].
pub async fn render_text(metrics: &BgpMetrics) -> std::io::Result<String> {
    let metrics = metrics.clone();
    let render = async move {
        let permit = RENDER_SLOT.acquire().await.map_err(std::io::Error::other)?;
        tokio::task::spawn_blocking(move || {
            // The permit moves with the render, so a dropped or timed-out
            // caller does not release the slot while the render still runs.
            let _permit = permit;
            let families = metrics.registry().gather();
            let mut buf = Vec::new();
            TextEncoder::new()
                .encode(&families, &mut buf)
                .map_err(std::io::Error::other)?;
            String::from_utf8(buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
        .await
        .map_err(std::io::Error::other)?
    };
    tokio::time::timeout(RENDER_DEADLINE, render)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "metrics render deadline exceeded",
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    /// Blocks `gather` until released, reporting on entry whether the test
    /// had already released the earlier render.
    struct GatedCollector {
        gauge: prometheus::IntGauge,
        released: Arc<AtomicBool>,
        entered: mpsc::Sender<bool>,
        release: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl prometheus::core::Collector for GatedCollector {
        fn desc(&self) -> Vec<&prometheus::core::Desc> {
            prometheus::core::Collector::desc(&self.gauge)
        }

        fn collect(&self) -> Vec<prometheus::proto::MetricFamily> {
            let _ = self.entered.send(self.released.load(Ordering::SeqCst));
            // Bounded so a failing test cannot wedge the process.
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(30));
            prometheus::core::Collector::collect(&self.gauge)
        }
    }

    /// Blocking tasks inhibit paused-clock auto-advance, so only the explicit
    /// `advance` below expires a deadline.
    #[tokio::test(start_paused = true)]
    async fn timed_out_render_keeps_the_render_slot() {
        let metrics = BgpMetrics::new();
        let released = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        metrics
            .registry()
            .register(Box::new(GatedCollector {
                gauge: prometheus::IntGauge::new("test_gated_render", "test").unwrap(),
                released: released.clone(),
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
            }))
            .unwrap();
        let entered_rx = Arc::new(std::sync::Mutex::new(entered_rx));
        let next_entry = || {
            let entered_rx = entered_rx.clone();
            tokio::task::spawn_blocking(move || {
                entered_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("render must enter gather")
            })
        };

        let first = tokio::spawn({
            let metrics = metrics.clone();
            async move { render_text(&metrics).await }
        });
        assert!(!next_entry().await.unwrap(), "first render enters gather");
        tokio::time::advance(RENDER_DEADLINE).await;
        let error = first.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        // The expired caller left; its render still owns the slot, so no
        // later render can reach gather until the first one finishes.
        assert!(
            RENDER_SLOT.try_acquire().is_err(),
            "a timed-out render released the render slot while still running"
        );
        let second = tokio::spawn({
            let metrics = metrics.clone();
            async move { render_text(&metrics).await }
        });
        tokio::task::yield_now().await;
        released.store(true, Ordering::SeqCst);
        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        assert!(
            next_entry().await.unwrap(),
            "second render entered gather while the timed-out render held the slot"
        );
        let text = second.await.unwrap().unwrap();
        assert!(text.contains("test_gated_render 0\n"), "{text}");
    }
}
