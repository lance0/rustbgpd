//! Prometheus text rendering shared by the HTTP `/metrics` endpoint and the
//! `GetMetrics` RPC.

use std::time::Duration;

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::Semaphore;

/// Bounds one caller's whole render operation: waiting for the slot plus the
/// render itself. Far above a normal render, below Prometheus's default 10 s
/// scrape timeout.
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

    #[tokio::test(start_paused = true)]
    async fn held_render_slot_times_out_without_releasing_it() {
        let held = RENDER_SLOT.acquire().await.unwrap();
        let started = tokio::time::Instant::now();
        let error = render_text(&BgpMetrics::new()).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), RENDER_DEADLINE);
        assert_eq!(RENDER_SLOT.available_permits(), 0);
        drop(held);
    }
}
