//! Prometheus text rendering shared by the HTTP `/metrics` endpoint and the
//! `GetMetrics` RPC.

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::Semaphore;

/// One whole-registry render in flight per process; later callers wait for
/// the slot instead of each occupying a blocking-pool thread. A daemon has
/// one registry, so a process-wide slot is also a per-registry slot.
static RENDER_SLOT: Semaphore = Semaphore::const_new(1);

/// Gather and encode the whole registry as Prometheus text.
///
/// The render scales with peer count (tens of milliseconds and several MiB
/// at 1000 peers), so it runs on the blocking pool rather than stalling an
/// async worker and every task queued behind it.
///
/// # Errors
///
/// Returns an error if encoding fails, the output is not UTF-8, or the
/// blocking render task panics.
pub async fn render_text(metrics: &BgpMetrics) -> std::io::Result<String> {
    let permit = RENDER_SLOT.acquire().await.map_err(std::io::Error::other)?;
    let metrics = metrics.clone();
    tokio::task::spawn_blocking(move || {
        // The permit moves with the render, so a dropped caller does not
        // release the slot while the render is still running.
        let _permit = permit;
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&families, &mut buf)
            .map_err(std::io::Error::other)?;
        String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })
    .await
    .map_err(std::io::Error::other)?
}
