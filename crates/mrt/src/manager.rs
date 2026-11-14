//! MRT manager: periodic timer + on-demand trigger + RIB query.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info};

use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;

use crate::codec::StreamEncodeError;
use crate::stream::StreamingSnapshot;
use rustbgpd_rib::MrtSnapshotCursor;

use crate::types::{MrtSnapshotChunk, MrtWriterConfig};
use crate::writer;

fn periodic_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

/// A failed or canceled dump: the operator-facing message plus the bounded
/// `mrt_dump_failures_total{stage}` class. `stage` is `None` for a
/// caller-canceled on-demand dump, which is not a writer failure.
struct DumpError {
    stage: Option<&'static str>,
    message: String,
}

/// Dropping an async owner also cancels any blocking encoder it dispatched.
struct CancelEncoding(Arc<AtomicBool>);

impl Drop for CancelEncoding {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl DumpError {
    fn at(stage: &'static str, message: String) -> Self {
        Self {
            stage: Some(stage),
            message,
        }
    }

    fn canceled(message: &str) -> Self {
        Self {
            stage: None,
            message: message.to_string(),
        }
    }
}

/// MRT dump manager. Periodically queries the RIB and writes `TABLE_DUMP_V2` files.
pub struct MrtManager {
    config: MrtWriterConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    trigger_rx: mpsc::Receiver<oneshot::Sender<Result<PathBuf, String>>>,
    local_bgp_id: Ipv4Addr,
    metrics: BgpMetrics,
}

impl MrtManager {
    /// Create a new MRT manager with the given configuration.
    #[must_use]
    pub fn new(
        config: MrtWriterConfig,
        rib_tx: mpsc::Sender<RibUpdate>,
        trigger_rx: mpsc::Receiver<oneshot::Sender<Result<PathBuf, String>>>,
        local_bgp_id: Ipv4Addr,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            config,
            rib_tx,
            trigger_rx,
            local_bgp_id,
            metrics,
        }
    }

    /// Run the manager loop. Returns when the trigger channel closes.
    pub async fn run(mut self) {
        self.metrics
            .set_mrt_dump_interval_seconds(self.config.dump_interval);
        let mut interval = periodic_interval(Duration::from_secs(self.config.dump_interval));
        // Skip the immediate first tick — the first dump will fire after one interval.
        interval.tick().await;

        info!(
            interval_secs = self.config.dump_interval,
            output_dir = %self.config.output_dir.display(),
            "MRT manager started"
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    debug!("MRT periodic dump triggered");
                    if let Err(e) = self.do_dump(None).await {
                        error!(error = %e, "periodic MRT dump failed");
                    }
                }
                maybe_reply = self.trigger_rx.recv() => {
                    if let Some(mut reply) = maybe_reply {
                        // The reply channel doubles as the cancel token: a
                        // request whose caller is gone (e.g. a canceled gRPC
                        // dump request queued behind a slow dump) is skipped
                        // before the RIB snapshot, encode, and file write.
                        if reply.is_closed() {
                            debug!("MRT on-demand dump canceled before start; skipping");
                            continue;
                        }
                        debug!("MRT on-demand dump triggered");
                        let result = self.do_dump(Some(&mut reply)).await;
                        let _ = reply.send(result);
                    } else {
                        debug!("MRT trigger channel closed, shutting down");
                        break;
                    }
                }
            }
        }

        info!("MRT manager shutting down");
    }

    /// Run one dump and account for it: a published file stamps the
    /// success gauges and bytes counter; a failure increments
    /// `mrt_dump_failures_total{stage}`; a caller cancellation is neither.
    async fn do_dump(
        &self,
        cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
    ) -> Result<PathBuf, String> {
        let started = Instant::now();
        match self.dump_once(cancel).await {
            Ok((path, bytes_written)) => {
                self.metrics
                    .record_mrt_dump_success(bytes_written, started.elapsed());
                Ok(path)
            }
            Err(DumpError { stage, message }) => {
                if let Some(stage) = stage {
                    self.metrics.record_mrt_dump_failure(stage);
                }
                Err(message)
            }
        }
    }

    async fn dump_once(
        &self,
        mut cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
    ) -> Result<(PathBuf, u64), DumpError> {
        // Reject structurally impossible output paths before asking the
        // RIB actor to start the snapshot walk. Permissions and storage can
        // still change before publication, so the write remains fallible.
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || writer::prepare_output_dir(&config))
            .await
            .map_err(|e| {
                DumpError::at(
                    "preflight",
                    format!("output directory preflight join error: {e}"),
                )
            })?
            .map_err(|e| {
                DumpError::at(
                    "preflight",
                    format!("output directory preflight error: {e}"),
                )
            })?;

        // The record timestamp is the start of the walk: every route in the
        // file was read at or after it.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts32 = u32::try_from(timestamp).unwrap_or(u32::MAX);

        let cancellation = CancelEncoding(Arc::new(AtomicBool::new(false)));
        let mut first = self.query_chunk(None, cancel.as_deref_mut()).await?;
        let mut cursor = first.next.take();
        let config = self.config.clone();
        let collector = self.local_bgp_id;
        let cancelled = Arc::clone(&cancellation.0);
        let mut stream = Self::encode_step(
            move || {
                let mut stream =
                    StreamingSnapshot::new(&config, collector, ts32, &first.peers, cancelled)?;
                stream.push(&first)?;
                Ok(stream)
            },
            cancel.as_deref_mut(),
            &cancellation.0,
        )
        .await?;
        while let Some(position) = cursor {
            let mut chunk = self
                .query_chunk(Some(position), cancel.as_deref_mut())
                .await?;
            cursor = chunk.next.take();
            // Await the write before requesting another chunk. A slow disk
            // never queues a second copy of the table behind this task.
            stream = Self::encode_step(
                move || {
                    stream.push(&chunk)?;
                    Ok(stream)
                },
                cancel.as_deref_mut(),
                &cancellation.0,
            )
            .await?;
        }
        Self::encode_step(move || stream.finish(), cancel, &cancellation.0).await
    }

    async fn encode_step<T: Send + 'static>(
        work: impl FnOnce() -> Result<T, StreamEncodeError> + Send + 'static,
        cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
        cancelled: &AtomicBool,
    ) -> Result<T, DumpError> {
        let mut task = tokio::task::spawn_blocking(work);
        let result = if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                () = cancel.closed() => {
                    cancelled.store(true, Ordering::Release);
                    // Finish may already have published. Preserve success so
                    // that committed dumps still update their metrics.
                    return match task.await {
                        Ok(Ok(value)) => Ok(value),
                        _ => Err(DumpError::canceled("MRT dump canceled while encoding")),
                    };
                }
                result = &mut task => result,
            }
        } else {
            task.await
        };
        result
            .map_err(|error| DumpError::at("write", format!("MRT encoder task failed: {error}")))?
            .map_err(|error| match error {
                StreamEncodeError::Encode(error) => {
                    DumpError::at("encode", format!("encode error: {error}"))
                }
                StreamEncodeError::Io(error) => {
                    DumpError::at("write", format!("write error: {error}"))
                }
            })
    }

    async fn query_chunk(
        &self,
        cursor: Option<MrtSnapshotCursor>,
        mut cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
    ) -> Result<MrtSnapshotChunk, DumpError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let query = RibUpdate::QueryMrtSnapshotChunk {
            cursor,
            reply: reply_tx,
        };
        let closed = |e| DumpError::at("snapshot", format!("RIB channel closed: {e}"));
        let dropped = |e| DumpError::at("snapshot", format!("RIB reply dropped: {e}"));

        if let Some(cancel) = cancel.as_deref_mut() {
            tokio::select! {
                biased;
                () = cancel.closed() => {
                    return Err(DumpError::canceled("MRT dump canceled while queueing RIB snapshot"));
                }
                result = self.rib_tx.send(query) => {
                    result.map_err(closed)?;
                }
            }
        } else {
            self.rib_tx.send(query).await.map_err(closed)?;
        }

        if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                () = cancel.closed() => {
                    Err(DumpError::canceled("MRT dump canceled while awaiting RIB snapshot"))
                }
                result = reply_rx => {
                    result.map_err(dropped)?.map_err(|error| DumpError::at("snapshot", error))
                }
            }
        } else {
            reply_rx
                .await
                .map_err(dropped)?
                .map_err(|error| DumpError::at("snapshot", error))
        }
    }
}

// Every test runs on a paused clock. Dumps fsync and rename on the blocking
// pool, which can take seconds on a loaded host, and tokio does not
// auto-advance a paused clock while a blocking task is in flight. The
// timeouts below therefore bound only time the manager spends idle, so they
// still catch a manager that stops without replying.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::types::MrtPeerEntry;
    use crate::writer::private_tempdir;

    /// Read one exported sample (gauge or counter) by family name and an
    /// optional label match; 0 when the family or series is absent.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the sampled families are integral gauges and counters"
    )]
    fn metric_sample(metrics: &BgpMetrics, name: &str, label: Option<(&str, &str)>) -> i64 {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|f| f.name() == name)
            .and_then(|mut f| {
                f.take_metric().into_iter().find(|m| match label {
                    None => true,
                    Some((k, v)) => m
                        .get_label()
                        .iter()
                        .any(|l| l.name() == k && l.value() == v),
                })
            })
            .map_or(0, |m| {
                // Counter families follow the `_total` naming convention;
                // everything else sampled here is a gauge.
                if name.ends_with("_total") {
                    m.get_counter().get_value() as i64
                } else {
                    m.get_gauge().get_value() as i64
                }
            })
    }

    fn test_config(output_dir: PathBuf) -> MrtWriterConfig {
        MrtWriterConfig {
            output_dir,
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_interval_skips_missed_tick_bursts() {
        let start = tokio::time::Instant::now();
        let mut interval = periodic_interval(Duration::from_secs(10));
        interval.tick().await;

        // A dump held the manager for 35 seconds. Exactly one overdue tick is
        // consumed; the following tick must be the next cadence boundary, not
        // another member of the default Burst backlog.
        tokio::time::advance(Duration::from_secs(35)).await;
        assert_eq!(
            interval.tick().await.duration_since(start),
            Duration::from_secs(10)
        );
        assert_eq!(
            interval.tick().await.duration_since(start),
            Duration::from_secs(40)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn manager_shuts_down_on_trigger_close() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400, // long interval, won't fire
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);

        let mgr = MrtManager::new(
            config,
            rib_tx,
            trigger_rx,
            Ipv4Addr::new(1, 2, 3, 4),
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        drop(trigger_tx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("MRT manager did not exit after trigger channel closed")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn on_demand_trigger_produces_file() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let before = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        let mgr = MrtManager::new(
            config,
            rib_tx,
            trigger_rx,
            Ipv4Addr::new(1, 2, 3, 4),
            metrics.clone(),
        );
        let handle = tokio::spawn(mgr.run());

        // Spawn a task to reply to the RIB query
        let rib_handler = tokio::spawn(async move {
            if let Some(RibUpdate::QueryMrtSnapshotChunk { reply, .. }) = rib_rx.recv().await {
                let _ = reply.send(Ok(MrtSnapshotChunk {
                    peers: vec![MrtPeerEntry {
                        peer: rustbgpd_rib::PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(
                            10, 0, 0, 1,
                        ))),
                        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                        interface: None,
                        peer_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                        peer_asn: 65001,
                    }],
                    routes: vec![],
                    evpn_routes: vec![],
                    next: None,
                }));
            }
        });

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("timeout waiting for MRT dump reply")
            .expect("reply channel closed");

        let path = result.expect("MRT dump should succeed");
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".mrt"));

        // Dump health metrics: the success stamps the timestamp, the bytes
        // counter matches the published file, and nothing counts as a failure.
        let on_disk = i64::try_from(std::fs::metadata(&path).unwrap().len()).unwrap();
        assert!(on_disk > 0, "PEER_INDEX_TABLE must produce bytes");
        assert_eq!(
            metric_sample(&metrics, "mrt_dump_interval_seconds", None),
            86400
        );
        assert!(
            metric_sample(&metrics, "mrt_last_dump_success_timestamp_seconds", None) >= before,
            "success timestamp must be stamped"
        );
        assert_eq!(
            metric_sample(&metrics, "mrt_dump_bytes_written_total", None),
            on_disk
        );
        assert_eq!(metric_sample(&metrics, "mrt_dump_failures_total", None), 0);

        rib_handler.await.unwrap();
        drop(trigger_tx);
        handle.await.unwrap();
    }

    /// The published size comes from the written file's descriptor: a dump
    /// whose directory is renamed after it was pinned still publishes, so it
    /// is reported as a success with the published file's size, not as a
    /// failed lookup of the old path.
    #[tokio::test(start_paused = true)]
    async fn dump_size_survives_the_output_dir_moving_after_the_pin() {
        static CHECKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        /// The first call is the preflight; the second runs after the
        /// dump's own pin, and moves the directory away.
        fn move_after_pin(path: &std::path::Path, _: &std::fs::File) -> std::io::Result<()> {
            if CHECKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                std::fs::rename(path, path.with_file_name("moved"))?;
            }
            Ok(())
        }
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            ancestor_check: Some(move_after_pin),
            ..test_config(dir.path().join("dumps"))
        };
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let manager = MrtManager::new(
            config,
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            metrics.clone(),
        );
        let handle = tokio::spawn(manager.run());
        let rib_handler = tokio::spawn(async move {
            if let Some(RibUpdate::QueryMrtSnapshotChunk { reply, .. }) = rib_rx.recv().await {
                let _ = reply.send(Ok(MrtSnapshotChunk {
                    peers: vec![],
                    routes: vec![],
                    evpn_routes: vec![],
                    next: None,
                }));
            }
        });

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let path = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("timeout waiting for MRT dump reply")
            .expect("reply channel closed")
            .expect("a dump published into the pinned directory must succeed");
        assert!(!path.exists(), "the configured spelling moved away");
        let published = dir.path().join("moved").join(path.file_name().unwrap());
        let on_disk = i64::try_from(std::fs::metadata(&published).unwrap().len()).unwrap();
        assert!(on_disk > 0);
        assert_eq!(
            metric_sample(&metrics, "mrt_dump_bytes_written_total", None),
            on_disk
        );
        assert_eq!(metric_sample(&metrics, "mrt_dump_failures_total", None), 0);

        rib_handler.await.unwrap();
        drop(trigger_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn canceled_trigger_skips_dump_before_snapshot() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);

        let mgr = MrtManager::new(
            config,
            rib_tx,
            trigger_rx,
            Ipv4Addr::new(1, 2, 3, 4),
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        // Count RIB snapshot queries: the canceled trigger must never
        // reach the RIB (skip happens before snapshot/encode/write).
        let rib_handler = tokio::spawn(async move {
            let mut snapshots = 0usize;
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::QueryMrtSnapshotChunk { reply, .. } = update {
                    snapshots += 1;
                    let _ = reply.send(Ok(MrtSnapshotChunk {
                        peers: vec![],
                        routes: vec![],
                        evpn_routes: vec![],
                        next: None,
                    }));
                }
            }
            snapshots
        });

        // Canceled request: receiver dropped before the manager sees it.
        let (canceled_tx, canceled_rx) = oneshot::channel();
        drop(canceled_rx);
        trigger_tx.send(canceled_tx).await.unwrap();

        // Live request queued behind it still completes.
        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("timeout waiting for MRT dump reply")
            .expect("reply channel closed")
            .expect("live MRT dump should succeed");

        drop(trigger_tx);
        handle.await.unwrap();
        let snapshots = rib_handler.await.unwrap();
        assert_eq!(snapshots, 1, "canceled dump must not query the RIB");
    }

    #[tokio::test(start_paused = true)]
    async fn impossible_output_path_fails_before_rib_snapshot_query() {
        let dir = private_tempdir();
        let output_file = dir.path().join("not-a-directory");
        std::fs::write(&output_file, b"occupied").unwrap();

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let manager = MrtManager::new(
            test_config(output_file.clone()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            metrics.clone(),
        );
        let handle = tokio::spawn(manager.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("output preflight must not wait for the RIB")
            .expect("manager must return the preflight failure")
            .expect_err("regular-file output path must be rejected");
        assert!(error.contains("output directory preflight"), "{error}");
        assert!(
            rib_rx.try_recv().is_err(),
            "structurally impossible output must emit zero RIB queries"
        );
        assert_eq!(
            metric_sample(
                &metrics,
                "mrt_dump_failures_total",
                Some(("stage", "preflight"))
            ),
            1
        );
        assert_eq!(
            metric_sample(&metrics, "mrt_last_dump_success_timestamp_seconds", None),
            0,
            "a failed dump must not stamp a success"
        );

        drop(trigger_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_while_awaiting_rib_drops_reply_without_file() {
        let dir = private_tempdir();
        let output_dir = dir.path().join("lazy-output");
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let manager = MrtManager::new(
            test_config(output_dir.clone()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            metrics.clone(),
        );
        let handle = tokio::spawn(manager.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let RibUpdate::QueryMrtSnapshotChunk {
            reply: snapshot_reply,
            ..
        } = tokio::time::timeout(Duration::from_secs(2), rib_rx.recv())
            .await
            .expect("manager did not query the RIB")
            .expect("RIB query channel closed")
        else {
            panic!("unexpected RIB update");
        };

        // Cancel after the query is enqueued but before the RIB responds.
        drop(reply_rx);
        tokio::time::timeout(Duration::from_secs(2), async {
            // Sleep, not yield: a yield keeps the paused clock from advancing,
            // so the bound would never fire.
            while !snapshot_reply.is_closed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("manager retained the RIB reply after caller cancellation");

        assert!(
            output_dir.is_dir(),
            "preflight lazily creates the directory"
        );
        assert_eq!(
            std::fs::read_dir(&output_dir).unwrap().count(),
            0,
            "canceled dump must not encode or publish a file"
        );

        drop(snapshot_reply);
        drop(trigger_tx);
        handle.await.unwrap();
        assert_eq!(
            metric_sample(&metrics, "mrt_dump_failures_total", None),
            0,
            "a caller-canceled dump is not a writer failure"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_while_queueing_on_full_rib_channel_exits_without_dump() {
        let dir = private_tempdir();
        let output_dir = dir.path().join("lazy-output");
        let (rib_tx, rib_rx) = mpsc::channel(1);
        let (filler_reply, _filler_receiver) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryMrtSnapshotChunk {
                cursor: None,
                reply: filler_reply,
            })
            .await
            .unwrap();
        let (trigger_tx, trigger_rx) = mpsc::channel(1);
        let manager = MrtManager::new(
            test_config(output_dir.clone()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(manager.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !output_dir.is_dir() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("manager did not finish output preflight");

        // Preflight proves the manager passed the initial cancellation check.
        // With the RIB channel still full, only the cancel-aware send select can
        // let the manager observe shutdown and return.
        drop(reply_rx);
        drop(trigger_tx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("canceled dump remained blocked queueing the RIB query")
            .unwrap();

        assert_eq!(rib_rx.len(), 1, "canceled dump enqueued another RIB query");
        assert_eq!(
            std::fs::read_dir(&output_dir).unwrap().count(),
            0,
            "canceled dump must not publish a file"
        );
    }

    type Trigger = mpsc::Sender<oneshot::Sender<Result<PathBuf, String>>>;

    /// A manager whose RIB queries arrive on the returned receiver, and a
    /// real, empty RIB actor to answer them. An empty table still takes two
    /// turns (unicast, then EVPN), so the first reply carries a real cursor.
    fn manager_with_proxied_rib(
        output_dir: PathBuf,
        metrics: &BgpMetrics,
    ) -> (
        Trigger,
        mpsc::Receiver<RibUpdate>,
        mpsc::Sender<RibUpdate>,
        tokio::task::JoinHandle<()>,
    ) {
        let (rib_tx, rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let manager = MrtManager::new(
            test_config(output_dir),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            metrics.clone(),
        );
        let handle = tokio::spawn(manager.run());
        let (actor_tx, actor_rx) = mpsc::channel(16);
        let actor = rustbgpd_rib::RibManager::new(
            actor_rx,
            mpsc::channel(1).1,
            None,
            None,
            BgpMetrics::new(),
        );
        tokio::spawn(actor.run());
        (trigger_tx, rib_rx, actor_tx, handle)
    }

    /// The RIB actor going away between two chunks (daemon shutdown) fails
    /// the dump at the `snapshot` stage; its staged bytes are removed.
    #[tokio::test(start_paused = true)]
    async fn rib_loss_between_chunks_fails_the_dump_without_a_file() {
        let dir = private_tempdir();
        let metrics = BgpMetrics::new();
        let (trigger_tx, mut rib_rx, actor_tx, handle) =
            manager_with_proxied_rib(dir.path().to_path_buf(), &metrics);

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let first = rib_rx.recv().await.expect("first chunk query");
        actor_tx.send(first).await.unwrap();
        let second = rib_rx.recv().await.expect("second chunk query");
        assert!(matches!(
            second,
            RibUpdate::QueryMrtSnapshotChunk {
                cursor: Some(_),
                ..
            }
        ));
        drop(second);

        let error = reply_rx.await.unwrap().expect_err("partial snapshot");
        assert!(error.contains("RIB reply dropped"), "{error}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(
            metric_sample(
                &metrics,
                "mrt_dump_failures_total",
                Some(("stage", "snapshot"))
            ),
            1
        );
        drop(trigger_tx);
        handle.await.unwrap();
    }

    /// A caller that goes away between two chunks stops the walk: the
    /// manager drops the chunk it was waiting on and publishes nothing.
    #[tokio::test(start_paused = true)]
    async fn cancellation_between_chunks_stops_the_walk_without_a_file() {
        let dir = private_tempdir();
        let metrics = BgpMetrics::new();
        let (trigger_tx, mut rib_rx, actor_tx, handle) =
            manager_with_proxied_rib(dir.path().to_path_buf(), &metrics);

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let first = rib_rx.recv().await.expect("first chunk query");
        actor_tx.send(first).await.unwrap();
        let Some(RibUpdate::QueryMrtSnapshotChunk {
            reply: second_reply,
            ..
        }) = rib_rx.recv().await
        else {
            panic!("second chunk query");
        };

        drop(reply_rx);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !second_reply.is_closed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("manager kept walking after caller cancellation");
        drop(trigger_tx);
        handle.await.unwrap();
        assert!(rib_rx.recv().await.is_none(), "a canceled walk asked again");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(metric_sample(&metrics, "mrt_dump_failures_total", None), 0);
    }

    #[tokio::test]
    async fn cancellation_waits_for_blocking_stage_cleanup() {
        let dir = private_tempdir();
        let config = test_config(dir.path().to_path_buf());
        let cancelled = Arc::new(AtomicBool::new(false));
        let owner_flag = Arc::clone(&cancelled);
        let work_flag = Arc::clone(&cancelled);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (mut reply_tx, reply_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _guard = CancelEncoding(Arc::clone(&owner_flag));
            MrtManager::encode_step(
                move || {
                    let stream =
                        StreamingSnapshot::new(&config, Ipv4Addr::LOCALHOST, 1, &[], work_flag)?;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    stream.finish()
                },
                Some(&mut reply_tx),
                &owner_flag,
            )
            .await
        });
        started_rx.await.unwrap();
        drop(reply_rx);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !handle.is_finished(),
            "cancellation detached the blocking writer"
        );
        release_tx.send(()).unwrap();
        let result = handle.await.unwrap();
        assert!(matches!(result, Err(DumpError { stage: None, .. })));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn aborting_async_owner_cancels_its_blocking_writer() {
        let dir = private_tempdir();
        let config = test_config(dir.path().to_path_buf());
        let cancelled = Arc::new(AtomicBool::new(false));
        let owner_flag = Arc::clone(&cancelled);
        let work_flag = Arc::clone(&cancelled);
        let (started_tx, started_rx) = oneshot::channel();
        let (settled_tx, settled_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let handle = tokio::spawn(async move {
            let _guard = CancelEncoding(Arc::clone(&owner_flag));
            MrtManager::encode_step(
                move || {
                    let stream =
                        StreamingSnapshot::new(&config, Ipv4Addr::LOCALHOST, 1, &[], work_flag)?;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    let result = stream.finish();
                    settled_tx.send(result.is_err()).unwrap();
                    result
                },
                None,
                &owner_flag,
            )
            .await
        });
        started_rx.await.unwrap();
        handle.abort();
        assert!(matches!(handle.await, Err(error) if error.is_cancelled()));
        assert!(cancelled.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        assert!(settled_rx.await.unwrap());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn cancellation_after_publication_preserves_the_committed_result() {
        let dir = private_tempdir();
        let config = test_config(dir.path().to_path_buf());
        let cancelled = Arc::new(AtomicBool::new(false));
        let owner_flag = Arc::clone(&cancelled);
        let work_flag = Arc::clone(&cancelled);
        let (published_tx, published_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (mut reply_tx, reply_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            MrtManager::encode_step(
                move || {
                    let stream =
                        StreamingSnapshot::new(&config, Ipv4Addr::LOCALHOST, 1, &[], work_flag)?;
                    let result = stream.finish()?;
                    published_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(result)
                },
                Some(&mut reply_tx),
                &owner_flag,
            )
            .await
        });
        published_rx.await.unwrap();
        drop(reply_rx);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        release_tx.send(()).unwrap();
        let Ok((path, bytes)) = handle.await.unwrap() else {
            panic!("a committed dump was reported as canceled");
        };
        assert_eq!(std::fs::metadata(path).unwrap().len(), bytes);
        assert!(bytes > 0);
    }

    /// Ticks that come due while a dump is in flight start one dump when it
    /// ends, not one per missed tick, and never a second walk alongside it.
    #[tokio::test(start_paused = true)]
    async fn ticks_due_during_a_dump_start_one_dump_after_it() {
        let dir = private_tempdir();
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let manager = MrtManager::new(
            MrtWriterConfig {
                dump_interval: 10,
                ..test_config(dir.path().to_path_buf())
            },
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            BgpMetrics::new(),
        );
        let start = tokio::time::Instant::now();
        let handle = tokio::spawn(manager.run());

        let mut queried_at = Vec::new();
        while queried_at.len() < 3 {
            let Some(RibUpdate::QueryMrtSnapshotChunk { reply, .. }) = rib_rx.recv().await else {
                panic!("RIB query");
            };
            queried_at.push(start.elapsed().as_secs());
            if queried_at.len() == 1 {
                // The first walk outlasts the ticks at 20 s and 30 s.
                tokio::time::sleep(Duration::from_secs(25)).await;
                assert!(rib_rx.is_empty(), "a second walk started alongside");
            }
            let _ = reply.send(Ok(MrtSnapshotChunk::default()));
        }
        assert_eq!(queried_at, [10, 35, 40]);
        drop(trigger_tx);
        handle.await.unwrap();
    }

    /// The record timestamp is taken when the walk starts, so every route
    /// in the file was read at or after it. The RIB answers a second later
    /// here; a timestamp taken after the walk would carry that second.
    #[tokio::test(start_paused = true)]
    async fn record_timestamp_is_the_start_of_the_walk() {
        let dir = private_tempdir();
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let manager = MrtManager::new(
            test_config(dir.path().to_path_buf()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(manager.run());
        let unix_now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let Some(RibUpdate::QueryMrtSnapshotChunk { reply, .. }) = rib_rx.recv().await else {
            panic!("RIB query");
        };
        // Wall-clock time: the record timestamp is not on tokio's clock.
        std::thread::sleep(Duration::from_millis(1100));
        let answered = unix_now();
        let _ = reply.send(Ok(MrtSnapshotChunk::default()));

        let path = reply_rx.await.unwrap().expect("dump");
        let bytes = std::fs::read(path).unwrap();
        let record = u64::from(u32::from_be_bytes(bytes[..4].try_into().unwrap()));
        assert!(
            record < answered,
            "record timestamp {record} is not before the RIB answered at {answered}"
        );
        drop(trigger_tx);
        handle.await.unwrap();
    }
}
