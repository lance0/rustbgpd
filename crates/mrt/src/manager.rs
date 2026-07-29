//! MRT manager: periodic timer + on-demand trigger + RIB query.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info};

use rustbgpd_rib::RibUpdate;

use crate::codec;
use crate::types::{MrtSnapshotData, MrtWriterConfig};
use crate::writer;

fn periodic_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

/// MRT dump manager. Periodically queries the RIB and writes `TABLE_DUMP_V2` files.
pub struct MrtManager {
    config: MrtWriterConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    trigger_rx: mpsc::Receiver<oneshot::Sender<Result<PathBuf, String>>>,
    local_bgp_id: Ipv4Addr,
}

impl MrtManager {
    /// Create a new MRT manager with the given configuration.
    #[must_use]
    pub fn new(
        config: MrtWriterConfig,
        rib_tx: mpsc::Sender<RibUpdate>,
        trigger_rx: mpsc::Receiver<oneshot::Sender<Result<PathBuf, String>>>,
        local_bgp_id: Ipv4Addr,
    ) -> Self {
        Self {
            config,
            rib_tx,
            trigger_rx,
            local_bgp_id,
        }
    }

    /// Run the manager loop. Returns when the trigger channel closes.
    pub async fn run(mut self) {
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

    async fn do_dump(
        &self,
        cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
    ) -> Result<PathBuf, String> {
        // Reject structurally impossible output paths before asking the
        // RIB actor to clone a full snapshot. Permissions and storage can
        // still change before publication, so the write remains fallible.
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || writer::prepare_output_dir(&config))
            .await
            .map_err(|e| format!("output directory preflight join error: {e}"))?
            .map_err(|e| format!("output directory preflight error: {e}"))?;

        let snapshot = self.query_snapshot(cancel).await?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts32 = u32::try_from(timestamp).unwrap_or(u32::MAX);

        let data = codec::encode_snapshot(
            self.local_bgp_id,
            &snapshot.peers,
            &snapshot.routes,
            &snapshot.evpn_routes,
            ts32,
        )
        .map_err(|e| format!("encode error: {e}"))?;

        let config = self.config.clone();
        tokio::task::spawn_blocking(move || writer::write_dump(&config, &data))
            .await
            .map_err(|e| format!("join error: {e}"))?
            .map_err(|e| {
                error!(error = %e, "MRT dump write failed");
                format!("write error: {e}")
            })
    }

    async fn query_snapshot(
        &self,
        mut cancel: Option<&mut oneshot::Sender<Result<PathBuf, String>>>,
    ) -> Result<MrtSnapshotData, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let query = RibUpdate::QueryMrtSnapshot { reply: reply_tx };

        if let Some(cancel) = cancel.as_deref_mut() {
            tokio::select! {
                biased;
                () = cancel.closed() => {
                    return Err("MRT dump canceled while queueing RIB snapshot".to_string());
                }
                result = self.rib_tx.send(query) => {
                    result.map_err(|e| format!("RIB channel closed: {e}"))?;
                }
            }
        } else {
            self.rib_tx
                .send(query)
                .await
                .map_err(|e| format!("RIB channel closed: {e}"))?;
        }

        if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                () = cancel.closed() => {
                    Err("MRT dump canceled while awaiting RIB snapshot".to_string())
                }
                result = reply_rx => {
                    result.map_err(|e| format!("RIB reply dropped: {e}"))
                }
            }
        } else {
            reply_rx
                .await
                .map_err(|e| format!("RIB reply dropped: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::types::MrtPeerEntry;

    fn test_config(output_dir: PathBuf) -> MrtWriterConfig {
        MrtWriterConfig {
            output_dir,
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
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

    #[tokio::test]
    async fn manager_shuts_down_on_trigger_close() {
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400, // long interval, won't fire
            compress: false,
            file_prefix: "rib".to_string(),
        };

        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);

        let mgr = MrtManager::new(config, rib_tx, trigger_rx, Ipv4Addr::new(1, 2, 3, 4));
        let handle = tokio::spawn(mgr.run());

        drop(trigger_tx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("MRT manager did not exit after trigger channel closed")
            .unwrap();
    }

    #[tokio::test]
    async fn on_demand_trigger_produces_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
        };

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);

        let mgr = MrtManager::new(config, rib_tx, trigger_rx, Ipv4Addr::new(1, 2, 3, 4));
        let handle = tokio::spawn(mgr.run());

        // Spawn a task to reply to the RIB query
        let rib_handler = tokio::spawn(async move {
            if let Some(RibUpdate::QueryMrtSnapshot { reply }) = rib_rx.recv().await {
                let _ = reply.send(MrtSnapshotData {
                    peers: vec![MrtPeerEntry {
                        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                        peer_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                        peer_asn: 65001,
                    }],
                    routes: vec![],
                    evpn_routes: vec![],
                });
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

        rib_handler.await.unwrap();
        drop(trigger_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn canceled_trigger_skips_dump_before_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 86400,
            compress: false,
            file_prefix: "rib".to_string(),
        };

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);

        let mgr = MrtManager::new(config, rib_tx, trigger_rx, Ipv4Addr::new(1, 2, 3, 4));
        let handle = tokio::spawn(mgr.run());

        // Count RIB snapshot queries: the canceled trigger must never
        // reach the RIB (skip happens before snapshot/encode/write).
        let rib_handler = tokio::spawn(async move {
            let mut snapshots = 0usize;
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::QueryMrtSnapshot { reply } = update {
                    snapshots += 1;
                    let _ = reply.send(MrtSnapshotData {
                        peers: vec![],
                        routes: vec![],
                        evpn_routes: vec![],
                    });
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

    #[tokio::test]
    async fn impossible_output_path_fails_before_rib_snapshot_query() {
        let dir = tempfile::tempdir().unwrap();
        let output_file = dir.path().join("not-a-directory");
        std::fs::write(&output_file, b"occupied").unwrap();

        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let manager = MrtManager::new(
            test_config(output_file.clone()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
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

        drop(trigger_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_while_awaiting_rib_drops_reply_without_file() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("lazy-output");
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (trigger_tx, trigger_rx) = mpsc::channel(16);
        let manager = MrtManager::new(
            test_config(output_dir.clone()),
            rib_tx,
            trigger_rx,
            Ipv4Addr::LOCALHOST,
        );
        let handle = tokio::spawn(manager.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        let RibUpdate::QueryMrtSnapshot {
            reply: snapshot_reply,
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
            while !snapshot_reply.is_closed() {
                tokio::task::yield_now().await;
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
    }

    #[tokio::test]
    async fn cancellation_while_queueing_on_full_rib_channel_exits_without_dump() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("lazy-output");
        let (rib_tx, rib_rx) = mpsc::channel(1);
        let (filler_reply, _filler_receiver) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryMrtSnapshot {
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
        );
        let handle = tokio::spawn(manager.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx.send(reply_tx).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !output_dir.is_dir() {
                tokio::task::yield_now().await;
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
}
