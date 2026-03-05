//! MRT manager: periodic timer + on-demand trigger + RIB query.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

use rustbgpd_rib::RibUpdate;

use crate::codec;
use crate::types::{MrtSnapshotData, MrtWriterConfig};
use crate::writer;

/// MRT dump manager. Periodically queries the RIB and writes `TABLE_DUMP_V2` files.
pub struct MrtManager {
    config: MrtWriterConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    trigger_rx: mpsc::Receiver<oneshot::Sender<Result<PathBuf, String>>>,
    local_bgp_id: Ipv4Addr,
}

impl MrtManager {
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
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.dump_interval));
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
                    if let Err(e) = self.do_dump().await {
                        error!(error = %e, "periodic MRT dump failed");
                    }
                }
                maybe_reply = self.trigger_rx.recv() => {
                    if let Some(reply) = maybe_reply {
                        debug!("MRT on-demand dump triggered");
                        let result = self.do_dump().await;
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

    async fn do_dump(&self) -> Result<PathBuf, String> {
        let snapshot = self.query_snapshot().await?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts32 = u32::try_from(timestamp).unwrap_or(u32::MAX);

        let data =
            codec::encode_snapshot(self.local_bgp_id, &snapshot.peers, &snapshot.routes, ts32)
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

    async fn query_snapshot(&self) -> Result<MrtSnapshotData, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryMrtSnapshot { reply: reply_tx })
            .await
            .map_err(|e| format!("RIB channel closed: {e}"))?;
        reply_rx
            .await
            .map_err(|e| format!("RIB reply dropped: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::types::MrtPeerEntry;

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
}
