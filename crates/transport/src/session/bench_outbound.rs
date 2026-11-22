//! Benchmark seam: drive one real session's `send_route_update` against an
//! in-memory writer queue, so the outbound grouping and encode path can be
//! timed without TCP.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Waker};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use bytes::Bytes;
use rustbgpd_fsm::NegotiatedSession;
use rustbgpd_rib::{OutboundRouteUpdate, Route, SharedGroupEncode};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::mpsc;

use super::{PeerSession, SessionIdentity};
use rustbgpd_fsm::PeerConfig;

use crate::config::TransportConfig;

/// One established eBGP route-server-client session whose writer queue is
/// an unbounded-enough in-memory channel drained after every envelope.
pub struct OutboundEncodeBench {
    session: PeerSession,
    bulk_rx: mpsc::Receiver<Bytes>,
    completed: tokio::sync::watch::Sender<u64>,
    priority_rx: mpsc::UnboundedReceiver<Bytes>,
}

impl OutboundEncodeBench {
    /// Build the session. `queue` bounds the in-memory writer queue.
    ///
    /// # Panics
    ///
    /// Never for the fixed literal peer address.
    #[must_use]
    pub fn new(queue: usize) -> Self {
        let mut peer_config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
        let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        config.route_server_client = true;
        Self::with_config(config, BgpMetrics::new(), Ipv4Addr::new(10, 0, 0, 2), queue)
    }

    /// Construct one already-negotiated iBGP route-reflector client for the
    /// manager-direct loopback harness. Handshake and inbound FSM are outside the cell.
    #[must_use]
    pub fn reflector_client(
        peer: Ipv4Addr,
        flowspec: bool,
        metrics: BgpMetrics,
        queue: usize,
    ) -> Self {
        let router_id = Ipv4Addr::new(10, 255, 255, 255);
        let mut peer_config = PeerConfig::new(64_512, 64_512, router_id);
        peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
        if flowspec {
            peer_config.families.push((Afi::Ipv4, Safi::FlowSpec));
        }
        let mut config = TransportConfig::new(peer_config, SocketAddr::new(IpAddr::V4(peer), 179));
        config.route_reflector_client = true;
        config.cluster_id = Some(router_id);
        config.local_address = Some(IpAddr::V4(router_id));
        Self::with_config(config, metrics, peer, queue)
    }

    fn with_config(
        config: TransportConfig,
        metrics: BgpMetrics,
        router_id: Ipv4Addr,
        queue: usize,
    ) -> Self {
        let peer_asn = config.peer.remote_asn;
        let families = config.peer.families.clone();
        let (_command_tx, commands) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mut session = PeerSession::new_at_tcp_ao_generation(
            config,
            metrics,
            commands,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            SessionIdentity::default(),
            crate::TcpAoRotationGeneration::STARTUP,
        );
        let mut negotiated = NegotiatedSession::default();
        negotiated.peer_asn = peer_asn;
        negotiated.peer_router_id = router_id;
        negotiated.hold_time = 90;
        negotiated.keepalive_interval = 30;
        negotiated.four_octet_as = true;
        negotiated.negotiated_families = families;
        session.negotiated = Some(Arc::new(negotiated));
        let (bulk_tx, bulk_rx) = mpsc::channel(queue);
        let (completed, writer_completed) = tokio::sync::watch::channel(0);
        let (priority_tx, priority_rx) = mpsc::unbounded_channel();
        session.writer_bulk_tx = Some(bulk_tx);
        session.writer_completed = Some(writer_completed);
        session.writer_priority_tx = Some(priority_tx);
        Self {
            session,
            bulk_rx,
            completed,
            priority_rx,
        }
    }

    /// Register this session's own encoder with the RIB so each admitted
    /// envelope retains the snapshot used for its preflight.
    #[must_use]
    pub fn export_encoder(&self) -> Arc<dyn rustbgpd_rib::update::ExactExportEncoder> {
        self.session.publish_export_profile();
        self.session.export_encoder.clone()
    }

    /// Send all frames for an admitted RIB envelope to its loopback peer.
    /// Acknowledge each writer batch only after TCP accepted its bytes.
    ///
    /// # Errors
    ///
    /// Returns the socket error or a session writer teardown.
    pub async fn write_envelope(
        &mut self,
        update: OutboundRouteUpdate,
        socket: &mut TcpStream,
    ) -> io::Result<()> {
        self.session.handle_outbound_route_update(update).await;
        loop {
            if self.session.writer_bulk_tx.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "outbound session writer closed",
                ));
            }
            while let Ok(frame) = self.priority_rx.try_recv() {
                socket.write_all(&frame).await?;
            }
            while let Ok(frame) = self.bulk_rx.try_recv() {
                socket.write_all(&frame).await?;
            }
            self.completed
                .send_replace(self.session.writer_bulk_admitted);
            if self.session.pending_outbound.is_none() {
                return Ok(());
            }
            self.session.advance_pending_outbound();
        }
    }

    /// Encode one announce-only envelope and return the time spent in
    /// `send_route_update` alone. The in-memory writer queue is drained
    /// afterwards, outside the returned duration, so frame count does not
    /// add channel-receive work to the measurement.
    ///
    /// # Panics
    ///
    /// If the writer queue saturated and the session tore down.
    pub fn send(&mut self, announce: &Arc<Vec<Route>>) -> std::time::Duration {
        let update = OutboundRouteUpdate {
            exact_export_snapshot: Some(self.session.publish_export_profile()),
            announce: Arc::clone(announce),
            next_hop_override: vec![None; announce.len()].into(),
            ..OutboundRouteUpdate::default()
        };
        // This encode-only sink drains after the complete call. Its byte
        // watermark belongs to the paced fixtures, which model writer progress.
        let completion = self.session.writer_completed.take();
        let start = std::time::Instant::now();
        self.session.send_route_update(update);
        let elapsed = start.elapsed();
        self.session.writer_completed = completion;
        assert!(
            self.session.writer_bulk_tx.is_some(),
            "bench writer queue saturated"
        );
        self.complete();
        elapsed
    }

    /// Deliver through the production admission cursor, including its byte
    /// budget. Complete writes between steps outside the returned duration.
    ///
    /// # Panics
    ///
    /// If the fixed benchmark session is missing negotiation or tears down.
    pub fn send_paced(
        &mut self,
        announce: &Arc<Vec<Route>>,
        extended_messages: bool,
    ) -> std::time::Duration {
        let update = OutboundRouteUpdate {
            announce: Arc::clone(announce),
            next_hop_override: vec![None; announce.len()].into(),
            ..OutboundRouteUpdate::default()
        };
        self.send_paced_update(update, (Afi::Ipv4, Safi::Unicast), extended_messages)
    }

    /// Deliver a family-specific envelope through the same admission cursor.
    /// Negotiation and snapshot capture remain outside the timed interval.
    ///
    /// # Panics
    ///
    /// If negotiation is missing, the session tears down, or no frame is emitted.
    pub fn send_paced_update(
        &mut self,
        mut update: OutboundRouteUpdate,
        family: (Afi, Safi),
        extended_messages: bool,
    ) -> std::time::Duration {
        let negotiated = Arc::make_mut(self.session.negotiated.as_mut().unwrap());
        negotiated.peer_extended_message = extended_messages;
        if !negotiated.negotiated_families.contains(&family) {
            negotiated.negotiated_families.push(family);
        }
        update.exact_export_snapshot = Some(self.session.publish_export_profile());
        let before = self.session.writer_bulk_admitted;
        let elapsed = self.deliver(update);
        assert!(
            self.session.writer_bulk_admitted > before,
            "empty benchmark delivery"
        );
        elapsed
    }

    /// Negotiate Add-Path send for `family`, so its NLRI carry path IDs.
    ///
    /// # Panics
    ///
    /// If the fixed benchmark session is missing negotiation.
    pub fn negotiate_add_path_send(&mut self, family: (Afi, Safi)) {
        Arc::make_mut(self.session.negotiated.as_mut().unwrap())
            .add_path_families
            .insert(family, rustbgpd_wire::AddPathMode::Send);
    }

    fn complete(&mut self) {
        while self.bulk_rx.try_recv().is_ok() {}
        self.completed
            .send_replace(self.session.writer_bulk_admitted);
    }
}

impl OutboundEncodeBench {
    /// Deliver one envelope through the session's real outbound cursor
    /// (shared-encode election included) and return the time spent in the
    /// session alone; the writer queue is drained between admission steps,
    /// outside the returned duration.
    fn deliver(&mut self, update: OutboundRouteUpdate) -> std::time::Duration {
        let start = std::time::Instant::now();
        {
            // This producer future only suspends to yield between encoded
            // slices; writer admission never awaits capacity or I/O. Poll it
            // directly so this synchronous microbench measures session work
            // without executor scheduling or writer-drain work.
            let mut delivery = std::pin::pin!(self.session.handle_outbound_route_update(update));
            let mut cx = Context::from_waker(Waker::noop());
            while delivery.as_mut().poll(&mut cx).is_pending() {}
        }
        let mut elapsed = start.elapsed();
        while self.session.pending_outbound.is_some() {
            self.complete();
            let start = std::time::Instant::now();
            self.session.advance_pending_outbound();
            elapsed += start.elapsed();
        }
        assert!(
            self.session.writer_bulk_tx.is_some(),
            "bench writer queue saturated"
        );
        self.complete();
        elapsed
    }
}

/// Identical update-group members receiving one grouped distribution pass:
/// the same announce inventory behind one shared-encode cell, plus the
/// same unicast withdrawals.
pub struct OutboundGroupBench {
    members: Vec<OutboundEncodeBench>,
}

impl OutboundGroupBench {
    /// Build `members` sessions, each with a `queue`-deep writer queue.
    #[must_use]
    pub fn new(members: usize, queue: usize) -> Self {
        Self {
            members: (0..members)
                .map(|_| OutboundEncodeBench::new(queue))
                .collect(),
        }
    }

    /// Deliver one pass to every member and return the summed session time.
    ///
    /// # Panics
    ///
    /// If a member's writer queue saturated and the session tore down.
    pub fn send(
        &mut self,
        announce: &Arc<Vec<Route>>,
        withdraw: &[(Prefix, u32)],
    ) -> std::time::Duration {
        let shared = Arc::new(SharedGroupEncode::default());
        self.members
            .iter_mut()
            .map(|member| {
                let update = OutboundRouteUpdate {
                    exact_export_snapshot: Some(member.session.publish_export_profile()),
                    announce: Arc::clone(announce),
                    next_hop_override: vec![None; announce.len()].into(),
                    withdraw: withdraw.to_vec(),
                    shared_group_encode: Some(Arc::clone(&shared)),
                    ..OutboundRouteUpdate::default()
                };
                member.deliver(update)
            })
            .sum()
    }
}
