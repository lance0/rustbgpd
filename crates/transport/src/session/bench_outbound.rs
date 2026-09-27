//! Benchmark seam: drive one real session's `send_route_update` against an
//! in-memory writer queue, so the outbound grouping and encode path can be
//! timed without TCP.

use std::net::Ipv4Addr;
use std::sync::Arc;

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
    _priority_rx: mpsc::UnboundedReceiver<Bytes>,
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
        let (_command_tx, commands) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mut session = PeerSession::new_at_tcp_ao_generation(
            config,
            BgpMetrics::new(),
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
        negotiated.peer_asn = 65_002;
        negotiated.peer_router_id = Ipv4Addr::new(10, 0, 0, 2);
        negotiated.hold_time = 90;
        negotiated.keepalive_interval = 30;
        negotiated.four_octet_as = true;
        negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
        session.negotiated = Some(Arc::new(negotiated));
        let (bulk_tx, bulk_rx) = mpsc::channel(queue);
        let (priority_tx, priority_rx) = mpsc::unbounded_channel();
        session.writer_bulk_tx = Some(bulk_tx);
        session.writer_priority_tx = Some(priority_tx);
        Self {
            session,
            bulk_rx,
            _priority_rx: priority_rx,
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
    pub fn send(&mut self, announce: &Arc<[Route]>) -> std::time::Duration {
        let update = OutboundRouteUpdate {
            exact_export_snapshot: Some(self.session.publish_export_profile()),
            announce: Arc::clone(announce),
            next_hop_override: vec![None; announce.len()].into(),
            ..OutboundRouteUpdate::default()
        };
        let start = std::time::Instant::now();
        self.session.send_route_update(update);
        let elapsed = start.elapsed();
        assert!(
            self.session.writer_bulk_tx.is_some(),
            "bench writer queue saturated"
        );
        while self.bulk_rx.try_recv().is_ok() {}
        elapsed
    }
}

impl OutboundEncodeBench {
    /// Deliver one envelope through the session's real outbound cursor
    /// (shared-encode election included) and return the time spent in the
    /// session alone; the writer queue is drained between admission steps,
    /// outside the returned duration.
    fn deliver(&mut self, update: OutboundRouteUpdate) -> std::time::Duration {
        let start = std::time::Instant::now();
        self.session.handle_outbound_route_update(update);
        let mut elapsed = start.elapsed();
        while self.session.pending_outbound.is_some() {
            while self.bulk_rx.try_recv().is_ok() {}
            let start = std::time::Instant::now();
            self.session.advance_pending_outbound();
            elapsed += start.elapsed();
        }
        assert!(
            self.session.writer_bulk_tx.is_some(),
            "bench writer queue saturated"
        );
        while self.bulk_rx.try_recv().is_ok() {}
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
        announce: &Arc<[Route]>,
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
