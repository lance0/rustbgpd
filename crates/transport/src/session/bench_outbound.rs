//! Benchmark seam: drive one real session's `send_route_update` against an
//! in-memory writer queue, so the outbound grouping and encode path can be
//! timed without TCP.

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::task::{Context, Waker};

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
        let (completed, writer_completed) = tokio::sync::watch::channel(0);
        let (priority_tx, priority_rx) = mpsc::unbounded_channel();
        session.writer_bulk_tx = Some(bulk_tx);
        session.writer_completed = Some(writer_completed);
        session.writer_priority_tx = Some(priority_tx);
        Self {
            session,
            bulk_rx,
            completed,
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
