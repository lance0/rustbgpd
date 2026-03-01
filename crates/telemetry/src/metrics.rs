use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

/// Prometheus metrics for the BGP daemon.
///
/// All metrics are registered against an explicit [`Registry`], not the
/// global default. This keeps tests isolated and gives the caller full
/// control over metric lifetime and exposition.
///
/// Label values are plain strings — this crate has no dependency on
/// `rustbgpd-fsm` or `rustbgpd-wire`.  Callers pass `state.as_str()`,
/// `"keepalive"`, etc.
#[derive(Debug, Clone)]
pub struct BgpMetrics {
    registry: Registry,

    // ── Session ────────────────────────────────────────────────────
    state_transitions: IntCounterVec,
    session_flaps: IntCounterVec,
    session_established: IntCounterVec,

    // ── Notifications ──────────────────────────────────────────────
    notifications_sent: IntCounterVec,
    notifications_received: IntCounterVec,

    // ── Messages ───────────────────────────────────────────────────
    messages_sent: IntCounterVec,
    messages_received: IntCounterVec,

    // ── RIB ──────────────────────────────────────────────────────
    rib_prefixes: IntGaugeVec,
    rib_adj_out_prefixes: IntGaugeVec,
    rib_loc_prefixes: IntGaugeVec,

    // ── Policy ──────────────────────────────────────────────────
    max_prefix_exceeded: IntCounterVec,

    // ── RIB drops ───────────────────────────────────────────────
    outbound_route_drops: IntCounterVec,

    // ── Graceful Restart ──────────────────────────────────────
    gr_active_peers: IntGaugeVec,
    gr_stale_routes: IntGaugeVec,
    gr_timer_expired: IntCounterVec,
}

impl BgpMetrics {
    /// Create a new metrics instance with a fresh [`Registry`].
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails (programming error, not runtime).
    #[must_use]
    pub fn new() -> Self {
        Self::with_registry(Registry::new())
    }

    /// Create a new metrics instance registered against the given
    /// [`Registry`].
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails.
    #[must_use]
    #[expect(clippy::too_many_lines)]
    pub fn with_registry(registry: Registry) -> Self {
        let state_transitions = IntCounterVec::new(
            Opts::new(
                "bgp_session_state_transitions_total",
                "Total BGP session state transitions",
            ),
            &["peer", "from", "to"],
        )
        .expect("valid metric definition");

        let session_flaps = IntCounterVec::new(
            Opts::new(
                "bgp_session_flaps_total",
                "Total BGP session flaps (transitions out of Established)",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let session_established = IntCounterVec::new(
            Opts::new(
                "bgp_session_established_total",
                "Total times a BGP session reached Established",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let notifications_sent = IntCounterVec::new(
            Opts::new(
                "bgp_notifications_sent_total",
                "Total BGP NOTIFICATION messages sent",
            ),
            &["peer", "code", "subcode"],
        )
        .expect("valid metric definition");

        let notifications_received = IntCounterVec::new(
            Opts::new(
                "bgp_notifications_received_total",
                "Total BGP NOTIFICATION messages received",
            ),
            &["peer", "code", "subcode"],
        )
        .expect("valid metric definition");

        let messages_sent = IntCounterVec::new(
            Opts::new("bgp_messages_sent_total", "Total BGP messages sent by type"),
            &["peer", "type"],
        )
        .expect("valid metric definition");

        let messages_received = IntCounterVec::new(
            Opts::new(
                "bgp_messages_received_total",
                "Total BGP messages received by type",
            ),
            &["peer", "type"],
        )
        .expect("valid metric definition");

        let rib_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_prefixes",
                "Number of prefixes in Adj-RIB-In per peer and AFI/SAFI",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let rib_adj_out_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_adj_out_prefixes",
                "Number of prefixes in Adj-RIB-Out per peer and AFI/SAFI",
            ),
            &["peer", "afi_safi"],
        )
        .expect("valid metric definition");

        let rib_loc_prefixes = IntGaugeVec::new(
            Opts::new(
                "bgp_rib_loc_prefixes",
                "Number of prefixes in the Loc-RIB per AFI/SAFI",
            ),
            &["afi_safi"],
        )
        .expect("valid metric definition");

        let max_prefix_exceeded = IntCounterVec::new(
            Opts::new(
                "bgp_max_prefix_exceeded_total",
                "Number of times a peer exceeded its max-prefix limit",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let outbound_route_drops = IntCounterVec::new(
            Opts::new(
                "bgp_outbound_route_drops_total",
                "Number of outbound route updates dropped due to full channel",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let gr_active_peers = IntGaugeVec::new(
            Opts::new(
                "bgp_gr_active_peers",
                "Number of peers currently in graceful restart",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let gr_stale_routes = IntGaugeVec::new(
            Opts::new(
                "bgp_gr_stale_routes",
                "Number of stale routes during graceful restart",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        let gr_timer_expired = IntCounterVec::new(
            Opts::new(
                "bgp_gr_timer_expired_total",
                "Number of graceful restart timer expirations",
            ),
            &["peer"],
        )
        .expect("valid metric definition");

        registry
            .register(Box::new(state_transitions.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(session_flaps.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(session_established.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(notifications_sent.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(notifications_received.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(messages_sent.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(messages_received.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_adj_out_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(rib_loc_prefixes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(max_prefix_exceeded.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(outbound_route_drops.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_active_peers.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_stale_routes.clone()))
            .expect("metric not already registered");
        registry
            .register(Box::new(gr_timer_expired.clone()))
            .expect("metric not already registered");

        Self {
            registry,
            state_transitions,
            session_flaps,
            session_established,
            notifications_sent,
            notifications_received,
            messages_sent,
            messages_received,
            rib_prefixes,
            rib_adj_out_prefixes,
            rib_loc_prefixes,
            max_prefix_exceeded,
            outbound_route_drops,
            gr_active_peers,
            gr_stale_routes,
            gr_timer_expired,
        }
    }

    /// The underlying Prometheus registry, for gathering metrics.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // ── Recording methods ──────────────────────────────────────────

    /// Record a session state transition.
    ///
    /// Automatically increments the flap counter when leaving
    /// `"established"` and the established counter when entering it.
    pub fn record_state_transition(&self, peer: &str, from: &str, to: &str) {
        self.state_transitions
            .with_label_values(&[peer, from, to])
            .inc();

        if from == "established" {
            self.session_flaps.with_label_values(&[peer]).inc();
        }
        if to == "established" {
            self.session_established.with_label_values(&[peer]).inc();
        }
    }

    /// Record a NOTIFICATION sent to a peer.
    pub fn record_notification_sent(&self, peer: &str, code: &str, subcode: &str) {
        self.notifications_sent
            .with_label_values(&[peer, code, subcode])
            .inc();
    }

    /// Record a NOTIFICATION received from a peer.
    pub fn record_notification_received(&self, peer: &str, code: &str, subcode: &str) {
        self.notifications_received
            .with_label_values(&[peer, code, subcode])
            .inc();
    }

    /// Record a BGP message sent to a peer.
    pub fn record_message_sent(&self, peer: &str, msg_type: &str) {
        self.messages_sent
            .with_label_values(&[peer, msg_type])
            .inc();
    }

    /// Record a BGP message received from a peer.
    pub fn record_message_received(&self, peer: &str, msg_type: &str) {
        self.messages_received
            .with_label_values(&[peer, msg_type])
            .inc();
    }

    /// Set the number of prefixes in Adj-RIB-In for a peer/AFI-SAFI.
    pub fn set_rib_prefixes(&self, peer: &str, afi_safi: &str, count: i64) {
        self.rib_prefixes
            .with_label_values(&[peer, afi_safi])
            .set(count);
    }

    /// Set the number of prefixes in Adj-RIB-Out for a peer/AFI-SAFI.
    pub fn set_adj_rib_out_prefixes(&self, peer: &str, afi_safi: &str, count: i64) {
        self.rib_adj_out_prefixes
            .with_label_values(&[peer, afi_safi])
            .set(count);
    }

    /// Set the number of prefixes in the Loc-RIB for an AFI/SAFI.
    pub fn set_loc_rib_prefixes(&self, afi_safi: &str, count: i64) {
        self.rib_loc_prefixes
            .with_label_values(&[afi_safi])
            .set(count);
    }

    /// Record a max-prefix-exceeded event for a peer.
    pub fn record_max_prefix_exceeded(&self, peer: &str) {
        self.max_prefix_exceeded.with_label_values(&[peer]).inc();
    }

    /// Record an outbound route update drop for a peer.
    pub fn record_outbound_route_drop(&self, peer: &str) {
        self.outbound_route_drops.with_label_values(&[peer]).inc();
    }

    /// Set the GR active flag for a peer (1 = in GR, 0 = not).
    pub fn set_gr_active(&self, peer: &str, active: bool) {
        self.gr_active_peers
            .with_label_values(&[peer])
            .set(i64::from(active));
    }

    /// Set the number of stale routes for a GR peer.
    pub fn set_gr_stale_routes(&self, peer: &str, count: i64) {
        self.gr_stale_routes.with_label_values(&[peer]).set(count);
    }

    /// Record a GR timer expiration for a peer.
    pub fn record_gr_timer_expired(&self, peer: &str) {
        self.gr_timer_expired.with_label_values(&[peer]).inc();
    }
}

impl Default for BgpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Encoder;

    use super::*;

    /// Helper: gather all metrics from the registry as text.
    fn gather_text(m: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = m.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn new_creates_metrics_at_zero() {
        let m = BgpMetrics::new();
        let text = gather_text(&m);
        // Metrics should be registered but no label vectors initialized yet
        // (prometheus only emits metrics once a label combination is observed)
        assert!(!text.contains("bgp_session_state_transitions_total"));
    }

    #[test]
    fn state_transition_increments_counter() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.1", "idle", "connect");

        let val = m
            .state_transitions
            .with_label_values(&["10.0.0.1", "idle", "connect"])
            .get();
        assert_eq!(val, 2);
    }

    #[test]
    fn flap_counter_increments_when_leaving_established() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "established", "idle");

        let flaps = m.session_flaps.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(flaps, 1);
    }

    #[test]
    fn flap_counter_does_not_increment_for_other_transitions() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.1", "connect", "open_sent");

        let flaps = m.session_flaps.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(flaps, 0);
    }

    #[test]
    fn established_counter_increments_when_entering_established() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "open_confirm", "established");

        let est = m.session_established.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(est, 1);
    }

    #[test]
    fn notification_sent_counter() {
        let m = BgpMetrics::new();
        m.record_notification_sent("10.0.0.1", "2", "2");
        m.record_notification_sent("10.0.0.1", "2", "2");
        m.record_notification_sent("10.0.0.1", "6", "0");

        let open_err = m
            .notifications_sent
            .with_label_values(&["10.0.0.1", "2", "2"])
            .get();
        assert_eq!(open_err, 2);

        let cease = m
            .notifications_sent
            .with_label_values(&["10.0.0.1", "6", "0"])
            .get();
        assert_eq!(cease, 1);
    }

    #[test]
    fn notification_received_counter() {
        let m = BgpMetrics::new();
        m.record_notification_received("10.0.0.2", "4", "0");

        let val = m
            .notifications_received
            .with_label_values(&["10.0.0.2", "4", "0"])
            .get();
        assert_eq!(val, 1);
    }

    #[test]
    fn message_sent_counter() {
        let m = BgpMetrics::new();
        m.record_message_sent("10.0.0.1", "open");
        m.record_message_sent("10.0.0.1", "keepalive");
        m.record_message_sent("10.0.0.1", "keepalive");

        let open = m
            .messages_sent
            .with_label_values(&["10.0.0.1", "open"])
            .get();
        assert_eq!(open, 1);

        let ka = m
            .messages_sent
            .with_label_values(&["10.0.0.1", "keepalive"])
            .get();
        assert_eq!(ka, 2);
    }

    #[test]
    fn message_received_counter() {
        let m = BgpMetrics::new();
        m.record_message_received("10.0.0.2", "update");

        let val = m
            .messages_received
            .with_label_values(&["10.0.0.2", "update"])
            .get();
        assert_eq!(val, 1);
    }

    #[test]
    fn rib_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_rib_prefixes("10.0.0.1", "ipv4_unicast", 42);

        let val = m
            .rib_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 42);

        m.set_rib_prefixes("10.0.0.1", "ipv4_unicast", 0);
        let val = m
            .rib_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 0);
    }

    #[test]
    fn per_peer_isolation() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_state_transition("10.0.0.2", "idle", "connect");

        let p1 = m
            .state_transitions
            .with_label_values(&["10.0.0.1", "idle", "connect"])
            .get();
        let p2 = m
            .state_transitions
            .with_label_values(&["10.0.0.2", "idle", "connect"])
            .get();
        assert_eq!(p1, 1);
        assert_eq!(p2, 1);
    }

    #[test]
    fn gather_produces_valid_text() {
        let m = BgpMetrics::new();
        m.record_state_transition("10.0.0.1", "idle", "connect");
        m.record_message_sent("10.0.0.1", "open");

        let text = gather_text(&m);
        assert!(text.contains("bgp_session_state_transitions_total"));
        assert!(text.contains("bgp_messages_sent_total"));
        assert!(text.contains("10.0.0.1"));
    }

    #[test]
    fn adj_rib_out_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_adj_rib_out_prefixes("10.0.0.1", "ipv4_unicast", 5);

        let val = m
            .rib_adj_out_prefixes
            .with_label_values(&["10.0.0.1", "ipv4_unicast"])
            .get();
        assert_eq!(val, 5);
    }

    #[test]
    fn loc_rib_prefixes_gauge() {
        let m = BgpMetrics::new();
        m.set_loc_rib_prefixes("ipv4_unicast", 42);

        let val = m
            .rib_loc_prefixes
            .with_label_values(&["ipv4_unicast"])
            .get();
        assert_eq!(val, 42);
    }

    #[test]
    fn max_prefix_exceeded_counter() {
        let m = BgpMetrics::new();
        m.record_max_prefix_exceeded("10.0.0.1");
        m.record_max_prefix_exceeded("10.0.0.1");

        let val = m.max_prefix_exceeded.with_label_values(&["10.0.0.1"]).get();
        assert_eq!(val, 2);
    }

    #[test]
    fn with_registry_uses_provided_registry() {
        let reg = Registry::new();
        let m = BgpMetrics::with_registry(reg);
        m.record_state_transition("10.0.0.1", "idle", "connect");

        let families = m.registry().gather();
        assert!(!families.is_empty());
    }
}
