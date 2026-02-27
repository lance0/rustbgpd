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

    // ── RIB (stubs — wired in M1) ─────────────────────────────────
    rib_prefixes: IntGaugeVec,
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
    ///
    /// Stub for M1 — exists at zero until RIB processing is implemented.
    pub fn set_rib_prefixes(&self, peer: &str, afi_safi: &str, count: i64) {
        self.rib_prefixes
            .with_label_values(&[peer, afi_safi])
            .set(count);
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
    fn with_registry_uses_provided_registry() {
        let reg = Registry::new();
        let m = BgpMetrics::with_registry(reg);
        m.record_state_transition("10.0.0.1", "idle", "connect");

        let families = m.registry().gather();
        assert!(!families.is_empty());
    }
}
