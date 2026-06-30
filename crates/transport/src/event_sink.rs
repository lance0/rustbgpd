//! Sink boundary for handing transport-layer policy decisions to an
//! out-of-crate consumer (ADR-0072 follow-up sprint, PR2).
//!
//! `crates/transport` cannot depend on `crates/api` (would cycle
//! through the proto types and the event-history wiring), and it
//! also cannot depend on `rustbgpd-event-history` directly because
//! the encode step needs `crates/api`'s proto conversion helpers.
//! Mirroring the [`rustbgpd_rib::RibEventSink`] pattern: define a
//! tiny trait here, let the binary plug in an EHM-backed
//! implementation that owns both the EHM handle and the proto
//! encoders.
//!
//! Today the only event surfaced through this sink is
//! [`OtcRouteBlockedEvent`] — emitted at the four OTC ingress/egress
//! decision sites that already increment the
//! `bgp_otc_routes_blocked_total` counter (ADR-0071). Additional
//! transport-policy events can be added here as new trait methods
//! with `default { /* no-op */ }` bodies so existing sinks remain
//! source-compatible.

use std::net::IpAddr;

use rustbgpd_telemetry::reason_labels::OtcBlockReason;
use rustbgpd_wire::BgpRole;

/// Direction in which an OTC route-leak rule fired.
///
/// Maps to the operator-facing `direction` field on the proto event.
/// Ingress decisions cover the three I1 / I2 / malformed-length
/// cases at `crates/transport/src/session/inbound.rs`; egress
/// decisions cover the single suppression site at
/// `crates/transport/src/session/outbound.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtcDirection {
    /// Inbound UPDATE rejected because the OTC attribute made the
    /// route invalid for this local role.
    Ingress,
    /// Outbound route suppressed because it carries OTC and the
    /// session's local role is one of `Customer` / `Peer` /
    /// `RouteServerClient` — i.e. we'd be advertising the route
    /// up to a Provider / lateral Peer / Route Server, which RFC
    /// 9234 §5 prohibits for OTC-tagged routes.
    Egress,
}

impl OtcDirection {
    /// Operator-facing string used in event payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

/// Structured event payload emitted whenever an OTC route-leak rule
/// blocks one or more unicast routes (RFC 9234 §5).
///
/// The legacy `bgp_otc_routes_blocked_total{peer, reason}` counter
/// and the per-`NeighborState` `otc_routes_blocked` scalar are
/// unchanged — this is a parallel structured surface for incident
/// reconstruction, not a replacement.
///
/// `reason` is the typed canonical vocabulary shared with the
/// counter — see
/// [`rustbgpd_telemetry::reason_labels::OtcBlockReason`]. Sinks
/// render it with `as_str()` (a `&'static str`, no allocation).
#[derive(Debug, Clone)]
pub struct OtcRouteBlockedEvent {
    /// Address of the peer that triggered the decision.
    pub peer: IpAddr,
    /// Whether this was an inbound or outbound decision.
    pub direction: OtcDirection,
    /// Canonical reason shared with the
    /// `bgp_otc_routes_blocked_total{reason=…}` label vocabulary.
    pub reason: OtcBlockReason,
    /// Wire-format prefix strings (`"203.0.113.0/24"`). For ingress
    /// this is every announced unicast prefix in the rejected
    /// UPDATE — body NLRI plus any IPv4/IPv6 unicast `MP_REACH_NLRI`
    /// entry. For egress this is a single prefix (the loop already
    /// runs per-route).
    pub prefixes: Vec<String>,
    /// Local BGP role at the moment of the decision. `None` only
    /// when the session has no negotiated role (in which case OTC
    /// ingress action would have been `None` and this event would
    /// not have been emitted, so production paths always set this).
    pub local_role: Option<BgpRole>,
    /// Peer's advertised BGP role, if the Role capability was
    /// negotiated (RFC 9234 §4). `None` when the peer didn't
    /// advertise a role.
    pub remote_role: Option<BgpRole>,
    /// The OTC attribute value (ASN). `None` only when the
    /// attribute was malformed-length (codec couldn't decode an
    /// ASN), matching the `malformed_length` reason path.
    pub otc_value: Option<u32>,
    /// `AS_PATH` rendered via [`rustbgpd_wire::AsPath::to_aspath_string`]
    /// — preserves `AS_SET` / `AS_SEQUENCE` segments via `{…}`
    /// notation rather than collapsing to a lossy `repeated uint32`.
    /// Empty string when the UPDATE / route carried no `AS_PATH`
    /// attribute.
    pub as_path: String,
}

/// Object-safe sink that receives transport-policy events.
///
/// Implementations must be non-blocking. The binary-side EHM-backed
/// implementation uses `EventHistorySender::try_send` (drop on full
/// queue + metric + degraded flag). Implementations MUST NOT panic
/// in the publish hot path; a panic here would unwind through the
/// per-peer session task.
///
/// Method takes `&OtcRouteBlockedEvent` rather than an owned value
/// so the production session path can allocate the event once and
/// hand it off; sinks that need to retain state clone what they
/// need.
pub trait TransportEventSink: Send + Sync + 'static {
    /// Whether this sink retains structured OTC route-blocked events.
    ///
    /// The default is `true` for real sinks. The no-op sink overrides this so
    /// the session can skip building event-only strings while preserving the
    /// counters and warnings that remain authoritative without event history.
    fn wants_otc_route_blocked(&self) -> bool {
        true
    }

    /// Hand an [`OtcRouteBlockedEvent`] to the sink. Called from
    /// `PeerSession` **after** the existing counter +
    /// per-`NeighborState` scalar have been updated, so the legacy
    /// surfaces are guaranteed consistent regardless of whether the
    /// sink drops the event.
    fn publish_otc_route_blocked(&self, event: &OtcRouteBlockedEvent);
}

/// No-op sink used when `[event_history]` is disabled or EHM failed
/// to start with `required = false`. Keeps `PeerSession`'s sink
/// slot non-`Option<T>` so the publish hot path is one virtual call
/// regardless of EHM state — and the published-event allocation is
/// only paid on the OTC slow path, which is already a tracing
/// `warn!` site, so the extra indirection never shows up in a hot
/// loop.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTransportEventSink;

impl TransportEventSink for NoopTransportEventSink {
    fn wants_otc_route_blocked(&self) -> bool {
        false
    }

    fn publish_otc_route_blocked(&self, _event: &OtcRouteBlockedEvent) {}
}
