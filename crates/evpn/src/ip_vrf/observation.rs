//! Local IP-VRF route observation types (Gate 9 slice 6a).
//!
//! Carries the kernel-route-table dump from the dataplane crate up to
//! the daemon's L3 originator (slice 6b). Pure data; no I/O, no
//! netlink, no kernel-side state. The dataplane crate's
//! [`crate::dataplane`] surface owns the types in its
//! [`crate::DataplaneReport`] and the daemon mirrors them onto a
//! `tokio::sync::watch` channel for the originator.
//!
//! ADR-0054 §1 puts the L2 boundary at "Linux observes, daemon
//! decides"; this module is the L3 mirror. The dataplane crate
//! observes kernel routes inside each configured `IpVrf.table_id` and
//! the daemon decides whether to originate. The classifier filters
//! out routes installed by other routing daemons, non-forwardable
//! route types, and the loop-back hazard of routes whose output
//! device is the IP-VRF's own L3VXLAN.

use std::collections::HashMap;

use rustbgpd_wire::EvpnIpPrefixValue;

use crate::ip_vrf::IpVrfId;

/// Why the dataplane crate's classifier rejected a kernel route.
/// Labels are exposed as Prometheus counter values via [`Self::label`];
/// keep the variant names stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteFilterReason {
    /// `RTPROT_BGP`, `RTPROT_ZEBRA`, `RTPROT_OSPF`, `RTPROT_BIRD`,
    /// `RTPROT_RIP`, `RTPROT_ISIS`, `RTPROT_BABEL`, or any other
    /// `RTPROT_` value that suggests another active routing daemon
    /// installed the route. Re-originating would create an
    /// origination loop on the host.
    InstalledByRoutingDaemon,
    /// Output device matches the IP-VRF's `l3vxlan_device`. Almost
    /// certainly a route slice 6c installed; emitting it as a local
    /// Type 5 would echo it back to its origin.
    OutputDeviceIsL3Vxlan,
    /// `RTN_LOCAL`, `RTN_BROADCAST`, `RTN_MULTICAST`,
    /// `RTN_UNREACHABLE`, `RTN_PROHIBIT`, `RTN_BLACKHOLE`,
    /// `RTN_THROW`. Only `RTN_UNICAST` is a Type 5 candidate.
    NonForwardableType,
    /// Link-local or multicast destination (`169.254.0.0/16`,
    /// `fe80::/10`, `224.0.0.0/4`, `ff00::/8`).
    LinkLocalOrMulticast,
    /// The route's destination address family disagreed with the
    /// header's `address_family`, the destination attribute was
    /// missing on a non-default route, or the prefix length was out
    /// of range. Surfaced for kernel-vs-parser drift observability.
    Malformed,
}

impl RouteFilterReason {
    /// Stable Prometheus-label form. Matches the
    /// `evpn_ip_vrf_observed_routes_filtered_total{reason=…}` label
    /// values surfaced by the daemon.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::InstalledByRoutingDaemon => "installed_by_routing_daemon",
            Self::OutputDeviceIsL3Vxlan => "output_device_is_l3vxlan",
            Self::NonForwardableType => "non_forwardable_type",
            Self::LinkLocalOrMulticast => "link_local_or_multicast",
            Self::Malformed => "malformed",
        }
    }
}

/// How a local IP-VRF route was learned, from the kernel's
/// perspective. Preserved on the observation so future policy can
/// distinguish (e.g., never originate `Connected` interface routes).
/// All three variants are currently eligible for Type 5 origination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// `RTPROT_KERNEL` — kernel-installed connected routes (typically
    /// from `ip addr add` on an interface enslaved to the VRF).
    Connected,
    /// `RTPROT_STATIC` — operator-supplied via
    /// `ip route add ... proto static`.
    Static,
    /// `RTPROT_BOOT` — manual `ip route add` without an explicit
    /// proto. Treated equivalently to `Static` for origination; the
    /// variant is preserved for observability.
    Manual,
}

/// One observable local route in an IP-VRF route table the daemon
/// might originate as Type 5. Emitted by the dataplane crate's route
/// dump and consumed by the daemon's L3 originator (slice 6b).
///
/// `vrf_id` is duplicated when the observation rides on a
/// `HashMap<IpVrfId, Vec<LocalIpRouteObservation>>` keyed by the
/// same id — that's deliberate, so a flat per-route log line carries
/// its own VRF context without the consumer having to thread it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalIpRouteObservation {
    /// IP-VRF this observation belongs to.
    pub vrf_id: IpVrfId,
    /// Prefix the kernel reports.
    pub prefix: EvpnIpPrefixValue,
    /// Where the kernel learned this route.
    pub source: RouteSource,
}

/// Per-pass IP-VRF route-table dump produced by the dataplane crate.
/// Carried on [`crate::DataplaneReport::ip_vrf_routes`] so the daemon
/// can fan it out to the L3 originator (slice 6b) and to Prometheus
/// counters without re-walking netlink.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpVrfRouteDump {
    /// Observations per IP-VRF. `Vec` is empty when the VRF has no
    /// eligible routes this pass; every configured VRF appears as a
    /// key so the daemon can emit a zero-valued gauge.
    pub observations: HashMap<IpVrfId, Vec<LocalIpRouteObservation>>,
    /// Per-`(IpVrfId, RouteFilterReason)` count of routes filtered
    /// this pass. The daemon increments `…_filtered_total` counters
    /// by these deltas.
    pub filter_counts: HashMap<(IpVrfId, RouteFilterReason), u64>,
}
