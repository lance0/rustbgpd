use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, AspaValidationContext, EvpnRoute, EvpnRouteKey, ExtendedCommunity,
    FlowSpecRule, LargeCommunity, Origin, PathAttribute, Prefix, RpkiValidation,
    bgpls::{BgpLsNlri, BgpLsNlriKey},
};

/// Interface scope required to resolve an IPv6 link-local next-hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHopScope {
    /// Configured interface name, kept for operator-facing status and later FIB
    /// projection.
    pub interface: Arc<str>,
    /// Linux interface index for the scope.
    pub ifindex: u32,
}

/// How a route was learned, used for best-path selection and iBGP split-horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOrigin {
    /// Learned from an eBGP peer (remote ASN != local ASN).
    Ebgp,
    /// Learned from an iBGP peer (remote ASN == local ASN).
    Ibgp,
    /// Locally originated (gRPC injection).
    Local,
}

/// BGP-LS route family carried by the ADR-0077 receive/API slice.
///
/// This is deliberately independent from wire-level `Afi`/`Safi` enums while
/// the RIB keeps BGP-LS as its own typed family instead of reusing unicast
/// prefix identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpLsFamily {
    /// AFI 16388 / SAFI 71 — base BGP-LS.
    LinkState,
    /// AFI 16388 / SAFI 72 — BGP-LS VPN with an 8-octet Route Distinguisher.
    LinkStateVpn,
}

impl BgpLsFamily {
    /// Whether this family requires the NLRI to carry an 8-octet Route Distinguisher.
    #[must_use]
    pub fn requires_route_distinguisher(self) -> bool {
        matches!(self, Self::LinkStateVpn)
    }
}

/// Opaque BGP-LS route identity for the RIB.
///
/// The key preserves the complete NLRI identity bytes from the wire codec, so
/// unknown NLRI types and descriptor TLVs remain distinguishable without display
/// parsing. `path_id` is reserved for a future Add-Path-enabled BGP-LS slice and
/// is always zero until negotiation grows that capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgpLsRouteKey {
    /// Base BGP-LS or BGP-LS VPN.
    pub family: BgpLsFamily,
    /// Opaque RFC 9552 NLRI identity.
    pub nlri: BgpLsNlriKey,
    /// Add-Path path identifier. Zero means no Add-Path.
    pub path_id: u32,
}

/// A single route stored in the Adj-RIB-In.
#[derive(Debug, Clone)]
pub struct Route {
    /// The destination prefix.
    pub prefix: Prefix,
    /// The next-hop address (IPv4 or IPv6 global).
    pub next_hop: IpAddr,
    /// IPv6 link-local next-hop carried alongside the global next-hop
    /// per RFC 4760 §3 / RFC 2545 §3. Populated when the received
    /// `MP_REACH_NLRI` had a 32-byte next-hop. Re-encoded by the MRT
    /// exporter and the BGP UPDATE encoder when present.
    pub link_local_next_hop: Option<Ipv6Addr>,
    /// Interface scope for an IPv6 link-local primary next-hop. Boxed so the
    /// common `None` case keeps clone-heavy `Route` values small.
    pub next_hop_scope: Option<Box<NextHopScope>>,
    /// The peer that advertised this route.
    pub peer: IpAddr,
    /// BGP path attributes (ORIGIN, `AS_PATH`, communities, etc.).
    ///
    /// Wrapped in `Arc` for cheap cloning when routes are copied between
    /// Adj-RIB-In, Loc-RIB, and Adj-RIB-Out. Use `Arc::make_mut()` for
    /// the rare cases that need mutation (LLGR community injection).
    pub attributes: Arc<Vec<PathAttribute>>,
    /// When this route was received (monotonic clock).
    pub received_at: Instant,
    /// How this route was learned (eBGP, iBGP, or locally originated).
    pub origin_type: RouteOrigin,
    /// BGP router-id of the peer that sent this route (for `ORIGINATOR_ID`).
    pub peer_router_id: Ipv4Addr,
    /// Whether this route is stale due to a peer graceful restart.
    pub is_stale: bool,
    /// Whether this route is in long-lived graceful restart stale phase (RFC 9494).
    pub is_llgr_stale: bool,
    /// Add-Path path identifier (RFC 7911). 0 = no Add-Path / default path.
    pub path_id: u32,
    /// RPKI origin validation state (RFC 6811). Default: `NotFound`.
    pub validation_state: RpkiValidation,
    /// ASPA path verification state. Default: `Unknown`.
    pub aspa_state: AspaValidation,
    /// Relationship context used to recompute `aspa_state` on ASPA cache
    /// updates. Empty for locally originated or non-BGP synthetic routes.
    pub aspa_context: AspaValidationContext,
}

/// One equal-cost next-hop in a multipath/ECMP install candidate.
///
/// Carries the global next-hop plus the IPv6 link-local next-hop and the
/// provenance (advertising peer + Add-Path id) rather than a bare `IpAddr`,
/// so IPv6 link-local forwarding works today and recursive next-hop
/// resolution can be added later without reshaping the RIB→FIB contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibInstallNextHop {
    /// Global next-hop address (IPv4 or IPv6).
    pub next_hop: IpAddr,
    /// IPv6 link-local next-hop carried alongside the global one, if any.
    pub link_local_next_hop: Option<Ipv6Addr>,
    /// Interface scope for an IPv6 link-local primary next-hop, if any.
    pub next_hop_scope: Option<NextHopScope>,
    /// The peer that advertised the path this next-hop came from.
    pub peer: IpAddr,
    /// Add-Path path id of the source path (0 = no Add-Path).
    pub path_id: u32,
    /// ADR-0068 multipath weight, `1..=256` (the Linux kernel weight, encoded as
    /// `rtnh_hops = weight - 1`). `1` for every next-hop means equal-cost — the
    /// ADR-0066 default. When `link_bandwidth_weighted` is on and the whole
    /// equal-cost group carries a Link Bandwidth Extended Community, weights are
    /// normalized over the group in proportion to bandwidth.
    pub weight: u16,
}

/// A prefix's FIB install candidate: the chosen best route plus the
/// equal-cost next-hop set to program (length 1 = single-path, today's
/// behavior). **Ordering contract** (FIB consumers may rely on it): `next_hops[0]`
/// is always the best route's next-hop; the remaining entries are equal-cost
/// siblings (see `best_path::multipath_equal`) ordered by
/// `(next_hop, peer, path_id)`. Deduped by next-hop and bounded by the per-table
/// `maximum_paths`.
/// (No `PartialEq`/`Eq`: `Route` carries an `Instant` and is not `Eq`;
/// compare the public fields in tests.)
#[derive(Debug, Clone)]
pub struct FibInstallCandidate {
    /// The selected best route (drives metadata: prefix, origin, etc.).
    pub best: Route,
    /// Equal-cost next-hops to install as ECMP, canonically ordered.
    pub next_hops: Vec<FibInstallNextHop>,
}

impl Route {
    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// Link Bandwidth in **bytes per second** (draft-ietf-idr-link-bandwidth),
    /// if the route carries a Link Bandwidth Extended Community. Used to weight
    /// next hops for unequal-cost multipath. Returns the first match's bandwidth;
    /// the advertising AS is discarded since weighting only needs the magnitude.
    #[must_use]
    pub fn link_bandwidth(&self) -> Option<f32> {
        self.extended_communities()
            .iter()
            .find_map(|c| c.as_link_bandwidth().map(|(_asn, bw)| bw))
    }

    /// Extract the ORIGIN attribute value, defaulting to Incomplete.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Origin(o) => Some(*o),
                _ => None,
            })
            .unwrap_or(Origin::Incomplete)
    }

    /// Extract the `AS_PATH` attribute, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
    }

    /// Extract the `LOCAL_PREF` attribute value, defaulting to 100.
    #[must_use]
    pub fn local_pref(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LocalPref(lp) => Some(*lp),
                _ => None,
            })
            .unwrap_or(100)
    }

    /// Extract the explicit `LOCAL_PREF` attribute value, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        })
    }

    /// Extract the MED attribute value, defaulting to 0.
    #[must_use]
    pub fn med(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Med(m) => Some(*m),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Extract the explicit MED attribute value, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::Med(m) => Some(*m),
            _ => None,
        })
    }

    /// Extract COMMUNITIES (RFC 1997) values, returning empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES (RFC 4360) values, returning empty slice if absent.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES (RFC 8092) values, returning empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract `ORIGINATOR_ID` (RFC 4456) if present.
    #[must_use]
    pub fn originator_id(&self) -> Option<Ipv4Addr> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::OriginatorId(id) => Some(*id),
            _ => None,
        })
    }

    /// Extract `CLUSTER_LIST` (RFC 4456), returning empty slice if absent.
    #[must_use]
    pub fn cluster_list(&self) -> &[Ipv4Addr] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ClusterList(ids) => Some(ids.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

/// A `FlowSpec` route stored in the RIB (RFC 8955).
///
/// Parallel to [`Route`] but keyed by [`FlowSpecRule`] instead of [`Prefix`].
/// `FlowSpec` rules are variable-length TLV structures, so they cannot be `Copy`
/// and use separate storage in the RIB.
#[derive(Debug, Clone)]
pub struct FlowSpecRoute {
    /// The `FlowSpec` match rule (RFC 8955).
    pub rule: FlowSpecRule,
    /// Address family (IPv4 or IPv6).
    pub afi: Afi,
    /// The peer that advertised this route.
    pub peer: IpAddr,
    /// BGP path attributes.
    pub attributes: Vec<PathAttribute>,
    /// When this route was received (monotonic clock).
    pub received_at: Instant,
    /// How this route was learned (eBGP, iBGP, or local).
    pub origin_type: RouteOrigin,
    /// BGP router-id of the advertising peer.
    pub peer_router_id: Ipv4Addr,
    /// Whether this route is stale due to graceful restart.
    pub is_stale: bool,
    /// Whether this route is in LLGR stale phase (RFC 9494).
    pub is_llgr_stale: bool,
    /// Add-Path path identifier (RFC 7911). 0 = no Add-Path.
    pub path_id: u32,
}

/// A single BGP-LS route stored by the ADR-0077 receive/API slice.
///
/// The route remains opaque: rustbgpd stores and exposes RFC 9552 identity and
/// TLV bytes without building a local LSDB or computing paths from BGP-LS data.
#[derive(Debug, Clone)]
pub struct BgpLsRibRoute {
    /// Base BGP-LS or BGP-LS VPN.
    pub family: BgpLsFamily,
    /// Full opaque NLRI, preserving unknown NLRI types and TLVs.
    pub nlri: BgpLsNlri,
    /// BGP-LS next-hop from `MP_REACH_NLRI`.
    pub next_hop: IpAddr,
    /// The peer that advertised this route.
    pub peer: IpAddr,
    /// BGP path attributes.
    pub attributes: Arc<Vec<PathAttribute>>,
    /// When this route was received (monotonic clock).
    pub received_at: Instant,
    /// How this route was learned (eBGP, iBGP, or local).
    pub origin_type: RouteOrigin,
    /// BGP router-id of the advertising peer.
    pub peer_router_id: Ipv4Addr,
    /// Whether this route is stale due to graceful restart.
    pub is_stale: bool,
    /// Whether this route is in LLGR stale phase (RFC 9494).
    pub is_llgr_stale: bool,
    /// Add-Path path identifier. Zero means no Add-Path.
    pub path_id: u32,
}

impl BgpLsRibRoute {
    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// Identity key suitable for BGP-LS Adj-RIB-In, Loc-RIB, and Adj-RIB-Out maps.
    #[must_use]
    pub fn key(&self) -> BgpLsRouteKey {
        debug_assert_eq!(
            self.family.requires_route_distinguisher(),
            self.nlri.route_distinguisher.is_some(),
            "BGP-LS family and NLRI Route Distinguisher disagree"
        );
        BgpLsRouteKey {
            family: self.family,
            nlri: self.nlri.key(),
            path_id: self.path_id,
        }
    }
}

impl FlowSpecRoute {
    /// Extract the ORIGIN attribute value, defaulting to `Incomplete`.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Origin(o) => Some(*o),
                _ => None,
            })
            .unwrap_or(Origin::Incomplete)
    }

    /// Extract the `AS_PATH` attribute, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
    }

    /// Extract the `LOCAL_PREF` attribute value, defaulting to 100.
    #[must_use]
    pub fn local_pref(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LocalPref(lp) => Some(*lp),
                _ => None,
            })
            .unwrap_or(100)
    }

    /// Extract the explicit `LOCAL_PREF` attribute value, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        })
    }

    /// Extract the MED attribute value, defaulting to 0.
    #[must_use]
    pub fn med(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Med(m) => Some(*m),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Extract the explicit MED attribute value, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::Med(m) => Some(*m),
            _ => None,
        })
    }

    /// Extract COMMUNITIES (RFC 1997) values, returning empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES (RFC 4360) values, returning empty slice if absent.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES (RFC 8092) values, returning empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract `ORIGINATOR_ID` (RFC 4456) if present.
    #[must_use]
    pub fn originator_id(&self) -> Option<Ipv4Addr> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::OriginatorId(id) => Some(*id),
            _ => None,
        })
    }

    /// Extract `CLUSTER_LIST` (RFC 4456), returning empty slice if absent.
    #[must_use]
    pub fn cluster_list(&self) -> &[Ipv4Addr] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ClusterList(ids) => Some(ids.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }
}

/// A single EVPN route stored in the Adj-RIB-In (RFC 7432).
///
/// Parallel to [`Route`] and [`FlowSpecRoute`] but keyed by [`EvpnRouteKey`]
/// instead of a prefix. EVPN routes are typed — each variant carries the
/// full wire payload so the RR can round-trip it to other peers.
#[derive(Debug, Clone)]
pub struct EvpnRibRoute {
    /// The EVPN route (Type 1-5 with full payload). The single source of
    /// truth for route identity — call [`Self::key`] to derive the
    /// `EvpnRouteKey`. There is no cached key field: a stored copy
    /// would create a sync surface that future Route Types (e.g.,
    /// RFC 9251 §6/7/8) would have to keep aligned for no benefit
    /// since `EvpnRoute::key()` is O(1) and allocation-free.
    pub route: EvpnRoute,
    /// The VTEP loopback IP (next-hop), carried separately for policy / display.
    pub next_hop: IpAddr,
    /// IPv6 link-local next-hop carried alongside the global next-hop
    /// per RFC 4760 §3 / RFC 2545 §3. Set when the received
    /// `MP_REACH_NLRI` had a 32-byte next-hop; preserved through the
    /// RR forwarding path so re-advertisement and MRT export can
    /// emit the same wire form.
    pub link_local_next_hop: Option<Ipv6Addr>,
    /// The peer that advertised this route.
    pub peer: IpAddr,
    /// BGP path attributes (ORIGIN, `AS_PATH`, extended communities, etc.).
    pub attributes: Arc<Vec<PathAttribute>>,
    /// When this route was received (monotonic clock).
    pub received_at: Instant,
    /// How this route was learned (eBGP, iBGP, or local).
    pub origin_type: RouteOrigin,
    /// BGP router-id of the advertising peer (for `ORIGINATOR_ID`).
    pub peer_router_id: Ipv4Addr,
    /// Whether this route is stale due to graceful restart.
    pub is_stale: bool,
    /// Whether this route is in LLGR stale phase (RFC 9494).
    pub is_llgr_stale: bool,
}

impl EvpnRibRoute {
    /// Identity key derived from the underlying `EvpnRoute`. Suitable as
    /// a `HashMap` key in any of the three EVPN RIB tables.
    /// `EvpnRouteKey` is `Copy`, so this is essentially free.
    #[must_use]
    pub fn key(&self) -> EvpnRouteKey {
        self.route.key()
    }

    /// Extract the ORIGIN attribute value, defaulting to `Incomplete`.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Origin(o) => Some(*o),
                _ => None,
            })
            .unwrap_or(Origin::Incomplete)
    }

    /// Extract the `AS_PATH` attribute, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
    }

    /// Extract the `LOCAL_PREF` attribute value, defaulting to 100.
    #[must_use]
    pub fn local_pref(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LocalPref(lp) => Some(*lp),
                _ => None,
            })
            .unwrap_or(100)
    }

    /// Extract the explicit `LOCAL_PREF` attribute value, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        })
    }

    /// Extract the MED attribute value, defaulting to 0.
    #[must_use]
    pub fn med(&self) -> u32 {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Med(m) => Some(*m),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Extract the explicit MED attribute value, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::Med(m) => Some(*m),
            _ => None,
        })
    }

    /// Extract COMMUNITIES (RFC 1997) values, returning empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES (RFC 4360) values.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES (RFC 8092) values.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract `ORIGINATOR_ID` (RFC 4456) if present.
    #[must_use]
    pub fn originator_id(&self) -> Option<Ipv4Addr> {
        self.attributes.iter().find_map(|a| match a {
            PathAttribute::OriginatorId(id) => Some(*id),
            _ => None,
        })
    }

    /// Extract `CLUSTER_LIST` (RFC 4456), returning empty slice if absent.
    #[must_use]
    pub fn cluster_list(&self) -> &[Ipv4Addr] {
        self.attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ClusterList(ids) => Some(ids.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// EVPN wire route type (1..=5).
    #[must_use]
    pub fn route_type(&self) -> u8 {
        self.route.route_type()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{
        PathAttribute,
        bgpls::{BgpLsNlri, decode_bgpls_nlri, decode_bgpls_vpn_nlri},
    };

    use super::*;

    fn bgpls_route(family: BgpLsFamily, nlri: BgpLsNlri) -> BgpLsRibRoute {
        BgpLsRibRoute {
            family,
            nlri,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    fn base_bgpls_nlri() -> BgpLsNlri {
        decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xbb, 0xcc])
            .expect("fixture BGP-LS NLRI decodes")
            .pop()
            .expect("fixture contains one NLRI")
    }

    fn vpn_bgpls_nlri() -> BgpLsNlri {
        decode_bgpls_vpn_nlri(&[
            0xfd, 0xe8, 0, 11, // 8-byte RD + 3-byte opaque payload
            0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc,
        ])
        .expect("fixture BGP-LS VPN NLRI decodes")
        .pop()
        .expect("fixture contains one NLRI")
    }

    #[test]
    #[should_panic(expected = "BGP-LS family and NLRI Route Distinguisher disagree")]
    fn bgpls_key_rejects_base_family_with_vpn_nlri_in_debug_builds() {
        let _ = bgpls_route(BgpLsFamily::LinkState, vpn_bgpls_nlri()).key();
    }

    #[test]
    #[should_panic(expected = "BGP-LS family and NLRI Route Distinguisher disagree")]
    fn bgpls_key_rejects_vpn_family_without_rd_in_debug_builds() {
        let _ = bgpls_route(BgpLsFamily::LinkStateVpn, base_bgpls_nlri()).key();
    }
}
