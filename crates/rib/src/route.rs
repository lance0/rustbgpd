use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, EvpnRoute, EvpnRouteKey, ExtendedCommunity, FlowSpecRule,
    LargeCommunity, Origin, PathAttribute, Prefix, RpkiValidation,
};

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
    /// ASPA upstream path verification state. Default: `Unknown`.
    pub aspa_state: AspaValidation,
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
    /// The peer that advertised the path this next-hop came from.
    pub peer: IpAddr,
    /// Add-Path path id of the source path (0 = no Add-Path).
    pub path_id: u32,
}

/// A prefix's FIB install candidate: the chosen best route plus the
/// equal-cost next-hop set to program (length 1 = single-path, today's
/// behavior). `next_hops[0]` is always the best route's next-hop; the
/// remainder are equal-cost siblings (see `best_path::multipath_equal`),
/// deduped by next-hop and bounded by the per-table `maximum_paths`.
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
