use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, AspaValidationContext, EvpnRoute, EvpnRouteKey, ExtendedCommunity,
    FlowSpecRule, LabeledNlri, LargeCommunity, Origin, PathAttribute, Prefix, RpkiValidation,
    RtcNlri, Safi, VpnAddressFamily, VpnNlri, VpnRouteKey,
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
    /// Convert a wire AFI/SAFI pair into the typed BGP-LS RIB family.
    #[must_use]
    pub fn from_afi_safi(afi: Afi, safi: Safi) -> Option<Self> {
        match (afi, safi) {
            (Afi::BgpLs, Safi::BgpLs) => Some(Self::LinkState),
            (Afi::BgpLs, Safi::BgpLsVpn) => Some(Self::LinkStateVpn),
            _ => None,
        }
    }

    /// Convert the typed BGP-LS RIB family back to its wire AFI/SAFI pair.
    #[must_use]
    pub fn to_afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::LinkState => (Afi::BgpLs, Safi::BgpLs),
            Self::LinkStateVpn => (Afi::BgpLs, Safi::BgpLsVpn),
        }
    }

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

    /// Extract the `AS_PATH`, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::AsPath(path) => Some(path),
            _ => None,
        })
    }

    /// Extract the explicit `LOCAL_PREF`, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract the explicit MED, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::Communities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::ExtendedCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

/// VPNv4/VPNv6 (RFC 4364 / RFC 4659) route identity for the RIB.
///
/// The wire [`VpnRouteKey`] carries the AFI-scoped Route Distinguisher plus IP
/// prefix (the family is implicit in the prefix). The MPLS label stack is route
/// *data*, not identity, so it is not part of the key. `path_id` is reserved for
/// a future Add-Path-enabled slice and is always zero until negotiation grows
/// that capability — kept as a RIB-layer wrapper so the wire route identity stays
/// a pure RD + prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VpnRibRouteKey {
    /// Wire route identity: Route Distinguisher + VPN IP prefix (V4/V6).
    pub nlri_key: VpnRouteKey,
    /// Add-Path path identifier. Zero means no Add-Path.
    pub path_id: u32,
}

impl VpnRibRouteKey {
    /// The wire AFI/SAFI pair for this key (`Ipv4`/`Ipv6` + `MplsVpn`),
    /// derived from the RD-scoped prefix family.
    #[must_use]
    pub fn afi_safi(&self) -> (Afi, Safi) {
        let afi = match self.nlri_key.prefix.family() {
            VpnAddressFamily::V4 => Afi::Ipv4,
            VpnAddressFamily::V6 => Afi::Ipv6,
        };
        (afi, Safi::MplsVpn)
    }
}

/// A single VPNv4/VPNv6 route stored by the ADR-0077 route-reflector slice.
///
/// rustbgpd reflects VPN routes as a route reflector / controller feed: it
/// preserves the Route Distinguisher, MPLS label stack, and next-hop unchanged
/// and never installs an MPLS FIB entry or imports into a VRF (ADR-0077 §6).
#[derive(Debug, Clone)]
pub struct VpnRibRoute {
    /// Full NLRI: RD + prefix + MPLS label stack (preserved verbatim).
    pub nlri: VpnNlri,
    /// VPN next-hop from `MP_REACH_NLRI` (Route-Distinguisher-stripped).
    pub next_hop: IpAddr,
    /// The peer that advertised this route.
    pub peer: IpAddr,
    /// BGP path attributes. Route Targets ride here as extended communities.
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

impl VpnRibRoute {
    /// The VPN address family (V4/V6), derived from the NLRI prefix.
    #[must_use]
    pub fn family(&self) -> VpnAddressFamily {
        self.nlri.prefix.family()
    }

    /// The wire AFI/SAFI pair for this route (`Ipv4`/`Ipv6` + `MplsVpn`).
    #[must_use]
    pub fn afi_safi(&self) -> (Afi, Safi) {
        let afi = match self.family() {
            VpnAddressFamily::V4 => Afi::Ipv4,
            VpnAddressFamily::V6 => Afi::Ipv6,
        };
        (afi, Safi::MplsVpn)
    }

    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// Identity key suitable for VPN Adj-RIB-In, Loc-RIB, and Adj-RIB-Out maps.
    #[must_use]
    pub fn key(&self) -> VpnRibRouteKey {
        VpnRibRouteKey {
            nlri_key: self.nlri.key(),
            path_id: self.path_id,
        }
    }

    /// The inner IP prefix as an ordinary [`Prefix`], for honest export-policy
    /// prefix matching (ADR-0077) — unlike BGP-LS, a VPN route has a real
    /// prefix.
    #[must_use]
    pub fn inner_prefix(&self) -> Prefix {
        match self.nlri.prefix {
            rustbgpd_wire::VpnPrefix::V4 { addr, len } => {
                Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(addr, len))
            }
            rustbgpd_wire::VpnPrefix::V6 { addr, len } => {
                Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(addr, len))
            }
        }
    }

    /// Extract the `AS_PATH`, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::AsPath(path) => Some(path),
            _ => None,
        })
    }

    /// Extract the explicit `LOCAL_PREF`, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract the explicit MED, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::Communities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES values, returning an empty slice if absent.
    ///
    /// Route Targets (RFC 4360) are the load-bearing members here; they are
    /// preserved verbatim through reflection.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::ExtendedCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

/// IPv4/IPv6 labeled-unicast (RFC 8277, SAFI 4) route identity for the RIB.
///
/// Route identity is the IP prefix plus Add-Path path-id; the MPLS label
/// stack is route *data*, not identity (RFC 8277 §2.3 implicit-replace is
/// per-prefix), matching the SAFI 128 VPN decision. The key deliberately
/// wraps the unicast [`Prefix`] in a labeled-specific struct so the labeled
/// table can never be confused with the unicast RIB maps (ADR-0077 §2).
/// `path_id` carries the RFC 7911 Add-Path path identifier (zero when
/// Add-Path is not in use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabeledRibRouteKey {
    /// The IP prefix (route identity within SAFI 4).
    pub prefix: Prefix,
    /// Add-Path path identifier. Zero means no Add-Path.
    pub path_id: u32,
}

impl LabeledRibRouteKey {
    /// The wire AFI/SAFI pair for this key (`Ipv4`/`Ipv6` +
    /// `LabeledUnicast`), derived from the prefix family.
    #[must_use]
    pub const fn afi_safi(&self) -> (Afi, Safi) {
        let afi = match self.prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        };
        (afi, Safi::LabeledUnicast)
    }
}

/// A single IPv4/IPv6 labeled-unicast route stored by the ADR-0077
/// route-reflector slice.
///
/// rustbgpd reflects labeled routes as a route reflector only: it preserves
/// the MPLS label stack and next-hop unchanged and never allocates,
/// rewrites, or programs labels (ADR-0077 §4/§6).
#[derive(Debug, Clone)]
pub struct LabeledRibRoute {
    /// Full NLRI: prefix + MPLS label stack (preserved verbatim).
    pub nlri: LabeledNlri,
    /// Global next-hop from `MP_REACH_NLRI`.
    pub next_hop: IpAddr,
    /// IPv6 link-local next-hop carried alongside the global one (RFC 8950 §4
    /// / RFC 2545 §3 two-address form), populated when the received labeled
    /// `MP_REACH_NLRI` had a 32-byte next-hop. Reflected verbatim so labeled
    /// IPv6 link-local forwarding survives reflection (LAN-190); `None` for
    /// IPv4 or single-address IPv6 next-hops.
    pub link_local_next_hop: Option<Ipv6Addr>,
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

impl LabeledRibRoute {
    /// The wire AFI/SAFI pair for this route (`Ipv4`/`Ipv6` +
    /// `LabeledUnicast`).
    #[must_use]
    pub const fn afi_safi(&self) -> (Afi, Safi) {
        let afi = match self.nlri.prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        };
        (afi, Safi::LabeledUnicast)
    }

    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// Identity key suitable for labeled Adj-RIB-In, Loc-RIB, and
    /// Adj-RIB-Out maps.
    #[must_use]
    pub const fn key(&self) -> LabeledRibRouteKey {
        LabeledRibRouteKey {
            prefix: self.nlri.key(),
            path_id: self.path_id,
        }
    }

    /// Extract COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::Communities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract the `AS_PATH`, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::AsPath(path) => Some(path),
            _ => None,
        })
    }

    /// Extract the explicit `LOCAL_PREF`, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract the explicit MED, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract EXTENDED COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::ExtendedCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

/// RT-Constrain (RFC 4684) route identity for the RIB.
///
/// The wire [`RtcNlri`] is the full route identity — a 0–96-bit prefix over
/// origin AS + Route Target. `path_id` is reserved for a future
/// Add-Path-enabled slice and is always zero until negotiation grows that
/// capability, mirroring [`VpnRibRouteKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RtcRibRouteKey {
    /// Wire route identity: the RT membership NLRI itself.
    pub nlri: RtcNlri,
    /// Add-Path path identifier. Zero means no Add-Path.
    pub path_id: u32,
}

impl RtcRibRouteKey {
    /// The wire AFI/SAFI pair for RT-Constrain. RFC 4684 defines the family
    /// only for AFI 1, so this is a constant.
    #[must_use]
    pub const fn afi_safi() -> (Afi, Safi) {
        (Afi::Ipv4, Safi::RtConstrain)
    }
}

/// A single RT-Constrain route stored by the RTC route-reflector slice.
///
/// RT membership NLRI reflect between clients like any other family
/// (RFC 4684 §3.2); the membership information additionally drives the
/// VPNv4/VPNv6 outbound filter in a later slice.
#[derive(Debug, Clone)]
pub struct RtcRibRoute {
    /// The RT membership NLRI (full route identity).
    pub nlri: RtcNlri,
    /// Next-hop from `MP_REACH_NLRI`.
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

impl RtcRibRoute {
    /// The wire AFI/SAFI pair for this route: always `(Ipv4, RtConstrain)`.
    #[must_use]
    pub const fn afi_safi(&self) -> (Afi, Safi) {
        RtcRibRouteKey::afi_safi()
    }

    /// Whether this route was learned via an eBGP session.
    #[must_use]
    pub fn is_ebgp(&self) -> bool {
        self.origin_type == RouteOrigin::Ebgp
    }

    /// Identity key suitable for RTC Adj-RIB-In, Loc-RIB, and Adj-RIB-Out maps.
    #[must_use]
    pub fn key(&self) -> RtcRibRouteKey {
        RtcRibRouteKey {
            nlri: self.nlri,
            path_id: self.path_id,
        }
    }

    /// Extract the `AS_PATH`, returning `None` if absent.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::AsPath(path) => Some(path),
            _ => None,
        })
    }

    /// Extract the explicit `LOCAL_PREF`, if present.
    #[must_use]
    pub fn local_pref_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract the explicit MED, if present.
    #[must_use]
    pub fn med_attr(&self) -> Option<u32> {
        self.attributes.iter().find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
    }

    /// Extract COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn communities(&self) -> &[u32] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::Communities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract EXTENDED COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn extended_communities(&self) -> &[ExtendedCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::ExtendedCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Extract LARGE COMMUNITIES values, returning an empty slice if absent.
    #[must_use]
    pub fn large_communities(&self) -> &[LargeCommunity] {
        self.attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
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

    use std::collections::HashMap;

    use rustbgpd_wire::{
        Afi, MplsLabelEntry, PathAttribute, RouteDistinguisher, Safi, VpnAddressFamily, VpnNlri,
        VpnPrefix,
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

    fn vpn_v4_nlri(addr: [u8; 4], len: u8, label: u32) -> VpnNlri {
        VpnNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher::new([0, 0, 0, 0, 0, 0, 0, 1]),
            prefix: VpnPrefix::v4(Ipv4Addr::from(addr), len).unwrap(),
        }
    }

    fn vpn_v6_nlri(addr: [u8; 16], len: u8, label: u32) -> VpnNlri {
        VpnNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher::new([0, 0, 0, 0, 0, 0, 0, 1]),
            prefix: VpnPrefix::v6(std::net::Ipv6Addr::from(addr), len).unwrap(),
        }
    }

    fn make_vpn_route(nlri: VpnNlri, path_id: u32) -> VpnRibRoute {
        VpnRibRoute {
            nlri,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id,
        }
    }

    #[test]
    fn vpn_route_key_round_trips_through_map() {
        let route = make_vpn_route(vpn_v4_nlri([10, 0, 1, 0], 24, 100), 0);
        let key = route.key();

        let mut map: HashMap<VpnRibRouteKey, VpnRibRoute> = HashMap::new();
        map.insert(key.clone(), route.clone());

        let stored = map.get(&key).expect("route retrievable by its own key");
        assert_eq!(stored.nlri, route.nlri);
        assert_eq!(key.nlri_key, route.nlri.key());
        assert_eq!(key.path_id, 0);
    }

    #[test]
    fn vpn_same_rd_prefix_different_path_id_are_distinct_keys() {
        let nlri = vpn_v4_nlri([203, 0, 113, 0], 24, 100);
        let a = make_vpn_route(nlri.clone(), 1);
        let b = make_vpn_route(nlri, 2);

        assert_eq!(
            a.key().nlri_key,
            b.key().nlri_key,
            "same RD + prefix means identical wire NLRI key"
        );
        assert_ne!(
            a.key(),
            b.key(),
            "differing path_id makes the RIB key distinct"
        );

        let mut map: HashMap<VpnRibRouteKey, VpnRibRoute> = HashMap::new();
        map.insert(a.key(), a);
        map.insert(b.key(), b);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn vpn_label_stack_is_not_part_of_the_key() {
        // Labels are route data, not identity: relabel keeps the same key.
        let a = make_vpn_route(vpn_v4_nlri([198, 51, 100, 0], 24, 100), 0);
        let b = make_vpn_route(vpn_v4_nlri([198, 51, 100, 0], 24, 200), 0);

        assert_eq!(a.key(), b.key());
        assert_ne!(a.nlri, b.nlri);
    }

    #[test]
    fn vpn_family_matches_prefix() {
        let v4 = make_vpn_route(vpn_v4_nlri([10, 0, 0, 0], 8, 100), 0);
        let v6 = make_vpn_route(
            vpn_v6_nlri(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                48,
                100,
            ),
            0,
        );

        assert_eq!(v4.family(), VpnAddressFamily::V4);
        assert_eq!(v6.family(), VpnAddressFamily::V6);
    }

    #[test]
    fn vpn_afi_safi_maps_family_to_wire_pair() {
        let v4 = make_vpn_route(vpn_v4_nlri([10, 0, 0, 0], 8, 100), 0);
        let v6 = make_vpn_route(
            vpn_v6_nlri(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                48,
                100,
            ),
            0,
        );

        assert_eq!(v4.afi_safi(), (Afi::Ipv4, Safi::MplsVpn));
        assert_eq!(v6.afi_safi(), (Afi::Ipv6, Safi::MplsVpn));
    }

    fn make_rtc_route(local_admin: u32, path_id: u32) -> RtcRibRoute {
        // 2-octet-AS RT:65001:<local_admin>, origin AS 65001, full /96.
        let rt = 0x0002_FDE9_0000_0000_u64 | u64::from(local_admin);
        RtcRibRoute {
            nlri: RtcNlri::new(65001, rt, 96).unwrap(),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id,
        }
    }

    #[test]
    fn rtc_route_key_round_trips_through_map() {
        let route = make_rtc_route(100, 0);
        let key = route.key();

        let mut map: HashMap<RtcRibRouteKey, RtcRibRoute> = HashMap::new();
        map.insert(key.clone(), route.clone());

        let stored = map.get(&key).expect("route retrievable by its own key");
        assert_eq!(stored.nlri, route.nlri);
        assert_eq!(key.nlri, route.nlri);
        assert_eq!(key.path_id, 0);
    }

    #[test]
    fn rtc_same_nlri_different_path_id_are_distinct_keys() {
        let a = make_rtc_route(100, 1);
        let b = make_rtc_route(100, 2);

        assert_eq!(a.key().nlri, b.key().nlri, "same wire NLRI identity");
        assert_ne!(
            a.key(),
            b.key(),
            "differing path_id makes the RIB key distinct"
        );

        let mut map: HashMap<RtcRibRouteKey, RtcRibRoute> = HashMap::new();
        map.insert(a.key(), a);
        map.insert(b.key(), b);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn rtc_afi_safi_is_constant_ipv4_rt_constrain() {
        assert_eq!(RtcRibRouteKey::afi_safi(), (Afi::Ipv4, Safi::RtConstrain));
        assert_eq!(
            make_rtc_route(100, 0).afi_safi(),
            (Afi::Ipv4, Safi::RtConstrain)
        );
    }
}
