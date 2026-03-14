use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, ExtendedCommunity, FlowSpecRule, LargeCommunity, Origin,
    PathAttribute, Prefix, RpkiValidation,
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
    /// The next-hop address (IPv4 or IPv6).
    pub next_hop: IpAddr,
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
