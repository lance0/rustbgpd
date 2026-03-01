use std::net::IpAddr;
use std::time::Instant;

use rustbgpd_wire::{AsPath, ExtendedCommunity, Origin, PathAttribute, Prefix};

/// A single route stored in the Adj-RIB-In.
#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: Prefix,
    pub next_hop: IpAddr,
    pub peer: IpAddr,
    pub attributes: Vec<PathAttribute>,
    pub received_at: Instant,
    /// Whether this route was learned via an eBGP session (local ASN != remote ASN).
    pub is_ebgp: bool,
    /// Whether this route is stale due to a peer graceful restart.
    pub is_stale: bool,
}

impl Route {
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
}
