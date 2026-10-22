//! Interface-only unnumbered neighbor configuration (ADR-0142).
//!
//! The configuration shape lives here: the `remote_asn` matching mode
//! ([`RemoteAsn`]), the `[global.unnumbered]` settings
//! ([`UnnumberedConfig`]), and [`NeighborList`], which keeps
//! `[[neighbors]]` entries that name an interface and no address apart from
//! the addressed ones. Code that walks `config.neighbors` sees only addressed
//! neighbors; interface-only ones are reached through
//! [`NeighborList::interface_only`].

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_policy::sets::SetStore;

use super::{Config, ConfigError, Neighbor, ResolvedNeighbor};

/// RFC 4861 §6.2.1 `MaxRtrAdvInterval` bounds for `ra_interval_secs`; the
/// discovery engine enforces the same range.
const RA_INTERVAL_SECS: std::ops::RangeInclusive<u16> = 4..=1800;

/// A neighbor's `remote_asn`: a number, `"external"` (any ASN except
/// `global.asn`) or `"internal"` (`global.asn`). Both string forms are
/// checked against the ASN the peer actually sends in OPEN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteAsn {
    Asn(u32),
    External,
    Internal,
}

impl Default for RemoteAsn {
    fn default() -> Self {
        Self::Asn(0)
    }
}

impl From<u32> for RemoteAsn {
    fn from(asn: u32) -> Self {
        Self::Asn(asn)
    }
}

impl RemoteAsn {
    /// The numeric ASN the runtime compares and classifies with: the number,
    /// `local_asn` for `internal`, and `0` for `external`. `0` never means
    /// "any" for `external`: the OPEN check is [`Self::is_external`].
    #[must_use]
    pub fn resolve(self, local_asn: u32) -> u32 {
        match self {
            Self::Asn(asn) => asn,
            Self::Internal => local_asn,
            Self::External => 0,
        }
    }

    /// `remote_asn = "external"`.
    #[must_use]
    pub fn is_external(self) -> bool {
        self == Self::External
    }

    /// `numeric`, `external` or `internal`, as `--diff` and the API name it.
    #[must_use]
    pub fn mode(self) -> &'static str {
        match self {
            Self::Asn(_) => "numeric",
            Self::External => "external",
            Self::Internal => "internal",
        }
    }

    /// The configured number, if this is the numeric form.
    #[must_use]
    pub fn numeric(self) -> Option<u32> {
        match self {
            Self::Asn(asn) => Some(asn),
            Self::External | Self::Internal => None,
        }
    }
}

impl fmt::Display for RemoteAsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn(asn) => write!(f, "{asn}"),
            Self::External => f.write_str("external"),
            Self::Internal => f.write_str("internal"),
        }
    }
}

impl Serialize for RemoteAsn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Asn(asn) => serializer.serialize_u32(*asn),
            Self::External => serializer.serialize_str("external"),
            Self::Internal => serializer.serialize_str("internal"),
        }
    }
}

impl<'de> Deserialize<'de> for RemoteAsn {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = RemoteAsn;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"an ASN, "external" or "internal""#)
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<RemoteAsn, E> {
                u32::try_from(value)
                    .map(RemoteAsn::Asn)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Unsigned(value), &self))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<RemoteAsn, E> {
                u32::try_from(value)
                    .map(RemoteAsn::Asn)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(value), &self))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<RemoteAsn, E> {
                match value {
                    "external" => Ok(RemoteAsn::External),
                    "internal" => Ok(RemoteAsn::Internal),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Str(value), &self)),
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl JsonSchema for RemoteAsn {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("RemoteAsn")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "anyOf": [
                { "type": "integer", "format": "uint32", "minimum": 0 },
                { "type": "string", "enum": ["external", "internal"] }
            ]
        })
    }
}

/// `[global.unnumbered]`: Router Advertisement settings for interface-only
/// neighbors. Restart-required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnnumberedConfig {
    /// Send Router Advertisements and the link-up Router Solicitation on
    /// interface-only neighbors' interfaces. `false` disables sending only;
    /// reception stays on, so `CAP_NET_RAW` is still required. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_advertisements: Option<bool>,
    /// RFC 4861 `MaxRtrAdvInterval` in seconds, 4..=1800. The advertised
    /// Router Lifetime is three times this value. Default: 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ra_interval_secs: Option<u16>,
}

/// `[[neighbors]]`, split into addressed neighbors (the `Vec` this derefs
/// to) and interface-only neighbors. It serializes back as one array, with
/// each interface-only entry after the addressed entries that preceded it
/// when it was loaded, so a runtime rewrite keeps the operator's order.
#[derive(Debug, Clone, Default)]
pub struct NeighborList {
    addressed: Vec<Neighbor>,
    interface_only: Vec<Neighbor>,
    /// Per interface-only entry: how many addressed entries preceded it.
    anchors: Vec<usize>,
}

/// Position is presentation, not configuration: two lists with the same
/// entries are equal however they interleave.
impl PartialEq for NeighborList {
    fn eq(&self, other: &Self) -> bool {
        self.addressed == other.addressed && self.interface_only == other.interface_only
    }
}

impl NeighborList {
    /// Neighbors with `interface` and no `address`.
    #[must_use]
    pub fn interface_only(&self) -> &[Neighbor] {
        &self.interface_only
    }

    /// Addressed neighbors, then interface-only ones: for inventories that
    /// apply to every configured neighbor.
    pub fn all(&self) -> impl Iterator<Item = &Neighbor> {
        self.addressed.iter().chain(&self.interface_only)
    }

    /// Mutable [`Self::all`].
    pub fn all_mut(&mut self) -> impl Iterator<Item = &mut Neighbor> {
        self.addressed.iter_mut().chain(&mut self.interface_only)
    }

    /// The interface-only neighbor on `interface`.
    #[must_use]
    pub fn interface_only_on(&self, interface: &str) -> Option<&Neighbor> {
        self.interface_only
            .iter()
            .find(|neighbor| neighbor.interface.as_deref() == Some(interface))
    }

    /// Take `running`'s interface-only neighbors and their positions
    /// (reload pins them).
    pub fn pin_interface_only(&mut self, running: &Self) {
        self.interface_only.clone_from(&running.interface_only);
        self.anchors.clone_from(&running.anchors);
    }

    /// Every entry in configuration order.
    fn in_order(&self) -> Vec<&Neighbor> {
        let mut ordered = Vec::with_capacity(self.addressed.len() + self.interface_only.len());
        let mut pending = self.anchors.iter().zip(&self.interface_only).peekable();
        for (index, neighbor) in self.addressed.iter().enumerate() {
            while let Some((_, interface_only)) = pending.next_if(|(anchor, _)| **anchor <= index) {
                ordered.push(interface_only);
            }
            ordered.push(neighbor);
        }
        ordered.extend(pending.map(|(_, interface_only)| interface_only));
        ordered
    }
}

impl From<Vec<Neighbor>> for NeighborList {
    fn from(neighbors: Vec<Neighbor>) -> Self {
        let mut list = Self::default();
        for neighbor in neighbors {
            if neighbor.is_interface_only() {
                list.anchors.push(list.addressed.len());
                list.interface_only.push(neighbor);
            } else {
                list.addressed.push(neighbor);
            }
        }
        list
    }
}

impl FromIterator<Neighbor> for NeighborList {
    fn from_iter<I: IntoIterator<Item = Neighbor>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl std::ops::Deref for NeighborList {
    type Target = Vec<Neighbor>;

    fn deref(&self) -> &Vec<Neighbor> {
        &self.addressed
    }
}

impl std::ops::DerefMut for NeighborList {
    fn deref_mut(&mut self) -> &mut Vec<Neighbor> {
        &mut self.addressed
    }
}

impl<'a> IntoIterator for &'a NeighborList {
    type Item = &'a Neighbor;
    type IntoIter = std::slice::Iter<'a, Neighbor>;

    fn into_iter(self) -> Self::IntoIter {
        self.addressed.iter()
    }
}

impl<'a> IntoIterator for &'a mut NeighborList {
    type Item = &'a mut Neighbor;
    type IntoIter = std::slice::IterMut<'a, Neighbor>;

    fn into_iter(self) -> Self::IntoIter {
        self.addressed.iter_mut()
    }
}

impl Serialize for NeighborList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.in_order())
    }
}

impl<'de> Deserialize<'de> for NeighborList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<Neighbor>::deserialize(deserializer).map(Self::from)
    }
}

impl JsonSchema for NeighborList {
    fn inline_schema() -> bool {
        Vec::<Neighbor>::inline_schema()
    }

    fn schema_name() -> Cow<'static, str> {
        Vec::<Neighbor>::schema_name()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        Vec::<Neighbor>::json_schema(generator)
    }
}

/// Interface-only neighbors (compared by interface, so reordering is not a
/// change) or `[global.unnumbered]` differ: restart-required.
#[must_use]
pub fn interface_only_neighbors_changed(old: &Config, new: &Config) -> bool {
    fn by_interface(config: &Config) -> std::collections::BTreeMap<Option<&str>, &Neighbor> {
        config
            .neighbors
            .interface_only()
            .iter()
            .map(|neighbor| (neighbor.interface.as_deref(), neighbor))
            .collect()
    }
    old.global.unnumbered != new.global.unnumbered || by_interface(old) != by_interface(new)
}

fn invalid(neighbor: &Neighbor, field: &str, reason: &str) -> ConfigError {
    ConfigError::InvalidNeighborConfig {
        address: neighbor.label(),
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

impl Config {
    /// ADR-0142 rules for interface-only neighbors and `[global.unnumbered]`.
    /// Their ordinary per-neighbor fields are checked with every other
    /// neighbor's.
    pub(super) fn validate_interface_only_neighbors(&self) -> Result<(), ConfigError> {
        if let Some(interval) = self
            .global
            .unnumbered
            .as_ref()
            .and_then(|unnumbered| unnumbered.ra_interval_secs)
            && !RA_INTERVAL_SECS.contains(&interval)
        {
            return Err(ConfigError::InvalidUnnumbered {
                reason: format!(
                    "ra_interval_secs {interval} is outside 4..=1800 (RFC 4861 section 6.2.1)"
                ),
            });
        }
        let neighbors = self.neighbors.interface_only();
        let Some(first) = neighbors.first() else {
            return Ok(());
        };
        if !cfg!(target_os = "linux") {
            return Err(invalid(
                first,
                "interface",
                "interface-only neighbors need Linux (raw ICMPv6 Router Advertisement sockets)",
            ));
        }
        if self.global.listen_addresses.is_some() {
            return Err(ConfigError::InvalidListenAddresses {
                reason: format!(
                    "{} is a scoped IPv6 link-local peer, which is not supported with explicit \
                     listen_addresses",
                    first.label()
                ),
            });
        }
        let mut seen = HashSet::new();
        for neighbor in neighbors {
            let interface = neighbor.interface.as_deref().unwrap_or_default();
            if interface.trim().is_empty() {
                return Err(invalid(
                    neighbor,
                    "interface",
                    "interface must not be empty",
                ));
            }
            if !seen.insert(interface) {
                return Err(invalid(
                    neighbor,
                    "interface",
                    "only one interface-only neighbor is allowed per interface",
                ));
            }
            if self
                .neighbors
                .iter()
                .any(|other| other.interface.as_deref() == Some(interface))
            {
                return Err(invalid(
                    neighbor,
                    "interface",
                    "the interface already has a static link-local neighbor",
                ));
            }
            self.validate_interface_only_fields(neighbor)?;
        }
        Ok(())
    }

    /// Fields an interface-only neighbor may not set, directly or through
    /// its peer group.
    fn validate_interface_only_fields(&self, neighbor: &Neighbor) -> Result<(), ConfigError> {
        let group = self.peer_group_for_neighbor(neighbor)?;
        if neighbor.md5_password.is_some()
            || group.is_some_and(|group| group.md5_password.is_some())
        {
            return Err(invalid(
                neighbor,
                "md5_password",
                "TCP MD5 is not supported on interface-only neighbors yet; these sessions \
                 have no TCP-layer authentication (ADR-0142)",
            ));
        }
        if neighbor.tcp_ao.is_some() {
            return Err(invalid(
                neighbor,
                "tcp_ao",
                "TCP-AO is not supported on interface-only neighbors yet; these sessions \
                 have no TCP-layer authentication (ADR-0142)",
            ));
        }
        // Per-peer inventories built from configured addresses at startup and
        // reload. A learned address is never in them, so these settings would
        // be accepted and never applied; refuse them until they are wired to
        // the binding.
        if neighbor.max_prefixes_out_ipv4_unicast.is_some()
            || neighbor.max_prefixes_out_ipv6_unicast.is_some()
        {
            return Err(invalid(
                neighbor,
                "max_prefixes_out_ipv4_unicast",
                "per-neighbor outbound prefix maxima are not supported on interface-only \
                 neighbors yet; set them on the peer group",
            ));
        }
        if !self
            .effective_conditional_advertisements(neighbor)
            .is_empty()
        {
            return Err(invalid(
                neighbor,
                "conditional_advertisements",
                "conditional advertisements are not supported on interface-only neighbors yet",
            ));
        }
        if neighbor
            .log_level
            .as_deref()
            .or_else(|| group.and_then(|group| group.log_level.as_deref()))
            .is_some()
        {
            return Err(invalid(
                neighbor,
                "log_level",
                "a per-neighbor log_level is not supported on interface-only neighbors yet",
            ));
        }
        // GTSM is enforced by the listener's per-peer IP_MINTTL selectors,
        // built from configured addresses at startup and reload; a learned
        // address is not in that inventory, so it would go unprotected.
        if neighbor
            .ttl_security
            .or_else(|| group.and_then(|group| group.ttl_security))
            .unwrap_or(false)
        {
            return Err(invalid(
                neighbor,
                "ttl_security",
                "GTSM (ttl_security) is not supported on interface-only neighbors yet",
            ));
        }
        if neighbor
            .bfd
            .as_ref()
            .or_else(|| group.and_then(|group| group.bfd.as_ref()))
            .is_some_and(|bfd| bfd.enabled)
        {
            return Err(invalid(
                neighbor,
                "bfd",
                "BFD for interface-only neighbors is not supported yet",
            ));
        }
        if neighbor
            .fast_external_failover
            .or_else(|| group.and_then(|group| group.fast_external_failover))
            == Some(false)
        {
            return Err(invalid(
                neighbor,
                "fast_external_failover",
                "cannot be disabled on an interface-only neighbor: confirmed carrier loss \
                 always ends its session",
            ));
        }
        Ok(())
    }

    /// The configured record of a managed peer: its static `[[neighbors]]`
    /// entry, or, for a peer an interface-only neighbor bound on
    /// `peer.interface`, that neighbor with the learned address filled in.
    /// Every peer-to-record lookup goes through this, so a bound peer is
    /// never mistaken for a static neighbor whose record went missing.
    #[must_use]
    pub fn neighbor_record(&self, peer: &PeerKey) -> Option<Cow<'_, Neighbor>> {
        let address = peer.address.to_string();
        if let Some(neighbor) = self
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == address && neighbor.interface == peer.interface)
        {
            return Some(Cow::Borrowed(neighbor));
        }
        let IpAddr::V6(learned) = peer.address else {
            return None;
        };
        if !learned.is_unicast_link_local() {
            return None;
        }
        let mut bound = self
            .neighbors
            .interface_only_on(peer.interface.as_deref()?)?
            .clone();
        bound.address = address;
        Some(Cow::Owned(bound))
    }

    /// Interface-only neighbors resolved with a placeholder link-local
    /// address and no scope: for startup inventories that need only their
    /// settings (listener MSS clamp, Graceful Restart timing), never for a
    /// transport.
    pub(crate) fn interface_only_resolved_for_comparison(
        &self,
    ) -> Result<Vec<ResolvedNeighbor>, ConfigError> {
        self.neighbors
            .interface_only()
            .iter()
            .map(|neighbor| {
                self.resolve_bound_interface_neighbor(neighbor, Ipv6Addr::UNSPECIFIED, 0)
            })
            .collect()
    }

    /// Resolve an interface-only neighbor bound to `address%ifindex`: the
    /// neighbor as if configured with that address, scoped to that index,
    /// with fast external failover always on (ADR-0142 lifecycle).
    pub(crate) fn resolve_bound_interface_neighbor(
        &self,
        neighbor: &Neighbor,
        address: Ipv6Addr,
        ifindex: u32,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        let mut bound = neighbor.clone();
        bound.address = address.to_string();
        let mut resolved = self.resolve_neighbor_pinned_with_store(
            &bound,
            false,
            &mut SetStore::new(),
            Some(ifindex),
        )?;
        resolved.transport_config.fast_external_failover = true;
        Ok(resolved)
    }
}

impl Neighbor {
    /// The address that selects default families: the configured one, or an
    /// IPv6 link-local placeholder for an interface-only neighbor.
    pub(crate) fn family_address(&self) -> Result<IpAddr, ConfigError> {
        if self.is_interface_only() {
            return Ok(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)));
        }
        self.address
            .parse()
            .map_err(
                |error: std::net::AddrParseError| ConfigError::InvalidNeighborAddress {
                    value: self.address.clone(),
                    reason: error.to_string(),
                },
            )
    }

    /// `interface` set and `address` omitted: an interface-only neighbor.
    #[must_use]
    pub fn is_interface_only(&self) -> bool {
        self.address.is_empty() && self.interface.is_some()
    }

    /// Operator name for messages: the address, or `interface <name>`.
    #[must_use]
    pub fn label(&self) -> String {
        match (&self.interface, self.address.is_empty()) {
            (Some(interface), true) => format!("interface {interface}"),
            _ => self.address.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_asn_round_trips_every_form() {
        for (toml, expected) in [
            ("remote_asn = 65001", RemoteAsn::Asn(65001)),
            ("remote_asn = \"external\"", RemoteAsn::External),
            ("remote_asn = \"internal\"", RemoteAsn::Internal),
        ] {
            #[derive(Serialize, Deserialize)]
            struct Row {
                remote_asn: RemoteAsn,
            }
            let row: Row = toml::from_str(toml).unwrap();
            assert_eq!(row.remote_asn, expected);
            assert_eq!(toml::to_string(&row).unwrap().trim(), toml);
        }
    }

    #[test]
    fn remote_asn_rejects_other_strings_and_out_of_range_numbers() {
        #[derive(Debug, Deserialize)]
        #[expect(dead_code, reason = "only the parse outcome is asserted")]
        struct Row {
            remote_asn: RemoteAsn,
        }
        for toml in [
            "remote_asn = \"ebgp\"",
            "remote_asn = -1",
            "remote_asn = 4294967296",
        ] {
            let error = toml::from_str::<Row>(toml).unwrap_err().to_string();
            assert!(
                error.contains(r#"an ASN, "external" or "internal""#),
                "{toml}: {error}"
            );
        }
    }

    #[test]
    fn remote_asn_resolution() {
        assert_eq!(RemoteAsn::Asn(65002).resolve(65001), 65002);
        assert_eq!(RemoteAsn::Internal.resolve(65001), 65001);
        assert_eq!(RemoteAsn::External.resolve(65001), 0);
        assert!(RemoteAsn::External.is_external());
        assert!(!RemoteAsn::Asn(0).is_external());
    }
}
