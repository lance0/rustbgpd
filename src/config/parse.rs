use super::{
    Afi, CommunityMatch, ConfigError, ExtendedCommunity, HashMap, IpAddr, Ipv4Addr, Ipv4Prefix,
    Ipv6Addr, Ipv6Prefix, LargeCommunity, NamedPolicyConfig, NeighborSetConfig, NextHopAction,
    PeerGroupConfig, Policy, PolicyAction, PolicyChain, PolicyStatement, PolicyStatementConfig,
    Prefix, RouteModifications, Safi, parse_community_match,
};
use rustbgpd_policy::{NeighborSetMatch, RouteType};

/// Parse and validate a single CIDR prefix string with optional ge/le bounds.
fn parse_prefix_entry(
    prefix_str: &str,
    ge: Option<u8>,
    le: Option<u8>,
) -> Result<Prefix, ConfigError> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!(
                "invalid prefix {prefix_str:?}, expected CIDR notation (e.g. 10.0.0.0/8 or 2001:db8::/32)"
            ),
        });
    }
    let len: u8 = parts[1]
        .parse()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!("invalid prefix length in {prefix_str:?}"),
        })?;

    let (prefix, max_len) = if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
        if len > 32 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("prefix length {len} exceeds 32 in {prefix_str:?}"),
            });
        }
        (Prefix::V4(Ipv4Prefix::new(v4, len)), 32u8)
    } else if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
        if len > 128 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("prefix length {len} exceeds 128 in {prefix_str:?}"),
            });
        }
        (Prefix::V6(Ipv6Prefix::new(v6, len)), 128u8)
    } else {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("invalid address in prefix {prefix_str:?}"),
        });
    };

    if let Some(ge) = ge {
        if ge > max_len {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("ge value {ge} exceeds {max_len} in {prefix_str:?}"),
            });
        }
        if ge < len {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("ge value {ge} is less than prefix length {len} in {prefix_str:?}"),
            });
        }
    }
    if let Some(le) = le
        && le > max_len
    {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("le value {le} exceeds {max_len} in {prefix_str:?}"),
        });
    }
    if let (Some(ge), Some(le)) = (ge, le)
        && ge > le
    {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("ge value {ge} exceeds le value {le} in {prefix_str:?}"),
        });
    }
    Ok(prefix)
}

/// Parse a list of statement configs into `PolicyStatement`s.
#[expect(
    clippy::too_many_lines,
    reason = "maps the full policy statement config surface into runtime matches"
)]
fn parse_policy_statements(
    entries: &[PolicyStatementConfig],
    neighbor_sets: &HashMap<String, NeighborSetConfig>,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<Vec<PolicyStatement>, ConfigError> {
    let mut parsed = Vec::with_capacity(entries.len());
    for e in entries {
        let action = match e.action.as_str() {
            "permit" => PolicyAction::Permit,
            "deny" => PolicyAction::Deny,
            other => {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!("unknown action {other:?}, expected \"permit\" or \"deny\""),
                });
            }
        };

        let match_community: Vec<_> = e
            .match_community
            .iter()
            .map(|s| {
                parse_community_match(s)
                    .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })
            })
            .collect::<Result<_, _>>()?;

        let prefix = if let Some(ref prefix_str) = e.prefix {
            Some(parse_prefix_entry(prefix_str, e.ge, e.le)?)
        } else {
            if e.ge.is_some() || e.le.is_some() {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: "ge/le cannot be set without a prefix".to_string(),
                });
            }
            None
        };

        let match_as_path = if let Some(ref pat) = e.match_as_path {
            Some(
                rustbgpd_policy::AsPathRegex::new(pat)
                    .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })?,
            )
        } else {
            None
        };

        let match_rpki_validation = if let Some(ref s) = e.match_rpki_validation {
            Some(s.parse::<rustbgpd_wire::RpkiValidation>().map_err(|_| {
                ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "invalid match_rpki_validation {s:?}: expected \"valid\", \"invalid\", or \"not_found\""
                    ),
                }
            })?)
        } else {
            None
        };

        let match_neighbor_set = if let Some(ref name) = e.match_neighbor_set {
            Some(resolve_neighbor_set(name, neighbor_sets, peer_groups)?)
        } else {
            None
        };

        let match_route_type = if let Some(ref value) = e.match_route_type {
            Some(parse_route_type(value)?)
        } else {
            None
        };

        let match_next_hop = if let Some(ref value) = e.match_next_hop {
            Some(parse_match_next_hop(value)?)
        } else {
            None
        };

        if let (Some(ge), Some(le)) = (e.match_as_path_length_ge, e.match_as_path_length_le)
            && ge > le
        {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!(
                    "match_as_path_length_ge ({ge}) exceeds match_as_path_length_le ({le})"
                ),
            });
        }

        if let (Some(ge), Some(le)) = (e.match_local_pref_ge, e.match_local_pref_le)
            && ge > le
        {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("match_local_pref_ge ({ge}) exceeds match_local_pref_le ({le})"),
            });
        }

        if let (Some(ge), Some(le)) = (e.match_med_ge, e.match_med_le)
            && ge > le
        {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("match_med_ge ({ge}) exceeds match_med_le ({le})"),
            });
        }

        if prefix.is_none()
            && match_community.is_empty()
            && match_as_path.is_none()
            && match_neighbor_set.is_none()
            && match_route_type.is_none()
            && e.match_as_path_length_ge.is_none()
            && e.match_as_path_length_le.is_none()
            && e.match_local_pref_ge.is_none()
            && e.match_local_pref_le.is_none()
            && e.match_med_ge.is_none()
            && e.match_med_le.is_none()
            && match_next_hop.is_none()
            && match_rpki_validation.is_none()
        {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: "entry must have at least one match condition".to_string(),
            });
        }

        // Build route modifications from set_* fields
        let modifications = parse_modifications(e, action)?;

        parsed.push(PolicyStatement {
            prefix,
            ge: e.ge,
            le: e.le,
            action,
            match_community,
            match_as_path,
            match_neighbor_set,
            match_route_type,
            match_rpki_validation,
            match_aspa_validation: None,
            match_as_path_length_ge: e.match_as_path_length_ge,
            match_as_path_length_le: e.match_as_path_length_le,
            match_local_pref_ge: e.match_local_pref_ge,
            match_local_pref_le: e.match_local_pref_le,
            match_med_ge: e.match_med_ge,
            match_med_le: e.match_med_le,
            match_next_hop,
            modifications,
        });
    }
    Ok(parsed)
}

/// Parse inline policy entries into a single `Policy` with `default_action=Permit`.
pub(super) fn parse_policy(
    entries: &[PolicyStatementConfig],
    neighbor_sets: &HashMap<String, NeighborSetConfig>,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<Option<Policy>, ConfigError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let parsed = parse_policy_statements(entries, neighbor_sets, peer_groups)?;
    Ok(Some(Policy {
        entries: parsed,
        default_action: PolicyAction::Permit,
    }))
}

/// Parse a named policy definition with configurable default action.
pub(super) fn parse_named_policy(
    name: &str,
    cfg: &NamedPolicyConfig,
    neighbor_sets: &HashMap<String, NeighborSetConfig>,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<Policy, ConfigError> {
    let default_action = match cfg.default_action.as_str() {
        "permit" => PolicyAction::Permit,
        "deny" => PolicyAction::Deny,
        other => {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!(
                    "policy {name:?}: unknown default_action {other:?}, expected \"permit\" or \"deny\""
                ),
            });
        }
    };
    let entries = parse_policy_statements(&cfg.statements, neighbor_sets, peer_groups)?;
    Ok(Policy {
        entries,
        default_action,
    })
}

/// Resolve a list of policy names to a `PolicyChain`.
pub(super) fn resolve_chain(
    names: &[String],
    definitions: &HashMap<String, NamedPolicyConfig>,
    neighbor_sets: &HashMap<String, NeighborSetConfig>,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<Option<PolicyChain>, ConfigError> {
    if names.is_empty() {
        return Ok(None);
    }
    let policies = names
        .iter()
        .map(|name| {
            definitions
                .get(name.as_str())
                .ok_or_else(|| ConfigError::UndefinedPolicy { name: name.clone() })
                .and_then(|cfg| parse_named_policy(name, cfg, neighbor_sets, peer_groups))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(PolicyChain::new(policies)))
}

fn resolve_neighbor_set(
    name: &str,
    neighbor_sets: &HashMap<String, NeighborSetConfig>,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<NeighborSetMatch, ConfigError> {
    let set = neighbor_sets
        .get(name)
        .ok_or_else(|| ConfigError::InvalidNeighborSet {
            reason: format!("undefined neighbor set {name:?}"),
        })?;
    parse_neighbor_set(name, set, peer_groups)
}

pub(super) fn parse_neighbor_set(
    name: &str,
    set: &NeighborSetConfig,
    peer_groups: &HashMap<String, PeerGroupConfig>,
) -> Result<NeighborSetMatch, ConfigError> {
    if set.addresses.is_empty() && set.remote_asns.is_empty() && set.peer_groups.is_empty() {
        return Err(ConfigError::InvalidNeighborSet {
            reason: format!("neighbor_set {name:?} must not be empty"),
        });
    }

    let addresses = set
        .addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|e| ConfigError::InvalidNeighborSet {
                    reason: format!("neighbor_set {name:?}: invalid address {value:?}: {e}"),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for group in &set.peer_groups {
        if !peer_groups.contains_key(group) {
            return Err(ConfigError::UndefinedPeerGroup {
                name: group.clone(),
            });
        }
    }

    Ok(NeighborSetMatch {
        addresses,
        remote_asns: set.remote_asns.clone(),
        peer_groups: set.peer_groups.clone(),
    })
}

fn parse_route_type(value: &str) -> Result<RouteType, ConfigError> {
    match value {
        "local" => Ok(RouteType::Local),
        "internal" => Ok(RouteType::Internal),
        "external" => Ok(RouteType::External),
        other => Err(ConfigError::InvalidPolicyEntry {
            reason: format!(
                "invalid match_route_type {other:?}: expected \"local\", \"internal\", or \"external\""
            ),
        }),
    }
}

fn parse_match_next_hop(value: &str) -> Result<IpAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::InvalidPolicyEntry {
        reason: format!("invalid match_next_hop {value:?}: expected an IP address"),
    })
}

/// Parse the `set_*` fields into `RouteModifications`, with validation.
fn parse_modifications(
    e: &PolicyStatementConfig,
    action: PolicyAction,
) -> Result<RouteModifications, ConfigError> {
    let has_set_fields = e.set_local_pref.is_some()
        || e.set_med.is_some()
        || e.set_next_hop.is_some()
        || !e.set_community_add.is_empty()
        || !e.set_community_remove.is_empty()
        || e.set_as_path_prepend.is_some();

    if has_set_fields && action == PolicyAction::Deny {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: "set_* fields cannot be used with action = \"deny\"".to_string(),
        });
    }

    if !has_set_fields {
        return Ok(RouteModifications::default());
    }

    // Parse next-hop action
    let set_next_hop = if let Some(ref nh) = e.set_next_hop {
        match nh.as_str() {
            "self" => Some(NextHopAction::Self_),
            other => {
                let addr: IpAddr = other.parse().map_err(|_| ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "invalid set_next_hop {other:?}: expected \"self\" or an IP address"
                    ),
                })?;
                Some(NextHopAction::Specific(addr))
            }
        }
    } else {
        None
    };

    // Parse AS_PATH prepend
    let as_path_prepend = if let Some(ref pp) = e.set_as_path_prepend {
        if pp.count == 0 || pp.count > 10 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("set_as_path_prepend count must be 1-10, got {}", pp.count),
            });
        }
        Some((pp.asn, pp.count))
    } else {
        None
    };

    // Parse community add/remove values
    let add = parse_community_values(&e.set_community_add)?;
    let remove = parse_community_values(&e.set_community_remove)?;

    Ok(RouteModifications {
        set_local_pref: e.set_local_pref,
        set_med: e.set_med,
        set_next_hop,
        communities_add: add.standard,
        communities_remove: remove.standard,
        extended_communities_add: add.extended,
        extended_communities_remove: remove.extended,
        large_communities_add: add.large,
        large_communities_remove: remove.large,
        as_path_prepend,
    })
}

/// Classified community values parsed from config strings.
struct CommunityValues {
    standard: Vec<u32>,
    extended: Vec<ExtendedCommunity>,
    large: Vec<LargeCommunity>,
}

/// Parse community strings and classify into standard, extended, and large buckets.
fn parse_community_values(strings: &[String]) -> Result<CommunityValues, ConfigError> {
    let mut standard = Vec::new();
    let mut extended = Vec::new();
    let mut large = Vec::new();
    for s in strings {
        let cm = parse_community_match(s)
            .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })?;
        match cm {
            CommunityMatch::Standard { value } => standard.push(value),
            CommunityMatch::RouteTarget { global, local } => {
                extended.push(build_rt_ec(global, local)?);
            }
            CommunityMatch::RouteOrigin { global, local } => {
                extended.push(build_ro_ec(global, local)?);
            }
            CommunityMatch::LargeCommunity {
                global_admin,
                local_data1,
                local_data2,
            } => {
                large.push(LargeCommunity::new(global_admin, local_data1, local_data2));
            }
        }
    }
    Ok(CommunityValues {
        standard,
        extended,
        large,
    })
}

/// Build a 2-octet AS Route Target extended community.
///
/// Rejects `global` > 65535 since the 2-octet AS-Specific sub-type only
/// carries a `u16` AS number.
fn build_rt_ec(global: u32, local: u32) -> Result<ExtendedCommunity, ConfigError> {
    let asn: u16 = global
        .try_into()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!(
                "RT extended community ASN {global} exceeds 65535 (2-octet AS sub-type)"
            ),
        })?;
    let mut b = [0u8; 8];
    b[0] = 0x00; // Transitive Two-Octet AS-Specific
    b[1] = 0x02; // Route Target
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&local.to_be_bytes());
    Ok(ExtendedCommunity::new(u64::from_be_bytes(b)))
}

/// Build a 2-octet AS Route Origin extended community.
///
/// Rejects `global` > 65535 since the 2-octet AS-Specific sub-type only
/// carries a `u16` AS number.
fn build_ro_ec(global: u32, local: u32) -> Result<ExtendedCommunity, ConfigError> {
    let asn: u16 = global
        .try_into()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!(
                "RO extended community ASN {global} exceeds 65535 (2-octet AS sub-type)"
            ),
        })?;
    let mut b = [0u8; 8];
    b[0] = 0x00; // Transitive Two-Octet AS-Specific
    b[1] = 0x03; // Route Origin
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&local.to_be_bytes());
    Ok(ExtendedCommunity::new(u64::from_be_bytes(b)))
}

/// Parse a list of address family strings into `(Afi, Safi)` pairs.
pub(super) fn parse_families(families: &[String]) -> Result<Vec<(Afi, Safi)>, ConfigError> {
    let mut result = Vec::with_capacity(families.len());
    for f in families {
        let family = match f.as_str() {
            "ipv4_unicast" => (Afi::Ipv4, Safi::Unicast),
            "ipv6_unicast" => (Afi::Ipv6, Safi::Unicast),
            "ipv4_flowspec" => (Afi::Ipv4, Safi::FlowSpec),
            "ipv6_flowspec" => (Afi::Ipv6, Safi::FlowSpec),
            other => {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "unknown address family {other:?}, expected one of: \
                         \"ipv4_unicast\", \"ipv6_unicast\", \"ipv4_flowspec\", \"ipv6_flowspec\""
                    ),
                });
            }
        };
        if !result.contains(&family) {
            result.push(family);
        }
    }
    Ok(result)
}
