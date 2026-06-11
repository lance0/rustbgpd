//! gNMI Set to ADR-0076 config-transaction translation.
//!
//! The API crate owns gNMI request normalization. This module owns the
//! daemon-local OpenConfig-to-rustbgpd candidate mapping because it needs the
//! runtime config snapshot and the config transaction controller.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

use rustbgpd_api::gnmi;
use rustbgpd_api::server::{GnmiSetError, GnmiSetOperation, GnmiSetTransaction};
use serde_json::Value;

use crate::config::{
    Config, DynamicNeighborConfig, Neighbor, PeerGroupConfig, effective_prefix_str,
};

const DEFAULT_NETWORK_INSTANCE: &str = "DEFAULT";
const DEFAULT_PROTOCOL_NAME: &str = "BGP";

#[derive(Debug, Clone, Eq, PartialEq)]
enum SetPath {
    Neighbor {
        address: IpAddr,
    },
    NeighborConfigLeaf {
        address: IpAddr,
        leaf: NeighborConfigLeaf,
    },
    PeerGroup {
        name: String,
    },
    PeerGroupConfigLeaf {
        name: String,
        leaf: PeerGroupConfigLeaf,
    },
    DynamicNeighbor {
        prefix: String,
    },
    DynamicNeighborConfigLeaf {
        prefix: String,
        leaf: DynamicNeighborConfigLeaf,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum NeighborConfigLeaf {
    NeighborAddress,
    PeerAs,
    Description,
    PeerGroup,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PeerGroupConfigLeaf {
    PeerGroupName,
    AuthPassword,
    RemovePrivateAs,
    HoldTime,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DynamicNeighborConfigLeaf {
    Prefix,
    PeerGroup,
}

#[derive(Clone)]
struct NeighborDraft {
    neighbor: Neighbor,
    has_remote_asn: bool,
}

#[derive(Clone)]
struct DynamicNeighborDraft {
    range: DynamicNeighborConfig,
    has_peer_group: bool,
}

/// Apply a normalized gNMI Set transaction to a full runtime config snapshot.
///
/// This function is intentionally pure: it does not stage or persist anything.
/// The caller must serialize the returned candidate and commit it through
/// ADR-0076.
pub(crate) fn apply_transaction_to_config(
    mut config: Config,
    transaction: &GnmiSetTransaction,
) -> Result<Config, GnmiSetError> {
    let mut drafts = std::mem::take(&mut config.neighbors)
        .into_iter()
        .map(|neighbor| NeighborDraft {
            neighbor,
            has_remote_asn: true,
        })
        .collect::<Vec<_>>();
    let mut peer_groups = std::mem::take(&mut config.peer_groups);
    let mut dynamic_drafts = std::mem::take(&mut config.dynamic_neighbors)
        .into_iter()
        .map(|range| DynamicNeighborDraft {
            has_peer_group: !range.peer_group.is_empty(),
            range,
        })
        .collect::<Vec<_>>();

    for operation in &transaction.operations {
        match operation {
            GnmiSetOperation::Delete(path) => {
                apply_delete(&mut drafts, &mut peer_groups, &mut dynamic_drafts, path)?;
            }
            GnmiSetOperation::Replace(update) | GnmiSetOperation::Update(update) => {
                apply_update(&mut drafts, &mut peer_groups, &mut dynamic_drafts, update)?;
            }
        }
    }

    config.neighbors = finalize_neighbors(drafts)?;
    config.peer_groups = peer_groups;
    config.dynamic_neighbors = finalize_dynamic_neighbors(dynamic_drafts)?;
    Ok(config)
}

fn apply_delete(
    drafts: &mut Vec<NeighborDraft>,
    peer_groups: &mut HashMap<String, PeerGroupConfig>,
    dynamic_drafts: &mut Vec<DynamicNeighborDraft>,
    path: &gnmi::Path,
) -> Result<(), GnmiSetError> {
    match parse_set_path(path)? {
        SetPath::Neighbor { address } => {
            if let Some(index) = neighbor_index(drafts, address)? {
                drafts.remove(index);
            }
            Ok(())
        }
        SetPath::NeighborConfigLeaf { .. } => Err(GnmiSetError::Unimplemented(
            "gNMI Set currently supports deleting whole static neighbor entries only".to_string(),
        )),
        SetPath::PeerGroup { name } => {
            peer_groups.remove(&name);
            Ok(())
        }
        SetPath::PeerGroupConfigLeaf { .. } => Err(GnmiSetError::Unimplemented(
            "gNMI Set currently supports deleting whole peer-group entries only".to_string(),
        )),
        SetPath::DynamicNeighbor { prefix } => {
            if let Some(index) = dynamic_neighbor_index(dynamic_drafts, &prefix) {
                dynamic_drafts.remove(index);
            }
            Ok(())
        }
        SetPath::DynamicNeighborConfigLeaf { .. } => Err(GnmiSetError::Unimplemented(
            "gNMI Set currently supports deleting whole dynamic-neighbor-prefix entries only"
                .to_string(),
        )),
    }
}

fn apply_update(
    drafts: &mut Vec<NeighborDraft>,
    peer_groups: &mut HashMap<String, PeerGroupConfig>,
    dynamic_drafts: &mut Vec<DynamicNeighborDraft>,
    update: &gnmi::Update,
) -> Result<(), GnmiSetError> {
    let path = update.path.as_ref().ok_or_else(|| {
        GnmiSetError::InvalidArgument("gNMI Set update requires a path".to_string())
    })?;
    let set_path = parse_set_path(path)?;
    let value = typed_value_to_json(update.val.as_ref().ok_or_else(|| {
        GnmiSetError::InvalidArgument("gNMI Set update requires a TypedValue".to_string())
    })?)?;
    match set_path {
        SetPath::NeighborConfigLeaf { address, leaf } => {
            apply_neighbor_leaf(drafts, address, leaf, value)
        }
        SetPath::PeerGroupConfigLeaf { name, leaf } => {
            apply_peer_group_leaf(peer_groups, &name, leaf, value)
        }
        SetPath::DynamicNeighborConfigLeaf { prefix, leaf } => {
            apply_dynamic_neighbor_leaf(dynamic_drafts, &prefix, leaf, value)
        }
        SetPath::Neighbor { .. } | SetPath::PeerGroup { .. } | SetPath::DynamicNeighbor { .. } => {
            Err(GnmiSetError::Unimplemented(
                "gNMI Set update/replace currently supports OpenConfig BGP config leaves only"
                    .to_string(),
            ))
        }
    }
}

fn apply_neighbor_leaf(
    drafts: &mut Vec<NeighborDraft>,
    address: IpAddr,
    leaf: NeighborConfigLeaf,
    value: Value,
) -> Result<(), GnmiSetError> {
    let index = ensure_neighbor_draft(drafts, address)?;
    let draft = &mut drafts[index];
    match leaf {
        NeighborConfigLeaf::NeighborAddress => {
            let configured = parse_ip_value(value, "neighbor-address")?;
            if configured != address {
                return Err(GnmiSetError::InvalidArgument(format!(
                    "neighbor-address value {configured} does not match neighbor key {address}"
                )));
            }
        }
        NeighborConfigLeaf::PeerAs => {
            draft.neighbor.remote_asn = parse_u32_value(value, "peer-as")?;
            draft.has_remote_asn = true;
        }
        NeighborConfigLeaf::Description => {
            draft.neighbor.description = Some(parse_string_value(value, "description")?);
        }
        NeighborConfigLeaf::PeerGroup => {
            draft.neighbor.peer_group = Some(parse_string_value(value, "peer-group")?);
        }
    }
    Ok(())
}

fn apply_peer_group_leaf(
    peer_groups: &mut HashMap<String, PeerGroupConfig>,
    name: &str,
    leaf: PeerGroupConfigLeaf,
    value: Value,
) -> Result<(), GnmiSetError> {
    let group = peer_groups
        .entry(name.to_string())
        .or_insert_with(empty_peer_group);
    match leaf {
        PeerGroupConfigLeaf::PeerGroupName => {
            let configured = parse_string_value(value, "peer-group-name")?;
            if configured != name {
                return Err(GnmiSetError::InvalidArgument(format!(
                    "peer-group-name value {configured:?} does not match peer-group key {name:?}"
                )));
            }
        }
        PeerGroupConfigLeaf::AuthPassword => {
            group.md5_password = Some(parse_string_value(value, "auth-password")?);
        }
        PeerGroupConfigLeaf::RemovePrivateAs => {
            group.remove_private_as = Some(parse_remove_private_as_value(value)?);
        }
        PeerGroupConfigLeaf::HoldTime => {
            group.hold_time = Some(parse_u16_value(value, "hold-time")?);
        }
    }
    Ok(())
}

fn apply_dynamic_neighbor_leaf(
    dynamic_drafts: &mut Vec<DynamicNeighborDraft>,
    prefix: &str,
    leaf: DynamicNeighborConfigLeaf,
    value: Value,
) -> Result<(), GnmiSetError> {
    let index = ensure_dynamic_neighbor_draft(dynamic_drafts, prefix);
    let draft = &mut dynamic_drafts[index];
    match leaf {
        DynamicNeighborConfigLeaf::Prefix => {
            let configured = parse_string_value(value, "prefix")?;
            let configured_key = effective_prefix_str(&configured).ok_or_else(|| {
                GnmiSetError::InvalidArgument(format!(
                    "prefix value {configured:?} is not a valid addr/len prefix"
                ))
            })?;
            // Canonical-key comparison: equivalent non-canonical forms
            // (host bits set) of the same range are a match.
            if Some(configured_key) != effective_prefix_str(prefix) {
                return Err(GnmiSetError::InvalidArgument(format!(
                    "dynamic-neighbor-prefix value {configured:?} does not match prefix key {prefix:?}"
                )));
            }
        }
        DynamicNeighborConfigLeaf::PeerGroup => {
            let peer_group = parse_string_value(value, "peer-group")?;
            let peer_group = peer_group.trim();
            if peer_group.is_empty() {
                return Err(GnmiSetError::InvalidArgument(
                    "peer-group requires a non-empty string value".to_string(),
                ));
            }
            draft.range.peer_group = peer_group.to_string();
            draft.has_peer_group = true;
        }
    }
    Ok(())
}

fn finalize_neighbors(drafts: Vec<NeighborDraft>) -> Result<Vec<Neighbor>, GnmiSetError> {
    let mut neighbors = Vec::with_capacity(drafts.len());
    for draft in drafts {
        if !draft.has_remote_asn {
            return Err(GnmiSetError::InvalidArgument(format!(
                "neighbor {} requires config/peer-as",
                draft.neighbor.address
            )));
        }
        neighbors.push(draft.neighbor);
    }
    Ok(neighbors)
}

fn finalize_dynamic_neighbors(
    drafts: Vec<DynamicNeighborDraft>,
) -> Result<Vec<DynamicNeighborConfig>, GnmiSetError> {
    let mut ranges = Vec::with_capacity(drafts.len());
    for draft in drafts {
        if !draft.has_peer_group {
            return Err(GnmiSetError::InvalidArgument(format!(
                "dynamic-neighbor-prefix {} requires config/peer-group",
                draft.range.prefix
            )));
        }
        ranges.push(draft.range);
    }
    Ok(ranges)
}

fn ensure_neighbor_draft(
    drafts: &mut Vec<NeighborDraft>,
    address: IpAddr,
) -> Result<usize, GnmiSetError> {
    if let Some(index) = neighbor_index(drafts, address)? {
        return Ok(index);
    }
    drafts.push(NeighborDraft {
        neighbor: empty_neighbor(address),
        has_remote_asn: false,
    });
    Ok(drafts.len() - 1)
}

fn ensure_dynamic_neighbor_draft(drafts: &mut Vec<DynamicNeighborDraft>, prefix: &str) -> usize {
    if let Some(index) = dynamic_neighbor_index(drafts, prefix) {
        return index;
    }
    drafts.push(DynamicNeighborDraft {
        range: empty_dynamic_neighbor(prefix),
        has_peer_group: false,
    });
    drafts.len() - 1
}

fn dynamic_neighbor_index(drafts: &[DynamicNeighborDraft], prefix: &str) -> Option<usize> {
    // Match on the canonical (masked network, length) key, not the raw
    // string, so `10.0.0.5/24` addresses the range configured as
    // `10.0.0.0/24` — the same equivalence the config validator and the
    // runtime add/delete paths use via `effective_prefix_str`.
    let key = effective_prefix_str(prefix)?;
    drafts
        .iter()
        .position(|draft| effective_prefix_str(&draft.range.prefix) == Some(key))
}

fn neighbor_index(
    drafts: &[NeighborDraft],
    address: IpAddr,
) -> Result<Option<usize>, GnmiSetError> {
    for (index, draft) in drafts.iter().enumerate() {
        let current = draft.neighbor.address.parse::<IpAddr>().map_err(|error| {
            GnmiSetError::Internal(format!(
                "runtime config contains invalid neighbor address {:?}: {error}",
                draft.neighbor.address
            ))
        })?;
        if current == address {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn empty_dynamic_neighbor(prefix: &str) -> DynamicNeighborConfig {
    DynamicNeighborConfig {
        prefix: prefix.to_string(),
        peer_group: String::new(),
        remote_asn: 0,
        description: None,
    }
}

fn empty_neighbor(address: IpAddr) -> Neighbor {
    Neighbor {
        address: address.to_string(),
        interface: None,
        remote_asn: 0,
        description: None,
        peer_group: None,
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        route_server_client: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        log_level: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
    }
}

fn empty_peer_group() -> PeerGroupConfig {
    PeerGroupConfig::default()
}

fn parse_set_path(path: &gnmi::Path) -> Result<SetPath, GnmiSetError> {
    #[allow(deprecated)]
    if !path.element.is_empty() {
        return Err(GnmiSetError::InvalidArgument(
            "legacy string path elements are not supported; use PathElem".to_string(),
        ));
    }
    if !path.origin.is_empty() && path.origin != "openconfig" {
        return Err(GnmiSetError::Unimplemented(format!(
            "unsupported gNMI Set origin {}",
            path.origin
        )));
    }
    let elem = &path.elem;
    if elem.len() < 6 {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig Set path".to_string(),
        ));
    }
    expect_no_keys(&elem[0], "network-instances")?;
    expect_key_alias(
        &elem[1],
        "network-instance",
        "name",
        &[DEFAULT_NETWORK_INSTANCE, "default"],
    )?;
    expect_no_keys(&elem[2], "protocols")?;
    expect_protocol_key(&elem[3])?;
    expect_no_keys(&elem[4], "bgp")?;
    match elem[5].name.as_str() {
        "neighbors" => parse_neighbor_set_path(&elem[5..]),
        "global" => parse_global_set_path(&elem[5..]),
        "peer-groups" => parse_peer_group_set_path(&elem[5..]),
        _ => Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP Set path".to_string(),
        )),
    }
}

fn parse_global_set_path(elem: &[gnmi::PathElem]) -> Result<SetPath, GnmiSetError> {
    if elem.len() < 3 {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP global Set path".to_string(),
        ));
    }
    expect_no_keys(&elem[0], "global")?;
    expect_no_keys(&elem[1], "dynamic-neighbor-prefixes")?;
    let prefix = expect_dynamic_neighbor_prefix_key(&elem[2])?;

    match elem.get(3).map(|tail| tail.name.as_str()) {
        None => Ok(SetPath::DynamicNeighbor { prefix }),
        Some("config") => {
            ensure_no_extra_leaf_keys(&elem[3])?;
            let Some(leaf) = elem.get(4) else {
                return Err(GnmiSetError::Unimplemented(
                    "gNMI Set currently supports dynamic-neighbor-prefix config leaves, not config container replace/update"
                        .to_string(),
                ));
            };
            if elem.len() != 5 {
                return Err(GnmiSetError::Unimplemented(
                    "unsupported OpenConfig BGP dynamic-neighbor-prefix config subtree".to_string(),
                ));
            }
            ensure_no_extra_leaf_keys(leaf)?;
            let leaf = match leaf.name.as_str() {
                "prefix" => DynamicNeighborConfigLeaf::Prefix,
                "peer-group" => DynamicNeighborConfigLeaf::PeerGroup,
                _ => {
                    return Err(GnmiSetError::Unimplemented(
                        "unsupported OpenConfig BGP dynamic-neighbor-prefix config leaf"
                            .to_string(),
                    ));
                }
            };
            Ok(SetPath::DynamicNeighborConfigLeaf { prefix, leaf })
        }
        Some("state") => Err(GnmiSetError::Unimplemented(
            "OpenConfig dynamic-neighbor-prefix state is not supported by gNMI Set".to_string(),
        )),
        _ => Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP dynamic-neighbor-prefix Set path".to_string(),
        )),
    }
}

fn parse_neighbor_set_path(elem: &[gnmi::PathElem]) -> Result<SetPath, GnmiSetError> {
    if elem.len() < 2 {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP neighbor Set path".to_string(),
        ));
    }
    expect_no_keys(&elem[0], "neighbors")?;
    let address = expect_neighbor_key(&elem[1])?;
    reject_link_local(address)?;

    match elem.get(2).map(|tail| tail.name.as_str()) {
        None => Ok(SetPath::Neighbor { address }),
        Some("config") => {
            ensure_no_extra_leaf_keys(&elem[2])?;
            let Some(leaf) = elem.get(3) else {
                return Err(GnmiSetError::Unimplemented(
                    "gNMI Set currently supports neighbor config leaves, not config container replace/update"
                        .to_string(),
                ));
            };
            if elem.len() != 4 {
                return Err(GnmiSetError::Unimplemented(
                    "unsupported OpenConfig BGP neighbor config subtree".to_string(),
                ));
            }
            ensure_no_extra_leaf_keys(leaf)?;
            let leaf = match leaf.name.as_str() {
                "neighbor-address" => NeighborConfigLeaf::NeighborAddress,
                "peer-as" => NeighborConfigLeaf::PeerAs,
                "description" => NeighborConfigLeaf::Description,
                "peer-group" => NeighborConfigLeaf::PeerGroup,
                "enabled" => {
                    return Err(GnmiSetError::Unimplemented(
                        "OpenConfig neighbor config/enabled is not supported by gNMI Set yet; use runtime admin enable/disable APIs"
                            .to_string(),
                    ));
                }
                "local-as" => {
                    return Err(GnmiSetError::Unimplemented(
                        "OpenConfig neighbor config/local-as is not supported; rustbgpd is single-AS"
                            .to_string(),
                    ));
                }
                _ => {
                    return Err(GnmiSetError::Unimplemented(
                        "unsupported OpenConfig BGP neighbor config leaf".to_string(),
                    ));
                }
            };
            Ok(SetPath::NeighborConfigLeaf { address, leaf })
        }
        _ => Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP neighbor Set path".to_string(),
        )),
    }
}

fn parse_peer_group_set_path(elem: &[gnmi::PathElem]) -> Result<SetPath, GnmiSetError> {
    if elem.len() < 2 {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP peer-group Set path".to_string(),
        ));
    }
    expect_no_keys(&elem[0], "peer-groups")?;
    let name = expect_peer_group_key(&elem[1])?;

    match elem.get(2).map(|tail| tail.name.as_str()) {
        None => Ok(SetPath::PeerGroup { name }),
        Some("config") => {
            ensure_no_extra_leaf_keys(&elem[2])?;
            let Some(leaf) = elem.get(3) else {
                return Err(GnmiSetError::Unimplemented(
                    "gNMI Set currently supports peer-group config leaves, not config container replace/update"
                        .to_string(),
                ));
            };
            if elem.len() != 4 {
                return Err(GnmiSetError::Unimplemented(
                    "unsupported OpenConfig BGP peer-group config subtree".to_string(),
                ));
            }
            ensure_no_extra_leaf_keys(leaf)?;
            let leaf = match leaf.name.as_str() {
                "peer-group-name" => PeerGroupConfigLeaf::PeerGroupName,
                "auth-password" => PeerGroupConfigLeaf::AuthPassword,
                "remove-private-as" => PeerGroupConfigLeaf::RemovePrivateAs,
                "peer-as"
                | "local-as"
                | "peer-type"
                | "send-community"
                | "send-community-type"
                | "description" => {
                    return Err(GnmiSetError::Unimplemented(format!(
                        "OpenConfig peer-group config/{} is not supported by gNMI Set yet",
                        leaf.name
                    )));
                }
                _ => {
                    return Err(GnmiSetError::Unimplemented(
                        "unsupported OpenConfig BGP peer-group config leaf".to_string(),
                    ));
                }
            };
            Ok(SetPath::PeerGroupConfigLeaf { name, leaf })
        }
        Some("timers") => {
            ensure_no_extra_leaf_keys(&elem[2])?;
            if elem.len() != 5 {
                return Err(GnmiSetError::Unimplemented(
                    "unsupported OpenConfig BGP peer-group timers subtree".to_string(),
                ));
            }
            expect_no_keys(&elem[3], "config")?;
            ensure_no_extra_leaf_keys(&elem[4])?;
            match elem[4].name.as_str() {
                "hold-time" => Ok(SetPath::PeerGroupConfigLeaf {
                    name,
                    leaf: PeerGroupConfigLeaf::HoldTime,
                }),
                _ => Err(GnmiSetError::Unimplemented(
                    "unsupported OpenConfig BGP peer-group timers config leaf".to_string(),
                )),
            }
        }
        _ => Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP peer-group Set path".to_string(),
        )),
    }
}

fn expect_no_keys(elem: &gnmi::PathElem, name: &str) -> Result<(), GnmiSetError> {
    if elem.name != name {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig Set path".to_string(),
        ));
    }
    ensure_no_extra_leaf_keys(elem)
}

fn expect_key_alias(
    elem: &gnmi::PathElem,
    name: &str,
    key: &str,
    values: &[&str],
) -> Result<(), GnmiSetError> {
    if elem.name != name {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig Set path".to_string(),
        ));
    }
    if elem.key.len() != 1 || !elem.key.contains_key(key) {
        return Err(GnmiSetError::InvalidArgument(format!(
            "{name} requires only the {key} key"
        )));
    }
    let value = &elem.key[key];
    if values.iter().any(|candidate| value == candidate) {
        Ok(())
    } else {
        Err(GnmiSetError::Unimplemented(format!(
            "{name}[{key}={value}] is not supported"
        )))
    }
}

fn expect_protocol_key(elem: &gnmi::PathElem) -> Result<(), GnmiSetError> {
    if elem.name != "protocol" {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig Set path".to_string(),
        ));
    }
    if elem.key.len() != 2 || !elem.key.contains_key("identifier") || !elem.key.contains_key("name")
    {
        return Err(GnmiSetError::InvalidArgument(
            "protocol requires identifier and name keys".to_string(),
        ));
    }
    let identifier = &elem.key["identifier"];
    if !matches!(
        identifier.as_str(),
        "BGP" | "openconfig-policy-types:BGP" | "oc-pol-types:BGP"
    ) {
        return Err(GnmiSetError::Unimplemented(format!(
            "protocol identifier {identifier} is not supported"
        )));
    }
    let name = &elem.key["name"];
    if name != DEFAULT_PROTOCOL_NAME {
        return Err(GnmiSetError::Unimplemented(format!(
            "protocol name {name} is not supported"
        )));
    }
    Ok(())
}

fn expect_neighbor_key(elem: &gnmi::PathElem) -> Result<IpAddr, GnmiSetError> {
    if elem.name != "neighbor" {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP neighbors Set path".to_string(),
        ));
    }
    if elem.key.len() != 1 || !elem.key.contains_key("neighbor-address") {
        return Err(GnmiSetError::InvalidArgument(
            "neighbor requires only the neighbor-address key".to_string(),
        ));
    }
    let raw = &elem.key["neighbor-address"];
    if raw == "*" {
        return Err(GnmiSetError::InvalidArgument(
            "gNMI Set does not support wildcard neighbor-address".to_string(),
        ));
    }
    raw.parse::<IpAddr>()
        .map_err(|_| GnmiSetError::InvalidArgument(format!("invalid neighbor-address key {raw}")))
}

fn expect_dynamic_neighbor_prefix_key(elem: &gnmi::PathElem) -> Result<String, GnmiSetError> {
    if elem.name != "dynamic-neighbor-prefix" {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP dynamic-neighbor-prefixes Set path".to_string(),
        ));
    }
    if elem.key.len() != 1 || !elem.key.contains_key("prefix") {
        return Err(GnmiSetError::InvalidArgument(
            "dynamic-neighbor-prefix requires only the prefix key".to_string(),
        ));
    }
    let prefix = elem.key["prefix"].trim();
    if prefix.is_empty() || prefix == "*" {
        return Err(GnmiSetError::InvalidArgument(
            "dynamic-neighbor-prefix key must be a non-empty literal".to_string(),
        ));
    }
    if effective_prefix_str(prefix).is_none() {
        return Err(GnmiSetError::InvalidArgument(format!(
            "dynamic-neighbor-prefix key {prefix:?} is not a valid addr/len prefix"
        )));
    }
    Ok(prefix.to_string())
}

fn expect_peer_group_key(elem: &gnmi::PathElem) -> Result<String, GnmiSetError> {
    if elem.name != "peer-group" {
        return Err(GnmiSetError::Unimplemented(
            "unsupported OpenConfig BGP peer-groups Set path".to_string(),
        ));
    }
    if elem.key.len() != 1 || !elem.key.contains_key("peer-group-name") {
        return Err(GnmiSetError::InvalidArgument(
            "peer-group requires only the peer-group-name key".to_string(),
        ));
    }
    let name = elem.key["peer-group-name"].trim();
    if name.is_empty() || name == "*" {
        return Err(GnmiSetError::InvalidArgument(
            "peer-group-name key must be a non-empty literal".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn ensure_no_extra_leaf_keys(elem: &gnmi::PathElem) -> Result<(), GnmiSetError> {
    if elem.key.is_empty() {
        Ok(())
    } else {
        Err(GnmiSetError::InvalidArgument(format!(
            "{} does not accept keys",
            elem.name
        )))
    }
}

fn reject_link_local(address: IpAddr) -> Result<(), GnmiSetError> {
    if matches!(address, IpAddr::V6(addr) if is_ipv6_link_local(addr)) {
        return Err(GnmiSetError::Unimplemented(
            "gNMI Set for IPv6 link-local/BGP unnumbered neighbors requires an interface and is not supported yet"
                .to_string(),
        ));
    }
    Ok(())
}

const fn is_ipv6_link_local(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

fn typed_value_to_json(value: &gnmi::TypedValue) -> Result<Value, GnmiSetError> {
    let Some(value) = value.value.as_ref() else {
        return Err(GnmiSetError::InvalidArgument(
            "gNMI Set update requires a TypedValue value".to_string(),
        ));
    };
    match value {
        gnmi::typed_value::Value::StringVal(value) => Ok(Value::String(value.clone())),
        gnmi::typed_value::Value::IntVal(value) => Ok(Value::Number((*value).into())),
        gnmi::typed_value::Value::UintVal(value) => {
            Ok(Value::Number(serde_json::Number::from(*value)))
        }
        gnmi::typed_value::Value::JsonVal(bytes) | gnmi::typed_value::Value::JsonIetfVal(bytes) => {
            serde_json::from_slice(bytes).map_err(|error| {
                GnmiSetError::InvalidArgument(format!("invalid JSON value: {error}"))
            })
        }
        _ => Err(GnmiSetError::InvalidArgument(
            "unsupported gNMI Set TypedValue for OpenConfig BGP config".to_string(),
        )),
    }
}

fn parse_string_value(value: Value, leaf: &str) -> Result<String, GnmiSetError> {
    match value {
        Value::String(value) => Ok(value),
        _ => Err(GnmiSetError::InvalidArgument(format!(
            "{leaf} requires a string value"
        ))),
    }
}

fn parse_ip_value(value: Value, leaf: &str) -> Result<IpAddr, GnmiSetError> {
    let raw = parse_string_value(value, leaf)?;
    raw.parse::<IpAddr>()
        .map_err(|_| GnmiSetError::InvalidArgument(format!("{leaf} requires an IP address")))
}

fn parse_u32_value(value: Value, leaf: &str) -> Result<u32, GnmiSetError> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                GnmiSetError::InvalidArgument(format!("{leaf} requires a uint32 value"))
            }),
        Value::String(value) => value
            .parse::<u32>()
            .map_err(|_| GnmiSetError::InvalidArgument(format!("{leaf} requires a uint32 value"))),
        _ => Err(GnmiSetError::InvalidArgument(format!(
            "{leaf} requires a uint32 value"
        ))),
    }
}

fn parse_u16_value(value: Value, leaf: &str) -> Result<u16, GnmiSetError> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                GnmiSetError::InvalidArgument(format!("{leaf} requires a uint16 value"))
            }),
        Value::String(value) => value
            .parse::<u16>()
            .map_err(|_| GnmiSetError::InvalidArgument(format!("{leaf} requires a uint16 value"))),
        _ => Err(GnmiSetError::InvalidArgument(format!(
            "{leaf} requires a uint16 value"
        ))),
    }
}

fn parse_remove_private_as_value(value: Value) -> Result<String, GnmiSetError> {
    let raw = parse_string_value(value, "remove-private-as")?;
    let identity = raw.rsplit(':').next().unwrap_or(&raw);
    match identity.to_ascii_uppercase().as_str() {
        "PRIVATE_AS_REMOVE" | "REMOVE" => Ok("remove".to_string()),
        "PRIVATE_AS_REMOVE_ALL" | "REMOVE_ALL" | "ALL" => Ok("all".to_string()),
        "PRIVATE_AS_REPLACE_ALL" | "REPLACE_ALL" | "REPLACE" => Ok("replace".to_string()),
        _ => Ok(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use rustbgpd_api::gnmi::typed_value::Value as TypedValue;

    fn base_config() -> Config {
        toml::from_str(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 1179

[global.telemetry]
log_format = "plain"

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
description = "old"
"#,
        )
        .unwrap()
    }

    fn bgp_prefix_elem() -> Vec<gnmi::PathElem> {
        vec![
            pe("network-instances"),
            keyed_pe("network-instance", "name", "DEFAULT"),
            pe("protocols"),
            protocol_pe(),
            pe("bgp"),
        ]
    }

    fn path(address: &str, tail: &[&str]) -> gnmi::Path {
        let mut elem = bgp_prefix_elem();
        elem.push(pe("neighbors"));
        elem.push(keyed_pe("neighbor", "neighbor-address", address));
        elem.extend(tail.iter().map(|name| pe(name)));
        gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem,
            target: String::new(),
        }
    }

    fn peer_group_path(name: &str, tail: &[&str]) -> gnmi::Path {
        let mut elem = bgp_prefix_elem();
        elem.push(pe("peer-groups"));
        elem.push(keyed_pe("peer-group", "peer-group-name", name));
        elem.extend(tail.iter().map(|name| pe(name)));
        gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem,
            target: String::new(),
        }
    }

    fn dynamic_neighbor_path(prefix: &str, tail: &[&str]) -> gnmi::Path {
        let mut elem = bgp_prefix_elem();
        elem.push(pe("global"));
        elem.push(pe("dynamic-neighbor-prefixes"));
        elem.push(keyed_pe("dynamic-neighbor-prefix", "prefix", prefix));
        elem.extend(tail.iter().map(|name| pe(name)));
        gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem,
            target: String::new(),
        }
    }

    fn update(address: &str, leaf: &str, value: TypedValue) -> GnmiSetOperation {
        GnmiSetOperation::Update(gnmi::Update {
            path: Some(path(address, &["config", leaf])),
            #[allow(deprecated)]
            value: None,
            val: Some(gnmi::TypedValue { value: Some(value) }),
            duplicates: 0,
        })
    }

    fn peer_group_update(name: &str, tail: &[&str], value: TypedValue) -> GnmiSetOperation {
        GnmiSetOperation::Update(gnmi::Update {
            path: Some(peer_group_path(name, tail)),
            #[allow(deprecated)]
            value: None,
            val: Some(gnmi::TypedValue { value: Some(value) }),
            duplicates: 0,
        })
    }

    fn dynamic_neighbor_update(prefix: &str, tail: &[&str], value: TypedValue) -> GnmiSetOperation {
        GnmiSetOperation::Update(gnmi::Update {
            path: Some(dynamic_neighbor_path(prefix, tail)),
            #[allow(deprecated)]
            value: None,
            val: Some(gnmi::TypedValue { value: Some(value) }),
            duplicates: 0,
        })
    }

    fn transaction(operations: Vec<GnmiSetOperation>) -> GnmiSetTransaction {
        GnmiSetTransaction {
            prefix: None,
            operations,
            commit_action: None,
        }
    }

    fn pe(name: &str) -> gnmi::PathElem {
        gnmi::PathElem {
            name: name.to_string(),
            key: HashMap::new(),
        }
    }

    fn keyed_pe(name: &str, key: &str, value: &str) -> gnmi::PathElem {
        gnmi::PathElem {
            name: name.to_string(),
            key: HashMap::from([(key.to_string(), value.to_string())]),
        }
    }

    fn protocol_pe() -> gnmi::PathElem {
        gnmi::PathElem {
            name: "protocol".to_string(),
            key: HashMap::from([
                ("identifier".to_string(), "BGP".to_string()),
                ("name".to_string(), "BGP".to_string()),
            ]),
        }
    }

    #[test]
    fn set_peer_as_creates_static_neighbor() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![update(
                "192.0.2.2",
                "peer-as",
                TypedValue::UintVal(65003),
            )]),
        )
        .unwrap();

        let neighbor = candidate
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == "192.0.2.2")
            .unwrap();
        assert_eq!(neighbor.remote_asn, 65003);
    }

    #[test]
    fn set_updates_description_and_peer_group() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![
                update(
                    "192.0.2.1",
                    "description",
                    TypedValue::JsonIetfVal(br#""new""#.to_vec()),
                ),
                update(
                    "192.0.2.1",
                    "peer-group",
                    TypedValue::StringVal("rs-clients".to_string()),
                ),
            ]),
        )
        .unwrap();

        let neighbor = &candidate.neighbors[0];
        assert_eq!(neighbor.description.as_deref(), Some("new"));
        assert_eq!(neighbor.peer_group.as_deref(), Some("rs-clients"));
    }

    #[test]
    fn set_delete_neighbor_removes_entry() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![GnmiSetOperation::Delete(path("192.0.2.1", &[]))]),
        )
        .unwrap();

        assert!(candidate.neighbors.is_empty());
    }

    #[test]
    fn set_delete_missing_neighbor_is_silent() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![GnmiSetOperation::Delete(path("192.0.2.99", &[]))]),
        )
        .unwrap();

        assert_eq!(candidate.neighbors.len(), 1);
    }

    #[test]
    fn set_rejects_neighbor_address_mismatch() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![update(
                "192.0.2.1",
                "neighbor-address",
                TypedValue::StringVal("192.0.2.2".to_string()),
            )]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("does not match neighbor key"));
    }

    #[test]
    fn set_rejects_enabled_until_durable_model_exists() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![update(
                "192.0.2.1",
                "enabled",
                TypedValue::BoolVal(false),
            )]),
        )
        .unwrap_err();

        assert!(matches!(error, GnmiSetError::Unimplemented(_)));
        assert!(error.to_string().contains("enabled"));
    }

    #[test]
    fn set_rejects_link_local_without_interface_identity() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![update(
                "fe80::1",
                "peer-as",
                TypedValue::UintVal(65003),
            )]),
        )
        .unwrap_err();

        assert!(matches!(error, GnmiSetError::Unimplemented(_)));
        assert!(error.to_string().contains("link-local"));
    }

    #[test]
    fn set_peer_group_name_creates_peer_group() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![peer_group_update(
                "rs-clients",
                &["config", "peer-group-name"],
                TypedValue::StringVal("rs-clients".to_string()),
            )]),
        )
        .unwrap();

        assert!(candidate.peer_groups.contains_key("rs-clients"));
    }

    #[test]
    fn set_peer_group_updates_supported_config_leaves() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![
                peer_group_update(
                    "rs-clients",
                    &["config", "auth-password"],
                    TypedValue::StringVal("secret".to_string()),
                ),
                peer_group_update(
                    "rs-clients",
                    &["config", "remove-private-as"],
                    TypedValue::StringVal("PRIVATE_AS_REMOVE_ALL".to_string()),
                ),
                peer_group_update(
                    "rs-clients",
                    &["timers", "config", "hold-time"],
                    TypedValue::UintVal(45),
                ),
            ]),
        )
        .unwrap();

        let group = candidate.peer_groups.get("rs-clients").unwrap();
        assert_eq!(group.md5_password.as_deref(), Some("secret"));
        assert_eq!(group.remove_private_as.as_deref(), Some("all"));
        assert_eq!(group.hold_time, Some(45));
    }

    #[test]
    fn set_peer_group_unknown_remove_private_as_identity_is_rejected_downstream() {
        // The bridge passes an unrecognized identity through verbatim —
        // it must never be silently mapped to a known mode (or to
        // disabled). The ADR-0076 candidate validation then rejects the
        // transaction with the config-level unknown-mode diagnostic,
        // which the commit path surfaces as InvalidArgument.
        let mut candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![peer_group_update(
                "rs-clients",
                &["config", "remove-private-as"],
                TypedValue::StringVal("openconfig-bgp-types:PRIVATE_AS_KEEP".to_string()),
            )]),
        )
        .unwrap();
        // Keep the round-trip focused on the leaf under test: the bare
        // test config has no gRPC roles, which tier enforcement (the
        // serialized default) would reject before reaching the
        // remove-private-as validation.
        candidate.security.grpc.enforcement = crate::config::GrpcEnforcementConfig::Legacy;
        let group = candidate.peer_groups.get("rs-clients").unwrap();
        assert_eq!(
            group.remove_private_as.as_deref(),
            Some("openconfig-bgp-types:PRIVATE_AS_KEEP"),
            "unknown identity must pass through verbatim, never coerced"
        );

        let candidate_toml = toml::to_string_pretty(&candidate).unwrap();
        let error =
            Config::load_toml_with_diagnostics(&candidate_toml, "gnmi set candidate").unwrap_err();
        assert!(
            error.contains("unknown mode"),
            "candidate validation must reject the unknown identity, got: {error}"
        );
    }

    #[test]
    fn set_peer_group_delete_removes_entry() {
        let mut config = base_config();
        config
            .peer_groups
            .insert("rs-clients".to_string(), empty_peer_group());

        let candidate = apply_transaction_to_config(
            config,
            &transaction(vec![GnmiSetOperation::Delete(peer_group_path(
                "rs-clients",
                &[],
            ))]),
        )
        .unwrap();

        assert!(!candidate.peer_groups.contains_key("rs-clients"));
    }

    #[test]
    fn set_peer_group_delete_missing_is_silent() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![GnmiSetOperation::Delete(peer_group_path(
                "missing",
                &[],
            ))]),
        )
        .unwrap();

        assert!(candidate.peer_groups.is_empty());
    }

    #[test]
    fn set_rejects_peer_group_name_mismatch() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![peer_group_update(
                "rs-clients",
                &["config", "peer-group-name"],
                TypedValue::StringVal("other".to_string()),
            )]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("does not match peer-group key"));
    }

    #[test]
    fn set_rejects_peer_group_peer_as_until_native_model_exists() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![peer_group_update(
                "rs-clients",
                &["config", "peer-as"],
                TypedValue::UintVal(65002),
            )]),
        )
        .unwrap_err();

        assert!(matches!(error, GnmiSetError::Unimplemented(_)));
        assert!(error.to_string().contains("peer-as"));
    }

    #[test]
    fn set_dynamic_neighbor_creates_range_with_accept_any_asn_default() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![
                dynamic_neighbor_update(
                    "10.0.0.0/24",
                    &["config", "prefix"],
                    TypedValue::StringVal("10.0.0.0/24".to_string()),
                ),
                dynamic_neighbor_update(
                    "10.0.0.0/24",
                    &["config", "peer-group"],
                    TypedValue::StringVal(" ix-members ".to_string()),
                ),
            ]),
        )
        .unwrap();

        assert_eq!(candidate.dynamic_neighbors.len(), 1);
        let range = &candidate.dynamic_neighbors[0];
        assert_eq!(range.prefix, "10.0.0.0/24");
        assert_eq!(range.peer_group, "ix-members");
        assert_eq!(range.remote_asn, 0);
        assert_eq!(range.description, None);
    }

    #[test]
    fn set_dynamic_neighbor_updates_peer_group_preserving_native_fields() {
        let mut config = base_config();
        config.dynamic_neighbors.push(DynamicNeighborConfig {
            prefix: "10.0.0.0/24".to_string(),
            peer_group: "old".to_string(),
            remote_asn: 65010,
            description: Some("existing".to_string()),
        });

        let candidate = apply_transaction_to_config(
            config,
            &transaction(vec![dynamic_neighbor_update(
                "10.0.0.0/24",
                &["config", "peer-group"],
                TypedValue::StringVal("new".to_string()),
            )]),
        )
        .unwrap();

        let range = &candidate.dynamic_neighbors[0];
        assert_eq!(range.peer_group, "new");
        assert_eq!(range.remote_asn, 65010);
        assert_eq!(range.description.as_deref(), Some("existing"));
    }

    #[test]
    fn set_dynamic_neighbor_delete_removes_range() {
        let mut config = base_config();
        config.dynamic_neighbors.push(DynamicNeighborConfig {
            prefix: "10.0.0.0/24".to_string(),
            peer_group: "ix-members".to_string(),
            remote_asn: 0,
            description: None,
        });

        let candidate = apply_transaction_to_config(
            config,
            &transaction(vec![GnmiSetOperation::Delete(dynamic_neighbor_path(
                "10.0.0.0/24",
                &[],
            ))]),
        )
        .unwrap();

        assert!(candidate.dynamic_neighbors.is_empty());
    }

    #[test]
    fn set_dynamic_neighbor_delete_missing_is_silent() {
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![GnmiSetOperation::Delete(dynamic_neighbor_path(
                "10.0.0.0/24",
                &[],
            ))]),
        )
        .unwrap();

        assert!(candidate.dynamic_neighbors.is_empty());
    }

    #[test]
    fn set_dynamic_neighbor_noncanonical_key_matches_configured_range() {
        // `10.0.0.5/24` and `10.0.0.0/24` cover the identical address
        // set (host bits are masked off, the same canonical key the
        // config validator uses) — the update must address the existing
        // range, not create a duplicate draft.
        let mut config = base_config();
        config.dynamic_neighbors.push(DynamicNeighborConfig {
            prefix: "10.0.0.0/24".to_string(),
            peer_group: "old".to_string(),
            remote_asn: 65010,
            description: Some("existing".to_string()),
        });

        let candidate = apply_transaction_to_config(
            config,
            &transaction(vec![dynamic_neighbor_update(
                "10.0.0.5/24",
                &["config", "peer-group"],
                TypedValue::StringVal("new".to_string()),
            )]),
        )
        .unwrap();

        assert_eq!(candidate.dynamic_neighbors.len(), 1);
        let range = &candidate.dynamic_neighbors[0];
        assert_eq!(range.prefix, "10.0.0.0/24");
        assert_eq!(range.peer_group, "new");
        assert_eq!(range.remote_asn, 65010);
    }

    #[test]
    fn set_dynamic_neighbor_delete_matches_noncanonical_key() {
        let mut config = base_config();
        config.dynamic_neighbors.push(DynamicNeighborConfig {
            prefix: "10.0.0.0/24".to_string(),
            peer_group: "ix-members".to_string(),
            remote_asn: 0,
            description: None,
        });

        let candidate = apply_transaction_to_config(
            config,
            &transaction(vec![GnmiSetOperation::Delete(dynamic_neighbor_path(
                "10.0.0.5/24",
                &[],
            ))]),
        )
        .unwrap();

        assert!(candidate.dynamic_neighbors.is_empty());
    }

    #[test]
    fn set_dynamic_neighbor_prefix_leaf_accepts_equivalent_form() {
        // Value and key with the same canonical prefix are a match even
        // when the raw strings differ.
        let candidate = apply_transaction_to_config(
            base_config(),
            &transaction(vec![
                dynamic_neighbor_update(
                    "10.0.0.0/24",
                    &["config", "prefix"],
                    TypedValue::StringVal("10.0.0.5/24".to_string()),
                ),
                dynamic_neighbor_update(
                    "10.0.0.0/24",
                    &["config", "peer-group"],
                    TypedValue::StringVal("ix-members".to_string()),
                ),
            ]),
        )
        .unwrap();

        assert_eq!(candidate.dynamic_neighbors.len(), 1);
        assert_eq!(candidate.dynamic_neighbors[0].peer_group, "ix-members");
    }

    #[test]
    fn set_rejects_unparseable_dynamic_neighbor_prefix_key() {
        for bad in ["not-a-prefix", "10.0.0.0/40", "10.0.0.0"] {
            let error = apply_transaction_to_config(
                base_config(),
                &transaction(vec![dynamic_neighbor_update(
                    bad,
                    &["config", "peer-group"],
                    TypedValue::StringVal("ix-members".to_string()),
                )]),
            )
            .unwrap_err();

            assert!(
                matches!(error, GnmiSetError::InvalidArgument(_)),
                "key {bad:?}: expected InvalidArgument, got {error:?}"
            );
            assert!(
                error.to_string().contains("not a valid addr/len prefix"),
                "key {bad:?}: unexpected message {error}"
            );
        }
    }

    #[test]
    fn set_rejects_unparseable_dynamic_neighbor_prefix_value() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![dynamic_neighbor_update(
                "10.0.0.0/24",
                &["config", "prefix"],
                TypedValue::StringVal("10.0.0.0/40".to_string()),
            )]),
        )
        .unwrap_err();

        assert!(matches!(error, GnmiSetError::InvalidArgument(_)));
        assert!(error.to_string().contains("not a valid addr/len prefix"));
    }

    #[test]
    fn set_rejects_dynamic_neighbor_prefix_mismatch() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![dynamic_neighbor_update(
                "10.0.0.0/24",
                &["config", "prefix"],
                TypedValue::StringVal("10.0.1.0/24".to_string()),
            )]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("does not match prefix key"));
    }

    #[test]
    fn set_rejects_dynamic_neighbor_missing_peer_group() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![dynamic_neighbor_update(
                "10.0.0.0/24",
                &["config", "prefix"],
                TypedValue::StringVal("10.0.0.0/24".to_string()),
            )]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires config/peer-group"));
    }

    #[test]
    fn set_rejects_dynamic_neighbor_state_path() {
        let error = apply_transaction_to_config(
            base_config(),
            &transaction(vec![GnmiSetOperation::Delete(dynamic_neighbor_path(
                "10.0.0.0/24",
                &["state"],
            ))]),
        )
        .unwrap_err();

        assert!(matches!(error, GnmiSetError::Unimplemented(_)));
        assert!(error.to_string().contains("state"));
    }
}
