//! gNMI Set to ADR-0076 config-transaction translation.
//!
//! The API crate owns gNMI request normalization. This module owns the
//! daemon-local OpenConfig-to-rustbgpd candidate mapping because it needs the
//! runtime config snapshot and the config transaction controller.

use std::net::{IpAddr, Ipv6Addr};

use rustbgpd_api::gnmi;
use rustbgpd_api::server::{GnmiSetError, GnmiSetOperation, GnmiSetTransaction};
use serde_json::Value;

use crate::config::{Config, Neighbor};

const DEFAULT_NETWORK_INSTANCE: &str = "DEFAULT";
const DEFAULT_PROTOCOL_NAME: &str = "BGP";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SetPath {
    Neighbor {
        address: IpAddr,
    },
    NeighborConfigLeaf {
        address: IpAddr,
        leaf: NeighborConfigLeaf,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum NeighborConfigLeaf {
    NeighborAddress,
    PeerAs,
    Description,
    PeerGroup,
}

#[derive(Clone)]
struct NeighborDraft {
    neighbor: Neighbor,
    has_remote_asn: bool,
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
    let mut drafts = config
        .neighbors
        .into_iter()
        .map(|neighbor| NeighborDraft {
            neighbor,
            has_remote_asn: true,
        })
        .collect::<Vec<_>>();

    for operation in &transaction.operations {
        match operation {
            GnmiSetOperation::Delete(path) => apply_delete(&mut drafts, path)?,
            GnmiSetOperation::Replace(update) | GnmiSetOperation::Update(update) => {
                apply_update(&mut drafts, update)?;
            }
        }
    }

    config.neighbors = finalize_neighbors(drafts)?;
    Ok(config)
}

fn apply_delete(drafts: &mut Vec<NeighborDraft>, path: &gnmi::Path) -> Result<(), GnmiSetError> {
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
    }
}

fn apply_update(
    drafts: &mut Vec<NeighborDraft>,
    update: &gnmi::Update,
) -> Result<(), GnmiSetError> {
    let path = update.path.as_ref().ok_or_else(|| {
        GnmiSetError::InvalidArgument("gNMI Set update requires a path".to_string())
    })?;
    let SetPath::NeighborConfigLeaf { address, leaf } = parse_set_path(path)? else {
        return Err(GnmiSetError::Unimplemented(
            "gNMI Set update/replace currently supports static neighbor config leaves only"
                .to_string(),
        ));
    };
    let value = typed_value_to_json(update.val.as_ref().ok_or_else(|| {
        GnmiSetError::InvalidArgument("gNMI Set update requires a TypedValue".to_string())
    })?)?;
    apply_neighbor_leaf(drafts, address, leaf, value)
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
        remove_private_as: None,
        add_path: None,
        log_level: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
    }
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
    if elem.len() < 7 {
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
    expect_no_keys(&elem[5], "neighbors")?;
    let address = expect_neighbor_key(&elem[6])?;
    reject_link_local(address)?;

    match elem.get(7).map(|tail| tail.name.as_str()) {
        None => Ok(SetPath::Neighbor { address }),
        Some("config") => {
            ensure_no_extra_leaf_keys(&elem[7])?;
            let Some(leaf) = elem.get(8) else {
                return Err(GnmiSetError::Unimplemented(
                    "gNMI Set currently supports neighbor config leaves, not config container replace/update"
                        .to_string(),
                ));
            };
            if elem.len() != 9 {
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
            "unsupported gNMI Set TypedValue for OpenConfig BGP neighbor config".to_string(),
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

    fn path(address: &str, tail: &[&str]) -> gnmi::Path {
        let mut elem = vec![
            pe("network-instances"),
            keyed_pe("network-instance", "name", "DEFAULT"),
            pe("protocols"),
            protocol_pe(),
            pe("bgp"),
            pe("neighbors"),
            keyed_pe("neighbor", "neighbor-address", address),
        ];
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

    fn transaction(operations: Vec<GnmiSetOperation>) -> GnmiSetTransaction {
        GnmiSetTransaction {
            prefix: None,
            operations,
            extensions: Vec::new(),
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
}
