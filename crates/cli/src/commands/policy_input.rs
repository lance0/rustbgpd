//! JSON deserialization for policy statements.
//!
//! Operators feed policy / peer-group / neighbor-set definitions to
//! `rbgp ... set` via `--from-file <PATH>`. The file is JSON
//! whose shape mirrors the corresponding proto message; we deserialize
//! into local serde-friendly mirrors and convert into the proto types
//! used on the wire. Keeping the conversion explicit (rather than
//! re-deriving Serialize/Deserialize on the prost-generated structs)
//! lets us emit better error messages and stay decoupled from the proto
//! crate's optionality conventions (proto3 `optional` → `Option<T>` on
//! Rust prost types).

use serde::Deserialize;

use crate::error::CliError;
use crate::proto;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPolicyDefinition {
    pub default_action: String,
    #[serde(default)]
    pub statements: Vec<JsonPolicyStatement>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPolicyStatement {
    pub action: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub ge: Option<u32>,
    #[serde(default)]
    pub le: Option<u32>,
    #[serde(default)]
    pub match_community: Vec<String>,
    #[serde(default)]
    pub match_as_path: Option<String>,
    #[serde(default)]
    pub match_as_path_length_ge: Option<u32>,
    #[serde(default)]
    pub match_as_path_length_le: Option<u32>,
    #[serde(default)]
    pub match_rpki_validation: Option<String>,
    #[serde(default)]
    pub match_aspa_validation: Option<String>,
    #[serde(default)]
    pub match_neighbor_set: Option<String>,
    #[serde(default)]
    pub match_route_type: Option<String>,
    #[serde(default)]
    pub match_evpn_route_type: Option<u32>,
    #[serde(default)]
    pub match_local_pref_ge: Option<u32>,
    #[serde(default)]
    pub match_local_pref_le: Option<u32>,
    #[serde(default)]
    pub match_med_ge: Option<u32>,
    #[serde(default)]
    pub match_med_le: Option<u32>,
    #[serde(default)]
    pub match_next_hop: Option<String>,
    #[serde(default)]
    pub set_local_pref: Option<u32>,
    #[serde(default)]
    pub set_med: Option<u32>,
    #[serde(default)]
    pub set_next_hop: Option<String>,
    #[serde(default)]
    pub set_community_add: Vec<String>,
    #[serde(default)]
    pub set_community_remove: Vec<String>,
    #[serde(default)]
    pub set_as_path_prepend: Option<JsonAsPathPrepend>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonAsPathPrepend {
    pub asn: u32,
    pub count: u32,
}

impl From<JsonPolicyDefinition> for proto::PolicyDefinition {
    fn from(j: JsonPolicyDefinition) -> Self {
        proto::PolicyDefinition {
            default_action: j.default_action,
            statements: j.statements.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<JsonPolicyStatement> for proto::PolicyStatement {
    fn from(j: JsonPolicyStatement) -> Self {
        proto::PolicyStatement {
            action: j.action,
            prefix: j.prefix,
            ge: j.ge,
            le: j.le,
            match_community: j.match_community,
            match_as_path: j.match_as_path,
            match_as_path_length_ge: j.match_as_path_length_ge,
            match_as_path_length_le: j.match_as_path_length_le,
            match_rpki_validation: j.match_rpki_validation,
            match_aspa_validation: j.match_aspa_validation,
            match_neighbor_set: j.match_neighbor_set,
            match_route_type: j.match_route_type,
            match_evpn_route_type: j.match_evpn_route_type,
            match_local_pref_ge: j.match_local_pref_ge,
            match_local_pref_le: j.match_local_pref_le,
            match_med_ge: j.match_med_ge,
            match_med_le: j.match_med_le,
            match_next_hop: j.match_next_hop,
            set_local_pref: j.set_local_pref,
            set_med: j.set_med,
            set_next_hop: j.set_next_hop,
            set_community_add: j.set_community_add,
            set_community_remove: j.set_community_remove,
            set_as_path_prepend: j.set_as_path_prepend.map(Into::into),
        }
    }
}

impl From<JsonAsPathPrepend> for proto::AsPathPrepend {
    fn from(j: JsonAsPathPrepend) -> Self {
        proto::AsPathPrepend {
            asn: j.asn,
            count: j.count,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonNeighborSetDefinition {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub remote_asns: Vec<u32>,
    #[serde(default)]
    pub peer_groups: Vec<String>,
}

impl From<JsonNeighborSetDefinition> for proto::NeighborSetDefinition {
    fn from(j: JsonNeighborSetDefinition) -> Self {
        proto::NeighborSetDefinition {
            addresses: j.addresses,
            remote_asns: j.remote_asns,
            peer_groups: j.peer_groups,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPeerGroupDefinition {
    #[serde(default)]
    pub hold_time: Option<u32>,
    #[serde(default)]
    pub send_hold_time: Option<u32>,
    #[serde(default)]
    pub max_prefixes: Option<u32>,
    #[serde(default)]
    pub max_prefix_restart_seconds: Option<u32>,
    #[serde(default)]
    pub md5_password: Option<String>,
    #[serde(default)]
    pub has_md5_password: Option<bool>,
    #[serde(default)]
    pub ttl_security: Option<bool>,
    #[serde(default)]
    pub families: Vec<String>,
    #[serde(default)]
    pub graceful_restart: Option<bool>,
    #[serde(default)]
    pub gr_restart_time: Option<u32>,
    #[serde(default)]
    pub gr_peer_restart_time_max: Option<u32>,
    #[serde(default)]
    pub gr_stale_routes_time: Option<u64>,
    #[serde(default)]
    pub llgr_stale_time: Option<u32>,
    #[serde(default)]
    pub local_ipv6_nexthop: Option<String>,
    #[serde(default)]
    pub route_reflector_client: Option<bool>,
    #[serde(default)]
    pub orr_vantage: Option<String>,
    #[serde(default)]
    pub route_server_client: Option<bool>,
    #[serde(default)]
    pub per_client_best: Option<bool>,
    #[serde(default)]
    pub remove_private_as: Option<String>,
    #[serde(default)]
    pub add_path_receive: Option<bool>,
    #[serde(default)]
    pub add_path_send: Option<bool>,
    #[serde(default)]
    pub add_path_send_max: Option<u32>,
    #[serde(default)]
    pub paths_limit_receive_max: Option<u32>,
    #[serde(default)]
    pub import_policy: Vec<JsonPolicyStatement>,
    #[serde(default)]
    pub export_policy: Vec<JsonPolicyStatement>,
    #[serde(default)]
    pub import_policy_chain: Vec<String>,
    #[serde(default)]
    pub export_policy_chain: Vec<String>,
}

impl From<JsonPeerGroupDefinition> for proto::PeerGroupDefinition {
    fn from(j: JsonPeerGroupDefinition) -> Self {
        let has_md5_password = j
            .has_md5_password
            .or_else(|| j.md5_password.as_ref().map(|_| true));
        proto::PeerGroupDefinition {
            hold_time: j.hold_time,
            send_hold_time: j.send_hold_time,
            max_prefixes: j.max_prefixes,
            max_prefix_restart_seconds: j.max_prefix_restart_seconds,
            md5_password: j.md5_password,
            ttl_security: j.ttl_security,
            families: j.families,
            graceful_restart: j.graceful_restart,
            gr_restart_time: j.gr_restart_time,
            gr_peer_restart_time_max: j.gr_peer_restart_time_max,
            gr_stale_routes_time: j.gr_stale_routes_time,
            llgr_stale_time: j.llgr_stale_time,
            local_ipv6_nexthop: j.local_ipv6_nexthop,
            route_reflector_client: j.route_reflector_client,
            orr_vantage: j.orr_vantage,
            route_server_client: j.route_server_client,
            per_client_best: j.per_client_best,
            remove_private_as: j.remove_private_as,
            add_path_receive: j.add_path_receive,
            add_path_send: j.add_path_send,
            add_path_send_max: j.add_path_send_max,
            paths_limit_receive_max: j.paths_limit_receive_max,
            import_policy: j.import_policy.into_iter().map(Into::into).collect(),
            export_policy: j.export_policy.into_iter().map(Into::into).collect(),
            import_policy_chain: j.import_policy_chain,
            export_policy_chain: j.export_policy_chain,
            has_md5_password,
        }
    }
}

/// Read a JSON definition file from disk into a deserializable type.
/// Returns `CliError::Argument` on read or parse failure with a message
/// that names the path and the underlying serde error.
pub fn load_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::Argument(format!("failed to read {path}: {e}")))?;
    serde_json::from_str(&raw)
        .map_err(|e| CliError::Argument(format!("failed to parse {path} as JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal_policy_definition() {
        let json = r#"{"default_action":"permit"}"#;
        let parsed: JsonPolicyDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.default_action, "permit");
        assert!(parsed.statements.is_empty());

        let proto = proto::PolicyDefinition::from(parsed);
        assert_eq!(proto.default_action, "permit");
        assert!(proto.statements.is_empty());
    }

    #[test]
    fn round_trip_full_policy_statement() {
        let json = r#"{
            "default_action": "deny",
            "statements": [{
                "action": "permit",
                "prefix": "10.0.0.0/8",
                "ge": 16,
                "le": 24,
                "match_community": ["65001:100"],
                "match_as_path_length_ge": 2,
                "set_local_pref": 200,
                "set_community_add": ["65001:200"],
                "set_as_path_prepend": {"asn": 65000, "count": 3}
            }]
        }"#;
        let parsed: JsonPolicyDefinition = serde_json::from_str(json).unwrap();
        let proto = proto::PolicyDefinition::from(parsed);
        assert_eq!(proto.statements.len(), 1);
        let s = &proto.statements[0];
        assert_eq!(s.action, "permit");
        assert_eq!(s.prefix.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(s.ge, Some(16));
        assert_eq!(s.le, Some(24));
        assert_eq!(s.match_community, vec!["65001:100".to_string()]);
        assert_eq!(s.match_as_path_length_ge, Some(2));
        assert_eq!(s.set_local_pref, Some(200));
        assert_eq!(s.set_community_add, vec!["65001:200".to_string()]);
        let prepend = s.set_as_path_prepend.as_ref().unwrap();
        assert_eq!(prepend.asn, 65000);
        assert_eq!(prepend.count, 3);
    }

    #[test]
    fn rejects_unknown_field() {
        let json = r#"{"default_action":"permit","ham":"sandwich"}"#;
        let err = serde_json::from_str::<JsonPolicyDefinition>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }

    #[test]
    fn neighbor_set_definition_round_trip() {
        let json = r#"{
            "addresses": ["10.0.0.1", "10.0.0.2"],
            "remote_asns": [65001, 65002],
            "peer_groups": ["transit"]
        }"#;
        let parsed: JsonNeighborSetDefinition = serde_json::from_str(json).unwrap();
        let proto = proto::NeighborSetDefinition::from(parsed);
        assert_eq!(proto.addresses.len(), 2);
        assert_eq!(proto.remote_asns, vec![65001, 65002]);
        assert_eq!(proto.peer_groups, vec!["transit".to_string()]);
    }

    #[test]
    fn peer_group_definition_round_trip() {
        let json = r#"{
            "hold_time": 90,
            "max_prefix_restart_seconds": 300,
            "families": ["ipv4_unicast", "ipv6_unicast"],
            "import_policy_chain": ["from-transit"],
            "export_policy_chain": ["to-transit"],
            "route_reflector_client": true,
            "paths_limit_receive_max": 7
        }"#;
        let parsed: JsonPeerGroupDefinition = serde_json::from_str(json).unwrap();
        let proto = proto::PeerGroupDefinition::from(parsed);
        assert_eq!(proto.hold_time, Some(90));
        assert_eq!(proto.max_prefix_restart_seconds, Some(300));
        assert_eq!(proto.families.len(), 2);
        assert_eq!(proto.import_policy_chain, vec!["from-transit".to_string()]);
        assert_eq!(proto.export_policy_chain, vec!["to-transit".to_string()]);
        assert_eq!(proto.route_reflector_client, Some(true));
        assert_eq!(proto.paths_limit_receive_max, Some(7));
        assert_eq!(proto.has_md5_password, None);
    }

    #[test]
    fn peer_group_definition_can_preserve_or_clear_redacted_md5() {
        let preserve_json = r#"{
            "families": ["ipv4_unicast"],
            "has_md5_password": true
        }"#;
        let preserve: JsonPeerGroupDefinition = serde_json::from_str(preserve_json).unwrap();
        let preserve = proto::PeerGroupDefinition::from(preserve);
        assert_eq!(preserve.md5_password, None);
        assert_eq!(preserve.has_md5_password, Some(true));

        let clear_json = r#"{
            "families": ["ipv4_unicast"],
            "has_md5_password": false
        }"#;
        let clear: JsonPeerGroupDefinition = serde_json::from_str(clear_json).unwrap();
        let clear = proto::PeerGroupDefinition::from(clear);
        assert_eq!(clear.md5_password, None);
        assert_eq!(clear.has_md5_password, Some(false));
    }
}
