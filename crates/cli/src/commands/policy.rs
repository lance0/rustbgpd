//! `rbgp policy ...` — wraps PolicyService gRPCs.
//!
//! - `list` / `get NAME` / `set NAME --from-file FILE` / `delete NAME`
//!   for named `[[policy_definitions]]` entries.
//! - `chain show [--neighbor ADDR]` for global or per-neighbor chains.
//! - `chain set-import [--neighbor ADDR] POL...` /
//!   `chain set-export [--neighbor ADDR] POL...` to install (or
//!   replace) a chain. Omitting `--neighbor` applies the change to
//!   the global chain.
//! - `chain clear-import [--neighbor ADDR]` /
//!   `chain clear-export [--neighbor ADDR]` to drop the resolved
//!   chain entirely. Omitting `--neighbor` clears the global chain.

use serde::Serialize;

use crate::commands::policy_input::{JsonPolicyDefinition, load_json};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    self, ClearGlobalExportChainRequest, ClearGlobalImportChainRequest,
    ClearNeighborExportChainRequest, ClearNeighborImportChainRequest, DeletePolicyRequest,
    ExplainImportPolicyRequest, GetGlobalPolicyChainsRequest, GetNeighborPolicyChainsRequest,
    GetPolicyRequest, ListPoliciesRequest, SetGlobalExportChainRequest,
    SetGlobalImportChainRequest, SetNeighborExportChainRequest, SetNeighborImportChainRequest,
    SetPolicyRequest,
};

#[derive(Debug, Serialize)]
struct JsonPolicySummary {
    name: String,
    default_action: String,
    statement_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonPolicyDetail {
    name: String,
    default_action: String,
    statements: Vec<JsonPolicyStatementOut>,
}

#[derive(Debug, Default, Serialize)]
struct JsonPolicyStatementOut {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    le: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    match_community: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_rpki_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_aspa_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_neighbor_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_route_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_evpn_route_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_local_pref: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_med: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_add: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_remove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_as_path_prepend: Option<JsonAsPathPrependOut>,
}

#[derive(Debug, Serialize)]
struct JsonAsPathPrependOut {
    asn: u32,
    count: u32,
}

impl From<proto::PolicyStatement> for JsonPolicyStatementOut {
    fn from(s: proto::PolicyStatement) -> Self {
        JsonPolicyStatementOut {
            action: s.action,
            prefix: s.prefix,
            ge: s.ge,
            le: s.le,
            match_community: s.match_community,
            match_as_path: s.match_as_path,
            match_as_path_length_ge: s.match_as_path_length_ge,
            match_as_path_length_le: s.match_as_path_length_le,
            match_rpki_validation: s.match_rpki_validation,
            match_aspa_validation: s.match_aspa_validation,
            match_neighbor_set: s.match_neighbor_set,
            match_route_type: s.match_route_type,
            match_evpn_route_type: s.match_evpn_route_type,
            match_local_pref_ge: s.match_local_pref_ge,
            match_local_pref_le: s.match_local_pref_le,
            match_med_ge: s.match_med_ge,
            match_med_le: s.match_med_le,
            match_next_hop: s.match_next_hop,
            set_local_pref: s.set_local_pref,
            set_med: s.set_med,
            set_next_hop: s.set_next_hop,
            set_community_add: s.set_community_add,
            set_community_remove: s.set_community_remove,
            set_as_path_prepend: s.set_as_path_prepend.map(|p| JsonAsPathPrependOut {
                asn: p.asn,
                count: p.count,
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonChains {
    #[serde(skip_serializing_if = "Option::is_none")]
    neighbor: Option<String>,
    import_policy_names: Vec<String>,
    export_policy_names: Vec<String>,
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_policies(ListPoliciesRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonPolicySummary> = resp
            .policies
            .iter()
            .map(|p| JsonPolicySummary {
                name: p.name.clone(),
                default_action: p
                    .definition
                    .as_ref()
                    .map(|d| d.default_action.clone())
                    .unwrap_or_default(),
                statement_count: p
                    .definition
                    .as_ref()
                    .map(|d| d.statements.len())
                    .unwrap_or(0),
            })
            .collect();
        output::print_json_pretty(&out)?;
    } else if resp.policies.is_empty() {
        println!("No policies configured");
    } else {
        println!("{:<32} {:<10} STATEMENTS", "NAME", "DEFAULT");
        for p in &resp.policies {
            let def = p.definition.as_ref();
            let default_action = def.map(|d| d.default_action.as_str()).unwrap_or("-");
            let count = def.map(|d| d.statements.len()).unwrap_or(0);
            println!("{:<32} {:<10} {}", p.name, default_action, count);
        }
    }
    Ok(())
}

pub async fn get(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_policy(GetPolicyRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();

    let def = resp.definition.unwrap_or_default();
    if json {
        let detail = JsonPolicyDetail {
            name: resp.name.clone(),
            default_action: def.default_action.clone(),
            statements: def.statements.into_iter().map(Into::into).collect(),
        };
        output::print_json_pretty(&detail)?;
    } else {
        println!("Name:           {}", resp.name);
        println!("Default Action: {}", def.default_action);
        println!("Statements:     {}", def.statements.len());
        for (i, s) in def.statements.iter().enumerate() {
            println!("  [{i}] action={}", s.action);
            print_statement_details(s, "      ");
        }
    }
    Ok(())
}

pub async fn set(
    connection: Connection,
    name: &str,
    from_file: &str,
    json: bool,
) -> Result<(), CliError> {
    let definition: JsonPolicyDefinition = load_json(from_file)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .set_policy(SetPolicyRequest {
            name: name.to_string(),
            definition: Some(definition.into()),
        })
        .await?;
    output::print_result(json, "set_policy", name, &format!("Policy {name} set"))
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_policy(DeletePolicyRequest {
            name: name.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_policy",
        name,
        &format!("Policy {name} deleted"),
    )
}

#[derive(Debug, Serialize)]
struct JsonImportExplainMatch {
    outcome: String,
    path_id: u32,
    matched_policy: Option<String>,
    rpki_validation: Option<String>,
    aspa_validation: Option<String>,
    modifications: Option<JsonImportExplainModifications>,
    evaluated_at_unix_ns: Option<i64>,
    policy_generation: Option<u64>,
    // Unconditional key (run-stable): empty for outcomes that carry no
    // statement trace (stale / withdrawn / evicted / not_seen, or a
    // chain-less peer).
    statements: Vec<JsonImportExplainStatement>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainStatement {
    policy_index: u32,
    policy_name: Option<String>,
    // `None` when the policy fell through to its default action
    // (`default_action == true`).
    statement_index: Option<u32>,
    default_action: bool,
    action: String,
    matched_conditions: Vec<String>,
    modifications: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainModifications {
    set_local_pref: Option<u32>,
    set_med: Option<u32>,
    set_next_hop: Option<String>,
    communities_add: Vec<u32>,
    communities_remove: Vec<u32>,
    extended_communities_add: Vec<u64>,
    extended_communities_remove: Vec<u64>,
    large_communities_add: Vec<String>,
    large_communities_remove: Vec<String>,
    as_path_prepend_asn: Option<u32>,
    as_path_prepend_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplain {
    peer_address: String,
    prefix: String,
    afi_safi: String,
    current_policy_generation: u64,
    matches: Vec<JsonImportExplainMatch>,
}

/// Render a proto outcome enum as a stable lowercase operator string.
fn outcome_label(outcome: i32) -> &'static str {
    match proto::ImportExplainOutcome::try_from(outcome) {
        Ok(proto::ImportExplainOutcome::Permit) => "permit",
        Ok(proto::ImportExplainOutcome::Deny) => "deny",
        Ok(proto::ImportExplainOutcome::Withdrawn) => "withdrawn",
        Ok(proto::ImportExplainOutcome::Evicted) => "evicted",
        Ok(proto::ImportExplainOutcome::Stale) => "stale",
        Ok(proto::ImportExplainOutcome::NotSeen) => "not_seen",
        Ok(proto::ImportExplainOutcome::Unspecified) | Err(_) => "unspecified",
    }
}

/// Whether an outcome carries a recorded decision (and therefore
/// populated policy / validation / modification fields).
fn outcome_has_decision(outcome: i32) -> bool {
    matches!(
        proto::ImportExplainOutcome::try_from(outcome),
        Ok(proto::ImportExplainOutcome::Permit
            | proto::ImportExplainOutcome::Deny
            | proto::ImportExplainOutcome::Withdrawn
            | proto::ImportExplainOutcome::Stale)
    )
}

/// Split a CIDR (`"192.0.2.0/24"` / `"2001:db8::/32"`) into the address
/// string, prefix length, and the matching `AddressFamily`. ADR-0073
/// scopes explain to IPv4 / IPv6 unicast, so the address family is
/// inferred from the prefix rather than asked for separately.
fn parse_cidr(prefix: &str) -> Result<(String, u32, proto::AddressFamily), CliError> {
    let (addr, len) = prefix
        .split_once('/')
        .ok_or_else(|| CliError::Argument(format!("--prefix must be CIDR (got {prefix:?})")))?;
    let length: u32 = len
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix length in {prefix:?}")))?;
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix address in {prefix:?}")))?;
    match ip {
        std::net::IpAddr::V4(_) if length <= 32 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv4Unicast))
        }
        std::net::IpAddr::V6(_) if length <= 128 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv6Unicast))
        }
        _ => Err(CliError::Argument(format!(
            "prefix length out of range for address family in {prefix:?}"
        ))),
    }
}

pub async fn explain_import(
    connection: Connection,
    neighbor: &str,
    prefix: &str,
    path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, prefix_length, afi_safi) = parse_cidr(prefix)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .explain_import_policy(ExplainImportPolicyRequest {
            peer_address: neighbor.to_string(),
            afi_safi: afi_safi as i32,
            prefix: addr,
            prefix_length,
            path_id,
        })
        .await?
        .into_inner();

    if json {
        let out = JsonImportExplain {
            peer_address: resp.peer_address.clone(),
            prefix: format!("{}/{}", resp.prefix, resp.prefix_length),
            afi_safi: address_family_label(resp.afi_safi).to_string(),
            current_policy_generation: resp.current_policy_generation,
            matches: resp.matches.iter().map(match_to_json).collect(),
        };
        output::print_json_pretty(&out)?;
        return Ok(());
    }

    println!(
        "import policy explain — peer {} prefix {}/{} (policy generation {})",
        resp.peer_address, resp.prefix, resp.prefix_length, resp.current_policy_generation
    );
    if resp.matches.len() > 1 {
        println!("{} matching paths:", resp.matches.len());
    }
    for m in &resp.matches {
        let path = if m.path_id == 0 {
            String::new()
        } else {
            format!(" path-id {}", m.path_id)
        };
        println!("  {}{}", outcome_label(m.outcome), path);
        if outcome_has_decision(m.outcome) {
            if !m.matched_policy.is_empty() {
                println!("    policy:  {}", m.matched_policy);
            } else {
                println!("    policy:  inline");
            }
            println!(
                "    rpki:    {}    aspa: {}",
                blank_dash(&m.rpki_validation),
                blank_dash(&m.aspa_validation)
            );
            println!("    eval-ns: {}", m.evaluated_at_unix_ns);
            if let Some(mods) = &m.modifications {
                let summary = modifications_summary(mods);
                if !summary.is_empty() {
                    println!("    mods:    {summary}");
                }
            }
            for (i, s) in m.statements.iter().enumerate() {
                if i == 0 {
                    println!("    statements:");
                }
                println!("      {}", statement_line(s));
            }
        }
    }
    Ok(())
}

/// One text row per statement-trace step:
/// `[0] policy lp-bump statement 1 permit  match: community 65001:100  set: local_pref 100 -> 200`
/// or, for a default-action fallthrough,
/// `[1] policy guard default-action deny`.
fn statement_line(s: &proto::ImportExplainStatementStep) -> String {
    let policy = if s.policy_name.is_empty() {
        "inline"
    } else {
        &s.policy_name
    };
    let mut line = format!("[{}] policy {policy}", s.policy_index);
    if s.default_action {
        line.push_str(&format!(" default-action {}", s.action));
    } else {
        line.push_str(&format!(" statement {} {}", s.statement_index, s.action));
        if !s.matched_conditions.is_empty() {
            line.push_str(&format!("  match: {}", s.matched_conditions.join(", ")));
        }
        if !s.modifications.is_empty() {
            line.push_str(&format!("  set: {}", s.modifications.join(", ")));
        }
    }
    line
}

fn blank_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

/// Map one proto match into its JSON shape. Decision-bearing fields
/// (policy / validation / modifications / timestamps) are populated
/// only for outcomes that recorded a decision; `NOT_SEEN` / `EVICTED`
/// leave them `None` so the JSON doesn't imply data that isn't there.
fn match_to_json(m: &proto::ImportExplainMatch) -> JsonImportExplainMatch {
    let has_decision = outcome_has_decision(m.outcome);
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    JsonImportExplainMatch {
        outcome: outcome_label(m.outcome).to_string(),
        path_id: m.path_id,
        matched_policy: has_decision.then(|| non_empty(&m.matched_policy)).flatten(),
        rpki_validation: has_decision
            .then(|| non_empty(&m.rpki_validation))
            .flatten(),
        aspa_validation: has_decision
            .then(|| non_empty(&m.aspa_validation))
            .flatten(),
        modifications: if has_decision {
            m.modifications.as_ref().map(modifications_to_json)
        } else {
            None
        },
        evaluated_at_unix_ns: has_decision.then_some(m.evaluated_at_unix_ns),
        policy_generation: has_decision.then_some(m.policy_generation),
        statements: m.statements.iter().map(statement_to_json).collect(),
    }
}

fn statement_to_json(s: &proto::ImportExplainStatementStep) -> JsonImportExplainStatement {
    JsonImportExplainStatement {
        policy_index: s.policy_index,
        policy_name: (!s.policy_name.is_empty()).then(|| s.policy_name.clone()),
        statement_index: (!s.default_action).then_some(s.statement_index),
        default_action: s.default_action,
        action: s.action.clone(),
        matched_conditions: s.matched_conditions.clone(),
        modifications: s.modifications.clone(),
    }
}

fn address_family_label(afi_safi: i32) -> &'static str {
    match proto::AddressFamily::try_from(afi_safi) {
        Ok(proto::AddressFamily::Ipv4Unicast) => "ipv4-unicast",
        Ok(proto::AddressFamily::Ipv6Unicast) => "ipv6-unicast",
        _ => "unspecified",
    }
}

fn modifications_to_json(m: &proto::ExplainModifications) -> JsonImportExplainModifications {
    JsonImportExplainModifications {
        set_local_pref: m.set_local_pref,
        set_med: m.set_med,
        set_next_hop: Some(m.set_next_hop.clone()).filter(|s| !s.is_empty()),
        communities_add: m.communities_add.clone(),
        communities_remove: m.communities_remove.clone(),
        extended_communities_add: m.extended_communities_add.clone(),
        extended_communities_remove: m.extended_communities_remove.clone(),
        large_communities_add: m.large_communities_add.clone(),
        large_communities_remove: m.large_communities_remove.clone(),
        as_path_prepend_asn: m.as_path_prepend_asn,
        as_path_prepend_count: m.as_path_prepend_count,
    }
}

fn modifications_summary(m: &proto::ExplainModifications) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(lp) = m.set_local_pref {
        parts.push(format!("local_pref={lp}"));
    }
    if let Some(med) = m.set_med {
        parts.push(format!("med={med}"));
    }
    if !m.set_next_hop.is_empty() {
        parts.push(format!("next_hop={}", m.set_next_hop));
    }
    if !m.communities_add.is_empty() {
        parts.push(format!("comm+={}", m.communities_add.len()));
    }
    if !m.communities_remove.is_empty() {
        parts.push(format!("comm-={}", m.communities_remove.len()));
    }
    if !m.extended_communities_add.is_empty() {
        parts.push(format!("extcomm+={}", m.extended_communities_add.len()));
    }
    if !m.extended_communities_remove.is_empty() {
        parts.push(format!("extcomm-={}", m.extended_communities_remove.len()));
    }
    if !m.large_communities_add.is_empty() {
        parts.push(format!("largecomm+={}", m.large_communities_add.len()));
    }
    if !m.large_communities_remove.is_empty() {
        parts.push(format!("largecomm-={}", m.large_communities_remove.len()));
    }
    if let (Some(asn), Some(count)) = (m.as_path_prepend_asn, m.as_path_prepend_count) {
        parts.push(format!("prepend={asn}x{count}"));
    }
    parts.join(" ")
}

pub async fn chain_show(
    connection: Connection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (import, export, address) = match neighbor {
        Some(addr) => {
            let resp = client
                .get_neighbor_policy_chains(GetNeighborPolicyChainsRequest {
                    address: addr.to_string(),
                })
                .await?
                .into_inner();
            (
                resp.import_policy_names,
                resp.export_policy_names,
                Some(resp.address),
            )
        }
        None => {
            let resp = client
                .get_global_policy_chains(GetGlobalPolicyChainsRequest {})
                .await?
                .into_inner();
            (resp.import_policy_names, resp.export_policy_names, None)
        }
    };

    if json {
        let out = JsonChains {
            neighbor: address,
            import_policy_names: import,
            export_policy_names: export,
        };
        output::print_json_pretty(&out)?;
    } else {
        let scope = neighbor.unwrap_or("global");
        println!("Scope:        {scope}");
        println!(
            "Import Chain: {}",
            if import.is_empty() {
                "(none)".to_string()
            } else {
                import.join(" -> ")
            }
        );
        println!(
            "Export Chain: {}",
            if export.is_empty() {
                "(none)".to_string()
            } else {
                export.join(" -> ")
            }
        );
    }
    Ok(())
}

pub async fn chain_set(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    policy_names: Vec<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            client
                .set_global_import_chain(SetGlobalImportChainRequest {
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                "global".to_string(),
                "Global import chain updated".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            client
                .set_global_export_chain(SetGlobalExportChainRequest {
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                "global".to_string(),
                "Global export chain updated".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            client
                .set_neighbor_import_chain(SetNeighborImportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain updated"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            client
                .set_neighbor_export_chain(SetNeighborExportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain updated"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "set_import_chain",
            ChainDirection::Export => "set_export_chain",
        },
        &target,
        &message,
    )
}

pub async fn chain_clear(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            client
                .clear_global_import_chain(ClearGlobalImportChainRequest {})
                .await?;
            (
                "global".to_string(),
                "Global import chain cleared".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            client
                .clear_global_export_chain(ClearGlobalExportChainRequest {})
                .await?;
            (
                "global".to_string(),
                "Global export chain cleared".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            client
                .clear_neighbor_import_chain(ClearNeighborImportChainRequest {
                    address: addr.to_string(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain cleared"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            client
                .clear_neighbor_export_chain(ClearNeighborExportChainRequest {
                    address: addr.to_string(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain cleared"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "clear_import_chain",
            ChainDirection::Export => "clear_export_chain",
        },
        &target,
        &message,
    )
}

#[derive(Clone, Copy, Debug)]
pub enum ChainDirection {
    Import,
    Export,
}

fn print_statement_details(s: &proto::PolicyStatement, indent: &str) {
    if let Some(p) = &s.prefix {
        println!("{indent}prefix={p}");
    }
    if let Some(g) = s.ge {
        println!("{indent}ge={g}");
    }
    if let Some(l) = s.le {
        println!("{indent}le={l}");
    }
    if !s.match_community.is_empty() {
        println!("{indent}match_community={}", s.match_community.join(","));
    }
    if let Some(p) = &s.match_as_path {
        println!("{indent}match_as_path={p}");
    }
    if let Some(n) = &s.match_neighbor_set {
        println!("{indent}match_neighbor_set={n}");
    }
    if let Some(rt) = &s.match_route_type {
        println!("{indent}match_route_type={rt}");
    }
    if let Some(rt) = s.match_evpn_route_type {
        println!("{indent}match_evpn_route_type={rt}");
    }
    if let Some(v) = &s.match_rpki_validation {
        println!("{indent}match_rpki_validation={v}");
    }
    if let Some(v) = &s.match_aspa_validation {
        println!("{indent}match_aspa_validation={v}");
    }
    if let Some(n) = &s.match_next_hop {
        println!("{indent}match_next_hop={n}");
    }
    if let Some(lp) = s.set_local_pref {
        println!("{indent}set_local_pref={lp}");
    }
    if let Some(med) = s.set_med {
        println!("{indent}set_med={med}");
    }
    if let Some(n) = &s.set_next_hop {
        println!("{indent}set_next_hop={n}");
    }
    if !s.set_community_add.is_empty() {
        println!(
            "{indent}set_community_add={}",
            s.set_community_add.join(",")
        );
    }
    if !s.set_community_remove.is_empty() {
        println!(
            "{indent}set_community_remove={}",
            s.set_community_remove.join(",")
        );
    }
    if let Some(p) = &s.set_as_path_prepend {
        println!(
            "{indent}set_as_path_prepend=asn={} count={}",
            p.asn, p.count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use std::io::Write;

    #[tokio::test]
    async fn list_renders_empty() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        list(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn set_reads_json_file_and_sends_definition() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"{{"default_action":"deny","statements":[{{"action":"permit","prefix":"10.0.0.0/8","set_local_pref":300}}]}}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        set(
            connection,
            "from-transit",
            tmp.path().to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        let captured = server.state.last_set_policy.lock().await.clone().unwrap();
        assert_eq!(captured.name, "from-transit");
        let def = captured.definition.unwrap();
        assert_eq!(def.default_action, "deny");
        assert_eq!(def.statements.len(), 1);
        assert_eq!(def.statements[0].action, "permit");
        assert_eq!(def.statements[0].set_local_pref, Some(300));
    }

    #[tokio::test]
    async fn explain_infers_afi_from_prefix_and_sends_request() {
        // Pin: the CLI infers AFI from the prefix (no --afi flag) and
        // sends a well-formed request with the parsed address + length.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "192.0.2.1", "2001:db8::/32", Some(7), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.peer_address, "192.0.2.1");
        assert_eq!(captured.prefix, "2001:db8::");
        assert_eq!(captured.prefix_length, 32);
        assert_eq!(captured.path_id, Some(7));
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv6Unicast as i32,
            "AFI inferred from the v6 prefix"
        );
    }

    #[tokio::test]
    async fn explain_rejects_non_cidr_prefix() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "192.0.2.1", "192.0.2.0", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)));
    }

    #[tokio::test]
    async fn explain_all_paths_returns_every_match() {
        // Pin 7: omitting --path-id surfaces all matching paths, not an
        // arbitrary first hit. The mock returns two paths in that case.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.path_id, None);
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv4Unicast as i32
        );
    }

    #[tokio::test]
    async fn explain_renders_text_and_json() {
        // Pin 8: both render paths run cleanly over a populated
        // multi-match response (permit + deny, modifications present).
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        explain_import(json_conn, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        explain_import(text_conn, "192.0.2.1", "192.0.2.0/24", None, false)
            .await
            .unwrap();
    }

    #[test]
    fn statement_line_renders_match_and_set_clauses() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "edge-import".to_string(),
            default_action: false,
            statement_index: 1,
            action: "permit".to_string(),
            matched_conditions: vec![
                "prefix 10.0.0.0/8 le 24".to_string(),
                "community 65001:100".to_string(),
            ],
            modifications: vec!["local_pref 100 -> 200".to_string()],
        };
        assert_eq!(
            statement_line(&step),
            "[0] policy edge-import statement 1 permit  \
             match: prefix 10.0.0.0/8 le 24, community 65001:100  \
             set: local_pref 100 -> 200"
        );
    }

    #[test]
    fn statement_line_renders_default_action_and_inline_policy() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 2,
            policy_name: String::new(),
            default_action: true,
            statement_index: 0,
            action: "deny".to_string(),
            matched_conditions: vec![],
            modifications: vec![],
        };
        assert_eq!(
            statement_line(&step),
            "[2] policy inline default-action deny"
        );
    }

    #[test]
    fn statement_to_json_nulls_index_on_default_action_only() {
        let matched = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "p".to_string(),
            default_action: false,
            statement_index: 3,
            action: "permit".to_string(),
            matched_conditions: vec!["any".to_string()],
            modifications: vec![],
        };
        let j = statement_to_json(&matched);
        assert_eq!(j.statement_index, Some(3));
        assert_eq!(j.policy_name.as_deref(), Some("p"));

        let fallthrough = proto::ImportExplainStatementStep {
            default_action: true,
            policy_name: String::new(),
            action: "deny".to_string(),
            ..Default::default()
        };
        let j = statement_to_json(&fallthrough);
        assert_eq!(j.statement_index, None, "fallthrough has no statement");
        assert_eq!(j.policy_name, None, "inline policy serializes as null");
    }

    #[tokio::test]
    async fn delete_sends_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "from-transit", true).await.unwrap();
        let captured = server
            .state
            .last_delete_policy
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "from-transit");
    }

    #[tokio::test]
    async fn chain_show_global_prints() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, None, true).await.unwrap();
    }

    #[tokio::test]
    async fn chain_show_per_neighbor_prints() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, Some("10.0.0.2"), true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn chain_set_global_import_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Import,
            None,
            vec!["a".to_string(), "b".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_global_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(
            captured.policy_names,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[tokio::test]
    async fn chain_set_neighbor_export_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Export,
            Some("10.0.0.2"),
            vec!["x".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_neighbor_export_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
        assert_eq!(captured.policy_names, vec!["x".to_string()]);
    }

    #[tokio::test]
    async fn chain_clear_neighbor_import_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_clear(connection, ChainDirection::Import, Some("10.0.0.2"), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_clear_neighbor_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
    }
}
