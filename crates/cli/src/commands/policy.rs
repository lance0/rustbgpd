//! `rustbgpctl policy ...` — wraps PolicyService gRPCs.
//!
//! - `list` / `get NAME` / `set NAME --from-file FILE` / `delete NAME`
//!   for named [[policy_definitions]] entries.
//! - `chain show [--neighbor ADDR]` for global or per-neighbor chains.
//! - `chain set-import|set-export {--neighbor ADDR | --global} POL...`
//!   to install (or replace) a chain.
//! - `chain clear-import|clear-export {--neighbor ADDR | --global}` to
//!   drop the resolved chain entirely.

use serde::Serialize;

use crate::commands::policy_input::{JsonPolicyDefinition, load_json};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    self, ClearGlobalExportChainRequest, ClearGlobalImportChainRequest,
    ClearNeighborExportChainRequest, ClearNeighborImportChainRequest, DeletePolicyRequest,
    GetGlobalPolicyChainsRequest, GetNeighborPolicyChainsRequest, GetPolicyRequest,
    ListPoliciesRequest, SetGlobalExportChainRequest, SetGlobalImportChainRequest,
    SetNeighborExportChainRequest, SetNeighborImportChainRequest, SetPolicyRequest,
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
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize policy list as JSON")
        );
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
        println!(
            "{}",
            serde_json::to_string_pretty(&detail)
                .expect("failed to serialize policy detail as JSON")
        );
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
    output::print_result(json, "set_policy", name, &format!("Policy {name} set"));
    Ok(())
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
    );
    Ok(())
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
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize chains as JSON")
        );
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
    );
    Ok(())
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
    );
    Ok(())
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
