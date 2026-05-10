//! `rustbgpctl neighbor-set ...` — wraps PolicyService neighbor-set RPCs.
//!
//! Neighbor sets are the named (addresses, ASNs, peer-groups) tuple
//! that policy `match_neighbor_set` resolves against. Backed by
//! PolicyService — neighbor-set is not its own service.

use serde::Serialize;

use crate::commands::policy_input::{JsonNeighborSetDefinition, load_json};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    DeleteNeighborSetRequest, GetNeighborSetRequest, ListNeighborSetsRequest, SetNeighborSetRequest,
};

#[derive(Debug, Serialize)]
struct JsonNeighborSetSummary {
    name: String,
    address_count: usize,
    asn_count: usize,
    peer_group_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonNeighborSetDetail {
    name: String,
    addresses: Vec<String>,
    remote_asns: Vec<u32>,
    peer_groups: Vec<String>,
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_neighbor_sets(ListNeighborSetsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonNeighborSetSummary> = resp
            .neighbor_sets
            .iter()
            .map(|ns| {
                let def = ns.definition.as_ref();
                JsonNeighborSetSummary {
                    name: ns.name.clone(),
                    address_count: def.map(|d| d.addresses.len()).unwrap_or(0),
                    asn_count: def.map(|d| d.remote_asns.len()).unwrap_or(0),
                    peer_group_count: def.map(|d| d.peer_groups.len()).unwrap_or(0),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize neighbor-set list as JSON")
        );
    } else if resp.neighbor_sets.is_empty() {
        println!("No neighbor sets configured");
    } else {
        println!(
            "{:<32} {:<10} {:<6} PEER_GROUPS",
            "NAME", "ADDRESSES", "ASNS"
        );
        for ns in &resp.neighbor_sets {
            let def = ns.definition.as_ref();
            println!(
                "{:<32} {:<10} {:<6} {}",
                ns.name,
                def.map(|d| d.addresses.len()).unwrap_or(0),
                def.map(|d| d.remote_asns.len()).unwrap_or(0),
                def.map(|d| d.peer_groups.len()).unwrap_or(0),
            );
        }
    }
    Ok(())
}

pub async fn get(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_neighbor_set(GetNeighborSetRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();

    let def = resp.definition.unwrap_or_default();
    if json {
        let detail = JsonNeighborSetDetail {
            name: resp.name.clone(),
            addresses: def.addresses.clone(),
            remote_asns: def.remote_asns.clone(),
            peer_groups: def.peer_groups.clone(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&detail)
                .expect("failed to serialize neighbor-set detail as JSON")
        );
    } else {
        println!("Name:        {}", resp.name);
        println!(
            "Addresses:   {}",
            if def.addresses.is_empty() {
                "(none)".to_string()
            } else {
                def.addresses.join(", ")
            }
        );
        println!(
            "Remote ASNs: {}",
            if def.remote_asns.is_empty() {
                "(none)".to_string()
            } else {
                def.remote_asns
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        println!(
            "Peer Groups: {}",
            if def.peer_groups.is_empty() {
                "(none)".to_string()
            } else {
                def.peer_groups.join(", ")
            }
        );
    }
    Ok(())
}

pub async fn set(
    connection: Connection,
    name: &str,
    from_file: &str,
    json: bool,
) -> Result<(), CliError> {
    let definition: JsonNeighborSetDefinition = load_json(from_file)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .set_neighbor_set(SetNeighborSetRequest {
            name: name.to_string(),
            definition: Some(definition.into()),
        })
        .await?;
    output::print_result(
        json,
        "set_neighbor_set",
        name,
        &format!("Neighbor set {name} set"),
    );
    Ok(())
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_neighbor_set(DeleteNeighborSetRequest {
            name: name.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_neighbor_set",
        name,
        &format!("Neighbor set {name} deleted"),
    );
    Ok(())
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
    async fn set_reads_json_and_sends() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"{{"addresses":["10.0.0.1","10.0.0.2"],"remote_asns":[65001],"peer_groups":["transit"]}}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        set(
            connection,
            "transit-peers",
            tmp.path().to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        let captured = server
            .state
            .last_set_neighbor_set
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "transit-peers");
        let def = captured.definition.unwrap();
        assert_eq!(
            def.addresses,
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
        assert_eq!(def.remote_asns, vec![65001]);
        assert_eq!(def.peer_groups, vec!["transit".to_string()]);
    }

    #[tokio::test]
    async fn delete_sends_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "transit-peers", true).await.unwrap();
        let captured = server
            .state
            .last_delete_neighbor_set
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "transit-peers");
    }
}
