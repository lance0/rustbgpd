//! `rustbgpctl dynamic-neighbor ...` — wraps NeighborService dynamic-range RPCs.
//!
//! Dynamic neighbor ranges accept inbound sessions from any peer whose source
//! address falls in a configured prefix, binding them to a peer group. Backed
//! by NeighborService (`ListDynamicNeighbors` / `AddDynamicNeighbor` /
//! `DeleteDynamicNeighbor`).

use serde::Serialize;

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    AddDynamicNeighborRequest, DeleteDynamicNeighborRequest, DynamicNeighborRange,
    ListDynamicNeighborsRequest,
};

#[derive(Debug, Serialize)]
struct JsonDynamicRange {
    prefix: String,
    peer_group: String,
    remote_asn: u32,
    description: String,
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_dynamic_neighbors(ListDynamicNeighborsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonDynamicRange> = resp
            .ranges
            .iter()
            .map(|r| JsonDynamicRange {
                prefix: r.prefix.clone(),
                peer_group: r.peer_group.clone(),
                remote_asn: r.remote_asn,
                description: r.description.clone(),
            })
            .collect();
        output::print_json_pretty(&out)?;
    } else if resp.ranges.is_empty() {
        println!("No dynamic neighbor ranges configured");
    } else {
        println!(
            "{:<22} {:<24} {:<10} DESCRIPTION",
            "PREFIX", "PEER_GROUP", "REMOTE_ASN"
        );
        for r in &resp.ranges {
            let asn = if r.remote_asn == 0 {
                "any".to_string()
            } else {
                r.remote_asn.to_string()
            };
            println!(
                "{:<22} {:<24} {:<10} {}",
                r.prefix, r.peer_group, asn, r.description
            );
        }
    }
    Ok(())
}

pub async fn add(
    connection: Connection,
    prefix: &str,
    peer_group: &str,
    remote_asn: u32,
    description: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_dynamic_neighbor(AddDynamicNeighborRequest {
            range: Some(DynamicNeighborRange {
                prefix: prefix.to_string(),
                peer_group: peer_group.to_string(),
                remote_asn,
                description: description.unwrap_or_default(),
            }),
        })
        .await?;
    output::print_result(
        json,
        "add_dynamic_neighbor",
        prefix,
        &format!("Dynamic neighbor range {prefix} added"),
    )
}

pub async fn delete(connection: Connection, prefix: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_dynamic_neighbor(DeleteDynamicNeighborRequest {
            prefix: prefix.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_dynamic_neighbor",
        prefix,
        &format!("Dynamic neighbor range {prefix} deleted"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn list_renders_empty() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        list(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn add_sends_range() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        add(connection, "10.0.0.0/24", "transit", 0, None, true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_add_dynamic_neighbor
            .lock()
            .await
            .clone()
            .unwrap();
        let range = captured.range.unwrap();
        assert_eq!(range.prefix, "10.0.0.0/24");
        assert_eq!(range.peer_group, "transit");
        assert_eq!(range.remote_asn, 0);
    }

    #[tokio::test]
    async fn delete_sends_prefix() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "10.0.0.0/24", true).await.unwrap();
        let captured = server
            .state
            .last_delete_dynamic_neighbor
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.prefix, "10.0.0.0/24");
    }
}
