//! `rbgp orr` — RFC 9107 ORR per-vantage status (resolution, SPF reach,
//! bound peers) plus topology totals.

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{ListOrrStatusRequest, ListOrrStatusResponse, OrrVantageStatusEntry};
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};

pub async fn status(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_orr_status(ListOrrStatusRequest {})
        .await?
        .into_inner();
    print_orr_status(&resp, json)
}

/// Table label for a resolved vantage's node: IGP Router-ID when present,
/// else the (shortened) node key, else `-`.
fn node_label(entry: &OrrVantageStatusEntry) -> String {
    if !entry.router_id.is_empty() {
        entry.router_id.clone()
    } else if entry.node_key.len() > 16 {
        format!("{}..", &entry.node_key[..14])
    } else if !entry.node_key.is_empty() {
        entry.node_key.clone()
    } else {
        "-".to_string()
    }
}

fn print_orr_status(resp: &ListOrrStatusResponse, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonOrrStatus(resp))?;
    } else if resp.vantages.is_empty() {
        println!("No ORR vantages configured");
        println!(
            "Topology: {} nodes, {} links",
            resp.topology_nodes, resp.topology_links
        );
    } else {
        println!(
            "{:<40} {:<10} {:<18} {:<8} Peers",
            "Vantage", "Resolved", "Node", "Reach"
        );
        println!("{}", "-".repeat(90));
        for entry in &resp.vantages {
            println!(
                "{:<40} {:<10} {:<18} {:<8} {}",
                entry.vantage,
                entry.resolved,
                node_label(entry),
                entry.reachable_nodes,
                entry.peers.join(" ")
            );
        }
        println!(
            "Topology: {} nodes, {} links",
            resp.topology_nodes, resp.topology_links
        );
    }
    Ok(())
}

struct JsonOrrStatus<'a>(&'a ListOrrStatusResponse);

impl Serialize for JsonOrrStatus<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("vantages", &JsonVantages(&self.0.vantages))?;
        map.serialize_entry("topology_nodes", &self.0.topology_nodes)?;
        map.serialize_entry("topology_links", &self.0.topology_links)?;
        map.end()
    }
}

struct JsonVantages<'a>(&'a [OrrVantageStatusEntry]);

impl Serialize for JsonVantages<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            seq.serialize_element(&JsonVantageRef(entry))?;
        }
        seq.end()
    }
}

struct JsonVantageRef<'a>(&'a OrrVantageStatusEntry);

impl Serialize for JsonVantageRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entry = self.0;
        let mut map = serializer.serialize_map(Some(8))?;
        map.serialize_entry("vantage", &entry.vantage)?;
        map.serialize_entry("resolved", &entry.resolved)?;
        map.serialize_entry("node_key", &entry.node_key)?;
        map.serialize_entry("asn", &entry.asn)?;
        map.serialize_entry("bgp_ls_id", &entry.bgp_ls_id)?;
        map.serialize_entry("router_id", &entry.router_id)?;
        map.serialize_entry("reachable_nodes", &entry.reachable_nodes)?;
        map.serialize_entry("peers", &entry.peers)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn orr_status_calls_rpc_and_renders_rows() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        status(connection, true).await.unwrap();
        assert!(
            server.state.last_list_orr_status.lock().await.is_some(),
            "ORR status request captured"
        );

        // Node label prefers the router-ID, falls back to the shortened
        // key, then `-` when unresolved.
        let resolved = OrrVantageStatusEntry {
            vantage: "10.0.8.1".to_string(),
            resolved: true,
            node_key: "0200000000000000000000fc00020000".to_string(),
            asn: 64512,
            bgp_ls_id: 0,
            router_id: "000000000001".to_string(),
            reachable_nodes: 4,
            peers: vec!["192.0.2.1".to_string()],
        };
        let unresolved = OrrVantageStatusEntry {
            vantage: "203.0.113.9".to_string(),
            resolved: false,
            node_key: String::new(),
            asn: 0,
            bgp_ls_id: 0,
            router_id: String::new(),
            reachable_nodes: 0,
            peers: vec!["192.0.2.2".to_string()],
        };
        assert_eq!(node_label(&resolved), "000000000001");
        assert_eq!(node_label(&unresolved), "-");
        let mut no_router_id = resolved.clone();
        no_router_id.router_id = String::new();
        assert_eq!(node_label(&no_router_id), "02000000000000..");

        print_orr_status(
            &ListOrrStatusResponse {
                vantages: vec![resolved, unresolved],
                topology_nodes: 4,
                topology_links: 4,
            },
            false,
        )
        .unwrap();
        print_orr_status(&ListOrrStatusResponse::default(), false).unwrap();
    }
}
