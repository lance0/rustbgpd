//! `rbgp topology nodes|links` — RFC 9107 ORR topology derived from the
//! BGP-LS Adj-RIB-In union across peers.

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::{
    ListTopologyLinksRequest, ListTopologyNodesRequest, TopologyLinkEntry, TopologyNodeEntry,
};
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};

pub async fn nodes(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client = connection.rib_listing_client();
    let resp = client
        .list_topology_nodes(ListTopologyNodesRequest {})
        .await?
        .into_inner();
    print_topology_nodes(&resp.nodes, json)
}

pub async fn links(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client = connection.rib_listing_client();
    let resp = client
        .list_topology_links(ListTopologyLinksRequest {})
        .await?
        .into_inner();
    print_topology_links(&resp.links, json)
}

/// Shorten a full node-key hex string for table display.
fn short_key(key: &str) -> String {
    if key.len() > 16 {
        format!("{}..", &key[..14])
    } else {
        key.to_string()
    }
}

/// Table label for a link endpoint: IGP Router-ID when present, else the
/// shortened node key.
fn endpoint_label(router_id: &str, key: &str) -> String {
    if router_id.is_empty() {
        short_key(key)
    } else {
        router_id.to_string()
    }
}

fn print_topology_nodes(nodes: &[TopologyNodeEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonTopologyNodes(nodes))?;
    } else if nodes.is_empty() {
        println!("No topology nodes");
    } else {
        println!("{:<18} {:<10} {:<18} Links", "Key", "AS", "Router-ID");
        println!("{}", "-".repeat(56));
        for node in nodes {
            let asn = if node.asn == 0 {
                "-".to_string()
            } else {
                node.asn.to_string()
            };
            let router_id = if node.router_id.is_empty() {
                "-"
            } else {
                &node.router_id
            };
            println!(
                "{:<18} {:<10} {:<18} {}",
                short_key(&node.key),
                asn,
                router_id,
                node.link_count
            );
        }
    }
    Ok(())
}

fn print_topology_links(links: &[TopologyLinkEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonTopologyLinks(links))?;
    } else if links.is_empty() {
        println!("No topology links");
    } else {
        println!("{:<18} {:<18} {:<8} Addresses", "Local", "Remote", "Cost");
        println!("{}", "-".repeat(76));
        for link in links {
            println!(
                "{:<18} {:<18} {:<8} {}",
                endpoint_label(&link.local_router_id, &link.local_key),
                endpoint_label(&link.remote_router_id, &link.remote_key),
                link.cost,
                link.addresses.join(" ")
            );
        }
    }
    Ok(())
}

struct JsonTopologyNodes<'a>(&'a [TopologyNodeEntry]);

impl Serialize for JsonTopologyNodes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for node in self.0 {
            seq.serialize_element(&JsonTopologyNodeRef(node))?;
        }
        seq.end()
    }
}

struct JsonTopologyNodeRef<'a>(&'a TopologyNodeEntry);

impl Serialize for JsonTopologyNodeRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let node = self.0;
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("key", &node.key)?;
        map.serialize_entry("asn", &node.asn)?;
        map.serialize_entry("bgp_ls_id", &node.bgp_ls_id)?;
        map.serialize_entry("router_id", &node.router_id)?;
        map.serialize_entry("link_count", &node.link_count)?;
        map.end()
    }
}

struct JsonTopologyLinks<'a>(&'a [TopologyLinkEntry]);

impl Serialize for JsonTopologyLinks<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for link in self.0 {
            seq.serialize_element(&JsonTopologyLinkRef(link))?;
        }
        seq.end()
    }
}

struct JsonTopologyLinkRef<'a>(&'a TopologyLinkEntry);

impl Serialize for JsonTopologyLinkRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let link = self.0;
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("local_key", &link.local_key)?;
        map.serialize_entry("local_router_id", &link.local_router_id)?;
        map.serialize_entry("remote_key", &link.remote_key)?;
        map.serialize_entry("remote_router_id", &link.remote_router_id)?;
        map.serialize_entry("cost", &link.cost)?;
        map.serialize_entry("addresses", &link.addresses)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn topology_nodes_calls_rpc_and_renders_rows() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        nodes(connection, true).await.unwrap();
        assert!(
            server.state.last_list_topology_nodes.lock().await.is_some(),
            "topology nodes request captured"
        );

        // Table rendering: 0/empty descriptor fields render as `-`, long
        // keys are shortened.
        let rows = vec![
            TopologyNodeEntry {
                key: "0200000000000000000000fc00020000".to_string(),
                asn: 64512,
                bgp_ls_id: 0,
                router_id: "000000000001".to_string(),
                link_count: 2,
            },
            TopologyNodeEntry {
                key: "02aabb".to_string(),
                asn: 0,
                bgp_ls_id: 0,
                router_id: String::new(),
                link_count: 0,
            },
        ];
        assert_eq!(short_key(&rows[0].key), "02000000000000..");
        assert_eq!(short_key(&rows[1].key), "02aabb");
        print_topology_nodes(&rows, false).unwrap();
        print_topology_nodes(&[], false).unwrap();
    }

    #[tokio::test]
    async fn topology_links_calls_rpc_and_renders_rows() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        links(connection, true).await.unwrap();
        assert!(
            server.state.last_list_topology_links.lock().await.is_some(),
            "topology links request captured"
        );

        // Endpoint label prefers the router-ID, falls back to the key.
        let row = TopologyLinkEntry {
            local_key: "02aabb".to_string(),
            local_router_id: "000000000001".to_string(),
            remote_key: "02ccdd".to_string(),
            remote_router_id: String::new(),
            cost: 10,
            addresses: vec!["10.0.8.1".to_string(), "10.0.8.2".to_string()],
        };
        assert_eq!(
            endpoint_label(&row.local_router_id, &row.local_key),
            "000000000001"
        );
        assert_eq!(
            endpoint_label(&row.remote_router_id, &row.remote_key),
            "02ccdd"
        );
        print_topology_links(&[row], false).unwrap();
        print_topology_links(&[], false).unwrap();
    }
}
