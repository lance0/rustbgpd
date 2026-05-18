//! `rustbgpctl peer-group ...` — wraps PeerGroupService gRPCs.
//!
//! - `list` / `get NAME` / `set NAME --from-file FILE` / `delete NAME`
//!   for named `[[peer_groups]]` entries.
//! - `attach ADDR --group NAME` / `detach ADDR` to bind / unbind a
//!   neighbor to / from a peer group.

use serde::Serialize;

use crate::commands::policy_input::{JsonPeerGroupDefinition, load_json};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::peer_group_service_client::PeerGroupServiceClient;
use crate::proto::{
    ClearNeighborPeerGroupRequest, DeletePeerGroupRequest, GetPeerGroupRequest,
    ListPeerGroupsRequest, SetNeighborPeerGroupRequest, SetPeerGroupRequest,
};

#[derive(Debug, Serialize)]
struct JsonPeerGroupSummary {
    name: String,
    families: Vec<String>,
    has_md5_password: bool,
    add_path_send: bool,
    add_path_send_max: u32,
    import_chain_len: usize,
    export_chain_len: usize,
}

#[derive(Debug, Serialize)]
struct JsonPeerGroupDetail {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hold_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_prefixes: Option<u32>,
    has_md5_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_security: Option<bool>,
    families: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graceful_restart: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gr_restart_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gr_stale_routes_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llgr_stale_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ipv6_nexthop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_reflector_client: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_server_client: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_private_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_path_receive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_path_send: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_path_send_max: Option<u32>,
    inline_import_policy_count: usize,
    inline_export_policy_count: usize,
    import_policy_chain: Vec<String>,
    export_policy_chain: Vec<String>,
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_peer_groups(ListPeerGroupsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonPeerGroupSummary> = resp
            .peer_groups
            .iter()
            .map(|pg| {
                let def = pg.definition.as_ref();
                JsonPeerGroupSummary {
                    name: pg.name.clone(),
                    families: def.map(|d| d.families.clone()).unwrap_or_default(),
                    has_md5_password: def.is_some_and(|d| d.has_md5_password),
                    add_path_send: def.and_then(|d| d.add_path_send).unwrap_or(false),
                    add_path_send_max: def.and_then(|d| d.add_path_send_max).unwrap_or(0),
                    import_chain_len: def.map(|d| d.import_policy_chain.len()).unwrap_or(0),
                    export_chain_len: def.map(|d| d.export_policy_chain.len()).unwrap_or(0),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize peer-group list as JSON")
        );
    } else if resp.peer_groups.is_empty() {
        println!("No peer groups configured");
    } else {
        println!("{:<32} {:<24} IMPORT EXPORT", "NAME", "FAMILIES");
        for pg in &resp.peer_groups {
            let def = pg.definition.as_ref();
            let families = def.map(|d| d.families.join(",")).unwrap_or_default();
            let import_len = def.map(|d| d.import_policy_chain.len()).unwrap_or(0);
            let export_len = def.map(|d| d.export_policy_chain.len()).unwrap_or(0);
            println!(
                "{:<32} {:<24} {:>6} {:>6}",
                pg.name, families, import_len, export_len
            );
        }
    }
    Ok(())
}

pub async fn get(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_peer_group(GetPeerGroupRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();

    let def = resp.definition.unwrap_or_default();
    if json {
        let detail = JsonPeerGroupDetail {
            name: resp.name.clone(),
            hold_time: def.hold_time,
            max_prefixes: def.max_prefixes,
            has_md5_password: def.has_md5_password,
            ttl_security: def.ttl_security,
            families: def.families.clone(),
            graceful_restart: def.graceful_restart,
            gr_restart_time: def.gr_restart_time,
            gr_stale_routes_time: def.gr_stale_routes_time,
            llgr_stale_time: def.llgr_stale_time,
            local_ipv6_nexthop: def.local_ipv6_nexthop.clone(),
            route_reflector_client: def.route_reflector_client,
            route_server_client: def.route_server_client,
            remove_private_as: def.remove_private_as.clone(),
            add_path_receive: def.add_path_receive,
            add_path_send: def.add_path_send,
            add_path_send_max: def.add_path_send_max,
            inline_import_policy_count: def.import_policy.len(),
            inline_export_policy_count: def.export_policy.len(),
            import_policy_chain: def.import_policy_chain.clone(),
            export_policy_chain: def.export_policy_chain.clone(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&detail)
                .expect("failed to serialize peer-group detail as JSON")
        );
    } else {
        println!("Name:                  {}", resp.name);
        if let Some(h) = def.hold_time {
            println!("Hold Time:             {h}");
        }
        if let Some(m) = def.max_prefixes {
            println!("Max Prefixes:          {m}");
        }
        if def.has_md5_password {
            println!("MD5 Password:          (set)");
        }
        if let Some(t) = def.ttl_security {
            println!("TTL Security:          {t}");
        }
        if !def.families.is_empty() {
            println!("Families:              {}", def.families.join(", "));
        }
        if let Some(g) = def.graceful_restart {
            println!("Graceful Restart:      {g}");
        }
        if let Some(t) = def.gr_restart_time {
            println!("GR Restart Time:       {t}");
        }
        if let Some(t) = def.gr_stale_routes_time {
            println!("GR Stale Routes Time:  {t}");
        }
        if let Some(t) = def.llgr_stale_time {
            println!("LLGR Stale Time:       {t}");
        }
        if let Some(n) = &def.local_ipv6_nexthop {
            println!("Local IPv6 Nexthop:    {n}");
        }
        if let Some(rr) = def.route_reflector_client {
            println!("RR Client:             {rr}");
        }
        if let Some(rs) = def.route_server_client {
            println!("RS Client:             {rs}");
        }
        if let Some(r) = &def.remove_private_as {
            println!("Remove Private AS:     {r}");
        }
        if let Some(b) = def.add_path_receive {
            println!("Add-Path Receive:      {b}");
        }
        if let Some(b) = def.add_path_send {
            println!("Add-Path Send:         {b}");
        }
        if let Some(m) = def.add_path_send_max
            && m > 0
        {
            println!("Add-Path Send Max:     {m}");
        }
        println!(
            "Inline Import Policy:  {} statements",
            def.import_policy.len()
        );
        println!(
            "Inline Export Policy:  {} statements",
            def.export_policy.len()
        );
        println!(
            "Import Chain:          {}",
            if def.import_policy_chain.is_empty() {
                "(none)".to_string()
            } else {
                def.import_policy_chain.join(" -> ")
            }
        );
        println!(
            "Export Chain:          {}",
            if def.export_policy_chain.is_empty() {
                "(none)".to_string()
            } else {
                def.export_policy_chain.join(" -> ")
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
    let definition: JsonPeerGroupDefinition = load_json(from_file)?;
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .set_peer_group(SetPeerGroupRequest {
            name: name.to_string(),
            definition: Some(definition.into()),
        })
        .await?;
    output::print_result(
        json,
        "set_peer_group",
        name,
        &format!("Peer group {name} set"),
    );
    Ok(())
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_peer_group(DeletePeerGroupRequest {
            name: name.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_peer_group",
        name,
        &format!("Peer group {name} deleted"),
    );
    Ok(())
}

pub async fn attach(
    connection: Connection,
    address: &str,
    group: &str,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .set_neighbor_peer_group(SetNeighborPeerGroupRequest {
            address: address.to_string(),
            peer_group: group.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "attach_peer_group",
        address,
        &format!("Neighbor {address} attached to peer-group {group}"),
    );
    Ok(())
}

pub async fn detach(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PeerGroupServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .clear_neighbor_peer_group(ClearNeighborPeerGroupRequest {
            address: address.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "detach_peer_group",
        address,
        &format!("Neighbor {address} detached from its peer-group"),
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
    async fn set_reads_json_and_sends_definition() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"{{"hold_time":120,"families":["ipv4_unicast"],"import_policy_chain":["a"],"add_path_send":true,"add_path_send_max":4}}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        set(connection, "transit", tmp.path().to_str().unwrap(), true)
            .await
            .unwrap();

        let captured = server
            .state
            .last_set_peer_group
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "transit");
        let def = captured.definition.unwrap();
        assert_eq!(def.hold_time, Some(120));
        assert_eq!(def.families, vec!["ipv4_unicast".to_string()]);
        assert_eq!(def.import_policy_chain, vec!["a".to_string()]);
        assert_eq!(def.add_path_send, Some(true));
        assert_eq!(def.add_path_send_max, Some(4));
    }

    #[tokio::test]
    async fn delete_sends_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "transit", true).await.unwrap();
        let captured = server
            .state
            .last_delete_peer_group
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "transit");
    }

    #[tokio::test]
    async fn attach_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        attach(connection, "10.0.0.2", "transit", true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_set_neighbor_peer_group
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
        assert_eq!(captured.peer_group, "transit");
    }

    #[tokio::test]
    async fn detach_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        detach(connection, "10.0.0.2", true).await.unwrap();
        let captured = server
            .state
            .last_clear_neighbor_peer_group
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
    }
}
