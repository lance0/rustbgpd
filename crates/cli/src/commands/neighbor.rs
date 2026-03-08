use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonNeighbor, JsonNeighborDetail};
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    AddNeighborRequest, DeleteNeighborRequest, DisableNeighborRequest, EnableNeighborRequest,
    GetNeighborStateRequest, ListNeighborsRequest, NeighborConfig, SoftResetInRequest,
};

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_neighbors(ListNeighborsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonNeighbor> = resp
            .neighbors
            .iter()
            .map(|n| {
                let cfg = n.config.as_ref();
                JsonNeighbor {
                    address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
                    remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
                    state: output::format_state(n.state).to_string(),
                    uptime_seconds: n.uptime_seconds,
                    prefixes_received: n.prefixes_received,
                    prefixes_sent: n.prefixes_sent,
                    description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize neighbor list as JSON")
        );
    } else if resp.neighbors.is_empty() {
        println!("No neighbors configured");
    } else {
        output::print_neighbor_table(&resp.neighbors);
    }
    Ok(())
}

pub async fn show(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let n = client
        .get_neighbor_state(GetNeighborStateRequest {
            address: address.to_string(),
        })
        .await?
        .into_inner();

    let cfg = n.config.as_ref();
    if json {
        let out = JsonNeighborDetail {
            address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
            remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
            state: output::format_state(n.state).to_string(),
            uptime_seconds: n.uptime_seconds,
            prefixes_received: n.prefixes_received,
            prefixes_sent: n.prefixes_sent,
            updates_received: n.updates_received,
            updates_sent: n.updates_sent,
            notifications_received: n.notifications_received,
            notifications_sent: n.notifications_sent,
            flap_count: n.flap_count,
            last_error: n.last_error.clone(),
            description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
            hold_time: cfg.map(|c| c.hold_time).unwrap_or(0),
            families: cfg.map(|c| c.families.clone()).unwrap_or_default(),
            peer_group: cfg.map(|c| c.peer_group.clone()).unwrap_or_default(),
            route_server_client: cfg.map(|c| c.route_server_client).unwrap_or(false),
            add_path_receive: cfg.map(|c| c.add_path_receive).unwrap_or(false),
            add_path_send: cfg.map(|c| c.add_path_send).unwrap_or(false),
            add_path_send_max: cfg.map(|c| c.add_path_send_max).unwrap_or(0),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize neighbor detail as JSON")
        );
    } else {
        println!(
            "Neighbor:              {}",
            cfg.map(|c| c.address.as_str()).unwrap_or("")
        );
        println!(
            "Remote ASN:            {}",
            cfg.map(|c| c.remote_asn).unwrap_or(0)
        );
        println!(
            "Description:           {}",
            cfg.map(|c| c.description.as_str()).unwrap_or("")
        );
        println!(
            "Hold Time:             {}",
            cfg.map(|c| c.hold_time).unwrap_or(0)
        );
        println!(
            "Families:              {}",
            cfg.map(|c| c.families.join(", ")).unwrap_or_default()
        );
        let peer_group = cfg.map(|c| c.peer_group.as_str()).unwrap_or("");
        if !peer_group.is_empty() {
            println!("Peer Group:            {peer_group}");
        }
        println!(
            "Route Server Client:   {}",
            cfg.map(|c| c.route_server_client).unwrap_or(false)
        );
        println!(
            "Add-Path Receive:      {}",
            cfg.map(|c| c.add_path_receive).unwrap_or(false)
        );
        println!(
            "Add-Path Send:         {}",
            cfg.map(|c| c.add_path_send).unwrap_or(false)
        );
        let add_path_send_max = cfg.map(|c| c.add_path_send_max).unwrap_or(0);
        if add_path_send_max > 0 {
            println!("Add-Path Send Max:     {add_path_send_max}");
        }
        println!("State:                 {}", output::colored_state(n.state));
        println!(
            "Uptime:                {}",
            output::format_duration(n.uptime_seconds)
        );
        println!("Prefixes Received:     {}", n.prefixes_received);
        println!("Prefixes Sent:         {}", n.prefixes_sent);
        println!("Updates Received:      {}", n.updates_received);
        println!("Updates Sent:          {}", n.updates_sent);
        println!("Notifications Received:{}", n.notifications_received);
        println!("Notifications Sent:    {}", n.notifications_sent);
        println!("Flap Count:            {}", n.flap_count);
        if !n.last_error.is_empty() {
            println!("Last Error:            {}", n.last_error);
        }
    }
    Ok(())
}

pub struct AddNeighborOpts {
    pub asn: u32,
    pub description: Option<String>,
    pub hold_time: Option<u32>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<String>,
    pub route_server_client: bool,
    pub add_path_receive: bool,
    pub add_path_send: bool,
    pub add_path_send_max: u32,
}

pub async fn add(
    connection: Connection,
    address: &str,
    opts: AddNeighborOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_neighbor(AddNeighborRequest {
            config: Some(NeighborConfig {
                address: address.to_string(),
                remote_asn: opts.asn,
                description: opts.description.unwrap_or_default(),
                hold_time: opts.hold_time.unwrap_or(0),
                max_prefixes: opts.max_prefixes.unwrap_or(0),
                families: opts.families,
                peer_group: String::new(),
                remove_private_as: String::new(),
                route_server_client: opts.route_server_client,
                add_path_receive: opts.add_path_receive,
                add_path_send: opts.add_path_send,
                add_path_send_max: opts.add_path_send_max,
            }),
        })
        .await?;
    output::print_result(
        json,
        "add_neighbor",
        address,
        &format!("Neighbor {address} added"),
    );
    Ok(())
}

pub async fn delete(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_neighbor(DeleteNeighborRequest {
            address: address.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_neighbor",
        address,
        &format!("Neighbor {address} deleted"),
    );
    Ok(())
}

pub async fn enable(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .enable_neighbor(EnableNeighborRequest {
            address: address.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "enable_neighbor",
        address,
        &format!("Neighbor {address} enabled"),
    );
    Ok(())
}

pub async fn disable(
    connection: Connection,
    address: &str,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .disable_neighbor(DisableNeighborRequest {
            address: address.to_string(),
            reason: reason.unwrap_or_default(),
        })
        .await?;
    output::print_result(
        json,
        "disable_neighbor",
        address,
        &format!("Neighbor {address} disabled"),
    );
    Ok(())
}

pub async fn softreset(
    connection: Connection,
    address: &str,
    family: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .soft_reset_in(SoftResetInRequest {
            address: address.to_string(),
            families: family.into_iter().collect(),
        })
        .await?;
    output::print_result(
        json,
        "softreset",
        address,
        &format!("Soft reset requested for {address}"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn add_sends_route_server_and_add_path_fields() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        add(
            connection,
            "10.0.0.2",
            AddNeighborOpts {
                asn: 65002,
                description: Some("peer-2".to_string()),
                hold_time: Some(90),
                max_prefixes: Some(1000),
                families: vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()],
                route_server_client: true,
                add_path_receive: true,
                add_path_send: true,
                add_path_send_max: 4,
            },
            true,
        )
        .await
        .unwrap();

        let request = server.state.last_add_neighbor.lock().await.clone().unwrap();
        assert!(request.route_server_client);
        assert!(request.add_path_receive);
        assert!(request.add_path_send);
        assert_eq!(request.add_path_send_max, 4);
        assert_eq!(request.remote_asn, 65002);
    }

    #[tokio::test]
    async fn softreset_sends_family_filter() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        softreset(
            connection,
            "10.0.0.2",
            Some("ipv6_unicast".to_string()),
            true,
        )
        .await
        .unwrap();

        let request = server.state.last_softreset.lock().await.clone().unwrap();
        assert_eq!(request.address, "10.0.0.2");
        assert_eq!(request.families, vec!["ipv6_unicast".to_string()]);
    }
}
