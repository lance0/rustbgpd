use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonNeighbor, JsonNeighborDetail};
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    AddNeighborRequest, DeleteNeighborRequest, DisableNeighborRequest, EnableNeighborRequest,
    GetNeighborStateRequest, ListNeighborsRequest, NeighborConfig, SetGracefulShutdownRequest,
    SoftResetInRequest,
};

fn split_scoped_address(address: &str) -> (String, String) {
    address.rsplit_once('%').map_or_else(
        || (address.to_string(), String::new()),
        |(addr, iface)| (addr.to_string(), iface.to_string()),
    )
}

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
                    interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
                    remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
                    state: output::format_state_with_stale(n.state, n.stale).to_string(),
                    stale: n.stale,
                    uptime_seconds: n.uptime_seconds,
                    prefixes_received: n.prefixes_received,
                    prefixes_sent: n.prefixes_sent,
                    description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
                }
            })
            .collect();
        output::print_json_pretty(&out)?;
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
    let (address_only, interface) = split_scoped_address(address);
    let n = client
        .get_neighbor_state(GetNeighborStateRequest {
            address: address_only,
            interface,
        })
        .await?
        .into_inner();

    let cfg = n.config.as_ref();
    // Unicast distribution mode, mirroring the RIB's mode ladder
    // (negotiated Add-Path send outranks the per-client-best fallback).
    // An ORR vantage is not on the runtime NeighborConfig surface, so
    // it is recognized via the update-group ungrouped reason.
    //
    // LAN-211 #6: this reads the *configured* add_path_send/per_client_best
    // bits echoed on NeighborConfig, so a peer that configured Add-Path but
    // never negotiated it still prints "add-path". A negotiated/effective
    // mode is not surfaced on NeighborState (update_group is a shadow-mode
    // grouping string, "group:N" when grouped), so fixing this needs new
    // plumbing; deferred.
    let distribution_mode = if cfg.map(|c| c.add_path_send).unwrap_or(false) {
        "add-path"
    } else if cfg.map(|c| c.per_client_best).unwrap_or(false) {
        "per-client-best"
    } else if n.update_group == "orr_vantage" {
        "orr"
    } else {
        "single-best"
    };
    if json {
        let out = JsonNeighborDetail {
            address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
            interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
            remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
            state: output::format_state_with_stale(n.state, n.stale).to_string(),
            stale: n.stale,
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
            send_hold_time: cfg.and_then(|c| c.send_hold_time).unwrap_or(0),
            families: cfg.map(|c| c.families.clone()).unwrap_or_default(),
            peer_group: cfg.map(|c| c.peer_group.clone()).unwrap_or_default(),
            route_server_client: cfg.map(|c| c.route_server_client).unwrap_or(false),
            per_client_best: cfg.map(|c| c.per_client_best).unwrap_or(false),
            distribution_mode: distribution_mode.to_string(),
            add_path_receive: cfg.map(|c| c.add_path_receive).unwrap_or(false),
            add_path_send: cfg.map(|c| c.add_path_send).unwrap_or(false),
            add_path_send_max: cfg.map(|c| c.add_path_send_max).unwrap_or(0),
            role: cfg.map(|c| c.role.clone()).unwrap_or_default(),
            strict_role: cfg.map(|c| c.strict_role).unwrap_or(false),
            remote_role: n.remote_role.clone(),
            role_negotiated: n.role_negotiated,
            otc_routes_blocked: n.otc_routes_blocked,
            import_policy_routes_permitted: n.import_policy_routes_permitted,
            import_policy_routes_denied: n.import_policy_routes_denied,
            export_policy_routes_permitted: n.export_policy_routes_permitted,
            export_policy_routes_denied: n.export_policy_routes_denied,
            update_group: n.update_group.clone(),
        };
        output::print_json_pretty(&out)?;
    } else {
        println!(
            "Neighbor:              {}",
            cfg.map(|c| c.address.as_str()).unwrap_or("")
        );
        let interface = cfg.map(|c| c.interface.as_str()).unwrap_or("");
        if !interface.is_empty() {
            println!("Interface:             {interface}");
        }
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
            "Send Hold Time:        {}",
            cfg.and_then(|c| c.send_hold_time).unwrap_or(0)
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
        if cfg.map(|c| c.per_client_best).unwrap_or(false) {
            println!("Per-Client Best:       true");
        }
        println!("Distribution Mode:     {distribution_mode}");
        let role = cfg.map(|c| c.role.as_str()).unwrap_or("");
        if !role.is_empty() {
            println!("BGP Role:              {role}");
            println!(
                "Strict Role:           {}",
                cfg.map(|c| c.strict_role).unwrap_or(false)
            );
            let remote_role = n.remote_role.as_str();
            println!(
                "Remote Role:           {}",
                if remote_role.is_empty() {
                    "not advertised"
                } else {
                    remote_role
                }
            );
            println!("Role Negotiated:       {}", n.role_negotiated);
        }
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
        println!(
            "State:                 {}",
            output::colored_state_with_stale(n.state, n.stale)
        );
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
        println!("OTC Routes Blocked:    {}", n.otc_routes_blocked);
        println!("Policy Stats:");
        println!(
            "  Import — permitted: {} denied: {}",
            n.import_policy_routes_permitted, n.import_policy_routes_denied
        );
        println!(
            "  Export — permitted: {} denied: {}",
            n.export_policy_routes_permitted, n.export_policy_routes_denied
        );
        if !n.update_group.is_empty() {
            println!("Update Group:          {}", n.update_group);
        }
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
    pub send_hold_time: Option<u32>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<String>,
    pub route_server_client: bool,
    pub per_client_best: bool,
    pub role: Option<String>,
    pub strict_role: bool,
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
    let (address_only, interface) = split_scoped_address(address);
    client
        .add_neighbor(AddNeighborRequest {
            config: Some(NeighborConfig {
                address: address_only,
                interface,
                remote_asn: opts.asn,
                description: opts.description.unwrap_or_default(),
                hold_time: opts.hold_time.unwrap_or(0),
                send_hold_time: opts.send_hold_time,
                max_prefixes: opts.max_prefixes.unwrap_or(0),
                families: opts.families,
                peer_group: String::new(),
                remove_private_as: String::new(),
                route_server_client: opts.route_server_client,
                per_client_best: opts.per_client_best,
                role: opts.role.unwrap_or_default(),
                strict_role: opts.strict_role,
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
    )?;
    output::print_next_step(
        json,
        &format!(
            "watch the session establish: rbgp watch {address} (or check: rbgp neighbor {address})"
        ),
    );
    Ok(())
}

pub async fn delete(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let (address_only, interface) = split_scoped_address(address);
    client
        .delete_neighbor(DeleteNeighborRequest {
            address: address_only,
            interface,
        })
        .await?;
    output::print_result(
        json,
        "delete_neighbor",
        address,
        &format!("Neighbor {address} deleted"),
    )
}

pub async fn enable(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let (address_only, interface) = split_scoped_address(address);
    client
        .enable_neighbor(EnableNeighborRequest {
            address: address_only,
            interface,
        })
        .await?;
    output::print_result(
        json,
        "enable_neighbor",
        address,
        &format!("Neighbor {address} enabled"),
    )
}

pub async fn disable(
    connection: Connection,
    address: &str,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let (address_only, interface) = split_scoped_address(address);
    client
        .disable_neighbor(DisableNeighborRequest {
            address: address_only,
            reason: reason.unwrap_or_default(),
            interface,
        })
        .await?;
    output::print_result(
        json,
        "disable_neighbor",
        address,
        &format!("Neighbor {address} disabled"),
    )?;
    output::print_next_step(
        json,
        &format!("re-enable when ready: rbgp neighbor {address} enable"),
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
    let (address_only, interface) = split_scoped_address(address);
    client
        .soft_reset_in(SoftResetInRequest {
            address: address_only,
            families: family.into_iter().collect(),
            interface,
        })
        .await?;
    output::print_result(
        json,
        "softreset",
        address,
        &format!("Soft reset requested for {address}"),
    )
}

/// Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates.
/// `peer = None` applies to every currently-managed peer (operator
/// running planned maintenance on the whole router).
pub async fn set_graceful_shutdown(
    connection: Connection,
    peer: Option<String>,
    enabled: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let address = peer.clone().unwrap_or_default();
    let (address_only, interface) = split_scoped_address(&address);
    client
        .set_graceful_shutdown(SetGracefulShutdownRequest {
            address: address_only,
            enabled,
            interface,
        })
        .await?;
    let scope = peer.as_deref().unwrap_or("all peers");
    let verb = if enabled { "enabled" } else { "cleared" };
    output::print_result(
        json,
        "set_graceful_shutdown",
        scope,
        &format!("GRACEFUL_SHUTDOWN advertise {verb} for {scope}"),
    )?;
    let status_cmd = match peer.as_deref() {
        Some(peer) => format!("rbgp neighbor {peer}"),
        None => "rbgp neighbor".to_string(),
    };
    output::print_next_step(json, &format!("check session status: {status_cmd}"));
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
                send_hold_time: Some(480),
                max_prefixes: Some(1000),
                families: vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()],
                route_server_client: true,
                per_client_best: false,
                role: Some("rs".to_string()),
                strict_role: true,
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
        assert_eq!(request.role, "rs");
        assert!(request.strict_role);
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
