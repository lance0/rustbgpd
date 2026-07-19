use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonNeighbor, JsonNeighborDetail, JsonPathsLimit, JsonSelectionDeferralFamily,
    JsonTcpAoKeyState, JsonTcpAoState,
};
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

pub async fn list(connection: Connection, json: bool, wide: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_neighbors(ListNeighborsRequest {})
        .await?
        .into_inner();

    if json {
        // `--wide` is display-only: JSON always carries every field.
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
                    messages_received: n.messages_received,
                    messages_sent: n.messages_sent,
                    flap_count: n.flap_count,
                    route_reflector_client: n.route_reflector_client,
                    description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
                }
            })
            .collect();
        output::print_json_pretty(&out)?;
    } else if resp.neighbors.is_empty() {
        println!("{EMPTY_NEIGHBOR_LIST}");
    } else {
        output::print_neighbor_table(&resp.neighbors, wide);
    }
    Ok(())
}

/// Friendly empty state: what happened, plus the one command that
/// changes it.
const EMPTY_NEIGHBOR_LIST: &str =
    "no neighbors configured — add one: rbgp neighbor <addr> add --remote-asn <asn>";

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
    let distribution_mode = effective_distribution_mode_label(
        n.effective_distribution_mode,
        cfg.map(|c| c.add_path_send).unwrap_or(false),
        cfg.map(|c| c.per_client_best).unwrap_or(false),
        &n.update_group,
    );
    let max_prefix_action = max_prefix_action_label(
        &n.max_prefix_action,
        cfg.and_then(|config| config.max_prefix_restart_seconds),
    );
    if json {
        let out = JsonNeighborDetail {
            address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
            interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
            remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
            state: output::format_state_with_stale(n.state, n.stale).to_string(),
            stale: n.stale,
            slow_peer: n.slow_peer,
            graceful_shutdown_advertise_intent: n.graceful_shutdown_advertise_intent,
            uptime_seconds: n.uptime_seconds,
            prefixes_received: n.prefixes_received,
            prefixes_sent: n.prefixes_sent,
            updates_received: n.updates_received,
            updates_sent: n.updates_sent,
            notifications_received: n.notifications_received,
            notifications_sent: n.notifications_sent,
            messages_received: n.messages_received,
            messages_sent: n.messages_sent,
            flap_count: n.flap_count,
            last_error: n.last_error.clone(),
            max_prefix_action: max_prefix_action.to_string(),
            max_prefix_restart_seconds: cfg.and_then(|c| c.max_prefix_restart_seconds),
            max_prefix_restart_remaining_millis: n.max_prefix_restart_remaining_millis,
            authentication: authentication_label(n.authentication).to_string(),
            tcp_ao_health: tcp_ao_health_label(n.tcp_ao_health).to_string(),
            tcp_ao_desired_generation: n.tcp_ao_desired_generation,
            tcp_ao_applied_generation: n.tcp_ao_applied_generation,
            tcp_ao_rotation_phase: n.tcp_ao_rotation_phase.clone(),
            tcp_ao_rotation_error: n.tcp_ao_rotation_error.clone(),
            tcp_ao: n.tcp_ao.as_ref().map(|ao| JsonTcpAoState {
                current_key_id: ao.current_key_id,
                rnext_key_id: ao.rnext_key_id,
                ao_required: ao.ao_required,
                accept_icmps: ao.accept_icmps,
                packets_good: ao.packets_good,
                packets_bad: ao.packets_bad,
                packets_key_not_found: ao.packets_key_not_found,
                packets_ao_required: ao.packets_ao_required,
                packets_dropped_icmp: ao.packets_dropped_icmp,
                keys: ao
                    .keys
                    .iter()
                    .map(|key| JsonTcpAoKeyState {
                        peer_address: key.peer_address.clone(),
                        prefix_length: key.prefix_length,
                        send_id: key.send_id,
                        recv_id: key.recv_id,
                        algorithm: key.algorithm.clone(),
                        is_current: key.is_current,
                        is_rnext: key.is_rnext,
                        preferred: key.preferred,
                        deprecated: key.deprecated,
                        vrf_ifindex: key.vrf_ifindex,
                        packets_good: key.packets_good,
                        packets_bad: key.packets_bad,
                    })
                    .collect(),
            }),
            description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
            hold_time: cfg.map(|c| c.hold_time).unwrap_or(0),
            send_hold_time: cfg.and_then(|c| c.send_hold_time).unwrap_or(0),
            families: cfg.map(|c| c.families.clone()).unwrap_or_default(),
            peer_group: cfg.map(|c| c.peer_group.clone()).unwrap_or_default(),
            route_reflector_client: n.route_reflector_client,
            route_server_client: cfg.map(|c| c.route_server_client).unwrap_or(false),
            per_client_best: cfg.map(|c| c.per_client_best).unwrap_or(false),
            distribution_mode: distribution_mode.to_string(),
            add_path_receive: cfg.map(|c| c.add_path_receive).unwrap_or(false),
            add_path_send: cfg.map(|c| c.add_path_send).unwrap_or(false),
            add_path_send_max: cfg.map(|c| c.add_path_send_max).unwrap_or(0),
            paths_limits: n
                .paths_limits
                .iter()
                .map(|limit| {
                    let (effective_send_active, effective_send_max) =
                        normalized_effective_send(limit);
                    JsonPathsLimit {
                        family: limit.family.clone(),
                        configured_receive_max: limit.configured_receive_max,
                        advertised_receive_max: limit.advertised_receive_max,
                        received_receive_max: limit.received_receive_max,
                        effective_send_max: limit.effective_send_max,
                        effective_send_limit: effective_send_active.then_some(effective_send_max),
                        effective_send_active,
                    }
                })
                .collect(),
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
            selection_deferral: n
                .selection_deferral
                .iter()
                .map(|row| JsonSelectionDeferralFamily {
                    afi: row.afi,
                    safi: row.safi,
                    active: row.active,
                    waiter_state: row.waiter_state.clone(),
                    waiter_session_id: row.waiter_session_id,
                    blocking_waiters: row.blocking_waiters,
                    remaining_millis: row.remaining_millis,
                    release_reason: row.release_reason.clone(),
                })
                .collect(),
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
        println!("Max-Prefix Action:     {max_prefix_action}");
        if let Some(seconds) = cfg.and_then(|c| c.max_prefix_restart_seconds) {
            println!("Max-Prefix Restart:    {seconds}s configured");
        }
        if let Some(remaining) = n.max_prefix_restart_remaining_millis {
            println!("Max-Prefix Hold-Down:  {remaining}ms remaining");
        }
        println!(
            "Families:              {}",
            cfg.map(|c| c.families.join(", ")).unwrap_or_default()
        );
        let peer_group = cfg.map(|c| c.peer_group.as_str()).unwrap_or("");
        if !peer_group.is_empty() {
            println!("Peer Group:            {peer_group}");
        }
        println!("RR Client:             {}", n.route_reflector_client);
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
        for limit in &n.paths_limits {
            let (effective_send_active, effective_send_max) = normalized_effective_send(limit);
            let effective_send =
                paths_limit_effective_send_label(effective_send_active, effective_send_max);
            println!(
                "Paths-Limit {}: configured={} advertised={} received={} effective-send={}",
                limit.family,
                limit.configured_receive_max,
                limit.advertised_receive_max,
                limit.received_receive_max,
                effective_send
            );
        }
        println!(
            "State:                 {}",
            output::colored_state_with_stale(n.state, n.stale)
        );
        if n.slow_peer {
            println!("Slow Peer:             true (outbound queue persistently backlogged)");
        }
        println!(
            "GShut Advertise Intent: {}",
            graceful_shutdown_advertise_intent_label(n.graceful_shutdown_advertise_intent)
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
        println!("Messages Received:     {}", n.messages_received);
        println!("Messages Sent:         {}", n.messages_sent);
        println!(
            "Authentication:        {}",
            authentication_label(n.authentication)
        );
        if matches!(
            crate::proto::AuthenticationMode::try_from(n.authentication),
            Ok(crate::proto::AuthenticationMode::TcpAo)
        ) {
            println!(
                "TCP-AO Health:        {}",
                tcp_ao_health_label(n.tcp_ao_health)
            );
            println!(
                "TCP-AO Rotation:      desired={} applied={} phase={}",
                n.tcp_ao_desired_generation, n.tcp_ao_applied_generation, n.tcp_ao_rotation_phase
            );
            if !n.tcp_ao_rotation_error.is_empty() {
                println!("TCP-AO Rotation Error: {}", n.tcp_ao_rotation_error);
            }
        }
        if let Some(ao) = &n.tcp_ao {
            println!(
                "TCP-AO Keys:           current={} rnext={}",
                ao.current_key_id
                    .map_or_else(|| "none".to_string(), |v| v.to_string()),
                ao.rnext_key_id
                    .map_or_else(|| "none".to_string(), |v| v.to_string())
            );
            println!(
                "TCP-AO Packets:        good={} bad={} key-not-found={} unsigned-required={}",
                ao.packets_good, ao.packets_bad, ao.packets_key_not_found, ao.packets_ao_required
            );
            for key in &ao.keys {
                println!(
                    "  MKT {}/{}: send={} recv={} algorithm={} current={} rnext={} preferred={} deprecated={} vrf-ifindex={} good={} bad={}",
                    key.peer_address,
                    key.prefix_length,
                    key.send_id,
                    key.recv_id,
                    key.algorithm,
                    key.is_current,
                    key.is_rnext,
                    key.preferred,
                    key.deprecated,
                    key.vrf_ifindex
                        .map_or_else(|| "unbound".to_string(), |value| value.to_string()),
                    key.packets_good,
                    key.packets_bad
                );
            }
        }
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
        if !n.selection_deferral.is_empty() {
            println!("Selection Deferral:");
            for row in &n.selection_deferral {
                let state = if row.active {
                    format!(
                        "active; waiter={}; session={}; blocking={}; remaining={}ms",
                        row.waiter_state,
                        row.waiter_session_id
                            .map_or_else(|| "none".to_string(), |id| id.to_string()),
                        row.blocking_waiters,
                        row.remaining_millis
                    )
                } else {
                    format!(
                        "released={}; waiter={}; session={}",
                        row.release_reason,
                        row.waiter_state,
                        row.waiter_session_id
                            .map_or_else(|| "none".to_string(), |id| id.to_string())
                    )
                };
                println!("  AFI {}/SAFI {} — {state}", row.afi, row.safi);
            }
        }
        println!("Flap Count:            {}", n.flap_count);
        if !n.last_error.is_empty() {
            println!("Last Error:            {}", n.last_error);
        }
    }
    Ok(())
}

fn authentication_label(value: i32) -> &'static str {
    match crate::proto::AuthenticationMode::try_from(value) {
        Ok(crate::proto::AuthenticationMode::TcpAo) => "tcp_ao",
        Ok(crate::proto::AuthenticationMode::Md5) => "md5",
        Ok(crate::proto::AuthenticationMode::Plaintext) => "plaintext",
        Ok(crate::proto::AuthenticationMode::Unspecified) | Err(_) => "unknown",
    }
}

fn graceful_shutdown_advertise_intent_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn max_prefix_action_label(reported: &str, restart_seconds: Option<u32>) -> &str {
    if reported.is_empty() {
        if restart_seconds.is_some() {
            "restart"
        } else {
            "shutdown"
        }
    } else {
        reported
    }
}

fn tcp_ao_health_label(value: i32) -> &'static str {
    match crate::proto::TcpAoHealth::try_from(value) {
        Ok(crate::proto::TcpAoHealth::NotApplicable) => "not_applicable",
        Ok(crate::proto::TcpAoHealth::Unavailable) => "unavailable",
        Ok(crate::proto::TcpAoHealth::Healthy) => "healthy",
        Ok(crate::proto::TcpAoHealth::Degraded) => "degraded",
        Ok(crate::proto::TcpAoHealth::Unspecified) | Err(_) => "unknown",
    }
}

fn effective_distribution_mode_label(
    value: i32,
    legacy_add_path_send: bool,
    legacy_per_client_best: bool,
    legacy_update_group: &str,
) -> &'static str {
    match crate::proto::EffectiveDistributionMode::try_from(value) {
        Ok(crate::proto::EffectiveDistributionMode::SingleBest) => "single-best",
        Ok(crate::proto::EffectiveDistributionMode::AddPath) => "add-path",
        Ok(crate::proto::EffectiveDistributionMode::Orr) => "orr",
        Ok(crate::proto::EffectiveDistributionMode::PerClientBest) => "per-client-best",
        Ok(crate::proto::EffectiveDistributionMode::Unknown) | Err(_) => "unknown",
        Ok(crate::proto::EffectiveDistributionMode::Unspecified) => {
            if legacy_add_path_send {
                "add-path"
            } else if legacy_per_client_best {
                "per-client-best"
            } else if legacy_update_group == "orr_vantage" {
                "orr"
            } else {
                "single-best"
            }
        }
    }
}

fn paths_limit_effective_send_label(active: bool, max: u32) -> String {
    if !active {
        "inactive".to_string()
    } else if max == 0 {
        "unlimited".to_string()
    } else {
        max.to_string()
    }
}

fn normalized_effective_send(limit: &crate::proto::PathsLimitState) -> (bool, u32) {
    if let Some(normalized) = limit.effective_send_limit {
        return (true, normalized);
    }
    match limit.effective_send_max {
        0 => (false, 0),
        u32::MAX => (true, 0),
        finite => (true, finite),
    }
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
    pub paths_limit_receive_max: u16,
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
                paths_limit_receive_max: u32::from(opts.paths_limit_receive_max),
                max_prefix_restart_seconds: None,
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

    #[test]
    fn effective_distribution_mode_is_live_and_backward_compatible() {
        assert_eq!(
            effective_distribution_mode_label(
                crate::proto::EffectiveDistributionMode::AddPath as i32,
                false,
                false,
                ""
            ),
            "add-path"
        );
        assert_eq!(
            effective_distribution_mode_label(
                crate::proto::EffectiveDistributionMode::PerClientBest as i32,
                false,
                false,
                ""
            ),
            "per-client-best"
        );
        assert_eq!(
            effective_distribution_mode_label(0, true, false, ""),
            "add-path"
        );
        assert_eq!(
            effective_distribution_mode_label(0, false, true, ""),
            "per-client-best"
        );
        assert_eq!(
            effective_distribution_mode_label(0, false, false, "orr_vantage"),
            "orr"
        );
        assert_eq!(
            effective_distribution_mode_label(
                crate::proto::EffectiveDistributionMode::Unknown as i32,
                true,
                true,
                "orr_vantage"
            ),
            "unknown"
        );
        assert_eq!(
            effective_distribution_mode_label(i32::MAX, true, true, "orr_vantage"),
            "unknown"
        );
    }

    #[test]
    fn paths_limit_effective_send_distinguishes_inactive_and_unlimited() {
        assert_eq!(paths_limit_effective_send_label(false, 0), "inactive");
        assert_eq!(paths_limit_effective_send_label(true, 0), "unlimited");
        assert_eq!(paths_limit_effective_send_label(true, 4), "4");
    }

    /// Load-bearing: inversion or collapsing rolling-upgrade absence into
    /// disabled changes one of these exact operator-facing labels.
    #[test]
    fn graceful_shutdown_advertise_intent_is_presence_aware() {
        assert_eq!(
            graceful_shutdown_advertise_intent_label(Some(true)),
            "enabled"
        );
        assert_eq!(
            graceful_shutdown_advertise_intent_label(Some(false)),
            "disabled"
        );
        assert_eq!(graceful_shutdown_advertise_intent_label(None), "unknown");
    }

    /// Load-bearing: returning the raw protobuf string makes both old-daemon
    /// cases blank instead of deriving a truthful action from config presence.
    #[test]
    fn max_prefix_action_is_rolling_upgrade_safe() {
        assert_eq!(max_prefix_action_label("", None), "shutdown");
        assert_eq!(max_prefix_action_label("", Some(30)), "restart");
        assert_eq!(max_prefix_action_label("shutdown", Some(30)), "shutdown");
    }

    #[test]
    fn paths_limit_new_and_legacy_servers_normalize_bidirectionally() {
        let row = |raw, normalized| crate::proto::PathsLimitState {
            effective_send_max: raw,
            effective_send_limit: normalized,
            ..Default::default()
        };

        assert_eq!(
            normalized_effective_send(&row(u32::MAX, Some(0))),
            (true, 0)
        );
        assert_eq!(normalized_effective_send(&row(4, Some(4))), (true, 4));
        assert_eq!(normalized_effective_send(&row(0, None)), (false, 0));
        assert_eq!(normalized_effective_send(&row(u32::MAX, None)), (true, 0));
        assert_eq!(normalized_effective_send(&row(3, None)), (true, 3));
        assert_eq!(normalized_effective_send(&row(0, Some(0))), (true, 0));
    }

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
                paths_limit_receive_max: 3,
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
        assert_eq!(request.paths_limit_receive_max, 3);
        assert_eq!(request.remote_asn, 65002);
    }

    /// The zero-peer human output must say what happened AND hand the
    /// operator the exact next command; `-j` mode bypasses it entirely
    /// and serializes the empty list as `[]`.
    #[test]
    fn empty_state_names_the_add_command_and_json_stays_pure() {
        assert_eq!(
            EMPTY_NEIGHBOR_LIST,
            "no neighbors configured — add one: rbgp neighbor <addr> add --remote-asn <asn>"
        );
        let json = serde_json::to_string_pretty(&Vec::<crate::output::JsonNeighbor>::new())
            .expect("serialize");
        assert_eq!(json, "[]");
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
