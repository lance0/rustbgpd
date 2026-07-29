use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonNegotiatedGracefulRestart, JsonNegotiatedSession, JsonNeighbor, JsonNeighborDetail,
    JsonOutboundPrefixLimit, JsonPathsLimit, JsonSelectionDeferralFamily, JsonTcpAoKeyState,
    JsonTcpAoState, JsonUpdateGroupComparison,
};
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    AddNeighborRequest, DeleteNeighborRequest, DisableNeighborRequest, EnableNeighborRequest,
    GetNeighborStateRequest, ListNeighborsRequest, NeighborConfig, RefreshOutboundRequest,
    SetGracefulShutdownRequest, SoftResetInRequest,
};

pub(super) fn bare_ip_rpc_address(address: &str) -> &str {
    let Some((bare, zone)) = address.split_once('%') else {
        return address;
    };
    if zone.is_empty() || zone.contains('%') {
        return address;
    }
    match bare.parse::<std::net::Ipv6Addr>() {
        Ok(ip) if ip.is_unicast_link_local() => bare,
        _ => address,
    }
}

pub(super) fn restore_matching_scoped_address(requested: Option<&str>, response: &mut String) {
    let Some(address) = requested else {
        return;
    };
    let bare = bare_ip_rpc_address(address);
    if bare == address {
        return;
    }
    if matches!(
        (
            bare.parse::<std::net::IpAddr>(),
            response.parse::<std::net::IpAddr>(),
        ),
        (Ok(requested_ip), Ok(response_ip)) if requested_ip == response_ip
    ) {
        address.clone_into(response);
    }
}

fn split_scoped_address(address: &str) -> (String, String) {
    address.rsplit_once('%').map_or_else(
        || (address.to_string(), String::new()),
        |(addr, iface)| (addr.to_string(), iface.to_string()),
    )
}

fn json_neighbor(n: &crate::proto::NeighborState) -> JsonNeighbor {
    let cfg = n.config.as_ref();
    JsonNeighbor {
        address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
        interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
        remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
        state: output::format_state_with_stale(n.state, n.stale).to_string(),
        stale: n.stale,
        slow_peer: n.slow_peer,
        uptime_seconds: n.uptime_seconds,
        prefixes_received: n.prefixes_received,
        prefixes_sent: n.prefixes_sent,
        messages_received: n.messages_received,
        messages_sent: n.messages_sent,
        flap_count: n.flap_count,
        last_error: n.last_error.clone(),
        route_reflector_client: n.route_reflector_client,
        description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
    }
}

pub async fn list(connection: Connection, json: bool, wide: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_neighbors(ListNeighborsRequest {})
        .await?
        .into_inner();

    if json {
        // `--wide` is display-only: JSON is unaffected by it and may omit
        // optional false healthy-state fields.
        let out: Vec<JsonNeighbor> = resp.neighbors.iter().map(json_neighbor).collect();
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

fn json_update_group_comparison(
    primary_neighbor: &str,
    comparison_neighbor: &str,
    value: Option<&crate::proto::UpdateGroupComparison>,
) -> Result<JsonUpdateGroupComparison, CliError> {
    let value = value.ok_or_else(|| {
        CliError::Rpc("update-group comparison is not supported by this daemon".into())
    })?;
    Ok(JsonUpdateGroupComparison {
        primary_neighbor: primary_neighbor.to_string(),
        comparison_neighbor: comparison_neighbor.to_string(),
        verdict: comparison_verdict_label(value.verdict).to_string(),
        primary_membership: comparison_membership_label(value.primary_membership).to_string(),
        comparison_membership: comparison_membership_label(value.comparison_membership).to_string(),
        differences: value
            .differences
            .iter()
            .map(|value| comparison_difference_label(*value).to_string())
            .collect(),
    })
}

#[derive(Debug)]
enum NeighborShow {
    Comparison(JsonUpdateGroupComparison),
    Detail(Box<crate::proto::NeighborState>),
}

async fn query_neighbor(
    connection: Connection,
    address: &str,
    compare: Option<&str>,
) -> Result<NeighborShow, CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let (address_only, interface) = split_scoped_address(address);
    let (compare_address, compare_interface) =
        compare.map(split_scoped_address).unwrap_or_default();
    let state = client
        .get_neighbor_state(GetNeighborStateRequest {
            address: address_only,
            interface,
            compare_address,
            compare_interface,
        })
        .await?
        .into_inner();
    match compare {
        Some(comparison) => json_update_group_comparison(
            address,
            comparison,
            state.update_group_comparison.as_ref(),
        )
        .map(NeighborShow::Comparison),
        None => Ok(NeighborShow::Detail(Box::new(state))),
    }
}

fn render_update_group_comparison(value: &JsonUpdateGroupComparison) -> String {
    let mut output = format!(
        "Update Group Compare: {} vs {} — {} ({} / {})\n",
        value.primary_neighbor,
        value.comparison_neighbor,
        value.verdict,
        value.primary_membership,
        value.comparison_membership
    );
    if !value.differences.is_empty() {
        output.push_str(&format!(
            "Differences:          {}\n",
            value.differences.join(", ")
        ));
    }
    output
}

pub async fn show(
    connection: Connection,
    address: &str,
    compare: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let n = match query_neighbor(connection, address, compare).await? {
        NeighborShow::Comparison(comparison) => {
            if json {
                output::print_json_pretty(&comparison)?;
            } else {
                print!("{}", render_update_group_comparison(&comparison));
            }
            return Ok(());
        }
        NeighborShow::Detail(state) => *state,
    };

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
    let effective_max_prefixes = effective_max_prefix_limit(
        n.effective_max_prefixes,
        cfg.map(|config| config.max_prefixes).unwrap_or(0),
    );
    if json {
        let (negotiation_available, negotiated_session) = negotiated_session_json(&n);
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
            prefixes_received_ipv4: n.prefixes_received_ipv4,
            prefixes_received_ipv6: n.prefixes_received_ipv6,
            prefixes_sent: n.prefixes_sent,
            updates_received: n.updates_received,
            updates_sent: n.updates_sent,
            notifications_received: n.notifications_received,
            notifications_sent: n.notifications_sent,
            messages_received: n.messages_received,
            messages_sent: n.messages_sent,
            flap_count: n.flap_count,
            last_error: n.last_error.clone(),
            effective_max_prefixes,
            effective_max_prefixes_ipv4: n.effective_max_prefixes_ipv4,
            effective_max_prefixes_ipv6: n.effective_max_prefixes_ipv6,
            max_prefix_headroom: n.max_prefix_headroom,
            max_prefix_headroom_ipv4: n.max_prefix_headroom_ipv4,
            max_prefix_headroom_ipv6: n.max_prefix_headroom_ipv6,
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
            min_hold_time: cfg.and_then(|c| c.min_hold_time),
            send_hold_time: cfg.and_then(|c| c.send_hold_time).unwrap_or(0),
            families: cfg.map(|c| c.families.clone()).unwrap_or_default(),
            required_families: cfg.map(|c| c.required_families.clone()).unwrap_or_default(),
            negotiation_available,
            negotiated_session,
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
            rfc8212_import_policy: rfc8212_policy_status_label(n.rfc8212_import_policy).to_string(),
            rfc8212_export_policy: rfc8212_policy_status_label(n.rfc8212_export_policy).to_string(),
            outbound_prefix_limits: n
                .outbound_prefix_limits
                .iter()
                .map(|row| JsonOutboundPrefixLimit {
                    family: row.family.clone(),
                    usage: row.usage,
                    limit: row.limit,
                    headroom: row.headroom,
                    blocking: row.blocking,
                    reason: row.reason.clone(),
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
        if let Some(minimum) = cfg.and_then(|c| c.min_hold_time) {
            println!("Minimum Hold Time:     {minimum}");
        }
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
        if let Some(required) = cfg
            .map(|c| &c.required_families)
            .filter(|required| !required.is_empty())
        {
            println!("Required Families:     {}", required.join(", "));
        }
        println!("Negotiation:           {}", negotiation_status_label(&n));
        if let Some(negotiated) = n.negotiated_session.as_ref() {
            println!(
                "Negotiated Hold Time: {}",
                optional_seconds_label(negotiated.hold_time_seconds)
            );
            println!(
                "Remote Router ID:     {}",
                negotiated.remote_router_id.as_deref().unwrap_or("unknown")
            );
            println!(
                "Four-Octet AS:        {}",
                optional_bool_label(negotiated.four_octet_as)
            );
            print!("{}", render_negotiated_capability_details(negotiated));
            println!(
                "Negotiated Families:  {}",
                negotiated_families_label(&negotiated.families)
            );
            println!(
                "Graceful Restart:     {}",
                graceful_restart_status_label(negotiated.graceful_restart.as_ref())
            );
            if let Some(gr) = negotiated.graceful_restart.as_ref() {
                println!(
                    "GR Peer Families:    {}",
                    negotiated_families_label(&gr.peer_families)
                );
                println!(
                    "GR Peer Restart Time: {}",
                    optional_seconds_label(gr.peer_restart_time_seconds)
                );
                println!(
                    "GR Effective Retention: {}",
                    gr.effective_retention_time_seconds.map_or_else(
                        || "disabled locally".to_string(),
                        |seconds| format!("{seconds}s")
                    )
                );
            }
        }
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
        println!("  IPv4 Unicast:        {}", n.prefixes_received_ipv4);
        println!("  IPv6 Unicast:        {}", n.prefixes_received_ipv6);
        println!(
            "Max Prefixes:          {}",
            max_prefix_capacity_label(effective_max_prefixes, n.max_prefix_headroom, n.stale)
        );
        println!(
            "Max Prefixes IPv4:     {}",
            max_prefix_capacity_label(
                n.effective_max_prefixes_ipv4,
                n.max_prefix_headroom_ipv4,
                n.stale
            )
        );
        println!(
            "Max Prefixes IPv6:     {}",
            max_prefix_capacity_label(
                n.effective_max_prefixes_ipv6,
                n.max_prefix_headroom_ipv6,
                n.stale
            )
        );
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
        // ADR-0112: two rows, never one. A peer with an import policy and no
        // export policy is a real and common half-configured state, and
        // collapsing it would hide the denied half.
        println!("RFC 8212 Policy:");
        println!(
            "  Import: {}",
            rfc8212_policy_status_label(n.rfc8212_import_policy)
        );
        println!(
            "  Export: {}",
            rfc8212_policy_status_label(n.rfc8212_export_policy)
        );
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
        if !n.outbound_prefix_limits.is_empty() {
            println!("Outbound Prefix Limits:");
            for row in &n.outbound_prefix_limits {
                // Unlimited prints as `unlimited`, never a synthetic 0, and a
                // blocking family names the stable reason it is withholding.
                let capacity = match (row.limit, row.headroom) {
                    (Some(limit), Some(headroom)) => {
                        format!("limit={limit}; headroom={headroom}")
                    }
                    _ => "limit=unlimited".to_string(),
                };
                let blocking = row
                    .reason
                    .as_deref()
                    .map_or_else(String::new, |reason| format!("; blocking={reason}"));
                println!(
                    "  {:<14} usage={}; {capacity}{blocking}",
                    row.family, row.usage
                );
            }
        }
        println!("Flap Count:            {}", n.flap_count);
        if !n.last_error.is_empty() {
            println!("Last Error:            {}", n.last_error);
        }
    }
    Ok(())
}

fn negotiation_status_label(state: &crate::proto::NeighborState) -> &'static str {
    match state.negotiation_available {
        None => "unknown (not exposed by daemon)",
        Some(false) if state.stale => "unknown (stale state)",
        Some(false) => "unavailable (session not Established)",
        Some(true) if state.negotiated_session.is_some() => "negotiated",
        Some(true) => "unknown (incomplete daemon response)",
    }
}

fn negotiated_session_json(
    state: &crate::proto::NeighborState,
) -> (Option<bool>, Option<JsonNegotiatedSession>) {
    let negotiated = state
        .negotiated_session
        .as_ref()
        .map(|negotiated| JsonNegotiatedSession {
            hold_time_seconds: negotiated.hold_time_seconds,
            remote_router_id: negotiated.remote_router_id.clone(),
            four_octet_as: negotiated.four_octet_as,
            families: negotiated.families.clone(),
            peer_route_refresh: negotiated.peer_route_refresh,
            peer_enhanced_route_refresh: negotiated.peer_enhanced_route_refresh,
            peer_extended_message: negotiated.peer_extended_message,
            outbound_max_message_bytes: negotiated.outbound_max_message_bytes,
            graceful_restart: negotiated.graceful_restart.as_ref().map(|gr| {
                JsonNegotiatedGracefulRestart {
                    peer_families: gr.peer_families.clone(),
                    peer_restart_time_seconds: gr.peer_restart_time_seconds,
                    effective_retention_time_seconds: gr.effective_retention_time_seconds,
                }
            }),
        });
    (state.negotiation_available, negotiated)
}

fn optional_seconds_label(value: Option<u32>) -> String {
    value.map_or_else(|| "unknown".to_string(), |seconds| format!("{seconds}s"))
}

fn optional_bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn render_negotiated_capability_details(
    negotiated: &crate::proto::NegotiatedSessionState,
) -> String {
    format!(
        "Peer Route Refresh:   {}\n\
         Peer Enhanced RR:     {}\n\
         Peer Extended Msgs:   {}\n\
         Outbound Max Message: {}\n",
        optional_bool_label(negotiated.peer_route_refresh),
        optional_bool_label(negotiated.peer_enhanced_route_refresh),
        optional_bool_label(negotiated.peer_extended_message),
        negotiated
            .outbound_max_message_bytes
            .map_or_else(|| "unknown".to_string(), |bytes| format!("{bytes} bytes"))
    )
}

fn negotiated_families_label(families: &[String]) -> String {
    if families.is_empty() {
        "none".to_string()
    } else {
        families.join(", ")
    }
}

fn graceful_restart_status_label(
    state: Option<&crate::proto::NegotiatedGracefulRestartState>,
) -> &'static str {
    match state.and_then(|gr| gr.effective_retention_time_seconds) {
        None if state.is_none() => "unsupported for negotiated families",
        None => "peer capable; disabled locally",
        Some(_) => "peer capable; helper active",
    }
}

fn comparison_verdict_label(value: i32) -> &'static str {
    match crate::proto::UpdateGroupComparisonVerdict::try_from(value) {
        Ok(crate::proto::UpdateGroupComparisonVerdict::Unknown) => "unknown",
        Ok(crate::proto::UpdateGroupComparisonVerdict::Private) => "private",
        Ok(crate::proto::UpdateGroupComparisonVerdict::Shared) => "shared",
        Ok(crate::proto::UpdateGroupComparisonVerdict::Separate) => "separate",
        Ok(crate::proto::UpdateGroupComparisonVerdict::Unspecified) | Err(_) => "unknown",
    }
}

fn comparison_membership_label(value: i32) -> &'static str {
    use crate::proto::UpdateGroupComparisonMembership as M;
    match M::try_from(value) {
        Ok(M::Grouped) => "grouped",
        Ok(M::PolicyPeerContext) => "policy_peer_context",
        Ok(M::AddPathSend) => "add_path_send",
        Ok(M::PerClientBest) => "per_client_best",
        Ok(M::OrrVantage) => "orr_vantage",
        Ok(M::OrfInstalled) => "orf_installed",
        Ok(M::SlowPeer) => "slow_peer",
        Ok(M::Unknown | M::Unspecified) | Err(_) => "unknown",
    }
}

fn comparison_difference_label(value: i32) -> &'static str {
    use crate::proto::UpdateGroupComparisonDifference as D;
    match D::try_from(value) {
        Ok(D::ExportPolicy) => "export_policy",
        Ok(D::SessionKind) => "session_kind",
        Ok(D::RouteReflectorClient) => "route_reflector_client",
        Ok(D::LocalRole) => "local_role",
        Ok(D::Rfc1997Mode) => "rfc1997_mode",
        Ok(D::NegotiatedFamilies) => "negotiated_families",
        Ok(D::LlgrFamilies) => "llgr_families",
        Ok(D::Unspecified) | Err(_) => "unknown",
    }
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

fn effective_max_prefix_limit(reported: Option<u32>, legacy: u32) -> Option<u32> {
    reported.or_else(|| (legacy != 0).then_some(legacy))
}

fn max_prefix_capacity_label(limit: Option<u32>, headroom: Option<u32>, stale: bool) -> String {
    match (limit, headroom, stale) {
        (None, _, _) => "unlimited".to_string(),
        (Some(limit), _, true) => format!("{limit} (headroom unavailable: stale state)"),
        (Some(limit), Some(headroom), false) => format!("{limit} ({headroom} remaining)"),
        (Some(limit), None, false) => format!("{limit} (headroom unavailable)"),
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

/// ADR-0112 directional status label.
///
/// `UNSPECIFIED` is what an older daemon leaves behind, and an unrecognized
/// value is what a newer one may send; both render `unknown` rather than being
/// folded into `not_required`. Treating either as "no requirement" would make
/// a rolling upgrade quietly report a peer as fine while its reserved deny is
/// live on the other side.
pub(crate) fn rfc8212_policy_status_label(value: i32) -> &'static str {
    match crate::proto::Rfc8212PolicyStatus::try_from(value) {
        Ok(crate::proto::Rfc8212PolicyStatus::NotRequired) => "not_required",
        Ok(crate::proto::Rfc8212PolicyStatus::Present) => "present",
        Ok(crate::proto::Rfc8212PolicyStatus::Missing) => "missing",
        Ok(
            crate::proto::Rfc8212PolicyStatus::Unspecified
            | crate::proto::Rfc8212PolicyStatus::Unknown,
        )
        | Err(_) => "unknown",
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
    pub min_hold_time: Option<u32>,
    pub send_hold_time: Option<u32>,
    pub max_prefixes: Option<u32>,
    pub peer_group: Option<String>,
    pub max_prefix_restart_seconds: Option<u32>,
    pub families: Vec<String>,
    pub required_families: Vec<String>,
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
                min_hold_time: opts.min_hold_time,
                send_hold_time: opts.send_hold_time,
                max_prefixes: opts.max_prefixes.unwrap_or(0),
                families: opts.families,
                required_families: opts.required_families,
                peer_group: opts.peer_group.unwrap_or_default(),
                remove_private_as: String::new(),
                route_server_client: opts.route_server_client,
                per_client_best: opts.per_client_best,
                role: opts.role.unwrap_or_default(),
                strict_role: opts.strict_role,
                add_path_receive: opts.add_path_receive,
                add_path_send: opts.add_path_send,
                add_path_send_max: opts.add_path_send_max,
                paths_limit_receive_max: u32::from(opts.paths_limit_receive_max),
                max_prefix_restart_seconds: opts.max_prefix_restart_seconds,
            }),
            intent: None,
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

fn refresh_outbound_json(address: &str, scheduled: bool) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "action": "refresh_outbound",
        "target": address,
        "scheduled": scheduled,
    })
}

fn refresh_outbound_message(address: &str) -> String {
    format!("Outbound refresh scheduled for {address}")
}

pub async fn refresh_outbound(
    connection: Connection,
    address: &str,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let (address_only, interface) = split_scoped_address(address);
    let response = client
        .refresh_outbound(RefreshOutboundRequest {
            address: address_only,
            interface,
        })
        .await?
        .into_inner();
    if !response.scheduled {
        return Err(CliError::Rpc(
            "daemon did not schedule the outbound refresh".into(),
        ));
    }
    if json {
        output::print_json_pretty(&refresh_outbound_json(address, response.scheduled))
    } else {
        println!("{}", refresh_outbound_message(address));
        Ok(())
    }
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
    fn bare_ip_rpc_address_strips_only_one_valid_link_local_zone() {
        let cases = [
            ("fe80::1%eth0", "fe80::1"),
            ("febf::abcd%swp1", "febf::abcd"),
            ("FE80::1%Ethernet1", "FE80::1"),
            ("fe80::1", "fe80::1"),
            ("fe80::gg%eth0", "fe80::gg%eth0"),
            ("fe80::1%", "fe80::1%"),
            ("fe80::1%eth0%extra", "fe80::1%eth0%extra"),
            ("192.0.2.1%eth0", "192.0.2.1%eth0"),
            ("2001:db8::1%eth0", "2001:db8::1%eth0"),
            ("ff02::1%eth0", "ff02::1%eth0"),
        ];
        for (input, expected) in cases {
            assert_eq!(bare_ip_rpc_address(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn scoped_output_restores_matching_filtered_identity() {
        let mut canonical = "fe80::9".to_string();
        restore_matching_scoped_address(Some("fe80:0:0:0:0:0:0:9%eth0"), &mut canonical);
        assert_eq!(canonical, "fe80:0:0:0:0:0:0:9%eth0");
    }

    #[test]
    fn scoped_output_leaves_unrelated_rows_unchanged() {
        let mut unrelated = "fe80::10".to_string();
        restore_matching_scoped_address(Some("fe80::9%eth0"), &mut unrelated);
        assert_eq!(unrelated, "fe80::10");
    }

    #[test]
    fn scoped_output_leaves_unfiltered_rows_unchanged() {
        let mut unfiltered = "fe80::9".to_string();
        restore_matching_scoped_address(None, &mut unfiltered);
        assert_eq!(unfiltered, "fe80::9");
    }

    /// ADR-0112 rolling-version contract. Zero is what an older daemon leaves
    /// behind and a future variant is what a newer one may send; both must
    /// render `unknown`. Mapping either onto `not_required` would tell an
    /// operator mid-upgrade that a peer has no requirement while its reserved
    /// deny is live on the other side, so both halves are load-bearing.
    #[test]
    fn rfc8212_policy_status_renders_absent_and_future_values_as_unknown() {
        assert_eq!(rfc8212_policy_status_label(0), "unknown");
        assert_eq!(rfc8212_policy_status_label(i32::MAX), "unknown");
        assert_eq!(
            rfc8212_policy_status_label(crate::proto::Rfc8212PolicyStatus::Unknown as i32),
            "unknown"
        );
        assert_eq!(
            rfc8212_policy_status_label(crate::proto::Rfc8212PolicyStatus::NotRequired as i32),
            "not_required"
        );
        assert_eq!(
            rfc8212_policy_status_label(crate::proto::Rfc8212PolicyStatus::Present as i32),
            "present"
        );
        assert_eq!(
            rfc8212_policy_status_label(crate::proto::Rfc8212PolicyStatus::Missing as i32),
            "missing"
        );
    }

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

    /// Load-bearing: collapsing protobuf absence into zero, or deriving
    /// headroom from a stale zero count, changes these operator-facing labels.
    #[test]
    fn max_prefix_capacity_distinguishes_finite_unlimited_and_stale() {
        assert_eq!(
            max_prefix_capacity_label(Some(20), Some(9), false),
            "20 (9 remaining)"
        );
        assert_eq!(max_prefix_capacity_label(None, None, false), "unlimited");
        assert_eq!(
            max_prefix_capacity_label(Some(20), None, true),
            "20 (headroom unavailable: stale state)"
        );
    }

    /// Load-bearing: ignoring the legacy config value makes a new CLI call an
    /// older daemon's finite aggregate limit unlimited during rolling upgrade.
    #[test]
    fn effective_max_prefix_limit_falls_back_without_inventing_zero() {
        assert_eq!(effective_max_prefix_limit(Some(20), 10), Some(20));
        assert_eq!(effective_max_prefix_limit(None, 10), Some(10));
        assert_eq!(effective_max_prefix_limit(None, 0), None);
    }

    /// Load-bearing proof: collapsing protobuf presence, ignoring stale, or
    /// treating peer GR capability as local helper activation, dropping a
    /// negotiated-capability mapping/row, or inventing an answer for an older
    /// daemon changes an exact JSON value or human label below.
    #[test]
    fn negotiated_runtime_labels_cover_rolling_upgrade_and_gr_states() {
        let mut state = crate::proto::NeighborState::default();
        assert_eq!(
            negotiation_status_label(&state),
            "unknown (not exposed by daemon)"
        );
        assert_eq!(negotiated_session_json(&state).0, None);
        assert!(negotiated_session_json(&state).1.is_none());

        state.negotiation_available = Some(false);
        state.stale = true;
        assert_eq!(negotiation_status_label(&state), "unknown (stale state)");
        assert_eq!(negotiated_session_json(&state).0, Some(false));
        assert!(negotiated_session_json(&state).1.is_none());

        state.stale = false;
        assert_eq!(
            negotiation_status_label(&state),
            "unavailable (session not Established)"
        );
        assert_eq!(negotiated_session_json(&state).0, Some(false));
        assert!(negotiated_session_json(&state).1.is_none());

        state.negotiation_available = Some(true);
        state.negotiated_session = Some(crate::proto::NegotiatedSessionState {
            hold_time_seconds: Some(0),
            remote_router_id: Some("192.0.2.7".to_string()),
            four_octet_as: Some(false),
            families: vec!["ipv4_unicast".to_string()],
            peer_route_refresh: Some(false),
            peer_enhanced_route_refresh: Some(false),
            peer_extended_message: Some(false),
            outbound_max_message_bytes: Some(4096),
            graceful_restart: None,
        });
        assert_eq!(negotiation_status_label(&state), "negotiated");
        let negotiated = state.negotiated_session.as_ref().unwrap();
        assert_eq!(
            graceful_restart_status_label(negotiated.graceful_restart.as_ref()),
            "unsupported for negotiated families"
        );
        assert_eq!(optional_seconds_label(negotiated.hold_time_seconds), "0s");
        assert_eq!(optional_bool_label(negotiated.four_octet_as), "false");
        let (available, json) = negotiated_session_json(&state);
        assert_eq!(available, Some(true));
        let json = json.unwrap();
        assert_eq!(json.hold_time_seconds, Some(0));
        assert_eq!(json.four_octet_as, Some(false));
        assert_eq!(json.peer_route_refresh, Some(false));
        assert_eq!(json.peer_enhanced_route_refresh, Some(false));
        assert_eq!(json.peer_extended_message, Some(false));
        assert_eq!(json.outbound_max_message_bytes, Some(4096));
        assert!(json.graceful_restart.is_none());
        let rendered = render_negotiated_capability_details(negotiated);
        assert!(rendered.contains("Peer Route Refresh:   false\n"));
        assert!(rendered.contains("Peer Enhanced RR:     false\n"));
        assert!(rendered.contains("Peer Extended Msgs:   false\n"));
        assert!(rendered.contains("Outbound Max Message: 4096 bytes\n"));

        let negotiated = state.negotiated_session.as_mut().unwrap();
        negotiated.peer_route_refresh = Some(true);
        negotiated.peer_enhanced_route_refresh = Some(true);
        negotiated.peer_extended_message = Some(true);
        negotiated.outbound_max_message_bytes = Some(65_535);
        let json = negotiated_session_json(&state).1.unwrap();
        assert_eq!(json.peer_route_refresh, Some(true));
        assert_eq!(json.peer_enhanced_route_refresh, Some(true));
        assert_eq!(json.peer_extended_message, Some(true));
        assert_eq!(json.outbound_max_message_bytes, Some(65_535));
        let rendered =
            render_negotiated_capability_details(state.negotiated_session.as_ref().unwrap());
        assert!(rendered.contains("Peer Route Refresh:   true\n"));
        assert!(rendered.contains("Peer Enhanced RR:     true\n"));
        assert!(rendered.contains("Peer Extended Msgs:   true\n"));
        assert!(rendered.contains("Outbound Max Message: 65535 bytes\n"));

        let negotiated = state.negotiated_session.as_mut().unwrap();
        negotiated.peer_route_refresh = None;
        negotiated.peer_enhanced_route_refresh = None;
        negotiated.peer_extended_message = None;
        negotiated.outbound_max_message_bytes = None;
        let json = negotiated_session_json(&state).1.unwrap();
        assert_eq!(json.peer_route_refresh, None);
        assert_eq!(json.peer_enhanced_route_refresh, None);
        assert_eq!(json.peer_extended_message, None);
        assert_eq!(json.outbound_max_message_bytes, None);
        let rendered =
            render_negotiated_capability_details(state.negotiated_session.as_ref().unwrap());
        assert!(rendered.contains("Peer Route Refresh:   unknown\n"));
        assert!(rendered.contains("Peer Enhanced RR:     unknown\n"));
        assert!(rendered.contains("Peer Extended Msgs:   unknown\n"));
        assert!(rendered.contains("Outbound Max Message: unknown\n"));

        state.negotiated_session.as_mut().unwrap().graceful_restart =
            Some(crate::proto::NegotiatedGracefulRestartState {
                peer_families: vec!["ipv4_unicast".to_string()],
                peer_restart_time_seconds: Some(0),
                effective_retention_time_seconds: None,
            });
        let gr = state
            .negotiated_session
            .as_ref()
            .unwrap()
            .graceful_restart
            .as_ref();
        assert_eq!(
            graceful_restart_status_label(gr),
            "peer capable; disabled locally"
        );
        let json = negotiated_session_json(&state).1.unwrap();
        let json_gr = json.graceful_restart.unwrap();
        assert_eq!(json_gr.peer_restart_time_seconds, Some(0));
        assert_eq!(json_gr.effective_retention_time_seconds, None);

        state
            .negotiated_session
            .as_mut()
            .unwrap()
            .graceful_restart
            .as_mut()
            .unwrap()
            .effective_retention_time_seconds = Some(300);
        let gr = state
            .negotiated_session
            .as_ref()
            .unwrap()
            .graceful_restart
            .as_ref();
        assert_eq!(
            graceful_restart_status_label(gr),
            "peer capable; helper active"
        );
        assert_eq!(
            negotiated_session_json(&state)
                .1
                .unwrap()
                .graceful_restart
                .unwrap()
                .effective_retention_time_seconds,
            Some(300)
        );
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn comparison_request_mapping_and_output_branch_are_exact() {
        use crate::proto::{UpdateGroupComparisonDifference as D,
            UpdateGroupComparisonMembership as M, UpdateGroupComparisonVerdict as V};
        use rustbgpd_api::proto::{GetNeighborStateRequest as ServerRequest, UpdateGroupComparison as P};
        let value = P {
            verdict: V::Separate.into(),
            primary_membership: M::AddPathSend.into(),
            comparison_membership: M::SlowPeer.into(),
            differences: vec![D::ExportPolicy.into(), D::SessionKind.into(), D::RouteReflectorClient.into(),
                D::LocalRole.into(), D::Rfc1997Mode.into(), D::NegotiatedFamilies.into(), D::LlgrFamilies.into()],
        };
        let server = spawn_mock_server(None).await;
        *server.state.neighbor_comparison.lock().await = Some(value);
        // The mock pins CLI scope splitting; daemon scope rejection is tested separately.
        let connection = connect(&server.addr, None).await.unwrap();
        let NeighborShow::Comparison(comparison) = query_neighbor(
            connection.clone(), "fe80::1%eth0", Some("fe80::2%eth1")).await.unwrap() else {
            panic!("comparison request selected neighbor detail output");
        };
        let request = server.state.last_get_neighbor_state.lock().await.clone().unwrap();
        assert_eq!(request, ServerRequest { address: "fe80::1".into(), interface: "eth0".into(),
            compare_address: "fe80::2".into(), compare_interface: "eth1".into() });
        assert_eq!(comparison, JsonUpdateGroupComparison { primary_neighbor: "fe80::1%eth0".into(),
            comparison_neighbor: "fe80::2%eth1".into(), verdict: "separate".into(),
            primary_membership: "add_path_send".into(), comparison_membership: "slow_peer".into(),
            differences: "export_policy session_kind route_reflector_client local_role rfc1997_mode negotiated_families llgr_families"
                .split_whitespace().map(str::to_string).collect() });
        assert_eq!(render_update_group_comparison(&comparison),
            "Update Group Compare: fe80::1%eth0 vs fe80::2%eth1 — separate (add_path_send / slow_peer)\n\
             Differences:          export_policy, session_kind, route_reflector_client, local_role, rfc1997_mode, negotiated_families, llgr_families\n"
        );
        assert!(matches!(query_neighbor(connection, "192.0.2.1", None).await.unwrap(), NeighborShow::Detail(_)));
        *server.state.neighbor_comparison.lock().await = None;
        let error = query_neighbor(connect(&server.addr, None).await.unwrap(), "192.0.2.1", Some("192.0.2.2")).await.unwrap_err();
        assert_eq!(error.to_string(), "update-group comparison is not supported by this daemon");

        macro_rules! labels {
            ($mapper:expr; $($input:expr => $expected:literal),+ $(,)?) => {
                $(assert_eq!($mapper($input.into()), $expected);)+
            };
        }
        labels!(comparison_verdict_label; V::Unknown => "unknown", V::Private => "private", V::Shared => "shared", V::Separate => "separate", V::Unspecified => "unknown", i32::MAX => "unknown");
        labels!(comparison_membership_label; M::Unknown => "unknown", M::Grouped => "grouped", M::PolicyPeerContext => "policy_peer_context", M::AddPathSend => "add_path_send", M::PerClientBest => "per_client_best", M::OrrVantage => "orr_vantage", M::OrfInstalled => "orf_installed", M::SlowPeer => "slow_peer", M::Unspecified => "unknown", i32::MAX => "unknown");
        labels!(comparison_difference_label; D::ExportPolicy => "export_policy", D::SessionKind => "session_kind", D::RouteReflectorClient => "route_reflector_client", D::LocalRole => "local_role", D::Rfc1997Mode => "rfc1997_mode", D::NegotiatedFamilies => "negotiated_families", D::LlgrFamilies => "llgr_families", D::Unspecified => "unknown", i32::MAX => "unknown");
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
        // Mutation-red for min_hold_time: removing the request assignment
        // makes the captured request carry None instead of 30.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        add(
            connection,
            "10.0.0.2",
            AddNeighborOpts {
                min_hold_time: Some(30),
                asn: 65002,
                description: Some("peer-2".to_string()),
                hold_time: Some(90),
                send_hold_time: Some(480),
                max_prefixes: Some(1000),
                peer_group: Some("rs-members".to_string()),
                max_prefix_restart_seconds: Some(30),
                families: vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()],
                required_families: vec!["ipv6_unicast".to_string()],
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
        assert_eq!(request.min_hold_time, Some(30));
        assert_eq!(request.required_families, vec!["ipv6_unicast"]);
        assert_eq!(request.peer_group, "rs-members");
        assert_eq!(request.max_prefix_restart_seconds, Some(30));

        let connection = connect(&server.addr, None).await.unwrap();
        add(
            connection,
            "10.0.0.3",
            AddNeighborOpts {
                min_hold_time: None,
                asn: 65003,
                description: None,
                hold_time: None,
                send_hold_time: None,
                max_prefixes: None,
                peer_group: None,
                max_prefix_restart_seconds: None,
                families: Vec::new(),
                required_families: Vec::new(),
                route_server_client: false,
                per_client_best: false,
                role: None,
                strict_role: false,
                add_path_receive: false,
                add_path_send: false,
                add_path_send_max: 0,
                paths_limit_receive_max: 0,
            },
            true,
        )
        .await
        .unwrap();

        let request = server.state.last_add_neighbor.lock().await.clone().unwrap();
        assert_eq!(request.peer_group, "");
        assert_eq!(request.max_prefix_restart_seconds, None);
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

    /// Load-bearing mutation proof: replacing `slow_peer: n.slow_peer` in
    /// `json_neighbor` with `false` makes the first assertion red; removing
    /// the false-value serde omission makes the second assertion red.
    #[test]
    fn neighbor_list_json_preserves_only_active_slow_peer_flags() {
        let mut state = crate::proto::NeighborState {
            config: Some(crate::proto::NeighborConfig {
                address: "10.0.0.2".to_string(),
                remote_asn: 65002,
                ..Default::default()
            }),
            slow_peer: true,
            ..Default::default()
        };

        let value = serde_json::to_value(json_neighbor(&state)).expect("serialize neighbor");
        assert_eq!(value["slow_peer"], true);

        state.slow_peer = false;
        let value = serde_json::to_value(json_neighbor(&state)).expect("serialize neighbor");
        assert!(value.get("slow_peer").is_none());
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

    /// Load-bearing CLI proof: removing scoped-address splitting, duplicating
    /// the RPC, or changing the exact human/JSON receipt makes this test red.
    #[tokio::test]
    async fn refresh_outbound_sends_scoped_peer_and_has_explicit_json_receipt() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        refresh_outbound(connection, "fe80::2%eth1", true)
            .await
            .unwrap();

        let request = server
            .state
            .last_refresh_outbound
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(request.address, "fe80::2");
        assert_eq!(request.interface, "eth1");
        assert_eq!(
            server
                .state
                .refresh_outbound_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one CLI invocation must issue exactly one RPC"
        );
        assert_eq!(
            refresh_outbound_message("fe80::2%eth1"),
            "Outbound refresh scheduled for fe80::2%eth1"
        );
        assert_eq!(
            refresh_outbound_json("fe80::2%eth1", true),
            serde_json::json!({
                "ok": true,
                "action": "refresh_outbound",
                "target": "fe80::2%eth1",
                "scheduled": true,
            })
        );
    }

    /// Removing the fail-closed `scheduled` check makes this test return
    /// success against a daemon that explicitly declined the operation.
    #[tokio::test]
    async fn refresh_outbound_rejects_unscheduled_response() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .refresh_outbound_declined
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        let error = refresh_outbound(connection, "192.0.2.1", false)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "daemon did not schedule the outbound refresh"
        );
    }
}
