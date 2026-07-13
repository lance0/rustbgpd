use serde::Serialize;

use std::net::IpAddr;

use crate::error::CliError;
use crate::proto;
use owo_colors::{OwoColorize, Stream::Stdout};

/// Format seconds as a human-readable uptime.
///
/// - >= 7 days: "7d 3h"
/// - >= 1 day: "1d 4h 12m"
/// - < 1 day: "01:23:45"
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days >= 7 {
        format!("{days}d {hours}h")
    } else if days >= 1 {
        format!("{days}d {hours}h {mins}m")
    } else {
        format!("{hours:02}:{mins:02}:{secs:02}")
    }
}

/// Format an AS path from a list of ASNs.
pub fn format_as_path(as_path: &[u32]) -> String {
    if as_path.is_empty() {
        return String::new();
    }
    as_path
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a standard community (u32), using RFC aliases for well-known values.
pub fn format_community(c: u32) -> String {
    match c {
        rustbgpd_wire::COMMUNITY_NO_EXPORT => return "NO_EXPORT".to_string(),
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE => return "NO_ADVERTISE".to_string(),
        rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED => return "NO_EXPORT_SUBCONFED".to_string(),
        rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN => return "GRACEFUL_SHUTDOWN".to_string(),
        rustbgpd_wire::COMMUNITY_BLACKHOLE => return "BLACKHOLE".to_string(),
        rustbgpd_wire::COMMUNITY_LLGR_STALE => return "LLGR_STALE".to_string(),
        rustbgpd_wire::COMMUNITY_NO_LLGR => return "NO_LLGR".to_string(),
        _ => {}
    }

    let high = c >> 16;
    let low = c & 0xFFFF;
    format!("{high}:{low}")
}

/// Format origin code: 0=igp, 1=egp, 2=incomplete.
pub fn format_origin(origin: u32) -> &'static str {
    match origin {
        0 => "igp",
        1 => "egp",
        2 => "incomplete",
        _ => "?",
    }
}

/// Format session state enum to string.
pub fn format_state(state: i32) -> &'static str {
    match state {
        1 => "Idle",
        2 => "Connect",
        3 => "Active",
        4 => "OpenSent",
        5 => "OpenConfirm",
        6 => "Established",
        _ => "Unknown",
    }
}

/// Format session state, surfacing `Stale` when the daemon couldn't read
/// fresh state from the peer session task (e.g. session actor parked
/// under load — the bounded `query_state_timeout` returned `None`).
///
/// `stale=true` overrides the state value because a stalled session's
/// `state` field is a placeholder `Idle` rather than an authoritative
/// reading; reporting it raw would misclassify a hung-but-alive session
/// as cleanly torn down.
pub fn format_state_with_stale(state: i32, stale: bool) -> &'static str {
    if stale { "Stale" } else { format_state(state) }
}

/// Return colored session state string.
pub fn colored_state(state: i32) -> String {
    let label = format_state(state);
    match state {
        6 => format!("{}", label.if_supports_color(Stdout, |s| s.green())),
        2 | 4 | 5 => format!("{}", label.if_supports_color(Stdout, |s| s.yellow())),
        _ => format!("{}", label.if_supports_color(Stdout, |s| s.red())),
    }
}

/// Colored variant of [`format_state_with_stale`]. Stale renders in
/// red+bold so it's visually distinct from a healthy `Idle`.
pub fn colored_state_with_stale(state: i32, stale: bool) -> String {
    if stale {
        format!("{}", "Stale".if_supports_color(Stdout, |s| s.red()))
    } else {
        colored_state(state)
    }
}

/// Return colored best-path marker.
pub fn colored_best_marker(best: bool) -> String {
    if best {
        format!("{}", "*>".if_supports_color(Stdout, |s| s.green()))
    } else {
        "  ".to_string()
    }
}

/// Return colored health string.
pub fn colored_health(healthy: bool) -> String {
    if healthy {
        format!("{}", "healthy".if_supports_color(Stdout, |s| s.green()))
    } else {
        format!("{}", "unhealthy".if_supports_color(Stdout, |s| s.red()))
    }
}

/// Return colored event type string.
pub fn colored_event_type(event_type: &str) -> String {
    match event_type {
        "added" | "best_changed" | "established" | "peer_enabled" => {
            format!("{}", event_type.if_supports_color(Stdout, |s| s.green()))
        }
        "withdrawn" | "lost" | "peer_disabled" => {
            format!("{}", event_type.if_supports_color(Stdout, |s| s.red()))
        }
        "state_changed" => format!("{}", event_type.if_supports_color(Stdout, |s| s.yellow())),
        _ => event_type.to_string(),
    }
}

/// Map address family string to proto enum value.
pub fn parse_family(family: &str) -> Option<i32> {
    match family {
        "ipv4_unicast" | "ipv4-unicast" | "ipv4" => Some(proto::AddressFamily::Ipv4Unicast as i32),
        "ipv6_unicast" | "ipv6-unicast" | "ipv6" => Some(proto::AddressFamily::Ipv6Unicast as i32),
        "ipv4_flowspec" | "ipv4-flowspec" => Some(proto::AddressFamily::Ipv4Flowspec as i32),
        "ipv6_flowspec" | "ipv6-flowspec" => Some(proto::AddressFamily::Ipv6Flowspec as i32),
        "bgpls" | "bgp_ls" | "bgp-ls" | "linkstate" => Some(proto::AddressFamily::BgpLs as i32),
        "bgpls_vpn" | "bgpls-vpn" | "bgp_ls_vpn" | "bgp-ls-vpn" | "linkstate_vpn"
        | "linkstate-vpn" => Some(proto::AddressFamily::BgpLsVpn as i32),
        _ => None,
    }
}

/// Format address family enum value to string.
pub fn format_family(afi: i32) -> &'static str {
    match afi {
        1 => "ipv4_unicast",
        2 => "ipv6_unicast",
        3 => "ipv4_flowspec",
        4 => "ipv6_flowspec",
        6 => "bgp_ls",
        7 => "bgp_ls_vpn",
        _ => "unknown",
    }
}

/// Format event severity enum value to string.
pub fn format_severity(severity: i32) -> &'static str {
    match severity {
        1 => "info",
        2 => "warning",
        3 => "error",
        _ => "unknown",
    }
}

// -- JSON output structs --

#[derive(Serialize)]
pub struct JsonGlobal {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u32,
    pub tcp_ao_support: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tcp_ao_detail: String,
}

#[derive(Serialize)]
pub struct JsonNeighbor {
    pub address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub interface: String,
    pub remote_asn: u32,
    pub state: String,
    /// True when the daemon couldn't read fresh state from the peer
    /// session task — `state` is a placeholder Idle rather than an
    /// authoritative reading. Omitted from JSON when false to keep
    /// healthy-state output uncluttered.
    #[serde(skip_serializing_if = "is_false")]
    pub stale: bool,
    pub uptime_seconds: u64,
    pub prefixes_received: u64,
    pub prefixes_sent: u64,
    /// Total BGP messages received/sent, all types (daemon-lifetime;
    /// persists across session flaps, includes KEEPALIVEs).
    pub messages_received: u64,
    pub messages_sent: u64,
    pub flap_count: u64,
    pub route_reflector_client: bool,
    pub description: String,
}

#[derive(Serialize)]
pub struct JsonNeighborDetail {
    pub address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub interface: String,
    pub remote_asn: u32,
    pub state: String,
    /// See [`JsonNeighbor::stale`].
    #[serde(skip_serializing_if = "is_false")]
    pub stale: bool,
    pub uptime_seconds: u64,
    pub prefixes_received: u64,
    pub prefixes_sent: u64,
    pub updates_received: u64,
    pub updates_sent: u64,
    pub notifications_received: u64,
    pub notifications_sent: u64,
    /// See [`JsonNeighbor::messages_received`].
    pub messages_received: u64,
    pub messages_sent: u64,
    pub flap_count: u64,
    pub last_error: String,
    pub authentication: String,
    pub tcp_ao_health: String,
    pub tcp_ao_desired_generation: u64,
    pub tcp_ao_applied_generation: u64,
    pub tcp_ao_rotation_phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tcp_ao_rotation_error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_ao: Option<JsonTcpAoState>,
    pub description: String,
    pub hold_time: u32,
    /// Effective RFC 9687 send hold time in seconds (0 = disabled).
    pub send_hold_time: u32,
    pub families: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub peer_group: String,
    pub route_reflector_client: bool,
    pub route_server_client: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub per_client_best: bool,
    /// Effective live unicast distribution mode, or `unknown` while down.
    pub distribution_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub role: String,
    pub strict_role: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote_role: String,
    pub role_negotiated: bool,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub otc_routes_blocked: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub import_policy_routes_permitted: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub import_policy_routes_denied: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub export_policy_routes_permitted: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub export_policy_routes_denied: u64,
    pub add_path_receive: bool,
    pub add_path_send: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub add_path_send_max: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths_limits: Vec<JsonPathsLimit>,
    /// Update-group membership: `group:N` or the ungrouped reason.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub update_group: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selection_deferral: Vec<JsonSelectionDeferralFamily>,
}

#[derive(Serialize)]
pub struct JsonSelectionDeferralFamily {
    pub afi: u32,
    pub safi: u32,
    pub active: bool,
    pub waiter_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiter_session_id: Option<u64>,
    pub blocking_waiters: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub remaining_millis: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub release_reason: String,
}

#[derive(Serialize)]
pub struct JsonTcpAoState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_key_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rnext_key_id: Option<u32>,
    pub ao_required: bool,
    pub accept_icmps: bool,
    pub packets_good: u64,
    pub packets_bad: u64,
    pub packets_key_not_found: u64,
    pub packets_ao_required: u64,
    pub packets_dropped_icmp: u64,
    pub keys: Vec<JsonTcpAoKeyState>,
}

#[derive(Serialize)]
pub struct JsonTcpAoKeyState {
    pub peer_address: String,
    pub prefix_length: u32,
    pub send_id: u32,
    pub recv_id: u32,
    pub algorithm: String,
    pub is_current: bool,
    pub is_rnext: bool,
    pub preferred: bool,
    pub deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf_ifindex: Option<u32>,
    pub packets_good: u64,
    pub packets_bad: u64,
}

#[derive(Serialize)]
pub struct JsonPathsLimit {
    pub family: String,
    pub configured_receive_max: u32,
    pub advertised_receive_max: u32,
    pub received_receive_max: u32,
    /// Legacy raw value: zero inactive, `u32::MAX` unlimited.
    pub effective_send_max: u32,
    /// Normalized active limit: zero unlimited, finite otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_send_limit: Option<u32>,
    pub effective_send_active: bool,
}

#[cfg(test)]
#[derive(Serialize)]
pub struct JsonRoute {
    pub prefix: String,
    pub next_hop: String,
    pub as_path: Vec<u32>,
    pub local_pref: u32,
    pub med: u32,
    pub origin: String,
    pub best: bool,
    pub peer_address: String,
    pub communities: Vec<String>,
    pub large_communities: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub path_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub validation_state: String,
}

#[derive(Serialize)]
pub struct JsonExplainReason {
    pub code: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct JsonExplainModifications {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_local_pref: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_med: Option<u32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub set_next_hop: String,
    pub communities_add: Vec<String>,
    pub communities_remove: Vec<String>,
    pub extended_communities_add: Vec<u64>,
    pub extended_communities_remove: Vec<u64>,
    pub large_communities_add: Vec<String>,
    pub large_communities_remove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_path_prepend_asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_path_prepend_count: Option<u32>,
}

#[derive(Serialize)]
pub struct JsonExplainAdvertisedRoute {
    pub decision: String,
    pub peer_address: String,
    pub prefix: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_hop: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub path_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub route_peer_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub route_type: String,
    pub reasons: Vec<JsonExplainReason>,
    pub modifications: JsonExplainModifications,
    /// RFC 9107 ORR vantage; both ORR fields are absent on non-ORR
    /// explains so the pre-ORR JSON shape is unchanged.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub orr_vantage: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub orr_candidates: Vec<JsonOrrExplainCandidate>,
    /// Export gate ladder in live evaluation order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<JsonExportGateStep>,
    /// Update group the peer's export is staged under; absent when the
    /// peer takes the per-peer export path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_group_id: Option<u64>,
    /// True on an advertise decision when the identical route already
    /// sits in the advertised state (peer in sync, nothing re-sent).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_advertised: bool,
    /// Route Distinguisher for a VPN explain; absent for unicast.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rd: String,
}

#[derive(Serialize)]
pub struct JsonExportGateStep {
    pub gate: String,
    pub code: String,
    /// `pass`, `stop`, or `not_applicable`.
    pub verdict: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct JsonOrrExplainCandidate {
    pub peer_address: String,
    pub next_hop: String,
    /// Vantage interior cost to `next_hop`; `null` = unreachable.
    pub cost: Option<u64>,
    pub selected: bool,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize)]
pub struct JsonHealth {
    pub healthy: bool,
    pub uptime_seconds: u64,
    pub active_peers: u32,
    pub total_routes: u32,
}

#[derive(Serialize)]
pub struct JsonRouteEvent {
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub event_id: u64,
    pub event_type: String,
    pub prefix: String,
    pub peer_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub previous_peer_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target_peer_address: String,
    pub afi_safi: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub path_id: u32,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub missed_count: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Compute extra bytes added by ANSI escape codes in a colored string.
fn ansi_overhead(colored: &str, plain_len: usize) -> usize {
    colored.len().saturating_sub(plain_len)
}

/// Print neighbor table with dynamic column widths and colored state.
/// `wide` appends the classic operator columns (MsgRcvd, MsgSent,
/// Flaps, RRC) plus the overloaded `State/PfxRcd` — prefixes-received
/// count when Established, state name otherwise — as the last column.
pub fn print_neighbor_table(neighbors: &[proto::NeighborState], wide: bool) {
    print!("{}", render_neighbor_table(neighbors, wide));
}

fn render_neighbor_table(neighbors: &[proto::NeighborState], wide: bool) -> String {
    use std::fmt::Write as _;

    // Compute column data and max widths
    struct Row {
        addr: String,
        asn: String,
        state_plain: String,
        state_colored: String,
        uptime: String,
        rx: String,
        tx: String,
        desc: String,
        // Wide-only extras (empty when `wide` is false).
        msg_rcvd: String,
        msg_sent: String,
        flaps: String,
        rrc: String,
        state_pfx: String,
    }

    let rows: Vec<Row> = neighbors
        .iter()
        .map(|n| {
            let cfg = n.config.as_ref();
            let (msg_rcvd, msg_sent, flaps, rrc, state_pfx) = if wide {
                // The classic overloaded summary column: a number means
                // Established (prefixes received); anything else is the
                // session state. Stale overrides — a placeholder Idle
                // must not render as a count.
                let state_pfx = if !n.stale && n.state == proto::SessionState::Established as i32 {
                    n.prefixes_received.to_string()
                } else {
                    colored_state_with_stale(n.state, n.stale)
                };
                (
                    n.messages_received.to_string(),
                    n.messages_sent.to_string(),
                    n.flap_count.to_string(),
                    if n.route_reflector_client { "*" } else { "" }.to_string(),
                    state_pfx,
                )
            } else {
                Default::default()
            };
            Row {
                addr: cfg
                    .map(|c| {
                        if c.interface.is_empty() {
                            c.address.clone()
                        } else {
                            format!("{}%{}", c.address, c.interface)
                        }
                    })
                    .unwrap_or_default(),
                asn: cfg.map(|c| c.remote_asn.to_string()).unwrap_or_default(),
                state_plain: format_state_with_stale(n.state, n.stale).to_string(),
                state_colored: colored_state_with_stale(n.state, n.stale),
                uptime: format_duration(n.uptime_seconds),
                rx: n.prefixes_received.to_string(),
                tx: n.prefixes_sent.to_string(),
                desc: cfg.map(|c| c.description.clone()).unwrap_or_default(),
                msg_rcvd,
                msg_sent,
                flaps,
                rrc,
                state_pfx,
            }
        })
        .collect();

    let w_addr = rows.iter().map(|r| r.addr.len()).max().unwrap_or(0).max(8);
    let w_asn = rows.iter().map(|r| r.asn.len()).max().unwrap_or(0).max(2);
    let w_state = rows
        .iter()
        .map(|r| r.state_plain.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let w_uptime = rows
        .iter()
        .map(|r| r.uptime.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let w_rx = rows.iter().map(|r| r.rx.len()).max().unwrap_or(0).max(6);
    let w_tx = rows.iter().map(|r| r.tx.len()).max().unwrap_or(0).max(6);

    let mut out = String::new();
    if !wide {
        let _ = writeln!(
            out,
            "{:<w_addr$} {:<w_asn$} {:<w_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$}  Description",
            "Neighbor", "AS", "State", "Uptime", "Rx Pfx", "Tx Pfx",
        );

        for row in &rows {
            let overhead = ansi_overhead(&row.state_colored, row.state_plain.len());
            let padded_state = w_state + overhead;
            let _ = writeln!(
                out,
                "{:<w_addr$} {:<w_asn$} {:<padded_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$}  {}",
                row.addr, row.asn, row.state_colored, row.uptime, row.rx, row.tx, row.desc,
            );
        }
        return out;
    }

    // Wide: default columns in order, then the extras, with the
    // overloaded State/PfxRcd last for maximal muscle-memory.
    let w_desc = rows.iter().map(|r| r.desc.len()).max().unwrap_or(0).max(11); // "Description"
    let w_mr = rows
        .iter()
        .map(|r| r.msg_rcvd.len())
        .max()
        .unwrap_or(0)
        .max(7); // "MsgRcvd"
    let w_ms = rows
        .iter()
        .map(|r| r.msg_sent.len())
        .max()
        .unwrap_or(0)
        .max(7); // "MsgSent"
    let w_fl = rows.iter().map(|r| r.flaps.len()).max().unwrap_or(0).max(5); // "Flaps"

    let _ = writeln!(
        out,
        "{:<w_addr$} {:<w_asn$} {:<w_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$} \
         {:<w_desc$} {:>w_mr$} {:>w_ms$} {:>w_fl$} {:<3} State/PfxRcd",
        "Neighbor",
        "AS",
        "State",
        "Uptime",
        "Rx Pfx",
        "Tx Pfx",
        "Description",
        "MsgRcvd",
        "MsgSent",
        "Flaps",
        "RRC",
    );

    for row in &rows {
        let overhead = ansi_overhead(&row.state_colored, row.state_plain.len());
        let padded_state = w_state + overhead;
        let _ = writeln!(
            out,
            "{:<w_addr$} {:<w_asn$} {:<padded_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$} \
             {:<w_desc$} {:>w_mr$} {:>w_ms$} {:>w_fl$} {:<3} {}",
            row.addr,
            row.asn,
            row.state_colored,
            row.uptime,
            row.rx,
            row.tx,
            row.desc,
            row.msg_rcvd,
            row.msg_sent,
            row.flaps,
            row.rrc,
            row.state_pfx,
        );
    }
    out
}

/// Render one MED table cell. `med_attr` is the honest absence marker
/// (LAN-313): when the daemon supports it (populated anywhere in the
/// response), an absent MED renders as "-"; against an older daemon the
/// bare 0-defaulted `med` field is shown as-is.
fn format_med(med: u32, med_attr: Option<u32>, med_attr_supported: bool) -> String {
    match med_attr {
        Some(m) => m.to_string(),
        None if med_attr_supported => "-".to_string(),
        None => med.to_string(),
    }
}

/// Print route table with dynamic column widths and colored best marker.
pub fn print_route_table(routes: &[proto::Route]) {
    print!("{}", render_route_table(routes));
}

fn render_route_table(routes: &[proto::Route]) -> String {
    use std::fmt::Write as _;

    struct Row {
        marker_colored: String,
        marker_plain_len: usize,
        prefix: String,
        next_hop: String,
        as_path: String,
        lp: String,
        med: String,
        origin: String,
        path_id: String,
    }

    // GR stale flag column ("S" = stale per RFC 4724, "L" = LLGR stale
    // per RFC 9494), prepended to the best marker only when some route
    // carries a flag so the everyday table is unchanged.
    let any_stale = routes.iter().any(|r| r.stale || r.llgr_stale);
    // A daemon that populates `med_attr` anywhere in the response is
    // MED-absence-aware: render an absent MED as "-". Older daemons
    // never set it, so fall back to the bare (0-defaulted) `med` field.
    let med_attr_supported = routes.iter().any(|r| r.med_attr.is_some());
    let rows: Vec<Row> = routes
        .iter()
        .map(|r| {
            let path_id = if r.path_id > 0 {
                r.path_id.to_string()
            } else {
                String::new()
            };
            let mut marker_colored = String::new();
            let mut marker_plain_len = 2;
            if any_stale {
                marker_plain_len = 3;
                if r.llgr_stale {
                    let _ = write!(
                        marker_colored,
                        "{}",
                        "L".if_supports_color(Stdout, |s| s.red())
                    );
                } else if r.stale {
                    let _ = write!(
                        marker_colored,
                        "{}",
                        "S".if_supports_color(Stdout, |s| s.red())
                    );
                } else {
                    marker_colored.push(' ');
                }
            }
            marker_colored.push_str(&colored_best_marker(r.best));
            Row {
                marker_colored,
                marker_plain_len,
                prefix: format!("{}/{}", r.prefix, r.prefix_length),
                next_hop: r.next_hop.clone(),
                as_path: format_as_path(&r.as_path),
                lp: r.local_pref.to_string(),
                med: format_med(r.med, r.med_attr, med_attr_supported),
                origin: format_origin(r.origin).to_string(),
                path_id,
            }
        })
        .collect();

    let w_pfx = rows
        .iter()
        .map(|r| r.prefix.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let w_nh = rows
        .iter()
        .map(|r| r.next_hop.len())
        .max()
        .unwrap_or(0)
        .max(8);
    let w_asp = rows
        .iter()
        .map(|r| r.as_path.len())
        .max()
        .unwrap_or(0)
        .max(7);
    let w_lp = rows.iter().map(|r| r.lp.len()).max().unwrap_or(0).max(2);
    let w_med = rows.iter().map(|r| r.med.len()).max().unwrap_or(0).max(3);
    let w_orig = rows
        .iter()
        .map(|r| r.origin.len())
        .max()
        .unwrap_or(0)
        .max(6);

    let mut out = String::new();
    let header_pad = if any_stale { "    " } else { "   " };
    let _ = writeln!(
        out,
        "{header_pad}{:<w_pfx$} {:<w_nh$} {:<w_asp$} {:>w_lp$} {:>w_med$}  {:<w_orig$} PathID",
        "Prefix", "Next Hop", "AS Path", "LP", "MED", "Origin",
    );

    for row in &rows {
        let overhead = ansi_overhead(&row.marker_colored, row.marker_plain_len);
        let marker_width = row.marker_plain_len + overhead;
        let _ = writeln!(
            out,
            "{:<marker_width$} {:<w_pfx$} {:<w_nh$} {:<w_asp$} {:>w_lp$} {:>w_med$}  {:<w_orig$} {}",
            row.marker_colored,
            row.prefix,
            row.next_hop,
            row.as_path,
            row.lp,
            row.med,
            row.origin,
            row.path_id,
        );
    }
    out
}

/// Print a mutating command result, either as JSON or plain text.
pub fn print_result(json: bool, action: &str, target: &str, message: &str) -> Result<(), CliError> {
    if json {
        let out = serde_json::json!({
            "ok": true,
            "action": action,
            "target": target,
        });
        print_json_pretty(&out)?;
    } else {
        println!("{message}");
    }
    Ok(())
}

/// Compose the one-line "what next" footer for a lifecycle command, or
/// `None` under `--json` — machine output must stay pure JSON, so every
/// footer routes through this suppression gate.
pub fn next_step(json: bool, text: &str) -> Option<String> {
    (!json).then(|| format!("next: {text}"))
}

/// Print the "what next" footer to stderr, so it never mixes into
/// pipeable stdout. No-op under `--json`.
pub fn print_next_step(json: bool, text: &str) {
    if let Some(line) = next_step(json, text) {
        eprintln!("{line}");
    }
}

/// Print a pretty JSON value, returning a CLI error instead of panicking if
/// serialization fails.
pub fn print_json_pretty<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Print a compact single-line JSON value for streaming commands.
pub fn print_json_line<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

/// Parse "prefix/length" or "prefix" (for host routes) into (IP, length).
pub fn parse_prefix_addr(s: &str) -> Result<(IpAddr, u32), String> {
    if let Some((addr, len)) = s.split_once('/') {
        let length: u32 = len
            .parse()
            .map_err(|_| format!("invalid prefix length: {len}"))?;
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid IP address in prefix: {addr}"))?;
        match ip {
            IpAddr::V4(_) if length > 32 => {
                return Err(format!("prefix length {length} exceeds 32 for IPv4"));
            }
            IpAddr::V6(_) if length > 128 => {
                return Err(format!("prefix length {length} exceeds 128 for IPv6"));
            }
            _ => {}
        }
        Ok((ip, length))
    } else {
        // Host route
        let ip: IpAddr = s
            .parse()
            .map_err(|_| format!("invalid IP address in prefix: {s}"))?;
        match ip {
            IpAddr::V4(_) => Ok((ip, 32)),
            IpAddr::V6(_) => Ok((ip, 128)),
        }
    }
}

/// Parse "prefix/length" or "prefix" (for host routes) into (prefix, length).
pub fn parse_prefix(s: &str) -> Result<(String, u32), String> {
    parse_prefix_addr(s).map(|(addr, length)| (addr.to_string(), length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_type(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    fn assert_json_shape(value: &Value, shape: &Value, contract_id: &str) {
        let object = value.as_object().expect("representative JSON is an object");
        for (key, expected) in shape["required_json_types"].as_object().unwrap() {
            let field = object
                .get(key)
                .unwrap_or_else(|| panic!("required {contract_id} field {key:?} is absent"));
            assert_json_type(field, expected, contract_id, key);
        }
        for (key, expected) in shape["optional_json_types"].as_object().unwrap() {
            if let Some(field) = object.get(key) {
                assert_json_type(field, expected, contract_id, key);
            }
        }
    }

    fn assert_json_type(value: &Value, expected: &Value, contract_id: &str, key: &str) {
        let allowed: Vec<&str> = match expected {
            Value::String(value) => vec![value.as_str()],
            Value::Array(values) => values.iter().map(|value| value.as_str().unwrap()).collect(),
            _ => panic!("invalid {contract_id} type floor for {key:?}"),
        };
        assert!(
            allowed.contains(&json_type(value)),
            "{contract_id} field {key:?} changed JSON type: expected {allowed:?}, got {}",
            json_type(value)
        );
    }

    fn assert_inventory_json_contract(value: &Value, contract_id: &str) {
        let inventory_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/v1-stable-surface.json"
        );
        let inventory: Value =
            serde_json::from_str(&std::fs::read_to_string(inventory_path).unwrap()).unwrap();
        let contract = inventory["cli"]["test_pinned_json_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["id"] == contract_id)
            .unwrap_or_else(|| panic!("missing JSON contract {contract_id}"));
        assert_json_shape(value, contract, contract_id);
        for nested in contract["nested_json_contracts"].as_array().unwrap() {
            match nested["path"].as_str().unwrap() {
                "selection_deferral[]" => {
                    for row in value["selection_deferral"].as_array().unwrap() {
                        assert_json_shape(row, nested, contract_id);
                    }
                }
                "tcp_ao" => assert_json_shape(&value["tcp_ao"], nested, contract_id),
                "tcp_ao.keys[]" => {
                    for key in value["tcp_ao"]["keys"].as_array().unwrap() {
                        assert_json_shape(key, nested, contract_id);
                    }
                }
                path => panic!("unhandled {contract_id} nested contract path {path}"),
            }
        }
    }

    #[test]
    fn paths_limit_json_preserves_raw_and_adds_normalized_limit() {
        let row = JsonPathsLimit {
            family: "ipv4_unicast".to_string(),
            configured_receive_max: 3,
            advertised_receive_max: 3,
            received_receive_max: 0,
            effective_send_max: u32::MAX,
            effective_send_limit: Some(0),
            effective_send_active: true,
        };
        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value["effective_send_max"], u64::from(u32::MAX));
        assert_eq!(value["effective_send_limit"], 0);
        assert_eq!(value["effective_send_active"], true);
    }
    use serde_json::Value;
    use std::collections::BTreeMap;

    #[test]
    fn next_step_footer_golden_and_suppressed_under_json() {
        // Golden shape for the human footer...
        assert_eq!(
            next_step(
                false,
                "confirm within the window: rbgp config confirm deploy-1"
            ),
            Some("next: confirm within the window: rbgp config confirm deploy-1".to_string())
        );
        // ...and proof `-j` output carries NO footer: every lifecycle footer
        // routes through this gate.
        assert_eq!(next_step(true, "anything"), None);
    }

    #[test]
    fn test_format_duration() {
        // Force colors off for test determinism
        owo_colors::set_override(false);

        assert_eq!(format_duration(0), "00:00:00");
        assert_eq!(format_duration(61), "00:01:01");
        assert_eq!(format_duration(3661), "01:01:01");
        // >= 1 day
        assert_eq!(format_duration(86400), "1d 0h 0m");
        assert_eq!(format_duration(90000), "1d 1h 0m");
        assert_eq!(format_duration(100000), "1d 3h 46m");
        // >= 7 days
        assert_eq!(format_duration(604800), "7d 0h");
        assert_eq!(format_duration(615600), "7d 3h");
    }

    #[test]
    fn test_format_med() {
        // MED-absence-aware daemon: explicit values (including 0) render
        // as numbers, an absent MED renders as "-".
        assert_eq!(format_med(0, Some(0), true), "0");
        assert_eq!(format_med(50, Some(50), true), "50");
        assert_eq!(format_med(0, None, true), "-");
        // Older daemon (med_attr populated nowhere): the bare
        // 0-defaulted field passes through unchanged.
        assert_eq!(format_med(0, None, false), "0");
        assert_eq!(format_med(50, None, false), "50");
    }

    #[test]
    fn test_format_as_path() {
        assert_eq!(format_as_path(&[]), "");
        assert_eq!(format_as_path(&[65001]), "65001");
        assert_eq!(format_as_path(&[65001, 65002, 65003]), "65001 65002 65003");
    }

    #[test]
    fn test_format_community() {
        assert_eq!(format_community(0xFFFF_0001), "65535:1");
        assert_eq!(format_community(0x0001_0064), "1:100");
        assert_eq!(
            format_community(rustbgpd_wire::COMMUNITY_NO_ADVERTISE),
            "NO_ADVERTISE"
        );
        assert_eq!(
            format_community(rustbgpd_wire::COMMUNITY_BLACKHOLE),
            "BLACKHOLE"
        );
        assert_eq!(
            format_community(rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN),
            "GRACEFUL_SHUTDOWN"
        );
    }

    #[test]
    fn test_format_origin() {
        assert_eq!(format_origin(0), "igp");
        assert_eq!(format_origin(1), "egp");
        assert_eq!(format_origin(2), "incomplete");
        assert_eq!(format_origin(99), "?");
    }

    #[test]
    fn test_format_state() {
        assert_eq!(format_state(1), "Idle");
        assert_eq!(format_state(6), "Established");
        assert_eq!(format_state(0), "Unknown");
    }

    #[test]
    fn test_format_state_with_stale_overrides_state() {
        // Stale wins regardless of the underlying state: a stalled
        // session's `state` field is a placeholder Idle, so reporting
        // it raw would misclassify hung-but-alive sessions.
        assert_eq!(format_state_with_stale(6, false), "Established");
        assert_eq!(format_state_with_stale(6, true), "Stale");
        assert_eq!(format_state_with_stale(1, true), "Stale");
        assert_eq!(format_state_with_stale(1, false), "Idle");
    }

    #[test]
    fn test_colored_state_contains_label() {
        assert!(colored_state(6).contains("Established"));
        assert!(colored_state(1).contains("Idle"));
        assert!(colored_state(3).contains("Active"));
        assert!(colored_state(2).contains("Connect"));
        assert!(colored_state(4).contains("OpenSent"));
        assert!(colored_state(5).contains("OpenConfirm"));
        assert!(colored_state(0).contains("Unknown"));
    }

    #[test]
    fn test_colored_state_with_stale_contains_stale_label() {
        assert!(colored_state_with_stale(6, true).contains("Stale"));
        assert!(colored_state_with_stale(6, false).contains("Established"));
    }

    #[test]
    fn test_colored_health_contains_label() {
        assert!(colored_health(true).contains("healthy"));
        assert!(colored_health(false).contains("unhealthy"));
    }

    #[test]
    fn test_colored_event_type_contains_label() {
        assert!(colored_event_type("added").contains("added"));
        assert!(colored_event_type("withdrawn").contains("withdrawn"));
        assert!(colored_event_type("best_changed").contains("best_changed"));
        assert_eq!(colored_event_type("unknown"), "unknown");
    }

    #[test]
    fn test_parse_family() {
        assert_eq!(parse_family("ipv4_unicast"), Some(1));
        assert_eq!(parse_family("ipv6"), Some(2));
        assert_eq!(parse_family("ipv4_flowspec"), Some(3));
        assert_eq!(parse_family("bogus"), None);
    }

    #[test]
    fn test_parse_prefix() {
        assert_eq!(parse_prefix("10.0.0.0/24"), Ok(("10.0.0.0".into(), 24)));
        assert_eq!(parse_prefix("10.0.0.1"), Ok(("10.0.0.1".into(), 32)));
        assert_eq!(parse_prefix("2001:db8::/32"), Ok(("2001:db8::".into(), 32)));
        assert_eq!(parse_prefix("::1"), Ok(("::1".into(), 128)));
        assert!(parse_prefix("10.0.0.0/33").is_err());
        assert!(parse_prefix("::1/129").is_err());
        assert!(parse_prefix("10.0.0.0/abc").is_err());
        assert!(parse_prefix("999.999.999.999/24").is_err());
        assert!(parse_prefix("not-an-ip").is_err());
    }

    #[test]
    fn print_json_pretty_surfaces_serialize_errors() {
        let mut non_string_keyed_map = BTreeMap::new();
        non_string_keyed_map.insert(vec![1_u8], "value");

        let err = print_json_pretty(&non_string_keyed_map).unwrap_err();
        assert!(matches!(err, CliError::Json(_)));
    }

    #[test]
    fn test_json_neighbor_detail_serializes_dynamic_peer_fields() {
        let detail = JsonNeighborDetail {
            address: "10.0.0.2".to_string(),
            interface: "eth0".to_string(),
            remote_asn: 65002,
            state: "Established".to_string(),
            stale: true,
            uptime_seconds: 42,
            prefixes_received: 1,
            prefixes_sent: 2,
            updates_received: 3,
            updates_sent: 4,
            notifications_received: 5,
            notifications_sent: 6,
            messages_received: 20,
            messages_sent: 21,
            flap_count: 7,
            last_error: String::new(),
            authentication: "tcp_ao".to_string(),
            tcp_ao_health: "unavailable".to_string(),
            tcp_ao_desired_generation: 2,
            tcp_ao_applied_generation: 1,
            tcp_ao_rotation_phase: "add_only".to_string(),
            tcp_ao_rotation_error: String::new(),
            tcp_ao: Some(JsonTcpAoState {
                current_key_id: Some(7),
                rnext_key_id: Some(9),
                ao_required: true,
                accept_icmps: false,
                packets_good: 12,
                packets_bad: 0,
                packets_key_not_found: 0,
                packets_ao_required: 0,
                packets_dropped_icmp: 0,
                keys: vec![JsonTcpAoKeyState {
                    peer_address: "10.0.0.2".to_string(),
                    prefix_length: 32,
                    send_id: 7,
                    recv_id: 9,
                    algorithm: "hmac(sha256)".to_string(),
                    is_current: true,
                    is_rnext: true,
                    preferred: true,
                    deprecated: false,
                    vrf_ifindex: Some(10),
                    packets_good: 12,
                    packets_bad: 0,
                }],
            }),
            description: "peer-2".to_string(),
            hold_time: 90,
            send_hold_time: 480,
            families: vec!["ipv4_unicast".to_string()],
            peer_group: "rs-clients".to_string(),
            route_reflector_client: false,
            route_server_client: true,
            per_client_best: true,
            distribution_mode: "add-path".to_string(),
            role: "rs".to_string(),
            strict_role: true,
            remote_role: "rs-client".to_string(),
            role_negotiated: true,
            otc_routes_blocked: 3,
            import_policy_routes_permitted: 8,
            import_policy_routes_denied: 1,
            export_policy_routes_permitted: 5,
            export_policy_routes_denied: 2,
            add_path_receive: true,
            add_path_send: true,
            add_path_send_max: 4,
            paths_limits: vec![JsonPathsLimit {
                family: "ipv4_unicast".to_string(),
                configured_receive_max: 4,
                advertised_receive_max: 4,
                received_receive_max: 4,
                effective_send_max: 4,
                effective_send_limit: Some(4),
                effective_send_active: true,
            }],
            update_group: "group:0".to_string(),
            selection_deferral: vec![JsonSelectionDeferralFamily {
                afi: 1,
                safi: 1,
                active: true,
                waiter_state: "awaiting_eor".to_string(),
                waiter_session_id: Some(42),
                blocking_waiters: 2,
                remaining_millis: 1_500,
                release_reason: "all_eor".to_string(),
            }],
        };

        let value: Value =
            serde_json::from_str(&serde_json::to_string(&detail).expect("JSON serialize"))
                .expect("JSON parse");

        // The inventory is the required-key/type floor. This assertion
        // deliberately allows additive fields while rejecting removal or
        // type drift of every currently promised field.
        assert_inventory_json_contract(&value, "neighbor-detail-v1");

        assert_eq!(value["peer_group"], "rs-clients");
        assert_eq!(value["route_server_client"], true);
        assert_eq!(value["role"], "rs");
        assert_eq!(value["strict_role"], true);
        assert_eq!(value["remote_role"], "rs-client");
        assert_eq!(value["role_negotiated"], true);
        assert_eq!(value["authentication"], "tcp_ao");
        assert_eq!(value["tcp_ao_health"], "unavailable");
        assert_eq!(value["tcp_ao_desired_generation"], 2);
        assert_eq!(value["tcp_ao_applied_generation"], 1);
        assert_eq!(value["tcp_ao_rotation_phase"], "add_only");
        assert_eq!(value["tcp_ao"]["keys"][0]["algorithm"], "hmac(sha256)");
        assert!(value.to_string().find("secret").is_none());
        assert_eq!(value["otc_routes_blocked"], 3);
        assert_eq!(value["import_policy_routes_permitted"], 8);
        assert_eq!(value["import_policy_routes_denied"], 1);
        assert_eq!(value["export_policy_routes_permitted"], 5);
        assert_eq!(value["export_policy_routes_denied"], 2);
        assert_eq!(value["add_path_receive"], true);
        assert_eq!(value["add_path_send"], true);
        assert_eq!(value["add_path_send_max"], 4);
        assert_eq!(value["messages_received"], 20);
        assert_eq!(value["messages_sent"], 21);
        assert_eq!(value["route_reflector_client"], false);
        assert_eq!(value["selection_deferral"][0]["afi"], 1);
        assert_eq!(
            value["selection_deferral"][0]["waiter_state"],
            "awaiting_eor"
        );
        assert_eq!(value["selection_deferral"][0]["waiter_session_id"], 42);
        assert_eq!(value["selection_deferral"][0]["blocking_waiters"], 2);
    }

    fn table_fixture() -> Vec<proto::NeighborState> {
        vec![
            proto::NeighborState {
                config: Some(proto::NeighborConfig {
                    address: "10.0.0.1".to_string(),
                    remote_asn: 64512,
                    description: "core-rr-client".to_string(),
                    ..Default::default()
                }),
                state: proto::SessionState::Established as i32,
                uptime_seconds: 3700,
                prefixes_received: 100,
                prefixes_sent: 5,
                messages_received: 1234,
                messages_sent: 567,
                flap_count: 2,
                route_reflector_client: true,
                ..Default::default()
            },
            proto::NeighborState {
                config: Some(proto::NeighborConfig {
                    address: "2001:db8::2".to_string(),
                    remote_asn: 65001,
                    ..Default::default()
                }),
                state: proto::SessionState::Idle as i32,
                flap_count: 9,
                ..Default::default()
            },
        ]
    }

    /// Pins the default table byte-for-byte: `--wide` must not change
    /// the zero-flag output existing operators and scripts see.
    #[test]
    fn neighbor_table_default_golden() {
        owo_colors::set_override(false);
        let expected = "\
Neighbor    AS    State       Uptime   Rx Pfx Tx Pfx  Description
10.0.0.1    64512 Established 01:01:40    100      5  core-rr-client
2001:db8::2 65001 Idle        00:00:00      0      0  \n";
        assert_eq!(render_neighbor_table(&table_fixture(), false), expected);
    }

    /// Golden wide table: default columns unchanged and in order, then
    /// MsgRcvd/MsgSent/Flaps/RRC, with the overloaded State/PfxRcd last
    /// (prefix count when Established, state name otherwise).
    #[test]
    fn neighbor_table_wide_golden() {
        owo_colors::set_override(false);
        let expected = "\
Neighbor    AS    State       Uptime   Rx Pfx Tx Pfx Description    MsgRcvd MsgSent Flaps RRC State/PfxRcd
10.0.0.1    64512 Established 01:01:40    100      5 core-rr-client    1234     567     2 *   100
2001:db8::2 65001 Idle        00:00:00      0      0                      0       0     9     Idle\n";
        assert_eq!(render_neighbor_table(&table_fixture(), true), expected);
    }

    /// A stale row must never render its placeholder state as a
    /// prefix count in State/PfxRcd, even when the placeholder says
    /// Established.
    #[test]
    fn neighbor_table_wide_stale_overrides_pfxrcd() {
        owo_colors::set_override(false);
        let mut neighbors = table_fixture();
        neighbors[0].stale = true;
        let rendered = render_neighbor_table(&neighbors, true);
        let first_row = rendered.lines().nth(1).expect("row rendered");
        assert!(first_row.ends_with("Stale"), "got: {first_row:?}");
        assert!(!first_row.ends_with("100"));
    }

    fn route_fixture(stale: bool, llgr_stale: bool) -> proto::Route {
        proto::Route {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.1".to_string(),
            as_path: vec![65001],
            local_pref: 100,
            best: true,
            stale,
            llgr_stale,
            ..Default::default()
        }
    }

    /// Without any GR-stale route the table keeps its classic 2-char
    /// marker column — unchanged from the pre-LAN-347 layout.
    #[test]
    fn route_table_no_stale_layout_unchanged() {
        owo_colors::set_override(false);
        let rendered = render_route_table(&[route_fixture(false, false)]);
        let mut lines = rendered.lines();
        assert!(lines.next().unwrap().starts_with("   Prefix"));
        assert!(lines.next().unwrap().starts_with("*> 10.0.0.0/24"));
    }

    /// A GR-stale route widens the marker column with an "S" (stale,
    /// RFC 4724) or "L" (LLGR stale, RFC 9494) flag; unflagged rows
    /// stay aligned (LAN-347).
    #[test]
    fn route_table_marks_stale_routes() {
        owo_colors::set_override(false);
        let mut llgr = route_fixture(true, true);
        llgr.best = false;
        let routes = [
            route_fixture(false, false),
            route_fixture(true, false),
            llgr,
        ];
        let rendered = render_route_table(&routes);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("    Prefix"), "got: {:?}", lines[0]);
        assert!(
            lines[1].starts_with(" *> 10.0.0.0/24"),
            "got: {:?}",
            lines[1]
        );
        assert!(
            lines[2].starts_with("S*> 10.0.0.0/24"),
            "got: {:?}",
            lines[2]
        );
        assert!(
            lines[3].starts_with("L   10.0.0.0/24"),
            "got: {:?}",
            lines[3]
        );
    }
}
