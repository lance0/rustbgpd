use serde::Serialize;

use std::net::IpAddr;

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

/// Format a standard community (u32) as ASN:value.
pub fn format_community(c: u32) -> String {
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

/// Return colored session state string.
pub fn colored_state(state: i32) -> String {
    let label = format_state(state);
    match state {
        6 => format!("{}", label.if_supports_color(Stdout, |s| s.green())),
        2 | 4 | 5 => format!("{}", label.if_supports_color(Stdout, |s| s.yellow())),
        _ => format!("{}", label.if_supports_color(Stdout, |s| s.red())),
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
        "added" | "best_changed" => {
            format!("{}", event_type.if_supports_color(Stdout, |s| s.green()))
        }
        "withdrawn" => format!("{}", event_type.if_supports_color(Stdout, |s| s.red())),
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
        _ => "unknown",
    }
}

// -- JSON output structs --

#[derive(Serialize)]
pub struct JsonGlobal {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u32,
}

#[derive(Serialize)]
pub struct JsonNeighbor {
    pub address: String,
    pub remote_asn: u32,
    pub state: String,
    pub uptime_seconds: u64,
    pub prefixes_received: u64,
    pub prefixes_sent: u64,
    pub description: String,
}

#[derive(Serialize)]
pub struct JsonNeighborDetail {
    pub address: String,
    pub remote_asn: u32,
    pub state: String,
    pub uptime_seconds: u64,
    pub prefixes_received: u64,
    pub prefixes_sent: u64,
    pub updates_received: u64,
    pub updates_sent: u64,
    pub notifications_received: u64,
    pub notifications_sent: u64,
    pub flap_count: u64,
    pub last_error: String,
    pub description: String,
    pub hold_time: u32,
    pub families: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub peer_group: String,
    pub route_server_client: bool,
    pub add_path_receive: bool,
    pub add_path_send: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub add_path_send_max: u32,
}

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

fn is_zero(v: &u32) -> bool {
    *v == 0
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
    pub event_type: String,
    pub prefix: String,
    pub peer_address: String,
    pub afi_safi: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub path_id: u32,
}

/// Compute extra bytes added by ANSI escape codes in a colored string.
fn ansi_overhead(colored: &str, plain_len: usize) -> usize {
    colored.len().saturating_sub(plain_len)
}

/// Print neighbor table with dynamic column widths and colored state.
pub fn print_neighbor_table(neighbors: &[proto::NeighborState]) {
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
    }

    let rows: Vec<Row> = neighbors
        .iter()
        .map(|n| {
            let cfg = n.config.as_ref();
            Row {
                addr: cfg.map(|c| c.address.clone()).unwrap_or_default(),
                asn: cfg.map(|c| c.remote_asn.to_string()).unwrap_or_default(),
                state_plain: format_state(n.state).to_string(),
                state_colored: colored_state(n.state),
                uptime: format_duration(n.uptime_seconds),
                rx: n.prefixes_received.to_string(),
                tx: n.prefixes_sent.to_string(),
                desc: cfg.map(|c| c.description.clone()).unwrap_or_default(),
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

    println!(
        "{:<w_addr$} {:<w_asn$} {:<w_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$}  Description",
        "Neighbor", "AS", "State", "Uptime", "Rx Pfx", "Tx Pfx",
    );

    for row in &rows {
        let overhead = ansi_overhead(&row.state_colored, row.state_plain.len());
        let padded_state = w_state + overhead;
        println!(
            "{:<w_addr$} {:<w_asn$} {:<padded_state$} {:<w_uptime$} {:>w_rx$} {:>w_tx$}  {}",
            row.addr, row.asn, row.state_colored, row.uptime, row.rx, row.tx, row.desc,
        );
    }
}

/// Print route table with dynamic column widths and colored best marker.
pub fn print_route_table(routes: &[proto::Route]) {
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

    let rows: Vec<Row> = routes
        .iter()
        .map(|r| {
            let path_id = if r.path_id > 0 {
                r.path_id.to_string()
            } else {
                String::new()
            };
            Row {
                marker_colored: colored_best_marker(r.best),
                marker_plain_len: 2,
                prefix: format!("{}/{}", r.prefix, r.prefix_length),
                next_hop: r.next_hop.clone(),
                as_path: format_as_path(&r.as_path),
                lp: r.local_pref.to_string(),
                med: r.med.to_string(),
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

    println!(
        "   {:<w_pfx$} {:<w_nh$} {:<w_asp$} {:>w_lp$} {:>w_med$}  {:<w_orig$} PathID",
        "Prefix", "Next Hop", "AS Path", "LP", "MED", "Origin",
    );

    for row in &rows {
        let overhead = ansi_overhead(&row.marker_colored, row.marker_plain_len);
        let marker_width = 2 + overhead;
        println!(
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
}

/// Print a mutating command result, either as JSON or plain text.
pub fn print_result(json: bool, action: &str, target: &str, message: &str) {
    if json {
        let out = serde_json::json!({
            "ok": true,
            "action": action,
            "target": target,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize command result as JSON")
        );
    } else {
        println!("{message}");
    }
}

/// Parse "prefix/length" or "prefix" (for host routes) into (prefix, length).
pub fn parse_prefix(s: &str) -> Result<(String, u32), String> {
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
        Ok((addr.to_string(), length))
    } else {
        // Host route
        let ip: IpAddr = s
            .parse()
            .map_err(|_| format!("invalid IP address in prefix: {s}"))?;
        match ip {
            IpAddr::V4(_) => Ok((s.to_string(), 32)),
            IpAddr::V6(_) => Ok((s.to_string(), 128)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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
    fn test_format_as_path() {
        assert_eq!(format_as_path(&[]), "");
        assert_eq!(format_as_path(&[65001]), "65001");
        assert_eq!(format_as_path(&[65001, 65002, 65003]), "65001 65002 65003");
    }

    #[test]
    fn test_format_community() {
        assert_eq!(format_community(0xFFFF_0001), "65535:1");
        assert_eq!(format_community(0x0001_0064), "1:100");
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
    fn test_json_neighbor_detail_serializes_dynamic_peer_fields() {
        let detail = JsonNeighborDetail {
            address: "10.0.0.2".to_string(),
            remote_asn: 65002,
            state: "Established".to_string(),
            uptime_seconds: 42,
            prefixes_received: 1,
            prefixes_sent: 2,
            updates_received: 3,
            updates_sent: 4,
            notifications_received: 5,
            notifications_sent: 6,
            flap_count: 7,
            last_error: String::new(),
            description: "peer-2".to_string(),
            hold_time: 90,
            families: vec!["ipv4_unicast".to_string()],
            peer_group: "rs-clients".to_string(),
            route_server_client: true,
            add_path_receive: true,
            add_path_send: true,
            add_path_send_max: 4,
        };

        let value: Value =
            serde_json::from_str(&serde_json::to_string(&detail).expect("JSON serialize"))
                .expect("JSON parse");

        assert_eq!(value["peer_group"], "rs-clients");
        assert_eq!(value["route_server_client"], true);
        assert_eq!(value["add_path_receive"], true);
        assert_eq!(value["add_path_send"], true);
        assert_eq!(value["add_path_send_max"], 4);
    }
}
