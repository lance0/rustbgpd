use serde::Serialize;

use crate::proto;

/// Format seconds as HH:MM:SS or "never" if 0.
pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "never".into();
    }
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    format!("{h:02}:{m:02}:{s:02}")
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

/// Map address family string to proto enum value.
pub fn parse_family(family: &str) -> Option<i32> {
    match family {
        "ipv4_unicast" | "ipv4-unicast" | "ipv4" => {
            Some(proto::AddressFamily::Ipv4Unicast as i32)
        }
        "ipv6_unicast" | "ipv6-unicast" | "ipv6" => {
            Some(proto::AddressFamily::Ipv6Unicast as i32)
        }
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

/// Print a table row with fixed column widths.
pub fn print_neighbor_header() {
    println!(
        "{:<16} {:<8} {:<14} {:<10} {:>7} {:>7}  Description",
        "Neighbor", "AS", "State", "Uptime", "Rx Pfx", "Tx Pfx"
    );
}

pub fn print_neighbor_row(n: &proto::NeighborState) {
    let cfg = n.config.as_ref();
    let addr = cfg.map(|c| c.address.as_str()).unwrap_or("");
    let asn = cfg.map(|c| c.remote_asn).unwrap_or(0);
    let desc = cfg.map(|c| c.description.as_str()).unwrap_or("");
    println!(
        "{:<16} {:<8} {:<14} {:<10} {:>7} {:>7}  {}",
        addr,
        asn,
        format_state(n.state),
        format_duration(n.uptime_seconds),
        n.prefixes_received,
        n.prefixes_sent,
        desc,
    );
}

pub fn print_route_header() {
    println!(
        "   {:<20} {:<17} {:<16} {:>4} {:>5}  {:<11} PathID",
        "Prefix", "Next Hop", "AS Path", "LP", "MED", "Origin"
    );
}

pub fn print_route_row(r: &proto::Route) {
    let prefix = format!("{}/{}", r.prefix, r.prefix_length);
    let best_marker = if r.best { "*>" } else { "  " };
    let path_id = if r.path_id > 0 {
        r.path_id.to_string()
    } else {
        String::new()
    };
    println!(
        "{} {:<20} {:<17} {:<16} {:>4} {:>5}  {:<11} {}",
        best_marker,
        prefix,
        r.next_hop,
        format_as_path(&r.as_path),
        r.local_pref,
        r.med,
        format_origin(r.origin),
        path_id,
    );
}

/// Print a mutating command result, either as JSON or plain text.
pub fn print_result(json: bool, action: &str, target: &str, message: &str) {
    if json {
        let out = serde_json::json!({
            "ok": true,
            "action": action,
            "target": target,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("{message}");
    }
}

/// Parse "prefix/length" or "prefix" (for host routes) into (prefix, length).
pub fn parse_prefix(s: &str) -> Result<(String, u32), String> {
    if let Some((addr, len)) = s.split_once('/') {
        let length: u32 = len.parse().map_err(|_| format!("invalid prefix length: {len}"))?;
        // Basic validation
        if addr.contains(':') {
            if length > 128 {
                return Err(format!("prefix length {length} exceeds 128 for IPv6"));
            }
        } else if length > 32 {
            return Err(format!("prefix length {length} exceeds 32 for IPv4"));
        }
        Ok((addr.to_string(), length))
    } else {
        // Host route
        if s.contains(':') {
            Ok((s.to_string(), 128))
        } else {
            Ok((s.to_string(), 32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "never");
        assert_eq!(format_duration(61), "00:01:01");
        assert_eq!(format_duration(3661), "01:01:01");
        assert_eq!(format_duration(86400), "24:00:00");
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
    }
}
