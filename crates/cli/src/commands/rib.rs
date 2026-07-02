use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonExplainAdvertisedRoute, JsonExplainModifications, JsonExplainReason,
};
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddPathRequest, AddressFamily, BgpLsRouteEntry, BlackholeDiscardState, DeletePathRequest,
    ExplainAdvertisedRouteRequest, ExplainBestPathRequest, ExplainBestPathResponse,
    ExplainDecision, FibRouteState, ListBgpLsRequest, ListBlackholeDiscardsRequest,
    ListFibRoutesRequest, ListFibRoutesResponse, ListRoutesRequest, ListRtcRoutesRequest,
    ListVpnRoutesRequest, Route, RtcRouteEntry, VpnRouteEntry,
};
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use std::collections::HashSet;

/// Parsed route filter options from CLI flags.
pub struct RouteFilterOpts {
    pub prefix: Option<String>,
    pub longer: bool,
    pub origin_asn: Option<u32>,
    pub community: Vec<u32>,
    pub large_community: Vec<String>,
}

/// Parsed general FIB status filter options from CLI flags.
pub struct FibRouteFilterOpts {
    pub table: Option<String>,
    pub state: Option<String>,
    pub reason: Option<String>,
    pub prefix: Option<String>,
    pub peer: Option<String>,
    pub page_size: Option<u32>,
    pub page_token: Option<String>,
}

fn make_route_request(
    neighbor: Option<&str>,
    family: Option<i32>,
    filters: &RouteFilterOpts,
) -> Result<ListRoutesRequest, CliError> {
    let (prefix_filter, prefix_filter_length) = if let Some(ref p) = filters.prefix {
        let (addr, len) = output::parse_prefix(p).map_err(CliError::Argument)?;
        (addr, len)
    } else {
        (String::new(), 0)
    };

    Ok(ListRoutesRequest {
        neighbor_address: neighbor.unwrap_or("").to_string(),
        afi_safi: family.unwrap_or(0),
        page_size: 0,
        page_token: String::new(),
        prefix_filter,
        prefix_filter_length,
        longer_prefixes: filters.longer,
        origin_asn: filters.origin_asn.unwrap_or(0),
        community_filter: filters.community.clone(),
        large_community_filter: filters.large_community.clone(),
    })
}

fn parse_fib_state(s: &str) -> Result<i32, CliError> {
    match s {
        "installed" => Ok(FibRouteState::Installed as i32),
        "rejected" => Ok(FibRouteState::Rejected as i32),
        "failed" => Ok(FibRouteState::Failed as i32),
        other => Err(CliError::Argument(format!(
            "unsupported FIB route state {other:?}; expected installed, rejected, or failed"
        ))),
    }
}

fn make_fib_request(filters: &FibRouteFilterOpts) -> Result<ListFibRoutesRequest, CliError> {
    let page_size = filters.page_size.unwrap_or(0);
    if filters
        .page_token
        .as_ref()
        .is_some_and(|token| !token.is_empty())
        && page_size == 0
    {
        return Err(CliError::Argument(
            "--page-token requires --page-size greater than 0".to_string(),
        ));
    }

    let (prefix, prefix_length) = if let Some(prefix) = &filters.prefix {
        output::parse_prefix(prefix).map_err(CliError::Argument)?
    } else {
        (String::new(), 0)
    };
    let peer_address = if let Some(peer) = &filters.peer {
        let addr: std::net::IpAddr = peer
            .parse()
            .map_err(|e| CliError::Argument(format!("invalid --peer address: {e}")))?;
        addr.to_string()
    } else {
        String::new()
    };

    Ok(ListFibRoutesRequest {
        table_name: filters.table.clone().unwrap_or_default(),
        state: filters
            .state
            .as_deref()
            .map(parse_fib_state)
            .transpose()?
            .unwrap_or(FibRouteState::Unspecified as i32),
        reason: filters.reason.clone().unwrap_or_default(),
        prefix,
        prefix_length,
        peer_address,
        page_size,
        page_token: filters.page_token.clone().unwrap_or_default(),
    })
}

fn include_fib_page_meta(filters: &FibRouteFilterOpts) -> bool {
    filters.page_size.is_some_and(|page_size| page_size > 0)
}

fn parse_bgpls_family(family: Option<&str>) -> Result<i32, CliError> {
    let Some(family) = family else {
        return Ok(AddressFamily::Unspecified as i32);
    };
    match output::parse_family(family) {
        Some(value)
            if value == AddressFamily::BgpLs as i32 || value == AddressFamily::BgpLsVpn as i32 =>
        {
            Ok(value)
        }
        Some(_) | None => Err(CliError::Argument(format!(
            "unsupported BGP-LS family {family:?}; expected linkstate \
             (aliases: bgpls, bgp-ls, bgp_ls) or linkstate_vpn \
             (aliases: bgpls-vpn, bgp-ls-vpn, bgp_ls_vpn)"
        ))),
    }
}

fn make_bgpls_request(
    family: Option<&str>,
    peer: Option<String>,
    nlri_type: Option<u32>,
) -> Result<ListBgpLsRequest, CliError> {
    Ok(ListBgpLsRequest {
        afi_safi: parse_bgpls_family(family)?,
        peer_filter: peer.unwrap_or_default(),
        nlri_type_filter: nlri_type.unwrap_or(0),
    })
}

fn parse_vpn_family(family: Option<&str>) -> Result<String, CliError> {
    match family {
        None => Ok(String::new()),
        Some("l3vpn_ipv4_unicast" | "vpnv4" | "vpn-ipv4" | "vpn_ipv4") => {
            Ok("l3vpn_ipv4_unicast".to_string())
        }
        Some("l3vpn_ipv6_unicast" | "vpnv6" | "vpn-ipv6" | "vpn_ipv6") => {
            Ok("l3vpn_ipv6_unicast".to_string())
        }
        Some(other) => Err(CliError::Argument(format!(
            "unsupported VPN family {other:?}; expected l3vpn_ipv4_unicast \
             (alias: vpnv4) or l3vpn_ipv6_unicast (alias: vpnv6)"
        ))),
    }
}

fn make_vpn_request(
    family: Option<&str>,
    peer: Option<String>,
) -> Result<ListVpnRoutesRequest, CliError> {
    Ok(ListVpnRoutesRequest {
        afi_safi: parse_vpn_family(family)?,
        peer_filter: peer.unwrap_or_default(),
    })
}

fn print_routes(routes: &[crate::proto::Route], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No routes");
    } else {
        output::print_route_table(routes);
    }
    Ok(())
}

fn print_bgpls_routes(routes: &[BgpLsRouteEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonBgpLsRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No BGP-LS routes");
    } else {
        println!(
            "{:<12} {:<18} {:<12} {:<18} {:<18} Payload",
            "Family", "NLRI Type", "RD", "Next Hop", "Peer"
        );
        println!("{}", "-".repeat(104));
        for route in routes {
            let rd = if route.route_distinguisher.is_empty() {
                "-".to_string()
            } else {
                hex_lower(&route.route_distinguisher)
            };
            println!(
                "{:<12} {:<18} {:<12} {:<18} {:<18} {}",
                bgpls_family_display(route),
                bgpls_type_display(route),
                rd,
                route.next_hop,
                route.peer_address,
                hex_lower(&route.payload)
            );
        }
    }
    Ok(())
}

fn print_vpn_routes(routes: &[VpnRouteEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonVpnRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No VPN routes");
    } else {
        println!(
            "{:<16} {:<24} {:<14} {:<18} {:<18} Route Targets",
            "RD", "Prefix", "Labels", "Next Hop", "Peer"
        );
        println!("{}", "-".repeat(110));
        for route in routes {
            let labels = route
                .labels
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{:<16} {:<24} {:<14} {:<18} {:<18} {}",
                route.route_distinguisher_str,
                route.prefix,
                labels,
                route.next_hop,
                route.peer_address,
                vpn_route_targets(route).join(" ")
            );
        }
    }
    Ok(())
}

fn print_rtc_routes(routes: &[RtcRouteEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonRtcRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No RTC routes");
    } else {
        println!(
            "{:<10} {:<20} {:<5} {:<18} From-Peer",
            "Origin-AS", "Route-Target", "Len", "Next-Hop"
        );
        println!("{}", "-".repeat(76));
        for route in routes {
            let (origin_as, route_target) = if route.is_default {
                ("-".to_string(), "default".to_string())
            } else {
                (route.origin_as.to_string(), route.route_target.clone())
            };
            println!(
                "{:<10} {:<20} {:<5} {:<18} {}",
                origin_as,
                route_target,
                route.prefix_len,
                route.next_hop,
                rtc_from_peer(route)
            );
        }
    }
    Ok(())
}

/// The locally-originated default RTC NLRI carries the `LOCAL_PEER`
/// sentinel (unspecified address); render it as `local`.
fn rtc_from_peer(route: &RtcRouteEntry) -> &str {
    if route.peer_address == "0.0.0.0" {
        "local"
    } else {
        &route.peer_address
    }
}

struct JsonRtcRoutes<'a>(&'a [RtcRouteEntry]);

impl Serialize for JsonRtcRoutes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonRtcRouteRef(route))?;
        }
        seq.end()
    }
}

struct JsonRtcRouteRef<'a>(&'a RtcRouteEntry);

impl Serialize for JsonRtcRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.0;
        let mut len = 8;
        if route.path_id != 0 {
            len += 1;
        }
        if route.stale {
            len += 1;
        }
        if route.llgr_stale {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("is_default", &route.is_default)?;
        map.serialize_entry("origin_as", &route.origin_as)?;
        map.serialize_entry("route_target", &route.route_target)?;
        map.serialize_entry("prefix_len", &route.prefix_len)?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("peer_address", &route.peer_address)?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("communities", &route.communities)?;
        if route.path_id != 0 {
            map.serialize_entry("path_id", &route.path_id)?;
        }
        if route.stale {
            map.serialize_entry("stale", &route.stale)?;
        }
        if route.llgr_stale {
            map.serialize_entry("llgr_stale", &route.llgr_stale)?;
        }
        map.end()
    }
}

fn vpn_route_targets(route: &VpnRouteEntry) -> Vec<&str> {
    route
        .extended_communities
        .iter()
        .filter(|ec| ec.starts_with("RT:"))
        .map(String::as_str)
        .collect()
}

struct JsonVpnRoutes<'a>(&'a [VpnRouteEntry]);

impl Serialize for JsonVpnRoutes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonVpnRouteRef(route))?;
        }
        seq.end()
    }
}

struct JsonVpnRouteRef<'a>(&'a VpnRouteEntry);

impl Serialize for JsonVpnRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.0;
        let mut len = 10;
        if route.path_id != 0 {
            len += 1;
        }
        if route.stale {
            len += 1;
        }
        if route.llgr_stale {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("afi_safi", &route.afi_safi)?;
        map.serialize_entry("route_distinguisher", &route.route_distinguisher_str)?;
        map.serialize_entry(
            "route_distinguisher_bytes",
            &hex_lower(&route.route_distinguisher),
        )?;
        map.serialize_entry("prefix", &route.prefix)?;
        map.serialize_entry("labels", &route.labels)?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("peer_address", &route.peer_address)?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("communities", &route.communities)?;
        map.serialize_entry("extended_communities", &route.extended_communities)?;
        if route.path_id != 0 {
            map.serialize_entry("path_id", &route.path_id)?;
        }
        if route.stale {
            map.serialize_entry("stale", &route.stale)?;
        }
        if route.llgr_stale {
            map.serialize_entry("llgr_stale", &route.llgr_stale)?;
        }
        map.end()
    }
}

struct JsonRoutes<'a>(&'a [Route]);

impl Serialize for JsonRoutes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonRouteRef(route))?;
        }
        seq.end()
    }
}

struct JsonBgpLsRoutes<'a>(&'a [BgpLsRouteEntry]);

impl Serialize for JsonBgpLsRoutes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonBgpLsRouteRef(route))?;
        }
        seq.end()
    }
}

struct JsonBgpLsRouteRef<'a>(&'a BgpLsRouteEntry);

impl Serialize for JsonBgpLsRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.0;
        let mut len = 14;
        if route.path_id != 0 {
            len += 1;
        }
        if route.llgr_stale {
            len += 1;
        }
        if route.stale {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("family", bgpls_family_display(route))?;
        map.serialize_entry("nlri_type", &route.nlri_type)?;
        map.serialize_entry("nlri_type_name", &route.nlri_type_name)?;
        map.serialize_entry(
            "route_distinguisher",
            &hex_lower(&route.route_distinguisher),
        )?;
        map.serialize_entry("payload", &hex_lower(&route.payload))?;
        map.serialize_entry("descriptor", &hex_lower(&route.descriptor))?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("peer_address", &route.peer_address)?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("communities", &JsonCommunities(&route.communities))?;
        map.serialize_entry("extended_communities", &route.extended_communities)?;
        map.serialize_entry("bgp_ls_attribute", &hex_lower(&route.bgp_ls_attribute))?;
        if route.path_id != 0 {
            map.serialize_entry("path_id", &route.path_id)?;
        }
        if route.stale {
            map.serialize_entry("stale", &route.stale)?;
        }
        if route.llgr_stale {
            map.serialize_entry("llgr_stale", &route.llgr_stale)?;
        }
        map.end()
    }
}

fn bgpls_family_display(route: &BgpLsRouteEntry) -> &str {
    if route.family.is_empty() {
        output::format_family(route.afi_safi)
    } else {
        &route.family
    }
}

fn bgpls_type_display(route: &BgpLsRouteEntry) -> String {
    if route.nlri_type_name.is_empty() {
        route.nlri_type.to_string()
    } else {
        format!("{} ({})", route.nlri_type, route.nlri_type_name)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

struct JsonRouteRef<'a>(&'a Route);

impl Serialize for JsonRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.0;
        let mut len = 10;
        if route.path_id != 0 {
            len += 1;
        }
        if !route.validation_state.is_empty() {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("prefix", &JsonRoutePrefix(route))?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("local_pref", &route.local_pref)?;
        map.serialize_entry("med", &route.med)?;
        map.serialize_entry("origin", output::format_origin(route.origin))?;
        map.serialize_entry("best", &route.best)?;
        map.serialize_entry("peer_address", &route.peer_address)?;
        map.serialize_entry("communities", &JsonCommunities(&route.communities))?;
        map.serialize_entry("large_communities", &route.large_communities)?;
        if route.path_id != 0 {
            map.serialize_entry("path_id", &route.path_id)?;
        }
        if !route.validation_state.is_empty() {
            map.serialize_entry("validation_state", &route.validation_state)?;
        }
        map.end()
    }
}

struct JsonRoutePrefix<'a>(&'a Route);

impl Serialize for JsonRoutePrefix<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&format_args!("{}/{}", self.0.prefix, self.0.prefix_length))
    }
}

struct JsonCommunities<'a>(&'a [u32]);

impl Serialize for JsonCommunities<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for community in self.0 {
            seq.serialize_element(&output::format_community(*community))?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct JsonBlackholeDiscard {
    prefix: String,
    peer_address: String,
    state: String,
    reason: String,
}

#[derive(Serialize)]
struct JsonFibRouteStatus {
    table_name: String,
    table_id: u32,
    metric: u32,
    prefix: String,
    next_hop: String,
    /// All equal-cost next-hops (unicast multipath / ECMP), canonical. One
    /// entry == single-path. `next_hop` is the best/representative next-hop and
    /// is a member of this set when non-empty (not necessarily `next_hops[0]`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    next_hops: Vec<String>,
    peer_address: String,
    state: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling: Option<JsonFibRouteSamplingMetadata>,
}

#[derive(Clone, Hash, PartialEq, Eq, Serialize)]
struct JsonFibRouteSamplingMetadata {
    table_name: String,
    table_id: u32,
    metric: u32,
    reason: String,
    sampled_rows: u64,
    suppressed_rows: u64,
    total_rows: u64,
    max_routes: u32,
    sample_limit: u32,
    complete: bool,
}

#[derive(Serialize)]
struct JsonFibRoutePage {
    routes: Vec<JsonFibRouteStatus>,
    next_page_token: String,
    total_count: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sampling: Vec<JsonFibRouteSamplingMetadata>,
}

fn print_blackhole_discards(
    discards: &[crate::proto::BlackholeDiscard],
    json: bool,
) -> Result<(), CliError> {
    if json {
        let out: Vec<JsonBlackholeDiscard> =
            discards.iter().map(blackhole_discard_to_json).collect();
        output::print_json_pretty(&out)?;
    } else if discards.is_empty() {
        println!("No BLACKHOLE discard routes");
    } else {
        println!("{:<43} {:<18} {:<10} Reason", "Prefix", "Peer", "State");
        println!("{}", "-".repeat(88));
        for d in discards {
            println!(
                "{:<43} {:<18} {:<10} {}",
                format!("{}/{}", d.prefix, d.prefix_length),
                d.peer_address,
                blackhole_state_label(d.state),
                d.reason
            );
        }
    }
    Ok(())
}

fn print_fib_routes(
    resp: &ListFibRoutesResponse,
    json: bool,
    include_page_meta: bool,
) -> Result<(), CliError> {
    if json {
        let routes: Vec<JsonFibRouteStatus> =
            resp.routes.iter().map(fib_route_status_to_json).collect();
        if include_page_meta {
            let out = JsonFibRoutePage {
                sampling: fib_sampling_metadata(&resp.routes),
                routes,
                next_page_token: resp.next_page_token.clone(),
                total_count: resp.total_count,
            };
            output::print_json_pretty(&out)?;
        } else {
            output::print_json_pretty(&routes)?;
        }
    } else if resp.routes.is_empty() {
        println!("{}", empty_fib_routes_message(resp, include_page_meta));
    } else {
        println!(
            "{:<16} {:<10} {:<43} {:<39} {:<10} Reason",
            "Table", "Metric", "Prefix", "Next hop", "State"
        );
        println!("{}", "-".repeat(132));
        for r in &resp.routes {
            println!(
                "{:<16} {:<10} {:<43} {:<39} {:<10} {}",
                r.table_name,
                r.metric,
                format!("{}/{}", r.prefix, r.prefix_length),
                fib_next_hop_display(r),
                fib_state_label(r.state),
                r.reason
            );
        }
    }
    if include_page_meta && !json {
        println!("Total matching rows: {}", resp.total_count);
        if !resp.next_page_token.is_empty() {
            println!("Next page token: {}", resp.next_page_token);
        }
        for sampling in fib_sampling_metadata(&resp.routes) {
            println!(
                "Sampling: table={} metric={} reason={} sampled={} suppressed={} total={} max_routes={} sample_limit={} complete={}",
                sampling.table_name,
                sampling.metric,
                sampling.reason,
                sampling.sampled_rows,
                sampling.suppressed_rows,
                sampling.total_rows,
                sampling.max_routes,
                sampling.sample_limit,
                sampling.complete
            );
        }
    }
    Ok(())
}

fn empty_fib_routes_message(resp: &ListFibRoutesResponse, include_page_meta: bool) -> &'static str {
    if include_page_meta && resp.total_count > 0 {
        "No general FIB routes on this page"
    } else {
        "No general FIB routes"
    }
}

fn blackhole_discard_to_json(d: &crate::proto::BlackholeDiscard) -> JsonBlackholeDiscard {
    JsonBlackholeDiscard {
        prefix: format!("{}/{}", d.prefix, d.prefix_length),
        peer_address: d.peer_address.clone(),
        state: blackhole_state_label(d.state).to_string(),
        reason: d.reason.clone(),
    }
}

fn fib_route_status_to_json(r: &crate::proto::FibRouteStatus) -> JsonFibRouteStatus {
    JsonFibRouteStatus {
        table_name: r.table_name.clone(),
        table_id: r.table_id,
        metric: r.metric,
        prefix: format!("{}/{}", r.prefix, r.prefix_length),
        next_hop: r.next_hop.clone(),
        next_hops: r.next_hops.clone(),
        peer_address: r.peer_address.clone(),
        state: fib_state_label(r.state).to_string(),
        reason: r.reason.clone(),
        sampling: fib_route_sampling_metadata(r),
    }
}

/// Render the next-hop column: comma-joined ECMP set when multipath, else the
/// scalar. Falls back to the scalar `next_hop` when an older server returns no
/// `next_hops` list.
fn fib_next_hop_display(r: &crate::proto::FibRouteStatus) -> String {
    if r.next_hops.len() > 1 {
        r.next_hops.join(", ")
    } else {
        r.next_hop.clone()
    }
}

fn fib_sampling_metadata(
    routes: &[crate::proto::FibRouteStatus],
) -> Vec<JsonFibRouteSamplingMetadata> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for sampling in routes.iter().filter_map(fib_route_sampling_metadata) {
        if seen.insert(sampling.clone()) {
            out.push(sampling);
        }
    }
    out
}

fn fib_route_sampling_metadata(
    route: &crate::proto::FibRouteStatus,
) -> Option<JsonFibRouteSamplingMetadata> {
    if route.sampling_total_rows == 0
        && route.sampling_sampled_rows == 0
        && route.sampling_suppressed_rows == 0
    {
        return None;
    }
    Some(JsonFibRouteSamplingMetadata {
        table_name: route.table_name.clone(),
        table_id: route.table_id,
        metric: route.metric,
        reason: route.reason.clone(),
        sampled_rows: route.sampling_sampled_rows,
        suppressed_rows: route.sampling_suppressed_rows,
        total_rows: route.sampling_total_rows,
        max_routes: route.sampling_max_routes,
        sample_limit: route.sampling_sample_limit,
        complete: route.sampling_complete,
    })
}

fn blackhole_state_label(state: i32) -> &'static str {
    match BlackholeDiscardState::try_from(state) {
        Ok(BlackholeDiscardState::Installed) => "installed",
        Ok(BlackholeDiscardState::Rejected) => "rejected",
        Ok(BlackholeDiscardState::Failed) => "failed",
        Ok(BlackholeDiscardState::Unspecified) | Err(_) => "unknown",
    }
}

fn fib_state_label(state: i32) -> &'static str {
    match FibRouteState::try_from(state) {
        Ok(FibRouteState::Installed) => "installed",
        Ok(FibRouteState::Rejected) => "rejected",
        Ok(FibRouteState::Failed) => "failed",
        Ok(FibRouteState::Unspecified) | Err(_) => "unknown",
    }
}

fn explain_to_json(
    explain: &crate::proto::ExplainAdvertisedRouteResponse,
) -> JsonExplainAdvertisedRoute {
    JsonExplainAdvertisedRoute {
        decision: match ExplainDecision::try_from(explain.decision)
            .unwrap_or(ExplainDecision::Unspecified)
        {
            ExplainDecision::Advertise => "advertise",
            ExplainDecision::Deny => "deny",
            ExplainDecision::NoBestRoute => "no_best_route",
            ExplainDecision::UnsupportedFamily => "unsupported_family",
            ExplainDecision::Unspecified => "unspecified",
        }
        .to_string(),
        peer_address: explain.peer_address.clone(),
        prefix: format!("{}/{}", explain.prefix, explain.prefix_length),
        next_hop: explain.next_hop.clone(),
        path_id: explain.path_id,
        route_peer_address: explain.route_peer_address.clone(),
        route_type: explain.route_type.clone(),
        reasons: explain
            .reasons
            .iter()
            .map(|reason| JsonExplainReason {
                code: reason.code.clone(),
                message: reason.message.clone(),
            })
            .collect(),
        modifications: explain.modifications.as_ref().map_or_else(
            || JsonExplainModifications {
                set_local_pref: None,
                set_med: None,
                set_next_hop: String::new(),
                communities_add: vec![],
                communities_remove: vec![],
                extended_communities_add: vec![],
                extended_communities_remove: vec![],
                large_communities_add: vec![],
                large_communities_remove: vec![],
                as_path_prepend_asn: None,
                as_path_prepend_count: None,
            },
            |mods| JsonExplainModifications {
                set_local_pref: mods.set_local_pref,
                set_med: mods.set_med,
                set_next_hop: mods.set_next_hop.clone(),
                communities_add: mods
                    .communities_add
                    .iter()
                    .map(|c| output::format_community(*c))
                    .collect(),
                communities_remove: mods
                    .communities_remove
                    .iter()
                    .map(|c| output::format_community(*c))
                    .collect(),
                extended_communities_add: mods.extended_communities_add.clone(),
                extended_communities_remove: mods.extended_communities_remove.clone(),
                large_communities_add: mods.large_communities_add.clone(),
                large_communities_remove: mods.large_communities_remove.clone(),
                as_path_prepend_asn: mods.as_path_prepend_asn,
                as_path_prepend_count: mods.as_path_prepend_count,
            },
        ),
    }
}

fn print_explain_advertised(
    explain: &crate::proto::ExplainAdvertisedRouteResponse,
    json: bool,
) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&explain_to_json(explain))?;
        return Ok(());
    }

    let decision =
        match ExplainDecision::try_from(explain.decision).unwrap_or(ExplainDecision::Unspecified) {
            ExplainDecision::Advertise => "Advertise",
            ExplainDecision::Deny => "Deny",
            ExplainDecision::NoBestRoute => "No Best Route",
            ExplainDecision::UnsupportedFamily => "Unsupported Family",
            ExplainDecision::Unspecified => "Unspecified",
        };
    println!(
        "{decision}: {}/{} to {}",
        explain.prefix, explain.prefix_length, explain.peer_address
    );
    if !explain.route_peer_address.is_empty() {
        println!("Route peer: {}", explain.route_peer_address);
    }
    if !explain.route_type.is_empty() {
        println!("Route type: {}", explain.route_type);
    }
    if !explain.next_hop.is_empty() {
        println!("Next hop:   {}", explain.next_hop);
    }
    if explain.path_id != 0 {
        println!("Path ID:    {}", explain.path_id);
    }
    if !explain.reasons.is_empty() {
        println!("Reasons:");
        for reason in &explain.reasons {
            println!("- {}: {}", reason.code, reason.message);
        }
    }
    if let Some(mods) = explain.modifications.as_ref()
        && (mods.set_local_pref.is_some()
            || mods.set_med.is_some()
            || !mods.set_next_hop.is_empty()
            || !mods.communities_add.is_empty()
            || !mods.communities_remove.is_empty()
            || !mods.extended_communities_add.is_empty()
            || !mods.extended_communities_remove.is_empty()
            || !mods.large_communities_add.is_empty()
            || !mods.large_communities_remove.is_empty()
            || mods.as_path_prepend_asn.is_some()
            || mods.as_path_prepend_count.is_some())
    {
        println!("Modifications:");
        if let Some(value) = mods.set_local_pref {
            println!("- set_local_pref: {value}");
        }
        if let Some(value) = mods.set_med {
            println!("- set_med: {value}");
        }
        if !mods.set_next_hop.is_empty() {
            println!("- set_next_hop: {}", mods.set_next_hop);
        }
        if !mods.communities_add.is_empty() {
            println!(
                "- communities_add: {}",
                mods.communities_add
                    .iter()
                    .map(|c| output::format_community(*c))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !mods.communities_remove.is_empty() {
            println!(
                "- communities_remove: {}",
                mods.communities_remove
                    .iter()
                    .map(|c| output::format_community(*c))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !mods.extended_communities_add.is_empty() {
            println!(
                "- extended_communities_add: {}",
                mods.extended_communities_add
                    .iter()
                    .map(|ec| format!("0x{ec:016x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !mods.extended_communities_remove.is_empty() {
            println!(
                "- extended_communities_remove: {}",
                mods.extended_communities_remove
                    .iter()
                    .map(|ec| format!("0x{ec:016x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !mods.large_communities_add.is_empty() {
            println!(
                "- large_communities_add: {}",
                mods.large_communities_add.join(", ")
            );
        }
        if !mods.large_communities_remove.is_empty() {
            println!(
                "- large_communities_remove: {}",
                mods.large_communities_remove.join(", ")
            );
        }
        if let (Some(asn), Some(count)) = (mods.as_path_prepend_asn, mods.as_path_prepend_count) {
            println!("- as_path_prepend: {asn} x {count}");
        }
    }
    Ok(())
}

/// Top-level shape of `--json` best-path explain output. Designed
/// so that a global-view explain (no `--explain-peer`) emits a
/// stable key set across runs — only the Add-Path-related fields
/// (`peer_address`, `add_path_send_max`, per-candidate
/// `advertised_path_id`) are skipped via `skip_serializing_if`
/// when not peer-scoped. The pre-existing `best_route` and
/// per-candidate `route` keys keep emitting as `null` when absent
/// — downstream JSON consumers depend on the key set being stable
/// across global-view runs, regardless of whether a best route
/// exists. The tiebreaker-attribution fields (`best_reason`,
/// `best_reason_detail`, per-candidate `vs_best_detail` and
/// `multipath`) are emitted unconditionally for the same reason:
/// always present, never data-dependent.
struct JsonExplainBestPathRef<'a>(&'a ExplainBestPathResponse);

impl Serialize for JsonExplainBestPathRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let resp = self.0;
        let peer_scoped = !resp.peer_address.is_empty();
        let mut len = 5;
        if peer_scoped {
            len += 2;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("prefix", &JsonExplainPrefix(resp))?;
        if peer_scoped {
            map.serialize_entry("peer_address", &resp.peer_address)?;
            map.serialize_entry("add_path_send_max", &resp.add_path_send_max)?;
        }
        map.serialize_entry(
            "best_route",
            &JsonOptionalRouteRef(resp.best_route.as_ref()),
        )?;
        map.serialize_entry("best_reason", &resp.best_reason)?;
        map.serialize_entry("best_reason_detail", &resp.best_reason_detail)?;
        map.serialize_entry(
            "candidates",
            &JsonExplainCandidatesRef {
                candidates: &resp.candidates,
                peer_scoped,
            },
        )?;
        map.end()
    }
}

struct JsonExplainPrefix<'a>(&'a ExplainBestPathResponse);

impl Serialize for JsonExplainPrefix<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&format_args!("{}/{}", self.0.prefix, self.0.prefix_length))
    }
}

struct JsonOptionalRouteRef<'a>(Option<&'a Route>);

impl Serialize for JsonOptionalRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(route) => JsonRouteRef(route).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

struct JsonExplainCandidatesRef<'a> {
    candidates: &'a [crate::proto::BestPathCandidate],
    peer_scoped: bool,
}

impl Serialize for JsonExplainCandidatesRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.candidates.len()))?;
        for candidate in self.candidates {
            seq.serialize_element(&JsonExplainCandidateRef {
                candidate,
                peer_scoped: self.peer_scoped,
            })?;
        }
        seq.end()
    }
}

struct JsonExplainCandidateRef<'a> {
    candidate: &'a crate::proto::BestPathCandidate,
    peer_scoped: bool,
}

impl Serialize for JsonExplainCandidateRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let candidate = self.candidate;
        let mut len = 5;
        if self.peer_scoped {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("route", &JsonOptionalRouteRef(candidate.route.as_ref()))?;
        map.serialize_entry("vs_best_reason", &candidate.vs_best_reason)?;
        map.serialize_entry("vs_best_detail", &candidate.vs_best_detail)?;
        map.serialize_entry("vs_best_ordering", &candidate.vs_best_ordering)?;
        map.serialize_entry("multipath", &candidate.multipath)?;
        if self.peer_scoped {
            map.serialize_entry("advertised_path_id", &candidate.advertised_path_id)?;
        }
        map.end()
    }
}

fn explain_best_path_to_json(resp: &ExplainBestPathResponse) -> JsonExplainBestPathRef<'_> {
    JsonExplainBestPathRef(resp)
}

fn print_explain_best_path(
    resp: &crate::proto::ExplainBestPathResponse,
    json: bool,
) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&explain_best_path_to_json(resp))?;
        return Ok(());
    }

    println!(
        "Best-path explanation for {}/{}",
        resp.prefix, resp.prefix_length
    );
    if !resp.peer_address.is_empty() {
        println!(
            "Scope:      peer {} (Add-Path send_max={})",
            resp.peer_address, resp.add_path_send_max
        );
    }

    if let Some(ref best) = resp.best_route {
        println!(
            "Best route: peer={}, next_hop={}, as_path={:?}",
            best.peer_address, best.next_hop, best.as_path
        );
    } else {
        println!("No best route");
        return Ok(());
    }

    if resp.best_reason == "only_path" {
        println!("Selected:   only path for this prefix");
    } else if resp.best_reason_detail.is_empty() {
        println!("Selected:   {}", resp.best_reason);
    } else {
        println!(
            "Selected:   {} ({}) vs runner-up",
            resp.best_reason, resp.best_reason_detail
        );
    }

    if resp.candidates.is_empty() {
        println!("No candidates");
        return Ok(());
    }

    println!();
    let peer_scoped = !resp.peer_address.is_empty();
    if peer_scoped {
        println!(
            "{:<18} {:<18} {:<22} {:<26} {:<8} {:<10} Adv-PathID",
            "Peer", "Next Hop", "Reason", "Detail", "Result", "Multipath"
        );
        println!("{}", "-".repeat(118));
        for c in &resp.candidates {
            if let Some(ref r) = c.route {
                let advert = if c.advertised_path_id == 0 {
                    "(filtered)".to_string()
                } else {
                    c.advertised_path_id.to_string()
                };
                println!(
                    "{:<18} {:<18} {:<22} {:<26} {:<8} {:<10} {}",
                    r.peer_address,
                    r.next_hop,
                    c.vs_best_reason,
                    c.vs_best_detail,
                    c.vs_best_ordering,
                    c.multipath,
                    advert
                );
            }
        }
    } else {
        println!(
            "{:<18} {:<18} {:<22} {:<26} {:<8} Multipath",
            "Peer", "Next Hop", "Reason", "Detail", "Result"
        );
        println!("{}", "-".repeat(106));
        for c in &resp.candidates {
            if let Some(ref r) = c.route {
                println!(
                    "{:<18} {:<18} {:<22} {:<26} {:<8} {}",
                    r.peer_address,
                    r.next_hop,
                    c.vs_best_reason,
                    c.vs_best_detail,
                    c.vs_best_ordering,
                    c.multipath
                );
            }
        }
    }
    Ok(())
}

pub async fn explain_best_path(
    connection: Connection,
    prefix: &str,
    peer: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .explain_best_path(ExplainBestPathRequest {
            prefix: addr,
            prefix_length: len,
            peer_address: peer.unwrap_or("").to_string(),
        })
        .await?
        .into_inner();
    print_explain_best_path(&resp, json)
}

pub async fn best(
    connection: Connection,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_best_routes(make_route_request(None, family, filters)?)
        .await?
        .into_inner();
    print_routes(&resp.routes, json)
}

pub async fn blackholes(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_blackhole_discards(ListBlackholeDiscardsRequest {})
        .await?
        .into_inner();
    print_blackhole_discards(&resp.discards, json)
}

pub async fn fib(
    connection: Connection,
    filters: FibRouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_fib_routes(make_fib_request(&filters)?)
        .await?
        .into_inner();
    print_fib_routes(&resp, json, include_fib_page_meta(&filters))
}

pub async fn bgpls(
    connection: Connection,
    family: Option<&str>,
    peer: Option<String>,
    nlri_type: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_bgp_ls_routes(make_bgpls_request(family, peer, nlri_type)?)
        .await?
        .into_inner();
    print_bgpls_routes(&resp.routes, json)
}

pub async fn vpn(
    connection: Connection,
    family: Option<&str>,
    peer: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_vpn_routes(make_vpn_request(family, peer)?)
        .await?
        .into_inner();
    print_vpn_routes(&resp.routes, json)
}

pub async fn rtc(connection: Connection, peer: Option<String>, json: bool) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_rtc_routes(ListRtcRoutesRequest {
            peer_filter: peer.unwrap_or_default(),
        })
        .await?
        .into_inner();
    print_rtc_routes(&resp.routes, json)
}

pub async fn received(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_received_routes(make_route_request(Some(address), family, filters)?)
        .await?
        .into_inner();
    print_routes(&resp.routes, json)
}

pub async fn advertised(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_advertised_routes(make_route_request(Some(address), family, filters)?)
        .await?
        .into_inner();
    print_routes(&resp.routes, json)
}

pub async fn explain_advertised(
    connection: Connection,
    address: &str,
    prefix: &str,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .explain_advertised_route(ExplainAdvertisedRouteRequest {
            peer_address: address.to_string(),
            prefix: addr,
            prefix_length: len,
        })
        .await?
        .into_inner();
    print_explain_advertised(&resp, json)
}

pub struct AddRouteOpts {
    pub next_hop: String,
    pub origin: Option<u32>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub as_path: Vec<u32>,
    pub communities: Vec<u32>,
    pub large_communities: Vec<String>,
    pub path_id: Option<u32>,
}

pub async fn add_route(
    connection: Connection,
    prefix: &str,
    opts: AddRouteOpts,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_path(AddPathRequest {
            prefix: addr,
            prefix_length: len,
            next_hop: opts.next_hop,
            as_path: opts.as_path,
            origin: opts.origin.unwrap_or(0),
            local_pref: opts.local_pref,
            med: opts.med,
            communities: opts.communities,
            extended_communities: vec![],
            large_communities: opts.large_communities,
            path_id: opts.path_id.unwrap_or(0),
        })
        .await?;
    output::print_result(json, "add_route", prefix, &format!("Route {prefix} added"))
}

pub async fn delete_route(
    connection: Connection,
    prefix: &str,
    path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_path(DeletePathRequest {
            prefix: addr,
            prefix_length: len,
            path_id: path_id.unwrap_or(0),
        })
        .await?;
    output::print_result(
        json,
        "delete_route",
        prefix,
        &format!("Route {prefix} deleted"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    fn legacy_route_to_json(r: &Route) -> output::JsonRoute {
        output::JsonRoute {
            prefix: format!("{}/{}", r.prefix, r.prefix_length),
            next_hop: r.next_hop.clone(),
            as_path: r.as_path.clone(),
            local_pref: r.local_pref,
            med: r.med,
            origin: output::format_origin(r.origin).to_string(),
            best: r.best,
            peer_address: r.peer_address.clone(),
            communities: r
                .communities
                .iter()
                .map(|c| output::format_community(*c))
                .collect(),
            large_communities: r.large_communities.clone(),
            path_id: r.path_id,
            validation_state: r.validation_state.clone(),
        }
    }

    #[derive(serde::Serialize)]
    struct LegacyJsonExplainBestPath {
        prefix: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        add_path_send_max: Option<u32>,
        best_route: Option<output::JsonRoute>,
        best_reason: String,
        best_reason_detail: String,
        candidates: Vec<LegacyJsonExplainCandidate>,
    }

    #[derive(serde::Serialize)]
    struct LegacyJsonExplainCandidate {
        route: Option<output::JsonRoute>,
        vs_best_reason: String,
        vs_best_detail: String,
        vs_best_ordering: String,
        multipath: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        advertised_path_id: Option<u32>,
    }

    fn legacy_explain_best_path_to_json(
        resp: &ExplainBestPathResponse,
    ) -> LegacyJsonExplainBestPath {
        let peer_scoped = !resp.peer_address.is_empty();
        LegacyJsonExplainBestPath {
            prefix: format!("{}/{}", resp.prefix, resp.prefix_length),
            peer_address: peer_scoped.then(|| resp.peer_address.clone()),
            add_path_send_max: peer_scoped.then_some(resp.add_path_send_max),
            best_route: resp.best_route.as_ref().map(legacy_route_to_json),
            best_reason: resp.best_reason.clone(),
            best_reason_detail: resp.best_reason_detail.clone(),
            candidates: resp
                .candidates
                .iter()
                .map(|c| LegacyJsonExplainCandidate {
                    route: c.route.as_ref().map(legacy_route_to_json),
                    vs_best_reason: c.vs_best_reason.clone(),
                    vs_best_detail: c.vs_best_detail.clone(),
                    vs_best_ordering: c.vs_best_ordering.clone(),
                    multipath: c.multipath.clone(),
                    advertised_path_id: peer_scoped.then_some(c.advertised_path_id),
                })
                .collect(),
        }
    }

    fn route_for_json(path_id: u32, validation_state: &str) -> Route {
        Route {
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            next_hop: "198.51.100.1".to_string(),
            as_path: vec![64512, 64496],
            local_pref: 200,
            med: 50,
            origin: 0,
            best: true,
            peer_address: "192.0.2.1".to_string(),
            communities: vec![rustbgpd_wire::COMMUNITY_NO_EXPORT, (64512_u32 << 16) | 100],
            large_communities: vec!["64512:1:100".to_string()],
            path_id,
            validation_state: validation_state.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn explain_advertised_calls_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        explain_advertised(connection, "192.0.2.1", "203.0.113.0/24", false)
            .await
            .unwrap();

        let req = server
            .state
            .last_explain_advertised
            .lock()
            .await
            .clone()
            .expect("explain request captured");
        assert_eq!(req.peer_address, "192.0.2.1");
        assert_eq!(req.prefix, "203.0.113.0");
        assert_eq!(req.prefix_length, 24);
    }

    #[tokio::test]
    async fn explain_best_path_calls_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        explain_best_path(connection, "203.0.113.0/24", None, true)
            .await
            .unwrap();

        let req = server
            .state
            .last_explain_best_path
            .lock()
            .await
            .clone()
            .expect("explain best-path request captured");
        assert_eq!(req.prefix, "203.0.113.0");
        assert_eq!(req.prefix_length, 24);
        assert!(req.peer_address.is_empty());
    }

    #[tokio::test]
    async fn bgpls_sends_filters_and_renders_raw_bytes() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        bgpls(
            connection,
            Some("linkstate"),
            Some("198.51.100.1".to_string()),
            Some(1),
            true,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_list_bgpls
            .lock()
            .await
            .clone()
            .expect("BGP-LS request captured");
        assert_eq!(req.afi_safi, AddressFamily::BgpLs as i32);
        assert_eq!(req.peer_filter, "198.51.100.1");
        assert_eq!(req.nlri_type_filter, 1);
    }

    #[tokio::test]
    async fn vpn_sends_filters_and_accepts_shorthand_family() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        vpn(
            connection,
            Some("vpnv4"),
            Some("198.51.100.1".to_string()),
            true,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_list_vpn
            .lock()
            .await
            .clone()
            .expect("VPN request captured");
        assert_eq!(req.afi_safi, "l3vpn_ipv4_unicast");
        assert_eq!(req.peer_filter, "198.51.100.1");
    }

    #[tokio::test]
    async fn rtc_sends_peer_filter_and_renders_default_and_local_rows() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        rtc(connection, Some("198.51.100.1".to_string()), true)
            .await
            .unwrap();

        let req = server
            .state
            .last_list_rtc
            .lock()
            .await
            .clone()
            .expect("RTC request captured");
        assert_eq!(req.peer_filter, "198.51.100.1");

        // Row rendering: the default row shows `default` and the locally
        // originated entry (peer 0.0.0.0) renders FROM-PEER as `local`.
        let default_row = RtcRouteEntry {
            is_default: true,
            origin_as: 0,
            route_target: String::new(),
            prefix_len: 0,
            next_hop: "0.0.0.0".to_string(),
            peer_address: "0.0.0.0".to_string(),
            as_path: vec![],
            communities: vec![],
            stale: false,
            llgr_stale: false,
            path_id: 0,
        };
        assert_eq!(rtc_from_peer(&default_row), "local");
        let full_row = RtcRouteEntry {
            is_default: false,
            origin_as: 65001,
            route_target: "RT:65001:100".to_string(),
            prefix_len: 96,
            next_hop: "192.0.2.1".to_string(),
            peer_address: "198.51.100.1".to_string(),
            as_path: vec![64512],
            communities: vec![],
            stale: false,
            llgr_stale: false,
            path_id: 0,
        };
        assert_eq!(rtc_from_peer(&full_row), "198.51.100.1");
        print_rtc_routes(&[default_row, full_row], false).unwrap();
    }

    #[test]
    fn vpn_family_parse_rejects_unknown_and_maps_aliases() {
        assert_eq!(parse_vpn_family(None).unwrap(), "");
        assert_eq!(
            parse_vpn_family(Some("vpnv6")).unwrap(),
            "l3vpn_ipv6_unicast"
        );
        assert_eq!(
            parse_vpn_family(Some("l3vpn_ipv4_unicast")).unwrap(),
            "l3vpn_ipv4_unicast"
        );
        assert!(parse_vpn_family(Some("evpn")).is_err());
    }

    #[tokio::test]
    async fn blackholes_calls_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        blackholes(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn fib_calls_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        fib(
            connection,
            FibRouteFilterOpts {
                table: None,
                state: None,
                reason: None,
                prefix: None,
                peer: None,
                page_size: None,
                page_token: None,
            },
            true,
        )
        .await
        .unwrap();
    }

    #[test]
    fn fib_request_filters_are_parsed() {
        let request = make_fib_request(&FibRouteFilterOpts {
            table: Some("edge".to_string()),
            state: Some("rejected".to_string()),
            reason: Some("route_limit_exceeded".to_string()),
            prefix: Some("203.0.113.0/24".to_string()),
            peer: Some("198.51.100.2".to_string()),
            page_size: Some(50),
            page_token: Some("100".to_string()),
        })
        .unwrap();

        assert_eq!(request.table_name, "edge");
        assert_eq!(request.state, FibRouteState::Rejected as i32);
        assert_eq!(request.reason, "route_limit_exceeded");
        assert_eq!(request.prefix, "203.0.113.0");
        assert_eq!(request.prefix_length, 24);
        assert_eq!(request.peer_address, "198.51.100.2");
        assert_eq!(request.page_size, 50);
        assert_eq!(request.page_token, "100");
    }

    #[test]
    fn fib_request_defaults_to_unpaged_snapshot() {
        let request = make_fib_request(&FibRouteFilterOpts {
            table: None,
            state: None,
            reason: None,
            prefix: None,
            peer: None,
            page_size: None,
            page_token: None,
        })
        .unwrap();

        assert_eq!(request.page_size, 0);
        assert!(request.page_token.is_empty());
    }

    #[test]
    fn fib_request_rejects_page_token_without_nonzero_page_size() {
        let err = make_fib_request(&FibRouteFilterOpts {
            table: None,
            state: None,
            reason: None,
            prefix: None,
            peer: None,
            page_size: None,
            page_token: Some("100".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("--page-size"));

        let err = make_fib_request(&FibRouteFilterOpts {
            table: None,
            state: None,
            reason: None,
            prefix: None,
            peer: None,
            page_size: Some(0),
            page_token: Some("100".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("--page-size"));
    }

    #[test]
    fn fib_page_metadata_is_only_enabled_for_nonzero_page_size() {
        let filters = FibRouteFilterOpts {
            table: None,
            state: None,
            reason: None,
            prefix: None,
            peer: None,
            page_size: Some(0),
            page_token: None,
        };
        assert!(!include_fib_page_meta(&filters));

        let filters = FibRouteFilterOpts {
            page_size: Some(50),
            ..filters
        };
        assert!(include_fib_page_meta(&filters));
    }

    #[test]
    fn fib_request_rejects_bad_filters() {
        let err = make_fib_request(&FibRouteFilterOpts {
            table: None,
            state: Some("stuck".to_string()),
            reason: None,
            prefix: None,
            peer: None,
            page_size: None,
            page_token: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported FIB route state"));

        let err = make_fib_request(&FibRouteFilterOpts {
            table: None,
            state: None,
            reason: None,
            prefix: None,
            peer: Some("not-an-ip".to_string()),
            page_size: None,
            page_token: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid --peer address"));
    }

    #[test]
    fn blackhole_json_shape_is_stable() {
        let discard = crate::proto::BlackholeDiscard {
            prefix: "203.0.113.66".to_string(),
            prefix_length: 32,
            peer_address: "192.0.2.1".to_string(),
            state: crate::proto::BlackholeDiscardState::Rejected as i32,
            reason: "not_ebgp".to_string(),
        };

        let value = serde_json::to_value(blackhole_discard_to_json(&discard)).unwrap();
        assert_eq!(value["prefix"], "203.0.113.66/32");
        assert_eq!(value["peer_address"], "192.0.2.1");
        assert_eq!(value["state"], "rejected");
        assert_eq!(value["reason"], "not_ebgp");
    }

    #[test]
    fn fib_json_shape_is_stable() {
        let route = crate::proto::FibRouteStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.1".to_string(),
            peer_address: "198.51.100.1".to_string(),
            state: crate::proto::FibRouteState::Failed as i32,
            reason: "install_failed:EPERM".to_string(),
            ..Default::default()
        };

        let value = serde_json::to_value(fib_route_status_to_json(&route)).unwrap();
        assert_eq!(value["table_name"], "edge");
        assert_eq!(value["table_id"], 1000);
        assert_eq!(value["metric"], 200);
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["next_hop"], "192.0.2.1");
        assert_eq!(value["peer_address"], "198.51.100.1");
        assert_eq!(value["state"], "failed");
        assert_eq!(value["reason"], "install_failed:EPERM");
        assert!(value.get("sampling").is_none());
    }

    #[test]
    fn fib_json_and_display_render_multipath_next_hops() {
        let route = crate::proto::FibRouteStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.1".to_string(),
            next_hops: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
            peer_address: "198.51.100.1".to_string(),
            state: crate::proto::FibRouteState::Installed as i32,
            reason: "owned".to_string(),
            ..Default::default()
        };

        let value = serde_json::to_value(fib_route_status_to_json(&route)).unwrap();
        assert_eq!(value["next_hop"], "192.0.2.1");
        assert_eq!(value["next_hops"][0], "192.0.2.1");
        assert_eq!(value["next_hops"][1], "192.0.2.2");
        assert_eq!(fib_next_hop_display(&route), "192.0.2.1, 192.0.2.2");

        // A single-path row keeps the scalar shape and omits the list from JSON
        // only when the server sent an empty list (older server back-compat).
        let mut single = route.clone();
        single.next_hops = vec!["192.0.2.1".to_string()];
        assert_eq!(fib_next_hop_display(&single), "192.0.2.1");
        let mut legacy = route;
        legacy.next_hops = vec![];
        assert_eq!(fib_next_hop_display(&legacy), "192.0.2.1");
        let legacy_value = serde_json::to_value(fib_route_status_to_json(&legacy)).unwrap();
        assert!(legacy_value.get("next_hops").is_none());
    }

    #[test]
    fn fib_json_includes_sampling_metadata_when_present() {
        let route = crate::proto::FibRouteStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.1".to_string(),
            next_hops: vec!["192.0.2.1".to_string()],
            peer_address: "198.51.100.1".to_string(),
            state: crate::proto::FibRouteState::Rejected as i32,
            reason: "route_limit_exceeded".to_string(),
            sampling_sampled_rows: 128,
            sampling_suppressed_rows: 22,
            sampling_total_rows: 150,
            sampling_max_routes: 1,
            sampling_sample_limit: 128,
            sampling_complete: false,
        };

        let value = serde_json::to_value(fib_route_status_to_json(&route)).unwrap();
        assert_eq!(value["sampling"]["sampled_rows"], 128);
        assert_eq!(value["sampling"]["suppressed_rows"], 22);
        assert_eq!(value["sampling"]["total_rows"], 150);
        assert_eq!(value["sampling"]["complete"], false);
    }

    #[test]
    fn fib_sampling_metadata_deduplicates_with_stable_order() {
        let first = crate::proto::FibRouteStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            reason: "route_limit_exceeded".to_string(),
            sampling_sampled_rows: 128,
            sampling_suppressed_rows: 22,
            sampling_total_rows: 150,
            sampling_max_routes: 1,
            sampling_sample_limit: 128,
            sampling_complete: false,
            ..Default::default()
        };
        let mut duplicate = first.clone();
        duplicate.prefix = "203.0.113.1".to_string();
        let mut second = first.clone();
        second.table_name = "core".to_string();
        second.table_id = 2000;

        let sampling = fib_sampling_metadata(&[first, duplicate, second]);
        assert_eq!(sampling.len(), 2);
        assert_eq!(sampling[0].table_name, "edge");
        assert_eq!(sampling[1].table_name, "core");
    }

    #[test]
    fn route_list_json_matches_legacy_owned_builder() {
        let mut second = route_for_json(42, "valid");
        second.prefix = "2001:db8::".to_string();
        second.prefix_length = 32;
        second.next_hop = "2001:db8::1".to_string();
        second.best = false;
        let routes = vec![route_for_json(0, ""), second];

        let direct = serde_json::to_string_pretty(&JsonRoutes(&routes)).unwrap();
        let legacy: Vec<_> = routes.iter().map(legacy_route_to_json).collect();
        let legacy = serde_json::to_string_pretty(&legacy).unwrap();

        assert_eq!(direct, legacy);
    }

    #[test]
    fn explain_best_path_json_matches_legacy_owned_builder() {
        let mut candidate_route = route_for_json(9, "invalid");
        candidate_route.best = false;
        let resp = ExplainBestPathResponse {
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "192.0.2.99".to_string(),
            add_path_send_max: 4,
            best_route: Some(route_for_json(7, "valid")),
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
            candidates: vec![
                crate::proto::BestPathCandidate {
                    route: Some(candidate_route),
                    vs_best_reason: "higher_local_pref".to_string(),
                    vs_best_detail: "local_pref 100 < 200".to_string(),
                    vs_best_ordering: "worse".to_string(),
                    multipath: "none".to_string(),
                    advertised_path_id: 2,
                },
                crate::proto::BestPathCandidate {
                    route: None,
                    vs_best_reason: "only_path".to_string(),
                    vs_best_detail: String::new(),
                    vs_best_ordering: "equal".to_string(),
                    multipath: "eligible".to_string(),
                    advertised_path_id: 0,
                },
            ],
        };

        let direct = serde_json::to_string_pretty(&explain_best_path_to_json(&resp)).unwrap();
        let legacy =
            serde_json::to_string_pretty(&legacy_explain_best_path_to_json(&resp)).unwrap();

        assert_eq!(direct, legacy);
    }

    #[test]
    fn fib_paginated_json_shape_includes_metadata() {
        let out = JsonFibRoutePage {
            routes: vec![],
            next_page_token: "100".to_string(),
            total_count: 250,
            sampling: vec![],
        };

        let value = serde_json::to_value(out).unwrap();
        assert!(value["routes"].as_array().unwrap().is_empty());
        assert_eq!(value["next_page_token"], "100");
        assert_eq!(value["total_count"], 250);
    }

    #[test]
    fn paginated_empty_fib_page_uses_page_specific_message() {
        let resp = ListFibRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
            total_count: 250,
        };

        assert_eq!(
            empty_fib_routes_message(&resp, true),
            "No general FIB routes on this page"
        );
        assert_eq!(
            empty_fib_routes_message(&resp, false),
            "No general FIB routes"
        );
    }

    /// Pre-existing `best_route` and per-candidate `route` keys
    /// must emit as `null` when absent — that's the v0.7.0 shape.
    /// This test would fail if `skip_serializing_if = "Option::is_none"`
    /// ever leaks back onto those fields.
    #[test]
    fn json_absent_best_route_emits_null_not_omitted() {
        let resp = crate::proto::ExplainBestPathResponse {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            best_route: None,
            candidates: vec![crate::proto::BestPathCandidate {
                route: None,
                vs_best_reason: "higher_local_pref".to_string(),
                vs_best_ordering: "worse".to_string(),
                advertised_path_id: 0,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: "none".to_string(),
            }],
            peer_address: String::new(),
            add_path_send_max: 0,
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
        };
        let out = explain_best_path_to_json(&resp);
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("best_route"),
            "best_route key must always be present (as null when absent)"
        );
        assert!(
            obj.get("best_route").unwrap().is_null(),
            "absent best_route must serialize to JSON null"
        );
        let cand = obj
            .get("candidates")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.first())
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert!(
            cand.contains_key("route"),
            "candidate.route must always be present"
        );
        assert!(
            cand.get("route").unwrap().is_null(),
            "absent candidate.route must serialize to JSON null"
        );
    }

    /// Global-view JSON output omits `peer_address` /
    /// `add_path_send_max` (and per-candidate `advertised_path_id`)
    /// so the v0.7.0 JSON shape contract stays intact for clients
    /// that haven't migrated to the peer-scoped form. Peer-scoped
    /// JSON output emits all three.
    #[test]
    fn json_global_view_omits_addpath_keys() {
        let resp = crate::proto::ExplainBestPathResponse {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            best_route: None,
            candidates: vec![crate::proto::BestPathCandidate {
                route: None,
                vs_best_reason: "higher_local_pref".to_string(),
                vs_best_ordering: "worse".to_string(),
                advertised_path_id: 0,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: "none".to_string(),
            }],
            peer_address: String::new(),
            add_path_send_max: 0,
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
        };
        let out = explain_best_path_to_json(&resp);
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("peer_address"),
            "global view must not expose peer_address"
        );
        assert!(
            !obj.contains_key("add_path_send_max"),
            "global view must not expose add_path_send_max"
        );
        let cand = obj
            .get("candidates")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.first())
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert!(
            !cand.contains_key("advertised_path_id"),
            "global view must not expose advertised_path_id on candidates"
        );
    }

    #[test]
    fn json_peer_scoped_emits_addpath_keys() {
        let resp = crate::proto::ExplainBestPathResponse {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            best_route: None,
            candidates: vec![crate::proto::BestPathCandidate {
                route: None,
                vs_best_reason: "higher_local_pref".to_string(),
                vs_best_ordering: "worse".to_string(),
                advertised_path_id: 2,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: "none".to_string(),
            }],
            peer_address: "10.0.0.99".to_string(),
            add_path_send_max: 4,
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
        };
        let out = explain_best_path_to_json(&resp);
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        assert_eq!(v["peer_address"], "10.0.0.99");
        assert_eq!(v["add_path_send_max"], 4);
        assert_eq!(v["candidates"][0]["advertised_path_id"], 2);
    }

    /// The tiebreaker-attribution keys (`best_reason`,
    /// `best_reason_detail`, per-candidate `vs_best_detail` and
    /// `multipath`) are emitted unconditionally — global view and
    /// peer-scoped alike — so the JSON key set stays run-stable.
    #[test]
    fn json_emits_tiebreaker_attribution_keys() {
        let resp = crate::proto::ExplainBestPathResponse {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            best_route: None,
            candidates: vec![crate::proto::BestPathCandidate {
                route: None,
                vs_best_reason: "higher_local_pref".to_string(),
                vs_best_ordering: "worse".to_string(),
                advertised_path_id: 0,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: "relax_only".to_string(),
            }],
            peer_address: String::new(),
            add_path_send_max: 0,
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
        };
        let out = explain_best_path_to_json(&resp);
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        assert_eq!(v["best_reason"], "higher_local_pref");
        assert_eq!(v["best_reason_detail"], "local_pref 200 > 100");
        assert_eq!(v["candidates"][0]["vs_best_detail"], "local_pref 100 < 200");
        assert_eq!(v["candidates"][0]["multipath"], "relax_only");
    }
}
