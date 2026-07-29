use crate::commands::neighbor::{bare_ip_rpc_address, restore_matching_scoped_address};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonExplainAdvertisedRoute, JsonExplainModifications, JsonExplainReason,
    JsonOrrExplainCandidate, JsonRouteSourceIdentity,
};
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddPathRequest, AddressFamily, BgpLsRouteEntry, BlackholeDiscardState, DeletePathRequest,
    ExplainAdvertisedRouteRequest, ExplainBestPathRequest, ExplainBestPathResponse,
    ExplainDecision, ExportGateVerdict, FibRouteState, LabeledRouteEntry, ListBgpLsRequest,
    ListBlackholeDiscardsRequest, ListFibRoutesRequest, ListFibRoutesResponse,
    ListLabeledRoutesRequest, ListRejectedRoutesRequest, ListRejectedRoutesResponse,
    ListRoutesRequest, ListRtcRoutesRequest, ListVpnRoutesRequest, Route, RtcRouteEntry,
    VpnRouteEntry,
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
        neighbor_address: neighbor
            .map(bare_ip_rpc_address)
            .unwrap_or_default()
            .to_string(),
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

type RibClient = RibServiceClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        crate::connection::AuthInterceptor,
    >,
>;

/// Which unicast route-listing RPC [`fetch_all_route_pages`] drives.
enum RouteListRpc {
    Best,
    Received,
    Advertised,
}

/// Requested page size for transparent pagination — matches the
/// server's per-page cap so the loop takes the fewest round trips.
const ROUTE_PAGE_SIZE: u32 = 1000;

/// Fetch every page of a route listing. The server bounds each page;
/// the CLI follows `next_page_token` until the listing completes, so
/// output is never silently truncated.
async fn fetch_all_route_pages(
    client: &mut RibClient,
    rpc: &RouteListRpc,
    mut req: ListRoutesRequest,
) -> Result<Vec<Route>, CliError> {
    req.page_size = ROUTE_PAGE_SIZE;
    let mut routes = Vec::new();
    loop {
        let resp = match rpc {
            RouteListRpc::Best => client.list_best_routes(req.clone()).await?,
            RouteListRpc::Received => client.list_received_routes(req.clone()).await?,
            RouteListRpc::Advertised => client.list_advertised_routes(req.clone()).await?,
        }
        .into_inner();
        routes.extend(resp.routes);
        if resp.next_page_token.is_empty() {
            return Ok(routes);
        }
        req.page_token = resp.next_page_token;
    }
}

/// Fetch only the backend's exact matching-row count for one route
/// view. A one-row page keeps the response bounded; the continuation
/// token and row itself are deliberately ignored because `total_count`
/// describes the complete filtered query.
async fn fetch_route_count(
    client: &mut RibClient,
    rpc: &RouteListRpc,
    mut req: ListRoutesRequest,
) -> Result<u64, CliError> {
    req.page_size = 1;
    req.page_token.clear();
    let resp = match rpc {
        RouteListRpc::Best => client.list_best_routes(req).await?,
        RouteListRpc::Received => client.list_received_routes(req).await?,
        RouteListRpc::Advertised => client.list_advertised_routes(req).await?,
    }
    .into_inner();
    Ok(resp.total_count)
}

fn route_count_message(total_count: u64) -> String {
    format!("Total matching routes: {total_count}")
}

fn route_count_json(total_count: u64) -> serde_json::Value {
    serde_json::json!({ "total_count": total_count })
}

fn print_route_count(total_count: u64, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&route_count_json(total_count))
    } else {
        println!("{}", route_count_message(total_count));
        Ok(())
    }
}

async fn count_routes(
    connection: Connection,
    rpc: RouteListRpc,
    neighbor: Option<&str>,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let total_count = fetch_route_count(
        &mut client,
        &rpc,
        make_route_request(neighbor, family, filters)?,
    )
    .await?;
    print_route_count(total_count, json)
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
        let addr: std::net::IpAddr = bare_ip_rpc_address(peer)
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
        peer_filter: peer
            .as_deref()
            .map(bare_ip_rpc_address)
            .unwrap_or_default()
            .to_string(),
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
        peer_filter: peer
            .as_deref()
            .map(bare_ip_rpc_address)
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_labeled_family(family: Option<&str>) -> Result<String, CliError> {
    match family {
        None => Ok(String::new()),
        Some("ipv4_labeled_unicast" | "labeled-v4" | "labeled_v4" | "labeled-ipv4") => {
            Ok("ipv4_labeled_unicast".to_string())
        }
        Some("ipv6_labeled_unicast" | "labeled-v6" | "labeled_v6" | "labeled-ipv6") => {
            Ok("ipv6_labeled_unicast".to_string())
        }
        Some(other) => Err(CliError::Argument(format!(
            "unsupported labeled family {other:?}; expected ipv4_labeled_unicast \
             (alias: labeled-v4) or ipv6_labeled_unicast (alias: labeled-v6)"
        ))),
    }
}

fn make_labeled_request(
    family: Option<&str>,
    peer: Option<String>,
) -> Result<ListLabeledRoutesRequest, CliError> {
    Ok(ListLabeledRoutesRequest {
        afi_safi: parse_labeled_family(family)?,
        peer_filter: peer
            .as_deref()
            .map(bare_ip_rpc_address)
            .unwrap_or_default()
            .to_string(),
    })
}

fn print_routes(
    routes: &[crate::proto::Route],
    show_age: bool,
    json: bool,
) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No routes");
    } else {
        output::print_route_table(routes, show_age);
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

fn print_labeled_routes(routes: &[LabeledRouteEntry], json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_pretty(&JsonLabeledRoutes(routes))?;
    } else if routes.is_empty() {
        println!("No labeled routes");
    } else {
        println!(
            "{:<24} {:<14} {:<18} {:<18} Path ID",
            "Prefix", "Labels", "Next Hop", "Peer"
        );
        println!("{}", "-".repeat(88));
        for route in routes {
            let labels = route
                .labels
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{:<24} {:<14} {:<18} {:<18} {}",
                route.prefix, labels, route.next_hop, route.peer_address, route.path_id
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

struct JsonLabeledRoutes<'a>(&'a [LabeledRouteEntry]);

impl Serialize for JsonLabeledRoutes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonLabeledRouteRef(route))?;
        }
        seq.end()
    }
}

struct JsonLabeledRouteRef<'a>(&'a LabeledRouteEntry);

impl Serialize for JsonLabeledRouteRef<'_> {
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
        map.serialize_entry("afi_safi", &route.afi_safi)?;
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
        let med_attr_supported = self.0.iter().any(|r| r.med_attr.is_some());
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for route in self.0 {
            seq.serialize_element(&JsonRouteRef {
                route,
                med_attr_supported,
            })?;
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

struct JsonRouteRef<'a> {
    route: &'a Route,
    /// Whether any route in the enclosing response carried `med_attr`
    /// — i.e. the daemon distinguishes MED-absent from MED 0. When
    /// true, an absent MED serializes as `null`; when false (older
    /// daemon), the bare 0-defaulted `med` field is emitted as-is.
    med_attr_supported: bool,
}

impl Serialize for JsonRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.route;
        let mut len = 12;
        if route.path_id != 0 {
            len += 1;
        }
        if !route.validation_state.is_empty() {
            len += 1;
        }
        if !route.aspa_state.is_empty() {
            len += 1;
        }
        if route.stale {
            len += 1;
        }
        if route.llgr_stale {
            len += 1;
        }
        if route.local_pref_attr.is_some() {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("prefix", &JsonRoutePrefix(route))?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("local_pref", &route.local_pref)?;
        if let Some(local_pref) = route.local_pref_attr {
            map.serialize_entry("local_pref_attr", &local_pref)?;
        }
        match route.med_attr {
            Some(med) => map.serialize_entry("med", &med)?,
            None if self.med_attr_supported => map.serialize_entry("med", &None::<u32>)?,
            None => map.serialize_entry("med", &route.med)?,
        }
        map.serialize_entry("origin", output::format_origin(route.origin))?;
        map.serialize_entry("best", &route.best)?;
        map.serialize_entry("peer_address", &route.peer_address)?;
        map.serialize_entry("communities", &JsonCommunities(&route.communities))?;
        map.serialize_entry("extended_communities", &route.extended_communities)?;
        map.serialize_entry("large_communities", &route.large_communities)?;
        if route.path_id != 0 {
            map.serialize_entry("path_id", &route.path_id)?;
        }
        if !route.validation_state.is_empty() {
            map.serialize_entry("validation_state", &route.validation_state)?;
        }
        if !route.aspa_state.is_empty() {
            map.serialize_entry("aspa_state", &route.aspa_state)?;
        }
        map.serialize_entry(
            "received_at_epoch_seconds",
            &route.received_at_epoch_seconds,
        )?;
        if route.stale {
            map.serialize_entry("stale", &route.stale)?;
        }
        if route.llgr_stale {
            map.serialize_entry("llgr_stale", &route.llgr_stale)?;
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
        orr_vantage: explain.orr_vantage.clone(),
        orr_candidates: explain
            .orr_candidates
            .iter()
            .map(|candidate| JsonOrrExplainCandidate {
                peer_address: candidate.peer_address.clone(),
                next_hop: candidate.next_hop.clone(),
                cost: candidate.cost,
                selected: candidate.selected,
            })
            .collect(),
        gates: explain
            .gates
            .iter()
            .map(|step| output::JsonExportGateStep {
                gate: step.gate.clone(),
                code: step.code.clone(),
                verdict: gate_verdict_label(step.verdict).to_string(),
                detail: step.detail.clone(),
            })
            .collect(),
        update_group_id: explain.update_group_id,
        already_advertised: explain.already_advertised,
        rd: explain.rd.clone(),
        source: explain
            .source
            .as_ref()
            .map(|source| JsonRouteSourceIdentity {
                peer_address: source.peer_address.clone(),
                path_id: source.path_id,
            }),
    }
}

/// Render an export gate verdict for text/JSON output.
///
/// This maps the *proto* `ExportGateVerdict` (which has an extra
/// `Unspecified` variant crossing the client/server boundary), so it can't
/// reuse `rustbgpd_rib::ExportGateVerdict::label()` directly. These labels
/// must stay in sync with that server-side `label()`.
fn gate_verdict_label(verdict: i32) -> &'static str {
    match ExportGateVerdict::try_from(verdict).unwrap_or(ExportGateVerdict::Unspecified) {
        ExportGateVerdict::Pass => "pass",
        ExportGateVerdict::Stop => "stop",
        ExportGateVerdict::NotApplicable => "not_applicable",
        ExportGateVerdict::Unspecified => "unspecified",
    }
}

/// Render an ORR vantage cost for text output (`12` / `unreachable`).
fn orr_cost_label(cost: Option<u64>) -> String {
    cost.map_or_else(|| "unreachable".to_string(), |c| c.to_string())
}

fn advertised_path_id_line(
    explain: &crate::proto::ExplainAdvertisedRouteResponse,
) -> Option<String> {
    if explain.source.is_some() {
        Some(format!("Outbound path ID: {}", explain.path_id))
    } else {
        (explain.path_id != 0).then(|| format!("Path ID: {}", explain.path_id))
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
    if !explain.rd.is_empty() {
        println!("RD:         {}", explain.rd);
    }
    if let Some(source) = &explain.source {
        println!(
            "Source path: {} inbound path ID {}",
            source.peer_address, source.path_id
        );
    }
    if let Some(group_id) = explain.update_group_id {
        println!("Update group: {group_id} (shared staging; split horizon applied per member)");
    }
    if !explain.route_peer_address.is_empty() {
        println!("Route peer: {}", explain.route_peer_address);
    }
    if !explain.route_type.is_empty() {
        println!("Route type: {}", explain.route_type);
    }
    if !explain.next_hop.is_empty() {
        println!("Next hop:   {}", explain.next_hop);
    }
    if let Some(line) = advertised_path_id_line(explain) {
        println!("{line}");
    }
    if !explain.orr_vantage.is_empty() {
        println!("ORR vantage: {}", explain.orr_vantage);
    }
    if !explain.orr_candidates.is_empty() {
        println!("ORR candidates (per-vantage best first):");
        for candidate in &explain.orr_candidates {
            println!(
                "- {} next-hop {} cost={}{}",
                candidate.peer_address,
                candidate.next_hop,
                orr_cost_label(candidate.cost),
                if candidate.selected {
                    " (selected)"
                } else {
                    ""
                }
            );
        }
    }
    if !explain.gates.is_empty() {
        println!("Gate ladder (live evaluation order):");
        for step in &explain.gates {
            let mark = match ExportGateVerdict::try_from(step.verdict)
                .unwrap_or(ExportGateVerdict::Unspecified)
            {
                ExportGateVerdict::Pass => "pass",
                ExportGateVerdict::Stop => "STOP",
                ExportGateVerdict::NotApplicable | ExportGateVerdict::Unspecified => "n/a ",
            };
            println!("  [{mark}] {:<14} {}", step.gate, step.detail);
        }
    }
    if explain.already_advertised {
        println!(
            "Adj-RIB-Out in sync: identical route already advertised - nothing would be \
             re-sent; remote acceptance is not observable"
        );
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
        let med_attr_supported = resp
            .best_route
            .iter()
            .chain(resp.candidates.iter().filter_map(|c| c.route.as_ref()))
            .any(|r| r.med_attr.is_some());
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
            &JsonOptionalRouteRef {
                route: resp.best_route.as_ref(),
                med_attr_supported,
            },
        )?;
        map.serialize_entry("best_reason", &resp.best_reason)?;
        map.serialize_entry("best_reason_detail", &resp.best_reason_detail)?;
        map.serialize_entry(
            "candidates",
            &JsonExplainCandidatesRef {
                candidates: &resp.candidates,
                peer_scoped,
                med_attr_supported,
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

struct JsonOptionalRouteRef<'a> {
    route: Option<&'a Route>,
    med_attr_supported: bool,
}

impl Serialize for JsonOptionalRouteRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.route {
            Some(route) => JsonRouteRef {
                route,
                med_attr_supported: self.med_attr_supported,
            }
            .serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

struct JsonExplainCandidatesRef<'a> {
    candidates: &'a [crate::proto::BestPathCandidate],
    peer_scoped: bool,
    med_attr_supported: bool,
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
                med_attr_supported: self.med_attr_supported,
            })?;
        }
        seq.end()
    }
}

struct JsonExplainCandidateRef<'a> {
    candidate: &'a crate::proto::BestPathCandidate,
    peer_scoped: bool,
    med_attr_supported: bool,
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
        map.serialize_entry(
            "route",
            &JsonOptionalRouteRef {
                route: candidate.route.as_ref(),
                med_attr_supported: self.med_attr_supported,
            },
        )?;
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
    let mut resp = client
        .explain_best_path(ExplainBestPathRequest {
            prefix: addr,
            prefix_length: len,
            peer_address: peer
                .map(bare_ip_rpc_address)
                .unwrap_or_default()
                .to_string(),
        })
        .await?
        .into_inner();
    restore_matching_scoped_address(peer, &mut resp.peer_address);
    print_explain_best_path(&resp, json)
}

pub async fn best(
    connection: Connection,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    show_age: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let routes = fetch_all_route_pages(
        &mut client,
        &RouteListRpc::Best,
        make_route_request(None, family, filters)?,
    )
    .await?;
    print_routes(&routes, show_age, json)
}

pub async fn count_best(
    connection: Connection,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    count_routes(connection, RouteListRpc::Best, None, family, filters, json).await
}

pub async fn blackholes(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client = connection.rib_listing_client();
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
    let mut client = connection.rib_listing_client();
    let mut resp = client
        .list_fib_routes(make_fib_request(&filters)?)
        .await?
        .into_inner();
    for route in &mut resp.routes {
        restore_matching_scoped_address(filters.peer.as_deref(), &mut route.peer_address);
    }
    print_fib_routes(&resp, json, include_fib_page_meta(&filters))
}

pub async fn bgpls(
    connection: Connection,
    family: Option<&str>,
    peer: Option<String>,
    nlri_type: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let requested_peer = peer.clone();
    let mut client = connection.rib_listing_client();
    let mut resp = client
        .list_bgp_ls_routes(make_bgpls_request(family, peer, nlri_type)?)
        .await?
        .into_inner();
    for route in &mut resp.routes {
        restore_matching_scoped_address(requested_peer.as_deref(), &mut route.peer_address);
    }
    print_bgpls_routes(&resp.routes, json)
}

pub async fn vpn(
    connection: Connection,
    family: Option<&str>,
    peer: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let requested_peer = peer.clone();
    let mut client = connection.rib_listing_client();
    let mut resp = client
        .list_vpn_routes(make_vpn_request(family, peer)?)
        .await?
        .into_inner();
    for route in &mut resp.routes {
        restore_matching_scoped_address(requested_peer.as_deref(), &mut route.peer_address);
    }
    print_vpn_routes(&resp.routes, json)
}

pub async fn labeled(
    connection: Connection,
    family: Option<&str>,
    peer: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let requested_peer = peer.clone();
    let mut client = connection.rib_listing_client();
    let mut resp = client
        .list_labeled_routes(make_labeled_request(family, peer)?)
        .await?
        .into_inner();
    for route in &mut resp.routes {
        restore_matching_scoped_address(requested_peer.as_deref(), &mut route.peer_address);
    }
    print_labeled_routes(&resp.routes, json)
}

pub async fn rtc(connection: Connection, peer: Option<String>, json: bool) -> Result<(), CliError> {
    let mut client = connection.rib_listing_client();
    let mut resp = client
        .list_rtc_routes(ListRtcRoutesRequest {
            peer_filter: peer
                .as_deref()
                .map(bare_ip_rpc_address)
                .unwrap_or_default()
                .to_string(),
        })
        .await?
        .into_inner();
    for route in &mut resp.routes {
        restore_matching_scoped_address(peer.as_deref(), &mut route.peer_address);
    }
    print_rtc_routes(&resp.routes, json)
}

pub async fn received(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    show_age: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut routes = fetch_all_route_pages(
        &mut client,
        &RouteListRpc::Received,
        make_route_request(Some(address), family, filters)?,
    )
    .await?;
    for route in &mut routes {
        restore_matching_scoped_address(Some(address), &mut route.peer_address);
    }
    print_routes(&routes, show_age, json)
}

pub async fn count_received(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    count_routes(
        connection,
        RouteListRpc::Received,
        Some(address),
        family,
        filters,
        json,
    )
    .await
}

/// LAN-472: list the retained rejected routes for a peer with their
/// reject reasons — `rbgp rib received <peer> --rejected`. Served by
/// `PolicyService.ListRejectedRoutes` (the retention store lives on the
/// peer's session, not in the RIB).
pub async fn rejected(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut resp = client
        .list_rejected_routes(ListRejectedRoutesRequest {
            peer_address: bare_ip_rpc_address(address).to_string(),
        })
        .await?
        .into_inner();
    restore_matching_scoped_address(Some(address), &mut resp.peer_address);
    print_rejected_routes(&resp, json)
}

#[derive(Serialize)]
struct JsonRejectedRoute<'a> {
    prefix: String,
    path_id: u32,
    reason: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    reason_detail: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    next_hop: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    as_path: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    communities: &'a [u32],
    // Retention truncates community lists under a per-entry byte
    // budget; a non-zero count means "…and N more" were dropped.
    #[serde(skip_serializing_if = "dropped_count_is_zero")]
    communities_dropped: u32,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    large_communities: &'a [String],
    #[serde(skip_serializing_if = "dropped_count_is_zero")]
    large_communities_dropped: u32,
    #[serde(skip_serializing_if = "str::is_empty")]
    rpki_validation: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    aspa_validation: &'a str,
    rejected_at_unix_ns: i64,
}

// serde's skip_serializing_if requires a fn(&T) -> bool.
fn dropped_count_is_zero(count: &u32) -> bool {
    *count == 0
}

#[derive(Serialize)]
struct JsonRejectedRoutes<'a> {
    peer_address: &'a str,
    retention_enabled: bool,
    capacity: u32,
    rejected_routes: Vec<JsonRejectedRoute<'a>>,
}

fn print_rejected_routes(resp: &ListRejectedRoutesResponse, json: bool) -> Result<(), CliError> {
    if json {
        let rejected_routes = resp
            .routes
            .iter()
            .map(|r| JsonRejectedRoute {
                prefix: format!("{}/{}", r.prefix, r.prefix_length),
                path_id: r.path_id,
                reason: &r.reason,
                reason_detail: &r.reason_detail,
                next_hop: &r.next_hop,
                as_path: &r.as_path,
                communities: &r.communities,
                communities_dropped: r.communities_dropped,
                large_communities: &r.large_communities,
                large_communities_dropped: r.large_communities_dropped,
                rpki_validation: &r.rpki_validation,
                aspa_validation: &r.aspa_validation,
                rejected_at_unix_ns: r.rejected_at_unix_ns,
            })
            .collect();
        return output::print_json_pretty(&JsonRejectedRoutes {
            peer_address: &resp.peer_address,
            retention_enabled: resp.retention_enabled,
            capacity: resp.capacity,
            rejected_routes,
        });
    }
    if !resp.retention_enabled {
        println!(
            "Rejected-route retention is disabled for {} ([policy.reject_retention] enabled = false)",
            resp.peer_address
        );
        return Ok(());
    }
    if resp.routes.is_empty() {
        println!("No rejected routes retained for {}", resp.peer_address);
        return Ok(());
    }
    println!(
        "{:<22} {:<8} {:<18} {:<28} {:<18} {:<10} AS Path",
        "Prefix", "PathId", "Reason", "Detail", "Next Hop", "RPKI"
    );
    println!("{}", "-".repeat(120));
    for r in &resp.routes {
        println!(
            "{:<22} {:<8} {:<18} {:<28} {:<18} {:<10} {}",
            format!("{}/{}", r.prefix, r.prefix_length),
            r.path_id,
            r.reason,
            if r.reason_detail.is_empty() {
                "-"
            } else {
                &r.reason_detail
            },
            if r.next_hop.is_empty() {
                "-"
            } else {
                &r.next_hop
            },
            if r.rpki_validation.is_empty() {
                "-"
            } else {
                &r.rpki_validation
            },
            r.as_path,
        );
    }
    let shown = resp.routes.len();
    if u32::try_from(shown).unwrap_or(u32::MAX) >= resp.capacity {
        println!(
            "(store at capacity {} — showing the most recent rejections; \
             raise [policy.reject_retention] capacity for full coverage)",
            resp.capacity
        );
    }
    Ok(())
}

pub async fn advertised(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    show_age: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut routes = fetch_all_route_pages(
        &mut client,
        &RouteListRpc::Advertised,
        make_route_request(Some(address), family, filters)?,
    )
    .await?;
    for route in &mut routes {
        restore_matching_scoped_address(Some(address), &mut route.peer_address);
    }
    print_routes(&routes, show_age, json)
}

pub async fn count_advertised(
    connection: Connection,
    address: &str,
    family: Option<i32>,
    filters: &RouteFilterOpts,
    json: bool,
) -> Result<(), CliError> {
    count_routes(
        connection,
        RouteListRpc::Advertised,
        Some(address),
        family,
        filters,
        json,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI export explain maps the peer, family identity, optional source identity, and output mode"
)]
pub async fn explain_advertised(
    connection: Connection,
    address: &str,
    prefix: &str,
    rd: Option<&str>,
    labeled: bool,
    source_peer: Option<&str>,
    source_path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let requested_source = source_peer.filter(|_| source_path_id.is_some());
    let mut resp = client
        .explain_advertised_route(ExplainAdvertisedRouteRequest {
            peer_address: bare_ip_rpc_address(address).to_string(),
            prefix: addr,
            prefix_length: len,
            rd: rd.unwrap_or_default().to_string(),
            labeled,
            source: source_peer.zip(source_path_id).map(|(peer, path_id)| {
                crate::proto::RouteSourceIdentity {
                    peer_address: bare_ip_rpc_address(peer).to_string(),
                    path_id,
                }
            }),
        })
        .await?
        .into_inner();
    restore_matching_scoped_address(Some(address), &mut resp.peer_address);
    restore_matching_scoped_address(requested_source, &mut resp.route_peer_address);
    if let Some(source) = &mut resp.source {
        restore_matching_scoped_address(requested_source, &mut source.peer_address);
    }
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
            extended_communities: r.extended_communities.clone(),
            large_communities: r.large_communities.clone(),
            path_id: r.path_id,
            validation_state: r.validation_state.clone(),
            aspa_state: r.aspa_state.clone(),
            received_at_epoch_seconds: r.received_at_epoch_seconds,
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
            extended_communities: vec![0x0002_fc00_0000_0064, 0x4004_c000_0201_0032],
            large_communities: vec!["64512:1:100".to_string()],
            path_id,
            validation_state: validation_state.to_string(),
            aspa_state: "valid".to_string(),
            received_at_epoch_seconds: 1_750_000_000,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn explain_advertised_calls_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        explain_advertised(
            connection,
            "fe80::1%eth0",
            "203.0.113.0/24",
            None,
            false,
            Some("fe80::2%eth1"),
            Some(0),
            false,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_explain_advertised
            .lock()
            .await
            .clone()
            .expect("explain request captured");
        assert_eq!(req.peer_address, "fe80::1");
        assert_eq!(req.prefix, "203.0.113.0");
        assert_eq!(req.prefix_length, 24);
        assert_eq!(req.rd, "");
        assert_eq!(req.source.as_ref().map(|source| source.path_id), Some(0));
        assert_eq!(
            req.source
                .as_ref()
                .map(|source| source.peer_address.as_str()),
            Some("fe80::2")
        );
        // Load-bearing proof: treating zero as absence makes these assertions red.
    }

    #[tokio::test]
    async fn explain_advertised_vpn_passes_rd() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        explain_advertised(
            connection,
            "192.0.2.1",
            "10.0.7.0/24",
            Some("65000:1"),
            false,
            None,
            None,
            false,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_explain_advertised
            .lock()
            .await
            .clone()
            .expect("explain request captured");
        assert_eq!(req.rd, "65000:1");
        assert_eq!(req.prefix, "10.0.7.0");
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
    async fn explain_best_path_scoped_peer_sends_bare_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        explain_best_path(
            connection,
            "203.0.113.0/24",
            Some("fe80:0:0:0:0:0:0:1%eth0"),
            true,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_explain_best_path
            .lock()
            .await
            .clone()
            .expect("explain best-path request captured");
        assert_eq!(req.peer_address, "fe80:0:0:0:0:0:0:1");
    }

    #[tokio::test]
    async fn bgpls_sends_filters_and_renders_raw_bytes() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        bgpls(
            connection,
            Some("linkstate"),
            Some("fe80::1%eth0".to_string()),
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
        assert_eq!(req.peer_filter, "fe80::1");
        assert_eq!(req.nlri_type_filter, 1);
    }

    #[tokio::test]
    async fn labeled_sends_filters_and_accepts_shorthand_family() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        labeled(
            connection,
            Some("labeled-v4"),
            Some("fe80::1%eth0".to_string()),
            true,
        )
        .await
        .unwrap();

        let req = server
            .state
            .last_list_labeled
            .lock()
            .await
            .clone()
            .expect("labeled request captured");
        assert_eq!(req.afi_safi, "ipv4_labeled_unicast");
        assert_eq!(req.peer_filter, "fe80::1");
    }

    #[test]
    fn labeled_family_parse_rejects_unknown_and_maps_aliases() {
        assert_eq!(parse_labeled_family(None).unwrap(), "");
        assert_eq!(
            parse_labeled_family(Some("labeled-v6")).unwrap(),
            "ipv6_labeled_unicast"
        );
        assert_eq!(
            parse_labeled_family(Some("ipv4_labeled_unicast")).unwrap(),
            "ipv4_labeled_unicast"
        );
        assert!(parse_labeled_family(Some("vpnv4")).is_err());
    }

    #[tokio::test]
    async fn vpn_sends_filters_and_accepts_shorthand_family() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        vpn(
            connection,
            Some("vpnv4"),
            Some("fe80::1%eth0".to_string()),
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
        assert_eq!(req.peer_filter, "fe80::1");
    }

    #[tokio::test]
    async fn rtc_sends_peer_filter_and_renders_default_and_local_rows() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        rtc(connection, Some("fe80::1%eth0".to_string()), true)
            .await
            .unwrap();

        let req = server
            .state
            .last_list_rtc
            .lock()
            .await
            .clone()
            .expect("RTC request captured");
        assert_eq!(req.peer_filter, "fe80::1");

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
                peer: Some("fe80::2%eth0".to_string()),
                page_size: None,
                page_token: None,
            },
            true,
        )
        .await
        .unwrap();

        let request = server
            .state
            .last_list_fib
            .lock()
            .await
            .clone()
            .expect("FIB request captured");
        assert_eq!(request.peer_address, "fe80::2");
    }

    #[test]
    fn fib_request_filters_are_parsed() {
        let request = make_fib_request(&FibRouteFilterOpts {
            table: Some("edge".to_string()),
            state: Some("rejected".to_string()),
            reason: Some("route_limit_exceeded".to_string()),
            prefix: Some("203.0.113.0/24".to_string()),
            peer: Some("fe80::2%eth0".to_string()),
            page_size: Some(50),
            page_token: Some("100".to_string()),
        })
        .unwrap();

        assert_eq!(request.table_name, "edge");
        assert_eq!(request.state, FibRouteState::Rejected as i32);
        assert_eq!(request.reason, "route_limit_exceeded");
        assert_eq!(request.prefix, "203.0.113.0");
        assert_eq!(request.prefix_length, 24);
        assert_eq!(request.peer_address, "fe80::2");
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
    fn explain_advertised_json_maps_orr_fields() {
        let resp = crate::proto::ExplainAdvertisedRouteResponse {
            decision: ExplainDecision::Advertise as i32,
            peer_address: "10.0.0.3".to_string(),
            prefix: "198.51.100.0".to_string(),
            prefix_length: 24,
            next_hop: "10.0.2.1".to_string(),
            source: Some(crate::proto::RouteSourceIdentity {
                peer_address: "192.0.2.9".to_string(),
                path_id: 0,
            }),
            orr_vantage: "10.0.1.1".to_string(),
            orr_candidates: vec![
                crate::proto::OrrExplainCandidate {
                    peer_address: "192.0.2.2".to_string(),
                    path_id: 0,
                    next_hop: "10.0.2.1".to_string(),
                    cost: Some(1),
                    selected: true,
                },
                crate::proto::OrrExplainCandidate {
                    peer_address: "192.0.2.1".to_string(),
                    path_id: 0,
                    next_hop: "203.0.113.99".to_string(),
                    cost: None,
                    selected: false,
                },
            ],
            ..Default::default()
        };

        let value = serde_json::to_value(explain_to_json(&resp)).unwrap();
        assert_eq!(value["orr_vantage"], "10.0.1.1");
        assert_eq!(value["orr_candidates"][0]["peer_address"], "192.0.2.2");
        assert_eq!(value["orr_candidates"][0]["cost"], 1);
        assert_eq!(value["orr_candidates"][0]["selected"], true);
        assert!(
            value["orr_candidates"][1]["cost"].is_null(),
            "unreachable cost serializes as null"
        );
        assert_eq!(value["orr_candidates"][1]["selected"], false);
        assert_eq!(value["source"]["path_id"], 0);
        assert_eq!(
            advertised_path_id_line(&resp).as_deref(),
            Some("Outbound path ID: 0")
        );
    }

    #[test]
    fn explain_advertised_json_omits_orr_fields_when_not_orr() {
        // Non-ORR responses keep the pre-ORR JSON shape byte-for-byte.
        let resp = crate::proto::ExplainAdvertisedRouteResponse::default();
        let value = serde_json::to_value(explain_to_json(&resp)).unwrap();
        assert!(value.get("orr_vantage").is_none());
        assert!(value.get("orr_candidates").is_none());
        // The gate-ladder fields are likewise absent when unset, so the
        // pre-ladder JSON shape is unchanged.
        assert!(value.get("gates").is_none());
        assert!(value.get("update_group_id").is_none());
        assert!(value.get("already_advertised").is_none());
        assert!(value.get("rd").is_none());
        assert!(value.get("source").is_none());
        assert_eq!(advertised_path_id_line(&resp), None);
    }

    #[test]
    fn explain_advertised_json_maps_gate_ladder_fields() {
        let resp = crate::proto::ExplainAdvertisedRouteResponse {
            decision: ExplainDecision::Deny as i32,
            peer_address: "10.0.0.3".to_string(),
            prefix: "198.51.100.0".to_string(),
            prefix_length: 24,
            rd: "65000:1".to_string(),
            update_group_id: Some(2),
            already_advertised: true,
            gates: vec![
                crate::proto::ExportGateStep {
                    gate: "family".to_string(),
                    code: "family".to_string(),
                    verdict: crate::proto::ExportGateVerdict::Pass as i32,
                    detail: "peer negotiated ipv4 mpls_vpn".to_string(),
                },
                crate::proto::ExportGateStep {
                    gate: "rt_membership".to_string(),
                    code: "rt_membership_miss".to_string(),
                    verdict: crate::proto::ExportGateVerdict::Stop as i32,
                    detail: "no Route Target of this route falls inside the peer's \
                             advertised RT-Constrain membership (RFC 4684)"
                        .to_string(),
                },
                crate::proto::ExportGateStep {
                    gate: "orf".to_string(),
                    code: "orf".to_string(),
                    verdict: crate::proto::ExportGateVerdict::NotApplicable as i32,
                    detail: "peer installed no Outbound Route Filter".to_string(),
                },
            ],
            ..Default::default()
        };

        let value = serde_json::to_value(explain_to_json(&resp)).unwrap();
        assert_eq!(value["rd"], "65000:1");
        assert_eq!(value["update_group_id"], 2);
        assert_eq!(value["already_advertised"], true);
        assert_eq!(value["gates"][0]["gate"], "family");
        assert_eq!(value["gates"][0]["verdict"], "pass");
        assert_eq!(value["gates"][1]["code"], "rt_membership_miss");
        assert_eq!(value["gates"][1]["verdict"], "stop");
        assert_eq!(value["gates"][2]["verdict"], "not_applicable");
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

    /// Load-bearing native-route fact proof: dropping the raw extended
    /// communities or receive epoch, reordering the extended communities,
    /// omitting the genuine ASPA `unknown` state, or emitting the empty
    /// compatibility sentinel makes an exact assertion red.
    #[test]
    fn route_list_json_exposes_native_route_facts_without_collapsing_unknowns() {
        let mut absent = route_for_json(0, "");
        absent.extended_communities = vec![9, 3, 7];
        absent.aspa_state.clear();
        absent.received_at_epoch_seconds = 0;
        let mut unknown = route_for_json(0, "");
        unknown.extended_communities = vec![11, 5];
        unknown.aspa_state = "unknown".to_string();
        unknown.received_at_epoch_seconds = 42;

        let value: serde_json::Value =
            serde_json::to_value(JsonRoutes(&[absent, unknown])).unwrap();
        assert_eq!(
            value[0]["extended_communities"],
            serde_json::json!([9, 3, 7])
        );
        assert!(value[0].get("aspa_state").is_none());
        assert_eq!(value[0]["received_at_epoch_seconds"], 0);
        assert_eq!(value[1]["extended_communities"], serde_json::json!([11, 5]));
        assert_eq!(value[1]["aspa_state"], "unknown");
        assert_eq!(value[1]["received_at_epoch_seconds"], 42);
    }

    #[test]
    fn route_list_json_honors_med_absence_marker() {
        // MED-absence-aware daemon: `med_attr` present somewhere in
        // the response, so an explicit MED 0 stays 0 and an absent MED
        // serializes as null.
        let mut zero = route_for_json(0, "");
        zero.med = 0;
        zero.med_attr = Some(0);
        let mut absent = route_for_json(0, "");
        absent.med = 0;
        absent.med_attr = None;
        let value: serde_json::Value = serde_json::to_value(JsonRoutes(&[zero, absent])).unwrap();
        assert_eq!(value[0]["med"], 0);
        assert_eq!(value[1]["med"], serde_json::Value::Null);

        // Older daemon: `med_attr` populated nowhere — the bare
        // 0-defaulted field passes through unchanged.
        let with_med = route_for_json(0, ""); // med: 50, med_attr: None
        let mut zero_med = route_for_json(0, "");
        zero_med.med = 0;
        let value: serde_json::Value =
            serde_json::to_value(JsonRoutes(&[with_med, zero_med])).unwrap();
        assert_eq!(value[0]["med"], 50);
        assert_eq!(value[1]["med"], 0);
    }

    #[test]
    fn route_list_json_exposes_explicit_local_pref_presence() {
        let mut explicit_zero = route_for_json(0, "");
        explicit_zero.local_pref = 0;
        explicit_zero.local_pref_attr = Some(0);
        let mut absent = route_for_json(0, "");
        absent.local_pref = 0;
        let value: serde_json::Value =
            serde_json::to_value(JsonRoutes(&[explicit_zero, absent])).unwrap();

        assert_eq!(value[0]["local_pref_attr"], 0);
        assert!(value[1].get("local_pref_attr").is_none());
    }

    /// GR stale flags serialize only when set, matching the VPN /
    /// labeled / RTC / BGP-LS route JSON convention (LAN-347).
    #[test]
    fn route_list_json_emits_stale_flags_only_when_set() {
        let fresh = route_for_json(0, "");
        let mut stale = route_for_json(0, "");
        stale.stale = true;
        let mut llgr = route_for_json(0, "");
        llgr.stale = true;
        llgr.llgr_stale = true;
        let value: serde_json::Value =
            serde_json::to_value(JsonRoutes(&[fresh, stale, llgr])).unwrap();
        assert!(value[0].get("stale").is_none());
        assert!(value[0].get("llgr_stale").is_none());
        assert_eq!(value[1]["stale"], true);
        assert!(value[1].get("llgr_stale").is_none());
        assert_eq!(value[2]["stale"], true);
        assert_eq!(value[2]["llgr_stale"], true);
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

    fn no_route_filters() -> RouteFilterOpts {
        RouteFilterOpts {
            prefix: None,
            longer: false,
            origin_asn: None,
            community: vec![],
            large_community: vec![],
        }
    }

    fn mock_route_page(
        prefix: &str,
        next_page_token: &str,
    ) -> rustbgpd_api::proto::ListRoutesResponse {
        rustbgpd_api::proto::ListRoutesResponse {
            routes: vec![rustbgpd_api::proto::Route {
                prefix: prefix.to_string(),
                prefix_length: 24,
                ..Default::default()
            }],
            next_page_token: next_page_token.to_string(),
            total_count: 2,
        }
    }

    fn count_filters() -> RouteFilterOpts {
        RouteFilterOpts {
            prefix: Some("2001:db8::/32".to_string()),
            longer: true,
            origin_asn: Some(64512),
            community: vec![(64512_u32 << 16) | 100],
            large_community: vec!["64512:1:100".to_string()],
        }
    }

    fn count_page(total_count: u64) -> rustbgpd_api::proto::ListRoutesResponse {
        rustbgpd_api::proto::ListRoutesResponse {
            routes: vec![rustbgpd_api::proto::Route {
                prefix: "2001:db8::".to_string(),
                prefix_length: 32,
                ..Default::default()
            }],
            // A count client must not follow this deliberately poisoned
            // continuation: `total_count` already covers the query.
            next_page_token: "poison-if-followed".to_string(),
            total_count,
        }
    }

    fn assert_count_request(request: &rustbgpd_api::proto::ListRoutesRequest, neighbor: &str) {
        assert_eq!(request.neighbor_address, neighbor);
        assert_eq!(request.afi_safi, AddressFamily::Ipv6Unicast as i32);
        assert_eq!(request.page_size, 1);
        assert!(request.page_token.is_empty());
        assert_eq!(request.prefix_filter, "2001:db8::");
        assert_eq!(request.prefix_filter_length, 32);
        assert!(request.longer_prefixes);
        assert_eq!(request.origin_asn, 64512);
        assert_eq!(request.community_filter, vec![(64512_u32 << 16) | 100]);
        assert_eq!(request.large_community_filter, vec!["64512:1:100"]);
    }

    /// Load-bearing output proof: changing the human label, JSON key, or
    /// dropping a zero count makes these exact assertions red.
    #[test]
    fn route_count_output_is_exact_for_zero_and_nonzero_totals() {
        assert_eq!(route_count_message(0), "Total matching routes: 0");
        assert_eq!(route_count_message(27), "Total matching routes: 27");
        assert_eq!(route_count_json(0), serde_json::json!({ "total_count": 0 }));
        assert_eq!(
            route_count_json(27),
            serde_json::json!({ "total_count": 27 })
        );
    }

    /// Load-bearing response proof: replacing the backend total with the
    /// returned row count (one) or following the poison continuation makes
    /// the value/call-count assertions red.
    #[tokio::test]
    async fn route_count_uses_backend_total_not_returned_row_count() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .list_route_pages
            .lock()
            .await
            .push(count_page(73));
        server
            .state
            .list_route_pages
            .lock()
            .await
            .push(count_page(999));
        let connection = connect(&server.addr, None).await.unwrap();
        let mut client =
            RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());

        let total = fetch_route_count(
            &mut client,
            &RouteListRpc::Best,
            make_route_request(
                None,
                Some(AddressFamily::Ipv6Unicast as i32),
                &count_filters(),
            )
            .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(total, 73);
        assert_eq!(
            server
                .state
                .list_best_route_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let remaining = server.state.list_route_pages.lock().await;
        assert_eq!(remaining.len(), 1, "poison continuation was consumed");
        assert_eq!(remaining[0].total_count, 999);
    }

    /// Load-bearing transport proof: selecting the wrong RPC, requesting
    /// more than one row, dropping any filter/scope, or following the poison
    /// continuation changes a counter/request assertion and makes this red.
    #[tokio::test]
    async fn count_uses_one_view_correct_filtered_rpc_for_each_route_view() {
        let server = spawn_mock_server(None).await;
        {
            let mut pages = server.state.list_route_pages.lock().await;
            pages.push(count_page(11));
            pages.push(count_page(22));
            pages.push(count_page(33));
        }
        let family = Some(AddressFamily::Ipv6Unicast as i32);
        let filters = count_filters();

        count_best(
            connect(&server.addr, None).await.unwrap(),
            family,
            &filters,
            false,
        )
        .await
        .unwrap();
        count_received(
            connect(&server.addr, None).await.unwrap(),
            "fe80::1%eth0",
            family,
            &filters,
            true,
        )
        .await
        .unwrap();
        count_advertised(
            connect(&server.addr, None).await.unwrap(),
            "fe80::2%eth1",
            family,
            &filters,
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            server
                .state
                .list_best_route_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            server
                .state
                .list_received_route_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            server
                .state
                .list_advertised_route_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let requests = server.state.list_route_requests.lock().await;
        assert_eq!(requests.len(), 3, "exactly one request per view");
        assert_count_request(&requests[0], "");
        assert_count_request(&requests[1], "fe80::1");
        assert_count_request(&requests[2], "fe80::2");
    }

    #[tokio::test]
    async fn scoped_route_lists_and_rejected_query_send_bare_addresses() {
        let server = spawn_mock_server(None).await;
        let filters = no_route_filters();

        received(
            connect(&server.addr, None).await.unwrap(),
            "fe80::1%eth0",
            None,
            &filters,
            false,
            true,
        )
        .await
        .unwrap();
        advertised(
            connect(&server.addr, None).await.unwrap(),
            "fe80::2%eth1",
            None,
            &filters,
            false,
            true,
        )
        .await
        .unwrap();
        rejected(
            connect(&server.addr, None).await.unwrap(),
            "fe80::3%eth2",
            true,
        )
        .await
        .unwrap();

        let requests = server.state.list_route_requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].neighbor_address, "fe80::1");
        assert_eq!(requests[1].neighbor_address, "fe80::2");
        drop(requests);
        let rejected = server
            .state
            .last_list_rejected
            .lock()
            .await
            .clone()
            .expect("rejected-route request captured");
        assert_eq!(rejected.peer_address, "fe80::3");
    }

    /// `rbgp rib received` follows `next_page_token` until the listing
    /// completes — no silent truncation at the server's page size.
    #[tokio::test]
    async fn received_paginates_transparently() {
        let server = spawn_mock_server(None).await;
        {
            let mut pages = server.state.list_route_pages.lock().await;
            pages.push(mock_route_page("10.0.0.0", "10.0.0.0/24|192.0.2.1|0"));
            pages.push(mock_route_page("10.0.1.0", ""));
        }

        let connection = connect(&server.addr, None).await.unwrap();
        received(
            connection,
            "fe80::1%eth0",
            None,
            &no_route_filters(),
            false,
            false,
        )
        .await
        .unwrap();

        let requests = server.state.list_route_requests.lock().await;
        assert_eq!(requests.len(), 2, "one RPC per page");
        assert!(requests[0].page_token.is_empty());
        assert_eq!(requests[0].neighbor_address, "fe80::1");
        assert!(requests[0].page_size > 0, "CLI requests bounded pages");
        assert_eq!(requests[1].page_token, "10.0.0.0/24|192.0.2.1|0");
    }

    /// `rbgp best` stops after a single page when the server reports
    /// the listing complete (empty `next_page_token`).
    #[tokio::test]
    async fn best_stops_on_final_page() {
        let server = spawn_mock_server(None).await;
        {
            let mut pages = server.state.list_route_pages.lock().await;
            pages.push(mock_route_page("10.0.0.0", ""));
        }

        let connection = connect(&server.addr, None).await.unwrap();
        best(connection, None, &no_route_filters(), false, false)
            .await
            .unwrap();

        let requests = server.state.list_route_requests.lock().await;
        assert_eq!(requests.len(), 1);
    }
}
