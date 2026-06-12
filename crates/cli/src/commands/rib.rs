use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonExplainAdvertisedRoute, JsonExplainModifications, JsonExplainReason, JsonRoute,
};
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddPathRequest, BlackholeDiscardState, DeletePathRequest, ExplainAdvertisedRouteRequest,
    ExplainBestPathRequest, ExplainDecision, FibRouteState, ListBlackholeDiscardsRequest,
    ListFibRoutesRequest, ListFibRoutesResponse, ListRoutesRequest,
};
use serde::Serialize;
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

fn route_to_json(r: &crate::proto::Route) -> JsonRoute {
    JsonRoute {
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

fn print_routes(routes: &[crate::proto::Route], json: bool) -> Result<(), CliError> {
    if json {
        let out: Vec<JsonRoute> = routes.iter().map(route_to_json).collect();
        output::print_json_pretty(&out)?;
    } else if routes.is_empty() {
        println!("No routes");
    } else {
        output::print_route_table(routes);
    }
    Ok(())
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
#[derive(Serialize)]
struct JsonExplainBestPath {
    prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_path_send_max: Option<u32>,
    /// Always emitted (as `null` when absent) — the v0.7.0 shape
    /// included this key unconditionally.
    best_route: Option<JsonRoute>,
    /// Decision step that selected the winner over the runner-up;
    /// `"only_path"` for a single-path prefix.
    best_reason: String,
    /// Compared values behind `best_reason`, winner's value first.
    /// Empty for `"only_path"`.
    best_reason_detail: String,
    candidates: Vec<JsonExplainCandidate>,
}

#[derive(Serialize)]
struct JsonExplainCandidate {
    /// Always emitted (as `null` when absent) — the v0.7.0 shape
    /// included this key unconditionally.
    route: Option<JsonRoute>,
    vs_best_reason: String,
    /// Compared values behind `vs_best_reason`, candidate's value
    /// first (e.g. `"local_pref 100 < 200"`).
    vs_best_detail: String,
    vs_best_ordering: String,
    /// Equal-cost multipath cut vs the best route: `"eligible"`,
    /// `"relax_only"`, or `"none"` (ADR-0066 grouping).
    multipath: String,
    /// Only emitted in peer-scoped mode; `0` in that mode means
    /// "filtered or beyond send_max", which is meaningful. In
    /// global-view mode the value is always `0` and would be
    /// noise, so the field is suppressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    advertised_path_id: Option<u32>,
}

fn explain_best_path_to_json(resp: &crate::proto::ExplainBestPathResponse) -> JsonExplainBestPath {
    let peer_scoped = !resp.peer_address.is_empty();
    JsonExplainBestPath {
        prefix: format!("{}/{}", resp.prefix, resp.prefix_length),
        peer_address: peer_scoped.then(|| resp.peer_address.clone()),
        add_path_send_max: peer_scoped.then_some(resp.add_path_send_max),
        best_route: resp.best_route.as_ref().map(route_to_json),
        best_reason: resp.best_reason.clone(),
        best_reason_detail: resp.best_reason_detail.clone(),
        candidates: resp
            .candidates
            .iter()
            .map(|c| JsonExplainCandidate {
                route: c.route.as_ref().map(route_to_json),
                vs_best_reason: c.vs_best_reason.clone(),
                vs_best_detail: c.vs_best_detail.clone(),
                vs_best_ordering: c.vs_best_ordering.clone(),
                multipath: c.multipath.clone(),
                advertised_path_id: peer_scoped.then_some(c.advertised_path_id),
            })
            .collect(),
    }
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
