use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{
    self, JsonExplainAdvertisedRoute, JsonExplainModifications, JsonExplainReason, JsonRoute,
};
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddPathRequest, DeletePathRequest, ExplainAdvertisedRouteRequest, ExplainBestPathRequest,
    ExplainDecision, ListRoutesRequest,
};

/// Parsed route filter options from CLI flags.
pub struct RouteFilterOpts {
    pub prefix: Option<String>,
    pub longer: bool,
    pub origin_asn: Option<u32>,
    pub community: Vec<u32>,
    pub large_community: Vec<String>,
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

fn print_routes(routes: &[crate::proto::Route], json: bool) {
    if json {
        let out: Vec<JsonRoute> = routes.iter().map(route_to_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize route list as JSON")
        );
    } else if routes.is_empty() {
        println!("No routes");
    } else {
        output::print_route_table(routes);
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

fn print_explain_advertised(explain: &crate::proto::ExplainAdvertisedRouteResponse, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&explain_to_json(explain))
                .expect("failed to serialize advertised-route explain as JSON")
        );
        return;
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
}

fn print_explain_best_path(resp: &crate::proto::ExplainBestPathResponse, json: bool) {
    if json {
        let out = serde_json::json!({
            "prefix": format!("{}/{}", resp.prefix, resp.prefix_length),
            "best_route": resp.best_route.as_ref().map(route_to_json),
            "candidates": resp.candidates.iter().map(|c| {
                serde_json::json!({
                    "route": c.route.as_ref().map(route_to_json),
                    "vs_best_reason": c.vs_best_reason,
                    "vs_best_ordering": c.vs_best_ordering,
                })
            }).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize best-path explain")
        );
        return;
    }

    println!(
        "Best-path explanation for {}/{}",
        resp.prefix, resp.prefix_length
    );

    if let Some(ref best) = resp.best_route {
        println!(
            "Best route: peer={}, next_hop={}, as_path={:?}",
            best.peer_address, best.next_hop, best.as_path
        );
    } else {
        println!("No best route");
        return;
    }

    if resp.candidates.is_empty() {
        println!("No candidates");
        return;
    }

    println!();
    println!(
        "{:<18} {:<18} {:<22} {:<8}",
        "Peer", "Next Hop", "Reason", "Result"
    );
    println!("{}", "-".repeat(70));

    for c in &resp.candidates {
        if let Some(ref r) = c.route {
            println!(
                "{:<18} {:<18} {:<22} {:<8}",
                r.peer_address, r.next_hop, c.vs_best_reason, c.vs_best_ordering
            );
        }
    }
}

pub async fn explain_best_path(
    connection: Connection,
    prefix: &str,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .explain_best_path(ExplainBestPathRequest {
            prefix: addr,
            prefix_length: len,
        })
        .await?
        .into_inner();
    print_explain_best_path(&resp, json);
    Ok(())
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
    print_routes(&resp.routes, json);
    Ok(())
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
    print_routes(&resp.routes, json);
    Ok(())
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
    print_routes(&resp.routes, json);
    Ok(())
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
    print_explain_advertised(&resp, json);
    Ok(())
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
    output::print_result(json, "add_route", prefix, &format!("Route {prefix} added"));
    Ok(())
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
    );
    Ok(())
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
}
