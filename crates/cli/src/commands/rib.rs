use tonic::transport::Channel;

use crate::error::CliError;
use crate::output::{self, JsonRoute};
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{AddPathRequest, DeletePathRequest, ListRoutesRequest};

fn make_route_request(neighbor: Option<&str>, family: Option<i32>) -> ListRoutesRequest {
    ListRoutesRequest {
        neighbor_address: neighbor.unwrap_or("").to_string(),
        afi_safi: family.unwrap_or(0),
        page_size: 0,
        page_token: String::new(),
    }
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
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if routes.is_empty() {
        println!("No routes");
    } else {
        output::print_route_header();
        for r in routes {
            output::print_route_row(r);
        }
    }
}

pub async fn best(channel: Channel, family: Option<i32>, json: bool) -> Result<(), CliError> {
    let mut client = RibServiceClient::new(channel);
    let resp = client
        .list_best_routes(make_route_request(None, family))
        .await?
        .into_inner();
    print_routes(&resp.routes, json);
    Ok(())
}

pub async fn received(
    channel: Channel,
    address: &str,
    family: Option<i32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client = RibServiceClient::new(channel);
    let resp = client
        .list_received_routes(make_route_request(Some(address), family))
        .await?
        .into_inner();
    print_routes(&resp.routes, json);
    Ok(())
}

pub async fn advertised(
    channel: Channel,
    address: &str,
    family: Option<i32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client = RibServiceClient::new(channel);
    let resp = client
        .list_advertised_routes(make_route_request(Some(address), family))
        .await?
        .into_inner();
    print_routes(&resp.routes, json);
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
    channel: Channel,
    prefix: &str,
    opts: AddRouteOpts,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client = InjectionServiceClient::new(channel);
    client
        .add_path(AddPathRequest {
            prefix: addr,
            prefix_length: len,
            next_hop: opts.next_hop,
            as_path: opts.as_path,
            origin: opts.origin.unwrap_or(0),
            local_pref: opts.local_pref.unwrap_or(0),
            med: opts.med.unwrap_or(0),
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
    channel: Channel,
    prefix: &str,
    path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, len) = output::parse_prefix(prefix).map_err(CliError::Argument)?;
    let mut client = InjectionServiceClient::new(channel);
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
