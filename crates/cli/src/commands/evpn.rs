use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::ListEvpnRequest;
use crate::proto::rib_service_client::RibServiceClient;

fn route_type_label(t: u32) -> &'static str {
    match t {
        1 => "ead",
        2 => "mac-ip",
        3 => "imet",
        4 => "es",
        5 => "ip-prefix",
        _ => "unknown",
    }
}

pub async fn list(
    connection: Connection,
    route_type: Option<u32>,
    peer: Option<String>,
    rd: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_evpn_routes(ListEvpnRequest {
            route_type_filter: route_type.unwrap_or(0),
            peer_filter: peer.unwrap_or_default(),
            rd_filter: rd.unwrap_or_default(),
        })
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp
            .routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "route_type": r.route_type,
                    "route_type_name": route_type_label(r.route_type),
                    "rd": r.rd,
                    "esi": r.esi,
                    "ethernet_tag": r.ethernet_tag,
                    "mac": r.mac,
                    "ip": r.ip,
                    "prefix": r.prefix,
                    "gateway": r.gateway,
                    "label": r.label,
                    "label2": r.label2,
                    "tunnel_type": r.tunnel_type,
                    "next_hop": r.next_hop,
                    "peer": r.peer_address,
                    "as_path": r.as_path,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize EVPN route list as JSON")
        );
    } else if resp.routes.is_empty() {
        println!("No EVPN routes");
    } else {
        for r in &resp.routes {
            let tag = route_type_label(r.route_type);
            let mut detail = Vec::new();
            detail.push(format!("rd={}", r.rd));
            if !r.esi.is_empty() {
                detail.push(format!("esi={}", r.esi));
            }
            if !r.ethernet_tag.is_empty() {
                detail.push(format!("tag={}", r.ethernet_tag));
            }
            if !r.mac.is_empty() {
                detail.push(format!("mac={}", r.mac));
            }
            if !r.ip.is_empty() {
                detail.push(format!("ip={}", r.ip));
            }
            if !r.prefix.is_empty() {
                detail.push(format!("prefix={}", r.prefix));
            }
            if !r.gateway.is_empty() {
                detail.push(format!("gw={}", r.gateway));
            }
            if r.label != 0 {
                detail.push(format!("label={}", r.label));
            }
            if r.label2 != 0 {
                detail.push(format!("label2={}", r.label2));
            }
            if r.tunnel_type == 8 {
                detail.push("encap=vxlan".to_string());
            } else if r.tunnel_type != 0 {
                detail.push(format!("encap-type={}", r.tunnel_type));
            }
            println!(
                "[{tag}] {} via {} from {}",
                detail.join(" "),
                r.next_hop,
                r.peer_address,
            );
        }
    }
    Ok(())
}
