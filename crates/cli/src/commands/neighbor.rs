use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonNeighbor, JsonNeighborDetail};
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    AddNeighborRequest, DeleteNeighborRequest, DisableNeighborRequest, EnableNeighborRequest,
    GetNeighborStateRequest, ListNeighborsRequest, NeighborConfig, SoftResetInRequest,
};

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_neighbors(ListNeighborsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonNeighbor> = resp
            .neighbors
            .iter()
            .map(|n| {
                let cfg = n.config.as_ref();
                JsonNeighbor {
                    address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
                    remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
                    state: output::format_state(n.state).to_string(),
                    uptime_seconds: n.uptime_seconds,
                    prefixes_received: n.prefixes_received,
                    prefixes_sent: n.prefixes_sent,
                    description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize neighbor list as JSON")
        );
    } else if resp.neighbors.is_empty() {
        println!("No neighbors configured");
    } else {
        output::print_neighbor_header();
        for n in &resp.neighbors {
            output::print_neighbor_row(n);
        }
    }
    Ok(())
}

pub async fn show(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let n = client
        .get_neighbor_state(GetNeighborStateRequest {
            address: address.to_string(),
        })
        .await?
        .into_inner();

    let cfg = n.config.as_ref();
    if json {
        let out = JsonNeighborDetail {
            address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
            remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
            state: output::format_state(n.state).to_string(),
            uptime_seconds: n.uptime_seconds,
            prefixes_received: n.prefixes_received,
            prefixes_sent: n.prefixes_sent,
            updates_received: n.updates_received,
            updates_sent: n.updates_sent,
            notifications_received: n.notifications_received,
            notifications_sent: n.notifications_sent,
            flap_count: n.flap_count,
            last_error: n.last_error.clone(),
            description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
            hold_time: cfg.map(|c| c.hold_time).unwrap_or(0),
            families: cfg.map(|c| c.families.clone()).unwrap_or_default(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize neighbor detail as JSON")
        );
    } else {
        println!(
            "Neighbor:              {}",
            cfg.map(|c| c.address.as_str()).unwrap_or("")
        );
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
        println!(
            "Families:              {}",
            cfg.map(|c| c.families.join(", ")).unwrap_or_default()
        );
        println!("State:                 {}", output::format_state(n.state));
        println!(
            "Uptime:                {}",
            output::format_duration(n.uptime_seconds)
        );
        println!("Prefixes Received:     {}", n.prefixes_received);
        println!("Prefixes Sent:         {}", n.prefixes_sent);
        println!("Updates Received:      {}", n.updates_received);
        println!("Updates Sent:          {}", n.updates_sent);
        println!("Notifications Received:{}", n.notifications_received);
        println!("Notifications Sent:    {}", n.notifications_sent);
        println!("Flap Count:            {}", n.flap_count);
        if !n.last_error.is_empty() {
            println!("Last Error:            {}", n.last_error);
        }
    }
    Ok(())
}

pub struct AddNeighborOpts {
    pub asn: u32,
    pub description: Option<String>,
    pub hold_time: Option<u32>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<String>,
}

pub async fn add(
    connection: Connection,
    address: &str,
    opts: AddNeighborOpts,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_neighbor(AddNeighborRequest {
            config: Some(NeighborConfig {
                address: address.to_string(),
                remote_asn: opts.asn,
                description: opts.description.unwrap_or_default(),
                hold_time: opts.hold_time.unwrap_or(0),
                max_prefixes: opts.max_prefixes.unwrap_or(0),
                families: opts.families,
                remove_private_as: String::new(),
            }),
        })
        .await?;
    output::print_result(
        json,
        "add_neighbor",
        address,
        &format!("Neighbor {address} added"),
    );
    Ok(())
}

pub async fn delete(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_neighbor(DeleteNeighborRequest {
            address: address.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_neighbor",
        address,
        &format!("Neighbor {address} deleted"),
    );
    Ok(())
}

pub async fn enable(connection: Connection, address: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .enable_neighbor(EnableNeighborRequest {
            address: address.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "enable_neighbor",
        address,
        &format!("Neighbor {address} enabled"),
    );
    Ok(())
}

pub async fn disable(
    connection: Connection,
    address: &str,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .disable_neighbor(DisableNeighborRequest {
            address: address.to_string(),
            reason: reason.unwrap_or_default(),
        })
        .await?;
    output::print_result(
        json,
        "disable_neighbor",
        address,
        &format!("Neighbor {address} disabled"),
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
    client
        .soft_reset_in(SoftResetInRequest {
            address: address.to_string(),
            families: family.into_iter().collect(),
        })
        .await?;
    output::print_result(
        json,
        "softreset",
        address,
        &format!("Soft reset requested for {address}"),
    );
    Ok(())
}
