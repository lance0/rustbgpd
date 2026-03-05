use tonic::transport::Channel;

use crate::error::CliError;
use crate::output;
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddFlowSpecRequest, DeleteFlowSpecRequest, FlowSpecAction, FlowSpecComponent, FlowSpecRedirect,
    FlowSpecTrafficAction, FlowSpecTrafficMarking, FlowSpecTrafficRate, ListFlowSpecRequest,
};

fn format_component(c: &FlowSpecComponent) -> String {
    let type_name = match c.r#type {
        1 => "dest",
        2 => "src",
        3 => "proto",
        4 => "port",
        5 => "dst-port",
        6 => "src-port",
        7 => "icmp-type",
        8 => "icmp-code",
        9 => "tcp-flags",
        10 => "pkt-len",
        11 => "dscp",
        12 => "fragment",
        13 => "flow-label",
        _ => "unknown",
    };
    if !c.prefix.is_empty() {
        format!("{type_name}={}", c.prefix)
    } else {
        format!("{type_name}={}", c.value)
    }
}

fn format_action(a: &FlowSpecAction) -> String {
    match &a.action {
        Some(crate::proto::flow_spec_action::Action::TrafficRate(r)) => {
            if r.rate == 0.0 {
                "drop".into()
            } else {
                format!("rate={:.0}", r.rate)
            }
        }
        Some(crate::proto::flow_spec_action::Action::TrafficAction(a)) => {
            let mut parts = Vec::new();
            if a.sample {
                parts.push("sample");
            }
            if a.terminal {
                parts.push("terminal");
            }
            parts.join(",")
        }
        Some(crate::proto::flow_spec_action::Action::TrafficMarking(m)) => {
            format!("mark-dscp={}", m.dscp)
        }
        Some(crate::proto::flow_spec_action::Action::Redirect(r)) => {
            format!("redirect={}", r.route_target)
        }
        None => "none".into(),
    }
}

pub async fn list(channel: Channel, family: Option<i32>, json: bool) -> Result<(), CliError> {
    let mut client = RibServiceClient::new(channel);
    let resp = client
        .list_flow_spec_routes(ListFlowSpecRequest {
            afi_safi: family.unwrap_or(0),
        })
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp
            .routes
            .iter()
            .map(|route| {
                serde_json::json!({
                    "components": route.components.iter().map(format_component).collect::<Vec<_>>(),
                    "actions": route.actions.iter().map(format_action).collect::<Vec<_>>(),
                    "peer_address": route.peer_address,
                    "afi_safi": output::format_family(route.afi_safi),
                    "as_path": route.as_path,
                    "communities": route.communities.iter().map(|c| output::format_community(*c)).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if resp.routes.is_empty() {
        println!("No FlowSpec routes");
    } else {
        for route in &resp.routes {
            let components: Vec<String> = route.components.iter().map(format_component).collect();
            let actions: Vec<String> = route.actions.iter().map(format_action).collect();
            println!(
                "  match [{}] action [{}] from {} ({})",
                components.join(", "),
                actions.join(", "),
                route.peer_address,
                output::format_family(route.afi_safi),
            );
        }
    }
    Ok(())
}

/// Parse a component like "dest=10.0.0.0/24" or "port==80".
fn parse_component(s: &str) -> Result<FlowSpecComponent, String> {
    let (type_name, value) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid component: {s} (expected type=value)"))?;
    let type_code = match type_name {
        "dest" => 1,
        "src" => 2,
        "proto" | "protocol" => 3,
        "port" => 4,
        "dst-port" => 5,
        "src-port" => 6,
        "icmp-type" => 7,
        "icmp-code" => 8,
        "tcp-flags" => 9,
        "pkt-len" => 10,
        "dscp" => 11,
        "fragment" => 12,
        "flow-label" => 13,
        _ => return Err(format!("unknown component type: {type_name}")),
    };
    // Types 1 and 2 are prefix types
    if type_code <= 2 {
        Ok(FlowSpecComponent {
            r#type: type_code,
            prefix: value.to_string(),
            value: String::new(),
            offset: 0,
        })
    } else {
        Ok(FlowSpecComponent {
            r#type: type_code,
            prefix: String::new(),
            value: value.to_string(),
            offset: 0,
        })
    }
}

/// Parse an action like "drop", "rate=1000", "redirect=65001:100", "mark-dscp=46".
fn parse_action(s: &str) -> Result<FlowSpecAction, String> {
    if s == "drop" {
        return Ok(FlowSpecAction {
            action: Some(crate::proto::flow_spec_action::Action::TrafficRate(
                FlowSpecTrafficRate { rate: 0.0 },
            )),
        });
    }
    if let Some(val) = s.strip_prefix("rate=") {
        let rate: f32 = val.parse().map_err(|_| format!("invalid rate: {val}"))?;
        return Ok(FlowSpecAction {
            action: Some(crate::proto::flow_spec_action::Action::TrafficRate(
                FlowSpecTrafficRate { rate },
            )),
        });
    }
    if let Some(val) = s.strip_prefix("redirect=") {
        return Ok(FlowSpecAction {
            action: Some(crate::proto::flow_spec_action::Action::Redirect(
                FlowSpecRedirect {
                    route_target: val.to_string(),
                },
            )),
        });
    }
    if let Some(val) = s.strip_prefix("mark-dscp=") {
        let dscp: u32 = val.parse().map_err(|_| format!("invalid DSCP: {val}"))?;
        if dscp > 63 {
            return Err(format!("invalid DSCP: {dscp} (expected 0-63)"));
        }
        return Ok(FlowSpecAction {
            action: Some(crate::proto::flow_spec_action::Action::TrafficMarking(
                FlowSpecTrafficMarking { dscp },
            )),
        });
    }
    if s == "sample" || s == "terminal" || s == "sample,terminal" {
        return Ok(FlowSpecAction {
            action: Some(crate::proto::flow_spec_action::Action::TrafficAction(
                FlowSpecTrafficAction {
                    sample: s.contains("sample"),
                    terminal: s.contains("terminal"),
                },
            )),
        });
    }
    Err(format!("unknown action: {s}"))
}

pub async fn add(
    channel: Channel,
    family: i32,
    components: &[String],
    actions: &[String],
    json: bool,
) -> Result<(), CliError> {
    let parsed_components: Vec<FlowSpecComponent> = components
        .iter()
        .map(|s| parse_component(s))
        .collect::<Result<_, _>>()
        .map_err(CliError::Argument)?;
    let parsed_actions: Vec<FlowSpecAction> = actions
        .iter()
        .map(|s| parse_action(s))
        .collect::<Result<_, _>>()
        .map_err(CliError::Argument)?;

    let mut client = InjectionServiceClient::new(channel);
    client
        .add_flow_spec(AddFlowSpecRequest {
            afi_safi: family,
            components: parsed_components,
            actions: parsed_actions,
            communities: vec![],
            extended_communities: vec![],
        })
        .await?;
    output::print_result(json, "add_flowspec", "", "FlowSpec rule added");
    Ok(())
}

pub async fn delete(
    channel: Channel,
    family: i32,
    components: &[String],
    json: bool,
) -> Result<(), CliError> {
    let parsed_components: Vec<FlowSpecComponent> = components
        .iter()
        .map(|s| parse_component(s))
        .collect::<Result<_, _>>()
        .map_err(CliError::Argument)?;

    let mut client = InjectionServiceClient::new(channel);
    client
        .delete_flow_spec(DeleteFlowSpecRequest {
            afi_safi: family,
            components: parsed_components,
        })
        .await?;
    output::print_result(json, "delete_flowspec", "", "FlowSpec rule deleted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_action;

    #[test]
    fn parse_action_rejects_out_of_range_dscp() {
        assert!(parse_action("mark-dscp=64").is_err());
    }

    #[test]
    fn parse_action_accepts_max_dscp() {
        assert!(parse_action("mark-dscp=63").is_ok());
    }
}
