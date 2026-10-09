//! `rbgp policy conditional-advertisements` — per-definition ADR-0137
//! conditional-advertisement state: condition, applied gate, settle timer,
//! and attached neighbors.

use std::io::Write;
use std::time::Duration;

use crate::connection::{Connection, read_rpc};
use crate::error::CliError;
use crate::output;
use crate::proto::{
    ConditionalAdvertisementStatus, ListConditionalAdvertisementsRequest,
    ListConditionalAdvertisementsResponse,
};

const NONE_INSTALLED: &str =
    "No conditional advertisements installed (none attached to a static neighbor)";

pub async fn status(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client = connection.policy_listing_client();
    let resp = read_rpc(
        "ListConditionalAdvertisements",
        client.list_conditional_advertisements(ListConditionalAdvertisementsRequest {}),
    )
    .await?
    .into_inner();
    if json {
        output::print_json_pretty(&status_json(&resp))?;
    } else {
        write_status(&mut std::io::stdout().lock(), &resp)?;
    }
    Ok(())
}

fn status_json(resp: &ListConditionalAdvertisementsResponse) -> serde_json::Value {
    serde_json::json!({
        "definitions": resp.definitions.iter().map(|definition| serde_json::json!({
            "name": definition.name,
            "advertise_if": definition.advertise_if,
            "conditions": definition.conditions.iter().map(|condition| serde_json::json!({
                "prefix": condition.prefix,
                "state": condition.state,
            })).collect::<Vec<_>>(),
            "observed": definition.observed,
            "observed_for_ms": definition.observed_for_ms,
            "applied": definition.applied,
            "settle_time_seconds": definition.settle_time_seconds,
            "settle_pending": definition.settle_pending,
            "settle_remaining_ms": definition.settle_remaining_ms,
            "selection_deferred": definition.selection_deferred,
            "attached_peers": definition.attached_peers,
        })).collect::<Vec<_>>(),
    })
}

fn seconds(ms: u64) -> String {
    format!("{:.1}s", Duration::from_millis(ms).as_secs_f64())
}

fn settle_text(definition: &ConditionalAdvertisementStatus) -> String {
    let settle_time = definition.settle_time_seconds;
    if definition.settle_pending {
        format!(
            "pending, {} left (settle_time {settle_time}s)",
            seconds(definition.settle_remaining_ms)
        )
    } else if definition.selection_deferred {
        format!("held by selection deferral (settle_time {settle_time}s)")
    } else {
        format!("settled (settle_time {settle_time}s)")
    }
}

fn write_status(
    writer: &mut impl Write,
    resp: &ListConditionalAdvertisementsResponse,
) -> std::io::Result<()> {
    if resp.definitions.is_empty() {
        return writeln!(writer, "{NONE_INSTALLED}");
    }
    for (index, definition) in resp.definitions.iter().enumerate() {
        if index > 0 {
            writeln!(writer)?;
        }
        let conditions = definition
            .conditions
            .iter()
            .map(|condition| format!("{} {}", condition.prefix, condition.state))
            .collect::<Vec<_>>()
            .join(", ");
        let attached = if definition.attached_peers.is_empty() {
            "-".to_string()
        } else {
            definition.attached_peers.join(" ")
        };
        writeln!(writer, "{}", definition.name)?;
        writeln!(writer, "  advertise if:  {}", definition.advertise_if)?;
        writeln!(writer, "  applied:       {}", definition.applied)?;
        writeln!(
            writer,
            "  observed:      {} for {}",
            definition.observed,
            seconds(definition.observed_for_ms)
        )?;
        writeln!(writer, "  settle:        {}", settle_text(definition))?;
        writeln!(writer, "  conditions:    {conditions}")?;
        writeln!(writer, "  attached:      {attached}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ConditionalAdvertisementCondition;

    fn response() -> ListConditionalAdvertisementsResponse {
        ListConditionalAdvertisementsResponse {
            definitions: vec![
                ConditionalAdvertisementStatus {
                    name: "backup".to_string(),
                    advertise_if: "absent".to_string(),
                    conditions: vec![ConditionalAdvertisementCondition {
                        prefix: "0.0.0.0/0".to_string(),
                        state: "absent".to_string(),
                    }],
                    observed: "absent".to_string(),
                    observed_for_ms: 42_000,
                    applied: "advertise".to_string(),
                    settle_time_seconds: 5,
                    settle_pending: false,
                    settle_remaining_ms: 0,
                    selection_deferred: false,
                    attached_peers: vec!["203.0.113.2".to_string()],
                },
                ConditionalAdvertisementStatus {
                    name: "core".to_string(),
                    advertise_if: "present".to_string(),
                    conditions: vec![
                        ConditionalAdvertisementCondition {
                            prefix: "198.51.100.0/24".to_string(),
                            state: "present".to_string(),
                        },
                        ConditionalAdvertisementCondition {
                            prefix: "2001:db8::/32".to_string(),
                            state: "absent".to_string(),
                        },
                    ],
                    observed: "present".to_string(),
                    observed_for_ms: 1_500,
                    applied: "pending".to_string(),
                    settle_time_seconds: 5,
                    settle_pending: true,
                    settle_remaining_ms: 3_500,
                    selection_deferred: false,
                    attached_peers: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
                },
            ],
        }
    }

    #[test]
    fn human_output_shows_each_definition() {
        let mut out = Vec::new();
        write_status(&mut out, &response()).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "backup\n\
             \x20 advertise if:  absent\n\
             \x20 applied:       advertise\n\
             \x20 observed:      absent for 42.0s\n\
             \x20 settle:        settled (settle_time 5s)\n\
             \x20 conditions:    0.0.0.0/0 absent\n\
             \x20 attached:      203.0.113.2\n\
             \n\
             core\n\
             \x20 advertise if:  present\n\
             \x20 applied:       pending\n\
             \x20 observed:      present for 1.5s\n\
             \x20 settle:        pending, 3.5s left (settle_time 5s)\n\
             \x20 conditions:    198.51.100.0/24 present, 2001:db8::/32 absent\n\
             \x20 attached:      192.0.2.1 192.0.2.2\n"
        );
    }

    #[test]
    fn deferral_hold_and_empty_install_are_named() {
        let mut held = response().definitions.remove(0);
        held.applied = "pending".to_string();
        held.selection_deferred = true;
        assert_eq!(
            settle_text(&held),
            "held by selection deferral (settle_time 5s)"
        );
        let mut out = Vec::new();
        write_status(&mut out, &ListConditionalAdvertisementsResponse::default()).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{NONE_INSTALLED}\n")
        );
    }

    #[test]
    fn json_shape_is_stable() {
        let value = status_json(&response());
        assert_eq!(
            value["definitions"][1],
            serde_json::json!({
                "name": "core",
                "advertise_if": "present",
                "conditions": [
                    {"prefix": "198.51.100.0/24", "state": "present"},
                    {"prefix": "2001:db8::/32", "state": "absent"},
                ],
                "observed": "present",
                "observed_for_ms": 1500,
                "applied": "pending",
                "settle_time_seconds": 5,
                "settle_pending": true,
                "settle_remaining_ms": 3500,
                "selection_deferred": false,
                "attached_peers": ["192.0.2.1", "192.0.2.2"],
            })
        );
    }
}
