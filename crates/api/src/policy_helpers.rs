//! Shared helpers for policy proto ↔ domain conversion.
//!
//! Used by both `PolicyService` and `PeerGroupService` to avoid
//! duplicating statement validation and conversion logic.

use tonic::Status;

use crate::peer_types::{PolicyAsPathPrependConfig, PolicyStatementDefinition};
use crate::proto;

#[allow(clippy::result_large_err)]
pub(crate) fn validate_policy_action(action: &str) -> Result<(), Status> {
    match action {
        "permit" | "deny" => Ok(()),
        other => Err(Status::invalid_argument(format!(
            "invalid policy action {other:?}, expected \"permit\" or \"deny\""
        ))),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn proto_statement_to_input(
    statement: proto::PolicyStatement,
) -> Result<PolicyStatementDefinition, Status> {
    validate_policy_action(&statement.action)?;
    let ge = statement
        .ge
        .map(u8::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("ge exceeds u8 range"))?;
    let le = statement
        .le
        .map(u8::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("le exceeds u8 range"))?;
    let set_as_path_prepend = statement
        .set_as_path_prepend
        .map(|prepend| {
            u8::try_from(prepend.count)
                .map(|count| PolicyAsPathPrependConfig {
                    asn: prepend.asn,
                    count,
                })
                .map_err(|_| Status::invalid_argument("set_as_path_prepend.count exceeds u8 range"))
        })
        .transpose()?;

    Ok(PolicyStatementDefinition {
        action: statement.action,
        prefix: statement.prefix,
        ge,
        le,
        match_community: statement.match_community,
        match_as_path: statement.match_as_path,
        match_neighbor_set: statement.match_neighbor_set,
        match_route_type: statement.match_route_type,
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop,
        match_rpki_validation: statement.match_rpki_validation,
        match_aspa_validation: statement.match_aspa_validation,
        set_local_pref: statement.set_local_pref,
        set_med: statement.set_med,
        set_next_hop: statement.set_next_hop,
        set_community_add: statement.set_community_add,
        set_community_remove: statement.set_community_remove,
        set_as_path_prepend,
    })
}
