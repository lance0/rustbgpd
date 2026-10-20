pub mod bfd;
pub mod conditional_advertisement;
pub mod config;
pub mod control;
pub mod diff;
pub mod doctor;
pub mod dynamic_neighbor;
pub mod evpn;
pub mod fib_table;
pub mod flowspec;
pub mod global;
pub mod neighbor;
pub mod neighbor_set;
pub mod orr;
pub mod peer_group;
pub mod policy;
pub mod policy_input;
pub mod rib;
pub mod rpki;
pub mod topology;
pub mod watch;

/// The lease owner a delete of injected state names (ADR-0141): `""` for an
/// unowned entry, or an override that deletes whatever the owner.
pub struct InjectedOwner {
    pub owner: String,
    pub override_owner: bool,
}

impl InjectedOwner {
    pub fn new(owner: Option<String>, override_owner: bool) -> Self {
        Self {
            owner: owner.unwrap_or_default(),
            override_owner,
        }
    }

    /// The daemon refuses a delete whose owner does not match with
    /// `FAILED_PRECONDITION`, naming the entry's owner; point at the flags.
    pub(crate) fn delete_error(status: tonic::Status) -> crate::error::CliError {
        if status.code() == tonic::Code::FailedPrecondition {
            return crate::error::CliError::Rpc(format!(
                "precondition failed: {}\n  \
                 hint: pass --owner with the entry's lease owner (omit it for an unowned entry), \
                 or --override-owner to delete it whatever its owner",
                status.message()
            ));
        }
        status.into()
    }
}

/// Name an `AddPath` or `AddFlowSpec` outcome against the previous local
/// entry; `unknown` for a daemon that predates it. `PathInjectOutcome` and
/// `FlowSpecInjectOutcome` share one numbering, pinned by a test below.
pub(crate) fn inject_outcome_name(outcome: i32) -> &'static str {
    use crate::proto::PathInjectOutcome;
    match PathInjectOutcome::try_from(outcome) {
        Ok(PathInjectOutcome::Created) => "created",
        Ok(PathInjectOutcome::Replaced) => "replaced",
        Ok(PathInjectOutcome::Unchanged) => "unchanged",
        Ok(PathInjectOutcome::Unspecified) | Err(_) => "unknown",
    }
}

/// Name a `DeletePath` or `DeleteFlowSpec` outcome; `unknown` for a daemon
/// that predates it. `PathDeleteOutcome` and `FlowSpecDeleteOutcome` share
/// one numbering, pinned by a test below.
pub(crate) fn delete_outcome_name(outcome: i32) -> &'static str {
    use crate::proto::PathDeleteOutcome;
    match PathDeleteOutcome::try_from(outcome) {
        Ok(PathDeleteOutcome::Deleted) => "deleted",
        Ok(PathDeleteOutcome::NotPresent) => "not_present",
        Ok(PathDeleteOutcome::Unspecified) | Err(_) => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{delete_outcome_name, inject_outcome_name};
    use crate::proto::{
        FlowSpecDeleteOutcome, FlowSpecInjectOutcome, PathDeleteOutcome, PathInjectOutcome,
    };

    #[test]
    fn unicast_and_flowspec_outcomes_share_names() {
        for (path, flowspec, name) in [
            (
                PathInjectOutcome::Unspecified,
                FlowSpecInjectOutcome::Unspecified,
                "unknown",
            ),
            (
                PathInjectOutcome::Created,
                FlowSpecInjectOutcome::Created,
                "created",
            ),
            (
                PathInjectOutcome::Replaced,
                FlowSpecInjectOutcome::Replaced,
                "replaced",
            ),
            (
                PathInjectOutcome::Unchanged,
                FlowSpecInjectOutcome::Unchanged,
                "unchanged",
            ),
        ] {
            assert_eq!(inject_outcome_name(path as i32), name);
            assert_eq!(inject_outcome_name(flowspec as i32), name);
        }
        for (path, flowspec, name) in [
            (
                PathDeleteOutcome::Unspecified,
                FlowSpecDeleteOutcome::Unspecified,
                "unknown",
            ),
            (
                PathDeleteOutcome::Deleted,
                FlowSpecDeleteOutcome::Deleted,
                "deleted",
            ),
            (
                PathDeleteOutcome::NotPresent,
                FlowSpecDeleteOutcome::NotPresent,
                "not_present",
            ),
        ] {
            assert_eq!(delete_outcome_name(path as i32), name);
            assert_eq!(delete_outcome_name(flowspec as i32), name);
        }
        // A value newer than this CLI is not guessed at.
        assert_eq!(inject_outcome_name(99), "unknown");
        assert_eq!(delete_outcome_name(99), "unknown");
    }
}
