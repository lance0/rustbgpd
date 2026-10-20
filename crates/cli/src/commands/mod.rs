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
