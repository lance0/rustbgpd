//! Operator-read admission at every peer-manager transaction wait.
//!
//! Every `await_with_readiness*` call site
//! is one row of [`WAIT_SITES`]: what the site awaits, how a stub parks the
//! transaction there, and whether a
//! concurrent operator read (`ListPeers`, `HasPeerAddress`) is
//! served or deliberately fenced while it is parked.
//!
//! `GetPolicyStats` import counters, peer validation and dataset status no
//! longer use the operator lane (ADR-0136): they read the peer manager's
//! published import roster. Removing `QueryImportPolicyTermHits` removed the
//! one wait that finished an admitted import collector,
//! `mod.rs::handle_operator_query` (`finish_admitted_operator_read`), and its
//! row. The export stage reads the RIB's published export roster; removing
//! the RIB summary-lane `ExportPolicyTermHits` and the general-lane
//! `QueryExportPolicyTermHits` left `GetPolicyStats` with no actor wait, and
//! it never had a row here. One driver runs every
//! row. [`wait_site_table_covers_every_call_site`] fails when a call site is
//! added without a row, so an admission decision cannot go unnoticed.

use super::*;

use std::collections::BTreeMap;

use crate::config::{PreparedDatasetGeneration, plan_reload_peer_actions};
use crate::peer_manager::generation::ReloadGenerationOutcome;
use rustbgpd_api::peer_types::{PeerInfo, PeerManagerOperatorQuery, ResolvedPeerPolicy};
use rustbgpd_api::runtime_config_settlement::RuntimeConfigPolicyFailureCode;
use rustbgpd_rib::{ExportPolicyCohortOutcome, PeerExportPolicyRestoreReceipt};
use rustbgpd_transport::ImportPolicyTermHits;

/// Fresh caller budget used by this matrix (`PEER_MANAGER_READ_TIMEOUT` in
/// the API crate). Prior queueing or other stages can consume that budget
/// before a read encounters even a shorter individual fence.
const READER_DEADLINE: Duration = Duration::from_secs(2);

/// Reads issued while the site is parked. Both contracts probe for `window`
/// (below the site's own bound) so no later wait can satisfy the proof.
#[derive(Clone, Copy, Debug)]
enum Contract {
    Served,
    Fenced { reason: &'static str },
    Unreachable { why: &'static str },
}

/// How the stub RIB parks the transaction.
#[derive(Clone, Copy)]
enum RibHold {
    None,
    /// Prefill the only slot and hold the receiver before the owner starts.
    Capacity,
    /// Hold the reply of the first matching command until release.
    Reply(fn(&RibUpdate) -> bool),
    /// Answer the first `n` matching commands, then hold the next one's reply.
    LaterReply(fn(&RibUpdate) -> bool, usize),
    /// Answer the first matching command, then stop receiving until release,
    /// so the next send parks on the full (capacity 1) channel.
    Receiver(fn(&RibUpdate) -> bool),
    /// Answer the first matching command, then drop the receiver.
    ExitAfter(fn(&RibUpdate) -> bool),
}

#[derive(Clone, Copy)]
enum SessionAction {
    Answer,
    Fail,
    /// Keep the reply alive and never answer: the command times out.
    Stall,
    Hold,
}

/// The first peer's session follows the row's script, indexed per command
/// kind; the second peer answers everything.
type SessionScript = fn(&PeerCommand, usize) -> SessionAction;

#[derive(Clone, Copy)]
enum CohortReply {
    Committed,
    Authoritative,
    Rejected,
}

#[derive(Clone, Copy)]
enum Drive {
    /// Two Established peers sharing one export move, driven as the forward
    /// reload owner (`allow_operator_reads = true`).
    ForwardCohort {
        import_delta: bool,
        cohort_reply: CohortReply,
    },
    /// One target: the authoritative per-peer walk, forward owner.
    ForwardWalk {
        clean: bool,
    },
    /// One target moving the RFC 8212 import verdict (preflight qualifies it).
    Rfc8212Transition {
        established: bool,
    },
    /// Forward live-impact transaction and catalog-mutation entries.
    ApiPolicyImpact,
    CatalogPolicyRefresh,
    HonorGracefulShutdown,
    HonorBlackhole,
    /// API publication-failure compensation replays captured prior policies
    /// while admitted reads report the sources' current values.
    ApiPublicationCompensation,
    /// A reload generation whose session replace is rejected after its
    /// policy cohort committed, so the unwind replays the prior chains
    /// with reads admitted after earlier restoration steps succeeded.
    CompensatingReplay,
    ValidationRefresh,
    DatasetRefresh,
    DatasetGeneration {
        compensate: bool,
    },
    RetainedStaleCapacity,
    ExportReplacementCapacity,
    DatasetExportCapacity {
        failed_restore: bool,
    },
    MaxPrefixRestart,
    OutboundRefresh,
    HotExportKnobs,
    GracefulShutdown,
    OutboundReplay,
    /// Reload settlement publishes the configured-owner catalogue to the RIB.
    ConfiguredOwnerPublication,
    /// A reload commits a BFD membership change and awaits the BFD actor.
    BfdReload,
}

#[derive(Clone, Copy)]
enum Completion {
    ExportApplied,
    ImportApplied,
    ExportRestored,
    Finished,
    PeerEnabled,
}

struct WaitSite {
    /// `file::enclosing_fn`; the completeness guard keys on this.
    site: &'static str,
    awaits: &'static str,
    drive: Drive,
    rib: RibHold,
    session: SessionScript,
    /// `Some` when the row re-exercises a site another row already covers,
    /// through a different production entry point. Such rows are not
    /// counted by the call-site guard.
    additional_entry: Option<&'static str>,
    window: Duration,
    contract: Contract,
    completion: Completion,
}

const HELD_FOREVER: Duration = Duration::from_secs(1);
const HALF_QUERY: Duration = Duration::from_millis(50);

fn answer_all(_: &PeerCommand, _: usize) -> SessionAction {
    SessionAction::Answer
}

fn hold_first_state(command: &PeerCommand, index: usize) -> SessionAction {
    match command {
        PeerCommand::QueryState { .. } if index == 0 => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn hold_second_state(command: &PeerCommand, index: usize) -> SessionAction {
    match command {
        PeerCommand::QueryState { .. } if index == 1 => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn stall_then_hold_state(command: &PeerCommand, index: usize) -> SessionAction {
    match (command, index) {
        (PeerCommand::QueryState { .. }, 0) => SessionAction::Stall,
        (PeerCommand::QueryState { .. }, 1) => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn hold_first_export_apply(command: &PeerCommand, index: usize) -> SessionAction {
    match command {
        PeerCommand::UpdateExportPolicy { .. } if index == 0 => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn fail_export_then_hold_state(command: &PeerCommand, index: usize) -> SessionAction {
    match (command, index) {
        (PeerCommand::UpdateExportPolicy { .. }, 0) => SessionAction::Fail,
        (PeerCommand::QueryState { .. }, 1) => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn hold_first_replay(command: &PeerCommand, index: usize) -> SessionAction {
    match command {
        PeerCommand::ReplayOutbound { .. } if index == 0 => SessionAction::Hold,
        _ => SessionAction::Answer,
    }
}

fn is_outbound_refresh(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::RefreshPeerOutbound { .. })
}

fn is_prestage(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::PrepareExportPolicyDestination { .. })
}

fn is_cohort_replace(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::ReplacePeerExportPolicies { .. })
}

fn is_authoritative_replace(update: &RibUpdate) -> bool {
    matches!(
        update,
        RibUpdate::ReplacePeerExportPoliciesAuthoritatively { .. }
    )
}

fn is_single_replace(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::ReplacePeerExportPolicy { .. })
}

fn is_restore(update: &RibUpdate) -> bool {
    matches!(
        update,
        RibUpdate::RestorePeerExportPoliciesAuthoritatively { .. }
    )
}

fn is_retained_stale(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::QueryPeerRetainedStale { .. })
}

fn is_owner_publication(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::PublishDampeningOwners { .. })
}

fn is_reevaluate(update: &RibUpdate) -> bool {
    matches!(update, RibUpdate::ReevaluatePeerExportPolicies { .. })
}

const FORWARD_COHORT: Drive = Drive::ForwardCohort {
    import_delta: false,
    cohort_reply: CohortReply::Committed,
};

const QUERY_PROBE_REASON: &str = "one session state probe bounded by PEER_QUERY_TIMEOUT (100 ms), \
     below the 2 s reader deadline; the readiness lane is drained after it";

/// One row per actor wait-helper call site, in source order.
const WAIT_SITES: &[WaitSite] = &[
    WaitSite {
        site: "policy.rs::qualify_rfc8212_import_transition",
        awaits: "PeerCommand::QueryState of the transitioning peer (preflight)",
        drive: Drive::Rfc8212Transition { established: true },
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::ImportApplied,
    },
    WaitSite {
        site: "policy.rs::query_peer_retained_stale",
        awaits: "RibUpdate::QueryPeerRetainedStale reply (preflight, down peer)",
        drive: Drive::Rfc8212Transition { established: false },
        rib: RibHold::Reply(is_retained_stale),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ImportApplied,
    },
    WaitSite {
        site: "policy.rs::export_only_policy_cohort_mask",
        awaits: "PeerCommand::QueryState of each winning cohort member",
        drive: FORWARD_COHORT,
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::hot_apply_session_policy",
        awaits: "PeerCommand::UpdateExportPolicy / UpdateImportPolicy acknowledgement",
        drive: FORWARD_COHORT,
        rib: RibHold::None,
        session: hold_first_export_apply,
        additional_entry: None,
        window: Duration::from_millis(250),
        contract: Contract::Fenced {
            reason: "the session is mid-install: until it acknowledges, neither chain is \
                     provably running, so a snapshot row could not be attributed to a \
                     generation; bounded by PEER_POLICY_UPDATE_TIMEOUT attention time (500 ms), \
                     below the 2 s reader deadline",
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::query_clean_session_state",
        awaits: "PeerCommand::QueryState, first probe",
        drive: Drive::ForwardWalk { clean: true },
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::query_clean_session_state",
        awaits: "PeerCommand::QueryState, bounded retry",
        drive: Drive::ForwardWalk { clean: true },
        rib: RibHold::None,
        session: stall_then_hold_state,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "RibUpdate::PrepareExportPolicyDestination reply (destination prestage)",
        drive: FORWARD_COHORT,
        rib: RibHold::Reply(is_prestage),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "PeerCommand::QueryState after reasserting a failed member's import chain",
        drive: Drive::ForwardCohort {
            import_delta: true,
            cohort_reply: CohortReply::Committed,
        },
        rib: RibHold::None,
        session: fail_export_then_hold_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: "failure path mid-unwind of one member: its prior chains were just \
                     reasserted and its Route Refresh debt is undecided; bounded by \
                     PEER_QUERY_TIMEOUT (100 ms), below the 2 s reader deadline",
        },
        completion: Completion::ExportRestored,
    },
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "PeerCommand::QueryState before the deferred Route Refresh (non-clean reload)",
        drive: Drive::ForwardCohort {
            import_delta: true,
            cohort_reply: CohortReply::Committed,
        },
        rib: RibHold::None,
        session: hold_second_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: FORWARD_COHORT,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    // Forward API entries share the SIGHUP owner's read admission.
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: Drive::ApiPolicyImpact,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        additional_entry: Some("apply_policy_impact_snapshot forward API transaction"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: Drive::CatalogPolicyRefresh,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        additional_entry: Some("apply_policy_change_owned forward catalog refresh"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    // This entry restores captured priors after API publication failed.
    // It is not the forward API transaction entry.
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: Drive::ApiPublicationCompensation,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        additional_entry: Some(
            "PeerManagerCommand::ApplyResolvedPolicySnapshot publication-failure compensation",
        ),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    // Clean generation replay admits live reads. The failed hot-knob restore
    // counterexample in reload_generation keeps the owner's full fence.
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "RibUpdate::PrepareExportPolicyDestination reply (destination prestage)",
        drive: Drive::CompensatingReplay,
        rib: RibHold::LaterReply(is_prestage, 1),
        session: answer_all,
        additional_entry: Some(
            "apply_reload_generation unwind (compensating replay of the prior generation's \
             chains after a rejected session replace, no earlier restoration failure)",
        ),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportRestored,
    },
    WaitSite {
        site: "policy.rs::apply_export_policy_replacements_authoritatively",
        awaits: "RibUpdate::ReplacePeerExportPoliciesAuthoritatively send (full RIB channel)",
        drive: Drive::ForwardCohort {
            import_delta: false,
            cohort_reply: CohortReply::Authoritative,
        },
        rib: RibHold::Receiver(is_cohort_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::apply_export_policy_replacements_authoritatively",
        awaits: "RibUpdate::ReplacePeerExportPoliciesAuthoritatively reply",
        drive: Drive::ForwardCohort {
            import_delta: false,
            cohort_reply: CohortReply::Authoritative,
        },
        rib: RibHold::Reply(is_authoritative_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::replace_peer_export_policy_in_rib",
        awaits: "RibUpdate::ReplacePeerExportPolicy reply (authoritative walk step)",
        drive: Drive::ForwardWalk { clean: false },
        rib: RibHold::Reply(is_single_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    // The rollback owner admits live peer-manager reads at both waits. The
    // RIB's general-query lane is a separate contract, not exercised here.
    WaitSite {
        site: "policy.rs::register_policy_rollback_rib",
        awaits: "rollback RestorePeerExportPoliciesAuthoritatively enqueue acknowledgement",
        drive: Drive::ForwardCohort {
            import_delta: false,
            cohort_reply: CohortReply::Rejected,
        },
        rib: RibHold::Receiver(is_cohort_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportRestored,
    },
    WaitSite {
        site: "policy.rs::register_policy_rollback_rib",
        awaits: "the detached rollback task after its enqueue failed",
        drive: Drive::ForwardCohort {
            import_delta: false,
            cohort_reply: CohortReply::Rejected,
        },
        rib: RibHold::ExitAfter(is_cohort_replace),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Unreachable {
            why: "the JoinHandle is awaited only in the arm where the detached task already \
                  returned (its RIB send failed and dropped the acknowledgement), so the wait \
                  completes on the next poll: no constant bounds it and nothing can hold it",
        },
        completion: Completion::ExportRestored,
    },
    // Deliberately served together with the rollback enqueue row above.
    WaitSite {
        site: "policy.rs::restore_resolved_policies",
        awaits: "rollback RestorePeerExportPoliciesAuthoritatively aggregate reply",
        drive: Drive::ForwardCohort {
            import_delta: false,
            cohort_reply: CohortReply::Rejected,
        },
        rib: RibHold::Reply(is_restore),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportRestored,
    },
    WaitSite {
        site: "policy.rs::soft_reset_import_validation_dependents",
        awaits: "PeerCommand::QueryState of each validation-dependent peer",
        drive: Drive::ValidationRefresh,
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: QUERY_PROBE_REASON,
        },
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::refresh_dataset_dependents",
        awaits: "PeerCommand::QueryState of each dataset-dependent peer",
        drive: Drive::DatasetRefresh,
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "RibUpdate::ReevaluatePeerExportPolicies reply",
        drive: Drive::DatasetGeneration { compensate: false },
        rib: RibHold::Reply(is_reevaluate),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::handle_due_max_prefix_restarts",
        awaits: "join_all of PeerCommand::Start sends to every due peer",
        drive: Drive::MaxPrefixRestart,
        rib: RibHold::None,
        session: answer_all,
        additional_entry: None,
        window: Duration::from_millis(250),
        contract: Contract::Fenced {
            reason: "every Start send shares one absolute PEER_LIFECYCLE_COMMAND_TIMEOUT \
                     deadline (500 ms) regardless of how many peers are due, below the 2 s \
                     reader deadline; the latch is consumed before the send, so a read would \
                     otherwise show a disabled peer whose restart is already committed",
        },
        completion: Completion::PeerEnabled,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "legacy dataset ReevaluatePeerExportPolicies reply",
        drive: Drive::DatasetRefresh,
        rib: RibHold::Reply(is_reevaluate),
        session: answer_all,
        additional_entry: Some("legacy refresh_dataset_dependents export reevaluation"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::apply_runtime_policies_for_peer_key",
        awaits: "post-ACK authoritative state query after matching bookkeeping",
        drive: Drive::ForwardWalk { clean: false },
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::apply_runtime_policies_for_peer_key",
        awaits: "honor_graceful_shutdown fan-out post-ACK state query",
        drive: Drive::HonorGracefulShutdown,
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: Some("SIGHUP honor_graceful_shutdown fan-out"),
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::apply_runtime_policies_for_peer_key",
        awaits: "honor_blackhole fan-out post-ACK state query",
        drive: Drive::HonorBlackhole,
        rib: RibHold::None,
        session: hold_first_state,
        additional_entry: Some("SIGHUP honor_blackhole fan-out"),
        window: HALF_QUERY,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "compensating dataset generation ReevaluatePeerExportPolicies reply",
        drive: Drive::DatasetGeneration { compensate: true },
        rib: RibHold::LaterReply(is_reevaluate, 1),
        session: answer_all,
        additional_entry: Some("dataset generation restoration after rejected session replacement"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "full RIB channel capacity before dispatch",
        drive: Drive::DatasetExportCapacity {
            failed_restore: false,
        },
        rib: RibHold::Capacity,
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::query_peer_retained_stale",
        awaits: "full RIB channel capacity before dispatch",
        drive: Drive::RetainedStaleCapacity,
        rib: RibHold::Capacity,
        session: answer_all,
        additional_entry: Some("full RIB channel before retained-stale proof"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::replace_peer_export_policy_in_rib",
        awaits: "full RIB channel capacity before dispatch",
        drive: Drive::ExportReplacementCapacity,
        rib: RibHold::Capacity,
        session: answer_all,
        additional_entry: Some("full RIB channel before authoritative replacement"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "dataset export capacity after an earlier failed restoration",
        drive: Drive::DatasetExportCapacity {
            failed_restore: true,
        },
        rib: RibHold::Capacity,
        session: answer_all,
        additional_entry: Some("failed prior restoration keeps the shared capacity wait fenced"),
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "earlier failed restoration can leave session and manager metadata inconsistent",
        },
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::refresh_peer_outbound_in_rib",
        awaits: "RibUpdate::RefreshPeerOutbound acknowledgement",
        drive: Drive::OutboundRefresh,
        rib: RibHold::Reply(is_outbound_refresh),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::refresh_peer_outbound_in_rib",
        awaits: "RibUpdate::RefreshPeerOutbound after acknowledged export-knob update",
        drive: Drive::HotExportKnobs,
        rib: RibHold::Reply(is_outbound_refresh),
        session: answer_all,
        additional_entry: Some("hot_update_peer_in_place"),
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "the session has candidate knobs while manager metadata retains prior \
                     values until refresh succeeds; reads would mix the two",
        },
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::refresh_peer_outbound_in_rib",
        awaits: "RibUpdate::RefreshPeerOutbound after acknowledged GSHUT toggle",
        drive: Drive::GracefulShutdown,
        rib: RibHold::Reply(is_outbound_refresh),
        session: answer_all,
        additional_entry: Some("set_graceful_shutdown"),
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::replay_outbound",
        awaits: "PeerCommand::ReplayOutbound scheduling acknowledgement",
        drive: Drive::OutboundReplay,
        rib: RibHold::None,
        session: hold_first_replay,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "configured_owners.rs::configured_owner_publication",
        awaits: "RibUpdate::PublishDampeningOwners acknowledgement (reload settlement)",
        drive: Drive::ConfiguredOwnerPublication,
        rib: RibHold::Reply(is_owner_publication),
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
    WaitSite {
        site: "bfd.rs::commit_bfd_reload",
        awaits: "BfdReloadCommand acknowledgement from the BFD actor",
        drive: Drive::BfdReload,
        rib: RibHold::None,
        session: answer_all,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::Finished,
    },
];

/// Shared hold point: a stub signals `held` when it parks the transaction and
/// resumes when the driver releases. Every stub of one row shares one gate.
#[derive(Clone)]
struct Gate {
    held: Arc<Notify>,
    release: tokio::sync::watch::Receiver<bool>,
    release_tx: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Gate {
    fn new() -> Self {
        let (release_tx, release) = tokio::sync::watch::channel(false);
        Self {
            held: Arc::new(Notify::new()),
            release,
            release_tx: Arc::new(release_tx),
        }
    }

    async fn hold(&self) {
        self.held.notify_one();
        let mut release = self.release.clone();
        while !*release.borrow() {
            if release.changed().await.is_err() {
                break;
            }
        }
    }

    async fn held(&self) {
        self.held.notified().await;
    }

    fn release(&self) {
        let _ = self.release_tx.send(true);
    }
}

fn answer_rib(update: RibUpdate, cohort_reply: CohortReply) {
    match update {
        RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
        RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
            let _ = reply.send(match cohort_reply {
                CohortReply::Committed => Ok(ExportPolicyCohortOutcome::Committed),
                CohortReply::Authoritative => {
                    Ok(ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply)
                }
                CohortReply::Rejected => Err("test: cohort rejected".to_string()),
            });
        }
        RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. }
        | RibUpdate::ReplacePeerExportPolicy { reply, .. }
        | RibUpdate::RefreshPeerOutbound { reply, .. }
        | RibUpdate::ReevaluatePeerExportPolicies { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
        RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } => {
            let _ = reply.send(Ok(replacements
                .iter()
                .rev()
                .map(|replacement| PeerExportPolicyRestoreReceipt::Restored {
                    peer: replacement.peer,
                })
                .collect()));
        }
        RibUpdate::QueryPeerRetainedStale { reply, .. } => {
            let _ = reply.send(0);
        }
        RibUpdate::PublishDampeningOwners { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
        _ => {}
    }
}

fn spawn_rib(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    gate: Gate,
    hold: RibHold,
    cohort_reply: CohortReply,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if matches!(hold, RibHold::Capacity) {
            gate.hold().await;
        }
        let mut armed = true;
        let mut skip = match hold {
            RibHold::LaterReply(_, skip) => skip,
            _ => 0,
        };
        while let Some(update) = rib_rx.recv().await {
            let matcher = match hold {
                RibHold::None | RibHold::Capacity => None,
                RibHold::Reply(matcher)
                | RibHold::LaterReply(matcher, _)
                | RibHold::Receiver(matcher)
                | RibHold::ExitAfter(matcher) => Some(matcher),
            };
            if !(armed && matcher.is_some_and(|matcher| matcher(&update))) {
                answer_rib(update, cohort_reply);
                continue;
            }
            if skip > 0 {
                skip -= 1;
                answer_rib(update, cohort_reply);
                continue;
            }
            armed = false;
            match hold {
                RibHold::Reply(..) | RibHold::LaterReply(..) => {
                    let gate = gate.clone();
                    tokio::spawn(async move {
                        gate.hold().await;
                        answer_rib(update, cohort_reply);
                    });
                }
                RibHold::Receiver(_) => {
                    answer_rib(update, cohort_reply);
                    gate.hold().await;
                }
                RibHold::ExitAfter(_) => {
                    answer_rib(update, cohort_reply);
                    break;
                }
                RibHold::None | RibHold::Capacity => unreachable!("matched without a matcher"),
            }
        }
    })
}

fn command_kind(command: &PeerCommand) -> &'static str {
    match command {
        PeerCommand::QueryState { .. } => "QueryState",
        PeerCommand::UpdateExportPolicy { .. } => "UpdateExportPolicy",
        PeerCommand::UpdateImportPolicy { .. } => "UpdateImportPolicy",
        PeerCommand::SendRouteRefresh { .. } => "SendRouteRefresh",
        PeerCommand::QueryImportPolicyTermHits { .. } => "QueryImportPolicyTermHits",
        PeerCommand::ReplayOutbound { .. } => "ReplayOutbound",
        _ => "other",
    }
}

fn answer_session(command: PeerCommand, addr: IpAddr, established: bool, fail: bool) {
    let failed = || {
        Err(rustbgpd_transport::PeerCommandError::CommandFailed(
            "test: injected failure".to_string(),
        ))
    };
    match command {
        PeerCommand::QueryState { reply } => {
            let mut state = policy_test_peer_state(
                addr,
                if established {
                    SessionState::Established
                } else {
                    SessionState::Idle
                },
            );
            state.negotiated_session = established.then(|| test_negotiated_session(true));
            let _ = reply.send(state);
        }
        PeerCommand::UpdateExportPolicy { reply, .. }
        | PeerCommand::UpdateImportPolicy { reply, .. }
        | PeerCommand::ReplayOutbound { reply }
        | PeerCommand::UpdateRuntimeConfig { reply, .. }
        | PeerCommand::UpdateGracefulShutdown { reply, .. }
        | PeerCommand::SendRouteRefresh { reply, .. } => {
            let _ = reply.send(if fail { failed() } else { Ok(()) });
        }
        PeerCommand::QueryImportPolicyTermHits { reply } => {
            let _ = reply.send(Some(ImportPolicyTermHits {
                generation: 1,
                evals: 0,
                eval_errors: 0,
                last_error: None,
                terms: Vec::new(),
            }));
        }
        _ => {}
    }
}

/// `parked`: the receiver holds at the gate before draining anything, with a
/// capacity of one so a pre-filled channel parks the next send.
fn spawn_session(
    addr: IpAddr,
    established: bool,
    gate: Gate,
    script: SessionScript,
    parked: bool,
) -> (PeerHandle, mpsc::Sender<PeerCommand>) {
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(if parked { 1 } else { 16 });
    let (publication, receiver) =
        tokio::sync::watch::channel(Some(installed_policy(1, Some(&PolicyChain::new(vec![])))));
    let commands = session_tx.clone();
    let task = tokio::spawn(async move {
        if parked {
            gate.hold().await;
        }
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        let mut stalled = Vec::new();
        let mut import_generation = 1;
        while let Some(command) = session_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
            let index = counts.entry(command_kind(&command)).or_default();
            let seen = *index;
            *index += 1;
            let action = script(&command, seen);
            if matches!(action, SessionAction::Answer)
                && let PeerCommand::UpdateImportPolicy { policy, .. } = &command
            {
                import_generation += 1;
                publication
                    .send_replace(Some(installed_policy(import_generation, policy.as_deref())));
            }
            match action {
                SessionAction::Answer => answer_session(command, addr, established, false),
                SessionAction::Fail => answer_session(command, addr, established, true),
                SessionAction::Stall => stalled.push(command),
                SessionAction::Hold => {
                    let gate = gate.clone();
                    tokio::spawn(async move {
                        gate.hold().await;
                        answer_session(command, addr, established, false);
                    });
                }
            }
        }
        drop(publication);
        Ok(())
    });
    (
        PeerHandle::from_parts_with_import_policy_counters(session_tx, task, receiver),
        commands,
    )
}

fn dataset_policy_chain() -> PolicyChain {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::{AsnSet, SetStore};

    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::new(DatasetHandle::new(
        "customers",
        DatasetKind::Asn,
        DatasetData::Asn(AsnSet::new([64500])),
    )));
    let compiled = RpolFile::parse(
        "dataset asn-set customers\npolicy p { term t { if route.origin-as in customers { accept } } }",
    )
    .expect("dataset policy parses")
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .expect("policy compiles")
    .expect("dataset binding is complete");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )])
}

/// Reload configs for the compensating replay: the candidate gives the two
/// matrix peers an export chain (a cohort) and changes a third, policy-free
/// neighbor's session-bound `remote_asn` (a replace, which is rejected); the
/// manager's prior config is the same neighbors without either. The rpol file
/// lives in a directory kept alive for the row.
fn reload_config(dir: &std::path::Path, candidate: bool) -> Config {
    let export = if candidate {
        "export_policy_chain = [\"members-out\"]"
    } else {
        ""
    };
    load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = [{rpol:?}]

[[neighbors]]
address = "10.39.0.1"
remote_asn = 65002
{export}

[[neighbors]]
address = "10.39.0.2"
remote_asn = 65003
{export}

[[neighbors]]
address = "10.39.0.3"
remote_asn = {replaced_asn}
"#,
        rpol = dir.join("members.rpol").to_str().unwrap(),
        replaced_asn = if candidate { 65014 } else { 65004 },
    ))
}

pub(super) fn dataset_generation_config(dir: &std::path::Path) -> Config {
    let rpol = dir.join("members.rpol");
    let data = dir.join("customers.list");
    std::fs::write(&rpol, "dataset asn-set customers\npolicy members-out { term all { if route.origin-as in customers { accept } } }").unwrap();
    std::fs::write(&data, "64500\n").unwrap();
    let toml = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = [{rpol:?}]
[policy.datasets.customers]
path = {data:?}
[[neighbors]]
address = "10.39.0.1"
remote_asn = 65002
import_policy_chain = ["members-out"]
export_policy_chain = ["members-out"]
[[neighbors]]
address = "10.39.0.2"
remote_asn = 65003
import_policy_chain = ["members-out"]
export_policy_chain = ["members-out"]
[[neighbors]]
address = "10.39.0.3"
remote_asn = 65004
"#,
        rpol = rpol.to_str().unwrap(),
        data = data.to_str().unwrap()
    );
    let path = dir.join("rustbgpd.toml");
    std::fs::write(&path, tier_authorized_uds_test_config(&toml)).unwrap();
    Config::load_with_diagnostics(path.to_str().unwrap()).unwrap()
}

fn replay_fixture(prior: &Config) -> Config {
    let dir = prior
        .policy
        .rpol_files
        .first()
        .and_then(|path| std::path::Path::new(path).parent())
        .expect("the prior config names the rpol directory")
        .to_path_buf();
    reload_config(&dir, true)
}

fn target(address: IpAddr, import: bool, export: bool) -> ResolvedPeerPolicy {
    ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: import.then(deny_policy_chain),
        export_policy: export.then(deny_policy_chain),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the matrix drives the real policy and dataset generation entries, including compensation"
)]
async fn drive(manager: &mut PeerManager, drive: Drive, peers: [IpAddr; 2]) -> Result<(), String> {
    let (targets, clean) = match drive {
        Drive::ForwardCohort { import_delta, .. } => (
            peers
                .iter()
                .map(|&peer| target(peer, import_delta, true))
                .collect(),
            false,
        ),
        Drive::ForwardWalk { clean } => (vec![target(peers[0], false, true)], clean),
        Drive::Rfc8212Transition { .. } => (vec![target(peers[0], true, false)], false),
        Drive::ApiPolicyImpact | Drive::ApiPublicationCompensation => (
            peers
                .iter()
                .map(|&peer| target(peer, false, true))
                .collect(),
            false,
        ),
        Drive::CatalogPolicyRefresh
        | Drive::HonorGracefulShutdown
        | Drive::HonorBlackhole
        | Drive::CompensatingReplay
        | Drive::ValidationRefresh
        | Drive::DatasetRefresh
        | Drive::DatasetGeneration { .. }
        | Drive::RetainedStaleCapacity
        | Drive::ExportReplacementCapacity
        | Drive::DatasetExportCapacity { .. }
        | Drive::OutboundRefresh
        | Drive::HotExportKnobs
        | Drive::GracefulShutdown
        | Drive::OutboundReplay
        | Drive::MaxPrefixRestart
        | Drive::ConfiguredOwnerPublication
        | Drive::BfdReload => (Vec::new(), false),
    };
    match drive {
        Drive::ForwardCohort { .. }
        | Drive::ForwardWalk { .. }
        | Drive::Rfc8212Transition { .. } => manager
            .apply_resolved_policy_snapshot_with_prestage_reads(
                targets,
                clean,
                OperatorReadAdmission::Served,
            )
            .await
            .map(drop)
            .map_err(|failure| failure.message),
        Drive::ApiPolicyImpact => manager
            .apply_policy_impact_snapshot(targets, Vec::new())
            .await
            .map(drop),
        Drive::HonorGracefulShutdown => manager.set_honor_graceful_shutdown(true).await,
        Drive::HonorBlackhole => manager.set_honor_blackhole(true).await,
        Drive::CatalogPolicyRefresh => {
            use rustbgpd_api::peer_types::{
                ConfigEvent, NamedPolicyDefinition, OwnedCatalogMutationOutcome,
            };

            manager.current_config.neighbors = peers
                .into_iter()
                .map(|peer| {
                    let mut neighbor = config_neighbor(peer, 65002);
                    neighbor.export_policy_chain = vec!["edge-export".to_string()];
                    neighbor
                })
                .collect();
            match manager
                .apply_policy_change_owned(
                    ConfigEvent::SetPolicy {
                        name: "edge-export".to_string(),
                        definition: NamedPolicyDefinition {
                            default_action: "deny".to_string(),
                            statements: Vec::new(),
                        },
                        ack: None,
                    },
                    None,
                )
                .await
            {
                OwnedCatalogMutationOutcome::Success => Ok(()),
                outcome => Err(format!("catalog mutation failed: {outcome:?}")),
            }
        }
        Drive::ApiPublicationCompensation => manager
            .apply_resolved_policy_snapshot_with_prestage_reads(
                targets,
                false,
                OperatorReadAdmission::Served,
            )
            .await
            .map(drop)
            .map_err(|failure| failure.message),
        Drive::CompensatingReplay => {
            let candidate = replay_fixture(&manager.current_config);
            let actions = plan_reload_peer_actions(&manager.current_config, &candidate)
                .map_err(|error| error.to_string())?;
            match Box::pin(manager.apply_reload_generation(
                candidate,
                actions,
                PreparedDatasetGeneration::default(),
            ))
            .await
            {
                ReloadGenerationOutcome::Applied(receipt) => Err(format!(
                    "the rejected session replace must unwind the generation: {receipt}"
                )),
                ReloadGenerationOutcome::FullyCompensated(message) => Err(message),
                outcome => panic!("the replay must fully compensate: {outcome:?}"),
            }
        }
        Drive::ValidationRefresh => {
            manager
                .soft_reset_import_validation_dependents(ImportValidationDependency::Rpki)
                .await
        }
        Drive::DatasetRefresh => {
            manager
                .refresh_dataset_dependents(&["customers".to_string()], &[])
                .await
        }
        Drive::DatasetGeneration { compensate } => {
            let dir = std::path::Path::new(&manager.current_config.policy.rpol_files[0])
                .parent()
                .unwrap();
            std::fs::write(dir.join("customers.list"), "64500\n64999\n").unwrap();
            let mut candidate = Config::load_with_diagnostics_and_staged_datasets(
                dir.join("rustbgpd.toml").to_str().unwrap(),
                &manager.current_config.policy.dataset_bindings,
            )
            .unwrap();
            if compensate {
                candidate.neighbors[2].remote_asn = 65014;
            }
            let staged =
                candidate.prepare_staged_datasets(&manager.current_config.policy.dataset_bindings);
            let prepared = staged
                .prepare_generation(&manager.current_config, &candidate)
                .unwrap();
            let actions = plan_reload_peer_actions(&manager.current_config, &candidate).unwrap();
            let outcome =
                Box::pin(manager.apply_reload_generation(candidate, actions, prepared)).await;
            assert!(
                if compensate {
                    matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_))
                } else {
                    matches!(outcome, ReloadGenerationOutcome::Applied(_))
                },
                "{outcome:?}"
            );
            Ok(())
        }
        Drive::RetainedStaleCapacity => manager.query_peer_retained_stale(
            peers[0], None, OperatorReadAdmission::Served).await.map(drop).map_err(|e| e.to_string()),
        Drive::ExportReplacementCapacity => manager.replace_peer_export_policy_in_rib(
            peers[0], Some(deny_policy_chain()), None, OperatorReadAdmission::Served).await.map_err(|e| e.to_string()),
        Drive::DatasetExportCapacity { failed_restore } => manager.reevaluate_dataset_exports(
            peers.to_vec(), false, if failed_restore { OperatorReadAdmission::Fenced {
                reason: "an earlier failed restoration retains its fence while awaiting capacity",
            }} else { OperatorReadAdmission::Served }, false).await.map_err(|e| e.to_string()),
        Drive::MaxPrefixRestart => {
            manager.handle_due_max_prefix_restarts().await;
            Ok(())
        }
        Drive::OutboundRefresh => manager
            .refresh_outbound(key(peers[0]))
            .await
            .map_err(|error| error.to_string()),
        Drive::HotExportKnobs => {
            let peer = key(peers[0]);
            let mut config = PeerManager::removed_peer_config(&peer, &manager.peers[&peer]);
            config.remove_private_as = rustbgpd_transport::RemovePrivateAs::All;
            manager
                .hot_update_peer_in_place(config)
                .await
                .map_err(|error| error.to_string())
        }
        Drive::GracefulShutdown => manager
            .set_graceful_shutdown(Some(key(peers[0])), true)
            .await
            .map_err(|error| error.to_string()),
        Drive::OutboundReplay => replay_outbound_result(manager, key(peers[0]))
            .await
            .map_err(|error| error.to_string()),
        Drive::ConfiguredOwnerPublication => {
            use rustbgpd_api::peer_types::ConfiguredOwnerPublicationOperation as Publication;
            let receipt = manager
                .configured_owner_publication(Publication::Begin)
                .await
                .map_err(|error| error.to_string())?;
            let published = manager
                .configured_owner_publication(Publication::Publish(receipt))
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(published, receipt);
            Ok(())
        }
        Drive::BfdReload => {
            let coupling = manager.bfd_coupling.as_mut().unwrap();
            let mut replacement = bfd_session(peers[0]);
            replacement.revision = 1;
            coupling.pending = Some(std::collections::HashMap::from([(peers[0], replacement)]));
            coupling.reloading = true;
            manager.commit_bfd_reload(None).await
        }
    }
}

fn bfd_session(peer: IpAddr) -> crate::bfd_runtime::BfdSessionParams {
    crate::bfd_runtime::BfdSessionParams {
        revision: 0,
        peer,
        scope_id: None,
        destination: crate::bfd_runtime::bfd_destination(peer, None, false)
            .expect("global test peer destination"),
        desired_min_tx_us: 300_000,
        required_min_rx_us: 300_000,
        detect_mult: 3,
        strict: false,
        enabled: true,
        multihop: false,
        source: None,
    }
}

/// Attach BFD coupling for `peer` with a BFD actor stub that parks each
/// reload acknowledgement on `gate`.
fn attach_held_bfd_actor(manager: PeerManager, peer: IpAddr, gate: Gate) -> PeerManager {
    let (desired_tx, _desired_rx) =
        tokio::sync::watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
            gate.hold().await;
            let acks = command
                .desired
                .sessions
                .iter()
                .filter(|params| params.enabled)
                .map(|params| crate::bfd_runtime::BfdStateChange {
                    revision: params.revision,
                    peer: params.peer,
                    state: rustbgpd_bfd::SessionState::Down,
                    diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
                    remote_admin_down: false,
                    resync: true,
                })
                .collect();
            let _ = command.reply.send(acks);
        }
    });
    manager
        .with_bfd_coupling(
            desired_tx,
            state_rx,
            std::collections::HashMap::from([(peer, bfd_session(peer))]),
        )
        .with_bfd_reload(reload_tx)
}

async fn list_peers(
    operator_tx: &mpsc::Sender<EnqueuedOperatorQuery>,
) -> oneshot::Receiver<Vec<PeerInfo>> {
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    response
}

async fn has_peer_address(
    operator_tx: &mpsc::Sender<EnqueuedOperatorQuery>,
    address: IpAddr,
) -> oneshot::Receiver<bool> {
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
        .await
        .unwrap();
    response
}

#[expect(
    clippy::too_many_lines,
    reason = "one driver runs every row: setup, hold, probe, release, and completion stay together"
)]
async fn run(row: &WaitSite) {
    let site = row.site;
    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 2));
    let gate = Gate::new();
    let cohort_reply = match row.drive {
        Drive::ForwardCohort { cohort_reply, .. } => cohort_reply,
        _ => CohortReply::Committed,
    };
    let rib_capacity = if matches!(row.rib, RibHold::Receiver(_) | RibHold::Capacity) {
        1
    } else {
        16
    };
    let (rib_tx, rib_rx) = mpsc::channel(rib_capacity);
    let rib = spawn_rib(rib_rx, gate.clone(), row.rib, cohort_reply);
    if matches!(row.rib, RibHold::Capacity) {
        let (reply, _response) = oneshot::channel();
        rib_tx
            .try_send(RibUpdate::QueryPeerRetainedStale { peer: first, reply })
            .unwrap();
        assert_eq!(rib_tx.capacity(), 0);
    }
    let (command_tx, command_rx) = mpsc::channel(16);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx)
    .with_readiness_queries(readiness_rx);

    let first_established = !matches!(row.drive, Drive::Rfc8212Transition { established: false });
    let parked = matches!(row.drive, Drive::MaxPrefixRestart);
    let (handle, first_commands) =
        spawn_session(first, first_established, gate.clone(), row.session, parked);
    insert_test_managed_peer_with_asn(&mut manager, first, 65002, handle, false);
    let (handle, _) = spawn_session(second, true, gate.clone(), answer_all, false);
    insert_test_managed_peer_with_asn(&mut manager, second, 65003, handle, false);
    let _rpol_dir = match row.drive {
        Drive::CompensatingReplay => {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("members.rpol"),
                "policy members-out { term all { set med 20; accept } }",
            )
            .unwrap();
            manager.replace_current_config(reload_config(dir.path(), false));
            let replaced = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 3));
            let (handle, _) = spawn_session(replaced, true, gate.clone(), answer_all, false);
            insert_test_managed_peer_with_asn(&mut manager, replaced, 65004, handle, false);
            manager.inject_reconfigure_failures.insert(key(replaced), 0);
            Some(dir)
        }
        Drive::DatasetGeneration { compensate } => {
            let dir = tempfile::tempdir().unwrap();
            manager.replace_current_config(dataset_generation_config(dir.path()));
            for peer in [first, second] {
                let neighbor = manager
                    .current_config
                    .neighbors
                    .iter()
                    .find(|n| n.address == peer.to_string())
                    .unwrap();
                let resolved = manager.current_config.resolve_neighbor(neighbor).unwrap();
                let entry = manager.peers.get_mut(&key(peer)).unwrap();
                entry.import_policy = resolved.import_policy;
                entry.export_policy = resolved.export_policy;
            }
            let third = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 3));
            let (handle, _) = spawn_session(third, true, gate.clone(), answer_all, false);
            insert_test_managed_peer_with_asn(&mut manager, third, 65004, handle, false);
            if compensate {
                manager.inject_reconfigure_failures.insert(key(third), 0);
            }
            Some(dir)
        }
        _ => None,
    };
    match row.drive {
        Drive::Rfc8212Transition { .. } => {
            manager.peers.get_mut(&key(first)).unwrap().import_policy =
                Some(crate::config::reserved_rfc8212_deny_chain(
                    crate::config::RFC8212_MISSING_IMPORT_POLICY,
                ));
        }
        Drive::ValidationRefresh => {
            for peer in [first, second] {
                manager.peers.get_mut(&key(peer)).unwrap().import_policy =
                    Some(validation_policy_chain(ImportValidationDependency::Rpki));
            }
        }
        Drive::DatasetRefresh => {
            for peer in [first, second] {
                let dependent = manager.peers.get_mut(&key(peer)).unwrap();
                dependent.import_policy = Some(dataset_policy_chain());
                dependent.export_policy = Some(dataset_policy_chain());
            }
        }
        Drive::MaxPrefixRestart => {
            let session_id = manager.peers[&key(first)].session_id();
            let latched = manager.peers.get_mut(&key(first)).unwrap();
            latched.enabled = false;
            latched.max_prefix_restart_seconds = Some(1);
            assert!(manager.install_max_prefix_latch(
                key(first),
                session_id,
                "test: max-prefix".to_string(),
                Some(1),
            ));
            manager
                .max_prefix_latches
                .get_mut(&key(first))
                .unwrap()
                .deadline = Some(tokio::time::Instant::now());
            // Fill the parked session's single slot so the Start send parks.
            first_commands
                .try_send(PeerCommand::Start)
                .expect("the parked session channel has one free slot");
        }
        Drive::ForwardCohort { .. }
        | Drive::ForwardWalk { .. }
        | Drive::ApiPolicyImpact
        | Drive::CatalogPolicyRefresh
        | Drive::HonorGracefulShutdown
        | Drive::HonorBlackhole
        | Drive::ApiPublicationCompensation
        | Drive::CompensatingReplay
        | Drive::DatasetGeneration { .. }
        | Drive::RetainedStaleCapacity
        | Drive::ExportReplacementCapacity
        | Drive::DatasetExportCapacity { .. }
        | Drive::OutboundRefresh
        | Drive::HotExportKnobs
        | Drive::GracefulShutdown
        | Drive::OutboundReplay
        | Drive::ConfiguredOwnerPublication => {}
        Drive::BfdReload => {
            manager = attach_held_bfd_actor(manager, first, gate.clone());
        }
    }

    let import_roster = manager.import_roster();
    let peers = [first, second];
    let drive_kind = row.drive;
    let transaction = tokio::spawn(async move {
        let result = drive(&mut manager, drive_kind, peers).await;
        (manager, result)
    });

    if let Contract::Unreachable { why } = row.contract {
        // Nothing can hold the site: prove the transaction passes through it
        // without a release.
        let (mut manager, result) = tokio::time::timeout(HELD_FOREVER, transaction)
            .await
            .unwrap_or_else(|_| {
                panic!("{site}: an unreachable site parked the transaction ({why})")
            })
            .unwrap();
        check_completion(row, &mut manager, result).await;
        drop(manager);
        rib.await.unwrap();
        return;
    }

    tokio::time::timeout(Duration::from_mins(5), gate.held())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{site}: the stub never parked the transaction on {}",
                row.awaits
            )
        });
    // Capacity rows call the exact helper directly; no earlier admitted
    // probe can satisfy the reads intended for its reserve wait.
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    let (mutation_reply, mut mutation_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::SyncExplainConfig {
            enabled: false,
            cache_size: 17,
            reject_retention_enabled: true,
            reject_retention_capacity: 1024,
            reply: mutation_reply,
        })
        .await
        .unwrap();
    let expected = if matches!(
        row.drive,
        Drive::DatasetGeneration { .. } | Drive::CompensatingReplay
    ) {
        3
    } else {
        2
    };
    // Import statistics read the published roster at every site, served or
    // fenced: they never wait for the parked owner (ADR-0136).
    let rows = tokio::time::timeout(HALF_QUERY, roster_import_rows(&import_roster))
        .await
        .unwrap_or_else(|_| panic!("{site}: import stats waited for the parked owner"));
    // A session whose drive installed no import chain adds no row.
    assert!(
        matches!(rows, Ok(ref rows) if !rows.is_empty() && rows.len() <= expected),
        "{site}: {rows:?}"
    );
    let read_deadline = tokio::time::Instant::now() + row.window;
    let mut infos = list_peers(&operator_tx).await;
    let mut known = has_peer_address(&operator_tx, first).await;
    // Readiness is served at every parked site, fenced or not.
    let (reply, response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    tokio::time::timeout_at(read_deadline, response)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{site}: a readiness ping must be served while {} is awaited",
                row.awaits
            )
        })
        .unwrap();
    match row.contract {
        Contract::Served => {
            let infos = tokio::time::timeout_at(read_deadline, &mut infos)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{site}: a neighbor snapshot must be served while {} is awaited",
                        row.awaits
                    )
                })
                .unwrap();
            assert_eq!(infos.len(), expected, "{site}");
            let known = tokio::time::timeout_at(read_deadline, &mut known)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{site}: a peer lookup must be served while {} is awaited",
                        row.awaits
                    )
                })
                .unwrap();
            assert!(known, "{site}");
        }
        Contract::Fenced { reason } => {
            assert!(
                tokio::time::timeout(row.window, &mut infos).await.is_err(),
                "{site}: a neighbor snapshot was served while {} is awaited, but the row says \
                 the site is fenced ({reason}); flip the row if that is now intended",
                row.awaits
            );
            assert!(
                tokio::time::timeout(Duration::ZERO, &mut known)
                    .await
                    .is_err(),
                "{site}: a peer lookup was served at a fenced site"
            );
        }
        Contract::Unreachable { .. } => unreachable!(),
    }
    assert!(
        !transaction.is_finished(),
        "{site}: the transaction must still be parked on {}",
        row.awaits
    );

    assert!(
        matches!(
            mutation_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "{site}: queued mutation must remain behind its owner"
    );
    gate.release();
    let (mut manager, result) = tokio::time::timeout(Duration::from_mins(5), transaction)
        .await
        .unwrap_or_else(|_| panic!("{site}: the transaction did not complete after release"))
        .unwrap();
    check_completion(row, &mut manager, result).await;
    drop(operator_tx);
    drop(manager);
    rib.await.unwrap();
}

async fn check_completion(row: &WaitSite, manager: &mut PeerManager, result: Result<(), String>) {
    let site = row.site;
    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1));
    let first_peer = &manager.peers[&key(first)];
    match row.completion {
        Completion::ExportApplied => {
            assert!(result.is_ok(), "{site}: {result:?}");
            assert_eq!(
                first_peer.export_policy,
                Some(if matches!(row.drive, Drive::CatalogPolicyRefresh) {
                    named_deny_policy_chain(&[Some("edge-export")])
                } else {
                    deny_policy_chain()
                }),
                "{site}"
            );
        }
        Completion::ImportApplied => {
            assert!(result.is_ok(), "{site}: {result:?}");
            assert_eq!(
                first_peer.import_policy,
                Some(deny_policy_chain()),
                "{site}"
            );
        }
        Completion::ExportRestored => {
            let error = result.expect_err(site);
            assert_eq!(first_peer.export_policy, None, "{site}: {error}");
            if let Contract::Unreachable { .. } = row.contract {
                assert!(
                    error.contains(
                        RuntimeConfigPolicyFailureCode::RollbackBatchUnavailable.as_str()
                    ),
                    "{site}: the failed-enqueue arm must report the unavailable batch: {error}"
                );
            }
        }
        Completion::Finished => assert!(result.is_ok(), "{site}: {result:?}"),
        Completion::PeerEnabled => {
            assert!(result.is_ok(), "{site}: {result:?}");
            assert!(
                first_peer.enabled,
                "{site}: the released Start must re-enable the peer"
            );
        }
    }
    for (_, managed) in manager.peers.drain() {
        let _ =
            tokio::time::timeout(Duration::from_secs(5), managed.into_parts().0.shutdown()).await;
    }
}

#[tokio::test(start_paused = true)]
async fn every_wait_site_honours_its_operator_read_contract() {
    for row in WAIT_SITES {
        tokio::time::timeout(Duration::from_mins(15), run(row))
            .await
            .unwrap_or_else(|_| panic!("{}: the row did not complete", row.site));
    }
}

/// Call sites of the wait helpers per enclosing function, excluding the
/// helper definitions themselves.
fn wait_call_sites(file: &str, source: &str) -> BTreeMap<String, usize> {
    const HELPERS: [&str; 2] = ["await_with_readiness", "await_with_readiness_budget"];
    let mut sites = BTreeMap::new();
    let mut current = "<none>";
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().take(5).collect();
        if let Some(name) = tokens
            .iter()
            .position(|token| *token == "fn")
            .and_then(|position| tokens.get(position + 1))
        {
            current = name
                .split(['(', '<'])
                .next()
                .expect("split yields at least one piece");
        }
        let calls = trimmed.matches(".await_with_readiness").count();
        if calls > 0 && !HELPERS.contains(&current) {
            *sites.entry(format!("{file}::{current}")).or_default() += calls;
        }
    }
    sites
}

/// A new actor wait-helper call site must get a row in `WAIT_SITES`
/// stating whether operator reads are served or fenced there, and why. Rows
/// that re-exercise a covered site through another entry point
/// (`additional_entry`) are not counted, so each site is keyed once.
#[test]
fn wait_site_table_covers_every_call_site() {
    // Scan every production source file of the module, so a new file cannot
    // escape the guard. `read_dir` is not recursive: `tests/` holds only test
    // drivers, which make no actor waits of their own.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/peer_manager");
    let mut sources = BTreeMap::new();
    let mut scanned = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let file = path.file_name().unwrap().to_str().unwrap().to_owned();
            sources.extend(wait_call_sites(
                &file,
                &std::fs::read_to_string(&path).unwrap(),
            ));
            scanned.insert(file);
        }
    }
    assert!(
        ["mod.rs", "policy.rs", "configured_owners.rs"]
            .iter()
            .all(|file| scanned.contains(*file)),
        "the scan must cover the module's source files: {scanned:?}"
    );
    let mut table = BTreeMap::new();
    for row in WAIT_SITES
        .iter()
        .filter(|row| row.additional_entry.is_none())
    {
        *table.entry(row.site.to_string()).or_default() += 1_usize;
    }
    assert_eq!(
        sources, table,
        "every actor wait-helper call site needs exactly one WAIT_SITES row keyed by \
         file::enclosing_fn (left: call sites in the source, right: table rows); add a row \
         stating whether operator reads are served or fenced at the new site, and why"
    );
}

/// Each session is healthy within its unchanged command/probe budget, but
/// their serial walk exceeds an operator RPC deadline. Probe the real owner
/// before the first acknowledgement, then require a complete read before
/// the walk ends and keep an ordinary mutation queued throughout.
#[expect(
    clippy::too_many_lines,
    reason = "one receipt keeps healthy serial sessions, held acknowledgement, read completion, and owner settlement together"
)]
async fn serial_policy_walk_serves_reads(drive_kind: Drive, preflight: bool) {
    let cohort = matches!(drive_kind, Drive::ForwardCohort { .. });
    let honor = matches!(
        drive_kind,
        Drive::HonorGracefulShutdown | Drive::HonorBlackhole
    );
    let count = if preflight { 32 } else { 8 };
    let gate = Gate::new();
    let (rib_tx, rib_rx) = mpsc::channel(16);
    let rib = spawn_rib(rib_rx, gate.clone(), RibHold::None, CohortReply::Committed);
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    let mut targets = Vec::new();
    let installs = Arc::new(AtomicUsize::new(0));
    for index in 0..count {
        let address = IpAddr::V4(Ipv4Addr::new(10, 39, 1, u8::try_from(index + 1).unwrap()));
        let (commands, mut receiver) = mpsc::channel::<PeerCommand>(16);
        let (publication, counters) =
            tokio::sync::watch::channel(Some(installed_policy(1, Some(&PolicyChain::new(vec![])))));
        let started = gate.held.clone();
        let installs = installs.clone();
        let task = tokio::spawn(async move {
            let mut import_generation = 1;
            while let Some(command) = receiver.recv().await {
                match command {
                    PeerCommand::Shutdown => break,
                    command @ PeerCommand::QueryState { .. } if preflight => {
                        started.notify_one();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(80)).await;
                            answer_session(command, address, true, false);
                        });
                    }
                    command @ (PeerCommand::UpdateImportPolicy { .. }
                    | PeerCommand::UpdateExportPolicy { .. }) => {
                        started.notify_one();
                        if !preflight {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                        installs.fetch_add(1, Ordering::SeqCst);
                        if let PeerCommand::UpdateImportPolicy { policy, .. } = &command {
                            import_generation += 1;
                            publication.send_replace(Some(installed_policy(
                                import_generation,
                                policy.as_deref(),
                            )));
                        }
                        answer_session(command, address, true, false);
                    }
                    command => answer_session(command, address, true, false),
                }
            }
            drop(publication);
            Ok(())
        });
        insert_test_managed_peer(
            &mut manager,
            address,
            PeerHandle::from_parts_with_import_policy_counters(commands, task, counters),
            false,
        );
        if !preflight && !honor {
            manager.current_config.global.ebgp_requires_policy = Some(true);
            let entry = manager.peers.get_mut(&key(address)).unwrap();
            entry.rfc8212_external = true;
            entry.export_policy = Some(crate::config::reserved_rfc8212_deny_chain(
                crate::config::RFC8212_MISSING_EXPORT_POLICY,
            ));
        }
        if preflight && !cohort {
            manager.peers.get_mut(&key(address)).unwrap().import_policy =
                Some(crate::config::reserved_rfc8212_deny_chain(
                    crate::config::RFC8212_MISSING_IMPORT_POLICY,
                ));
        }
        targets.push(ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: (preflight && !cohort).then(deny_policy_chain),
            export_policy: (!preflight || cohort).then(|| {
                if cohort {
                    deny_policy_chain()
                } else {
                    distinct_deny_policy_chain(index)
                }
            }),
        });
    }
    let import_roster = manager.import_roster();
    let started = tokio::time::Instant::now();
    let transaction = tokio::spawn(async move {
        let result = if honor {
            drive(
                &mut manager,
                drive_kind,
                [targets[0].address, targets[1].address],
            )
            .await
        } else {
            manager
                .apply_resolved_policy_snapshot_with_prestage_reads(
                    targets,
                    false,
                    OperatorReadAdmission::Served,
                )
                .await
                .map(drop)
                .map_err(|failure| failure.message)
        };
        (manager, result)
    });
    gate.held().await;
    let (reply, mut mutation) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::SyncExplainConfig {
            enabled: false,
            cache_size: 17,
            reject_retention_enabled: true,
            reject_retention_capacity: 1024,
            reply,
        })
        .await
        .unwrap();
    let mut infos = list_peers(&operator_tx).await;
    if !preflight {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut infos)
                .await
                .is_err(),
            "reads stay queued while the first session acknowledgement is held"
        );
        assert_eq!(installs.load(Ordering::SeqCst), 0);
    }
    let infos = tokio::time::timeout(READER_DEADLINE, infos)
        .await
        .expect("neighbor read finishes during the walk")
        .unwrap();
    assert_eq!(infos.len(), count);
    assert!(infos.iter().all(|info| !info.stale));
    if !preflight {
        assert_eq!(installs.load(Ordering::SeqCst), 1);
    }
    if !preflight && !honor {
        assert_eq!(
            infos
                .iter()
                .filter(|info| info.rfc8212_export_policy
                    == rustbgpd_api::peer_types::Rfc8212PolicyStatus::Present)
                .count(),
            1,
            "the acknowledged session and managed policy bookkeeping advance together before read service"
        );
    }
    let rows = tokio::time::timeout(READER_DEADLINE, roster_import_rows(&import_roster))
        .await
        .expect("complete import stats finish during the walk");
    assert!(matches!(rows, Ok(ref rows) if rows.len() == count));
    assert!(
        !transaction.is_finished(),
        "read must finish while the owner still walks"
    );
    assert!(matches!(
        mutation.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let (mut manager, result) = tokio::time::timeout(Duration::from_secs(20), transaction)
        .await
        .unwrap()
        .unwrap();
    result.expect("every session and RIB step succeeds");
    if honor {
        assert_eq!(installs.load(Ordering::SeqCst), count);
        assert!(if matches!(drive_kind, Drive::HonorBlackhole) {
            manager.current_config.global.honor_blackhole
        } else {
            manager.current_config.global.honor_graceful_shutdown
        });
        assert!(
            manager
                .peers
                .values()
                .all(|peer| peer.import_policy.is_some())
        );
    }
    assert!(
        started.elapsed() > READER_DEADLINE,
        "walk must exceed an operator deadline"
    );
    for (_, managed) in manager.peers.drain() {
        managed.into_parts().0.shutdown().await.unwrap().unwrap();
    }
    drop(manager);
    rib.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn successful_hot_apply_walk_serves_reads_between_acknowledged_peers() {
    for drive in [Drive::ForwardWalk { clean: false }, FORWARD_COHORT] {
        serial_policy_walk_serves_reads(drive, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn successful_preflight_and_selection_walks_serve_reads_before_completion() {
    for drive in [Drive::ForwardWalk { clean: false }, FORWARD_COHORT] {
        serial_policy_walk_serves_reads(drive, true).await;
    }
}

#[tokio::test(start_paused = true)]
async fn honor_graceful_shutdown_fanout_serves_reads_between_acknowledged_peers() {
    serial_policy_walk_serves_reads(Drive::HonorGracefulShutdown, false).await;
}

#[tokio::test(start_paused = true)]
async fn honor_blackhole_fanout_serves_reads_between_acknowledged_peers() {
    serial_policy_walk_serves_reads(Drive::HonorBlackhole, false).await;
}

#[tokio::test(start_paused = true)]
async fn legacy_dataset_refresh_bounds_capacity_and_reports_every_export_failure() {
    for full_channel in [true, false] {
        let (mut manager, _) = rfc8212_status_manager();
        let (rib_tx, rib_rx) = mpsc::channel(1);
        let mut receiver = Some(rib_rx);
        let peers = [
            "10.39.2.1".parse::<IpAddr>().unwrap(),
            "10.39.2.2".parse().unwrap(),
        ];
        if full_channel {
            let (reply, _response) = oneshot::channel();
            rib_tx
                .try_send(RibUpdate::QueryPeerRetainedStale {
                    peer: peers[0],
                    reply,
                })
                .unwrap();
        }
        manager.rib_tx = rib_tx;
        for peer in peers {
            let (handle, _) = spawn_session(peer, true, Gate::new(), answer_all, false);
            insert_test_managed_peer(&mut manager, peer, handle, false);
            manager.peers.get_mut(&key(peer)).unwrap().export_policy = Some(dataset_policy_chain());
        }
        let rib = (!full_channel).then(|| {
            let mut receiver = receiver.take().unwrap();
            tokio::spawn(async move {
                let RibUpdate::ReevaluatePeerExportPolicies { peers, reply } =
                    receiver.recv().await.unwrap()
                else {
                    panic!("legacy refresh must use the shared dataset reevaluation command")
                };
                assert_eq!(peers.len(), 2);
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "test: accepted reevaluation failed",
                    )))
                    .unwrap();
            })
        });
        let started = tokio::time::Instant::now();
        let failure = manager
            .refresh_dataset_dependents(&["customers".into()], &[])
            .await
            .unwrap_err();
        assert!(failure.contains("2 of 2"), "{failure}");
        for peer in peers {
            assert!(failure.contains(&format!("{peer} (export)")), "{failure}");
        }
        if full_channel {
            assert_eq!(started.elapsed(), RIB_REPLY_TIMEOUT);
            assert!(
                failure.contains("capacity deadline before dispatch"),
                "{failure}"
            );
            let receiver = receiver.as_mut().unwrap();
            assert!(matches!(
                receiver.try_recv(),
                Ok(RibUpdate::QueryPeerRetainedStale { .. })
            ));
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        } else {
            assert!(
                failure.contains("accepted reevaluation failed"),
                "{failure}"
            );
            rib.unwrap().await.unwrap();
        }
        for (_, managed) in manager.peers.drain() {
            managed.into_parts().0.shutdown().await.unwrap().unwrap();
        }
    }
}

/// The session never answers a state query, so an admitted neighbor
/// snapshot spends its whole `PEER_QUERY_TIMEOUT` inside the owner's wait.
fn stall_state(command: &PeerCommand, _: usize) -> SessionAction {
    match command {
        PeerCommand::QueryState { .. } => SessionAction::Stall,
        _ => SessionAction::Answer,
    }
}

/// Advance to just before the owner's five-second deadline, then admit a
/// single-peer read whose stalled session query carries the owner past it.
/// `GetPeerState` is always served in place, unlike a detached `ListPeers`.
async fn admit_snapshot_across_deadline(
    operator_tx: &mpsc::Sender<EnqueuedOperatorQuery>,
    peer: IpAddr,
) -> oneshot::Receiver<Option<PeerInfo>> {
    tokio::time::advance(RIB_REPLY_TIMEOUT.saturating_sub(PEER_QUERY_TIMEOUT / 2)).await;
    let (reply, infos) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::GetPeerState {
                peer: key(peer),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(PEER_QUERY_TIMEOUT * 3 / 4).await;
    infos
}

#[tokio::test(start_paused = true)]
async fn expired_capacity_wait_finishes_its_admitted_read_without_late_dispatch() {
    for drive_kind in [
        Drive::RetainedStaleCapacity,
        Drive::ExportReplacementCapacity,
        Drive::DatasetExportCapacity {
            failed_restore: false,
        },
    ] {
        let peer = "10.39.3.1".parse::<IpAddr>().unwrap();
        let gate = Gate::new();
        let (mut manager, _) = rfc8212_status_manager();
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let (reply, _response) = oneshot::channel();
        rib_tx
            .try_send(RibUpdate::QueryPeerRetainedStale { peer, reply })
            .unwrap();
        manager.rib_tx = rib_tx;
        let (operator_tx, operator_rx) = mpsc::channel(4);
        manager = manager.with_operator_queries(operator_rx);
        let (handle, _) = spawn_session(peer, true, gate.clone(), stall_state, false);
        insert_test_managed_peer(&mut manager, peer, handle, false);
        let transaction = tokio::spawn(async move {
            let result = drive(&mut manager, drive_kind, [peer, peer]).await;
            (manager, result)
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        let infos = admit_snapshot_across_deadline(&operator_tx, peer).await;
        assert!(
            !transaction.is_finished(),
            "owner expiry must not abandon an admitted read"
        );
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::QueryPeerRetainedStale { .. })
        ));
        let infos = tokio::time::timeout(PEER_QUERY_TIMEOUT, infos)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(infos, Some(ref info) if info.stale));
        let (mut manager, result) = transaction.await.unwrap();
        assert!(
            result.is_err(),
            "expired capacity must reject before dispatch"
        );
        assert!(matches!(
            rib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        for (_, managed) in manager.peers.drain() {
            managed.into_parts().0.shutdown().await.unwrap().unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn dataset_reply_preserves_legacy_wall_and_generation_attention_budgets() {
    for wall_reply_budget in [true, false] {
        let peer = "10.39.3.2".parse::<IpAddr>().unwrap();
        let gate = Gate::new();
        let (mut manager, _) = rfc8212_status_manager();
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        manager.rib_tx = rib_tx;
        let (operator_tx, operator_rx) = mpsc::channel(4);
        manager = manager.with_operator_queries(operator_rx);
        let (handle, _) = spawn_session(peer, true, gate.clone(), stall_state, false);
        insert_test_managed_peer(&mut manager, peer, handle, false);
        let transaction = tokio::spawn(async move {
            let result = manager
                .reevaluate_dataset_exports(
                    vec![peer],
                    false,
                    OperatorReadAdmission::Served,
                    wall_reply_budget,
                )
                .await;
            (manager, result)
        });
        let RibUpdate::ReevaluatePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected actual dataset reevaluation dispatch")
        };
        let infos = admit_snapshot_across_deadline(&operator_tx, peer).await;
        assert!(
            !transaction.is_finished(),
            "owner waits for the admitted read even after wall expiry"
        );
        assert!(
            tokio::time::timeout(PEER_QUERY_TIMEOUT, infos)
                .await
                .unwrap()
                .is_ok()
        );
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        if wall_reply_budget {
            assert!(
                transaction.is_finished(),
                "legacy reply expires after five wall seconds"
            );
        } else {
            assert!(
                !transaction.is_finished(),
                "generation reply still has attended budget left"
            );
            reply.send(Ok(())).unwrap();
        }
        let (mut manager, result) = transaction.await.unwrap();
        assert_eq!(result.is_err(), wall_reply_budget);
        for (_, managed) in manager.peers.drain() {
            managed.into_parts().0.shutdown().await.unwrap().unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Detached neighbor snapshots at transaction waits (ADR-0132, 2026-10-10
// amendment). Paused time: every step is a channel handshake, and nothing
// awaits an idle runtime while a session reply is held, so the 100 ms query
// deadline cannot elapse unless a test means it to.

/// A session whose commands the test observes in dequeue order. While
/// `hold` is set, the task hands each command to the test and dequeues the
/// next one only after the test resumes it; otherwise it answers normally.
struct ObservedSession {
    commands: mpsc::Sender<PeerCommand>,
    observed: mpsc::UnboundedReceiver<(PeerCommand, oneshot::Sender<()>)>,
    hold: Arc<AtomicBool>,
}

impl ObservedSession {
    fn queued(&self) -> usize {
        self.commands.max_capacity() - self.commands.capacity()
    }
}

fn spawn_observed_session(addr: IpAddr, capacity: usize) -> (PeerHandle, ObservedSession) {
    let (commands, mut rx) = mpsc::channel::<PeerCommand>(capacity);
    let (observed_tx, observed) = mpsc::unbounded_channel();
    let hold = Arc::new(AtomicBool::new(false));
    let task_hold = Arc::clone(&hold);
    let (publication, receiver) =
        tokio::sync::watch::channel(Some(installed_policy(1, Some(&PolicyChain::new(vec![])))));
    let task = tokio::spawn(async move {
        // The installed-policy publication lives as long as the session.
        let _publication = publication;
        while let Some(command) = rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
            if task_hold.load(Ordering::SeqCst) {
                let (resume, resumed) = oneshot::channel();
                if observed_tx.send((command, resume)).is_err() {
                    break;
                }
                let _ = resumed.await;
            } else {
                answer_session(command, addr, true, false);
            }
        }
        Ok(())
    });
    (
        PeerHandle::from_parts_with_import_policy_counters(commands.clone(), task, receiver),
        ObservedSession {
            commands,
            observed,
            hold,
        },
    )
}

const DETACH_FIRST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 41, 0, 1));
const DETACH_SECOND: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 41, 0, 2));

/// A manager with two observed sessions and an operator lane of
/// `operator_capacity` (the detached-snapshot limit).
fn detach_fixture(
    rib_tx: mpsc::Sender<RibUpdate>,
    operator_capacity: usize,
    first_capacity: usize,
) -> (
    PeerManager,
    mpsc::Sender<EnqueuedOperatorQuery>,
    ObservedSession,
    ObservedSession,
) {
    let (_command_tx, command_rx) = mpsc::channel(16);
    let (operator_tx, operator_rx) = mpsc::channel(operator_capacity);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    let (handle, first) = spawn_observed_session(DETACH_FIRST, first_capacity);
    insert_test_managed_peer_with_asn(&mut manager, DETACH_FIRST, 65002, handle, false);
    let (handle, second) = spawn_observed_session(DETACH_SECOND, 16);
    insert_test_managed_peer_with_asn(&mut manager, DETACH_SECOND, 65003, handle, false);
    (manager, operator_tx, first, second)
}

fn row(infos: &[PeerInfo], addr: IpAddr) -> &PeerInfo {
    infos
        .iter()
        .find(|info| info.address == addr)
        .expect("every admission-time peer has a row")
}

/// Admit one `ListPeers` exactly as an owner's wait helper does.
async fn admit_list_peers(manager: &mut PeerManager) -> oneshot::Receiver<Vec<PeerInfo>> {
    let (reply, response) = oneshot::channel();
    manager
        .handle_waiting_operator_query(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await;
    response
}

/// Take the held session's next command, which must be a state query.
async fn held_state_query(
    session: &mut ObservedSession,
) -> (oneshot::Sender<PeerSessionState>, oneshot::Sender<()>) {
    let (command, resume) = session.observed.recv().await.expect("session alive");
    let PeerCommand::QueryState { reply } = command else {
        panic!(
            "expected the admitted QueryState, got {}",
            command_kind(&command)
        );
    };
    (reply, resume)
}

#[tokio::test(start_paused = true)]
async fn detached_snapshot_lets_the_reload_finish_while_a_session_reply_is_held() {
    let gate = Gate::new();
    let (rib_tx, rib_rx) = mpsc::channel(16);
    let rib = spawn_rib(
        rib_rx,
        gate.clone(),
        RibHold::Reply(is_cohort_replace),
        CohortReply::Committed,
    );
    let (manager, operator_tx, mut first, _second) = detach_fixture(rib_tx, 4, 16);
    let transaction = tokio::spawn(async move {
        let mut manager = manager;
        let result = drive(&mut manager, FORWARD_COHORT, [DETACH_FIRST, DETACH_SECOND]).await;
        (manager, result)
    });

    // The owner is parked on the cohort RIB reply; admit a neighbor read and
    // hold the first session's answer to it.
    gate.held().await;
    first.hold.store(true, Ordering::SeqCst);
    let mut infos = list_peers(&operator_tx).await;
    let (state_reply, resume) = held_state_query(&mut first).await;

    // Releasing the RIB reply completes the transaction although the read
    // is still waiting for that session.
    gate.release();
    let (manager, result) = transaction.await.unwrap();
    result.expect("the cohort transaction commits");
    assert!(
        matches!(infos.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "the owner must not wait for an admitted neighbor snapshot's session replies"
    );

    // A later owner command to the held session queues behind the query.
    let mutation = tokio::spawn(async move {
        let mut manager = manager;
        let result = manager
            .set_graceful_shutdown(Some(key(DETACH_FIRST)), true)
            .await;
        (manager, result)
    });
    while first.queued() == 0 {
        tokio::task::yield_now().await;
    }
    assert!(
        first.observed.try_recv().is_err(),
        "the session dequeued a later owner command before answering the admitted query"
    );
    let mut answered = policy_test_peer_state(DETACH_FIRST, SessionState::Established);
    answered.updates_sent = 7;
    state_reply.send(answered).unwrap();
    resume.send(()).unwrap();

    let (command, resume) = first.observed.recv().await.unwrap();
    let PeerCommand::UpdateGracefulShutdown { enabled, reply } = command else {
        panic!("expected the graceful-shutdown update");
    };
    assert!(enabled);
    reply.send(Ok(())).unwrap();
    resume.send(()).unwrap();
    first.hold.store(false, Ordering::SeqCst);

    let infos = infos.await.expect("the detached snapshot replies");
    assert_eq!(infos.len(), 2);
    let held = row(&infos, DETACH_FIRST);
    assert!(!held.stale, "the held session answered within its deadline");
    assert_eq!(
        held.updates_sent, 7,
        "session half: the answer to the admitted query"
    );
    assert!(
        !held.graceful_shutdown_advertise_intent,
        "manager half: the value at admission, before the later command"
    );
    assert!(!row(&infos, DETACH_SECOND).stale);

    let (manager, result) = mutation.await.unwrap();
    result.expect("graceful-shutdown toggle");
    assert!(manager.peers[&key(DETACH_FIRST)].advertise_graceful_shutdown);
    drop(manager);
    rib.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn full_session_channel_serves_the_snapshot_in_place() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, _second) = detach_fixture(rib_tx, 4, 1);
    first.hold.store(true, Ordering::SeqCst);
    // One command parked in the session, one filling its only slot.
    let (parked, _parked_rx) = oneshot::channel();
    first
        .commands
        .try_send(PeerCommand::QueryState { reply: parked })
        .unwrap();
    let _held = first.observed.recv().await.unwrap();
    let (filler, _filler_rx) = oneshot::channel();
    first
        .commands
        .try_send(PeerCommand::QueryState { reply: filler })
        .unwrap();
    assert_eq!(first.commands.capacity(), 0);

    let mut infos = admit_list_peers(&mut manager).await;
    assert!(
        manager.detached_list_peers.is_empty(),
        "nothing was detached"
    );
    let infos = infos
        .try_recv()
        .expect("an in-place snapshot replies before the owner resumes");
    assert!(
        row(&infos, DETACH_FIRST).stale,
        "the full session timed out"
    );
    assert!(!row(&infos, DETACH_SECOND).stale);
}

#[tokio::test(start_paused = true)]
async fn detached_snapshots_are_capped_at_the_operator_lane_capacity() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, _second) = detach_fixture(rib_tx, 2, 16);
    first.hold.store(true, Ordering::SeqCst);
    let mut detached = Vec::new();
    for _ in 0..2 {
        let mut infos = admit_list_peers(&mut manager).await;
        assert!(
            matches!(infos.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
            "a snapshot under the limit is detached"
        );
        detached.push(infos);
    }
    assert_eq!(manager.detached_list_peers.len(), 2);
    let _held = held_state_query(&mut first).await;

    let mut third = admit_list_peers(&mut manager).await;
    assert_eq!(
        manager.detached_list_peers.len(),
        2,
        "the third snapshot is not detached"
    );
    let third = third
        .try_recv()
        .expect("a snapshot over the limit is answered in place");
    assert_eq!(third.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn canceled_detached_snapshot_drops_its_session_queries() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, _second) = detach_fixture(rib_tx, 4, 16);
    first.hold.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let infos = admit_list_peers(&mut manager).await;
    let (mut state_reply, _resume) = held_state_query(&mut first).await;
    drop(infos);
    state_reply.closed().await;
    assert!(
        started.elapsed() < PEER_QUERY_TIMEOUT,
        "caller cancellation, not the query deadline, released the session query"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_the_manager_aborts_detached_snapshots() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, _second) = detach_fixture(rib_tx, 4, 16);
    first.hold.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let infos = admit_list_peers(&mut manager).await;
    let _held = held_state_query(&mut first).await;
    drop(manager);
    assert!(
        infos.await.is_err(),
        "shutdown drops the reply instead of answering after the owner is gone"
    );
    assert!(started.elapsed() < PEER_QUERY_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn session_replaced_mid_snapshot_reports_the_row_stale() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, _second) = detach_fixture(rib_tx, 4, 16);
    first.hold.store(true, Ordering::SeqCst);
    let infos = admit_list_peers(&mut manager).await;
    // The predecessor session exits with the admitted query unanswered.
    let (state_reply, resume) = held_state_query(&mut first).await;
    drop((state_reply, resume));
    drop(first);
    let (handle, replacement) = spawn_observed_session(DETACH_FIRST, 16);
    replacement.hold.store(true, Ordering::SeqCst);
    insert_test_managed_peer_with_asn(&mut manager, DETACH_FIRST, 65002, handle, false);

    let infos = infos.await.expect("the snapshot completes");
    assert!(
        row(&infos, DETACH_FIRST).stale,
        "the exited predecessor's row is unavailable"
    );
    assert_eq!(
        replacement.queued(),
        0,
        "the replacement session never receives the earlier snapshot's query"
    );
}

/// Every row shares the admission deadline: a row joined after an earlier
/// held row does not get a fresh timeout of its own.
#[tokio::test(start_paused = true)]
async fn detached_snapshot_reply_after_the_deadline_is_stale_behind_a_held_row() {
    let (rib_tx, _rib_rx) = mpsc::channel(16);
    let (mut manager, _operator_tx, mut first, mut second) = detach_fixture(rib_tx, 4, 16);
    first.hold.store(true, Ordering::SeqCst);
    second.hold.store(true, Ordering::SeqCst);
    // Rows follow peer-table order; hold whichever row is joined first.
    let first_row = manager.peers.keys().next().unwrap().address;
    let (held, late) = if first_row == DETACH_FIRST {
        (&mut first, &mut second)
    } else {
        (&mut second, &mut first)
    };
    let late_addr = if first_row == DETACH_FIRST {
        DETACH_SECOND
    } else {
        DETACH_FIRST
    };
    let admitted = tokio::time::Instant::now();
    let infos = admit_list_peers(&mut manager).await;
    let (_held_reply, _held_resume) = held_state_query(held).await;
    let (late_reply, _late_resume) = held_state_query(late).await;
    let answer = tokio::spawn(async move {
        tokio::time::sleep_until(admitted + PEER_QUERY_TIMEOUT + Duration::from_millis(1)).await;
        let _ = late_reply.send(policy_test_peer_state(late_addr, SessionState::Established));
    });
    let infos = infos.await.unwrap();
    answer.await.unwrap();
    assert!(
        row(&infos, late_addr).stale,
        "a reply after the deadline is not fresh"
    );
}

/// The peer manager drains ready commands back to back inside one task poll,
/// up to Tokio's cooperative budget. A readiness reply sent mid-queue wakes
/// the probe's task into this worker's LIFO slot, which no other worker can
/// steal, so without a yield the answered probe waits for the rest of the
/// poll. The hook holds every later command until the answered probe has run:
/// a stranded probe cannot run, the hold times out and the test fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "the regression drives a held command queue through the run loop with a handshake"
)]
async fn readiness_ping_runs_while_commands_stay_queued() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const COMMANDS: usize = 64;
    let (commands, command_rx) = mpsc::channel(COMMANDS);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);

    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (ran_tx, ran_rx) = std::sync::mpsc::channel::<()>();
    let probe_ran = Arc::new(AtomicBool::new(false));
    let stranded = Arc::new(AtomicBool::new(false));
    let dispatched = Arc::new(AtomicUsize::new(0));
    manager.test_command_hook = Some(Arc::new({
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let ran_rx = Mutex::new(ran_rx);
        let probe_ran = Arc::clone(&probe_ran);
        let stranded = Arc::clone(&stranded);
        let dispatched = Arc::clone(&dispatched);
        let readiness_tx = readiness_tx.clone();
        move |command| {
            if !matches!(command, PeerManagerCommand::Ping { .. }) {
                return;
            }
            if dispatched.fetch_add(1, Ordering::SeqCst) == 0 {
                // Hold the first command inside the actor's poll until the
                // probe is queued behind the rest of the queue.
                entered_tx.lock().unwrap().send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test releases the first command");
                return;
            }
            // The readiness lane has capacity 1, so a free slot means the
            // actor has dequeued the probe and, in the same arm, replied.
            let answered = readiness_tx.capacity() == readiness_tx.max_capacity();
            if answered
                && !probe_ran.load(Ordering::SeqCst)
                && !stranded.load(Ordering::SeqCst)
                && ran_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(1))
                    .is_err()
            {
                // Bounded so the unfixed actor fails instead of hanging.
                stranded.store(true, Ordering::SeqCst);
            }
        }
    }));
    let actor = tokio::spawn(manager.run());

    // Command replies are dropped, so answering them wakes no task.
    for _ in 0..COMMANDS {
        let (reply, _) = oneshot::channel();
        commands
            .send(PeerManagerCommand::Ping { reply })
            .await
            .unwrap();
    }
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("actor dispatches the first command");
    })
    .await
    .unwrap();

    let (armed_tx, armed_rx) = oneshot::channel::<()>();
    let probe = tokio::spawn({
        let probe_ran = Arc::clone(&probe_ran);
        async move {
            let (reply, mut response) = oneshot::channel();
            let started = std::time::Instant::now();
            readiness_tx
                .send(rustbgpd_api::peer_types::PeerManagerReadinessQuery::Ping { reply })
                .await
                .unwrap();
            // Signal only once the reply waker is registered, so the actor's
            // reply has to wake this task rather than find it already ready.
            let mut armed = Some(armed_tx);
            let result = std::future::poll_fn(|cx| {
                let poll = std::future::Future::poll(std::pin::Pin::new(&mut response), cx);
                if poll.is_pending()
                    && let Some(armed) = armed.take()
                {
                    armed.send(()).unwrap();
                }
                poll
            })
            .await;
            let elapsed = started.elapsed();
            probe_ran.store(true, Ordering::SeqCst);
            let _ = ran_tx.send(());
            (result, elapsed)
        }
    });
    armed_rx.await.unwrap();
    release_tx.send(()).unwrap();

    let (result, elapsed) = probe.await.unwrap();
    result.unwrap();
    assert!(
        !stranded.load(Ordering::SeqCst),
        "the answered readiness ping stayed parked on the actor's worker behind queued commands"
    );
    assert!(
        elapsed < Duration::from_millis(200),
        "readiness ping took {elapsed:?} behind queued commands"
    );

    commands.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
    assert_eq!(dispatched.load(Ordering::SeqCst), COMMANDS);
}
