//! Operator-read admission at every peer-manager transaction wait.
//!
//! Every `await_with_readiness*` or `finish_admitted_operator_read` call site
//! is one row of [`WAIT_SITES`]: what the site awaits, how a stub parks the
//! transaction there, and whether a
//! concurrent operator read (`ListPeers`, `QueryImportPolicyTermHits`) is
//! served or deliberately fenced while it is parked. One driver runs every
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

/// Reads issued while the site is parked. `Fenced` rows probe for `window`
/// (below the site's own bound) so the release still lands inside the wait.
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
    /// The same cohort through `apply_resolved_policy_snapshot`, the entry
    /// `PeerManagerCommand::ApplyResolvedPolicySnapshot` and the config
    /// transaction rollback use: not the reload owner, admission off.
    StandalonePolicySnapshot,
    /// A reload generation whose session replace is rejected after its
    /// policy cohort committed, so the unwind replays the prior chains
    /// through `apply_resolved_policy_snapshot` with admission off.
    CompensatingReplay,
    ValidationRefresh,
    DatasetRefresh,
    MaxPrefixRestart,
    OutboundRefresh,
    HotExportKnobs,
    GracefulShutdown,
    OutboundReplay,
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
    /// Park one admitted term-hits read before probing.
    pre_read: bool,
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

fn hold_first_term_hits(command: &PeerCommand, index: usize) -> SessionAction {
    match command {
        PeerCommand::QueryImportPolicyTermHits { .. } if index == 0 => SessionAction::Hold,
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
        site: "mod.rs::handle_operator_query",
        awaits: "the admitted operator read's collector task (term-hits fan-out)",
        drive: FORWARD_COHORT,
        rib: RibHold::Reply(is_cohort_replace),
        session: hold_first_term_hits,
        pre_read: true,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "one admitted read completes before the next is polled: its collector must \
                     finish before a prestage ACK can advance a session's installed policy, and \
                     the collector uses the admitted read's absolute deadline; queued reads \
                     can already have spent part of their own budget",
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::qualify_rfc8212_import_transition",
        awaits: "PeerCommand::QueryState of the transitioning peer (preflight)",
        drive: Drive::Rfc8212Transition { established: true },
        rib: RibHold::None,
        session: hold_first_state,
        pre_read: false,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: QUERY_PROBE_REASON,
        },
        completion: Completion::ImportApplied,
    },
    WaitSite {
        site: "policy.rs::query_peer_retained_stale",
        awaits: "RibUpdate::QueryPeerRetainedStale reply (preflight, down peer)",
        drive: Drive::Rfc8212Transition { established: false },
        rib: RibHold::Reply(is_retained_stale),
        session: answer_all,
        pre_read: false,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "read-only RIB proof on the primary lane under the shared \
                     RIB_BATCH_REPLY_TIMEOUT walk budget (2 min): nothing is mutated yet, but \
                     only the forward reload's prestage and cohort waits admit reads, so this \
                     fence can outlast the 2 s reader deadline when the RIB lane is backed up",
        },
        completion: Completion::ImportApplied,
    },
    WaitSite {
        site: "policy.rs::export_only_policy_cohort_mask",
        awaits: "PeerCommand::QueryState of each winning cohort member",
        drive: FORWARD_COHORT,
        rib: RibHold::None,
        session: hold_first_state,
        pre_read: false,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: QUERY_PROBE_REASON,
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::hot_apply_session_policy",
        awaits: "PeerCommand::UpdateExportPolicy / UpdateImportPolicy acknowledgement",
        drive: FORWARD_COHORT,
        rib: RibHold::None,
        session: hold_first_export_apply,
        pre_read: false,
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
        pre_read: false,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: QUERY_PROBE_REASON,
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::query_clean_session_state",
        awaits: "PeerCommand::QueryState, bounded retry",
        drive: Drive::ForwardWalk { clean: true },
        rib: RibHold::None,
        session: stall_then_hold_state,
        pre_read: false,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "the retry is bounded by what remains of CLEAN_STATE_QUERY_WINDOW, one \
                     absolute 2 s window shared by the cohort, so it never exceeds the 2 s \
                     reader deadline; the probe gathers the acknowledgement evidence a \
                     snapshot would otherwise misreport",
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "RibUpdate::PrepareExportPolicyDestination reply (destination prestage)",
        drive: FORWARD_COHORT,
        rib: RibHold::Reply(is_prestage),
        session: answer_all,
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: "post-commit refresh dispatch decides each member's Route Refresh debt; \
                     bounded by PEER_QUERY_TIMEOUT (100 ms), below the 2 s reader deadline",
        },
        completion: Completion::ExportApplied,
    },
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: FORWARD_COHORT,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        pre_read: false,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Served,
        completion: Completion::ExportApplied,
    },
    // Non-owner entry through an admitting site. Expected to be decided
    // deliberately: the fence is the current default for every transaction
    // that is not the reload owner, and whether these entries should admit
    // reads is decided separately.
    WaitSite {
        site: "policy.rs::await_export_policy_cohort_rib_reply",
        awaits: "RibUpdate::ReplacePeerExportPolicies reply (cohort transition)",
        drive: Drive::StandalonePolicySnapshot,
        rib: RibHold::Reply(is_cohort_replace),
        session: answer_all,
        pre_read: false,
        additional_entry: Some(
            "PeerManagerCommand::ApplyResolvedPolicySnapshot (apply_resolved_policy_snapshot, \
             admission off)",
        ),
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "current default for a transaction that is not the reload owner: \
                     apply_resolved_policy_snapshot enters the cohort with admission off, so \
                     the same wait the SIGHUP owner serves stays fenced here, bounded by the \
                     RIB's transition ownership; whether standalone policy transactions should \
                     admit reads is decided separately",
        },
        completion: Completion::ExportApplied,
    },
    // Non-owner entry through an admitting site, from the reload's own
    // compensating replay. Expected to be decided deliberately alongside
    // the standalone row above.
    WaitSite {
        site: "policy.rs::try_apply_export_only_policy_cohort",
        awaits: "RibUpdate::PrepareExportPolicyDestination reply (destination prestage)",
        drive: Drive::CompensatingReplay,
        rib: RibHold::LaterReply(is_prestage, 1),
        session: answer_all,
        pre_read: false,
        additional_entry: Some(
            "apply_reload_generation unwind (compensating replay of the prior generation's \
             chains after a rejected session replace, admission off)",
        ),
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "a served read would observe the committed generation about to be \
                     reverted: the unwind replays the prior chains through \
                     apply_resolved_policy_snapshot with admission off, so the prestage the \
                     forward owner serves stays fenced here; decided separately",
        },
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
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "per-peer authoritative RIB replacement under the shared \
                     RIB_BATCH_REPLY_TIMEOUT walk budget (2 min): this peer's session already \
                     runs the new chain while the RIB still evaluates the prior one, and the \
                     walk mutates peer by peer with no admitting wait between steps; on the \
                     fallback path this fence can outlast the 2 s reader deadline",
        },
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
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
        additional_entry: None,
        window: HALF_QUERY,
        contract: Contract::Fenced {
            reason: QUERY_PROBE_REASON,
        },
        completion: Completion::Finished,
    },
    WaitSite {
        site: "policy.rs::reevaluate_dataset_exports",
        awaits: "RibUpdate::ReevaluatePeerExportPolicies reply",
        drive: Drive::DatasetRefresh,
        rib: RibHold::Reply(is_reevaluate),
        session: answer_all,
        pre_read: false,
        additional_entry: None,
        window: HELD_FOREVER,
        contract: Contract::Fenced {
            reason: "one batched RIB re-evaluation of every export chain referencing the \
                     swapped dataset; the referencing sessions were just refreshed and their \
                     export debt is undecided until the RIB answers; bounded by RIB_REPLY_TIMEOUT \
                     attention time (5 s), which can outlast the 2 s reader deadline",
        },
        completion: Completion::Finished,
    },
    WaitSite {
        site: "lifecycle.rs::handle_due_max_prefix_restarts",
        awaits: "join_all of PeerCommand::Start sends to every due peer",
        drive: Drive::MaxPrefixRestart,
        rib: RibHold::None,
        session: answer_all,
        pre_read: false,
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
        site: "lifecycle.rs::refresh_peer_outbound_in_rib",
        awaits: "RibUpdate::RefreshPeerOutbound acknowledgement",
        drive: Drive::OutboundRefresh,
        rib: RibHold::Reply(is_outbound_refresh),
        session: answer_all,
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
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
        pre_read: false,
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
        let mut armed = true;
        let mut skip = match hold {
            RibHold::LaterReply(_, skip) => skip,
            _ => 0,
        };
        while let Some(update) = rib_rx.recv().await {
            let matcher = match hold {
                RibHold::None => None,
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
                RibHold::None => unreachable!("matched without a matcher"),
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
    let commands = session_tx.clone();
    let task = tokio::spawn(async move {
        if parked {
            gate.hold().await;
        }
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        let mut stalled = Vec::new();
        while let Some(command) = session_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
            let index = counts.entry(command_kind(&command)).or_default();
            let seen = *index;
            *index += 1;
            match script(&command, seen) {
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
        Ok(())
    });
    (PeerHandle::from_parts(session_tx, task), commands)
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
        Drive::StandalonePolicySnapshot => (
            peers
                .iter()
                .map(|&peer| target(peer, false, true))
                .collect(),
            false,
        ),
        Drive::CompensatingReplay
        | Drive::ValidationRefresh
        | Drive::DatasetRefresh
        | Drive::OutboundRefresh
        | Drive::HotExportKnobs
        | Drive::GracefulShutdown
        | Drive::OutboundReplay
        | Drive::MaxPrefixRestart => (Vec::new(), false),
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
        Drive::StandalonePolicySnapshot => manager
            .apply_resolved_policy_snapshot(targets)
            .await
            .map(drop),
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
    }
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

async fn term_hits(
    operator_tx: &mpsc::Sender<EnqueuedOperatorQuery>,
) -> oneshot::Receiver<SessionQueryOutcome<Vec<(IpAddr, ImportPolicyTermHits)>>> {
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                peer: None,
                deadline: tokio::time::Instant::now() + READER_DEADLINE,
                reply,
            }
            .into(),
        )
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
    let rib_capacity = if matches!(row.rib, RibHold::Receiver(_)) {
        1
    } else {
        16
    };
    let (rib_tx, rib_rx) = mpsc::channel(rib_capacity);
    let rib = spawn_rib(rib_rx, gate.clone(), row.rib, cohort_reply);
    let (_command_tx, command_rx) = mpsc::channel(16);
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
            manager.current_config = reload_config(dir.path(), false);
            let replaced = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 3));
            let (handle, _) = spawn_session(replaced, true, gate.clone(), answer_all, false);
            insert_test_managed_peer_with_asn(&mut manager, replaced, 65004, handle, false);
            manager.inject_reconfigure_failures.insert(key(replaced), 0);
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
            let latched = manager.peers.get_mut(&key(first)).unwrap();
            latched.enabled = false;
            latched.max_prefix_restart_seconds = Some(1);
            let session_id = latched.session_id;
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
        | Drive::StandalonePolicySnapshot
        | Drive::OutboundRefresh
        | Drive::HotExportKnobs
        | Drive::GracefulShutdown
        | Drive::OutboundReplay
        | Drive::CompensatingReplay => {}
    }

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
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    // Kept alive until the row completes: dropping the receiver cancels the
    // admitted collector and the wait resumes.
    let mut admitted = None;
    if row.pre_read {
        admitted = Some(term_hits(&operator_tx).await);
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
    }
    let mut infos = list_peers(&operator_tx).await;
    let mut rows = term_hits(&operator_tx).await;
    match row.contract {
        Contract::Served => {
            let infos = tokio::time::timeout(HELD_FOREVER, &mut infos)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{site}: a neighbor snapshot must be served while {} is awaited",
                        row.awaits
                    )
                })
                .unwrap();
            assert_eq!(infos.len(), 2, "{site}");
            let rows = tokio::time::timeout(HELD_FOREVER, &mut rows)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{site}: the import-stats collection must be served while {} is awaited",
                        row.awaits
                    )
                })
                .unwrap();
            assert!(
                matches!(rows, SessionQueryOutcome::Reply(ref rows) if rows.len() == 2),
                "{site}: {rows:?}"
            );
        }
        Contract::Fenced { reason } => {
            assert!(
                tokio::time::timeout(row.window, &mut infos).await.is_err(),
                "{site}: a neighbor snapshot was served while {} is awaited, but the row says \
                 the site is fenced ({reason}); flip the row if that is now intended",
                row.awaits
            );
            assert!(
                tokio::time::timeout(Duration::ZERO, &mut rows)
                    .await
                    .is_err(),
                "{site}: the import-stats collection was served at a fenced site"
            );
        }
        Contract::Unreachable { .. } => unreachable!(),
    }
    assert!(
        !transaction.is_finished(),
        "{site}: the transaction must still be parked on {}",
        row.awaits
    );

    gate.release();
    let (mut manager, result) = tokio::time::timeout(Duration::from_mins(5), transaction)
        .await
        .unwrap_or_else(|_| panic!("{site}: the transaction did not complete after release"))
        .unwrap();
    check_completion(row, &mut manager, result).await;
    drop(admitted);
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
                Some(deny_policy_chain()),
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
        let _ = tokio::time::timeout(Duration::from_secs(5), managed.handle.shutdown()).await;
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
fn wait_call_sites(file: &'static str, source: &str) -> BTreeMap<String, usize> {
    const HELPERS: [&str; 3] = [
        "await_with_readiness",
        "await_with_readiness_budget",
        "finish_admitted_operator_read",
    ];
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
        let calls = trimmed.matches(".await_with_readiness").count()
            + trimmed.matches(".finish_admitted_operator_read").count();
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
    let mut sources = BTreeMap::new();
    for (file, source) in [
        ("mod.rs", include_str!("../mod.rs")),
        ("policy.rs", include_str!("../policy.rs")),
        ("lifecycle.rs", include_str!("../lifecycle.rs")),
    ] {
        sources.extend(wait_call_sites(file, source));
    }
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
