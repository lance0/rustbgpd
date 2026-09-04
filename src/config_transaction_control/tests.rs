use super::*;
use crate::config::FibTableConfig;
use crate::fib_runtime::{FibRuntimeCommand, OwnedFibReplaceOutcome};
use crate::test_support::{assert_tier_authorized_test_config, tier_authorized_uds_test_config};
use rustbgpd_api::peer_types::{
    FibTableSnapshot, RuntimeConfigDiff, RuntimeConfigTransactionCandidate,
    RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError,
};
use rustbgpd_api::rib_service::FibTableControlError;
use rustbgpd_policy::PolicyAction;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use tokio::sync::Mutex;

fn tier_transaction_test_config(source: &str) -> String {
    let prepared = tier_authorized_uds_test_config(source);
    let config = Config::load_toml_with_diagnostics(&prepared, "transaction test config")
        .expect("transaction test config must parse");
    assert_tier_authorized_test_config(&config);
    prepared
}

fn base_toml(extra: &str) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

{extra}
"#
    ))
}

#[test]
fn production_snapshot_callers_are_fenced_to_the_accepted_helper() {
    fn count_all(sources: &[&str], needle: &str) -> usize {
        sources
            .iter()
            .map(|source| source.matches(needle).count())
            .sum()
    }

    let source = include_str!("../config_transaction_control.rs");
    let production = source.split("#[cfg(test)]\nmod tests;").next().unwrap();
    let live_policy_impact = include_str!("live_policy_impact.rs");
    let production_sources = [production, live_policy_impact];
    assert_eq!(
        count_all(&production_sources, ".accepted_runtime_snapshot()"),
        2,
        "gNMI Set construction plus the test-only authority fallback use the accepted helper"
    );
    assert_eq!(
        count_all(&production_sources, ".accepted_prior_snapshot()"),
        1,
        "confirmed rollback must bind one accepted provenance generation"
    );
    assert_eq!(
        count_all(
            &production_sources,
            "use crate::reload::runtime_config_snapshot;"
        ),
        0
    );
    let apply = production
        .rsplit_once("let committed_candidate_toml")
        .unwrap()
        .1;
    assert!(!apply.contains("request.candidate_toml"));
    assert_eq!(
        count_all(&production_sources, "stage_preloaded_config_snapshot("),
        7,
        "one typed staging helper plus all six transaction-family calls"
    );
    assert_eq!(
        count_all(&production_sources, "TransactionConfigScope::FibTablesOnly"),
        1,
        "only the pure-FIB family may use the overlay scope"
    );
    assert_eq!(
        count_all(
            &production_sources,
            "PeerManagerCommand::StageConfigSnapshot"
        ),
        0
    );
    assert_eq!(
        count_all(
            &production_sources,
            "PeerManagerCommand::RestoreConfigSnapshot"
        ),
        0
    );

    let reload = include_str!("../reload.rs");
    let legacy = reload
        .find("pub(crate) async fn runtime_config_snapshot(")
        .unwrap();
    assert!(reload[..legacy].ends_with("#[cfg(test)]\n"));
}

#[test]
fn unwatched_apply_retains_response_attachment_through_settlement() {
    let source = include_str!("../config_transaction_control.rs");
    let production = source.split("#[cfg(test)]\nmod tests;").next().unwrap();
    let fallback = production
        .rsplit_once("let Some((watchdog, daemon_gate)) = self.settlement.clone() else {")
        .unwrap()
        .1
        .split_once("};")
        .unwrap()
        .0;
    let apply = fallback.find(".apply_locked(").unwrap();
    let detach = fallback.find("drop(context);").unwrap();
    let response = fallback.find("return result;").unwrap();
    assert!(apply < detach && detach < response);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the source proof inventories every transaction family mutation and recovery boundary"
)]
fn owned_transaction_phase_boundaries_are_closed() {
    fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
    }

    let source = include_str!("../config_transaction_control.rs");
    let live_policy_impact = include_str!("live_policy_impact.rs");
    let apply = body(
        source,
        "async fn apply_config_transaction_locked_with_preloaded",
        "async fn commit_apply_family(",
    );
    assert!(
        apply
            .find("let (plan, candidate, typed_plan) = if let")
            .unwrap()
            < apply.find("commit_apply_family(").unwrap()
    );
    assert!(!apply.contains("progress.begin_mutation()"));

    let dispatch = body(
        source,
        "async fn commit_apply_family(",
        "fn confirmed_apply_loosens_outbound_limits",
    );
    assert!(
        dispatch
            .find("prepare_outbound_prefix_limit_transaction")
            .unwrap()
            < dispatch.find("commit_apply_family_inner(").unwrap()
    );
    assert!(!dispatch.contains("progress.begin_mutation()"));

    let reload = include_str!("../reload.rs");
    for (start, end) in [
        (
            "async fn dispatch_rib_mutation_step",
            "/// Preflight `config`'s outbound prefix maxima",
        ),
        ("async fn dispatch_actor_mutation_step", "fn step_result"),
    ] {
        let mutation_dispatch = body(reload, start, end);
        let reserve = mutation_dispatch.find(".reserve().await").unwrap();
        let mutation = mutation_dispatch.find("progress.begin_mutation()").unwrap();
        let send = mutation_dispatch
            .find("permit.send(build(reply_tx))")
            .unwrap();
        assert!(reserve < mutation && mutation < send, "{start}");
    }
    for (send, phase) in [
        (
            "permit.send(PeerManagerCommand::ReconcilePeers",
            "progress.begin_mutation()",
        ),
        (
            "permit.send(FibRuntimeCommand::OwnedReplaceTables",
            "progress.begin_mutation()",
        ),
    ] {
        let send = reload.find(send).unwrap();
        let mutation = reload[..send].rfind(phase).unwrap();
        let reserve = reload[..mutation].rfind(".reserve().await").unwrap();
        assert!(reserve < mutation && mutation < send);
    }

    let rotation = include_str!("../peer_manager/rotation.rs");
    for (start, end) in [
        (
            "async fn preflight_tcp_ao_add_only(",
            "async fn apply_tcp_ao_add_only(",
        ),
        (
            "async fn preflight_tcp_ao_delete(",
            "async fn apply_tcp_ao_delete(",
        ),
        (
            "async fn preflight_tcp_ao_selection(",
            "async fn apply_tcp_ao_selection(",
        ),
    ] {
        let preflight = body(rotation, start, end);
        assert!(preflight.contains("&self,"), "{start}");
        for mutation in [
            "retain_desired_inventory",
            "mark_tcp_ao_rotation_failed",
            "self.tcp_ao_rotation =",
            ".get_mut(",
        ] {
            assert!(!preflight.contains(mutation), "{start}: {mutation}");
        }
    }
    for (start, end, first_session_mutation, phase) in [
        (
            "async fn apply_tcp_ao_add_only(",
            "async fn preflight_tcp_ao_delete(",
            "apply_to_session(",
            "TcpAoRotationPhase::AddOnly",
        ),
        (
            "async fn apply_tcp_ao_delete(",
            "async fn preflight_tcp_ao_selection(",
            "apply_delete_session(",
            "TcpAoRotationPhase::Deleting",
        ),
        (
            "async fn apply_tcp_ao_selection(",
            "#[cfg(test)]\nmod tests",
            "apply_selection_session(",
            "TcpAoRotationPhase::Selecting",
        ),
    ] {
        let apply = body(rotation, start, end);
        assert!(
            apply.find(phase).unwrap() < apply.find(first_session_mutation).unwrap(),
            "{start}"
        );
    }

    let listener = include_str!("../../crates/transport/src/listener.rs");
    let listener_dispatch = body(
        listener,
        "async fn dispatch<T, F>(",
        "/// Validate the complete desired listener inventory",
    );
    let reserve = listener_dispatch.find("self.tx.reserve()").unwrap();
    let phase = listener_dispatch.find("before_dispatch();").unwrap();
    let send = listener_dispatch.find("permit.send(command)").unwrap();
    assert!(reserve < phase && phase < send);

    let evpn = include_str!("../evpn_runtime_converger.rs");
    let changed_apply = body(
        evpn,
        "pub(crate) async fn apply_config_if_changed",
        "fn reload_state(",
    );
    assert!(
        changed_apply
            .find("if !changed(&config, &baseline)")
            .unwrap()
            < changed_apply
                .find("apply_candidate_config_locked(&config, false, begin_mutation)")
                .unwrap()
    );
    let candidate_apply = body(
        evpn,
        "async fn apply_evpn_runtime_candidate_locked",
        "/// Apply the #268-decomposed primitive steps",
    );
    let commit_path = candidate_apply.split_once("if plan.is_noop() {").unwrap().1;
    assert!(
        commit_path.find("validate_supported_plan_shape").unwrap()
            < commit_path.find("begin_mutation();").unwrap()
    );
    assert!(
        commit_path.rfind("begin_mutation();").unwrap()
            < commit_path.find("converger.converge(").unwrap()
    );

    for (family_source, start, end, first_mutation) in [
        (
            source,
            "async fn commit_fib_transaction(",
            "fn apply_family(",
            "stage_preloaded_config_snapshot(",
        ),
        (
            source,
            "async fn commit_candidate_snapshot_locked(",
            "async fn commit_dynamic_neighbors_locked(",
            "stage_preloaded_config_snapshot(",
        ),
        (
            source,
            "async fn commit_dynamic_neighbors_locked(",
            "async fn commit_static_neighbors_locked(",
            "stage_preloaded_config_snapshot(",
        ),
        (
            source,
            "async fn commit_static_neighbors_locked(",
            "struct PeerSessionReshapeCommit",
            "stage_preloaded_config_snapshot(",
        ),
        (
            live_policy_impact,
            "async fn commit_live_policy_impact_locked(",
            "#[derive(Default)]",
            "stage_preloaded_config_snapshot(",
        ),
        (
            source,
            "async fn commit_peer_session_reshape_locked(",
            "async fn send_bounce_dynamic_range_peers(",
            "stage_preloaded_config_snapshot(",
        ),
    ] {
        let owned = body(family_source, start, end);
        let reserve = owned.find("reserve_persist_permit(").unwrap();
        let mutation = owned.find("progress.begin_mutation()").unwrap();
        let first_mutation = owned.find(first_mutation).unwrap();
        let settling = owned.find("progress.begin_settling()").unwrap();
        let publication = owned.find("persist_candidate_config(").unwrap();
        assert!(reserve < mutation && mutation < first_mutation, "{start}");
        assert!(mutation < settling && settling < publication, "{start}");
    }

    for (family_source, start, end, rollback, expected) in [
        (
            source,
            "async fn commit_fib_transaction(",
            "fn apply_family(",
            "restore_preloaded_snapshot_after_error(",
            1,
        ),
        (
            source,
            "async fn commit_dynamic_neighbors_locked(",
            "async fn commit_static_neighbors_locked(",
            "rollback_snapshot_after_error(",
            1,
        ),
        (
            source,
            "async fn commit_static_neighbors_locked(",
            "struct PeerSessionReshapeCommit",
            "rollback_snapshot_after_error(",
            2,
        ),
        (
            source,
            "async fn commit_static_neighbors_locked(",
            "struct PeerSessionReshapeCommit",
            "rollback_static_and_snapshot(",
            5,
        ),
        (
            live_policy_impact,
            "async fn commit_live_policy_impact_locked(",
            "#[derive(Default)]",
            "rollback_snapshot_after_error(",
            2,
        ),
        (
            source,
            "async fn commit_peer_session_reshape_locked(",
            "async fn send_bounce_dynamic_range_peers(",
            "rollback_snapshot_after_error(",
            3,
        ),
    ] {
        let owned = body(family_source, start, end);
        let pre_persist = owned.split_once("persist_candidate_config(").unwrap().0;
        assert_eq!(pre_persist.matches(rollback).count(), expected, "{start}");
        for prefix in pre_persist.split(rollback).take(expected) {
            let after_phase = prefix.rsplit_once("progress.begin_settling();").unwrap().1;
            let structural = after_phase
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            assert_eq!(structural, "returnErr(", "{start}: {rollback}");
        }
    }

    let confirmed = body(
        source,
        "async fn apply_confirmed_locked(",
        "async fn confirm(",
    );
    assert!(
        confirmed.find("progress.begin_settling()").unwrap()
            < confirmed.find("match launch.publish(").unwrap()
    );
    let confirm = body(source, "async fn confirm_locked(", "async fn abort(");
    assert!(
        confirm.find("matching_pending(").unwrap()
            < confirm.find("progress.begin_settling()").unwrap()
    );
    let abort = body(
        source,
        "async fn abort_locked(",
        "async fn reset_rollback_duration_locked(",
    );
    assert!(
        abort.find("matching_pending(").unwrap() < abort.find("progress.begin_settling()").unwrap()
    );
    let auto = body(
        source,
        "async fn auto_revert(",
        "async fn matching_pending(",
    );
    assert!(
        auto.find("pending_for_timeout(").unwrap()
            < auto.find("progress.begin_settling()").unwrap()
    );
}

/// Returns the function introduced by `signature`, from the signature through
/// the brace that closes its body.
///
/// Braces inside string literals are counted too, so the target must keep them
/// balanced (format placeholders such as `{name}` do).
fn fn_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing {signature}"));
    let rest = &source[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("no body for {signature}"));
    let mut depth = 0usize;
    for (offset, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for {signature}")
}

#[test]
fn fn_body_stops_at_the_matching_brace() {
    let source =
        "fn first() {\n    if a { b() }\n    let _ = \"{x}\";\n}\n\nfn second() {\n    c()\n}\n";
    let body = fn_body(source, "fn first()");
    assert!(body.starts_with("fn first() {"));
    assert!(body.ends_with("let _ = \"{x}\";\n}"));
    assert!(body.contains("b()"));
    assert!(!body.contains("fn second"));
    assert!(!body.contains("c()"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one closed source inventory covers every runtime-config owner and prohibited bypass"
)]
fn runtime_config_coordinator_inventory_is_complete_and_closed() {
    fn production(source: &'static str) -> &'static str {
        source
            .split_once("\n#[cfg(test)]\nmod tests")
            .map_or(source, |v| v.0)
    }

    let server = production(include_str!("../../crates/api/src/server.rs"));
    let settlement = production(include_str!(
        "../../crates/api/src/runtime_config_settlement.rs"
    ));
    let neighbor = production(include_str!("../../crates/api/src/neighbor_service.rs"));
    let peer_group = production(include_str!("../../crates/api/src/peer_group_service.rs"));
    let policy = production(include_str!("../../crates/api/src/policy_service.rs"));
    let fib = production(include_str!("../fib_table_control.rs"));
    let transaction = production(include_str!("../config_transaction_control.rs"))
        .split_once("\n#[cfg(test)]\nasync fn apply_config_transaction(")
        .unwrap()
        .0;
    let main = production(include_str!("../main.rs"));
    let config_service = production(include_str!("../../crates/api/src/config_service.rs"));
    let gnmi_service = production(include_str!("../../crates/api/src/gnmi_service.rs"));
    let owners = [server, neighbor, peer_group, policy, fib, transaction, main];

    #[rustfmt::skip]
    let inventory = [
        (main, "RuntimeConfigCoordinator::new()", 1),
        (main, "\n                lock: runtime_config_lock.clone(),", 2),
        (main, "runtime_config_lock: runtime_config_lock.clone(),", 1),
        (main, "runtime_config_lock.acquire()", 0),
        (main, "RuntimeConfigOperationKind::Sighup,", 1),
        (main, "tokio::time::timeout_at(runtime_config_deadline, runtime_config_lock.acquire())", 0),
        (main, "RuntimeConfigSettlementWatchdog::new()", 1),
        (main, ".with_runtime_config_settlement(", 1),
        (main, "move || settlement_wait.wait_until_idle()", 0),
        (main, "move || settlement_wait.wait_until_idle_or_fail_stop()", 1),
        (transaction, "self.deps.lock.acquire()", 2),
        (transaction, ".execute_owned_operation(", 5),
        (settlement, "let coordinator_permit = coordinator.acquire().await?;", 1),
        (settlement, "watchdog.register_owned(", 1),
        (fib, ".acquire()", 1),
        (neighbor, "self.execute_owned_neighbor_mutation(", 4),
        (neighbor, "reserve_config_event_slot(self.config_tx.clone()).await?", 4),
        (server, "runtime_config_lock.acquire()", 0),
        (server, ".with_runtime_config_settlement(", 6),
        (server, "PeerGroupService::with_runtime_config_coordinator(", 2),
        (peer_group, "self.execute_owned_peer_group_mutation(", 4),
        (peer_group, "reserve_config_event_slot(self.config_tx.clone()).await?", 4),
        (policy, "self.execute_owned_policy_mutation(", 12),
        (policy, "reserve_config_event_slot(self.config_tx.clone()).await?", 12),
    ];
    for (source, shape, count) in inventory {
        assert_eq!(source.matches(shape).count(), count, "{shape}");
    }
    for kind in ["GnmiSet", "Confirm", "Abort", "Rollback", "AutoRevert"] {
        assert_eq!(
            transaction
                .matches(&format!("RuntimeConfigOperationKind::{kind}"))
                .count(),
            1,
            "settlement registration inventory for {kind}"
        );
    }
    assert!(!settlement.contains("set_response_attached"));
    assert!(!server.contains("ConfigTransactionResponseAttachment"));
    assert!(!transaction.contains("response_attached: bool"));
    assert_eq!(
        main.matches("OwnedRuntimeConfigRequestContext::detached()")
            .count(),
        1,
        "SIGHUP must register as detached"
    );
    assert_eq!(
        transaction
            .matches("OwnedRuntimeConfigRequestContext::detached()")
            .count(),
        1,
        "AutoRevert must register as detached"
    );
    assert_eq!(
        config_service
            .matches("OwnedRuntimeConfigRequestContext::unary()")
            .count(),
        3,
        "Confirm, Abort, and Rollback must carry unary attachment contexts"
    );
    assert_eq!(
        gnmi_service
            .matches("OwnedRuntimeConfigRequestContext::unary()")
            .count(),
        1,
        "gNMI Set must carry one unary attachment context"
    );
    let credential_reload = main.find("match credentials.reload()").unwrap();
    let credential_success = main[credential_reload..].find("Ok(generation) =>").unwrap();
    let credential_mutating = main[credential_reload..]
        .find("operation.advance_phase(RuntimeConfigSettlementPhase::Mutating)")
        .unwrap();
    let credential_effect = main[credential_reload..]
        .find("accepted_effect = true")
        .unwrap();
    assert!(
        credential_success < credential_mutating && credential_mutating < credential_effect,
        "SIGHUP credential reload enters Mutating only after atomic publication"
    );
    for kind in [
        "NeighborAdd",
        "NeighborDelete",
        "DynamicNeighborAdd",
        "DynamicNeighborDelete",
    ] {
        assert_eq!(
            neighbor
                .matches(&format!("RuntimeConfigOperationKind::{kind}"))
                .count(),
            1,
            "Neighbor4 settlement registration inventory for {kind}"
        );
        assert_eq!(
            settlement.matches(&format!("    {kind},")).count(),
            1,
            "closed operation-kind roster for {kind}"
        );
    }
    for kind in [
        "PolicySet",
        "PolicyDelete",
        "NeighborSetSet",
        "NeighborSetDelete",
        "GlobalImportChainSet",
        "GlobalExportChainSet",
        "GlobalImportChainClear",
        "GlobalExportChainClear",
        "NeighborImportChainSet",
        "NeighborExportChainSet",
        "NeighborImportChainClear",
        "NeighborExportChainClear",
    ] {
        assert_eq!(
            policy
                .matches(&format!("RuntimeConfigOperationKind::{kind}"))
                .count(),
            1,
            "Policy12 settlement registration inventory for {kind}"
        );
        assert_eq!(
            settlement.matches(&format!("    {kind},")).count(),
            1,
            "closed operation-kind roster for {kind}"
        );
    }
    for kind in [
        "PeerGroupSet",
        "PeerGroupDelete",
        "NeighborPeerGroupSet",
        "NeighborPeerGroupClear",
    ] {
        assert_eq!(
            peer_group
                .matches(&format!("RuntimeConfigOperationKind::{kind}"))
                .count(),
            1,
            "PeerGroup4 settlement registration inventory for {kind}"
        );
        assert_eq!(
            settlement.matches(&format!("    {kind},")).count(),
            1,
            "closed operation-kind roster for {kind}"
        );
    }
    let acquired = settlement
        .find("let coordinator_permit = coordinator.acquire().await?;")
        .unwrap();
    let registered = settlement.find("watchdog.register_owned(").unwrap();
    let body = settlement
        .find("let outcome = body(operation.clone()).await;")
        .unwrap();
    assert!(acquired < registered && registered < body);
    let owned_body = fn_body(neighbor, "async fn owned_neighbor_mutation_body");
    assert!(!owned_body.contains(".code()"));
    assert!(!owned_body.contains(".message()"));
    assert!(!owned_body.contains("to_string().contains"));
    let gate = owned_body.find("check_config_mutation_gate(").unwrap();
    let mutating = owned_body
        .find("advance_phase(RuntimeConfigSettlementPhase::Mutating)")
        .unwrap();
    let stage = owned_body
        .find("stage_runtime_config_event_typed(")
        .unwrap();
    let actor = owned_body
        .find("dispatch_owned_neighbor_mutation(")
        .unwrap();
    let settling = owned_body
        .find("advance_phase(RuntimeConfigSettlementPhase::SettlingRollback)")
        .unwrap();
    let commit = owned_body.find("staged.commit_typed()").unwrap();
    assert!(gate < mutating && mutating < stage && stage < actor);
    assert!(actor < settling && settling < commit);
    for legacy in [
        "PeerManagerCommand::RuntimeCreatePeer",
        "PeerManagerCommand::DeletePeer",
        "PeerManagerCommand::AddDynamicRange",
        "PeerManagerCommand::DeleteDynamicRange",
    ] {
        assert!(!neighbor.contains(legacy), "Neighbor4 bypass: {legacy}");
    }
    let peer_manager = production(include_str!("../peer_manager/mod.rs"));
    assert_eq!(
        peer_manager
            .matches("PeerManagerCommand::OwnedNeighborMutation")
            .count(),
        1
    );
    let owned_peer_group_body = peer_group
        .split_once("async fn owned_peer_group_mutation_body")
        .unwrap()
        .1
        .split_once("#[tonic::async_trait]")
        .unwrap()
        .0;
    assert!(!owned_peer_group_body.contains(".code()"));
    assert!(!owned_peer_group_body.contains(".message()"));
    assert!(!owned_peer_group_body.contains("to_string().contains"));
    let gate = owned_peer_group_body
        .find("check_config_mutation_gate(")
        .unwrap();
    let mutating = owned_peer_group_body
        .find("advance_phase(RuntimeConfigSettlementPhase::Mutating)")
        .unwrap();
    let stage = owned_peer_group_body
        .find("stage_runtime_config_event_typed(")
        .unwrap();
    let actor = owned_peer_group_body
        .find("dispatch_owned_catalog_mutation(")
        .unwrap();
    let settling = owned_peer_group_body
        .find("advance_phase(RuntimeConfigSettlementPhase::SettlingRollback)")
        .unwrap();
    let commit = owned_peer_group_body.find("staged.commit_typed()").unwrap();
    assert!(gate < mutating && mutating < stage && stage < actor);
    assert!(actor < settling && settling < commit);
    for legacy in [
        "PeerManagerCommand::SetPeerGroup",
        "PeerManagerCommand::DeletePeerGroup",
        "PeerManagerCommand::SetNeighborPeerGroup",
        "PeerManagerCommand::ClearNeighborPeerGroup",
    ] {
        assert!(!peer_group.contains(legacy), "PeerGroup4 bypass: {legacy}");
    }
    assert_eq!(
        peer_manager
            .matches("PeerManagerCommand::OwnedCatalogMutation")
            .count(),
        1
    );
    let owned_policy_body = policy
        .split_once("async fn owned_policy_mutation_body")
        .unwrap()
        .1
        .split_once("async fn require_managed_peer_address")
        .unwrap()
        .0;
    assert!(!owned_policy_body.contains(".code()"));
    assert!(!owned_policy_body.contains(".message()"));
    assert!(!owned_policy_body.contains("to_string().contains"));
    let gate = owned_policy_body
        .find("check_config_mutation_gate(")
        .unwrap();
    let mutating = owned_policy_body
        .find("advance_phase(RuntimeConfigSettlementPhase::Mutating)")
        .unwrap();
    let stage = owned_policy_body
        .find("stage_runtime_config_event_typed(")
        .unwrap();
    let actor = owned_policy_body
        .find("dispatch_owned_catalog_mutation(")
        .unwrap();
    let settling = owned_policy_body
        .find("advance_phase(RuntimeConfigSettlementPhase::SettlingRollback)")
        .unwrap();
    let commit = owned_policy_body.find("staged.commit_typed()").unwrap();
    assert!(gate < mutating && mutating < stage && stage < actor);
    assert!(actor < settling && settling < commit);
    for legacy in [
        "PeerManagerCommand::SetPolicy",
        "PeerManagerCommand::DeletePolicy",
        "PeerManagerCommand::SetNeighborSet",
        "PeerManagerCommand::DeleteNeighborSet",
        "PeerManagerCommand::SetGlobalImportChain",
        "PeerManagerCommand::SetGlobalExportChain",
        "PeerManagerCommand::ClearGlobalImportChain",
        "PeerManagerCommand::ClearGlobalExportChain",
        "PeerManagerCommand::SetNeighborImportChain",
        "PeerManagerCommand::SetNeighborExportChain",
        "PeerManagerCommand::ClearNeighborImportChain",
        "PeerManagerCommand::ClearNeighborExportChain",
    ] {
        assert!(!policy.contains(legacy), "Policy12 bypass: {legacy}");
    }

    #[rustfmt::skip]
    let prohibited_apis = ["add_permits", "forget", "acquire_many", "wait_idle", "reopen", "pub fn reset", "impl Default for RuntimeConfigCoordinator"];
    for prohibited in prohibited_apis {
        assert!(!server.contains(prohibited), "{prohibited}");
    }
    assert_eq!(server.matches(".close();").count(), 1);
    assert_eq!(main.matches("runtime_config_lock.close();").count(), 1);
    let shutdown_gate = main.find("daemon_gate.begin_shutdown();").unwrap();
    let watched_idle = main
        .find("move || settlement_wait.wait_until_idle_or_fail_stop()")
        .unwrap();
    let drained = main
        .find("runtime_config_lock.wait_until_drained().await;")
        .unwrap();
    let closed = main.find("runtime_config_lock.close();").unwrap();
    assert!(shutdown_gate < closed && closed < watched_idle && watched_idle < drained);
    assert!(
        owners[1..6]
            .iter()
            .all(|source| !source.contains(".close();"))
    );
    let qualified_mutex = ["Arc<tokio::sync::Mutex<", "()>>"].concat();
    let imported_mutex = ["Arc<Mutex<", "()>>"].concat();
    for source in &owners[..6] {
        assert!(!source.contains(&qualified_mutex));
        assert!(!source.contains(&imported_mutex));
    }
    assert!(
        !main.contains(
            "let runtime_config_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));"
        )
    );
}

/// LAN-910: the `[[dynamic_neighbors]]` executor commits by snapshot
/// replacement, so this inventory comparison is its only listener fence —
/// `delete_dynamic_range`'s per-range fence never runs for transactions.
#[test]
fn dynamic_range_listener_auth_inventory_flags_protected_range_changes() {
    const MD5_RANGE: &str = r#"
[[dynamic_neighbors]]
prefix = "10.9.0.0/24"
peer_group = "md5-members"
"#;
    const GTSM_RANGE: &str = r#"
[[dynamic_neighbors]]
prefix = "10.10.0.0/24"
peer_group = "gtsm-members"
"#;
    const PLAIN_RANGE: &str = r#"
[[dynamic_neighbors]]
prefix = "10.8.0.0/24"
peer_group = "plain"
"#;
    let load = |ranges: &str| {
        Config::load_toml_with_diagnostics(
            &format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.md5-members]
md5_password = "secret"

[peer_groups.gtsm-members]
ttl_security = true

[peer_groups.plain]
{ranges}
"#
            ),
            "inventory test config",
        )
        .expect("inventory test config must parse")
    };
    let full = load(&format!("{MD5_RANGE}{GTSM_RANGE}{PLAIN_RANGE}"));
    let no_plain = load(&format!("{MD5_RANGE}{GTSM_RANGE}"));
    let no_md5 = load(&format!("{GTSM_RANGE}{PLAIN_RANGE}"));
    let no_gtsm = load(&format!("{MD5_RANGE}{PLAIN_RANGE}"));

    assert_eq!(
        dynamic_range_listener_auth_inventory(&full),
        dynamic_range_listener_auth_inventory(&no_plain),
        "removing an unprotected range must not change the listener inventory"
    );
    assert_ne!(
        dynamic_range_listener_auth_inventory(&full),
        dynamic_range_listener_auth_inventory(&no_md5),
        "removing an MD5-protected range must change the listener inventory"
    );
    assert_ne!(
        dynamic_range_listener_auth_inventory(&full),
        dynamic_range_listener_auth_inventory(&no_gtsm),
        "removing a GTSM-protected range must change the listener inventory"
    );
}

#[tokio::test]
async fn accepted_runtime_snapshot_keeps_split_runtime_external_state_document_only() {
    let dir = tempfile::tempdir().unwrap();
    let runtime_rpol = dir.path().join("runtime.rpol");
    let runtime_dataset = dir.path().join("runtime-customers.txt");
    let desired_rpol = dir.path().join("desired.rpol");
    let desired_dataset = dir.path().join("desired-customers.txt");
    for path in [
        &runtime_rpol,
        &runtime_dataset,
        &desired_rpol,
        &desired_dataset,
    ] {
        std::fs::write(path, "captured then deleted\n").unwrap();
    }

    let mut runtime = Config::load_toml_with_diagnostics(&base_toml(""), "runtime").unwrap();
    runtime.policy.rpol_files = vec![runtime_rpol.display().to_string()];
    runtime.policy.import_chain = vec!["runtime-in".to_string()];
    runtime.policy.datasets.insert(
        "runtime-customers".to_string(),
        crate::config::DatasetFileConfig {
            path: runtime_dataset.display().to_string(),
        },
    );

    let mut desired = Config::load_toml_with_diagnostics(&base_toml(""), "desired").unwrap();
    desired.policy.rpol_files = vec![desired_rpol.display().to_string()];
    desired.policy.import_chain = vec!["desired-in".to_string()];
    desired.policy.datasets.insert(
        "desired-customers".to_string(),
        crate::config::DatasetFileConfig {
            path: desired_dataset.display().to_string(),
        },
    );
    let desired_handle = Arc::new(rustbgpd_policy::datasets::DatasetHandle::new(
        "desired-customers",
        rustbgpd_policy::datasets::DatasetKind::Asn,
        rustbgpd_policy::datasets::DatasetData::Asn(rustbgpd_policy::sets::AsnSet::new([64500])),
    ));
    desired
        .policy
        .dataset_bindings
        .insert(Arc::clone(&desired_handle));
    let desired = AcceptedConfigSnapshot::from_config_for_test(desired);
    let (_accepted_tx, accepted_rx) = watch::channel(desired);

    let runtime_toml = crate::config::persisted_config_document(&runtime).unwrap();
    let runtime_rpol_files = runtime.policy.rpol_files.clone();
    for path in [runtime_rpol, runtime_dataset, desired_rpol, desired_dataset] {
        std::fs::remove_file(path).unwrap();
    }
    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        for _ in 0..2 {
            let Some(PeerManagerCommand::RuntimeConfigSnapshot { reply }) = peer_rx.recv().await
            else {
                panic!("accepted snapshot helper must request the PM runtime TOML");
            };
            reply
                .send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                    toml: runtime_toml.clone(),
                    rpol_files: runtime_rpol_files.clone(),
                    rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                }))
                .unwrap();
        }
    });
    let controller = ConfigTransactionController::new_accepted(
        deps_value(None, peer_tx, None, Vec::new()),
        BgpMetrics::new(),
        accepted_rx,
    );

    let gnmi_construction = controller.accepted_runtime_snapshot().await.unwrap();
    let confirmed_rollback = controller.accepted_runtime_snapshot().await.unwrap();
    for snapshot in [&gnmi_construction, &confirmed_rollback] {
        assert_eq!(snapshot.policy.import_chain, ["runtime-in"]);
        assert!(snapshot.policy.datasets.contains_key("runtime-customers"));
        assert!(!snapshot.policy.datasets.contains_key("desired-customers"));
        assert!(
            snapshot
                .policy
                .dataset_bindings
                .get("runtime-customers")
                .is_none()
        );
        assert!(
            snapshot
                .policy
                .dataset_bindings
                .get("desired-customers")
                .is_none()
        );
        assert!(snapshot.policy.rpol.policies.is_empty());
    }
    assert!(Arc::strong_count(&desired_handle) >= 1);
}

#[tokio::test]
async fn accepted_prior_snapshot_keeps_one_provenance_generation_across_await() {
    // Destructive proof: borrowing accepted_rx after the peer-manager await
    // labels the old runtime config with the replacement source manifest
    // sent while the reply is in flight, changing source_sha256 below.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("policy.rpol");
    let config_path = dir.path().join("rustbgpd.toml");
    std::fs::write(&source, "policy p { term rest { accept } }\n").unwrap();
    std::fs::write(
        &config_path,
        base_toml(&format!(
            "[policy]\nrpol_files = [{:?}]\n",
            source.display().to_string()
        )),
    )
    .unwrap();
    let prior = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    std::fs::write(&source, "policy p { term rest { reject } }\n").unwrap();
    let replacement = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    assert_ne!(prior.source_sha256(), replacement.source_sha256());

    let runtime_toml = prior.normalized_toml().to_string();
    let runtime_rpol_files = prior.config_ref().policy.rpol_files.clone();
    let runtime_rpol = prior.config_ref().policy.rpol.clone();
    let prior_source_sha256 = prior.source_sha256();
    let replacement_source_sha256 = replacement.source_sha256();
    let (accepted_tx, accepted_rx) = watch::channel(prior);
    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let Some(PeerManagerCommand::RuntimeConfigSnapshot { reply }) = peer_rx.recv().await else {
            panic!("accepted prior helper must request the runtime snapshot");
        };
        accepted_tx.send(replacement).unwrap();
        reply
            .send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                toml: runtime_toml,
                rpol_files: runtime_rpol_files,
                rpol: runtime_rpol,
            }))
            .unwrap();
    });
    let controller = ConfigTransactionController::new_accepted(
        deps_value(None, peer_tx, None, Vec::new()),
        BgpMetrics::new(),
        accepted_rx,
    );

    let snapshot = controller.accepted_prior_snapshot().await.unwrap();
    assert_eq!(snapshot.source_sha256(), prior_source_sha256);
    assert_ne!(snapshot.source_sha256(), replacement_source_sha256);
}

fn config_transaction_lifecycle_metric(
    controller: &ConfigTransactionController,
    operation: &str,
    outcome: &str,
) -> f64 {
    controller
        .metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_config_transaction_lifecycle_total")
        .and_then(|family| {
            family.metric.iter().find(|metric| {
                let label_value = |name| {
                    metric
                        .get_label()
                        .iter()
                        .find(|label| label.name() == name)
                        .map(prometheus::proto::LabelPair::value)
                };
                label_value("operation") == Some(operation)
                    && label_value("outcome") == Some(outcome)
            })
        })
        .map_or(0.0, |metric| metric.get_counter().value())
}

fn assert_config_transaction_lifecycle_metric(
    controller: &ConfigTransactionController,
    operation: &str,
    outcome: &str,
    expected: f64,
) {
    let actual = config_transaction_lifecycle_metric(controller, operation, outcome);
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "metric operation={operation} outcome={outcome}: got {actual}, expected {expected}"
    );
}

use crate::test_support::basic_fib_table as table;

fn snapshot(table: &FibTableConfig) -> FibTableSnapshot {
    FibTableSnapshot {
        name: table.name.clone(),
        table_id: table.table_id,
        metric: table.metric,
        families: table.families.clone(),
        allowed_peer_groups: table.allowed_peer_groups.clone(),
        allowed_neighbors: table.allowed_neighbors.clone(),
        max_routes: table.max_routes,
        maximum_paths: table.maximum_paths,
        maximum_paths_ebgp: table.maximum_paths_ebgp,
        maximum_paths_ibgp: table.maximum_paths_ibgp,
    }
}

fn fib_config(table: &FibTableConfig) -> Config {
    Config::load_toml_with_diagnostics(
        &base_toml(&format!(
            "[[fib_tables]]\nname = {:?}\ntable_id = {}\nmetric = {}\nfamilies = [\"ipv4_unicast\"]\n",
            table.name, table.table_id, table.metric
        )),
        "FIB transaction fixture",
    )
    .unwrap()
}

fn peer_config_from_toml(toml: &str, address: &str) -> PeerManagerNeighborConfig {
    let config =
        Config::load_toml_with_diagnostics(toml, "test config").expect("test config must parse");
    let address: std::net::IpAddr = address.parse().expect("test address must parse");
    let resolved = config.resolved_neighbors().expect("neighbors must resolve");
    let neighbor = resolved
        .iter()
        .find(|neighbor| neighbor.transport_config.remote_addr.ip() == address)
        .expect("neighbor must exist");
    crate::reload::build_peer_mgr_config(
        &neighbor.transport_config,
        neighbor.max_prefix_restart_seconds,
        &neighbor.label,
        neighbor.import_policy.as_ref(),
        neighbor.export_policy.as_ref(),
        neighbor.peer_group.clone(),
    )
}

fn gnmi_set_add_neighbor(
    address: &str,
    remote_asn: u64,
) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: vec![rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
            gnmi_neighbor_config_path(address, "peer-as"),
            rustbgpd_api::gnmi::typed_value::Value::UintVal(remote_asn),
        ))],
        commit_action: None,
    }
}

fn gnmi_set_add_neighbor_confirmed(
    address: &str,
    remote_asn: u64,
    confirm_id: &str,
    timeout_seconds: u32,
) -> rustbgpd_api::server::GnmiSetTransaction {
    let mut transaction = gnmi_set_add_neighbor(address, remote_asn);
    transaction.commit_action = Some(rustbgpd_api::server::GnmiSetCommitAction::Commit {
        confirm_id: confirm_id.to_string(),
        confirm_timeout_seconds: timeout_seconds,
    });
    transaction
}

fn gnmi_set_commit_confirm(confirm_id: &str) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: Vec::new(),
        commit_action: Some(rustbgpd_api::server::GnmiSetCommitAction::Confirm {
            confirm_id: confirm_id.to_string(),
        }),
    }
}

fn gnmi_set_commit_cancel(confirm_id: &str) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: Vec::new(),
        commit_action: Some(rustbgpd_api::server::GnmiSetCommitAction::Cancel {
            confirm_id: confirm_id.to_string(),
        }),
    }
}

fn gnmi_set_peer_group_hold_time(
    name: &str,
    hold_time: u64,
) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: vec![rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
            gnmi_peer_group_path(name, &["timers", "config", "hold-time"]),
            rustbgpd_api::gnmi::typed_value::Value::UintVal(hold_time),
        ))],
        commit_action: None,
    }
}

fn gnmi_set_dynamic_neighbor(
    prefix: &str,
    peer_group: &str,
) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: vec![
            rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                gnmi_dynamic_neighbor_path(prefix, &["config", "prefix"]),
                rustbgpd_api::gnmi::typed_value::Value::StringVal(prefix.to_string()),
            )),
            rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                gnmi_dynamic_neighbor_path(prefix, &["config", "peer-group"]),
                rustbgpd_api::gnmi::typed_value::Value::StringVal(peer_group.to_string()),
            )),
        ],
        commit_action: None,
    }
}

fn gnmi_set_rollback_duration(
    confirm_id: &str,
    timeout_seconds: u32,
) -> rustbgpd_api::server::GnmiSetTransaction {
    rustbgpd_api::server::GnmiSetTransaction {
        prefix: None,
        operations: Vec::new(),
        commit_action: Some(
            rustbgpd_api::server::GnmiSetCommitAction::SetRollbackDuration {
                confirm_id: confirm_id.to_string(),
                confirm_timeout_seconds: timeout_seconds,
            },
        ),
    }
}

fn gnmi_update(
    path: rustbgpd_api::gnmi::Path,
    value: rustbgpd_api::gnmi::typed_value::Value,
) -> rustbgpd_api::gnmi::Update {
    rustbgpd_api::gnmi::Update {
        path: Some(path),
        #[allow(deprecated)]
        value: None,
        val: Some(rustbgpd_api::gnmi::TypedValue { value: Some(value) }),
        duplicates: 0,
    }
}

fn gnmi_neighbor_config_path(address: &str, leaf: &str) -> rustbgpd_api::gnmi::Path {
    rustbgpd_api::gnmi::Path {
        #[allow(deprecated)]
        element: Vec::new(),
        origin: String::new(),
        elem: vec![
            gnmi_pe("network-instances"),
            gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
            gnmi_pe("protocols"),
            gnmi_protocol_pe(),
            gnmi_pe("bgp"),
            gnmi_pe("neighbors"),
            gnmi_keyed_pe("neighbor", "neighbor-address", address),
            gnmi_pe("config"),
            gnmi_pe(leaf),
        ],
        target: String::new(),
    }
}

fn gnmi_peer_group_path(name: &str, tail: &[&str]) -> rustbgpd_api::gnmi::Path {
    let mut elem = vec![
        gnmi_pe("network-instances"),
        gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
        gnmi_pe("protocols"),
        gnmi_protocol_pe(),
        gnmi_pe("bgp"),
        gnmi_pe("peer-groups"),
        gnmi_keyed_pe("peer-group", "peer-group-name", name),
    ];
    elem.extend(tail.iter().map(|name| gnmi_pe(name)));
    rustbgpd_api::gnmi::Path {
        #[allow(deprecated)]
        element: Vec::new(),
        origin: String::new(),
        elem,
        target: String::new(),
    }
}

fn gnmi_dynamic_neighbor_path(prefix: &str, tail: &[&str]) -> rustbgpd_api::gnmi::Path {
    let mut elem = vec![
        gnmi_pe("network-instances"),
        gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
        gnmi_pe("protocols"),
        gnmi_protocol_pe(),
        gnmi_pe("bgp"),
        gnmi_pe("global"),
        gnmi_pe("dynamic-neighbor-prefixes"),
        gnmi_keyed_pe("dynamic-neighbor-prefix", "prefix", prefix),
    ];
    elem.extend(tail.iter().map(|name| gnmi_pe(name)));
    rustbgpd_api::gnmi::Path {
        #[allow(deprecated)]
        element: Vec::new(),
        origin: String::new(),
        elem,
        target: String::new(),
    }
}

fn gnmi_pe(name: &str) -> rustbgpd_api::gnmi::PathElem {
    rustbgpd_api::gnmi::PathElem {
        name: name.to_string(),
        key: HashMap::new(),
    }
}

fn gnmi_keyed_pe(name: &str, key: &str, value: &str) -> rustbgpd_api::gnmi::PathElem {
    rustbgpd_api::gnmi::PathElem {
        name: name.to_string(),
        key: HashMap::from([(key.to_string(), value.to_string())]),
    }
}

fn gnmi_protocol_pe() -> rustbgpd_api::gnmi::PathElem {
    rustbgpd_api::gnmi::PathElem {
        name: "protocol".to_string(),
        key: HashMap::from([
            ("identifier".to_string(), "BGP".to_string()),
            ("name".to_string(), "BGP".to_string()),
        ]),
    }
}

#[test]
fn resolve_static_neighbors_resolves_only_touched_neighbors() {
    let candidate = Config::load_toml_with_diagnostics(
        &base_toml(
            r#"
[peer_groups.edge]
hold_time = 75
max_prefixes = 9000

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "edge"
"#,
        ),
        "candidate config",
    )
    .expect("candidate must parse");
    let touched = candidate
        .neighbors
        .iter()
        .find(|neighbor| neighbor.address == "10.0.0.3")
        .expect("target neighbor must exist")
        .clone();

    let resolved =
        resolve_static_neighbors(&candidate, &[touched]).expect("target neighbor must resolve");

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].address.to_string(), "10.0.0.3");
    assert_eq!(resolved[0].peer_group.as_deref(), Some("edge"));
    assert_eq!(resolved[0].hold_time, Some(75));
    assert_eq!(resolved[0].max_prefixes, Some(9000));
}

#[test]
fn peer_lifecycle_errors_map_to_transaction_apply_classes() {
    let peer = PeerKey::new("10.0.0.2".parse().unwrap(), None);
    let duplicate =
        peer_lifecycle_error_to_apply_error(PeerLifecycleError::AlreadyExists(peer.clone()));
    assert!(matches!(
        duplicate,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("already exists")
    ));

    let missing = peer_lifecycle_error_to_apply_error(PeerLifecycleError::NotFound(peer));
    assert!(matches!(
        missing,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("not found")
    ));

    let invalid =
        peer_lifecycle_error_to_apply_error(PeerLifecycleError::Invalid("bad".to_string()));
    assert!(matches!(
        invalid,
        ConfigTransactionApplyError::InvalidArgument(ref message) if message == "bad"
    ));

    let restart = peer_lifecycle_error_to_apply_error(PeerLifecycleError::RestartRequired(
        "restart".to_string(),
    ));
    assert!(matches!(
        restart,
        ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "restart"
    ));

    let internal =
        peer_lifecycle_error_to_apply_error(PeerLifecycleError::Internal("boom".to_string()));
    assert!(matches!(
        internal,
        ConfigTransactionApplyError::Internal(ref message) if message == "boom"
    ));
}

#[test]
fn transaction_plan_errors_map_without_string_matching() {
    let stale = plan_error_to_status(RuntimeConfigTransactionPlanError::StaleSnapshot {
        expected: "old".to_string(),
        current: "new".to_string(),
    });
    assert!(matches!(
        stale,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("expected old, current new")
    ));

    let invalid = plan_error_to_status(RuntimeConfigTransactionPlanError::InvalidCandidate(
        "bad toml".to_string(),
    ));
    assert!(matches!(
        invalid,
        ConfigTransactionApplyError::InvalidArgument(ref message) if message == "bad toml"
    ));
}

fn diff() -> RuntimeConfigDiff {
    RuntimeConfigDiff {
        has_actionable_changes: true,
        has_reload_applied_changes: true,
        has_restart_required_changes: false,
        has_informational_changes: false,
        has_any_changes: true,
        human_text: "Reload-applied changes:\n".to_string(),
        diff_json: "{}".to_string(),
    }
}

fn plan(
    status: RuntimeConfigTransactionStatus,
    supported_sections: Vec<String>,
) -> RuntimeConfigTransactionPlan {
    RuntimeConfigTransactionPlan {
        status,
        runtime_snapshot_token: "kv1:old:1".to_string(),
        post_commit_runtime_snapshot_token: "kv1:new:2".to_string(),
        committed_candidate: None,
        diff: diff(),
        supported_sections,
        unsupported_sections: Vec::new(),
        restart_required_sections: Vec::new(),
        human_text: String::new(),
        update_group_impact: rustbgpd_rib::UpdateGroupImpactPlan::default(),
    }
}

fn attach_committed_candidate(
    mut plan: RuntimeConfigTransactionPlan,
    candidate_toml: &str,
) -> RuntimeConfigTransactionPlan {
    if plan.status == RuntimeConfigTransactionStatus::Committable
        && plan.committed_candidate.is_none()
    {
        let candidate = Config::load_toml_with_diagnostics(
            candidate_toml,
            "fake transaction planner candidate",
        )
        .expect("fake planner candidate must load");
        plan.committed_candidate = Some(RuntimeConfigTransactionCandidate::new(
            crate::config::persisted_config_document(&candidate)
                .expect("fake planner candidate must serialize"),
        ));
    }
    plan
}

async fn fake_peer_manager(
    mut rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    staged: Arc<Mutex<Vec<FibTableSnapshot>>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                reply,
                ..
            } => {
                let _ = reply.send(Ok(attach_committed_candidate(
                    plan.clone(),
                    &candidate_toml,
                )));
            }
            PeerManagerCommand::StageFibTables { tables, reply } => {
                *staged.lock().await = tables;
                let _ = reply.send(Ok(()));
            }
            PeerManagerCommand::SetFibTablesSnapshot { tables, reply } => {
                *staged.lock().await = tables;
                let _ = reply.send(());
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                let _ = reply.send(());
            }
            _ => panic!("unexpected peer-manager command in config transaction test"),
        }
    }
}

async fn fake_fib_actor(
    mut rx: mpsc::Receiver<FibRuntimeCommand>,
    state: Arc<Mutex<Vec<FibTableConfig>>>,
    replace_result: Option<Result<(), String>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            FibRuntimeCommand::GetTables { reply } => {
                let _ = reply.send(state.lock().await.clone());
            }
            FibRuntimeCommand::OwnedReplaceTables { tables, reply } => {
                let result = replace_result.clone().unwrap_or(Ok(()));
                let outcome = match result {
                    Ok(()) => {
                        *state.lock().await = tables;
                        OwnedFibReplaceOutcome::Applied
                    }
                    Err(error) => OwnedFibReplaceOutcome::RejectedNoEffect(error),
                };
                let _ = reply.send(outcome);
            }
        }
    }
}

fn spawn_typed_transaction_manager(
    snapshot_toml: Arc<Mutex<String>>,
    response: RuntimeConfigTransactionPlan,
) -> mpsc::Sender<InternalCommand> {
    spawn_typed_transaction_manager_controlled(
        snapshot_toml,
        response,
        TypedTransactionFakeControl::default(),
    )
}

#[derive(Clone, Default)]
struct TypedTransactionFakeControl {
    plans: Arc<Mutex<VecDeque<RuntimeConfigTransactionPlan>>>,
    stage_results: Arc<Mutex<VecDeque<Result<(), String>>>>,
    drop_stage_ack: Arc<AtomicBool>,
    drop_restore_ack: Arc<AtomicBool>,
}

fn spawn_typed_transaction_manager_controlled(
    snapshot_toml: Arc<Mutex<String>>,
    response: RuntimeConfigTransactionPlan,
    control: TypedTransactionFakeControl,
) -> mpsc::Sender<InternalCommand> {
    let initial = Config::load_toml_with_diagnostics(
        snapshot_toml
            .try_lock()
            .expect("typed transaction fake snapshot must be idle")
            .as_str(),
        "typed transaction fake initial config",
    )
    .expect("typed transaction fake initial config must load");
    let current = Arc::new(Mutex::new(initial));
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(fake_typed_transaction_manager_actor(
        rx,
        current,
        snapshot_toml,
        response,
        control,
    ));
    tx
}

fn spawn_typed_transaction_manager_with_current(
    current: Arc<Mutex<Config>>,
    response: RuntimeConfigTransactionPlan,
) -> mpsc::Sender<InternalCommand> {
    let snapshot_toml = Arc::new(Mutex::new(
        crate::config::persisted_config_document(
            &current
                .try_lock()
                .expect("typed transaction fake config must be idle"),
        )
        .expect("typed transaction fake config must serialize"),
    ));
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(fake_typed_transaction_manager_actor(
        rx,
        current,
        snapshot_toml,
        response,
        TypedTransactionFakeControl::default(),
    ));
    tx
}

async fn fake_typed_transaction_manager_actor(
    mut rx: mpsc::Receiver<InternalCommand>,
    current: Arc<Mutex<Config>>,
    snapshot_toml: Arc<Mutex<String>>,
    response: RuntimeConfigTransactionPlan,
    control: TypedTransactionFakeControl,
) {
    let mut plan_calls = 0usize;
    while let Some(command) = rx.recv().await {
        match command {
            InternalCommand::PlanTransactionConfig {
                candidate, reply, ..
            } => {
                let candidate_toml = crate::config::persisted_config_document(&candidate)
                    .expect("typed fake candidate must serialize");
                let response = control
                    .plans
                    .lock()
                    .await
                    .pop_front()
                    .unwrap_or_else(|| response.clone());
                let mut plan = attach_committed_candidate(response.clone(), &candidate_toml);
                if plan_calls > 0 {
                    plan.runtime_snapshot_token =
                        response.post_commit_runtime_snapshot_token.clone();
                }
                plan_calls += 1;
                let _ = reply.send(Ok(PlannedTransactionConfig { plan, candidate }));
            }
            InternalCommand::PlanAcceptedTransactionConfig {
                snapshot, reply, ..
            } => {
                let candidate = Box::new(snapshot.config());
                let candidate_toml = crate::config::persisted_config_document(&candidate)
                    .expect("typed fake retained candidate must serialize");
                let response = control
                    .plans
                    .lock()
                    .await
                    .pop_front()
                    .unwrap_or_else(|| response.clone());
                let mut plan = attach_committed_candidate(response.clone(), &candidate_toml);
                if plan_calls > 0 {
                    plan.runtime_snapshot_token =
                        response.post_commit_runtime_snapshot_token.clone();
                }
                plan_calls += 1;
                let _ = reply.send(Ok(PlannedTransactionConfig { plan, candidate }));
            }
            InternalCommand::StageTransactionConfig {
                candidate,
                scope,
                reply,
            } => {
                if let Some(Err(error)) = control.stage_results.lock().await.pop_front() {
                    let _ = reply.send(Err(error));
                    continue;
                }
                let mut current = current.lock().await;
                let staged = match scope {
                    TransactionConfigScope::Full => *candidate,
                    TransactionConfigScope::FibTablesOnly => {
                        let mut staged = current.clone();
                        staged.fib_tables.clone_from(&candidate.fib_tables);
                        staged.config_epoch = candidate.config_epoch;
                        staged.global.ebgp_requires_policy = candidate.global.ebgp_requires_policy;
                        staged
                    }
                };
                let previous = std::mem::replace(&mut *current, staged);
                *snapshot_toml.lock().await = crate::config::persisted_config_document(&current)
                    .expect("typed fake staged config must serialize");
                let rollback = TransactionConfigRollbackToken::capture(Box::new(previous), scope);
                if control.drop_stage_ack.load(Ordering::Relaxed) {
                    drop(reply);
                } else {
                    let _ = reply.send(Ok(rollback));
                }
            }
            InternalCommand::RestoreTransactionConfig { rollback, reply } => {
                *current.lock().await = rollback.previous().clone();
                *snapshot_toml.lock().await =
                    crate::config::persisted_config_document(rollback.previous())
                        .expect("typed fake restored config must serialize");
                if control.drop_restore_ack.load(Ordering::Relaxed) {
                    drop(reply);
                } else {
                    let _ = reply.send(());
                }
            }
            InternalCommand::ReplaceConfigSnapshot { .. } => {
                panic!("unexpected internal command in transaction snapshot fake")
            }
        }
    }
}

async fn fake_snapshot_peer_manager(
    rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
    peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
) {
    fake_snapshot_peer_manager_recording_bounces(
        rx,
        plan,
        snapshot_toml,
        peers,
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
}

/// `fake_snapshot_peer_manager` with a recorder for
/// `BounceDynamicRangePeers` selectors. The fake reports one signaled
/// session per targeted range and no failures.
async fn fake_snapshot_peer_manager_recording_bounces(
    rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
    peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
    bounce_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
) {
    fake_snapshot_peer_manager_recording_bounces_and_purges(
        rx,
        plan,
        snapshot_toml,
        peers,
        bounce_calls,
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
}

async fn fake_snapshot_peer_manager_recording_bounces_and_purges(
    mut rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
    peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
    bounce_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
    purge_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                reply,
                ..
            } => {
                let _ = reply.send(Ok(attach_committed_candidate(
                    plan.clone(),
                    &candidate_toml,
                )));
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                let _ = reply.send(());
            }
            PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                    toml: snapshot_toml.lock().await.clone(),
                    rpol_files: Vec::new(),
                    rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                }));
            }
            PeerManagerCommand::AddPeer { config, reply, .. } => {
                let mut peers = peers.lock().await;
                let key = PeerKey::new(config.address, config.interface.clone());
                if peers
                    .iter()
                    .any(|peer| PeerKey::new(peer.address, peer.interface.clone()) == key)
                {
                    let _ = reply.send(Err(PeerLifecycleError::AlreadyExists(key)));
                } else {
                    peers.push(config);
                    let _ = reply.send(Ok(()));
                }
            }
            PeerManagerCommand::DeletePeer { peer, reply, .. } => {
                let mut peers = peers.lock().await;
                if let Some(index) = peers.iter().position(|config| {
                    PeerKey::new(config.address, config.interface.clone()) == peer
                }) {
                    let _ = reply.send(Ok(peers.remove(index)));
                } else {
                    let _ = reply.send(Err(PeerLifecycleError::NotFound(peer)));
                }
            }
            PeerManagerCommand::ReconfigurePeer { config, reply } => {
                let mut peers = peers.lock().await;
                let _ = reply.send(fake_replace_peer_config(&mut peers, config));
            }
            PeerManagerCommand::ApplyPeerReshapeSnapshot { targets, reply } => {
                let mut peers = peers.lock().await;
                let _ = reply.send(fake_apply_peer_reshape_snapshot(&mut peers, targets));
            }
            PeerManagerCommand::BounceDynamicRangePeers {
                ranges,
                purge_ranges,
                reply,
            } => {
                let signaled = ranges.len();
                bounce_calls.lock().await.push(ranges);
                purge_calls.lock().await.push(purge_ranges);
                let _ = reply.send(DynamicPeerBounceOutcome {
                    signaled,
                    failures: Vec::new(),
                });
            }
            _ => panic!("unexpected peer-manager command in snapshot transaction test"),
        }
    }
}

fn fake_replace_peer_config(
    peers: &mut [PeerManagerNeighborConfig],
    config: PeerManagerNeighborConfig,
) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
    let key = PeerKey::new(config.address, config.interface.clone());
    if let Some(existing) = peers
        .iter_mut()
        .find(|existing| PeerKey::new(existing.address, existing.interface.clone()) == key)
    {
        Ok(std::mem::replace(existing, config))
    } else {
        Err(PeerLifecycleError::NotFound(key))
    }
}

fn fake_apply_peer_reshape_snapshot(
    peers: &mut [PeerManagerNeighborConfig],
    targets: Vec<PeerManagerNeighborConfig>,
) -> Result<Vec<PeerManagerNeighborConfig>, PeerLifecycleError> {
    let mut seen = BTreeSet::new();
    for target in &targets {
        let key = PeerKey::new(target.address, target.interface.clone());
        if !seen.insert(key.clone()) {
            return Err(PeerLifecycleError::Invalid(format!(
                "peer reshape target {key} appears more than once"
            )));
        }
    }
    let mut priors = Vec::with_capacity(targets.len());
    for target in targets {
        match fake_replace_peer_config(peers, target) {
            Ok(prior) => priors.push(prior),
            Err(error) => {
                for prior in priors.into_iter().rev() {
                    let _ = fake_replace_peer_config(peers, prior);
                }
                return Err(error);
            }
        }
    }
    Ok(priors)
}

/// Like `fake_snapshot_peer_manager`, but answers each successive
/// `PlanConfigTransaction` with the next queued plan — lets a test give
/// the initial apply a Committable plan and the rollback re-apply a
/// Rejected one.
async fn fake_snapshot_peer_manager_with_plans(
    mut rx: mpsc::Receiver<PeerManagerCommand>,
    plans: Arc<Mutex<VecDeque<RuntimeConfigTransactionPlan>>>,
    snapshot_toml: Arc<Mutex<String>>,
    peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                reply,
                ..
            } => {
                let plan = plans
                    .lock()
                    .await
                    .pop_front()
                    .expect("test queued too few transaction plans");
                let _ = reply.send(Ok(attach_committed_candidate(plan, &candidate_toml)));
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                let _ = reply.send(());
            }
            PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                    toml: snapshot_toml.lock().await.clone(),
                    rpol_files: Vec::new(),
                    rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                }));
            }
            PeerManagerCommand::AddPeer { config, reply, .. } => {
                peers.lock().await.push(config);
                let _ = reply.send(Ok(()));
            }
            _ => panic!("unexpected peer-manager command in queued-plan transaction test"),
        }
    }
}

/// A config with one static neighbor whose import chain resolves to a
/// named policy whose `default_action` is `action`. Diffing permit vs deny
/// produces a pure static-neighbor policy-chain impact.
/// Dynamic-range transaction tests use `dynamic_live_policy_toml`.
fn live_policy_toml(action: &str) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.f]
default_action = "{action}"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["f"]
"#
    ))
}

fn dynamic_live_policy_toml(action: &str) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
import_policy_chain = ["f"]

[policy.definitions.f]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.9/16"
peer_group = "ix"
remote_asn = 65030
"#
    ))
}

fn peer_group_reshape_toml(hold_time: u32) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = {hold_time}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
"#
    ))
}

/// Peer group referenced only by a `[[dynamic_neighbors]]` range: a
/// hold-time edit is a dynamic-range session reshape with no static
/// members.
fn dynamic_peer_group_reshape_toml(hold_time: u32) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
hold_time = {hold_time}

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
    ))
}

fn dynamic_discard_reshape_toml(discard_med: bool) -> String {
    let discard = if discard_med {
        "discard_path_attributes = [4]"
    } else {
        ""
    };
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
route_server_client = true
{discard}

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#,
    ))
}

/// The same dynamic-only peer group varying `md5_password` instead of
/// `hold_time`: a session reshape that also moves the startup/SIGHUP-pinned
/// listener key inventory for the range's prefix.
fn dynamic_peer_group_md5_reshape_toml(md5_password: &str) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
hold_time = 90
md5_password = "{md5_password}"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
    ))
}

fn dynamic_required_families_toml(required: bool) -> String {
    let required = if required {
        "required_families = [\"ipv6_unicast\"]"
    } else {
        "required_families = []"
    };
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[peer_groups.ix]
families = ["ipv4_unicast", "ipv6_unicast"]
{required}
[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
    ))
}

/// Peer group with one static member and one `[[dynamic_neighbors]]`
/// range: a hold-time edit reshapes the static member and resets the
/// range's live dynamic sessions.
fn mixed_peer_group_reshape_toml(hold_time: u32) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = {hold_time}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "edge"
remote_asn = 65030
"#
    ))
}

fn peer_group_reassignment_toml(group: &str) -> String {
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[peer_groups.core]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "{group}"
"#
    ))
}

fn resolved_static_peer_configs(toml: &str) -> Vec<PeerManagerNeighborConfig> {
    let config = Config::load_toml_with_diagnostics(toml, "peer reshape test config")
        .expect("test config must load");
    resolve_static_neighbors(&config, &config.neighbors).expect("test config peers must resolve")
}

fn peer_session_reshape_plan() -> RuntimeConfigTransactionPlan {
    plan(
        RuntimeConfigTransactionStatus::Committable,
        vec![
            "[peer_groups] catalog".to_string(),
            "effective neighbor session reshape".to_string(),
        ],
    )
}

/// Public half of the live-impact executor fake: serves the plan and drives
/// each policy-impact or
/// resolved-policy apply from `apply_results` (Ok returns the next
/// `captured_priors` entry, falling back to echoing targets when the test
/// does not care about the returned prior payload; Err simulates a mid-fanout
/// failure). Records static targets in `apply_calls` and dynamic selectors
/// in `dynamic_calls`.
async fn fake_live_policy_peer_manager(
    mut rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    _snapshot_toml: Arc<Mutex<String>>,
    apply_results: Arc<Mutex<VecDeque<Result<(), String>>>>,
    captured_priors: Arc<Mutex<VecDeque<Vec<ResolvedPeerPolicy>>>>,
    apply_calls: Arc<Mutex<Vec<Vec<ResolvedPeerPolicy>>>>,
    dynamic_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
) {
    let mut plan_calls = 0usize;
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                expected_runtime_snapshot_token,
                verify_external_inputs: _,
                reply,
            } => {
                let mut response = attach_committed_candidate(plan.clone(), &candidate_toml);
                if plan_calls > 0 {
                    response.runtime_snapshot_token =
                        plan.post_commit_runtime_snapshot_token.clone();
                }
                plan_calls += 1;
                if let Some(expected) =
                    expected_runtime_snapshot_token.filter(|value| !value.is_empty())
                    && expected != response.runtime_snapshot_token
                {
                    let _ = reply.send(Err(RuntimeConfigTransactionPlanError::StaleSnapshot {
                        expected,
                        current: response.runtime_snapshot_token,
                    }));
                } else {
                    let _ = reply.send(Ok(response));
                }
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                let _ = reply.send(());
            }
            PeerManagerCommand::ApplyPolicyImpactSnapshot {
                static_targets,
                dynamic_ranges,
                reply,
            } => {
                apply_calls.lock().await.push(static_targets.clone());
                dynamic_calls.lock().await.push(dynamic_ranges);
                match apply_results.lock().await.pop_front().unwrap_or(Ok(())) {
                    Ok(()) => {
                        let priors = captured_priors
                            .lock()
                            .await
                            .pop_front()
                            .unwrap_or_else(|| static_targets.clone());
                        let _ = reply.send(Ok(priors));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            PeerManagerCommand::ApplyResolvedPolicySnapshot { targets, reply } => {
                apply_calls.lock().await.push(targets.clone());
                dynamic_calls.lock().await.push(Vec::new());
                match apply_results.lock().await.pop_front().unwrap_or(Ok(())) {
                    Ok(()) => {
                        let priors = captured_priors
                            .lock()
                            .await
                            .pop_front()
                            .unwrap_or_else(|| targets.clone());
                        let _ = reply.send(Ok(priors));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            _ => panic!("unexpected peer-manager command in live-policy transaction test"),
        }
    }
}

fn deps_value(
    fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config_tx: Option<mpsc::Sender<rustbgpd_api::peer_types::ConfigEvent>>,
    startup_tables: Vec<FibTableConfig>,
) -> FibTableControlDeps {
    FibTableControlDeps {
        fib_cmd_tx,
        peer_mgr_tx,
        rib_tx: None,
        config_tx,
        lock: rustbgpd_api::server::RuntimeConfigCoordinator::new(),
        config_mutation_gate: None,
        startup_tables,
        confirm_journal_path: None,
        config_history_dir: None,
    }
}

fn deps(
    fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config_tx: Option<mpsc::Sender<rustbgpd_api::peer_types::ConfigEvent>>,
    startup_tables: Vec<FibTableConfig>,
) -> Arc<FibTableControlDeps> {
    Arc::new(deps_value(
        fib_cmd_tx,
        peer_mgr_tx,
        config_tx,
        startup_tables,
    ))
}

#[tokio::test(start_paused = true)]
async fn apply_times_out_before_coordinator_ownership_without_mutation() {
    let coordinator = rustbgpd_api::server::RuntimeConfigCoordinator::new();
    let blocker = coordinator.acquire().await.expect("coordinator owner");
    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    let (fib_tx, mut fib_rx) = mpsc::channel(1);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let (config_tx, mut config_rx) = mpsc::channel(1);
    let runtime = tempfile::tempdir().unwrap();
    let journal = runtime.path().join("commit-confirm-journal.json");
    let controller = ConfigTransactionController::new(
        FibTableControlDeps {
            lock: coordinator.clone(),
            rib_tx: Some(rib_tx),
            confirm_journal_path: Some(journal.clone()),
            ..deps_value(Some(fib_tx), peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
    );
    let apply = tokio::spawn(controller.clone().apply(confirmed_dynamic_request(
        base_toml("[peer_groups.blocked]"),
        "blocked-apply",
        60,
    )));
    tokio::task::yield_now().await;

    // This wall-clock oracle intentionally does not use the implementation constant: any
    // production drift from the ten-minute contract must make the test fail.
    tokio::time::advance(Duration::from_secs(599)).await;
    tokio::task::yield_now().await;
    assert!(!apply.is_finished(), "apply timed out before ten minutes");
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = apply.await.unwrap().unwrap_err();
    assert_eq!(
        error,
        ConfigTransactionApplyError::DeadlineExceeded(
            "config transaction timed out waiting for the runtime config coordinator; \
             coordinator ownership was not acquired and apply did not begin"
                .to_string()
        )
    );

    assert!(peer_rx.try_recv().is_err());
    assert!(fib_rx.try_recv().is_err());
    assert!(rib_rx.try_recv().is_err());
    assert!(config_rx.try_recv().is_err());
    assert!(!journal.exists());
    let state = controller.state.lock().await;
    assert!(state.applying_confirm_id.is_none());
    assert!(state.pending.is_none());
    assert!(state.last.is_none());
    assert!(state.ambiguous_failure_confirm_id.is_none());
    drop(state);

    drop(blocker);
    let next = tokio::spawn(
        controller
            .clone()
            .apply(proto::ApplyConfigTransactionRequest {
                candidate_toml: base_toml(""),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: "after-timeout".to_string(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            }),
    );
    let PeerManagerCommand::PlanConfigTransaction {
        candidate_toml,
        reply,
        ..
    } = peer_rx.recv().await.unwrap()
    else {
        panic!("unexpected peer-manager command after coordinator timeout");
    };
    assert_eq!(
        candidate_toml,
        base_toml(""),
        "timed-out apply remained queued"
    );
    reply
        .send(Ok(plan(RuntimeConfigTransactionStatus::Noop, Vec::new())))
        .unwrap();
    let response = next.await.unwrap().unwrap();
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Noop as i32
    );
    assert!(fib_rx.try_recv().is_err());
    assert!(rib_rx.try_recv().is_err());
    assert!(config_rx.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn apply_close_before_deadline_is_unavailable_without_mutation() {
    let coordinator = rustbgpd_api::server::RuntimeConfigCoordinator::new();
    let _owner = coordinator.acquire().await.expect("coordinator owner");
    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    let (fib_tx, mut fib_rx) = mpsc::channel(1);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let (config_tx, mut config_rx) = mpsc::channel(1);
    let runtime = tempfile::tempdir().unwrap();
    let journal = runtime.path().join("commit-confirm-journal.json");
    let controller = ConfigTransactionController::new(
        FibTableControlDeps {
            lock: coordinator.clone(),
            rib_tx: Some(rib_tx),
            confirm_journal_path: Some(journal.clone()),
            ..deps_value(Some(fib_tx), peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
    );
    let apply = tokio::spawn(controller.clone().apply(confirmed_dynamic_request(
        base_toml("[peer_groups.blocked]"),
        "closed-apply",
        60,
    )));
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(599)).await;
    tokio::task::yield_now().await;
    assert!(
        !apply.is_finished(),
        "apply ended before coordinator closure"
    );
    coordinator.close();
    let error = apply.await.unwrap().unwrap_err();
    assert!(
        matches!(error, ConfigTransactionApplyError::Unavailable(ref message)
            if message.contains("coordinator is closed")),
        "{error:?}"
    );
    assert!(peer_rx.try_recv().is_err());
    assert!(fib_rx.try_recv().is_err());
    assert!(rib_rx.try_recv().is_err());
    assert!(config_rx.try_recv().is_err());
    assert!(!journal.exists());
    let state = controller.state.lock().await;
    assert!(state.applying_confirm_id.is_none());
    assert!(state.pending.is_none());
    assert!(state.last.is_none());
    assert!(state.ambiguous_failure_confirm_id.is_none());
}

#[tokio::test]
async fn apply_requires_snapshot_token() {
    let (peer_tx, _peer_rx) = mpsc::channel(1);
    let err = apply_config_transaction(
        deps(None, peer_tx, None, Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: base_toml(""),
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::InvalidArgument(ref message) if message.contains("expected_runtime_snapshot_token")),
        "{err:?}"
    );
}

#[tokio::test]
async fn apply_rejects_cross_family_candidate_without_mutation() {
    let (peer_tx, peer_rx) = mpsc::channel(8);
    let staged = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(fake_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[[dynamic_neighbors]]".to_string(),
                "[[fib_tables]]".to_string(),
            ],
        ),
        staged.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(1);

    let response = apply_config_transaction(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: base_toml(
                r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
            ),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Rejected as i32
    );
    assert!(response.committed_sections.is_empty());
    assert!(staged.lock().await.is_empty());
    assert!(matches!(
        config_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty
            | tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}

#[tokio::test]
async fn apply_commits_dynamic_neighbors_full_set_after_persist_ack() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
    );
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("[[dynamic_neighbors]]"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx.clone(), Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(response.committed_sections, vec!["[[dynamic_neighbors]]"]);
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
}

async fn ack_config_transaction_commits(mut config_rx: mpsc::Receiver<ConfigEvent>) {
    while let Some(ConfigEvent::ConfigTransactionCommitted { ack, .. }) = config_rx.recv().await {
        if let Some(ack) = ack {
            ack.accept().await;
        }
    }
}

/// Persister that reports a clean write failure: the config file was
/// provably NOT replaced (unambiguous persist failure).
async fn reject_config_transaction_commits(mut config_rx: mpsc::Receiver<ConfigEvent>) {
    while let Some(ConfigEvent::ConfigTransactionCommitted { ack, .. }) = config_rx.recv().await {
        if let Some(ack) = ack {
            ack.fail_write("persist rejected by test");
        }
    }
}

/// Persister whose acknowledgement is lost (LAN-277 window (b)): the
/// caller can never learn whether the write happened.
async fn drop_config_transaction_commit_acks(mut config_rx: mpsc::Receiver<ConfigEvent>) {
    while let Some(ConfigEvent::ConfigTransactionCommitted { ack, .. }) = config_rx.recv().await {
        drop(ack);
    }
}

/// `fake_snapshot_peer_manager`, except `CommitConfigSnapshotStage` drops
/// its reply — the persist has already succeeded when that command runs,
/// so this simulates a post-persist finalization failure (LAN-277 window
/// (a)).
async fn fake_snapshot_peer_manager_dropping_stage_commit(
    mut rx: mpsc::Receiver<PeerManagerCommand>,
    plan: RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                reply,
                ..
            } => {
                let _ = reply.send(Ok(attach_committed_candidate(
                    plan.clone(),
                    &candidate_toml,
                )));
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                drop(reply);
            }
            PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                    toml: snapshot_toml.lock().await.clone(),
                    rpol_files: Vec::new(),
                    rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                }));
            }
            _ => panic!("unexpected peer-manager command in stage-commit-drop test"),
        }
    }
}

fn confirmed_dynamic_request(
    candidate_toml: String,
    confirm_id: &str,
    confirm_timeout_seconds: u32,
) -> proto::ApplyConfigTransactionRequest {
    proto::ApplyConfigTransactionRequest {
        candidate_toml,
        expected_runtime_snapshot_token: "kv1:old:1".to_string(),
        client_request_id: "deploy-1".to_string(),
        comment: "confirmed deploy".to_string(),
        confirm_id: confirm_id.to_string(),
        confirm_timeout_seconds,
    }
}

async fn confirmed_dynamic_controller(
    previous_toml: String,
    candidate_toml: String,
) -> (
    ConfigTransactionController,
    Arc<Mutex<String>>,
    tokio::task::JoinHandle<()>,
) {
    confirmed_dynamic_controller_with_journal(previous_toml, candidate_toml, None).await
}

async fn confirmed_dynamic_controller_with_journal(
    previous_toml: String,
    candidate_toml: String,
    confirm_journal_path: Option<std::path::PathBuf>,
) -> (
    ConfigTransactionController,
    Arc<Mutex<String>>,
    tokio::task::JoinHandle<()>,
) {
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            FibTableControlDeps {
                confirm_journal_path,
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    let response = controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml.clone(),
            "deploy-1",
            60,
        ))
        .await
        .expect("confirmed apply must succeed");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    let confirmation = response
        .confirmation
        .as_ref()
        .expect("confirmed apply must return pending metadata");
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    (controller, snapshot_toml, ack_task)
}

fn assert_snapshot_matches_config(snapshot_toml: &str, expected_toml: &str) {
    let snapshot = Config::load_toml_with_diagnostics(snapshot_toml, "restored runtime snapshot")
        .expect("restored snapshot must parse");
    let expected = Config::load_toml_with_diagnostics(expected_toml, "expected runtime snapshot")
        .expect("expected snapshot must parse");
    // Durable snapshots materialize the effective epoch/policy; compare the
    // complete canonical fixpoint rather than raw Option presence.
    assert_eq!(
        crate::config::persisted_config_document(&snapshot).unwrap(),
        crate::config::persisted_config_document(&expected).unwrap(),
    );
}

fn with_v3_test_authority(
    deps: FibTableControlDeps,
    dir: &std::path::Path,
    prior_toml: &str,
) -> ConfigTransactionController {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = dir.join("rustbgpd.toml");
    std::fs::write(&config_path, prior_toml).unwrap();
    ConfigTransactionController::new(deps, BgpMetrics::new()).with_confirm_v3_launch(
        crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap(),
    )
}

fn with_test_preloaded_plan(
    controller: ConfigTransactionController,
    response: rustbgpd_api::peer_types::RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
) -> ConfigTransactionController {
    with_test_preloaded_plan_controlled(
        controller,
        response,
        snapshot_toml,
        TypedTransactionFakeControl::default(),
    )
}

fn with_test_preloaded_plan_controlled(
    controller: ConfigTransactionController,
    response: rustbgpd_api::peer_types::RuntimeConfigTransactionPlan,
    snapshot_toml: Arc<Mutex<String>>,
    control: TypedTransactionFakeControl,
) -> ConfigTransactionController {
    controller.with_preloaded_planner(spawn_typed_transaction_manager_controlled(
        snapshot_toml,
        response,
        control,
    ))
}

fn dynamic_candidate_toml() -> String {
    base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    )
}

#[tokio::test]
async fn v3_publication_failure_never_enters_peer_or_persister_apply() {
    // Destructive proof: moving publication below planning/staging makes
    // one of these receiver assertions observe a command before failure.
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = root.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = root.path().join("rustbgpd.toml");
    let previous = base_toml("");
    std::fs::write(&config_path, &previous).unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);
    let (peer_tx, mut peer_rx) = mpsc::channel(8);
    let peer_apply_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&peer_apply_seen);
    let runtime = previous.clone();
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: runtime.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                _ => {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    });
    let (config_tx, mut config_rx) = mpsc::channel(8);
    let journal = state_dir.join(crate::confirm_journal::JOURNAL_FILE_NAME);
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap();

    // An unsafe fixed-slot occupant blocks publication and is never
    // removed based on its name alone.
    std::fs::create_dir(state_dir.join(crate::confirm_journal::v3::RAW_FILE_NAME)).unwrap();
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            confirm_journal_path: Some(journal),
            ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_confirm_v3_launch(launch);
    let error = controller
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "publisher-failure",
            60,
        ))
        .await
        .unwrap_err();
    // ADR-0127: no authority retained and nothing mutated — a clean
    // no-effect refusal, so the client sees FailedPrecondition.
    assert!(matches!(
        error,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("publication failed")
    ));
    assert!(!peer_apply_seen.load(std::sync::atomic::Ordering::SeqCst));
    assert!(config_rx.try_recv().is_err());
    assert_eq!(std::fs::read_to_string(config_path).unwrap(), previous);
}

#[tokio::test]
async fn oversized_v3_prior_is_a_precondition_failure_before_publication_or_mutation() {
    // Destructive proof: deleting the controller preflight replaces this
    // stable message with the publisher's limit refusal (which lacks the
    // "without confirmation" guidance asserted below); moving it after
    // publication or apply makes the empty-authority or mutation
    // assertions red.
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = root.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = root.path().join("rustbgpd.toml");
    let previous = base_toml("");
    std::fs::write(&config_path, &previous).unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let prior_bytes = accepted.normalized_toml().len();
    let limit = prior_bytes
        .checked_sub(1)
        .expect("canonical persisted config must not be empty");
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);
    let (peer_tx, mut peer_rx) = mpsc::channel(8);
    let peer_mutation_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&peer_mutation_seen);
    let runtime = previous.clone();
    let peer_task = tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: runtime.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                _ => {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    });
    let (config_tx, mut config_rx) = mpsc::channel(8);
    let journal = state_dir.join(crate::confirm_journal::JOURNAL_FILE_NAME);
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path)
        .unwrap()
        .with_max_raw_bytes_for_test(limit);
    let locator = launch.locator_path();
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            confirm_journal_path: Some(journal),
            ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_confirm_v3_launch(launch);

    let error = controller
        .clone()
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "oversized-prior",
            60,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains(&format!("{prior_bytes} bytes"))
                && message.contains(&format!("limit of {limit} bytes"))
                && message.contains("without confirmation")
    ));
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), previous);
    assert!(!locator.exists());
    assert!(std::fs::read_dir(&state_dir).unwrap().next().is_none());
    drop(controller);
    assert!(config_rx.recv().await.is_none());
    peer_task.await.unwrap();
    assert!(!peer_mutation_seen.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn v3_uncertain_locator_publication_arms_controller_mutation_fence() {
    // Destructive proof: treating the post-rename failure as ordinary
    // leaves this state unfenced even though boot authority is present.
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = root.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = root.path().join("rustbgpd.toml");
    let previous = base_toml("");
    std::fs::write(&config_path, &previous).unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);
    let (peer_tx, mut peer_rx) = mpsc::channel(8);
    let peer_apply_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&peer_apply_seen);
    let runtime = previous.clone();
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: runtime.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                _ => {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    });
    let (config_tx, mut config_rx) = mpsc::channel(8);
    let journal = state_dir.join(crate::confirm_journal::JOURNAL_FILE_NAME);
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path)
        .unwrap()
        .fail_locator_directory_sync_for_test();
    let locator = launch.locator_path();
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            confirm_journal_path: Some(journal),
            ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_confirm_v3_launch(launch);
    assert!(
        controller
            .clone()
            .apply(confirmed_dynamic_request(
                dynamic_candidate_toml(),
                "uncertain-locator",
                60,
            ))
            .await
            .is_err()
    );
    assert!(locator.exists());
    assert_eq!(
        controller
            .state
            .lock()
            .await
            .ambiguous_failure_confirm_id
            .as_deref(),
        Some("uncertain-locator")
    );
    assert!(!peer_apply_seen.load(std::sync::atomic::Ordering::SeqCst));
    assert!(config_rx.try_recv().is_err());
}

struct DiskBackedFibHarness {
    _root: tempfile::TempDir,
    controller: ConfigTransactionController,
    source: std::path::PathBuf,
    journal: std::path::PathBuf,
    locator: std::path::PathBuf,
    raw: std::path::PathBuf,
    metadata: std::path::PathBuf,
    fib_state: Arc<Mutex<Vec<FibTableConfig>>>,
    seen_preloaded: Arc<Mutex<Option<Arc<AcceptedConfigSnapshot>>>>,
    first_ack_released_at: Arc<Mutex<Option<tokio::time::Instant>>>,
    confirmation: proto::ConfigTransactionConfirmation,
    ack_task: tokio::task::JoinHandle<()>,
}

struct V3ExternalFenceHarness {
    _root: tempfile::TempDir,
    controller: ConfigTransactionController,
    current_toml: String,
    journal: std::path::PathBuf,
    locator: std::path::PathBuf,
}

fn v3_external_fence_harness(status: RuntimeConfigTransactionStatus) -> V3ExternalFenceHarness {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("config");
    let state_dir = root.path().join("state");
    std::fs::create_dir(&config_dir).unwrap();
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = config_dir.join("policy.rpol");
    std::fs::write(&source, "policy p { term rest { accept } }\n").unwrap();
    let config_path = config_dir.join("rustbgpd.toml");
    std::fs::write(
        &config_path,
        base_toml(&format!(
            "[policy]\nrpol_files = [{:?}]\n",
            source.display().to_string()
        )),
    )
    .unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let current_toml = accepted.normalized_toml().to_string();
    let runtime_rpol_files = accepted.config_ref().policy.rpol_files.clone();
    let runtime_rpol = accepted.config_ref().policy.rpol.clone();
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);
    let mut plan = plan(status, vec!["[[neighbors]] modify".to_string()]);
    if status == RuntimeConfigTransactionStatus::Rejected {
        plan.unsupported_sections = vec!["[policy] external inputs".to_string()];
    }
    let (peer_tx, mut peer_rx) = mpsc::channel(8);
    let runtime_toml = current_toml.clone();
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: runtime_toml.clone(),
                        rpol_files: runtime_rpol_files.clone(),
                        rpol: runtime_rpol.clone(),
                    }));
                }
                PeerManagerCommand::PlanConfigTransaction {
                    candidate_toml,
                    reply,
                    ..
                } => {
                    let _ = reply.send(Ok(attach_committed_candidate(
                        plan.clone(),
                        &candidate_toml,
                    )));
                }
                _ => panic!("unexpected peer-manager command in v3 external fence harness"),
            }
        }
    });
    let journal = state_dir.join(crate::confirm_journal::JOURNAL_FILE_NAME);
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap();
    let locator = launch.locator_path();
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            confirm_journal_path: Some(journal.clone()),
            ..deps_value(None, peer_tx, None, Vec::new())
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_confirm_v3_launch(launch);
    V3ExternalFenceHarness {
        _root: root,
        controller,
        current_toml,
        journal,
        locator,
    }
}

#[tokio::test]
async fn v3_activation_preserves_native_and_gnmi_full_snapshot_fence() {
    // Destructive proof: bypassing the ordinary planner makes either
    // full-snapshot request committable; publishing after the verdict or
    // skipping cleanup leaves v3 authority after the rejection.
    //
    // LAN-1020: the second publication used to race the first apply's
    // detached residue-cleanup thread over the tombstone names and could
    // fail with NotFound before the fence was consulted; remove_named_safe
    // now tolerates losing that unlink race, so publication succeeds and
    // only the plan verdict can reject here.
    let harness = v3_external_fence_harness(RuntimeConfigTransactionStatus::Rejected);
    let mut candidate: Config = toml::from_str(&harness.current_toml).unwrap();
    candidate.neighbors[0].description = Some("must remain fenced".to_string());
    let response = harness
        .controller
        .clone()
        .apply(confirmed_dynamic_request(
            toml::to_string_pretty(&candidate).unwrap(),
            "native-full-snapshot",
            60,
        ))
        .await
        .expect("external-input refusal is a rejected plan");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Rejected as i32
    );
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());

    let Err(error) = harness
        .controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "gnmi-full-snapshot",
            60,
        ))
        .await
    else {
        panic!("confirmed gNMI full-snapshot mutation remains fenced");
    };
    assert!(
        matches!(error, GnmiSetError::FailedPrecondition(_)),
        "expected FailedPrecondition, got: {error:?}"
    );
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());
}

#[tokio::test]
async fn v3_publication_failure_without_authority_is_failed_precondition() {
    // LAN-1020 / ADR-0127: a pre-rename publication failure retains no v3
    // authority and precedes every runtime mutation — a determinate clean
    // no-effect refusal that must surface as FailedPrecondition (matching
    // the NotPublished persistence mapping), never Internal, and must not
    // fence later applies.
    use std::os::unix::fs::PermissionsExt as _;

    let harness = v3_external_fence_harness(RuntimeConfigTransactionStatus::Rejected);
    let pending_dir = harness.journal.parent().unwrap().to_path_buf();
    let read_only = std::fs::Permissions::from_mode(0o500);
    std::fs::set_permissions(&pending_dir, read_only).unwrap();

    let Err(error) = harness
        .controller
        .clone()
        .apply(confirmed_dynamic_request(
            harness.current_toml.clone(),
            "native-unpublishable",
            60,
        ))
        .await
    else {
        panic!("unpublishable v3 pending storage must refuse the confirmed apply");
    };
    assert!(
        matches!(
            &error,
            ConfigTransactionApplyError::FailedPrecondition(message)
                if message.contains("publication failed")
        ),
        "expected FailedPrecondition, got: {error:?}"
    );
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());

    // No fence: the next confirmed apply is admitted and refused the
    // same clean way on the gNMI surface.
    let Err(error) = harness
        .controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "gnmi-unpublishable",
            60,
        ))
        .await
    else {
        panic!("unpublishable v3 pending storage must refuse the confirmed gNMI set");
    };
    assert!(
        matches!(
            &error,
            GnmiSetError::FailedPrecondition(message)
                if message.contains("publication failed")
        ),
        "expected FailedPrecondition, got: {error:?}"
    );
    std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn v3_activation_preserves_external_true_noop_exception() {
    // Destructive proof: reinstating the declaration fence rejects this
    // before planning; treating Noop as pending leaves authority or a
    // confirmation window for a transaction that changed nothing.
    let harness = v3_external_fence_harness(RuntimeConfigTransactionStatus::Noop);
    let response = harness
        .controller
        .clone()
        .apply(confirmed_dynamic_request(
            harness.current_toml.clone(),
            "external-noop",
            60,
        ))
        .await
        .expect("true no-op with unchanged external inputs remains allowed");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Noop as i32
    );
    assert!(response.confirmation.is_none());
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());
    assert!(harness.controller.state.lock().await.pending.is_none());
}

#[expect(
    clippy::too_many_lines,
    reason = "the focused harness keeps one complete external-source FIB transaction fixture"
)]
async fn external_fib_harness(
    timeout_seconds: u32,
    first_ack_delay: Option<Duration>,
) -> DiskBackedFibHarness {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("config");
    let state_dir = root.path().join("state");
    std::fs::create_dir(&config_dir).unwrap();
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let source = config_dir.join("policy.rpol");
    std::fs::write(&source, "policy p { term rest { accept } }\n").unwrap();
    let source_text = source.display();
    let previous_toml = base_toml(&format!(
        r#"
[policy]
rpol_files = ["{source_text}"]

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast"]
"#
    ));
    let candidate_toml = base_toml(&format!(
        r#"
[policy]
rpol_files = ["{source_text}"]

[[fib_tables]]
name = "core"
table_id = 1001
metric = 200
families = ["ipv4_unicast"]
"#
    ));
    let config_path = config_dir.join("rustbgpd.toml");
    std::fs::write(&config_path, &previous_toml).unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let runtime_rpol_files = accepted.config_ref().policy.rpol_files.clone();
    let runtime_config = Arc::new(Mutex::new(accepted.config_ref().clone()));
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);

    let original = table("edge", 1000);
    let replacement = table("core", 1001);
    let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
    let (fib_tx, fib_rx) = mpsc::channel(8);
    tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));

    let staged = Arc::new(Mutex::new(vec![snapshot(&original)]));
    let (peer_tx, mut peer_rx) = mpsc::channel(16);
    let runtime_toml = previous_toml.clone();
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: runtime_toml.clone(),
                        rpol_files: runtime_rpol_files.clone(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                PeerManagerCommand::PlanConfigTransaction {
                    candidate_toml,
                    reply,
                    ..
                } => {
                    let response = plan(
                        RuntimeConfigTransactionStatus::Committable,
                        vec!["[[fib_tables]]".to_string()],
                    );
                    let _ = reply.send(Ok(attach_committed_candidate(response, &candidate_toml)));
                }
                PeerManagerCommand::StageFibTables { tables, reply } => {
                    *staged.lock().await = tables;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::SetFibTablesSnapshot { tables, reply } => {
                    *staged.lock().await = tables;
                    let _ = reply.send(());
                }
                PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                    let _ = reply.send(());
                }
                _ => panic!("unexpected peer-manager command in v3 FIB harness"),
            }
        }
    });

    let seen_preloaded = Arc::new(Mutex::new(None));
    let seen = seen_preloaded.clone();
    let current = runtime_config.clone();
    let (internal_tx, mut internal_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Some(command) = internal_rx.recv().await {
            match command {
                InternalCommand::PlanTransactionConfig {
                    candidate,
                    expected_runtime_snapshot_token,
                    reply,
                } => {
                    let candidate_toml = crate::config::persisted_config_document(&candidate)
                        .expect("v3 FIB fake planner candidate must serialize");
                    let mut response = plan(
                        RuntimeConfigTransactionStatus::Committable,
                        vec!["[[fib_tables]]".to_string()],
                    );
                    response.runtime_snapshot_token =
                        expected_runtime_snapshot_token.unwrap_or_else(|| "kv1:old:1".to_string());
                    let plan = attach_committed_candidate(response, &candidate_toml);
                    let _ = reply.send(Ok(PlannedTransactionConfig { plan, candidate }));
                }
                InternalCommand::PlanAcceptedTransactionConfig {
                    snapshot,
                    expected_runtime_snapshot_token,
                    reply,
                } => {
                    let candidate_toml =
                        crate::config::persisted_config_document(snapshot.config_ref())
                            .expect("v3 FIB fake planner candidate must serialize");
                    let candidate = Box::new(snapshot.config());
                    *seen.lock().await = Some(snapshot);
                    let mut response = plan(
                        RuntimeConfigTransactionStatus::Committable,
                        vec!["[[fib_tables]]".to_string()],
                    );
                    response.runtime_snapshot_token =
                        expected_runtime_snapshot_token.unwrap_or_else(|| "kv1:new:2".to_string());
                    response.post_commit_runtime_snapshot_token = "kv1:rollback:3".to_string();
                    let plan = attach_committed_candidate(response, &candidate_toml);
                    let _ = reply.send(Ok(PlannedTransactionConfig { plan, candidate }));
                }
                InternalCommand::StageTransactionConfig {
                    candidate,
                    scope,
                    reply,
                } => {
                    let mut current = current.lock().await;
                    let staged = match scope {
                        TransactionConfigScope::Full => *candidate,
                        TransactionConfigScope::FibTablesOnly => {
                            let mut staged = current.clone();
                            staged.fib_tables.clone_from(&candidate.fib_tables);
                            staged.config_epoch = candidate.config_epoch;
                            staged.global.ebgp_requires_policy =
                                candidate.global.ebgp_requires_policy;
                            staged
                        }
                    };
                    let previous = std::mem::replace(&mut *current, staged);
                    let _ = reply.send(Ok(TransactionConfigRollbackToken::capture(
                        Box::new(previous),
                        scope,
                    )));
                }
                InternalCommand::RestoreTransactionConfig { rollback, reply } => {
                    *current.lock().await = rollback.previous().clone();
                    let _ = reply.send(());
                }
                InternalCommand::ReplaceConfigSnapshot { .. } => {
                    panic!("unexpected private command in v3 FIB harness")
                }
            }
        }
    });

    let (config_tx, mut config_rx) = mpsc::channel(8);
    let journal = state_dir.join(crate::confirm_journal::JOURNAL_FILE_NAME);
    let raw = state_dir.join(crate::confirm_journal::v3::RAW_FILE_NAME);
    let metadata = state_dir.join(crate::confirm_journal::v3::METADATA_FILE_NAME);
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap();
    let locator = launch.locator_path();
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            fib_cmd_tx: Some(fib_tx),
            peer_mgr_tx: peer_tx,
            rib_tx: None,
            config_tx: Some(config_tx),
            lock: rustbgpd_api::server::RuntimeConfigCoordinator::new(),
            config_mutation_gate: None,
            startup_tables: vec![original],
            confirm_journal_path: Some(journal.clone()),
            config_history_dir: None,
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_preloaded_planner(internal_tx);
    let controller = controller.with_confirm_v3_launch(launch);
    let ack_controller = controller.clone();
    let ack_locator = locator.clone();
    let ack_raw = raw.clone();
    let ack_metadata = metadata.clone();
    let first_ack_released_at = Arc::new(Mutex::new(None));
    let ack_released_at = Arc::clone(&first_ack_released_at);
    let ack_task = tokio::spawn(async move {
        let mut first_ack_delay = first_ack_delay;
        while let Some(event) = config_rx.recv().await {
            match event {
                ConfigEvent::FibTablesReplaced { ack: Some(ack), .. }
                | ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. } => {
                    if let Some(delay) = first_ack_delay.take() {
                        let state = ack_controller.state.lock().await;
                        assert_eq!(state.applying_confirm_id.as_deref(), Some("external-fib"));
                        assert!(state.pending.is_none());
                        drop(state);
                        assert!(ack_locator.exists() && ack_raw.exists() && ack_metadata.exists());
                        tokio::time::sleep(delay).await;
                        let authority: serde_json::Value =
                            serde_json::from_slice(&std::fs::read(&ack_metadata).unwrap()).unwrap();
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        assert!(authority["deadline_unix_seconds"].as_u64().unwrap() <= now);
                        *ack_released_at.lock().await = Some(tokio::time::Instant::now());
                    }
                    ack.accept().await;
                }
                _ => panic!("unexpected persistence event in v3 FIB harness"),
            }
        }
    });
    let response = controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml,
            "external-fib",
            timeout_seconds,
        ))
        .await
        .expect("external pure-FIB confirmed apply must remain committable");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    let confirmation = response.confirmation.unwrap();
    assert_eq!(*fib_state.lock().await, vec![replacement]);
    let state = controller.state.lock().await;
    let pending = state.pending.as_ref().unwrap();
    assert!(pending.v3_files.is_some());
    drop(state);

    DiskBackedFibHarness {
        _root: root,
        controller,
        source,
        journal,
        locator,
        raw,
        metadata,
        fib_state,
        seen_preloaded,
        first_ack_released_at,
        confirmation,
        ack_task,
    }
}

#[tokio::test]
async fn v3_pending_retains_prior_without_duplicate_toml() {
    // Destructive proof: restoring the eager `to_string()` allocation
    // makes the harness assertion observe both full representations.
    let harness = external_fib_harness(60, None).await;
    harness.ack_task.abort();
}

#[tokio::test]
async fn slow_v3_apply_starts_full_confirmation_window_after_commit() {
    // Destructive proofs: the delayed-ack harness asserts authority exists
    // while Apply is unfinished; moving the public wall deadline before
    // the ack collapses the distinct authority/public values, and moving
    // the live monotonic deadline before the ack violates its exact lower
    // bound. Dropping the timer fails the bounded terminal wait. Rebuilding
    // the prior from mutated source bytes breaks the Arc and FIB assertions.
    let harness = external_fib_harness(1, Some(Duration::from_millis(1_100))).await;
    let authority: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&harness.metadata).unwrap()).unwrap();
    let authority_deadline = authority["deadline_unix_seconds"].as_u64().unwrap();
    assert!(harness.confirmation.deadline_unix_seconds > authority_deadline);
    let ack_released_at = harness.first_ack_released_at.lock().await.unwrap();
    assert!(
        harness
            .controller
            .state
            .lock()
            .await
            .pending
            .as_ref()
            .unwrap()
            .deadline
            >= ack_released_at + Duration::from_secs(1)
    );
    assert_eq!(
        harness
            .controller
            .status()
            .await
            .unwrap()
            .confirmation
            .unwrap()
            .deadline_unix_seconds,
        harness.confirmation.deadline_unix_seconds
    );
    let prior = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .prior_snapshot
        .clone();
    std::fs::write(&harness.source, "policy p { term rest { reject } }\n").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = harness
                .controller
                .status()
                .await
                .unwrap()
                .confirmation
                .unwrap();
            if status.status == proto::ConfigTransactionConfirmationStatus::AutoReverted as i32 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("post-commit timer must auto-revert");
    assert!(Arc::ptr_eq(
        &prior,
        harness.seen_preloaded.lock().await.as_ref().unwrap()
    ));
    assert_eq!(*harness.fib_state.lock().await, vec![table("edge", 1000)]);
    assert!(!harness.locator.exists() && !harness.journal.exists());
    harness.ack_task.abort();
}

#[tokio::test]
async fn v3_external_fib_abort_reuses_exact_prior_and_is_terminal() {
    // Destructive proof: restoring from rollback TOML instead of the
    // retained Arc rereads the mutated rpol file and fails; dual-writing
    // retired authority creates the locator-free file; metadata-first cleanup leaves the
    // locator present at successful return.
    let harness = external_fib_harness(60, None).await;
    assert!(
        std::fs::read(&harness.metadata)
            .unwrap()
            .starts_with(b"{\"version\":3,")
    );
    assert!(!harness.journal.exists());
    assert!(harness.locator.exists());
    let prior = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .prior_snapshot
        .clone();
    std::fs::write(&harness.source, "policy p { term rest { reject } }\n").unwrap();
    harness
        .controller
        .clone()
        .abort(proto::AbortConfigTransactionRequest {
            confirm_id: "external-fib".to_string(),
        })
        .await
        .expect("live abort must reuse verified prior state without source reread");
    let seen = harness.seen_preloaded.lock().await.clone().unwrap();
    assert!(Arc::ptr_eq(&prior, &seen));
    assert_eq!(*harness.fib_state.lock().await, vec![table("edge", 1000)]);
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());
    harness.ack_task.abort();
}

#[tokio::test(start_paused = true)]
async fn v3_external_fib_timeout_reuses_prior_after_source_mutation() {
    // Destructive proof: removing the preloaded timeout lane or rebuilding
    // provenance from current external bytes leaves the replacement table
    // active and the locator armed after the timer fires.
    let harness = external_fib_harness(1, None).await;
    let prior = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .prior_snapshot
        .clone();
    std::fs::write(&harness.source, "policy p { term rest { reject } }\n").unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let status = harness.controller.status().await.unwrap();
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
    );
    let seen = harness.seen_preloaded.lock().await.clone().unwrap();
    assert!(Arc::ptr_eq(&prior, &seen));
    assert_eq!(*harness.fib_state.lock().await, vec![table("edge", 1000)]);
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());
    harness.ack_task.abort();
}

#[tokio::test]
async fn v3_confirm_is_terminal_before_residue_cleanup() {
    // Destructive proof: retaining v1's journal-as-authority rule or
    // clearing in-memory pending state before locator durability leaves
    // the locator present when the RPC reports permanent success.
    let harness = external_fib_harness(60, None).await;
    harness
        .controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "external-fib".to_string(),
        })
        .await
        .expect("confirm must durably remove v3 locator authority");
    assert!(!harness.locator.exists());
    assert!(!harness.journal.exists());
    assert_eq!(*harness.fib_state.lock().await, vec![table("core", 1001)]);
    harness.ack_task.abort();
}

#[tokio::test]
async fn v3_locator_sync_failure_keeps_confirm_pending_until_retry() {
    let harness = external_fib_harness(60, None).await;
    let files = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .v3_files
        .clone()
        .unwrap();
    files.fail_locator_directory_sync_once_for_test();
    assert!(
        harness
            .controller
            .clone()
            .confirm(proto::ConfirmConfigTransactionRequest {
                confirm_id: "external-fib".to_string(),
            })
            .await
            .is_err()
    );
    assert!(harness.controller.state.lock().await.pending.is_some());
    assert!(!harness.locator.exists());
    assert!(harness.raw.exists() && harness.metadata.exists());

    harness
        .controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "external-fib".to_string(),
        })
        .await
        .expect("retry must record terminal confirmation");
    assert!(harness.controller.state.lock().await.pending.is_none());
    harness.ack_task.abort();
}

#[tokio::test]
async fn uncommitted_authority_locator_sync_failure_is_ambiguous() {
    let harness = external_fib_harness(60, None).await;
    let files = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .v3_files
        .clone()
        .unwrap();
    files.fail_locator_directory_sync_once_for_test();
    let error = harness
        .controller
        .cleanup_uncommitted_authority(
            "external-fib",
            Some(files.as_ref()),
            "fault-injected cleanup",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::PublicationAmbiguous,
            ref message,
        }
            if message.contains("confirm outcome is ambiguous")
                && message.contains("daemon will exit for supervised recovery")
    ));
    assert_eq!(
        harness
            .controller
            .state
            .lock()
            .await
            .ambiguous_failure_confirm_id
            .as_deref(),
        Some("external-fib")
    );
    harness.ack_task.abort();
}

#[tokio::test]
async fn stalled_v3_residue_cleanup_releases_terminal_paths_and_is_singleton() {
    use std::os::unix::fs::PermissionsExt as _;

    let harness = external_fib_harness(60, None).await;
    let files = harness
        .controller
        .state
        .lock()
        .await
        .pending
        .as_ref()
        .unwrap()
        .v3_files
        .clone()
        .unwrap();
    let stall = crate::confirm_journal::v3::ResidueCleanupStall::default();
    files.stall_residue_cleanup_for_test(stall.clone());

    tokio::time::timeout(
        Duration::from_secs(1),
        harness
            .controller
            .clone()
            .confirm(proto::ConfirmConfigTransactionRequest {
                confirm_id: "external-fib".to_string(),
            }),
    )
    .await
    .expect("residue cleanup must not delay confirm")
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !stall.started() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached residue cleanup must start");
    assert!(!harness.locator.exists());
    assert!(!harness.raw.exists() && !harness.metadata.exists());
    assert!(harness.controller.state.lock().await.pending.is_none());
    harness
        .controller
        .reject_if_pending("ordinary or streamed config mutation")
        .await
        .expect("terminal state must reopen config admission");
    let _coordinator = tokio::time::timeout(
        Duration::from_secs(1),
        harness.controller.deps.lock.acquire(),
    )
    .await
    .expect("cleanup must not retain the coordinator")
    .unwrap();
    assert!(
        harness
            .controller
            .v3_residue_cleanup_active
            .load(Ordering::Acquire)
    );

    let second_root = tempfile::tempdir().unwrap();
    let second_state = second_root.path().join("state");
    std::fs::create_dir(&second_state).unwrap();
    std::fs::set_permissions(second_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&second_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let second_config = second_root.path().join("rustbgpd.toml");
    std::fs::write(&second_config, base_toml("")).unwrap();
    let second_prior = AcceptedConfigSnapshot::load(&second_config, None).unwrap();
    let second_launch =
        crate::confirm_journal::v3::LaunchIdentity::resolve(&second_config).unwrap();
    let second_files = second_launch
        .publish(&second_state, "second", 9, &second_prior)
        .unwrap();
    second_files.remove_locator_authority().unwrap();
    let second_handoff = harness
        .controller
        .claim_v3(&second_files, "second terminal transaction");
    assert!(second_handoff.is_none());
    let residue = [
        crate::confirm_journal::v3::RAW_FILE_NAME,
        crate::confirm_journal::v3::METADATA_FILE_NAME,
    ];
    assert!(residue.iter().all(|name| second_state.join(name).exists()));

    let cleanup_active = Arc::clone(&harness.controller.v3_residue_cleanup_active);
    harness.ack_task.abort();
    let drop_started = std::time::Instant::now();
    drop(harness.controller);
    assert!(drop_started.elapsed() < Duration::from_secs(1));
    stall.release();
    tokio::time::timeout(Duration::from_secs(2), async {
        while cleanup_active.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached cleanup must finish after release");
}

#[tokio::test]
async fn residue_thread_spawn_failure_is_terminal_and_releases_singleton() {
    let harness = external_fib_harness(60, None).await;
    harness
        .controller
        .v3_residue_cleanup_spawn_fail
        .store(true, Ordering::Release);
    harness
        .controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "external-fib".to_string(),
        })
        .await
        .expect("thread spawn failure must be terminal warning-only");
    assert!(!harness.locator.exists());
    assert!(harness.controller.state.lock().await.pending.is_none());
    assert!(
        !harness
            .controller
            .v3_residue_cleanup_active
            .load(Ordering::Acquire)
    );
    assert!(!harness.raw.exists() && !harness.metadata.exists());
    assert!(
        harness
            .raw
            .with_file_name("commit-confirm-v3-prior.cleanup")
            .exists()
            || harness
                .metadata
                .with_file_name("commit-confirm-v3-metadata.cleanup")
                .exists()
    );
    harness.ack_task.abort();
}

#[tokio::test]
async fn rejected_confirmed_apply_leaves_no_journal() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let history_dir = dir.path().join("history");
    std::fs::create_dir(&history_dir).unwrap();
    let history_sentinel = history_dir.join("existing.json");
    std::fs::write(&history_sentinel, "retained history").unwrap();
    let original_snapshot = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(original_snapshot.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(RuntimeConfigTransactionStatus::Rejected, Vec::new()),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    let mut deps = deps_value(None, peer_tx, Some(config_tx), Vec::new());
    deps.confirm_journal_path = Some(journal_path.clone());
    deps.config_history_dir = Some(history_dir.clone());
    let controller = with_v3_test_authority(deps, dir.path(), &original_snapshot);

    let response = controller
        .clone()
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "deploy-1",
            60,
        ))
        .await
        .expect("apply must return a rejected plan, not an error");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Rejected as i32
    );
    assert!(
        !journal_path.exists(),
        "a rejected confirmed apply must not leave a journal behind"
    );
    assert_eq!(*snapshot_toml.lock().await, original_snapshot);
    assert_eq!(
        std::fs::read_to_string(&history_sentinel).unwrap(),
        "retained history"
    );
    assert_eq!(std::fs::read_dir(&history_dir).unwrap().count(), 1);
    assert!(matches!(
        config_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

async fn assert_ambiguous_apply_failure_wedges(
    controller: &ConfigTransactionController,
    dir: &tempfile::TempDir,
    previous_toml: &str,
) -> ConfigTransactionApplyError {
    let err = controller
        .clone()
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "deploy-1",
            60,
        ))
        .await
        .expect_err("the ambiguous confirmed apply must fail");
    let config_path = dir.path().join("rustbgpd.toml");
    let launch = crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap();
    assert!(
        launch.locator_path().exists(),
        "ambiguous completion must retain v3 authority"
    );
    controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("the mutation fence must stay closed after an ambiguous failure");
    let overlap_err = controller
        .clone()
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "deploy-2",
            60,
        ))
        .await
        .expect_err("a second confirmed apply must be rejected while wedged");
    assert!(
        matches!(overlap_err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("ambiguous")),
        "{overlap_err:?}"
    );
    let status = controller.status().await.expect("status must succeed");
    assert!(
        status.human_text.contains("ambiguous"),
        "status must name the wedged state: {}",
        status.human_text
    );

    // Boot recovery: the retained journal reverts the (possibly-committed)
    // on-disk candidate back to the pre-transaction config.
    std::fs::write(&config_path, "unconfirmed candidate bytes").unwrap();
    let revert = launch
        .boot_revert_check()
        .expect("boot revert must apply")
        .expect("retained journal must trigger a boot revert");
    assert_eq!(revert.notice.confirm_id, "deploy-1");
    assert_snapshot_matches_config(
        &std::fs::read_to_string(&config_path).unwrap(),
        previous_toml,
    );
    assert!(
        !launch.locator_path().exists(),
        "boot revert must consume authority"
    );
    err
}

/// LAN-277 window (a): the candidate persisted, then finalization
/// (`CommitConfigSnapshotStage`) failed. On disk the candidate IS
/// committed while the caller sees an error — the journal must be
/// retained and mutations fenced until a restart boot-reverts.
#[tokio::test]
async fn confirmed_apply_post_persist_finalize_failure_retains_journal_and_fences_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_dropping_stage_commit(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan(
        with_v3_test_authority(
            FibTableControlDeps {
                confirm_journal_path: Some(journal_path.clone()),
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            dir.path(),
            &previous_toml,
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    let err = assert_ambiguous_apply_failure_wedges(&controller, &dir, &previous_toml).await;
    assert!(
        matches!(err, ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            ref message,
        } if message.contains("finalization") && message.contains("dropped its reply")),
        "{err:?}"
    );
    ack_task.abort();
}

/// LAN-277 window (b): the persistence acknowledgement was lost — the
/// caller never learns whether the config file now holds the candidate.
/// Even though the runtime snapshot rollback succeeds, the journal must
/// be retained and mutations fenced.
#[tokio::test]
async fn confirmed_apply_persist_ack_loss_retains_journal_and_fences_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(drop_config_transaction_commit_acks(config_rx));
    let controller = with_test_preloaded_plan(
        with_v3_test_authority(
            FibTableControlDeps {
                confirm_journal_path: Some(journal_path.clone()),
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            dir.path(),
            &previous_toml,
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    let err = assert_ambiguous_apply_failure_wedges(&controller, &dir, &previous_toml).await;
    assert!(
        matches!(err, ConfigTransactionApplyError::RecoveryRequired { ref message, .. }
            if message.contains("persistence acknowledgement") && message.contains("ambiguous")),
        "{err:?}"
    );
    ack_task.abort();
}

/// LAN-277 window (c): the persist failed cleanly but the compound
/// rollback of the staged snapshot then failed too — the runtime is left
/// part-candidate. The journal must be retained and mutations fenced.
#[tokio::test]
async fn confirmed_apply_compound_rollback_failure_retains_journal_and_fences_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let control = TypedTransactionFakeControl {
        drop_restore_ack: Arc::new(AtomicBool::new(true)),
        ..TypedTransactionFakeControl::default()
    };
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(reject_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan_controlled(
        with_v3_test_authority(
            FibTableControlDeps {
                confirm_journal_path: Some(journal_path.clone()),
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            dir.path(),
            &previous_toml,
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        control,
    );

    let err = assert_ambiguous_apply_failure_wedges(&controller, &dir, &previous_toml).await;
    assert!(
        matches!(err, ConfigTransactionApplyError::RecoveryRequired { ref message, .. }
            if message.contains("rollback failed") && message.contains("ambiguous")),
        "{err:?}"
    );
    ack_task.abort();
}

/// Counterpart to the ambiguous-window tests: a persist failure the
/// persister itself reported, followed by a successful rollback, is a
/// provably-clean failure — the journal is removed and the fence opens.
#[tokio::test]
async fn confirmed_apply_clean_persist_failure_removes_journal_and_opens_fence() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(reject_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan(
        with_v3_test_authority(
            FibTableControlDeps {
                confirm_journal_path: Some(journal_path.clone()),
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            dir.path(),
            &previous_toml,
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    let err = controller
        .clone()
        .apply(confirmed_dynamic_request(
            dynamic_candidate_toml(),
            "deploy-1",
            60,
        ))
        .await
        .expect_err("the rejected persist must fail the apply");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("persist rejected by test")),
        "{err:?}"
    );
    assert!(
        !journal_path.exists(),
        "a provably-clean failure must not retain the journal"
    );
    controller
        .reject_if_pending("test mutation")
        .await
        .expect("a clean failure must not fence later mutations");
    // The rollback restored the pre-transaction snapshot.
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    ack_task.abort();
}

#[tokio::test]
async fn confirmed_apply_enters_pending_and_confirm_clears_gate() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, _snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml, candidate_toml).await;

    let status = controller
        .clone()
        .status()
        .await
        .expect("status must succeed");
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    let gate_err = controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("pending confirmed transaction must block mutations");
    assert!(matches!(
        gate_err,
        ConfigTransactionApplyError::FailedPrecondition(_)
    ));

    let confirmed = controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect("confirm must succeed");
    assert_eq!(
        confirmed.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Confirmed as i32
    );
    assert_config_transaction_lifecycle_metric(&controller, "confirm", "success", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "confirm", "failure", 0.0);
    controller
        .clone()
        .auto_revert("deploy-1".to_string())
        .await
        .expect("stale timeout after confirm must be a no-op");
    let status = controller
        .clone()
        .status()
        .await
        .expect("status must succeed");
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Confirmed as i32
    );
    controller
        .reject_if_pending("test mutation")
        .await
        .expect("confirmed transaction should release mutation gate");
    drop(controller);
    ack_task.abort();
}

#[tokio::test]
async fn confirmed_abort_rolls_back_previous_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml.clone(), candidate_toml).await;

    let aborted = controller
        .clone()
        .abort(proto::AbortConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect("abort must roll back");
    assert_eq!(
        aborted.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Aborted as i32
    );
    assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 0.0);
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    ack_task.abort();
}

#[tokio::test]
async fn confirmed_confirm_wrong_id_keeps_pending() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, _snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml, candidate_toml).await;

    let err = controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "wrong-id".to_string(),
        })
        .await
        .expect_err("wrong confirm_id must fail");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("confirmed config transaction id mismatch")),
        "{err:?}"
    );

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    assert!(
        (config_transaction_lifecycle_metric(&controller, "confirm", "failure") - 0.0).abs()
            < f64::EPSILON,
        "precondition/id-mismatch errors are not lifecycle transitions"
    );
    let gate_err = controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("pending transaction must still gate mutations");
    assert!(matches!(
        gate_err,
        ConfigTransactionApplyError::FailedPrecondition(_)
    ));
    ack_task.abort();
}

#[tokio::test]
async fn confirmed_apply_rejects_overlap_while_pending() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, _snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml, candidate_toml.clone()).await;

    let err = controller
        .clone()
        .apply(confirmed_dynamic_request(candidate_toml, "deploy-2", 60))
        .await
        .expect_err("second confirmed apply must fail while pending");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("already awaiting confirmation")),
        "{err:?}"
    );

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    ack_task.abort();
}

/// LAN-277: a failed abort rollback leaves the unconfirmed candidate
/// running — that is NOT a terminal outcome. The transaction must stay
/// pending (mutation fence closed, second mutations rejected) and a retry
/// of the abort must be able to resolve it.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the test proves the complete failed-abort, fence, retry, and resolution lifecycle"
)]
async fn confirmed_abort_failure_keeps_pending_fence_and_allows_retry() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let control = TypedTransactionFakeControl {
        stage_results: Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err("stage rollback failed".to_string()),
        ]))),
        ..TypedTransactionFakeControl::default()
    };
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let journal_dir = tempfile::tempdir().unwrap();
    let journal_path = journal_dir.path().join("commit-confirm-journal.json");
    let controller = with_test_preloaded_plan_controlled(
        with_v3_test_authority(
            FibTableControlDeps {
                confirm_journal_path: Some(journal_path.clone()),
                ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
            },
            journal_dir.path(),
            &previous_toml,
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        control,
    );
    let metadata_path = journal_dir
        .path()
        .join(crate::confirm_journal::v3::METADATA_FILE_NAME);
    let rollback_failed = || {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        value["rollback_failed"].as_bool().unwrap()
    };

    controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml.clone(),
            "deploy-1",
            60,
        ))
        .await
        .expect("confirmed apply must succeed");
    assert!(
        !rollback_failed(),
        "a fresh journal must not carry a rollback failure"
    );

    let err = controller
        .clone()
        .abort(proto::AbortConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect_err("abort rollback failure must be reported");
    // The retained on-disk journal now records the failed rollback, so a
    // restart's boot-revert diagnostics can say the pre-restart state was
    // uncertain rather than the generic never-confirmed message.
    assert!(
        rollback_failed(),
        "a failed rollback must be recorded in the retained journal"
    );
    // A rollback re-apply that fails candidate validation is an internal
    // condition (the captured snapshot is bad), not a malformed abort
    // request, so the abort surfaces INTERNAL rather than INVALID_ARGUMENT.
    assert!(
        matches!(err, ConfigTransactionApplyError::Internal(ref message)
            if message.contains("failed to abort confirmed config transaction")
                && message.contains("rollback failed")
                && message.contains("stage rollback failed")),
        "{err:?}"
    );

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::AbortFailed as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 0.0);
    // The fence must stay closed: the unconfirmed candidate is still
    // running, and a second mutation on top of that inconsistency would
    // later be clobbered by a boot revert from the retained journal.
    controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("failed abort must keep the pending mutation gate closed");
    let overlap_err = controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml.clone(),
            "deploy-2",
            60,
        ))
        .await
        .expect_err("a second confirmed apply must be rejected after a failed abort");
    assert!(
        matches!(overlap_err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("awaiting confirmation")),
        "{overlap_err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);

    // Retrying the abort (the queued stage failure is consumed) resolves
    // the inconsistency: rollback succeeds, the fence opens.
    let aborted = controller
        .clone()
        .abort(proto::AbortConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect("abort retry must succeed once the rollback can commit");
    assert_eq!(
        aborted.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Aborted as i32
    );
    assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 1.0);
    controller
        .reject_if_pending("test mutation")
        .await
        .expect("successful abort retry must open the mutation gate");
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    assert!(
        !journal_path.exists(),
        "a successful abort retry must consume the journal"
    );
    ack_task.abort();
}

/// A rollback re-apply whose plan comes back `Rejected` returns `Ok`
/// at the RPC level but commits nothing — the aborted candidate is
/// still running. The abort must report `AbortFailed`, not record a
/// success while the runtime still holds the unconfirmed config.
/// LAN-277: the transaction stays pending (fence closed) and the
/// operator can resolve it by confirming the candidate.
#[tokio::test]
async fn confirmed_abort_with_rejected_rollback_keeps_pending_until_confirm() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let plans = Arc::new(Mutex::new(VecDeque::from([
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        plan(RuntimeConfigTransactionStatus::Rejected, Vec::new()),
    ])));
    let control = TypedTransactionFakeControl {
        plans: Arc::new(Mutex::new(VecDeque::from([
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            plan(RuntimeConfigTransactionStatus::Rejected, Vec::new()),
        ]))),
        ..TypedTransactionFakeControl::default()
    };
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_with_plans(
        peer_rx,
        plans,
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan_controlled(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(RuntimeConfigTransactionStatus::Rejected, Vec::new()),
        snapshot_toml.clone(),
        control,
    );

    controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml.clone(),
            "deploy-1",
            60,
        ))
        .await
        .expect("confirmed apply must succeed");

    let err = controller
        .clone()
        .abort(proto::AbortConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect_err("a rejected rollback re-apply must fail the abort");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("rollback failed")
                && message.contains("rejected")
                && message.contains("still running")),
        "{err:?}"
    );

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::AbortFailed as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 0.0);
    // The candidate snapshot is untouched — the rejected rollback
    // committed nothing.
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    // LAN-277: the fence stays closed while the inconsistency persists.
    controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("failed abort must keep the pending mutation gate closed");

    // Confirming the still-running candidate is a valid resolution: it
    // clears the pending state (and would consume the journal), and the
    // fence opens.
    let confirmed = controller
        .clone()
        .confirm(proto::ConfirmConfigTransactionRequest {
            confirm_id: "deploy-1".to_string(),
        })
        .await
        .expect("confirm must resolve a failed-abort pending transaction");
    assert_eq!(
        confirmed.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::Confirmed as i32
    );
    controller
        .reject_if_pending("test mutation")
        .await
        .expect("confirm must open the mutation gate");
    ack_task.abort();
}

#[tokio::test(start_paused = true)]
async fn confirmed_timeout_auto_reverts_previous_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    controller
        .clone()
        .apply(confirmed_dynamic_request(candidate_toml, "deploy-1", 1))
        .await
        .expect("confirmed apply must succeed");
    // Virtual time (start_paused): auto-advances past the 1s confirm
    // timeout so the spawned timer fires and runs auto-revert to completion,
    // deterministically and with no real wall-clock cost.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let status = controller.status().await.expect("status must succeed");
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
    );
    assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "success", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "failure", 0.0);
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    ack_task.abort();
}

#[tokio::test(start_paused = true)]
async fn gnmi_set_rollback_duration_reset_shortens_timer() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml.clone(), candidate_toml).await;

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 1))
        .await
        .expect("rollback-duration reset must succeed");

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.timeout_seconds, 1);

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let status = controller.status().await.expect("status must succeed");
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    ack_task.abort();
}

#[tokio::test(start_paused = true)]
async fn gnmi_set_rollback_duration_reset_extends_timer() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );
    controller
        .clone()
        .apply(confirmed_dynamic_request(candidate_toml, "deploy-1", 1))
        .await
        .expect("confirmed apply must succeed");

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 10))
        .await
        .expect("rollback-duration reset must succeed");
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.timeout_seconds, 10);

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_commit_confirm("deploy-1"))
        .await
        .expect("confirm after timer extension must succeed");
    ack_task.abort();
}

#[tokio::test]
async fn auto_revert_failure_records_lifecycle_metric() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let control = TypedTransactionFakeControl {
        stage_results: Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err("stage rollback failed".to_string()),
        ]))),
        ..TypedTransactionFakeControl::default()
    };
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let controller = with_test_preloaded_plan_controlled(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        control,
    );

    controller
        .clone()
        .apply(confirmed_dynamic_request(
            candidate_toml.clone(),
            "deploy-1",
            1,
        ))
        .await
        .expect("confirmed apply must succeed");
    {
        let mut state = controller.state.lock().await;
        state
            .pending
            .as_mut()
            .expect("confirmed apply should be pending")
            .deadline = tokio::time::Instant::now();
    }
    controller
        .clone()
        .auto_revert("deploy-1".to_string())
        .await
        .expect_err("auto-revert rollback should fail");

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::AutoRevertFailed as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-1");
    assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "failure", 1.0);
    assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "success", 0.0);
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    // LAN-277: a failed auto-revert keeps the transaction pending and the
    // mutation fence closed until the operator resolves it.
    controller
        .reject_if_pending("test mutation")
        .await
        .expect_err("failed auto-revert must keep the mutation fence closed");
    ack_task.abort();
}

#[tokio::test]
async fn apply_commits_catalog_snapshot_after_persist_ack() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.prep-only]
hold_time = 120

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.2"]

[policy.definitions.prep-only]
default_action = "permit"
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[policy] definitions".to_string(),
                "[policy] neighbor_sets".to_string(),
                "[peer_groups] catalog".to_string(),
            ],
        ),
    );
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[policy] definitions".to_string(),
                "[policy] neighbor_sets".to_string(),
                "[peer_groups] catalog".to_string(),
            ],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("[policy.definitions.prep-only]"));
            assert!(candidate_toml.contains("[peer_groups.prep-only]"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx.clone(), Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(
        response.committed_sections,
        vec![
            "[policy] definitions",
            "[policy] neighbor_sets",
            "[peer_groups] catalog",
        ]
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    assert!(response.human_text.contains("catalog-only"));
}

fn live_impact_plan() -> RuntimeConfigTransactionPlan {
    plan(
        RuntimeConfigTransactionStatus::Committable,
        vec![
            "[policy] definitions".to_string(),
            "[policy] live impact".to_string(),
        ],
    )
}

fn resolved_policy_targets(previous_toml: &str, candidate_toml: &str) -> Vec<ResolvedPeerPolicy> {
    let previous = Config::load_toml_with_diagnostics(previous_toml, "previous config")
        .expect("previous config must parse");
    let candidate = Config::load_toml_with_diagnostics(candidate_toml, "candidate config")
        .expect("candidate config must parse");
    resolve_live_policy_targets(&previous, &candidate)
        .expect("live policy targets must resolve")
        .static_targets
}

fn import_default_action(target: &ResolvedPeerPolicy) -> PolicyAction {
    target
        .import_policy
        .as_ref()
        .and_then(|chain| chain.policies.first())
        .map(|policy| policy.default_action)
        .expect("test target must carry one import policy")
}

fn resolved_dynamic_policy_target(toml: &str, address: &str) -> ResolvedPeerPolicy {
    let config =
        Config::load_toml_with_diagnostics(toml, "dynamic policy config").expect("valid TOML");
    let range = config
        .dynamic_neighbors
        .first()
        .expect("test config must define a dynamic range");
    let group = config
        .peer_groups
        .get(&range.peer_group)
        .expect("test config must define the range peer group");
    let address = address.parse().expect("valid test address");
    let resolved = config
        .resolve_dynamic_neighbor(
            address,
            range.remote_asn,
            "dynamic:ix",
            group,
            &range.peer_group,
            false,
        )
        .expect("dynamic policy must resolve");
    ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: resolved.import_policy,
        export_policy: resolved.export_policy,
    }
}

#[tokio::test]
async fn apply_commits_live_policy_impact_after_persist_ack() {
    let previous_toml = live_policy_toml("permit");
    let candidate_toml = live_policy_toml("deny");
    let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
        &candidate_toml,
        &previous_toml,
    )])));
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(snapshot_toml.clone(), live_impact_plan());
    let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(())])));
    let apply_calls = Arc::new(Mutex::new(Vec::new()));
    let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_live_policy_peer_manager(
        peer_rx,
        live_impact_plan(),
        snapshot_toml.clone(),
        apply_results,
        captured_priors,
        apply_calls.clone(),
        dynamic_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx.clone(), Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(
        response.committed_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    assert!(response.human_text.contains("live policy-impact"));
    assert_eq!(response.runtime_snapshot_token, "kv1:new:2");
    let chained = plan_candidate(
        &peer_tx,
        candidate_toml.clone(),
        response.runtime_snapshot_token.clone(),
        true,
    )
    .await
    .expect("returned post-commit token must chain into a second plan");
    assert_eq!(
        chained.runtime_snapshot_token,
        response.runtime_snapshot_token
    );
    let calls = apply_calls.lock().await;
    assert_eq!(calls.len(), 1, "exactly one apply call");
    assert_eq!(calls[0].len(), 1, "one impacted static neighbor");
    assert_eq!(calls[0][0].address.to_string(), "10.0.0.2");
    assert_eq!(import_default_action(&calls[0][0]), PolicyAction::Deny);
    assert_eq!(
        dynamic_calls.lock().await.as_slice(),
        &[Vec::<DynamicRangeTarget>::new()],
        "static live-policy impact must not send dynamic selectors"
    );
}

#[tokio::test]
async fn apply_commits_dynamic_range_live_policy_impact_after_persist_ack() {
    let previous_toml = dynamic_live_policy_toml("permit");
    let candidate_toml = dynamic_live_policy_toml("deny");
    let captured_priors = Arc::new(Mutex::new(VecDeque::from([vec![
        resolved_dynamic_policy_target(&previous_toml, "10.30.0.7"),
    ]])));
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(snapshot_toml.clone(), live_impact_plan());
    let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(())])));
    let apply_calls = Arc::new(Mutex::new(Vec::new()));
    let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_live_policy_peer_manager(
        peer_rx,
        live_impact_plan(),
        snapshot_toml.clone(),
        apply_results,
        captured_priors,
        apply_calls.clone(),
        dynamic_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(
        response.committed_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    assert!(response.human_text.contains("1 live session"));
    let calls = apply_calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].is_empty(),
        "dynamic-only live-policy impact must not send static targets"
    );
    let dynamic_calls = dynamic_calls.lock().await;
    assert_eq!(dynamic_calls.len(), 1);
    assert_eq!(dynamic_calls[0].len(), 1);
    assert_eq!(dynamic_calls[0][0].addr.to_string(), "10.30.0.0");
    assert_eq!(dynamic_calls[0][0].prefix_len, 16);
    assert_eq!(dynamic_calls[0][0].peer_group, "ix");
}

#[tokio::test]
async fn apply_commits_peer_session_reshape_after_persist_ack() {
    let previous_toml = peer_group_reshape_toml(90);
    let candidate_toml = peer_group_reshape_toml(45);
    let initial_peers = resolved_static_peer_configs(&previous_toml);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(initial_peers));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("hold_time = 45"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(
        response.committed_sections,
        vec![
            "[peer_groups] catalog",
            "effective neighbor session reshape",
        ]
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    assert!(response.human_text.contains("1 live session"));
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].hold_time, Some(45));
}

#[tokio::test]
async fn apply_commits_static_peer_group_reassignment_after_persist_ack() {
    let previous_toml = peer_group_reassignment_toml("edge");
    let candidate_toml = peer_group_reassignment_toml("core");
    let initial_peers = resolved_static_peer_configs(&previous_toml);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[[neighbors]] modify".to_string(),
                "effective neighbor session reshape".to_string(),
            ],
        ),
    );
    let peers = Arc::new(Mutex::new(initial_peers));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[[neighbors]] modify".to_string(),
                "effective neighbor session reshape".to_string(),
            ],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("peer_group = \"core\""));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(
        response.committed_sections,
        vec!["[[neighbors]] modify", "effective neighbor session reshape"]
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].peer_group.as_deref(), Some("core"));
    assert_eq!(peers[0].hold_time, Some(45));
}

#[tokio::test]
async fn apply_commits_dynamic_range_peer_group_reshape_after_persist_ack() {
    let previous_toml = dynamic_peer_group_reshape_toml(90);
    let candidate_toml = dynamic_peer_group_reshape_toml(45);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(Vec::new()));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
        bounce_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("hold_time = 45"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    // No static members: the reshape fan-out reconfigures nothing.
    assert!(peers.lock().await.is_empty());
    let bounce_calls = bounce_calls.lock().await;
    assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
    assert_eq!(bounce_calls[0].len(), 1);
    assert_eq!(bounce_calls[0][0].addr.to_string(), "10.30.0.0");
    assert_eq!(bounce_calls[0][0].prefix_len, 16);
    assert_eq!(bounce_calls[0][0].peer_group, "ix");
    assert!(
        response
            .human_text
            .contains("1 live dynamic session(s) signaled to reset"),
        "{}",
        response.human_text
    );
}

#[tokio::test]
async fn dynamic_discard_transaction_marks_the_range_for_purge_reset() {
    let previous_toml = dynamic_discard_reshape_toml(false);
    let candidate_toml = dynamic_discard_reshape_toml(true);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(Vec::new()));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let purge_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces_and_purges(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers,
        bounce_calls.clone(),
        purge_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("discard_path_attributes = [4]"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    let bounce_calls = bounce_calls.lock().await;
    let purge_calls = purge_calls.lock().await;
    assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
    assert_eq!(purge_calls.len(), 1, "{purge_calls:?}");
    assert_eq!(purge_calls[0], bounce_calls[0]);
    assert_eq!(purge_calls[0][0].peer_group, "ix");
}

/// LAN-911: a peer-group field reshape whose only members are
/// `[[dynamic_neighbors]]` ranges resolves zero static targets, so the
/// MD5/GTSM fence in `apply_peer_reshape_snapshot` never runs. Changing
/// the group's `md5_password` must still be refused restart-required
/// rather than bouncing the live sessions into a listener still pinned to
/// the old key.
#[tokio::test]
async fn dynamic_range_peer_group_auth_reshape_is_refused_restart_required() {
    let previous_toml = dynamic_peer_group_md5_reshape_toml("old-secret");
    let candidate_toml = dynamic_peer_group_md5_reshape_toml("new-secret");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(Vec::new()));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
        bounce_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("md5_password or ttl_security")
        ),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    assert!(peers.lock().await.is_empty());
    assert!(
        bounce_calls.lock().await.is_empty(),
        "a refused reshape must not signal dynamic session resets"
    );
}

#[tokio::test]
async fn apply_required_family_reshape_bounces_dynamic_range_after_persist_ack() {
    // Load-bearing: reverting the config field makes the candidate
    // invalid; removing dynamic SessionReshape targeting or the
    // post-persist range bounce produces zero exact bounce calls.
    let previous_toml = dynamic_required_families_toml(false);
    let candidate_toml = dynamic_required_families_toml(true);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(Vec::new()));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers,
        bounce_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("required_families = [\"ipv6_unicast\"]"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    let bounce_calls = bounce_calls.lock().await;
    assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
    assert_eq!(bounce_calls[0].len(), 1);
    assert_eq!(bounce_calls[0][0].addr.to_string(), "10.30.0.0");
    assert_eq!(bounce_calls[0][0].prefix_len, 16);
}

#[tokio::test]
async fn apply_commits_mixed_static_and_dynamic_peer_group_reshape_after_persist_ack() {
    let previous_toml = mixed_peer_group_reshape_toml(90);
    let candidate_toml = mixed_peer_group_reshape_toml(45);
    let initial_peers = resolved_static_peer_configs(&previous_toml);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(initial_peers));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
        bounce_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("hold_time = 45"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    {
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hold_time, Some(45));
    }
    let bounce_calls = bounce_calls.lock().await;
    assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
    assert_eq!(bounce_calls[0].len(), 1);
    assert_eq!(bounce_calls[0][0].peer_group, "edge");
    assert!(
        response
            .human_text
            .contains("1 live session(s) reconfigured")
    );
    assert!(
        response
            .human_text
            .contains("1 live dynamic session(s) signaled to reset"),
        "{}",
        response.human_text
    );
}

#[tokio::test]
async fn dynamic_range_peer_group_reshape_persistence_failure_skips_bounce() {
    // The dynamic reset is post-persist by contract: a failed transaction
    // must never flap a live dynamic session.
    let previous_toml = dynamic_peer_group_reshape_toml(90);
    let candidate_toml = dynamic_peer_group_reshape_toml(45);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(Vec::new()));
    let bounce_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
        bounce_calls.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    assert!(
        bounce_calls.lock().await.is_empty(),
        "a failed transaction must not signal dynamic session resets"
    );
}

#[tokio::test]
async fn peer_session_reshape_persistence_failure_rolls_back_live_and_snapshot() {
    let previous_toml = peer_group_reshape_toml(90);
    let candidate_toml = peer_group_reshape_toml(45);
    let initial_peers = resolved_static_peer_configs(&previous_toml);
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx =
        spawn_typed_transaction_manager(snapshot_toml.clone(), peer_session_reshape_plan());
    let peers = Arc::new(Mutex::new(initial_peers));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        peer_session_reshape_plan(),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].hold_time, Some(90));
}

#[tokio::test]
async fn live_policy_impact_persistence_failure_rolls_back_live_and_snapshot() {
    let previous_toml = live_policy_toml("permit");
    let candidate_toml = live_policy_toml("deny");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx = spawn_typed_transaction_manager(snapshot_toml.clone(), live_impact_plan());
    let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
        &candidate_toml,
        &previous_toml,
    )])));
    // commit apply succeeds; the rollback restore apply also succeeds.
    let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(()), Ok(())])));
    let apply_calls = Arc::new(Mutex::new(Vec::new()));
    let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_live_policy_peer_manager(
        peer_rx,
        live_impact_plan(),
        snapshot_toml.clone(),
        apply_results,
        captured_priors,
        apply_calls.clone(),
        dynamic_calls,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    let calls = apply_calls.lock().await;
    assert_eq!(calls.len(), 2, "commit apply + rollback restore");
    assert_eq!(
        calls[1][0].address.to_string(),
        "10.0.0.2",
        "restore re-applies the captured priors"
    );
    assert_eq!(import_default_action(&calls[0][0]), PolicyAction::Deny);
    assert_eq!(import_default_action(&calls[1][0]), PolicyAction::Permit);
}

#[tokio::test]
async fn live_policy_impact_mid_fanout_failure_rolls_back_snapshot() {
    let previous_toml = live_policy_toml("permit");
    let candidate_toml = live_policy_toml("deny");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx = spawn_typed_transaction_manager(snapshot_toml.clone(), live_impact_plan());
    // The apply itself fails; the peer-manager command self-heals its live
    // mutations, so the executor only rolls back the snapshot.
    let apply_results = Arc::new(Mutex::new(VecDeque::from([Err(
        "peer apply failed".to_string()
    )])));
    let captured_priors = Arc::new(Mutex::new(VecDeque::new()));
    let apply_calls = Arc::new(Mutex::new(Vec::new()));
    let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_live_policy_peer_manager(
        peer_rx,
        live_impact_plan(),
        snapshot_toml.clone(),
        apply_results,
        captured_priors,
        apply_calls.clone(),
        dynamic_calls,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        // Persist should never be reached; drain the channel if it closes.
        let _ = config_rx.recv().await;
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(format!("{err}").contains("peer apply failed"), "{err:?}");
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    let calls = apply_calls.lock().await;
    assert_eq!(
        calls.len(),
        1,
        "only the failed apply; no restore (command self-heals)"
    );
}

#[tokio::test]
async fn live_policy_impact_compound_rollback_failure_reports_internal() {
    let previous_toml = live_policy_toml("permit");
    let candidate_toml = live_policy_toml("deny");
    let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
        &candidate_toml,
        &previous_toml,
    )])));
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(snapshot_toml.clone(), live_impact_plan());
    // commit apply succeeds; the rollback restore apply FAILS too.
    let apply_results = Arc::new(Mutex::new(VecDeque::from([
        Ok(()),
        Err("restore failed".to_string()),
    ])));
    let apply_calls = Arc::new(Mutex::new(Vec::new()));
    let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_live_policy_peer_manager(
        peer_rx,
        live_impact_plan(),
        snapshot_toml.clone(),
        apply_results,
        captured_priors,
        apply_calls,
        dynamic_calls,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        &err,
        ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::KnownDivergence,
            ..
        }
    ));
    let message = format!("{err}");
    assert!(message.contains("persist failed"), "{message}");
    assert!(message.contains("live policy rollback"), "{message}");
}

#[tokio::test]
async fn catalog_snapshot_persistence_failure_rolls_back_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[policy.definitions.prep-only]
default_action = "permit"
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[policy] definitions".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[policy] definitions".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
}

#[tokio::test]
async fn dynamic_neighbor_persistence_failure_rolls_back_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
}

#[tokio::test]
async fn dropped_typed_stage_reply_fences_without_persisting() {
    let previous_toml = base_toml("");
    let candidate_toml = dynamic_candidate_toml();
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let control = TypedTransactionFakeControl {
        drop_stage_ack: Arc::new(AtomicBool::new(true)),
        ..TypedTransactionFakeControl::default()
    };
    let transaction_plan = plan(
        RuntimeConfigTransactionStatus::Committable,
        vec!["[[dynamic_neighbors]]".to_string()],
    );
    let internal_tx = spawn_typed_transaction_manager_controlled(
        snapshot_toml.clone(),
        transaction_plan.clone(),
        control,
    );
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        transaction_plan,
        snapshot_toml,
        Arc::new(Mutex::new(Vec::new())),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(1);

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            ..
        }
    ));
    assert!(config_rx.try_recv().is_err());
}

#[tokio::test]
async fn persistence_failure_reports_snapshot_rollback_failure() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let control = TypedTransactionFakeControl::default();
    control.drop_restore_ack.store(true, Ordering::Relaxed);
    let internal_tx = spawn_typed_transaction_manager_controlled(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        control,
    );
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml,
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            ..
        }
    ));
}

#[tokio::test]
async fn apply_commits_static_neighbor_add_after_persist_ack() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml,
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("10.0.0.3"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(response.committed_sections, vec!["[[neighbors]] add"]);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address.to_string(), "10.0.0.3");
}

#[tokio::test]
async fn gnmi_set_hook_commits_static_neighbor_add_through_transactions() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let persisted = Arc::new(Mutex::new(String::new()));
    let persisted_task = Arc::clone(&persisted);
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            *persisted_task.lock().await = candidate_toml;
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
    );

    controller
        .apply_gnmi_set(gnmi_set_add_neighbor("10.0.0.3", 65003))
        .await
        .unwrap();

    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address.to_string(), "10.0.0.3");
    assert_eq!(peers[0].remote_asn, 65003);
    let persisted = persisted.lock().await;
    assert!(persisted.contains("10.0.0.3"));
    assert_eq!(*snapshot_toml.lock().await, *persisted);
}

#[tokio::test]
async fn gnmi_set_hook_commits_peer_group_catalog_through_transactions() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[peer_groups] catalog".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let persisted = Arc::new(Mutex::new(String::new()));
    let persisted_task = Arc::clone(&persisted);
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            *persisted_task.lock().await = candidate_toml;
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[peer_groups] catalog".to_string()],
        ),
        snapshot_toml.clone(),
    );

    controller
        .apply_gnmi_set(gnmi_set_peer_group_hold_time("rs-clients", 45))
        .await
        .unwrap();

    let persisted = persisted.lock().await;
    assert!(persisted.contains("[peer_groups.rs-clients]"));
    assert!(persisted.contains("hold_time = 45"));
    assert_eq!(*snapshot_toml.lock().await, *persisted);
}

#[tokio::test]
async fn gnmi_set_hook_commits_dynamic_neighbors_through_transactions() {
    let previous_toml = base_toml(
        r"
[peer_groups.ix-members]
",
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let persisted = Arc::new(Mutex::new(String::new()));
    let persisted_task = Arc::clone(&persisted);
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            *persisted_task.lock().await = candidate_toml;
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
    );

    controller
        .apply_gnmi_set(gnmi_set_dynamic_neighbor("10.0.0.0/24", "ix-members"))
        .await
        .unwrap();

    let persisted = persisted.lock().await;
    assert!(persisted.contains("[[dynamic_neighbors]]"));
    assert!(persisted.contains("prefix = \"10.0.0.0/24\""));
    assert!(persisted.contains("peer_group = \"ix-members\""));
    assert!(persisted.contains("remote_asn = 0"));
    assert_eq!(*snapshot_toml.lock().await, *persisted);
}

#[tokio::test]
async fn gnmi_set_commit_request_enters_confirmed_pending() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
    );

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "deploy-42",
            120,
        ))
        .await
        .unwrap();

    let status = controller.status().await.unwrap();
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-42");
    assert_eq!(confirmation.timeout_seconds, 120);
    assert_eq!(peers.lock().await.len(), 1);
}

#[tokio::test]
async fn gnmi_set_commit_confirm_finalizes_pending_transaction() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
    );
    controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "deploy-42",
            120,
        ))
        .await
        .unwrap();

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_commit_confirm("deploy-42"))
        .await
        .unwrap();

    let status = controller.status().await.unwrap();
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Confirmed as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-42");
}

#[tokio::test]
async fn gnmi_set_commit_cancel_rolls_back_pending_transaction() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![NEIGHBOR_DELETE_SECTION.to_string()],
        ),
        snapshot_toml.clone(),
    );
    controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "deploy-42",
            120,
        ))
        .await
        .unwrap();

    controller
        .clone()
        .apply_gnmi_set(gnmi_set_commit_cancel("deploy-42"))
        .await
        .unwrap();

    let status = controller.status().await.unwrap();
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Aborted as i32
    );
    assert_eq!(confirmation.confirm_id, "deploy-42");
}

#[tokio::test]
async fn gnmi_set_confirm_and_cancel_validate_confirm_id() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml,
        peers,
    ));
    let controller = ConfigTransactionController::new(
        deps_value(None, peer_tx, None, Vec::new()),
        BgpMetrics::new(),
    );

    let Err(err) = controller
        .clone()
        .apply_gnmi_set(gnmi_set_commit_confirm("bad\nid"))
        .await
    else {
        panic!("malformed gNMI confirm id must reject");
    };
    assert!(matches!(
        err,
        GnmiSetError::InvalidArgument(ref message)
            if message.contains("must not contain control characters")
    ));

    let Err(err) = controller
        .apply_gnmi_set(gnmi_set_commit_cancel("bad\nid"))
        .await
    else {
        panic!("malformed gNMI cancel id must reject");
    };
    assert!(matches!(
        err,
        GnmiSetError::InvalidArgument(ref message)
            if message.contains("must not contain control characters")
    ));
}

#[tokio::test]
async fn gnmi_set_rollback_duration_rejects_missing_pending_wrong_id_and_zero_timeout() {
    let controller = ConfigTransactionController::new(
        deps_value(None, mpsc::channel(1).0, None, Vec::new()),
        BgpMetrics::new(),
    );
    let Err(err) = controller
        .clone()
        .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 120))
        .await
    else {
        panic!("rollback-duration reset without pending transaction must reject");
    };
    assert!(matches!(
        err,
        GnmiSetError::FailedPrecondition(ref message)
            if message.contains("no confirmed config transaction is pending")
    ));

    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
    );
    let (controller, _snapshot_toml, ack_task) =
        confirmed_dynamic_controller(previous_toml, candidate_toml).await;

    let Err(err) = controller
        .clone()
        .apply_gnmi_set(gnmi_set_rollback_duration("wrong-id", 120))
        .await
    else {
        panic!("rollback-duration reset with wrong id must reject");
    };
    assert!(matches!(
        err,
        GnmiSetError::FailedPrecondition(ref message)
            if message.contains("confirmed config transaction id mismatch")
    ));

    let Err(err) = controller
        .clone()
        .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 0))
        .await
    else {
        panic!("rollback-duration reset with zero timeout must reject");
    };
    assert!(matches!(
        err,
        GnmiSetError::InvalidArgument(ref message)
            if message.contains("confirm_timeout_seconds must be positive")
    ));

    let status = controller.status().await.expect("status must succeed");
    let confirmation = status.confirmation.unwrap();
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.timeout_seconds, 60);
    ack_task.abort();
}

#[tokio::test]
async fn gnmi_set_rejects_normal_set_while_confirmed_pending() {
    let previous_toml = base_toml("");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });
    let controller = with_test_preloaded_plan(
        ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        ),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
    );
    controller
        .clone()
        .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
            "10.0.0.3",
            65003,
            "deploy-42",
            120,
        ))
        .await
        .unwrap();

    let Err(err) = controller
        .apply_gnmi_set(gnmi_set_add_neighbor("10.0.0.4", 65004))
        .await
    else {
        panic!("normal gNMI Set must reject while confirmed transaction is pending");
    };
    assert!(matches!(
        err,
        GnmiSetError::FailedPrecondition(ref message)
            if message.contains("gnmi.gNMI/Set")
    ));
}

#[tokio::test]
async fn static_neighbor_add_resolves_canonical_ipv6_address() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[[neighbors]]
address = "2001:0db8:0000:0000:0000:0000:0000:0003"
remote_asn = 65003
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml,
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address.to_string(), "2001:db8::3");
}

#[tokio::test]
async fn apply_commits_static_neighbor_modify_after_persist_ack() {
    let previous_toml = base_toml("");
    let candidate_toml =
        previous_toml.replace("remote_asn = 65002", "remote_asn = 65002\nhold_time = 45");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let previous_peer = peer_config_from_toml(&previous_toml, "10.0.0.2");
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] modify".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(vec![previous_peer]));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] modify".to_string()],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("hold_time = 45"));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(response.committed_sections, vec!["[[neighbors]] modify"]);
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address.to_string(), "10.0.0.2");
    assert_eq!(peers[0].hold_time, Some(45));
}

#[tokio::test]
async fn static_neighbor_modify_persistence_failure_rolls_back_peer_and_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml =
        previous_toml.replace("remote_asn = 65002", "remote_asn = 65002\nhold_time = 45");
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let previous_peer = peer_config_from_toml(&previous_toml, "10.0.0.2");
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] modify".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(vec![previous_peer.clone()]));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] modify".to_string()],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
            config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, previous_peer.address);
    assert_eq!(peers[0].hold_time, previous_peer.hold_time);
}

#[tokio::test]
async fn static_neighbor_mid_batch_add_failure_rolls_back_prior_add_and_snapshot() {
    let previous_toml = base_toml("");
    let candidate_toml = base_toml(
        r#"
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
"#,
    );
    let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
    );
    let peers = Arc::new(Mutex::new(vec![peer_config_from_toml(
        &candidate_toml,
        "10.0.0.4",
    )]));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[neighbors]] add".to_string()],
        ),
        snapshot_toml.clone(),
        peers.clone(),
    ));
    let (config_tx, _config_rx) = mpsc::channel(8);

    let err = apply_config_transaction_with_internal(
        deps(None, peer_tx, Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("10.0.0.4") && message.contains("already exists")),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    let peers = peers.lock().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address.to_string(), "10.0.0.4");
}

#[tokio::test]
async fn apply_commits_fib_full_set_after_persist_ack() {
    let original = table("edge", 1000);
    let replacement = table("core", 1001);
    let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
    let staged = Arc::new(Mutex::new(vec![snapshot(&original)]));
    let current = Arc::new(Mutex::new(fib_config(&original)));
    let internal_tx = spawn_typed_transaction_manager_with_current(
        current.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[fib_tables]]".to_string()],
        ),
    );

    let (fib_tx, fib_rx) = mpsc::channel(8);
    tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[fib_tables]]".to_string()],
        ),
        staged.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(rustbgpd_api::peer_types::ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        }) = config_rx.recv().await
        {
            assert!(candidate_toml.contains("config_epoch = 1"));
            assert!(candidate_toml.contains("name = \"core\""));
            ack.accept().await;
        }
    });

    let response = apply_config_transaction_with_internal(
        deps(
            Some(fib_tx),
            peer_tx,
            Some(config_tx),
            vec![original.clone()],
        ),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: base_toml(
                r#"
[[fib_tables]]
name = "core"
table_id = 1001
metric = 200
families = ["ipv4_unicast"]
"#,
            ),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: "deploy-1".to_string(),
            comment: "commit FIB".to_string(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap();

    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(response.committed_sections, vec!["[[fib_tables]]"]);
    assert!(response.runtime_snapshot_token.starts_with("kv1:"));
    assert_eq!(*fib_state.lock().await, vec![replacement.clone()]);
    assert_eq!(current.lock().await.fib_tables, vec![replacement]);
    assert_eq!(*staged.lock().await, vec![snapshot(&original)]);
}

#[tokio::test]
async fn persistence_rejection_rolls_back_fib_transaction() {
    let original = table("edge", 1000);
    let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
    let staged = Arc::new(Mutex::new(vec![snapshot(&original)]));
    let prior = fib_config(&original);
    let current = Arc::new(Mutex::new(prior.clone()));
    let internal_tx = spawn_typed_transaction_manager_with_current(
        current.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[fib_tables]]".to_string()],
        ),
    );

    let (fib_tx, fib_rx) = mpsc::channel(8);
    tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[fib_tables]]".to_string()],
        ),
        staged.clone(),
    ));
    let (config_tx, mut config_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Some(rustbgpd_api::peer_types::ConfigEvent::ConfigTransactionCommitted {
            ack: Some(ack),
            ..
        }) = config_rx.recv().await
        {
            ack.fail_write("persist failed");
        }
    });

    let err = apply_config_transaction_with_internal(
        deps(
            Some(fib_tx),
            peer_tx,
            Some(config_tx),
            vec![original.clone()],
        ),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: base_toml(
                r#"
[[fib_tables]]
name = "core"
table_id = 1001
metric = 200
families = ["ipv4_unicast"]
"#,
            ),
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
        "{err:?}"
    );
    assert_eq!(*fib_state.lock().await, vec![original.clone()]);
    assert_eq!(*staged.lock().await, vec![snapshot(&original)]);
    assert_eq!(*current.lock().await, prior);
}

#[tokio::test]
async fn fib_stage_rejection_precedes_reconciler_and_persistence() {
    let edge = table("edge", 1000);
    let core = table("core", 1001);
    let (fib_tx, mut fib_rx) = mpsc::channel(4);
    let fib_task = tokio::spawn(async move {
        let Some(FibRuntimeCommand::GetTables { reply }) = fib_rx.recv().await else {
            panic!("FIB stage ordering must read the prior first");
        };
        reply.send(vec![edge]).unwrap();
        assert!(
            fib_rx.recv().await.is_none(),
            "stage rejection must precede typed FIB replacement"
        );
    });
    let (internal_tx, mut internal_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let Some(InternalCommand::StageTransactionConfig { reply, .. }) = internal_rx.recv().await
        else {
            panic!("transaction must stage its full snapshot");
        };
        reply.send(Err("stage rejected".to_string())).unwrap();
    });
    let (config_tx, mut config_rx) = mpsc::channel(1);
    let deps = deps(
        Some(fib_tx),
        mpsc::channel(1).0,
        Some(config_tx.clone()),
        Vec::new(),
    );
    let error = commit_fib_transaction(
        &deps,
        &internal_tx,
        &config_tx,
        "candidate".to_string(),
        fib_config(&core),
        "next".to_string(),
        proto::UpdateGroupImpactPlan::default(),
        &RuntimeConfigMutationProgress::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error.error,
        ConfigTransactionApplyError::InvalidArgument(_)
    ));
    drop(deps);
    drop(config_tx);
    fib_task.await.unwrap();
    assert!(
        config_rx.try_recv().is_err(),
        "rejected stage must not persist"
    );
}

#[tokio::test]
async fn fib_ack_loss_is_ambiguous_but_restores_tables_and_raw_snapshot() {
    let edge = table("edge", 1000);
    let core = table("core", 1001);
    let fib_state = Arc::new(Mutex::new(vec![edge.clone()]));
    let current = Arc::new(Mutex::new(fib_config(&edge)));
    let prior = current.lock().await.clone();
    let (fib_tx, fib_rx) = mpsc::channel(8);
    tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));
    let internal_tx = spawn_typed_transaction_manager_with_current(
        current.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[fib_tables]]".to_string()],
        ),
    );
    let (config_tx, mut config_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let Some(ConfigEvent::ConfigTransactionCommitted { ack, .. }) = config_rx.recv().await
        else {
            panic!("FIB transaction must use the full-config persistence seam")
        };
        drop(ack);
    });
    let deps = deps(
        Some(fib_tx),
        mpsc::channel(1).0,
        Some(config_tx.clone()),
        vec![edge.clone()],
    );
    let failure = commit_fib_transaction(
        &deps,
        &internal_tx,
        &config_tx,
        "candidate".to_string(),
        fib_config(&core),
        "next".to_string(),
        proto::UpdateGroupImpactPlan::default(),
        &RuntimeConfigMutationProgress::default(),
    )
    .await
    .unwrap_err();
    assert!(failure.fence_reason.is_some());
    assert_eq!(*fib_state.lock().await, vec![core]);
    assert_ne!(*current.lock().await, prior);
}

#[test]
fn fib_errors_map_to_apply_errors() {
    assert_eq!(
        fib_error_to_apply_error(FibTableControlError::Unavailable("busy".to_string())),
        ConfigTransactionApplyError::Unavailable("busy".to_string())
    );
}

#[test]
fn apply_response_preserves_the_accepted_plan_impact_exactly() {
    let impact = proto::UpdateGroupImpactPlan {
        schema_version: 1,
        capacity_class: "within_mixed".to_string(),
        capacity_basis: "fixture".to_string(),
        ..proto::UpdateGroupImpactPlan::default()
    };
    let response = committable_response(
        "after".to_string(),
        vec!["[policy]".to_string()],
        "committed".to_string(),
        Some(impact.clone()),
    );
    assert_eq!(response.update_group_impact, Some(impact));
}

fn update_group_equivalence_toml(candidate: bool) -> String {
    let peer_groups = if candidate {
        r#"
[peer_groups.ga]
export_policy_chain = ["new-shared"]
[peer_groups.gb]
export_policy_chain = ["b-private"]
[peer_groups.gc]
export_policy_chain = ["new-shared"]
[peer_groups.gd]
export_policy_chain = ["stable"]
[peer_groups.ge]
export_policy_chain = ["stable"]
"#
    } else {
        r#"
[peer_groups.ga]
export_policy_chain = ["old-shared"]
[peer_groups.gb]
export_policy_chain = ["old-shared"]
[peer_groups.gc]
export_policy_chain = ["c-distinct"]
[peer_groups.gd]
export_policy_chain = ["d-private"]
[peer_groups.ge]
export_policy_chain = ["stable"]
"#
    };
    tier_transaction_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.neighbor_sets.peer-context]
addresses = ["10.0.0.12"]

[policy.definitions.old-shared]
default_action = "permit"

[policy.definitions.c-distinct]
default_action = "deny"

[policy.definitions.d-private]
default_action = "permit"
[[policy.definitions.d-private.statements]]
match_neighbor_set = "peer-context"
action = "deny"

[policy.definitions.stable]
default_action = "permit"
[[policy.definitions.stable.statements]]
prefix = "203.0.113.0/24"
action = "deny"

[policy.definitions.new-shared]
default_action = "permit"
[[policy.definitions.new-shared.statements]]
prefix = "198.51.100.0/24"
action = "deny"

[policy.definitions.b-private]
default_action = "permit"
[[policy.definitions.b-private.statements]]
match_neighbor_set = "peer-context"
action = "deny"

{peer_groups}

[[neighbors]]
address = "10.0.0.11"
remote_asn = 65001
families = ["ipv4_unicast", "ipv6_unicast"]
peer_group = "ga"

[[neighbors]]
address = "10.0.0.12"
remote_asn = 65001
families = ["ipv4_unicast", "ipv6_unicast"]
peer_group = "gb"

[[neighbors]]
address = "10.0.0.13"
remote_asn = 65001
families = ["ipv4_unicast", "ipv6_unicast"]
peer_group = "gc"

[[neighbors]]
address = "10.0.0.14"
remote_asn = 65001
families = ["ipv4_unicast", "ipv6_unicast"]
peer_group = "gd"

[[neighbors]]
address = "10.0.0.15"
remote_asn = 65001
families = ["ipv4_unicast", "ipv6_unicast"]
peer_group = "ge"
"#
    ))
}

async fn query_real_update_group_snapshot(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
) -> rustbgpd_rib::UpdateGroupSnapshot {
    let (reply, receive) = oneshot::channel();
    rib_tx
        .send(rustbgpd_rib::RibUpdate::QueryUpdateGroupSnapshot { reply })
        .await
        .expect("real RIB must accept update-group snapshot query");
    receive
        .await
        .expect("real RIB must return update-group snapshot")
}

fn candidate_state_for_peer(
    impact: &rustbgpd_rib::UpdateGroupImpactPlan,
    peer: std::net::IpAddr,
) -> rustbgpd_rib::PlannedGroupability {
    let mut states = impact
        .entries
        .iter()
        .filter(|row| row.peer == peer)
        .map(|row| &row.candidate);
    let first = states
        .next()
        .expect("peer must have at least one planned family")
        .clone();
    assert!(
        states.all(|state| state == &first),
        "one candidate state across peer families"
    );
    first
}

fn planned_families(
    impact: &rustbgpd_rib::UpdateGroupImpactPlan,
    peer: std::net::IpAddr,
) -> BTreeSet<(u16, u8)> {
    impact
        .entries
        .iter()
        .filter(|row| row.peer == peer)
        .map(|row| (row.afi, row.safi))
        .collect()
}

fn planned_group_id(state: &rustbgpd_rib::PlannedGroupability) -> Option<&str> {
    match state {
        rustbgpd_rib::PlannedGroupability::Group { id } => Some(id),
        _ => None,
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the end-to-end oracle keeps the real plan, apply, persistence, RIB, and re-plan assertions in one auditable scenario"
)]
async fn config_transaction_plan_matches_real_post_apply_update_groups() {
    use rustbgpd_rib::{PlannedGroupability, UpdateGroupClassification, UpdateGroupImpactRollup};
    use rustbgpd_wire::{Afi, Safi};

    let current_toml = update_group_equivalence_toml(false);
    let candidate_toml = update_group_equivalence_toml(true);
    let current = Config::load_toml_with_diagnostics(&current_toml, "current parity config")
        .expect("current parity config must parse");
    let resolved = current
        .resolved_neighbors()
        .expect("current parity neighbors must resolve");
    assert_eq!(resolved.len(), 5);

    let (rib_tx, rib_rx) = mpsc::channel(128);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let rib_manager =
        rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let rib_task = tokio::spawn(rib_manager.run());

    let (peer_tx, peer_rx) = mpsc::channel(64);
    let (internal_tx, internal_rx) = mpsc::channel(1);
    let mut peer_manager = crate::peer_manager::PeerManager::new_with_config(
        peer_rx,
        internal_rx,
        current.global.asn,
        current.global.router_id.parse().unwrap(),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
        None,
        current.clone(),
    );

    let mut session_acks = BTreeMap::new();
    let mut outbound_receivers = Vec::new();
    for (index, neighbor) in resolved.into_iter().enumerate() {
        let peer = neighbor.transport_config.remote_addr.ip();
        let session_id = u64::try_from(index + 1).unwrap();
        session_acks.insert(
            peer,
            peer_manager.install_established_policy_test_peer(neighbor.clone(), session_id),
        );
        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
        rib_tx
            .send(rustbgpd_rib::RibUpdate::PeerUp {
                peer,
                session_id,
                peer_asn: neighbor.transport_config.peer.remote_asn,
                peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
                outbound_tx,
                export_policy: neighbor.export_policy,
                sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
                is_ebgp: false,
                route_reflector_client: false,
                orr_vantage: None,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: Vec::new(),
                add_path_send_max: 0,
                negotiated_orf_recv: Vec::new(),
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .expect("real RIB must accept PeerUp");
        let initial = outbound_rx
            .recv()
            .await
            .expect("real RIB must emit initial EoR");
        assert!(initial.announce.is_empty());
        assert!(initial.withdraw.is_empty());
        assert_eq!(
            initial
                .end_of_rib
                .iter()
                .map(|(afi, safi)| (*afi as u16, *safi as u8))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([(1, 1), (2, 1)])
        );
        outbound_receivers.push(outbound_rx);
    }
    let peer_task = tokio::spawn(peer_manager.run());

    let before = query_real_update_group_snapshot(&rib_tx).await;
    assert_eq!(before.peers.len(), 5, "all real PeerUp rows are visible");

    let planned = plan_candidate(&peer_tx, candidate_toml.clone(), String::new(), true)
        .await
        .expect("real PlanConfigTransaction flow must succeed");
    assert_eq!(planned.status, RuntimeConfigTransactionStatus::Committable);
    let committed_candidate_toml = planned
        .committed_candidate
        .as_ref()
        .expect("committable plan carries the exact committed candidate")
        .as_str()
        .to_string();
    assert_eq!(planned.update_group_impact.entries.len(), 10);
    assert_eq!(
        planned.update_group_impact.rollup,
        UpdateGroupImpactRollup {
            affected_peers: 4,
            affected_families: 8,
            no_op: 2,
            regroup: 4,
            shared_migration: 2,
            private_resync: 2,
            indeterminate: 0,
            projected_shared_groups: 2,
            projected_private_views: 1,
            local_resyncs: 8,
            remote_route_refreshes: 0,
        }
    );
    assert!(
        planned
            .update_group_impact
            .entries
            .iter()
            .all(|row| !row.remote_route_refresh)
    );

    let peers = (11_u8..=15)
        .map(|last| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last)))
        .collect::<Vec<_>>();
    let expected_transitions = [
        "regroup",
        "private_resync",
        "regroup",
        "shared_migration",
        "no_op",
    ];
    for (&peer, expected) in peers.iter().zip(expected_transitions) {
        let rows = planned
            .update_group_impact
            .entries
            .iter()
            .filter(|row| row.peer == peer)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.transition == expected));
        assert_eq!(
            planned_families(&planned.update_group_impact, peer),
            BTreeSet::from([(1, 1), (2, 1)])
        );
    }

    let peer_a = candidate_state_for_peer(&planned.update_group_impact, peers[0]);
    let peer_b = candidate_state_for_peer(&planned.update_group_impact, peers[1]);
    let peer_c = candidate_state_for_peer(&planned.update_group_impact, peers[2]);
    let peer_d = candidate_state_for_peer(&planned.update_group_impact, peers[3]);
    let peer_e = candidate_state_for_peer(&planned.update_group_impact, peers[4]);
    assert_eq!(planned_group_id(&peer_a), planned_group_id(&peer_c));
    assert_eq!(planned_group_id(&peer_d), planned_group_id(&peer_e));
    assert_ne!(planned_group_id(&peer_a), planned_group_id(&peer_d));
    let planned_private_fingerprint = match &peer_b {
        PlannedGroupability::Private {
            reason,
            fingerprint,
        } => {
            assert_eq!(reason, "policy_peer_context");
            fingerprint.clone()
        }
        other => panic!("peer B must plan private, got {other:?}"),
    };

    let persisted = Arc::new(Mutex::new(None));
    let persisted_task = Arc::clone(&persisted);
    let (config_tx, mut config_rx) = mpsc::channel(4);
    let persist_task = tokio::spawn(async move {
        let event = config_rx
            .recv()
            .await
            .expect("ApplyConfigTransaction must persist the candidate");
        let ConfigEvent::ConfigTransactionCommitted {
            candidate_toml,
            ack: Some(ack),
        } = event
        else {
            panic!("expected persisted config transaction event");
        };
        *persisted_task.lock().await = Some(candidate_toml);
        ack.accept().await;
    });

    let expected_apply_impact =
        rustbgpd_api::update_group_impact_to_proto(planned.update_group_impact.clone());
    let response = apply_config_transaction_with_internal(
        deps(None, peer_tx.clone(), Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: planned.runtime_snapshot_token.clone(),
            client_request_id: "plan-apply-parity".to_string(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .expect("real ApplyConfigTransaction flow must succeed");
    persist_task.await.unwrap();
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_eq!(response.update_group_impact, Some(expected_apply_impact));
    assert_eq!(
        persisted.lock().await.as_deref(),
        Some(committed_candidate_toml.as_str())
    );

    let after = query_real_update_group_snapshot(&rib_tx).await;
    let live = after
        .peers
        .iter()
        .map(|row| (row.peer, row))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(live.len(), 5);

    for &peer in &peers {
        let row = live[&peer];
        assert_eq!(
            row.input
                .sendable_families
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            planned_families(&planned.update_group_impact, peer),
            "planned family rows must match the real negotiated snapshot"
        );
    }

    for &peer in &[peers[0], peers[2], peers[3], peers[4]] {
        assert!(matches!(
            live[&peer].classification,
            UpdateGroupClassification::Groupable(_)
        ));
        assert!(live[&peer].runtime_membership.starts_with("group:"));
    }
    assert_eq!(
        live[&peers[1]].classification.reason(),
        Some("policy_peer_context")
    );
    assert_eq!(live[&peers[1]].runtime_membership, "policy_peer_context");
    assert_eq!(
        planned_private_fingerprint,
        format!("{:?}", live[&peers[1]].input),
        "planned private fingerprint must equal the real post-apply classifier input"
    );

    for receiver in &mut outbound_receivers {
        assert!(!receiver.is_closed(), "real RIB outbound stream stays live");
        while receiver.try_recv().is_ok() {}
    }

    for left in 0..peers.len() {
        for right in (left + 1)..peers.len() {
            let left_plan = candidate_state_for_peer(&planned.update_group_impact, peers[left]);
            let right_plan = candidate_state_for_peer(&planned.update_group_impact, peers[right]);
            if let (Some(left_id), Some(right_id)) =
                (planned_group_id(&left_plan), planned_group_id(&right_plan))
            {
                assert_eq!(
                    left_id == right_id,
                    live[&peers[left]].runtime_membership == live[&peers[right]].runtime_membership,
                    "plan-local group equality must equal real runtime partition equality"
                );
            }
        }
    }

    let live_shared_groups = live
        .values()
        .filter(|row| matches!(row.classification, UpdateGroupClassification::Groupable(_)))
        .map(|row| row.runtime_membership.as_str())
        .collect::<BTreeSet<_>>();
    let live_private_views = live
        .values()
        .filter(|row| row.classification.reason().is_some())
        .count();
    assert_eq!(live_shared_groups.len(), 2);
    assert_eq!(live_private_views, 1);
    assert_eq!(
        u32::try_from(live_shared_groups.len()).unwrap(),
        planned.update_group_impact.rollup.projected_shared_groups
    );
    assert_eq!(
        u32::try_from(live_private_views).unwrap(),
        planned.update_group_impact.rollup.projected_private_views
    );

    for (index, peer) in peers.iter().enumerate() {
        let acks = &session_acks[peer];
        if index < 4 {
            assert_eq!(acks.state_queries(), 1, "changed peer {peer}");
            assert_eq!(acks.export_updates(), 1, "changed peer {peer}");
        } else {
            assert_eq!(acks.state_queries(), 0, "stable peer {peer}");
            assert_eq!(acks.export_updates(), 0, "stable peer {peer}");
        }
        assert_eq!(acks.import_updates(), 0, "export-only peer {peer}");
        assert_eq!(acks.route_refreshes(), 0, "export-only peer {peer}");
    }

    let replanned = plan_candidate(&peer_tx, committed_candidate_toml, String::new(), true)
        .await
        .expect("re-plan of the committed candidate must succeed");
    assert_eq!(replanned.status, RuntimeConfigTransactionStatus::Noop);
    assert_eq!(replanned.update_group_impact.entries.len(), 10);
    assert!(
        replanned
            .update_group_impact
            .entries
            .iter()
            .all(|row| row.transition == "no_op")
    );
    assert_eq!(
        replanned.update_group_impact.rollup,
        UpdateGroupImpactRollup {
            no_op: 10,
            projected_shared_groups: 2,
            projected_private_views: 1,
            ..UpdateGroupImpactRollup::default()
        }
    );

    drop(peer_tx);
    peer_task.await.unwrap();
    for (peer, acks) in &session_acks {
        tokio::time::timeout(std::time::Duration::from_secs(1), acks.wait_for_exit())
            .await
            .unwrap_or_else(|_| panic!("Established test session {peer} did not exit"));
    }
    drop(rib_tx);
    rib_task.await.unwrap();
    drop(outbound_receivers);
}

const HETEROGENEOUS_UPDATE_GROUP_TOML: &str = r#"
policy = { definitions = { old-shared = { default_action = "permit" }, new-shared = { default_action = "permit", statements = [{ prefix = "198.51.100.0/24", action = "deny" }] } } }
peer_groups = { changed = { export_policy_chain = ["CHANGED_POLICY"] } }
neighbors = [
  { address = "10.0.0.11", remote_asn = 65002, peer_group = "changed" },
  { address = "10.0.0.12", remote_asn = 65001, peer_group = "changed" },
  { address = "10.0.0.13", remote_asn = 65001, route_reflector_client = true, peer_group = "changed" },
  { address = "10.0.0.14", remote_asn = 65001, route_reflector_client = true, orr_vantage = "192.0.2.14" },
  { address = "10.0.0.15", remote_asn = 65003, add_path = { send = true, send_max = 4 } },
]
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one oracle joins plan and live RIB")]
async fn config_transaction_plan_matches_real_post_apply_heterogeneous_update_groups() {
    use rustbgpd_rib::{PlannedGroupability, UpdateGroupImpactRollup};
    use rustbgpd_wire::{Afi, Safi};

    let current_toml = tier_transaction_test_config(
        &HETEROGENEOUS_UPDATE_GROUP_TOML.replace("CHANGED_POLICY", "old-shared"),
    );
    let candidate_toml = tier_transaction_test_config(
        &HETEROGENEOUS_UPDATE_GROUP_TOML.replace("CHANGED_POLICY", "new-shared"),
    );
    let current = Config::load_toml_with_diagnostics(&current_toml, "heterogeneous current")
        .expect("heterogeneous current config must parse");
    let resolved = current
        .resolved_neighbors()
        .expect("heterogeneous current neighbors must resolve");
    let peers = resolved
        .iter()
        .map(|row| row.transport_config.remote_addr.ip())
        .collect::<Vec<_>>();
    let expected_peers = (11..=15)
        .map(|last| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last)))
        .collect::<Vec<_>>();
    assert_eq!(peers, expected_peers);
    let (rib_tx, rib_rx) = mpsc::channel(128);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let rib_task = tokio::spawn(
        rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new()).run(),
    );
    let (peer_tx, peer_rx) = mpsc::channel(64);
    let (internal_tx, internal_rx) = mpsc::channel(1);
    let mut peer_manager = crate::peer_manager::PeerManager::new_with_config(
        peer_rx,
        internal_rx,
        current.global.asn,
        current.global.router_id.parse().unwrap(),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
        None,
        current.clone(),
    );

    let mut session_acks = BTreeMap::new();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
    for (index, neighbor) in resolved.into_iter().enumerate() {
        let peer = neighbor.transport_config.remote_addr.ip();
        let session_id = u64::try_from(index + 1).unwrap();
        session_acks.insert(
            peer,
            peer_manager.install_established_policy_test_peer(neighbor.clone(), session_id),
        );
        // Production PeerUp negotiated-state fixture; wire OPEN is out of scope.
        let add_path = (index == 4).then_some(vec![(Afi::Ipv4, Safi::Unicast)]);
        rib_tx
            .send(rustbgpd_rib::RibUpdate::PeerUp {
                peer,
                session_id,
                peer_asn: neighbor.transport_config.peer.remote_asn,
                peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
                outbound_tx: outbound_tx.clone(),
                export_policy: neighbor.export_policy,
                sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
                is_ebgp: neighbor.transport_config.peer.remote_asn != current.global.asn,
                route_reflector_client: neighbor.transport_config.route_reflector_client,
                orr_vantage: neighbor.transport_config.orr_vantage,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: add_path.clone().unwrap_or_default(),
                add_path_send_max: add_path.map_or(0, |_| 4),
                negotiated_orf_recv: Vec::new(),
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .expect("real RIB must accept heterogeneous PeerUp");
    }
    let peer_task = tokio::spawn(peer_manager.run());
    let before = query_real_update_group_snapshot(&rib_tx).await;
    assert_eq!(before.peers.len(), 5, "all heterogeneous peers are live");
    while outbound_rx.try_recv().is_ok() {}
    let planned = plan_candidate(&peer_tx, candidate_toml.clone(), String::new(), true)
        .await
        .expect("heterogeneous plan must succeed");
    assert_eq!(planned.status, RuntimeConfigTransactionStatus::Committable);
    let committed_candidate_toml = planned
        .committed_candidate
        .as_ref()
        .expect("committable plan carries the exact committed candidate")
        .as_str()
        .to_string();
    let impact = &planned.update_group_impact;
    assert_eq!(impact.entries.len(), 5);
    assert_eq!(
        impact.rollup,
        UpdateGroupImpactRollup {
            affected_peers: 3,
            affected_families: 3,
            no_op: 2,
            regroup: 3,
            projected_shared_groups: 3,
            projected_private_views: 2,
            local_resyncs: 3,
            ..UpdateGroupImpactRollup::default()
        }
    );
    for (index, peer) in peers.iter().enumerate() {
        let rows = impact
            .entries
            .iter()
            .filter(|row| row.peer == *peer)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].afi, rows[0].safi), (1, 1));
        assert_eq!(
            rows[0].transition,
            if index < 3 { "regroup" } else { "no_op" }
        );
    }
    let candidates = peers
        .iter()
        .map(|peer| candidate_state_for_peer(impact, *peer))
        .collect::<Vec<_>>();
    assert_eq!(
        candidates[..3]
            .iter()
            .map(|state| planned_group_id(state).unwrap().to_string())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    let private_fingerprints = peers[3..]
        .iter()
        .zip(["orr_vantage", "add_path_send"])
        .zip(&candidates[3..])
        .map(|((peer, expected_reason), state)| match state {
            PlannedGroupability::Private {
                reason,
                fingerprint,
            } => {
                assert_eq!(reason, expected_reason);
                (*peer, fingerprint.clone())
            }
            other => panic!("{peer} must plan private, got {other:?}"),
        })
        .collect::<BTreeMap<_, _>>();

    let (config_tx, config_rx) = mpsc::channel(4);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    apply_config_transaction_with_internal(
        deps(None, peer_tx.clone(), Some(config_tx), Vec::new()),
        proto::ApplyConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: planned.runtime_snapshot_token.clone(),
            client_request_id: "heterogeneous-plan-live-parity".to_string(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        },
        internal_tx,
    )
    .await
    .expect("heterogeneous apply must succeed");
    ack_task.await.unwrap();
    while outbound_rx.try_recv().is_ok() {}

    let after = query_real_update_group_snapshot(&rib_tx).await;
    let live = after
        .peers
        .iter()
        .map(|row| (row.peer, row))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        live.values()
            .filter(|row| row.classification.reason().is_none())
            .map(|row| row.runtime_membership.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    for (peer, reason) in peers[3..].iter().zip(["orr_vantage", "add_path_send"]) {
        assert_eq!(live[peer].classification.reason(), Some(reason));
        assert_eq!(
            private_fingerprints[peer],
            format!("{:?}", live[peer].input)
        );
    }
    for left in 0..peers.len() {
        for right in (left + 1)..peers.len() {
            assert_eq!(
                candidates[left] == candidates[right],
                live[&peers[left]].runtime_membership == live[&peers[right]].runtime_membership,
                "planned equality must exactly match live partition equality"
            );
        }
    }
    for (index, peer) in peers.iter().enumerate() {
        let acks = &session_acks[peer];
        assert_eq!(acks.state_queries(), u32::from(index < 3));
        assert_eq!(acks.export_updates(), u32::from(index < 3));
        assert_eq!((acks.import_updates(), acks.route_refreshes()), (0, 0));
    }

    let replanned = plan_candidate(&peer_tx, committed_candidate_toml, String::new(), true)
        .await
        .expect("re-plan of the committed candidate must succeed");
    assert_eq!(replanned.status, RuntimeConfigTransactionStatus::Noop);
    assert!(
        replanned
            .update_group_impact
            .entries
            .iter()
            .all(|row| row.transition == "no_op")
    );
    assert_eq!(
        replanned.update_group_impact.rollup,
        UpdateGroupImpactRollup {
            no_op: 5,
            projected_shared_groups: 3,
            projected_private_views: 2,
            ..UpdateGroupImpactRollup::default()
        }
    );

    drop(peer_tx);
    peer_task.await.unwrap();
    for (peer, acks) in &session_acks {
        tokio::time::timeout(std::time::Duration::from_secs(1), acks.wait_for_exit())
            .await
            .unwrap_or_else(|_| panic!("Established test session {peer} did not exit"));
    }
    drop(rib_tx);
    rib_task.await.unwrap();
}
// -----------------------------------------------------------------
// Recorded config history + rollback (Junos `rollback N`)
// -----------------------------------------------------------------

/// Red proof: removing the public snapshot barrier, sending the private
/// command first, cloning a replacement snapshot, or routing through the
/// public TOML planner breaks the ordering and pointer assertions below.
#[tokio::test]
async fn preloaded_plan_waits_for_public_barrier_and_carries_same_arc() {
    let config = Config::load_toml_with_diagnostics(&base_toml(""), "barrier test").unwrap();
    let snapshot = AcceptedConfigSnapshot::from_config_for_test(config);
    let (peer_tx, mut peer_rx) = mpsc::channel(2);
    let (internal_tx, mut internal_rx) = mpsc::channel(1);
    let controller = ConfigTransactionController::new(
        deps_value(None, peer_tx, None, Vec::new()),
        BgpMetrics::new(),
    )
    .with_preloaded_planner(internal_tx);
    let planned_snapshot = snapshot.clone();
    let task = tokio::spawn(async move {
        controller
            .plan_preloaded_snapshot(planned_snapshot, "expected-token".to_string())
            .await
    });

    let Some(PeerManagerCommand::RuntimeConfigSnapshot { reply }) = peer_rx.recv().await else {
        panic!("public runtime snapshot barrier must be first");
    };
    assert!(
        matches!(
            internal_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "private preloaded planning must wait for the public barrier reply"
    );
    reply
        .send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
            toml: snapshot.normalized_toml().to_string(),
            rpol_files: Vec::new(),
            rpol: snapshot.config_ref().policy.rpol.clone(),
        }))
        .unwrap();
    let command = internal_rx.recv().await.unwrap();
    let InternalCommand::PlanAcceptedTransactionConfig {
        snapshot: received,
        expected_runtime_snapshot_token,
        reply,
    } = command
    else {
        panic!("private lane must receive a preloaded plan command");
    };
    assert!(Arc::ptr_eq(&snapshot, &received));
    assert_eq!(
        expected_runtime_snapshot_token.as_deref(),
        Some("expected-token")
    );
    reply
        .send(Ok(PlannedTransactionConfig {
            plan: plan(RuntimeConfigTransactionStatus::Noop, Vec::new()),
            candidate: Box::new(received.config()),
        }))
        .unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().plan.status,
        RuntimeConfigTransactionStatus::Noop
    );
}

/// Controller wired with a real on-disk history dir and the dynamic
/// snapshot harness. Returns (controller, live runtime snapshot).
fn rollback_controller(
    history_dir: &std::path::Path,
    journal_path: Option<std::path::PathBuf>,
    current_toml: String,
) -> (
    ConfigTransactionController,
    Arc<Mutex<String>>,
    tokio::task::JoinHandle<()>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(history_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let snapshot_toml = Arc::new(Mutex::new(current_toml.clone()));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let (config_tx, config_rx) = mpsc::channel(8);
    let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
    let config_path = history_dir.join("runtime.toml");
    std::fs::write(&config_path, current_toml).unwrap();
    let launch = journal_path
        .as_ref()
        .map(|_| crate::confirm_journal::v3::LaunchIdentity::resolve(&config_path).unwrap());
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let (_accepted_tx, accepted_rx) = watch::channel(accepted);
    let internal_tx = spawn_typed_transaction_manager(
        snapshot_toml.clone(),
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
    );
    let controller = ConfigTransactionController::new_accepted(
        FibTableControlDeps {
            confirm_journal_path: journal_path,
            config_history_dir: Some(history_dir.to_path_buf()),
            ..deps_value(None, peer_tx, Some(config_tx), Vec::new())
        },
        BgpMetrics::new(),
        accepted_rx,
    )
    .with_preloaded_planner(internal_tx);
    let controller = launch.map_or(controller.clone(), |launch| {
        controller.with_confirm_v3_launch(launch)
    });
    (controller, snapshot_toml, ack_task)
}

fn record_v2_history(dir: &std::path::Path, toml: &str) -> Arc<AcceptedConfigSnapshot> {
    let snapshot = AcceptedConfigSnapshot::from_config_for_test(
        Config::load_toml_with_diagnostics(toml, "v2 history test").unwrap(),
    );
    crate::config_history::record_accepted(dir, &snapshot).unwrap();
    snapshot
}

/// Red proof: removing the v2 preloaded planning lane or changing index
/// ordering restores the wrong snapshot or bypasses the exact Arc path.
#[tokio::test]
async fn rollback_restores_the_previous_v2_config() {
    let dir = tempfile::tempdir().unwrap();
    let previous_toml = base_toml("");
    let current_toml = dynamic_candidate_toml();
    let previous = record_v2_history(dir.path(), &previous_toml);
    let current = record_v2_history(dir.path(), &current_toml);
    let (controller, runtime, ack_task) =
        rollback_controller(dir.path(), None, current_toml.clone());

    let listed = controller.history().unwrap();
    assert_eq!(listed.entries.len(), 2);
    assert!(listed.entries.iter().all(|entry| {
        entry.provenance_status == proto::ConfigHistoryProvenanceStatus::Recorded as i32
            && !entry.source_sha256.is_empty()
    }));
    assert_eq!(
        listed.entries[0].sha256,
        crate::config_history::v2::encode_hex(
            &crate::config_history::stored_manifest(&current).toml_sha256,
        )
    );
    assert_eq!(
        listed.entries[1].sha256,
        crate::config_history::v2::encode_hex(
            &crate::config_history::stored_manifest(&previous).toml_sha256,
        )
    );

    let response = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 1,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        })
        .await
        .expect("verified v2 rollback must use the preloaded plan lane");
    assert_eq!(
        response.status,
        proto::ConfigTransactionPlanStatus::Committable as i32
    );
    assert_snapshot_matches_config(&runtime.lock().await, &previous_toml);
    assert!(
        response
            .human_text
            .contains("Rolled back to applied config 1")
    );
    ack_task.abort();
}

#[tokio::test]
async fn rollback_beyond_history_errors_cleanly_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let current_toml = dynamic_candidate_toml();
    let _ = record_v2_history(dir.path(), &current_toml);
    let (controller, snapshot_toml, ack_task) =
        rollback_controller(dir.path(), None, current_toml.clone());

    let err = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 5,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        })
        .await
        .expect_err("out-of-range rollback must fail");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("index 5 is out of range") && message.contains("1 retained entry")),
        "{err:?}"
    );
    // MUTATION PROOF: nothing was applied.
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &current_toml);
    ack_task.abort();
}

#[tokio::test]
async fn rollback_rejects_index_zero_and_timeout_without_confirm_id() {
    let dir = tempfile::tempdir().unwrap();
    let current_toml = dynamic_candidate_toml();
    let _ = record_v2_history(dir.path(), &current_toml);
    let (controller, snapshot_toml, ack_task) =
        rollback_controller(dir.path(), None, current_toml.clone());

    let err = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 0,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        })
        .await
        .expect_err("rollback 0 must be rejected");
    assert!(
        matches!(err, ConfigTransactionApplyError::InvalidArgument(ref message)
            if message.contains("index must be >= 1")),
        "{err:?}"
    );

    let err = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 1,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 60,
        })
        .await
        .expect_err("timeout without confirm_id must be rejected");
    assert!(
        matches!(err, ConfigTransactionApplyError::InvalidArgument(ref message)
            if message.contains("confirm_id is required")),
        "{err:?}"
    );
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &current_toml);
    ack_task.abort();
}

#[tokio::test]
async fn history_and_rollback_fail_closed_without_history_dir() {
    let snapshot_toml = Arc::new(Mutex::new(base_toml("")));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let (peer_tx, peer_rx) = mpsc::channel(8);
    tokio::spawn(fake_snapshot_peer_manager(
        peer_rx,
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec!["[[dynamic_neighbors]]".to_string()],
        ),
        snapshot_toml.clone(),
        peers,
    ));
    let controller = ConfigTransactionController::new(
        deps_value(None, peer_tx, None, Vec::new()),
        BgpMetrics::new(),
    );

    let err = controller
        .history()
        .expect_err("history without a state dir must fail closed");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("config-history directory")),
        "{err:?}"
    );
    let err = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 1,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        })
        .await
        .expect_err("rollback without a state dir must fail closed");
    assert!(
        matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("config-history directory")),
        "{err:?}"
    );
}

#[tokio::test]
async fn history_lists_entries_newest_first_with_summaries() {
    // Red proof: omitting the v2 digest/status mapping or changing newest
    // ordering breaks the exact active-row assertions below.
    let dir = tempfile::tempdir().unwrap();
    let previous_toml = base_toml("");
    let current_toml = dynamic_candidate_toml();
    let previous = record_v2_history(dir.path(), &previous_toml);
    let current = record_v2_history(dir.path(), &current_toml);
    let (controller, _snapshot_toml, ack_task) =
        rollback_controller(dir.path(), None, current_toml.clone());

    let response = controller.history().expect("history must succeed");

    assert_eq!(response.entries.len(), 2);
    assert_eq!(response.entries[0].index, 0);
    assert_eq!(
        response.entries[0].sha256,
        crate::config_history::v2::encode_hex(
            &crate::config_history::stored_manifest(&current).toml_sha256
        )
    );
    assert_eq!(
        response.entries[1].sha256,
        crate::config_history::v2::encode_hex(
            &crate::config_history::stored_manifest(&previous).toml_sha256
        )
    );
    assert!(response.entries.iter().all(|entry| {
        !entry.source_sha256.is_empty()
            && entry.provenance_status == proto::ConfigHistoryProvenanceStatus::Recorded as i32
    }));
    // Summaries carry identity + counts, never document contents.
    assert!(
        response.entries[0].summary.contains("asn 65001"),
        "{}",
        response.entries[0].summary
    );
    assert!(
        response.entries[0].summary.contains("1 dynamic range(s)"),
        "{}",
        response.entries[0].summary
    );
    assert!(response.human_text.contains("2 v2 config history row(s)"));
    assert!(
        response.human_text.contains("index 0 is newest"),
        "{}",
        response.human_text
    );
    assert!(
        response
            .human_text
            .contains("Provenance-verified rows can be restored"),
        "{}",
        response.human_text
    );
    ack_task.abort();
}

#[tokio::test]
async fn history_redacts_unreadable_entry_metadata() {
    // Red proof: retaining either unverified digest or interpolating the
    // raw read error/path changes the exact redacted row assertions;
    // removing the controller's unreadable arm changes the exact refusal
    // to the storage-boundary fallback.
    let dir = tempfile::tempdir().unwrap();
    let previous_toml = base_toml("");
    let current_toml = dynamic_candidate_toml();
    let _ = record_v2_history(dir.path(), &previous_toml);
    let _ = record_v2_history(dir.path(), &current_toml);
    let entry_path = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("v2-00000000000000000001-")
        })
        .unwrap();
    std::fs::write(&entry_path, "corrupt secret material").unwrap();
    let (controller, snapshot_toml, ack_task) =
        rollback_controller(dir.path(), None, current_toml.clone());

    let response = controller
        .history()
        .expect("listing must degrade per entry");
    assert_eq!(response.entries.len(), 2);
    let row = &response.entries[1];
    assert!(row.sha256.is_empty());
    assert!(row.source_sha256.is_empty());
    assert_eq!(
        row.provenance_status,
        proto::ConfigHistoryProvenanceStatus::Unreadable as i32
    );
    assert_eq!(row.summary, "(unreadable config history entry)");
    assert!(!row.summary.contains(entry_path.to_string_lossy().as_ref()));
    assert!(!row.summary.contains("corrupt secret material"));

    let error = controller
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 1,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        })
        .await
        .expect_err("unreadable rollback must stop before the apply path");
    assert!(matches!(
        error,
        ConfigTransactionApplyError::FailedPrecondition(ref message)
            if message.contains("unreadable config history entry")
    ));
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &current_toml);

    ack_task.abort();
}

#[cfg(unix)]
/// Red proof: interpolating the scanner error, directory, or filename into
/// the public history error exposes the sensitive fixture strings below.
#[tokio::test]
async fn history_storage_errors_redact_paths() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::Builder::new()
        .prefix("sensitive-history-path-")
        .tempdir()
        .unwrap();
    let history = root.path().join("private-filename");
    std::fs::create_dir(&history).unwrap();
    std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o755)).unwrap();
    let current = dynamic_candidate_toml();
    let (controller, _snapshot, ack_task) = rollback_controller(&history, None, current);
    std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o755)).unwrap();

    let error = controller.history().unwrap_err();
    let rendered = format!("{error:?}");
    assert!(rendered.contains("storage is unavailable or unsafe"));
    assert!(!rendered.contains(root.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains("private-filename"));
    ack_task.abort();
}

#[tokio::test(start_paused = true)]
async fn confirmed_rollback_times_out_and_auto_reverts_the_rollback() {
    // rollback N + confirm-id + timeout: the rollback commits, opens a
    // confirm window (journal included), and when never confirmed the
    // timeout auto-revert restores the pre-rollback config — the whole
    // confirmed-commit lifecycle applies to rollback because rollback IS
    // an apply.
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal_path = dir.path().join("commit-confirm-journal.json");
    let history_dir = dir.path().join("config-history");
    let previous_toml = base_toml("");
    let current_toml = dynamic_candidate_toml();
    let _ = record_v2_history(&history_dir, &previous_toml);
    let _ = record_v2_history(&history_dir, &current_toml);
    let (controller, snapshot_toml, ack_task) = rollback_controller(
        &history_dir,
        Some(journal_path.clone()),
        current_toml.clone(),
    );
    let locator =
        crate::confirm_journal::v3::LaunchIdentity::resolve(&history_dir.join("runtime.toml"))
            .unwrap()
            .locator_path();

    let response = controller
        .clone()
        .rollback(proto::RollbackConfigTransactionRequest {
            index: 1,
            expected_runtime_snapshot_token: String::new(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: "rollback-1".to_string(),
            confirm_timeout_seconds: 1,
        })
        .await
        .expect("confirmed rollback must succeed");
    let confirmation = response
        .confirmation
        .expect("confirmed rollback must open a confirm window");
    assert_eq!(
        confirmation.status,
        proto::ConfigTransactionConfirmationStatus::Pending as i32
    );
    assert_eq!(confirmation.confirm_id, "rollback-1");
    // The rollback is live (runtime = previous config) and journaled.
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
    assert!(
        locator.exists(),
        "confirmed rollback must publish v3 authority"
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // MUTATION PROOF: the unconfirmed rollback auto-reverted — the
    // runtime is back on the pre-rollback config. (The auto-revert
    // re-applies the captured snapshot, which serializes normalized, so
    // compare as parsed configs, not raw bytes.)
    assert_snapshot_matches_config(&snapshot_toml.lock().await, &current_toml);
    let status = controller.status().await.expect("status must succeed");
    assert_eq!(
        status.confirmation.unwrap().status,
        proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
    );
    assert!(!locator.exists(), "auto-revert must consume v3 authority");
    ack_task.abort();
}
