use super::*;

/// ADR-0112: a child accepted by an accept-any (`remote_asn = 0`) dynamic
/// range keeps its reserved deny when live chains are re-resolved — even in
/// the worst case, where OPEN replaced the sentinel with the local ASN.
///
/// `sync_rpol_policies` changes no policy content here, so the reserved deny
/// is the only chain that can arrive. Resolving this peer from
/// `managed.remote_asn` instead of its pinned classification reads it as iBGP,
/// leaves both directions permit-all, and makes this red.
#[tokio::test]
async fn rfc8212_pinned_dynamic_child_keeps_deny_across_chain_reresolution() {
    use rustbgpd_policy::rpol::RpolPolicySet;

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut config = make_dynamic_manager_config();
    config.global.ebgp_requires_policy = Some(true);
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());
    // What the accept path produced: `remote_asn = 0` classified external.
    managed.rfc8212_external = true;
    // What OPEN then did to `remote_asn` — worst case, the local ASN.
    managed.remote_asn = 65001;
    managed.import_policy = None;
    managed.export_policy = None;

    mgr.sync_rpol_policies(
        Vec::new(),
        RpolPolicySet::default(),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("registry sync succeeds");

    let managed = mgr.peers.get(&key(addr)).expect("peer still present");
    for (direction, chain) in [
        (
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
            managed.import_policy.as_ref(),
        ),
        (
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
            managed.export_policy.as_ref(),
        ),
    ] {
        let chain = chain.unwrap_or_else(|| panic!("{direction} must be installed"));
        assert_eq!(
            chain
                .policies
                .iter()
                .map(|member| member.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some(direction)]
        );
    }

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0112 step 5: the directional status is a read of the chain the peer has
/// **installed**, never a re-resolution of the running config.
///
/// The state under test is the one a failed or not-yet-applied live edit
/// leaves behind: `current_config` already names explicit operator chains in
/// both directions while the peer still runs the reserved deny on import. A
/// surface that answered from `Config` would report `present` over a live
/// deny — the one answer ADR-0112 must never produce. Deriving the verdict
/// from anything other than `ManagedPeer`'s installed chains makes the import
/// assertion red.
#[tokio::test]
async fn rfc8212_status_reads_the_installed_chain_not_the_running_config() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
        ));
        // An ordinary operator chain that happens to deny everything: the
        // export direction has deliberate policy, so it is PRESENT.
        managed.export_policy = Some(deny_policy_chain());
    }

    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Missing,
        "the reserved deny is installed on import; the running config's explicit \
         chain is not evidence about this peer"
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Present,
        "an operator deny-all is deliberate policy — RFC 8212 wants a decision, \
         not a particular filtering strategy"
    );

    // The gauges share the derivation, so they cannot disagree with the row.
    mgr.refresh_rfc8212_policy_metrics(&key(addr));
    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        1
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        0
    );
}

/// ADR-0112 step 5: enforcement off, or an internal session, reports
/// `NOT_REQUIRED` — never `PRESENT`, which would claim a requirement was met
/// that was never applied. Treating `enforced` as unconditionally true makes
/// both halves red.
#[tokio::test]
async fn rfc8212_status_is_not_required_when_disabled_or_internal() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let external = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let internal = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    for addr in [external, internal] {
        let counters = Arc::new(FakePeerCounters::default());
        let handle = acking_counted_policy_handle(addr, counters);
        insert_test_managed_peer(&mut mgr, addr, handle, false);
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.import_policy = None;
        managed.export_policy = None;
    }
    mgr.peers.get_mut(&key(external)).unwrap().rfc8212_external = true;
    mgr.peers.get_mut(&key(internal)).unwrap().rfc8212_external = false;

    // Enforcement disabled process-wide: the external peer is exempt too.
    let managed = mgr.peers.get(&key(external)).unwrap();
    let info = super::snapshot::build_peer_info(&key(external), managed, None, false);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );

    // Enforcement on, but the session is iBGP.
    let managed = mgr.peers.get(&key(internal)).unwrap();
    let info = super::snapshot::build_peer_info(&key(internal), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );

    mgr.refresh_rfc8212_policy_metrics(&key(external));
    mgr.refresh_rfc8212_policy_metrics(&key(internal));
    for addr in [external, internal] {
        assert_eq!(
            mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
            0
        );
        assert_eq!(
            mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
            0
        );
    }
}

/// ADR-0112 step 5: a live policy edit moves the gauges with the chains it
/// installs, one direction at a time. Refreshing only at peer creation, or
/// only on the direction the caller changed, leaves a latched gauge and makes
/// this red.
#[tokio::test]
async fn rfc8212_gauges_track_a_live_policy_edit_in_both_directions() {
    let (mut mgr, mut rib_rx) = rfc8212_status_manager();
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
        ));
        managed.export_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
        ));
    }
    mgr.refresh_rfc8212_policy_metrics(&key(addr));
    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        1
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        1
    );

    // Operator adds an explicit import policy; export keeps the reserved deny,
    // exactly as resolution would hand both chains to this call.
    mgr.update_runtime_policies(
        addr,
        Some(deny_policy_chain()),
        Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
        )),
    )
    .await
    .expect("live import edit applies");

    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        0,
        "the import gauge must follow the chain the session acknowledged"
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        1,
        "the untouched export direction stays denied"
    );
    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Present
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Missing
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0112 step 5: a governed direction with no chain at all is unreachable
/// through resolution, and must never be rounded up to PRESENT.
///
/// `evaluate_chain(None, ..)` is permit-all, so reporting "explicit policy
/// present" for an absent chain would state the requirement was met on the
/// one shape that lets every route through unfiltered. Answering PRESENT for
/// any enforced direction — rather than only for one that actually carries a
/// chain — makes this red.
#[tokio::test]
async fn rfc8212_status_never_calls_a_governed_absent_chain_present() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = None;
        managed.export_policy = None;
    }

    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Unknown
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Unknown
    );
}

// ---------------------------------------------------------------------------
// ADR-0112 step 4 — live policy-presence transitions
// ---------------------------------------------------------------------------

fn rfc8212_missing_import() -> PolicyChain {
    crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_IMPORT_POLICY)
}

fn rfc8212_missing_export() -> PolicyChain {
    crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_EXPORT_POLICY)
}

/// A stub session whose reported FSM state and Route Refresh capability are
/// scripted, and which refuses `SendRouteRefresh` exactly when it reports the
/// capability absent — the two answers a real session keeps consistent.
///
/// `established_for` bounds how many `QueryState` answers report Established
/// before the session starts reporting `Idle`, which is how a flap between the
/// snapshot preflight and the per-peer apply is reproduced deterministically.
fn scripted_policy_handle(
    peer_addr: IpAddr,
    route_refresh: bool,
    established_for: usize,
    refreshes: Arc<AtomicUsize>,
) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut queries = 0usize;
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    queries += 1;
                    let state = if queries <= established_for {
                        SessionState::Established
                    } else {
                        SessionState::Idle
                    };
                    let mut snapshot = policy_test_peer_state(peer_addr, state);
                    snapshot.negotiated_session = (state == SessionState::Established)
                        .then(|| test_negotiated_session(route_refresh));
                    let _ = reply.send(snapshot);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    if route_refresh {
                        refreshes.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
                    }
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

fn rfc8212_target(
    addr: IpAddr,
    import: Option<PolicyChain>,
) -> rustbgpd_api::peer_types::ResolvedPeerPolicy {
    rustbgpd_api::peer_types::ResolvedPeerPolicy {
        address: addr,
        interface: None,
        import_policy: import,
        export_policy: Some(rfc8212_missing_export()),
    }
}

fn install_rfc8212_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
    handle: PeerHandle,
    import: Option<PolicyChain>,
) {
    insert_test_managed_peer(mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.rfc8212_external = true;
    managed.import_policy = import;
    managed.export_policy = Some(rfc8212_missing_export());
}

/// ADR-0112 step 4: an Established peer that never negotiated Route Refresh
/// cannot converge an import policy-presence change, so the edit is rejected
/// with clear/reconnect guidance and its chains stay exactly where they were.
///
/// Load-bearing: dropping the capability check in
/// `qualify_rfc8212_import_transition` lets the apply proceed and the assertion
/// on the retained prior chain fails — the peer would be left running the new
/// import chain over an `AdjRibIn` still full of routes the old verdict
/// accepted.
#[tokio::test]
async fn rfc8212_import_presence_edit_rejects_a_peer_without_route_refresh() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let handle = scripted_policy_handle(addr, false, usize::MAX, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect_err("a peer without Route Refresh must not take a presence transition");
    assert!(
        error.contains("did not negotiate Route Refresh"),
        "the error must name the missing capability: {error}"
    );
    assert!(
        error.contains("clear the session"),
        "the error must be actionable: {error}"
    );
    assert!(
        error.contains("no peer was modified"),
        "the rejection must state that nothing was mutated: {error}"
    );

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(rfc8212_missing_import()),
        "the prior reserved deny must remain authoritative"
    );
    assert!(
        !managed.pending_refresh && !managed.pending_export_apply,
        "a rejection before mutation must not arm retry intent"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        0,
        "no Route Refresh may be attempted for a rejected transition"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: one incapable peer rejects the whole multi-peer edit before
/// any peer is mutated.
///
/// Load-bearing: moving the preflight from `apply_resolved_policy_snapshot`
/// into the per-peer apply lets the capable peer commit first, and the
/// assertion that its chains are untouched fails.
#[tokio::test]
async fn rfc8212_import_presence_preflight_rejects_the_whole_edit_before_mutation() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let capable = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let incapable = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    let capable_refreshes = Arc::new(AtomicUsize::new(0));
    install_rfc8212_peer(
        &mut mgr,
        capable,
        scripted_policy_handle(capable, true, usize::MAX, Arc::clone(&capable_refreshes)),
        Some(rfc8212_missing_import()),
    );
    install_rfc8212_peer(
        &mut mgr,
        incapable,
        scripted_policy_handle(incapable, false, usize::MAX, Arc::new(AtomicUsize::new(0))),
        Some(rfc8212_missing_import()),
    );

    let error = mgr
        .apply_resolved_policy_snapshot(vec![
            rfc8212_target(capable, Some(deny_policy_chain())),
            rfc8212_target(incapable, Some(deny_policy_chain())),
        ])
        .await
        .expect_err("one incapable peer rejects the edit");
    assert!(
        error.contains(&incapable.to_string()),
        "the rejection must name the incapable peer: {error}"
    );

    for addr in [capable, incapable] {
        let managed = mgr.peers.get(&key(addr)).unwrap();
        assert_eq!(
            managed.import_policy,
            Some(rfc8212_missing_import()),
            "{addr} must keep its prior chain when the edit is rejected whole"
        );
    }
    assert_eq!(
        capable_refreshes.load(Ordering::SeqCst),
        0,
        "the capable peer must not be refreshed for an edit that never committed"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: a capable Established peer converges the transition —
/// chains advance and every negotiated family is asked to re-advertise.
#[tokio::test]
async fn rfc8212_import_presence_edit_commits_and_refreshes_a_capable_peer() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let handle = scripted_policy_handle(addr, true, usize::MAX, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    mgr.apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect("a Route Refresh capable peer takes the transition");

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.import_policy, Some(deny_policy_chain()));
    assert!(
        refreshes.load(Ordering::SeqCst) >= 1,
        "the committed transition must have queued a Route Refresh"
    );
    assert!(
        !managed.pending_refresh,
        "a delivered refresh must not leave retry intent armed"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: a down peer whose routes GR or LLGR still retains defers
/// the transition, and takes it once nothing is retained.
///
/// Load-bearing: answering from session-local state instead of the RIB (or
/// skipping the query for a non-Established peer) makes the retained case
/// commit, and the first assertion fails.
#[tokio::test]
async fn rfc8212_import_presence_edit_defers_while_gr_llgr_state_is_retained() {
    for (retained, expect_commit) in [(3usize, false), (0usize, true)] {
        let (mut mgr, rib_rx) = rfc8212_status_manager();
        let rib = spawn_rfc8212_rib_stub(rib_rx, retained);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let handle = scripted_policy_handle(addr, true, 0, Arc::new(AtomicUsize::new(0)));
        install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

        let outcome = mgr
            .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
            .await;
        let managed = mgr.peers.get(&key(addr)).unwrap();
        if expect_commit {
            outcome.expect("a down peer with nothing retained may take the transition");
            assert_eq!(managed.import_policy, Some(deny_policy_chain()));
        } else {
            let error = outcome.expect_err("retained stale state must defer the transition");
            assert!(
                error.contains("stale route"),
                "the error must name the retained state: {error}"
            );
            assert_eq!(
                managed.import_policy,
                Some(rfc8212_missing_import()),
                "the prior verdict stays paired with the routes retained under it"
            );
        }

        drop(mgr);
        rib.await.unwrap();
    }
}

/// ADR-0112 step 4: a peer that qualifies at preflight and flaps before its
/// Route Refresh can be delivered fails the edit rather than committing the
/// desired verdict over an undelivered refresh.
///
/// Load-bearing: letting the non-Established branch arm `pending_refresh` and
/// return `Ok` for a presence transition makes the error assertion fail and
/// leaves the new chain installed with no convergence behind it.
#[tokio::test]
async fn rfc8212_import_presence_edit_fails_when_the_peer_flaps_after_preflight() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    // Established for the snapshot preflight and the per-peer requalification,
    // Idle by the time the apply queries state for the refresh decision.
    let handle = scripted_policy_handle(addr, true, 2, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect_err("a flap before the refresh must fail the edit");
    assert!(
        error.contains("Route Refresh"),
        "the error must name the undelivered refresh: {error}"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        0,
        "no refresh was delivered, so none may be reported"
    );
    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(rfc8212_missing_import()),
        "rollback must restore the prior chain"
    );
    // Retry intent for a fully unwound forward is the captured prior, not an
    // armed flag. This forward bailed *before* any Route Refresh was attempted
    // — the peer stopped reporting Established — so `AdjRibIn` provably never
    // left the prior policy and the rollback is exact. `pending_refresh` means
    // unfinished convergence debt, not a rejected desired change; arming it
    // here would make an unrelated later edit refresh the restored policy. The
    // operator's intent survives structurally because `current_config` never
    // advanced: the next reload re-derives the same delta and requalifies.
    //
    // Discriminator: `rollback_arms_retry_when_a_partially_delivered_refresh_cannot_be_undone`
    // asserts the opposite for a forward that failed *at* the refresh step,
    // where one family may already have converged. Neither assertion means
    // anything without the other.
    assert!(
        !managed.pending_refresh && !managed.pending_export_apply,
        "a fully restored peer must not carry a spurious retry"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: the batched export cohort defers its members' Route
/// Refresh past the RIB commit, so a member whose RFC 8212 import verdict moves
/// is never selected into it.
///
/// Load-bearing: removing the disqualification from
/// `local_export_only_policy_pair` selects both peers and the presence
/// transition's refresh — its entire convergence — rides the deferred path.
#[tokio::test]
async fn rfc8212_import_presence_transition_is_excluded_from_the_export_cohort() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let plain = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let transitioning = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    install_rfc8212_peer(
        &mut mgr,
        plain,
        scripted_policy_handle(plain, true, usize::MAX, Arc::new(AtomicUsize::new(0))),
        Some(deny_policy_chain()),
    );
    install_rfc8212_peer(
        &mut mgr,
        transitioning,
        scripted_policy_handle(
            transitioning,
            true,
            usize::MAX,
            Arc::new(AtomicUsize::new(0)),
        ),
        Some(rfc8212_missing_import()),
    );

    // Identical export moves, so cohort identity is satisfied for both and only
    // the import-presence rule can separate them.
    let targets = vec![
        rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: plain,
            interface: None,
            import_policy: Some(deny_policy_chain()),
            export_policy: Some(distinct_deny_policy_chain(3)),
        },
        rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: transitioning,
            interface: None,
            import_policy: Some(deny_policy_chain()),
            export_policy: Some(distinct_deny_policy_chain(3)),
        },
    ];
    let mask = mgr.export_only_policy_cohort_mask(&targets).await;
    assert_eq!(
        mask,
        vec![false, false],
        "a presence transition disqualifies its cohort, dropping the pair below two members"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4 scoping: an ordinary import edit between two explicit chains
/// is not a policy-presence transition, so it keeps the pre-existing path — the
/// new gate must not start rejecting every policy edit on a peer that happens
/// to lack Route Refresh.
#[tokio::test]
async fn rfc8212_gate_ignores_an_ordinary_import_edit() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let handle = scripted_policy_handle(addr, false, usize::MAX, Arc::new(AtomicUsize::new(0)));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(deny_policy_chain()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(
            addr,
            Some(distinct_deny_policy_chain(3)),
        )])
        .await
        .expect_err("the stub session still rejects the ordinary refresh it cannot send");
    assert!(
        !error.contains("policy-presence"),
        "the presence gate must not claim an ordinary chain edit: {error}"
    );

    drop(mgr);
    rib.await.unwrap();
}
