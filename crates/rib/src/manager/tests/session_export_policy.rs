use super::*;
use rustbgpd_policy::{NamedPolicy, Policy, PolicyAction};

fn chain(action: PolicyAction) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: action,
    }])
}

fn register(manager: &mut RibManager, id: u64) {
    let (outbound_tx, _rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer: peer(),
        session_id: id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
}

fn peer() -> IpAddr {
    Ipv4Addr::new(10, 0, 0, 2).into()
}

fn record(manager: &mut RibManager, id: u64, policy: Option<PolicyChain>) {
    manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
        peer: peer(),
        session_id: id,
        export_policy: policy,
    });
}

#[tokio::test]
async fn accepted_session_policy_targets_survivor_without_outbound_commit() {
    let (_tx, rx) = mpsc::channel(16);
    let old = chain(PolicyAction::Deny);
    let next = chain(PolicyAction::Permit);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(old.clone()),
        None,
        BgpMetrics::new(),
    );
    register(&mut manager, 7);
    register(&mut manager, 8);
    record(&mut manager, 7, Some(next.clone()));
    let sessions = &manager.live_sessions[&peer()];
    assert_eq!(sessions[0].export_policy, Some(next));
    assert_eq!(sessions[1].export_policy, Some(old.clone()));
    assert_eq!(manager.export_chains[&peer()], Some(old.clone()));
    // Unknown and retired sessions cannot overwrite either current record.
    record(&mut manager, 99, None);
    assert_eq!(manager.live_sessions[&peer()].len(), 2);
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer(),
        session_id: 7,
    });
    record(&mut manager, 7, None);
    assert_eq!(manager.live_sessions[&peer()][0].export_policy, Some(old));
}

#[tokio::test]
async fn accepted_session_policy_rollback_and_none_survive_promotion() {
    let (_tx, rx) = mpsc::channel(16);
    let old = chain(PolicyAction::Deny);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(old.clone()),
        None,
        BgpMetrics::new(),
    );
    register(&mut manager, 7);
    assert_eq!(
        manager.live_sessions[&peer()][0].export_policy,
        Some(old.clone())
    );
    record(&mut manager, 7, Some(chain(PolicyAction::Permit)));
    record(&mut manager, 7, Some(old.clone()));
    register(&mut manager, 8);
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer(),
        session_id: 8,
    });
    assert_eq!(manager.export_chains[&peer()], Some(old.clone()));
    record(&mut manager, 7, None);
    register(&mut manager, 9);
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer(),
        session_id: 9,
    });
    assert_eq!(manager.export_chains[&peer()], None);
    // A fresh embedding PeerUp still inherits the configured fallback.
    register(&mut manager, 10);
    assert_eq!(manager.export_chains[&peer()], Some(old));
}

#[tokio::test]
async fn replaced_session_policy_releases_compiled_body_after_last_owner() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    register(&mut manager, 7);
    register(&mut manager, 8);
    let compiled = Arc::new(chain(PolicyAction::Deny).compiled().clone());
    let weak = Arc::downgrade(&compiled);
    let policy = PolicyChain::from_named(vec![NamedPolicy::from_rpol("old".into(), compiled)]);
    record(&mut manager, 7, Some(policy.clone()));
    record(&mut manager, 8, Some(policy));
    record(&mut manager, 7, None);
    assert!(
        weak.upgrade().is_some(),
        "unupdated sibling still owns old body"
    );
    record(&mut manager, 8, None);
    assert!(
        weak.upgrade().is_none(),
        "last replay owner released old body"
    );
}

/// Register `peer` ungrouped: Add-Path send keeps the chain per peer, so the
/// RIB installs the session's own (uncounted) chain rather than a group handle.
fn register_ungrouped(manager: &mut RibManager, peer: IpAddr, export_policy: Option<PolicyChain>) {
    let (outbound_tx, _rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 1,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 3),
        outbound_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 2,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
}

fn installed_counter_id(manager: &RibManager, peer: IpAddr) -> Option<u64> {
    manager.export_chains[&peer]
        .as_ref()
        .expect("peer has an installed chain")
        .installed_hit_counters()
        .map(|counters| counters.id())
}

/// ADR-0136: every export install path creates the chain's counter instance
/// before any route is evaluated or any statistics read runs, and a read then
/// reports that instance without creating another.
/// Break-to-red: removing the creation at construction, single replacement
/// or the batch kernel leaves that step's instance absent.
#[tokio::test]
async fn export_counters_are_created_at_every_install_path() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(chain(PolicyAction::Permit)),
        None,
        BgpMetrics::new(),
    );
    assert!(
        manager
            .export_chains
            .global()
            .unwrap()
            .installed_hit_counters()
            .is_some(),
        "global fallback is counted from construction"
    );

    let target = peer();
    register_ungrouped(&mut manager, target, Some(chain(PolicyAction::Deny)));
    assert_eq!(manager.grouped_member_of(target), None);
    let registered = installed_counter_id(&manager, target).expect("registration creates counters");

    manager
        .replace_peer_export_policy_synchronously(target, Some(chain(PolicyAction::Permit)))
        .unwrap();
    let replaced = installed_counter_id(&manager, target).expect("replacement creates counters");
    assert!(replaced > registered);

    manager
        .apply_export_policy_replacements_synchronously(vec![
            crate::update::PeerExportPolicyReplacement {
                peer: target,
                export_policy: Some(chain(PolicyAction::Deny)),
            },
        ])
        .unwrap();
    let batched = installed_counter_id(&manager, target).expect("batch creates counters");
    assert!(batched > replaced);

    manager
        .restore_export_policy_replacements_synchronously(vec![
            crate::update::PeerExportPolicyReplacement {
                peer: target,
                export_policy: Some(chain(PolicyAction::Permit)),
            },
        ])
        .unwrap();
    let restored = installed_counter_id(&manager, target).expect("rollback creates counters");
    assert!(restored > batched);

    let rows = manager_export_rows(&mut manager, None).await;
    assert_eq!(rows.len(), 2, "per-peer row plus the global fallback");
    assert_eq!(rows[0].peer, Some(target));
    assert_eq!(rows[0].counter_instance, restored);
    assert_eq!(installed_counter_id(&manager, target), Some(restored));
}

/// ADR-0136: a published export roster entry holds its chain's counter
/// instance, so an installed chain without counters cannot reach a read.
/// A chain inserted past every install path gets its instance when the
/// roster that designates it is published, and a read reports that instance;
/// a disabled peer reports no row and an unaffected peer the global fallback.
#[tokio::test]
async fn export_roster_entries_always_hold_the_evaluated_instance() {
    let uncounted: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();
    let disabled: IpAddr = Ipv4Addr::new(10, 0, 0, 8).into();
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(chain(PolicyAction::Permit)),
        None,
        BgpMetrics::new(),
    );
    // Bypass every install path: the chain has no instance yet.
    manager
        .export_chains
        .insert(uncounted, Some(chain(PolicyAction::Deny)));
    manager.export_chains.insert(disabled, None);
    assert!(
        manager.export_chains[&uncounted]
            .as_ref()
            .unwrap()
            .installed_hit_counters()
            .is_none()
    );

    let rows = manager_export_rows(&mut manager, None).await;
    let installed = manager.export_chains[&uncounted]
        .as_ref()
        .unwrap()
        .installed_hit_counters()
        .expect("publication gives the installed chain its instance")
        .id();
    let global = manager
        .export_chains
        .global()
        .unwrap()
        .installed_hit_counters()
        .unwrap()
        .id();
    let shape: Vec<_> = rows
        .iter()
        .map(|row| (row.peer, row.counter_instance))
        .collect();
    assert_eq!(shape, [(Some(uncounted), installed), (None, global)]);

    assert!(
        manager_export_rows(&mut manager, Some(disabled))
            .await
            .is_empty(),
        "no export policy installed is an empty success"
    );
    let fallback = manager_export_rows(&mut manager, Some(peer())).await;
    assert_eq!(
        fallback
            .iter()
            .map(|row| (row.peer, row.counter_instance))
            .collect::<Vec<_>>(),
        [(Some(peer()), global)],
        "an unaffected peer reads the counted global fallback"
    );
}
