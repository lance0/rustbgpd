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
    assert_eq!(manager.peer_export_policies[&peer()], Some(old.clone()));
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
    assert_eq!(manager.peer_export_policies[&peer()], Some(old.clone()));
    record(&mut manager, 7, None);
    register(&mut manager, 9);
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer(),
        session_id: 9,
    });
    assert_eq!(manager.peer_export_policies[&peer()], None);
    // A fresh embedding PeerUp still inherits the configured fallback.
    register(&mut manager, 10);
    assert_eq!(manager.peer_export_policies[&peer()], Some(old));
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
