use super::*;

use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, Safi};
use tokio::sync::oneshot;

use crate::dampening::DampeningInspection;
use crate::test_support::make_route;
use crate::update::{OutboundRouteUpdate, PeerSourceContext, RibUpdate};

fn manager(
    limits: DampeningHistoryLimits,
) -> (RibManager, mpsc::UnboundedReceiver<DampeningCapacityNotice>) {
    let (_, rx) = mpsc::channel(4);
    let (_, query_rx) = mpsc::channel(4);
    let (notices, notice_rx) = mpsc::unbounded_channel();
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    manager
        .install_dampening_history_for_test(DampeningParameters::default(), limits, notices)
        .unwrap();
    (manager, notice_rx)
}

fn limits(sources: usize, keys: usize) -> DampeningHistoryLimits {
    DampeningHistoryLimits {
        owners: 4,
        sources,
        history_keys: keys,
        source_history_keys: keys,
    }
}

fn owner(id: u64) -> Arc<DampeningOwner> {
    Arc::new(DampeningOwner::new(NonZeroU64::new(id).unwrap()))
}

fn source(peer: u8, session_id: u64, asn: u32, owner: &Arc<DampeningOwner>) -> ReceivedRouteSource {
    ReceivedRouteSource {
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, peer)),
        session_id,
        peer_asn: Some(asn),
        context: Some(Arc::new(PeerSourceContext {
            peer_interface: None,
            accepted_dynamic_range: None,
            route_server_client: false,
            dampening_admission: Some(DampeningAdmission::new(Arc::clone(owner))),
        })),
    }
}

fn admission(source: &ReceivedRouteSource) -> &DampeningAdmission {
    source
        .context
        .as_ref()
        .unwrap()
        .dampening_admission
        .as_ref()
        .unwrap()
}

fn register(
    manager: &mut RibManager,
    source: &ReceivedRouteSource,
    is_ebgp: bool,
    route_reflector_client: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(32);
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer: source.peer,
        session_id: source.session_id,
        context: source.context.clone().unwrap(),
    });
    manager.handle_update(RibUpdate::PeerUp {
        peer: source.peer,
        session_id: source.session_id,
        peer_asn: source.peer_asn.unwrap(),
        peer_router_id: crate::test_support::session_router_id(source.peer),
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp,
        route_reflector_client,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn publish(
    manager: &mut RibManager,
    publication: u64,
    owners: Vec<Arc<DampeningOwner>>,
) -> Result<(), DampeningControlError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PublishDampeningOwners {
        publication,
        owners,
        reply,
    });
    response.try_recv().unwrap()
}

fn prefix(id: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, id, 0), 24))
}

fn batch(
    source: &ReceivedRouteSource,
    announced: &[u8],
    withdrawn: &[u8],
    wire: bool,
) -> RibUpdate {
    let IpAddr::V4(peer) = source.peer else {
        panic!("IPv4 fixture")
    };
    let batch = RibUpdate::RoutesReceived {
        peer: source.peer,
        session_id: source.session_id,
        announced: announced
            .iter()
            .map(|&id| {
                let Prefix::V4(prefix) = prefix(id) else {
                    unreachable!()
                };
                make_route(prefix, peer)
            })
            .collect(),
        withdrawn: withdrawn.iter().map(|&id| (prefix(id), 0)).collect(),
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    if wire {
        RibUpdate::WireRoutesReceived(WireRoutesReceived::new(batch, withdrawn.len()))
    } else {
        batch
    }
}

fn deliver(manager: &mut RibManager, update: RibUpdate) {
    manager.handle_update(update);
    while manager.process_next_route_chunk() {}
}

fn retained<'a>(manager: &'a RibManager, source: &ReceivedRouteSource) -> &'a SourceHistory {
    let (identity, _) = DampeningHistoryState::identity(source).unwrap();
    &manager.dampening_history.history.as_ref().unwrap().sources[&identity]
}

fn inspection(
    manager: &RibManager,
    source: &ReceivedRouteSource,
    id: u8,
) -> Option<DampeningInspection> {
    retained(manager, source).engine.inspect(
        DampeningKey {
            prefix: prefix(id),
            path_id: 0,
        },
        manager
            .dampening_history
            .history
            .as_ref()
            .unwrap()
            .started
            .elapsed(),
    )
}

#[tokio::test(start_paused = true)]
async fn only_present_original_withdrawals_charge_and_replay_does_not() {
    let (mut manager, mut notices) = manager(limits(2, 4));
    let owner = owner(1);
    let source = source(1, 1, 65001, &owner);
    publish(&mut manager, 1, vec![owner]).unwrap();
    let _out = register(&mut manager, &source, true, false);

    deliver(&mut manager, batch(&source, &[1], &[], true));
    deliver(&mut manager, batch(&source, &[1], &[], true));
    assert!(retained(&manager, &source).engine.is_empty());
    deliver(&mut manager, batch(&source, &[], &[1, 1, 99], true));
    let charged = inspection(&manager, &source, 1).unwrap();
    assert!((charged.state.penalty - 1000.0).abs() < f64::EPSILON);
    assert_eq!(charged.state.flap_count, 1);
    let revision = retained(&manager, &source).engine.revision();
    deliver(&mut manager, batch(&source, &[], &[1, 99], true));
    assert_eq!(inspection(&manager, &source, 1), Some(charged));
    assert_eq!(retained(&manager, &source).engine.revision(), revision);

    deliver(&mut manager, batch(&source, &[1, 2], &[], false));
    deliver(&mut manager, batch(&source, &[], &[1, 2], false));
    assert_eq!(inspection(&manager, &source, 1), Some(charged));
    assert!(inspection(&manager, &source, 2).is_none());
    assert!(notices.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn history_qualifies_only_external_non_server_non_reflector_sources() {
    for (ebgp, rr, rs, qualified) in [
        (true, false, false, true),
        (false, false, false, false),
        (true, true, false, false),
        (true, false, true, false),
    ] {
        let (mut manager, _notices) = manager(limits(2, 4));
        let owner = owner(1);
        let mut source = source(1, 1, 65001, &owner);
        Arc::make_mut(source.context.as_mut().unwrap()).route_server_client = rs;
        publish(&mut manager, 1, vec![owner]).unwrap();
        let _out = register(&mut manager, &source, ebgp, rr);
        deliver(&mut manager, batch(&source, &[1], &[], true));
        deliver(&mut manager, batch(&source, &[], &[1], true));
        assert_eq!(
            manager.dampening_history.history.as_ref().unwrap().keys,
            usize::from(qualified)
        );
        assert_eq!(
            manager
                .dampening_history
                .history
                .as_ref()
                .unwrap()
                .sources
                .len(),
            usize::from(qualified)
        );
        assert!(manager.ribs[&source.peer].get(&prefix(1), 0).is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn queued_tentative_batch_keeps_its_admission_after_owner_publication() {
    let (mut manager, _notices) = manager(limits(2, 4));
    let owner = owner(1);
    let source = source(1, 1, 65001, &owner);
    let _out = register(&mut manager, &source, true, false);
    deliver(&mut manager, batch(&source, &[1], &[], false));
    manager.handle_update(batch(&source, &[], &[1], true));
    assert!(
        manager
            .pending_route_batches
            .front()
            .unwrap()
            .dampening_source
            .is_none()
    );
    publish(&mut manager, 1, vec![owner]).unwrap();
    assert!(
        manager
            .pending_route_batches
            .front()
            .unwrap()
            .dampening_source
            .is_none()
    );
    while manager.process_next_route_chunk() {}
    assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 0);
    assert!(manager.ribs[&source.peer].get(&prefix(1), 0).is_none());
    deliver(&mut manager, batch(&source, &[1], &[], true));
    deliver(&mut manager, batch(&source, &[], &[1], true));
    assert_eq!(
        inspection(&manager, &source, 1).unwrap().state.flap_count,
        1
    );
}

#[tokio::test(start_paused = true)]
async fn same_owner_role_replacement_pins_tentative_history_admission() {
    let (mut manager, _notices) = manager(limits(2, 4));
    let owner = owner(1);
    publish(&mut manager, 1, vec![Arc::clone(&owner)]).unwrap();
    let mut previous = source(1, 1, 65001, &owner);
    Arc::make_mut(previous.context.as_mut().unwrap()).route_server_client = true;
    let _previous_out = register(&mut manager, &previous, true, false);
    deliver(&mut manager, batch(&previous, &[1], &[], true));
    deliver(&mut manager, batch(&previous, &[], &[1], true));
    assert!(
        manager
            .dampening_history
            .history
            .as_ref()
            .unwrap()
            .sources
            .is_empty()
    );

    let mut candidate = source(1, 2, 65001, &owner);
    let tentative = admission(&previous).tentative_publication();
    Arc::make_mut(candidate.context.as_mut().unwrap()).dampening_admission =
        Some(tentative.clone());
    let _candidate_out = register(&mut manager, &candidate, true, false);
    deliver(&mut manager, batch(&candidate, &[1], &[], false));
    manager.handle_update(batch(&candidate, &[], &[1], true));
    assert!(
        manager
            .pending_route_batches
            .front()
            .unwrap()
            .dampening_source
            .is_none()
    );
    publish(&mut manager, 2, vec![Arc::clone(&owner)]).unwrap();
    tentative.acknowledge_publication();
    while manager.process_next_route_chunk() {}
    assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 0);
    assert!(manager.ribs[&candidate.peer].get(&prefix(1), 0).is_none());
    deliver(&mut manager, batch(&candidate, &[1], &[], true));
    deliver(&mut manager, batch(&candidate, &[], &[1], true));
    assert_eq!(
        inspection(&manager, &candidate, 1)
            .unwrap()
            .state
            .flap_count,
        1
    );
    assert_eq!(
        admission(&previous).owner.id(),
        admission(&candidate).owner.id()
    );
}

#[tokio::test(start_paused = true)]
async fn reconnect_keeps_history_but_negotiated_asn_changes_source_identity() {
    let (mut manager, _notices) = manager(limits(3, 4));
    let owner = owner(1);
    let mut source = source(1, 1, 65001, &owner);
    publish(&mut manager, 1, vec![owner]).unwrap();
    let _first_out = register(&mut manager, &source, true, false);
    deliver(&mut manager, batch(&source, &[1], &[], true));
    deliver(&mut manager, batch(&source, &[], &[1], true));
    manager.handle_update(RibUpdate::PeerDown {
        peer: source.peer,
        session_id: source.session_id,
    });
    source.session_id = 2;
    let _second_out = register(&mut manager, &source, true, false);
    deliver(&mut manager, batch(&source, &[1], &[], true));
    assert_eq!(
        inspection(&manager, &source, 1).unwrap().state.flap_count,
        1
    );
    deliver(&mut manager, batch(&source, &[], &[1], true));
    assert_eq!(
        inspection(&manager, &source, 1).unwrap().state.flap_count,
        2
    );
    let old = source.clone();
    manager.handle_update(RibUpdate::PeerDown {
        peer: source.peer,
        session_id: source.session_id,
    });
    source.session_id = 3;
    source.peer_asn = Some(65002);
    let _third_out = register(&mut manager, &source, true, false);
    deliver(&mut manager, batch(&source, &[1], &[], true));
    deliver(&mut manager, batch(&source, &[], &[1], true));
    assert_eq!(
        inspection(&manager, &source, 1).unwrap().state.flap_count,
        1
    );
    assert_eq!(inspection(&manager, &old, 1).unwrap().state.flap_count, 2);
    assert_eq!(
        manager
            .dampening_history
            .history
            .as_ref()
            .unwrap()
            .sources
            .len(),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn full_source_budget_preserves_withdrawals_and_blocks_reachable_input_once() {
    let (mut manager, mut notices) = manager(limits(1, 2));
    let owner = owner(1);
    let first = source(1, 1, 65001, &owner);
    let refused = source(2, 2, 65002, &owner);
    let observer = source(3, 3, 65003, &owner);
    publish(&mut manager, 1, vec![owner]).unwrap();
    let _first_out = register(&mut manager, &first, true, false);
    let _refused_out = register(&mut manager, &refused, true, false);
    let mut downstream = register(&mut manager, &observer, true, false);
    deliver(&mut manager, batch(&first, &[1], &[], true));
    deliver(&mut manager, batch(&refused, &[2], &[], false));
    assert!(manager.ribs[&refused.peer].get(&prefix(2), 0).is_some());
    while downstream.try_recv().is_ok() {}

    deliver(&mut manager, batch(&refused, &[3], &[2], true));
    assert!(admission(&refused).is_blocked());
    assert!(manager.ribs[&refused.peer].get(&prefix(2), 0).is_none());
    assert!(manager.ribs[&refused.peer].get(&prefix(3), 0).is_none());
    assert!(manager.loc_rib.get(&prefix(2)).is_none());
    let mut withdrawal_seen = false;
    while let Ok(update) = downstream.try_recv() {
        withdrawal_seen |= update.withdraw.contains(&(prefix(2), 0));
        assert!(
            !update
                .announce
                .iter()
                .any(|route| route.prefix == prefix(3))
        );
    }
    assert!(
        withdrawal_seen,
        "capacity refusal must still withdraw downstream"
    );
    assert_eq!(
        notices.try_recv().unwrap().reason,
        DampeningCapacityReason::Sources
    );
    deliver(&mut manager, batch(&refused, &[4], &[2], true));
    assert!(notices.try_recv().is_err());
    assert_eq!(
        manager
            .dampening_history
            .history
            .as_ref()
            .unwrap()
            .sources
            .len(),
        1
    );
    assert!(manager.ribs[&refused.peer].get(&prefix(4), 0).is_none());
}

#[tokio::test(start_paused = true)]
async fn key_exhaustion_does_not_mutate_retained_penalty_revision_or_deadline() {
    for per_source in [false, true] {
        let mut credits = limits(2, 1);
        if per_source {
            credits.history_keys = 2;
        } else {
            credits.source_history_keys = 2;
        }
        let (mut manager, mut notices) = manager(credits);
        let owner = owner(1);
        let source = source(1, 1, 65001, &owner);
        publish(&mut manager, 1, vec![owner]).unwrap();
        let _out = register(&mut manager, &source, true, false);
        deliver(&mut manager, batch(&source, &[1, 2], &[], true));
        deliver(&mut manager, batch(&source, &[], &[1], true));
        let before = inspection(&manager, &source, 1).unwrap();
        let revision = retained(&manager, &source).engine.revision();
        let deadline = retained(&manager, &source).engine.next_due();
        deliver(&mut manager, batch(&source, &[3], &[2], true));
        assert_eq!(inspection(&manager, &source, 1), Some(before));
        assert_eq!(retained(&manager, &source).engine.revision(), revision);
        assert_eq!(retained(&manager, &source).engine.next_due(), deadline);
        assert!(inspection(&manager, &source, 2).is_none());
        assert!(manager.ribs[&source.peer].get(&prefix(2), 0).is_none());
        assert!(manager.ribs[&source.peer].get(&prefix(3), 0).is_none());
        assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
        let expected = if per_source {
            DampeningCapacityReason::SourceHistoryKeys
        } else {
            DampeningCapacityReason::HistoryKeys
        };
        assert_eq!(notices.try_recv().unwrap().reason, expected);
    }
}

#[tokio::test(start_paused = true)]
async fn retirement_keeps_credits_until_nodes_and_pending_notice_owner_are_gone() {
    let mut credits = limits(1, 1);
    credits.owners = 1;
    credits.source_history_keys = 2;
    let (mut manager, mut notices) = manager(credits);
    let old_owner = owner(1);
    let source = source(1, 1, 65001, &old_owner);
    publish(&mut manager, 1, vec![Arc::clone(&old_owner)]).unwrap();
    let _out = register(&mut manager, &source, true, false);
    deliver(&mut manager, batch(&source, &[1, 2], &[], true));
    deliver(&mut manager, batch(&source, &[], &[1, 2], true));
    let notice = notices.try_recv().unwrap();
    manager.handle_update(RibUpdate::PeerDown {
        peer: source.peer,
        session_id: source.session_id,
    });
    publish(&mut manager, 2, vec![]).unwrap();
    drop(source);
    drop(old_owner);
    assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
    assert_eq!(manager.dampening_history.retire(0), 0);
    assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
    assert_eq!(manager.dampening_history.retire(1), 1);
    assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 0);
    assert!(
        manager
            .dampening_history
            .history
            .as_ref()
            .unwrap()
            .sources
            .is_empty()
    );
    assert_eq!(manager.dampening_history.retired_owners.len(), 1);
    assert_eq!(
        publish(&mut manager, 3, vec![owner(2)]),
        Err(DampeningControlError::OwnerCapacity)
    );
    assert!(manager.dampening_history.retire(1) <= 1);
    assert_eq!(manager.dampening_history.retired_owners.len(), 1);
    assert_eq!(manager.dampening_history.retire(1), 0);
    drop(notice);
    manager.dampening_history.arm_owner_retirement();
    assert!(manager.dampening_history.retire(1) <= 1);
    assert!(manager.dampening_history.retired_owners.is_empty());
    publish(&mut manager, 3, vec![owner(2)]).unwrap();
}

fn prepare(
    manager: &mut RibManager,
    source: &ReceivedRouteSource,
) -> Result<DampeningEnableReceipt, DampeningControlError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareDampeningEnable {
        source: source.clone(),
        reason: DampeningCapacityReason::Sources,
        reply,
    });
    response.try_recv().unwrap()
}

fn complete(
    manager: &mut RibManager,
    receipt: DampeningEnableReceipt,
    enabled: bool,
) -> Result<(), DampeningControlError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::CompleteDampeningEnable {
        receipt,
        enabled,
        reply,
    });
    response.try_recv().unwrap()
}

#[tokio::test(start_paused = true)]
async fn recovery_reserves_one_key_and_preserves_new_history_and_new_blocks() {
    for enabled in [true, false] {
        let mut credits = limits(1, 1);
        credits.source_history_keys = 2;
        let (mut manager, mut notices) = manager(credits);
        let old_owner = owner(1);
        let new_owner = owner(2);
        let old = source(1, 1, 65001, &old_owner);
        let mut recovering = source(2, 2, 65002, &new_owner);
        publish(&mut manager, 1, vec![old_owner, Arc::clone(&new_owner)]).unwrap();
        let _old_out = register(&mut manager, &old, true, false);
        let _refused_out = register(&mut manager, &recovering, true, false);
        deliver(&mut manager, batch(&old, &[1], &[], true));
        deliver(&mut manager, batch(&recovering, &[2], &[], true));
        assert_eq!(
            notices.try_recv().unwrap().reason,
            DampeningCapacityReason::Sources
        );
        assert_eq!(
            prepare(&mut manager, &recovering),
            Err(DampeningControlError::StaleAuthority)
        );
        manager.handle_update(RibUpdate::PeerDown {
            peer: recovering.peer,
            session_id: recovering.session_id,
        });
        admission(&recovering).acknowledge_capacity_disable();
        assert_eq!(
            prepare(&mut manager, &recovering),
            Err(DampeningControlError::Capacity(
                DampeningCapacityReason::Sources
            ))
        );
        publish(&mut manager, 2, vec![new_owner]).unwrap();
        assert_eq!(manager.dampening_history.retire(1), 1);
        let receipt = prepare(&mut manager, &recovering).unwrap();
        assert!(!admission(&recovering).is_blocked());
        assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
        assert!(
            manager
                .dampening_history
                .history
                .as_ref()
                .unwrap()
                .recovery_reserved_key
        );
        recovering.session_id = 3;
        let _fresh_out = register(&mut manager, &recovering, true, false);
        deliver(&mut manager, batch(&recovering, &[2], &[], true));
        deliver(&mut manager, batch(&recovering, &[], &[2], true));
        assert_eq!(
            inspection(&manager, &recovering, 2)
                .unwrap()
                .state
                .flap_count,
            1
        );
        assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
        assert!(
            !manager
                .dampening_history
                .history
                .as_ref()
                .unwrap()
                .recovery_reserved_key
        );
        if enabled {
            deliver(&mut manager, batch(&recovering, &[3], &[], true));
            deliver(&mut manager, batch(&recovering, &[], &[3], true));
            assert!(admission(&recovering).is_blocked());
            assert_eq!(
                notices.try_recv().unwrap().reason,
                DampeningCapacityReason::HistoryKeys
            );
        }
        complete(&mut manager, receipt, enabled).unwrap();
        assert!(admission(&recovering).is_blocked());
        assert_eq!(
            inspection(&manager, &recovering, 2)
                .unwrap()
                .state
                .flap_count,
            1
        );
        assert_eq!(manager.dampening_history.history.as_ref().unwrap().keys, 1);
        assert!(
            manager
                .dampening_history
                .history
                .as_ref()
                .unwrap()
                .recovery
                .is_none()
        );
        assert_eq!(
            complete(&mut manager, receipt, enabled),
            Err(DampeningControlError::StaleAuthority)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn disabled_history_publication_retains_no_retirement_metadata() {
    let (_, rx) = mpsc::channel(4);
    let (_, query_rx) = mpsc::channel(4);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let first = owner(1);
    let second = owner(2);
    publish(&mut manager, 1, vec![Arc::clone(&first)]).unwrap();
    publish(&mut manager, 2, vec![Arc::clone(&second)]).unwrap();
    publish(&mut manager, 3, vec![]).unwrap();
    assert!(manager.dampening_history.history.is_none());
    assert!(manager.dampening_history.owners.is_empty());
    assert!(manager.dampening_history.retired_owners.is_empty());
    assert!(!manager.dampening_history.owner_retirement_pending);
    assert!(manager.dampening_history.owner_retirement_cursor.is_none());
    assert!(!first.records_wire_history());
    assert!(!second.records_wire_history());
    assert_eq!(manager.dampening_history.retire(1), 0);
}

#[tokio::test(start_paused = true)]
async fn blocked_source_still_withdraws_rtc_while_rejecting_rtc_announcements() {
    let (mut manager, mut notices) = manager(limits(1, 2));
    let owner = owner(1);
    let first = source(1, 1, 65001, &owner);
    let refused = source(2, 2, 65002, &owner);
    publish(&mut manager, 1, vec![owner]).unwrap();
    let _first_out = register(&mut manager, &first, true, false);
    let _refused_out = register(&mut manager, &refused, true, false);
    let old = crate::route::RtcRibRoute {
        nlri: rustbgpd_wire::RtcNlri::DEFAULT,
        next_hop: refused.peer,
        peer: refused.peer,
        attributes: crate::AttrSet::new(vec![]),
        received_at: std::time::Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: crate::test_support::session_router_id(refused.peer),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    let mut new = old.clone();
    new.nlri = rustbgpd_wire::RtcNlri::new(65002, 0x0002_FDEA_0000_0064, 96).unwrap();
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer: refused.peer,
        session_id: refused.session_id,
        announced: vec![old.clone()],
        withdrawn: vec![],
    });
    assert!(manager.ribs[&refused.peer].get_rtc(&old.key()).is_some());
    deliver(&mut manager, batch(&first, &[1], &[], true));
    deliver(&mut manager, batch(&refused, &[2], &[], true));
    assert!(admission(&refused).is_blocked());
    assert_eq!(
        notices.try_recv().unwrap().reason,
        DampeningCapacityReason::Sources
    );
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer: refused.peer,
        session_id: refused.session_id,
        announced: vec![new.clone()],
        withdrawn: vec![old.key()],
    });
    assert!(manager.ribs[&refused.peer].get_rtc(&old.key()).is_none());
    assert!(manager.ribs[&refused.peer].get_rtc(&new.key()).is_none());
    assert!(notices.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn closed_capacity_notice_lane_terminates_rib_actor() {
    let (mut manager, notices) = manager(limits(1, 1));
    drop(notices);
    let owner = owner(1);
    let first = source(1, 1, 65001, &owner);
    let refused = source(2, 2, 65002, &owner);
    publish(&mut manager, 1, vec![owner]).unwrap();
    let _first_out = register(&mut manager, &first, true, false);
    let _refused_out = register(&mut manager, &refused, true, false);
    deliver(&mut manager, batch(&first, &[1], &[], true));
    deliver(&mut manager, batch(&refused, &[2], &[], true));
    assert!(admission(&refused).is_blocked());
    assert!(manager.dampening_history.notice_failed());
    assert!(manager.ribs[&refused.peer].get(&prefix(2), 0).is_none());
    // Keep the actor's primary lane open: completion must be the lost-control
    // fail-stop path, not an ordinary channel-close shutdown.
    let (_live_tx, live_rx) = mpsc::channel(4);
    manager.rx = live_rx;
    tokio::time::timeout(std::time::Duration::from_secs(1), Box::pin(manager.run()))
        .await
        .expect("RIB exits when capacity-disable ownership is unavailable");
}
