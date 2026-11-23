use super::*;

/// Fill `peer`'s writer, withdraw `missed` from the fixture source so the
/// member owes that withdrawal, then drain only the fillers.
fn owe_withdrawal(
    manager: &mut RibManager,
    peer: PeerId,
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    missed: Prefix,
) {
    let sender = manager.outbound_peers[&peer].clone();
    let mut fillers = 0;
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {
        fillers += 1;
    }
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 42)),
        announced: vec![],
        withdrawn: vec![(missed, 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
    assert!(
        manager.dirty_peers.contains(&peer),
        "{peer} missed the withdrawal"
    );
    for _ in 0..fillers {
        receiver.try_recv().expect("filler");
    }
    assert!(
        receiver.try_recv().is_err(),
        "the full writer took nothing else"
    );
}

/// The withdrawals and announcements (with communities) a receiver holds now.
fn drain_wire(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> (Vec<(Prefix, u32)>, Vec<(Prefix, Vec<u32>)>) {
    let (mut withdrawn, mut announced) = (Vec::new(), Vec::new());
    while let Ok(update) = receiver.try_recv().map(delivered) {
        withdrawn.extend(update.unicast_withdrawals().copied());
        announced.extend(
            update
                .announce
                .iter()
                .map(|route| (route.prefix, route.communities().to_vec())),
        );
    }
    (withdrawn, announced)
}

/// A clean cohort admits only clean members, so its commit can never meet a
/// dirty mover. A member that owes a withdrawal sends the cohort to the
/// authoritative path before anything is emitted. That path moves the member
/// with its shared cohort and retries it before replying, with no tick.
#[test]
fn a_dirty_member_reaches_the_authoritative_path_and_heals_before_reply() {
    let (mut manager, peers, mut receivers) = direct_clean_transition_manager(2, 2, None);
    let mover = peers[0];
    let missed = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 0, 0), 24));
    let kept = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 1, 0), 24));
    owe_withdrawal(&mut manager, mover, &mut receivers[0], missed);
    while receivers[1].try_recv().is_ok() {}

    let policy = community_chain(0xFDE8_2102);
    let _cohort = start_clean_transition(&mut manager, &peers, &policy);
    loop {
        let (_, outcome) = step_parked_transition(&mut manager);
        if outcome == "fallback" {
            break;
        }
        assert_eq!(
            outcome, "continue",
            "a dirty member must not reach the commit"
        );
    }
    assert!(manager.dirty_peers.contains(&mover));
    for receiver in &mut receivers {
        assert!(
            receiver.try_recv().is_err(),
            "nothing is emitted before the fallback"
        );
    }

    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: batch_replacements(&peers, &policy),
        reply,
    });
    assert_eq!(response.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    let receipt = manager.authoritative_transition_receipts.last().unwrap();
    assert_eq!(
        (receipt.shared_members, receipt.lagging_members),
        (2, 1),
        "the dirty member moved with its shared cohort"
    );
    assert!(
        !manager.dirty_peers.contains(&mover),
        "the authoritative batch must retry its dirty mover before replying"
    );
    let (withdrawn, announced) = drain_wire(&mut receivers[0]);
    assert_eq!(withdrawn, [(missed, 0)]);
    assert!(
        announced
            .iter()
            .any(|(prefix, communities)| *prefix == kept && communities.contains(&0xFDE8_2102)),
        "the mover holds the new policy's route: {announced:?}"
    );
}
