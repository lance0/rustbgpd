use super::*;

#[tokio::test]
async fn inbound_orf_emits_peer_orf_update_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!((update.afi, update.safi), (Afi::Ipv4, Safi::Unicast));
    assert_eq!(update.when, WhenToRefresh::Immediate);
    assert_eq!(update.groups[0].len(), 1);
}

#[tokio::test]
async fn inbound_orf_preserves_defer_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let rr = orf_rr_with_when(
        WhenToRefresh::Defer,
        OrfType::AddressPrefix,
        one_permit_entry(),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!(update.when, WhenToRefresh::Defer);
    assert_eq!(update.groups[0].len(), 1);
}

#[tokio::test]
async fn inbound_orf_ignored_when_family_not_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // negotiated_session() leaves negotiated_orf_recv empty.
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(!handled, "ORF for an un-negotiated family is ignored");
    assert!(
        rib_rx.try_recv().is_err(),
        "no PeerOrfUpdate should be emitted"
    );
}

#[tokio::test]
async fn inbound_orf_ignores_legacy_type_128() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    // Family negotiated, but the legacy type 128 is never negotiated by us.
    let rr = orf_rr(OrfType::AddressPrefixLegacy, one_permit_entry());
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(!handled, "legacy type 128 is not a negotiated type");
    assert!(rib_rx.try_recv().is_err());
}

#[tokio::test]
async fn inbound_orf_malformed_group_resets_via_remove_all() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    // A malformed Address-Prefix group → RFC 5291 §6 reset (REMOVE-ALL).
    let rr = orf_rr(
        OrfType::AddressPrefix,
        OrfEntries::Malformed(Bytes::from_static(&[0x40])),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled);
    assert_eq!(update.groups[0].len(), 1);
    assert_eq!(update.groups[0][0].action, OrfAction::RemoveAll);
}

#[tokio::test]
async fn inbound_orf_rejected_by_rib_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let (handled, update) = drive_inbound_orf_with_reply(
        &mut session,
        &mut rib_rx,
        &rr,
        Err("stale ORF update".to_string()),
    )
    .await;
    assert!(
        !handled,
        "RIB rejection must not silently suppress plain Route Refresh fallback"
    );
    assert_eq!((update.afi, update.safi), (Afi::Ipv4, Safi::Unicast));
}

fn permit_group(sequence: u32) -> OrfEntryGroup {
    let OrfEntries::AddressPrefix(mut entries) = one_permit_entry() else {
        unreachable!("one_permit_entry is an Address-Prefix list");
    };
    entries[0].sequence = sequence;
    OrfEntryGroup {
        orf_type: OrfType::AddressPrefix,
        entries: OrfEntries::AddressPrefix(entries),
    }
}

/// One ROUTE-REFRESH is one RIB command carrying its negotiated-type groups
/// in wire order: a malformed group as its REMOVE-ALL reset in place, an
/// un-negotiated type left out.
#[tokio::test]
async fn inbound_orf_groups_travel_in_one_rib_command_in_wire_order() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let mut rr = orf_rr_with_groups(vec![
        permit_group(1),
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefixLegacy,
            entries: one_permit_entry(),
        },
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: OrfEntries::Malformed(Bytes::from_static(&[0x40])),
        },
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: OrfEntries::AddressPrefix(vec![]),
        },
        permit_group(2),
    ]);
    rr.orf.as_mut().unwrap().when_to_refresh = WhenToRefresh::Defer;
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled);
    assert_eq!(update.when, WhenToRefresh::Defer);
    let shape: Vec<Vec<(OrfAction, u32)>> = update
        .groups
        .iter()
        .map(|group| group.iter().map(|e| (e.action, e.sequence)).collect())
        .collect();
    assert_eq!(
        shape,
        vec![
            vec![(OrfAction::Add, 1)],
            vec![(OrfAction::RemoveAll, 0)],
            vec![],
            vec![(OrfAction::Add, 2)],
        ]
    );
    assert!(rib_rx.try_recv().is_err(), "one message is one RIB command");
}

/// The group count multiplies neither the RIB commands nor the time the
/// session spends waiting on a RIB that does not answer.
#[tokio::test(start_paused = true)]
async fn inbound_orf_group_count_does_not_multiply_commands_or_reply_wait() {
    for groups in [1_u32, 8, 1357] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut neg = negotiated_session(65002, false);
        neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
        session.negotiated = Some(Arc::new(neg));
        let rr = orf_rr_with_groups(
            (0..groups)
                .map(|_| OrfEntryGroup {
                    orf_type: OrfType::AddressPrefix,
                    entries: OrfEntries::AddressPrefix(vec![]),
                })
                .collect(),
        );
        let started = tokio::time::Instant::now();
        let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
        tokio::pin!(process);
        // Hold every reply open: the RIB never answers.
        let mut commands = Vec::new();
        let handled = loop {
            tokio::select! {
                msg = rib_rx.recv() => commands.push(msg.expect("RIB channel open")),
                handled = &mut process => break handled,
            }
        };
        assert!(!handled, "an unanswered ORF falls back to plain refresh");
        assert_eq!(
            (commands.len(), started.elapsed()),
            (1, Duration::from_millis(500)),
            "{groups} groups"
        );
    }
}

#[tokio::test]
async fn inbound_orf_dropped_rib_reply_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let msg = tokio::select! {
        msg = rib_rx.recv() => msg.expect("PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = msg else {
        panic!("expected RibUpdate::PeerOrfUpdate");
    };
    drop(reply);
    let handled = process.await;
    assert!(
        !handled,
        "dropped RIB reply must not silently suppress plain Route Refresh fallback"
    );
}

#[tokio::test]
async fn inbound_orf_rib_reply_timeout_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let msg = tokio::select! {
        msg = rib_rx.recv() => msg.expect("PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = msg else {
        panic!("expected RibUpdate::PeerOrfUpdate");
    };
    let _keep_reply_open = reply;
    let handled = tokio::time::timeout(Duration::from_secs(1), process)
        .await
        .expect("ORF reply wait should be bounded");
    assert!(
        !handled,
        "RIB reply timeout must not silently suppress plain Route Refresh fallback"
    );
}
