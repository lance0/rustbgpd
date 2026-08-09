use super::*;

#[tokio::test]
async fn inbound_orf_emits_peer_orf_update_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!((update.afi, update.safi), (Afi::Ipv4, Safi::Unicast));
    assert_eq!(update.when, WhenToRefresh::Immediate);
    assert_eq!(update.entries.len(), 1);
}

#[tokio::test]
async fn inbound_orf_preserves_defer_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr_with_when(
        WhenToRefresh::Defer,
        OrfType::AddressPrefix,
        one_permit_entry(),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!(update.when, WhenToRefresh::Defer);
    assert_eq!(update.entries.len(), 1);
}

#[tokio::test]
async fn inbound_orf_ignored_when_family_not_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // negotiated_session() leaves negotiated_orf_recv empty.
    session.negotiated = Some(negotiated_session(65002, false));
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
    session.negotiated = Some(neg);
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
    session.negotiated = Some(neg);
    // A malformed Address-Prefix group → RFC 5291 §5.2 reset (REMOVE-ALL).
    let rr = orf_rr(
        OrfType::AddressPrefix,
        OrfEntries::Malformed(Bytes::from_static(&[0x40])),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled);
    assert_eq!(update.entries.len(), 1);
    assert_eq!(update.entries[0].action, OrfAction::RemoveAll);
}

#[tokio::test]
async fn inbound_orf_rejected_by_rib_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
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

#[tokio::test]
async fn inbound_orf_any_rib_group_rejection_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr_with_groups(vec![
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: one_permit_entry(),
        },
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: one_permit_entry(),
        },
    ]);
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let first = tokio::select! {
        msg = rib_rx.recv() => msg.expect("first PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before first RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = first else {
        panic!("expected first RibUpdate::PeerOrfUpdate");
    };
    reply
        .send(Ok(()))
        .expect("process_inbound_orf should await first RIB reply");
    let second = tokio::select! {
        msg = rib_rx.recv() => msg.expect("second PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before second RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = second else {
        panic!("expected second RibUpdate::PeerOrfUpdate");
    };
    reply
        .send(Err("peer no longer registered".to_string()))
        .expect("process_inbound_orf should await second RIB reply");
    let handled = process.await;
    assert!(
        !handled,
        "any RIB rejection must fall through to the plain Route Refresh path"
    );
}

#[tokio::test]
async fn inbound_orf_dropped_rib_reply_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
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
    session.negotiated = Some(neg);
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
