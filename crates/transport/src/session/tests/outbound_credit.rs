use super::*;

fn v4(index: u32) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::from((20 << 24) | (index << 8)),
        24,
    ))
}

/// An envelope's shared group withdrawals go out in the unicast withdraw
/// phase, sliced like its own, and all of them before its own rows: the
/// session sends every row exactly once, then the End-of-RIB.
#[tokio::test]
async fn shared_withdrawals_precede_own_withdrawals_on_the_wire() {
    const SHARED: u32 = 1_500;
    const OWN: u32 = 700;
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    recv_peer_up_after_export_context(&mut rib_rx).await;
    read_single_bgp_message(&mut server).await;
    read_single_bgp_message(&mut server).await;
    session
        .outbound_tx
        .clone()
        .try_send(OutboundRouteUpdate {
            exact_export_snapshot: Some(session.publish_export_profile()),
            shared_withdraw: Arc::new((0..SHARED).map(|i| (v4(i), 0)).collect::<Vec<_>>()).into(),
            withdraw: (SHARED..SHARED + OWN).map(|i| (v4(i), 0)).collect(),
            end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
            ..OutboundRouteUpdate::default()
        })
        .unwrap();
    let actor = tokio::spawn(async move { session.run().await });
    let mut order = Vec::new();
    loop {
        let Message::Update(message) = read_single_bgp_message(&mut server).await else {
            panic!("unexpected non-UPDATE");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        if parsed.withdrawn.is_empty() && parsed.announced.is_empty() {
            break;
        }
        order.extend(
            parsed
                .withdrawn
                .iter()
                .map(|entry| (u32::from(entry.prefix.addr) >> 8) & 0xffff),
        );
    }
    let total = usize::try_from(SHARED + OWN).unwrap();
    assert_eq!(order.len(), total, "every withdrawal sent once");
    assert_eq!(
        order
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        total
    );
    let last_shared = order.iter().rposition(|&index| index < SHARED).unwrap();
    let first_own = order.iter().position(|&index| index >= SHARED).unwrap();
    assert!(
        last_shared < first_own,
        "a member's own row overtook a shared row"
    );
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap().unwrap();
}
