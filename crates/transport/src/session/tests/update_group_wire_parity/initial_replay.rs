//! Compare the joining receiver's TCP stream across initial replay paths.
use super::*;

const UNICAST: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const ROUTES: u16 = 10_240;

fn prefix(i: u16) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(0x0ac8_0000 + u32::from(i)), 32)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Changes {
    None,
    DifferentKeys,
    WithdrawThenReannounce,
}

async fn update_source(
    tx: &mpsc::Sender<RibUpdate>,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) {
    tx.send(RibUpdate::RoutesReceived {
        peer: PeerId::from_addr(IpAddr::V4(A)),
        session_id: 0,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
}

async fn winners(tx: &mpsc::Sender<RibUpdate>, prefixes: Vec<Prefix>) -> Vec<Option<Route>> {
    let (reply, installed) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutesExact {
        prefixes,
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        reply,
    })
    .await
    .unwrap();
    installed.await.unwrap().unwrap().routes
}

async fn withdraw_then_reannounce(
    tx: &mpsc::Sender<RibUpdate>,
    restored: Ipv4Prefix,
    equivalent: Ipv4Prefix,
) {
    let key = Prefix::V4(restored);
    let fresh = prefix(ROUTES);
    let fresh_key = Prefix::V4(fresh);
    assert!(winners(tx, vec![fresh_key]).await[0].is_none());
    let inserted = make_sourced_route(A, fresh, 65021);
    update_source(tx, vec![inserted.clone()], vec![(key, 0)]).await;
    let rows = winners(tx, vec![key, fresh_key]).await;
    assert!(
        rows[0].is_none(),
        "first UPDATE withdrew the original winner"
    );
    assert_eq!(rows[1].as_ref().unwrap().as_path(), inserted.as_path());

    let new = make_sourced_route(A, restored, 65022);
    let mut rewritten = make_sourced_route(A, equivalent, 65021);
    AttrSet::edit(&mut rewritten.attributes, |attrs| {
        attrs.push(PathAttribute::Med(333));
    });
    update_source(tx, vec![new.clone(), rewritten], vec![(fresh_key, 0)]).await;
    let rows = winners(tx, vec![key, Prefix::V4(equivalent), fresh_key]).await;
    assert!(
        rows[2].is_none(),
        "second UPDATE withdrew the inserted winner"
    );
    assert_eq!(rows[0].as_ref().unwrap().as_path(), new.as_path());
    assert_eq!(
        rows[1].as_ref().unwrap().med(),
        333,
        "source change installed before releasing the page"
    );
    for asn in [65023, 65024] {
        let replacement = make_sourced_route(A, restored, asn);
        update_source(tx, vec![replacement.clone()], vec![]).await;
        let installed = winners(tx, vec![key]).await;
        assert_eq!(
            installed[0].as_ref().unwrap().as_path(),
            replacement.as_path()
        );
    }
    let reinserted = make_sourced_route(A, fresh, 65022);
    update_source(tx, vec![reinserted.clone()], vec![]).await;
    let rows = winners(tx, vec![fresh_key]).await;
    assert_eq!(rows[0].as_ref().unwrap().as_path(), reinserted.as_path());
}

async fn change_admitted_prefixes(
    tx: &mpsc::Sender<RibUpdate>,
    removed: Ipv4Prefix,
    changed: Ipv4Prefix,
) {
    update_source(
        tx,
        vec![
            make_sourced_route(A, prefix(ROUTES), 65021),
            make_sourced_route(A, changed, 65022),
        ],
        vec![(Prefix::V4(removed), 0)],
    )
    .await;
    // Keep this page's latch until the ordinary UPDATE is applied.
    let marker = Prefix::V4(prefix(ROUTES));
    let rows = winners(tx, vec![Prefix::V4(removed), marker]).await;
    assert!(rows[0].is_none());
    assert_eq!(rows[1].as_ref().unwrap().prefix, marker);
}

fn wire_key(prefix: Ipv4Prefix) -> Key {
    let mut nlri = vec![prefix.len];
    nlri.extend_from_slice(&prefix.addr.octets()[..usize::from(prefix.len).div_ceil(8)]);
    ((1, 1), nlri)
}

fn check_restored(wire: &WireTrace, restored: Ipv4Prefix, equivalent: Ipv4Prefix) {
    let key = wire_key(restored);
    let events = &wire.events[&key];
    assert_eq!(
        events.len(),
        5,
        "each separately installed export change must reach the wire"
    );
    assert!(events[1].1.is_none());
    let old = events[0].1.as_ref().unwrap();
    let restored = events[2].1.as_ref().unwrap();
    // The unmodified /24 was seeded with the replacement AS path and uses the same chain.
    assert_eq!(
        restored,
        &wire.state[&wire_key(v4_prefix(1))],
        "exact replacement wire bytes"
    );
    for (index, asn) in [(0, 65021), (2, 65022), (3, 65023), (4, 65024)] {
        let attrs = events[index].1.as_ref().expect("an announcement");
        let decoded =
            rustbgpd_wire::attribute::decode_path_attributes(&attrs.0, true, &[]).unwrap();
        assert!(decoded.contains(&PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![LOCAL_ASN, asn])],
        })));
        assert!(decoded.contains(&PathAttribute::Med(77)));
    }
    assert_eq!(&wire.state[&key], events[4].1.as_ref().unwrap());
    assert_eq!(
        &wire.state[&wire_key(equivalent)],
        old,
        "policy rewrites both source MEDs to 77"
    );
    let fresh = wire_key(prefix(ROUTES));
    let fresh_events = &wire.events[&fresh];
    assert_eq!(
        fresh_events.len(),
        3,
        "insert, withdrawal and reannouncement must all reach TCP"
    );
    assert_eq!(fresh_events[0].1.as_ref(), Some(old));
    assert!(fresh_events[1].1.is_none());
    assert_eq!(fresh_events[2].1.as_ref(), Some(restored));
    assert_eq!(&wire.state[&fresh], restored);
    for (other, events) in &wire.events {
        if *other != key && *other != fresh {
            assert_eq!(events.len(), 1, "unexpected repeat for {other:?}");
        }
    }
}

fn check_wire(
    wire: &mut WireTrace,
    paced: bool,
    changes: Changes,
    edits: Option<(Ipv4Prefix, Ipv4Prefix)>,
) {
    if !paced {
        assert_eq!(wire.eors.remove(&(1, 128)), Some(vec![BTreeMap::new()]));
    }
    assert_eq!(
        wire.state.len(),
        usize::from(ROUTES) + 1 + usize::from(changes == Changes::WithdrawThenReannounce)
    );
    let progress: BTreeMap<_, _> = wire
        .events
        .iter()
        .map(|(key, events)| (key.clone(), events.len()))
        .collect();
    assert!(
        wire.eors[&(1, 1)] == [progress],
        "all rows and repairs before exactly one marker"
    );
    if changes == Changes::WithdrawThenReannounce {
        let (restored, equivalent) = edits.unwrap();
        check_restored(wire, restored, equivalent);
        return;
    }
    for (key, events) in &wire.events {
        if let Some((removed, changed)) = edits {
            if *key == wire_key(removed) {
                assert_eq!(events.len(), 2, "original row and its withdrawal");
                assert!(events[0].1.is_some() && events[1].1.is_none());
                continue;
            }
            if *key == wire_key(changed) {
                assert_eq!(events.len(), 2, "original row and its replacement");
                assert!(events.iter().all(|(_, attrs)| attrs.is_some()));
                assert_ne!(events[0].1, events[1].1, "replacement AS path reached TCP");
                continue;
            }
        }
        assert_eq!(events.len(), 1, "duplicate initial row {key:?}");
    }
    if let Some((removed, changed)) = edits {
        assert!(wire.events.contains_key(&wire_key(removed)));
        assert!(!wire.state.contains_key(&wire_key(removed)));
        assert!(wire.state.contains_key(&wire_key(changed)));
        assert!(wire.state.contains_key(&wire_key(prefix(ROUTES))));
    }
}

async fn edit_received_page(
    session: &mut PeerSession,
    wire: &mut TcpStream,
    tx: &mpsc::Sender<RibUpdate>,
) -> (Vec<Vec<u8>>, (Ipv4Prefix, Ipv4Prefix)) {
    let page = session.outbound_rx.recv().await.expect("first replay page");
    let mut keys = page.announce.iter().filter_map(|row| match row.prefix {
        Prefix::V4(p) if p.len == 32 => Some(p),
        _ => None,
    });
    let (restored, equivalent) = (keys.next().unwrap(), keys.next().unwrap());
    let latch = Arc::clone(
        page.latch
            .as_ref()
            .expect("first page owns its operation latch"),
    );
    let ((), frames) = tokio::join!(session.test_drain_outbound(page), async {
        let mut waiting =
            std::collections::BTreeSet::from([wire_key(restored), wire_key(equivalent)]);
        let mut frames = Vec::new();
        while !waiting.is_empty() {
            let frame = read_single_raw_bgp_message(wire).await;
            if frame[18] == 2 {
                let received = trace(std::slice::from_ref(&frame));
                waiting.retain(|key| !received.state.contains_key(key));
                frames.push(frame);
            }
        }
        frames
    });
    withdraw_then_reannounce(tx, restored, equivalent).await;
    drop(latch);
    (frames, (restored, equivalent))
}

async fn establish_member(
    tx: &mpsc::Sender<RibUpdate>,
    paced: bool,
    policy: bool,
    changes: Changes,
) -> (PeerSession, TcpStream, usize, mpsc::Sender<PeerCommand>) {
    let mut config = initial_dump_config(None);
    let mut families = vec![UNICAST];
    if !paced {
        // A mixed-SAFI group retains the synchronous unicast replay.
        families.push((Afi::Ipv4, Safi::MplsVpn));
    }
    config.peer.families.clone_from(&families);
    let (command_sender, commands) = mpsc::channel(1);
    let mut session = PeerSession::new(
        config,
        BgpMetrics::new(),
        commands,
        tx.clone(),
        None,
        policy.then(|| {
            if changes == Changes::WithdrawThenReannounce {
                PolicyChain::new(vec![Policy {
                    entries: vec![statement(
                        PolicyAction::Permit,
                        None,
                        None,
                        RouteModifications {
                            set_med: Some(77),
                            ..RouteModifications::default()
                        },
                    )],
                    default_action: PolicyAction::Permit,
                }])
            } else {
                export_chain(false)
            }
        }),
        None,
        None,
        None,
        false,
    );
    if changes != Changes::None {
        (session.outbound_tx, session.outbound_rx) = mpsc::channel(1);
    }
    let (client, wire) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    let mut capabilities: Vec<_> = families
        .iter()
        .map(|&(afi, safi)| Capability::MultiProtocol { afi, safi })
        .collect();
    capabilities.push(Capability::FourOctetAs { asn: 65010 });
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: 65010,
            hold_time: 90,
            bgp_identifier: B,
            capabilities,
        }))
        .await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);

    (session, wire, families.len(), command_sender)
}

async fn replay(paced: bool, policy: bool, changes: Changes) -> WireTrace {
    let (tx, rx) = mpsc::channel(32);
    let (_queries, queries) = mpsc::channel(1);
    let mut manager = rustbgpd_rib::RibManager::new(rx, queries, None, None, BgpMetrics::new());
    let mut base = (0..ROUTES)
        .map(|i| make_sourced_route(A, prefix(i), 65021))
        .collect::<Vec<_>>();
    // The shareable chain gives this row a different MED and next hop.
    base.push(make_sourced_route(
        A,
        v4_prefix(1),
        if changes == Changes::WithdrawThenReannounce {
            65022
        } else {
            65021
        },
    ));
    manager.bench_seed_loc_rib(base);
    let actor = tokio::spawn(manager.run());
    let (mut session, mut wire, family_count, _commands) =
        establish_member(&tx, paced, policy, changes).await;
    // Hold the first page's real operation latch across every change, even after its writer
    // has sent the routes and the loopback receiver has decoded them.
    let (mut frames, mut edits) = if changes == Changes::WithdrawThenReannounce {
        let (frames, edits) = edit_received_page(&mut session, &mut wire, &tx).await;
        (frames, Some(edits))
    } else {
        (Vec::new(), None)
    };
    let mut pages = usize::from(edits.is_some());
    let reader = tokio::spawn(async move {
        loop {
            let frame = read_single_raw_bgp_message(&mut wire).await;
            if frame[18] == 2 {
                // The fence is sent alone after all negotiated markers.
                if frame.ends_with(&[25, 192, 0, 2, 128]) {
                    break;
                }
                frames.push(frame);
            }
        }
        trace(&frames)
    });
    let mut ends = 0;
    while ends < family_count {
        let update = session.outbound_rx.recv().await.expect("live writer");
        if !update.announce.is_empty() {
            pages += 1;
            if changes == Changes::DifferentKeys && edits.is_none() && update.announce.len() >= 2 {
                let (Prefix::V4(removed), Prefix::V4(replaced)) =
                    (update.announce[0].prefix, update.announce[1].prefix)
                else {
                    unreachable!()
                };
                edits = Some((removed, replaced));
                change_admitted_prefixes(&tx, removed, replaced).await;
            }
        }
        ends += update.end_of_rib.len();
        session.test_drain_outbound(update).await;
    }
    if paced {
        assert!(
            pages > 1,
            "the candidate must traverse multiple replay pages"
        );
    } else {
        assert_eq!(pages, 1, "reference must exercise the one-turn dump");
    }
    let mut fence = empty_outbound_update();
    fence.exact_export_snapshot = Some(session.publish_export_profile());
    fence.announce = vec![make_sourced_route(
        A,
        Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25),
        65021,
    )]
    .into();
    fence.next_hop_override = vec![None].into();
    session.test_drain_outbound(fence).await;
    let mut wire = reader.await.unwrap();
    actor.abort();
    let _ = actor.await;
    assert_eq!(edits.is_some(), changes != Changes::None);
    check_wire(&mut wire, paced, changes, edits);
    wire
}

#[tokio::test]
async fn paced_and_one_turn_replay_match_on_the_wire() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let mut special = Vec::new();
        for policy in [false, true] {
            let reference = Box::pin(replay(false, policy, Changes::None)).await;
            let candidate = Box::pin(replay(true, policy, Changes::None)).await;
            assert!(
                candidate == reference,
                "wire inventory, attribute bytes or marker differ (policy={policy})"
            );
            special.push(candidate.state[&((1, 1), vec![24, 10, 200, 1])].clone());
        }
        assert_ne!(
            special[0], special[1],
            "the policy must change wire attributes"
        );
    })
    .await
    .expect("clean replay to finish");
}

#[tokio::test]
async fn full_writer_delivers_a_withdrawal_behind_the_replay_cursor_before_eor() {
    tokio::time::timeout(
        Duration::from_secs(45),
        Box::pin(replay(true, true, Changes::DifferentKeys)),
    )
    .await
    .expect("partial replay to resume");
}

#[tokio::test]
async fn held_page_delivers_withdraw_then_three_distinct_announcements_before_eor() {
    tokio::time::timeout(
        Duration::from_secs(45),
        Box::pin(replay(true, true, Changes::WithdrawThenReannounce)),
    )
    .await
    .expect("separately applied updates reach the receiver");
}
