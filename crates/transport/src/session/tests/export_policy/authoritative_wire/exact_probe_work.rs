use super::*;

const SOURCES: u8 = 8;

fn work_prefix(index: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(0x0a40_0000 + (index << 8)), 24)
}

fn work_policy(tag: u32) -> PolicyChain {
    let mut term = retention_statement(None, PolicyAction::Permit);
    term.modifications.communities_add.push(tag);
    PolicyChain::new(vec![Policy {
        entries: vec![term],
        default_action: PolicyAction::Deny,
    }])
}

async fn seed_probe_routes(primary: &mpsc::Sender<RibUpdate>, rows_per_source: u32) {
    for n in 0..SOURCES {
        let source = Ipv4Addr::new(192, 0, 2, n + 1);
        let peer = PeerId::from_ipv4(source);
        register_test_source(primary, peer, 0).await;
        let start = u32::from(n) * rows_per_source;
        // One pinned source attribute allocation per origin, just as for a
        // packed UPDATE. Every source has a distinct next hop and AS_PATH.
        let route = make_sourced_route(source, work_prefix(start), 65_100 + u32::from(n));
        let announced = (start..start + rows_per_source)
            .map(|index| Route {
                prefix: Prefix::V4(work_prefix(index)),
                ..route.clone()
            })
            .collect();
        primary
            .send(RibUpdate::RoutesReceived {
                session_id: 0,
                peer,
                announced,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            })
            .await
            .unwrap();
    }
    let (reply, count) = oneshot::channel();
    primary
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    let rows = u32::from(SOURCES) * rows_per_source;
    assert_eq!(count.await.unwrap(), usize::try_from(rows).unwrap());
}

async fn probe_member(
    primary: &mpsc::Sender<RibUpdate>,
    n: u8,
    expected_rows: u32,
) -> (PeerId, u64, mpsc::Receiver<OutboundRouteUpdate>) {
    use rustbgpd_rib::ExactExportSnapshot;

    let (mut session, _) = make_test_session_with_rib(65001, 65002);
    let peer = PeerId::from_ipv4(Ipv4Addr::new(10, 0, 0, n + 1));
    session.rib_tx = primary.clone();
    session.peer_ip = peer.addr();
    session.config.route_server_client = true;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    session.publish_export_profile();
    let owner = session.export_encoder.snapshot().owner_id();
    primary
        .send(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 1,
            rs_control_asn: Some(65_001),
        })
        .await
        .unwrap();
    let mut exports = register_export_session(&session, 1, Some(work_policy(OLD))).await;
    let mut rows = 0;
    loop {
        let update = exports.recv().await.unwrap();
        assert!(
            update
                .announce
                .iter()
                .all(|route| route.communities() == [OLD])
        );
        rows += update.announce.len();
        if !update.end_of_rib.is_empty() {
            assert_eq!(update.end_of_rib, [(Afi::Ipv4, Safi::Unicast)]);
            break;
        }
    }
    assert_eq!(rows, usize::try_from(expected_rows).unwrap());
    (peer, owner, exports)
}

fn take_probe_work() -> [usize; 4] {
    [
        export::PREPARED_UNICAST_BUNDLES.take(),
        export::UNICAST_PROBE_BUILDS.take(),
        export::EXACT_BATCH_ROWS.take(),
        export::REUSED_EXACT_LENGTHS.take(),
    ]
}

// Pack the actor's retained payload once, just as the elected producer does:
// one preparation cache across source-grouped windows, one physical UPDATE
// per returned chunk. Decode the bytes independently of RIB table inspection.
fn packed_source_frames(
    update: &OutboundRouteUpdate,
    expected_rows: &BTreeSet<(Prefix, PeerId)>,
) -> [usize; SOURCES as usize] {
    let profile = update
        .exact_export_snapshot
        .as_ref()
        .unwrap()
        .as_any()
        .downcast_ref::<export::SessionExportProfile>()
        .unwrap();
    let mut cache = export::PreparedAttrCache::default();
    let order = shared_group::source_grouped_order(&update.announce);
    let mut seen = BTreeSet::new();
    let mut frames = [0; SOURCES as usize];
    for indices in order.chunks(shared_group::PROGRESSIVE_SLICE_ROUTES) {
        let chunks = shared_group::encode_shared_unicast_slice(
            profile,
            &mut cache,
            &update.announce,
            &update.next_hop_override,
            indices,
        )
        .expect("authoritative shared payload must encode");
        for mut chunk in chunks {
            assert_eq!((chunk.afi, chunk.safi), (Afi::Ipv4, Safi::Unicast));
            let IpAddr::V4(source) = chunk.source.addr() else {
                panic!("unexpected source address");
            };
            let n = source.octets()[3] - 1;
            frames[usize::from(n)] += 1;
            let Message::Update(message) =
                rustbgpd_wire::decode_message(&mut chunk.bytes, rustbgpd_wire::MAX_MESSAGE_LEN)
                    .unwrap()
            else {
                panic!("expected one BGP UPDATE per chunk");
            };
            assert!(chunk.bytes.is_empty());
            let parsed = message.parse(true, false, &[]).unwrap();
            assert!(parsed.withdrawn.is_empty() && !parsed.announced.is_empty());
            let expected_attrs = [
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65_100 + u32::from(n)])],
                }),
                PathAttribute::NextHop(source),
                PathAttribute::Communities(vec![NEW]),
            ];
            assert_eq!(parsed.attributes.len(), expected_attrs.len());
            assert!(expected_attrs.iter().all(|a| parsed.attributes.contains(a)));
            for entry in parsed.announced {
                assert_eq!(entry.path_id, 0);
                assert!(seen.insert((Prefix::V4(entry.prefix), chunk.source)));
            }
        }
    }
    assert_eq!(&seen, expected_rows);
    frames
}

async fn authoritative_probe_work(
    member_count: u8,
    rows_per_source: u32,
) -> ([usize; 4], [usize; SOURCES as usize]) {
    let rows = u32::from(SOURCES) * rows_per_source;
    let (primary, rx) = mpsc::channel(64);
    let (query, queries) = mpsc::channel(8);
    let actor = tokio::spawn(
        rustbgpd_rib::RibManager::new(rx, queries, None, None, BgpMetrics::new()).run(),
    );
    seed_probe_routes(&primary, rows_per_source).await;
    let mut members = Vec::new();
    let mut owners = BTreeSet::new();
    for n in 0..member_count {
        let member = probe_member(&primary, n, rows).await;
        assert!(owners.insert(member.1), "distinct session encoder owner");
        members.push(member);
    }
    let replacements = members
        .iter()
        .map(|&(peer, _, _)| PeerExportPolicyReplacement {
            peer,
            export_policy: Some(work_policy(NEW)),
        })
        .collect();
    let (reply, applied) = oneshot::channel();
    let pages = rustbgpd_rib::authoritative_reload_build_pages();
    // This current-thread runtime also polls the actor. Exclude initial
    // exports and measure only the authoritative command through its reply.
    take_probe_work();
    primary
        .try_send(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        })
        .unwrap();
    assert_eq!(applied.await.unwrap().unwrap(), Vec::<PeerId>::new());
    let work = take_probe_work();
    assert!(rustbgpd_rib::authoritative_reload_build_pages() - pages > 1);
    let mut payload = None;
    let mut frames = None;
    for (peer, owner, mut exports) in members {
        let update = exports.try_recv().unwrap();
        assert_eq!(
            update.exact_export_snapshot.as_ref().unwrap().owner_id(),
            owner
        );
        assert_eq!(update.announce_source_exclusion, Some(peer));
        assert_eq!(update.unicast_withdrawals().count(), 0);
        assert!(exports.try_recv().is_err());
        let cell = update.shared_group_encode.as_ref().unwrap();
        if let Some((first, first_cell)) = &payload {
            assert!(Arc::ptr_eq(first, &update.announce));
            assert!(Arc::ptr_eq(first_cell, cell));
        } else {
            assert_eq!(update.announce.len(), usize::try_from(rows).unwrap());
            let expected: BTreeSet<_> = (0..rows)
                .map(|index| {
                    let n = u8::try_from(index / rows_per_source).unwrap();
                    let source = PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, n + 1));
                    (Prefix::V4(work_prefix(index)), source)
                })
                .collect();
            let actual: BTreeSet<_> = update
                .announce
                .iter()
                .map(|route| {
                    assert_eq!(route.communities(), [NEW]);
                    (route.prefix, route.peer)
                })
                .collect();
            assert_eq!(expected, actual);
            frames = Some(packed_source_frames(&update, &expected));
            payload = Some((Arc::clone(&update.announce), Arc::clone(cell)));
        }
    }
    drop((primary, query));
    actor.await.unwrap();
    (work, frames.unwrap())
}

#[tokio::test]
async fn authoritative_reload_exact_probe_work_is_bounded_by_source_shapes() {
    let before = rustbgpd_rib::authoritative_reload_build_pages();
    let small = Box::pin(authoritative_probe_work(8, 2_048)).await;
    let pages = rustbgpd_rib::authoritative_reload_build_pages() - before;
    let large = Box::pin(authoritative_probe_work(32, 2_048)).await;
    // One physical preparation and one real message build per source. There
    // is one full row walk for the cohort. Every further member proves only
    // its own ceiling against the maximum message size.
    let sources = usize::from(SOURCES);
    let rows = sources * 2_048;
    // Each source fills a 2,048-route production slice. Its /24 NLRI
    // occupies four bytes per row, so it packs into three standard 4 KiB
    // UPDATEs with the source's small, fixed path attributes.
    let frames = [3; SOURCES as usize];
    assert_eq!(
        [small, large],
        [
            ([sources, sources, rows, 7], frames),
            ([sources, sources, rows, 31], frames),
        ]
    );
    // Still above 10,000 winners, with fewer build pages and the same eight
    // source attribute values. Only source boundaries relative to the fixed
    // encode slices move: 1,536 / (512 + 1,024) / (1,024 + 512) / 1,536.
    let before = rustbgpd_rib::authoritative_reload_build_pages();
    let shorter = Box::pin(authoritative_probe_work(8, 1_536)).await;
    let fewer_pages = rustbgpd_rib::authoritative_reload_build_pages() - before;
    assert!(fewer_pages < pages, "build pages {fewer_pages} vs {pages}");
    assert_eq!(
        shorter,
        (
            [sources, sources, sources * 1_536, 7],
            [2, 3, 3, 2, 2, 3, 3, 2]
        )
    );
}
