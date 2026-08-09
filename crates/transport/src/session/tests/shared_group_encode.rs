use super::*;

#[tokio::test]
async fn shared_transition_payload_excludes_only_the_target_source() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let own = make_route(100);
    assert_eq!(own.peer, session.peer_ip);
    let other_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let other = Route {
        prefix: Prefix::V4(other_prefix),
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        ..own.clone()
    };
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce_source_exclusion = Some(session.peer_ip);
    update.announce = vec![own, other.clone()].into();
    update.next_hop_override = vec![None, None].into();
    session.send_route_update(update);

    let Message::Update(message) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = message.parse(true, false, &[]).unwrap();
    assert_eq!(parsed.announced.len(), 1);
    assert_eq!(parsed.announced[0].prefix, other_prefix);
}

/// The first member of a grouped fanout encodes the shared inventory once;
/// the second reuses the published bytes. Each member's stream is the
/// inventory minus its own source's chunks (split horizon composes from
/// whole per-source chunks).
#[tokio::test]
async fn shared_group_encode_first_member_encodes_and_second_reuses() {
    let source_a = Ipv4Addr::new(10, 30, 0, 1);
    let source_b = Ipv4Addr::new(10, 30, 0, 2);
    let source_c = Ipv4Addr::new(10, 30, 0, 3);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_c = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
        make_sourced_route(source_c, prefix_c, 64_603),
    ];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let published = shared.cell.get().expect("first member publishes the cell");
    let (chunk_count, terminal) = published
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .expect("cell payload is the transport shared-encode type")
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete),
        "uniform-profile inventory must complete"
    );
    assert_eq!(chunk_count, 3, "one chunk per source at this size");
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 2).await,
        {
            let mut expected = vec![Prefix::V4(prefix_b), Prefix::V4(prefix_c)];
            expected.sort_unstable();
            expected
        },
        "member A receives the table minus its own source"
    );

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    assert!(
        Arc::ptr_eq(shared.cell.get().unwrap(), published),
        "second member reuses the published encode"
    );
    assert_eq!(
        read_announced_prefixes(&mut wire_b, 2).await,
        {
            let mut expected = vec![Prefix::V4(prefix_a), Prefix::V4(prefix_c)];
            expected.sort_unstable();
            expected
        },
        "member B receives the table minus its own source"
    );
}

/// A member whose export profile is not provably wire-identical to the
/// encoder's must fall back to its ordinary per-session encode and still
/// deliver a correct stream.
#[tokio::test]
async fn shared_group_encode_profile_mismatch_falls_back_to_local_encode() {
    let source_a = Ipv4Addr::new(10, 31, 0, 1);
    let source_b = Ipv4Addr::new(10, 31, 0, 2);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    assert!(shared.cell.get().is_some());
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 1).await,
        vec![Prefix::V4(prefix_b)]
    );

    // Different local ASN = different wire bytes (AS_PATH prepend) — the
    // equality proof must reject the published encode.
    let (mut member_b, mut wire_b) = shared_group_member(64_999).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    assert_eq!(
        read_announced_prefixes(&mut wire_b, 1).await,
        vec![Prefix::V4(prefix_a)],
        "fallback member still delivers its correct per-session stream"
    );
}

/// Shared chunks carry their family; a member that did not negotiate a
/// family skips those chunks even though the encoder produced them.
#[tokio::test]
async fn shared_group_encode_skips_chunks_of_unnegotiated_families() {
    let source_a = Ipv4Addr::new(10, 32, 0, 1);
    let source_b = Ipv4Addr::new(10, 32, 0, 2);
    let prefix_v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6_route = Route {
        prefix: Prefix::V6(Ipv6Prefix::new(
            "2001:db8:2::".parse::<Ipv6Addr>().unwrap(),
            48,
        )),
        next_hop: IpAddr::V6("2001:db8::b".parse::<Ipv6Addr>().unwrap()),
        ..make_sourced_route(source_b, prefix_v4, 64_602)
    };
    let announce = vec![make_sourced_route(source_a, prefix_v4, 64_601), v6_route];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    // Encoder negotiated IPv4 only, and its own source is excluded — its
    // wire stream must skip the IPv6 chunk it still encoded for the group.
    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let published = shared.cell.get().expect("cell published");
    let (chunk_count, terminal) = published
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 2,
        "encoder produced the IPv6 chunk for dual-stack members"
    );
    // Member A negotiated only IPv4-unicast and excluded source A: nothing
    // but the IPv6 chunk remains, and that chunk is skipped — so the next
    // message on the wire would block forever. Prove the skip by sending a
    // sentinel envelope through the ordinary path and reading it back.
    let mut sentinel = empty_outbound_update();
    sentinel.exact_export_snapshot = Some(member_a.publish_export_profile());
    let sentinel_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25);
    sentinel.announce = vec![make_sourced_route(source_b, sentinel_prefix, 64_602)].into();
    sentinel.next_hop_override = vec![None].into();
    member_a.handle_outbound_route_update(sentinel).await;
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 1).await,
        vec![Prefix::V4(sentinel_prefix)],
        "no IPv6 UPDATE preceded the sentinel on an IPv4-only session"
    );
}

/// A stream that terminates `Failed` after a member already sent shared
/// chunks must fall back to the full local encode: the receiver sees the
/// head chunk again (byte-identical, idempotent) and every remaining route
/// exactly once — repetition is possible, skipping is not.
#[tokio::test]
async fn shared_group_encode_midstream_failure_falls_back_without_skips() {
    use super::shared_group::{ProgressiveUnicastEncode, StreamTerminal};
    let source_a = Ipv4Addr::new(10, 33, 0, 1);
    let source_b = Ipv4Addr::new(10, 33, 0, 2);
    let source_x = Ipv4Addr::new(10, 33, 0, 9);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];

    let (mut member, mut wire) = shared_group_member(65001).await;
    let profile = (*member.publish_export_profile()).clone();
    let encode = ProgressiveUnicastEncode::test_new(profile.clone());
    // Simulate an encoder that published the first source's chunk and then
    // hit an anomaly.
    let mut cache = super::export::PreparedAttrCache::default();
    let head = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce[..1],
        &[None],
        &[0],
    )
    .expect("head slice encodes");
    encode.test_publish(head);
    encode.test_finish(StreamTerminal::Failed);
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    assert!(
        shared
            .cell
            .set(Arc::new(encode) as Arc<dyn std::any::Any + Send + Sync>)
            .is_ok(),
        "fresh cell"
    );

    // Exclusion targets an uninvolved source, so this member wants both
    // routes.
    let update = shared_group_envelope(&member, &shared, source_x, &announce);
    member.handle_outbound_route_update(update).await;

    // Wire: the shared head chunk (prefix A), then the full local fallback
    // stream (prefix A and prefix B in distinct-attr UPDATEs).
    assert_eq!(
        read_announced_prefixes(&mut wire, 3).await,
        {
            let mut expected = vec![
                Prefix::V4(prefix_a),
                Prefix::V4(prefix_a),
                Prefix::V4(prefix_b),
            ];
            expected.sort_unstable();
            expected
        },
        "head chunk repeats (idempotent), nothing is skipped"
    );
}

/// The encoder unwinding without a terminal must leave `Failed`, never a
/// stream consumers could wait on forever.
#[tokio::test]
async fn shared_group_encoder_guard_publishes_failed_on_unwind() {
    use super::shared_group::{EncoderGuard, ProgressiveUnicastEncode, StreamTerminal};
    let (member, _wire) = shared_group_member(65001).await;
    let encode = ProgressiveUnicastEncode::test_new((*member.publish_export_profile()).clone());
    drop(EncoderGuard(&encode));
    assert_eq!(encode.test_snapshot(), (0, Some(StreamTerminal::Failed)));
}

/// An inventory larger than one encoder slice is published progressively
/// across slices and streams completely to a consumer, with split horizon
/// still composed from whole per-source chunks.
#[tokio::test]
async fn shared_group_encode_streams_multiple_slices() {
    let sources = [
        Ipv4Addr::new(10, 34, 0, 1),
        Ipv4Addr::new(10, 34, 0, 2),
        Ipv4Addr::new(10, 34, 0, 3),
    ];
    // One attribute Arc per source so same-source routes group into shared
    // chunks (mirroring interned route-server tables).
    let attrs: Vec<Arc<Vec<PathAttribute>>> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![
                        64_601 + u32::try_from(i).unwrap(),
                    ])],
                }),
                PathAttribute::NextHop(*source),
            ])
        })
        .collect();
    let total = 2_100_usize; // > one 2048-route slice
    let announce: Vec<Route> = (0..total)
        .map(|i| {
            let source = sources[i % 3];
            Route {
                prefix: Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x0A40_0000_u32 + u32::try_from(i).unwrap() * 256),
                    24,
                )),
                peer: IpAddr::V4(source),
                next_hop: IpAddr::V4(source),
                attributes: Arc::clone(&attrs[i % 3]),
                ..make_route(100)
            }
        })
        .collect();
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, sources[0], &announce);
    member_a.handle_outbound_route_update(update).await;
    let (chunk_count, terminal) = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 4,
        "source-sorted iteration keeps per-source chunks dense: three whole \
         sources in slice one, the third source's tail in slice two"
    );

    let expected_a: Vec<Prefix> = {
        let mut v: Vec<Prefix> = announce
            .iter()
            .filter(|route| route.peer != IpAddr::V4(sources[0]))
            .map(|route| route.prefix)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(read_announced_prefixes(&mut wire_a, 3).await, expected_a);

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, sources[1], &announce);
    member_b.handle_outbound_route_update(update).await;
    let expected_b: Vec<Prefix> = {
        let mut v: Vec<Prefix> = announce
            .iter()
            .filter(|route| route.peer != IpAddr::V4(sources[1]))
            .map(|route| route.prefix)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(read_announced_prefixes(&mut wire_b, 3).await, expected_b);
}

/// Two different source peers whose routes carry a pointer-identical
/// attribute `Arc` (the shape global attribute interning produces) must
/// still land in distinct per-source chunks. If the shared group key ever
/// merged them, split horizon would compose wrongly: the excluded member
/// would either lose the other source's route (silent under-advertise) or
/// receive its own route back (leak).
#[tokio::test]
async fn shared_group_interned_attrs_across_sources_never_merge_chunks() {
    let shared_attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64_601])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 40, 0, 9)),
    ]);
    let source_a = Ipv4Addr::new(10, 40, 0, 1);
    let source_b = Ipv4Addr::new(10, 40, 0, 2);
    let source_c = Ipv4Addr::new(10, 40, 0, 3);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_c = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let route_a = Route {
        prefix: Prefix::V4(prefix_a),
        peer: IpAddr::V4(source_a),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 9)),
        attributes: Arc::clone(&shared_attrs),
        ..make_route(100)
    };
    let route_b = Route {
        prefix: Prefix::V4(prefix_b),
        peer: IpAddr::V4(source_b),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 9)),
        attributes: Arc::clone(&shared_attrs),
        ..make_route(100)
    };
    let route_c = make_sourced_route(source_c, prefix_c, 64_603);
    let announce = vec![route_a, route_b, route_c];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let (chunk_count, terminal) = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 3,
        "pointer-identical attrs across two sources must still yield two distinct chunks"
    );
    let map_a = shared_group_read_prefix_attr_map(&mut wire_a, 2).await;
    assert_eq!(
        map_a
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [prefix_b.to_string(), prefix_c.to_string()].into(),
        "member A: everything except its own source, despite interned attrs"
    );

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    let map_b = shared_group_read_prefix_attr_map(&mut wire_b, 2).await;
    assert_eq!(
        map_b
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [prefix_a.to_string(), prefix_c.to_string()].into(),
        "member B: everything except its own source"
    );

    // Ordinary-path reference with an identical profile: same envelope, no
    // cell. The shared bytes must be attribute-identical per prefix.
    let (mut member_r, mut wire_r) = shared_group_member(65001).await;
    let mut reference = shared_group_envelope(&member_r, &shared, source_b, &announce);
    reference.shared_group_encode = None;
    member_r.handle_outbound_route_update(reference).await;
    let map_r = shared_group_read_prefix_attr_map(&mut wire_r, 2).await;
    assert_eq!(
        map_b, map_r,
        "shared stream must be attribute-identical to the ordinary per-session encode"
    );
}

/// The encoder walks the inventory through a source-sorted index while
/// `next_hop_override` stays parallel to the ORIGINAL announce order. If
/// the encoder ever indexed the overrides by sorted position, an override
/// would land on the wrong prefix — a silent wrong next hop on the wire.
#[tokio::test]
async fn shared_group_nh_override_alignment_survives_source_sort() {
    // Original order deliberately unsorted by source so the sorted index
    // walk permutes positions: sources .3, .1, .2.
    let prefix_0 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_2 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let announce = vec![
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 3), prefix_0, 64_603),
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 1), prefix_1, 64_601),
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 2), prefix_2, 64_602),
    ];
    let overrides: Vec<Option<rustbgpd_policy::NextHopAction>> =
        vec![None, Some(rustbgpd_policy::NextHopAction::Self_), None];
    let excluded = Ipv4Addr::new(10, 41, 0, 9);
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member, mut wire) = shared_group_member(65001).await;
    let mut update = shared_group_envelope(&member, &shared, excluded, &announce);
    update.next_hop_override = overrides.clone().into();
    member.handle_outbound_route_update(update).await;
    let map_shared = shared_group_read_prefix_attr_map(&mut wire, 3).await;

    let self_hop = format!("{:?}", PathAttribute::NextHop(Ipv4Addr::LOCALHOST));
    assert!(
        map_shared[&prefix_1.to_string()].contains(&self_hop),
        "override at original index 1 must produce next-hop-self on prefix_1; got {:?}",
        map_shared[&prefix_1.to_string()]
    );
    assert!(
        map_shared[&prefix_0.to_string()].contains(&format!(
            "{:?}",
            PathAttribute::NextHop(Ipv4Addr::new(10, 41, 0, 3))
        )),
        "prefix_0 keeps its source next hop"
    );
    assert!(
        map_shared[&prefix_2.to_string()].contains(&format!(
            "{:?}",
            PathAttribute::NextHop(Ipv4Addr::new(10, 41, 0, 2))
        )),
        "prefix_2 keeps its source next hop"
    );

    // Attribute-equivalence against the ordinary path with the same
    // overrides.
    let (mut member_r, mut wire_r) = shared_group_member(65001).await;
    let mut reference = shared_group_envelope(&member_r, &shared, excluded, &announce);
    reference.next_hop_override = overrides.into();
    reference.shared_group_encode = None;
    member_r.handle_outbound_route_update(reference).await;
    let map_r = shared_group_read_prefix_attr_map(&mut wire_r, 3).await;
    assert_eq!(map_shared, map_r);
}

/// A consumer that starts streaming BEFORE the encoder has published
/// anything must observe every later slice and the terminal, with
/// publications racing its notify loop (lost-wakeup / stale-snapshot
/// regression guard).
#[tokio::test]
async fn shared_group_consumer_streams_concurrently_with_live_encoder() {
    use super::shared_group::{ProgressiveUnicastEncode, StreamTerminal};
    let source_a = Ipv4Addr::new(10, 42, 0, 1);
    let source_b = Ipv4Addr::new(10, 42, 0, 2);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];
    let (member, mut wire) = shared_group_member(65001).await;
    let profile = (*member.publish_export_profile()).clone();
    let mut cache = super::export::PreparedAttrCache::default();
    let slice_1 = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce,
        &[None, None],
        &[0],
    )
    .unwrap();
    let slice_2 = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce,
        &[None, None],
        &[1],
    )
    .unwrap();
    let typed = Arc::new(ProgressiveUnicastEncode::test_new(profile));
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    assert!(
        shared
            .cell
            .set(Arc::clone(&typed) as Arc<dyn std::any::Any + Send + Sync>)
            .is_ok()
    );
    let update = shared_group_envelope(&member, &shared, Ipv4Addr::new(10, 42, 0, 9), &announce);
    let mut member = member;
    let consumer = tokio::spawn(async move {
        member.handle_outbound_route_update(update).await;
    });
    // Publish while the consumer is (very likely) parked on the notify.
    tokio::time::sleep(Duration::from_millis(50)).await;
    typed.test_publish(slice_1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    typed.test_publish(slice_2);
    typed.test_finish(StreamTerminal::Complete);
    tokio::time::timeout(Duration::from_secs(5), consumer)
        .await
        .expect("consumer must terminate once the stream completes")
        .unwrap();
    let map = shared_group_read_prefix_attr_map(&mut wire, 2).await;
    assert_eq!(
        map.keys().cloned().collect::<Vec<_>>(),
        {
            let mut v = vec![prefix_a.to_string(), prefix_b.to_string()];
            v.sort();
            v
        },
        "both progressively published slices reach the wire, none skipped"
    );
}

/// The wire-equivalence proof must ignore ONLY byte-inert fields. Extended
/// Messages changes the negotiated ceiling but never the bytes of a
/// 4096-fitting message (shared chunks are encoded at the standard
/// ceiling), so it must NOT break sharing; Add-Path send changes NLRI
/// framing and MUST break it.
#[tokio::test]
async fn shared_group_wire_equivalence_proof_ignores_only_byte_inert_fields() {
    let (a, _wire_a) = shared_group_member(65001).await;
    let (mut b, _wire_b) = shared_group_member(65001).await;
    b.negotiated.as_mut().unwrap().peer_extended_message = true;
    let profile_a = a.publish_export_profile();
    let profile_b = b.publish_export_profile();
    assert!(
        profile_a.has_same_wire_encoding(&profile_b),
        "extended-message ceiling is byte-inert at the shared 4096 ceiling"
    );
    let (mut c, _wire_c) = shared_group_member(65001).await;
    c.negotiated
        .as_mut()
        .unwrap()
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Send);
    let profile_c = c.publish_export_profile();
    assert!(
        !profile_a.has_same_wire_encoding(&profile_c),
        "Add-Path send changes NLRI bytes and must break the proof"
    );
}
