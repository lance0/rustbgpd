use super::*;

/// Clean permitted UPDATEs must not construct reject-only diagnostic state
/// or allocate the rejected-route LRU.
/// Break-to-red: restoring eager `LruCache::new` makes the structural
/// allocation assertion fail; eagerly initializing the prototype makes the
/// build-count assertion fail; dropping accepted paths fails the state
/// assertions.
#[tokio::test]
async fn reject_retention_permitted_update_stays_allocation_free() {
    let first = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let (mut session, _metrics) = retention_session_with_chain(None, |_| {});

    session
        .process_update(retention_update(&[first, second], &[]))
        .await;

    assert_eq!(rejected_route_prototype_builds(&session), 0);
    assert!(session.rejected_routes.is_empty());
    assert!(
        session.rejected_routes.is_unallocated(),
        "a session with no retained rejection must hold no LRU allocation"
    );
    assert_eq!(session.known_prefix_count(), 2);
    assert_eq!(session.import_policy_routes_permitted, 2);
}

/// Body and MP policy denies in one UPDATE share one bounded prototype and
/// timestamp; the next UPDATE constructs fresh state from its own attributes.
/// Break-to-red: per-identity construction changes the first count/timestamps;
/// cross-UPDATE reuse makes the third entry retain the first UPDATE's summary.
#[tokio::test]
async fn reject_retention_shares_prototype_across_body_and_mp_policy_denies() {
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, _metrics) = retention_session_with_chain(Some(chain), |_| {});
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let body = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let mp = Prefix::V6(Ipv6Prefix::new("2001:db8:505::".parse().unwrap(), 64));
    let later = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    let first_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![100]),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: mp,
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: body,
            }],
            &[],
            &first_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|(key, _)| *key == retention_key(body)));
    assert!(entries.iter().any(|(key, _)| {
        *key == RetentionKey {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            prefix: mp,
            path_id: 0,
        }
    }));
    assert_eq!(entries[0].1.rejected_at, entries[1].1.rejected_at);
    assert_eq!(rejected_route_prototype_builds(&session), 1);

    let second_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![200]),
    ];
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: later,
            }],
            &[],
            &second_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let entries = session.rejected_routes.snapshot();
    let later_entry = entries
        .iter()
        .find(|(key, _)| *key == retention_key(later))
        .expect("second UPDATE rejection retained");
    assert_eq!(rejected_route_prototype_builds(&session), 2);
    assert_eq!(later_entry.1.as_path, "65002 65003");
    assert_eq!(later_entry.1.communities, vec![200]);
}

/// LAN-472 pin: a policy deny retains the route with reason
/// `policy_reject` and the attribute summary the member-support surface
/// renders; a permitted sibling in the same UPDATE is not retained. The
/// gauge tracks the store, and a subsequent explicit withdrawal clears
/// both.
#[tokio::test]
async fn reject_retention_records_policy_deny_and_clears_on_withdraw() {
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;
    let denied = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![retention_statement(
            Some(Prefix::V4(denied)),
            PolicyAction::Deny,
        )],
        default_action: PolicyAction::Permit,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |_| {});
    session
        .process_update(retention_update(&[denied, permitted], &[]))
        .await;

    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 1, "only the denied prefix is retained");
    let (key, entry) = &entries[0];
    assert_eq!(*key, retention_key(denied));
    assert_eq!(entry.reason, ImportRejectReason::PolicyReject);
    assert_eq!(entry.next_hop, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    assert_eq!(entry.as_path, "65002");
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 1);

    // Explicit withdrawal clears the retained reject — the question
    // "why isn't my route accepted?" is moot once the peer stops
    // announcing it. The gauge follows in both directions.
    session
        .process_update(retention_update(&[], &[denied]))
        .await;
    assert!(
        session.rejected_routes.is_empty(),
        "withdrawal clears the retained reject"
    );
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 0);
}

/// LAN-472 pin: when a previously rejected identity is later accepted
/// (policy outcome changes with the announcement contents), the stale
/// reject entry is cleared — the surface never claims a live route is
/// filtered.
#[tokio::test]
async fn reject_retention_clears_when_route_is_later_accepted() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    // Deny when community 999 is attached; permit otherwise.
    let mut deny_communities = retention_statement(None, PolicyAction::Deny);
    deny_communities.match_community =
        vec![rustbgpd_policy::CommunityMatch::Standard { value: 999 }];
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![deny_communities],
        default_action: PolicyAction::Permit,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |_| {});

    let tagged = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Communities(vec![999]),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(tagged).await;
    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].1.communities,
        vec![999],
        "the rejected UPDATE's communities are retained for the surface"
    );

    // Re-announce without the community — accepted, entry cleared.
    session
        .process_update(retention_update(&[prefix], &[]))
        .await;
    assert!(
        session.rejected_routes.is_empty(),
        "acceptance clears the stale reject entry"
    );
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 0);
}

/// A hostile UPDATE with maximal attributes — a long `AS_PATH` and
/// hundreds of (large) communities — must produce a bounded retained
/// entry: the AS-path string is truncated with the marker and the
/// community vectors are capped with the dropped counts recorded, so
/// the per-entry byte budget holds at capture time regardless of what
/// the peer sends.
#[tokio::test]
async fn reject_retention_bounds_maximal_attribute_entry() {
    use super::rejected_routes::{
        MAX_RETAINED_AS_PATH_BYTES, MAX_RETAINED_COMMUNITIES, MAX_RETAINED_LARGE_COMMUNITIES,
        RETENTION_TRUNCATION_MARKER,
    };
    use rustbgpd_wire::LargeCommunity;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, _metrics) = retention_session_with_chain(Some(chain), |_| {});
    // Two 250-ASN AS_SEQUENCE segments (255 is the per-segment wire
    // max), 200 standard and 100 large communities.
    let segment: Vec<u32> = (0..250).map(|i| 4_200_000_000 + i).collect();
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSequence(segment.clone()),
                    AsPathSegment::AsSequence(segment),
                ],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Communities((0..200).collect()),
            PathAttribute::LargeCommunities(
                (0..100)
                    .map(|i| LargeCommunity {
                        global_admin: 65001,
                        local_data1: i,
                        local_data2: 0,
                    })
                    .collect(),
            ),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 1, "the denied prefix is retained");
    let entry = &entries[0].1;
    assert!(
        entry.as_path.len() <= MAX_RETAINED_AS_PATH_BYTES,
        "AS-path string must be capped, got {} bytes",
        entry.as_path.len()
    );
    assert!(
        entry.as_path.ends_with(RETENTION_TRUNCATION_MARKER),
        "truncated AS-path must carry the marker"
    );
    assert!(
        entry.as_path.starts_with("4200000000 "),
        "the leading hops survive truncation"
    );
    assert_eq!(entry.communities.len(), MAX_RETAINED_COMMUNITIES);
    assert_eq!(
        entry.communities_dropped as usize,
        200 - MAX_RETAINED_COMMUNITIES,
        "dropped standard communities are counted for the surface"
    );
    assert_eq!(
        entry.large_communities.len(),
        MAX_RETAINED_LARGE_COMMUNITIES
    );
    assert_eq!(
        entry.large_communities_dropped as usize,
        100 - MAX_RETAINED_LARGE_COMMUNITIES,
        "dropped large communities are counted for the surface"
    );
}

/// LAN-472 pin: the store is bounded by the configured capacity — a
/// reject storm converges on the most recent rejections instead of
/// growing without bound (this repo's reload-stall week was exactly
/// this class of bug).
#[tokio::test]
async fn reject_retention_cap_evicts_oldest_reject() {
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |config| {
        config.reject_retention_capacity = 2;
    });
    let first = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let third = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session
        .process_update(retention_update(&[first, second, third], &[]))
        .await;
    let keys: Vec<RetentionKey> = session
        .rejected_routes
        .snapshot()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(keys.len(), 2, "bounded at the configured capacity");
    assert!(
        !keys.contains(&retention_key(first)),
        "oldest reject evicted under the cap"
    );
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 2);
}

/// LAN-472 pin: `[policy.reject_retention] enabled = false` records
/// nothing, and the command surface reports the disabled state as a
/// configuration fact rather than an empty answer. Break-to-red: constructing
/// despite the off switch makes the prototype-count assertion fail.
#[tokio::test]
async fn reject_retention_disabled_records_nothing_and_reports_disabled() {
    let denied = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |config| {
        config.reject_retention_enabled = false;
    });
    session
        .process_update(retention_update(&[denied], &[]))
        .await;
    assert_eq!(session.import_policy_routes_denied, 1);
    assert_eq!(rejected_route_prototype_builds(&session), 0);
    assert!(session.rejected_routes.is_empty());
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 0);

    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::ListRejectedRoutes { reply: reply_tx })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    let reply = reply_rx.await.expect("session replied");
    assert!(!reply.enabled, "disabled state is a configuration fact");
    assert!(reply.entries.is_empty());
}

/// LAN-472 pin: an AS_PATH-loop rejection (which funnels through the
/// shared RFC 7606 treat-as-withdraw primitive, like the RR-loop and
/// malformed-attribute paths) retains the announced identities under
/// the loop reason.
#[tokio::test]
async fn reject_retention_records_as_path_loop_reason() {
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;
    let looped = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (mut session, metrics) = retention_session_with_chain(None, |_| {});
    // AS_PATH contains our own ASN (65001) → RFC 4271 §9.1.2 loop.
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: looped,
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002, 65001])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, retention_key(looped));
    assert_eq!(entries[0].1.reason, ImportRejectReason::AsPathLoop);
    assert_eq!(entries[0].1.as_path, "65002 65001");
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 1);
}

/// LAN-472 pin: an RFC 9234 OTC ingress drop (a pre-policy hygiene
/// gate) retains the announced identity with the OTC reason token and
/// the canonical sub-reason detail. Break-to-red: constructing per rejected
/// identity makes the shared timestamp or exact build count fail.
#[tokio::test]
async fn reject_retention_records_otc_ingress_drop_with_detail() {
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;
    let first = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let (mut session, metrics) = retention_session_with_chain(None, |_| {});
    session.config.peer.local_role = Some(BgpRole::RouteServer);
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: first,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: second,
            },
        ],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::OnlyToCustomer(65002),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].1.rejected_at, entries[1].1.rejected_at);
    assert_eq!(rejected_route_prototype_builds(&session), 1);
    for (key, entry) in entries {
        assert!(key == retention_key(first) || key == retention_key(second));
        assert_eq!(entry.reason, ImportRejectReason::OtcRouteLeak);
        assert_eq!(entry.next_hop, None, "OTC does not invent a next-hop");
        assert_eq!(
            entry.detail.as_deref(),
            Some("ingress_from_customer_rsclient"),
            "the canonical OTC sub-reason token rides in the detail field"
        );
    }
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 2);
}

/// LAN-472 pin: the retention store is per-session diagnostic state —
/// `Action::SessionDown` flushes it and zeroes the gauge, mirroring the
/// ADR-0073 import-decision-cache contract.
#[tokio::test]
async fn session_down_flushes_reject_retention_and_gauge() {
    let denied = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |_| {});
    session
        .process_update(retention_update(&[denied], &[]))
        .await;
    assert_eq!(session.rejected_routes.len(), 1);
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 1);

    session.execute_actions(vec![Action::SessionDown]).await;
    assert!(
        session.rejected_routes.is_empty(),
        "reject retention must be flushed on SessionDown"
    );
    assert_eq!(
        metrics.rejected_routes_retained("10.0.0.2"),
        0,
        "the gauge follows the flush"
    );
}

/// LAN-472 pin: the `ListRejectedRoutes` session command returns the
/// retained entries (sorted by key) with the enabled flag and the
/// configured capacity, and is a read — it must not move the
/// permit/deny counters or the store.
#[tokio::test]
async fn list_rejected_routes_command_returns_sorted_snapshot() {
    let a = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let b = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, _metrics) = retention_session_with_chain(Some(chain), |_| {});
    session.process_update(retention_update(&[a, b], &[])).await;

    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::ListRejectedRoutes { reply: reply_tx })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    let reply = reply_rx.await.expect("session replied");
    assert!(reply.enabled);
    assert_eq!(
        reply.capacity,
        super::rejected_routes::DEFAULT_REJECT_RETENTION_CAPACITY
    );
    let keys: Vec<RetentionKey> = reply.entries.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        keys,
        vec![retention_key(b), retention_key(a)],
        "entries are sorted by key for stable output"
    );
    assert_eq!(
        session.rejected_routes.len(),
        2,
        "the query is a read — the store is untouched"
    );
}
