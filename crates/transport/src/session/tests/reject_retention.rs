use super::*;

fn named_rpol_reject_chain() -> PolicyChain {
    let file =
        rustbgpd_policy::rpol::RpolFile::parse("policy member-import { term deny-all { reject } }")
            .expect("clean rpol");
    let mut store = rustbgpd_policy::sets::SetStore::new();
    let compiled = file
        .compile_policy("member-import", &[], &mut store)
        .expect("policy exists");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "member-import".to_string(),
        Arc::new(compiled),
    )])
}

async fn query_policy_reject_counts(
    session: &mut PeerSession,
) -> Option<crate::PolicyRejectCounts> {
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    state.await.unwrap().policy_reject_counts
}

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
    assert_eq!(
        session
            .config
            .neighbor_counters
            .import_policy_routes_permitted(),
        2
    );
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    assert_eq!(
        state.await.unwrap().policy_reject_counts,
        Some(crate::PolicyRejectCounts::default()),
        "enabled empty retention is authoritatively zero"
    );
}

/// Body and MP policy denies in one UPDATE share one bounded prototype and
/// timestamp; the next UPDATE constructs fresh state from its own attributes.
/// Break-to-red: per-identity construction changes the first count/timestamps;
/// cross-UPDATE reuse makes the third entry retain the first UPDATE's summary.
#[tokio::test]
async fn reject_retention_shares_prototype_across_body_and_mp_policy_denies() {
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let chain = named_rpol_reject_chain();
    let (mut session, _metrics) = retention_session_with_chain(Some(chain), |_| {});
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let body = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:505::".parse().unwrap(), 64));
    let later = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    let first_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![100]),
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: vec![NlriEntry { path_id: 0, prefix }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
            vpn_flowspec_announced: vec![],
        })),
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
    assert!(
        entries
            .iter()
            .all(|(_, entry)| { entry.detail.as_deref() == Some("member-import:deny-all") })
    );
    assert!(entries.iter().any(|(key, _)| *key == retention_key(body)));
    assert!(entries.iter().any(|(key, _)| {
        *key == RetentionKey {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            prefix,
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
    assert_eq!(
        query_policy_reject_counts(&mut session).await,
        Some(crate::PolicyRejectCounts {
            ipv4_unicast: 2,
            ipv6_unicast: 1,
        })
    );
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
    let (reply, count) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    let state = count.await.unwrap();
    assert_eq!(state.rejected_routes_retained, 1);
    assert_eq!(
        state.policy_reject_counts,
        Some(crate::PolicyRejectCounts {
            ipv4_unicast: 1,
            ipv6_unicast: 0,
        })
    );

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
    let (reply, count) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    let state = count.await.unwrap();
    assert_eq!(state.rejected_routes_retained, 0);
    assert_eq!(
        state.policy_reject_counts,
        Some(crate::PolicyRejectCounts::default()),
        "removing the final reject restores authoritative zero"
    );
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
            PathAttribute::CommunitiesPartial(vec![999]),
            PathAttribute::LargeCommunitiesPartial(vec![rustbgpd_wire::LargeCommunity::new(
                65_002, 1, 999,
            )]),
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
    assert_eq!(
        entries[0].1.large_communities,
        vec![rustbgpd_wire::LargeCommunity::new(65_002, 1, 999)],
        "the rejected UPDATE's Partial Large Communities are retained for the surface"
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
    assert_eq!(session.rejected_routes.evictions_since_reset(), 1);
    assert_eq!(metrics.rejected_route_retention_evictions("10.0.0.2"), 1);
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    assert_eq!(
        state.await.unwrap().policy_reject_counts,
        None,
        "the first eviction makes retained policy-reject counts incomplete"
    );

    session
        .process_update(retention_update(&[third], &[]))
        .await;
    assert_eq!(
        session.rejected_routes.evictions_since_reset(),
        1,
        "refresh is not loss"
    );
    assert_eq!(metrics.rejected_route_retention_evictions("10.0.0.2"), 1);
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
    assert_eq!(
        session
            .config
            .neighbor_counters
            .import_policy_routes_denied(),
        1
    );
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
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply: reply_tx })
        .await;
    assert_eq!(
        reply_rx.await.unwrap().policy_reject_counts,
        None,
        "disabled retention cannot authoritatively count policy rejects"
    );
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

/// RFC 9774: an `AS_SET` announcement is treat-as-withdraw at decode, before
/// import policy. Behind a deny-all import chain it is retained under the
/// `treat_as_withdraw` reason, never `policy_reject`, and import explain has
/// no decision for it. Break-to-red: letting the route reach the chain
/// retains it as `PolicyReject`, counts a policy reject, and caches a
/// decision.
#[tokio::test]
async fn as_set_announcement_is_treat_as_withdraw_not_a_policy_reject() {
    use super::import_decision_cache::LookupResult;
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (mut session, metrics) =
        retention_session_with_chain(Some(named_rpol_reject_chain()), |_| {});
    session.import_explain_enabled = true;
    // ORIGIN IGP, AS_PATH = AS_SET {65002}, NEXT_HOP 10.0.0.2.
    let attrs = vec![
        0x40, 1, 1, 0, 0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA, 0x40, 3, 4, 10, 0, 0, 2,
    ];
    session
        .process_update(rfc7606_update(attrs, &[prefix]))
        .await;

    let entries = session.rejected_routes.snapshot();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, retention_key(prefix));
    assert_eq!(entries[0].1.reason, ImportRejectReason::TreatAsWithdraw);
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 1);
    assert_eq!(
        query_policy_reject_counts(&mut session).await,
        Some(crate::PolicyRejectCounts::default())
    );
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
    assert!(matches!(
        session
            .import_decision_cache
            .lookup(&retention_key(prefix), session.import_policy_generation),
        LookupResult::NotSeen
    ));
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
    let displaced = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (mut session, metrics) = retention_session_with_chain(Some(chain), |config| {
        config.reject_retention_capacity = 1;
    });
    session
        .process_update(retention_update(&[denied, displaced], &[]))
        .await;
    assert_eq!(session.rejected_routes.len(), 1);
    assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 1);
    assert_eq!(session.rejected_routes.evictions_since_reset(), 1);

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
    assert_eq!(session.rejected_routes.evictions_since_reset(), 0);
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    assert_eq!(
        state.await.unwrap().policy_reject_counts,
        Some(crate::PolicyRejectCounts::default()),
        "session reset restores enabled-store zero authority"
    );
}

/// The crate README must expose the current completeness contract in
/// the one bounded feature bullet operators and embedders will read.
#[test]
fn transport_readme_pins_rejected_route_retention_completeness() {
    const README: &str = include_str!("../../../README.md");
    const START: &str = "- **Rejected-route retention**";
    const END: &str = "- **Private AS removal**";

    assert_eq!(README.matches(START).count(), 1, "unique section start");
    assert_eq!(README.matches(END).count(), 1, "unique section end");
    let start = README.find(START).expect("rejected-route retention bullet");
    let relative_end = README[start..]
        .find(END)
        .expect("private-AS bullet follows rejected-route retention");
    let section = README[start..start + relative_end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for clause in [
        "**On by default:** `TransportConfig::reject_retention_enabled` defaults to `true`",
        "unlike the opt-in import-explain cache above",
        "The `ListRejectedRoutes` reply reports `retention_enabled`, `capacity`, and `evictions_since_reset`",
        "`retention_enabled = false` makes an empty result a configuration fact",
        "zero evictions proves no retained rejection was displaced by capacity since the session reset",
        "a nonzero count means the bounded listing may be incomplete",
        "Entries and the eviction count are diagnostic state and reset with the session",
    ] {
        assert!(section.contains(clause), "missing README clause: {clause}");
    }
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
    let super::rejected_routes::RejectedRoutesReply {
        enabled,
        capacity,
        evictions_since_reset,
        entries,
    } = reply_rx.await.expect("session replied");
    assert!(enabled);
    assert_eq!(
        capacity,
        super::rejected_routes::DEFAULT_REJECT_RETENTION_CAPACITY
    );
    assert_eq!(evictions_since_reset, 0);
    let keys: Vec<RetentionKey> = entries.iter().map(|(k, _)| k.clone()).collect();
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

async fn query_pre_policy_route_counts(
    session: &mut PeerSession,
) -> Option<crate::PrePolicyRouteCounts> {
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    state.await.unwrap().pre_policy_route_counts
}

fn pre_policy_v4(count: u64) -> crate::PrePolicyRouteCounts {
    crate::PrePolicyRouteCounts {
        ipv4_unicast: count,
        ipv6_unicast: 0,
    }
}

fn deny_prefix_chain(denied: &[Ipv4Prefix]) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: denied
            .iter()
            .map(|&prefix| retention_statement(Some(Prefix::V4(prefix)), PolicyAction::Deny))
            .collect(),
        default_action: PolicyAction::Permit,
    }])
}

/// The pre-policy count is accepted routes plus every retained rejection the
/// peer still announces: a policy deny and an `AS_PATH` loop stay counted, a
/// treat-as-withdraw removes the route, and a withdrawal removes it.
/// Break-to-red: counting only policy rejects drops the loop (3 → 2 after the
/// loop); counting treat-as-withdraw keeps the third value at 4.
#[tokio::test]
async fn pre_policy_route_counts_follow_accepts_rejects_and_withdrawals() {
    let denied = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25);
    let looped = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (mut session, _metrics) =
        retention_session_with_chain(Some(deny_prefix_chain(&[denied])), |_| {});
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(0))
    );

    session
        .process_update(retention_update(&[denied, first, second], &[]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(3))
    );

    session
        .process_update(UpdateMessage::build(
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
        ))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(4)),
        "a looped route stays in the pre-policy Adj-RIB-In"
    );

    // RFC 9774 AS_SET: treat-as-withdraw replaces the accepted `first`.
    let as_set_attrs = vec![
        0x40, 1, 1, 0, 0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA, 0x40, 3, 4, 10, 0, 0, 2,
    ];
    session
        .process_update(rfc7606_update(as_set_attrs, &[first]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(3)),
        "treat-as-withdraw removes the route from the pre-policy count"
    );

    session
        .process_update(retention_update(&[], &[denied, second]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(1))
    );
}

/// Without retention, or after the first eviction, rejected routes the peer
/// still announces are unknown, so the count is omitted rather than reported
/// as the accepted count. Break-to-red: dropping either authority check
/// reports `Some`.
#[tokio::test]
async fn pre_policy_route_counts_require_authoritative_retention() {
    let denied = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

    let (mut disabled, _metrics) =
        retention_session_with_chain(Some(deny_prefix_chain(&[denied])), |config| {
            config.reject_retention_enabled = false;
        });
    disabled
        .process_update(retention_update(&[denied, accepted], &[]))
        .await;
    assert_eq!(query_pre_policy_route_counts(&mut disabled).await, None);

    let (mut evicting, _metrics) =
        retention_session_with_chain(Some(deny_prefix_chain(&[denied, other])), |config| {
            config.reject_retention_capacity = 1;
        });
    evicting
        .process_update(retention_update(&[denied, accepted], &[]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut evicting).await,
        Some(pre_policy_v4(2))
    );
    evicting
        .process_update(retention_update(&[other], &[]))
        .await;
    assert_eq!(evicting.rejected_routes.evictions_since_reset(), 1);
    assert_eq!(
        query_pre_policy_route_counts(&mut evicting).await,
        None,
        "the evicted rejection is still announced but no longer counted"
    );
    evicting
        .process_update(retention_update(&[], &[other]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut evicting).await,
        None,
        "authority returns only with a session reset"
    );
}

/// Max-prefix `Block` withholds a policy-accepted announcement from both the
/// accepted set and the store, and unicast Add-Path receive counts paths in
/// the store but prefixes in the accepted set; either omits the count while
/// retention itself stays authoritative. Break-to-red: dropping the latch or
/// the Add-Path check reports `Some`.
#[tokio::test]
async fn pre_policy_route_counts_omit_block_withholding_and_add_path() {
    let first = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    let (mut blocking, _metrics) = retention_session_with_chain(None, |config| {
        config.max_prefix_action = MaxPrefixAction::Block;
        config.max_prefixes_ipv4 = Some(1);
    });
    blocking
        .process_update(retention_update(&[first], &[]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut blocking).await,
        Some(pre_policy_v4(1))
    );
    blocking
        .process_update(retention_update(&[second], &[]))
        .await;
    assert_eq!(
        blocking.known_prefix_count(),
        1,
        "the second route is withheld"
    );
    assert_eq!(query_pre_policy_route_counts(&mut blocking).await, None);
    assert_eq!(
        query_policy_reject_counts(&mut blocking).await,
        Some(crate::PolicyRejectCounts::default()),
        "retention itself remains authoritative"
    );

    let (mut add_path, _metrics) = retention_session_with_chain(None, |_| {});
    let mut negotiated = negotiated_session(65002, false);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Receive);
    install_test_negotiated_session(&mut add_path, negotiated);
    assert_eq!(query_pre_policy_route_counts(&mut add_path).await, None);
    assert_eq!(
        query_policy_reject_counts(&mut add_path).await,
        Some(crate::PolicyRejectCounts::default())
    );
}

fn policy_rejects_v4(count: u64) -> crate::PolicyRejectCounts {
    crate::PolicyRejectCounts {
        ipv4_unicast: count,
        ipv6_unicast: 0,
    }
}

fn retained_v4_prefixes(session: &PeerSession) -> Vec<Prefix> {
    session
        .rejected_routes
        .snapshot()
        .into_iter()
        .map(|(key, _)| key.prefix)
        .collect()
}

/// Two policy denies and one accept, then an enhanced refresh opened on a
/// live RIB channel that replays the accept and only `kept`.
async fn refresh_session_replaying_one_rejection(
    omitted: Ipv4Prefix,
    kept: Ipv4Prefix,
    accepted: Ipv4Prefix,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let (mut session, _metrics) =
        retention_session_with_chain(Some(deny_prefix_chain(&[omitted, kept])), |_| {});
    let (rib_tx, rib_rx) = mpsc::channel(64);
    session.rib_tx = rib_tx;
    session
        .process_update(retention_update(&[omitted, kept, accepted], &[]))
        .await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(3))
    );
    assert_eq!(
        query_policy_reject_counts(&mut session).await,
        Some(policy_rejects_v4(2))
    );

    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .process_update(retention_update(&[kept, accepted], &[]))
        .await;
    (session, rib_rx)
}

/// RFC 7313: a rejection the peer leaves out of an enhanced refresh is stale
/// at `EoRR` and leaves the rejected-route store together with the accepted
/// stale set, so BMP types 22 and 7/18/19 stay exact across the refresh.
/// Before `EoRR` the omitted rejection is still counted, like an accepted
/// stale route. Break-to-red: dropping the store sweep leaves `omitted`
/// retained and the counts at 3 and 2.
#[tokio::test]
async fn enhanced_refresh_sweeps_omitted_rejection_at_eorr() {
    let omitted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let (mut session, _rib_rx) =
        refresh_session_replaying_one_rejection(omitted, kept, accepted).await;
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(3)),
        "the omitted rejection is stale, not yet purged, inside the window"
    );

    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(retained_v4_prefixes(&session), vec![Prefix::V4(kept)]);
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(2))
    );
    assert_eq!(
        query_policy_reject_counts(&mut session).await,
        Some(policy_rejects_v4(1))
    );
}

/// The timed-out window closes on the same admitted boundary as `EoRR` and
/// sweeps the store the same way. While the RIB cannot admit the timeout the
/// window stays open and nothing is swept, so the count still includes the
/// stale rejection alongside the unswept accepted set. Break-to-red: dropping
/// the store sweep leaves the count at 3 after the admitted timeout.
#[tokio::test(start_paused = true)]
async fn enhanced_refresh_timeout_sweeps_omitted_rejection_only_when_admitted() {
    let omitted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let kept = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let (mut session, rib_rx) =
        refresh_session_replaying_one_rejection(omitted, kept, accepted).await;
    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;

    let (live_tx, mut live_rx) = mpsc::channel(64);
    drop(rib_rx);
    assert_eq!(session.expire_refresh_accounting_windows(), Err(()));
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(session.rejected_routes.len(), 2);
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(3))
    );

    session.rib_tx = live_tx;
    session.expire_refresh_accounting_windows().unwrap();
    assert!(matches!(
        live_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(retained_v4_prefixes(&session), vec![Prefix::V4(kept)]);
    assert_eq!(
        query_pre_policy_route_counts(&mut session).await,
        Some(pre_policy_v4(2))
    );
    assert_eq!(
        query_policy_reject_counts(&mut session).await,
        Some(policy_rejects_v4(1))
    );
}

/// A rejection re-sent inside the window is a replay even when an eviction
/// in the same window drops a stale identity first; the sweep then finds that
/// identity absent without the per-reason counters drifting, and the counts
/// stay omitted because the store lost authority. Break-to-red: dropping the
/// in-window replay sweeps the re-rejected `first`.
#[tokio::test]
async fn enhanced_refresh_sweep_keeps_replays_across_eviction() {
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let third = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 102, 0), 24);
    let (mut session, _metrics) =
        retention_session_with_chain(Some(deny_prefix_chain(&[first, second, third])), |config| {
            config.reject_retention_capacity = 2;
        });
    session
        .process_update(retention_update(&[first, second], &[]))
        .await;
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .process_update(retention_update(&[first], &[]))
        .await;
    session
        .process_update(retention_update(&[third], &[]))
        .await;
    assert_eq!(session.rejected_routes.evictions_since_reset(), 1);
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(
        retained_v4_prefixes(&session),
        vec![Prefix::V4(first), Prefix::V4(third)]
    );
    assert_eq!(session.rejected_routes.policy_reject_counts(), (2, 0));
    assert_eq!(query_pre_policy_route_counts(&mut session).await, None);
}

/// Policy denies the route while it carries community 999.
fn community_tagged_update(prefix: Ipv4Prefix) -> UpdateMessage {
    UpdateMessage::build(
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
    )
}

/// A route import policy accepts is no longer a policy reject, even when
/// max-prefix `Block` then withholds it, so its stale entry leaves the store
/// (RFC 9972 type 22 and `--rejected`). Max-prefix accounting is unchanged:
/// withheld by the accepted bound, `held` still holds its received slot as a
/// rejected identity; withheld by a full received bound, it never had one.
/// Break-to-red: removing store entries only for the routes `Block` keeps
/// leaves `held` retained under both bounds.
#[tokio::test]
async fn block_withheld_policy_accept_clears_stale_reject() {
    let first = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let held = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut deny_communities = retention_statement(None, PolicyAction::Deny);
    deny_communities.match_community =
        vec![rustbgpd_policy::CommunityMatch::Standard { value: 999 }];
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![deny_communities],
        default_action: PolicyAction::Permit,
    }]);
    // (accepted bound, received bound, `held` keeps its received slot)
    for (accepted, received, keeps_received_slot) in [(Some(1), 3, true), (None, 1, false)] {
        let (mut session, metrics) = retention_session_with_chain(Some(chain.clone()), |config| {
            config.max_prefix_action = MaxPrefixAction::Block;
            config.max_prefixes_ipv4 = accepted;
            config.max_prefixes_received_ipv4 = Some(received);
        });
        session
            .process_update(retention_update(&[first], &[]))
            .await;
        session.process_update(community_tagged_update(held)).await;
        assert_eq!(retained_v4_prefixes(&session), vec![Prefix::V4(held)]);

        session.process_update(retention_update(&[held], &[])).await;
        assert_eq!(session.known_prefix_count(), 1, "`held` is withheld");
        assert!(
            session.rejected_routes.is_empty(),
            "a policy accept clears the stale reject even when `Block` withholds it"
        );
        assert_eq!(
            query_policy_reject_counts(&mut session).await,
            Some(crate::PolicyRejectCounts::default())
        );
        assert_eq!(metrics.rejected_routes_retained("10.0.0.2"), 0);
        assert_eq!(
            session.has_rejected_identity(Prefix::V4(held)),
            keeps_received_slot
        );
    }
}

/// The refresh sweep is per family: an IPv6 rejection survives an IPv4
/// enhanced refresh that omits every rejection. Break-to-red: dropping the
/// AFI/SAFI filter in `RejectedRouteStore::family_keys` sweeps the IPv6
/// entry at the IPv4 `EoRR`.
#[tokio::test]
async fn ipv4_enhanced_refresh_keeps_ipv6_rejection() {
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, _metrics) =
        retention_session_with_chain(Some(named_rpol_reject_chain()), |_| {});
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let v4 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:505::".parse().unwrap(), 64));
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: v4,
            }],
            &[],
            &[
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    next_hop: "2001:db8::2".parse().unwrap(),
                    link_local_next_hop: None,
                    announced: vec![NlriEntry {
                        path_id: 0,
                        prefix: v6,
                    }],
                    flowspec_announced: vec![],
                    evpn_announced: vec![],
                    bgpls_announced: vec![],
                    labeled_announced: vec![],
                    vpn_announced: vec![],
                    rtc_announced: vec![],
                    vpn_flowspec_announced: vec![],
                })),
            ],
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    assert_eq!(session.rejected_routes.policy_reject_counts(), (1, 1));

    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    let retained: Vec<Prefix> = session
        .rejected_routes
        .snapshot()
        .into_iter()
        .map(|(key, _)| key.prefix)
        .collect();
    assert_eq!(retained, vec![v6]);
    assert_eq!(session.rejected_routes.policy_reject_counts(), (0, 1));
}
