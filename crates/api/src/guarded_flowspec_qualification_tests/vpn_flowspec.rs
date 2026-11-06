//! VPN scope under guarded retries, queue delay and owner expiry.

use super::*;

const FAMILIES: [proto::AddressFamily; 4] = [
    proto::AddressFamily::Ipv4Flowspec,
    proto::AddressFamily::Ipv6Flowspec,
    proto::AddressFamily::L3vpnIpv4Flowspec,
    proto::AddressFamily::L3vpnIpv6Flowspec,
];
const RD_A: &str = "65000:1";
const RD_B: &str = "0x00020000fde80001";
const SCOPE_RTS: [u64; 2] = [0x0002_fde8_0000_0001, 0x0202_0000_fde8_0309];

fn scoped_rule(family: proto::AddressFamily, rd: &str) -> proto::AddFlowSpecRequest {
    let mut rule = rule("203.0.113.0/24");
    rule.afi_safi = family as i32;
    // Identical components across AFIs expose a missing family discriminator.
    rule.components = vec![proto::FlowSpecComponent {
        r#type: 4,
        value: "=80".into(),
        ..Default::default()
    }];
    rule.rd = rd.into();
    if !rd.is_empty() {
        rule.actions.clear();
        rule.extended_communities = vec![
            0x1234_5678_90ab_cdef,
            SCOPE_RTS[1],
            0x8006_0000_0000_0000,
            SCOPE_RTS[0],
            0x1234_5678_90ab_cdef,
        ];
    }
    rule
}

fn add_request(
    rule: proto::AddFlowSpecRequest,
    window: proto::MutationWindow,
    revision: u64,
) -> proto::AddGuardedFlowSpecRequest {
    proto::AddGuardedFlowSpecRequest {
        rule: Some(rule),
        lease: Some(lease("ctl", 60)),
        window: Some(window),
        revision,
    }
}

fn delete_request(
    rule: &proto::AddFlowSpecRequest,
    revision: u64,
) -> proto::DeleteGuardedFlowSpecRequest {
    proto::DeleteGuardedFlowSpecRequest {
        afi_safi: rule.afi_safi,
        components: rule.components.clone(),
        rd: rule.rd.clone(),
        owner: "ctl".into(),
        revision,
    }
}

async fn scoped_rows(rig: &Rig, local: bool) -> Vec<proto::FlowSpecRouteEntry> {
    let mut rows = Vec::new();
    for family in FAMILIES {
        let page = rig
            .rib
            .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                afi_safi: family as i32,
                received_peer_address: if local {
                    "0.0.0.0".into()
                } else {
                    String::new()
                },
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        if local {
            assert!(page.received_view);
            rows.extend(
                page.received_routes
                    .into_iter()
                    .map(|row| row.route.unwrap()),
            );
        } else {
            rows.extend(page.routes);
        }
    }
    rows.sort_by(|a, b| (a.afi_safi, &a.rd).cmp(&(b.afi_safi, &b.rd)));
    rows
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one scoped lifecycle covers retries, RT replacement, delayed delete and all sibling identities"
)]
async fn vpn_flowspec_guarded_rt_replacement_and_queued_delete_preserve_siblings() {
    let rig = Rig::start();
    let window = rig.window("ctl", 120).await;
    let other_window = rig.window("other", 120).await;
    for family in FAMILIES {
        for rd in if (family as i32) < 13 {
            vec![""]
        } else {
            vec![RD_A, RD_B]
        } {
            let response = rig
                .direct
                .add_guarded_flow_spec(Request::new(add_request(
                    scoped_rule(family, rd),
                    window,
                    1,
                )))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response.result.unwrap().outcome(),
                proto::FlowSpecInjectOutcome::Created
            );
        }
    }
    assert_eq!(scoped_rows(&rig, true).await.len(), 6);
    for family in &FAMILIES[2..] {
        let target = scoped_rule(*family, RD_A);
        let before = scoped_rows(&rig, true).await;
        let row = before
            .iter()
            .find(|row| row.afi_safi == *family as i32 && row.rd == RD_A)
            .unwrap();
        assert_eq!(row.route_targets, ["65000:1", "0.65000:777"]);
        assert_eq!(
            row.extended_communities
                .iter()
                .copied()
                .filter(|value| !SCOPE_RTS.contains(value))
                .collect::<Vec<_>>(),
            [
                0x1234_5678_90ab_cdef,
                0x8006_0000_0000_0000,
                0x1234_5678_90ab_cdef
            ]
        );
        for typed in [true, false] {
            let mut retry = target.clone();
            retry.extended_communities = row
                .extended_communities
                .iter()
                .copied()
                .filter(|value| !typed || !SCOPE_RTS.contains(value))
                .collect();
            retry.route_targets = if typed {
                row.route_targets.clone()
            } else {
                vec![]
            };
            assert_eq!(
                rig.direct
                    .add_guarded_flow_spec(Request::new(add_request(retry, window, 1)))
                    .await
                    .unwrap()
                    .into_inner()
                    .result
                    .unwrap()
                    .outcome(),
                proto::FlowSpecInjectOutcome::Unchanged
            );
        }
        let mut replacement = target.clone();
        replacement
            .extended_communities
            .retain(|value| !SCOPE_RTS.contains(value));
        replacement.route_targets = vec!["65000:2".into()];
        assert_eq!(
            outcome(
                &rig.direct
                    .add_guarded_flow_spec(Request::new(add_request(
                        replacement.clone(),
                        window,
                        1
                    )))
                    .await
            ),
            refused("REVISION_MISMATCH")
        );
        let mut foreign = add_request(target.clone(), other_window, 1);
        foreign.lease = Some(lease("other", 60));
        assert_eq!(
            outcome(
                &rig.direct
                    .add_guarded_flow_spec(Request::new(foreign))
                    .await
            ),
            refused("OWNER_MISMATCH")
        );
        let mut foreign = delete_request(&target, 1);
        foreign.owner = "other".into();
        assert_eq!(
            outcome(
                &rig.direct
                    .delete_guarded_flow_spec(Request::new(foreign))
                    .await
            ),
            refused("OWNER_MISMATCH")
        );
        assert_eq!(
            outcome(
                &rig.direct
                    .add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                        rule: Some(target.clone()),
                        lease: Some(lease("ctl", 60)),
                    }))
                    .await
            ),
            refused("OWNER_MISMATCH")
        );
        assert_eq!(
            outcome(
                &rig.direct
                    .delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                        afi_safi: target.afi_safi,
                        components: target.components.clone(),
                        rd: target.rd.clone(),
                        owner: "ctl".into(),
                        ..Default::default()
                    }))
                    .await
            ),
            refused("OWNER_MISMATCH")
        );
        assert_eq!(scoped_rows(&rig, true).await, before);

        let (service, mut queued) = rig.relayed();
        let delayed = delete_request(&target, 1);
        let call = tokio::spawn(async move {
            service
                .delete_guarded_flow_spec(Request::new(delayed))
                .await
        });
        let update = queued.recv().await.unwrap();
        assert_eq!(
            rig.direct
                .delete_guarded_flow_spec(Request::new(delete_request(&target, 1)))
                .await
                .unwrap()
                .into_inner()
                .outcome(),
            proto::FlowSpecDeleteOutcome::Deleted
        );
        assert_eq!(
            rig.direct
                .add_guarded_flow_spec(Request::new(add_request(replacement, window, 2)))
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap()
                .outcome(),
            proto::FlowSpecInjectOutcome::Created
        );
        rig.rib_tx.send(update).await.unwrap();
        assert_eq!(outcome(&call.await.unwrap()), refused("REVISION_MISMATCH"));
        let after = scoped_rows(&rig, true).await;
        let is_target =
            |row: &&proto::FlowSpecRouteEntry| row.afi_safi == *family as i32 && row.rd == RD_A;
        assert_eq!(
            after
                .iter()
                .filter(|row| !is_target(row))
                .collect::<Vec<_>>(),
            before
                .iter()
                .filter(|row| !is_target(row))
                .collect::<Vec<_>>()
        );
        let row = after.iter().find(is_target).unwrap();
        assert_eq!(row.route_targets, ["65000:2"]);
        assert_eq!(
            (row.injection_owner.as_str(), row.admission_revision),
            ("guarded:ctl", Some(2))
        );
    }
    let local = scoped_rows(&rig, true).await;
    let keys = rig
        .direct
        .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
            owner: "guarded:ctl".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys.keys.len(), 6);
    for key in keys.keys {
        let Some(proto::leased_key::Key::FlowSpec(scoped)) = key.key else {
            panic!("FlowSpec key")
        };
        let row = local
            .iter()
            .find(|row| row.afi_safi == scoped.afi_safi && row.rd == scoped.rd)
            .unwrap();
        assert_eq!(row.injection_owner, "guarded:ctl");
        assert_eq!(
            key.admission_revision,
            Some(if scoped.afi_safi >= 13 && scoped.rd == RD_A {
                2
            } else {
                1
            })
        );
        assert_eq!(key.admission_revision, row.admission_revision);
        assert_eq!(key.generation, row.lease_generation);
        assert_eq!(Some(key.lease_remaining_ms), row.lease_remaining_ms);
    }
    let selected = scoped_rows(&rig, false).await;
    assert_eq!(selected.len(), local.len());
    for row in selected {
        assert_eq!(
            (
                row.injection_owner.as_str(),
                row.admission_revision,
                row.lease_generation
            ),
            ("", None, None)
        );
    }
    for family in &FAMILIES[2..] {
        let target = scoped_rule(*family, RD_A);
        for expected in [
            proto::FlowSpecDeleteOutcome::Deleted,
            proto::FlowSpecDeleteOutcome::NotPresent,
        ] {
            assert_eq!(
                rig.direct
                    .delete_guarded_flow_spec(Request::new(delete_request(&target, 2)))
                    .await
                    .unwrap()
                    .into_inner()
                    .outcome(),
                expected
            );
        }
    }
    assert_eq!(scoped_rows(&rig, true).await.len(), 4);
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn vpn_flowspec_expired_queued_window_cannot_admit_or_change_a_sibling() {
    for family in &FAMILIES[2..] {
        let rig = Rig::start();
        let live = rig.window("ctl", 120).await;
        for sibling in FAMILIES {
            let rd = if (sibling as i32) < 13 { "" } else { RD_B };
            rig.direct
                .add_guarded_flow_spec(Request::new(add_request(scoped_rule(sibling, rd), live, 1)))
                .await
                .unwrap();
        }
        let expired = rig.window("ctl", 2).await;
        let target = scoped_rule(*family, RD_A);
        let (service, mut queued) = rig.relayed();
        let request = add_request(target.clone(), expired, 1);
        let call =
            tokio::spawn(async move { service.add_guarded_flow_spec(Request::new(request)).await });
        let update = queued.recv().await.unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        let before = (
            scoped_rows(&rig, true).await,
            rig.lease("guarded:ctl").await,
        );
        rig.rib_tx.send(update).await.unwrap();
        assert_eq!(outcome(&call.await.unwrap()), refused("WINDOW_NOT_LIVE"));
        assert_eq!(
            (
                scoped_rows(&rig, true).await,
                rig.lease("guarded:ctl").await
            ),
            before
        );
        rig.direct
            .add_guarded_flow_spec(Request::new(add_request(target.clone(), live, 2)))
            .await
            .unwrap();
        let before = scoped_rows(&rig, true).await;
        assert_eq!(
            outcome(
                &rig.direct
                    .add_guarded_flow_spec(Request::new(add_request(target, expired, 1)))
                    .await
            ),
            refused("REVISION_MISMATCH")
        );
        assert_eq!(scoped_rows(&rig, true).await, before);
        rig.stop().await;
    }
}

async fn owned_add(
    rig: &Rig,
    rule: proto::AddFlowSpecRequest,
    owner: &str,
    seconds: u32,
    window: Option<proto::MutationWindow>,
) -> Option<proto::LeaseGeneration> {
    if let Some(window) = window {
        rig.direct
            .add_guarded_flow_spec(Request::new(proto::AddGuardedFlowSpecRequest {
                rule: Some(rule),
                lease: Some(lease(owner, seconds)),
                window: Some(window),
                revision: 1,
            }))
            .await
            .unwrap()
            .into_inner()
            .generation
    } else {
        rig.direct
            .add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                rule: Some(rule),
                lease: Some(lease(owner, seconds)),
            }))
            .await
            .unwrap()
            .into_inner()
            .generation
    }
}

#[tokio::test(start_paused = true)]
async fn vpn_flowspec_one_owner_shares_a_deadline_and_separate_owners_expire_independently() {
    for guarded in [false, true] {
        let rig = Rig::start();
        let window = if guarded {
            Some(rig.window("ctl", 120).await)
        } else {
            None
        };
        let owner = if guarded { "guarded:ctl" } else { "ctl" };
        let generation = owned_add(&rig, scoped_rule(FAMILIES[0], ""), "ctl", 5, window).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        for family in &FAMILIES[1..] {
            for rd in if (*family as i32) < 13 {
                vec![""]
            } else {
                vec![RD_A, RD_B]
            } {
                assert_eq!(
                    owned_add(&rig, scoped_rule(*family, rd), "ctl", 10, window).await,
                    generation
                );
            }
        }
        let keys = rig
            .direct
            .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: owner.into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(keys.keys.len(), 6);
        assert_eq!(keys.generation, generation);
        for key in keys.keys {
            assert_eq!(key.generation, generation);
            assert_eq!(
                key.lease_remaining_ms, 10_000,
                "joining one scope extends the whole owner"
            );
        }
        for (other, seconds, rd) in [("short", 5, "192.0.2.1:7"), ("long", 20, "192.0.2.1:8")] {
            let window = if guarded {
                Some(rig.window(other, 120).await)
            } else {
                None
            };
            for family in &FAMILIES[2..] {
                let other_generation =
                    owned_add(&rig, scoped_rule(*family, rd), other, seconds, window).await;
                assert_ne!(other_generation, generation);
            }
        }
        tokio::time::advance(Duration::from_secs(6)).await;
        settle().await;
        let rows = scoped_rows(&rig, true).await;
        assert_eq!(
            rows.iter()
                .filter(|row| row.injection_owner == owner)
                .count(),
            6
        );
        assert_eq!(rows.len(), 8, "only the short owner's two AFIs expired");
        assert!(
            rows.iter()
                .all(|row| !row.injection_owner.ends_with("short"))
        );
        assert_eq!(rig.lease(owner).await.unwrap().1, 4_000);
        tokio::time::advance(Duration::from_secs(5)).await;
        settle().await;
        let rows = scoped_rows(&rig, true).await;
        assert_eq!(
            rows.len(),
            2,
            "the shared owner expired in every RD and AFI"
        );
        assert!(rows.iter().all(|row| row.injection_owner.ends_with("long")));
        assert_eq!(rig.lease(owner).await, None);
        tokio::time::advance(Duration::from_secs(10)).await;
        settle().await;
        assert_eq!(scoped_rows(&rig, true).await.len(), 0);
        rig.stop().await;
    }
}
