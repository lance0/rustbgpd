//! Scoped controller lifecycle against the real RIB for both VPN AFIs.

use super::tests::{
    AcceptAllEncoder, flowspec_rate, flowspec_rule_components, lease_conflict_reason,
    publish_managed, rib_service_with_roster,
};
use super::*;
use crate::proto::injection_service_server::InjectionService as _;
use crate::proto::rib_service_server::RibService as _;
use crate::rib_service::RibService;

const FAMILIES: [proto::AddressFamily; 4] = [
    proto::AddressFamily::Ipv4Flowspec,
    proto::AddressFamily::Ipv6Flowspec,
    proto::AddressFamily::L3vpnIpv4Flowspec,
    proto::AddressFamily::L3vpnIpv6Flowspec,
];
const RD_A: &str = "65000:1";
const RD_B: &str = "0x00020000fde80001";
const SCOPE_RTS: [u64; 2] = [0x0002_fde8_0000_0001, 0x0202_0000_fde8_0309];

fn rule(family: proto::AddressFamily, rd: &str) -> proto::AddFlowSpecRequest {
    proto::AddFlowSpecRequest {
        afi_safi: family as i32,
        // Identical non-prefix components make the AFI discriminator load-bearing.
        components: flowspec_rule_components()[1..].to_vec(),
        actions: vec![flowspec_rate(0.0)],
        rd: rd.into(),
        route_targets: if rd.is_empty() {
            vec![]
        } else {
            vec!["65000:1".into()]
        },
        ..Default::default()
    }
}

fn delete(rule: &proto::AddFlowSpecRequest, owner: &str) -> proto::DeleteFlowSpecRequest {
    proto::DeleteFlowSpecRequest {
        afi_safi: rule.afi_safi,
        components: rule.components.clone(),
        rd: rule.rd.clone(),
        owner: owner.into(),
        ..Default::default()
    }
}

async fn add(
    service: &InjectionService,
    rule: proto::AddFlowSpecRequest,
    leased: bool,
) -> Result<proto::FlowSpecInjectOutcome, Status> {
    if leased {
        service
            .add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                rule: Some(rule),
                lease: Some(proto::InjectionLease {
                    owner: "ctl".into(),
                    lease_seconds: 60,
                }),
            }))
            .await
            .map(|response| response.into_inner().result.unwrap().outcome())
    } else {
        service
            .add_flow_spec(Request::new(rule))
            .await
            .map(|response| response.into_inner().outcome())
    }
}

async fn local(rib: &RibService) -> Vec<proto::FlowSpecRouteEntry> {
    let mut routes = Vec::new();
    for family in FAMILIES {
        let page = rib
            .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                afi_safi: family as i32,
                received_peer_address: "0.0.0.0".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(page.received_view);
        routes.extend(
            page.received_routes
                .into_iter()
                .map(|row| row.route.unwrap()),
        );
    }
    routes.sort_by(|a, b| (a.afi_safi, &a.rd).cmp(&(b.afi_safi, &b.rd)));
    routes
}

fn from_read_back(row: &proto::FlowSpecRouteEntry, typed_rts: bool) -> proto::AddFlowSpecRequest {
    proto::AddFlowSpecRequest {
        afi_safi: row.afi_safi,
        components: row.components.clone(),
        communities: row.communities.clone(),
        extended_communities: row
            .extended_communities
            .iter()
            .copied()
            .filter(|value| !typed_rts || !SCOPE_RTS.contains(value))
            .collect(),
        ipv6_extended_communities: row.ipv6_extended_communities.clone(),
        rd: row.rd.clone(),
        route_targets: if typed_rts {
            row.route_targets.clone()
        } else {
            vec![]
        },
        // The raw list already contains every typed action.
        ..Default::default()
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one real-RIB lifecycle checks both ownership modes and scope isolation"
)]
async fn vpn_flowspec_plain_and_leased_crud_preserve_rd_and_afi_siblings() {
    for leased in [false, true] {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let task = tokio::spawn(manager.run());
        let service =
            InjectionService::new(rib_tx.clone(), AuthTier::OperatorOnly, Arc::clone(&leases));
        let (rib, _roster) = rib_service_with_roster(rib_tx.clone());
        let rib = rib.with_injection_leases(leases);
        for family in FAMILIES {
            let rds: &[&str] = if (family as i32) < 13 {
                &[""]
            } else {
                &[RD_A, RD_B]
            };
            for rd in rds {
                assert_eq!(
                    add(&service, rule(family, rd), leased).await.unwrap(),
                    proto::FlowSpecInjectOutcome::Created
                );
                assert_eq!(
                    add(&service, rule(family, rd), leased).await.unwrap(),
                    proto::FlowSpecInjectOutcome::Unchanged
                );
            }
        }
        assert_eq!(local(&rib).await.len(), 6);
        for family in &FAMILIES[2..] {
            let target = rule(*family, RD_A);
            let before = local(&rib).await;
            let wrong = service
                .delete_flow_spec(Request::new(delete(&target, "other")))
                .await
                .unwrap_err();
            assert_eq!(
                lease_conflict_reason(&wrong),
                if leased {
                    "OWNER_MISMATCH"
                } else {
                    "KEY_UNOWNED"
                }
            );
            let wrong_add = service
                .add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                    rule: Some(target.clone()),
                    lease: Some(proto::InjectionLease {
                        owner: "other".into(),
                        lease_seconds: 60,
                    }),
                }))
                .await
                .unwrap_err();
            assert_eq!(
                lease_conflict_reason(&wrong_add),
                if leased {
                    "OWNER_MISMATCH"
                } else {
                    "KEY_UNOWNED"
                }
            );
            assert_eq!(local(&rib).await, before, "refusals retain every sibling");

            let mut replaced = target.clone();
            replaced.route_targets = vec!["65000:2".into()];
            assert_eq!(
                add(&service, replaced, leased).await.unwrap(),
                proto::FlowSpecInjectOutcome::Replaced
            );
            let after = local(&rib).await;
            let is_target =
                |row: &&proto::FlowSpecRouteEntry| row.afi_safi == *family as i32 && row.rd == RD_A;
            assert_eq!(
                after.iter().find(is_target).unwrap().route_targets,
                ["65000:2"]
            );
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
            let request = delete(&target, if leased { "ctl" } else { "" });
            assert_eq!(
                service
                    .delete_flow_spec(Request::new(request.clone()))
                    .await
                    .unwrap()
                    .into_inner()
                    .outcome(),
                proto::FlowSpecDeleteOutcome::Deleted
            );
            assert_eq!(
                local(&rib).await,
                before
                    .into_iter()
                    .filter(|row| !(row.afi_safi == *family as i32 && row.rd == RD_A))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                service
                    .delete_flow_spec(Request::new(request.clone()))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
            assert_eq!(
                service
                    .delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                        allow_missing: true,
                        ..request
                    }))
                    .await
                    .unwrap()
                    .into_inner()
                    .outcome(),
                proto::FlowSpecDeleteOutcome::NotPresent
            );
        }
        drop((service, rib, rib_tx));
        task.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "typed and raw replay must preserve one payload across plain and leased lifecycles"
)]
async fn vpn_flowspec_typed_or_raw_read_back_is_unchanged_with_interleaved_communities() {
    for leased in [false, true] {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let task = tokio::spawn(manager.run());
        let service =
            InjectionService::new(rib_tx.clone(), AuthTier::OperatorOnly, Arc::clone(&leases));
        let rib = RibService::new(rib_tx.clone()).with_injection_leases(leases);
        let rate = flowspec_action_to_ec(&flowspec_rate(123.0))
            .unwrap()
            .unwrap()
            .as_u64();
        let non_rts = [
            0x1234_5678_90ab_cdef,
            rate,
            0x2345_6789_0abc_def0,
            0x1234_5678_90ab_cdef,
        ];
        for family in &FAMILIES[2..] {
            let mut request = rule(*family, RD_B);
            request.actions.clear();
            request.route_targets.clear();
            request.communities = vec![123, 456, 123];
            request.extended_communities = vec![
                non_rts[0],
                SCOPE_RTS[1],
                non_rts[1],
                non_rts[2],
                SCOPE_RTS[0],
                non_rts[3],
            ];
            request.ipv6_extended_communities = vec![vec![0x7f; 20], vec![0x7f; 20]];
            assert_eq!(
                add(&service, request.clone(), leased).await.unwrap(),
                proto::FlowSpecInjectOutcome::Created
            );
            let rows = local(&rib).await;
            let row = rows
                .iter()
                .find(|row| row.afi_safi == *family as i32)
                .unwrap();
            assert_eq!(row.rd, RD_B);
            assert_eq!(row.route_targets, ["65000:1", "0.65000:777"]);
            assert_eq!(
                row.extended_communities
                    .iter()
                    .copied()
                    .filter(|value| !SCOPE_RTS.contains(value))
                    .collect::<Vec<_>>(),
                non_rts
            );
            assert_eq!(
                row.ipv6_extended_communities,
                request.ipv6_extended_communities
            );
            assert_eq!(row.communities, request.communities);
            assert_eq!(row.actions, vec![flowspec_rate(123.0)]);
            for typed in [true, false] {
                assert_eq!(
                    add(&service, from_read_back(row, typed), leased)
                        .await
                        .unwrap(),
                    proto::FlowSpecInjectOutcome::Unchanged
                );
            }
            let mut duplicate = from_read_back(row, false);
            duplicate.route_targets.clone_from(&row.route_targets);
            assert_eq!(
                add(&service, duplicate, leased).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
            assert_eq!(local(&rib).await, rows);
            let mut repeated_raw = from_read_back(row, false);
            repeated_raw.extended_communities.push(SCOPE_RTS[0]);
            assert_eq!(
                add(&service, repeated_raw, leased).await.unwrap(),
                proto::FlowSpecInjectOutcome::Replaced
            );
            let repeated_rows = local(&rib).await;
            let repeated = repeated_rows
                .iter()
                .find(|row| row.afi_safi == *family as i32)
                .unwrap();
            assert_eq!(
                repeated.route_targets,
                ["65000:1", "65000:1", "0.65000:777"]
            );
            assert_eq!(
                repeated
                    .extended_communities
                    .iter()
                    .filter(|value| **value == SCOPE_RTS[0])
                    .count(),
                2
            );
            assert_eq!(
                add(&service, from_read_back(repeated, false), leased)
                    .await
                    .unwrap(),
                proto::FlowSpecInjectOutcome::Unchanged
            );
            assert_eq!(
                add(&service, from_read_back(repeated, true), leased)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
            assert_eq!(local(&rib).await, repeated_rows);
        }
        drop((service, rib, rib_tx));
        task.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one owner walks and echo-deletes global, VPN and unicast keys without losing scope"
)]
async fn vpn_flowspec_page_one_lease_keys_echo_delete_only_the_listed_scope() {
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let manager = rustbgpd_rib::RibManager::new(
        rib_rx,
        mpsc::channel(1).1,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let leases = manager.injection_leases();
    let task = tokio::spawn(manager.run());
    let service =
        InjectionService::new(rib_tx.clone(), AuthTier::OperatorOnly, Arc::clone(&leases));
    let reader =
        InjectionService::new(rib_tx.clone(), AuthTier::SensitiveRead, Arc::clone(&leases));
    let rib = RibService::new(rib_tx.clone()).with_injection_leases(leases);
    let generation = service
        .add_leased_path(Request::new(proto::AddLeasedPathRequest {
            path: Some(proto::AddPathRequest {
                prefix: "192.0.2.1".into(),
                prefix_length: 32,
                next_hop: "0.0.0.0".into(),
                ..Default::default()
            }),
            lease: Some(proto::InjectionLease {
                owner: "ctl".into(),
                lease_seconds: 60,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .generation;
    let mut expected = Vec::new();
    for family in FAMILIES {
        let rds: &[&str] = if (family as i32) < 13 {
            &[""]
        } else {
            &[RD_A, RD_B]
        };
        for rd in rds {
            add(&service, rule(family, rd), true).await.unwrap();
            expected.push((family as i32, (*rd).to_string()));
        }
    }
    let mut token = String::new();
    let mut keys = Vec::new();
    loop {
        let page = reader
            .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                page_size: 1,
                page_token: token,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.keys.len(), 1);
        assert_eq!(page.generation, generation);
        assert_eq!(page.keys[0].generation, generation);
        assert_eq!(page.keys[0].lease_remaining_ms, 60_000);
        assert!(!keys.contains(&page.keys[0].key), "a page repeated a key");
        keys.push(page.keys[0].key.clone());
        token = page.next_page_token;
        if token.is_empty() {
            break;
        }
        assert!(keys.len() < 7, "the walk did not terminate");
    }
    assert_eq!(keys.len(), 7);
    let mut actual: Vec<_> = keys
        .iter()
        .filter_map(|key| match key {
            Some(proto::leased_key::Key::FlowSpec(key)) => Some((key.afi_safi, key.rd.clone())),
            _ => None,
        })
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    // The old projection loses the RD; both VPN families must refuse it.
    for family in &FAMILIES[2..] {
        let before = local(&rib).await;
        let mut request = delete(&rule(*family, RD_A), "ctl");
        request.rd.clear();
        assert_eq!(
            service
                .delete_flow_spec(Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(local(&rib).await, before);
    }
    for key in keys.into_iter().rev() {
        match key.unwrap() {
            proto::leased_key::Key::FlowSpec(key) => {
                let before = local(&rib).await;
                service
                    .delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                        afi_safi: key.afi_safi,
                        components: key.components,
                        rd: key.rd.clone(),
                        owner: "ctl".into(),
                        ..Default::default()
                    }))
                    .await
                    .unwrap();
                assert_eq!(
                    local(&rib).await,
                    before
                        .into_iter()
                        .filter(|row| !(row.afi_safi == key.afi_safi && row.rd == key.rd))
                        .collect::<Vec<_>>()
                );
            }
            proto::leased_key::Key::Path(key) => {
                service
                    .delete_path(Request::new(proto::DeletePathRequest {
                        prefix: key.prefix,
                        prefix_length: key.prefix_length,
                        path_id: key.path_id,
                        owner: "ctl".into(),
                        ..Default::default()
                    }))
                    .await
                    .unwrap();
            }
        }
    }
    assert_eq!(
        reader
            .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .keys
            .len(),
        0
    );
    drop((service, reader, rib, rib_tx));
    task.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one real peer roster checks all scope bindings and invalidation causes"
)]
async fn vpn_flowspec_export_evidence_requires_negotiation_and_fences_scope_tokens() {
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let manager = rustbgpd_rib::RibManager::new(
        rib_rx,
        mpsc::channel(1).1,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let leases = manager.injection_leases();
    let task = tokio::spawn(manager.run());
    let mut roster = crate::import_roster::ImportRosterPublisher::new();
    publish_managed(&mut roster, 3);
    let service = InjectionService::new(rib_tx.clone(), AuthTier::OperatorOnly, leases)
        .with_peer_roster(roster.reader());
    let mut outbound = Vec::new();
    for (octet, safi) in [
        (1, rustbgpd_wire::Safi::FlowSpecVpn),
        (2, rustbgpd_wire::Safi::FlowSpec),
    ] {
        let peer = PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)));
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        outbound.push(outbound_rx);
        rib_tx
            .send(RibUpdate::SetPeerExportEncoder {
                peer,
                session_id: 0,
                encoder: Arc::new(AcceptAllEncoder),
            })
            .await
            .unwrap();
        rib_tx
            .send(RibUpdate::PeerUp {
                peer,
                session_id: 0,
                peer_asn: 65_010,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                outbound_tx,
                export_policy: None,
                sendable_families: vec![(Afi::Ipv4, safi), (Afi::Ipv6, safi)],
                is_ebgp: true,
                route_reflector_client: false,
                orr_vantage: None,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: vec![],
                negotiated_llgr_families: vec![],
            })
            .await
            .unwrap();
    }
    for family in FAMILIES {
        for rd in if (family as i32) < 13 {
            vec![""]
        } else {
            vec![RD_A, RD_B]
        } {
            add(&service, rule(family, rd), false).await.unwrap();
        }
    }
    let list = |family: proto::AddressFamily, rd: &str, token: &str| {
        service.list_flow_spec_export_dispositions(Request::new(
            proto::ListFlowSpecExportDispositionsRequest {
                afi_safi: family as i32,
                components: rule(family, rd).components,
                rd: rd.into(),
                page_size: 1,
                page_token: token.into(),
                include_configured: true,
            },
        ))
    };
    for (index, family) in FAMILIES[2..].iter().enumerate() {
        for rd in [RD_A, RD_B] {
            let first = list(*family, rd, "").await.unwrap().into_inner();
            assert_eq!(
                first.peers[0].disposition,
                proto::PathExportDisposition::Committed as i32
            );
            let second = list(*family, rd, &first.next_page_token)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                (second.peers[0].disposition, second.peers[0].reason.as_str()),
                (
                    proto::PathExportDisposition::Withheld as i32,
                    "family_not_negotiated"
                )
            );
            let third = list(*family, rd, &second.next_page_token)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                (third.peers[0].disposition, third.peers[0].reason.as_str()),
                (
                    proto::PathExportDisposition::NotEstablished as i32,
                    "not_established"
                )
            );
            assert_eq!(third.next_page_token, "");
            for (other_family, other_rd) in [
                (*family, if rd == RD_A { RD_B } else { RD_A }),
                (FAMILIES[3 - index], rd),
                (FAMILIES[index], ""),
            ] {
                assert_eq!(
                    list(other_family, other_rd, &first.next_page_token)
                        .await
                        .unwrap_err()
                        .code(),
                    tonic::Code::InvalidArgument
                );
            }
            if rd == RD_A {
                let mut replacement = rule(*family, rd);
                replacement.route_targets = vec!["65000:2".into()];
                assert_eq!(
                    add(&service, replacement, false).await.unwrap(),
                    proto::FlowSpecInjectOutcome::Replaced
                );
            } else {
                service
                    .delete_flow_spec(Request::new(delete(&rule(*family, rd), "")))
                    .await
                    .unwrap();
            }
            assert_eq!(
                list(*family, rd, &first.next_page_token)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Aborted
            );
        }
        let global = list(FAMILIES[index], "", "").await.unwrap().into_inner();
        assert_eq!(
            global.peers[0].disposition,
            proto::PathExportDisposition::Withheld as i32
        );
        let global = list(FAMILIES[index], "", &global.next_page_token)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            global.peers[0].disposition,
            proto::PathExportDisposition::Committed as i32
        );
    }
    drop((service, rib_tx));
    task.await.unwrap();
}
