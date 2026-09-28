use super::*;

pub(super) async fn advertised(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<FlowSpecRoute> {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedFlowSpecRoutes {
        peer,
        filter: None,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one actor sequence covers export policy, family suppression, and committed withdrawal"
)]
async fn advertised_flowspec_tracks_committed_policy_and_withdrawal() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, RouteModifications};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let task = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.1".parse().unwrap();
    let denied: IpAddr = "192.0.2.2".parse().unwrap();
    let no_family: IpAddr = "192.0.2.3".parse().unwrap();
    let added = (65000 << 16) | 0x002a;
    let mut entry = super::flowspec::flowspec_policy_statement(
        0,
        RouteModifications {
            communities_add: vec![added],
            ..Default::default()
        },
    );
    entry.match_community.clear();
    let mut receivers = Vec::new();
    for (peer, policy, families) in [
        (
            target,
            Some(PolicyChain::new(vec![Policy {
                entries: vec![entry],
                default_action: PolicyAction::Deny,
            }])),
            ipv4_flowspec_sendable(),
        ),
        (
            denied,
            Some(PolicyChain::new(vec![Policy {
                entries: vec![],
                default_action: PolicyAction::Deny,
            }])),
            ipv4_flowspec_sendable(),
        ),
        (no_family, None, vec![(Afi::Ipv4, Safi::Unicast)]),
    ] {
        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: policy,
            sendable_families: families,
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut outbound_rx).await;
        receivers.push(outbound_rx);
    }
    let local = Ipv4Addr::UNSPECIFIED;
    let mut route = make_flowspec_route(local);
    route.origin_type = crate::route::RouteOrigin::Local;
    for suppressed in [false, true, false] {
        route
            .attributes
            .retain(|attr| !matches!(attr, PathAttribute::Communities(_)));
        if suppressed {
            route.attributes.push(PathAttribute::Communities(vec![
                rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
            ]));
        }
        let (reply, rx) = oneshot::channel();
        tx.send(RibUpdate::InjectFlowSpec {
            route: route.clone(),
            reply,
        })
        .await
        .unwrap();
        rx.await.unwrap().unwrap();
        let selected = query_flowspec_routes(&tx).await;
        assert_eq!(selected.len(), 1);
        assert!(!selected[0].communities().contains(&added));
        let rows = advertised(&tx, target).await;
        assert_eq!(rows.len(), usize::from(!suppressed));
        if let Some(row) = rows.first() {
            assert_eq!(row.peer, IpAddr::V4(local));
            assert!(row.communities().contains(&added));
        }
        assert!(advertised(&tx, denied).await.is_empty());
        assert!(advertised(&tx, no_family).await.is_empty());
    }
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawFlowSpec {
        key: route.selection_key(),
        allow_missing: false,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap().unwrap();
    assert!(advertised(&tx, target).await.is_empty());
    drop(tx);
    task.await.unwrap();
}

#[test]
fn advertised_flowspec_filters_before_clone_and_cancels_filtered_walk() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let mut out = crate::adj_rib_out::AdjRibOut::new(peer);
    for n in 0..600u16 {
        let mut route = make_flowspec_route(Ipv4Addr::UNSPECIFIED);
        let [hi, lo] = n.to_be_bytes();
        let prefix = if n % 2 == 0 {
            route.afi = Afi::Ipv6;
            rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, n, 0, 0, 0, 0, 0), 48),
                offset: 0,
            })
        } else {
            rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, hi, lo, 0), 24))
        };
        route.rule = rustbgpd_wire::FlowSpecRule {
            components: vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(prefix)],
        };
        out.insert_flowspec(route);
    }
    manager.adj_ribs_out.insert(peer, out);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (reply, mut rx) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedFlowSpecRoutes {
            peer,
            filter: Some(Box::new(move |row| row.afi == afi)),
            reply,
        });
        let rows = rx.try_recv().unwrap();
        assert_eq!(rows.len(), 300);
        assert!(
            rows.iter()
                .all(|row| row.afi == afi && row.peer == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
    }
    let (reply, rx) = oneshot::channel();
    drop(rx);
    manager.handle_update(RibUpdate::QueryAdvertisedFlowSpecRoutes {
        peer,
        filter: Some(Box::new(|_| panic!("canceled query visited a row"))),
        reply,
    });
    let visits = std::cell::Cell::new(0);
    let filter: crate::update::RibRowFilter<FlowSpecRoute> = Box::new(|_| false);
    assert!(
        manager
            .collect_advertised_flowspec(peer, Some(&filter), || {
                visits.set(visits.get() + 1);
                visits.get() == 2
            })
            .is_none(),
        "an entirely filtered walk must check cancellation mid-scan"
    );
    assert_eq!(visits.get(), 2);
}

#[test]
fn advertised_flowspec_retains_prior_until_full_channel_withdrawal_commits() {
    use crate::manager::distribution::OutboundCommitBatch;
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, out_tx);
    manager
        .peer_export_encoders
        .insert(peer, permissive_test_exact_export_encoder());
    let route = make_flowspec_route(Ipv4Addr::new(192, 0, 2, 2));
    let key = route.selection_key();
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            flowspec_announce: vec![route],
            ..Default::default()
        }
    ));
    assert!(!manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            flowspec_withdraw: vec![key.clone()],
            ..Default::default()
        }
    ));
    let rows = manager
        .collect_advertised_flowspec(peer, None, || false)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].selection_key(), key);
    out_rx.try_recv().unwrap();
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            flowspec_withdraw: vec![key],
            ..Default::default()
        }
    ));
    assert!(
        manager
            .collect_advertised_flowspec(peer, None, || false)
            .unwrap()
            .is_empty()
    );
}
