//! Replies held across `RebindPeer`: an interface-only neighbor that learns
//! a new address after the RIB built a page must not move the page's rows
//! or its continuation cursor to the new address.

use super::*;

fn neighbor(addr: &str, interface: &str) -> PeerId {
    PeerId::allocate(rustbgpd_rib::PeerEndpoint::new(
        addr.parse().unwrap(),
        Some(interface),
    ))
}

async fn received_page(
    tx: &mpsc::Sender<RibUpdate>,
    after: Option<RouteQueryKey>,
    expected_version: Option<RoutePageVersion>,
) -> Result<RoutePage, RoutePageError> {
    let (reply, rx) = tokio::sync::oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope: RouteQueryScope::Received { peer: None },
        filter: None,
        after,
        expected_version,
        page_size: 1,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap()
}

/// A route page converted after its source neighbor moved renders the
/// address the row had in the RIB turn that built the page, and its
/// continuation cursor names that address too, so the cursor keeps the
/// page's position. The continuation itself is refused: `RebindPeer`
/// advances the table version.
#[tokio::test]
async fn a_route_page_held_across_a_rebind_keeps_its_endpoint_and_cursor() {
    let (tx, rx) = mpsc::channel(8);
    let manager = rustbgpd_rib::RibManager::new(
        rx,
        mpsc::channel(1).1,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let actor = tokio::spawn(manager.run());
    let moving = neighbor("fe80::1", "swp1");
    let staying = neighbor("fe80::5", "swp2");
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    for (session_id, peer) in [(1, moving), (2, staying)] {
        tx.send(RibUpdate::RoutesReceived {
            session_id,
            peer,
            announced: vec![Route {
                peer,
                ..test_route(prefix, vec![])
            }],
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
    let held = received_page(&tx, None, None).await.unwrap();
    assert!(held.has_more);
    assert_eq!(held.routes[0].peer, moving);

    tx.send(RibUpdate::RebindPeer {
        peer: moving,
        endpoint: rustbgpd_rib::PeerEndpoint::new("fe80::9".parse().unwrap(), Some("swp1")),
    })
    .await
    .unwrap();
    let fresh = received_page(&tx, None, None).await.unwrap();
    assert_eq!(
        fresh.routes[0].peer, staying,
        "the rebind purged the old rows"
    );

    let scope = RouteQueryScope::Received { peer: None };
    let identity = "0".repeat(64);
    let response = route_page_to_response(&held, scope, &identity, false, None);
    assert_eq!(response.routes[0].peer_address, "fe80::1");
    assert_eq!(response.routes[0].peer_interface, "");
    let cursor = decode_route_page_token(&response.next_page_token).unwrap();
    assert_eq!(
        cursor.after,
        (
            prefix,
            PageSource {
                addr: "fe80::1".parse().unwrap(),
                peer: moving
            },
            0
        )
    );
    assert!(matches!(
        received_page(&tx, Some(cursor.after), Some(cursor.version)).await,
        Err(RoutePageError::Invalidated)
    ));

    drop(tx);
    actor.await.unwrap();
    assert!(moving.release() && staying.release());
}

/// The family page rows and cursors (EVPN, BGP-LS, labeled; VPN and RTC
/// format their cursors the same way) resolve through the page's scope.
#[test]
fn family_page_rows_and_cursors_keep_the_endpoint_of_their_page() {
    let moving = neighbor("fe80::1", "swp1");
    let (mut evpn, mut bgpls, _, mut labeled, _) = non_unicast_routes("fe80::1".parse().unwrap());
    evpn.peer = moving;
    bgpls[0].peer = moving;
    labeled.peer = moving;
    let peers = PeerScope::capture();
    assert!(moving.rebind(rustbgpd_rib::PeerEndpoint::new(
        "fe80::9".parse().unwrap(),
        Some("swp1")
    )));
    assert_eq!(moving.to_string(), "fe80::9");

    assert_eq!(
        evpn_route_to_proto_in(&evpn, &peers).peer_address,
        "fe80::1"
    );
    assert_eq!(
        labeled_route_to_proto_in(&labeled, &peers).peer_address,
        "fe80::1"
    );
    assert_eq!(
        bgpls_route_to_proto_in(&bgpls[0], &peers).peer_address,
        "fe80::1"
    );
    assert!(encode_bgpls_page_key(&bgpls[0], &peers).contains("~fe80::1~"));
    let version = RoutePageVersion {
        epoch: 1,
        generation: 1,
    };
    let token =
        encode_evpn_page_token(RouteQueryScope::Best, "0:", &evpn, &peers, version).unwrap();
    let cursor = decode_evpn_page_token(&token).unwrap();
    assert_eq!(cursor.after.1.addr, "fe80::1".parse::<IpAddr>().unwrap());
    assert!(moving.release());
}

/// An explanation converted after its source neighbor moved names the
/// address the RIB explained, for the best route and every candidate.
#[test]
fn an_explanation_held_across_a_rebind_keeps_its_endpoints() {
    let moving = neighbor("fe80::1", "swp1");
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let route = Route {
        peer: moving,
        ..test_route(prefix, vec![])
    };
    let explanation = rustbgpd_rib::ExplainBestPath {
        peer_scope: PeerScope::capture(),
        prefix,
        best: Some(route.clone()),
        candidates: vec![rustbgpd_rib::BestPathCandidate {
            route: Route {
                path_id: 2,
                ..route
            },
            vs_best_reason: rustbgpd_rib::BestPathReason::LowerPathId,
            vs_best_ordering: std::cmp::Ordering::Greater,
            advertised_path_id: 0,
            vs_best_detail: "path_id 2 > 0".to_string(),
            multipath: rustbgpd_rib::MultipathEligibility::None,
        }],
        peer: Some(moving),
        orr_vantage: None,
        add_path_send_max: 0,
        best_reason: Some(rustbgpd_rib::BestPathReason::LowerPathId),
        best_reason_detail: "path_id 0 < 2".to_string(),
    };
    assert!(moving.rebind(rustbgpd_rib::PeerEndpoint::new(
        "fe80::9".parse().unwrap(),
        Some("swp1")
    )));

    let response = explain_best_path_to_proto(explanation);
    assert_eq!(response.best_route.unwrap().peer_address, "fe80::1");
    assert_eq!(
        response.candidates[0].route.as_ref().unwrap().peer_address,
        "fe80::1"
    );
    assert_eq!(response.peer_address, "fe80::1");
    assert!(moving.release());
}
