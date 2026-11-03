//! ADR-0146 slice 1: received VPN `FlowSpec` (AFI 1 / SAFI 134) is decoded,
//! counted and discarded; it never reaches the RIB.

use super::*;
use rustbgpd_wire::{Ipv4UnicastMode, MpReachNlri, MpUnreachNlri, UpdateMessage, VpnFlowSpecRule};

const DISCARDED: &str = "bgp_vpn_flowspec_nlri_discarded_total";

fn vpn_rule(assigned: u8) -> VpnFlowSpecRule {
    VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, assigned]),
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 10), 32),
            ))],
        },
    }
}

fn reach(rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpReachNlri(Box::new(MpReachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        vpn_announced: vec![],
        labeled_announced: vec![],
        rtc_announced: vec![],
        vpn_flowspec_announced: rules,
    }))
}

fn unreach(rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: vec![],
        rtc_withdrawn: vec![],
        vpn_flowspec_withdrawn: rules,
    }))
}

fn update(attributes: &[PathAttribute]) -> UpdateMessage {
    UpdateMessage::build(&[], &[], attributes, true, false, Ipv4UnicastMode::Body)
}

fn announcement(rules: Vec<VpnFlowSpecRule>) -> UpdateMessage {
    update(&[
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        reach(rules),
    ])
}

fn session_with(
    families: Vec<(Afi, Safi)>,
) -> (PeerSession, tokio::sync::mpsc::Receiver<RibUpdate>) {
    let (mut session, rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = families;
    session.negotiated = Some(Arc::new(negotiated));
    (session, rib_rx)
}

fn discarded(session: &PeerSession) -> Vec<(HashMap<String, String>, f64)> {
    counter_samples(&session.metrics, DISCARDED)
}

#[tokio::test]
async fn received_vpn_flowspec_is_counted_and_never_reaches_the_rib() {
    let (mut session, mut rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);

    session
        .process_update(announcement(vec![vpn_rule(40), vpn_rule(41)]))
        .await;
    // A withdrawal carries NLRI, so it is counted and is not End-of-RIB.
    session
        .process_update(update(&[unreach(vec![vpn_rule(40)])]))
        .await;

    assert_eq!(
        discarded(&session),
        vec![(
            HashMap::from([("peer".to_string(), session.peer_label.clone())]),
            3.0,
        )]
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "VPN FlowSpec must not reach the RIB"
    );
    assert!(session.received_eor_families.is_empty());
}

#[tokio::test]
async fn vpn_flowspec_end_of_rib_is_accepted_and_not_counted() {
    let (mut session, mut rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);

    session.process_update(update(&[unreach(vec![])])).await;

    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndOfRib {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpecVpn,
            ..
        })
    ));
    assert!(
        session
            .received_eor_families
            .contains(&(Afi::Ipv4, Safi::FlowSpecVpn))
    );
    assert_eq!(discarded(&session), Vec::new());
}

#[tokio::test]
async fn unnegotiated_vpn_flowspec_is_ignored_without_counting() {
    let (mut session, mut rib_rx) = session_with(vec![(Afi::Ipv4, Safi::Unicast)]);

    session
        .process_update(announcement(vec![vpn_rule(40)]))
        .await;

    assert_eq!(discarded(&session), Vec::new());
    assert!(rib_rx.try_recv().is_err());
}

#[test]
fn vpn_flowspec_route_refresh_is_never_requested() {
    let (mut session, _rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    // No writer is installed, so any real request fails to enqueue.
    assert!(
        session
            .send_route_refresh(Afi::Ipv4, Safi::FlowSpec)
            .is_err()
    );
    assert_eq!(
        session.send_route_refresh(Afi::Ipv4, Safi::FlowSpecVpn),
        Ok(())
    );
}
