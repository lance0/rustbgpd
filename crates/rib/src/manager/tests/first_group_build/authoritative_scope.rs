use super::*;
use crate::update::PeerExportPolicyReplacement;

#[test]
fn authoritative_destination_requires_one_single_best_unicast_family() {
    let v6 = [(Afi::Ipv6, Safi::Unicast)];
    let evpn = [(Afi::L2Vpn, Safi::Evpn)];
    let mixed = [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)];
    for (families, per_client_best, paged) in [
        (&v6[..], false, true),
        (&DUAL[..], false, false),
        (&evpn[..], false, false),
        (&mixed[..], false, false),
        (&v6[..], true, false),
    ] {
        let (mut manager, _primary, _) = fixture(0);
        let peer = receiver(1);
        let (tx, _out) = mpsc::channel(32);
        let mut up = test_peer_up(peer, 1, tx);
        let RibUpdate::PeerUp {
            sendable_families,
            per_client_best: best,
            ..
        } = &mut up
        else {
            unreachable!()
        };
        families.clone_into(sendable_families);
        *best = per_client_best;
        manager.handle_update(up);
        let prefix = prefixes(1)[1];
        manager.handle_update(test_routes_received(
            peer_v4(SOURCE),
            vec![route(prefix, SOURCE, 100)],
        ));
        drain_route_chunks(&mut manager);
        let old_group = manager.grouped_member_of(peer);
        let destination = deny_default_prefix_chain();
        let (reply, mut ack) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: vec![PeerExportPolicyReplacement {
                peer,
                export_policy: Some(destination.clone()),
            }],
            reply,
        });
        assert_eq!(
            manager.first_group_build.is_some(),
            paged,
            "{families:?}, per-client-best={per_client_best}"
        );
        if paged {
            assert!(matches!(
                ack.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(manager.grouped_member_of(peer), old_group);
            assert!(manager.export_policy_for(peer).is_none());
            for _ in 0..64 {
                if manager.first_group_build.is_none() {
                    break;
                }
                manager.advance_first_group_build();
            }
        }
        let deferred = ack.try_recv().expect("one terminal reply").unwrap();
        if deferred.is_empty() {
            assert_eq!(manager.export_policy_for(peer), Some(&destination));
        } else {
            assert!(!paged);
            assert_eq!(deferred, [peer]);
            assert!(manager.export_policy_for(peer).is_none());
        }
    }
}

#[test]
fn authoritative_batch_with_two_destinations_preserves_the_existing_handoff() {
    let (mut manager, _primary, _) = fixture(0);
    let peers = [receiver(1), receiver(2)];
    let _writers = peers.map(|peer| join(&mut manager, peer, 1, &[(Afi::Ipv4, Safi::Unicast)]));
    let old = manager.grouped_member_of(peers[0]).unwrap();
    assert_eq!(manager.grouped_member_of(peers[1]), Some(old));
    let prefix = prefixes(1)[0];
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![route(prefix, SOURCE, 100)],
    ));
    drain_route_chunks(&mut manager);
    let policies = [deny_default_prefix_chain(), deny_prefixes_chain(&[prefix])];
    let (reply, mut ack) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: peers
            .into_iter()
            .zip(policies)
            .map(|(peer, chain)| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(chain),
            })
            .collect(),
        reply,
    });
    assert!(manager.first_group_build.is_none());
    assert_eq!(ack.try_recv().unwrap().unwrap(), peers);
    for peer in peers {
        assert_eq!(manager.grouped_member_of(peer), Some(old));
        assert!(manager.export_policy_for(peer).is_none());
    }
}
