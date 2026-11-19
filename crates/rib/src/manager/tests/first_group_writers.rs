//! The destination claim uses the same resulting group as the actual command.

use super::lifecycle::test_peer_up;
use super::*;

#[test]
fn membership_writers_claim_the_destination_before_install() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let (out, _out_rx) = mpsc::channel(32);
    manager.handle_update(test_peer_up(peer, 1, out));
    let v4 = manager.grouped_member_of(peer).unwrap();
    let slow = |session_id, slow| RibUpdate::PeerSlowState {
        peer,
        session_id,
        slow,
    };
    manager.handle_update(slow(1, true));
    assert!(!manager.mutation_targets_first_group(&slow(2, false), v4));
    assert!(manager.mutation_targets_first_group(&slow(1, false), v4));
    assert_eq!(manager.grouped_member_of(peer), None);
    manager.handle_update(slow(1, false));
    assert_eq!(manager.grouped_member_of(peer), Some(v4));
    assert!(!manager.mutation_targets_first_group(&slow(1, false), v4));

    let dual_peer = peer_v4(Ipv4Addr::new(192, 0, 2, 2));
    let (out, _dual_rx) = mpsc::channel(16);
    let mut up = test_peer_up(dual_peer, 3, out);
    let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    else {
        unreachable!()
    };
    sendable_families.push((Afi::Ipv6, Safi::Unicast));
    manager.handle_update(up);
    let dual = manager.grouped_member_of(dual_peer).unwrap();
    let unlock = |session_id, add_path_send_limit| RibUpdate::PeerFamilySendable {
        peer,
        session_id,
        family: (Afi::Ipv6, Safi::Unicast),
        add_path_send_limit,
    };
    assert!(!manager.mutation_targets_first_group(&unlock(2, None), dual));
    assert!(!manager.mutation_targets_first_group(&unlock(1, Some(4)), dual));
    assert!(manager.mutation_targets_first_group(&unlock(1, None), dual));
    assert_eq!(manager.grouped_member_of(peer), Some(v4));
    manager.handle_update(unlock(1, None));
    assert_eq!(manager.grouped_member_of(peer), Some(dual));
    assert!(!manager.mutation_targets_first_group(&unlock(1, None), dual));

    let install = |set| RibUpdate::InstallConditionalAdvertisements {
        set,
        swapping_datasets: vec![],
        reply: oneshot::channel().0,
    };
    let attached = crate::ConditionalAdvertisementSet {
        definitions: vec![crate::ConditionalAdvertisement {
            name: Arc::from("backup"),
            advertise_policy: deny_default_prefix_chain(),
            advertise_if: crate::ConditionalAdvertiseIf::Present,
            condition_prefixes: vec![],
            condition_policy: None,
            settle_time: Duration::ZERO,
            retiring: false,
        }],
        attachments: [(peer.endpoint().unwrap(), vec![Arc::from("backup")])]
            .into_iter()
            .collect(),
    };
    let original = manager.handle_install_conditional_advertisements(attached.clone(), &[]);
    assert_eq!(manager.grouped_member_of(peer), None);
    assert!(!manager.mutation_targets_first_group(&install(attached), dual));
    assert!(
        !manager.mutation_targets_first_group(
            &install(crate::ConditionalAdvertisementSet::default()),
            v4
        )
    );
    assert!(manager.mutation_targets_first_group(
        &install(crate::ConditionalAdvertisementSet::default()),
        dual
    ));
    let restore = RibUpdate::RestoreConditionalAdvertisements {
        capture: original,
        reply: oneshot::channel().0,
    };
    assert!(manager.mutation_targets_first_group(&restore, dual));
    manager.handle_update(restore);
    assert_eq!(manager.grouped_member_of(peer), Some(dual));
}

#[test]
fn abandoned_forward_and_authoritative_compensation_keep_their_reply_contracts() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let (out, _out_rx) = mpsc::channel(16);
    manager.handle_update(test_peer_up(peer, 1, out));
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(deny_default_prefix_chain()),
        reply: oneshot::channel().0,
    });
    assert_ne!(manager.grouped_member_of(peer), Some(gid));
    let replacements = || {
        vec![crate::update::PeerExportPolicyReplacement {
            peer,
            export_policy: None,
        }]
    };
    let forward = RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: replacements(),
        reply: oneshot::channel().0,
    };
    assert!(!manager.mutation_targets_first_group(&forward, gid));
    let (reply, _open) = oneshot::channel();
    let forward = RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: replacements(),
        reply,
    };
    assert!(manager.mutation_targets_first_group(&forward, gid));
    let restore = RibUpdate::RestorePacedExportPolicies {
        replacements: replacements(),
        cost: None,
        reply: oneshot::channel().0,
    };
    assert!(manager.mutation_targets_first_group(&restore, gid));
    assert_ne!(manager.grouped_member_of(peer), Some(gid));
    manager.handle_update(restore);
    assert_eq!(manager.grouped_member_of(peer), Some(gid));
}
