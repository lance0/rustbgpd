//! Which exempt keys a paced, published group carries when its helper flaps.

use std::collections::BTreeSet;

use super::*;
use crate::adj_rib_out::LocalExportSource;

const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const CAP: usize = super::super::HELPER_STALE_EXEMPT_LIMIT;
type Key = (Prefix, u32);

fn padding(index: usize) -> Key {
    let address = Ipv4Addr::from(0x0a00_0000 + u32::try_from(index).unwrap());
    (Prefix::V4(Ipv4Prefix::new(address, 32)), 0)
}

// Seed admission provenance for the padding alone. The two overflow routes
// use real injection, paced staging and outbound admission on the old session.
fn add_padding(manager: &mut RibManager, gid: usize, indices: std::ops::Range<usize>) {
    let table = &mut manager.group_ribs.get_mut(&gid).unwrap().table;
    assert!(table.uses_ordered_local_sources());
    for index in indices.rev() {
        table.set_local_export_source(
            padding(index),
            Some(LocalExportSource {
                path_id: 0,
                deferral_exempt: true,
            }),
        );
    }
}

fn flap_and_check(
    manager: &mut RibManager,
    address: Ipv4Addr,
    padding_rows: usize,
    sentinels: [Key; 2],
) {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: u64::from(address.octets()[3]),
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![FAMILY, V6],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let keys = &manager.helper_stale_exempt[&peer].keys;
    let expected = (0..padding_rows).map(padding).chain(sentinels).take(CAP);
    assert_eq!(keys.len(), (padding_rows + 2).min(CAP));
    assert!(keys.iter().copied().eq(expected), "exact carry for {peer}");
}

// The helper retains stale rows until their own family's End-of-RIB.
// An explicit withdrawal or a replacement would settle them earlier; this
// scenario forbids either for the two omitted, deleted rows.
fn observe_restart(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    sentinels: [Key; 2],
    stale: &mut BTreeSet<Key>,
    markers: &mut Vec<(Afi, Safi)>,
) {
    while let Ok(update) = rx.try_recv() {
        assert!(
            update
                .unicast_withdrawals()
                .all(|key| !sentinels.contains(key))
        );
        assert!(
            update
                .announce
                .iter()
                .all(|row| !sentinels.contains(&(row.prefix, row.path_id)))
        );
        for &family in &update.end_of_rib {
            assert!(
                !markers.contains(&family),
                "duplicate End-of-RIB for {family:?}"
            );
            markers.push(family);
            stale.retain(|(prefix, _)| crate::manager::helpers::prefix_family(prefix) != family);
        }
    }
}

type Restart = (
    mpsc::Receiver<OutboundRouteUpdate>,
    BTreeSet<Key>,
    Vec<(Afi, Safi)>,
);

fn advance_to_markers(
    manager: &mut RibManager,
    restarts: &mut [Restart; 2],
    sentinels: [Key; 2],
    expected: usize,
) {
    for _ in 0..(CAP / crate::outbound_credit::CHUNK_ROWS + 2) {
        for (receiver, stale, markers) in restarts.iter_mut() {
            observe_restart(receiver, sentinels, stale, markers);
        }
        if restarts
            .iter()
            .all(|(_, _, markers)| markers.len() == expected)
        {
            return;
        }
        manager.resync_dirty_peers_bounded();
        manager.settle_eor_after_pass();
    }
    panic!("both helpers must receive {expected} family markers");
}

#[test]
fn paced_group_helper_carry_cap_and_per_family_end_of_rib() {
    let peers = [91, 92, 93, 94].map(|n| Ipv4Addr::new(192, 0, 2, n));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let config = crate::EorGraceConfig {
        peers: peers
            .into_iter()
            .zip([V6, V6, V6, FAMILY])
            .map(|(address, held)| crate::EorGracePeerConfig {
                peer: peer_v4(address).into(),
                deadline,
                families: vec![held],
            })
            .collect(),
        replay_owners: vec![],
    };
    let (_tx, rx) = mpsc::channel(8);
    let mut manager =
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_eor_grace(config);
    manager.first_group_build_min_routes = 1;
    let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 99), 32);
    inject_rtbh(&mut manager, v4);
    let sentinels = [
        (Prefix::V4(v4), 0),
        inject_v6_rtbh(&mut manager, "2001:db8::99"),
    ];
    let mut old_receivers = Vec::new();
    for address in peers {
        let mut receiver = connect_waiter_for(&mut manager, address, &[FAMILY, V6]);
        if old_receivers.is_empty() {
            assert!(
                manager.first_group_build.is_some(),
                "the first session owns a private scan"
            );
            while manager.first_group_build.is_some() {
                manager.advance_first_group_build();
            }
        }
        let mut wire = BTreeSet::new();
        while let Ok(update) = receiver.try_recv() {
            wire.extend(update.announce.iter().map(|row| (row.prefix, row.path_id)));
        }
        assert_eq!(
            wire,
            BTreeSet::from(sentinels),
            "both real rows were advertised to {address}"
        );
        old_receivers.push(receiver);
    }
    let gid = manager.grouped_member_of(peer_v4(peers[0])).unwrap();
    assert!(
        peers
            .iter()
            .all(|&address| manager.grouped_member_of(peer_v4(address)) == Some(gid))
    );
    add_padding(&mut manager, gid, 0..CAP - 3);
    flap_and_check(&mut manager, peers[0], CAP - 3, sentinels);
    add_padding(&mut manager, gid, CAP - 3..CAP - 2);
    flap_and_check(&mut manager, peers[1], CAP - 2, sentinels);
    add_padding(&mut manager, gid, CAP - 2..CAP);
    for &address in &peers[2..] {
        flap_and_check(&mut manager, address, CAP, sentinels);
    }
    drop(old_receivers);
    delete(&mut manager, v4);
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: sentinels[1].0,
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(response.try_recv().unwrap().unwrap().removed);
    let mut restarts = [peers[2], peers[3]].map(|address| {
        (
            connect_waiter_for(&mut manager, address, &[FAMILY, V6]),
            BTreeSet::from(sentinels),
            Vec::new(),
        )
    });
    advance_to_markers(&mut manager, &mut restarts, sentinels, 1);
    for ((_, stale, markers), (first, remaining)) in restarts
        .iter()
        .zip([(FAMILY, sentinels[1]), (V6, sentinels[0])])
    {
        assert_eq!(markers, &[first]);
        assert_eq!(*stale, BTreeSet::from([remaining]));
    }
    manager.expire_eor_grace(deadline);
    advance_to_markers(&mut manager, &mut restarts, sentinels, 2);
    for ((_, stale, markers), order) in restarts.iter().zip([[FAMILY, V6], [V6, FAMILY]]) {
        assert_eq!(markers, &order);
        assert!(stale.is_empty());
    }
}
