//! The VPN cursor through the real `RibManager` actor loop on a paused
//! clock, with the owed index checked against its full-scan predicate
//! after every actor turn ([`RibManager::assert_owed_vpn_index`]).

use super::*;

fn check(manager: &RibManager) {
    manager.assert_owed_vpn_index();
}

fn peer_up(
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (outbound_tx, output) = mpsc::channel(channel);
    let update = RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: families.to_vec(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    };
    (update, output)
}

fn vpn_update(family: (Afi, Safi), announce: &[(u32, u32)], withdraw: &[u32]) -> RibUpdate {
    RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: announce
            .iter()
            .map(|&(index, label)| route_from(SOURCE, family, index, label, 200))
            .collect(),
        withdrawn: withdraw
            .iter()
            .map(|&index| VpnRibRouteKey {
                nlri_key: key(family, index),
                path_id: 0,
            })
            .collect(),
    }
}

/// Two queries in turn: every message queued before them has run.
async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    for _ in 0..2 {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        response.await.unwrap();
    }
}

/// Advance the clock `ticks` times by 10 ms; `reading` receivers write
/// after each.
async fn run_for(
    tx: &mpsc::Sender<RibUpdate>,
    receivers: &mut [Receiver],
    reading: &[bool],
    ticks: usize,
) {
    for _ in 0..ticks {
        tokio::time::advance(Duration::from_millis(10)).await;
        barrier(tx).await;
        for (receiver, &reading) in receivers.iter_mut().zip(reading) {
            if reading {
                receiver.write();
            }
        }
    }
}

/// Both VPN AFIs are held while three private receivers hold their tables
/// and a fourth joins; rows change inside the hold. `VPNv4` is released
/// while two receivers do not read, and rows of both AFIs change behind
/// and ahead of the walk (including a withdrawal and a relabel); `VPNv6` is
/// released later; then every receiver reads again. Every message, timer
/// and tick runs through `RibManager::run_actor`, and after every turn the
/// owing index, both VPN lists and every clean receiver's debt match their
/// full-scan predicate. Each receiver ends with the exact table of both
/// AFIs and one End-of-RIB per AFI, the joiner's after its last row; no
/// whole-family step runs and nothing stays owed.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one actor scenario: hold, release apart, pause, churn and resume in order"
)]
async fn a_vpn_release_and_resume_through_the_actor_loop_keep_the_owed_index_exact() {
    const ROWS: u32 = 120;
    let mut manager = deferral_manager(CREDIT, &[P4, P6]);
    manager.actor_turn_check = Some(check);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run_actor());
    let mut sources = Vec::new();
    for source in [SOURCE, SECOND] {
        let (update, rx) = peer_up(peer_v4(source), 0, 4096, &[V4]);
        tx.send(update).await.unwrap();
        sources.push(rx);
    }
    let mut models = [Model::new(P4, &all(ROWS)), Model::new(P6, &all(ROWS))];
    for model in &models {
        tx.send(vpn_update(model.family, &all(ROWS), &[]))
            .await
            .unwrap();
    }
    let mut receivers = Vec::new();
    for index in 0..3 {
        let (update, rx) = peer_up(receiver(index), 0, 64, &[P4, P6]);
        tx.send(update).await.unwrap();
        receivers.push(Receiver {
            peer: receiver(index),
            rx,
            wire: Wire::default(),
        });
    }
    run_for(&tx, &mut receivers, &[true; 3], 200).await;
    for receiver in &mut receivers {
        assert_eq!(receiver.wire.rows_of(P4), ROWS as usize, "initial table");
        assert_eq!(receiver.wire.markers, [1, 1]);
        // The initial table is a whole-table operation, outside credit.
        (receiver.wire.uncharged, receiver.wire.latched) = (0, 0);
    }

    // The hold: the waiter restarts, rows change, a receiver joins.
    tx.send(gr_context(&[P4, P6])).await.unwrap();
    let (update, waiter_rx) = peer_up(peer_v4(WAITER), 7, 4096, &[P4, P6]);
    tx.send(update).await.unwrap();
    receivers.push(Receiver {
        peer: peer_v4(WAITER),
        rx: waiter_rx,
        wire: Wire::default(),
    });
    for model in &mut models {
        let family = model.family;
        model.rows.extend([(3, 300), (ROWS, 100), (ROWS + 1, 100)]);
        model.rows.remove(&5);
        tx.send(vpn_update(
            family,
            &[(3, 300), (ROWS, 100), (ROWS + 1, 100)],
            &[5],
        ))
        .await
        .unwrap();
    }
    let (update, joiner_rx) = peer_up(receiver(3), 0, 64, &[P4, P6]);
    tx.send(update).await.unwrap();
    receivers.push(Receiver {
        peer: receiver(3),
        rx: joiner_rx,
        wire: Wire::default(),
    });
    let mut reading = [true; 5];
    run_for(&tx, &mut receivers, &reading, 20).await;
    assert_eq!(receivers[4].wire.table.len(), 0, "the joiner waits");

    // VPNv4 is released while receivers 1 and 2 do not read.
    reading[1] = false;
    reading[2] = false;
    tx.send(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 7,
        afi: P4.0,
        safi: P4.1,
    })
    .await
    .unwrap();
    run_for(&tx, &mut receivers, &reading, 3).await;
    // Behind and ahead of the walk, in both AFIs: a relabel, a withdrawal,
    // a new row.
    for model in &mut models {
        let family = model.family;
        model
            .rows
            .extend([(0, 444), (ROWS - 1, 445), (ROWS + 2, 100)]);
        model.rows.remove(&7);
        tx.send(vpn_update(
            family,
            &[(0, 444), (ROWS - 1, 445), (ROWS + 2, 100)],
            &[7],
        ))
        .await
        .unwrap();
    }
    run_for(&tx, &mut receivers, &reading, 5).await;
    tx.send(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 7,
        afi: P6.0,
        safi: P6.1,
    })
    .await
    .unwrap();
    run_for(&tx, &mut receivers, &reading, 50).await;

    // Resume: everyone reads.
    run_for(&tx, &mut receivers, &[true; 5], 500).await;
    drop(tx);
    let manager = actor.await.unwrap();
    drop(sources);

    let mut expected = models[0].table();
    expected.extend(models[1].table());
    for (index, receiver) in receivers.iter().enumerate() {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected, "{index}: exact table");
        assert_eq!(wire.markers, [1, 1], "{index}: one End-of-RIB per AFI");
        assert!(manager.owing(receiver.peer).is_none(), "{index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{index}");
        assert_eq!(wire.uncharged + wire.latched, 0, "{index}: charged");
    }
    let joiner = &receivers[4].wire;
    assert_eq!(
        joiner.rows_after_marker,
        [0, 0],
        "the marker follows the rows"
    );
    assert_eq!(steps_of(&manager, "whole"), 0, "no whole-family step");
    assert!(steps_of(&manager, "cursor") > 0);
    assert!(lists_freed(&manager));
    assert!(manager.owing_peers.is_empty());
}
