//! What the receiver accepts changes between the walk's starting log and
//! the step that completes its sample. The rate is read from rows the
//! early steps committed, so a change after them is invisible to it: keys
//! the receiver accepted are re-marked so it denies them (a MED,
//! community or next-hop change; a policy dataset re-evaluation logs the
//! same keys), or withdrawn. Each change logs keys in the list after the
//! starting log, and the walk then makes no estimate: every table ends at
//! or below the same walk with the presize off, within 2.3 times what it
//! holds.

use std::cell::RefCell;

use super::super::cursor_presize::{
    Growth, assert_at_or_below_control, assert_fitted, deny_med_chain, set_med, with_control,
    with_control_async,
};
use super::*;

fn row(index: u32, med: u32) -> VpnRibRoute {
    let mut route = route_from(SOURCE, P4, index, 100, 200);
    set_med(&mut route.attributes, med);
    route
}

/// The receiver's table: rows, keys, and the capacities of its route and
/// key indexes.
fn table(manager: &RibManager, peer: PeerId) -> (usize, usize, [usize; 2]) {
    let out = &manager.adj_ribs_out[&peer];
    let (routes, keys) = out.bench_vpn_capacities();
    (out.vpn_len(), out.vpn_key_len(), [routes, keys])
}

/// At or below the control within the spread of its 16 shards (each run
/// hashes its keys with its own seed, so the shards' capacities differ by
/// a few percent with no presize at all), and within 2.3 times what the
/// table holds.
fn assert_fits(head: (usize, usize, [usize; 2]), control: [usize; 2], case: &str) {
    let spread = control.map(|capacity| capacity + capacity / 20);
    assert_at_or_below_control(&head.2, &spread, case);
    assert_fitted(head.2[0], head.0, &format!("{case}: route index"));
    assert_fitted(head.2[1], head.1, &format!("{case}: key index"));
}

/// How the source changes the starting log after the walk's first steps.
#[derive(Clone, Copy)]
enum Change {
    /// Re-announce the keys with MED 1: still in the Loc-RIB, now denied.
    Deny,
    /// Withdraw the keys.
    Withdraw,
}

/// Credit `credit`; one pass (the starting log) of `total` keys behind
/// [`deny_med_chain`], `accepted(i)` of them accepted; `first` steps, all
/// before the estimate; then every accepted key but `kept(i)` is changed
/// by `change`, and the walk drains.
fn changed_after_first_steps(
    credit: usize,
    total: u32,
    first: usize,
    accepted: fn(u32) -> bool,
    kept: fn(u32) -> bool,
    change: Change,
) -> (usize, usize, [usize; 2]) {
    let mut manager = manager(credit);
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(
        &mut manager,
        peer,
        0,
        4096,
        &[P4],
        0,
        Some(deny_med_chain()),
    );
    Wire::default().write(&mut rx);
    manager.owe_eor(peer, P4);
    manager.owe_whole_family(peer, F4);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    let rows = (0..total)
        .map(|i| row(i, u32::from(!accepted(i))))
        .collect();
    send(&mut manager, SOURCE, rows, vec![]);
    for _ in 0..first {
        tick(&mut manager, &mut receivers);
    }
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, 0,
        "the change lands before the estimate"
    );
    let changed = (0..total).filter(|&i| accepted(i) && !kept(i));
    match change {
        Change::Deny => send(
            &mut manager,
            SOURCE,
            changed.map(|i| row(i, 1)).collect(),
            vec![],
        ),
        Change::Withdraw => send(
            &mut manager,
            SOURCE,
            vec![],
            changed.map(|i| key(P4, i)).collect(),
        ),
    }
    drain(&mut manager, &mut receivers);
    let expected = (0..total).filter(|&i| accepted(i) && kept(i)).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    table(&manager, peer)
}

fn assert_changed_fits(
    credit: usize,
    total: u32,
    first: usize,
    accepted: fn(u32) -> bool,
    kept: fn(u32) -> bool,
    change: Change,
    case: &str,
) {
    let (head, (_, _, control)) =
        with_control(|| changed_after_first_steps(credit, total, first, accepted, kept, change));
    assert_fits(head, control, case);
}

/// Credit 400 (steps of 200 keys): 40,000 keys, nine in ten accepted.
/// After one step the source re-marks every accepted key but one in a
/// hundred so the receiver denies it. Red when the walk estimates from a
/// sample that a logged change followed: 4.5 times what the table holds,
/// against 2.2 times.
#[test]
fn accepted_keys_denied_after_the_first_vpn_step_fit() {
    assert_changed_fits(
        400,
        40_000,
        1,
        |i| i % 10 != 0,
        |i| i % 100 == 1,
        Change::Deny,
        "denied after step 1",
    );
}

/// The same after two steps (400 keys read, about 360 rows: past the
/// sample's rows, under its keys). Red as above: 18 to 36 times, against
/// about 2.
#[test]
fn accepted_keys_denied_after_two_vpn_steps_fit() {
    assert_changed_fits(
        400,
        40_000,
        2,
        |i| i % 10 != 0,
        |i| i % 100 == 1,
        Change::Deny,
        "denied after step 2",
    );
}

/// The default step (credit 4,096, 1,024 keys): one in five of 100,000
/// accepted, so the first step commits about 205 rows, under the sample's
/// 256. After it the source re-marks nine in ten accepted keys denied.
/// Red as above: 3.6 to 7.2 times, against 1.8.
#[test]
fn accepted_keys_denied_after_a_default_vpn_step_fit() {
    assert_changed_fits(
        4 * CHUNK_ROWS,
        100_000,
        1,
        |i| i % 5 == 0,
        |i| i % 50 == 0,
        Change::Deny,
        "denied after a default step",
    );
}

/// Credit 480: six in ten of 40,000 accepted; after one step the source
/// withdraws every accepted key but one in a hundred.
#[test]
fn accepted_keys_withdrawn_after_the_first_vpn_step_fit() {
    assert_changed_fits(
        480,
        40_000,
        1,
        |i| i % 5 < 3,
        |i| i % 100 == 1,
        Change::Withdraw,
        "accepted withdrawn after step 1",
    );
}

/// Every key accepted; after one step one key in two is withdrawn.
#[test]
fn a_uniform_withdrawal_after_the_first_vpn_step_fits() {
    assert_changed_fits(
        480,
        40_000,
        1,
        |_| true,
        |i| i % 2 == 0,
        Change::Withdraw,
        "uniform withdrawal after step 1",
    );
}

// ---- Through `RibManager::run` on a paused clock.

thread_local! {
    /// The joiner, the growth of its table, its last state and the
    /// presizes made so far.
    static WATCHED: RefCell<Option<Watched>> = const { RefCell::new(None) };
}

type Watched = (PeerId, Growth, (usize, usize, [usize; 2]), usize);

fn watch(manager: &RibManager) {
    WATCHED.with(|watched| {
        if let Some((peer, growth, last, presizes)) = watched.borrow_mut().as_mut()
            && manager.adj_ribs_out.contains_key(peer)
        {
            *last = table(manager, *peer);
            growth.observe(last.0, last.2);
            *presizes = manager.adj_rib_out_commit_stats.walk_presizes;
        }
    });
}

fn vpn_pass(rows: Vec<VpnRibRoute>) -> RibUpdate {
    RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: rows,
        withdrawn: vec![],
    }
}

/// Release-started: SOURCE's 40,000 keys (nine in ten accepted by the
/// joiner) are held behind the waiter, whose End-of-RIBs release them; the
/// release logs the inventory. The joiner does not read for 20 ticks, so
/// its 400-row credit stops its walk at about 444 keys, under the sample.
/// The source then re-marks every accepted key but one in a hundred
/// denied, and the joiner reads again. Returns the joiner's last table and
/// its growth.
async fn denied_mid_sample_in_the_run_loop() -> ((usize, usize, [usize; 2]), Growth) {
    const TOTAL: u32 = 40_000;
    let accepted = |i: u32| i % 10 != 0;
    let kept = |i: u32| i % 100 == 1;
    let mut manager = deferral_manager(400, &[P4, P6]);
    manager.actor_turn_check = Some(watch);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let run = tokio::spawn(manager.run());
    let mut sources = Vec::new();
    for source in [SOURCE, SECOND] {
        let (update, rx) = actor::peer_up(peer_v4(source), 0, 4096, &[V4]);
        tx.send(update).await.unwrap();
        sources.push(rx);
    }
    let rows = (0..TOTAL)
        .map(|i| row(i, u32::from(!accepted(i))))
        .collect();
    tx.send(vpn_pass(rows)).await.unwrap();
    tx.send(gr_context(&[P4, P6])).await.unwrap();
    let (update, waiter_rx) = actor::peer_up(peer_v4(WAITER), 7, 4096, &[P4, P6]);
    tx.send(update).await.unwrap();
    let joiner = receiver(0);
    let (outbound_tx, joiner_rx) = mpsc::channel(4096);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: joiner,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: Some(deny_med_chain()),
        sendable_families: vec![P4, P6],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let mut receivers = vec![
        Receiver {
            peer: joiner,
            rx: joiner_rx,
            wire: Wire::default(),
        },
        Receiver {
            peer: peer_v4(WAITER),
            rx: waiter_rx,
            wire: Wire::default(),
        },
    ];
    actor::run_for(&tx, &mut receivers, &[true; 2], 5).await;
    assert!(receivers[0].wire.table.is_empty(), "the joiner waits");
    WATCHED.with(|watched| {
        *watched.borrow_mut() = Some((joiner, Growth::default(), (0, 0, [0; 2]), 0));
    });
    for family in [P4, P6] {
        tx.send(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: 7,
            afi: family.0,
            safi: family.1,
        })
        .await
        .unwrap();
    }
    actor::run_for(&tx, &mut receivers, &[false, true], 20).await;
    let paused = WATCHED.with(|watched| {
        watched
            .borrow()
            .as_ref()
            .map(|(_, _, last, presizes)| (last.0, *presizes))
    });
    // Nine in ten accepted: under 460 rows, the joiner has read fewer
    // keys than its sample's 512 and made no estimate (the waiter's own
    // walk may have).
    assert!(
        paused.is_some_and(|(rows, _)| rows > 0 && rows * 10 < 512 * 9),
        "the joiner stopped mid-sample: {paused:?} (rows, presizes)"
    );
    let again = (0..TOTAL)
        .filter(|&i| accepted(i) && !kept(i))
        .map(|i| row(i, 1))
        .collect();
    tx.send(vpn_pass(again)).await.unwrap();
    actor::run_for(&tx, &mut receivers, &[true; 2], 3_000).await;
    drop(tx);
    run.await.unwrap();
    drop(sources);
    let (_, growth, last, _) = WATCHED.with(|watched| watched.borrow_mut().take()).unwrap();
    assert_eq!(receivers[0].wire.markers, [1, 1], "the joiner settled");
    let expected = (0..TOTAL).filter(|&i| accepted(i) && kept(i)).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    assert_eq!(last.0, expected);
    (last, growth)
}

/// Red when the walk estimates from a sample that a logged change
/// followed: 18 to 36 times what the table holds, against about 1.9.
#[tokio::test(start_paused = true)]
async fn accepted_keys_denied_mid_sample_through_the_run_loop_fit() {
    let ((head, _), (control, _)) = Box::pin(with_control_async(|| {
        Box::pin(denied_mid_sample_in_the_run_loop())
    }))
    .await;
    assert_fits(head, control.2, "denied mid-sample, run loop");
}
