//! Rows that reach a walking receiver's EVPN table outside its cursor
//! steps: an RT-Constrain membership change restages every EVPN key into
//! the receiver's own owed set, which drains ahead of the cursor, and
//! ordinary passes, relogs, withdrawals and a route refresh land while the
//! walk runs. The presize rate counts only what the cursor steps read and
//! committed, so none of these rows can raise it: every table ends at or
//! below the capacities of the same walk with the presize off.

use std::cell::RefCell;

use super::super::cursor_presize::{
    assert_at_or_below_control, assert_fitted, with_control, with_control_async,
};
use super::*;

/// The EVPN table of `peer`: rows, and the capacities of its index and of
/// the slab's first segment.
fn evpn_table(manager: &RibManager, peer: PeerId) -> (usize, [usize; 2]) {
    let out = &manager.adj_ribs_out[&peer];
    let (index, segment) = out.evpn_capacities();
    (out.evpn_len(), [index, segment])
}

/// A manager whose VPN peers group (RT-Constrain membership is grouped
/// state), one receiver step per resync tick.
fn rtc_manager(credit: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(credit);
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

/// Receiver `index` imports Route Target `add` (and drops `drop`).
fn membership_update(index: u8, add: u16, drop: Option<u16>) -> RibUpdate {
    let address = Ipv4Addr::new(10, 0, 9, index + 1);
    RibUpdate::RtcRoutesReceived {
        peer: receiver(index),
        session_id: 0,
        announced: vec![make_rtc_rib_route(address, add, 100)],
        withdrawn: drop
            .map(|value| make_rtc_rib_route(address, value, 100).key())
            .into_iter()
            .collect(),
    }
}

fn rtc_eor(index: u8) -> RibUpdate {
    RibUpdate::EndOfRib {
        peer: receiver(index),
        session_id: 0,
        afi: RTC.0,
        safi: RTC.1,
    }
}

/// Keys of `rows` the cursor of `peer` has passed.
fn passed(manager: &RibManager, peer: PeerId, rows: u32) -> usize {
    (0..rows)
        .filter(|&index| manager.owed_evpn_cursor_passed(peer, &key(index)))
        .count()
}

/// Receivers 0 (R) and 1 hold VPN in one update group and EVPN privately,
/// and import Route Target 100. R owes EVPN whole.
fn rtc_receivers(manager: &mut RibManager) -> Vec<Receiver> {
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    std::mem::forget(up_sized(manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let receivers: Vec<Receiver> = (0..2)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_sized(manager, peer, 0, 4096, &families);
            manager.handle_update(membership_update(index, 100, None));
            manager.handle_update(rtc_eor(index));
            Wire::default().write(&mut rx);
            assert!(manager.vpn_grouped_member_of(peer).is_some(), "grouped VPN");
            assert!(
                manager.evpn_grouped_member_of(peer).is_none(),
                "private EVPN"
            );
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect();
    let r = receivers[0].peer;
    manager.owe_eor(r, EVPN);
    manager.owe_whole_family(r, FAMILY);
    receivers
}

// ---- A membership change under a live cursor.

const RESTAGE_ROWS: u32 = 20_000;

/// One in 97 keys carries RT 100 (imported from the start), one in 13 of
/// the rest RT 200 (imported after the membership change), the rest RT 300.
fn rt_of(index: u32) -> u16 {
    if index.is_multiple_of(97) {
        100
    } else if index.is_multiple_of(13) {
        200
    } else {
        300
    }
}

fn restaged_rows() -> usize {
    (0..RESTAGE_ROWS).filter(|&i| rt_of(i) != 300).count()
}

/// R walks a 20,000-key EVPN debt at 128 keys a step, importing 1% of
/// them. After its first step its membership adds RT 200 (7.6% of keys,
/// no winner changed): the restage joins R's own set, which drains ahead
/// of the cursor, so about 1,540 rows land in the table outside the
/// cursor steps.
fn restage_under_a_cursor() -> (usize, [usize; 2]) {
    let mut manager = rtc_manager(256);
    let mut receivers = rtc_receivers(&mut manager);
    let r = receivers[0].peer;
    let routes = (0..RESTAGE_ROWS)
        .map(|i| route_rt(i, 0, &[rt_of(i)]))
        .collect();
    received_routes(&mut manager, routes, &[]);
    let mut walked = 0;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
        walked = passed(&manager, r, RESTAGE_ROWS);
        if walked != 0 {
            break;
        }
    }
    assert!(walked != 0 && walked < 512, "walked {walked}");
    manager.handle_update(membership_update(0, 200, None));
    assert!(!manager.dirty_peers.contains(&r), "no resync");
    assert!(manager.owed_key_count(r, FAMILY) > 0, "R's set restaged");
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), restaged_rows(), "R's table");
    evpn_table(&manager, r)
}

/// Red with the rate taken from the table's growth since the walk began:
/// the restaged rows read as several rows a key, clamped to one, and the
/// index is reserved for every key ahead (about 16 times what it holds,
/// against 1.04 times without the presize).
#[test]
fn an_rtc_restage_under_an_evpn_cursor_does_not_raise_the_rate() {
    let ((rows, head), (_, control)) = with_control(restage_under_a_cursor);
    assert_at_or_below_control(&head, &control, "RTC restage");
    assert_fitted(head[0], rows, "RTC restage");
}

// The same restage through `RibManager::run_actor` on a paused clock.

thread_local! {
    /// (R, R's EVPN rows, R's own owed keys, whether R owes EVPN whole,
    /// keys R's cursor has passed) after the last actor turn.
    static R_STATE: RefCell<(Option<PeerId>, usize, usize, bool, usize)> =
        const { RefCell::new((None, 0, 0, false, 0)) };
}

fn watch_r(manager: &RibManager) {
    R_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(r) = state.0 {
            state.1 = manager
                .adj_ribs_out
                .get(&r)
                .map_or(0, crate::adj_rib_out::AdjRibOut::evpn_len);
            state.2 = manager.owed_key_count(r, FAMILY);
            state.3 = manager.owes_whole(r, FAMILY);
            state.4 = passed(manager, r, RESTAGE_ROWS);
        }
    });
}

fn r_state() -> (usize, usize, bool, usize) {
    R_STATE.with(|state| {
        let state = state.borrow();
        (state.1, state.2, state.3, state.4)
    })
}

fn actor_peer_up(
    peer: PeerId,
    families: &[(Afi, Safi)],
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (outbound_tx, output) = mpsc::channel(4096);
    let update = RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
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

fn evpn_routes(routes: Vec<EvpnRibRoute>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: routes,
        evpn_withdrawn: vec![],
        validated_with: None,
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

/// `ticks` 10 ms ticks; the receivers marked `reading` write after each.
async fn run_ticks(
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

/// No direct call: R and a sibling come up, R stops reading, 150 RT 100
/// rows spend R's credit and overflow its owed set past the byte cap (a
/// cursor at the list head, the set kept), and 20,000 rows are logged
/// ahead of it. R reads until its kept set has drained and its cursor has
/// stepped, and its membership then adds RT 200; then it reads to the end.
async fn actor_restage_under_a_cursor() -> (usize, [usize; 2]) {
    const EARLY: u32 = 150;
    let mut manager = rtc_manager(64);
    manager.actor_turn_check = Some(watch_r);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run_actor());
    let (update, source_rx) = actor_peer_up(peer_v4(SOURCE), &[V4]);
    tx.send(update).await.unwrap();
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    let mut receivers = Vec::new();
    for index in 0..2 {
        let (update, rx) = actor_peer_up(receiver(index), &families);
        tx.send(update).await.unwrap();
        tx.send(membership_update(index, 100, None)).await.unwrap();
        tx.send(rtc_eor(index)).await.unwrap();
        receivers.push(Receiver {
            peer: receiver(index),
            rx,
            wire: Wire::default(),
        });
    }
    run_ticks(&tx, &mut receivers, &[true; 2], 20).await;
    let r = receivers[0].peer;
    R_STATE.with(|state| state.borrow_mut().0 = Some(r));
    let early = (0..EARLY)
        .map(|i| route_rt(1_000_000 + i, 0, &[100]))
        .collect();
    tx.send(evpn_routes(early)).await.unwrap();
    run_ticks(&tx, &mut receivers, &[false, true], 3).await;
    assert!(r_state().2, "the byte cap started a cursor");
    let routes = (0..RESTAGE_ROWS)
        .map(|i| route_rt(i, 0, &[rt_of(i)]))
        .collect();
    tx.send(evpn_routes(routes)).await.unwrap();
    run_ticks(&tx, &mut receivers, &[false, true], 3).await;
    let mut walked = 0;
    for _ in 0..200 {
        run_ticks(&tx, &mut receivers, &[true; 2], 1).await;
        walked = r_state().3;
        if walked != 0 {
            break;
        }
    }
    assert!(walked != 0 && walked < 512, "walked {walked}");
    tx.send(membership_update(0, 200, None)).await.unwrap();
    barrier(&tx).await;
    assert!(r_state().1 > 0, "R's set restaged");
    let expected = restaged_rows() + EARLY as usize;
    for _ in 0..100 {
        run_ticks(&tx, &mut receivers, &[true; 2], 50).await;
        let (_, owed, whole, _) = r_state();
        if receivers[0].wire.table.len() == expected && owed == 0 && !whole {
            break;
        }
    }
    drop(tx);
    let manager = actor.await.unwrap();
    drop(source_rx);
    R_STATE.with(|state| state.borrow_mut().0 = None);
    assert!(!manager.owes(r, EVPN), "R settled");
    assert_eq!(receivers[0].wire.table.len(), expected, "R's table");
    evpn_table(&manager, r)
}

/// Red with the rate taken from the table's growth since the walk began:
/// about 15 times what it holds, against 1.9 times without the presize.
#[tokio::test(start_paused = true)]
async fn an_rtc_restage_under_an_evpn_cursor_through_the_actor_loop_fits() {
    let ((rows, head), (_, control)) = with_control_async(actor_restage_under_a_cursor).await;
    assert_at_or_below_control(&head, &control, "actor RTC restage");
    assert_fitted(head[0], rows, "actor RTC restage");
}

// ---- Injection at random points of a walk.

/// Keys of the injected walk; its cursor reads 128 a step, so about 160
/// ticks.
const WALK_ROWS: u32 = 20_000;
const WALK_TICKS: u64 = 160;

/// One in 40 keys carries RT 100 (imported from the start: the cursor's
/// sample completes after about 10,000 keys), the other multiples of 20 RT
/// 200 (500 more rows, imported on a restage), the rest RT 300. R's final
/// table stays under the presize limit and mid-way in its index's capacity
/// class, so only an over-reservation crosses it.
fn walk_rt(index: u32) -> u16 {
    if index.is_multiple_of(40) {
        100
    } else if index.is_multiple_of(20) {
        200
    } else {
        300
    }
}

/// A non-cursor path into R's table.
#[derive(Debug, Clone, Copy)]
enum Inject {
    /// An ordinary pass: 200 new RT 100 keys.
    Distribute,
    /// R's membership adds RT 200: every EVPN key joins R's own set.
    Restage,
    /// 300 keys change payload, logged again ahead of the cursor.
    Relog,
    /// 300 keys withdrawn.
    Withdraw,
    /// R asks for a route refresh of EVPN.
    Refresh,
}

/// Tiny deterministic generator (xorshift64).
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// The injections of `seed`: each path at a random tick of the walk (a
/// refresh in half the seeds), with a random key range.
fn schedule(seed: u64) -> Vec<(u64, Inject, u32)> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut plan = Vec::new();
    for inject in [
        Inject::Distribute,
        Inject::Restage,
        Inject::Relog,
        Inject::Withdraw,
        Inject::Refresh,
    ] {
        if matches!(inject, Inject::Refresh) && next(&mut state).is_multiple_of(2) {
            continue;
        }
        // Half the points fall in the first eight ticks, while the cursor's
        // sample is still forming; the rest anywhere in the walk.
        let window = if next(&mut state).is_multiple_of(2) {
            8
        } else {
            WALK_TICKS
        };
        let at = next(&mut state) % window;
        let from = u32::try_from(next(&mut state) % u64::from(WALK_ROWS - 300)).unwrap();
        plan.push((at, inject, from));
    }
    plan
}

fn inject(manager: &mut RibManager, r: PeerId, inject: Inject, from: u32) {
    match inject {
        Inject::Distribute => {
            let fresh = (0..200)
                .map(|i| route_rt(2_000_000 + from + i, 0, &[100]))
                .collect();
            received_routes(manager, fresh, &[]);
        }
        Inject::Restage => manager.handle_update(membership_update(0, 200, None)),
        Inject::Relog => {
            let again = (from..from + 300)
                .map(|i| route_rt(i, 1, &[walk_rt(i)]))
                .collect();
            received_routes(manager, again, &[]);
        }
        Inject::Withdraw => {
            let gone: Vec<u32> = (from..from + 300).collect();
            received_routes(manager, vec![], &gone);
        }
        Inject::Refresh => refresh_request(manager, r),
    }
}

/// R walks [`WALK_ROWS`] keys at 128 keys a step while `plan` injects
/// rows into its table. Returns R's table as sent, its rows, the
/// capacities and the presizes made.
fn injected_walk(
    plan: &[(u64, Inject, u32)],
) -> (BTreeMap<EvpnRouteKey, String>, usize, [usize; 2], usize) {
    let mut manager = rtc_manager(256);
    let mut receivers = rtc_receivers(&mut manager);
    let r = receivers[0].peer;
    let routes = (0..WALK_ROWS)
        .map(|i| route_rt(i, 0, &[walk_rt(i)]))
        .collect();
    received_routes(&mut manager, routes, &[]);
    for at in 0..WALK_TICKS {
        for &(_, path, from) in plan.iter().filter(|(when, _, _)| *when == at) {
            inject(&mut manager, r, path, from);
        }
        tick(&mut manager, &mut receivers);
    }
    drain(&mut manager, &mut receivers);
    assert!(!manager.owes(r, EVPN), "R settled");
    let (rows, capacities) = evpn_table(&manager, r);
    assert_eq!(receivers[0].wire.table.len(), rows, "R's table as sent");
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    (receivers[0].wire.table.clone(), rows, capacities, presizes)
}

/// Every seed's walk, with rows injected from each non-cursor path at
/// random points, ends with the same table as the control and capacities
/// at or below its, and some seeds do presize. Red with the rate taken
/// from the table's growth since the walk began: a restage while the
/// sample is still short reads as one row a key.
#[test]
fn rows_injected_outside_the_cursor_never_size_past_the_control() {
    let mut seeds_presized = 0;
    for seed in 0..12 {
        let plan = schedule(seed);
        let ((table, rows, head, presizes), (control_table, _, control, _)) =
            with_control(|| injected_walk(&plan));
        let case = format!("seed {seed} {plan:?}");
        assert_eq!(table, control_table, "{case}: same table");
        assert_at_or_below_control(&head, &control, &case);
        assert_fitted(head[0], rows, &case);
        seeds_presized += usize::from(presizes != 0);
    }
    assert!(seeds_presized > 0, "no seed presized");
}
