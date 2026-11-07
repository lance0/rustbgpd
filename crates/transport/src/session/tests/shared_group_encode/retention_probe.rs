//! Fresh-process lifecycle measurements. Run only this ignored test, with
//! `SHARED_RETENTION_PROBE_SHAPE=grouped_uc|grouped_vpn|diverse_uc`, using
//! `--release --features retention-probe -- --ignored --exact --nocapture`.
//! Compare identical probe sources over parent and candidate under the host
//! lock. This allocator applies only to Linux unit tests with the retention probe.

use super::*;
use crate::session::shared_group::ProgressiveGroupEncode;

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Copy)]
struct Memory {
    allocated: usize,
    active: usize,
    resident: usize,
    rss: u64,
    hwm: u64,
}

impl Memory {
    fn capture() -> Self {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let process_bytes = |name| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                * 1024
        };
        tikv_jemalloc_ctl::epoch::advance().unwrap();
        Self {
            allocated: tikv_jemalloc_ctl::stats::allocated::read().unwrap(),
            active: tikv_jemalloc_ctl::stats::active::read().unwrap(),
            resident: tikv_jemalloc_ctl::stats::resident::read().unwrap(),
            rss: process_bytes("VmRSS:"),
            hwm: process_bytes("VmHWM:"),
        }
    }

    fn print(self, shape: &str, phase: &str) {
        println!(
            "RETENTION_MEMORY {{\"shape\":\"{shape}\",\"phase\":\"{phase}\",\"allocated_bytes\":{},\"active_bytes\":{},\"resident_bytes\":{},\"rss_bytes\":{},\"hwm_bytes\":{}}}",
            self.allocated, self.active, self.resident, self.rss, self.hwm,
        );
    }
}

fn diverse_attributes(fixture: &mut RetirementFixture) {
    fixture.updates[1].announce = Arc::default();
    let routes = Arc::get_mut(&mut fixture.updates[0].announce).unwrap();
    for (index, route) in routes.iter_mut().enumerate() {
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.retain(|attr| {
                !matches!(attr, PathAttribute::Med(_) | PathAttribute::Communities(_))
            });
            attrs.push(PathAttribute::Med(u32::try_from(index).unwrap()));
            attrs.push(PathAttribute::Communities(
                (0..256).map(|value| 0xfde8_0000 + value).collect(),
            ));
        });
    }
    fixture.updates[1].announce = Arc::clone(&fixture.updates[0].announce);
}

fn announced(frame: &Bytes, vpn: bool) -> usize {
    let parsed = parse_frame(frame, false);
    if vpn {
        parsed
            .attributes
            .iter()
            .map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => mp.vpn_announced.len(),
                _ => 0,
            })
            .sum()
    } else {
        parsed.announced.len()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fresh-process probe keeps the encoder, delayed follower, blocked terminal and final destruction under one measured lifetime"
)]
#[tokio::test]
#[ignore = "fresh-process memory and drop-duration qualification under the host lock"]
async fn shared_retention_memory_probe() {
    let shape = std::env::var("SHARED_RETENTION_PROBE_SHAPE").unwrap();
    let (vpn, total) = match shape.as_str() {
        "grouped_uc" => (false, 1_000_000),
        "grouped_vpn" => (true, 1_000_000),
        "diverse_uc" => (false, 100_000),
        _ => panic!("unknown retention probe shape: {shape}"),
    };
    let baseline = Memory::capture();
    let mut fixture = RetirementFixture::new(vpn, total, total + 1);
    if shape == "diverse_uc" {
        diverse_attributes(&mut fixture);
    }
    let setup = Memory::capture();
    fixture.updates[1].end_of_rib =
        vec![(Afi::Ipv4, if vpn { Safi::MplsVpn } else { Safi::Unicast })];
    let update = fixture.updates.remove(0);
    fixture.members[0].0.test_drain_outbound(update).await;
    while fixture.members[0].2.try_recv().is_ok() {}
    let (stream, (chunks, wire_bytes, vector_bytes), last_frame_bytes) = {
        let cell = fixture.updates[0].shared_group_encode.as_ref().unwrap();
        let stream = Arc::clone(cell.cell.get().unwrap())
            .downcast::<ProgressiveGroupEncode>()
            .unwrap();
        let retained = stream.test_retained_bytes();
        let last = stream.snapshot_from(retained.0 - 1, 1).0[0].bytes.len();
        (Arc::downgrade(&stream), retained, last)
    };
    assert!(
        stream.upgrade().is_some(),
        "the unstarted follower owns the stream"
    );
    assert!(chunks > 1);
    let encoded = Memory::capture();
    let (writer, frames) = mpsc::channel(1);
    fixture.members[1].0.writer_bulk_tx = Some(writer);
    fixture.members[1].2 = frames;
    let update = fixture.updates.remove(0);
    let (member, _, frames) = &mut fixture.members[1];
    member.handle_outbound_route_update(update).await;
    let mut received = 0;
    for _ in 0..chunks {
        let next = member
            .pending_outbound
            .as_ref()
            .unwrap()
            .shared
            .as_ref()
            .unwrap()
            .1;
        let frame = frames.try_recv().unwrap();
        received += announced(&frame, vpn);
        drop(frame);
        if next == chunks - 1 {
            break;
        }
        member.advance_pending_outbound();
    }
    let before_last = Memory::capture();
    let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
    let deallocated = tikv_jemalloc_ctl::thread::deallocatedp::read().unwrap();
    let allocated_before = allocated.get();
    let deallocated_before = deallocated.get();
    let started = Instant::now();
    member.advance_pending_outbound();
    let final_announce_ns = started.elapsed().as_nanos();
    let allocated_delta = allocated.get() - allocated_before;
    let deallocated_delta = deallocated.get() - deallocated_before;
    let retained_at_eor = stream.upgrade().is_some();
    assert!(member.pending_outbound.as_ref().unwrap().shared.is_none());
    assert!(!member.pending_outbound.as_ref().unwrap().retiring());
    assert_eq!(member.writer_bulk_tx.as_ref().unwrap().capacity(), 0);
    let blocked_eor = Memory::capture();
    let frame = frames.try_recv().unwrap();
    assert_eq!(frame.len(), last_frame_bytes);
    received += announced(&frame, vpn);
    drop(frame);
    assert_eq!(received, total, "every announcement precedes EoR");

    let started = Instant::now();
    member.advance_pending_outbound();
    let eor_advance_ns = started.elapsed().as_nanos();
    let terminal = parse_frame(&frames.try_recv().unwrap(), false);
    assert_eq!(terminal.announced.len(), 0);
    if vpn {
        assert!(terminal.attributes.iter().any(|attr| matches!(attr,
            PathAttribute::MpUnreachNlri(mp) if mp.vpn_withdrawn.is_empty())));
    } else {
        assert!(terminal.attributes.is_empty() && terminal.withdrawn.is_empty());
    }
    let mut retirement_max_ns = 0;
    let mut retirement_steps = 0;
    let mut retirement_ns = Vec::new();
    let mut stream_drop_step_ns = if !retained_at_eor {
        final_announce_ns
    } else if stream.upgrade().is_none() {
        eor_advance_ns
    } else {
        0
    };
    for _ in 0..total + 32 {
        if member.pending_outbound.is_none() {
            break;
        }
        let held_before = stream.upgrade().is_some();
        let started = Instant::now();
        member.advance_pending_outbound();
        let elapsed = started.elapsed().as_nanos();
        retirement_max_ns = retirement_max_ns.max(elapsed);
        retirement_steps += 1;
        retirement_ns.push(elapsed);
        if held_before && stream.upgrade().is_none() {
            stream_drop_step_ns = elapsed;
        }
        tokio::task::yield_now().await;
    }
    assert!(member.pending_outbound.is_none());
    assert!(
        stream.upgrade().is_none(),
        "no stream owner survives retirement"
    );
    let retired = Memory::capture();
    for (phase, memory) in [
        ("baseline", baseline),
        ("setup", setup),
        ("encoded", encoded),
        ("before_last", before_last),
        ("blocked_eor", blocked_eor),
        ("retired", retired),
    ] {
        memory.print(&shape, phase);
    }
    println!(
        "RETENTION_RESULT {{\"shape\":\"{shape}\",\"routes\":{total},\"chunks\":{chunks},\"wire_bytes\":{wire_bytes},\"vector_bytes\":{vector_bytes},\"last_frame_bytes\":{last_frame_bytes},\"retained_at_eor\":{retained_at_eor},\"allocated_delta\":{allocated_delta},\"deallocated_delta\":{deallocated_delta},\"final_announce_ns\":{final_announce_ns},\"eor_advance_ns\":{eor_advance_ns},\"retirement_max_ns\":{retirement_max_ns},\"retirement_steps\":{retirement_steps},\"stream_drop_step_ns\":{stream_drop_step_ns},\"retirement_ns\":{retirement_ns:?}}}"
    );
}
