//! Private exported-source counters. Never linked by a normal repository build.
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static WORK: RefCell<Option<Work>> = const { RefCell::new(None) };
}
static NEXT: AtomicU64 = AtomicU64::new(1);
static CHANNELS: std::sync::Mutex<Vec<tokio::sync::mpsc::WeakSender<super::OutboundRouteUpdate>>> =
    std::sync::Mutex::new(Vec::new());

pub(super) fn channel_id(tx: &tokio::sync::mpsc::Sender<super::OutboundRouteUpdate>) -> u64 {
    let mut channels = CHANNELS.lock().expect("terminal channel observer");
    if let Some(index) = channels.iter().position(|channel| {
        channel
            .upgrade()
            .is_some_and(|sender| sender.same_channel(tx))
    }) {
        return index as u64 + 1;
    }
    // Weak identity observes reconnects without keeping a sender alive.
    channels.push(tx.downgrade());
    channels.len() as u64
}

#[derive(Default)]
struct Work {
    id: u64,
    group: usize,
    keys: usize,
    debtors: usize,
    stage_rows: u64,
    delta_rows: u64,
    prepare: u64,
    projection_walks: u64,
    projection_rows: u64,
    current_walks: u64,
    current_rows: u64,
    old_walks: u64,
    old_rows: u64,
    old_delta_rows: u64,
    success_walks: u64,
    success_rows: u64,
    data_admissions: u64,
    data_rows: u64,
    terminal_admissions: u64,
}

pub(super) fn wall_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("terminal observer clock")
        .as_micros()
}

pub(super) struct Scope(std::time::Instant);
impl Scope {
    pub(super) fn new(group: usize, keys: usize, debtors: usize) -> Self {
        WORK.with_borrow_mut(|slot| {
            assert!(slot.is_none(), "nested terminal producer observation");
            *slot = Some(Work {
                id: NEXT.fetch_add(1, Ordering::Relaxed),
                group,
                keys,
                debtors,
                ..Work::default()
            });
        });
        Self(std::time::Instant::now())
    }
}

pub(super) fn count(kind: &str, rows: usize) {
    WORK.with_borrow_mut(|slot| {
        if let Some(work) = slot {
            let value = match kind {
                "stage" => &mut work.stage_rows,
                "delta" => &mut work.delta_rows,
                "prepare" => &mut work.prepare,
                "projection_walk" => &mut work.projection_walks,
                "projection" => &mut work.projection_rows,
                "current_walk" => &mut work.current_walks,
                "current" => &mut work.current_rows,
                "old_walk" => &mut work.old_walks,
                "old" => &mut work.old_rows,
                "old_delta" => &mut work.old_delta_rows,
                "success_walk" => &mut work.success_walks,
                "success" => &mut work.success_rows,
                "data_admission" => &mut work.data_admissions,
                "data_rows" => &mut work.data_rows,
                "terminal_admission" => &mut work.terminal_admissions,
                _ => panic!("unknown private terminal counter"),
            };
            *value += rows as u64;
        }
    });
}

// Cumulative per-peer attempts and refusals at every standalone terminal-marker
// `try_send` site, in `MARKER_SITES` order. Absent sites are never reported as zero.
const MARKER_SITES: [&str; 3] = ["flush", "retry", "initial"];
static MARKERS: std::sync::Mutex<Vec<(crate::PeerId, [u64; 6])>> =
    std::sync::Mutex::new(Vec::new());

pub(super) fn marker(peer: crate::PeerId, site: &str, refused: bool) {
    let index = MARKER_SITES
        .iter()
        .position(|name| *name == site)
        .expect("unknown terminal marker site");
    let mut rows = MARKERS.lock().expect("terminal marker observer");
    let row = rows
        .iter()
        .position(|(key, _)| *key == peer)
        .unwrap_or_else(|| {
            rows.push((peer, [0; 6]));
            rows.len() - 1
        });
    rows[row].1[2 * index] += 1;
    rows[row].1[2 * index + 1] += u64::from(refused);
}

pub(super) fn markers(peer: crate::PeerId) -> String {
    let rows = MARKERS.lock().expect("terminal marker observer");
    let counts = rows
        .iter()
        .find(|(key, _)| *key == peer)
        .map_or([0; 6], |(_, counts)| *counts);
    let fields: Vec<String> = MARKER_SITES
        .iter()
        .enumerate()
        .map(|(index, site)| {
            format!(
                "\"{site}_attempts\":{},\"{site}_refused\":{}",
                counts[2 * index],
                counts[2 * index + 1]
            )
        })
        .collect();
    format!("{{{}}}", fields.join(","))
}

pub(super) fn id() -> u64 {
    WORK.with_borrow(|slot| slot.as_ref().map_or(0, |work| work.id))
}

impl Drop for Scope {
    fn drop(&mut self) {
        let work = WORK
            .with_borrow_mut(Option::take)
            .expect("terminal producer scope");
        eprintln!(
            concat!(
                "evpn_terminal_work {{\"wall_us\":{},\"id\":{},\"group\":{},",
                "\"keys\":{},\"debtors_before\":{},\"stage_rows\":{},\"delta_rows\":{},",
                "\"prepare_attempts\":{},\"projection_walks\":{},\"projection_rows\":{},",
                "\"current_walks\":{},\"current_rows\":{},\"old_walks\":{},\"old_rows\":{},",
                "\"old_delta_rows\":{},\"success_walks\":{},\"success_rows\":{},",
                "\"data_admissions\":{},\"data_rows\":{},\"terminal_admissions\":{},\"elapsed_us\":{}}}"
            ),
            wall_us(),
            work.id,
            work.group,
            work.keys,
            work.debtors,
            work.stage_rows,
            work.delta_rows,
            work.prepare,
            work.projection_walks,
            work.projection_rows,
            work.current_walks,
            work.current_rows,
            work.old_walks,
            work.old_rows,
            work.old_delta_rows,
            work.success_walks,
            work.success_rows,
            work.data_admissions,
            work.data_rows,
            work.terminal_admissions,
            self.0.elapsed().as_micros()
        );
    }
}
