//! An unpaced source burst through real sessions, beside a healthy source.
//!
//! Both sources are stub peers over TCP loopback, so every route passes the
//! production session read path and its admission into the RIB's channel.
//! The burst source writes its whole table as fast as its socket accepts
//! it; the healthy source sends one single-route UPDATE at a fixed cadence
//! throughout. The burst receivers read normally.
//!
//! The harness owns the channel between the sessions and the RIB, and puts
//! a forwarding tap on it: sessions admit into the tap's ingress channel, a
//! dedicated thread forwards every message in order into the RIB's channel.
//! The two channels together hold what the daemon's one channel holds. The
//! tap stamps a healthy update when the session's message reaches it
//! (admission), and sends a `QueryLocRibCount` marker immediately ahead of
//! it; the RIB serves its primary lane in order, so the marker's reply is
//! the moment the RIB reached the update's place in the queue (dispatch).
//! The marker is not unicast route input, so it also ends the distribution
//! window before each healthy update: healthy updates never coalesce with
//! what precedes them. A marker behind every burst message tells when the
//! RIB finished it, so the burst messages queued ahead of a healthy update
//! are those sent before it and not finished at its admission. A burst
//! message of 1,024 routes fills the window's affected-prefix bound by
//! itself, so those markers end no window the RIB would have extended.
//! Smaller burst messages (`--routes-per-update`) share a window, so a
//! marker goes only behind the message that brings a window begun after
//! the previous marker to one of its bounds (distinct affected prefixes,
//! route entries or messages), and behind
//! the last; a burst message then counts as ahead until the marker of its
//! group is answered.

use std::collections::BTreeSet;
use std::thread;

use rustbgpd_wire::{Ipv4NlriEntry, Ipv4UnicastMode, UpdateMessage};

use super::*;
use crate::credit_wire::unicast_index;

/// Burst routes per UPDATE by default: the RIB's route chunk and the
/// distribution window's affected-prefix bound, so each message is one
/// window. That is past 4,096 bytes, so the burst source then negotiates
/// Extended Message.
const ROWS_PER_UPDATE: usize = 1_024;
/// The distribution window's bounds: distinct affected prefixes, route
/// entries and messages.
const WINDOW_PREFIXES: usize = 1_024;
const WINDOW_ROUTES: usize = 4 * WINDOW_PREFIXES;
const WINDOW_MESSAGES: usize = 256;
/// Capacity of each half of the tapped channel; the daemon's is 4,096.
const TAP_CAPACITY: usize = 2_048;
/// Healthy updates sent before the burst starts: the run's own baseline.
const LEAD: Duration = Duration::from_millis(500);
/// The healthy source keeps sending this long after the burst has settled.
const TAIL: Duration = Duration::from_millis(300);
/// The healthy update a seeded stall holds, inside the lead.
const STALL_SEQUENCE: u32 = 5;
/// Next hop of every route the sources send: a session rejects a loopback
/// next hop, so the sources' own addresses cannot serve.
const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const COMPILERS: [&str; 4] = ["cargo", "rustc", "rustdoc", "clippy-driver"];
const COMPILER_WATCH_EVERY: Duration = Duration::from_secs(1);

/// The cell's own flags, taken out of `args` before [`Options::parse`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Variant {
    /// Split the reduced workload between two established burst sessions.
    pub two_sources: bool,
    /// No healthy updates: the burst's uncontended ingest rate.
    pub control: bool,
    /// Seeded defect: hold one healthy update this long between its
    /// admission stamp and its marker.
    pub stall: Option<Duration>,
    /// Seeded defect: sleep this long between burst UPDATEs.
    pub burst_interval: Option<Duration>,
    /// Burst routes instead of the shape's own: the RIB-side residence
    /// proof runs two sizes and compares the readings.
    pub rows: Option<usize>,
    /// Burst routes per UPDATE instead of 1,024: a different, named shape.
    pub routes_per_update: Option<usize>,
}

impl Variant {
    pub fn take(args: &mut Vec<String>) -> Result<Self> {
        let mut variant = Self::default();
        let mut rest = Vec::new();
        let mut taken = std::mem::take(args).into_iter();
        while let Some(arg) = taken.next() {
            let mut millis = || -> Result<Duration> {
                let value = taken
                    .next()
                    .with_context(|| format!("{arg} needs a value"))?;
                Ok(Duration::from_millis(value.parse()?))
            };
            match arg.as_str() {
                "--two-sources" => variant.two_sources = true,
                "--control" => variant.control = true,
                "--stall-ms" => variant.stall = Some(millis()?),
                "--burst-interval-ms" => variant.burst_interval = Some(millis()?),
                "--rows" => {
                    let value = taken.next().context("--rows needs a value")?;
                    variant.rows = Some(value.parse()?);
                }
                "--routes-per-update" => {
                    let value = taken.next().context("--routes-per-update needs a value")?;
                    variant.routes_per_update = Some(value.parse()?);
                }
                _ => rest.push(arg),
            }
        }
        *args = rest;
        ensure!(
            variant.stall.is_none_or(|stall| stall < LEAD / 2),
            "a seeded stall must stay inside half the {LEAD:?} lead"
        );
        ensure!(
            !(variant.control && variant.stall.is_some()),
            "the control sends no healthy update to stall"
        );
        ensure!(variant.rows != Some(0), "--rows needs at least one route");
        ensure!(
            variant
                .routes_per_update
                .is_none_or(|routes| (1..=ROWS_PER_UPDATE).contains(&routes)),
            "--routes-per-update must be 1 to {ROWS_PER_UPDATE}"
        );
        if variant.two_sources {
            ensure!(
                !variant.control
                    && !variant.seeded()
                    && variant.routes_per_update() == ROWS_PER_UPDATE,
                "--two-sources uses the ordinary unpaced UPDATE size and a healthy source"
            );
            ensure!(
                variant.rows.is_none_or(|n| (2..=16_000).contains(&n)),
                "--two-sources needs 2 to 16000 total routes"
            );
        }
        Ok(variant)
    }

    fn seeded(self) -> bool {
        self.stall.is_some() || self.burst_interval.is_some()
    }

    fn routes_per_update(self) -> usize {
        self.routes_per_update.unwrap_or(ROWS_PER_UPDATE)
    }

    /// The result's cell name: a smaller UPDATE is its own shape.
    fn cell(self) -> &'static str {
        if self.two_sources {
            return "source-burst-two";
        }
        match (self.routes_per_update() == ROWS_PER_UPDATE, self.control) {
            (true, false) => "source-burst",
            (true, true) => "source-burst-control",
            (false, false) => "source-burst-small",
            (false, true) => "source-burst-small-control",
        }
    }
}

/// One burst message as the plan built it and as the tap saw it admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BurstMessage {
    announced: usize,
    withdrawn: usize,
    /// Burst index of its first route.
    first: Option<usize>,
}

#[derive(Debug)]
struct Admitted {
    sequence: u32,
    at: Instant,
    /// Messages in the RIB's channel when the update reached the tap; not
    /// the message the RIB was serving nor one it had taken to look ahead.
    depth: usize,
    /// Burst messages forwarded before this update.
    burst_before: usize,
    /// The forwarder had waited for room in the RIB's channel while this
    /// update sat in the ingress channel, so its admission stamp is late.
    late: bool,
}

impl Admitted {
    /// Burst messages ahead of this update at its admission: forwarded
    /// before it and not yet finished. A message finished within the
    /// stamper's wake-up time of the admission, or one whose group's marker
    /// was not yet answered, can read as still ahead.
    fn burst_ahead(&self, finished: &[(Instant, usize)]) -> usize {
        let answered = finished.partition_point(|&(done, _)| done <= self.at);
        let done = answered
            .checked_sub(1)
            .map_or(0, |last| finished[last].1.min(self.burst_before));
        self.burst_before - done
    }
}

#[derive(Debug, Default)]
struct TapLog {
    healthy: Vec<Admitted>,
    /// When the marker ahead of each healthy sequence was answered.
    dispatched: Vec<(u32, Instant)>,
    burst: Vec<(Instant, usize, BurstMessage)>,
    /// When each burst marker was answered, in order, with the burst
    /// messages forwarded ahead of it: the RIB had finished those.
    finished: Vec<(Instant, usize)>,
    markers_lost: usize,
    peak_depth: usize,
    /// Forwards that found the RIB's channel full and waited for room.
    #[cfg(test)]
    forwards_waited: usize,
}

struct TapConfig {
    burst: PeerId,
    second: Option<PeerId>,
    healthy: PeerId,
    stall: Option<Duration>,
    /// Per burst message in order: whether a marker goes behind it.
    marked: Vec<bool>,
}

enum Class {
    Healthy(u32),
    Burst(usize, BurstMessage),
    Other,
}

enum Mark {
    Healthy(u32),
    /// Behind this many burst messages.
    Burst(usize),
}

fn classify(update: &RibUpdate, config: &TapConfig) -> Class {
    // A session charges its route messages to its ingest budget; the permit
    // travels on through the tap with the message.
    let (peer, announced, withdrawn) = match update.unmetered() {
        RibUpdate::RoutesReceived {
            peer,
            announced,
            withdrawn,
            ..
        } => (*peer, announced, withdrawn),
        RibUpdate::WireRoutesReceived(batch) => (batch.peer, &batch.announced, &batch.withdrawn),
        _ => return Class::Other,
    };
    if peer == config.healthy {
        let sequence = announced.first().and_then(Route::med_attr);
        sequence.map_or(Class::Other, Class::Healthy)
    } else if peer == config.burst || Some(peer) == config.second {
        let first = announced
            .first()
            .map(|route| route.prefix)
            .or_else(|| withdrawn.first().map(|&(prefix, _)| prefix));
        Class::Burst(
            usize::from(Some(peer) == config.second),
            BurstMessage {
                announced: announced.len(),
                withdrawn: withdrawn.len(),
                first: first.and_then(unicast_index),
            },
        )
    } else {
        Class::Other
    }
}

/// Forward `ingress` into `rib` in order on a thread of its own, stamping
/// as the module documentation describes. A second thread waits for the
/// markers, so neither stamp waits for a runtime worker. Both end once
/// every session has dropped its sender.
fn tap(
    config: TapConfig,
    mut ingress: mpsc::Receiver<RibUpdate>,
    rib: mpsc::Sender<RibUpdate>,
    log: Arc<Mutex<TapLog>>,
) -> [thread::JoinHandle<()>; 2] {
    let (marks, answers) = std::sync::mpsc::channel::<(Mark, oneshot::Receiver<usize>)>();
    let stamps = Arc::clone(&log);
    let stamper = thread::spawn(move || {
        for (mark, answer) in answers {
            // Taken when this thread wakes, a little after the RIB answered.
            let answered = answer.blocking_recv().is_ok();
            let now = Instant::now();
            let mut log = stamps.lock().expect("tap log");
            match (answered, mark) {
                (false, _) => log.markers_lost += 1,
                (true, Mark::Healthy(sequence)) => log.dispatched.push((sequence, now)),
                (true, Mark::Burst(through)) => log.finished.push((now, through)),
            }
        }
    });
    let forwarder = thread::spawn(move || {
        // Forward one message; `Some(true)` when it had to wait for room.
        let forward = |update: RibUpdate| match rib.try_send(update) {
            Ok(()) => Some(false),
            Err(mpsc::error::TrySendError::Full(update)) => {
                #[cfg(test)]
                {
                    log.lock().expect("tap log").forwards_waited += 1;
                }
                rib.blocking_send(update).ok().map(|()| true)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => None,
        };
        // Messages that sat in `ingress` while a forward waited for room.
        let mut delayed: usize = 0;
        let mut burst_seen = 0;
        while let Some(update) = ingress.blocking_recv() {
            let at = Instant::now();
            let late = delayed > 0;
            delayed = delayed.saturating_sub(1);
            let class = classify(&update, &config);
            // A marker goes ahead of a healthy update and behind each
            // burst message.
            let (mut ahead, mut behind) = (None, None);
            match class {
                Class::Healthy(sequence) => {
                    let depth = rib.max_capacity() - rib.capacity();
                    {
                        let mut log = log.lock().expect("tap log");
                        log.peak_depth = log.peak_depth.max(depth);
                        log.healthy.push(Admitted {
                            sequence,
                            at,
                            depth,
                            burst_before: burst_seen,
                            late,
                        });
                    }
                    if let Some(stall) = config.stall.filter(|_| sequence == STALL_SEQUENCE) {
                        thread::sleep(stall);
                    }
                    ahead = Some(Mark::Healthy(sequence));
                }
                Class::Burst(source, message) => {
                    log.lock()
                        .expect("tap log")
                        .burst
                        .push((at, source, message));
                    burst_seen += 1;
                    if config.marked.get(burst_seen - 1) == Some(&true) {
                        behind = Some(Mark::Burst(burst_seen));
                    }
                }
                Class::Other => {}
            }
            for (mark, update) in [(ahead, None), (None, Some(update)), (behind, None)] {
                let update = match (mark, update) {
                    (Some(mark), _) => {
                        let (reply, answer) = oneshot::channel();
                        if marks.send((mark, answer)).is_err() {
                            return;
                        }
                        RibUpdate::QueryLocRibCount { reply }
                    }
                    (None, Some(update)) => update,
                    (None, None) => continue,
                };
                match forward(update) {
                    None => return,
                    Some(true) => delayed = delayed.max(ingress.len()),
                    Some(false) => {}
                }
            }
        }
    });
    [forwarder, stamper]
}

fn wire_update(announced: &[usize], withdrawn: &[usize], med: u32) -> Message {
    let entries = |indices: &[usize]| -> Vec<Ipv4NlriEntry> {
        indices
            .iter()
            .map(|&index| Ipv4NlriEntry {
                path_id: 0,
                prefix: Ipv4Prefix::new(unicast_prefix(index), 24),
            })
            .collect()
    };
    let attributes = if announced.is_empty() {
        Vec::new()
    } else {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::NextHop(NEXT_HOP),
            PathAttribute::LocalPref(100),
            PathAttribute::Med(med),
        ]
    };
    Message::Update(UpdateMessage::build(
        &entries(announced),
        &entries(withdrawn),
        &attributes,
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

fn healthy_update(sequence: u32) -> Message {
    let entry = Ipv4NlriEntry {
        path_id: 0,
        prefix: Ipv4Prefix::new(CHURN_PREFIX, 24),
    };
    let attributes = [
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(NEXT_HOP),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(sequence),
    ];
    Message::Update(UpdateMessage::build(
        &[entry],
        &[],
        &attributes,
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

/// The burst source's messages in order: every route announced, then the
/// churn plan's subset withdrawn and half of that announced again at a new
/// version, so the final table is exact only if the source's order held.
/// Also returns whether a marker goes behind each message ([`marked`]).
fn burst_plan(
    range: std::ops::Range<usize>,
    per_update: usize,
    withdrawn: &[usize],
    reannounced: &[usize],
) -> (Vec<(Message, BurstMessage)>, Vec<bool>) {
    let owned = |indices: &[usize]| {
        indices.partition_point(|i| *i < range.start)..indices.partition_point(|i| *i < range.end)
    };
    let withdrawn = &withdrawn[owned(withdrawn)];
    let reannounced = &reannounced[owned(reannounced)];
    let all: Vec<usize> = range.collect();
    let mut plan = Vec::new();
    let mut prefixes = Vec::new();
    let stages: [(&[usize], bool, u32); 3] = [
        (&all, true, BURST_VERSION),
        (withdrawn, false, 0),
        (reannounced, true, CHURN_VERSION),
    ];
    for (indices, announce, med) in stages {
        for chunk in indices.chunks(per_update) {
            let (up, down): (&[usize], &[usize]) =
                if announce { (chunk, &[]) } else { (&[], chunk) };
            plan.push((
                wire_update(up, down, med),
                BurstMessage {
                    announced: up.len(),
                    withdrawn: down.len(),
                    first: chunk.first().copied(),
                },
            ));
            prefixes.push(chunk);
        }
    }
    let marked = marked(&prefixes, per_update);
    (plan, marked)
}

/// Which burst messages carry a marker behind them, given each message's
/// prefixes: the one that brings a window begun after the previous marker
/// to a bound where the RIB closes it anyway, and the last. The bounds are
/// distinct affected prefixes (a churn tail that withdraws and announces a
/// prefix again counts it once), route entries and messages. With
/// 1,024-route messages, every one, the tail's shorter messages included.
fn marked(burst: &[&[usize]], per_update: usize) -> Vec<bool> {
    if per_update >= WINDOW_PREFIXES {
        return vec![true; burst.len()];
    }
    let mut affected = HashSet::new();
    let (mut routes, mut messages) = (0, 0);
    let mut marked: Vec<bool> = burst
        .iter()
        .map(|&message| {
            affected.extend(message.iter().copied());
            routes += message.len();
            messages += 1;
            let closes = affected.len() >= WINDOW_PREFIXES
                || routes >= WINDOW_ROUTES
                || messages >= WINDOW_MESSAGES;
            if closes {
                affected.clear();
                (routes, messages) = (0, 0);
            }
            closes
        })
        .collect();
    if let Some(last) = marked.last_mut() {
        *last = true;
    }
    marked
}

#[derive(Debug, Default)]
struct CompilerWatch {
    samples: usize,
    observed: usize,
    first: Option<String>,
    unavailable: Option<String>,
}

fn compilers_running() -> std::io::Result<Option<String>> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let name = match std::fs::read_to_string(entry.path().join("comm")) {
            Ok(name) => name,
            Err(error) if process_gone(&error) => continue,
            // Any other failure leaves the process unchecked.
            Err(error) => return Err(error),
        };
        if COMPILERS.contains(&name.trim()) {
            return Ok(Some(name.trim().to_string()));
        }
    }
    Ok(None)
}

/// A process that exited between the listing and the read: its directory
/// is gone (`ENOENT`) or it went while being read (`ESRCH`).
fn process_gone(error: &std::io::Error) -> bool {
    const ESRCH: i32 = 3;
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(ESRCH)
}

/// Sample the process table for a compiler until `stop`, as the timed
/// EVPN qualification cells do.
fn watch_compilers(stop: Arc<AtomicBool>) -> thread::JoinHandle<CompilerWatch> {
    thread::spawn(move || {
        let mut watch = CompilerWatch::default();
        loop {
            match compilers_running() {
                Ok(seen) => {
                    watch.samples += 1;
                    watch.observed += usize::from(seen.is_some());
                    watch.first = watch.first.or(seen);
                }
                Err(error) => {
                    watch.unavailable.get_or_insert(error.to_string());
                }
            }
            if stop.load(Ordering::Acquire) {
                return watch;
            }
            thread::park_timeout(COMPILER_WATCH_EVERY);
        }
    })
}

fn deny_all() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }])
}

#[derive(Default)]
struct WriteResult {
    /// Every message handed to the writer.
    submitted: Option<Instant>,
    written: Option<Instant>,
    paced: Duration,
    /// With a start barrier: this socket's first write finished, and the
    /// writer passed the barrier.
    first_written: Option<Instant>,
    continued: Option<Instant>,
}

/// Write `plan` on `receiver`'s socket. A writer the session stops reading
/// blocks; at `until` it gives up and its result records how far it got.
async fn send_burst(
    receiver: &mut Receiver,
    plan: &[(Message, BurstMessage)],
    interval: Duration,
    start: Option<&tokio::sync::Barrier>,
    until: tokio::time::Instant,
) -> Result<WriteResult> {
    let mut result = WriteResult::default();
    for (index, (message, _)) in plan.iter().enumerate() {
        if index != 0 && !interval.is_zero() {
            let slept = Instant::now();
            tokio::time::sleep(interval).await;
            result.paced += slept.elapsed();
        }
        let Ok(sent) = tokio::time::timeout_at(until, receiver.stub_tx.send(message.clone())).await
        else {
            return Ok(result);
        };
        sent?;
        if let Some(start) = start.filter(|_| index == 0) {
            // Both sockets finish their first write before either writer continues.
            let Ok(drained) = tokio::time::timeout_at(until, receiver.io.drain_writes(1)).await
            else {
                return Ok(result);
            };
            drained?;
            result.first_written = Some(Instant::now());
            if tokio::time::timeout_at(until, start.wait()).await.is_err() {
                return Ok(result);
            }
            result.continued = Some(Instant::now());
        }
    }
    result.submitted = Some(Instant::now());
    result.written = tokio::time::timeout_at(until, receiver.io.drain_writes(plan.len() as u64))
        .await
        .is_ok_and(|drained| drained.is_ok())
        .then(Instant::now);
    Ok(result)
}

/// The tap's admissions from `source`, and when the RIB finished them: the
/// first burst marker answered behind that source's last planned message.
fn source_completion(
    burst: &[(Instant, usize, BurstMessage)],
    finished: &[(Instant, usize)],
    source: usize,
    planned: usize,
) -> (Vec<BurstMessage>, Option<Instant>) {
    let received: Vec<(usize, BurstMessage)> = burst
        .iter()
        .enumerate()
        .filter(|(_, (_, peer, _))| *peer == source)
        .map(|(position, &(_, _, message))| (position + 1, message))
        .collect();
    let done = received
        .last()
        .filter(|_| received.len() == planned)
        .and_then(|&(through, _)| finished.iter().find(|&&(_, seen)| seen >= through))
        .map(|&(at, _)| at);
    (
        received.into_iter().map(|(_, message)| message).collect(),
        done,
    )
}

/// The distinct prefixes a plan's UPDATEs carry, decoded from the wire.
fn planned_prefixes(plan: &[(Message, BurstMessage)]) -> Result<BTreeSet<usize>> {
    let mut prefixes = BTreeSet::new();
    for (message, _) in plan {
        let Message::Update(update) = message else {
            bail!("a burst message is not an UPDATE");
        };
        let observed = crate::credit_wire::observe(update, WireFamily::Unicast)?;
        prefixes.extend(observed.announced.iter().map(|&(index, _)| index));
        prefixes.extend(observed.withdrawn);
    }
    Ok(prefixes)
}

/// The cell, or with `variant.control` its control without healthy updates.
pub async fn run(output: &Path, options: &Options, variant: Variant) -> Result<bool> {
    let cell = variant.cell();
    let per_update = variant.routes_per_update();
    let (receivers, rows, every, deadline) = if options.reduced || variant.two_sources {
        (
            8,
            16_000,
            Duration::from_millis(5),
            Duration::from_secs(120),
        )
    } else {
        (150, 150_000, CHURN_EVERY, Duration::from_secs(900))
    };
    let rows = variant.rows.unwrap_or(rows);
    let interval = variant.burst_interval.unwrap_or(Duration::ZERO);
    let unicast = vec![(Afi::Ipv4, Safi::Unicast)];

    let daemon = options
        .daemon
        .clone()
        .unwrap_or_else(tokio::runtime::Handle::current);
    let metrics = BgpMetrics::new();
    let (ingress, ingress_rx) = mpsc::channel(TAP_CAPACITY);
    let (rib, rib_rx) = mpsc::channel(TAP_CAPACITY);
    let (query, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rib_rx, query_rx, None, Some(CLUSTER), metrics.clone());
    let mut fixture = Fixture {
        metrics,
        rib: ingress,
        _query: query,
        manager: daemon.spawn(manager.run()),
        daemon,
        receivers: Vec::new(),
        sources: Vec::new(),
    };
    // Burst receivers, the healthy receiver, then the burst and healthy sources.
    let sources = if variant.two_sources { 2 } else { 1 };
    let (healthy, burst_source) = (receivers, receivers + 1);
    let healthy_source = burst_source + sources;
    let (withdrawn, reannounced) = churn_plan(rows);
    let reference = Arc::new(Reference::churned(
        rows,
        BURST_VERSION,
        &withdrawn,
        &reannounced,
        CHURN_VERSION,
    ));
    let mut plans = Vec::new();
    let mut marked = Vec::new();
    for source in 0..sources {
        let range = source * rows / sources..(source + 1) * rows / sources;
        let (plan, marks) = burst_plan(range, per_update, &withdrawn, &reannounced);
        plans.push(plan);
        marked.extend(marks);
    }
    // What each source's plan carries, read back from its UPDATEs, and the
    // single-source plan's length for the same table.
    let carried = plans
        .iter()
        .map(|plan| planned_prefixes(plan))
        .collect::<Result<Vec<_>>>()?;
    let single_source_messages = variant.two_sources.then(|| {
        burst_plan(0..rows, per_update, &withdrawn, &reannounced)
            .0
            .len()
    });
    // Two sources use the standard UPDATE size, with a marker on every
    // message, so their arrival order cannot change the marker placement.
    let messages = marked.len();
    let burst_markers = marked.iter().filter(|&&mark| mark).count();
    let extended = plans.iter().flatten().any(|(message, _)| {
        matches!(message, Message::Update(update)
            if update.encoded_len() > usize::from(rustbgpd_wire::MAX_MESSAGE_LEN))
    });
    let log = Arc::new(Mutex::new(TapLog::default()));
    let tap_threads = tap(
        TapConfig {
            burst: PeerId::from_ipv4(receiver_ip(burst_source)),
            second: variant
                .two_sources
                .then(|| PeerId::from_ipv4(receiver_ip(burst_source + 1))),
            healthy: PeerId::from_ipv4(receiver_ip(healthy_source)),
            stall: variant.stall,
            marked,
        },
        ingress_rx,
        rib,
        Arc::clone(&log),
    );
    let mut specs: Vec<ReceiverSpec> = (0..receivers)
        .map(|_| (unicast.clone(), Some(private_unicast_policy())))
        .collect();
    specs.push((unicast.clone(), Some(healthy_policy())));
    specs.extend((0..=sources).map(|_| (unicast.clone(), Some(deny_all()))));
    // Only burst sources can need messages past 4,096 bytes.
    fixture
        .connect_extended(specs, Duration::from_secs(120), |index| {
            extended && (burst_source..healthy_source).contains(&index)
        })
        .await?;
    let registered_peers = fixture.receivers.len();
    eprintln!("{cell}: {registered_peers} sessions established");

    let stop = watch::channel(false);
    let mut collectors = Vec::new();
    for receiver in &mut fixture.receivers[..receivers] {
        let mut rx = receiver.rx.take().expect("receiver stream");
        let mut stop_rx = stop.1.clone();
        let state = Arc::new(Mutex::new(WireState::with_reference(
            WireFamily::Unicast,
            Arc::clone(&reference),
        )));
        let shared = Arc::clone(&state);
        collectors.push((
            state,
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        message = rx.recv() => {
                            let now = Instant::now();
                            let mut state = shared.lock().expect("wire state");
                            match message {
                                Some(message) => state.apply(&message, now),
                                None => return state.closed(),
                            }
                        }
                        _ = stop_rx.changed() => return,
                    }
                }
            }),
        ));
    }
    // The healthy receiver logs the healthy sequence; the sources' own
    // streams only have to stay open.
    let churn_state = Arc::new(Mutex::new(ChurnState::default()));
    let mut observers = Vec::new();
    for (offset, receiver) in fixture.receivers[healthy..].iter_mut().enumerate() {
        let mut rx = receiver.rx.take().expect("peer stream");
        let mut stop_rx = stop.1.clone();
        let shared = Arc::clone(&churn_state);
        observers.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    message = rx.recv() => {
                        let now = Instant::now();
                        let mut state = shared.lock().expect("churn state");
                        match message {
                            Some(message) if offset == 0 => state.apply(&message, now),
                            Some(Message::Notification(_)) => state.resets += 1,
                            Some(_) => {}
                            None => return state.resets += 1,
                        }
                    }
                    _ = stop_rx.changed() => return,
                }
            }
        }));
    }
    let until = Instant::now() + Duration::from_secs(30);
    while !collectors
        .iter()
        .all(|(state, _)| state.lock().expect("wire state").eor_seen)
    {
        ensure!(Instant::now() < until, "a receiver got no End-of-RIB");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let histograms_before: Vec<Buckets> = TURN_HISTOGRAMS
        .iter()
        .map(|(name, label)| buckets(&fixture.metrics, name, label))
        .collect();
    let watching = Arc::new(AtomicBool::new(false));
    let compilers = watch_compilers(Arc::clone(&watching));
    let t0 = Instant::now();
    let sampling = Arc::new(AtomicBool::new(false));
    let instruments = sampler(
        fixture.metrics.clone(),
        t0,
        Vec::new(),
        false,
        SAMPLE,
        Arc::clone(&sampling),
    );
    let sent_log = Arc::new(Mutex::new(Vec::<(u32, Instant)>::new()));
    let churning = Arc::new(AtomicBool::new(variant.control));
    let churn = {
        let (tx, log) = (
            fixture.receivers[healthy_source].stub_tx.clone(),
            Arc::clone(&sent_log),
        );
        let stop = Arc::clone(&churning);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            for sequence in 1.. {
                tick.tick().await;
                if stop.load(Ordering::Acquire) {
                    return;
                }
                let sent = Instant::now();
                if tx.send(healthy_update(sequence)).await.is_err() {
                    return;
                }
                log.lock().expect("sent log").push((sequence, sent));
            }
        })
    };
    tokio::time::sleep(LEAD).await;

    // The burst: every message handed to the source's writer back to back.
    let until = tokio::time::Instant::now() + deadline;
    let first_sent = Instant::now();
    let (first, rest) = fixture.receivers[burst_source..healthy_source].split_at_mut(1);
    let barrier = tokio::sync::Barrier::new(sources);
    let first = send_burst(
        &mut first[0],
        &plans[0],
        interval,
        variant.two_sources.then_some(&barrier),
        until,
    );
    let writers = if let Some(second) = rest.first_mut() {
        let second = send_burst(second, &plans[1], interval, Some(&barrier), until);
        let (a, b) = tokio::try_join!(first, second)?;
        vec![a, b]
    } else {
        vec![first.await?]
    };
    let submitted = writers
        .iter()
        .map(|w| w.submitted)
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().max());
    let written = writers
        .iter()
        .map(|w| w.written)
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().max());
    let paced: Duration = writers.iter().map(|w| w.paced).sum();
    eprintln!("{cell}: burst written at {:?}", written.map(|at| at - t0));
    // Finished: the RIB answered the marker behind the burst and every
    // burst receiver's table is exact.
    let settled = loop {
        let done = log.lock().expect("tap log").finished.len() == burst_markers;
        if done
            && collectors
                .iter()
                .all(|(state, _)| state.lock().expect("wire state").exact())
        {
            break true;
        }
        if tokio::time::Instant::now() >= until {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    eprintln!("{cell}: settled {settled} at {:?}", t0.elapsed());
    tokio::time::sleep(TAIL).await;
    churning.store(true, Ordering::Release);
    churn.await?;
    let sent = sent_log.lock().expect("sent log").clone();
    let last_sent = sent.last().map(|&(sequence, _)| sequence);
    let received_last = || {
        let state = churn_state.lock().expect("churn state");
        state.arrivals.last().map(|&(sequence, _)| sequence)
    };
    let until = Instant::now() + QUIET_CAP;
    while received_last() != last_sent && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sampling.store(true, Ordering::Release);
    let mut instruments = instruments.await?;
    drop(fold_slice_maxima(
        &fixture.metrics,
        &mut instruments.slice_max_us,
    ));
    watching.store(true, Ordering::Release);
    compilers.thread().unpark();
    let compilers = compilers.join().expect("compiler watch");
    let units: Vec<Value> = TURN_HISTOGRAMS
        .iter()
        .zip(&histograms_before)
        .map(|((name, label), before)| longest(before, &buckets(&fixture.metrics, name, label)))
        .collect();
    let down = fixture.not_established().await;
    let _ = stop.0.send(true);
    for (_, collector) in &mut collectors {
        collector.await?;
    }
    for observer in observers {
        observer.await?;
    }

    let ms = |at: Instant| at.saturating_duration_since(t0).as_secs_f64() * 1e3;
    let (mut exact, mut missing, mut resets) = (0, 0, 0);
    let mut completion = None;
    for (state, _) in &collectors {
        let state = state.lock().expect("wire state");
        exact += usize::from(state.exact());
        missing += state.missing();
        resets += state.resets;
        completion = completion.max(state.settled_at);
    }
    let (arrivals, peer_resets, decode_failures) = {
        let state = churn_state.lock().expect("churn state");
        (state.arrivals.clone(), state.resets, state.decode_failures)
    };
    let log = std::mem::take(&mut *log.lock().expect("tap log"));
    let messages_finished = log.finished.last().map_or(0, |&(_, through)| through);
    let burst_done = (messages_finished == messages)
        .then(|| log.finished.last().map(|&(at, _)| at))
        .flatten();
    // Per healthy update: its four stamps and what was queued ahead of it.
    // A sequence the RIB replaced before delivery counts as received at
    // the first later sequence's arrival.
    let updates: Vec<Value> = sent
        .iter()
        .map(|&(sequence, sent)| {
            let admitted = log.healthy.iter().find(|a| a.sequence == sequence);
            let dispatched = log.dispatched.iter().find(|&&(seen, _)| seen == sequence);
            let received = arrivals
                .iter()
                .find(|&&(seen, at)| seen >= sequence && at >= sent);
            json!([
                sequence,
                ms(sent),
                admitted.map(|a| ms(a.at)),
                dispatched.map(|&(_, at)| ms(at)),
                received.map(|&(_, at)| ms(at)),
                admitted.map(|a| a.burst_ahead(&log.finished)),
                admitted.map(|a| a.depth),
            ])
        })
        .collect();
    let admitted_in_order = log
        .healthy
        .iter()
        .map(|a| a.sequence)
        .eq(sent.iter().map(|&(sequence, _)| sequence));
    let arrivals_in_order = arrivals.windows(2).all(|pair| pair[0].0 < pair[1].0);
    let mut in_order = true;
    let mut sources_done = true;
    let mut source_results = Vec::new();
    for (source, plan) in plans.iter().enumerate() {
        let (received, done) = source_completion(&log.burst, &log.finished, source, plan.len());
        let ordered = received.iter().eq(plan.iter().map(|(_, msg)| msg));
        let writer = &writers[source];
        in_order &= ordered;
        sources_done &= done.is_some() && writer.written.is_some() && received.len() == plan.len();
        let prefixes = &carried[source];
        source_results.push(json!({
            "peer": receiver_ip(burst_source + source).to_string(),
            "routes": prefixes.len(),
            "prefix_range": prefixes.first().zip(prefixes.last()).map(|(lo, hi)| [*lo, hi + 1]),
            "messages_planned": plan.len(), "messages_admitted": received.len(),
            "in_order": ordered, "written_ms": writer.written.map(ms), "rib_done_ms": done.map(ms),
            "first_written_ms": writer.first_written.map(ms), "continued_ms": writer.continued.map(ms),
        }));
    }
    let first_admitted = log.burst.first().map(|&(at, _, _)| at);
    let rate = |to: Option<Instant>| {
        to.map(|to| rows as f64 / to.saturating_duration_since(first_sent).as_secs_f64())
    };
    let last_admitted = log.burst.last().map(|&(at, _, _)| at);
    let flaps = Snapshot::take(&fixture.metrics).total("bgp_session_flaps_total");
    let mut result = json!({
        "schema": "rrtransport-credit/1",
        "cell": cell,
        "family": "unicast",
        "mode": if options.correctness_only || variant.two_sources || variant.seeded() || variant.rows.is_some() {
            "correctness"
        } else {
            "measured"
        },
        "shape": {
            "receivers": receivers,
            "routes": rows,
            "rows_per_update": per_update,
            "burst_messages": messages,
            "burst_markers": burst_markers,
            "extended_message": extended,
            "burst_interval_ms": interval.as_secs_f64() * 1e3,
            "healthy_every_ms": every.as_secs_f64() * 1e3,
            "healthy_lead_ms": LEAD.as_secs_f64() * 1e3,
            "registered_peers": registered_peers,
            "tap_capacity": [TAP_CAPACITY, TAP_CAPACITY],
        },
        "seeded": variant.stall.map(|stall| json!({
            "stall_ms": stall.as_secs_f64() * 1e3,
            "sequence": STALL_SEQUENCE,
        })),
        "host": {
            "compiler_watch": {
                "every_ms": COMPILER_WATCH_EVERY.as_secs_f64() * 1e3,
                "samples": compilers.samples,
                "observed": compilers.observed,
                "first": compilers.first,
                "unavailable": compilers.unavailable,
            },
        },
        // Every time is in ms from t0, when the healthy source started.
        "burst": {
            "first_sent_ms": ms(first_sent),
            "submitted_ms": submitted.map(ms),
            "written_ms": written.map(ms),
            "paced_sleep_ms": paced.as_secs_f64() * 1e3,
            "messages_admitted": log.burst.len(),
            "first_admitted_ms": first_admitted.map(ms),
            "last_admitted_ms": last_admitted.map(ms),
            "messages_finished": messages_finished,
            "rib_done_ms": burst_done.map(ms),
            "completion_ms": completion.filter(|_| settled).map(ms),
            // Routes over the time from the first write to the session's
            // last admission, and to the RIB finishing the last message.
            "admit_routes_per_s": rate(last_admitted),
            "ingest_routes_per_s": rate(burst_done),
        },
        "healthy": {
            "sent": sent.len(),
            "columns": [
                "sequence", "sent_ms", "admitted_ms", "dispatched_ms", "received_ms",
                "burst_ahead", "queue_depth",
            ],
            "updates": updates,
            "last_sent": last_sent,
            "last_received": arrivals.last().map(|&(sequence, _)| sequence),
            "markers_lost": log.markers_lost,
            "peak_queue_depth": log.peak_depth,
            // Admitted after waiting in the ingress channel for room in the
            // RIB's: their admission stamps, and so their readings, are late.
            "stamped_late": log.healthy.iter().filter(|a| a.late).count(),
        },
        "checks": {
            "final_state_exact": settled
                && exact == receivers
                && arrivals.last().map(|&(sequence, _)| sequence) == last_sent,
            "per_source_order": in_order && admitted_in_order && arrivals_in_order,
            "sessions_established": down.is_empty() && resets + peer_resets == 0 && flaps.unwrap_or(0.0) == 0.0,
        },
        "wire": {
            "exact_receivers": exact,
            "missing_routes": missing,
            "burst_messages_in_order": in_order,
            "healthy_admitted_in_order": admitted_in_order,
            "healthy_arrivals_in_order": arrivals_in_order,
            "healthy_decode_failures": decode_failures,
            "stub_resets": resets + peer_resets,
            "not_established": down,
            "session_flaps_total": flaps,
        },
        "actor": {
            "slice_max_us": instruments.slice_max_us,
            "turn_longest_ms": units[0],
            "work_longest_ms": units[1],
        },
        "memory": memory_json(&instruments),
    });
    if variant.two_sources {
        let errors = churn_state.lock().expect("churn state").unexpected_updates;
        result["wire"]["healthy_table_errors"] = json!(errors);
        result["shape"]["burst_sources"] = json!(sources);
        result["shape"]["single_source_messages"] = json!(single_source_messages);
        result["burst"]["sources"] = json!(source_results);
        result["checks"]["sources_complete"] = json!(sources_done);
        result["checks"]["healthy_converged"] = json!(
            last_sent.is_some()
                && received_last() == last_sent
                && decode_failures == 0
                && errors == 0
        );
    }
    write_result(output, &format!("{cell}.json"), &result)?;
    fixture.close().await?;
    // The tap ends when the last session drops its sender.
    let until = Instant::now() + Duration::from_secs(5);
    while tap_threads.iter().any(|thread| !thread.is_finished()) && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(recorded_pass(&result))
}

#[cfg(test)]
mod tests {
    //! Seeded defects for the tap: its reading must follow a delay of known
    //! size, wherever the delay sits between the two stamps.
    use super::*;

    const HELD: Duration = Duration::from_millis(150);

    struct Reading {
        wait: Duration,
        burst_ahead: usize,
        late: bool,
    }

    /// The tap between a test's burst and a RIB stand-in the test serves by
    /// hand. Every wait is on the tap's state, never on elapsed time.
    struct Stand {
        ingress: Option<mpsc::Sender<RibUpdate>>,
        rib: mpsc::Receiver<RibUpdate>,
        log: Arc<Mutex<TapLog>>,
        threads: [thread::JoinHandle<()>; 2],
        burst: usize,
        answered: usize,
        offered: Option<Instant>,
    }

    impl Stand {
        /// The tap with `burst` single-route burst messages in its ingress.
        fn new(burst: usize, stall: Option<Duration>) -> Self {
            let (ingress, ingress_rx) = mpsc::channel(TAP_CAPACITY);
            let (rib, rib_rx) = mpsc::channel(TAP_CAPACITY);
            let log = Arc::new(Mutex::new(TapLog::default()));
            let threads = tap(
                TapConfig {
                    burst: PeerId::from_ipv4(SOURCE),
                    second: None,
                    healthy: PeerId::from_ipv4(CHURN_SOURCE),
                    stall,
                    marked: vec![true; burst],
                },
                ingress_rx,
                rib,
                Arc::clone(&log),
            );
            for start in 0..burst {
                let update = source_update(Family::Unicast, start..start + 1, BURST_VERSION, 100);
                ingress.blocking_send(update).expect("tap open");
            }
            Self {
                ingress: Some(ingress),
                rib: rib_rx,
                log,
                threads,
                burst,
                answered: 0,
                offered: None,
            }
        }

        fn wait_until(&self, done: impl Fn(&TapLog) -> bool) {
            while !done(&self.log.lock().expect("tap log")) {
                thread::sleep(Duration::from_millis(1));
            }
        }

        /// Serve the next `count` forwarded messages, and return once the
        /// stamper has logged every marker answered so far.
        fn serve(&mut self, count: usize) {
            for _ in 0..count {
                let update = self.rib.blocking_recv().expect("tap open");
                if let RibUpdate::QueryLocRibCount { reply } = update {
                    reply.send(0).expect("marker waiting");
                    self.answered += 1;
                }
            }
            let answered = self.answered;
            self.wait_until(|log| log.finished.len() + log.dispatched.len() >= answered);
        }

        /// Offer the healthy update behind the burst; nothing follows it.
        fn offer(&mut self) {
            let ingress = self.ingress.take().expect("offered once");
            self.offered = Some(Instant::now());
            ingress
                .blocking_send(churn_update(STALL_SEQUENCE))
                .expect("tap open");
        }

        /// Serve everything left and read the healthy update. Its stamps lie
        /// between its offer and the end of the tap, whatever the timing.
        fn finish(mut self) -> Reading {
            while let Some(update) = self.rib.blocking_recv() {
                if let RibUpdate::QueryLocRibCount { reply } = update {
                    let _ = reply.send(0);
                }
            }
            for thread in self.threads {
                thread.join().expect("tap thread");
            }
            let ended = Instant::now();
            let log = self.log.lock().expect("tap log");
            assert_eq!(log.markers_lost, 0);
            assert_eq!(log.burst.len(), self.burst);
            assert_eq!(log.finished.len(), self.burst);
            let (admitted, dispatched) = (&log.healthy[0], log.dispatched[0]);
            assert_eq!(
                (admitted.sequence, dispatched.0),
                (STALL_SEQUENCE, STALL_SEQUENCE)
            );
            let offered = self.offered.expect("healthy update offered");
            assert!(offered <= admitted.at && dispatched.1 <= ended);
            Reading {
                wait: dispatched.1 - admitted.at,
                burst_ahead: admitted.burst_ahead(&log.finished),
                late: admitted.late,
            }
        }
    }

    /// One healthy update's reading behind `burst` burst messages, with a
    /// RIB stand-in that serves the first `taken` forwarded messages before
    /// the healthy update is offered, and the rest `held` after the tap
    /// stamped its admission.
    fn reading(burst: usize, taken: usize, held: Duration, stall: Option<Duration>) -> Reading {
        let mut stand = Stand::new(burst, stall);
        stand.serve(taken);
        stand.offer();
        stand.wait_until(|log| !log.healthy.is_empty());
        thread::sleep(held);
        stand.finish()
    }

    #[test]
    fn reading_follows_how_long_the_rib_left_the_update_queued() {
        let prompt = reading(0, 0, Duration::ZERO, None);
        assert_eq!(prompt.burst_ahead, 0);
        assert!(!prompt.late);
        let queued = reading(3, 0, HELD, None);
        let wait = queued.wait;
        assert!(wait >= HELD, "queued update read {wait:?}");
        assert_eq!(
            queued.burst_ahead, 3,
            "every burst message was still queued ahead"
        );
        assert!(!queued.late);
    }

    /// A burst message the RIB has taken but not finished is still ahead:
    /// the channel no longer holds it, its marker is not yet answered.
    #[test]
    fn burst_ahead_counts_the_message_the_rib_is_serving() {
        assert_eq!(reading(3, 1, HELD, None).burst_ahead, 3);
        // Its marker answered: the RIB finished the first message.
        assert_eq!(reading(3, 2, HELD, None).burst_ahead, 2);
    }

    /// More forwards than the RIB's channel holds: the forwarder waits for
    /// room while the healthy update sits in the ingress channel.
    #[test]
    fn an_update_held_in_ingress_by_a_full_channel_is_stamped_late() {
        // Each burst message forwards with its marker: 1,024 fill the
        // RIB's channel, and the forwarder waits on the next with the
        // healthy update behind it in the ingress. A full channel alone
        // does not say the forwarder has tried it yet.
        let burst = TAP_CAPACITY / 2 + 8;
        let mut stand = Stand::new(burst, None);
        stand.offer();
        stand.wait_until(|log| log.forwards_waited > 0);
        // The RIB finishes the first burst message, and its marker is
        // stamped, before the forwarder has room to reach the update.
        stand.serve(2);
        let held = stand.finish();
        assert!(held.late);
        // What the RIB finished while the update waited unstamped is missed.
        assert!(held.burst_ahead < burst, "read {}", held.burst_ahead);
    }

    #[test]
    fn reading_follows_a_seeded_stall_behind_the_admission_stamp() {
        let stalled = reading(0, 0, Duration::ZERO, Some(HELD)).wait;
        assert!(stalled >= HELD, "stalled update read {stalled:?}");
    }

    #[test]
    fn burst_plan_ends_with_an_order_sensitive_tail() {
        let (withdrawn, reannounced) = churn_plan(2_500);
        let (plan, marks) = burst_plan(0..2_500, ROWS_PER_UPDATE, &withdrawn, &reannounced);
        let shape: Vec<_> = plan
            .iter()
            .map(|(_, m)| (m.announced, m.withdrawn, m.first))
            .collect();
        assert_eq!(
            shape,
            [
                (1_024, 0, Some(0)),
                (1_024, 0, Some(1_024)),
                (452, 0, Some(2_048)),
                (0, 25, Some(0)),
                (13, 0, Some(0)),
            ]
        );
        for (message, _) in &plan {
            let Message::Update(update) = message else {
                panic!("burst message is not an UPDATE");
            };
            let bytes = update.encoded_len();
            assert!(bytes <= usize::from(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN));
        }
        let Message::Update(full) = &plan[0].0 else {
            panic!("burst message is not an UPDATE");
        };
        assert!(
            full.encoded_len() > 4_096,
            "a full message needs Extended Message"
        );
        assert_eq!(marks, [true; 5], "every message, as before");
    }

    #[test]
    fn split_preserves_the_single_source_work_and_each_prefix_owner() {
        let rows = 2_201;
        let (withdrawn, reannounced) = churn_plan(rows);
        let entries = |range: std::ops::Range<usize>| {
            let (plan, _) = burst_plan(range.clone(), ROWS_PER_UPDATE, &withdrawn, &reannounced);
            let mut by_prefix = BTreeMap::<usize, Vec<Option<u32>>>::new();
            for (wire, _) in plan {
                let Message::Update(update) = wire else {
                    panic!("expected UPDATE")
                };
                let observed = crate::credit_wire::observe(&update, WireFamily::Unicast).unwrap();
                for (index, version) in observed.announced {
                    assert!(range.contains(&index));
                    by_prefix.entry(index).or_default().push(version);
                }
                for index in observed.withdrawn {
                    assert!(range.contains(&index));
                    by_prefix.entry(index).or_default().push(None);
                }
            }
            by_prefix
        };
        let mut split = entries(0..rows / 2);
        split.extend(entries(rows / 2..rows));
        assert_eq!(split, entries(0..rows));
        assert_eq!(split.len(), rows);
    }

    #[test]
    fn the_tap_labels_each_burst_source_by_its_own_peer() {
        let update = source_update(Family::Unicast, 0..1, BURST_VERSION, 100);
        let other = PeerId::from_ipv4(Ipv4Addr::new(127, 0, 0, 9));
        let label = |burst, second| {
            let config = TapConfig {
                burst,
                second,
                healthy: PeerId::from_ipv4(CHURN_SOURCE),
                stall: None,
                marked: Vec::new(),
            };
            match classify(&update, &config) {
                Class::Burst(source, _) => Some(source),
                _ => None,
            }
        };
        let source = PeerId::from_ipv4(SOURCE);
        assert_eq!(label(source, None), Some(0));
        assert_eq!(label(source, Some(other)), Some(0));
        assert_eq!(label(other, Some(source)), Some(1));
        assert_eq!(label(other, None), None);
    }

    /// Each source is done at the first marker behind its own last message,
    /// not at the first marker of the run nor at the burst's last.
    #[test]
    fn each_source_finishes_at_the_marker_behind_its_own_last_message() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let message = |first| BurstMessage {
            announced: 1,
            withdrawn: 0,
            first: Some(first),
        };
        // Admission order: 0, 1, 0, 1, 1, with a marker behind each.
        let burst: Vec<_> = [(0, 0), (1, 10), (0, 1), (1, 11), (1, 12)]
            .into_iter()
            .map(|(source, first)| (at(0), source, message(first)))
            .collect();
        let finished: Vec<_> = (1..=5)
            .map(|through| (at(through * 10), through as usize))
            .collect();
        let (received, done) = source_completion(&burst, &finished, 0, 2);
        assert_eq!(received, [message(0), message(1)]);
        assert_eq!(done, Some(at(30)));
        let (received, done) = source_completion(&burst, &finished, 1, 3);
        assert_eq!(received, [message(10), message(11), message(12)]);
        assert_eq!(done, Some(at(50)));
        // A source short of its plan is not done, whatever was answered.
        assert_eq!(source_completion(&burst, &finished, 1, 4).1, None);
        // Its last message's marker not yet answered.
        assert_eq!(source_completion(&burst, &finished[..2], 0, 2).1, None);
    }

    #[test]
    fn planned_prefixes_read_what_each_plan_carries() {
        let rows = 2_201;
        let (withdrawn, reannounced) = churn_plan(rows);
        let carried = |range: std::ops::Range<usize>| {
            planned_prefixes(&burst_plan(range, ROWS_PER_UPDATE, &withdrawn, &reannounced).0)
                .unwrap()
        };
        let low = carried(0..rows / 2);
        assert_eq!(low, (0..rows / 2).collect());
        assert_eq!(carried(rows / 2..rows), (rows / 2..rows).collect());
        assert_eq!(carried(0..rows).len(), rows);
    }

    #[test]
    fn healthy_last_sequence_cannot_hide_an_unexpected_route() {
        let mut state = ChurnState::default();
        state.apply(&wire_update(&[1], &[], BURST_VERSION), Instant::now());
        state.apply(&healthy_update(2), Instant::now());
        assert_eq!(state.arrivals.last().unwrap().0, 2);
        assert_eq!(state.unexpected_updates, 1);
    }

    /// Positions (1-based) of the messages a marker goes behind.
    fn marker_positions(burst: &[Vec<usize>], per_update: usize) -> Vec<usize> {
        let burst: Vec<&[usize]> = burst.iter().map(Vec::as_slice).collect();
        marked(&burst, per_update)
            .iter()
            .enumerate()
            .filter_map(|(index, &mark)| mark.then_some(index + 1))
            .collect()
    }

    #[test]
    fn small_updates_carry_the_remainder_and_share_a_marker_per_window() {
        let (withdrawn, reannounced) = churn_plan(2_550);
        let (plan, marks) = burst_plan(0..2_550, 100, &withdrawn, &reannounced);
        let shape: Vec<_> = plan
            .iter()
            .map(|(_, m)| (m.announced, m.withdrawn, m.first))
            .collect();
        // 26 announcements, the last with the remainder; 26 withdrawals in
        // one message; 13 announced again.
        assert_eq!(shape.len(), 28);
        assert!(shape[..25]
            .iter()
            .enumerate()
            .all(|(index, &message)| message == (100, 0, Some(index * 100))));
        assert_eq!(
            shape[25..],
            [(50, 0, Some(2_500)), (0, 26, Some(0)), (13, 0, Some(0))]
        );
        for (message, _) in &plan {
            let Message::Update(update) = message else {
                panic!("burst message is not an UPDATE");
            };
            assert!(
                update.encoded_len() <= usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
                "a 100-route message needs no Extended Message"
            );
        }
        // A marker where 1,024 prefixes have accumulated since the last one
        // (the 11th and 22nd messages), and behind the last.
        let marks: Vec<usize> = marks
            .iter()
            .enumerate()
            .filter_map(|(index, &mark)| mark.then_some(index + 1))
            .collect();
        assert_eq!(marks, [11, 22, 28]);
        // One-route messages: the window's message bound closes it first.
        let single: Vec<Vec<usize>> = (0..600).map(|index| vec![index]).collect();
        assert_eq!(marker_positions(&single, 1), [256, 512, 600]);
    }

    /// The window's affected-prefix bound counts distinct prefixes: a churn
    /// tail that withdraws prefixes and announces them again counts each
    /// once, so a marker there would close a window the RIB extends.
    #[test]
    fn markers_count_distinct_prefixes_not_route_entries() {
        let withdrawn: Vec<usize> = (0..600).collect();
        let fresh: Vec<usize> = (600..1_100).collect();
        let tail = [withdrawn.clone(), withdrawn.clone(), fresh, vec![2_000]];
        // 1,200 entries but 600 prefixes after the second message.
        assert_eq!(marker_positions(&tail, 100), [3, 4]);
        // The route-entry bound (4,096) still closes a window first.
        let repeated = vec![(0..1_000).collect::<Vec<usize>>(); 6];
        assert_eq!(marker_positions(&repeated, 100), [5, 6]);
    }

    /// A message whose group's marker is unanswered still counts as ahead.
    #[test]
    fn burst_ahead_counts_by_answered_group() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let admitted = Admitted {
            sequence: 1,
            at: at(10),
            depth: 0,
            burst_before: 15,
            late: false,
        };
        assert_eq!(admitted.burst_ahead(&[]), 15);
        assert_eq!(admitted.burst_ahead(&[(at(5), 11)]), 4);
        assert_eq!(admitted.burst_ahead(&[(at(5), 11), (at(20), 22)]), 4);
        assert_eq!(admitted.burst_ahead(&[(at(20), 11)]), 15);
    }

    #[test]
    fn variant_takes_only_its_own_flags() {
        let mut args: Vec<String> = [
            "--reduced",
            "--stall-ms",
            "200",
            "--burst-interval-ms",
            "5",
            "--rows",
            "32000",
            "--routes-per-update",
            "100",
        ]
        .map(String::from)
        .into();
        let variant = Variant::take(&mut args).expect("flags");
        assert_eq!(args, ["--reduced"]);
        assert_eq!(variant.stall, Some(Duration::from_millis(200)));
        assert_eq!(variant.burst_interval, Some(Duration::from_millis(5)));
        assert_eq!(variant.rows, Some(32_000));
        assert_eq!(variant.routes_per_update(), 100);
        assert_eq!(variant.cell(), "source-burst-small");
        assert!(variant.seeded() && !variant.control);
        let named = |flags: &[&str]| {
            let mut args = flags.iter().map(ToString::to_string).collect();
            Variant::take(&mut args).map(Variant::cell)
        };
        assert_eq!(named(&[]).expect("default"), "source-burst");
        assert_eq!(named(&["--two-sources"]).unwrap(), "source-burst-two");
        assert!(named(&["--two-sources", "--rows", "1"]).is_err());
        assert!(named(&["--two-sources", "--routes-per-update", "100"]).is_err());
        let control = named(&["--control", "--routes-per-update", "1024"]);
        assert_eq!(control.expect("explicit default"), "source-burst-control");
        let small = named(&["--control", "--routes-per-update", "1"]);
        assert_eq!(small.expect("smallest"), "source-burst-small-control");
        for bad in ["0", "1025", "x"] {
            assert!(named(&["--routes-per-update", bad]).is_err(), "{bad}");
        }
        assert!(named(&["--routes-per-update"]).is_err(), "no value");
        let mut late = vec!["--stall-ms".to_string(), "400".to_string()];
        assert!(Variant::take(&mut late).is_err(), "a stall past the lead");
        let mut empty = vec!["--rows".to_string(), "0".to_string()];
        assert!(Variant::take(&mut empty).is_err(), "an empty burst");
    }

    #[test]
    fn only_a_vanished_process_is_skipped() {
        assert!(process_gone(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
        assert!(process_gone(&std::io::Error::from_raw_os_error(3)));
        assert!(!process_gone(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }
}
