//! LAN-333 reload-stall harness: N real BGP stub clients dial into a
//! running rustbgpd route server over loopback TCP, announce a full
//! table, run steady churn, then drive changed-policy SIGHUP reloads
//! and measure UPDATE-delivery gaps at every receiving client.
//!
//! Shape pinned in docs/perf/reload-stall-2026-07.md.
//!
//! Usage:
//!   reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
//!       <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
//!       [changed_peers] [reload_cmd] [--flapstorm K] [--convergence-only]
//!
//! Stubs bind distinct 127.1.x.y source addresses (matching the
//! generated [[neighbors]] blocks) and connect to 127.0.0.1:<port>.
//! The last CHURNERS stubs each flap a dedicated 16-prefix block every
//! CHURN_MS milliseconds throughout. On ROUTE_REFRESH a stub re-sends
//! its base slice (plus its churn block if currently announced).
//!
//! IXP-matrix extensions (LAN-334) — the 9/10-positional-arg SIGHUP
//! invocation above is a frozen contract and behaves identically:
//! - `reload_cmd` (11th positional): each reload runs `sh -c <reload_cmd>`
//!   (e.g. `docker exec <c> birdc configure`) instead of SIGHUP-ing
//!   <daemon_pid>; a nonzero exit fails the run like a failed SIGHUP.
//! - `daemon_pid` 0: skip in-harness RSS sampling (an outer sampler owns
//!   it; RSS columns report 0). Requires `reload_cmd` or `--flapstorm`.
//! - `RELOADSTALL_OVERLAP_FILE` (env, reload mode only): a generator-emitted
//!   `member<TAB>global prefix index` allocation of overlap second
//!   announcers (LAN-892). Listed stubs additionally announce those base
//!   prefixes; completion targets exclude each observer's own announced set
//!   (slice + extras), which both update-group modes are guaranteed to
//!   deliver.
//! - `RELOADSTALL_RECEIVED_VIEW_FILE` (env, reload mode with
//!   RELOADSTALL_EVIDENCE_DIR): before the final evidence boundary, dump
//!   each observer's final-generation received view (base prefixes seen
//!   with the marker, BEFORE own-announcement exclusion) so the verifier
//!   can compute the per-client-best vs grouped received-view delta.
//! - `RELOADSTALL_STAGE_CMD` (env, SIGHUP reload mode only): after copying
//!   the selected A/B marker file but before RSS sampling and the trigger
//!   timestamp, run one `sh -c` staging command. The selected generation is
//!   exported as `RELOADSTALL_STAGE_GENERATION=a|b`. A nonzero exit fails
//!   before SIGHUP, so native trigger timing remains unchanged.
//! - `--flapstorm K` (anywhere in argv): alternative mode replacing the
//!   reload loop. After convergence + the control window, close the first
//!   K stub sockets simultaneously, timestamp every survivor's receipt of
//!   all K slices' withdrawals, reconnect the K after 10 s, re-announce
//!   their slices, and timestamp survivors' re-announce completion.
//!   3 rounds, per-round percentiles + `flapstorm_csv` lines.
//!
//! Soak extensions (route-server flagship soak) — all additive env vars;
//! every one absent reproduces the frozen one-shot contract exactly:
//! - `RELOADSTALL_CYCLE_QUIESCE_SECS`: inter-reload quiesce (default 20).
//!   The 24 h soak sets this to its reload interval so the existing
//!   reload loop self-paces for the whole window.
//! - `RELOADSTALL_TRIP_EVERY`: after every K-th reload cycle, run one
//!   max-prefix trip cycle on the designated member (stub 0): announce
//!   `RELOADSTALL_TRIP_PREFIXES` prefixes over the daemon-configured
//!   `max_prefixes` bound, ride the Cease teardown, verify withdraw
//!   propagation at every survivor, reconnect-retry through the
//!   hold-down until the daemon's one timed restart admits the session,
//!   re-announce only the compliant base slice, and verify re-announce
//!   propagation. 0/absent = never. Requires the SIGHUP reload mode with
//!   `changed_peers == n_peers`, no overlap, and `n_peers > CHURNERS`.
//! - `RELOADSTALL_TRIP_PREFIXES`: over-limit block size (default 64);
//!   drawn from base indexes `[total, total + K)` so observers'
//!   completion bitmaps ignore it and member-in treats it as base.
//! - `RELOADSTALL_TRIP_REESTABLISH_SECS`: teardown-to-re-established
//!   deadline (default 300); must exceed the daemon's configured
//!   `max_prefix_restart_seconds`.
//! - `RELOADSTALL_FINAL_QUIESCE_SECS`: post-run session hold (default:
//!   the cycle quiesce), applied only when the LAST reload carries a
//!   trip cycle: the engine keeps every stub session up after
//!   `trip N complete` so an outer runner can drain the trip's
//!   daemon-side evidence (usage/limit/headroom) from live metrics
//!   before teardown. Never applies to the one-shot contract (no trips).
//!
//! iBGP-RR extensions (route-reflector flagship soak) — additive env
//! vars; absent, the frozen eBGP route-server contract is untouched:
//! - `RELOADSTALL_IBGP_RR_ASN`: 1..=65535 switches the stubs to iBGP
//!   route-reflector-client mode: every stub OPENs with this shared
//!   local AS (the daemon's ASN), announces with an EMPTY AS_PATH plus
//!   LOCAL_PREF 100 (real-world iBGP origination; the daemon's
//!   validator mandates only ORIGIN+AS_PATH inbound), and the initial
//!   convergence uses the exact per-observer bitmap. Requires the
//!   zero-reload shape: reloads == 0, no flapstorm/reload_cmd/
//!   convergence-only, no overlap or evidence files, no trips.
//! - `RELOADSTALL_IBGP_RR_HOLD_SECS`: after the control window, hold
//!   the fleet under the steady churn for this many seconds (the 24 h
//!   soak window), with per-UPDATE event recording disabled to bound
//!   memory, then run the terminal reflected-delivery verification:
//!   every stub sends a Normal ROUTE_REFRESH and must complete its
//!   full-table-minus-own-slice bitmap exactly from the daemon's
//!   re-sent Adj-RIB-Out. Fail-closed throughout (any session drop or
//!   parse error during the hold aborts). Requires
//!   `RELOADSTALL_IBGP_RR_ASN`.

// Event.other and Ctx.n_peers are recorded for the observation/context
// model but not read by the percentile analysis; keep them so the
// recorded data shape matches what produced the receipt.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Origin, PathAttribute, RouteRefreshMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

const CHURNERS: u32 = 8;
const CHURN_BLOCK: u32 = 16;
const CHURN_MS: u64 = 125;
const NLRI_PER_MSG: usize = 900;
const HOLD_TIME: u16 = 180;
// Marker admin 65400 — deliberately NOT the route server's ASN (65500):
// rs_control_communities defaults on for rs-clients, and RS-administered
// standard communities are RFC 7947 control forms scrubbed from the wire,
// which would hide these markers from the observers. Must match
// gen-scenario.py's GENERATIONS / stable-out.
const COMMUNITY_GEN_A: u32 = (65_400 << 16) | 1_000;
const COMMUNITY_GEN_B: u32 = (65_400 << 16) | 2_000;
const COMMUNITY_STABLE: u32 = (65_400 << 16) | 9_000;
const STALL_WINDOW: Duration = Duration::from_secs(120);
/// First-output window: how long the base-table convergence and
/// reload-completion watchdogs wait for the FIRST observed
/// announcement of their phase before declaring a stall. Ingesting
/// the base table through IRR-scale per-peer import chains — or
/// re-parsing and recompiling a multi-MB policy on reload —
/// legitimately takes minutes of compute before the first UPDATE
/// reaches any observer; once output starts, the steady-state
/// [`STALL_WINDOW`] no-progress watchdog applies. A harness
/// parameter, not a measurement (completion and stall measurements
/// are timestamp-based and unaffected by watchdog size).
const FIRST_OUTPUT_WINDOW: Duration = Duration::from_secs(600);
/// Stub-establishment window: how long one stub keeps retrying its TCP
/// connect and transport-level pre-OPEN handshake (500 ms cadence) before
/// failing. The daemon may still be absorbing a large config, its accept
/// backlog may briefly overflow under the 64-stub establishment waves, or an
/// IdleHold timer may accept and close the socket before OPEN. BGP protocol
/// failures are never retried. A harness parameter, not a measurement
/// (establishment and flap re-announcement are timed outside it).
const CONNECT_WINDOW: Duration = Duration::from_secs(120);
const FLAP_ROUNDS: u32 = 3;
const FLAP_RECONNECT_SECS: u64 = 10;
/// Designated max-prefix trip member (soak mode): always stub 0, which is
/// never a churner (churners are the last CHURNERS stubs) and whose slice
/// is the contiguous window `[0, per_peer)` the flapstorm bitmap shape
/// already tracks.
const TRIP_MEMBER: u32 = 0;
/// How long the daemon may take to tear the designated member down after
/// the over-limit announcement (breach detection is per-UPDATE, so this is
/// generous headroom, not a measurement).
const TRIP_TEARDOWN_WINDOW: Duration = Duration::from_secs(60);
/// Cap on one reconnect attempt during the trip hold-down: a daemon that
/// accepts and then silently holds the socket must not wedge the retry
/// loop (the loop itself runs until the configured re-establish deadline).
const TRIP_ATTEMPT_WINDOW: Duration = Duration::from_secs(30);
const EVIDENCE_TIMEOUT: Duration = Duration::from_secs(15);
const PRE_CHURN_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(60);
const METRICS_DEADLINE: Duration = Duration::from_secs(5);
const METRICS_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
struct NotificationDepth {
    current: u64,
    high: u64,
}

fn metric_value(body: &str, name: &str) -> Result<u64, String> {
    let mut found = None;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let Some(metric) = fields.next() else {
            continue;
        };
        if metric.starts_with(name) && metric.as_bytes().get(name.len()) == Some(&b'{') {
            return Err(format!("labeled {name} sample is forbidden"));
        }
        if metric != name {
            continue;
        }
        let value = fields
            .next()
            .ok_or_else(|| format!("missing value for {name}"))?;
        if fields.next().is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "{name} must be one unlabeled unsigned integer without timestamp"
            ));
        }
        let value = value
            .parse()
            .map_err(|_| format!("{name} is out of range"))?;
        if found.replace(value).is_some() {
            return Err(format!("duplicate {name}"));
        }
    }
    found.ok_or_else(|| format!("missing {name}"))
}

async fn fetch_notification_depth(
    addr: SocketAddr,
    deadline: Instant,
) -> Result<NotificationDepth, String> {
    let work = async {
        let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream
            .take((METRICS_MAX_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        if response.len() > METRICS_MAX_BYTES {
            return Err("metrics response exceeds 32 MiB".into());
        }
        let text = std::str::from_utf8(&response).map_err(|_| "metrics response is not UTF-8")?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        let mut lines = head.lines();
        let status = lines.next().ok_or("missing HTTP status")?;
        if status.split_ascii_whitespace().nth(1) != Some("200") {
            return Err("metrics HTTP status is not 200".into());
        }
        let mut length = None;
        for line in lines {
            let (key, value) = line.split_once(':').ok_or("malformed HTTP header")?;
            if key.eq_ignore_ascii_case("transfer-encoding") {
                return Err("chunked metrics response is forbidden".into());
            }
            if key.eq_ignore_ascii_case("content-length")
                && length
                    .replace(
                        value
                            .trim()
                            .parse::<usize>()
                            .map_err(|_| "invalid Content-Length")?,
                    )
                    .is_some()
            {
                return Err("duplicate Content-Length".into());
            }
        }
        if length != Some(body.len()) {
            return Err("truncated or overlong metrics body".into());
        }
        let current = metric_value(body, "bgp_session_notification_outstanding")?;
        let high = metric_value(body, "bgp_session_notification_outstanding_high_watermark")?;
        if current > high {
            return Err("current exceeds high-water mark".into());
        }
        Ok(NotificationDepth { current, high })
    };
    tokio::time::timeout_at(deadline.into(), work)
        .await
        .map_err(|_| "metrics checkpoint exceeded 5 seconds".to_string())?
}

async fn notification_checkpoint(
    addr: SocketAddr,
    checkpoint: (&str, u32, usize, usize, u32, u64),
    prior_high: &mut u64,
) {
    let (stage, round, sessions, completions, target, parse_errors) = checkpoint;
    let started = Instant::now();
    let deadline = started + METRICS_DEADLINE;
    loop {
        let depth = fetch_notification_depth(addr, deadline)
            .await
            .unwrap_or_else(|e| {
                eprintln!("FAIL: session notification metrics: {e}");
                std::process::exit(1)
            });
        if depth.high == 0 || depth.high < *prior_high {
            eprintln!("FAIL: session notification high-water is zero or decreased");
            std::process::exit(1);
        }
        *prior_high = depth.high;
        if depth.current == 0 {
            println!("session_notification_receipt,stage={stage},round={round},sessions={sessions},completions={completions},target={target},current=0,high_watermark={},parse_errors={parse_errors},drain_wait_us={}", depth.high, started.elapsed().as_micros());
            return;
        }
        if Instant::now() >= deadline {
            eprintln!("FAIL: session notification dequeue did not drain within 5 seconds");
            std::process::exit(1);
        }
        tokio::time::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}

/// iBGP-RR mode (`RELOADSTALL_IBGP_RR_ASN`): 0 = off, the frozen eBGP
/// route-server contract. Set exactly once in `main` before the runtime
/// starts; read by every OPEN and announcement built afterwards
/// (including trip/flap reconnects, which re-run `establish_stub`).
static IBGP_RR_ASN: AtomicU32 = AtomicU32::new(0);

fn ibgp_rr_asn() -> u32 {
    IBGP_RR_ASN.load(Ordering::Relaxed)
}

/// Validated `RELOADSTALL_IBGP_RR_ASN`: 0/absent = eBGP (`None`);
/// 1..=65535 = the shared iBGP local AS (must fit the stub OPEN's u16
/// `my_as`, mirroring the generator's u16 daemon-ASN requirement).
fn ibgp_rr_mode(value: u64) -> Result<Option<u16>, String> {
    match value {
        0 => Ok(None),
        1..=65535 => Ok(Some(u16::try_from(value).unwrap())),
        other => Err(format!(
            "RELOADSTALL_IBGP_RR_ASN must be in 1..=65535 (u16 OPEN my_as), got {other}"
        )),
    }
}

/// What the shared per-observer bitmap is armed to track (flapstorm mode).
const FLAP_OFF: u32 = 0;
const FLAP_TRACK_WITHDRAWS: u32 = 1;
const FLAP_TRACK_ANNOUNCES: u32 = 2;

/// One received-UPDATE observation.
#[derive(Clone, Copy)]
struct Event {
    t_us: u64,
    /// announced NLRI in the base table space (20.0.0.0 onward, one first-octet per 65536 prefixes)
    base_ann: u32,
    /// everything else delivered in this UPDATE (churn announces + withdraws)
    other: u32,
}

struct Obs {
    events: Mutex<Vec<Event>>,
    /// cumulative base-space announced NLRI
    base_ann_total: AtomicU64,
    established: AtomicBool,
    /// communities seen on the most recently sampled fully-parsed UPDATE
    last_comms: Mutex<Vec<u32>>,
    /// Most recent announced UPDATE carrying the content-stable export marker.
    stable_marker_seen_at_us: AtomicU64,
    /// Community marker required for the active reload generation.
    expected_community: AtomicU32,
    /// Unique base prefixes observed with `expected_community`.
    generation: Mutex<GenerationProgress>,
    /// One outstanding ROUTE-REFRESH reply at a time (see the reader).
    refresh_pending: AtomicBool,
    /// Flapstorm arming: FLAP_OFF, or feed withdrawn/announced base
    /// prefixes into `generation` (which the reload path leaves idle in
    /// flapstorm mode — `expected_community` stays 0).
    flap_mode: AtomicU32,
}

/// A live stub session: its outbound channel plus the reader/writer task
/// handles, so flapstorm can hard-close the socket by aborting both tasks
/// (dropping both split halves closes the fd).
struct Stub {
    tx: mpsc::Sender<Message>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct GenerationProgress {
    seen: Vec<u64>,
    /// Every base prefix observed with the active generation marker BEFORE
    /// own-announcement exclusion — the LAN-892 received view. With overlap,
    /// per-client-best delivers runner-up paths for prefixes the observer
    /// itself announces; those are excluded from completion but must still be
    /// evidenced for the received-view delta.
    received: Vec<u64>,
    unique: u64,
    target: u64,
    excluded_start: usize,
    excluded_end: usize,
    /// Sorted extra own-announced indices (overlap second-announcer role),
    /// excluded from completion alongside the contiguous own slice.
    excluded_extra: Vec<usize>,
    completed_at_us: Option<u64>,
    first_marker_base_at_us: Option<u64>,
}

impl GenerationProgress {
    fn reset(&mut self, total_prefixes: u32, target: u64, excluded_start: u32, excluded_len: u32) {
        self.seen.clear();
        self.seen
            .resize(usize::try_from(total_prefixes).unwrap().div_ceil(64), 0);
        self.received.clear();
        self.received.resize(self.seen.len(), 0);
        self.unique = 0;
        self.target = target;
        self.excluded_start = usize::try_from(excluded_start).unwrap();
        self.excluded_end = usize::try_from(excluded_start + excluded_len).unwrap();
        self.excluded_extra.clear();
        self.completed_at_us = None;
        self.first_marker_base_at_us = None;
    }

    /// Exclude the observer's extra own-announced prefixes (overlap second-
    /// announcer role) from completion, shrinking the target to match. Call
    /// after `reset`; the generator guarantees these are outside the
    /// contiguous own slice.
    fn exclude_extra(&mut self, extra: &[u32]) {
        self.excluded_extra = extra.iter().map(|&idx| idx as usize).collect();
        self.excluded_extra.sort_unstable();
        self.target = self.target.saturating_sub(extra.len() as u64);
    }

    fn observe(&mut self, prefix_index: usize, t_us: u64) {
        if let Some(slot) = self.received.get_mut(prefix_index / 64) {
            *slot |= 1u64 << (prefix_index % 64);
        }
        if (self.excluded_start..self.excluded_end).contains(&prefix_index)
            || self.excluded_extra.binary_search(&prefix_index).is_ok()
        {
            return;
        }
        let word = prefix_index / 64;
        let bit = 1u64 << (prefix_index % 64);
        let Some(slot) = self.seen.get_mut(word) else {
            return;
        };
        if *slot & bit != 0 {
            return;
        }
        if self.first_marker_base_at_us.is_none() {
            self.first_marker_base_at_us = Some(t_us);
        }
        *slot |= bit;
        self.unique += 1;
        if self.unique >= self.target && self.completed_at_us.is_none() {
            self.completed_at_us = Some(t_us);
        }
    }
}

struct Ctx {
    t0: Instant,
    n_peers: u32,
    per_peer: u32,
    daemon: SocketAddr,
    obs: Vec<Obs>,
    /// Per-stub extra announced base indices beyond the contiguous own slice
    /// (`RELOADSTALL_OVERLAP_FILE`, the LAN-892 overlap dimension). Empty
    /// vectors when overlap is off — the historical disjoint shape.
    extras: Vec<Vec<u32>>,
    /// Daemon UPDATEs the stub failed to decode — a daemon defect that
    /// invalidates the run (see the reader and the exit check in `main`).
    parse_errors: AtomicU64,
    /// Total churner flap messages sent (one announce or withdraw each) —
    /// the soak churn-cycle accounting. Unread outside the iBGP-RR soak.
    churn_cycles: AtomicU64,
    /// Reader per-UPDATE event recording. Disabled for the iBGP-RR hold
    /// window: gap stats are not consumed there, and 24 h of events at
    /// churn cadence across 1000 observers would exhaust host memory.
    record_events: AtomicBool,
}

fn now_us(ctx: &Ctx) -> u64 {
    u64::try_from(ctx.t0.elapsed().as_micros()).unwrap()
}

fn wall_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

fn stub_addr(i: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        127,
        1,
        u8::try_from(i / 200).unwrap(),
        u8::try_from(i % 200 + 1).unwrap(),
    )
}

fn stub_asn(i: u32) -> u32 {
    64512 + i
}

/// Base-table /24 for global route index (same scheme as rrharness).
fn base_prefix(idx: u32) -> Ipv4Prefix {
    let a = 20 + u8::try_from(idx >> 16).expect("prefix space exhausted");
    let b = u8::try_from((idx >> 8) & 0xff).unwrap();
    let c = u8::try_from(idx & 0xff).unwrap();
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, 0), 24)
}

fn base_prefix_index(prefix: Ipv4Prefix, total_prefixes: u32) -> Option<usize> {
    if prefix.len != 24 {
        return None;
    }
    let [a, b, c, d] = prefix.addr.octets();
    // Lower bound only: the base space starts at 20.0.0.0 and grows one
    // first-octet per 65536 prefixes; the `index < total_prefixes` gate below
    // is the real upper bound (churn 172.16+.x maps to index >= 9.9M and is
    // rejected there). A hardcoded 20..30 octet cap here silently dropped
    // every prefix past index 655359 and wedged the 1M-route shape (LAN-449).
    if d != 0 || a < 20 {
        return None;
    }
    let index = (u32::from(a - 20) << 16) | (u32::from(b) << 8) | u32::from(c);
    (index < total_prefixes).then(|| usize::try_from(index).unwrap())
}

/// COMMUNITIES values as received, whichever Partial flavour the sender used.
/// Peers that set the RFC 4271 Partial bit on transitive attributes decode to
/// `CommunitiesPartial`; matching the bare variant alone read an empty slice
/// and stalled generation tracking against them.
fn observed_communities(attributes: &[PathAttribute]) -> &[u32] {
    attributes
        .iter()
        .find_map(PathAttribute::communities)
        .unwrap_or(&[])
}

fn observe_generation(
    progress: &mut GenerationProgress,
    expected_community: u32,
    communities: &[u32],
    announced: impl IntoIterator<Item = Ipv4Prefix>,
    total_prefixes: u32,
    t_us: u64,
) {
    if expected_community == 0 || !communities.contains(&expected_community) {
        return;
    }
    for prefix in announced {
        if let Some(index) = base_prefix_index(prefix, total_prefixes) {
            progress.observe(index, t_us);
        }
    }
}

fn churn_prefix(churner: u32, j: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(
        Ipv4Addr::new(
            172,
            16 + u8::try_from(churner).unwrap(),
            u8::try_from(j).unwrap(),
            0,
        ),
        24,
    )
}

fn base_attrs(i: u32) -> Vec<PathAttribute> {
    // Non-loopback synthetic next-hop: the daemon rejects 127/8
    // NEXT_HOP with UPDATE error subcode 8. Route-server mode passes
    // it through untouched; RR mode reflects it unchanged (no next-hop
    // resolution requirement — ORR interior cost is opt-in only);
    // observers never resolve it.
    let next_hop = PathAttribute::NextHop(Ipv4Addr::new(
        10,
        9,
        u8::try_from(i / 200).unwrap(),
        u8::try_from(i % 200 + 1).unwrap(),
    ));
    if ibgp_rr_asn() != 0 {
        // iBGP origination: EMPTY AS_PATH (locally-originated inside the
        // shared AS) plus LOCAL_PREF, mandatory-by-convention on iBGP
        // UPDATEs (the daemon's inbound validator mandates only
        // ORIGIN+AS_PATH, but real iBGP speakers always attach it).
        return vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            next_hop,
            PathAttribute::LocalPref(100),
        ];
    }
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![stub_asn(i)])],
        }),
        next_hop,
    ]
}

fn announce_msgs(i: u32, prefixes: &[Ipv4Prefix]) -> Vec<Message> {
    let attrs = base_attrs(i);
    prefixes
        .chunks(NLRI_PER_MSG)
        .map(|chunk| {
            let entries: Vec<Ipv4NlriEntry> = chunk
                .iter()
                .map(|p| Ipv4NlriEntry {
                    path_id: 0,
                    prefix: *p,
                })
                .collect();
            Message::Update(UpdateMessage::build(
                &entries,
                &[],
                &attrs,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
        })
        .collect()
}

fn withdraw_msg(prefixes: &[Ipv4Prefix]) -> Message {
    let entries: Vec<Ipv4NlriEntry> = prefixes
        .iter()
        .map(|p| Ipv4NlriEntry {
            path_id: 0,
            prefix: *p,
        })
        .collect();
    Message::Update(UpdateMessage::build(
        &[],
        &entries,
        &[],
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

/// Slice of the base table owned by stub `i`.
fn own_slice(ctx: &Ctx, i: u32) -> Vec<Ipv4Prefix> {
    let lo = i * ctx.per_peer;
    (lo..lo + ctx.per_peer).map(base_prefix).collect()
}

/// Everything stub `i` announces: its own slice plus its overlap
/// second-announcer prefixes (LAN-892; empty extras reproduce the
/// historical disjoint announcements exactly).
fn announced_prefixes(ctx: &Ctx, i: u32) -> Vec<Ipv4Prefix> {
    let mut prefixes = own_slice(ctx, i);
    prefixes.extend(ctx.extras[i as usize].iter().copied().map(base_prefix));
    prefixes
}

/// Parse the generator's overlap allocation (`member<TAB>global prefix index`
/// per line): the extra base prefixes each stub announces beyond its own
/// slice. Rejects out-of-range members and prefixes, own-slice entries
/// (already announced), and duplicates.
fn parse_overlap_file(
    text: &str,
    n_peers: u32,
    total: u32,
    per_peer: u32,
) -> Result<Vec<Vec<u32>>, String> {
    let mut extras = vec![Vec::new(); n_peers as usize];
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let (member, idx) = line
            .split_once('\t')
            .ok_or(format!("overlap line {number}: missing tab separator"))?;
        let member: u32 = member
            .parse()
            .map_err(|_| format!("overlap line {number}: invalid member index"))?;
        let idx: u32 = idx
            .parse()
            .map_err(|_| format!("overlap line {number}: invalid prefix index"))?;
        if member >= n_peers {
            return Err(format!(
                "overlap line {number}: member {member} out of range"
            ));
        }
        if idx >= total {
            return Err(format!(
                "overlap line {number}: prefix index {idx} out of range"
            ));
        }
        if idx / per_peer == member {
            return Err(format!(
                "overlap line {number}: prefix {idx} is in member {member}'s own slice"
            ));
        }
        let list: &mut Vec<u32> = &mut extras[member as usize];
        if list.contains(&idx) {
            return Err(format!(
                "overlap line {number}: duplicate ({member}, {idx})"
            ));
        }
        list.push(idx);
    }
    for list in &mut extras {
        list.sort_unstable();
    }
    Ok(extras)
}

/// Dump every observer's LAN-892 received view (final-generation base
/// prefixes seen, before own-announcement exclusion) as
/// `observer<TAB>missing_count<TAB>comma-joined missing indices`.
fn write_received_view(ctx: &Ctx, path: &Path) -> std::io::Result<()> {
    let total = usize::try_from(ctx.n_peers * ctx.per_peer).unwrap();
    let mut out = format!(
        "received_view_v1\ttotal={}\tpeers={}\n",
        ctx.n_peers * ctx.per_peer,
        ctx.n_peers
    );
    for (i, observer) in ctx.obs.iter().enumerate() {
        let generation = observer.generation.lock().unwrap();
        let missing: Vec<String> = (0..total)
            .filter(|&idx| {
                generation
                    .received
                    .get(idx / 64)
                    .is_none_or(|slot| slot & (1u64 << (idx % 64)) == 0)
            })
            .map(|idx| idx.to_string())
            .collect();
        out.push_str(&format!("{i}\t{}\t{}\n", missing.len(), missing.join(",")));
    }
    std::fs::write(path, out)
}

enum StubOpenError {
    Retryable(String),
    Fatal(String),
}

async fn open_stub_stream(
    daemon: SocketAddr,
    local: Ipv4Addr,
    open: &[u8],
    keepalive: &[u8],
) -> Result<TcpStream, StubOpenError> {
    let sock = TcpSocket::new_v4().map_err(|e| StubOpenError::Fatal(format!("socket: {e}")))?;
    sock.bind(SocketAddr::new(local.into(), 0))
        .map_err(|e| StubOpenError::Fatal(format!("bind {local}: {e}")))?;
    let mut stream = sock
        .connect(daemon)
        .await
        .map_err(|e| StubOpenError::Retryable(format!("connect from {local}: {e}")))?;
    stream.set_nodelay(true).ok();
    stream
        .write_all(open)
        .await
        .map_err(|e| StubOpenError::Retryable(format!("open write: {e}")))?;

    // Read the daemon's OPEN. A transport close before OPEN is retryable:
    // peers may accept a socket while an IdleHold timer still owns their FSM.
    // Protocol failures remain fatal so retries cannot hide bad wire behavior.
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN) {
            if buf.len() >= usize::from(total) {
                let mut b = buf.split_to(usize::from(total)).freeze();
                match decode_message(&mut b, MAX_MESSAGE_LEN) {
                    Ok(Message::Open(_)) => break,
                    Ok(Message::Notification(n)) => {
                        return Err(StubOpenError::Fatal(format!(
                            "NOTIFICATION during open: {:?}/{}",
                            n.code, n.subcode
                        )));
                    }
                    Ok(_) => continue, // tolerate keepalives etc.
                    Err(e) => {
                        return Err(StubOpenError::Fatal(format!("decode during open: {e}")));
                    }
                }
            }
        }
        let mut tmp = [0u8; 4096];
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| StubOpenError::Retryable(format!("read: {e}")))?;
        if n == 0 {
            return Err(StubOpenError::Retryable("closed before OPEN".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    stream
        .write_all(keepalive)
        .await
        .map_err(|e| StubOpenError::Retryable(format!("ka write: {e}")))?;
    Ok(stream)
}

async fn establish_stream_with_retry(
    daemon: SocketAddr,
    local: Ipv4Addr,
    open: &[u8],
    keepalive: &[u8],
    window: Duration,
) -> Result<(TcpStream, u32), String> {
    let deadline = Instant::now() + window;
    let mut retries = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "establishment from {local} timed out after {}s",
                window.as_secs()
            ));
        }
        match tokio::time::timeout(remaining, open_stub_stream(daemon, local, open, keepalive))
            .await
        {
            Ok(Ok(stream)) => return Ok((stream, retries)),
            Ok(Err(StubOpenError::Fatal(error))) => return Err(error),
            Ok(Err(StubOpenError::Retryable(error))) => {
                retries += 1;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!("{error} (retried for {}s)", window.as_secs()));
                }
                tokio::time::sleep(remaining.min(Duration::from_millis(500))).await;
            }
            Err(_) => {
                return Err(format!(
                    "establishment from {local} timed out after {}s",
                    window.as_secs()
                ));
            }
        }
    }
}

async fn establish_stub(ctx: Arc<Ctx>, i: u32) -> Result<Stub, String> {
    let local = stub_addr(i);

    // iBGP-RR mode: every stub OPENs with the shared local AS (the
    // daemon's own ASN); otherwise the per-stub eBGP ASN.
    let open_asn = match ibgp_rr_asn() {
        0 => stub_asn(i),
        shared => shared,
    };
    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(open_asn).unwrap(),
        hold_time: HOLD_TIME,
        bgp_identifier: Ipv4Addr::new(
            240,
            1,
            u8::try_from(i / 200).unwrap(),
            u8::try_from(i % 200 + 1).unwrap(),
        ),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: open_asn },
            Capability::RouteRefresh,
        ],
    };
    let bytes = encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    let ka = encode_message(&Message::Keepalive).unwrap();
    let (stream, retries) =
        establish_stream_with_retry(ctx.daemon, local, &bytes, &ka, CONNECT_WINDOW).await?;
    if retries > 0 {
        eprintln!("stub {i} establishment recovered after {retries} retries");
    }

    ctx.obs[i as usize]
        .established
        .store(true, Ordering::Relaxed);

    let (tx, mut tx_rx) = mpsc::channel::<Message>(256);
    let (mut reader, mut writer) = stream.into_split();

    // Writer task: outbound messages + periodic keepalive.
    let writer_ctx = Arc::clone(&ctx);
    let writer_handle = tokio::spawn(async move {
        let mut ka_tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ka_tick.tick().await;
        loop {
            tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { break };
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                _ = ka_tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).unwrap();
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                else => break,
            }
        }
        writer_ctx.obs[i as usize]
            .established
            .store(false, Ordering::Relaxed);
    });

    // Reader task: frame, decode, record UPDATE arrivals, answer
    // ROUTE_REFRESH by re-sending the base slice.
    let tx_for_reader = tx.clone();
    let rctx = Arc::clone(&ctx);
    let reader_handle = tokio::spawn(async move {
        let mut frame = BytesMut::with_capacity(1 << 16);
        let mut tmp = vec![0u8; 1 << 16];
        loop {
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    rctx.obs[i as usize]
                        .established
                        .store(false, Ordering::Relaxed);
                    return;
                }
                Ok(n) => n,
            };
            frame.extend_from_slice(&tmp[..n]);
            loop {
                if frame.len() < HEADER_LEN {
                    break;
                }
                let total = match peek_message_length(&frame, MAX_MESSAGE_LEN) {
                    Ok(Some(len)) => usize::from(len),
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("stub {i} invalid daemon frame: {error}");
                        rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                        rctx.obs[i as usize]
                            .established
                            .store(false, Ordering::Relaxed);
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut mb = frame.split_to(total).freeze();
                let msg = match decode_message(&mut mb, MAX_MESSAGE_LEN) {
                    Ok(m) => m,
                    Err(error) => {
                        eprintln!("stub {i} failed to decode daemon message: {error}");
                        rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                        rctx.obs[i as usize]
                            .established
                            .store(false, Ordering::Relaxed);
                        return;
                    }
                };
                match msg {
                    Message::Update(u) => {
                        // Parse the wire UPDATE once: NLRI, withdrawals, and
                        // attributes all come from the same decode (the earlier
                        // code decoded the NLRI twice, then re-parsed the whole
                        // UPDATE). A decode failure is a daemon defect, so count
                        // it and fail the run rather than silently skipping the
                        // UPDATE — a silent skip looks exactly like the daemon
                        // under-delivery this harness measures.
                        let parsed = match u.parse(true, false, &[]) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("stub {i} decode error on daemon UPDATE: {e}");
                                rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        let total_prefixes = rctx.n_peers * rctx.per_peer;
                        let mut base = 0u32;
                        let mut other = u32::try_from(parsed.withdrawn.len()).unwrap_or(0);
                        for e in &parsed.announced {
                            // Same predicate as generation tracking: a second,
                            // divergent octet-range check here is what capped
                            // base_ann_total at 655360 and hung convergence.
                            if base_prefix_index(e.prefix, total_prefixes).is_some() {
                                base += 1;
                            } else {
                                other += 1;
                            }
                        }
                        let ob = &rctx.obs[i as usize];
                        let t_us = now_us(&rctx);
                        if !parsed.announced.is_empty() {
                            // Borrow the communities out of the single parse;
                            // clone once only to store the last-seen sample.
                            let communities = observed_communities(&parsed.attributes);
                            *ob.last_comms.lock().unwrap() = communities.to_vec();
                            if communities.contains(&COMMUNITY_STABLE) {
                                ob.stable_marker_seen_at_us.store(t_us, Ordering::Release);
                            }

                            let expected = ob.expected_community.load(Ordering::Acquire);
                            if base > 0 && expected != 0 {
                                let mut generation = ob.generation.lock().unwrap();
                                if ob.expected_community.load(Ordering::Acquire) == expected {
                                    observe_generation(
                                        &mut generation,
                                        expected,
                                        communities,
                                        parsed.announced.iter().map(|entry| entry.prefix),
                                        total_prefixes,
                                        t_us,
                                    );
                                }
                            }
                        }
                        // Feed the armed direction into the shared bitmap, including withdrawals.
                        let flap_mode = ob.flap_mode.load(Ordering::Acquire);
                        if flap_mode != FLAP_OFF {
                            let tracked = if flap_mode == FLAP_TRACK_WITHDRAWS {
                                &parsed.withdrawn
                            } else {
                                &parsed.announced
                            };
                            let mut generation = ob.generation.lock().unwrap();
                            if ob.flap_mode.load(Ordering::Acquire) == flap_mode {
                                for e in tracked {
                                    if let Some(index) = base_prefix_index(e.prefix, total_prefixes)
                                    {
                                        generation.observe(index, t_us);
                                    }
                                }
                            }
                        }
                        ob.base_ann_total
                            .fetch_add(u64::from(base), Ordering::Relaxed);
                        if rctx.record_events.load(Ordering::Relaxed) {
                            ob.events.lock().unwrap().push(Event {
                                t_us,
                                base_ann: base,
                                other,
                            });
                        }
                    }
                    Message::RouteRefresh(_) => {
                        // Answer off-thread so the reader never blocks on a full
                        // writer channel while the daemon floods us. Bound it to
                        // one outstanding response per peer: a refresh storm must
                        // not spawn overlapping full-slice floods that duplicate
                        // announcements and skew the measurement.
                        if rctx.obs[i as usize]
                            .refresh_pending
                            .swap(true, Ordering::AcqRel)
                        {
                            continue;
                        }
                        let tx = tx_for_reader.clone();
                        let rc = Arc::clone(&rctx);
                        tokio::spawn(async move {
                            let slice = announced_prefixes(&rc, i);
                            for m in announce_msgs(i, &slice) {
                                if tx.send(m).await.is_err() {
                                    break;
                                }
                            }
                            rc.obs[i as usize]
                                .refresh_pending
                                .store(false, Ordering::Release);
                        });
                    }
                    _ => {}
                }
            }
        }
    });

    Ok(Stub {
        tx,
        reader: reader_handle,
        writer: writer_handle,
    })
}

/// Percentile over a sorted slice.
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

/// Max inter-UPDATE gap (ms) for one observer over [s_us, e_us].
/// Includes the leading gap from s_us to the first event; includes the
/// trailing gap to e_us when `trailing` is set (control windows and the
/// full-fleet reload window, whose stable observers have no completion event).
fn max_gap_ms(ctx: &Ctx, i: usize, s_us: u64, e_us: u64, trailing: bool) -> f64 {
    let ev = ctx.obs[i].events.lock().unwrap();
    let mut last = s_us;
    let mut max_gap = 0u64;
    for e in ev.iter() {
        if e.t_us < s_us {
            continue;
        }
        if e.t_us > e_us {
            break;
        }
        max_gap = max_gap.max(e.t_us - last);
        last = e.t_us;
    }
    if trailing {
        max_gap = max_gap.max(e_us.saturating_sub(last));
    }
    max_gap as f64 / 1000.0
}

/// First event time at which every expected unique base prefix was observed
/// with the active policy-generation community marker.
fn completion_us(ctx: &Ctx, i: usize) -> Option<u64> {
    ctx.obs[i].generation.lock().unwrap().completed_at_us
}

/// Per-cycle events drain (end of every reload cycle, after its CSV row).
/// A cycle's gap stats consume only its own `[t_hup, reload_end]` window,
/// so events from completed cycles are dead weight — without this the
/// per-observer Vec grows for the entire soak window (the iBGP-RR hold
/// bounds the same growth by disabling recording instead, since nothing
/// consumes gap stats there). `clear()` keeps capacity, so memory stays
/// bounded by the busiest single cycle.
fn drain_cycle_events(obs: &[Obs]) {
    for observer in obs {
        observer.events.lock().unwrap().clear();
    }
}

fn stable_marker_is_fresh(seen_at_us: u64, since_us: u64) -> bool {
    seen_at_us != 0 && seen_at_us >= since_us
}

fn stable_marker_peers_since(ctx: &Ctx, changed_peers: u32, since_us: u64) -> usize {
    ctx.obs
        .iter()
        .skip(changed_peers as usize)
        .filter(|observer| {
            stable_marker_is_fresh(
                observer.stable_marker_seen_at_us.load(Ordering::Acquire),
                since_us,
            )
        })
        .count()
}

fn rss_mib(pid: i32) -> u64 {
    if pid <= 0 {
        // daemon_pid 0: an outer sampler owns RSS; report 0 everywhere.
        return 0;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .unwrap_or(0)
                / 1024;
        }
    }
    0
}

#[derive(Clone, Copy)]
struct Stats {
    p50: f64,
    p95: f64,
    max: f64,
    n: usize,
}

fn stats_line(label: &str, mut vals: Vec<f64>) -> Stats {
    vals.sort_by(f64::total_cmp);
    let stats = Stats {
        p50: pct(&vals, 0.5),
        p95: pct(&vals, 0.95),
        max: pct(&vals, 1.0),
        n: vals.len(),
    };
    println!(
        "{label}: p50={:.2} p95={:.2} max={:.2} (n={})",
        stats.p50, stats.p95, stats.max, stats.n
    );
    stats
}

/// Progress watchdog for one flapstorm phase: every survivor (observers
/// `first..n_peers`) must complete its armed bitmap; fail loudly when no
/// survivor makes unique-prefix progress for STALL_WINDOW (same discipline
/// as the reload loop — no absolute deadline).
async fn wait_flap_completion(ctx: &Ctx, first: usize, round: u32, phase: &str) {
    let mut last_unique = 0u64;
    let mut last_progress = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if (first..ctx.obs.len()).all(|i| completion_us(ctx, i).is_some()) {
            return;
        }
        let sum: u64 = (first..ctx.obs.len())
            .map(|i| ctx.obs[i].generation.lock().unwrap().unique)
            .sum();
        if sum > last_unique {
            last_unique = sum;
            last_progress = Instant::now();
        } else if last_progress.elapsed() > STALL_WINDOW {
            let done = (first..ctx.obs.len())
                .filter(|&i| completion_us(ctx, i).is_some())
                .count();
            eprintln!(
                "flap {round} {phase} STALLED: no progress for {}s; \
                 survivors complete {done}/{}",
                STALL_WINDOW.as_secs(),
                ctx.obs.len() - first
            );
            for i in (first..ctx.obs.len())
                .filter(|&i| completion_us(ctx, i).is_none())
                .take(10)
            {
                let g = ctx.obs[i].generation.lock().unwrap();
                eprintln!(
                    "flap {round} {phase} observer {i} incomplete: unique={}/{}",
                    g.unique, g.target
                );
            }
            std::process::exit(1);
        }
    }
}

/// Arm every survivor's shared bitmap to track `mode` over the flapped
/// window (base indices `[0, flap_prefixes)`; everything else excluded).
fn arm_survivors(ctx: &Ctx, k: u32, flap_prefixes: u32, total: u32, mode: u32) {
    for observer in ctx.obs.iter().skip(k as usize) {
        observer.flap_mode.store(FLAP_OFF, Ordering::Release);
        observer.generation.lock().unwrap().reset(
            total,
            u64::from(flap_prefixes),
            flap_prefixes,
            total - flap_prefixes,
        );
        observer.flap_mode.store(mode, Ordering::Release);
    }
}

/// Disarm every survivor's shared bitmap (flapstorm rounds and trip cycles).
fn disarm_survivors(ctx: &Ctx, first: usize) {
    for observer in ctx.obs.iter().skip(first) {
        observer.flap_mode.store(FLAP_OFF, Ordering::Release);
    }
}

/// `--flapstorm K` mode: the alternative to the reload loop (see the crate
/// doc). The flapped cohort is the first K stubs — never the churners,
/// which are the last CHURNERS.
async fn run_flapstorm(
    ctx: &Arc<Ctx>,
    stubs: &mut [Stub],
    k: u32,
    pid: i32,
    metrics_addr: Option<SocketAddr>,
    prior_high: &mut u64,
) {
    let n_peers = ctx.n_peers;
    let total = n_peers * ctx.per_peer;
    let flap_prefixes = k * ctx.per_peer;
    let survivors = k as usize..n_peers as usize;
    println!(
        "flapstorm_csv_header,round,peers_total,peers_flapped,prefixes,flap_prefixes,\
         withdraw_p50_s,withdraw_p95_s,withdraw_max_s,\
         reannounce_p50_s,reannounce_p95_s,reannounce_max_s,\
         rss_mib,sessions_up,parse_errors"
    );
    for round in 1..=FLAP_ROUNDS {
        if let Some(addr) = metrics_addr {
            let up = ctx
                .obs
                .iter()
                .filter(|o| o.established.load(Ordering::Relaxed))
                .count();
            let errors = ctx.parse_errors.load(Ordering::Relaxed);
            if up != 700 || errors != 0 {
                eprintln!(
                    "FAIL: round-start receipt integrity: sessions={up}, parse_errors={errors}"
                );
                std::process::exit(1);
            }
            notification_checkpoint(addr, ("round_start", round, up, 0, 0, errors), prior_high)
                .await;
        }
        // Arm before closing so no withdrawal is missed.
        arm_survivors(ctx, k, flap_prefixes, total, FLAP_TRACK_WITHDRAWS);
        println!("flap {round} close wall_us={}", wall_us());
        let t_close = now_us(ctx);
        // Simultaneous close: abort both split-half tasks per flapped stub.
        for stub in stubs.iter().take(k as usize) {
            stub.reader.abort();
            stub.writer.abort();
        }
        for observer in ctx.obs.iter().take(k as usize) {
            observer.established.store(false, Ordering::Relaxed);
        }
        wait_flap_completion(ctx, k as usize, round, "withdraw").await;
        if let Some(addr) = metrics_addr {
            let up = ctx
                .obs
                .iter()
                .filter(|o| o.established.load(Ordering::Relaxed))
                .count();
            let completed = survivors
                .clone()
                .filter(|&i| completion_us(ctx, i).is_some())
                .count();
            let errors = ctx.parse_errors.load(Ordering::Relaxed);
            if up != 650 || completed != 650 || errors != 0 {
                eprintln!("FAIL: withdraw receipt integrity: sessions={up}, completions={completed}, parse_errors={errors}");
                std::process::exit(1);
            }
            notification_checkpoint(
                addr,
                (
                    "withdraw_drained",
                    round,
                    up,
                    completed,
                    flap_prefixes,
                    errors,
                ),
                prior_high,
            )
            .await;
        }
        let withdraw_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| completion_us(ctx, i))
            .map(|tc| tc.saturating_sub(t_close) as f64 / 1e6)
            .collect();
        let withdraw = stats_line(&format!("flap {round} withdraw_s"), withdraw_s);

        // Hold the sessions down until FLAP_RECONNECT_SECS past the close.
        let since_close_ms = now_us(ctx).saturating_sub(t_close) / 1000;
        let hold_ms = (FLAP_RECONNECT_SECS * 1000).saturating_sub(since_close_ms);
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;

        // Re-arm before any flapped session returns, so no announce is missed.
        arm_survivors(ctx, k, flap_prefixes, total, FLAP_TRACK_ANNOUNCES);
        for i in 0..k {
            match establish_stub(Arc::clone(ctx), i).await {
                Ok(stub) => stubs[i as usize] = stub,
                Err(e) => {
                    eprintln!("flap {round} reconnect stub {i} failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        let t_reann = now_us(ctx);
        println!("flap {round} reannounce wall_us={}", wall_us());
        for i in 0..k {
            let slice = announced_prefixes(ctx, i);
            for m in announce_msgs(i, &slice) {
                if stubs[i as usize].tx.send(m).await.is_err() {
                    eprintln!("flap {round} re-announce send failed for stub {i}");
                    std::process::exit(1);
                }
            }
        }
        wait_flap_completion(ctx, k as usize, round, "reannounce").await;
        let reann_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| completion_us(ctx, i))
            .map(|tc| tc.saturating_sub(t_reann) as f64 / 1e6)
            .collect();
        let reannounce = stats_line(&format!("flap {round} reannounce_s"), reann_s);
        // First re-announce arrival per survivor: distinguishes a steady
        // drain (first ≪ completion: fan-out throughput) from an
        // idle-then-burst gate (first ≈ completion: a daemon-side timer).
        let first_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| {
                let events = ctx.obs[i].events.lock().unwrap();
                events
                    .iter()
                    .find(|e| e.t_us >= t_reann && e.base_ann > 0)
                    .map(|e| e.t_us.saturating_sub(t_reann) as f64 / 1e6)
            })
            .collect();
        stats_line(&format!("flap {round} first_reann_s"), first_s);
        disarm_survivors(ctx, k as usize);
        let rss = rss_mib(pid);
        let up = ctx
            .obs
            .iter()
            .filter(|o| o.established.load(Ordering::Relaxed))
            .count();
        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        println!("flap {round} sessions_up {up}/{n_peers} rss_mib={rss}");
        if up != n_peers as usize || parse_errors != 0 {
            eprintln!(
                "FAIL: flap {round} integrity check failed: \
                 sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
            );
            std::process::exit(1);
        }
        if let Some(addr) = metrics_addr {
            let completed = survivors
                .clone()
                .filter(|&i| completion_us(ctx, i).is_some())
                .count();
            if completed != 650 {
                eprintln!("FAIL: reannounce receipt completions={completed}/650");
                std::process::exit(1);
            }
            notification_checkpoint(
                addr,
                (
                    "reannounce_drained",
                    round,
                    up,
                    completed,
                    flap_prefixes,
                    parse_errors,
                ),
                prior_high,
            )
            .await;
        }
        println!(
            "flapstorm_csv,{round},{n_peers},{k},{total},{flap_prefixes},\
             {:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{rss},{up},{parse_errors}",
            withdraw.p50,
            withdraw.p95,
            withdraw.max,
            reannounce.p50,
            reannounce.p95,
            reannounce.max,
        );
        // Quiesce between rounds.
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Strictly-parsed u64 env knob: absent = default, garbage = usage error.
fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Err(_) => default,
        Ok(value) => value.parse().unwrap_or_else(|_| {
            eprintln!("{name} must be a non-negative integer, got {value:?}");
            std::process::exit(2);
        }),
    }
}

/// Reload slots that carry a trailing max-prefix trip cycle (soak mode).
fn is_trip_slot(reload: u32, trip_every: u32) -> bool {
    trip_every != 0 && reload.is_multiple_of(trip_every)
}

/// Post-run session hold (seconds) before teardown. When the LAST reload
/// carries a trip cycle, the outer runner still has to observe the settled
/// post-recovery state (usage/limit/headroom) from the daemon's live
/// metrics after `trip N complete`; exiting immediately drops every stub
/// session and that peer-scoped state can never settle. Zero whenever the
/// last cycle cannot leave evidence pending — including the frozen
/// one-shot contract (`trip_every == 0`).
fn final_quiesce_secs(reloads: u32, trip_every: u32, hold_secs: u64) -> u64 {
    if is_trip_slot(reloads, trip_every) {
        hold_secs
    } else {
        0
    }
}

/// Over-limit trip block: base indexes `[total, total + count)`. Outside
/// every observer's completion bitmap (`base_prefix_index` rejects
/// `>= total`) and outside the churn space, but shaped exactly like base
/// routes for the daemon's import path and session accounting.
fn trip_block(total: u32, count: u32) -> Vec<Ipv4Prefix> {
    (total..total + count).map(base_prefix).collect()
}

/// One max-prefix trip cycle on the designated member (soak mode). The
/// flap bitmap machinery is reused with the K=1 window shape: survivors
/// track the designated member's slice `[0, per_peer)` through the
/// daemon-driven teardown (withdraws) and the post-restart re-announce.
/// Fail-closed at every phase, mirroring the flapstorm discipline.
async fn run_trip_cycle(
    ctx: &Arc<Ctx>,
    stubs: &mut [Stub],
    trip: u32,
    pid: i32,
    trip_prefix_count: u32,
    reestablish_window: Duration,
) {
    let n_peers = ctx.n_peers;
    let total = n_peers * ctx.per_peer;
    let survivors = TRIP_MEMBER as usize + 1;
    // Stale reload-generation markers must not feed the trip bitmaps.
    for observer in &ctx.obs {
        observer.expected_community.store(0, Ordering::Release);
    }
    // Arm withdraw tracking before the breach so no withdrawal is missed.
    arm_survivors(ctx, 1, ctx.per_peer, total, FLAP_TRACK_WITHDRAWS);
    println!(
        "trip {trip} announce_over wall_us={} member={TRIP_MEMBER} prefixes={trip_prefix_count}",
        wall_us()
    );
    let t_over = now_us(ctx);
    for msg in announce_msgs(TRIP_MEMBER, &trip_block(total, trip_prefix_count)) {
        if stubs[TRIP_MEMBER as usize].tx.send(msg).await.is_err() {
            eprintln!("FAIL: trip {trip} over-limit announce send failed");
            std::process::exit(1);
        }
    }
    let teardown_deadline = Instant::now() + TRIP_TEARDOWN_WINDOW;
    while ctx.obs[TRIP_MEMBER as usize]
        .established
        .load(Ordering::Relaxed)
    {
        if Instant::now() >= teardown_deadline {
            eprintln!(
                "FAIL: trip {trip} daemon did not tear down the designated member within {}s",
                TRIP_TEARDOWN_WINDOW.as_secs()
            );
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Abort the dead session's split-half tasks so a lingering writer
    // keepalive cannot stomp the NEW session's established flag later
    // (same discipline as the flapstorm close).
    stubs[TRIP_MEMBER as usize].reader.abort();
    stubs[TRIP_MEMBER as usize].writer.abort();
    let t_down = now_us(ctx);
    let teardown_s = t_down.saturating_sub(t_over) as f64 / 1e6;
    println!(
        "trip {trip} torn_down wall_us={} after_s={teardown_s:.3}",
        wall_us()
    );
    wait_flap_completion(ctx, survivors, trip, "trip-withdraw").await;
    let withdraw_s = (survivors..ctx.obs.len())
        .filter_map(|i| completion_us(ctx, i))
        .max()
        .map_or(f64::NAN, |tc| tc.saturating_sub(t_down) as f64 / 1e6);
    // Re-arm announce tracking before any reconnect can succeed so no
    // re-announce is missed.
    arm_survivors(ctx, 1, ctx.per_peer, total, FLAP_TRACK_ANNOUNCES);
    let reconnect_deadline = Instant::now() + reestablish_window;
    let stub = loop {
        match tokio::time::timeout(
            TRIP_ATTEMPT_WINDOW,
            establish_stub(Arc::clone(ctx), TRIP_MEMBER),
        )
        .await
        {
            Ok(Ok(stub)) => break stub,
            Ok(Err(error)) => {
                if Instant::now() >= reconnect_deadline {
                    eprintln!(
                        "FAIL: trip {trip} designated member not re-established within {}s: {error}",
                        reestablish_window.as_secs()
                    );
                    std::process::exit(1);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {
                if Instant::now() >= reconnect_deadline {
                    eprintln!(
                        "FAIL: trip {trip} designated member not re-established within {}s: attempt timed out",
                        reestablish_window.as_secs()
                    );
                    std::process::exit(1);
                }
            }
        }
    };
    stubs[TRIP_MEMBER as usize] = stub;
    let t_up = now_us(ctx);
    let holddown_s = t_up.saturating_sub(t_down) as f64 / 1e6;
    println!(
        "trip {trip} reestablished wall_us={} holddown_s={holddown_s:.3}",
        wall_us()
    );
    // Compliant base slice only — the over-limit block stays withdrawn.
    for msg in announce_msgs(TRIP_MEMBER, &own_slice(ctx, TRIP_MEMBER)) {
        if stubs[TRIP_MEMBER as usize].tx.send(msg).await.is_err() {
            eprintln!("FAIL: trip {trip} compliant re-announce send failed");
            std::process::exit(1);
        }
    }
    println!("trip {trip} reannounced wall_us={}", wall_us());
    wait_flap_completion(ctx, survivors, trip, "trip-reannounce").await;
    let reannounce_s = (survivors..ctx.obs.len())
        .filter_map(|i| completion_us(ctx, i))
        .max()
        .map_or(f64::NAN, |tc| tc.saturating_sub(t_up) as f64 / 1e6);
    disarm_survivors(ctx, survivors);
    let up = ctx
        .obs
        .iter()
        .filter(|o| o.established.load(Ordering::Relaxed))
        .count();
    let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
    if up != n_peers as usize || parse_errors != 0 {
        eprintln!(
            "FAIL: trip {trip} integrity check failed: sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
        );
        std::process::exit(1);
    }
    let rss = rss_mib(pid);
    println!(
        "trip_csv,{trip},{n_peers},{teardown_s:.3},{withdraw_s:.3},{holddown_s:.3},{reannounce_s:.3},{rss},{up},{parse_errors}"
    );
    println!("trip {trip} complete wall_us={} rss_mib={rss}", wall_us());
}

/// iBGP-RR soak phase (`RELOADSTALL_IBGP_RR_ASN` +
/// `RELOADSTALL_IBGP_RR_HOLD_SECS`): hold the fleet under the steady
/// churn for the whole window (fail-closed integrity check + one
/// `rr_hold` status line per minute), then verify terminal reflected
/// delivery: every observer re-requests the daemon's Adj-RIB-Out with a
/// Normal ROUTE_REFRESH and must complete its full-table-minus-own-slice
/// bitmap exactly. Churn prefixes (172.16+.x) sit outside the base
/// space, so in-flight churn cannot advance or pollute the bitmaps.
async fn run_ibgp_rr_soak(ctx: &Arc<Ctx>, stubs: &[Stub], hold_secs: u64, pid: i32) {
    let n_peers = ctx.n_peers;
    let total = n_peers * ctx.per_peer;
    let expected = u64::from(total - ctx.per_peer);
    // Bound hold-phase memory: stop recording per-UPDATE events and
    // release what convergence + the control window accumulated (gap
    // stats are never consumed past this point).
    ctx.record_events.store(false, Ordering::Release);
    for observer in &ctx.obs {
        let mut events = observer.events.lock().unwrap();
        events.clear();
        events.shrink_to_fit();
    }
    let hold_start = Instant::now();
    let hold = Duration::from_secs(hold_secs);
    loop {
        let elapsed = hold_start.elapsed();
        let up = ctx
            .obs
            .iter()
            .filter(|o| o.established.load(Ordering::Relaxed))
            .count();
        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        if up != n_peers as usize || parse_errors != 0 {
            eprintln!(
                "FAIL: rr hold integrity check failed at {}s: \
                 sessions_up={up}/{n_peers}, parse_errors={parse_errors}",
                elapsed.as_secs()
            );
            std::process::exit(1);
        }
        println!(
            "rr_hold elapsed_s={} churn_cycles={} sessions_up={up} rss_mib={}",
            elapsed.as_secs(),
            ctx.churn_cycles.load(Ordering::Relaxed),
            rss_mib(pid)
        );
        if elapsed >= hold {
            break;
        }
        tokio::time::sleep((hold - elapsed).min(Duration::from_secs(60))).await;
    }
    // Terminal verification: re-arm the initial-convergence bitmap shape
    // and ask the daemon to re-send its Adj-RIB-Out to every observer.
    disarm_survivors(ctx, 0);
    let mode = FLAP_TRACK_ANNOUNCES;
    for (i, observer) in ctx.obs.iter().enumerate() {
        let own_start = u32::try_from(i).unwrap() * ctx.per_peer;
        let mut generation = observer.generation.lock().unwrap();
        generation.reset(total, expected, own_start, ctx.per_peer);
        drop(generation);
        observer.flap_mode.store(mode, Ordering::Release);
    }
    println!("rr_terminal refresh wall_us={}", wall_us());
    for (i, stub) in stubs.iter().enumerate() {
        let msg = Message::RouteRefresh(RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast));
        if stub.tx.send(msg).await.is_err() {
            eprintln!("FAIL: rr terminal refresh send failed for stub {i}");
            std::process::exit(1);
        }
    }
    wait_flap_completion(ctx, 0, 1, "rr-terminal").await;
    let (up, parse_errors, min_unique, max_unique) = convergence_integrity(ctx);
    if !convergence_integrity_valid(
        n_peers as usize,
        expected,
        up,
        parse_errors,
        min_unique,
        max_unique,
    ) {
        eprintln!(
            "FAIL: rr terminal integrity check failed: unique={min_unique}..{max_unique} \
             expected={expected}, sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
        );
        std::process::exit(1);
    }
    disarm_survivors(ctx, 0);
    println!(
        "rr_terminal_receipt,peers={n_peers},prefixes={total},per_peer={},expected={expected},\
         min_unique={min_unique},max_unique={max_unique},sessions_up={up},\
         parse_errors={parse_errors},churn_cycles={}",
        ctx.per_peer,
        ctx.churn_cycles.load(Ordering::Relaxed)
    );
}

/// Hold the live stub sessions open while an outer measurement runner captures
/// its final daemon evidence.
///
/// This is deliberately opt-in and file-based: the frozen positional CLI stays
/// unchanged, while the ready/ack boundary makes it impossible for the runner
/// to accidentally scrape after dropping every stub socket. The bounded wait
/// fails the receipt instead of parking the host if the runner disappears.
async fn await_evidence_capture(evidence_dir: &Path, timeout: Duration) -> std::io::Result<()> {
    std::fs::create_dir_all(evidence_dir)?;
    if std::fs::read_dir(evidence_dir)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "final evidence directory is not empty",
        ));
    }
    std::fs::write(evidence_dir.join("ready"), b"ready\n")?;
    let deadline = Instant::now() + timeout;
    while !evidence_dir.join("ack").is_file() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "final evidence acknowledgement not received within {}s",
                    timeout.as_secs()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

async fn await_pre_churn_evidence_capture(
    evidence_dir: &Path,
    timeout: Duration,
) -> std::io::Result<()> {
    std::fs::create_dir_all(evidence_dir)?;
    if std::fs::read_dir(evidence_dir)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "pre-churn evidence directory is not empty",
        ));
    }
    std::fs::write(evidence_dir.join("ready"), b"ready\n")?;
    if !std::fs::symlink_metadata(evidence_dir.join("ready"))?
        .file_type()
        .is_file()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "pre-churn ready marker is not a regular file",
        ));
    }
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::symlink_metadata(evidence_dir.join("ack")) {
            Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "pre-churn evidence acknowledgement not received within {}s",
                    timeout.as_secs()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn final_evidence_allowed(_reloads: u32, flapstorm: Option<u32>) -> bool {
    flapstorm.is_none()
}

fn needs_first_exact_bitmap(reloads: u32, flapstorm: Option<u32>) -> bool {
    reloads > 0 || flapstorm.is_some()
}

fn take_single_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let count = args.iter().filter(|arg| arg.as_str() == flag).count();
    assert!(count <= 1, "{flag} may be specified only once");
    args.retain(|arg| arg != flag);
    count == 1
}

fn convergence_only_allowed(
    enabled: bool,
    reloads: u32,
    control_secs: u64,
    flapstorm: Option<u32>,
    reload_cmd: Option<&str>,
    evidence_dir: Option<&Path>,
    pre_churn_evidence_dir: Option<&Path>,
) -> bool {
    !enabled
        || (reloads == 0
            && control_secs == 0
            && flapstorm.is_none()
            && reload_cmd.is_none()
            && evidence_dir.is_some()
            && pre_churn_evidence_dir.is_none())
}

fn convergence_integrity(ctx: &Ctx) -> (usize, u64, u64, u64) {
    let counts: Vec<u64> = ctx
        .obs
        .iter()
        .map(|observer| observer.generation.lock().unwrap().unique)
        .collect();
    (
        ctx.obs
            .iter()
            .filter(|observer| observer.established.load(Ordering::Relaxed))
            .count(),
        ctx.parse_errors.load(Ordering::Relaxed),
        *counts.iter().min().unwrap_or(&0),
        *counts.iter().max().unwrap_or(&0),
    )
}

fn convergence_integrity_valid(
    n_peers: usize,
    expected: u64,
    up: usize,
    parse_errors: u64,
    min_unique: u64,
    max_unique: u64,
) -> bool {
    up == n_peers && parse_errors == 0 && min_unique == expected && max_unique == expected
}

#[allow(clippy::too_many_lines)]
fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    let convergence_only = take_single_flag(&mut a, "--convergence-only");
    // --flapstorm K may appear anywhere; strip it before positional parsing.
    let mut flapstorm: Option<u32> = None;
    if let Some(pos) = a.iter().position(|s| s == "--flapstorm") {
        flapstorm = Some(
            a.get(pos + 1)
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| {
                    eprintln!("--flapstorm requires a stub count K");
                    std::process::exit(2);
                }),
        );
        a.drain(pos..=pos + 1);
    }
    if a.len() < 10 {
        eprintln!(
            "usage: reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
             <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
             [changed_peers] [reload_cmd] [--flapstorm K]\n\
             [--convergence-only]\n\
             reload_cmd: run `sh -c <reload_cmd>` per reload instead of SIGHUP-ing <daemon_pid>\n\
             daemon_pid 0: skip in-harness RSS sampling (outer sampler owns it); \
             requires reload_cmd, --flapstorm, or --convergence-only\n\
             --flapstorm K: flap the first K stubs for {FLAP_ROUNDS} rounds instead of reloading"
        );
        std::process::exit(2);
    }
    let n_peers: u32 = a[1].parse().unwrap();
    let total: u32 = a[2].parse().unwrap();
    let port: u16 = a[3].parse().unwrap();
    let pid: i32 = a[4].parse().unwrap();
    let policy_live = a[5].clone();
    let policy_a = a[6].clone();
    let policy_b = a[7].clone();
    let reloads: u32 = a[8].parse().unwrap();
    let control_secs: u64 = a[9].parse().unwrap();
    let changed_peers: u32 = a.get(10).map_or(n_peers, |value| value.parse().unwrap());
    let reload_cmd: Option<String> = a.get(11).cloned();
    let evidence_dir = std::env::var_os("RELOADSTALL_EVIDENCE_DIR").map(PathBuf::from);
    let pre_churn_evidence_dir =
        std::env::var_os("RELOADSTALL_PRE_CHURN_EVIDENCE_DIR").map(PathBuf::from);
    let overlap_file = std::env::var_os("RELOADSTALL_OVERLAP_FILE").map(PathBuf::from);
    let received_view_file = std::env::var_os("RELOADSTALL_RECEIVED_VIEW_FILE").map(PathBuf::from);
    let stage_cmd = std::env::var("RELOADSTALL_STAGE_CMD").ok();
    let notification_metrics_addr = std::env::var("RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR")
        .ok()
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .unwrap_or_else(|_| {
            eprintln!("RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR must be a loopback SocketAddr with nonzero port");
            std::process::exit(2);
        });
    if notification_metrics_addr.is_some_and(|addr| !addr.ip().is_loopback() || addr.port() == 0)
        || notification_metrics_addr.is_some() && flapstorm.is_none()
    {
        eprintln!("RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR requires --flapstorm and a loopback SocketAddr with nonzero port");
        std::process::exit(2);
    }
    // Soak-mode knobs; every default reproduces the frozen one-shot contract.
    let cycle_quiesce_secs = env_u64("RELOADSTALL_CYCLE_QUIESCE_SECS", 20);
    let trip_every = u32::try_from(env_u64("RELOADSTALL_TRIP_EVERY", 0)).unwrap();
    let trip_prefix_count = u32::try_from(env_u64("RELOADSTALL_TRIP_PREFIXES", 64)).unwrap();
    let trip_reestablish = Duration::from_secs(env_u64("RELOADSTALL_TRIP_REESTABLISH_SECS", 300));
    let final_quiesce = env_u64("RELOADSTALL_FINAL_QUIESCE_SECS", cycle_quiesce_secs);
    // iBGP-RR soak knobs; both absent reproduces the frozen eBGP contract.
    let ibgp_rr = ibgp_rr_mode(env_u64("RELOADSTALL_IBGP_RR_ASN", 0)).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let ibgp_hold_secs = env_u64("RELOADSTALL_IBGP_RR_HOLD_SECS", 0);
    if let Some(shared_as) = ibgp_rr {
        IBGP_RR_ASN.store(u32::from(shared_as), Ordering::Relaxed);
    }
    assert!(n_peers >= CHURNERS, "n_peers must be at least {CHURNERS}");
    assert!(
        (1..=n_peers).contains(&changed_peers),
        "changed_peers must be in 1..={n_peers}"
    );
    assert!(
        pid != 0 || convergence_only || reload_cmd.is_some() || flapstorm.is_some(),
        "daemon_pid 0 (outer RSS sampler) requires --convergence-only, reload_cmd, or --flapstorm"
    );
    assert!(
        convergence_only_allowed(
            convergence_only,
            reloads,
            control_secs,
            flapstorm,
            reload_cmd.as_deref(),
            evidence_dir.as_deref(),
            pre_churn_evidence_dir.as_deref(),
        ),
        "--convergence-only requires reloads=0, control_secs=0, no --flapstorm, no reload_cmd, RELOADSTALL_EVIDENCE_DIR, and no pre-churn evidence directory"
    );
    assert!(
        evidence_dir.is_none() || final_evidence_allowed(reloads, flapstorm),
        "RELOADSTALL_EVIDENCE_DIR is not valid for flapstorm measurements"
    );
    assert!(
        stage_cmd.is_none()
            || (reloads > 0 && flapstorm.is_none() && !convergence_only && reload_cmd.is_none()),
        "RELOADSTALL_STAGE_CMD requires the native SIGHUP reload mode"
    );
    if let Some(k) = flapstorm {
        assert!(
            (1..=n_peers - CHURNERS).contains(&k),
            "--flapstorm K must be in 1..={} (the last {CHURNERS} stubs are churners)",
            n_peers - CHURNERS
        );
    }
    let per_peer = total / n_peers;
    assert_eq!(total % n_peers, 0, "total must divide evenly");
    if trip_every > 0 {
        assert!(
            reloads > 0 && flapstorm.is_none() && !convergence_only && reload_cmd.is_none(),
            "RELOADSTALL_TRIP_EVERY requires the SIGHUP reload mode (reloads > 0)"
        );
        assert!(
            n_peers > CHURNERS,
            "trips need a non-churner designated member: n_peers must exceed {CHURNERS}"
        );
        assert!(
            changed_peers == n_peers,
            "trips require the all-changed reload shape (changed_peers == n_peers)"
        );
        assert!(
            overlap_file.is_none(),
            "trips require disjoint announcements (no RELOADSTALL_OVERLAP_FILE)"
        );
        assert!(
            trip_prefix_count >= 1,
            "RELOADSTALL_TRIP_PREFIXES must be at least 1"
        );
    }
    if ibgp_rr.is_some() {
        // The iBGP-RR soak is the zero-reload shape: no policy
        // generations exist toward iBGP clients, and every other
        // instrument assumes the eBGP route-server scenario.
        assert!(
            reloads == 0
                && flapstorm.is_none()
                && !convergence_only
                && reload_cmd.is_none()
                && trip_every == 0,
            "RELOADSTALL_IBGP_RR_ASN requires reloads == 0 with no flapstorm, \
             reload_cmd, --convergence-only, or trip cycles"
        );
        assert!(
            overlap_file.is_none()
                && evidence_dir.is_none()
                && pre_churn_evidence_dir.is_none()
                && received_view_file.is_none(),
            "RELOADSTALL_IBGP_RR_ASN is incompatible with overlap, evidence, \
             and received-view files"
        );
        assert!(
            changed_peers == n_peers,
            "RELOADSTALL_IBGP_RR_ASN requires the all-peer shape (omit changed_peers)"
        );
    }
    assert!(
        ibgp_hold_secs == 0 || ibgp_rr.is_some(),
        "RELOADSTALL_IBGP_RR_HOLD_SECS requires RELOADSTALL_IBGP_RR_ASN"
    );
    // Overlap and the received-view dump are reload-mode instruments only:
    // flapstorm and convergence-only completion accounting assumes the
    // historical disjoint announcements.
    assert!(
        overlap_file.is_none() || (reloads > 0 && flapstorm.is_none() && !convergence_only),
        "RELOADSTALL_OVERLAP_FILE requires the reload mode (reloads > 0)"
    );
    assert!(
        received_view_file.is_none()
            || (reloads > 0
                && flapstorm.is_none()
                && !convergence_only
                && changed_peers == n_peers
                && evidence_dir.is_some()),
        "RELOADSTALL_RECEIVED_VIEW_FILE requires the all-changed reload mode \
         with RELOADSTALL_EVIDENCE_DIR (the dump precedes the final boundary)"
    );
    let extras = match overlap_file.as_deref() {
        Some(path) => {
            let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
                eprintln!(
                    "cannot read RELOADSTALL_OVERLAP_FILE {}: {error}",
                    path.display()
                );
                std::process::exit(2);
            });
            parse_overlap_file(&text, n_peers, total, per_peer).unwrap_or_else(|error| {
                eprintln!(
                    "invalid RELOADSTALL_OVERLAP_FILE {}: {error}",
                    path.display()
                );
                std::process::exit(2);
            })
        }
        None => vec![Vec::new(); n_peers as usize],
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(24)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let ctx = Arc::new(Ctx {
            t0: Instant::now(),
            n_peers,
            per_peer,
            daemon: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port),
            obs: (0..n_peers)
                .map(|_| Obs {
                    events: Mutex::new(Vec::with_capacity(1 << 14)),
                    base_ann_total: AtomicU64::new(0),
                    established: AtomicBool::new(false),
                    last_comms: Mutex::new(Vec::new()),
                    stable_marker_seen_at_us: AtomicU64::new(0),
                    expected_community: AtomicU32::new(0),
                    generation: Mutex::new(GenerationProgress::default()),
                    refresh_pending: AtomicBool::new(false),
                    flap_mode: AtomicU32::new(FLAP_OFF),
                })
                .collect(),
            extras,
            parse_errors: AtomicU64::new(0),
            churn_cycles: AtomicU64::new(0),
            record_events: AtomicBool::new(true),
        });
        println!(
            "# reloadstall peers={n_peers} changed_peers={changed_peers} \
             stable_peers={} prefixes={total} per_peer={per_peer} pid={pid}",
            n_peers - changed_peers
        );

        // --- Establish all sessions (waves of 64). ---
        let mut stubs: Vec<Stub> = Vec::with_capacity(n_peers as usize);
        for wave in (0..n_peers).collect::<Vec<_>>().chunks(64) {
            let mut handles = Vec::new();
            for &i in wave {
                let c = Arc::clone(&ctx);
                handles.push((i, tokio::spawn(establish_stub(c, i))));
            }
            for (i, h) in handles {
                match h.await.unwrap() {
                    Ok(stub) => stubs.push(stub),
                    Err(e) => {
                        eprintln!("stub {i} failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!(
            "established {} at {:.1}s",
            stubs.len(),
            ctx.t0.elapsed().as_secs_f64()
        );

        let expected = u64::from(total - per_peer);
        // Per-observer completion target: overlap second announcers also
        // exclude their extra announced prefixes (a member never depends on
        // receiving what it announces; grouped mode may legitimately
        // suppress those toward the best-path announcer).
        let targets: Vec<u64> = ctx
            .extras
            .iter()
            .map(|extra| expected - extra.len() as u64)
            .collect();
        let exact_initial = convergence_only || needs_first_exact_bitmap(reloads, flapstorm); // FIRST_EXACT_ARM:
        // The iBGP-RR soak gates its initial convergence on the same
        // exact bitmap (its terminal verification re-arms it later).
        let exact_initial = exact_initial || ibgp_rr.is_some();
        if exact_initial {
            for (i, observer) in ctx.obs.iter().enumerate() {
                let own_start = u32::try_from(i).unwrap() * per_peer;
                let mut generation = observer.generation.lock().unwrap();
                generation.reset(total, expected, own_start, per_peer);
                generation.exclude_extra(&ctx.extras[i]);
                let mode = &observer.flap_mode;
                mode.store(FLAP_TRACK_ANNOUNCES, Ordering::Release);
            }
        }
        // --- Announce base table (FIRST_EXACT_SEND). ---
        for i in 0..n_peers {
            let slice = announced_prefixes(&ctx, i);
            for m in announce_msgs(i, &slice) {
                stubs[i as usize].tx.send(m).await.unwrap();
            }
        }
        // Require every observer's table-minus-own-slice; abort stalls (LAN-449).
        let mut last_sum = 0u64;
        let mut last_progress = Instant::now();
        let unique = loop { // FIRST_EXACT_COUNT_LOOP:
            tokio::time::sleep(Duration::from_millis(200)).await;
            let counts: Vec<u64> = ctx
                .obs
                .iter()
                .map(|observer| {
                    if exact_initial {
                        observer.generation.lock().unwrap().unique
                    } else {
                        observer.base_ann_total.load(Ordering::Relaxed)
                    }
                })
                .collect();
            if counts
                .iter()
                .zip(&targets)
                .all(|(count, target)| count >= target)
            {
                break counts;
            }
            let sum: u64 = counts.iter().sum();
            // Before the first observed announcement, allow the larger
            // FIRST_OUTPUT_WINDOW: large-policy imports compute for
            // minutes before anything reaches the wire.
            let window = if last_sum == 0 {
                FIRST_OUTPUT_WINDOW
            } else {
                STALL_WINDOW
            };
            if sum > last_sum {
                last_sum = sum;
                last_progress = Instant::now();
            } else if last_progress.elapsed() > window {
                let below: Vec<(usize, u64)> = counts
                    .iter()
                    .enumerate()
                    .filter(|&(i, &c)| c < targets[i])
                    .map(|(i, &c)| (i, c))
                    .collect();
                eprintln!(
                    "FAIL: base-table convergence stalled for {}s: expected >= {expected} \
                     base prefixes per observer, {} of {n_peers} observers below; \
                     first stalled (observer, observed): {:?}",
                    window.as_secs(),
                    below.len(),
                    &below[..below.len().min(10)]
                );
                std::process::exit(1);
            }
        };
        if exact_initial {
            if !convergence_only {
                for observer in &ctx.obs {
                    let _g = observer.generation.lock().unwrap();
                    observer.flap_mode.store(FLAP_OFF, Ordering::Release);
                }
            } // FIRST_EXACT_RECEIPT
            println!(
                "first_exact_bitmap,mode={},peers={n_peers},total={total},per_peer={per_peer},expected={expected},completed={},min_unique={},max_unique={}",
                if convergence_only {
                    "convergence-only"
                } else if flapstorm.is_some() {
                    "flapstorm"
                } else if ibgp_rr.is_some() {
                    "ibgp-rr"
                } else {
                    "reload"
                },
                unique
                    .iter()
                    .zip(&targets)
                    .filter(|(count, target)| count >= target)
                    .count(),
                unique.iter().min().unwrap(),
                unique.iter().max().unwrap()
            );
        }
        println!(
            "converged (>= {expected}/observer) at {:.1}s rss_mib={}",
            ctx.t0.elapsed().as_secs_f64(),
            rss_mib(pid)
        );

        if convergence_only {
            let evidence_dir = evidence_dir.as_deref().unwrap();
            let check = |stage| {
                let (up, parse_errors, min_unique, max_unique) =
                    convergence_integrity(&ctx);
                if !convergence_integrity_valid(
                    n_peers as usize,
                    expected,
                    up,
                    parse_errors,
                    min_unique,
                    max_unique,
                ) {
                    eprintln!(
                        "FAIL: convergence-only {stage} integrity check failed: unique={min_unique}..{max_unique} expected={expected}, sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
                    );
                    std::process::exit(1);
                }
                (up, parse_errors, min_unique, max_unique)
            };
            check("pre-ack"); // CONVERGENCE_ONLY_INTEGRITY_CALL
            if let Err(error) = await_evidence_capture(evidence_dir, EVIDENCE_TIMEOUT).await {
                eprintln!("FAIL: convergence-only evidence handshake failed: {error}");
                std::process::exit(1);
            }
            let (up, parse_errors, min_unique, max_unique) =
                check("post-ack"); // CONVERGENCE_ONLY_INTEGRITY_CALL
            for observer in &ctx.obs {
                let _generation = observer.generation.lock().unwrap();
                observer.flap_mode.store(FLAP_OFF, Ordering::Release);
            } // CONVERGENCE_ONLY_DISARM
            println!(
                "convergence_only_receipt,peers={n_peers},prefixes={total},per_peer={per_peer},expected={expected},min_unique={min_unique},max_unique={max_unique},sessions_up={up},parse_errors={parse_errors}"
            );
            std::process::exit(0);
        }

        if let Some(evidence_dir) = pre_churn_evidence_dir.as_deref() {
            if let Err(error) =
                await_pre_churn_evidence_capture(evidence_dir, PRE_CHURN_EVIDENCE_TIMEOUT).await
            {
                eprintln!("FAIL: pre-churn evidence handshake failed: {error}");
                std::process::exit(1);
            }
        }

        // --- Start churn: last CHURNERS stubs flap a dedicated block. ---
        for c in 0..CHURNERS {
            let i = n_peers - CHURNERS + c;
            let tx = stubs[i as usize].tx.clone();
            let block: Vec<Ipv4Prefix> = (0..CHURN_BLOCK).map(|j| churn_prefix(c, j)).collect();
            let cctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                // Stagger churners across the interval.
                tokio::time::sleep(Duration::from_millis(
                    u64::from(c) * CHURN_MS / u64::from(CHURNERS),
                ))
                .await;
                let mut announced = false;
                loop {
                    let msg = if announced {
                        withdraw_msg(&block)
                    } else {
                        announce_msgs(i, &block).pop().unwrap()
                    };
                    announced = !announced;
                    if tx.send(msg).await.is_err() {
                        return;
                    }
                    cctx.churn_cycles.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(CHURN_MS)).await;
                }
            });
        }
        // Let churn reach steady state.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // --- Control window. ---
        let cs = now_us(&ctx);
        tokio::time::sleep(Duration::from_secs(control_secs)).await;
        let ce = now_us(&ctx);
        let gaps: Vec<f64> = (0..n_peers as usize)
            .map(|i| max_gap_ms(&ctx, i, cs, ce, true))
            .collect();
        stats_line("control_maxgap_ms", gaps);
        println!("control_rss_mib {}", rss_mib(pid));

        // --- Flapstorm mode: an alternative to the reload loop. ---
        if let Some(k) = flapstorm {
            let mut prior_high = 0;
            if let Some(addr) = notification_metrics_addr {
                if n_peers != 700 || total != 400_400 || k != 50 {
                    eprintln!("RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR requires the 700-peer, 400400-prefix, 50-flap receipt shape");
                    std::process::exit(2);
                }
                let up = ctx.obs.iter().filter(|o| o.established.load(Ordering::Relaxed)).count();
                let completed = unique.iter().zip(&targets).filter(|(count, target)| count >= target).count();
                let errors = ctx.parse_errors.load(Ordering::Relaxed);
                if up != 700 || completed != 700 || errors != 0 { eprintln!("FAIL: initial receipt integrity: sessions={up}, completions={completed}, parse_errors={errors}"); std::process::exit(1); }
                notification_checkpoint(addr, ("initial_drained", 0, up, completed, expected as u32, errors), &mut prior_high).await;
            }
            run_flapstorm(&ctx, &mut stubs, k, pid, notification_metrics_addr, &mut prior_high).await;
            println!("done rss_mib={}", rss_mib(pid));
            let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
            if parse_errors > 0 {
                eprintln!(
                    "FAIL: {parse_errors} daemon UPDATE decode error(s) — a wire defect; measurement is invalid"
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        }

        // --- iBGP-RR soak mode: churn hold + terminal refresh verify. ---
        if ibgp_rr.is_some() {
            run_ibgp_rr_soak(&ctx, &stubs, ibgp_hold_secs, pid).await;
            println!("done rss_mib={}", rss_mib(pid));
            let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
            if parse_errors > 0 {
                eprintln!(
                    "FAIL: {parse_errors} daemon UPDATE decode error(s) — a wire defect; measurement is invalid"
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        }

        println!(
            "reloadstall_csv_header,reload,peers_total,peers_changed,peers_stable,prefixes,\
             completion_p50_s,completion_p95_s,completion_max_s,\
             changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,\
             all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,\
             all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,\
             changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,\
             rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
        );
        if trip_every > 0 {
            println!(
                "trip_csv_header,trip,peers_total,teardown_s,withdraw_s,holddown_s,\
                 reannounce_s,rss_mib,sessions_up,parse_errors"
            );
        }

        // --- Reload loop. ---
        for r in 1..=reloads {
            let next = if r % 2 == 1 { &policy_b } else { &policy_a };
            let expected_community = if r % 2 == 1 {
                COMMUNITY_GEN_B
            } else {
                COMMUNITY_GEN_A
            };
            std::fs::copy(next, &policy_live).unwrap();
            if let Some(cmd) = &stage_cmd {
                let generation = if r % 2 == 1 { "b" } else { "a" };
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .env("RELOADSTALL_STAGE_GENERATION", generation)
                    .status();
                if !matches!(&status, Ok(status) if status.success()) {
                    eprintln!("reload {r} pre-trigger stage failed: {status:?}");
                    std::process::exit(1);
                }
            }
            let rss_before = rss_mib(pid);
            for (i, observer) in ctx
                .obs
                .iter()
                .take(changed_peers as usize)
                .enumerate()
            {
                observer.expected_community.store(0, Ordering::Release);
                let mut generation = observer.generation.lock().unwrap();
                generation.reset(total, expected, u32::try_from(i).unwrap() * per_peer, per_peer);
                generation.exclude_extra(&ctx.extras[i]);
            }
            // The tracker stays disarmed until its trigger timestamp exists,
            // so a delayed UPDATE from an older A/B generation cannot become
            // pre-trigger evidence (or underflow the duration below).
            let t_hup = now_us(&ctx);
            for observer in ctx.obs.iter().take(changed_peers as usize) {
                observer
                    .expected_community
                    .store(expected_community, Ordering::Release);
            }
            let expected_stable = usize::try_from(n_peers - changed_peers).unwrap();
            if let Some(cmd) = &reload_cmd {
                // Matrix cells (BIRD/OpenBGPD) reload via a command, e.g.
                // `docker exec <c> birdc configure`; nonzero exit = reload
                // failure, same handling as a failed SIGHUP.
                println!("reload {r} reload_cmd wall_us={} policy={next}", wall_us());
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .status();
                if !matches!(&status, Ok(s) if s.success()) {
                    eprintln!("reload {r} reload_cmd failed: {status:?}");
                    std::process::exit(1);
                }
            } else {
                println!("reload {r} SIGHUP wall_us={} policy={next}", wall_us());
                let kill_rc = unsafe { libc::kill(pid, libc::SIGHUP) };
                if kill_rc != 0 {
                    eprintln!(
                        "reload {r} failed to deliver SIGHUP: {}",
                        std::io::Error::last_os_error()
                    );
                    std::process::exit(1);
                }
            }
            // Completion is intentionally scoped to observers whose effective
            // export chain changed. Stable proof starts only after every
            // changed observer has the new generation, below.
            // Progress watchdog, not an absolute deadline: full-fleet
            // re-advertisement time scales with peers x prefixes, so any
            // fixed deadline falsely fails some larger shape while the wire
            // is still delivering. Fail loudly only when no changed observer
            // makes generation progress for STALL_WINDOW.
            let unique_sum = |ctx: &Ctx| -> u64 {
                (0..changed_peers as usize)
                    .map(|i| ctx.obs[i].generation.lock().unwrap().unique)
                    .sum()
            };
            let mut last_unique = 0u64;
            let mut last_progress = Instant::now();
            let mut ticks = 0u32;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let done =
                    (0..changed_peers as usize).all(|i| completion_us(&ctx, i).is_some());
                if done {
                    break;
                }
                ticks += 1;
                if ticks.is_multiple_of(100) {
                    let sat = (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} progress: complete={sat}/{changed_peers}");
                }
                let sum = unique_sum(&ctx);
                // Before the first re-advertised prefix, allow the
                // larger FIRST_OUTPUT_WINDOW: a large-policy reload
                // re-parses and recompiles for minutes before the
                // first marker UPDATE reaches the wire (the reload
                // completion/stall *measurements* are timestamp-based
                // and unaffected by this watchdog).
                let window = if last_unique == 0 {
                    FIRST_OUTPUT_WINDOW
                } else {
                    STALL_WINDOW
                };
                if sum > last_unique {
                    last_unique = sum;
                    last_progress = Instant::now();
                } else if last_progress.elapsed() > window {
                    println!(
                        "reload {r} STALLED: no re-advertisement progress for {}s",
                        window.as_secs()
                    );
                    let sat = (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} observers_complete {sat}/{changed_peers}");
                    // Per-observer expected-vs-observed for the first few
                    // incomplete observers, so a wedge here is diagnosable.
                    for i in (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_none())
                        .take(10)
                    {
                        let g = ctx.obs[i].generation.lock().unwrap();
                        eprintln!(
                            "reload {r} observer {i} incomplete: unique={}/{}",
                            g.unique, g.target
                        );
                    }
                    std::process::exit(1);
                }
            }
            let reload_end_us = (0..changed_peers as usize)
                .filter_map(|i| completion_us(&ctx, i))
                .max()
                .expect("changed_peers is non-zero and every observer completed");
            // Reset the evidence threshold only after the changed cohort has
            // fully received the target generation. Fresh stable-marker churn
            // after this point proves stable observers retained stable-out
            // through the completed transition, rather than merely sampling
            // an UPDATE queued before or during it.
            let marker_since_us = now_us(&ctx);
            let mut stable_ticks = 0u32;
            let mut last_stable = 0usize;
            let mut stable_progress = Instant::now();
            loop {
                let stable_marker_peers =
                    stable_marker_peers_since(&ctx, changed_peers, marker_since_us);
                if stable_marker_peers == expected_stable {
                    break;
                }
                if stable_marker_peers > last_stable {
                    last_stable = stable_marker_peers;
                    stable_progress = Instant::now();
                } else if stable_progress.elapsed() > STALL_WINDOW {
                    eprintln!(
                        "reload {r} STALLED: no post-completion stable-marker progress for {}s: {stable_marker_peers}/{expected_stable}",
                        STALL_WINDOW.as_secs()
                    );
                    std::process::exit(1);
                }
                stable_ticks += 1;
                if stable_ticks.is_multiple_of(20) {
                    eprintln!(
                        "reload {r} post-completion stable markers: {stable_marker_peers}/{expected_stable}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Changed-observer completion and gap metrics preserve the
            // historical measurement. The all-observer gap extends through
            // the slowest changed observer so stable sessions cannot disappear
            // from the receipt just because they have no completion marker.
            let mut comp_s: Vec<f64> = Vec::new();
            let mut gaps: Vec<f64> = Vec::new();
            let mut firsts: Vec<f64> = Vec::new();
            for i in 0..changed_peers as usize {
                if let Some(tc) = completion_us(&ctx, i) {
                    comp_s.push((tc - t_hup) as f64 / 1e6);
                    gaps.push(max_gap_ms(&ctx, i, t_hup, tc, false));
                    // Leading generation stall: trigger -> first base-prefix
                    // UPDATE carrying the expected generation marker.
                    let generation = ctx.obs[i].generation.lock().unwrap();
                    if let Some(first) = generation.first_marker_base_at_us {
                        let elapsed = first
                            .checked_sub(t_hup)
                            .expect("generation evidence predates reload trigger");
                        firsts.push(elapsed as f64 / 1000.0);
                    }
                }
            }
            let all_observer_gaps: Vec<f64> = (0..n_peers as usize)
                .map(|i| max_gap_ms(&ctx, i, t_hup, reload_end_us, true))
                .collect();
            let completion = stats_line(&format!("reload {r} completion_s"), comp_s);
            let changed_gap = stats_line(&format!("reload {r} maxgap_ms"), gaps);
            let all_gap = stats_line(
                &format!("reload {r} all_observer_maxgap_ms"),
                all_observer_gaps,
            );
            let first_generation_update = stats_line(
                &format!("reload {r} changed_first_generation_update_ms"),
                firsts,
            );
            let rss_after = rss_mib(pid);
            println!(
                "reload {r} rss_mib before={rss_before} after={} comms_sample={:?}",
                rss_after,
                ctx.obs[0].last_comms.lock().unwrap().clone()
            );
            let up = ctx
                .obs
                .iter()
                .filter(|o| o.established.load(Ordering::Relaxed))
                .count();
            println!("reload {r} sessions_up {up}/{n_peers}");
            let stable_marker_peers =
                stable_marker_peers_since(&ctx, changed_peers, marker_since_us);
            println!(
                "reload {r} stable_marker_peers {stable_marker_peers}/{expected_stable}"
            );
            let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
            if stable_marker_peers != expected_stable
                || up != n_peers as usize
                || parse_errors != 0
            {
                eprintln!(
                    "FAIL: reload {r} integrity check failed: stable_marker_peers={stable_marker_peers}/{expected_stable}, sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
                );
                std::process::exit(1);
            }
            println!(
                "reloadstall_csv,{r},{n_peers},{changed_peers},{},{total},\
                 {:.6},{:.6},{:.6},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},\
                 {:.3},{:.3},{:.3},{rss_before},{rss_after},{stable_marker_peers},{up},{parse_errors}",
                n_peers - changed_peers,
                completion.p50,
                completion.p95,
                completion.max,
                changed_gap.p50,
                changed_gap.p95,
                changed_gap.max,
                all_gap.p50,
                all_gap.p95,
                all_gap.max,
                first_generation_update.p50,
                first_generation_update.p95,
                first_generation_update.max,
            );
            drain_cycle_events(&ctx.obs);
            // Quiesce between cycles (soak mode overrides the historical 20 s
            // to self-pace the whole window).
            tokio::time::sleep(Duration::from_secs(cycle_quiesce_secs)).await;
            if is_trip_slot(r, trip_every) {
                run_trip_cycle(
                    &ctx,
                    &mut stubs,
                    r / trip_every,
                    pid,
                    trip_prefix_count,
                    trip_reestablish,
                )
                .await;
            }
        }

        // Hold every session up after a final-cycle trip so the outer
        // runner can drain the trip's daemon-side evidence from live
        // metrics before teardown (see final_quiesce_secs).
        let hold = final_quiesce_secs(reloads, trip_every, final_quiesce);
        if hold > 0 {
            println!("final quiesce {hold}s");
            tokio::time::sleep(Duration::from_secs(hold)).await;
        }

        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        let Some(evidence_dir) = evidence_dir.as_deref() else {
            println!("done rss_mib={}", rss_mib(pid));
            if parse_errors > 0 {
                eprintln!(
                    "FAIL: {parse_errors} daemon UPDATE decode error(s) — a wire defect; measurement is invalid"
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        };
        let up = ctx
            .obs
            .iter()
            .filter(|observer| observer.established.load(Ordering::Relaxed))
            .count();
        if up != n_peers as usize || parse_errors != 0 {
            eprintln!(
                "FAIL: final integrity check failed: sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
            );
            std::process::exit(1);
        }
        println!("final sessions_up {up}/{n_peers} parse_errors={parse_errors}");
        if let Some(path) = received_view_file.as_deref() {
            if let Err(error) = write_received_view(&ctx, path) {
                eprintln!("FAIL: received-view dump failed: {error}");
                std::process::exit(1);
            }
        }
        if let Err(error) = await_evidence_capture(evidence_dir, EVIDENCE_TIMEOUT).await {
            eprintln!("FAIL: final evidence handshake failed: {error}");
            std::process::exit(1);
        }
        println!("done rss_mib={}", rss_mib(pid));
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_open(asn: u32) -> Vec<u8> {
        encode_message(&Message::Open(OpenMessage {
            version: 4,
            my_as: u16::try_from(asn).unwrap(),
            hold_time: HOLD_TIME,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            capabilities: vec![Capability::FourOctetAs { asn }],
        }))
        .unwrap()
        .to_vec()
    }

    #[tokio::test]
    async fn establishment_retries_a_transport_close_before_open() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let daemon = listener.local_addr().unwrap();
        let server_open = test_open(65_500);
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let mut client_open = [0u8; 4096];
            assert!(second.read(&mut client_open).await.unwrap() > 0);
            second.write_all(&server_open).await.unwrap();
        });

        let client_open = test_open(64_512);
        let keepalive = encode_message(&Message::Keepalive).unwrap();
        let (stream, retries) = establish_stream_with_retry(
            daemon,
            Ipv4Addr::new(127, 0, 0, 2),
            &client_open,
            &keepalive,
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        assert_eq!(retries, 1);
        drop(stream);
        server.await.unwrap();
    }

    #[test]
    fn notification_metric_parser_fails_closed() {
        let n = "bgp_session_notification_outstanding";
        assert_eq!(metric_value(&format!("{n} 1\n"), n), Ok(1));
        assert!(metric_value(&format!("{n}{{x=\"y\"}} 1\n{n} 1\n"), n).is_err());
        assert!(metric_value(&format!("{n} 1\n{n} 2\n"), n).is_err());
        for value in ["-1", "1.0", "1e2", "NaN", "1 2"] {
            assert!(metric_value(&format!("{n} {value}\n"), n).is_err());
        }
    }

    fn evidence_test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "reloadstall-{label}-{}-{}",
            std::process::id(),
            wall_us()
        ))
    }

    #[tokio::test]
    async fn evidence_handshake_keeps_boundary_until_ack() {
        let directory = evidence_test_dir("ack");
        let waiter_dir = directory.clone();
        let waiter = tokio::spawn(async move {
            await_evidence_capture(&waiter_dir, Duration::from_secs(1)).await
        });
        while !directory.join("ready").is_file() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished(), "barrier advanced before regular ack");
        std::fs::write(directory.join("ack"), b"ack\n").unwrap();
        waiter.await.unwrap().unwrap();
        assert!(directory.join("ready").is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn evidence_handshake_timeout_fails_closed() {
        let directory = evidence_test_dir("timeout");
        let error = await_pre_churn_evidence_capture(&directory, Duration::from_millis(10))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(directory.join("ready").is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn evidence_handshake_rejects_stale_boundary_files() {
        for marker in ["ready", "ack"] {
            let directory = evidence_test_dir(marker);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(marker), b"stale\n").unwrap();

            let error = await_pre_churn_evidence_capture(&directory, Duration::from_millis(10))
                .await
                .unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    async fn evidence_handshake_rejects_non_regular_ack() {
        let directory = evidence_test_dir("ack-directory");
        let writer_dir = directory.clone();
        let writer = tokio::spawn(async move {
            while !writer_dir.join("ready").is_file() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            std::fs::create_dir(writer_dir.join("ack")).unwrap();
        });
        let error = await_pre_churn_evidence_capture(&directory, Duration::from_millis(25))
            .await
            .unwrap_err();
        writer.await.unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pre_churn_evidence_barrier_is_ordered_before_churn() {
        let source = include_str!("main.rs");
        let marker = |needle: &str| source.find(needle).unwrap();
        let ordered = ["ARM:", "SEND", "COUNT_LOOP:", "RECEIPT"].map(|suffix| {
            let needle = ["FIRST_EXACT_", suffix].concat();
            assert_eq!(source.matches(&needle).count(), 1);
            marker(&needle)
        });
        let barrier = source
            .find("await_pre_churn_evidence_capture(evidence_dir, PRE_CHURN_EVIDENCE_TIMEOUT)")
            .unwrap();
        let churn = source.find("// --- Start churn:").unwrap();
        let disarm_source = ["flap_mode.store(", "FLAP_OFF"].concat();
        let cutoff = marker("_g = observer.generation.lock().unwrap();");
        let disarm = source.match_indices(&disarm_source).nth(2).unwrap().0;
        assert!(ordered[..3].is_sorted() && ordered[2] < cutoff);
        assert!(cutoff < disarm && disarm < ordered[3]);
        assert!(ordered[3] < barrier && barrier < churn);
        let arm_source = "store(FLAP_TRACK_ANNOUNCES, Ordering::Release)";
        assert_eq!(source.matches(arm_source).count(), 2);
        let recheck_source = ["flap_mode.load(Ordering::Acquire) == ", "flap_mode"].concat();
        assert_eq!(source.matches(&recheck_source).count(), 1);
        let count_source = "observer.generation.lock().unwrap().unique";
        assert_eq!(source.matches(count_source).count(), 3);
        assert_eq!(source.matches(&disarm_source).count(), 4);
        let opt_in = ["RELOADSTALL_PRE_", "CHURN_EVIDENCE_DIR"].concat();
        assert_eq!(
            source.matches(&opt_in).count(),
            1,
            "removing opt-in or making the barrier unconditional changes behavior"
        );
    }

    #[test]
    fn final_evidence_accepts_reloads_but_rejects_flapstorm() {
        assert!(final_evidence_allowed(4, None));
        assert!(final_evidence_allowed(0, None));
        assert!(!final_evidence_allowed(0, Some(1)));
        assert!(!final_evidence_allowed(4, Some(1)));
    }

    #[test]
    fn optional_stage_hook_precedes_sampling_and_trigger() {
        let source = include_str!("main.rs");
        let copy = source.find("std::fs::copy(next, &policy_live)").unwrap();
        let stage = source
            .find(".env(\"RELOADSTALL_STAGE_GENERATION\", generation)")
            .unwrap();
        let rss = source[stage..]
            .find("let rss_before = rss_mib(pid)")
            .unwrap()
            + stage;
        let trigger = source[rss..].find("let t_hup = now_us(&ctx)").unwrap() + rss;
        assert!(copy < stage && stage < rss && rss < trigger);
        assert_eq!(source.matches("RELOADSTALL_STAGE_CMD").count(), 4);
    }

    #[test]
    fn first_exact_bitmap_mode_matrix() {
        assert!(!needs_first_exact_bitmap(0, None));
        assert!(needs_first_exact_bitmap(1, None));
        assert!(needs_first_exact_bitmap(0, Some(1)));
        assert!(needs_first_exact_bitmap(1, Some(1)));
    }

    #[test]
    fn convergence_only_mode_matrix_is_fail_closed() {
        let evidence = Path::new("evidence");
        let pre_churn = Path::new("pre-churn");
        assert!(convergence_only_allowed(
            true,
            0,
            0,
            None,
            None,
            Some(evidence),
            None
        ));
        for rejected in [
            convergence_only_allowed(true, 1, 0, None, None, Some(evidence), None),
            convergence_only_allowed(true, 0, 1, None, None, Some(evidence), None),
            convergence_only_allowed(true, 0, 0, Some(1), None, Some(evidence), None),
            convergence_only_allowed(true, 0, 0, None, Some("reload"), Some(evidence), None),
            convergence_only_allowed(true, 0, 0, None, None, None, None),
            convergence_only_allowed(true, 0, 0, None, None, Some(evidence), Some(pre_churn)),
        ] {
            assert!(!rejected);
        }
        let mut duplicate = vec!["--convergence-only".to_owned(); 2];
        assert!(std::panic::catch_unwind(move || take_single_flag(
            &mut duplicate,
            "--convergence-only"
        ))
        .is_err());
    }

    #[test]
    fn convergence_only_integrity_requires_exact_equality_and_health() {
        assert!(convergence_integrity_valid(8, 700, 8, 0, 700, 700));
        assert!(!convergence_integrity_valid(8, 700, 8, 0, 699, 700));
        assert!(!convergence_integrity_valid(8, 700, 8, 0, 700, 701));
        assert!(!convergence_integrity_valid(8, 700, 7, 0, 700, 700));
        assert!(!convergence_integrity_valid(8, 700, 8, 1, 700, 700));
    }

    #[test]
    fn convergence_only_source_arms_and_checks_around_ack_before_churn() {
        let source = include_str!("main.rs");
        let exact_arm = [
            "let exact_initial = convergence_only || ",
            "needs_first_exact_bitmap(reloads, flapstorm)",
        ]
        .concat();
        assert!(source.contains(&exact_arm));
        let call_marker = ["CONVERGENCE_ONLY_", "INTEGRITY_CALL"].concat();
        assert_eq!(source.matches(&call_marker).count(), 2);
        let first_check = source.find("check(\"pre-ack\")").unwrap();
        let ack_marker = ["await_evidence_", "capture(evidence_dir, EVIDENCE_TIMEOUT)"].concat();
        let ack = source.find(&ack_marker).unwrap();
        let second_check = source.find("check(\"post-ack\")").unwrap();
        let disarm = source.find("CONVERGENCE_ONLY_DISARM").unwrap();
        let receipt = source.find("convergence_only_receipt,").unwrap();
        let exit = source[receipt..].find("std::process::exit(0)").unwrap() + receipt;
        let pre_churn = source
            .find("if let Some(evidence_dir) = pre_churn_evidence_dir")
            .unwrap();
        let churn = source.find("// --- Start churn:").unwrap();
        assert!(first_check < ack && ack < second_check && second_check < disarm);
        assert!(disarm < receipt);
        assert!(receipt < exit && exit < pre_churn && pre_churn < churn);
    }

    #[test]
    fn pre_churn_evidence_timeout_is_exactly_sixty_seconds() {
        assert_eq!(PRE_CHURN_EVIDENCE_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn generation_progress_counts_unique_prefixes_only() {
        let mut progress = GenerationProgress::default();
        progress.reset(128, 2, 100, 26);

        progress.observe(7, 10);
        progress.observe(7, 20);
        assert_eq!(
            progress.unique, 1,
            "a duplicate announce is not completion progress"
        );
        assert_eq!(progress.completed_at_us, None);

        progress.observe(63, 30);
        assert_eq!(progress.unique, 2);
        assert_eq!(progress.completed_at_us, Some(30));
        progress.observe(64, 40);
        assert_eq!(
            progress.completed_at_us,
            Some(30),
            "completion time is stable"
        );
    }

    #[test]
    fn generation_progress_rejects_stale_policy_markers() {
        let mut progress = GenerationProgress::default();
        progress.reset(128, 1, 100, 27);
        let announced = [base_prefix(7)];

        observe_generation(
            &mut progress,
            0,
            &[COMMUNITY_GEN_B],
            announced.iter().copied(),
            128,
            5,
        );
        assert_eq!(
            progress.first_marker_base_at_us, None,
            "generation evidence must stay empty while the tracker is disarmed"
        );

        observe_generation(
            &mut progress,
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_A],
            announced.iter().copied(),
            128,
            10,
        );
        assert_eq!(progress.unique, 0);
        assert_eq!(progress.completed_at_us, None);
        assert_eq!(progress.first_marker_base_at_us, None);

        // Churn carrying the expected marker is not base-generation output.
        observe_generation(
            &mut progress,
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_B],
            std::iter::once(churn_prefix(0, 0)),
            128,
            15,
        );
        assert_eq!(progress.first_marker_base_at_us, None);

        observe_generation(
            &mut progress,
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_B],
            announced.iter().copied(),
            128,
            20,
        );
        assert_eq!(progress.unique, 1);
        assert_eq!(progress.completed_at_us, Some(20));
        assert_eq!(progress.first_marker_base_at_us, Some(20));

        progress.reset(128, 1, 100, 27);
        assert_eq!(
            progress.first_marker_base_at_us, None,
            "a new generation must not inherit first-output evidence"
        );
    }

    #[test]
    fn generation_progress_reads_partial_flagged_communities() {
        // BIRD sets the RFC 4271 Partial bit on transit routes (flags 0xe0),
        // so COMMUNITIES decodes to `CommunitiesPartial`. Both flavours must
        // drive generation progress identically or the harness reports a
        // false reload stall against a daemon that re-advertised correctly.
        let announced = [base_prefix(7)];
        let mut observed = Vec::new();

        for attribute in [
            PathAttribute::Communities(vec![COMMUNITY_GEN_B]),
            PathAttribute::CommunitiesPartial(vec![COMMUNITY_GEN_B]),
        ] {
            let attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
                attribute,
            ];
            let communities = observed_communities(&attributes);
            assert_eq!(communities, [COMMUNITY_GEN_B]);

            let mut progress = GenerationProgress::default();
            progress.reset(128, 1, 100, 27);
            observe_generation(
                &mut progress,
                COMMUNITY_GEN_B,
                communities,
                announced.iter().copied(),
                128,
                20,
            );
            observed.push((progress.unique, progress.first_marker_base_at_us));
        }

        assert_eq!(observed[0], (1, Some(20)));
        assert_eq!(
            observed[0], observed[1],
            "Partial-flagged COMMUNITIES must be observed like the bare variant"
        );
    }

    #[test]
    fn generation_progress_rejects_observers_own_slice() {
        let mut progress = GenerationProgress::default();
        progress.reset(4, 3, 2, 1);

        progress.observe(2, 5);
        assert_eq!(progress.first_marker_base_at_us, None);
        progress.observe(0, 10);
        progress.observe(1, 20);
        assert_eq!(progress.unique, 2, "own prefix must not advance completion");
        assert_eq!(progress.completed_at_us, None);
        assert_eq!(
            progress.first_marker_base_at_us,
            Some(10),
            "excluded own-slice output must not set or replace accepted evidence"
        );

        progress.observe(3, 40);
        assert_eq!(progress.unique, 3);
        assert_eq!(progress.completed_at_us, Some(40));
    }

    #[test]
    fn flap_window_tracks_only_flapped_slices() {
        // 4 peers x 2 prefixes each, K=2 flapped: window = indices [0, 4),
        // exclusion covers [4, 8) — the arm_survivors reset shape.
        let mut progress = GenerationProgress::default();
        progress.reset(8, 4, 4, 4);

        progress.observe(4, 10); // survivor's own slice: excluded
        progress.observe(7, 20); // another survivor slice: excluded
        assert_eq!(progress.unique, 0, "non-flapped indices must not count");

        for idx in 0..4u64 {
            progress.observe(usize::try_from(idx).unwrap(), 30 + idx);
        }
        assert_eq!(progress.unique, 4);
        assert_eq!(progress.completed_at_us, Some(33));
    }

    #[test]
    fn stable_marker_freshness_rejects_missing_and_pre_threshold_evidence() {
        assert!(!stable_marker_is_fresh(0, 100));
        assert!(!stable_marker_is_fresh(99, 100));
        assert!(stable_marker_is_fresh(100, 100));
        assert!(stable_marker_is_fresh(101, 100));
    }

    #[test]
    fn overlap_file_parses_and_rejects_malformed_allocations() {
        let extras = parse_overlap_file("1\t0\n0\t7\n1\t5\n", 4, 8, 2).unwrap();
        assert_eq!(extras, vec![vec![7], vec![0, 5], vec![], vec![]]);
        assert!(parse_overlap_file("", 4, 8, 2)
            .unwrap()
            .iter()
            .all(Vec::is_empty));
        for (bad, why) in [
            ("1 0", "missing tab"),
            ("x\t0", "member parse"),
            ("1\tx", "index parse"),
            ("4\t0", "member out of range"),
            ("1\t8", "prefix out of range"),
            ("1\t3", "own-slice prefix"),
            ("1\t0\n1\t0", "duplicate"),
        ] {
            assert!(parse_overlap_file(bad, 4, 8, 2).is_err(), "{why}");
        }
    }

    #[test]
    fn received_view_records_before_exclusion_and_extras_shrink_target() {
        let mut progress = GenerationProgress::default();
        progress.reset(8, 6, 2, 2); // observer 1 of 4, per_peer 2
        progress.exclude_extra(&[5]);
        assert_eq!(progress.target, 5);

        progress.observe(2, 10); // own slice: excluded from completion
        progress.observe(5, 20); // overlap extra: excluded from completion
        assert_eq!(progress.unique, 0);
        for idx in [0, 1, 4, 6, 7] {
            progress.observe(idx, 30);
        }
        assert_eq!(progress.unique, 5);
        assert_eq!(progress.completed_at_us, Some(30));
        // The received view keeps every delivered prefix, including the
        // excluded own announcements (the per-client-best runner-up path).
        let received: Vec<usize> = (0..8)
            .filter(|idx| progress.received[idx / 64] & (1 << (idx % 64)) != 0)
            .collect();
        assert_eq!(received, vec![0, 1, 2, 4, 5, 6, 7]);
        progress.reset(8, 6, 2, 2);
        assert!(progress.excluded_extra.is_empty(), "reset clears extras");
        assert!(progress.received.iter().all(|&slot| slot == 0));
    }

    #[test]
    fn trip_slot_schedule_matches_planned_counts() {
        // trip_every 0 (the frozen one-shot default) never trips.
        assert!((1..=48).all(|r| !is_trip_slot(r, 0)));
        // The flagship shape: 48 reloads, trip every 8th -> 6 trips.
        let slots: Vec<u32> = (1..=48).filter(|&r| is_trip_slot(r, 8)).collect();
        assert_eq!(slots, vec![8, 16, 24, 32, 40, 48]);
        // The smoke shape: 5 reloads, trip every 2nd -> 2 trips.
        let slots: Vec<u32> = (1..=5).filter(|&r| is_trip_slot(r, 2)).collect();
        assert_eq!(slots, vec![2, 4]);
    }

    #[test]
    fn reload_cycle_drain_keeps_observer_events_bounded() {
        let observer = || Obs {
            events: Mutex::new(
                (0..1000)
                    .map(|t_us| Event {
                        t_us,
                        base_ann: 1,
                        other: 0,
                    })
                    .collect(),
            ),
            base_ann_total: AtomicU64::new(0),
            established: AtomicBool::new(true),
            last_comms: Mutex::new(Vec::new()),
            stable_marker_seen_at_us: AtomicU64::new(0),
            expected_community: AtomicU32::new(0),
            generation: Mutex::new(GenerationProgress::default()),
            refresh_pending: AtomicBool::new(false),
            flap_mode: AtomicU32::new(FLAP_OFF),
        };
        let obs = vec![observer(), observer()];
        let capacity_before = obs[0].events.lock().unwrap().capacity();
        drain_cycle_events(&obs);
        for o in &obs {
            let events = o.events.lock().unwrap();
            assert!(events.is_empty(), "cycle drain must empty every observer");
            assert_eq!(
                events.capacity(),
                capacity_before,
                "drain keeps capacity: memory bound = busiest single cycle"
            );
        }
        // The drain must run inside the reload loop, after the cycle's CSV
        // row (its stats consumed the events) and before the quiesce.
        let source = include_str!("main.rs");
        let call = ["drain_cycle_events", "(&ctx.obs)"].concat();
        assert_eq!(source.matches(&call).count(), 1);
        let csv_needle = ["reloadstall_csv,", "{r}"].concat();
        let csv = source.find(&csv_needle).unwrap();
        let drain = source.find(&call).unwrap();
        let quiesce_needle = ["from_secs(cycle_", "quiesce_secs)"].concat();
        let quiesce = source.find(&quiesce_needle).unwrap();
        assert!(csv < drain && drain < quiesce);
    }

    #[test]
    fn final_quiesce_applies_only_when_the_last_reload_trips() {
        // Flagship: 48 reloads, trip every 8th -> trip 6 rides reload 48,
        // so the engine must hold sessions for the runner's evidence drain.
        assert_eq!(final_quiesce_secs(48, 8, 120), 120);
        // Masked smoke shape: last trip on reload 4 of 5 settles while the
        // engine is still alive; no hold.
        assert_eq!(final_quiesce_secs(5, 2, 120), 0);
        // The frozen one-shot contract (no trips) never holds.
        assert_eq!(final_quiesce_secs(4, 0, 120), 0);
    }

    #[test]
    fn trip_block_is_outside_every_completion_bitmap() {
        for total in [600, 400_000] {
            let block = trip_block(total, 64);
            assert_eq!(block.len(), 64);
            assert_eq!(block[0], base_prefix(total));
            for prefix in &block {
                assert_eq!(
                    base_prefix_index(*prefix, total),
                    None,
                    "trip prefixes must never advance an observer bitmap"
                );
            }
        }
    }

    #[test]
    fn soak_env_defaults_preserve_the_one_shot_contract() {
        // Absent env vars must reproduce the historical quiesce and
        // trip-free behavior exactly.
        assert_eq!(env_u64("RELOADSTALL_TEST_UNSET_KNOB", 20), 20);
        assert!(!is_trip_slot(4, 0));
    }

    #[test]
    fn ibgp_rr_mode_accepts_u16_asns_only() {
        assert_eq!(ibgp_rr_mode(0), Ok(None));
        assert_eq!(ibgp_rr_mode(1), Ok(Some(1)));
        assert_eq!(ibgp_rr_mode(64512), Ok(Some(64512)));
        assert_eq!(ibgp_rr_mode(65535), Ok(Some(65535)));
        assert!(ibgp_rr_mode(65536).is_err());
        assert!(ibgp_rr_mode(4_200_000_000).is_err());
    }

    #[test]
    fn ibgp_rr_attrs_switch_and_ebgp_default_is_untouched() {
        // Single test for both modes: the mode static is process-global,
        // so this is the only test allowed to flip it (and it restores
        // the eBGP default before returning).
        let ebgp = base_attrs(7);
        assert_eq!(
            ebgp,
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![64519])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 8)),
            ],
            "eBGP announcement attributes are a frozen contract"
        );

        IBGP_RR_ASN.store(64512, Ordering::Relaxed);
        let ibgp = base_attrs(7);
        IBGP_RR_ASN.store(0, Ordering::Relaxed);
        assert_eq!(
            ibgp,
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 8)),
                PathAttribute::LocalPref(100),
            ],
            "iBGP origination: empty AS_PATH + LOCAL_PREF, same next-hop"
        );
        // The iBGP UPDATE must encode (empty AS_PATH is a valid empty
        // attribute) and decode back to the same generated shape.
        let messages = {
            IBGP_RR_ASN.store(64512, Ordering::Relaxed);
            let messages = announce_msgs(7, &[base_prefix(3)]);
            IBGP_RR_ASN.store(0, Ordering::Relaxed);
            messages
        };
        assert_eq!(messages.len(), 1);
        let bytes = encode_message(&messages[0]).expect("iBGP UPDATE encodes");
        let mut buf = bytes::Bytes::copy_from_slice(&bytes);
        let Message::Update(update) = decode_message(&mut buf, MAX_MESSAGE_LEN).unwrap() else {
            panic!("expected an UPDATE");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        assert_eq!(parsed.announced.len(), 1);
        assert!(parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(100))));
        assert!(parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(path) if path.segments.is_empty())));
    }

    #[test]
    fn base_prefix_index_round_trips_and_rejects_non_base_routes() {
        for index in [0, 1, 65_535, 65_536, 400_399] {
            assert_eq!(
                base_prefix_index(base_prefix(index), 400_400),
                Some(index as usize)
            );
        }
        assert_eq!(base_prefix_index(base_prefix(400_400), 400_400), None);
        assert_eq!(
            base_prefix_index(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 24), 400_400),
            None
        );
        // 1M-route shape (LAN-449): indexes past 655359 use first octets >= 30
        // and must still round-trip; the total gate stays the upper bound.
        for index in [655_359, 655_360, 999_999] {
            assert_eq!(
                base_prefix_index(base_prefix(index), 1_000_000),
                Some(index as usize)
            );
        }
        assert_eq!(base_prefix_index(base_prefix(1_000_000), 1_000_000), None);
        assert_eq!(
            base_prefix_index(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 24), 1_000_000),
            None
        );
    }
}
