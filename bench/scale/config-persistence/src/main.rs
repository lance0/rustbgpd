//! Config persistence / history / rollback / commit-confirm integration receipt.
//!
//! Three real BGP stub sessions dial a running rustbgpd over loopback TCP and
//! exchange real OPEN/KEEPALIVE/UPDATE messages encoded and decoded by
//! `crates/wire`. One stub originates the table; the other two observe it. The
//! harness owns the daemon process itself, because three of the five areas it
//! covers only exist across a restart:
//!
//! | stub | role |
//! |---|---|
//! | 0 | route source, originates the table |
//! | 1 | subject — the session a rejected mutation must leave untouched |
//! | 2 | bystander — an unrelated session that must also be undisturbed |
//!
//! Areas, in the order the phases run them:
//!
//! 1. a persisted mutation survives a restart;
//! 2. history records it and `config rollback` restores a prior generation;
//! 3. commit-confirm succeeds, times out, and survives a SIGKILL inside the
//!    confirmation window;
//! 4. an injected persistence failure (a config directory sealed to `0o500`)
//!    leaves runtime config, session identity, flap state, cumulative
//!    counters, and wire state UNCHANGED — not restored;
//! 5. the persisted file, the runtime snapshot, and the history record agree
//!    after every successful mutation.
//!
//! Every assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line, and a
//! machine-readable summary is written to `<out_dir>/summary.json`. A failed
//! check exits 1; an operational failure (session, timeout, tooling) exits 2.
//!
//! Usage:
//!   configpersist <daemon_bin> <rbgp_bin> <config_path> <state_dir> \
//!       <bgp_port> <metrics_addr> <out_dir>
//!
//! Shape pinned in docs/perf/config-persistence-2026-07.md.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustbgpd_wire::attribute::MpReachNlri;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::nlri::{NlriEntry, Prefix};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Pinned shape. The receipt discloses these exact numbers; they are constants
// rather than arguments so a published row cannot describe a different run
// than the one the driver performed.
// ---------------------------------------------------------------------------

const PEERS: usize = 3;
const SOURCE: usize = 0;
const SUBJECT: usize = 1;
const BYSTANDER: usize = 2;
/// The two stubs that must hold the whole table. The source never receives its
/// own routes back, so it is deliberately not a convergence observer.
const OBSERVERS: [usize; 2] = [SUBJECT, BYSTANDER];

/// IPv4 and IPv6 unicast prefixes the source originates. Small on purpose:
/// this receipt measures config-plane behavior, and the table exists only so
/// the sessions carry real wire history a rejected mutation could disturb.
const V4_ROUTES: usize = 6;
const V6_ROUTES: usize = 3;

const HOLD_TIME: u16 = 180;
/// Longest wait for a convergence or readiness predicate.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(60);
/// Quiet window after a predicate holds, so a late UPDATE cannot be mistaken
/// for a settled state. Also the window a rejected mutation gets to prove it
/// changed nothing.
const SETTLE: Duration = Duration::from_secs(5);
/// Confirm window for the timeout case, plus the slack the driver waits past
/// it before asserting the auto-revert landed.
const TIMEOUT_CONFIRM_SECONDS: u32 = 10;
/// Confirm window for the SIGKILL case: long enough that the restart is
/// unambiguously *inside* the window rather than racing its expiry.
const RESTART_CONFIRM_SECONDS: u32 = 600;

/// Neighbors the phases add. None of them is ever dialed: they exist to be
/// written, restored, reverted, and refused.
const ADD_RESTART: &str = "127.9.2.11";
const ADD_ROLLED_BACK: &str = "127.9.2.12";
const ADD_CONFIRMED: &str = "127.9.2.13";
const ADD_TIMED_OUT: &str = "127.9.2.14";
const ADD_KILLED: &str = "127.9.2.15";
const ADD_REFUSED: &str = "127.9.2.16";

fn peer_addr(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 9, 2, u8::try_from(i + 1).expect("peer index fits"))
}

fn peer_asn(i: usize) -> u32 {
    64701 + u32::try_from(i).expect("peer index fits")
}

fn v4_prefix(i: usize) -> Ipv4Prefix {
    Ipv4Prefix::new(
        Ipv4Addr::new(21, 0, u8::try_from(i).expect("route index fits"), 0),
        24,
    )
}

fn v6_prefix(i: usize) -> Ipv6Prefix {
    Ipv6Prefix::new(
        Ipv6Addr::new(
            0x2001,
            0x0db9,
            0,
            u16::try_from(i).expect("route index fits"),
            0,
            0,
            0,
            0,
        ),
        64,
    )
}

// ---------------------------------------------------------------------------
// Per-observer wire state.
// ---------------------------------------------------------------------------

/// What one stub has actually seen on the wire. `v4`/`v6` are the currently
/// advertised sets. The cumulative counters exist so a phase can assert *no*
/// churn reached a peer, which a set snapshot cannot show, and
/// `link_drops`/`notifications` so it can assert the TCP session itself was
/// never disturbed.
#[derive(Default)]
struct Wire {
    v4: HashSet<Ipv4Prefix>,
    v6: HashSet<Ipv6Prefix>,
    announced_nlri: u64,
    withdrawn_nlri: u64,
    updates: u64,
    notifications: u64,
    link_drops: u64,
}

/// The wire-side identity of one session, in the form a phase compares before
/// and after. A torn-down session cannot reproduce it: reconnecting resets
/// every cumulative counter and increments `link_drops`.
#[derive(Debug, PartialEq, Eq)]
struct WireIdentity {
    v4: usize,
    v6: usize,
    announced_nlri: u64,
    withdrawn_nlri: u64,
    updates: u64,
    notifications: u64,
    link_drops: u64,
    established: bool,
    decode_errors: u64,
}

struct Obs {
    wire: Mutex<Wire>,
    established: AtomicBool,
    decode_errors: AtomicU64,
}

impl Obs {
    fn new() -> Self {
        Self {
            wire: Mutex::new(Wire::default()),
            established: AtomicBool::new(false),
            decode_errors: AtomicU64::new(0),
        }
    }

    /// Forget a previous session's wire history. Called only where the
    /// receipt has just torn the daemon down on purpose.
    fn reset(&self) {
        *self.wire.lock().expect("wire state lock") = Wire::default();
        self.decode_errors.store(0, Ordering::Release);
    }

    fn identity(&self) -> WireIdentity {
        let wire = self.wire.lock().expect("wire state lock");
        WireIdentity {
            v4: wire.v4.len(),
            v6: wire.v6.len(),
            announced_nlri: wire.announced_nlri,
            withdrawn_nlri: wire.withdrawn_nlri,
            updates: wire.updates,
            notifications: wire.notifications,
            link_drops: wire.link_drops,
            established: self.established.load(Ordering::Acquire),
            decode_errors: self.decode_errors.load(Ordering::Acquire),
        }
    }

    fn converged(&self) -> bool {
        let wire = self.wire.lock().expect("wire state lock");
        wire.v4.len() == V4_ROUTES && wire.v6.len() == V6_ROUTES
    }
}

struct Ctx {
    daemon: SocketAddr,
    obs: Vec<Obs>,
}

// ---------------------------------------------------------------------------
// Session establishment.
// ---------------------------------------------------------------------------

fn mp_reach_v6(prefixes: &[Ipv6Prefix]) -> MpReachNlri {
    MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db9, 0xffff, 0, 0, 0, 0, 1)),
        link_local_next_hop: None,
        announced: prefixes
            .iter()
            .map(|prefix| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(*prefix),
            })
            .collect(),
        flowspec_announced: Vec::new(),
        evpn_announced: Vec::new(),
        bgpls_announced: Vec::new(),
        vpn_announced: Vec::new(),
        labeled_announced: Vec::new(),
        rtc_announced: Vec::new(),
    }
}

/// The source's full table as two UPDATEs: one legacy-body IPv4 message and
/// one `MP_REACH_NLRI` IPv6 message.
fn source_table() -> Vec<Message> {
    let v4: Vec<Ipv4NlriEntry> = (0..V4_ROUTES)
        .map(|i| Ipv4NlriEntry {
            path_id: 0,
            prefix: v4_prefix(i),
        })
        .collect();
    let v6: Vec<Ipv6Prefix> = (0..V6_ROUTES).map(v6_prefix).collect();

    let v4_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(SOURCE)])],
        }),
        // A 127/8 NEXT_HOP is rejected with UPDATE error subcode 8, so the
        // source uses a synthetic off-loopback address. Observers never
        // resolve it.
        PathAttribute::NextHop(Ipv4Addr::new(10, 9, 2, 1)),
    ];
    let v6_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(SOURCE)])],
        }),
        PathAttribute::MpReachNlri(mp_reach_v6(&v6)),
    ];

    vec![
        Message::Update(UpdateMessage::build(
            &v4,
            &[],
            &v4_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        )),
        Message::Update(UpdateMessage::build(
            &[],
            &[],
            &v6_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        )),
    ]
}

async fn establish(ctx: Arc<Ctx>, i: usize) -> Result<mpsc::Sender<Message>, String> {
    let local = peer_addr(i);
    let sock = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    sock.bind(SocketAddr::new(local.into(), 0))
        .map_err(|e| format!("bind {local}: {e}"))?;
    let mut stream = sock
        .connect(ctx.daemon)
        .await
        .map_err(|e| format!("connect from {local}: {e}"))?;
    stream.set_nodelay(true).ok();

    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(peer_asn(i)).expect("stub ASN fits two octets"),
        hold_time: HOLD_TIME,
        // Higher than the daemon's router-id so RFC 6286 collision
        // resolution keeps this inbound connection.
        bgp_identifier: Ipv4Addr::new(240, 9, 2, u8::try_from(i + 1).expect("peer index fits")),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: peer_asn(i) },
            Capability::RouteRefresh,
        ],
    };
    let bytes = encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("open write: {e}"))?;

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN) {
            if buf.len() >= usize::from(total) {
                let mut body = buf.split_to(usize::from(total)).freeze();
                match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(Message::Open(_)) => break,
                    Ok(Message::Notification(n)) => {
                        return Err(format!(
                            "NOTIFICATION during open: {:?}/{}",
                            n.code, n.subcode
                        ))
                    }
                    Ok(_) => continue,
                    Err(e) => return Err(format!("decode during open: {e}")),
                }
            }
        }
        let mut tmp = [0u8; 4096];
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("closed before OPEN".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let keepalive = encode_message(&Message::Keepalive).expect("keepalive encodes");
    stream
        .write_all(&keepalive)
        .await
        .map_err(|e| format!("keepalive write: {e}"))?;
    ctx.obs[i].established.store(true, Ordering::Release);

    let (tx, mut tx_rx) = mpsc::channel::<Message>(64);
    let (mut reader, mut writer) = stream.into_split();

    let writer_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { break };
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                _ = tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).expect("keepalive encodes");
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                else => break,
            }
        }
        drop(writer);
        writer_ctx.obs[i]
            .established
            .store(false, Ordering::Release);
    });

    let reader_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut frame = BytesMut::with_capacity(1 << 16);
        let mut tmp = vec![0u8; 1 << 16];
        loop {
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
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
                        reader_ctx.obs[i]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        record_link_drop(&reader_ctx, i);
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut body = frame.split_to(total).freeze();
                let msg = match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(msg) => msg,
                    Err(error) => {
                        eprintln!("stub {i} failed to decode daemon message: {error}");
                        reader_ctx.obs[i]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        record_link_drop(&reader_ctx, i);
                        return;
                    }
                };
                match msg {
                    Message::Notification(n) => {
                        // A NOTIFICATION is the daemon deliberately ending the
                        // session, which is precisely what a rejected mutation
                        // must never cause.
                        eprintln!("stub {i} NOTIFICATION {:?}/{}", n.code, n.subcode);
                        reader_ctx.obs[i]
                            .wire
                            .lock()
                            .expect("wire state lock")
                            .notifications += 1;
                    }
                    Message::Update(update) => {
                        let parsed = match update.parse(true, false, &[]) {
                            Ok(parsed) => parsed,
                            Err(error) => {
                                // A daemon UPDATE this harness cannot decode is
                                // a daemon defect, and silently skipping it
                                // looks exactly like the absence being measured.
                                eprintln!("stub {i} decode error on daemon UPDATE: {error}");
                                reader_ctx.obs[i]
                                    .decode_errors
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        let mut wire = reader_ctx.obs[i].wire.lock().expect("wire state lock");
                        wire.updates += 1;
                        for entry in &parsed.withdrawn {
                            wire.v4.remove(&entry.prefix);
                            wire.withdrawn_nlri += 1;
                        }
                        for entry in &parsed.announced {
                            wire.v4.insert(entry.prefix);
                            wire.announced_nlri += 1;
                        }
                        for attribute in &parsed.attributes {
                            match attribute {
                                PathAttribute::MpReachNlri(mp) => {
                                    for entry in &mp.announced {
                                        match entry.prefix {
                                            Prefix::V4(p) => {
                                                wire.v4.insert(p);
                                            }
                                            Prefix::V6(p) => {
                                                wire.v6.insert(p);
                                            }
                                        }
                                        wire.announced_nlri += 1;
                                    }
                                }
                                PathAttribute::MpUnreachNlri(mp) => {
                                    for entry in &mp.withdrawn {
                                        match entry.prefix {
                                            Prefix::V4(p) => {
                                                wire.v4.remove(&p);
                                            }
                                            Prefix::V6(p) => {
                                                wire.v6.remove(&p);
                                            }
                                        }
                                        wire.withdrawn_nlri += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        record_link_drop(&reader_ctx, i);
    });

    Ok(tx)
}

/// The read side ended: the TCP session is gone. Counted, not merely flagged,
/// so a drop-and-reconnect inside one phase cannot hide behind a restored
/// `established` bit.
fn record_link_drop(ctx: &Arc<Ctx>, i: usize) {
    if ctx.obs[i].established.swap(false, Ordering::AcqRel) {
        ctx.obs[i].wire.lock().expect("wire state lock").link_drops += 1;
    }
}

/// Dial every stub and have the source announce its table. Called at cold
/// start and after each deliberate daemon restart.
async fn connect_fleet(ctx: &Arc<Ctx>) -> Result<Vec<mpsc::Sender<Message>>, String> {
    let mut senders = Vec::new();
    for i in 0..PEERS {
        ctx.obs[i].reset();
        senders.push(establish(Arc::clone(ctx), i).await?);
    }
    for msg in source_table() {
        senders[SOURCE]
            .send(msg)
            .await
            .map_err(|e| format!("source announce: {e}"))?;
    }
    Ok(senders)
}

// ---------------------------------------------------------------------------
// Daemon lifecycle. This receipt owns it: three of its five areas only exist
// across a restart.
// ---------------------------------------------------------------------------

struct Daemon {
    bin: PathBuf,
    config: PathBuf,
    out: PathBuf,
    generation: u32,
    child: Option<tokio::process::Child>,
    pid: u32,
}

impl Daemon {
    async fn start(&mut self) -> Result<u32, String> {
        self.generation += 1;
        let path = self.out.join(format!("daemon-{}.log", self.generation));
        let log = std::fs::File::create(&path).map_err(|e| format!("daemon log: {e}"))?;
        let errlog = log
            .try_clone()
            .map_err(|e| format!("daemon log dup: {e}"))?;
        let child = tokio::process::Command::new(&self.bin)
            .arg(&self.config)
            .env("RUST_LOG", "info")
            .stdout(log)
            .stderr(errlog)
            .spawn()
            .map_err(|e| format!("spawn daemon: {e}"))?;
        self.pid = child.id().ok_or("daemon reported no pid")?;
        self.child = Some(child);
        Ok(self.pid)
    }

    /// Ready means a real gRPC round trip answered, not merely that the socket
    /// exists.
    async fn wait_ready(&mut self, rbgp: &Rbgp) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < CONVERGE_TIMEOUT {
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!("daemon exited during startup: {status}"));
                }
            }
            if rbgp
                .try_run(&["global"])
                .await
                .is_ok_and(|(code, ..)| code == 0)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("daemon did not become ready".into())
    }

    async fn stop(&mut self, signal: i32) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        // SAFETY: `kill` with a valid signal number is safe; this harness owns
        // the pid and reaps the child immediately below.
        unsafe {
            libc::kill(
                i32::try_from(self.pid).map_err(|e| format!("pid: {e}"))?,
                signal,
            );
        }
        tokio::time::timeout(Duration::from_secs(30), child.wait())
            .await
            .map_err(|_| format!("daemon did not exit on signal {signal}"))?
            .map_err(|e| format!("wait daemon: {e}"))?;
        Ok(())
    }

    /// Stop and restart, waiting for a real gRPC round trip. Redialling the
    /// fleet is deliberately NOT part of this: the phase does it separately so
    /// a daemon that came back without a usable BGP listener is reported as a
    /// named failing check rather than aborting the run.
    async fn restart(&mut self, signal: i32, rbgp: &Rbgp) -> Result<u32, String> {
        self.stop(signal).await?;
        let pid = self.start().await?;
        self.wait_ready(rbgp).await?;
        Ok(pid)
    }

    /// This generation's daemon log, for the surfaces `rbgp` does not expose.
    fn log_text(&self) -> String {
        std::fs::read_to_string(self.out.join(format!("daemon-{}.log", self.generation)))
            .unwrap_or_default()
    }
}

/// Restart the daemon and redial, recording both the listener outcome and the
/// session recovery as checks. Returns the new pid.
///
/// A daemon whose BGP listener failed to bind keeps running and answers gRPC,
/// so the failure has to be asserted explicitly or it would surface only as an
/// unexplained connection refusal much later.
async fn restart_and_redial(
    checks: &mut Checks,
    args: &Args,
    daemon: &mut Daemon,
    ctx: &Arc<Ctx>,
    senders: &mut Vec<mpsc::Sender<Message>>,
    signal: i32,
    phase: &str,
) -> Result<u32, String> {
    let old_pid = daemon.pid;
    senders.clear();
    let pid = daemon.restart(signal, &args.rbgp).await?;
    checks.assert(
        &format!("{phase}.daemon_is_a_new_process"),
        pid != old_pid,
        format!("before={old_pid} after={pid}"),
    );
    let log = daemon.log_text();
    checks.assert(
        &format!("{phase}.bgp_listener_bound"),
        !log.contains("failed to bind BGP listener"),
        if log.contains("failed to bind BGP listener") {
            "the restarted daemon could not bind its BGP listen port".to_string()
        } else {
            "bound".to_string()
        },
    );
    match connect_fleet(ctx).await {
        Ok(dialled) => {
            *senders = dialled;
            let reconverged = wait_for(|| OBSERVERS.iter().all(|i| ctx.obs[*i].converged())).await;
            checks.assert(
                &format!("{phase}.sessions_and_wire_recovered"),
                reconverged.is_some(),
                format!("elapsed={reconverged:?}"),
            );
        }
        Err(error) => {
            checks.assert(
                &format!("{phase}.sessions_and_wire_recovered"),
                false,
                format!("redial failed: {error}"),
            );
        }
    }
    Ok(pid)
}

// ---------------------------------------------------------------------------
// Daemon observation: Prometheus scrape, `rbgp`, and small document readers.
// ---------------------------------------------------------------------------

async fn scrape(addr: SocketAddr) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("metrics connect: {e}"))?;
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("metrics request: {e}"))?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .map_err(|e| format!("metrics read: {e}"))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Sum of every Prometheus sample whose label set contains all of `labels`.
/// Summing rather than taking the first match is what makes the per-type
/// `bgp_messages_*_total` families usable as one per-peer total.
///
/// `None` means the series is absent, which this receipt makes load bearing:
/// a reaped-and-restarted metric series is a visible mutation.
fn sum_samples(scrape: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    let mut total = None;
    for line in scrape.lines() {
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        if !rest.starts_with('{') && !rest.starts_with(' ') {
            continue;
        }
        if !labels
            .iter()
            .all(|(key, value)| rest.contains(&format!("{key}=\"{value}\"")))
        {
            continue;
        }
        if let Some(value) = rest
            .rsplit(' ')
            .next()
            .and_then(|v| v.trim().parse::<f64>().ok())
        {
            total = Some(total.unwrap_or(0.0) + value);
        }
    }
    total
}

struct Rbgp {
    bin: PathBuf,
    addr: String,
}

impl Rbgp {
    /// Exit status plus both streams. `config plan` and `config diff` use
    /// terraform-style exits (2 = changes present), so a nonzero status is not
    /// automatically a failure.
    async fn try_run(&self, args: &[&str]) -> Result<(i32, String, String), String> {
        let out = tokio::process::Command::new(&self.bin)
            .arg("--addr")
            .arg(&self.addr)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("rbgp {args:?}: {e}"))?;
        Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    async fn run(&self, args: &[&str]) -> Result<String, String> {
        let (code, stdout, stderr) = self.try_run(args).await?;
        if code != 0 {
            return Err(format!("rbgp {args:?} exited {code}: {}", stderr.trim()));
        }
        Ok(stdout)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// First `"key": <digits>` value in a JSON document.
fn json_u64(doc: &str, key: &str) -> Option<u64> {
    let rest = doc.split(&format!("\"{key}\":")).nth(1)?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// First `"key": "<value>"` string in a JSON document.
fn json_str(doc: &str, key: &str) -> Option<String> {
    let rest = doc.split(&format!("\"{key}\":")).nth(1)?.trim_start();
    Some(rest.strip_prefix('"')?.split('"').next()?.to_string())
}

/// Every `"key": "<value>"` string in a JSON document, in document order.
fn json_all_strs(doc: &str, key: &str) -> Vec<String> {
    doc.split(&format!("\"{key}\":"))
        .skip(1)
        .filter_map(|rest| {
            let rest = rest.trim_start().strip_prefix('"')?;
            Some(rest.split('"').next()?.to_string())
        })
        .collect()
}

/// Every neighbor address in a config TOML document. Both the persisted file
/// and the daemon's effective-config dump put exactly one `address = "…"` key
/// on each `[[neighbors]]` entry, and nothing else in this receipt's config
/// uses that key.
fn toml_neighbor_addresses(toml_text: &str) -> BTreeSet<String> {
    toml_text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("address = \""))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_string)
        .collect()
}

/// The history entries the daemon retains, newest first, as
/// `(index, sha256)`.
fn history_entries(json: &str) -> Vec<(u64, String)> {
    let indexes: Vec<u64> = json
        .split("\"index\":")
        .skip(1)
        .filter_map(|rest| {
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            digits.parse().ok()
        })
        .collect();
    indexes
        .into_iter()
        .zip(json_all_strs(json, "sha256"))
        .collect()
}

/// Retained history entry files, oldest first. Entry names carry a
/// zero-padded monotonic sequence prefix, so lexical order is age order.
fn history_files(args: &Args) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = args
        .state_dir
        .join("config-history")
        .read_dir()
        .map_err(|e| format!("read history dir: {e}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    Ok(files)
}

fn newest_history_document(args: &Args) -> Result<String, String> {
    let files = history_files(args)?;
    let newest = files.last().ok_or("config history is empty")?;
    std::fs::read_to_string(newest).map_err(|e| format!("read history entry: {e}"))
}

// ---------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------

struct Checks {
    rows: Vec<(String, bool, String)>,
}

impl Checks {
    fn assert(&mut self, name: &str, pass: bool, detail: String) {
        println!(
            "CHECK {name} {} {detail}",
            if pass { "PASS" } else { "FAIL" }
        );
        self.rows.push((name.to_string(), pass, detail));
    }

    fn eq<T: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        let pass = got == want;
        self.assert(name, pass, format!("got={got:?} want={want:?}"));
    }

    /// A cumulative counter must never go backwards. A reaped-and-restarted
    /// metric series is a visible mutation even when the value looks similar,
    /// so "did not rebase" is asserted as `after >= before`, not `after != 0`.
    fn monotonic(&mut self, name: &str, before: Option<f64>, after: Option<f64>) {
        let pass = matches!((before, after), (Some(b), Some(a)) if a >= b);
        self.assert(name, pass, format!("before={before:?} after={after:?}"));
    }

    fn failed(&self) -> usize {
        self.rows.iter().filter(|(_, pass, _)| !pass).count()
    }
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

struct Args {
    daemon_bin: PathBuf,
    rbgp: Rbgp,
    config: PathBuf,
    state_dir: PathBuf,
    port: u16,
    metrics: SocketAddr,
    out: PathBuf,
}

impl Args {
    fn config_dir(&self) -> &Path {
        self.config.parent().expect("config path has a parent")
    }

    fn staged_temp(&self) -> PathBuf {
        let mut path = self.config.clone().into_os_string();
        path.push(".tmp");
        PathBuf::from(path)
    }

    fn unconfirmed_backup(&self) -> PathBuf {
        let mut path = self.config.clone().into_os_string();
        path.push(".unconfirmed");
        PathBuf::from(path)
    }

    fn journal(&self) -> PathBuf {
        self.state_dir.join("commit-confirm-journal.json")
    }

    fn config_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.config).unwrap_or_default()
    }

    fn config_text(&self) -> String {
        String::from_utf8_lossy(&self.config_bytes()).into_owned()
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: configpersist <daemon_bin> <rbgp_bin> <config_path> <state_dir> \
         <bgp_port> <metrics_addr> <out_dir>"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.len() != 7 {
        usage();
    }
    let state_dir = PathBuf::from(&argv[3]);
    Args {
        daemon_bin: PathBuf::from(&argv[0]),
        rbgp: Rbgp {
            bin: PathBuf::from(&argv[1]),
            addr: format!("unix://{}", state_dir.join("grpc.sock").display()),
        },
        config: PathBuf::from(&argv[2]),
        state_dir,
        port: argv[4].parse().unwrap_or_else(|_| usage()),
        metrics: argv[5].parse().unwrap_or_else(|_| usage()),
        out: PathBuf::from(&argv[6]),
    }
}

/// Poll `predicate` up to [`CONVERGE_TIMEOUT`]. `None` means it never held. A
/// timeout is a normal, reportable outcome for a phase gate — the run keeps
/// collecting evidence so one failure does not hide the rest of the picture.
async fn wait_for<F>(mut predicate: F) -> Option<Duration>
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < CONVERGE_TIMEOUT {
        if predicate() {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Take write permission away from the config *directory* so the daemon's
/// staging write fails with `EACCES` — the persistence failure an operator
/// actually hits on a read-only or root-owned config mount. Probing with a
/// real write is the honest check: the whole premise is that writing fails, so
/// ask the filesystem rather than guessing from the effective uid.
fn seal_config_dir(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    if std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).is_err() {
        return false;
    }
    let probe = dir.join("write-probe");
    if std::fs::write(&probe, b"probe").is_ok() {
        std::fs::remove_file(&probe).ok();
        unseal_config_dir(dir);
        return false;
    }
    true
}

fn unseal_config_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("unseal config dir");
}

/// The three-way agreement this receipt closes after every successful
/// mutation: the persisted file, the daemon's runtime snapshot, and the
/// newest history record.
///
/// Disk-to-history is byte level once the daemon itself has written the file:
/// the persister serializes one string and uses it for both, so the retained
/// entry's embedded digest must be the digest of the file.
///
/// `byte_exact` is false only at boot, before any daemon write. The boot entry
/// is deliberately the serialized *runtime* snapshot rather than a re-read of
/// the operator's file — re-reading would race an edit made between startup
/// validation and the persister task starting — so at boot the two documents
/// are semantically equal but not byte-equal, and that weaker contract is what
/// gets asserted.
///
/// Disk-to-runtime is semantic in every phase: the effective dump is
/// canonicalized and secret-redacted, so it legitimately reformats.
async fn assert_agreement(
    checks: &mut Checks,
    args: &Args,
    phase: &str,
    byte_exact: bool,
) -> Result<(), String> {
    let bytes = args.config_bytes();
    let disk_hash = sha256_hex(&bytes);
    let history = args.rbgp.run(&["-j", "config", "history"]).await?;
    std::fs::write(args.out.join(format!("history-{phase}.json")), &history)
        .map_err(|e| format!("write history: {e}"))?;
    let entries = history_entries(&history);
    if byte_exact {
        checks.assert(
            &format!("agree.{phase}.history_entry0_sha256_equals_disk"),
            entries
                .first()
                .is_some_and(|(index, hash)| *index == 0 && *hash == disk_hash),
            format!("disk={disk_hash} newest={:?}", entries.first()),
        );
    } else {
        let newest = newest_history_document(args)?;
        checks.eq(
            &format!("agree.{phase}.history_entry0_neighbors_equal_disk"),
            toml_neighbor_addresses(&newest),
            toml_neighbor_addresses(&args.config_text()),
        );
    }

    let effective = args.rbgp.run(&["config", "effective"]).await?;
    std::fs::write(args.out.join(format!("effective-{phase}.toml")), &effective)
        .map_err(|e| format!("write effective: {e}"))?;
    let disk_neighbors = toml_neighbor_addresses(&args.config_text());
    let runtime_neighbors = toml_neighbor_addresses(&effective);
    checks.assert(
        &format!("agree.{phase}.runtime_neighbors_equal_disk"),
        disk_neighbors == runtime_neighbors,
        format!("disk={disk_neighbors:?} runtime={runtime_neighbors:?}"),
    );

    let check = tokio::process::Command::new(&args.daemon_bin)
        .arg("--check")
        .arg(&args.config)
        .output()
        .await
        .map_err(|e| format!("rustbgpd --check: {e}"))?;
    checks.assert(
        &format!("agree.{phase}.persisted_file_validates"),
        check.status.success(),
        format!(
            "exit={:?} stderr={}",
            check.status.code(),
            String::from_utf8_lossy(&check.stderr).trim()
        ),
    );
    Ok(())
}

/// Apply `candidate` as a commit-confirmed transaction. Returns the plan's
/// runtime snapshot token and the apply output.
async fn commit_confirmed(
    args: &Args,
    candidate: &Path,
    confirm_id: &str,
    timeout_seconds: u32,
) -> Result<String, String> {
    let candidate = candidate.to_string_lossy().into_owned();
    // `config plan` uses terraform-style exits: 2 means "changes present".
    let (code, plan, stderr) = args
        .rbgp
        .try_run(&["-j", "config", "plan", &candidate])
        .await?;
    if code != 2 {
        return Err(format!(
            "config plan exited {code} (want 2): {}",
            stderr.trim()
        ));
    }
    let token = json_str(&plan, "runtime_snapshot_token")
        .ok_or_else(|| format!("plan carried no runtime_snapshot_token: {plan}"))?;
    let timeout = timeout_seconds.to_string();
    args.rbgp
        .run(&[
            "-j",
            "config",
            "apply",
            &candidate,
            "--expected-runtime-snapshot-token",
            &token,
            "--confirm-id",
            confirm_id,
            "--confirm-timeout",
            &timeout,
        ])
        .await
}

/// Write `<config file> + one more neighbor` as a transaction candidate.
fn write_candidate(args: &Args, name: &str, address: &str, asn: u32) -> Result<PathBuf, String> {
    let path = args.out.join(format!("candidate-{name}.toml"));
    let body = format!(
        "{}\n[[neighbors]]\naddress = \"{address}\"\nremote_asn = {asn}\nhold_time = 180\n",
        args.config_text().trim_end()
    );
    std::fs::write(&path, body).map_err(|e| format!("write candidate: {e}"))?;
    Ok(path)
}

async fn add_neighbor(
    args: &Args,
    address: &str,
    asn: u32,
) -> Result<(i32, String, String), String> {
    let asn = asn.to_string();
    args.rbgp
        .try_run(&["neighbor", address, "add", "--remote-asn", &asn])
        .await
}

/// Addresses the running daemon reports as configured peers.
async fn runtime_peers(args: &Args) -> Result<BTreeSet<String>, String> {
    let json = args.rbgp.run(&["-j", "neighbor"]).await?;
    Ok(json_all_strs(&json, "address").into_iter().collect())
}

// ---------------------------------------------------------------------------
// Phases.
// ---------------------------------------------------------------------------

/// Area 1: a persisted mutation lands on disk, in the runtime, and in history,
/// and survives a clean restart.
async fn phase_persist_and_restart(
    checks: &mut Checks,
    args: &Args,
    daemon: &mut Daemon,
    ctx: &Arc<Ctx>,
    senders: &mut Vec<mpsc::Sender<Message>>,
) -> Result<(), String> {
    let before = args.config_text();
    let history_before = history_entries(&args.rbgp.run(&["-j", "config", "history"]).await?).len();

    let (code, _, stderr) = add_neighbor(args, ADD_RESTART, 64711).await?;
    checks.assert(
        "persist.add_accepted",
        code == 0,
        format!("exit={code} stderr={}", stderr.trim()),
    );

    let after = args.config_text();
    checks.assert(
        "persist.file_holds_the_neighbor",
        after.contains(ADD_RESTART) && !before.contains(ADD_RESTART),
        format!(
            "before_had={} after_has={}",
            before.contains(ADD_RESTART),
            after.contains(ADD_RESTART)
        ),
    );
    checks.assert(
        "persist.runtime_holds_the_neighbor",
        runtime_peers(args).await?.contains(ADD_RESTART),
        format!("peers={:?}", runtime_peers(args).await?),
    );
    let history_after = history_entries(&args.rbgp.run(&["-j", "config", "history"]).await?).len();
    checks.eq(
        "persist.history_grew_by_one",
        history_after,
        history_before + 1,
    );
    checks.assert(
        "persist.no_staged_temp_file_left",
        !args.staged_temp().exists(),
        format!("exists={}", args.staged_temp().exists()),
    );
    assert_agreement(checks, args, "persist", true).await?;

    let persisted = args.config_bytes();
    restart_and_redial(checks, args, daemon, ctx, senders, libc::SIGTERM, "restart").await?;
    checks.assert(
        "restart.config_bytes_unchanged_by_the_restart",
        args.config_bytes() == persisted,
        format!("sha256={}", sha256_hex(&args.config_bytes())),
    );
    checks.assert(
        "restart.runtime_still_holds_the_neighbor",
        runtime_peers(args).await?.contains(ADD_RESTART),
        format!("peers={:?}", runtime_peers(args).await?),
    );
    assert_agreement(checks, args, "restart", true).await?;
    Ok(())
}

/// Area 2: history records each applied generation, and `config rollback`
/// restores a prior one in the runtime as well as on disk.
async fn phase_history_and_rollback(
    checks: &mut Checks,
    args: &Args,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    let history = args.rbgp.run(&["-j", "config", "history"]).await?;
    let entries = history_entries(&history);
    checks.assert(
        "history.indexes_are_dense_and_newest_first",
        !entries.is_empty()
            && entries
                .iter()
                .enumerate()
                .all(|(position, (index, _))| u64::try_from(position) == Ok(*index)),
        format!(
            "count={} indexes={:?}",
            entries.len(),
            entries.iter().map(|(i, _)| *i).collect::<Vec<_>>()
        ),
    );
    checks.assert(
        "history.entries_have_distinct_digests",
        entries
            .iter()
            .map(|(_, hash)| hash)
            .collect::<BTreeSet<_>>()
            .len()
            == entries.len(),
        format!("count={}", entries.len()),
    );

    let (code, _, stderr) = add_neighbor(args, ADD_ROLLED_BACK, 64712).await?;
    checks.assert(
        "rollback.second_add_accepted",
        code == 0,
        format!("exit={code} stderr={}", stderr.trim()),
    );
    assert_agreement(checks, args, "rollback-precondition", true).await?;

    // The newest retained entry is the config this add just wrote; the one
    // before it is the generation `rollback 1` must restore.
    let files = history_files(args)?;
    let target_text = newest_history_document(args)?;
    checks.assert(
        "rollback.newest_history_entry_is_the_file_on_disk",
        target_text.as_bytes() == args.config_bytes(),
        format!("entry_sha256={}", sha256_hex(target_text.as_bytes())),
    );

    let subject_wire_before = ctx.obs[SUBJECT].identity();
    let restored_from = files
        .iter()
        .rev()
        .nth(1)
        .ok_or("history holds no previous generation to roll back to")?;
    let restored_text =
        std::fs::read_to_string(restored_from).map_err(|e| format!("read entry: {e}"))?;

    let (code, _, stderr) = args.rbgp.try_run(&["config", "rollback", "1"]).await?;
    checks.assert(
        "rollback.accepted",
        code == 0,
        format!("exit={code} stderr={}", stderr.trim()),
    );

    let disk = args.config_text();
    checks.assert(
        "rollback.disk_dropped_the_rolled_back_neighbor",
        !disk.contains(ADD_ROLLED_BACK),
        format!("present={}", disk.contains(ADD_ROLLED_BACK)),
    );
    checks.assert(
        "rollback.disk_kept_the_earlier_neighbor",
        disk.contains(ADD_REFUSED),
        format!("present={}", disk.contains(ADD_REFUSED)),
    );
    checks.eq(
        "rollback.disk_neighbors_equal_the_restored_generation",
        toml_neighbor_addresses(&disk),
        toml_neighbor_addresses(&restored_text),
    );
    let peers = runtime_peers(args).await?;
    checks.assert(
        "rollback.runtime_dropped_the_rolled_back_neighbor",
        !peers.contains(ADD_ROLLED_BACK),
        format!("peers={peers:?}"),
    );
    checks.assert(
        "rollback.runtime_kept_the_earlier_neighbor",
        peers.contains(ADD_REFUSED),
        format!("peers={peers:?}"),
    );

    tokio::time::sleep(SETTLE).await;
    let subject_wire_after = ctx.obs[SUBJECT].identity();
    checks.eq(
        "rollback.unrelated_session_not_reset",
        (
            subject_wire_after.link_drops,
            subject_wire_after.notifications,
            subject_wire_after.established,
        ),
        (
            subject_wire_before.link_drops,
            subject_wire_before.notifications,
            true,
        ),
    );
    assert_agreement(checks, args, "rollback", true).await?;
    Ok(())
}

/// Area 3a: a confirmed commit-confirm transaction becomes permanent and
/// consumes its revert journal.
async fn phase_commit_confirm_success(checks: &mut Checks, args: &Args) -> Result<(), String> {
    let candidate = write_candidate(args, "confirmed", ADD_CONFIRMED, 64713)?;
    let apply = commit_confirmed(args, &candidate, "receipt-confirmed", 300).await?;
    checks.eq(
        "confirm.apply_reports_pending",
        json_str(&apply, "status").as_deref(),
        Some("pending"),
    );
    checks.assert(
        "confirm.revert_journal_written",
        args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    checks.assert(
        "confirm.disk_holds_the_candidate_inside_the_window",
        args.config_text().contains(ADD_CONFIRMED),
        format!("present={}", args.config_text().contains(ADD_CONFIRMED)),
    );

    let (code, _, stderr) = args
        .rbgp
        .try_run(&["config", "confirm", "receipt-confirmed"])
        .await?;
    checks.assert(
        "confirm.confirm_accepted",
        code == 0,
        format!("exit={code} stderr={}", stderr.trim()),
    );
    checks.assert(
        "confirm.revert_journal_consumed",
        !args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    let status = args.rbgp.run(&["-j", "config", "status"]).await?;
    checks.assert(
        "confirm.no_pending_confirmation_remains",
        !matches!(json_str(&status, "status").as_deref(), Some("pending")),
        format!("status={:?}", json_str(&status, "status")),
    );
    checks.assert(
        "confirm.disk_holds_the_candidate_after_confirming",
        args.config_text().contains(ADD_CONFIRMED),
        format!("present={}", args.config_text().contains(ADD_CONFIRMED)),
    );
    checks.assert(
        "confirm.runtime_holds_the_candidate",
        runtime_peers(args).await?.contains(ADD_CONFIRMED),
        format!("peers={:?}", runtime_peers(args).await?),
    );
    assert_agreement(checks, args, "confirm", true).await?;
    Ok(())
}

/// Area 3b: an unconfirmed transaction auto-reverts on its own deadline.
async fn phase_commit_confirm_timeout(
    checks: &mut Checks,
    args: &Args,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    let pre_commit = args.config_bytes();
    let subject_before = ctx.obs[SUBJECT].identity();
    let candidate = write_candidate(args, "timeout", ADD_TIMED_OUT, 64714)?;
    let apply =
        commit_confirmed(args, &candidate, "receipt-timeout", TIMEOUT_CONFIRM_SECONDS).await?;
    checks.eq(
        "timeout.apply_reports_pending",
        json_str(&apply, "status").as_deref(),
        Some("pending"),
    );
    checks.assert(
        "timeout.revert_journal_written",
        args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    checks.assert(
        "timeout.disk_holds_the_candidate_inside_the_window",
        args.config_text().contains(ADD_TIMED_OUT),
        format!("present={}", args.config_text().contains(ADD_TIMED_OUT)),
    );

    // Wait past the deadline rather than sleeping exactly to it.
    let reverted = wait_for(|| !args.config_text().contains(ADD_TIMED_OUT)).await;
    checks.assert(
        "timeout.disk_auto_reverted",
        reverted.is_some(),
        format!("elapsed={reverted:?} window={TIMEOUT_CONFIRM_SECONDS}s"),
    );
    let status = args.rbgp.run(&["-j", "config", "status"]).await?;
    checks.eq(
        "timeout.status_reports_auto_reverted",
        json_str(&status, "status").as_deref(),
        Some("auto_reverted"),
    );
    checks.assert(
        "timeout.revert_journal_consumed",
        !args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    checks.assert(
        "timeout.runtime_reverted",
        !runtime_peers(args).await?.contains(ADD_TIMED_OUT),
        format!("peers={:?}", runtime_peers(args).await?),
    );
    checks.eq(
        "timeout.disk_neighbors_equal_the_pre_commit_generation",
        toml_neighbor_addresses(&args.config_text()),
        toml_neighbor_addresses(&String::from_utf8_lossy(&pre_commit)),
    );
    let subject_after = ctx.obs[SUBJECT].identity();
    checks.eq(
        "timeout.unrelated_session_not_reset",
        (
            subject_after.link_drops,
            subject_after.notifications,
            subject_after.established,
        ),
        (
            subject_before.link_drops,
            subject_before.notifications,
            true,
        ),
    );
    Ok(())
}

/// Area 3c: a daemon SIGKILLed inside the confirmation window comes back in a
/// defined state — the pre-transaction config restored, the unconfirmed
/// candidate preserved for the operator, and the revert intent consumed.
async fn phase_commit_confirm_restart(
    checks: &mut Checks,
    args: &Args,
    daemon: &mut Daemon,
    ctx: &Arc<Ctx>,
    senders: &mut Vec<mpsc::Sender<Message>>,
) -> Result<(), String> {
    let pre_commit = args.config_bytes();
    let candidate = write_candidate(args, "killed", ADD_KILLED, 64715)?;
    let apply =
        commit_confirmed(args, &candidate, "receipt-killed", RESTART_CONFIRM_SECONDS).await?;
    checks.eq(
        "restartwindow.apply_reports_pending",
        json_str(&apply, "status").as_deref(),
        Some("pending"),
    );
    checks.assert(
        "restartwindow.revert_journal_written_before_the_kill",
        args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    checks.assert(
        "restartwindow.disk_held_the_candidate_before_the_kill",
        args.config_text().contains(ADD_KILLED),
        format!("present={}", args.config_text().contains(ADD_KILLED)),
    );

    restart_and_redial(
        checks,
        args,
        daemon,
        ctx,
        senders,
        libc::SIGKILL,
        "restartwindow",
    )
    .await?;
    checks.assert(
        "restartwindow.revert_journal_consumed_by_boot",
        !args.journal().exists(),
        format!("exists={}", args.journal().exists()),
    );
    let backup = args.unconfirmed_backup();
    let backup_text = std::fs::read_to_string(&backup).unwrap_or_default();
    checks.assert(
        "restartwindow.unconfirmed_candidate_saved_aside",
        backup.exists() && backup_text.contains(ADD_KILLED),
        format!(
            "exists={} holds_candidate={}",
            backup.exists(),
            backup_text.contains(ADD_KILLED)
        ),
    );
    checks.assert(
        "restartwindow.disk_reverted_to_the_pre_commit_config",
        !args.config_text().contains(ADD_KILLED),
        format!("present={}", args.config_text().contains(ADD_KILLED)),
    );
    checks.eq(
        "restartwindow.disk_neighbors_equal_the_pre_commit_generation",
        toml_neighbor_addresses(&args.config_text()),
        toml_neighbor_addresses(&String::from_utf8_lossy(&pre_commit)),
    );
    checks.assert(
        "restartwindow.runtime_reverted_to_the_pre_commit_config",
        !runtime_peers(args).await?.contains(ADD_KILLED),
        format!("peers={:?}", runtime_peers(args).await?),
    );
    let status = args.rbgp.run(&["-j", "config", "status"]).await?;
    checks.assert(
        "restartwindow.no_pending_confirmation_after_boot",
        !matches!(json_str(&status, "status").as_deref(), Some("pending")),
        format!("status={:?}", json_str(&status, "status")),
    );
    let check = tokio::process::Command::new(&args.daemon_bin)
        .arg("--check")
        .arg(&args.config)
        .output()
        .await
        .map_err(|e| format!("rustbgpd --check: {e}"))?;
    checks.assert(
        "restartwindow.recovered_config_is_not_torn",
        check.status.success(),
        format!("exit={:?}", check.status.code()),
    );
    Ok(())
}

/// Area 4: an injected persistence failure leaves runtime config, session
/// identity, flap state, cumulative counters, and wire state UNCHANGED.
///
/// Not restored — unchanged. A rebuilt session reports a new identity, a
/// zeroed uptime, zeroed counters, and a fresh metric series, so every
/// assertion here is one a compensating implementation would fail.
#[allow(clippy::too_many_lines)]
async fn phase_rejected_mutation(
    checks: &mut Checks,
    args: &Args,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    let subject = peer_addr(SUBJECT).to_string();
    let bystander = peer_addr(BYSTANDER).to_string();

    // Let the sessions accumulate an age and a message history first: an
    // untouched session and a rebuilt one are indistinguishable at uptime 0.
    tokio::time::sleep(SETTLE).await;

    let before_json = args.rbgp.run(&["-j", "neighbor", &subject]).await?;
    std::fs::write(args.out.join("subject-before.json"), &before_json)
        .map_err(|e| format!("write subject json: {e}"))?;
    let before_metrics = scrape(args.metrics).await?;
    std::fs::write(
        args.out.join("metrics-before-rejection.prom"),
        &before_metrics,
    )
    .map_err(|e| format!("write metrics: {e}"))?;
    let config_before = args.config_bytes();
    let history_before = history_entries(&args.rbgp.run(&["-j", "config", "history"]).await?).len();
    let subject_wire_before = ctx.obs[SUBJECT].identity();
    let bystander_wire_before = ctx.obs[BYSTANDER].identity();
    let peers_before = runtime_peers(args).await?;

    // Non-vacuity: at uptime 0 with no messages exchanged, an untouched
    // session and a freshly rebuilt one are indistinguishable, and every
    // assertion below would hold for both.
    checks.assert(
        "reject.subject_carries_counters_a_rebuild_could_not_reproduce",
        json_u64(&before_json, "uptime_seconds").unwrap_or(0) > 0
            && json_u64(&before_json, "messages_received").unwrap_or(0) > 0
            && json_u64(&before_json, "messages_sent").unwrap_or(0) > 0
            && json_u64(&before_json, "updates_sent").unwrap_or(0) > 0,
        format!(
            "uptime_seconds={:?} messages_received={:?} messages_sent={:?} updates_sent={:?}",
            json_u64(&before_json, "uptime_seconds"),
            json_u64(&before_json, "messages_received"),
            json_u64(&before_json, "messages_sent"),
            json_u64(&before_json, "updates_sent"),
        ),
    );

    let sealed = seal_config_dir(args.config_dir());
    checks.assert(
        "reject.config_directory_seal_binds",
        sealed,
        format!("dir_mode=0o500 writes_fail={sealed}"),
    );
    if !sealed {
        return Ok(());
    }

    let (delete_code, _, delete_err) = args.rbgp.try_run(&["neighbor", &subject, "delete"]).await?;
    let (add_code, _, add_err) = add_neighbor(args, ADD_REFUSED, 64716).await?;
    // The rejected mutations get the same settle window a successful one would
    // have used, so a delayed teardown cannot slip past the snapshot below.
    tokio::time::sleep(SETTLE).await;

    let after_json = args.rbgp.run(&["-j", "neighbor", &subject]).await?;
    std::fs::write(args.out.join("subject-after.json"), &after_json)
        .map_err(|e| format!("write subject json: {e}"))?;
    let after_metrics = scrape(args.metrics).await?;
    std::fs::write(
        args.out.join("metrics-after-rejection.prom"),
        &after_metrics,
    )
    .map_err(|e| format!("write metrics: {e}"))?;
    let config_after = args.config_bytes();
    let staged_left = args.staged_temp().exists();
    let subject_wire_after = ctx.obs[SUBJECT].identity();
    let bystander_wire_after = ctx.obs[BYSTANDER].identity();
    let peers_after = runtime_peers(args).await?;
    let history_after = history_entries(&args.rbgp.run(&["-j", "config", "history"]).await?).len();

    unseal_config_dir(args.config_dir());

    checks.assert(
        "reject.delete_refused_with_failed_precondition",
        delete_code != 0 && delete_err.contains("config persistence failed"),
        format!("exit={delete_code} stderr={}", delete_err.trim()),
    );
    checks.assert(
        "reject.add_refused_with_failed_precondition",
        add_code != 0 && add_err.contains("config persistence failed"),
        format!("exit={add_code} stderr={}", add_err.trim()),
    );

    // --- runtime config -----------------------------------------------------
    checks.eq(
        "reject.runtime_peer_set_unchanged",
        peers_after.clone(),
        peers_before,
    );
    checks.assert(
        "reject.refused_add_created_no_peer",
        !peers_after.contains(ADD_REFUSED),
        format!("peers={peers_after:?}"),
    );

    // --- session identity ---------------------------------------------------
    for field in ["address", "state"] {
        checks.eq(
            &format!("reject.session_{field}_unchanged"),
            json_str(&after_json, field),
            json_str(&before_json, field),
        );
    }
    checks.eq(
        "reject.session_remote_asn_unchanged",
        json_u64(&after_json, "remote_asn"),
        json_u64(&before_json, "remote_asn"),
    );
    checks.eq(
        "reject.session_still_established",
        json_str(&after_json, "state").as_deref(),
        Some("Established"),
    );

    // --- flap state ---------------------------------------------------------
    checks.eq(
        "reject.flap_count_unchanged",
        json_u64(&after_json, "flap_count"),
        json_u64(&before_json, "flap_count"),
    );
    checks.eq(
        "reject.notifications_sent_unchanged",
        json_u64(&after_json, "notifications_sent"),
        json_u64(&before_json, "notifications_sent"),
    );

    // --- cumulative counters: not rebased -----------------------------------
    // A rebuilt session restarts every one of these at zero, and a torn-down
    // uptime restarts below the value it had.
    for field in [
        "uptime_seconds",
        "updates_sent",
        "messages_received",
        "messages_sent",
    ] {
        let before = json_u64(&before_json, field);
        let after = json_u64(&after_json, field);
        checks.assert(
            &format!("reject.{field}_did_not_rebase"),
            matches!((before, after), (Some(b), Some(a)) if a >= b),
            format!("before={before:?} after={after:?}"),
        );
    }

    // --- metric series: not reaped and restarted ----------------------------
    let peer = [("peer", subject.as_str())];
    checks.monotonic(
        "reject.metric_messages_received_total_did_not_rebase",
        sum_samples(&before_metrics, "bgp_messages_received_total", &peer),
        sum_samples(&after_metrics, "bgp_messages_received_total", &peer),
    );
    checks.monotonic(
        "reject.metric_messages_sent_total_did_not_rebase",
        sum_samples(&before_metrics, "bgp_messages_sent_total", &peer),
        sum_samples(&after_metrics, "bgp_messages_sent_total", &peer),
    );
    checks.eq(
        "reject.metric_session_established_total_unchanged",
        sum_samples(&after_metrics, "bgp_session_established_total", &peer),
        sum_samples(&before_metrics, "bgp_session_established_total", &peer),
    );
    checks.eq(
        "reject.metric_session_flaps_total_unchanged",
        sum_samples(&after_metrics, "bgp_session_flaps_total", &peer),
        sum_samples(&before_metrics, "bgp_session_flaps_total", &peer),
    );
    checks.eq(
        "reject.metric_state_transitions_unchanged",
        sum_samples(&after_metrics, "bgp_session_state_transitions_total", &peer),
        sum_samples(
            &before_metrics,
            "bgp_session_state_transitions_total",
            &peer,
        ),
    );
    let bystander_peer = [("peer", bystander.as_str())];
    checks.eq(
        "reject.bystander_metric_session_established_total_unchanged",
        sum_samples(
            &after_metrics,
            "bgp_session_established_total",
            &bystander_peer,
        ),
        sum_samples(
            &before_metrics,
            "bgp_session_established_total",
            &bystander_peer,
        ),
    );

    // --- wire state ---------------------------------------------------------
    checks.eq(
        "reject.subject_wire_state_unchanged",
        subject_wire_after,
        subject_wire_before,
    );
    checks.eq(
        "reject.bystander_wire_state_unchanged",
        bystander_wire_after,
        bystander_wire_before,
    );

    // --- disk ---------------------------------------------------------------
    checks.assert(
        "reject.config_bytes_unchanged",
        config_after == config_before,
        format!(
            "before={} after={}",
            sha256_hex(&config_before),
            sha256_hex(&config_after)
        ),
    );
    checks.assert(
        "reject.no_staged_temp_file_left",
        !staged_left,
        format!("exists={staged_left}"),
    );
    checks.eq("reject.history_did_not_grow", history_after, history_before);

    // --- the daemon is not wedged ------------------------------------------
    let (code, _, stderr) = add_neighbor(args, ADD_REFUSED, 64716).await?;
    checks.assert(
        "reject.mutations_succeed_again_once_writable",
        code == 0,
        format!("exit={code} stderr={}", stderr.trim()),
    );
    checks.assert(
        "reject.recovery_mutation_landed_on_disk",
        args.config_text().contains(ADD_REFUSED),
        format!("present={}", args.config_text().contains(ADD_REFUSED)),
    );
    assert_agreement(checks, args, "post-rejection", true).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    let args = parse_args();
    let mut checks = Checks { rows: Vec::new() };

    let ctx = Arc::new(Ctx {
        daemon: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port),
        obs: (0..PEERS).map(|_| Obs::new()).collect(),
    });
    let mut daemon = Daemon {
        bin: args.daemon_bin.clone(),
        config: args.config.clone(),
        out: args.out.clone(),
        generation: 0,
        child: None,
        pid: 0,
    };

    let result = run(&args, &mut checks, &mut daemon, &ctx).await;
    // Never leave the config directory sealed, whatever went wrong.
    unseal_config_dir(args.config_dir());
    let _ = daemon.stop(libc::SIGTERM).await;

    let failed = checks.failed();
    let summary = format!(
        "{{\n  \"checks\": {},\n  \"failed\": {},\n  \"rows\": [\n{}\n  ]\n}}\n",
        checks.rows.len(),
        failed,
        checks
            .rows
            .iter()
            .map(|(name, pass, detail)| format!(
                "    {{\"check\": \"{name}\", \"pass\": {pass}, \"detail\": {}}}",
                json_quote(detail)
            ))
            .collect::<Vec<_>>()
            .join(",\n"),
    );
    if let Err(error) = std::fs::write(args.out.join("summary.json"), summary) {
        eprintln!("failed to write summary.json: {error}");
    }

    if let Err(error) = result {
        eprintln!("RUN FAILED: {error}");
        println!("SUMMARY checks={} failed={failed}", checks.rows.len());
        return ExitCode::from(2);
    }
    println!("SUMMARY checks={} failed={failed}", checks.rows.len());
    if failed > 0 {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn json_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn run(
    args: &Args,
    checks: &mut Checks,
    daemon: &mut Daemon,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    daemon.start().await?;
    daemon.wait_ready(&args.rbgp).await?;
    let mut senders = connect_fleet(ctx).await?;

    let converged = wait_for(|| OBSERVERS.iter().all(|i| ctx.obs[*i].converged()))
        .await
        .ok_or("cold convergence never held")?;
    checks.assert(
        "baseline.sessions_established",
        (0..PEERS).all(|i| ctx.obs[i].established.load(Ordering::Acquire)),
        format!("peers={PEERS} elapsed={converged:?}"),
    );
    checks.assert(
        "baseline.wire_converged",
        OBSERVERS.iter().all(|i| ctx.obs[*i].converged()),
        format!("v4={V4_ROUTES} v6={V6_ROUTES} elapsed={converged:?}"),
    );
    let boot_history = history_entries(&args.rbgp.run(&["-j", "config", "history"]).await?);
    checks.assert(
        "baseline.boot_config_recorded_in_history",
        !boot_history.is_empty(),
        format!("entries={}", boot_history.len()),
    );
    assert_agreement(checks, args, "baseline", false).await?;

    // Phase order is deliberate: everything that needs the original, never
    // interrupted sessions runs before the first restart, so a restart-path
    // failure cannot silently weaken the rejected-mutation evidence.
    phase_rejected_mutation(checks, args, ctx).await?;
    phase_history_and_rollback(checks, args, ctx).await?;
    phase_commit_confirm_success(checks, args).await?;
    phase_commit_confirm_timeout(checks, args, ctx).await?;
    phase_persist_and_restart(checks, args, daemon, ctx, &mut senders).await?;
    phase_commit_confirm_restart(checks, args, daemon, ctx, &mut senders).await?;

    let decode_errors: u64 = (0..PEERS)
        .map(|i| ctx.obs[i].decode_errors.load(Ordering::Acquire))
        .sum();
    checks.eq("wire.stub_decode_errors", decode_errors, 0);

    let mut per_peer = BTreeMap::new();
    for i in 0..PEERS {
        per_peer.insert(
            peer_addr(i).to_string(),
            format!("{:?}", ctx.obs[i].identity()),
        );
    }
    std::fs::write(
        args.out.join("wire-final.txt"),
        per_peer
            .iter()
            .map(|(peer, state)| format!("{peer} {state}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .map_err(|e| format!("write wire state: {e}"))?;
    drop(senders);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_readers_pull_the_first_match() {
        let doc = r#"{
  "address": "127.9.2.2",
  "state": "Established",
  "uptime_seconds": 42,
  "flap_count": 0
}"#;
        assert_eq!(json_str(doc, "address").as_deref(), Some("127.9.2.2"));
        assert_eq!(json_str(doc, "state").as_deref(), Some("Established"));
        assert_eq!(json_u64(doc, "uptime_seconds"), Some(42));
        assert_eq!(json_u64(doc, "flap_count"), Some(0));
        assert_eq!(json_u64(doc, "absent"), None);
    }

    #[test]
    fn json_all_strs_collects_every_occurrence_in_order() {
        let doc = r#"[{"address": "10.0.0.1"}, {"address":"10.0.0.2"}]"#;
        assert_eq!(
            json_all_strs(doc, "address"),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
    }

    #[test]
    fn history_entries_pair_indexes_with_digests() {
        let doc = r#"{"entries": [
  {"index": 0, "timestamp_unix_seconds": 1, "sha256": "aa"},
  {"index": 1, "timestamp_unix_seconds": 2, "sha256": "bb"}
]}"#;
        assert_eq!(
            history_entries(doc),
            vec![(0, "aa".to_string()), (1, "bb".to_string())]
        );
    }

    #[test]
    fn toml_neighbor_addresses_ignores_other_keys() {
        let doc = r#"
[global]
router_id = "10.0.0.1"

[global.telemetry]
prometheus_addr = "127.0.0.1:19189"

[[neighbors]]
address = "127.9.2.1"

[[neighbors]]
address = "127.9.2.2"
"#;
        let addrs = toml_neighbor_addresses(doc);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains("127.9.2.1") && addrs.contains("127.9.2.2"));
    }

    #[test]
    fn sum_samples_totals_a_labelled_family_and_reports_absence() {
        let scrape = concat!(
            "bgp_messages_received_total{peer=\"127.9.2.2\",type=\"update\"} 3\n",
            "bgp_messages_received_total{peer=\"127.9.2.2\",type=\"keepalive\"} 4\n",
            "bgp_messages_received_total{peer=\"127.9.2.3\",type=\"update\"} 9\n",
        );
        assert_eq!(
            sum_samples(
                scrape,
                "bgp_messages_received_total",
                &[("peer", "127.9.2.2")]
            ),
            Some(7.0)
        );
        // A reaped series must read as absent, not as a silent zero.
        assert_eq!(
            sum_samples(scrape, "bgp_session_flaps_total", &[("peer", "127.9.2.2")]),
            None
        );
    }

    #[test]
    fn sum_samples_does_not_match_a_longer_metric_name() {
        let scrape = "bgp_session_flaps_total_extra{peer=\"127.9.2.2\"} 4\n";
        assert_eq!(
            sum_samples(scrape, "bgp_session_flaps_total", &[("peer", "127.9.2.2")]),
            None
        );
    }

    #[test]
    fn wire_identity_distinguishes_a_reconnected_session() {
        let obs = Obs::new();
        obs.established.store(true, Ordering::Release);
        {
            let mut wire = obs.wire.lock().unwrap();
            wire.updates = 5;
            wire.announced_nlri = 9;
        }
        let before = obs.identity();
        obs.reset();
        obs.established.store(true, Ordering::Release);
        assert_ne!(
            before,
            obs.identity(),
            "a reset session must not compare equal"
        );
    }

    #[test]
    fn fleet_addresses_and_asns_are_distinct() {
        let addrs: HashSet<_> = (0..PEERS).map(peer_addr).collect();
        let asns: HashSet<_> = (0..PEERS).map(peer_asn).collect();
        assert_eq!(addrs.len(), PEERS);
        assert_eq!(asns.len(), PEERS);
        let added: HashSet<_> = [
            ADD_RESTART,
            ADD_ROLLED_BACK,
            ADD_CONFIRMED,
            ADD_TIMED_OUT,
            ADD_KILLED,
            ADD_REFUSED,
        ]
        .into_iter()
        .collect();
        assert_eq!(added.len(), 6, "phase neighbors must not collide");
        for i in 0..PEERS {
            assert!(
                !added.contains(peer_addr(i).to_string().as_str()),
                "a phase neighbor must not collide with a live session"
            );
        }
    }

    #[test]
    fn source_table_encodes_both_families_on_the_wire() {
        let msgs = source_table();
        assert_eq!(msgs.len(), 2);
        let mut v4 = 0;
        let mut v6 = 0;
        for msg in &msgs {
            let Message::Update(update) = msg else {
                panic!("expected UPDATE")
            };
            let bytes = encode_message(msg).expect("source UPDATE encodes");
            assert!(bytes.len() <= usize::from(MAX_MESSAGE_LEN));
            let parsed = update
                .parse(true, false, &[])
                .expect("source UPDATE parses");
            v4 += parsed.announced.len();
            for attribute in &parsed.attributes {
                if let PathAttribute::MpReachNlri(mp) = attribute {
                    v6 += mp.announced.len();
                }
            }
        }
        assert_eq!(v4, V4_ROUTES);
        assert_eq!(v6, V6_ROUTES);
    }

    #[test]
    fn json_quote_escapes_what_a_detail_line_can_contain() {
        assert_eq!(json_quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(json_quote("a\nb"), r#""a\nb""#);
    }
}
