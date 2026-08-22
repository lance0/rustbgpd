//! Real-binary pass-through receipt for `ATOMIC_AGGREGATE` + `AGGREGATOR`.
//!
//! Two BGP stub sessions dial a spawned rustbgpd over loopback TCP. The
//! source announces one IPv4 prefix carrying `ATOMIC_AGGREGATE` and
//! `AGGREGATOR`; the observer reads the daemon's export. The test asserts
//! that the route was accepted into the source's Adj-RIB-In (`rbgp rib
//! received`, no UPDATE validation error in the daemon log) and that both
//! attributes reach the observer intact on the wire.
//!
//! Stub mechanics follow `tests/outbound_prefix_limits.rs`.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{Message, decode_message, encode_message};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{
    Aggregator, AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Origin, PathAttribute,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

const SOURCE: usize = 0;
const OBSERVER: usize = 1;
const PEERS: usize = 2;
const HOLD_TIME: u16 = 180;
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(60);

fn peer_addr(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 9, 1, u8::try_from(i + 1).expect("peer index fits"))
}

fn peer_asn(i: usize) -> u32 {
    64601 + u32::try_from(i).expect("peer index fits")
}

fn announced_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(20, 1, 0, 0), 16)
}

fn aggregator() -> Aggregator {
    Aggregator {
        asn: peer_asn(SOURCE),
        router_id: Ipv4Addr::new(192, 0, 2, 1),
        partial: false,
    }
}

/// The source's announcement: an aggregate carrying both aggregation
/// attributes.
fn source_update() -> Message {
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(SOURCE)])],
        }),
        // A 127/8 NEXT_HOP is rejected with UPDATE error subcode 8, so the
        // source uses a synthetic off-loopback address.
        PathAttribute::NextHop(Ipv4Addr::new(10, 9, 1, 1)),
        PathAttribute::AtomicAggregate,
        PathAttribute::Aggregator(aggregator()),
    ];
    Message::Update(UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: announced_prefix(),
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

/// What one stub has seen on the wire: every parsed announcement as
/// (prefixes, attributes).
#[derive(Default)]
struct Obs {
    announcements: Mutex<Vec<(Vec<Ipv4Prefix>, Vec<PathAttribute>)>>,
    established: AtomicBool,
    decode_errors: Mutex<Vec<String>>,
}

struct Ctx {
    daemon: SocketAddr,
    obs: Vec<Obs>,
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
        bgp_identifier: Ipv4Addr::new(240, 9, 1, u8::try_from(i + 1).expect("peer index fits")),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
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
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN)
            && buf.len() >= usize::from(total)
        {
            let mut body = buf.split_to(usize::from(total)).freeze();
            match decode_message(&mut body, MAX_MESSAGE_LEN) {
                Ok(Message::Open(_)) => break,
                Ok(Message::Notification(n)) => {
                    return Err(format!(
                        "NOTIFICATION during open: {:?}/{}",
                        n.code, n.subcode
                    ));
                }
                Ok(_) => continue,
                Err(e) => return Err(format!("decode during open: {e}")),
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

    let (tx, mut tx_rx) = mpsc::channel::<Message>(16);
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
        writer_ctx.obs[i]
            .established
            .store(false, Ordering::Release);
    });

    let reader_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        // Start from the OPEN loop's leftover: on loopback the daemon's
        // first KEEPALIVE often shares a read with its OPEN, so parse
        // what is already buffered before the first read instead of
        // dropping it.
        let mut frame = buf;
        let mut tmp = vec![0u8; 1 << 16];
        loop {
            loop {
                if frame.len() < HEADER_LEN {
                    break;
                }
                let total = match peek_message_length(&frame, MAX_MESSAGE_LEN) {
                    Ok(Some(len)) => usize::from(len),
                    Ok(None) => break,
                    Err(error) => {
                        reader_ctx.obs[i]
                            .decode_errors
                            .lock()
                            .expect("decode error lock")
                            .push(format!("invalid daemon frame: {error}"));
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut body = frame.split_to(total).freeze();
                match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    // The daemon's KEEPALIVE completes the session.
                    Ok(Message::Keepalive) => {
                        reader_ctx.obs[i].established.store(true, Ordering::Release);
                    }
                    Ok(Message::Update(update)) => match update.parse(true, false, &[]) {
                        Ok(parsed) => reader_ctx.obs[i]
                            .announcements
                            .lock()
                            .expect("announcement lock")
                            .push((
                                parsed.announced.iter().map(|entry| entry.prefix).collect(),
                                parsed.attributes,
                            )),
                        Err(error) => reader_ctx.obs[i]
                            .decode_errors
                            .lock()
                            .expect("decode error lock")
                            .push(format!("daemon UPDATE failed to parse: {error}")),
                    },
                    Ok(_) => {}
                    Err(error) => {
                        reader_ctx.obs[i]
                            .decode_errors
                            .lock()
                            .expect("decode error lock")
                            .push(format!("daemon message failed to decode: {error}"));
                        return;
                    }
                }
            }
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    reader_ctx.obs[i]
                        .established
                        .store(false, Ordering::Release);
                    return;
                }
                Ok(n) => n,
            };
            frame.extend_from_slice(&tmp[..n]);
        }
    });

    Ok(tx)
}

/// `rbgp` against the spawned daemon. `CARGO_BIN_EXE_rbgp` is not set for a
/// dev-dependency's binary, so fall back to `cargo run -p rustbgpctl`.
struct Rbgp {
    argv: Vec<String>,
    addr: String,
}

impl Rbgp {
    fn new(addr: String) -> Self {
        let argv = if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
            vec![path]
        } else {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            vec![
                cargo,
                "run".into(),
                "--quiet".into(),
                "-p".into(),
                "rustbgpctl".into(),
                "--bin".into(),
                "rbgp".into(),
                "--".into(),
            ]
        };
        Self { argv, addr }
    }

    async fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = tokio::process::Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .arg("--addr")
            .arg(&self.addr)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("rbgp {args:?}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "rbgp {args:?} exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read loopback port")
        .port()
}

/// Short-path runtime dir: the gRPC UDS must fit `sockaddr_un.sun_path`,
/// which a tempdir under a deep build path may not.
struct RunDir {
    path: PathBuf,
}

impl RunDir {
    fn new(tag: &str) -> Self {
        let path = PathBuf::from(format!("/tmp/rustbgpd-{tag}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("create run dir");
        let mut permissions = std::fs::metadata(&path)
            .expect("stat run dir")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
        std::fs::set_permissions(&path, permissions).expect("restrict run dir");
        Self { path }
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn emit_config(path: &Path, bgp_port: u16, metrics: SocketAddr, rundir: &Path) {
    let rundir = rundir.display();
    let body = format!(
        r#"# Generated by tests/atomic_aggregate_passthrough.rs — do not edit.
[global]
asn = 65500
router_id = "10.255.0.1"
listen_port = {bgp_port}
runtime_state_dir = "{rundir}"

[global.telemetry]
prometheus_addr = "{metrics}"
log_format = "json"

[global.telemetry.grpc_uds]
path = "{rundir}/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[[neighbors]]
address = "127.9.1.1"
remote_asn = 64601
description = "aggregate-source"
hold_time = 180
families = ["ipv4_unicast"]

[[neighbors]]
address = "127.9.1.2"
remote_asn = 64602
description = "observer"
hold_time = 180
families = ["ipv4_unicast"]
"#
    );
    std::fs::write(path, body).expect("write config");
}

struct Daemon {
    child: std::process::Child,
    log_path: PathBuf,
}

impl Daemon {
    fn spawn(config: &Path, log_path: PathBuf) -> Self {
        let stdout = std::fs::File::create(&log_path).expect("create daemon log");
        let stderr = stdout.try_clone().expect("clone daemon log handle");
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("spawn rustbgpd");
        Self { child, log_path }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

async fn wait_until_serving(rbgp: &Rbgp, sock: &Path, daemon: &mut Daemon) {
    let deadline = Instant::now() + CONVERGE_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(status) = daemon.child.try_wait().expect("query daemon status") {
            panic!(
                "rustbgpd exited during startup with {status}\nlog:\n{}",
                daemon.log()
            );
        }
        if sock.exists() && rbgp.run(&["global"]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("daemon never became ready\nlog:\n{}", daemon.log());
}

async fn wait_for<F>(mut predicate: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < CONVERGE_TIMEOUT {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atomic_aggregate_and_aggregator_survive_adj_rib_in_to_export() {
    let rundir = RunDir::new("atomicagg");
    let bgp_port = free_port();
    let metrics: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let config = rundir.path.join("config.toml");
    emit_config(&config, bgp_port, metrics, &rundir.path);

    let sock = rundir.path.join("grpc.sock");
    let rbgp = Rbgp::new(format!("unix://{}", sock.display()));
    let mut daemon = Daemon::spawn(&config, rundir.path.join("daemon.log"));
    wait_until_serving(&rbgp, &sock, &mut daemon).await;

    let ctx = Arc::new(Ctx {
        daemon: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bgp_port),
        obs: (0..PEERS).map(|_| Obs::default()).collect(),
    });
    let mut senders = Vec::new();
    for i in 0..PEERS {
        senders.push(
            establish(Arc::clone(&ctx), i)
                .await
                .expect("stub session establishes"),
        );
    }
    assert!(
        wait_for(|| ctx
            .obs
            .iter()
            .all(|o| o.established.load(Ordering::Acquire)))
        .await,
        "not every stub session reached Established\nlog:\n{}",
        daemon.log()
    );

    senders[SOURCE]
        .send(source_update())
        .await
        .expect("source session open for announce");

    // (b) Export: the observer receives the prefix with both attributes.
    let received = wait_for(|| {
        ctx.obs[OBSERVER]
            .announcements
            .lock()
            .expect("announcement lock")
            .iter()
            .any(|(prefixes, _)| prefixes.contains(&announced_prefix()))
    })
    .await;
    let announcements = ctx.obs[OBSERVER]
        .announcements
        .lock()
        .expect("announcement lock")
        .clone();
    let decode_errors = ctx.obs[OBSERVER]
        .decode_errors
        .lock()
        .expect("decode error lock")
        .clone();
    assert!(
        received,
        "observer never received {} (announcements: {announcements:?}, decode errors: {decode_errors:?})\nlog:\n{}",
        announced_prefix(),
        daemon.log()
    );
    assert!(decode_errors.is_empty(), "{decode_errors:?}");
    let (_, attrs) = announcements
        .iter()
        .find(|(prefixes, _)| prefixes.contains(&announced_prefix()))
        .expect("announcement located above");
    assert!(
        attrs.contains(&PathAttribute::AtomicAggregate),
        "ATOMIC_AGGREGATE missing from export: {attrs:?}"
    );
    assert!(
        attrs.contains(&PathAttribute::Aggregator(aggregator())),
        "AGGREGATOR missing from export: {attrs:?}"
    );

    // (a) Adj-RIB-In: the source's route was accepted, not treat-as-withdrawn.
    let source = peer_addr(SOURCE).to_string();
    let received_json = rbgp
        .run(&["-j", "rib", "received", &source, "-a", "ipv4-unicast"])
        .await
        .expect("rbgp rib received");
    assert!(
        received_json.contains(&announced_prefix().to_string()),
        "{} absent from the source's accepted Adj-RIB-In: {received_json}",
        announced_prefix()
    );
    let log = daemon.log();
    assert!(
        !log.contains("UPDATE validation error"),
        "the daemon rejected an UPDATE:\n{log}"
    );
}
