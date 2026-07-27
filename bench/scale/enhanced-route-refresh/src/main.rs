//! Real-session RFC 7313 inventory receipt driver.
//!
//! One Enhanced Route Refresh-capable BGP peer announces an exact IPv4
//! table, then drives first/duplicate BoRR, one-prefix replay, EoRR, and
//! timeout completion. File barriers let the outer runner capture the
//! production daemon's metrics and memory at every boundary without racing
//! the next peer action.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::route_refresh::{RouteRefreshMessage, RouteRefreshSubtype};
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Origin, PathAttribute};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot};

const PEER_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 1, 0, 1);
const PEER_ASN: u32 = 64_512;
const PEER_ROUTER_ID: Ipv4Addr = Ipv4Addr::new(240, 1, 0, 1);
const HOLD_TIME: u16 = 600;
const NLRI_PER_MESSAGE: usize = 900;
const DEFAULT_PREFIXES: u32 = 100_000;
const BARRIER_TIMEOUT: Duration = Duration::from_secs(360);

enum WriterCommand {
    Message(Message),
    Flush(oneshot::Sender<()>),
}

struct Session {
    tx: mpsc::Sender<WriterCommand>,
    healthy: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Session {
    fn ensure_healthy(&self) -> Result<(), String> {
        if self.healthy.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(self
            .failure
            .lock()
            .expect("reader failure mutex poisoned")
            .clone()
            .unwrap_or_else(|| "BGP session is no longer established".to_owned()))
    }

    async fn send(&self, message: Message) -> Result<(), String> {
        self.ensure_healthy()?;
        self.tx
            .send(WriterCommand::Message(message))
            .await
            .map_err(|_| "BGP writer stopped".to_owned())
    }

    async fn flush(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterCommand::Flush(tx))
            .await
            .map_err(|_| "BGP writer stopped before flush".to_owned())?;
        rx.await
            .map_err(|_| "BGP writer stopped during flush".to_owned())?;
        self.ensure_healthy()
    }

    async fn send_all<I>(&self, messages: I) -> Result<(), String>
    where
        I: IntoIterator<Item = Message>,
    {
        for message in messages {
            self.send(message).await?;
        }
        self.flush().await
    }

    fn abort(self) {
        self.reader.abort();
        self.writer.abort();
    }
}

fn base_prefix(index: u32) -> Ipv4Prefix {
    let first = 20 + u8::try_from(index >> 16).expect("100k receipt prefix space exhausted");
    let second = u8::try_from((index >> 8) & 0xff).expect("second octet");
    let third = u8::try_from(index & 0xff).expect("third octet");
    Ipv4Prefix::new(Ipv4Addr::new(first, second, third, 0), 24)
}

fn attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![PEER_ASN])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 1)),
    ]
}

fn announce_messages(first: u32, count: u32) -> Vec<Message> {
    let attributes = attributes();
    let prefixes: Vec<Ipv4Prefix> = (first..first + count).map(base_prefix).collect();
    prefixes
        .chunks(NLRI_PER_MESSAGE)
        .map(|chunk| {
            let announced: Vec<Ipv4NlriEntry> = chunk
                .iter()
                .map(|prefix| Ipv4NlriEntry {
                    path_id: 0,
                    prefix: *prefix,
                })
                .collect();
            Message::Update(UpdateMessage::build(
                &announced,
                &[],
                &attributes,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
        })
        .collect()
}

fn end_of_rib() -> Message {
    Message::Update(UpdateMessage::build(
        &[],
        &[],
        &[],
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

fn refresh(subtype: RouteRefreshSubtype) -> Message {
    Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(
        Afi::Ipv4,
        Safi::Unicast,
        subtype,
    ))
}

async fn next_message(stream: &mut TcpStream, frame: &mut BytesMut) -> Result<Message, String> {
    loop {
        if frame.len() >= HEADER_LEN {
            let length = peek_message_length(frame, MAX_MESSAGE_LEN)
                .map_err(|error| format!("invalid BGP frame: {error}"))?;
            if let Some(length) = length {
                let length = usize::from(length);
                if frame.len() >= length {
                    let mut bytes = frame.split_to(length).freeze();
                    return decode_message(&mut bytes, MAX_MESSAGE_LEN)
                        .map_err(|error| format!("BGP decode failed: {error}"));
                }
            }
        }

        let mut bytes = [0_u8; 1 << 14];
        let read = stream
            .read(&mut bytes)
            .await
            .map_err(|error| format!("BGP read failed: {error}"))?;
        if read == 0 {
            return Err("BGP peer closed the session".to_owned());
        }
        frame.extend_from_slice(&bytes[..read]);
    }
}

async fn establish(daemon_port: u16) -> Result<Session, String> {
    let socket = TcpSocket::new_v4().map_err(|error| format!("socket failed: {error}"))?;
    socket
        .bind(SocketAddr::new(PEER_ADDRESS.into(), 0))
        .map_err(|error| format!("bind {PEER_ADDRESS} failed: {error}"))?;
    let mut stream = socket
        .connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), daemon_port))
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("TCP_NODELAY failed: {error}"))?;

    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(PEER_ASN).expect("two-octet receipt ASN"),
        hold_time: HOLD_TIME,
        bgp_identifier: PEER_ROUTER_ID,
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: PEER_ASN },
            Capability::RouteRefresh,
            Capability::EnhancedRouteRefresh,
        ],
    };
    let encoded = encode_message(&Message::Open(open))
        .map_err(|error| format!("OPEN encode failed: {error}"))?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|error| format!("OPEN write failed: {error}"))?;

    let mut frame = BytesMut::with_capacity(1 << 16);
    let daemon_open = loop {
        match next_message(&mut stream, &mut frame).await? {
            Message::Open(open) => break open,
            Message::Notification(notification) => {
                return Err(format!(
                    "NOTIFICATION during OPEN: {:?}/{}",
                    notification.code, notification.subcode
                ));
            }
            _ => {}
        }
    };
    if !daemon_open
        .capabilities
        .contains(&Capability::EnhancedRouteRefresh)
    {
        return Err("daemon did not negotiate Enhanced Route Refresh".to_owned());
    }
    if !daemon_open.capabilities.contains(&Capability::RouteRefresh) {
        return Err("daemon did not negotiate Route Refresh".to_owned());
    }

    stream
        .write_all(
            &encode_message(&Message::Keepalive)
                .map_err(|error| format!("KEEPALIVE encode failed: {error}"))?,
        )
        .await
        .map_err(|error| format!("KEEPALIVE write failed: {error}"))?;
    loop {
        match next_message(&mut stream, &mut frame).await? {
            Message::Keepalive => break,
            Message::Notification(notification) => {
                return Err(format!(
                    "NOTIFICATION before Established: {:?}/{}",
                    notification.code, notification.subcode
                ));
            }
            _ => {}
        }
    }

    let healthy = Arc::new(AtomicBool::new(true));
    let failure = Arc::new(Mutex::new(None));
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<WriterCommand>(256);

    let writer_healthy = Arc::clone(&healthy);
    let writer_failure = Arc::clone(&failure);
    let writer_task = tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;
        loop {
            let result = tokio::select! {
                command = rx.recv() => match command {
                    Some(WriterCommand::Message(message)) => {
                        match encode_message(&message) {
                            Ok(bytes) => writer.write_all(&bytes).await,
                            Err(error) => {
                                *writer_failure.lock().expect("writer failure mutex poisoned") =
                                    Some(format!("BGP encode failed: {error}"));
                                break;
                            }
                        }
                    }
                    Some(WriterCommand::Flush(ack)) => {
                        let result = writer.flush().await;
                        if result.is_ok() {
                            let _ = ack.send(());
                        }
                        result
                    }
                    None => break,
                },
                _ = keepalive.tick() => {
                    let bytes = encode_message(&Message::Keepalive)
                        .expect("KEEPALIVE always encodes");
                    writer.write_all(&bytes).await
                }
            };
            if let Err(error) = result {
                *writer_failure
                    .lock()
                    .expect("writer failure mutex poisoned") =
                    Some(format!("BGP write failed: {error}"));
                break;
            }
        }
        writer_healthy.store(false, Ordering::Release);
    });

    let reader_healthy = Arc::clone(&healthy);
    let reader_failure = Arc::clone(&failure);
    let reader_task = tokio::spawn(async move {
        let mut bytes = vec![0_u8; 1 << 16];
        loop {
            loop {
                if frame.len() < HEADER_LEN {
                    break;
                }
                let length = match peek_message_length(&frame, MAX_MESSAGE_LEN) {
                    Ok(Some(length)) => usize::from(length),
                    Ok(None) => break,
                    Err(error) => {
                        *reader_failure
                            .lock()
                            .expect("reader failure mutex poisoned") =
                            Some(format!("invalid daemon BGP frame: {error}"));
                        reader_healthy.store(false, Ordering::Release);
                        return;
                    }
                };
                if frame.len() < length {
                    break;
                }
                let mut message = frame.split_to(length).freeze();
                match decode_message(&mut message, MAX_MESSAGE_LEN) {
                    Ok(Message::Notification(notification)) => {
                        *reader_failure
                            .lock()
                            .expect("reader failure mutex poisoned") = Some(format!(
                            "daemon sent NOTIFICATION {:?}/{}",
                            notification.code, notification.subcode
                        ));
                        reader_healthy.store(false, Ordering::Release);
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        *reader_failure
                            .lock()
                            .expect("reader failure mutex poisoned") =
                            Some(format!("daemon BGP decode failed: {error}"));
                        reader_healthy.store(false, Ordering::Release);
                        return;
                    }
                }
            }

            match reader.read(&mut bytes).await {
                Ok(0) => {
                    *reader_failure
                        .lock()
                        .expect("reader failure mutex poisoned") =
                        Some("daemon closed the BGP session".to_owned());
                    reader_healthy.store(false, Ordering::Release);
                    return;
                }
                Ok(read) => frame.extend_from_slice(&bytes[..read]),
                Err(error) => {
                    *reader_failure
                        .lock()
                        .expect("reader failure mutex poisoned") =
                        Some(format!("daemon BGP read failed: {error}"));
                    reader_healthy.store(false, Ordering::Release);
                    return;
                }
            }
        }
    });

    Ok(Session {
        tx,
        healthy,
        failure,
        reader: reader_task,
        writer: writer_task,
    })
}

async fn barrier(session: &Session, directory: &Path, name: &str) -> Result<(), String> {
    session.ensure_healthy()?;
    let ready = directory.join(format!("{name}.ready"));
    let ack = directory.join(format!("{name}.ack"));
    if ready.exists() || ack.exists() {
        return Err(format!("stale barrier file for {name}"));
    }
    std::fs::write(&ready, b"ready\n")
        .map_err(|error| format!("write {} failed: {error}", ready.display()))?;
    println!("phase_ready,{name}");

    let deadline = Instant::now() + BARRIER_TIMEOUT;
    while !ack.is_file() {
        session.ensure_healthy()?;
        if Instant::now() >= deadline {
            return Err(format!(
                "phase {name} was not acknowledged within {} seconds",
                BARRIER_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    println!("phase_ack,{name}");
    Ok(())
}

async fn run(daemon_port: u16, evidence_dir: PathBuf, prefixes: u32) -> Result<(), String> {
    if prefixes != DEFAULT_PREFIXES {
        return Err(format!(
            "the durable receipt shape is fixed at {DEFAULT_PREFIXES} prefixes, got {prefixes}"
        ));
    }
    std::fs::create_dir_all(&evidence_dir)
        .map_err(|error| format!("create {} failed: {error}", evidence_dir.display()))?;
    if std::fs::read_dir(&evidence_dir)
        .map_err(|error| format!("read {} failed: {error}", evidence_dir.display()))?
        .next()
        .is_some()
    {
        return Err(format!(
            "evidence directory is not empty: {}",
            evidence_dir.display()
        ));
    }

    let session = establish(daemon_port).await?;
    println!(
        "session_established,peer={PEER_ADDRESS},prefixes={prefixes},enhanced_route_refresh=true"
    );

    session.send_all(announce_messages(0, prefixes)).await?;
    session.send(end_of_rib()).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "baseline").await?;

    barrier(&session, &evidence_dir, "first-borr-arm").await?;
    session.send(refresh(RouteRefreshSubtype::BoRR)).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "first-borr").await?;

    barrier(&session, &evidence_dir, "replay-one-arm").await?;
    session.send_all(announce_messages(0, 1)).await?;
    barrier(&session, &evidence_dir, "replay-one").await?;

    barrier(&session, &evidence_dir, "duplicate-borr-arm").await?;
    session.send(refresh(RouteRefreshSubtype::BoRR)).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "duplicate-borr").await?;

    barrier(&session, &evidence_dir, "eorr-arm").await?;
    session.send(refresh(RouteRefreshSubtype::EoRR)).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "eorr").await?;

    barrier(&session, &evidence_dir, "restored-arm").await?;
    session.send_all(announce_messages(0, prefixes)).await?;
    session.send(end_of_rib()).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "restored").await?;

    barrier(&session, &evidence_dir, "timeout-borr-arm").await?;
    session.send(refresh(RouteRefreshSubtype::BoRR)).await?;
    session.flush().await?;
    barrier(&session, &evidence_dir, "timeout-borr").await?;
    barrier(&session, &evidence_dir, "timeout-complete").await?;

    session.ensure_healthy()?;
    println!("receipt_complete,prefixes={prefixes}");
    session.abort();
    Ok(())
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if !(3..=4).contains(&arguments.len()) {
        eprintln!("usage: enhanced-route-refresh-receipt <daemon-port> <evidence-dir> [prefixes]");
        std::process::exit(2);
    }
    let daemon_port = arguments[1]
        .parse::<u16>()
        .unwrap_or_else(|error| panic!("invalid daemon port: {error}"));
    let evidence_dir = PathBuf::from(&arguments[2]);
    let prefixes = arguments
        .get(3)
        .map_or(Ok(DEFAULT_PREFIXES), |value| value.parse::<u32>())
        .unwrap_or_else(|error| panic!("invalid prefix count: {error}"));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    if let Err(error) = runtime.block_on(run(daemon_port, evidence_dir, prefixes)) {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn announcement_plan_encodes_every_receipt_prefix_exactly_once() {
        let mut seen = HashSet::new();
        for message in announce_messages(0, DEFAULT_PREFIXES) {
            let Message::Update(update) = message else {
                panic!("announcement builder emitted a non-UPDATE");
            };
            let parsed = update
                .parse(true, false, &[])
                .expect("generated UPDATE parses");
            for route in parsed.announced {
                assert!(seen.insert(route.prefix), "duplicate {}", route.prefix);
            }
        }
        assert_eq!(seen.len(), usize::try_from(DEFAULT_PREFIXES).unwrap());
        for index in 0..DEFAULT_PREFIXES {
            assert!(seen.contains(&base_prefix(index)), "missing index {index}");
        }
    }

    #[test]
    fn receipt_shape_refuses_smaller_nonrepresentative_tables() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let directory =
            std::env::temp_dir().join(format!("err-receipt-shape-{}", std::process::id()));
        let error = runtime
            .block_on(run(1, directory, DEFAULT_PREFIXES - 1))
            .unwrap_err();
        assert!(error.contains("fixed at 100000 prefixes"), "{error}");
    }
}
