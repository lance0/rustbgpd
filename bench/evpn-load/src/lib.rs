//! Minimal iBGP peer for EVPN scale-load generation.
//!
//! Not a full BGP implementation — no FSM transitions beyond `OpenSent` →
//! `OpenConfirm` → `Established`, hold-timer enforcement is the only
//! timer wired (it tears the session if no inbound traffic arrives
//! within the negotiated hold window so a stuck RR is detected), no
//! graceful error recovery. The scope is one-shot scale harnesses that
//! open a session, flood routes, and measure convergence.
//!
//! Built directly on top of `rustbgpd-wire` + tokio. Keeps rate control
//! and message shape fully in this crate's control so Gate 5 does not
//! depend on another daemon's behavior as the load generator.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{Message, decode_message, encode_message};
use rustbgpd_wire::open::OpenMessage;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

/// Errors during peer session setup or I/O.
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire encode: {0}")]
    Encode(#[from] rustbgpd_wire::error::EncodeError),
    #[error("wire decode: {0}")]
    Decode(#[from] rustbgpd_wire::error::DecodeError),
    #[error("remote closed connection before OPEN")]
    PrematureClose,
    #[error("expected OPEN, got {0:?}")]
    UnexpectedMessageDuringOpen(String),
    #[error("peer sent NOTIFICATION code={code} subcode={subcode}")]
    Notification { code: String, subcode: u8 },
    #[error("send channel closed")]
    SendChannelClosed,
}

/// Peer session configuration.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Local listen address — the RR will dial us here. BGP uses 179.
    pub listen: SocketAddr,
    /// Our AS number (4-octet).
    pub local_as: u32,
    /// Our BGP router-id.
    pub router_id: Ipv4Addr,
    /// Hold time to advertise; also drives our KEEPALIVE cadence (hold/3).
    pub hold_time: u16,
    /// Address families to activate via `MultiProtocol` capability.
    pub families: Vec<(Afi, Safi)>,
}

impl PeerConfig {
    /// A [`PeerConfig`] preloaded for L2VPN/EVPN only (single family).
    #[must_use]
    pub fn evpn_only(listen: SocketAddr, local_as: u32, router_id: Ipv4Addr) -> Self {
        Self {
            listen,
            local_as,
            router_id,
            hold_time: 90,
            families: vec![(Afi::L2Vpn, Safi::Evpn)],
        }
    }
}

/// Handle to a live BGP session. Provides a send channel for outbound
/// messages and a receive stream for inbound ones.
///
/// **Important:** the inbound channel `rx` is bounded (currently
/// 65 536 messages). The reader task drives `rx_tx.send(m).await`,
/// which means it **back-pressures the TCP read loop** if the consumer
/// stops draining. A non-draining consumer (e.g. a write-only synthetic
/// peer) under sustained inbound traffic will eventually fill the
/// channel, the reader task will park on send, the kernel TCP receive
/// buffer will fill, and the remote peer's writer will block on
/// `write_all` — surfacing as "saturated" from rustbgpd's perspective.
///
/// This is fine for an honest BGP daemon because real BGP daemons
/// always drain their inbound traffic. For load-test scaffolding that
/// only sends, **either drain `rx` in a discard task or use a real
/// consumer**:
///
/// ```ignore
/// // Drain-and-discard pattern for a write-only synthetic peer.
/// let mut rx = handle.rx;
/// tokio::spawn(async move { while rx.recv().await.is_some() {} });
/// ```
///
/// The +49-min "wedge" the M33 soak harness reproduced before
/// `f7c1033` was exactly this: the testers leaked their `rx` and
/// stalled the RR's writer.
pub struct PeerHandle {
    /// Send messages to be written to the wire.
    pub tx: mpsc::Sender<Message>,
    /// Inbound messages decoded off the wire. **Must be drained** —
    /// see the type-level docs for the consumer-stalls-the-reader
    /// gotcha.
    pub rx: mpsc::Receiver<Message>,
    /// Time the session reached Established.
    pub established_at: Instant,
}

/// Listen on `cfg.listen`, accept the first inbound TCP, exchange OPEN,
/// send KEEPALIVE, and return a handle. The session continues in
/// background tasks (reader, writer, keepalive sender) until tx is
/// dropped or rx drains.
///
/// Listen-rather-than-dial is deliberate: rustbgpd's neighbor model
/// always actively dials its configured peers. If both sides dial,
/// the collision-resolution window holds the inbound TCP pending
/// while the outbound retries indefinitely (when the other side
/// isn't listening). Accepting inbound avoids the deadlock.
///
/// # Errors
///
/// Returns a [`PeerError`] if bind/accept, OPEN exchange, or initial
/// KEEPALIVE fails.
#[expect(clippy::too_many_lines, reason = "reader task body is the bulk")]
pub async fn establish(cfg: PeerConfig) -> Result<PeerHandle, PeerError> {
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "evpn-load peer listening for BGP session");
    let (mut stream, remote) = listener.accept().await?;
    tracing::info!(%remote, "evpn-load peer accepted inbound BGP connection");
    drop(listener);

    // Send our OPEN first — simplifies the handshake; the peer will
    // respond in kind.
    let our_open = build_open(&cfg);
    let bytes = encode_message(&Message::Open(our_open))?;
    stream.write_all(&bytes).await?;

    // Read the peer's OPEN.
    let mut buf = BytesMut::with_capacity(4096);
    let _peer_open = read_expected_open(&mut stream, &mut buf).await?;

    // Send KEEPALIVE to confirm. At this point we treat the session as
    // Established. Hold-timer enforcement is wired in the reader task
    // (RFC 4271 §4.4 / §6.5): if no inbound traffic arrives within the
    // negotiated hold window the session is torn down so a stuck RR
    // gets detected rather than masked as "in progress".
    let ka = encode_message(&Message::Keepalive)?;
    stream.write_all(&ka).await?;

    let established_at = Instant::now();

    let (tx_out, mut tx_rx) = mpsc::channel::<Message>(1024);
    let (rx_tx, rx_out) = mpsc::channel::<Message>(65536);

    let (mut reader, mut writer) = stream.into_split();

    let hold = cfg.hold_time;
    let ka_interval = keepalive_interval(hold);

    // Writer task: pulls from tx, writes to socket, injects periodic KEEPALIVE.
    tokio::spawn(async move {
        if let Some(interval) = ka_interval {
            let mut ka_tick = tokio::time::interval(interval);
            ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ka_tick.tick().await; // fire immediately, then cadence
            loop {
                tokio::select! {
                    Some(msg) = tx_rx.recv() => {
                        match encode_message(&msg) {
                            Ok(bytes) => {
                                if writer.write_all(&bytes).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                tracing::error!(?e, "encode failed in writer task");
                                return;
                            }
                        }
                    }
                    _ = ka_tick.tick() => {
                        if let Ok(bytes) = encode_message(&Message::Keepalive)
                            && writer.write_all(&bytes).await.is_err() {
                                return;
                        }
                    }
                    else => return,
                }
            }
        } else {
            while let Some(msg) = tx_rx.recv().await {
                let bytes = match encode_message(&msg) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!(?e, "encode failed in writer task");
                        return;
                    }
                };
                if writer.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        }
    });

    // Reader task: framed decode, push to rx_tx, enforce hold timer.
    //
    // Hold-timer enforcement (RFC 4271 §4.4 / §6.5): if no inbound
    // message arrives within `hold` seconds the session is torn down.
    // For a synthetic peer this is the only way to detect a stuck RR
    // (TCP open, no traffic) — without the timer the tester would
    // sit forever and the harness would mistake silence for "in
    // progress." We implement it by selecting between socket read
    // and a deadline timer that gets reset on every byte received.
    let hold_secs = u64::from(hold);
    tokio::spawn(async move {
        let mut frame_buf = BytesMut::with_capacity(65536);
        let mut tmp = [0u8; 8192];
        let hold_dur = Duration::from_secs(hold_secs);
        // hold=0 means "no hold timer" per RFC 4271 §4.2 — disable enforcement.
        let timer_enabled = hold_secs > 0;
        let mut deadline = if timer_enabled {
            tokio::time::Instant::now() + hold_dur
        } else {
            // Far-future placeholder — never fires.
            tokio::time::Instant::now() + Duration::from_hours(24 * 365)
        };
        loop {
            let n = tokio::select! {
                read_res = reader.read(&mut tmp) => match read_res {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                },
                () = tokio::time::sleep_until(deadline), if timer_enabled => {
                    tracing::warn!(
                        hold_secs,
                        "hold timer expired — no inbound traffic from RR; closing session"
                    );
                    return;
                }
            };
            // Any received bytes reset the hold deadline (RFC 4271 §6.5).
            if timer_enabled {
                deadline = tokio::time::Instant::now() + hold_dur;
            }
            frame_buf.extend_from_slice(&tmp[..n]);
            loop {
                let have = frame_buf.len();
                if have < HEADER_LEN {
                    break;
                }
                let peek = peek_message_length(&frame_buf[..have], MAX_MESSAGE_LEN);
                let total = match peek {
                    Ok(Some(len)) => usize::from(len),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::error!(?e, "frame peek error — dropping session");
                        return;
                    }
                };
                if have < total {
                    break;
                }
                let msg_bytes = frame_buf.split_to(total).freeze();
                let mut mb = msg_bytes;
                match decode_message(&mut mb, MAX_MESSAGE_LEN) {
                    Ok(m) => {
                        if rx_tx.send(m).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(?e, "decode error — dropping session");
                        return;
                    }
                }
            }
        }
    });

    Ok(PeerHandle {
        tx: tx_out,
        rx: rx_out,
        established_at,
    })
}

fn keepalive_interval(hold_time: u16) -> Option<Duration> {
    if hold_time == 0 {
        None
    } else {
        Some(Duration::from_secs(u64::from(hold_time) / 3))
    }
}

fn build_open(cfg: &PeerConfig) -> OpenMessage {
    let mut caps: Vec<Capability> = cfg
        .families
        .iter()
        .map(|(afi, safi)| Capability::MultiProtocol {
            afi: *afi,
            safi: *safi,
        })
        .collect();
    caps.push(Capability::FourOctetAs { asn: cfg.local_as });
    caps.push(Capability::RouteRefresh);

    OpenMessage {
        version: 4,
        my_as: u16::try_from(cfg.local_as).unwrap_or(23456),
        hold_time: cfg.hold_time,
        bgp_identifier: cfg.router_id,
        capabilities: caps,
    }
}

async fn read_expected_open(
    stream: &mut TcpStream,
    buf: &mut BytesMut,
) -> Result<OpenMessage, PeerError> {
    loop {
        let peek = peek_message_length(buf, MAX_MESSAGE_LEN)?;
        if let Some(total) = peek
            && buf.len() >= usize::from(total)
        {
            let slice = buf.split_to(usize::from(total)).freeze();
            let mut b: Bytes = slice;
            let msg = decode_message(&mut b, MAX_MESSAGE_LEN)?;
            return match msg {
                Message::Open(o) => Ok(o),
                Message::Notification(n) => Err(PeerError::Notification {
                    code: format!("{}", n.code),
                    subcode: n.subcode,
                }),
                other => Err(PeerError::UnexpectedMessageDuringOpen(format!(
                    "{:?}",
                    other.message_type()
                ))),
            };
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(PeerError::PrematureClose);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Convenience: sleep a small amount, useful in tests.
pub async fn yield_for(ms: u64) {
    sleep(Duration::from_millis(ms)).await;
}

/// Ethernet-style MAC generator keyed by index. Produces deterministic
/// MACs of the shape `02:00:00:AA:BB:CC` where the last 3 bytes are the
/// 24-bit index, useful for synthetic load.
#[must_use]
pub fn synth_mac(index: u32) -> [u8; 6] {
    let i = index & 0x00FF_FFFF;
    [
        0x02,
        0x00,
        0x00,
        ((i >> 16) & 0xFF) as u8,
        ((i >> 8) & 0xFF) as u8,
        (i & 0xFF) as u8,
    ]
}

/// 10-byte EVPN Ethernet Segment Identifier generator keyed by index.
/// Produces a deterministic, **non-zero** ESI (RFC 7432 §7.1 / §7.4
/// require ESI != 0 for Type 1/4): leading byte `0x03` (ESI Type 3 —
/// "MAC-based" per RFC 7432 §5), then a fixed 5-byte synthetic
/// es-sys-mac, then a 4-byte big-endian es-id derived from `index + 1`
/// so index=0 still yields a valid non-zero ESI.
#[must_use]
pub fn synth_esi(index: u32) -> [u8; 10] {
    let id = index.saturating_add(1).to_be_bytes();
    [
        0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, id[0], id[1], id[2], id[3],
    ]
}

/// Convenience: build an IPv4 next-hop from a router-id.
#[must_use]
pub const fn v4_next_hop(id: Ipv4Addr) -> IpAddr {
    IpAddr::V4(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_mac_is_deterministic_and_locally_administered() {
        // 02: locally administered bit set, unicast.
        assert_eq!(synth_mac(0)[0], 0x02);
        assert_ne!(synth_mac(1), synth_mac(2));
        let m = synth_mac(0x0010_2030);
        assert_eq!(m[3..6], [0x10, 0x20, 0x30]);
    }

    #[test]
    fn peer_config_evpn_only_defaults() {
        let addr: SocketAddr = "0.0.0.0:179".parse().unwrap();
        let cfg = PeerConfig::evpn_only(addr, 65000, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.hold_time, 90);
        assert_eq!(cfg.families, vec![(Afi::L2Vpn, Safi::Evpn)]);
    }

    #[test]
    fn hold_zero_disables_periodic_keepalives() {
        assert_eq!(keepalive_interval(0), None);
        assert_eq!(keepalive_interval(3), Some(Duration::from_secs(1)));
        assert_eq!(keepalive_interval(180), Some(Duration::from_mins(1)));
    }
}
