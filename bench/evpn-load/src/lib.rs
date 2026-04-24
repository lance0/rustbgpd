//! Minimal iBGP peer for EVPN scale-load generation.
//!
//! Not a full BGP implementation — no FSM transitions beyond `OpenSent` →
//! `OpenConfirm` → `Established`, no timer enforcement, no graceful error
//! recovery. The scope is one-shot scale harnesses that open a session,
//! flood routes, and measure convergence.
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
use tokio::net::TcpStream;
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
    /// Target address (RR) to dial.
    pub target: SocketAddr,
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
    pub fn evpn_only(target: SocketAddr, local_as: u32, router_id: Ipv4Addr) -> Self {
        Self {
            target,
            local_as,
            router_id,
            hold_time: 90,
            families: vec![(Afi::L2Vpn, Safi::Evpn)],
        }
    }
}

/// Handle to a live BGP session. Provides a send channel for outbound
/// messages and a receive stream for inbound ones.
pub struct PeerHandle {
    /// Send messages to be written to the wire.
    pub tx: mpsc::Sender<Message>,
    /// Inbound messages decoded off the wire.
    pub rx: mpsc::Receiver<Message>,
    /// Time the session reached Established.
    pub established_at: Instant,
}

/// Dial, exchange OPEN, send initial KEEPALIVE, wait for Established,
/// then return a handle. The session continues in background tasks
/// (reader, writer, keepalive sender) until tx is dropped or rx drains.
///
/// # Errors
///
/// Returns a [`PeerError`] if the TCP connect, OPEN exchange, or initial
/// KEEPALIVE fails.
pub async fn establish(cfg: PeerConfig) -> Result<PeerHandle, PeerError> {
    let mut stream = TcpStream::connect(cfg.target).await?;

    // Send our OPEN first — simplifies the handshake; the peer will
    // respond in kind.
    let our_open = build_open(&cfg);
    let bytes = encode_message(&Message::Open(our_open))?;
    stream.write_all(&bytes).await?;

    // Read the peer's OPEN.
    let mut buf = BytesMut::with_capacity(4096);
    let _peer_open = read_expected_open(&mut stream, &mut buf).await?;

    // Send KEEPALIVE to confirm. At this point we treat the session as
    // Established (we skip hold-timer enforcement — this is a benchmark
    // tool, not a production peer).
    let ka = encode_message(&Message::Keepalive)?;
    stream.write_all(&ka).await?;

    let established_at = Instant::now();

    let (tx_out, mut tx_rx) = mpsc::channel::<Message>(1024);
    let (rx_tx, rx_out) = mpsc::channel::<Message>(65536);

    let (mut reader, mut writer) = stream.into_split();

    let hold = cfg.hold_time;
    let ka_interval = Duration::from_secs(u64::from(hold) / 3);

    // Writer task: pulls from tx, writes to socket, injects periodic KEEPALIVE.
    tokio::spawn(async move {
        let mut ka_tick = tokio::time::interval(ka_interval);
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
    });

    // Reader task: framed decode, push to rx_tx.
    tokio::spawn(async move {
        let mut frame_buf = BytesMut::with_capacity(65536);
        let mut tmp = [0u8; 8192];
        loop {
            match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => frame_buf.extend_from_slice(&tmp[..n]),
            }
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
        let addr: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let cfg = PeerConfig::evpn_only(addr, 65000, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.hold_time, 90);
        assert_eq!(cfg.families, vec![(Afi::L2Vpn, Safi::Evpn)]);
    }
}
