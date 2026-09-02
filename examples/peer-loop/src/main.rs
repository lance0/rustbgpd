//! Minimal BGP speaker whose rustbgpd dependencies are `rustbgpd-wire` and
//! `rustbgpd-fsm`.
//!
//! The FSM owns no I/O. This binary owns the TCP socket and the timers, turns
//! socket and timer outcomes into [`Event`]s, and handles the required
//! [`Action`]s the FSM hands back. It dials one peer, negotiates IPv4 unicast,
//! answers the keepalive timer, prints successfully parsed UPDATEs, and exits
//! non-zero when the session ends: NOTIFICATION, hold-timer expiry, or a closed
//! connection.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use clap::Parser;
use rustbgpd_fsm::{Action, Event, PeerConfig, Session, TimerType};
use rustbgpd_wire::{
    Afi, BgpCodec, BgpCodecError, EXTENDED_MAX_MESSAGE_LEN, Message, NotificationMessage,
    PathAttribute, Safi, UpdateMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until};
use tokio_util::codec::{Decoder, Encoder};

/// Dial one BGP peer, drive the session to Established, and print parsed UPDATEs.
#[derive(Parser)]
struct Args {
    /// Peer IP address.
    #[arg(long)]
    peer: IpAddr,
    /// Peer TCP port.
    #[arg(long, default_value_t = 179, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Local autonomous system number.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    local_asn: u32,
    /// Expected peer autonomous system number.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    remote_asn: u32,
    /// Local BGP identifier.
    #[arg(long, value_parser = parse_router_id)]
    router_id: Ipv4Addr,
    /// Proposed hold time in seconds; 0 disables the hold and keepalive timers.
    #[arg(long, default_value_t = 90, value_parser = parse_hold_time)]
    hold_time: u16,
}

fn parse_router_id(value: &str) -> Result<Ipv4Addr, String> {
    let router_id = value
        .parse::<Ipv4Addr>()
        .map_err(|error| error.to_string())?;
    if router_id.is_unspecified() {
        Err("router ID must not be 0.0.0.0".to_string())
    } else {
        Ok(router_id)
    }
}

fn parse_hold_time(value: &str) -> Result<u16, String> {
    let hold_time = value.parse::<u16>().map_err(|error| error.to_string())?;
    if hold_time == 0 || hold_time >= 3 {
        Ok(hold_time)
    } else {
        Err("hold time must be 0 or at least 3 seconds".to_string())
    }
}

/// Why the session ended. Every variant is a non-zero exit for the binary.
#[derive(Debug)]
enum SessionEnd {
    Notification(NotificationMessage),
    NotificationSent(NotificationMessage),
    HoldTimerExpired,
    ConnectionClosed,
    Codec(BgpCodecError),
}

impl fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Notification(n) => {
                write!(f, "NOTIFICATION received: {} subcode {}", n.code, n.subcode)
            }
            Self::NotificationSent(n) => {
                write!(f, "NOTIFICATION sent: {} subcode {}", n.code, n.subcode)
            }
            Self::HoldTimerExpired => f.write_str("hold timer expired"),
            Self::ConnectionClosed => f.write_str("peer closed the connection"),
            Self::Codec(e) => write!(f, "codec error: {e}"),
        }
    }
}

impl std::error::Error for SessionEnd {}

impl From<BgpCodecError> for SessionEnd {
    fn from(error: BgpCodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<std::io::Error> for SessionEnd {
    fn from(error: std::io::Error) -> Self {
        Self::Codec(error.into())
    }
}

/// Everything the embedder owns around the pure FSM: framing, timers, and the
/// negotiated facts the UPDATE parser needs.
struct Speaker {
    session: Session,
    codec: BgpCodec,
    inbound: BytesMut,
    hold_deadline: Option<Instant>,
    keepalive_deadline: Option<Instant>,
    four_octet_as: bool,
}

impl Speaker {
    /// Feed one event to the FSM and handle the actions it returns.
    async fn dispatch(
        &mut self,
        event: Event,
        stream: &mut TcpStream,
        sink: &mut dyn FnMut(String),
    ) -> Result<(), SessionEnd> {
        let mut ending = match &event {
            Event::NotificationReceived(n) => Some(SessionEnd::Notification(n.clone())),
            Event::HoldTimerExpires => Some(SessionEnd::HoldTimerExpired),
            Event::DecodeError(e) => Some(SessionEnd::Codec(e.clone().into())),
            _ => None,
        };
        let mut close = false;
        for action in self.session.handle_event(event) {
            match action {
                Action::SendOpen(open) => {
                    self.send(stream, Message::Open(open)).await?;
                    self.codec
                        .set_inbound_max_message_len(EXTENDED_MAX_MESSAGE_LEN);
                }
                Action::SendKeepalive => self.send(stream, Message::Keepalive).await?,
                Action::SendNotification(notification) => {
                    // On the way out the peer may already be gone, so a failed
                    // NOTIFICATION write must not hide the real reason.
                    let sent = self
                        .send(stream, Message::Notification(notification.clone()))
                        .await;
                    if ending.is_none() {
                        sent?;
                        ending = Some(SessionEnd::NotificationSent(notification));
                    }
                }
                Action::StartTimer(TimerType::Hold, secs) => {
                    self.hold_deadline = Some(deadline(secs))
                }
                Action::StartTimer(TimerType::Keepalive, secs) => {
                    self.keepalive_deadline = Some(deadline(secs));
                }
                Action::StopTimer(TimerType::Hold) => self.hold_deadline = None,
                Action::StopTimer(TimerType::Keepalive) => self.keepalive_deadline = None,
                Action::StateChanged { old, new } => sink(format!("state {old:?} -> {new:?}")),
                Action::SessionEstablished(negotiated) => {
                    if negotiated.peer_extended_message {
                        self.codec
                            .set_outbound_max_message_len(EXTENDED_MAX_MESSAGE_LEN);
                    }
                    self.four_octet_as = negotiated.four_octet_as;
                    sink(format!(
                        "established peer-as={} peer-id={} hold={}s keepalive={}s families={:?}",
                        negotiated.peer_asn,
                        negotiated.peer_router_id,
                        negotiated.hold_time,
                        negotiated.keepalive_interval,
                        negotiated.negotiated_families
                    ));
                }
                Action::CloseTcpConnection => close = true,
                // The socket is already open and never reconnects, so the
                // connect and ConnectRetry actions have nothing to do here.
                // `Action` and `TimerType` are non-exhaustive.
                _ => {}
            }
        }
        if close {
            Err(ending.unwrap_or(SessionEnd::ConnectionClosed))
        } else {
            Ok(())
        }
    }

    async fn send(&mut self, stream: &mut TcpStream, message: Message) -> Result<(), SessionEnd> {
        let mut out = BytesMut::new();
        self.codec.encode(message, &mut out)?;
        stream.write_all(&out).await?;
        Ok(())
    }

    /// Print the UPDATE and turn it into the FSM event. A malformed UPDATE
    /// becomes a decode error so the FSM sends the RFC 4271 NOTIFICATION.
    fn update_event(&self, update: &UpdateMessage, sink: &mut dyn FnMut(String)) -> Event {
        match update.parse(self.four_octet_as, false, &[]) {
            Ok(parsed) => {
                let announced = join(
                    parsed
                        .announced
                        .iter()
                        .map(|entry| entry.prefix.to_string()),
                );
                let withdrawn = join(
                    parsed
                        .withdrawn
                        .iter()
                        .map(|entry| entry.prefix.to_string()),
                );
                let attributes = join(parsed.attributes.iter().map(summarize));
                sink(format!(
                    "update announced=[{announced}] withdrawn=[{withdrawn}] attributes=[{attributes}]"
                ));
                Event::UpdateReceived
            }
            Err(error) => Event::DecodeError(error),
        }
    }

    fn message_event(&self, message: Message, sink: &mut dyn FnMut(String)) -> Option<Event> {
        match message {
            Message::Open(open) => Some(Event::OpenReceived(open)),
            Message::Keepalive => Some(Event::KeepaliveReceived),
            Message::Update(update) => Some(self.update_event(&update, sink)),
            Message::Notification(notification) => Some(Event::NotificationReceived(notification)),
            Message::RouteRefresh(refresh) => refresh
                .afi()
                .zip(refresh.safi())
                .map(|(afi, safi)| Event::RouteRefreshReceived { afi, safi }),
            // `Message` is non-exhaustive. A future message type must not be
            // misclassified as KEEPALIVE and refresh the hold timer.
            _ => None,
        }
    }
}

fn deadline(secs: u32) -> Instant {
    Instant::now() + Duration::from_secs(u64::from(secs))
}

fn join(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(" ")
}

fn summarize(attribute: &PathAttribute) -> String {
    match attribute {
        PathAttribute::Origin(origin) => format!("origin={origin}"),
        PathAttribute::AsPath(path) => {
            format!("as-path=[{}]", join(path.asns().map(|asn| asn.to_string())))
        }
        PathAttribute::NextHop(next_hop) => format!("next-hop={next_hop}"),
        PathAttribute::Med(med) => format!("med={med}"),
        PathAttribute::LocalPref(pref) => format!("local-pref={pref}"),
        PathAttribute::Communities(list) => format!(
            "communities=[{}]",
            join(list.iter().map(|c| format!("{}:{}", c >> 16, c & 0xffff)))
        ),
        other => format!("attr{}", other.type_code()),
    }
}

/// Read one framed message; EOF ends the session.
async fn read_message(
    stream: &mut TcpStream,
    codec: &mut BgpCodec,
    inbound: &mut BytesMut,
) -> Result<Message, SessionEnd> {
    loop {
        if let Some(message) = codec.decode(inbound)? {
            return Ok(message);
        }
        if stream.read_buf(inbound).await? == 0 {
            return Err(SessionEnd::ConnectionClosed);
        }
    }
}

/// Run one session over a connected socket until it ends. Every
/// operator-visible line goes through `sink` so a test can capture it.
async fn run(
    mut stream: TcpStream,
    config: PeerConfig,
    sink: &mut dyn FnMut(String),
) -> SessionEnd {
    let mut speaker = Speaker {
        session: Session::new(config),
        codec: BgpCodec::new(),
        inbound: BytesMut::with_capacity(4096),
        hold_deadline: None,
        keepalive_deadline: None,
        four_octet_as: false,
    };
    // The socket is already connected, so Connect is entered and left at once.
    for event in [Event::ManualStart, Event::TcpConnectionConfirmed] {
        if let Err(end) = speaker.dispatch(event, &mut stream, sink).await {
            return end;
        }
    }
    loop {
        let event = tokio::select! {
            received = read_message(&mut stream, &mut speaker.codec, &mut speaker.inbound) => {
                match received {
                    Ok(message) => match speaker.message_event(message, sink) {
                        Some(event) => event,
                        None => continue,
                    },
                    Err(SessionEnd::Codec(BgpCodecError::Decode(error))) => Event::DecodeError(error),
                    Err(end) => return end,
                }
            }
            () = sleep_until(speaker.hold_deadline.unwrap_or_else(Instant::now)),
                if speaker.hold_deadline.is_some() => Event::HoldTimerExpires,
            () = sleep_until(speaker.keepalive_deadline.unwrap_or_else(Instant::now)),
                if speaker.keepalive_deadline.is_some() => Event::KeepaliveTimerExpires,
        };
        if let Err(end) = speaker.dispatch(event, &mut stream, sink).await {
            return end;
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = PeerConfig::new(args.local_asn, args.remote_asn, args.router_id);
    config.hold_time = args.hold_time;
    config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let stream = TcpStream::connect(SocketAddr::new(args.peer, args.port)).await?;
    println!("connected to {}", stream.peer_addr()?);
    Err(run(stream, config, &mut |line| println!("{line}"))
        .await
        .into())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rustbgpd_wire::{
        AsPath, AsPathSegment, Capability, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode,
        MAX_MESSAGE_LEN, NotificationCode, OpenMessage, Origin, RouteRefreshMessage,
    };
    use tokio::net::TcpListener;

    use super::*;

    const PEER_ASN: u16 = 65_002;
    const PEER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    /// Hand-driven responder from the same crates: wire framing only, no FSM.
    struct Responder {
        stream: TcpStream,
        codec: BgpCodec,
        inbound: BytesMut,
    }

    impl Responder {
        async fn accept(listener: TcpListener) -> Self {
            let (stream, _) = listener.accept().await.unwrap();
            Self {
                stream,
                codec: BgpCodec::new(),
                inbound: BytesMut::new(),
            }
        }

        async fn send(&mut self, message: Message) {
            let mut out = BytesMut::new();
            self.codec.encode(message, &mut out).unwrap();
            self.stream.write_all(&out).await.unwrap();
        }

        async fn recv(&mut self) -> Message {
            read_message(&mut self.stream, &mut self.codec, &mut self.inbound)
                .await
                .unwrap()
        }

        /// Complete the OPEN/KEEPALIVE handshake proposing a 3-second hold time,
        /// which negotiates a 1-second keepalive interval on the speaker.
        async fn establish(&mut self) {
            self.send(Message::Open(OpenMessage {
                version: 4,
                my_as: PEER_ASN,
                hold_time: 3,
                bgp_identifier: PEER_ID,
                capabilities: vec![
                    Capability::MultiProtocol {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                    },
                    Capability::FourOctetAs {
                        asn: u32::from(PEER_ASN),
                    },
                ],
            }))
            .await;
            assert!(matches!(self.recv().await, Message::Open(_)));
            self.send(Message::Keepalive).await;
            assert!(matches!(self.recv().await, Message::Keepalive));
        }
    }

    async fn speak_to(addr: SocketAddr) -> (SessionEnd, Vec<String>) {
        let mut config = PeerConfig::new(65_001, u32::from(PEER_ASN), Ipv4Addr::new(10, 0, 0, 1));
        config.hold_time = 3;
        config.families = vec![(Afi::Ipv4, Safi::Unicast)];
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut lines = Vec::new();
        let end = run(stream, config, &mut |line| lines.push(line)).await;
        (end, lines)
    }

    #[test]
    fn cli_rejects_invalid_protocol_values() {
        let base = [
            "peer-loop",
            "--peer",
            "192.0.2.1",
            "--port",
            "179",
            "--local-asn",
            "65001",
            "--remote-asn",
            "65002",
            "--router-id",
            "192.0.2.2",
            "--hold-time",
            "90",
        ];
        for (flag, value) in [
            ("--port", "0"),
            ("--local-asn", "0"),
            ("--remote-asn", "0"),
            ("--router-id", "0.0.0.0"),
            ("--hold-time", "1"),
            ("--hold-time", "2"),
        ] {
            let mut args = base;
            let index = args.iter().position(|arg| *arg == flag).unwrap();
            args[index + 1] = value;
            assert!(
                Args::try_parse_from(args).is_err(),
                "accepted {flag}={value}"
            );
        }
        for hold_time in ["0", "3", "65535"] {
            let mut args = base;
            args[12] = hold_time;
            assert!(
                Args::try_parse_from(args).is_ok(),
                "rejected --hold-time={hold_time}"
            );
        }
    }

    #[test]
    fn route_refresh_mapping_preserves_known_families_and_ignores_unknown_ones() {
        let speaker = Speaker {
            session: Session::new(PeerConfig::default()),
            codec: BgpCodec::new(),
            inbound: BytesMut::new(),
            hold_deadline: None,
            keepalive_deadline: None,
            four_octet_as: false,
        };
        let mut sink = |_| {};
        assert!(matches!(
            speaker.message_event(
                Message::RouteRefresh(RouteRefreshMessage::new(Afi::Ipv6, Safi::Unicast)),
                &mut sink
            ),
            Some(Event::RouteRefreshReceived {
                afi: Afi::Ipv6,
                safi: Safi::Unicast
            })
        ));
        let mut unknown = RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast);
        unknown.afi_raw = u16::MAX;
        assert!(
            speaker
                .message_event(Message::RouteRefresh(unknown), &mut sink)
                .is_none()
        );
    }

    #[tokio::test]
    async fn extended_message_limits_follow_directional_negotiation() {
        for peer_extended in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_server, _) = listener.accept().await.unwrap();
            let mut config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
            config.families = vec![(Afi::Ipv4, Safi::Unicast)];
            let mut speaker = Speaker {
                session: Session::new(config),
                codec: BgpCodec::new(),
                inbound: BytesMut::new(),
                hold_deadline: None,
                keepalive_deadline: None,
                four_octet_as: false,
            };
            let mut sink = |_| {};
            speaker
                .dispatch(Event::ManualStart, &mut client, &mut sink)
                .await
                .unwrap();
            speaker
                .dispatch(Event::TcpConnectionConfirmed, &mut client, &mut sink)
                .await
                .unwrap();
            assert_eq!(
                speaker.codec.inbound_max_message_len(),
                EXTENDED_MAX_MESSAGE_LEN
            );
            assert_eq!(speaker.codec.outbound_max_message_len(), MAX_MESSAGE_LEN);
            let mut capabilities = vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65_002 },
            ];
            if peer_extended {
                capabilities.push(Capability::ExtendedMessage);
            }
            speaker
                .dispatch(
                    Event::OpenReceived(OpenMessage {
                        version: 4,
                        my_as: 65_002,
                        hold_time: 90,
                        bgp_identifier: PEER_ID,
                        capabilities,
                    }),
                    &mut client,
                    &mut sink,
                )
                .await
                .unwrap();
            speaker
                .dispatch(Event::KeepaliveReceived, &mut client, &mut sink)
                .await
                .unwrap();
            assert_eq!(
                speaker.codec.inbound_max_message_len(),
                EXTENDED_MAX_MESSAGE_LEN
            );
            assert_eq!(
                speaker.codec.outbound_max_message_len(),
                if peer_extended {
                    EXTENDED_MAX_MESSAGE_LEN
                } else {
                    MAX_MESSAGE_LEN
                }
            );
        }
    }

    #[tokio::test]
    async fn establishes_prints_one_update_and_exits_on_notification() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut peer = Responder::accept(listener).await;
            peer.establish().await;
            // The speaker's own keepalive timer must fire without prompting.
            assert!(matches!(peer.recv().await, Message::Keepalive));
            let update = UpdateMessage::try_build(
                &[Ipv4NlriEntry {
                    path_id: 0,
                    prefix: Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
                }],
                &[],
                &[
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![u32::from(PEER_ASN)])],
                    }),
                    PathAttribute::NextHop(PEER_ID),
                ],
                true,
                false,
                Ipv4UnicastMode::Body,
            )
            .unwrap();
            peer.send(Message::Update(update)).await;
            peer.send(Message::Notification(NotificationMessage {
                code: NotificationCode::Cease,
                subcode: 2, // Administrative Shutdown
                data: Bytes::new(),
            }))
            .await;
        });

        let (end, lines) = speak_to(addr).await;
        responder.await.unwrap();

        assert!(
            matches!(end, SessionEnd::Notification(ref n) if n.code == NotificationCode::Cease),
            "{end:?}"
        );
        assert!(
            lines.iter().any(|line| line
                == "established peer-as=65002 peer-id=10.0.0.2 hold=3s keepalive=1s families=[(Ipv4, Unicast)]"),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line
                == "update announced=[198.51.100.0/24] withdrawn=[] attributes=[origin=IGP as-path=[65002] next-hop=10.0.0.2]"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn exits_on_hold_timer_expiry_after_sending_the_notification() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut peer = Responder::accept(listener).await;
            peer.establish().await;
            // Stay silent; skip the speaker's keepalives until its hold timer fires.
            loop {
                match peer.recv().await {
                    Message::Keepalive => {}
                    Message::Notification(n) => {
                        assert_eq!(n.code, NotificationCode::HoldTimerExpired);
                        break;
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        });

        let (end, lines) = speak_to(addr).await;
        responder.await.unwrap();

        assert!(matches!(end, SessionEnd::HoldTimerExpired), "{end:?}");
        assert!(
            lines.iter().any(|line| line.starts_with("established ")),
            "{lines:?}"
        );
    }
}
