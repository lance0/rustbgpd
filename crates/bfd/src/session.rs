//! Single-hop asynchronous BFD session state machine (RFC 5880 §6.8), pure and
//! sans-IO. It consumes [`Event`]s and produces [`Action`]s; the actor owns the
//! sockets, the real clock, and transmit jitter. Demand mode, echo, and
//! authentication are out of scope for this implementation.

use crate::action::{Action, TimerKind};
use crate::event::Event;
use crate::packet::{ControlPacket, Diagnostic};
use crate::state::SessionState;

/// RFC 5880 §6.8.3: while the session is not Up, the transmit interval must be
/// at least one second so idle sessions consume negligible bandwidth.
pub const SLOW_TX_INTERVAL_US: u32 = 1_000_000;

/// Error constructing a [`Session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The local discriminator was zero. RFC 5880 §6.8.6 requires it to be
    /// non-zero, or every packet we emit is discarded by a compliant peer.
    #[error("local discriminator must be non-zero (RFC 5880 §6.8.6)")]
    ZeroDiscriminator,
}

/// Static configuration for a session. Intervals are in microseconds.
///
/// This implementation keeps the local intervals fixed for the session's life
/// (no runtime renegotiation beyond the slow→fast change when coming Up), which
/// keeps the Poll machinery to the bring-up case only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Our discriminator. Must be non-zero and unique per local session.
    pub local_discriminator: u32,
    /// Our desired minimum transmit interval once Up (microseconds).
    pub desired_min_tx_interval_us: u32,
    /// Our required minimum receive interval (microseconds).
    pub required_min_rx_interval_us: u32,
    /// Detection multiplier we advertise (clamped to at least 1).
    pub detect_mult: u8,
}

/// A BFD session. Construct with [`Session::new`]; drive with [`Session::handle`];
/// tear down with [`Session::administratively_down`].
#[derive(Debug, Clone)]
pub struct Session {
    cfg: SessionConfig,
    state: SessionState,
    local_diag: Diagnostic,
    remote_discriminator: u32,
    /// Peer's Required Min RX — bounds how fast *we* transmit.
    remote_min_rx_us: u32,
    /// Peer's last Desired Min TX — feeds our detection time.
    remote_desired_min_tx_us: u32,
    remote_detect_mult: u8,
    /// Whether any valid control packet has been received yet. Gates the
    /// detection timer (which can't be inferred from the remote's interval
    /// fields, since 0 is a legal advertisement).
    remote_seen: bool,
    /// We are running a Poll Sequence (sending `P` until we get an `F`).
    poll_in_progress: bool,
    /// Last transmit interval we asked the actor to arm (`None` = tx stopped).
    current_tx_interval_us: Option<u32>,
    /// Whether the most recent reason this session is not Up is the remote
    /// signaling `AdminDown` (vs a detection timeout or a remote-signaled
    /// `Down`). RFC 5882 §4.2: a client with its own liveness should take no
    /// control-protocol action on a remote `AdminDown`, so the BGP coupling uses
    /// this to distinguish "peer disabled BFD" from a genuine liveness failure.
    remote_admin_down: bool,
}

impl Session {
    /// Create a session in the `Down` state and arm the (slow) transmit timer.
    /// Returns the session and the initial actions the actor must perform.
    ///
    /// # Errors
    /// Returns [`SessionError::ZeroDiscriminator`] if `cfg.local_discriminator`
    /// is 0 — a non-zero discriminator is required by RFC 5880 §6.8.6 (the
    /// `DiscriminatorAllocator` guarantees it).
    pub fn new(mut cfg: SessionConfig) -> Result<(Session, Vec<Action>), SessionError> {
        if cfg.local_discriminator == 0 {
            return Err(SessionError::ZeroDiscriminator);
        }
        cfg.detect_mult = cfg.detect_mult.max(1);
        let tx = max(
            slow_or_fast(SessionState::Down, cfg.desired_min_tx_interval_us),
            1,
        );
        let session = Session {
            cfg,
            state: SessionState::Down,
            local_diag: Diagnostic::None,
            remote_discriminator: 0,
            // RFC 5880 §6.8.1: RemoteMinRxInterval is initialized to 1.
            remote_min_rx_us: 1,
            remote_desired_min_tx_us: 0,
            remote_detect_mult: 1,
            remote_seen: false,
            poll_in_progress: false,
            current_tx_interval_us: Some(tx),
            remote_admin_down: false,
        };
        let actions = vec![Action::StartTimer {
            kind: TimerKind::Tx,
            interval_us: tx,
        }];
        Ok((session, actions))
    }

    /// Current session state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Our local discriminator.
    #[must_use]
    pub fn local_discriminator(&self) -> u32 {
        self.cfg.local_discriminator
    }

    /// The discriminator we have learned for the remote end (0 until learned).
    #[must_use]
    pub fn remote_discriminator(&self) -> u32 {
        self.remote_discriminator
    }

    /// Whether this session is down because the remote signaled `AdminDown`
    /// (rather than a detection timeout or remote-signaled `Down`). RFC 5882
    /// §4.2: the BGP coupling uses this to avoid tearing a non-strict BGP
    /// session down when the peer merely disabled BFD administratively.
    #[must_use]
    pub fn remote_admin_down(&self) -> bool {
        self.remote_admin_down
    }

    /// Drive the state machine with a runtime event.
    #[must_use]
    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::PacketReceived(pkt) => self.on_packet(&pkt),
            Event::TxTimerExpires => self.on_tx_timer(),
            Event::DetectTimerExpires => self.on_detect_timer(),
        }
    }

    /// Administratively shut the session down: emit a final `AdminDown` packet
    /// so the peer goes Down promptly (RFC 5880 §6.8.16), then stop the timers.
    #[must_use]
    pub fn administratively_down(&mut self) -> Vec<Action> {
        if self.state == SessionState::AdminDown {
            return Vec::new();
        }
        let old = self.state;
        self.state = SessionState::AdminDown;
        self.local_diag = Diagnostic::AdministrativelyDown;
        // This is our own administrative shutdown, not the remote's.
        self.remote_admin_down = false;
        self.poll_in_progress = false;
        self.current_tx_interval_us = None;
        vec![
            Action::StateChanged {
                old,
                new: SessionState::AdminDown,
                diagnostic: self.local_diag,
            },
            Action::SendPacket(self.build_packet(false, false)),
            Action::StopTimer {
                kind: TimerKind::Tx,
            },
            Action::StopTimer {
                kind: TimerKind::Detect,
            },
        ]
    }

    fn on_packet(&mut self, pkt: &ControlPacket) -> Vec<Action> {
        // We never negotiate authentication, so a packet claiming it is discarded.
        if pkt.auth_present {
            return Vec::new();
        }
        // A session we have shut down ignores all incoming packets.
        if self.state == SessionState::AdminDown {
            return Vec::new();
        }

        // RFC 5880 §6.8.6 demultiplexing, before touching any session state:
        //  - a non-zero Your Discriminator must select *this* session;
        //  - a zero Your Discriminator is only valid while the sender is still
        //    Down/AdminDown (it hasn't learned us yet).
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.cfg.local_discriminator {
            return Vec::new();
        }
        if pkt.your_discriminator == 0
            && !matches!(pkt.state, SessionState::Down | SessionState::AdminDown)
        {
            return Vec::new();
        }

        self.remote_seen = true;
        self.remote_discriminator = pkt.my_discriminator;
        self.remote_min_rx_us = pkt.required_min_rx_interval;
        self.remote_desired_min_tx_us = pkt.desired_min_tx_interval;
        self.remote_detect_mult = pkt.detect_mult.max(1);

        let mut actions = Vec::new();

        // Poll/Final bookkeeping (RFC 5880 §6.8.6).
        if pkt.final_bit {
            self.poll_in_progress = false;
        }

        let old = self.state;
        self.apply_fsm(pkt.state);
        if self.state != old {
            // Coming Up changes our transmit rate (slow→fast); RFC 5880 §6.8.3
            // effects that via a Poll Sequence.
            if self.state == SessionState::Up {
                self.poll_in_progress = true;
            }
            actions.push(Action::StateChanged {
                old,
                new: self.state,
                diagnostic: self.local_diag,
            });
        }

        // Every received packet resets the detection timer (async mode).
        if let Some(detect) = self.detect_time_us() {
            actions.push(Action::StartTimer {
                kind: TimerKind::Detect,
                interval_us: detect,
            });
        }

        // Re-arm the transmit timer only when the interval actually changed.
        self.sync_tx_timer(&mut actions);

        // Respond to a Poll immediately with a Final, outside the tx timer.
        if pkt.poll {
            actions.push(Action::SendPacket(self.build_packet(false, true)));
        }

        actions
    }

    fn on_tx_timer(&mut self) -> Vec<Action> {
        if self.current_tx_interval_us.is_none() || self.state == SessionState::AdminDown {
            return Vec::new();
        }
        let interval = self.tx_interval_us();
        vec![
            Action::SendPacket(self.build_packet(self.poll_in_progress, false)),
            Action::StartTimer {
                kind: TimerKind::Tx,
                interval_us: interval,
            },
        ]
    }

    fn on_detect_timer(&mut self) -> Vec<Action> {
        // Only an established-ish session can time out; Down/AdminDown ignore it.
        if matches!(self.state, SessionState::Down | SessionState::AdminDown) {
            return Vec::new();
        }
        let old = self.state;
        self.state = SessionState::Down;
        self.local_diag = Diagnostic::ControlDetectionTimeExpired;
        // A detection timeout is a genuine liveness failure, not a remote
        // AdminDown — the BGP coupling must tear the session down.
        self.remote_admin_down = false;
        self.remote_discriminator = 0;
        self.poll_in_progress = false;
        let mut actions = vec![
            Action::StateChanged {
                old,
                new: SessionState::Down,
                diagnostic: self.local_diag,
            },
            Action::StopTimer {
                kind: TimerKind::Detect,
            },
        ];
        // Drop back to the slow transmit rate now that we are no longer Up.
        self.sync_tx_timer(&mut actions);
        actions
    }

    /// RFC 5880 §6.8.6 state transitions (async, no demand).
    fn apply_fsm(&mut self, received: SessionState) {
        // Track whether the remote is signaling AdminDown (RFC 5882 §4.2). This
        // reflects the last received remote state: true for AdminDown, false for
        // any liveness-bearing state (Down/Init/Up).
        self.remote_admin_down = received == SessionState::AdminDown;
        if received == SessionState::AdminDown {
            if self.state != SessionState::Down {
                self.local_diag = Diagnostic::NeighborSignaledDown;
                self.state = SessionState::Down;
            }
            return;
        }
        match self.state {
            SessionState::Down => match received {
                // Recovering: the most recent state change is now to Init/Up, so
                // the local diagnostic (RFC 5880 §6.8.1) is no longer the prior
                // failure cause. Clear it so a recovered session and its outgoing
                // packets don't keep reporting the stale "detection time expired"
                // / "neighbor signaled down".
                SessionState::Down => {
                    self.state = SessionState::Init;
                    self.local_diag = Diagnostic::None;
                }
                SessionState::Init => {
                    self.state = SessionState::Up;
                    self.local_diag = Diagnostic::None;
                }
                _ => {}
            },
            SessionState::Init => {
                if matches!(received, SessionState::Init | SessionState::Up) {
                    self.state = SessionState::Up;
                    self.local_diag = Diagnostic::None;
                }
            }
            SessionState::Up => {
                if received == SessionState::Down {
                    self.local_diag = Diagnostic::NeighborSignaledDown;
                    self.state = SessionState::Down;
                }
            }
            SessionState::AdminDown => {}
        }
    }

    /// Re-arm or stop the transmit timer if the computed interval changed.
    fn sync_tx_timer(&mut self, actions: &mut Vec<Action>) {
        let desired = self.desired_tx_interval();
        if desired != self.current_tx_interval_us {
            self.current_tx_interval_us = desired;
            match desired {
                Some(interval) => actions.push(Action::StartTimer {
                    kind: TimerKind::Tx,
                    interval_us: interval,
                }),
                None => actions.push(Action::StopTimer {
                    kind: TimerKind::Tx,
                }),
            }
        }
    }

    /// The transmit interval we should be using now, or `None` if the peer's
    /// Required Min RX is 0 (it wants no periodic packets, RFC 5880 §6.8.3).
    fn desired_tx_interval(&self) -> Option<u32> {
        if self.remote_min_rx_us == 0 {
            return None;
        }
        Some(self.tx_interval_us())
    }

    fn tx_interval_us(&self) -> u32 {
        let local = slow_or_fast(self.state, self.cfg.desired_min_tx_interval_us);
        max(max(local, self.remote_min_rx_us), 1)
    }

    /// Detection time (microseconds), or `None` before any packet has been
    /// received. RFC 5880 §6.8.4: `remote DetectMult × max(our RequiredMinRx,
    /// remote's last Desired Min TX)`. A peer may legitimately advertise a
    /// Desired Min TX of 0, so "have we heard from the peer" is tracked
    /// separately (`remote_seen`) rather than inferred from that field; the
    /// negotiated interval is clamped to ≥1 so the timer is never zero-duration.
    fn detect_time_us(&self) -> Option<u32> {
        if !self.remote_seen {
            return None;
        }
        let rx = max(
            self.cfg.required_min_rx_interval_us,
            self.remote_desired_min_tx_us,
        )
        .max(1);
        let detect = u64::from(self.remote_detect_mult) * u64::from(rx);
        Some(u32::try_from(detect).unwrap_or(u32::MAX))
    }

    fn build_packet(&self, poll: bool, final_bit: bool) -> ControlPacket {
        ControlPacket {
            diagnostic: self.local_diag,
            state: self.state,
            poll,
            final_bit,
            control_plane_independent: false,
            auth_present: false,
            demand: false,
            multipoint: false,
            detect_mult: self.cfg.detect_mult,
            my_discriminator: self.cfg.local_discriminator,
            your_discriminator: self.remote_discriminator,
            desired_min_tx_interval: slow_or_fast(self.state, self.cfg.desired_min_tx_interval_us),
            required_min_rx_interval: self.cfg.required_min_rx_interval_us,
            required_min_echo_rx_interval: 0,
        }
    }
}

/// The effective desired-min-tx for a state: the configured fast value once Up,
/// otherwise at least the slow floor (RFC 5880 §6.8.3).
fn slow_or_fast(state: SessionState, fast_us: u32) -> u32 {
    if state == SessionState::Up {
        fast_us
    } else {
        max(fast_us, SLOW_TX_INTERVAL_US)
    }
}

fn max(a: u32, b: u32) -> u32 {
    if a >= b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SessionConfig {
        SessionConfig {
            local_discriminator: 0x0000_00AA,
            desired_min_tx_interval_us: 300_000,
            required_min_rx_interval_us: 300_000,
            detect_mult: 3,
        }
    }

    /// A packet as if from a healthy peer in the given state.
    fn peer(state: SessionState, your_discr: u32) -> ControlPacket {
        ControlPacket {
            diagnostic: Diagnostic::None,
            state,
            poll: false,
            final_bit: false,
            control_plane_independent: false,
            auth_present: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            my_discriminator: 0x0000_00BB,
            your_discriminator: your_discr,
            desired_min_tx_interval: 300_000,
            required_min_rx_interval: 300_000,
            required_min_echo_rx_interval: 0,
        }
    }

    fn state_changes(actions: &[Action]) -> Vec<(SessionState, SessionState)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::StateChanged { old, new, .. } => Some((*old, *new)),
                _ => None,
            })
            .collect()
    }

    fn sent(actions: &[Action]) -> Vec<&ControlPacket> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendPacket(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn new_session_starts_down_and_arms_slow_tx() {
        let (s, actions) = Session::new(cfg()).expect("non-zero discriminator");
        assert_eq!(s.state(), SessionState::Down);
        assert_eq!(
            actions,
            vec![Action::StartTimer {
                kind: TimerKind::Tx,
                interval_us: SLOW_TX_INTERVAL_US
            }]
        );
    }

    #[test]
    fn three_way_handshake_down_then_init_then_up() {
        let (mut s, _) = Session::new(cfg()).expect("non-zero discriminator");

        // Peer is Down → we go Down→Init.
        let a1 = s.handle(Event::PacketReceived(peer(SessionState::Down, 0)));
        assert_eq!(s.state(), SessionState::Init);
        assert_eq!(
            state_changes(&a1),
            vec![(SessionState::Down, SessionState::Init)]
        );
        // We learned the peer discriminator.
        assert_eq!(s.remote_discriminator(), 0x0000_00BB);

        // Peer now reflects Init → we go Init→Up and start a Poll.
        let a2 = s.handle(Event::PacketReceived(peer(SessionState::Init, 0x0000_00AA)));
        assert_eq!(s.state(), SessionState::Up);
        assert_eq!(
            state_changes(&a2),
            vec![(SessionState::Init, SessionState::Up)]
        );
        // Coming Up drops us to the fast transmit rate.
        assert!(a2.iter().any(|a| matches!(
            a,
            Action::StartTimer {
                kind: TimerKind::Tx,
                interval_us: 300_000
            }
        )));
        // And it resets the detection timer to detect_mult × negotiated rx.
        assert!(a2.iter().any(|a| matches!(
            a,
            Action::StartTimer {
                kind: TimerKind::Detect,
                interval_us: 900_000
            }
        )));
    }

    #[test]
    fn detection_timeout_brings_session_down_and_slows_tx() {
        let (mut s, _) = bring_up();
        let actions = s.handle(Event::DetectTimerExpires);
        assert_eq!(s.state(), SessionState::Down);
        assert_eq!(
            state_changes(&actions),
            vec![(SessionState::Up, SessionState::Down)]
        );
        // Back to the slow transmit rate.
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::StartTimer {
                kind: TimerKind::Tx,
                interval_us: SLOW_TX_INTERVAL_US
            }
        )));
        // Sent packets now carry the control-detection-time-expired diagnostic.
        let next = s.handle(Event::TxTimerExpires);
        assert_eq!(
            sent(&next)[0].diagnostic,
            Diagnostic::ControlDetectionTimeExpired
        );
    }

    #[test]
    fn neighbor_admin_down_takes_us_down() {
        let (mut s, _) = bring_up();
        let actions = s.handle(Event::PacketReceived(peer(
            SessionState::AdminDown,
            0x0000_00AA,
        )));
        assert_eq!(s.state(), SessionState::Down);
        assert_eq!(
            state_changes(&actions),
            vec![(SessionState::Up, SessionState::Down)]
        );
        let next = s.handle(Event::TxTimerExpires);
        assert_eq!(sent(&next)[0].diagnostic, Diagnostic::NeighborSignaledDown);
    }

    #[test]
    fn responds_to_poll_with_an_immediate_final() {
        let (mut s, _) = bring_up();
        let mut polled = peer(SessionState::Up, 0x0000_00AA);
        polled.poll = true;
        let actions = s.handle(Event::PacketReceived(polled));
        let finals: Vec<_> = sent(&actions)
            .into_iter()
            .filter(|p| p.final_bit && !p.poll)
            .collect();
        assert_eq!(finals.len(), 1, "exactly one Final response");
    }

    #[test]
    fn periodic_tx_carries_poll_until_final_received() {
        let (mut s, _) = bring_up();
        // After coming Up a Poll Sequence is in progress.
        let tx1 = s.handle(Event::TxTimerExpires);
        assert!(sent(&tx1)[0].poll, "tx carries Poll during the sequence");

        // Peer answers with Final → Poll Sequence ends.
        let mut fin = peer(SessionState::Up, 0x0000_00AA);
        fin.final_bit = true;
        let _ = s.handle(Event::PacketReceived(fin));
        let tx2 = s.handle(Event::TxTimerExpires);
        assert!(!sent(&tx2)[0].poll, "Poll cleared after Final");
    }

    #[test]
    fn administratively_down_emits_admindown_packet_and_stops_timers() {
        let (mut s, _) = bring_up();
        let actions = s.administratively_down();
        assert_eq!(s.state(), SessionState::AdminDown);
        let pkt = sent(&actions)[0];
        assert_eq!(pkt.state, SessionState::AdminDown);
        assert_eq!(pkt.diagnostic, Diagnostic::AdministrativelyDown);
        assert!(actions.contains(&Action::StopTimer {
            kind: TimerKind::Tx
        }));
        assert!(actions.contains(&Action::StopTimer {
            kind: TimerKind::Detect
        }));
        // A shut-down session ignores further packets.
        assert!(
            s.handle(Event::PacketReceived(peer(SessionState::Up, 0x0000_00AA)))
                .is_empty()
        );
    }

    #[test]
    fn down_session_ignores_spurious_detect_timer() {
        let (mut s, _) = Session::new(cfg()).expect("non-zero discriminator");
        assert!(s.handle(Event::DetectTimerExpires).is_empty());
        assert_eq!(s.state(), SessionState::Down);
    }

    #[test]
    fn discards_packet_addressed_to_a_different_session() {
        let (mut s, _) = bring_up();
        // A packet whose Your Discriminator is some other session's local id is
        // not for us: no actions, no state change, remote discr unchanged.
        let mut stray = peer(SessionState::Down, 0x0000_0099);
        stray.my_discriminator = 0x0000_0CCC;
        assert!(s.handle(Event::PacketReceived(stray)).is_empty());
        assert_eq!(s.state(), SessionState::Up);
        assert_eq!(s.remote_discriminator(), 0x0000_00BB);
    }

    #[test]
    fn zero_local_discriminator_is_rejected() {
        let mut bad = cfg();
        bad.local_discriminator = 0;
        assert!(matches!(
            Session::new(bad),
            Err(SessionError::ZeroDiscriminator)
        ));
    }

    #[test]
    fn detection_arms_even_when_peer_advertises_zero_desired_min_tx() {
        let (mut s, _) = Session::new(cfg()).expect("non-zero discriminator");
        // A peer may legitimately advertise Desired Min TX = 0; detection must
        // still arm, falling back to our Required Min RX (300_000) × the peer's
        // detect_mult (3) = 900_000.
        let mut p = peer(SessionState::Down, 0);
        p.desired_min_tx_interval = 0;
        let actions = s.handle(Event::PacketReceived(p));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::StartTimer {
                kind: TimerKind::Detect,
                interval_us: 900_000
            }
        )));
    }

    #[test]
    fn discards_zero_your_discriminator_unless_sender_is_down() {
        let (mut s, _) = Session::new(cfg()).expect("non-zero discriminator");
        // Your Discriminator 0 is only valid while the sender is Down/AdminDown;
        // an Up/Init packet with Your Discr 0 must be ignored.
        assert!(
            s.handle(Event::PacketReceived(peer(SessionState::Up, 0)))
                .is_empty()
        );
        assert_eq!(s.state(), SessionState::Down);
        // The legitimate bootstrap (Down, Your Discr 0) is accepted.
        let actions = s.handle(Event::PacketReceived(peer(SessionState::Down, 0)));
        assert_eq!(s.state(), SessionState::Init);
        assert!(!actions.is_empty());
    }

    /// Bring a fresh session to Up (Down→Init→Up) and return it.
    fn bring_up() -> (Session, Vec<Action>) {
        let (mut s, _) = Session::new(cfg()).expect("non-zero discriminator");
        let _ = s.handle(Event::PacketReceived(peer(SessionState::Down, 0)));
        let actions = s.handle(Event::PacketReceived(peer(SessionState::Init, 0x0000_00AA)));
        assert_eq!(s.state(), SessionState::Up);
        (s, actions)
    }

    fn first_state_change_diag(actions: &[Action]) -> Option<Diagnostic> {
        actions.iter().find_map(|a| match a {
            Action::StateChanged { diagnostic, .. } => Some(*diagnostic),
            _ => None,
        })
    }

    #[test]
    fn recovery_clears_stale_failure_diagnostic() {
        // A detection timeout sets the local diagnostic to "detection time
        // expired".
        let (mut s, _) = bring_up();
        let down = s.handle(Event::DetectTimerExpires);
        assert_eq!(s.state(), SessionState::Down);
        assert_eq!(
            first_state_change_diag(&down),
            Some(Diagnostic::ControlDetectionTimeExpired)
        );

        // Recovering Down→Init→Up must clear the diagnostic so the recovered
        // state — and the session's outgoing packets — stop reporting the stale
        // failure cause (RFC 5880 §6.8.1: the diagnostic reflects the *most
        // recent* state change).
        let init = s.handle(Event::PacketReceived(peer(SessionState::Down, 0)));
        assert_eq!(s.state(), SessionState::Init);
        assert_eq!(
            first_state_change_diag(&init),
            Some(Diagnostic::None),
            "Down→Init clears the failure diagnostic"
        );

        let up = s.handle(Event::PacketReceived(peer(SessionState::Init, 0x0000_00AA)));
        assert_eq!(s.state(), SessionState::Up);
        assert!(state_changes(&up).contains(&(SessionState::Init, SessionState::Up)));
        assert_eq!(
            sent(&s.handle(Event::TxTimerExpires))[0].diagnostic,
            Diagnostic::None,
            "recovered Up packets carry no stale diagnostic"
        );
    }
}
