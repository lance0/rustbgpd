use bytes::Bytes;

use rustbgpd_wire::OpenMessage;
use rustbgpd_wire::notification::NotificationCode;

use crate::action::{Action, NegotiatedSession, TimerType};
use crate::config::PeerConfig;
use crate::event::Event;
use crate::negotiation::validate_open;
use crate::state::SessionState;

/// Maximum connect-retry backoff in seconds.
const MAX_RETRY_SECS: u32 = 300;

/// Initial hold timer before OPEN negotiation (RFC 4271: "large value").
const INITIAL_HOLD_SECS: u32 = 240;

/// The BGP finite state machine for a single peer session.
///
/// Pure state machine — `(State, Event) → (State, Vec<Action>)`.
/// No I/O, no timers, no async runtime.
#[derive(Debug)]
pub struct Session {
    state: SessionState,
    config: PeerConfig,
    negotiated: Option<NegotiatedSession>,
    connect_retry_counter: u32,
}

impl Session {
    /// Create a new session in the `Idle` state.
    #[must_use]
    pub fn new(config: PeerConfig) -> Self {
        Self {
            state: SessionState::Idle,
            config,
            negotiated: None,
            connect_retry_counter: 0,
        }
    }

    /// Current FSM state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Negotiated session parameters (available after `OpenConfirm`).
    #[must_use]
    pub fn negotiated(&self) -> Option<&NegotiatedSession> {
        self.negotiated.as_ref()
    }

    /// Current connect-retry counter (for diagnostics).
    #[must_use]
    pub fn connect_retry_counter(&self) -> u32 {
        self.connect_retry_counter
    }

    /// Process an event and return the resulting actions.
    ///
    /// This method never fails — every `(State, Event)` pair produces a
    /// well-defined list of actions.  Invalid combinations result in a
    /// transition to Idle with an appropriate NOTIFICATION.
    pub fn handle_event(&mut self, event: Event) -> Vec<Action> {
        match self.state {
            SessionState::Idle => self.handle_idle(event),
            SessionState::Connect => self.handle_connect(event),
            SessionState::Active => self.handle_active(event),
            SessionState::OpenSent => self.handle_open_sent(event),
            SessionState::OpenConfirm => self.handle_open_confirm(event),
            SessionState::Established => self.handle_established(event),
        }
    }

    // ── Per-state handlers ─────────────────────────────────────────────

    #[expect(clippy::needless_pass_by_value)]
    fn handle_idle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStart => {
                self.connect_retry_counter = 0;
                let mut actions = vec![
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                    Action::InitiateTcpConnection,
                ];
                actions.push(self.transition_to(SessionState::Connect));
                actions
            }
            // RFC 4271: In Idle, all other events are ignored.
            _ => vec![],
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    fn handle_connect(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop => self.enter_idle_silent(),

            Event::ConnectRetryTimerExpires => {
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                    Action::InitiateTcpConnection,
                ];
                actions.push(self.transition_to(SessionState::Connect));
                actions
            }

            Event::TcpConnectionConfirmed | Event::TcpConnectionAcknowledged => {
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::SendOpen(self.build_open()),
                    Action::StartTimer(TimerType::Hold, INITIAL_HOLD_SECS),
                ];
                actions.push(self.transition_to(SessionState::OpenSent));
                actions
            }

            Event::TcpConnectionFails => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                ];
                actions.push(self.transition_to(SessionState::Active));
                actions
            }

            // Decode errors on the wire → close and go to Idle
            Event::DecodeError(_) => {
                self.connect_retry_counter += 1;
                self.enter_idle_silent()
            }

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    fn handle_active(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop => self.enter_idle_silent(),

            Event::ConnectRetryTimerExpires => {
                let mut actions = vec![
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                    Action::InitiateTcpConnection,
                ];
                actions.push(self.transition_to(SessionState::Connect));
                actions
            }

            Event::TcpConnectionConfirmed | Event::TcpConnectionAcknowledged => {
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::SendOpen(self.build_open()),
                    Action::StartTimer(TimerType::Hold, INITIAL_HOLD_SECS),
                ];
                actions.push(self.transition_to(SessionState::OpenSent));
                actions
            }

            Event::TcpConnectionFails => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                ];
                actions.push(self.transition_to(SessionState::Active));
                actions
            }

            Event::DecodeError(_) => {
                self.connect_retry_counter += 1;
                self.enter_idle_silent()
            }

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    fn handle_open_sent(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop => {
                self.enter_idle_with_notification(NotificationCode::Cease, 0, Bytes::new())
            }

            Event::HoldTimerExpires => self.enter_idle_with_notification(
                NotificationCode::HoldTimerExpired,
                0,
                Bytes::new(),
            ),

            Event::TcpConnectionFails => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                ];
                actions.push(self.transition_to(SessionState::Active));
                actions
            }

            Event::OpenReceived(open) => match validate_open(&open, &self.config) {
                Ok(neg) => {
                    let hold = u32::from(neg.hold_time);
                    let ka = u32::from(neg.keepalive_interval);
                    self.negotiated = Some(neg);
                    let mut actions = vec![Action::SendKeepalive];
                    if hold > 0 {
                        actions.push(Action::StartTimer(TimerType::Hold, hold));
                        actions.push(Action::StartTimer(TimerType::Keepalive, ka));
                    } else {
                        actions.push(Action::StopTimer(TimerType::Hold));
                    }
                    actions.push(self.transition_to(SessionState::OpenConfirm));
                    actions
                }
                Err(notification) => {
                    self.connect_retry_counter += 1;
                    let mut actions = vec![
                        Action::SendNotification(notification),
                        Action::CloseTcpConnection,
                        Action::StopTimer(TimerType::Hold),
                    ];
                    actions.push(self.transition_to(SessionState::Idle));
                    actions
                }
            },

            Event::NotificationReceived(_) => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::DecodeError(ref e) => {
                let (code, subcode, data) = e.to_notification();
                self.connect_retry_counter += 1;
                self.enter_idle_with_notification(code, subcode, data)
            }

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    fn handle_open_confirm(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop => {
                self.enter_idle_with_notification(NotificationCode::Cease, 0, Bytes::new())
            }

            Event::HoldTimerExpires => self.enter_idle_with_notification(
                NotificationCode::HoldTimerExpired,
                0,
                Bytes::new(),
            ),

            Event::KeepaliveTimerExpires => {
                vec![
                    Action::SendKeepalive,
                    Action::StartTimer(
                        TimerType::Keepalive,
                        self.negotiated
                            .as_ref()
                            .map_or(30, |n| u32::from(n.keepalive_interval)),
                    ),
                ]
            }

            Event::KeepaliveReceived => {
                if let Some(neg) = self.negotiated.clone() {
                    let hold = u32::from(neg.hold_time);
                    let mut actions = Vec::new();
                    if hold > 0 {
                        actions.push(Action::StartTimer(TimerType::Hold, hold));
                    }
                    actions.push(self.transition_to(SessionState::Established));
                    actions.push(Action::SessionEstablished(neg));
                    actions
                } else {
                    // Should not happen — negotiated is set in OpenSent
                    self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new())
                }
            }

            Event::NotificationReceived(_) => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::TcpConnectionFails => {
                self.connect_retry_counter += 1;
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::DecodeError(ref e) => {
                let (code, subcode, data) = e.to_notification();
                self.connect_retry_counter += 1;
                self.enter_idle_with_notification(code, subcode, data)
            }

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    fn handle_established(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop => {
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(
                    NotificationCode::Cease,
                    0,
                    Bytes::new(),
                ));
                actions
            }

            Event::HoldTimerExpires => {
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(
                    NotificationCode::HoldTimerExpired,
                    0,
                    Bytes::new(),
                ));
                actions
            }

            Event::KeepaliveTimerExpires => {
                vec![
                    Action::SendKeepalive,
                    Action::StartTimer(
                        TimerType::Keepalive,
                        self.negotiated
                            .as_ref()
                            .map_or(30, |n| u32::from(n.keepalive_interval)),
                    ),
                ]
            }

            Event::KeepaliveReceived | Event::UpdateReceived => {
                let mut actions = Vec::new();
                if let Some(ref neg) = self.negotiated {
                    let hold = u32::from(neg.hold_time);
                    if hold > 0 {
                        actions.push(Action::StartTimer(TimerType::Hold, hold));
                    }
                }
                actions
            }

            Event::UpdateValidationError(notif) => {
                self.connect_retry_counter += 1;
                self.negotiated = None;
                let mut actions = vec![
                    Action::SessionDown,
                    Action::SendNotification(notif),
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::NotificationReceived(_) => {
                self.connect_retry_counter += 1;
                self.negotiated = None;
                let mut actions = vec![
                    Action::SessionDown,
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::TcpConnectionFails => {
                self.connect_retry_counter += 1;
                self.negotiated = None;
                let mut actions = vec![
                    Action::SessionDown,
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                    Action::StartTimer(TimerType::ConnectRetry, self.connect_retry_duration()),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::DecodeError(ref e) => {
                let (code, subcode, data) = e.to_notification();
                self.connect_retry_counter += 1;
                self.negotiated = None;
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(code, subcode, data));
                actions
            }

            _ => {
                self.negotiated = None;
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(
                    NotificationCode::FsmError,
                    0,
                    Bytes::new(),
                ));
                actions
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// Transition to a new state, returning the `StateChanged` action.
    fn transition_to(&mut self, new: SessionState) -> Action {
        let old = self.state;
        self.state = new;
        Action::StateChanged { old, new }
    }

    /// Build the OPEN message from our config.
    fn build_open(&self) -> OpenMessage {
        OpenMessage {
            version: 4,
            my_as: self.config.open_my_as(),
            hold_time: self.config.hold_time,
            bgp_identifier: self.config.local_router_id,
            capabilities: self.config.local_capabilities(),
        }
    }

    /// Compute connect-retry duration with exponential backoff.
    /// `base * 2^counter`, capped at `MAX_RETRY_SECS`.
    fn connect_retry_duration(&self) -> u32 {
        let base = self.config.connect_retry_secs;
        let shift = self.connect_retry_counter.min(31);
        base.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
            .min(MAX_RETRY_SECS)
    }

    /// Send a NOTIFICATION, close TCP, stop timers, transition to Idle.
    fn enter_idle_with_notification(
        &mut self,
        code: NotificationCode,
        subcode: u8,
        data: Bytes,
    ) -> Vec<Action> {
        self.connect_retry_counter += 1;
        let notification = rustbgpd_wire::NotificationMessage::new(code, subcode, data);
        let mut actions = vec![
            Action::SendNotification(notification),
            Action::CloseTcpConnection,
            Action::StopTimer(TimerType::ConnectRetry),
            Action::StopTimer(TimerType::Hold),
            Action::StopTimer(TimerType::Keepalive),
        ];
        actions.push(self.transition_to(SessionState::Idle));
        actions
    }

    /// Close TCP, stop timers, transition to Idle (no NOTIFICATION).
    fn enter_idle_silent(&mut self) -> Vec<Action> {
        self.connect_retry_counter += 1;
        let mut actions = vec![
            Action::CloseTcpConnection,
            Action::StopTimer(TimerType::ConnectRetry),
            Action::StopTimer(TimerType::Hold),
            Action::StopTimer(TimerType::Keepalive),
        ];
        actions.push(self.transition_to(SessionState::Idle));
        actions
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{Afi, Capability, Safi};

    use super::*;

    fn test_config() -> PeerConfig {
        PeerConfig {
            local_asn: 65001,
            remote_asn: 65002,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
        }
    }

    fn peer_open() -> OpenMessage {
        OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65002 },
            ],
        }
    }

    fn has_action(actions: &[Action], pred: impl Fn(&Action) -> bool) -> bool {
        actions.iter().any(pred)
    }

    fn assert_state_changed(actions: &[Action], expected_new: SessionState) {
        assert!(
            has_action(actions, |a| matches!(
                a,
                Action::StateChanged { new, .. } if *new == expected_new
            )),
            "expected StateChanged to {expected_new:?} in {actions:?}"
        );
    }

    // ── Idle state ─────────────────────────────────────────────────

    #[test]
    fn idle_manual_start_transitions_to_connect() {
        let mut s = Session::new(test_config());
        let actions = s.handle_event(Event::ManualStart);

        assert_eq!(s.state(), SessionState::Connect);
        assert_state_changed(&actions, SessionState::Connect);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::InitiateTcpConnection
        )));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::StartTimer(TimerType::ConnectRetry, _)
        )));
    }

    #[test]
    fn idle_ignores_other_events() {
        let mut s = Session::new(test_config());
        assert!(s.handle_event(Event::KeepaliveReceived).is_empty());
        assert!(s.handle_event(Event::TcpConnectionFails).is_empty());
        assert!(s.handle_event(Event::HoldTimerExpires).is_empty());
        assert_eq!(s.state(), SessionState::Idle);
    }

    #[test]
    fn idle_manual_start_resets_retry_counter() {
        let mut s = Session::new(test_config());
        // Simulate some prior failures by manipulating via a round trip
        s.handle_event(Event::ManualStart);
        // Now in Connect, fail TCP
        s.handle_event(Event::TcpConnectionFails);
        // Now in Active with counter > 0
        assert!(s.connect_retry_counter() > 0);
        // Go to idle
        s.handle_event(Event::ManualStop);
        // ManualStart should reset
        s.handle_event(Event::ManualStart);
        assert_eq!(s.connect_retry_counter(), 0);
    }

    // ── Connect state ──────────────────────────────────────────────

    #[test]
    fn connect_manual_stop_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::ManualStop);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    #[test]
    fn connect_tcp_confirmed_sends_open_goes_opensent() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::TcpConnectionConfirmed);

        assert_eq!(s.state(), SessionState::OpenSent);
        assert!(has_action(&actions, |a| matches!(a, Action::SendOpen(_))));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::StartTimer(TimerType::Hold, 240)
        )));
    }

    #[test]
    fn connect_tcp_acknowledged_sends_open_goes_opensent() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::TcpConnectionAcknowledged);

        assert_eq!(s.state(), SessionState::OpenSent);
        assert!(has_action(&actions, |a| matches!(a, Action::SendOpen(_))));
    }

    #[test]
    fn connect_tcp_fails_goes_active() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Active);
        assert_state_changed(&actions, SessionState::Active);
    }

    #[test]
    fn connect_retry_timer_restarts_connection() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);

        assert_eq!(s.state(), SessionState::Connect);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::InitiateTcpConnection
        )));
    }

    #[test]
    fn connect_unexpected_event_goes_idle_with_notification() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::KeepaliveReceived);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(_)
        )));
    }

    // ── Active state ───────────────────────────────────────────────

    #[test]
    fn active_manual_stop_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionFails); // → Active
        let actions = s.handle_event(Event::ManualStop);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    #[test]
    fn active_connect_retry_timer_goes_connect() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionFails); // → Active
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);

        assert_eq!(s.state(), SessionState::Connect);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::InitiateTcpConnection
        )));
    }

    #[test]
    fn active_tcp_confirmed_sends_open() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionFails); // → Active
        let actions = s.handle_event(Event::TcpConnectionConfirmed);

        assert_eq!(s.state(), SessionState::OpenSent);
        assert!(has_action(&actions, |a| matches!(a, Action::SendOpen(_))));
    }

    #[test]
    fn active_tcp_fails_stays_active() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionFails); // → Active
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Active);
        assert_state_changed(&actions, SessionState::Active);
    }

    // ── OpenSent state ─────────────────────────────────────────────

    #[test]
    fn opensent_manual_stop_sends_cease() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        let actions = s.handle_event(Event::ManualStop);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::Cease
        )));
    }

    #[test]
    fn opensent_hold_timer_expires_sends_notification() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        let actions = s.handle_event(Event::HoldTimerExpires);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::HoldTimerExpired
        )));
    }

    #[test]
    fn opensent_tcp_fails_goes_active() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Active);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    #[test]
    fn opensent_valid_open_goes_openconfirm() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        let actions = s.handle_event(Event::OpenReceived(peer_open()));

        assert_eq!(s.state(), SessionState::OpenConfirm);
        assert!(has_action(&actions, |a| matches!(a, Action::SendKeepalive)));
        assert!(s.negotiated().is_some());
    }

    #[test]
    fn opensent_invalid_open_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        let mut bad_open = peer_open();
        bad_open.my_as = 65099;
        bad_open.capabilities = vec![Capability::FourOctetAs { asn: 65099 }];
        let actions = s.handle_event(Event::OpenReceived(bad_open));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(_)
        )));
    }

    #[test]
    fn opensent_notification_received_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        let notif =
            rustbgpd_wire::NotificationMessage::new(NotificationCode::Cease, 0, Bytes::new());
        let actions = s.handle_event(Event::NotificationReceived(notif));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    // ── OpenConfirm state ──────────────────────────────────────────

    #[test]
    fn openconfirm_keepalive_received_goes_established() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        let actions = s.handle_event(Event::KeepaliveReceived);

        assert_eq!(s.state(), SessionState::Established);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SessionEstablished(_)
        )));
    }

    #[test]
    fn openconfirm_keepalive_timer_sends_keepalive() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        let actions = s.handle_event(Event::KeepaliveTimerExpires);

        assert!(has_action(&actions, |a| matches!(a, Action::SendKeepalive)));
        assert_eq!(s.state(), SessionState::OpenConfirm);
    }

    #[test]
    fn openconfirm_manual_stop_sends_cease() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        let actions = s.handle_event(Event::ManualStop);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::Cease
        )));
    }

    #[test]
    fn openconfirm_hold_timer_expires_sends_notification() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        let actions = s.handle_event(Event::HoldTimerExpires);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::HoldTimerExpired
        )));
    }

    #[test]
    fn openconfirm_notification_received_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));

        let notif =
            rustbgpd_wire::NotificationMessage::new(NotificationCode::Cease, 0, Bytes::new());
        let actions = s.handle_event(Event::NotificationReceived(notif));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    #[test]
    fn openconfirm_tcp_fails_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    // ── Established state ──────────────────────────────────────────

    fn reach_established() -> Session {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);
        s.handle_event(Event::OpenReceived(peer_open()));
        s.handle_event(Event::KeepaliveReceived);
        assert_eq!(s.state(), SessionState::Established);
        s
    }

    #[test]
    fn established_manual_stop_emits_session_down() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::ManualStop);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::Cease
        )));
    }

    #[test]
    fn established_hold_timer_expires_emits_session_down() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::HoldTimerExpires);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
    }

    #[test]
    fn established_keepalive_timer_sends_keepalive() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::KeepaliveTimerExpires);

        assert_eq!(s.state(), SessionState::Established);
        assert!(has_action(&actions, |a| matches!(a, Action::SendKeepalive)));
    }

    #[test]
    fn established_keepalive_received_restarts_hold() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::KeepaliveReceived);

        assert_eq!(s.state(), SessionState::Established);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::StartTimer(TimerType::Hold, _)
        )));
    }

    #[test]
    fn established_update_received_restarts_hold() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::UpdateReceived);

        assert_eq!(s.state(), SessionState::Established);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::StartTimer(TimerType::Hold, _)
        )));
    }

    #[test]
    fn established_update_validation_error_tears_down() {
        let mut s = reach_established();
        let notif = rustbgpd_wire::NotificationMessage::new(
            NotificationCode::UpdateMessage,
            3, // Missing Well-known
            Bytes::from_static(&[1]),
        );
        let actions = s.handle_event(Event::UpdateValidationError(notif));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::UpdateMessage
        )));
    }

    #[test]
    fn established_notification_received_goes_idle() {
        let mut s = reach_established();
        let notif =
            rustbgpd_wire::NotificationMessage::new(NotificationCode::Cease, 0, Bytes::new());
        let actions = s.handle_event(Event::NotificationReceived(notif));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::CloseTcpConnection
        )));
    }

    #[test]
    fn established_tcp_fails_goes_idle() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
    }

    #[test]
    fn established_unexpected_event_sends_fsm_error() {
        let mut s = reach_established();
        let actions = s.handle_event(Event::ManualStart);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::FsmError
        )));
    }

    // ── Backoff ────────────────────────────────────────────────────

    #[test]
    fn exponential_backoff() {
        let mut s = Session::new(test_config());
        assert_eq!(s.connect_retry_duration(), 30);

        s.connect_retry_counter = 1;
        assert_eq!(s.connect_retry_duration(), 60);

        s.connect_retry_counter = 2;
        assert_eq!(s.connect_retry_duration(), 120);

        s.connect_retry_counter = 3;
        assert_eq!(s.connect_retry_duration(), 240);

        // Capped at 300
        s.connect_retry_counter = 4;
        assert_eq!(s.connect_retry_duration(), 300);

        s.connect_retry_counter = 10;
        assert_eq!(s.connect_retry_duration(), 300);
    }

    #[test]
    fn build_open_uses_config() {
        let s = Session::new(test_config());
        let open = s.build_open();
        assert_eq!(open.version, 4);
        assert_eq!(open.my_as, 65001);
        assert_eq!(open.hold_time, 90);
        assert_eq!(open.bgp_identifier, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!open.capabilities.is_empty());
    }
}
