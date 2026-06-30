//! Core FSM session — `(State, Event) -> (State, Vec<Action>)`.

use bytes::Bytes;

use rustbgpd_wire::notification::{NotificationCode, cease_subcode, open_subcode};
use rustbgpd_wire::{Capability, OpenMessage};

use crate::action::{Action, NegotiatedSession, TimerType};
use crate::config::PeerConfig;
use crate::event::Event;
use crate::negotiation::validate_open;
use crate::state::SessionState;

/// Maximum connect-retry backoff in seconds.
const MAX_RETRY_SECS: u32 = 300;

/// Fast TCP-level retries before returning to the configured exponential base.
///
/// A refused TCP dial usually means peer boot ordering, not a protocol/config
/// error. Retry those first misses quickly so cold-start convergence is not
/// dominated by the configured `ConnectRetry` base. OPEN validation failures and
/// NOTIFICATION-driven Idle fallback stay on the slower daemon reconnect guard.
const FAST_TCP_CONNECT_RETRY_SECS: u32 = 1;
const FAST_TCP_CONNECT_RETRY_ATTEMPTS: u32 = 2;

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

    /// Negotiated session parameters while OpenConfirm/Established state is live.
    ///
    /// Cleared on every transition back to Idle so operator-facing state queries
    /// never report stale metadata from a failed handshake.
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

    /// Emit a `StaleTimerIgnored` action for a timer-expired event that
    /// arrived in a state where the corresponding timer should not be
    /// running. RFC 4271 §8.1's per-state event tables don't list these
    /// pairs, but tearing a healthy session down because the daemon-side
    /// timer infrastructure delivered a late tick is operationally
    /// hostile — every other reasonable implementation we surveyed
    /// (FRR/BIRD/GoBGP) drops the event silently. The action lets the
    /// daemon expose a counter so it stays observable instead of fully
    /// invisible.
    fn ignore_stale_timer(&self, timer: TimerType) -> Vec<Action> {
        vec![Action::StaleTimerIgnored {
            state: self.state,
            timer,
        }]
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "state handlers consume Event variants while dispatching the FSM"
    )]
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
            // RFC 4271: In Idle, no timers should be running. Late timer
            // ticks indicate a daemon-side bug (timer not stopped on the
            // last transition into Idle) — surface them through the
            // StaleTimerIgnored counter so they can be observed without
            // tearing the session down.
            Event::ConnectRetryTimerExpires => self.ignore_stale_timer(TimerType::ConnectRetry),
            Event::HoldTimerExpires => self.ignore_stale_timer(TimerType::Hold),
            Event::KeepaliveTimerExpires => self.ignore_stale_timer(TimerType::Keepalive),
            // RFC 4271: In Idle, all other events are ignored.
            _ => vec![],
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "state handlers consume Event variants while dispatching the FSM"
    )]
    fn handle_connect(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop { .. } | Event::DecodeError(_) => self.enter_idle_silent(),

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
                self.increment_connect_retry_counter();
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::StartTimer(
                        TimerType::ConnectRetry,
                        self.tcp_connect_failure_retry_duration(),
                    ),
                ];
                actions.push(self.transition_to(SessionState::Active));
                actions
            }

            // RFC 4271: in Connect, only the ConnectRetry timer is
            // running. Hold/Keepalive ticks are stale.
            Event::HoldTimerExpires => self.ignore_stale_timer(TimerType::Hold),
            Event::KeepaliveTimerExpires => self.ignore_stale_timer(TimerType::Keepalive),

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "state handlers consume Event variants while dispatching the FSM"
    )]
    fn handle_active(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop { .. } | Event::DecodeError(_) => self.enter_idle_silent(),

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
                self.increment_connect_retry_counter();
                let mut actions = vec![
                    Action::StopTimer(TimerType::ConnectRetry),
                    Action::StartTimer(
                        TimerType::ConnectRetry,
                        self.tcp_connect_failure_retry_duration(),
                    ),
                ];
                actions.push(self.transition_to(SessionState::Active));
                actions
            }

            // RFC 4271: in Active, only the ConnectRetry timer is
            // running. Hold/Keepalive ticks are stale.
            Event::HoldTimerExpires => self.ignore_stale_timer(TimerType::Hold),
            Event::KeepaliveTimerExpires => self.ignore_stale_timer(TimerType::Keepalive),

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    fn handle_open_sent(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop { reason } => self.enter_idle_with_notification(
                NotificationCode::Cease,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                reason.unwrap_or_default(),
            ),

            Event::HoldTimerExpires => self.enter_idle_with_notification(
                NotificationCode::HoldTimerExpired,
                0,
                Bytes::new(),
            ),

            Event::TcpConnectionFails => {
                self.increment_connect_retry_counter();
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StartTimer(
                        TimerType::ConnectRetry,
                        self.tcp_connect_failure_retry_duration(),
                    ),
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
                    self.increment_connect_retry_counter();
                    let mut actions = Vec::with_capacity(5);
                    // Observability hook for RFC 9234 Role-Mismatch (2/11):
                    // emit a typed action so transport can label
                    // bgp_role_mismatch_total{peer, local_role, remote_role}.
                    // For OPENs carrying duplicate Role caps, the FIRST Role
                    // value is reported as remote_role — sufficient for the
                    // bounded label set; the negotiator already rejected.
                    if notification.code == NotificationCode::OpenMessage
                        && notification.subcode == open_subcode::ROLE_MISMATCH
                    {
                        let remote_role = open.capabilities.iter().find_map(|c| match c {
                            Capability::Role { role } => Some(*role),
                            _ => None,
                        });
                        actions.push(Action::RoleMismatchObserved {
                            local_role: self.config.local_role,
                            remote_role,
                        });
                    }
                    actions.push(Action::SendNotification(notification));
                    actions.push(Action::CloseTcpConnection);
                    actions.push(Action::StopTimer(TimerType::Hold));
                    actions.push(self.transition_to(SessionState::Idle));
                    actions
                }
            },

            Event::NotificationReceived(_) => {
                self.increment_connect_retry_counter();
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::DecodeError(ref e) => {
                let (code, subcode, data) = e.to_notification();
                self.enter_idle_with_notification(code, subcode, data)
            }

            // RFC 4271: in OpenSent, only the Hold timer is running.
            // ConnectRetry/Keepalive ticks are stale.
            Event::ConnectRetryTimerExpires => self.ignore_stale_timer(TimerType::ConnectRetry),
            Event::KeepaliveTimerExpires => self.ignore_stale_timer(TimerType::Keepalive),

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    fn handle_open_confirm(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop { reason } => self.enter_idle_with_notification(
                NotificationCode::Cease,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                reason.unwrap_or_default(),
            ),

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
                    actions.push(Action::SessionEstablished(Box::new(neg)));
                    actions
                } else {
                    // Should not happen — negotiated is set in OpenSent
                    self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new())
                }
            }

            Event::NotificationReceived(_) => {
                self.increment_connect_retry_counter();
                let mut actions = vec![
                    Action::CloseTcpConnection,
                    Action::StopTimer(TimerType::Hold),
                    Action::StopTimer(TimerType::Keepalive),
                ];
                actions.push(self.transition_to(SessionState::Idle));
                actions
            }

            Event::TcpConnectionFails => {
                self.increment_connect_retry_counter();
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
                self.enter_idle_with_notification(code, subcode, data)
            }

            // RFC 4271: in OpenConfirm, only Hold + Keepalive timers
            // are running. ConnectRetry ticks are stale.
            Event::ConnectRetryTimerExpires => self.ignore_stale_timer(TimerType::ConnectRetry),

            _ => self.enter_idle_with_notification(NotificationCode::FsmError, 0, Bytes::new()),
        }
    }

    fn handle_established(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ManualStop { reason } => {
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(
                    NotificationCode::Cease,
                    cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                    reason.unwrap_or_default(),
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

            Event::KeepaliveReceived
            | Event::UpdateReceived
            | Event::RouteRefreshReceived { .. } => {
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
                self.increment_connect_retry_counter();
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
                self.increment_connect_retry_counter();
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
                self.increment_connect_retry_counter();
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
                self.negotiated = None;
                let mut actions = vec![Action::SessionDown];
                actions.extend(self.enter_idle_with_notification(code, subcode, data));
                actions
            }

            // RFC 4271: in Established, only Hold + Keepalive timers
            // are running. ConnectRetry ticks are stale.
            Event::ConnectRetryTimerExpires => self.ignore_stale_timer(TimerType::ConnectRetry),

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
        if new == SessionState::Idle {
            self.negotiated = None;
        }
        self.state = new;
        Action::StateChanged { old, new }
    }

    fn increment_connect_retry_counter(&mut self) {
        self.connect_retry_counter = self.connect_retry_counter.saturating_add(1);
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

    /// Compute the normal connect-retry duration with exponential backoff.
    /// `base * 2^counter`, capped at `MAX_RETRY_SECS`.
    fn connect_retry_duration(&self) -> u32 {
        self.connect_retry_backoff_duration(self.connect_retry_counter)
    }

    fn connect_retry_backoff_duration(&self, counter: u32) -> u32 {
        let base = self.config.connect_retry_secs;
        let shift = counter.min(31);
        base.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
            .min(MAX_RETRY_SECS)
    }

    /// Compute the retry wait after a TCP-level connection miss.
    ///
    /// The first misses are usually a peer that is still booting or has not yet
    /// bound its listener. Keep those quick, then resume the configured
    /// exponential curve so persistent failures still back off.
    fn tcp_connect_failure_retry_duration(&self) -> u32 {
        if self.connect_retry_counter <= FAST_TCP_CONNECT_RETRY_ATTEMPTS {
            return FAST_TCP_CONNECT_RETRY_SECS;
        }

        let backoff_counter = self
            .connect_retry_counter
            .saturating_sub(FAST_TCP_CONNECT_RETRY_ATTEMPTS + 1);
        self.connect_retry_backoff_duration(backoff_counter)
    }

    /// Send a NOTIFICATION, close TCP, stop timers, transition to Idle.
    fn enter_idle_with_notification(
        &mut self,
        code: NotificationCode,
        subcode: u8,
        data: Bytes,
    ) -> Vec<Action> {
        self.increment_connect_retry_counter();
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
        self.increment_connect_retry_counter();
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
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            local_role: None,
            strict_role: false,
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
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

    fn connect_retry_timer_secs(actions: &[Action]) -> Option<u32> {
        actions.iter().find_map(|action| match action {
            Action::StartTimer(TimerType::ConnectRetry, secs) => Some(*secs),
            _ => None,
        })
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
        assert_eq!(connect_retry_timer_secs(&actions), Some(30));
    }

    #[test]
    fn idle_ignores_other_events() {
        let mut s = Session::new(test_config());
        // Non-timer events are silently dropped — no Action emitted.
        assert!(s.handle_event(Event::KeepaliveReceived).is_empty());
        assert!(s.handle_event(Event::TcpConnectionFails).is_empty());
        assert_eq!(s.state(), SessionState::Idle);
        // Timer events emit StaleTimerIgnored; covered by
        // `idle_stale_*` tests below.
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
        s.handle_event(Event::ManualStop { reason: None });
        // ManualStart should reset
        s.handle_event(Event::ManualStart);
        assert_eq!(s.connect_retry_counter(), 0);
    }

    // ── Connect state ──────────────────────────────────────────────

    #[test]
    fn connect_manual_stop_goes_idle() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::ManualStop { reason: None });

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
        let actions = s.handle_event(Event::ManualStop { reason: None });

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
        let actions = s.handle_event(Event::ManualStop { reason: None });

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
    fn opensent_role_mismatch_emits_observer_action_with_local_and_remote_roles() {
        // RFC 9234 incompatible pair: both ends configured Provider.
        // The negotiator returns NOTIFICATION 2/11; the session handler must
        // ALSO emit `Action::RoleMismatchObserved { local, remote }` so the
        // transport layer can record bgp_role_mismatch_total with bounded
        // role labels (the notification body itself is empty per RFC).
        let mut cfg = test_config();
        cfg.local_role = Some(rustbgpd_wire::BgpRole::Provider);

        let mut s = Session::new(cfg);
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        let mut bad_open = peer_open();
        bad_open.capabilities.push(Capability::Role {
            role: rustbgpd_wire::BgpRole::Provider,
        });
        let actions = s.handle_event(Event::OpenReceived(bad_open));

        assert_eq!(s.state(), SessionState::Idle);
        // Both actions present.
        assert!(
            has_action(&actions, |a| matches!(
                a,
                Action::RoleMismatchObserved {
                    local_role: Some(rustbgpd_wire::BgpRole::Provider),
                    remote_role: Some(rustbgpd_wire::BgpRole::Provider),
                }
            )),
            "expected RoleMismatchObserved with both roles; got {actions:?}"
        );
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n)
                if n.code == NotificationCode::OpenMessage
                    && n.subcode == open_subcode::ROLE_MISMATCH
        )));

        // Ordering: the observer action MUST come before the
        // SendNotification so the metric is recorded even if the wire send
        // is short-circuited by a downstream error.
        let observer_idx = actions
            .iter()
            .position(|a| matches!(a, Action::RoleMismatchObserved { .. }))
            .expect("RoleMismatchObserved present");
        let notif_idx = actions
            .iter()
            .position(|a| matches!(a, Action::SendNotification(_)))
            .expect("SendNotification present");
        assert!(
            observer_idx < notif_idx,
            "RoleMismatchObserved must precede SendNotification (got idx {observer_idx} vs {notif_idx})"
        );
    }

    #[test]
    fn opensent_role_mismatch_strict_no_remote_role_reports_none_remote() {
        // Strict mode: we configured Customer; peer didn't advertise Role.
        // The observer action should label remote_role as None.
        let mut cfg = test_config();
        cfg.local_role = Some(rustbgpd_wire::BgpRole::Customer);
        cfg.strict_role = true;

        let mut s = Session::new(cfg);
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        // peer_open() does NOT include a Role capability.
        let actions = s.handle_event(Event::OpenReceived(peer_open()));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            has_action(&actions, |a| matches!(
                a,
                Action::RoleMismatchObserved {
                    local_role: Some(rustbgpd_wire::BgpRole::Customer),
                    remote_role: None,
                }
            )),
            "strict-mode mismatch must report remote_role=None; got {actions:?}"
        );
    }

    #[test]
    fn opensent_non_role_open_error_does_not_emit_observer_action() {
        // BAD_PEER_AS (subcode 2) must NOT emit RoleMismatchObserved —
        // that's reserved strictly for subcode 11 (Role Mismatch). Confirms
        // we don't over-fire the observability hook on unrelated rejections.
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        let mut bad_open = peer_open();
        bad_open.my_as = 65099;
        bad_open.capabilities = vec![Capability::FourOctetAs { asn: 65099 }];
        let actions = s.handle_event(Event::OpenReceived(bad_open));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            !has_action(&actions, |a| matches!(
                a,
                Action::RoleMismatchObserved { .. }
            )),
            "non-role OPEN error must not emit RoleMismatchObserved; got {actions:?}"
        );
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
        assert!(s.negotiated().is_some());
        let actions = s.handle_event(Event::ManualStop { reason: None });

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            s.negotiated().is_none(),
            "OpenConfirm teardown must not leave negotiated metadata visible in Idle"
        );
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
        assert!(s.negotiated().is_some());
        let actions = s.handle_event(Event::HoldTimerExpires);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            s.negotiated().is_none(),
            "OpenConfirm hold-expiry teardown must clear negotiated metadata"
        );
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
        assert!(s.negotiated().is_some());
        let actions = s.handle_event(Event::NotificationReceived(notif));

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            s.negotiated().is_none(),
            "OpenConfirm NOTIFICATION teardown must clear negotiated metadata"
        );
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
        assert!(s.negotiated().is_some());
        let actions = s.handle_event(Event::TcpConnectionFails);

        assert_eq!(s.state(), SessionState::Idle);
        assert!(
            s.negotiated().is_none(),
            "OpenConfirm TCP failure must clear negotiated metadata"
        );
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
        let actions = s.handle_event(Event::ManualStop { reason: None });

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

    #[test]
    fn established_manual_stop_with_reason_includes_data() {
        let mut s = reach_established();
        let reason_data = rustbgpd_wire::notification::encode_shutdown_communication("maintenance");
        let actions = s.handle_event(Event::ManualStop {
            reason: Some(reason_data.clone()),
        });

        assert_eq!(s.state(), SessionState::Idle);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(n) if n.code == NotificationCode::Cease
                && n.subcode == 2
                && n.data == reason_data
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
    fn connect_retry_counter_saturates_at_u32_max() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        assert_eq!(s.state(), SessionState::Connect);
        s.connect_retry_counter = u32::MAX;

        let actions = s.handle_event(Event::TcpConnectionFails);
        assert_eq!(s.state(), SessionState::Active);
        assert_eq!(s.connect_retry_counter(), u32::MAX);
        assert_eq!(
            connect_retry_timer_secs(&actions),
            Some(300),
            "saturating the diagnostic counter must not wrap back to the fast retry path"
        );
    }

    #[test]
    fn tcp_connection_failures_retry_fast_before_backing_off() {
        let mut cfg = test_config();
        cfg.connect_retry_secs = 5;
        let mut s = Session::new(cfg);

        s.handle_event(Event::ManualStart);
        let actions = s.handle_event(Event::TcpConnectionFails);
        assert_eq!(s.state(), SessionState::Active);
        assert_eq!(connect_retry_timer_secs(&actions), Some(1));

        let actions = s.handle_event(Event::TcpConnectionFails);
        assert_eq!(s.state(), SessionState::Active);
        assert_eq!(connect_retry_timer_secs(&actions), Some(1));

        let actions = s.handle_event(Event::TcpConnectionFails);
        assert_eq!(s.state(), SessionState::Active);
        assert_eq!(connect_retry_timer_secs(&actions), Some(5));

        let actions = s.handle_event(Event::TcpConnectionFails);
        assert_eq!(s.state(), SessionState::Active);
        assert_eq!(connect_retry_timer_secs(&actions), Some(10));
    }

    #[test]
    fn open_rejection_does_not_start_fast_tcp_retry_timer() {
        let mut s = Session::new(test_config());
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::TcpConnectionConfirmed);

        let mut open = peer_open();
        open.my_as = 65003;
        open.capabilities = vec![Capability::FourOctetAs { asn: 65003 }];
        let actions = s.handle_event(Event::OpenReceived(open));

        assert_eq!(s.state(), SessionState::Idle);
        assert_eq!(connect_retry_timer_secs(&actions), None);
        assert!(has_action(&actions, |a| matches!(
            a,
            Action::SendNotification(_)
        )));
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

    // ── Stale timer events ─────────────────────────────────────────
    //
    // RFC 4271 §8.1's per-state event tables don't list every (state,
    // timer) pair. A timer firing in a state where it should not be
    // running indicates a daemon-side timer-management bug, not a
    // peer protocol violation; tearing the session down would convert
    // a daemon bug into a real-world reachability outage. Each arm
    // emits a `StaleTimerIgnored` action so the daemon can bump a
    // counter for visibility, but the session stays put.

    /// Helper: assert the actions list is exactly one
    /// `StaleTimerIgnored` for the expected (state, timer).
    fn assert_stale_timer(actions: &[Action], state: SessionState, timer: TimerType) {
        assert_eq!(actions.len(), 1, "expected exactly one action: {actions:?}");
        match &actions[0] {
            Action::StaleTimerIgnored { state: s, timer: t } => {
                assert_eq!(*s, state, "state label mismatch");
                assert_eq!(*t, timer, "timer label mismatch");
            }
            other => panic!("expected StaleTimerIgnored, got {other:?}"),
        }
    }

    /// Drive the session into a state for stale-timer tests. Helper
    /// keeps the per-test setup short.
    fn drive_to(state: SessionState) -> Session {
        let mut s = Session::new(test_config());
        if state == SessionState::Idle {
            return s;
        }
        s.handle_event(Event::ManualStart);
        if state == SessionState::Connect {
            return s;
        }
        if state == SessionState::Active {
            s.handle_event(Event::TcpConnectionFails);
            return s;
        }
        s.handle_event(Event::TcpConnectionConfirmed);
        if state == SessionState::OpenSent {
            return s;
        }
        s.handle_event(Event::OpenReceived(peer_open()));
        if state == SessionState::OpenConfirm {
            return s;
        }
        s.handle_event(Event::KeepaliveReceived);
        assert_eq!(s.state(), SessionState::Established);
        s
    }

    // -- Idle (none of the timers should be running) --

    #[test]
    fn idle_stale_connect_retry_timer_is_observable() {
        let mut s = drive_to(SessionState::Idle);
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);
        assert_stale_timer(&actions, SessionState::Idle, TimerType::ConnectRetry);
        assert_eq!(s.state(), SessionState::Idle);
    }

    #[test]
    fn idle_stale_hold_timer_is_observable() {
        let mut s = drive_to(SessionState::Idle);
        let actions = s.handle_event(Event::HoldTimerExpires);
        assert_stale_timer(&actions, SessionState::Idle, TimerType::Hold);
        assert_eq!(s.state(), SessionState::Idle);
    }

    #[test]
    fn idle_stale_keepalive_timer_is_observable() {
        let mut s = drive_to(SessionState::Idle);
        let actions = s.handle_event(Event::KeepaliveTimerExpires);
        assert_stale_timer(&actions, SessionState::Idle, TimerType::Keepalive);
        assert_eq!(s.state(), SessionState::Idle);
    }

    // -- Connect (only ConnectRetry should be running) --

    #[test]
    fn connect_stale_hold_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::Connect);
        let actions = s.handle_event(Event::HoldTimerExpires);
        assert_stale_timer(&actions, SessionState::Connect, TimerType::Hold);
        assert_eq!(s.state(), SessionState::Connect);
    }

    #[test]
    fn connect_stale_keepalive_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::Connect);
        let actions = s.handle_event(Event::KeepaliveTimerExpires);
        assert_stale_timer(&actions, SessionState::Connect, TimerType::Keepalive);
        assert_eq!(s.state(), SessionState::Connect);
    }

    // -- Active (only ConnectRetry should be running) --

    #[test]
    fn active_stale_hold_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::Active);
        let actions = s.handle_event(Event::HoldTimerExpires);
        assert_stale_timer(&actions, SessionState::Active, TimerType::Hold);
        assert_eq!(s.state(), SessionState::Active);
    }

    #[test]
    fn active_stale_keepalive_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::Active);
        let actions = s.handle_event(Event::KeepaliveTimerExpires);
        assert_stale_timer(&actions, SessionState::Active, TimerType::Keepalive);
        assert_eq!(s.state(), SessionState::Active);
    }

    // -- OpenSent (only Hold should be running) --

    #[test]
    fn open_sent_stale_connect_retry_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::OpenSent);
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);
        assert_stale_timer(&actions, SessionState::OpenSent, TimerType::ConnectRetry);
        assert_eq!(s.state(), SessionState::OpenSent);
    }

    #[test]
    fn open_sent_stale_keepalive_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::OpenSent);
        let actions = s.handle_event(Event::KeepaliveTimerExpires);
        assert_stale_timer(&actions, SessionState::OpenSent, TimerType::Keepalive);
        assert_eq!(s.state(), SessionState::OpenSent);
    }

    // -- OpenConfirm (Hold + Keepalive should be running) --

    #[test]
    fn open_confirm_stale_connect_retry_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::OpenConfirm);
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);
        assert_stale_timer(&actions, SessionState::OpenConfirm, TimerType::ConnectRetry);
        assert_eq!(s.state(), SessionState::OpenConfirm);
    }

    // -- Established (Hold + Keepalive should be running) --

    #[test]
    fn established_stale_connect_retry_timer_does_not_tear_session_down() {
        let mut s = drive_to(SessionState::Established);
        let actions = s.handle_event(Event::ConnectRetryTimerExpires);
        assert_stale_timer(&actions, SessionState::Established, TimerType::ConnectRetry);
        assert_eq!(s.state(), SessionState::Established);
        // Crucially: no SessionDown action — the existing established
        // session is undisturbed.
        assert!(
            !has_action(&actions, |a| matches!(a, Action::SessionDown)),
            "stale connect-retry must not emit SessionDown: {actions:?}"
        );
    }
}
