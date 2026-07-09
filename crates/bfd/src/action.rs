//! Outputs of the sans-IO session state machine.
//!
//! The actor that owns the real sockets and timers executes these: send a
//! packet, (re)arm or stop a timer, or surface a session-state change.

use crate::packet::{ControlPacket, Diagnostic};
use crate::state::SessionState;

/// Which per-session timer an [`Action`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// Periodic control-packet transmit timer.
    Tx,
    /// Detection timer — fires if no packet arrives within the window.
    Detect,
}

/// An action the actor must perform on behalf of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Transmit this control packet to the peer now.
    SendPacket(ControlPacket),
    /// Arm (or re-arm) a timer to fire after `interval_us` microseconds. The
    /// actor applies transmit jitter (RFC 5880 §6.8.7) to the `Tx` timer.
    StartTimer {
        /// Which timer.
        kind: TimerKind,
        /// Interval in microseconds.
        interval_us: u32,
    },
    /// Cancel a timer (e.g. transmit halted, or detection no longer armed).
    StopTimer {
        /// Which timer.
        kind: TimerKind,
    },
    /// The session state changed. `diagnostic` is the local diagnostic that
    /// accompanies the new state.
    ///
    /// `old == new` is possible: it is a coupling-level re-report emitted when
    /// the local state did not move but the remote flipped into or out of
    /// `AdminDown` (query [`crate::Session::remote_admin_down`]), which RFC
    /// 5882 §4.1/§4.2 requires the BGP coupling to act on.
    StateChanged {
        /// Previous state.
        old: SessionState,
        /// New state.
        new: SessionState,
        /// Local diagnostic for the transition.
        diagnostic: Diagnostic,
    },
}
