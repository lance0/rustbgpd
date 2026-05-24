//! Inputs to the sans-IO session state machine.
//!
//! The session never reads a clock or touches a socket: it consumes these
//! events (a received packet, or a timer the actor armed firing) and emits
//! [`crate::action::Action`]s.

use crate::packet::ControlPacket;

/// An event driving the [`crate::session::Session`] state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A control packet was received and structurally validated.
    PacketReceived(ControlPacket),
    /// The transmit timer fired — time to send a periodic control packet.
    TxTimerExpires,
    /// The detection timer fired — no packet within the detection window.
    DetectTimerExpires,
}
