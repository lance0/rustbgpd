//! BFD session state (RFC 5880 §6.8.1 `bfd.SessionState`).

/// The four BFD session states. The wire encoding (RFC 5880 §4.1 `Sta`) is a
/// 2-bit field; the numeric values here match it exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// The session is administratively down (`AdminDown`, value 0).
    AdminDown,
    /// The session is down or has just been created (`Down`, value 1).
    Down,
    /// The remote end is communicating but the session is not yet up
    /// (`Init`, value 2).
    Init,
    /// The session is up (`Up`, value 3).
    Up,
}

impl SessionState {
    /// The 2-bit wire value (RFC 5880 §4.1 `Sta`).
    #[must_use]
    pub fn to_wire(self) -> u8 {
        match self {
            SessionState::AdminDown => 0,
            SessionState::Down => 1,
            SessionState::Init => 2,
            SessionState::Up => 3,
        }
    }

    /// Decode the 2-bit wire value. Only `0..=3` are valid, so this is total.
    #[must_use]
    pub fn from_wire(value: u8) -> SessionState {
        match value & 0b11 {
            0 => SessionState::AdminDown,
            1 => SessionState::Down,
            2 => SessionState::Init,
            _ => SessionState::Up,
        }
    }
}
