use std::fmt;

/// RFC 4271 §8 — BGP session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl SessionState {
    /// Short lowercase name for structured logging.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connect => "connect",
            Self::Active => "active",
            Self::OpenSent => "open_sent",
            Self::OpenConfirm => "open_confirm",
            Self::Established => "established",
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_as_str() {
        let states = [
            SessionState::Idle,
            SessionState::Connect,
            SessionState::Active,
            SessionState::OpenSent,
            SessionState::OpenConfirm,
            SessionState::Established,
        ];
        for s in states {
            assert_eq!(s.to_string(), s.as_str());
        }
    }
}
