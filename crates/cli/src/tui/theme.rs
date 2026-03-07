use ratatui::style::Color;

pub struct Theme {
    pub border: Color,
    pub header_fg: Color,
    pub text: Color,
    pub text_dim: Color,
    pub highlight: Color,
    pub state_established: Color,
    pub state_connecting: Color,
    pub state_down: Color,
    pub event_added: Color,
    pub event_withdrawn: Color,
    pub error: Color,
    pub accent: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border: Color::Cyan,
            header_fg: Color::White,
            text: Color::Gray,
            text_dim: Color::DarkGray,
            highlight: Color::Cyan,
            state_established: Color::Green,
            state_connecting: Color::Yellow,
            state_down: Color::Red,
            event_added: Color::Green,
            event_withdrawn: Color::Red,
            error: Color::Red,
            accent: Color::Cyan,
        }
    }
}

impl Theme {
    pub fn state_color(&self, state: i32) -> Color {
        match state {
            6 => self.state_established,
            2 | 4 | 5 => self.state_connecting,
            _ => self.state_down,
        }
    }

    pub fn event_color(&self, event_type: &str) -> Color {
        match event_type {
            "added" | "best_changed" => self.event_added,
            "withdrawn" => self.event_withdrawn,
            _ => self.text,
        }
    }
}
