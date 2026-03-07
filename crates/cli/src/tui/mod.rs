mod app;
mod data;
mod theme;
mod ui;

use std::io;
use std::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

use crate::connection::Connection;
use crate::error::CliError;
use app::App;
use theme::Theme;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

pub async fn run(connection: Connection, interval: u64) -> Result<(), CliError> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let theme = Theme::default();
    let mut app = App::new();

    let (data_tx, mut data_rx) = mpsc::channel(4);
    let (event_tx, mut event_rx) = mpsc::channel(64);

    let _fetcher =
        data::spawn_fetcher(connection, Duration::from_secs(interval), data_tx, event_tx);

    loop {
        terminal.draw(|f| ui::draw(f, &mut app, &theme))?;

        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key);
            if app.should_quit {
                break;
            }
        }

        while let Ok(snapshot) = data_rx.try_recv() {
            app.on_data(snapshot);
        }

        while let Ok(route_event) = event_rx.try_recv() {
            app.on_route_event(route_event);
        }
    }

    Ok(())
}
