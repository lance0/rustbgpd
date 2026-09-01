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
use tokio::sync::{mpsc, watch};

use crate::connection::Connection;
use crate::error::CliError;
use app::{App, RibIntent};
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
    let _guard = TerminalGuard;
    io::stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let theme = Theme::default();
    let mut app = App::new();

    let (data_tx, mut data_rx) = mpsc::channel(4);
    let (event_tx, mut event_rx) = mpsc::channel(64);
    let (event_watch_tx, event_watch_rx) = watch::channel(false);
    let (rib_lane, mut rib_rx) = data::spawn_rib_query_lane(connection.clone());

    let _fetcher = data::spawn_fetcher(
        connection,
        Duration::from_secs(interval),
        data_tx,
        event_tx,
        event_watch_rx,
    );
    let mut events_enabled = false;

    loop {
        terminal.draw(|f| ui::draw(f, &mut app, &theme))?;

        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key);
            if app.should_quit {
                rib_lane.cancel();
                rib_lane.close();
                break;
            }
        }

        while let Ok(snapshot) = data_rx.try_recv() {
            app.on_data(snapshot);
        }

        while let Ok(route_event) = event_rx.try_recv() {
            app.on_route_event(route_event);
        }

        while let Ok(result) = rib_rx.try_recv() {
            app.on_rib_result(result);
        }

        while let Some(intent) = app.take_rib_intent() {
            match intent {
                RibIntent::Cancel => rib_lane.cancel(),
                RibIntent::Query {
                    view_id,
                    peer_address,
                    query,
                } => {
                    let Some(request_id) =
                        rib_lane.query(view_id, peer_address.clone(), query.clone())
                    else {
                        app.rib_unavailable("query lane closed");
                        continue;
                    };
                    app.record_rib_request(data::RibQueryIdentity {
                        request_id,
                        view_id,
                        peer_address,
                        query,
                    });
                }
            }
        }

        let should_watch_events = app.route_events_visible();
        if should_watch_events != events_enabled {
            events_enabled = should_watch_events;
            let _ = event_watch_tx.send(events_enabled);
        }
    }

    Ok(())
}
