mod app;
mod data;
mod theme;
mod ui;

use std::io;
use std::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};

use crate::connection::Connection;
use crate::error::CliError;
use app::{App, RibIntent};
use theme::Theme;

struct TerminalGuard;

/// Ctrl-C as the event loop sees it. Termination signals are forwarded as
/// this key so they quit through the same guarded path.
const QUIT_KEY: KeyEvent = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

/// Forward the first SIGTERM, SIGINT, or SIGHUP as [`QUIT_KEY`]. Raw mode
/// turns Ctrl-C into a key event, but a signal from another process never
/// reaches the event loop, and its default disposition would end the process
/// inside the alternate screen with the cursor hidden.
fn spawn_signal_forwarder(tx: mpsc::Sender<KeyEvent>) -> io::Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
            _ = hangup.recv() => {}
        }
        let _ = tx.send(QUIT_KEY).await;
    });
    Ok(())
}

/// Leave the alternate screen and show the cursor. Ratatui hides the cursor
/// during `draw()`, and `LeaveAlternateScreen` does not restore it.
fn restore_screen(out: &mut impl io::Write) {
    let _ = out.execute(LeaveAlternateScreen);
    let _ = out.execute(crossterm::cursor::Show);
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        restore_screen(&mut io::stdout());
    }
}

pub async fn run(connection: Connection, interval: u64) -> Result<(), CliError> {
    let (signal_tx, mut signal_rx) = mpsc::channel(1);
    spawn_signal_forwarder(signal_tx)?;
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

        let key = if let Ok(key) = signal_rx.try_recv() {
            Some(key)
        } else if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            Some(key)
        } else {
            None
        };
        if let Some(key) = key {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_screen_emits_leave_alternate_then_cursor_show() {
        let mut output = Vec::new();
        restore_screen(&mut output);

        let leave = output
            .windows(b"\x1b[?1049l".len())
            .position(|w| w == b"\x1b[?1049l")
            .expect("restore_screen must emit LeaveAlternateScreen");
        let show = output
            .windows(b"\x1b[?25h".len())
            .position(|w| w == b"\x1b[?25h")
            .expect("restore_screen must emit cursor::Show");
        assert!(
            leave < show,
            "LeaveAlternateScreen must precede cursor::Show"
        );
    }

    #[tokio::test]
    async fn termination_signal_arrives_as_the_ctrl_c_quit_key() {
        let (tx, mut rx) = mpsc::channel(1);
        spawn_signal_forwarder(tx).expect("register signal handlers");
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP).expect("raise SIGHUP");
        let key = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("signal forwarded within 5s")
            .expect("forwarder sends before closing");
        assert_eq!(key, QUIT_KEY, "a signal must arrive as the Ctrl-C key");

        let mut app = App::new();
        app.on_key(key);
        assert!(
            app.should_quit,
            "the forwarded key must take the quit branch"
        );
    }
}
