mod app;
mod data;
mod theme;
mod ui;

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
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
fn spawn_signal_forwarder(tx: mpsc::Sender<io::Result<KeyEvent>>) -> io::Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
            _ = hangup.recv() => {}
        }
        let _ = tx.send(Ok(QUIT_KEY)).await;
    });
    Ok(())
}

/// Wait up to `timeout` for input on `tty`; `true` if the terminal has hung
/// up. crossterm 0.29 must never read a hung-up terminal: its read loop
/// exits only on data or `WouldBlock`, so the EOF or EIO a hung-up terminal
/// returns makes it re-read forever on a full core, never returning.
fn tty_hung_up(tty: BorrowedFd<'_>, timeout: PollTimeout) -> io::Result<bool> {
    let mut fds = [PollFd::new(tty, PollFlags::POLLIN)];
    loop {
        match poll(&mut fds, timeout) {
            Ok(_) => break,
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let revents = fds[0].revents().unwrap_or(PollFlags::empty());
    Ok(revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL))
}

/// Read keys from `tty` until it hangs up (`Ok`) or crossterm fails. Waiting
/// happens in [`tty_hung_up`], never inside crossterm.
fn read_keys(tty: BorrowedFd<'_>, tx: &mpsc::Sender<io::Result<KeyEvent>>) -> io::Result<()> {
    loop {
        if tty_hung_up(tty, PollTimeout::NONE)? {
            return Ok(());
        }
        // Input is pending. Hand over every event crossterm parses from it
        // before blocking again. A hangup in the gap between the check and
        // crossterm's read wedges this thread, but not the event loop: it
        // still ends on the SIGHUP that comes with it, or on its next draw.
        loop {
            if let Event::Key(key) = event::read()?
                && tx.blocking_send(Ok(key)).is_err()
            {
                return Ok(());
            }
            if tty_hung_up(tty, PollTimeout::ZERO)? || !event::poll(Duration::ZERO)? {
                break;
            }
        }
    }
}

/// Forward terminal keys on a dedicated thread, so the event loop waits on
/// the channel it shares with the signal forwarder and never blocks inside
/// crossterm. A hangup arrives as [`QUIT_KEY`]; a read error ends the TUI
/// with that error. A plain thread, not `spawn_blocking`: runtime shutdown
/// must not wait for a read that never returns.
fn spawn_input_reader(tty: OwnedFd, tx: mpsc::Sender<io::Result<KeyEvent>>) {
    std::thread::spawn(move || {
        let end = read_keys(tty.as_fd(), &tx).map(|()| QUIT_KEY);
        let _ = tx.blocking_send(end);
    });
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

pub async fn run(connection: Connection, interval: u64, no_color: bool) -> Result<(), CliError> {
    // stdin is a terminal (checked before connecting), so it is the fd
    // crossterm reads keys from.
    let tty = io::stdin().as_fd().try_clone_to_owned()?;
    let (key_tx, mut key_rx) = mpsc::channel(16);
    spawn_signal_forwarder(key_tx.clone())?;
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    io::stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(io::stdout());
    // Never dropped: `TerminalGuard` restores the cursor, and ratatui's own
    // restore `eprintln!`s its failure, which panics once the terminal has
    // hung up and turns a clean quit into exit status 101.
    let mut terminal = std::mem::ManuallyDrop::new(Terminal::new(backend)?);
    terminal.clear()?;
    spawn_input_reader(tty, key_tx);

    let theme = if no_color {
        Theme::monochrome()
    } else {
        Theme::default()
    };
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

        let key = match tokio::time::timeout(Duration::from_millis(50), key_rx.recv()).await {
            Ok(Some(key)) => Some(key?),
            // Both senders send a quit before closing; never spin on a closed channel.
            Ok(None) => Some(QUIT_KEY),
            Err(_) => None,
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
            .expect("forwarder sends before closing")
            .expect("a signal is not an error");
        assert_eq!(key, QUIT_KEY, "a signal must arrive as the Ctrl-C key");

        let mut app = App::new();
        app.on_key(key);
        assert!(
            app.should_quit,
            "the forwarded key must take the quit branch"
        );
    }

    #[tokio::test]
    async fn terminal_hangup_arrives_as_the_ctrl_c_quit_key() {
        let pty = nix::pty::openpty(None, None).expect("open a pty pair");
        let tty = pty.slave;
        assert!(
            !tty_hung_up(tty.as_fd(), PollTimeout::ZERO).expect("poll idle tty"),
            "an idle terminal has not hung up"
        );
        nix::unistd::write(&pty.master, b"q\n").expect("type into the pty");
        assert!(
            !tty_hung_up(tty.as_fd(), PollTimeout::NONE).expect("poll tty with input"),
            "pending input is not a hangup"
        );

        // Closing the master is what a dropped SSH session or a killed tmux
        // server does; reads on the slave now return EOF.
        drop(pty.master);
        assert!(
            tty_hung_up(tty.as_fd(), PollTimeout::NONE).expect("poll hung-up tty"),
            "a closed master must read as a hangup"
        );

        let (tx, mut rx) = mpsc::channel(1);
        spawn_input_reader(tty, tx);
        let key = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("hangup forwarded within 5s")
            .expect("reader sends before closing")
            .expect("a hangup is not an error");
        assert_eq!(key, QUIT_KEY, "a hangup must arrive as the Ctrl-C key");

        let mut app = App::new();
        app.on_key(key);
        assert!(
            app.should_quit,
            "the forwarded key must take the quit branch"
        );
    }
}
