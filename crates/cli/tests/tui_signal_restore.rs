#![cfg(target_os = "linux")]

//! `rbgp top` must leave the alternate screen and show the cursor when the
//! process is terminated by a signal, not only when the operator presses
//! `q` or Ctrl-C. The TUI runs under a pseudo-terminal lent by util-linux
//! `script`, which mirrors everything the TUI writes to its own stdout.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const ENTER_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";
const LEAVE_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049l";
const CURSOR_POSITION_QUERY: &[u8] = b"\x1b[6n";
const CURSOR_POSITION_REPORT: &[u8] = b"\x1b[1;1R";
const HIDE_CURSOR: &[u8] = b"\x1b[?25l";
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn sigterm_restores_the_terminal() {
    // A bare listener completes the TCP handshake, which is all the CLI's
    // connect step needs. The TUI's RPCs then stay in flight, which keeps it
    // on screen with a visible error and no daemon to run.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = format!("http://{}", listener.local_addr().expect("local addr"));

    // `exec` makes rbgp the direct child of `script`, so /proc names its pid.
    let command = format!("exec {} -s {addr} top", env!("CARGO_BIN_EXE_rbgp"));
    let mut script = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn script(1)");
    // Held open so `script` never sees EOF on its stdin; it is also the
    // TUI's keyboard.
    let mut stdin = script.stdin.take().expect("script stdin");
    let mut stdout = script.stdout.take().expect("script stdout");
    let output = Arc::new(Mutex::new(Vec::new()));
    let reader = {
        let output = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf)
                && n > 0
            {
                output.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        })
    };

    let children = format!("/proc/{0}/task/{0}/children", script.id());
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut answered = 0;
    let tui = loop {
        // Nothing emulates a terminal behind the pty, so answer the cursor
        // position query ratatui sends while setting up; unanswered, setup
        // fails after a timeout and the event loop is never reached.
        let queries = count(&output.lock().unwrap(), CURSOR_POSITION_QUERY);
        while answered < queries {
            stdin
                .write_all(CURSOR_POSITION_REPORT)
                .expect("answer cursor query");
            stdin.flush().expect("flush cursor report");
            answered += 1;
        }
        let child = std::fs::read_to_string(&children).unwrap_or_default();
        // A hidden cursor means a frame was drawn, so the event loop is
        // running when the signal arrives.
        if find(&output.lock().unwrap(), HIDE_CURSOR).is_some()
            && let Some(pid) = child.split_whitespace().next()
        {
            break Pid::from_raw(pid.parse().expect("child pid"));
        }
        assert!(
            Instant::now() < deadline,
            "TUI never drew a frame; output: {:?}",
            String::from_utf8_lossy(&output.lock().unwrap())
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    kill(tui, Signal::SIGTERM).expect("deliver SIGTERM");
    let status = script.wait().expect("wait for script");
    reader.join().expect("reader thread");
    let output = output.lock().unwrap();

    let enter = find(&output, ENTER_ALTERNATE_SCREEN).expect("alternate screen entered");
    let after_enter = &output[enter + ENTER_ALTERNATE_SCREEN.len()..];
    let leave = find(after_enter, LEAVE_ALTERNATE_SCREEN)
        .expect("a TUI terminated by SIGTERM must leave the alternate screen");
    let after_leave = &after_enter[leave + LEAVE_ALTERNATE_SCREEN.len()..];
    assert!(
        find(after_leave, SHOW_CURSOR).is_some(),
        "a TUI terminated by SIGTERM must show the cursor after leaving the alternate screen"
    );
    // `script -e` returns the child's status (128 + signal for a signal
    // death). A forwarded signal exits through the normal quit path.
    assert_eq!(
        status.code(),
        Some(0),
        "a signal-driven quit exits like `q`; status: {status:?}"
    );
}
