#![cfg(target_os = "linux")]

//! `rbgp top` must leave the alternate screen and show the cursor when the
//! process is terminated by a signal, not only when the operator presses
//! `q` or Ctrl-C. The TUI runs under a pseudo-terminal lent by util-linux
//! `script`, which mirrors everything the TUI writes to its own stdout.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
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

struct ScriptGuard {
    child: Child,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ScriptGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let children = format!("/proc/{0}/task/{0}/children", self.child.id());
            for pid in std::fs::read_to_string(children)
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|pid| pid.parse().ok())
            {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn sgr_codes(output: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(output)
        .split("\x1b[")
        .skip(1)
        .filter_map(|sequence| sequence.split_once('m').map(|(codes, _)| codes))
        .filter(|codes| {
            codes
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b';')
        })
        .flat_map(|codes| codes.split(';').map(|code| code.parse().unwrap_or(0)))
        .collect()
}

#[test]
fn sigterm_restores_the_terminal_and_color_policy_preserves_emphasis() {
    for (flag, no_color, colored) in [
        ("", None, true),
        ("--no-color", None, false),
        ("", Some("1"), false),
        ("", Some(""), false),
    ] {
        let output = run_tui(flag, no_color);
        let has_color = sgr_codes(&output)
            .into_iter()
            .any(|code| matches!(code, 30..=38 | 40..=48 | 58 | 90..=97 | 100..=107));
        assert_eq!(
            has_color,
            colored,
            "flag={flag:?} NO_COLOR={no_color:?}: {:?}",
            String::from_utf8_lossy(&output)
        );
        let heading = find(&output, b"Dashboard").expect("help heading rendered");
        let mut bold = false;
        for code in sgr_codes(&output[..heading]) {
            match code {
                0 | 22 => bold = false,
                1 => bold = true,
                _ => {}
            }
        }
        assert!(bold, "help heading must retain bold emphasis");
    }
}

fn run_tui(flag: &str, no_color: Option<&str>) -> Vec<u8> {
    // A bare listener completes the TCP handshake, which is all the CLI's
    // connect step needs. The TUI's RPCs then stay in flight, which keeps it
    // on screen with a visible error and no daemon to run.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = format!("http://{}", listener.local_addr().expect("local addr"));

    // `exec` makes rbgp the direct child of `script`, so /proc names its pid.
    let command_line = format!(
        "stty rows 24 cols 160 && exec {} -s {addr} {flag} top",
        env!("CARGO_BIN_EXE_rbgp")
    );
    let mut command = Command::new("script");
    command.env_remove("NO_COLOR").env("TERM", "xterm-256color");
    if let Some(value) = no_color {
        command.env("NO_COLOR", value);
    }
    let child = command
        .args(["-qec", &command_line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn script(1)");
    let mut script = ScriptGuard {
        child,
        reader: None,
    };
    // Held open so `script` never sees EOF on its stdin; it is also the
    // TUI's keyboard.
    let mut stdin = script.child.stdin.take().expect("script stdin");
    let mut stdout = script.child.stdout.take().expect("script stdout");
    let output = Arc::new(Mutex::new(Vec::new()));
    script.reader = Some({
        let output = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf)
                && n > 0
            {
                output.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        })
    });

    let children = format!("/proc/{0}/task/{0}/children", script.child.id());
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut answered = 0;
    let mut help_requested = false;
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
        if !help_requested && find(&output.lock().unwrap(), b"rustbgpd").is_some() {
            stdin.write_all(b"h").expect("open help");
            stdin.flush().expect("flush help key");
            help_requested = true;
        }
        let child = std::fs::read_to_string(&children).unwrap_or_default();
        // Require actual content: a zero-sized terminal can hide its cursor
        // without rendering any cells, which cannot prove the color policy.
        let frame_ready = {
            let bytes = output.lock().unwrap();
            find(&bytes, HIDE_CURSOR).is_some() && find(&bytes, b"Dashboard").is_some()
        };
        if frame_ready && let Some(pid) = child.split_whitespace().next() {
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = script.child.try_wait().expect("wait for script") {
            break status;
        }
        assert!(Instant::now() < deadline, "TUI did not exit after SIGTERM");
        std::thread::sleep(Duration::from_millis(10));
    };
    script.reader.take().unwrap().join().expect("reader thread");
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
    output.clone()
}
