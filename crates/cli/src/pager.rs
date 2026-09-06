use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};

use crate::error::CliError;
use crate::output;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum PagerMode {
    #[default]
    Auto,
    Always,
    Never,
}

pub(crate) fn validate_request(
    mode: PagerMode,
    json: bool,
    supported: bool,
) -> Result<(), CliError> {
    validate_request_with_tty(mode, json, supported, io::stdout().is_terminal())
}

fn validate_request_with_tty(
    mode: PagerMode,
    json: bool,
    supported: bool,
    stdout_is_tty: bool,
) -> Result<(), CliError> {
    if mode != PagerMode::Always {
        return Ok(());
    }
    if json {
        return Err(CliError::Argument(
            "--pager always cannot be combined with --json".into(),
        ));
    }
    if !stdout_is_tty {
        return Err(CliError::Argument(
            "--pager always requires stdout to be a terminal".into(),
        ));
    }
    if !supported {
        return Err(CliError::Argument(
            "--pager always is supported only for human best, received, and advertised unicast RIB listings".into(),
        ));
    }
    Ok(())
}

pub(crate) fn write_payload(mode: PagerMode, payload: &str) -> Result<(), CliError> {
    let stdout_is_tty = io::stdout().is_terminal();
    let terminal_rows = stdout_is_tty
        .then(crossterm::terminal::size)
        .and_then(Result::ok)
        .map(|(_, rows)| rows);
    if !should_page(mode, stdout_is_tty, terminal_rows, payload.lines().count()) {
        return output::write_bytes(&mut io::stdout().lock(), payload.as_bytes());
    }

    run_pager(&pager_argv(mode), payload, mode, &mut io::stdout().lock())
}

fn should_page(
    mode: PagerMode,
    stdout_is_tty: bool,
    terminal_rows: Option<u16>,
    payload_rows: usize,
) -> bool {
    match mode {
        PagerMode::Never => false,
        PagerMode::Always => stdout_is_tty,
        PagerMode::Auto => {
            stdout_is_tty && terminal_rows.is_some_and(|rows| payload_rows > usize::from(rows))
        }
    }
}

fn pager_argv(mode: PagerMode) -> Vec<String> {
    let rbgp_pager = env::var("RBGP_PAGER").ok();
    let pager = env::var("PAGER").ok();
    pager_argv_from(mode, rbgp_pager.as_deref(), pager.as_deref())
}

fn pager_argv_from(mode: PagerMode, rbgp_pager: Option<&str>, pager: Option<&str>) -> Vec<String> {
    rbgp_pager
        .filter(|value| !value.trim_ascii().is_empty())
        .or_else(|| pager.filter(|value| !value.trim_ascii().is_empty()))
        .map(|value| value.split_ascii_whitespace().map(str::to_owned).collect())
        .unwrap_or_else(|| match mode {
            PagerMode::Auto => vec!["less".into(), "-FRX".into()],
            PagerMode::Always => vec!["less".into(), "-RX".into()],
            PagerMode::Never => unreachable!("never mode writes directly"),
        })
}

fn run_pager(
    argv: &[String],
    payload: &str,
    mode: PagerMode,
    fallback: &mut dyn Write,
) -> Result<(), CliError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(CliError::Argument("pager command is empty".into()));
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if mode == PagerMode::Auto && error.kind() == io::ErrorKind::NotFound => {
            return output::write_bytes(fallback, payload.as_bytes());
        }
        Err(error) => return Err(CliError::Io(error)),
    };

    let write_result = child
        .stdin
        .as_mut()
        .expect("piped pager stdin")
        .write_all(payload.as_bytes());
    let status = child.wait()?;
    classify_pager_result(write_result, status)
}

fn classify_pager_result(
    write_result: io::Result<()>,
    status: std::process::ExitStatus,
) -> Result<(), CliError> {
    if !status.success() {
        return Err(CliError::Io(io::Error::other(match status.code() {
            Some(code) => format!("pager exited with status {code}"),
            None => "pager terminated by signal".to_string(),
        })));
    }
    match write_result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(CliError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_rejects_invalid_surfaces_before_connect() {
        assert!(validate_request_with_tty(PagerMode::Always, true, true, true).is_err());
        assert!(validate_request_with_tty(PagerMode::Always, false, true, false).is_err());
        assert!(validate_request_with_tty(PagerMode::Always, false, false, true).is_err());
        assert!(validate_request_with_tty(PagerMode::Always, false, true, true).is_ok());
        assert!(validate_request_with_tty(PagerMode::Auto, true, false, false).is_ok());
    }

    #[test]
    fn process_failures_do_not_replay_payload() {
        let argv = vec!["/definitely/missing/rbgp-pager".to_string()];
        let mut fallback = Vec::new();
        assert!(run_pager(&argv, "payload", PagerMode::Always, &mut fallback).is_err());
        assert!(fallback.is_empty());
        assert!(run_pager(&[], "payload", PagerMode::Always, &mut fallback).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn child_status_is_checked_after_payload_delivery() {
        assert!(
            run_pager(
                &["/bin/true".into()],
                "payload",
                PagerMode::Always,
                &mut Vec::new(),
            )
            .is_ok()
        );
        let error = run_pager(
            &["/bin/false".into()],
            "payload",
            PagerMode::Always,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "pager exited with status 1");

        let status = Command::new("/bin/false").status().unwrap();
        let error = classify_pager_result(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")),
            status,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "pager exited with status 1");
    }

    #[test]
    fn pager_command_uses_first_nonempty_ascii_token_list() {
        assert_eq!(
            pager_argv_from(PagerMode::Auto, Some(" \t"), Some("more -f")),
            ["more", "-f"]
        );
        assert_eq!(
            pager_argv_from(PagerMode::Always, Some("cat -n"), Some("more")),
            ["cat", "-n"]
        );
        for mode in [PagerMode::Auto, PagerMode::Always] {
            assert_eq!(
                pager_argv_from(mode, Some("less -S"), Some("more -f")),
                ["less", "-S"]
            );
            assert_eq!(pager_argv_from(mode, None, Some("less -S")), ["less", "-S"]);
        }
        assert_eq!(
            pager_argv_from(PagerMode::Auto, None, None),
            ["less", "-FRX"]
        );
        assert_eq!(
            pager_argv_from(PagerMode::Always, None, None),
            ["less", "-RX"]
        );
    }

    #[test]
    fn paging_decision_is_tty_height_aware_and_never_is_direct() {
        assert!(should_page(PagerMode::Auto, true, Some(23), 24));
        assert!(!should_page(PagerMode::Auto, true, Some(24), 24));
        assert!(!should_page(PagerMode::Auto, true, None, 100));
        assert!(!should_page(PagerMode::Auto, false, Some(1), 100));
        assert!(!should_page(PagerMode::Never, true, Some(1), 100));
        assert!(should_page(PagerMode::Always, true, None, 1));
    }

    #[test]
    fn auto_missing_executable_falls_back_byte_identically() {
        let argv = vec!["/definitely/missing/rbgp-pager".to_string()];
        let mut fallback = Vec::new();
        run_pager(&argv, "table\nfooter\n", PagerMode::Auto, &mut fallback).unwrap();
        assert_eq!(fallback, b"table\nfooter\n");
    }
}
