//! CLI wrapper around the renderer library. See `README.md` for the
//! refresh loop (`render → rustbgpd --check --strict → swap → SIGHUP`).

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rs_config_render::{Options, render};

#[derive(Parser)]
#[command(
    name = "rs-config-render",
    version,
    about = "Render rustbgpd route-server configuration from `arouteserver template-context` output"
)]
struct Cli {
    /// Path to `arouteserver template-context` output (YAML; JSON also parses)
    #[arg(long)]
    context: PathBuf,
    /// Output directory (created if missing)
    #[arg(long)]
    out_dir: PathBuf,
    /// Abort when a client's generated prefix-set has fewer members
    #[arg(long, default_value_t = 1)]
    min_prefixes: u32,
    /// Abort when a client's generated origin asn-set has fewer members
    #[arg(long, default_value_t = 1)]
    min_origins: u32,
    /// RTR cache endpoint (host:port) for [[rpki.cache_servers]]; repeatable.
    /// Required when the context enables RPKI origin validation.
    #[arg(long = "rtr-cache")]
    rtr_cache: Vec<String>,
    /// Proceed despite a context-shape fingerprint mismatch
    #[arg(long)]
    allow_shape_drift: bool,
}

#[derive(Debug)]
enum StdoutWriteError {
    BrokenPipe,
    Other(std::io::Error),
}
impl From<std::io::Error> for StdoutWriteError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::Other(error)
        }
    }
}
fn write_stdout_with(
    writer: &mut dyn std::io::Write,
    output: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
) -> Result<(), StdoutWriteError> {
    output(writer)?;
    writer.flush()?;
    Ok(())
}
fn write_stdout(
    output: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
) -> Result<(), StdoutWriteError> {
    let stdout = std::io::stdout();
    write_stdout_with(&mut stdout.lock(), output)
}
fn stdout_exit_with(
    result: Result<(), StdoutWriteError>,
    diagnostic: &mut dyn std::io::Write,
) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(StdoutWriteError::BrokenPipe) => ExitCode::from(1),
        Err(StdoutWriteError::Other(error)) => {
            let _ = writeln!(
                diagnostic,
                "rs-config-render: failed to write stdout: {error}"
            );
            ExitCode::from(1)
        }
    }
}
fn stdout_exit(result: Result<(), StdoutWriteError>) -> ExitCode {
    let stderr = std::io::stderr();
    stdout_exit_with(result, &mut stderr.lock())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let context = match std::fs::read_to_string(&cli.context) {
        Ok(context) => context,
        Err(e) => {
            eprintln!(
                "rs-config-render: cannot read {}: {e}",
                cli.context.display()
            );
            return ExitCode::from(1);
        }
    };
    let opts = Options {
        min_prefixes: cli.min_prefixes,
        min_origins: cli.min_origins,
        rtr_caches: cli.rtr_cache,
        allow_shape_drift: cli.allow_shape_drift,
    };
    let rendered = match render(&context, &opts) {
        Ok(rendered) => rendered,
        Err(e) => {
            eprintln!("rs-config-render: {e}");
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(1));
        }
    };
    for warning in &rendered.warnings {
        eprintln!("rs-config-render: warning: {warning}");
    }
    for (rel_path, contents) in &rendered.files {
        let path = cli.out_dir.join(rel_path);
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("rs-config-render: cannot create {}: {e}", parent.display());
            return ExitCode::from(1);
        }
        if let Err(e) = std::fs::write(&path, contents) {
            eprintln!("rs-config-render: cannot write {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }
    let receipt_path = cli.out_dir.join("render-receipt.json");
    let receipt =
        serde_json::to_string_pretty(&rendered.receipt).expect("receipt serialization cannot fail");
    if let Err(e) = std::fs::write(&receipt_path, receipt + "\n") {
        eprintln!(
            "rs-config-render: cannot write {}: {e}",
            receipt_path.display()
        );
        return ExitCode::from(1);
    }
    stdout_exit(write_stdout(|writer| {
        writeln!(
            writer,
            "rendered {} file(s) + receipt into {} — gate with `rustbgpd --check --strict {}` before swapping",
            rendered.files.len(),
            cli.out_dir.display(),
            cli.out_dir.join("config.toml").display()
        )
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs::File, io::BufWriter};

    #[test]
    fn stdout_exit_distinguishes_quiet_broken_pipe_from_other_flush_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = BufWriter::new(File::open(file.path()).unwrap());
        let result = write_stdout_with(&mut writer, |out| out.write_all(b"complete"));
        assert_eq!(writer.buffer(), b"complete");
        let mut err = Vec::new();
        assert_eq!(stdout_exit_with(result, &mut err), ExitCode::from(1));
        let err_text = String::from_utf8(err.clone()).unwrap();
        assert!(err_text.starts_with("rs-config-render: failed to write stdout: "));
        assert!(err_text.ends_with('\n'));
        err.clear();
        let broken = stdout_exit_with(Err(StdoutWriteError::BrokenPipe), &mut err);
        assert_eq!(broken, ExitCode::from(1));
        assert!(err.is_empty());
    }
}
