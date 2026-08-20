//! CLI wrapper around the renderer library. See `README.md` for the
//! refresh loop (`render → rustbgpd --check --strict → swap → SIGHUP`).

#![deny(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use rs_config_render::{
    Options, RenderError, SiteLocalFile, SiteLocalInput, render, render_site_local,
};

#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Arouteserver,
    IxpManagerV1,
}

#[derive(Parser)]
#[command(
    name = "rs-config-render activate",
    about = "Atomically publish and settle a validated local candidate"
)]
struct ActivateArgs {
    /// Private rendered candidate directory
    #[arg(long)]
    candidate: PathBuf,
    /// Private activation state directory
    #[arg(long)]
    state_dir: PathBuf,
    /// rustbgpd binary used for version and strict candidate checks
    #[arg(long)]
    check_with: PathBuf,
    /// Exact rbgp executable used for health and live config comparison
    #[arg(long)]
    rbgp: PathBuf,
    /// Running rustbgpd gRPC address
    #[arg(long)]
    rbgp_addr: String,
    /// Maximum seconds for each activation or rollback settlement
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=120))]
    settle_seconds: u64,
    /// Permit publication only when no current generation or daemon exists
    #[arg(long)]
    initial: bool,
    /// Exact activation executable; never evaluated by a shell
    #[arg(long)]
    activation_command: PathBuf,
    /// Literal activation argument; repeatable and never shell-evaluated
    #[arg(long, allow_hyphen_values = true)]
    activation_arg: Vec<OsString>,
}

#[derive(Parser)]
#[command(
    name = "rs-config-render",
    version,
    about = "Render rustbgpd route-server configuration from supported upstream exports"
)]
struct Cli {
    /// Input document format
    #[arg(long, value_enum, default_value = "arouteserver")]
    input_format: InputFormat,
    /// Path to the selected input document (arouteserver YAML/JSON or IXP Manager JSON)
    #[arg(long)]
    context: PathBuf,
    /// Output directory (created if missing)
    #[arg(long)]
    out_dir: PathBuf,
    /// Abort when a client's generated prefix-set has fewer members
    #[arg(long)]
    min_prefixes: Option<u32>,
    /// Abort when a client's generated origin asn-set has fewer members
    #[arg(long)]
    min_origins: Option<u32>,
    /// RTR cache endpoint (host:port) for [[rpki.cache_servers]]; repeatable.
    /// Required when the context enables RPKI origin validation.
    #[arg(long = "rtr-cache")]
    rtr_cache: Vec<String>,
    /// Proceed despite a context-shape fingerprint mismatch
    #[arg(long)]
    allow_shape_drift: bool,
    /// Exact UTF-8 site-local .rpol source; repeatable and requires --merge-toml
    #[arg(long = "extra-rpol")]
    extra_rpol: Vec<PathBuf>,
    /// Strict site-local hook TOML; exactly one when --extra-rpol is used
    #[arg(long = "merge-toml")]
    merge_toml: Vec<PathBuf>,
    /// Required positive automatic restart delay for IXP Manager max-prefix
    #[arg(long)]
    max_prefix_restart_seconds: Option<u32>,
    /// rustbgpd binary used for mandatory version and strict candidate checks
    #[arg(long)]
    check_with: Option<PathBuf>,
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

fn parse_activation() -> Option<ActivateArgs> {
    let mut args = std::env::args_os();
    let binary = args.next()?;
    (args.next().as_deref() == Some(OsStr::new("activate")))
        .then(|| ActivateArgs::parse_from(std::iter::once(binary).chain(args)))
}

fn main() -> ExitCode {
    if let Some(args) = parse_activation() {
        let options = rs_config_render::activation::Options {
            candidate: &args.candidate,
            state_dir: &args.state_dir,
            checker: &args.check_with,
            rbgp: &args.rbgp,
            rbgp_addr: &args.rbgp_addr,
            settle: Duration::from_secs(args.settle_seconds),
            initial: args.initial,
            activation_command: &args.activation_command,
            activation_args: &args.activation_arg,
        };
        return match rs_config_render::activation::activate(&options) {
            Ok(status) => {
                let status = match status {
                    rs_config_render::activation::Status::Activated => "activated",
                    rs_config_render::activation::Status::Noop => "noop",
                };
                stdout_exit(write_stdout(|writer| {
                    writeln!(writer, "activation {status}")
                }))
            }
            Err(error) => {
                let (code, message) = match error {
                    rs_config_render::activation::Error::Refused(reason) => (2, reason),
                    rs_config_render::activation::Error::RolledBack => {
                        (4, "candidate failed settlement; prior generation restored")
                    }
                    rs_config_render::activation::Error::RecoveryRequired => {
                        (5, "recovery required; inspect private activation state")
                    }
                };
                eprintln!("rs-config-render: activation: {message}");
                ExitCode::from(code)
            }
        };
    }
    let cli = Cli::parse();
    let customized = !cli.extra_rpol.is_empty() || !cli.merge_toml.is_empty();
    if matches!(cli.input_format, InputFormat::IxpManagerV1) {
        if customized
            || cli.min_prefixes.is_some()
            || cli.min_origins.is_some()
            || !cli.rtr_cache.is_empty()
            || cli.allow_shape_drift
        {
            eprintln!("rs-config-render: IXP Manager mode does not accept arouteserver options");
            return ExitCode::from(2);
        }
        let (Some(restart), Some(checker)) =
            (cli.max_prefix_restart_seconds, cli.check_with.as_deref())
        else {
            eprintln!(
                "rs-config-render: IXP Manager mode requires --max-prefix-restart-seconds and --check-with"
            );
            return ExitCode::from(2);
        };
        return match rs_config_render::ixp_manager::write_checked_candidate(
            &cli.context,
            &cli.out_dir,
            restart,
            checker,
        ) {
            Ok(files) => stdout_exit(write_stdout(|writer| {
                writeln!(
                    writer,
                    "validated {files} candidate file(s) + receipt into {}",
                    cli.out_dir.display()
                )
            })),
            Err(error) => {
                eprintln!("rs-config-render: {error}");
                ExitCode::from(error.exit_code())
            }
        };
    }
    if cli.max_prefix_restart_seconds.is_some() || cli.check_with.is_some() {
        eprintln!("rs-config-render: IXP Manager options require --input-format ixp-manager-v1");
        return ExitCode::from(2);
    }
    if customized && (cli.extra_rpol.is_empty() || cli.merge_toml.len() != 1) {
        eprintln!(
            "rs-config-render: {}",
            RenderError::Refused(vec![
                "customization requires at least one --extra-rpol and exactly one --merge-toml"
                    .into(),
            ])
        );
        return ExitCode::from(2);
    }
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
        min_prefixes: cli.min_prefixes.unwrap_or(1),
        min_origins: cli.min_origins.unwrap_or(1),
        rtr_caches: cli.rtr_cache,
        allow_shape_drift: cli.allow_shape_drift,
    };
    let site = customized.then(|| {
        let read = |path: &PathBuf| {
            std::fs::read(path)
                .map(|bytes| SiteLocalFile {
                    source_path: path.display().to_string(),
                    bytes,
                })
                .map_err(|error| format!("cannot read {}: {error}", path.display()))
        };
        Ok::<_, String>(SiteLocalInput {
            merge: read(&cli.merge_toml[0])?,
            policies: cli.extra_rpol.iter().map(read).collect::<Result<_, _>>()?,
        })
    });
    let site = match site.transpose() {
        Ok(site) => site,
        Err(error) => {
            eprintln!("rs-config-render: {error}");
            return ExitCode::from(1);
        }
    };
    let rendered = match site.as_ref().map_or_else(
        || render(&context, &opts),
        |site| render_site_local(&context, &opts, site),
    ) {
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
