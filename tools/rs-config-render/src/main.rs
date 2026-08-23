//! CLI wrapper around the renderer library. See `README.md` for the
//! refresh loop (`render → rustbgpd --check --strict → swap → SIGHUP`).

#![deny(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use rs_config_render::{
    Exit, Options, RenderError, SiteLocalFile, SiteLocalInput, render, render_site_local,
};

#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Arouteserver,
    IxpManagerV1,
    IxpManagerV2,
}

#[derive(Parser)]
#[command(
    name = "rs-config-render activate",
    about = "Atomically publish and settle a validated local candidate"
)]
struct ActivateArgs {
    #[command(flatten)]
    host: HostBindingArgs,
    /// Private rendered candidate directory
    #[arg(long)]
    candidate: PathBuf,
    /// rustbgpd binary used for version and strict candidate checks
    #[arg(long)]
    check_with: PathBuf,
    /// Exact rbgp executable used for health and live config comparison
    #[arg(long)]
    rbgp: PathBuf,
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
    name = "rs-config-render prune",
    about = "Remove activation generations no retention rule keeps (dry run unless --apply)"
)]
struct PruneArgs {
    #[command(flatten)]
    host: HostBindingArgs,
    /// Most recent generations to retain besides current, its predecessor,
    /// and anything a receipt or pending lifecycle journal references
    #[arg(long)]
    keep: usize,
    /// Remove the planned generations instead of only reporting them
    #[arg(long)]
    apply: bool,
}

#[derive(Parser)]
#[command(
    name = "rs-config-render status",
    about = "Report activation and lifecycle state for one handle without changing it"
)]
struct StatusArgs {
    #[command(flatten)]
    host: HostBindingArgs,
    /// Exact rbgp executable; when given, probe the daemon and compare its
    /// runtime with `current`
    #[arg(long)]
    rbgp: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = "rs-config-render recover",
    about = "Resolve manual-recovery (exit 5) state; every verb is a dry run unless --apply"
)]
struct RecoverArgs {
    #[command(subcommand)]
    command: RecoverCommand,
}

#[derive(Subcommand)]
enum RecoverCommand {
    /// Keep the live candidate: probe the daemon, deliver `updated`, clear fence and journal
    KeepCurrent(KeepCurrentArgs),
    /// Re-stage the previous generation through the activation path, deliver
    /// `release-update-lock`, clear fence and journal
    Rollback(RollbackArgs),
    /// Deliver one callback standalone (retryable); the journal records delivery
    ReleaseLock(ReleaseLockArgs),
    /// Remove fence and journal once no upstream lock is owed
    Clear(RecoverCommonArgs),
}

#[derive(clap::Args)]
struct RecoverCommonArgs {
    #[command(flatten)]
    host: HostBindingArgs,
    /// Perform the planned steps instead of only printing them
    #[arg(long)]
    apply: bool,
    /// IXP Manager root origin; required with a lifecycle journal
    #[arg(long, requires = "api_key_file")]
    ixp_origin: Option<String>,
    /// Absolute mode-0600 file containing the API key; required with a lifecycle journal
    #[arg(long, requires = "ixp_origin")]
    api_key_file: Option<PathBuf>,
    /// Whole-request deadline in seconds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    request_timeout_seconds: u64,
    /// Permit plaintext HTTP only to a numeric loopback origin
    #[arg(long)]
    allow_http_loopback: bool,
}

impl RecoverCommonArgs {
    fn connection(&self) -> Option<rs_config_render::recover::Connection<'_>> {
        Some(rs_config_render::recover::Connection {
            ixp_origin: self.ixp_origin.as_deref()?,
            api_key_file: self.api_key_file.as_deref()?,
            timeout: Duration::from_secs(self.request_timeout_seconds),
            allow_http_loopback: self.allow_http_loopback,
        })
    }
}

#[derive(clap::Args)]
struct KeepCurrentArgs {
    #[command(flatten)]
    common: RecoverCommonArgs,
    /// Exact rbgp executable used for the health and live config probe
    #[arg(long)]
    rbgp: PathBuf,
    /// Proceed although the daemon is not proven healthy and settled on current
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args)]
struct RollbackArgs {
    #[command(flatten)]
    common: RecoverCommonArgs,
    /// Exact rbgp executable used for settlement
    #[arg(long)]
    rbgp: PathBuf,
    /// Maximum seconds for the rollback settlement
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=120))]
    settle_seconds: u64,
    /// Exact activation executable; never evaluated by a shell
    #[arg(long)]
    activation_command: PathBuf,
    /// Literal activation argument; repeatable and never shell-evaluated
    #[arg(long, allow_hyphen_values = true)]
    activation_arg: Vec<OsString>,
    /// Generation to re-stage (`generations/<digest>`); defaults to the
    /// activation receipt's previous_generation when that receipt describes
    /// the current attempt
    #[arg(long)]
    to: Option<String>,
}

#[derive(clap::Args)]
struct ReleaseLockArgs {
    #[command(flatten)]
    common: RecoverCommonArgs,
    /// The candidate stays live: deliver `updated`
    #[arg(
        long,
        conflicts_with = "rolled_back",
        required_unless_present = "rolled_back"
    )]
    kept: bool,
    /// The candidate was rolled away from or never activated: deliver `release-update-lock`
    #[arg(long)]
    rolled_back: bool,
}

#[derive(clap::Args)]
struct HostBindingArgs {
    #[arg(long)]
    router_handle: String,
    #[arg(long)]
    runtime_state_dir: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    host_state_dir: PathBuf,
    #[arg(long)]
    rbgp_addr: String,
}

impl HostBindingArgs {
    fn binding(&self) -> Result<rs_config_render::ixp_manager_host::Binding, &'static str> {
        rs_config_render::ixp_manager_host::Binding::new(
            &self.router_handle,
            &self.runtime_state_dir,
            &self.state_dir,
            &self.host_state_dir,
            &self.rbgp_addr,
        )
    }
}

#[derive(Parser)]
#[command(
    name = "rs-config-render ixp-manager-lifecycle",
    about = "Run the authenticated IXP Manager v7.4 router lifecycle"
)]
struct LifecycleArgs {
    #[command(subcommand)]
    command: LifecycleCommand,
}

#[derive(Subcommand)]
enum LifecycleCommand {
    /// Lock, fetch, render, activate, and acknowledge one router configuration
    Run(LifecycleRunArgs),
    /// Replay one durable pending callback without fetching or activating
    Resume(LifecycleResumeArgs),
}

#[derive(clap::Args)]
struct LifecycleConnectionArgs {
    #[command(flatten)]
    host: HostBindingArgs,
    /// IXP Manager root origin; HTTPS is required by default
    #[arg(long)]
    ixp_origin: String,
    /// Absolute mode-0600 file containing the API key
    #[arg(long)]
    api_key_file: PathBuf,
    /// Whole-request deadline in seconds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    request_timeout_seconds: u64,
    /// Permit plaintext HTTP only to a numeric loopback origin
    #[arg(long)]
    allow_http_loopback: bool,
}

#[derive(clap::Args)]
struct LifecycleRunArgs {
    #[command(flatten)]
    connection: LifecycleConnectionArgs,
    /// Empty private directory for the fetched, rendered candidate
    #[arg(long)]
    candidate_dir: PathBuf,
    /// rustbgpd binary used for mandatory strict candidate checks
    #[arg(long)]
    check_with: PathBuf,
    /// Positive automatic restart delay for IXP Manager max-prefix
    #[arg(long)]
    max_prefix_restart_seconds: u32,
    /// Exact rbgp executable used for health and live config comparison
    #[arg(long)]
    rbgp: PathBuf,
    /// Maximum seconds for activation settlement
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=120))]
    settle_seconds: u64,
    /// Permit initial publication only when no current generation or daemon exists
    #[arg(long)]
    initial: bool,
    /// Exact activation executable; never evaluated by a shell
    #[arg(long)]
    activation_command: PathBuf,
    /// Literal activation argument; repeatable and never shell-evaluated
    #[arg(long, allow_hyphen_values = true)]
    activation_arg: Vec<OsString>,
}

#[derive(clap::Args)]
struct LifecycleResumeArgs {
    #[command(flatten)]
    connection: LifecycleConnectionArgs,
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
    #[arg(long)]
    router_handle: Option<String>,
    #[arg(long)]
    runtime_state_dir: Option<PathBuf>,
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
        Ok(()) => Exit::Success.into(),
        Err(StdoutWriteError::BrokenPipe) => Exit::InvalidInput.into(),
        Err(StdoutWriteError::Other(error)) => {
            let _ = writeln!(
                diagnostic,
                "rs-config-render: failed to write stdout: {error}"
            );
            Exit::InvalidInput.into()
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

fn parse_status() -> Option<StatusArgs> {
    let mut args = std::env::args_os();
    let binary = args.next()?;
    (args.next().as_deref() == Some(OsStr::new("status")))
        .then(|| StatusArgs::parse_from(std::iter::once(binary).chain(args)))
}

fn parse_recover() -> Option<RecoverArgs> {
    let mut args = std::env::args_os();
    let binary = args.next()?;
    (args.next().as_deref() == Some(OsStr::new("recover")))
        .then(|| RecoverArgs::parse_from(std::iter::once(binary).chain(args)))
}

fn recover_exit(
    common: &RecoverCommonArgs,
    verb: &rs_config_render::recover::Verb<'_>,
) -> ExitCode {
    let name = verb.name();
    let binding = match common.host.binding() {
        Ok(binding) => binding,
        Err(reason) => {
            eprintln!("rs-config-render: recover {name}: {reason}");
            return Exit::Refused.into();
        }
    };
    let options = rs_config_render::recover::Options {
        state_dir: &common.host.state_dir,
        binding: &binding,
        apply: common.apply,
        connection: common.connection(),
    };
    match rs_config_render::recover::recover(&options, verb) {
        Ok(outcome) => {
            let count = outcome.steps.len();
            let summary = if common.apply {
                format!("recover {name}: applied {count} step(s)")
            } else {
                format!(
                    "recover {name}: dry run — {count} step(s) planned; pass --apply to perform them"
                )
            };
            stdout_exit(write_stdout(|writer| {
                for step in &outcome.steps {
                    writeln!(writer, "recover {name}: {step}")?;
                }
                writeln!(writer, "{summary}")
            }))
        }
        Err(failure) => {
            let written = write_stdout(|writer| {
                for step in &failure.completed.steps {
                    writeln!(writer, "recover {name}: {step}")?;
                }
                Ok(())
            });
            if let Err(error) = written {
                return stdout_exit(Err(error));
            }
            eprintln!("rs-config-render: recover {name}: {}", failure.error);
            failure.error.exit_code().into()
        }
    }
}

fn parse_prune() -> Option<PruneArgs> {
    let mut args = std::env::args_os();
    let binary = args.next()?;
    (args.next().as_deref() == Some(OsStr::new("prune")))
        .then(|| PruneArgs::parse_from(std::iter::once(binary).chain(args)))
}

fn parse_lifecycle() -> Option<LifecycleArgs> {
    let mut args = std::env::args_os();
    let binary = args.next()?;
    (args.next().as_deref() == Some(OsStr::new("ixp-manager-lifecycle")))
        .then(|| LifecycleArgs::parse_from(std::iter::once(binary).chain(args)))
}

fn lifecycle_exit(
    result: Result<
        rs_config_render::ixp_manager_lifecycle::Status,
        rs_config_render::ixp_manager_lifecycle::Error,
    >,
) -> ExitCode {
    match result {
        Ok(status) => {
            let status = match status {
                rs_config_render::ixp_manager_lifecycle::Status::Activated => "activated",
                rs_config_render::ixp_manager_lifecycle::Status::Noop => "noop",
                rs_config_render::ixp_manager_lifecycle::Status::Updated => "updated",
            };
            stdout_exit(write_stdout(|writer| {
                writeln!(writer, "IXP Manager lifecycle {status}")
            }))
        }
        Err(error) => {
            eprintln!("rs-config-render: IXP Manager lifecycle: {error}");
            error.exit_code().into()
        }
    }
}

fn main() -> ExitCode {
    if let Some(args) = parse_status() {
        let binding = match args.host.binding() {
            Ok(binding) => binding,
            Err(reason) => {
                eprintln!("rs-config-render: status: {reason}");
                return Exit::Refused.into();
            }
        };
        return match rs_config_render::recover::status(&rs_config_render::recover::StatusOptions {
            state_dir: &args.host.state_dir,
            binding: &binding,
            rbgp: args.rbgp.as_deref(),
        }) {
            Ok(report) => stdout_exit(write_stdout(|writer| write!(writer, "{report}"))),
            Err(error) => {
                eprintln!("rs-config-render: status: {error}");
                error.exit_code().into()
            }
        };
    }
    if let Some(args) = parse_recover() {
        use rs_config_render::recover::{Released, RollbackActivation, Verb};
        return match &args.command {
            RecoverCommand::KeepCurrent(args) => recover_exit(
                &args.common,
                &Verb::KeepCurrent {
                    rbgp: &args.rbgp,
                    force: args.force,
                },
            ),
            RecoverCommand::Rollback(args) => recover_exit(
                &args.common,
                &Verb::Rollback {
                    activation: RollbackActivation {
                        rbgp: &args.rbgp,
                        settle: Duration::from_secs(args.settle_seconds),
                        activation_command: &args.activation_command,
                        activation_args: &args.activation_arg,
                    },
                    to: args.to.as_deref(),
                },
            ),
            RecoverCommand::ReleaseLock(args) => recover_exit(
                &args.common,
                &Verb::ReleaseLock(if args.kept {
                    Released::Kept
                } else {
                    Released::RolledBack
                }),
            ),
            RecoverCommand::Clear(common) => recover_exit(common, &Verb::Clear),
        };
    }
    if let Some(args) = parse_prune() {
        let binding = match args.host.binding() {
            Ok(binding) => binding,
            Err(reason) => {
                eprintln!("rs-config-render: prune: {reason}");
                return Exit::Refused.into();
            }
        };
        return match rs_config_render::prune::prune(&rs_config_render::prune::Options {
            state_dir: &args.host.state_dir,
            keep: args.keep,
            apply: args.apply,
            binding: &binding,
        }) {
            Ok(plan) => {
                for (digest, error) in &plan.failed {
                    eprintln!("rs-config-render: prune: cannot remove {digest}: {error}");
                }
                let (kept, removed) = (plan.kept.len(), plan.removed.len());
                let summary = if args.apply {
                    format!("prune: removed {removed} generation(s), kept {kept}")
                } else {
                    format!(
                        "prune: dry run — {removed} generation(s) would be removed, {kept} kept; pass --apply to remove"
                    )
                };
                let written = stdout_exit(write_stdout(|writer| {
                    write!(writer, "{plan}")?;
                    writeln!(writer, "{summary}")
                }));
                if plan.failed.is_empty() {
                    written
                } else {
                    Exit::OutputUnusable.into()
                }
            }
            Err(error) => {
                eprintln!("rs-config-render: prune: {error}");
                error.exit_code().into()
            }
        };
    }
    if let Some(args) = parse_lifecycle() {
        return match args.command {
            LifecycleCommand::Run(args) => {
                let connection = args.connection;
                let binding = match connection.host.binding() {
                    Ok(binding) => binding,
                    Err(reason) => {
                        eprintln!("rs-config-render: IXP Manager lifecycle: {reason}");
                        return Exit::Refused.into();
                    }
                };
                lifecycle_exit(rs_config_render::ixp_manager_lifecycle::run(
                    &rs_config_render::ixp_manager_lifecycle::Options {
                        ixp_origin: &connection.ixp_origin,
                        router_handle: &connection.host.router_handle,
                        api_key_file: &connection.api_key_file,
                        candidate_dir: &args.candidate_dir,
                        state_dir: &connection.host.state_dir,
                        checker: &args.check_with,
                        max_prefix_restart_seconds: args.max_prefix_restart_seconds,
                        rbgp: &args.rbgp,
                        rbgp_addr: &connection.host.rbgp_addr,
                        activation_command: &args.activation_command,
                        activation_args: &args.activation_arg,
                        settle: Duration::from_secs(args.settle_seconds),
                        timeout: Duration::from_secs(connection.request_timeout_seconds),
                        initial: args.initial,
                        allow_http_loopback: connection.allow_http_loopback,
                        binding: &binding,
                    },
                ))
            }
            LifecycleCommand::Resume(args) => {
                let connection = args.connection;
                let binding = match connection.host.binding() {
                    Ok(binding) => binding,
                    Err(reason) => {
                        eprintln!("rs-config-render: IXP Manager lifecycle: {reason}");
                        return Exit::Refused.into();
                    }
                };
                lifecycle_exit(rs_config_render::ixp_manager_lifecycle::resume(
                    &rs_config_render::ixp_manager_lifecycle::ResumeOptions {
                        ixp_origin: &connection.ixp_origin,
                        router_handle: &connection.host.router_handle,
                        api_key_file: &connection.api_key_file,
                        state_dir: &connection.host.state_dir,
                        timeout: Duration::from_secs(connection.request_timeout_seconds),
                        allow_http_loopback: connection.allow_http_loopback,
                        binding: &binding,
                    },
                ))
            }
        };
    }
    if let Some(args) = parse_activation() {
        let binding = match args.host.binding() {
            Ok(binding) => binding,
            Err(reason) => {
                eprintln!("rs-config-render: activation: {reason}");
                return Exit::Refused.into();
            }
        };
        let options = rs_config_render::activation::Options {
            candidate: &args.candidate,
            state_dir: &args.host.state_dir,
            checker: &args.check_with,
            rbgp: &args.rbgp,
            rbgp_addr: &args.host.rbgp_addr,
            settle: Duration::from_secs(args.settle_seconds),
            initial: args.initial,
            activation_command: &args.activation_command,
            activation_args: &args.activation_arg,
            binding: &binding,
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
                let message = match error {
                    rs_config_render::activation::Error::Refused(reason) => reason,
                    rs_config_render::activation::Error::RolledBack => {
                        "activation command did not start; prior generation restored"
                    }
                    rs_config_render::activation::Error::RecoveryRequired => {
                        "recovery required; inspect private activation state"
                    }
                };
                eprintln!("rs-config-render: activation: {message}");
                error.exit_code().into()
            }
        };
    }
    let cli = Cli::parse();
    let customized = !cli.extra_rpol.is_empty() || !cli.merge_toml.is_empty();
    let ixp_schema = match cli.input_format {
        InputFormat::IxpManagerV1 => Some(rs_config_render::ixp_manager::SchemaVersion::V1),
        InputFormat::IxpManagerV2 => Some(rs_config_render::ixp_manager::SchemaVersion::V2),
        InputFormat::Arouteserver => None,
    };
    if let Some(schema) = ixp_schema {
        if customized
            || cli.min_prefixes.is_some()
            || cli.min_origins.is_some()
            || !cli.rtr_cache.is_empty()
            || cli.allow_shape_drift
        {
            eprintln!("rs-config-render: IXP Manager mode does not accept arouteserver options");
            return Exit::Refused.into();
        }
        let (Some(restart), Some(checker)) =
            (cli.max_prefix_restart_seconds, cli.check_with.as_deref())
        else {
            eprintln!(
                "rs-config-render: IXP Manager mode requires --max-prefix-restart-seconds and --check-with"
            );
            return Exit::Refused.into();
        };
        let (Some(handle), Some(runtime)) = (
            cli.router_handle.as_deref(),
            cli.runtime_state_dir.as_deref(),
        ) else {
            eprintln!(
                "rs-config-render: IXP Manager mode requires --router-handle and --runtime-state-dir"
            );
            return Exit::Refused.into();
        };
        let binding = match rs_config_render::ixp_manager_host::RenderBinding::new(handle, runtime)
        {
            Ok(binding) => binding,
            Err(reason) => {
                eprintln!("rs-config-render: {reason}");
                return Exit::Refused.into();
            }
        };
        return match rs_config_render::ixp_manager::write_checked_candidate(
            &cli.context,
            &cli.out_dir,
            restart,
            checker,
            &binding,
            schema,
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
                error.exit_code().into()
            }
        };
    }
    if cli.max_prefix_restart_seconds.is_some()
        || cli.check_with.is_some()
        || cli.router_handle.is_some()
        || cli.runtime_state_dir.is_some()
    {
        eprintln!(
            "rs-config-render: IXP Manager options require --input-format ixp-manager-v1 or ixp-manager-v2"
        );
        return Exit::Refused.into();
    }
    if customized && (cli.extra_rpol.is_empty() || cli.merge_toml.len() != 1) {
        eprintln!(
            "rs-config-render: {}",
            RenderError::Refused(vec![
                "customization requires at least one --extra-rpol and exactly one --merge-toml"
                    .into(),
            ])
        );
        return Exit::Refused.into();
    }
    let context = match std::fs::read_to_string(&cli.context) {
        Ok(context) => context,
        Err(e) => {
            eprintln!(
                "rs-config-render: cannot read {}: {e}",
                cli.context.display()
            );
            return Exit::InvalidInput.into();
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
            return Exit::InvalidInput.into();
        }
    };
    let rendered = match site.as_ref().map_or_else(
        || render(&context, &opts),
        |site| render_site_local(&context, &opts, site),
    ) {
        Ok(rendered) => rendered,
        Err(e) => {
            eprintln!("rs-config-render: {e}");
            return e.exit_code().into();
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
            return Exit::OutputUnusable.into();
        }
        if let Err(e) = std::fs::write(&path, contents) {
            eprintln!("rs-config-render: cannot write {}: {e}", path.display());
            return Exit::OutputUnusable.into();
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
        return Exit::OutputUnusable.into();
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
        assert_eq!(
            stdout_exit_with(result, &mut err),
            ExitCode::from(Exit::InvalidInput)
        );
        let err_text = String::from_utf8(err.clone()).unwrap();
        assert!(err_text.starts_with("rs-config-render: failed to write stdout: "));
        assert!(err_text.ends_with('\n'));
        err.clear();
        let broken = stdout_exit_with(Err(StdoutWriteError::BrokenPipe), &mut err);
        assert_eq!(broken, ExitCode::from(Exit::InvalidInput));
        assert!(err.is_empty());
    }
}
