//! CLI wrapper around the renderer library. See `README.md` for the
//! refresh loop (`render → rustbgpd --check → swap → SIGHUP`).

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
    println!(
        "rendered {} file(s) + receipt into {} — gate with `rustbgpd --check {}` before swapping",
        rendered.files.len(),
        cli.out_dir.display(),
        cli.out_dir.join("config.toml").display()
    );
    ExitCode::SUCCESS
}
