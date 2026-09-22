//! Structured JSON logging via `tracing`.

use std::sync::OnceLock;

use tracing_subscriber::filter::{Directive, EnvFilter};
use tracing_subscriber::fmt;

/// Reloads the live `EnvFilter` in place. Boxed so the caller never has to
/// name the `reload::Handle`'s formatter type parameter — the concrete
/// subscriber type produced by the fmt builder is a mouthful and is
/// irrelevant here; only the ability to swap the filter matters.
type ReloadFn = Box<dyn Fn(EnvFilter) -> Result<(), String> + Send + Sync>;

/// The live filter reload hook, installed by [`init_logging`] once the
/// global subscriber is set. Process-global to match the tracing subscriber
/// itself — threading the handle from startup down to the SIGHUP reload task
/// would touch every struct in between for no benefit.
static RELOAD_HANDLE: OnceLock<ReloadFn> = OnceLock::new();

/// The raw `RUST_LOG` value. Non-UTF-8 bytes are replaced rather than
/// treated as unset, so the directive holding them is reported as
/// unparseable instead of silently discarding the whole variable.
fn rust_log_env() -> Option<String> {
    std::env::var_os("RUST_LOG").map(|v| v.to_string_lossy().into_owned())
}

/// Base filter from a `RUST_LOG` value (`info` when unset) with the given
/// per-peer directives appended. Rebuilt in full on every reload so the
/// base level always survives — dropping it would silence everything not
/// covered by a per-peer directive.
///
/// `RUST_LOG` is parsed one comma-separated directive at a time (the same
/// split `EnvFilter` itself uses): valid directives are kept, and every
/// unparseable one is named with its parse error in the returned one-line
/// report for the caller to print. `EnvFilter::try_from_default_env` would reject the whole
/// variable over one bad directive, and `parse_lossy` only prints the errors
/// itself, so neither lets the caller report them. Blank pieces (an empty,
/// whitespace-only or separator-only value) are skipped without a report.
/// Whenever no valid directive remains, the base falls back to `info`, as
/// for an unset variable, rather than an empty filter that disables all
/// logging.
fn build_filter(
    rust_log: Option<&str>,
    extra_directives: &[String],
) -> Result<(EnvFilter, Option<String>), LoggingError> {
    let mut rejected = Vec::new();
    let mut fell_back = false;
    let base = match rust_log {
        None => EnvFilter::new("info"),
        Some(value) => {
            let valid: Vec<&str> = value
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .filter(|s| match s.parse::<Directive>() {
                    Ok(_) => true,
                    Err(e) => {
                        rejected.push(format!("`{s}`: {e}"));
                        false
                    }
                })
                .collect();
            if valid.is_empty() {
                fell_back = true;
                EnvFilter::new("info")
            } else {
                // Every directive already parsed, so this drops nothing.
                EnvFilter::builder().parse_lossy(valid.join(","))
            }
        }
    };
    let report = (!rejected.is_empty()).then(|| {
        let outcome = if fell_back {
            "no valid directives remain; using info"
        } else {
            "keeping the valid ones"
        };
        format!(
            "ignoring unparseable RUST_LOG directive(s), {outcome}: {}",
            rejected.join("; ")
        )
    });
    Ok((append_directives(base, extra_directives)?, report))
}

/// Append per-peer directives onto a base filter. Split out from
/// [`build_filter`] so tests can pin the base deterministically instead of
/// depending on the ambient `RUST_LOG`.
fn append_directives(
    mut filter: EnvFilter,
    extra_directives: &[String],
) -> Result<EnvFilter, LoggingError> {
    for directive in extra_directives {
        filter = filter.add_directive(
            directive
                .parse()
                .map_err(|e| LoggingError::InvalidDirective(format!("{directive}: {e}")))?,
        );
    }
    Ok(filter)
}

/// Initialize the global tracing subscriber with JSON output and
/// `RUST_LOG` env-filter.
///
/// Call once at startup.  Defaults to `info` level if `RUST_LOG` is not
/// set.
///
/// `extra_directives` are appended to the filter and can include
/// per-peer span filters such as `[peer{peer_addr=10.0.0.1}]=debug` (the
/// span directive MUST be bracketed — see `per_peer_log_directives`).
///
/// The filter is installed behind a [`tracing_subscriber::reload`] handle
/// so per-peer levels can be re-applied at runtime via
/// [`reload_per_peer_directives`] (SIGHUP) without a restart. The global
/// base level is fixed at startup from `RUST_LOG`.
///
/// # Errors
///
/// Returns a [`LoggingError`] if the global subscriber has already been
/// set (e.g., called twice or a test already installed one). An
/// unparseable `RUST_LOG` directive is not an error: it is dropped, the
/// valid directives are kept, and one warning line naming it and its parse
/// error is printed to stderr.
pub fn init_logging(extra_directives: &[String]) -> Result<(), LoggingError> {
    let (filter, report) = build_filter(rust_log_env().as_deref(), extra_directives)?;
    // Reported on stderr rather than as an event: a `warn` would pass
    // through the very filter being reported on, and a `RUST_LOG=error`
    // base would hide it.
    if let Some(report) = report {
        eprintln!("warning: {report}");
    }

    let builder = fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_filter_reloading();
    let handle = builder.reload_handle();
    builder
        .try_init()
        .map_err(|e| LoggingError::AlreadyInitialized(e.to_string()))?;

    // Only publish the reload hook after the subscriber actually installed,
    // so a failed double-init never overwrites a live handle. `set` failing
    // means init_logging ran twice — the first handle stays authoritative.
    let _ = RELOAD_HANDLE.set(Box::new(move |filter| {
        handle.reload(filter).map_err(|e| e.to_string())
    }));
    Ok(())
}

/// Re-apply per-peer log directives to the live subscriber (SIGHUP path).
///
/// Rebuilds the full filter (base level from `RUST_LOG` + all current
/// per-peer directives) and swaps it into the running subscriber, so
/// `log_level` edits take effect without a restart. Reapplying identical
/// directives is a harmless no-op.
///
/// Defensive by construction: a malformed directive is rejected here (the
/// filter is rebuilt into a local before the swap), so the live filter is
/// never taken down — the old one keeps running. Config validation already
/// gates the values; this is belt-and-suspenders.
///
/// # Errors
///
/// Returns [`LoggingError::InvalidDirective`] if a per-peer directive fails
/// to parse (the live filter is left untouched). Unparseable `RUST_LOG`
/// directives are dropped and reported on stderr and as a `warn` event, not
/// an error, or [`LoggingError::ReloadFailed`]
/// if the subscriber was dropped. When no reloadable subscriber is
/// installed (e.g. a test set its own, or `init_logging` was never called),
/// this logs a warning and returns `Ok(())` — a reload with nowhere to go
/// is a no-op, not a failure.
pub fn reload_per_peer_directives(directives: &[String]) -> Result<(), LoggingError> {
    let (filter, report) = build_filter(rust_log_env().as_deref(), directives)?;
    // Also on stderr: the `warn` passes through the filter being reported
    // on, so a `RUST_LOG=error` base would hide it.
    if let Some(report) = report {
        eprintln!("warning: {report}");
        tracing::warn!("{report}");
    }
    if let Some(reload) = RELOAD_HANDLE.get() {
        reload(filter).map_err(LoggingError::ReloadFailed)
    } else {
        tracing::warn!(
            "per-peer log_level reload requested but no reloadable logging \
             subscriber is installed; live filter unchanged"
        );
        Ok(())
    }
}

/// Errors from logging initialization.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The global tracing subscriber was already set.
    #[error("logging subscriber already initialized: {0}")]
    AlreadyInitialized(String),
    /// A per-peer log filter directive was malformed.
    #[error("invalid log filter directive: {0}")]
    InvalidDirective(String),
    /// Swapping the live filter failed (the subscriber was dropped).
    #[error("failed to reload log filter: {0}")]
    ReloadFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::reload;

    #[test]
    fn init_logging_returns_result() {
        // We can't reliably test init_logging() in unit tests because the
        // global subscriber may already be set by another test. Instead,
        // verify that calling it produces a well-formed Result.
        let result = init_logging(&[]);
        // Either Ok (first call) or Err (already set) — neither should panic.
        assert!(result.is_ok() || result.is_err());
    }

    /// Layer that counts events that pass the filter — a probe for whether
    /// the `reload::Handle` + `EnvFilter` actually enable/disable a span level.
    struct CountLayer(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> Layer<S> for CountLayer {
        fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Behavior proof (not just compile): per-peer `log_level` genuinely
    /// updates the live filter, and the global base survives every reload.
    ///
    /// Tests the `reload::Handle` + `EnvFilter` directly (thread-local
    /// `set_default`, no global install) so it is independent of whatever
    /// other tests installed the process-global subscriber. The reloaded
    /// filter is built with the exact `[peer{peer_addr=X}]=level` directive
    /// `per_peer_log_directives` emits, against the exact
    /// `info_span!("peer", peer_addr=...)` span the transport layer creates
    /// — so this pins the string format that actually flips a real span.
    /// (The unbracketed `peer{...}=level` form does NOT parse — that latent
    /// boot-abort bug is exactly what this test would have caught.)
    #[test]
    fn per_peer_directive_reload_flips_span_level_and_keeps_base() {
        let base = EnvFilter::new("info");
        let (filter_layer, handle) = reload::Layer::new(base);
        let count = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(filter_layer)
            .with(CountLayer(count.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let debug_in_peer_span = || {
            let span = tracing::info_span!("peer", peer_addr = "10.0.0.9");
            let _e = span.enter();
            tracing::debug!("probe");
        };
        let info_in_peer_span = || {
            let span = tracing::info_span!("peer", peer_addr = "10.0.0.9");
            let _e = span.enter();
            tracing::info!("base-probe");
        };

        // Base is info: debug inside the peer span is filtered out.
        debug_in_peer_span();
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "debug disabled at base info"
        );
        // ...but the base info level itself is enabled.
        info_in_peer_span();
        assert_eq!(count.load(Ordering::SeqCst), 1, "info enabled at base");

        // Reload with the real directive format for this peer at debug.
        let reloaded = append_directives(
            EnvFilter::new("info"),
            &["[peer{peer_addr=10.0.0.9}]=debug".to_string()],
        )
        .expect("directive parses");
        handle.reload(reloaded).expect("reload succeeds");

        // Debug now reaches the layer for this peer span — live update.
        debug_in_peer_span();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "debug enabled for the peer span after reload"
        );
        // Base info still enabled — the reload did not drop the base level.
        info_in_peer_span();
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "base info survives the reload"
        );

        // Revert to base-only: debug is filtered out again.
        handle
            .reload(EnvFilter::new("info"))
            .expect("revert reload succeeds");
        debug_in_peer_span();
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "debug disabled again after reverting the directive"
        );
    }

    /// A malformed directive is rejected without a subscriber installed,
    /// and `build_filter` surfaces the parse error rather than panicking —
    /// the reload path can then leave the live filter untouched. The bad
    /// level (`notalevel`) is the same failure class the unbracketed
    /// span-directive form trips into.
    #[test]
    fn malformed_directive_is_a_clean_error() {
        let err = build_filter(None, &["target=notalevel".to_string()]);
        assert!(matches!(err, Err(LoggingError::InvalidDirective(_))));
    }

    /// One unparseable `RUST_LOG` directive no longer discards the rest:
    /// `info` survives and the bad directive is reported with its parse
    /// error. The unbracketed span form was once the documented one.
    #[test]
    fn rust_log_keeps_valid_directives_and_reports_invalid_ones() {
        let (filter, report) =
            build_filter(Some("warn,peer{peer_addr=10.0.0.1}=debug"), &[]).expect("filter");
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::WARN));
        let bad = "peer{peer_addr=10.0.0.1}=debug";
        let error = bad
            .parse::<Directive>()
            .expect_err("bad directive")
            .to_string();
        assert_eq!(
            report.as_deref(),
            Some(
                format!(
                    "ignoring unparseable RUST_LOG directive(s), keeping the valid ones: \
                     `{bad}`: {error}"
                )
                .as_str()
            )
        );

        let (filter, report) =
            build_filter(Some("info,peer{peer_addr=10.0.0.1}=debug"), &[]).expect("filter");
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
        assert!(
            report.is_some_and(|r| r.contains("keeping the valid ones") && r.contains(bad)),
            "bad directive reported"
        );
    }

    /// A valid `RUST_LOG` (bracketed span form included) and an unset one
    /// report nothing; unset still defaults to `info`.
    #[test]
    fn valid_or_unset_rust_log_reports_nothing() {
        let (filter, report) =
            build_filter(Some("info,[peer{peer_addr=10.0.0.1}]=debug"), &[]).expect("filter");
        assert_eq!(report, None);
        assert!(
            filter.to_string().contains("peer_addr"),
            "span directive kept: {filter}"
        );

        let (filter, report) = build_filter(None, &[]).expect("filter");
        assert_eq!(report, None);
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
    }

    /// An empty, whitespace-only or separator-only `RUST_LOG` behaves as
    /// unset: `info`, no report. `EnvFilter` alone turns `""` and `","`
    /// into an empty filter that disables all logging.
    #[test]
    fn blank_rust_log_is_info_without_report() {
        for value in ["", " ", ",", " , "] {
            let (filter, report) = build_filter(Some(value), &[]).expect("filter");
            assert_eq!(report, None, "{value:?}");
            assert_eq!(
                filter.max_level_hint(),
                Some(LevelFilter::INFO),
                "{value:?} falls back to info"
            );
        }
    }

    /// A `RUST_LOG` with no valid directive falls back to `info` (as the
    /// old whole-variable rejection did) rather than an empty filter that
    /// would disable all logging, reports what it dropped, and says it is
    /// using `info` rather than claiming to keep valid directives.
    #[test]
    fn wholly_invalid_rust_log_falls_back_to_info_and_reports() {
        let (filter, report) =
            build_filter(Some("foo=notalevel,peer{peer_addr=10.0.0.1}=debug"), &[])
                .expect("filter");
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
        let report = report.expect("report");
        assert!(
            report.starts_with(
                "ignoring unparseable RUST_LOG directive(s), no valid directives remain; using info: "
            ) && report.contains("`foo=notalevel`: ")
                && report.contains("`peer{peer_addr=10.0.0.1}=debug`: "),
            "{report}"
        );
    }
}
