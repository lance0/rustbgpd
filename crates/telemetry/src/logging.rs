//! Structured JSON or human-readable text logging via `tracing`.

use std::collections::HashMap;
use std::io::IsTerminal as _;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Metadata, Subscriber, span};
use tracing_subscriber::filter::{Directive, EnvFilter, FilterExt as _, LevelFilter};
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::{Context, Filter, Layer, SubscriberExt as _};
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::util::SubscriberInitExt as _;

/// Configured per-peer levels, keyed by a session span's peer key: its
/// `peer` field when recorded (an interface-only neighbor's
/// `interface:<name>`), else its `peer_addr`.
#[derive(Debug, Default)]
struct PeerLevels {
    levels: HashMap<String, LevelFilter>,
    /// The most verbose configured level; `None` when there are none.
    max: Option<LevelFilter>,
}

impl PeerLevels {
    fn parse(levels: &[(String, String)]) -> Result<Self, LoggingError> {
        let levels = levels
            .iter()
            .map(|(key, level)| {
                level
                    .parse::<LevelFilter>()
                    .map(|level| (key.clone(), level))
                    .map_err(|e| LoggingError::InvalidDirective(format!("{key}={level}: {e}")))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let max = levels.values().copied().max();
        Ok(Self { levels, max })
    }
}

type SharedPeerLevels = Arc<RwLock<PeerLevels>>;

/// The live per-peer levels, installed by [`init_logging`]. Process-global
/// to match the tracing subscriber itself; a reload swaps the map, and the
/// session spans that already exist read it on their next event.
static PEER_LEVELS: OnceLock<SharedPeerLevels> = OnceLock::new();

/// A `peer` span's key into [`PeerLevels`], kept in its extensions.
struct PeerKey(String);

#[derive(Default)]
struct PeerKeyVisitor {
    peer: Option<String>,
    peer_addr: Option<String>,
}

impl PeerKeyVisitor {
    fn set(&mut self, field: &Field, value: String) {
        match field.name() {
            "peer" => self.peer = Some(value),
            "peer_addr" => self.peer_addr = Some(value),
            _ => {}
        }
    }
}

impl Visit for PeerKeyVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.set(field, format!("{value:?}"));
    }
}

/// Shows every `peer` session span, and enables events inside one at that
/// peer's configured level, read from the live map on every event so a
/// reload reaches sessions that are already running. Combined with the
/// `RUST_LOG` filter by `or`: a per-peer level adds verbosity and never
/// hides what `RUST_LOG` enables, as the span directives it replaces did.
///
/// A session span is created once per session, so showing it at every
/// level costs nothing per message; its fields then accompany the
/// session's events under any `RUST_LOG`, before and after a reload.
///
/// ponytail: one read lock and a scope walk per event while any per-peer
/// level is set; a lock-free swap if that shows up in a profile.
struct PeerLevelFilter(SharedPeerLevels);

impl PeerLevelFilter {
    fn max(&self) -> Option<LevelFilter> {
        self.0.read().unwrap_or_else(PoisonError::into_inner).max
    }
}

fn is_peer_span(meta: &Metadata<'_>) -> bool {
    meta.is_span() && meta.name() == "peer"
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Filter<S> for PeerLevelFilter {
    fn enabled(&self, meta: &Metadata<'_>, cx: &Context<'_, S>) -> bool {
        if meta.is_span() {
            return is_peer_span(meta);
        }
        let peers = self.0.read().unwrap_or_else(PoisonError::into_inner);
        if peers.max.is_none_or(|max| meta.level() > &max) {
            return false;
        }
        let Some(current) = cx.lookup_current() else {
            return false;
        };
        current
            .scope()
            .find_map(|span| {
                span.extensions()
                    .get::<PeerKey>()
                    .map(|PeerKey(key)| peers.levels.get(key).copied())
            })
            .flatten()
            .is_some_and(|level| meta.level() <= &level)
    }

    fn callsite_enabled(&self, meta: &'static Metadata<'static>) -> Interest {
        if is_peer_span(meta) {
            Interest::always()
        } else if self.max().is_some_and(|max| meta.level() <= &max) {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }

    /// At least `INFO`, the `peer` span's level, so a session span is
    /// created under a quieter `RUST_LOG`.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(
            self.max()
                .map_or(LevelFilter::INFO, |max| max.max(LevelFilter::INFO)),
        )
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, cx: Context<'_, S>) {
        if !is_peer_span(attrs.metadata()) {
            return;
        }
        let mut visitor = PeerKeyVisitor::default();
        attrs.record(&mut visitor);
        if let (Some(key), Some(span)) = (visitor.peer.or(visitor.peer_addr), cx.span(id)) {
            span.extensions_mut().insert(PeerKey(key));
        }
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, cx: Context<'_, S>) {
        let mut visitor = PeerKeyVisitor::default();
        values.record(&mut visitor);
        if let (Some(peer), Some(span)) = (visitor.peer, cx.span(id))
            && is_peer_span(span.metadata())
        {
            span.extensions_mut().replace(PeerKey(peer));
        }
    }
}

/// The raw `RUST_LOG` value. Non-UTF-8 bytes are replaced rather than
/// treated as unset, so the directive holding them is reported as
/// unparseable instead of silently discarding the whole variable.
fn rust_log_env() -> Option<String> {
    std::env::var_os("RUST_LOG").map(|v| v.to_string_lossy().into_owned())
}

/// Base filter from a `RUST_LOG` value (`info` when unset).
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
fn build_filter(rust_log: Option<&str>) -> (EnvFilter, Option<String>) {
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
                        // Escaped for the report only, so a control
                        // character in the directive (or echoed in a field
                        // regex error) cannot split the one-line warning.
                        rejected.push(format!(
                            "`{}`: {}",
                            escape_controls(s),
                            escape_controls(&e.to_string())
                        ));
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
    (base, report)
}

/// Escape control characters (`\n` becomes `\\n`) and leave everything else,
/// quotes included, as written.
fn escape_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Replaces the per-peer levels of a [`peer_level_layer`], as
/// [`reload_per_peer_levels`] does for the installed subscriber.
pub struct PeerLevelHandle(SharedPeerLevels);

impl PeerLevelHandle {
    /// Replace the levels; spans that already exist follow on their next
    /// event.
    ///
    /// # Errors
    ///
    /// [`LoggingError::InvalidDirective`] if a level does not parse; the
    /// levels are left untouched.
    pub fn replace(&self, peer_levels: &[(String, String)]) -> Result<(), LoggingError> {
        install_levels(&self.0, PeerLevels::parse(peer_levels)?);
        Ok(())
    }
}

/// `output` filtered by `base` or the per-peer levels, as the daemon's
/// output is, with a handle to its levels (none at first): for tests that
/// drive a real session span.
#[must_use]
pub fn peer_level_layer<S, L>(output: L, base: EnvFilter) -> (impl Layer<S>, PeerLevelHandle)
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    L: Layer<S>,
{
    let peers = SharedPeerLevels::default();
    (
        with_peer_levels(output, base, Arc::clone(&peers)),
        PeerLevelHandle(peers),
    )
}

fn with_peer_levels<S, L>(output: L, base: EnvFilter, peers: SharedPeerLevels) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    L: Layer<S>,
{
    output.with_filter(base.or(PeerLevelFilter(peers)))
}

/// The daemon's one output layer: JSON or text on `writer`, filtered by
/// `RUST_LOG` or the per-peer levels.
fn output_layer<W>(
    json: bool,
    ansi: bool,
    writer: W,
    env: EnvFilter,
    peers: SharedPeerLevels,
) -> Box<dyn Layer<Registry> + Send + Sync>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = fmt::layer()
        .with_writer(writer)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false);
    let output = if json {
        layer.json().boxed()
    } else {
        layer.with_ansi(ansi).boxed()
    };
    with_peer_levels(output, env, peers).boxed()
}

/// Initialize the global tracing subscriber with JSON output (or
/// human-readable text when `json` is false) and `RUST_LOG` env-filter.
///
/// Call once at startup.  Defaults to `info` level if `RUST_LOG` is not
/// set.
///
/// `peer_levels` are `(peer key, level)` pairs: a session's events are also
/// enabled at its peer's level, matched by the `peer` session span's `peer`
/// field when recorded, else its `peer_addr`.
/// [`reload_per_peer_levels`] replaces them at runtime (SIGHUP), and spans
/// that already exist follow. The `RUST_LOG` filter is fixed at startup.
///
/// # Errors
///
/// Returns a [`LoggingError`] if a per-peer level does not parse or the
/// global subscriber has already been set (e.g., called twice or a test
/// already installed one). An unparseable `RUST_LOG` directive is not an
/// error: it is dropped, the valid directives are kept, and one warning
/// line naming it and its parse error is printed to stderr.
pub fn init_logging(peer_levels: &[(String, String)], json: bool) -> Result<(), LoggingError> {
    let peers = Arc::new(RwLock::new(PeerLevels::parse(peer_levels)?));
    let (env, report) = build_filter(rust_log_env().as_deref());
    // Reported on stderr rather than as an event: a `warn` would pass
    // through the very filter being reported on, and a `RUST_LOG=error`
    // base would hide it.
    if let Some(report) = report {
        eprintln!("warning: {report}");
    }
    let ansi = std::io::stdout().is_terminal();
    tracing_subscriber::registry()
        .with(output_layer(
            json,
            ansi,
            std::io::stdout,
            env,
            Arc::clone(&peers),
        ))
        .try_init()
        .map_err(|e| LoggingError::AlreadyInitialized(e.to_string()))?;
    // Only publish after the subscriber actually installed, so a failed
    // double-init never replaces the live map. `set` failing means
    // init_logging ran twice: the first map stays authoritative.
    let _ = PEER_LEVELS.set(peers);
    Ok(())
}

/// Replace the live per-peer levels (SIGHUP path), so `log_level` edits
/// take effect without a restart, in sessions already running as well as
/// new ones. Reapplying identical levels is a harmless no-op.
///
/// # Errors
///
/// Returns [`LoggingError::InvalidDirective`] if a level fails to parse;
/// the live levels are left untouched. Unparseable `RUST_LOG` directives
/// are reported again on stderr and as a `warn` event, not an error. When
/// [`init_logging`] never installed a subscriber (e.g. a test set its own),
/// this logs a warning and returns `Ok(())` — a reload with nowhere to go
/// is a no-op, not a failure.
pub fn reload_per_peer_levels(peer_levels: &[(String, String)]) -> Result<(), LoggingError> {
    let levels = PeerLevels::parse(peer_levels)?;
    // Also on stderr: the `warn` passes through the filter being reported
    // on, so a `RUST_LOG=error` base would hide it.
    if let (_, Some(report)) = build_filter(rust_log_env().as_deref()) {
        eprintln!("warning: {report}");
        tracing::warn!("{report}");
    }
    let Some(live) = PEER_LEVELS.get() else {
        tracing::warn!(
            "per-peer log_level reload requested but no logging subscriber \
             is installed; live levels unchanged"
        );
        return Ok(());
    };
    install_levels(live, levels);
    Ok(())
}

fn install_levels(live: &SharedPeerLevels, levels: PeerLevels) {
    *live.write().unwrap_or_else(PoisonError::into_inner) = levels;
    // Callsite interest and the max-level hint follow the new levels.
    tracing::callsite::rebuild_interest_cache();
}

/// Errors from logging initialization.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The global tracing subscriber was already set.
    #[error("logging subscriber already initialized: {0}")]
    AlreadyInitialized(String),
    /// A per-peer log level was malformed.
    #[error("invalid per-peer log level: {0}")]
    InvalidDirective(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::fmt;

    #[test]
    fn init_logging_installs_once_and_refuses_a_second_install() {
        // The only `init_logging` caller in this test binary, so the first
        // install owns the global subscriber and publishes the live levels.
        init_logging(&[], true).unwrap();
        assert!(PEER_LEVELS.get().is_some());
        assert!(matches!(
            init_logging(&[], false),
            Err(LoggingError::AlreadyInitialized(_))
        ));
    }

    /// Layer that counts events that pass its filter.
    struct CountLayer(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> Layer<S> for CountLayer {
        fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, level)| ((*key).to_owned(), (*level).to_owned()))
            .collect()
    }

    /// A counting subscriber filtered by `base` or the per-peer levels, as
    /// the daemon's output is.
    fn counting(
        base: &str,
    ) -> (
        impl Subscriber + Send + Sync,
        PeerLevelHandle,
        Arc<AtomicUsize>,
    ) {
        let count = Arc::new(AtomicUsize::new(0));
        let (layer, handle) = peer_level_layer(CountLayer(count.clone()), EnvFilter::new(base));
        (tracing_subscriber::registry().with(layer), handle, count)
    }

    fn emitted(count: &AtomicUsize, span: &tracing::Span, level: tracing::Level) -> usize {
        let before = count.load(Ordering::SeqCst);
        span.in_scope(|| match level {
            tracing::Level::ERROR => tracing::error!("probe"),
            tracing::Level::WARN => tracing::warn!("probe"),
            tracing::Level::INFO => tracing::info!("probe"),
            _ => tracing::debug!("probe"),
        });
        count.load(Ordering::SeqCst) - before
    }

    /// A per-peer level edit reaches a session span that already exists,
    /// an unchanged reload keeps it, and removing it takes effect, without
    /// touching the `RUST_LOG` base. An `EnvFilter` span directive matched
    /// only spans created after its reload and dropped a live span's
    /// override at the next one.
    #[test]
    fn per_peer_level_reload_reaches_live_spans_and_keeps_base() {
        let (subscriber, handle, count) = counting("info");
        let _guard = tracing::subscriber::set_default(subscriber);
        let session = tracing::info_span!("peer", peer_addr = "10.0.0.9");
        let other = tracing::info_span!("peer", peer_addr = "10.0.0.8");
        let emitted = |span, level| emitted(&count, span, level);
        assert_eq!(emitted(&session, tracing::Level::DEBUG), 0, "base info");
        assert_eq!(emitted(&session, tracing::Level::INFO), 1, "base info");

        // Mutation-red: a level captured when the span is created never
        // reaches this live span.
        handle.replace(&pairs(&[("10.0.0.9", "debug")])).unwrap();
        assert_eq!(emitted(&session, tracing::Level::DEBUG), 1, "live span");
        assert_eq!(emitted(&other, tracing::Level::DEBUG), 0, "other peer");
        handle.replace(&pairs(&[("10.0.0.9", "debug")])).unwrap();
        assert_eq!(emitted(&session, tracing::Level::DEBUG), 1, "unchanged");

        handle.replace(&[]).unwrap();
        assert_eq!(emitted(&session, tracing::Level::DEBUG), 0, "removed");
        assert_eq!(emitted(&session, tracing::Level::INFO), 1, "base kept");
    }

    /// Above an `info` base a session span is still recorded, so a level
    /// set later, or one below the span's own level, reaches it.
    #[test]
    fn a_quieter_base_still_lets_a_reload_reach_the_session() {
        for (base, level, event) in [
            ("warn", "debug", tracing::Level::DEBUG),
            ("error", "warn", tracing::Level::WARN),
        ] {
            let (subscriber, handle, count) = counting(base);
            let _guard = tracing::subscriber::set_default(subscriber);
            let session = tracing::info_span!("peer", peer_addr = "10.0.0.9");
            assert_eq!(emitted(&count, &session, event), 0, "{base} base");
            // Mutation-red: a span neither filter enabled when it started
            // keeps no key for the reload to find.
            handle.replace(&pairs(&[("10.0.0.9", level)])).unwrap();
            assert_eq!(emitted(&count, &session, event), 1, "{base} base, {level}");
        }
    }

    /// A recorded `peer` field, an interface-only session's stable label,
    /// is its key; its learned `peer_addr` no longer selects it.
    #[test]
    fn a_recorded_peer_label_keys_the_session() {
        let (subscriber, handle, count) = counting("info");
        let _guard = tracing::subscriber::set_default(subscriber);
        let session =
            tracing::info_span!("peer", peer_addr = "fe80::2", peer = tracing::field::Empty);
        session.record("peer", "interface:swp1");
        handle.replace(&pairs(&[("fe80::2", "debug")])).unwrap();
        assert_eq!(
            emitted(&count, &session, tracing::Level::DEBUG),
            0,
            "an address-keyed level does not match"
        );
        handle
            .replace(&pairs(&[("interface:swp1", "debug")]))
            .unwrap();
        assert_eq!(
            emitted(&count, &session, tracing::Level::DEBUG),
            1,
            "the label matches"
        );
    }

    /// A `Vec` behind a lock, as a `fmt` writer.
    #[derive(Clone, Default)]
    struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    /// Events outside and inside two session spans, one with a debug level.
    fn emit_log_sample() {
        tracing::info!(answer = 42, "outside");
        let debugged = tracing::info_span!("peer", peer_addr = "10.0.0.9", remote_asn = 65002);
        let other = tracing::info_span!("peer", peer_addr = "10.0.0.8", remote_asn = 65003);
        for span in [&debugged, &other] {
            span.in_scope(|| {
                tracing::info!(prefixes = 3, "inside");
                tracing::debug!("detail");
                tracing::warn!(reason = "x", "warned");
            });
        }
    }

    /// Output lines without the timestamp each line starts with.
    fn untimed(buffer: &Buffer, json: bool) -> String {
        let bytes = buffer.0.lock().unwrap().clone();
        let text = String::from_utf8(bytes).unwrap();
        let mut untimed = String::new();
        for line in text.lines() {
            let (_, rest) = if json {
                line.split_once(",\"level\"").unwrap()
            } else {
                line.split_once(' ').unwrap()
            };
            untimed.push_str(rest);
            untimed.push('\n');
        }
        untimed
    }

    /// The sample's output through the daemon's layer.
    fn new_output(json: bool, base: &str, level: Option<&str>) -> String {
        let buffer = Buffer::default();
        let peer_levels = level.map_or_else(Vec::new, |level| pairs(&[("10.0.0.9", level)]));
        let live = Arc::new(RwLock::new(PeerLevels::parse(&peer_levels).unwrap()));
        let subscriber = tracing_subscriber::registry().with(output_layer(
            json,
            false,
            buffer.clone(),
            EnvFilter::new(base),
            live,
        ));
        tracing::subscriber::with_default(subscriber, emit_log_sample);
        untimed(&buffer, json)
    }

    /// Under the default `info` base the JSON and text output, with and
    /// without a per-peer level, match the `fmt` subscriber with an
    /// `EnvFilter` span directive that this layer replaced, byte for byte
    /// past the timestamp. Under a quieter base the same events print
    /// exactly as they do under `info`, session span fields included.
    #[test]
    fn output_matches_the_env_filter_subscriber() {
        for json in [true, false] {
            for (level, lines) in [(Some("debug"), 6), (None, 5)] {
                let mut filter = EnvFilter::new("info");
                if let Some(level) = level {
                    filter = filter.add_directive(
                        format!("[peer{{peer_addr=10.0.0.9}}]={level}")
                            .parse()
                            .unwrap(),
                    );
                }
                let old = Buffer::default();
                let builder = fmt()
                    .with_writer(old.clone())
                    .with_env_filter(filter)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_ansi(false);
                if json {
                    tracing::subscriber::with_default(builder.json().finish(), emit_log_sample);
                } else {
                    tracing::subscriber::with_default(builder.finish(), emit_log_sample);
                }
                let (old, info) = (untimed(&old, json), new_output(json, "info", level));
                let case = format!("json={json} level={level:?}");
                assert_eq!(info.lines().count(), lines, "{case}: {info}");
                assert_eq!(info, old, "{case}");

                for (base, kept) in [("warn", "WARN"), ("error", "ERROR")] {
                    // Mutation-red: a span hidden from the output drops its
                    // fields from the session's warn and error events.
                    let mut expected = String::new();
                    for line in info.lines().filter(|line| {
                        line.contains(kept)
                            || (kept == "WARN" && line.contains("ERROR"))
                            || (level.is_some() && line.contains("10.0.0.9"))
                    }) {
                        expected.push_str(line);
                        expected.push('\n');
                    }
                    assert_eq!(
                        new_output(json, base, level),
                        expected,
                        "{case} base={base}"
                    );
                }
            }
        }
    }

    /// Under a quieter `RUST_LOG`, a level set by a reload on a session that
    /// is already running prints its events with the session span's fields,
    /// in JSON and in text.
    #[test]
    fn a_reload_under_a_quieter_base_keeps_the_span_fields() {
        for json in [true, false] {
            let buffer = Buffer::default();
            let live = SharedPeerLevels::default();
            let subscriber = tracing_subscriber::registry().with(output_layer(
                json,
                false,
                buffer.clone(),
                EnvFilter::new("warn"),
                Arc::clone(&live),
            ));
            tracing::subscriber::with_default(subscriber, || {
                let session =
                    tracing::info_span!("peer", peer_addr = "10.0.0.9", remote_asn = 65002);
                install_levels(
                    &live,
                    PeerLevels::parse(&pairs(&[("10.0.0.9", "debug")])).unwrap(),
                );
                session.in_scope(|| tracing::debug!("after reload"));
            });
            let output = untimed(&buffer, json);
            let fields = if json {
                ["\"peer_addr\":\"10.0.0.9\"", "\"remote_asn\":65002"]
            } else {
                ["peer_addr=\"10.0.0.9\"", "remote_asn=65002"]
            };
            // Mutation-red: a span shown only when a level was set at its
            // creation leaves the line without its fields.
            assert!(
                output.contains("after reload") && fields.iter().all(|f| output.contains(f)),
                "json={json}: {output}"
            );
        }
    }

    /// A malformed per-peer level is a clean error, not a panic, and the
    /// reload path then leaves the live levels untouched.
    #[test]
    fn malformed_peer_level_is_a_clean_error() {
        let pairs = [("10.0.0.1".to_owned(), "notalevel".to_owned())];
        assert!(matches!(
            PeerLevels::parse(&pairs),
            Err(LoggingError::InvalidDirective(_))
        ));
    }

    /// One unparseable `RUST_LOG` directive no longer discards the rest:
    /// `info` survives and the bad directive is reported with its parse
    /// error. The unbracketed span form was once the documented one.
    #[test]
    fn rust_log_keeps_valid_directives_and_reports_invalid_ones() {
        let (filter, report) = build_filter(Some("warn,peer{peer_addr=10.0.0.1}=debug"));
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

        let (filter, report) = build_filter(Some("info,peer{peer_addr=10.0.0.1}=debug"));
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
        let (filter, report) = build_filter(Some("info,[peer{peer_addr=10.0.0.1}]=debug"));
        assert_eq!(report, None);
        assert!(
            filter.to_string().contains("peer_addr"),
            "span directive kept: {filter}"
        );

        let (filter, report) = build_filter(None);
        assert_eq!(report, None);
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
    }

    /// An empty, whitespace-only or separator-only `RUST_LOG` behaves as
    /// unset: `info`, no report. `EnvFilter` alone turns `""` and `","`
    /// into an empty filter that disables all logging.
    #[test]
    fn blank_rust_log_is_info_without_report() {
        for value in ["", " ", ",", " , "] {
            let (filter, report) = build_filter(Some(value));
            assert_eq!(report, None, "{value:?}");
            assert_eq!(
                filter.max_level_hint(),
                Some(LevelFilter::INFO),
                "{value:?} falls back to info"
            );
        }
    }

    /// A control character in a rejected directive is escaped, so the
    /// report stays one line and cannot pass for separate log output.
    #[test]
    fn rejected_directive_is_escaped_in_the_report() {
        let (filter, report) = build_filter(Some("info,bad\nlevel=x"));
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
        let report = report.expect("report");
        assert!(!report.contains(['\n', '\r']), "{report:?}");
        assert!(report.contains("`bad\\nlevel=x`: "), "{report:?}");
        let (_, report) = build_filter(Some("bad\r\u{1b}[2J=x"));
        let report = report.expect("report");
        assert!(!report.chars().any(char::is_control), "{report:?}");
        assert!(report.contains("`bad\\r\\u{1b}[2J=x`: "), "{report:?}");
    }

    /// A `RUST_LOG` with no valid directive falls back to `info` (as the
    /// old whole-variable rejection did) rather than an empty filter that
    /// would disable all logging, reports what it dropped, and says it is
    /// using `info` rather than claiming to keep valid directives.
    #[test]
    fn wholly_invalid_rust_log_falls_back_to_info_and_reports() {
        let (filter, report) = build_filter(Some("foo=notalevel,peer{peer_addr=10.0.0.1}=debug"));
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
