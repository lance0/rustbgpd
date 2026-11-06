//! Diagnostics for the `.rpol` frontend: labeled source spans rendered
//! through `ariadne`.
//!
//! Every parse and type error carries at least one span+label pair into
//! the original source; [`Diagnostics::render`] produces the familiar
//! excerpt-with-underline report. Rendering is colorless by default so
//! output is byte-stable in tests; the CLI opts into color when stderr
//! is a terminal.

use std::fmt;
use std::ops::Range;

/// A byte range into one source file of a compile.
///
/// `file` indexes the module list of the compile that produced the
/// span (LAN-300): 0 is the main file, which is also the only file a
/// single-source compile ([`crate::rpol::RpolFile::parse`]) ever has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset of the first character.
    pub start: usize,
    /// Byte offset one past the last character.
    pub end: usize,
    /// Module (file) index within the compile; 0 = main file.
    pub file: u32,
}

impl Span {
    /// Construct a span from a byte range into the main file.
    #[must_use]
    pub fn new(range: Range<usize>) -> Self {
        Self::in_file(range, 0)
    }

    /// Construct a span from a byte range into module `file`.
    #[must_use]
    pub fn in_file(range: Range<usize>, file: u32) -> Self {
        Self {
            start: range.start,
            end: range.end,
            file,
        }
    }

    /// The smallest span covering both `self` and `other`.
    #[must_use]
    pub fn to(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            file: self.file,
        }
    }

    /// The span as a byte range.
    #[must_use]
    pub fn range(self) -> Range<usize> {
        self.start..self.end
    }
}

/// A value paired with its source span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    /// The value.
    pub node: T,
    /// Where it came from in the source.
    pub span: Span,
}

impl<T> Spanned<T> {
    /// Pair a value with its span.
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }
}

/// Compiler stage that produced a diagnostic, with stable CLI labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// A diagnostic constructed without an explicit stage.
    Compile,
    /// Tokenization failed.
    Lex,
    /// Source syntax is invalid.
    Parse,
    /// Module or external binding resolution failed.
    Resolve,
    /// Typechecking, name checking, or a static resource bound failed.
    Typecheck,
    /// Lowering to the executable policy representation failed.
    Lower,
}

impl DiagnosticCode {
    /// Stable `rbgp policy check -j` finding code.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Compile => "compile-error",
            Self::Lex => "lex-error",
            Self::Parse => "parse-error",
            Self::Resolve => "resolve-error",
            Self::Typecheck => "typecheck-error",
            Self::Lower => "lower-error",
        }
    }
}

/// One compile error: a message, labeled source spans (the first is
/// primary), and free-form notes (used for did-you-mean suggestions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The compiler stage, independent of the human-readable message.
    pub code: DiagnosticCode,
    /// Top-line error message.
    pub message: String,
    /// Labeled spans; the first is the primary location.
    pub labels: Vec<(Span, String)>,
    /// Trailing notes (suggestions, semantics reminders).
    pub notes: Vec<String>,
}

impl Diagnostic {
    /// A diagnostic with one primary label.
    #[must_use]
    pub fn new(span: Span, message: impl Into<String>, label: impl Into<String>) -> Self {
        Self::coded(DiagnosticCode::Compile, span, message, label)
    }

    /// A diagnostic attributed to one compiler stage.
    #[must_use]
    pub fn coded(
        code: DiagnosticCode,
        span: Span,
        message: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            labels: vec![(span, label.into())],
            notes: Vec::new(),
        }
    }

    /// Attach a secondary labeled span.
    #[must_use]
    pub fn with_label(mut self, span: Span, label: impl Into<String>) -> Self {
        self.labels.push((span, label.into()));
        self
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// The accumulated diagnostics of one compile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics(pub Vec<Diagnostic>);

impl Diagnostics {
    /// True when no diagnostics were produced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Render every diagnostic as an ariadne report against `source`,
    /// attributed to `filename` — the single-source form; every span's
    /// `file` index is expected to be 0. `color` enables ANSI styling.
    #[must_use]
    pub fn render(&self, filename: &str, source: &str, color: bool) -> String {
        self.render_sources(&[(filename.to_string(), source.to_string())], color)
    }

    /// Render the diagnostics against a multi-module compile (LAN-300):
    /// `sources[i]` is the `(display path, text)` of module `i`, matching
    /// each span's `file` index, so an error in an imported file renders
    /// an excerpt of — and names — that file.
    ///
    /// The output is bounded: at most [`MAX_RENDERED_DIAGNOSTICS`]
    /// reports and about [`MAX_RENDERED_BYTES`] bytes, with a closing
    /// line counting what was left out. The sources are indexed once for
    /// all reports, so the cost is linear in source size plus the
    /// reports rendered.
    #[must_use]
    pub fn render_sources(&self, sources: &[(String, String)], color: bool) -> String {
        use ariadne::{Config, Label, Report, ReportKind};
        use std::fmt::Write as _;

        let name_of = |span: &Span| -> String {
            sources
                .get(span.file as usize)
                .or_else(|| sources.first())
                .map(|(name, _)| name.clone())
                .unwrap_or_default()
        };
        // One line index per source for every report; building it per
        // report made rendering quadratic in the diagnostic count.
        let mut cache = ariadne::sources(
            sources
                .iter()
                .map(|(name, text)| (name.clone(), text.as_str())),
        );
        let mut out = CappedBuffer::default();
        let mut rendered = 0;
        for diag in self.0.iter().take(MAX_RENDERED_DIAGNOSTICS) {
            let primary = diag.labels.first().map_or_else(
                || (name_of(&Span::new(0..0)), 0..0),
                |(span, _)| (name_of(span), span.range()),
            );
            let mut report = Report::build(ReportKind::Error, primary)
                .with_config(Config::default().with_color(color))
                .with_message(&diag.message);
            for (index, (span, label)) in diag.labels.iter().enumerate() {
                report = report.with_label(
                    Label::new((name_of(span), span.range()))
                        .with_message(label)
                        .with_order(i32::try_from(index).unwrap_or(i32::MAX)),
                );
            }
            for note in &diag.notes {
                report = report.with_note(note);
            }
            if report.finish().write(&mut cache, &mut out).is_err() {
                break; // the byte cap: the partial report stays, marked below
            }
            rendered += 1;
        }
        let truncated = out.full;
        let mut text = String::from_utf8_lossy(&out.bytes).into_owned();
        let omitted = self.0.len() - rendered;
        if truncated {
            let _ = writeln!(
                text,
                "\n... output truncated at {MAX_RENDERED_BYTES} bytes; {omitted} more \
                 diagnostic(s) not shown"
            );
        } else if omitted > 0 {
            let _ = writeln!(text, "... {omitted} more diagnostic(s) not shown");
        }
        text
    }
}

/// Reports rendered by [`Diagnostics::render_sources`]; the rest are counted.
pub const MAX_RENDERED_DIAGNOSTICS: usize = 50;

/// Rendered bytes kept by [`Diagnostics::render_sources`].
pub const MAX_RENDERED_BYTES: usize = 256 * 1024;

/// An in-memory writer that accepts [`MAX_RENDERED_BYTES`], then fails.
#[derive(Default)]
struct CappedBuffer {
    bytes: Vec<u8>,
    full: bool,
}

impl std::io::Write for CappedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = MAX_RENDERED_BYTES - self.bytes.len();
        if buf.len() > room {
            self.bytes.extend_from_slice(&buf[..room]);
            self.full = true;
            return Err(std::io::Error::other("diagnostic output cap reached"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for diag in &self.0 {
            writeln!(f, "error: {}", diag.message)?;
        }
        Ok(())
    }
}

/// Levenshtein edit distance, used for did-you-mean suggestions.
fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b_chars.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let next = (prev + cost).min(row[j] + 1).min(row[j + 1] + 1);
            prev = row[j + 1];
            row[j + 1] = next;
        }
    }
    *row.last().expect("row is never empty")
}

/// The closest candidate to `name` within a small edit distance, for
/// "did you mean" notes. Candidates further than 1/3 of the name's
/// length (minimum 2) away are not suggested.
pub(crate) fn closest<'a>(
    name: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    closest_matches(name, candidates, 1).into_iter().next()
}

/// Up to `max` candidates to `name` within a small edit distance, closest
/// first, for "did you mean" suggestions. Candidates further than 1/3 of
/// the name's length (minimum 2) away are not suggested. Shared by the
/// `.rpol` frontend and the TOML config diagnostics.
pub fn closest_matches<'a>(
    name: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    max: usize,
) -> Vec<&'a str> {
    let budget = (name.len() / 3).max(2);
    let mut ranked: Vec<(usize, &str)> = candidates
        .into_iter()
        .map(|candidate| (edit_distance(name, candidate), candidate))
        .filter(|&(distance, _)| distance <= budget)
        .collect();
    ranked.sort_by_key(|&(distance, _)| distance);
    ranked
        .into_iter()
        .take(max)
        .map(|(_, candidate)| candidate)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closest_suggests_within_budget() {
        assert_eq!(
            closest("custmers", ["customers", "bogons"]),
            Some("customers")
        );
        assert_eq!(closest("zzz", ["customers", "bogons"]), None);
    }

    /// Thousands of diagnostics against a large source render within a fixed
    /// bound: the sources are indexed once and the output is capped.
    #[test]
    fn render_is_bounded_for_many_diagnostics() {
        use std::fmt::Write as _;

        let mut source = String::new();
        for index in 0..4000 {
            let _ = writeln!(
                source,
                "policy p{index} {{ term t {{ if route.nosuch == 1 {{ reject }} }} }}"
            );
        }
        let Err(diagnostics) = crate::rpol::RpolFile::parse(&source) else {
            panic!("unknown route fields fail to compile");
        };
        let count = diagnostics.len();
        assert!(count >= 4000, "{count}");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(diagnostics.render("candidate.rpol", &source, false));
        });
        let rendered = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("rendering 4000 diagnostics against 280 KB finishes within 10 s");
        assert!(
            rendered.len() <= MAX_RENDERED_BYTES + 256,
            "{}",
            rendered.len()
        );
        assert!(
            rendered.contains(&format!(
                "{} more diagnostic(s) not shown",
                count - MAX_RENDERED_DIAGNOSTICS
            )),
            "{}",
            &rendered[rendered.len().saturating_sub(300)..]
        );
    }

    /// One oversized report still stops at the byte cap.
    #[test]
    fn render_stops_at_the_byte_cap() {
        let source = format!("{}\n", "x".repeat(MAX_RENDERED_BYTES * 2));
        let diags = Diagnostics(vec![
            Diagnostic::new(Span::new(0..source.len() - 1), "long", "here"),
            Diagnostic::new(Span::new(0..1), "second", "here"),
        ]);
        let rendered = diags.render("long.rpol", &source, false);
        assert!(
            rendered.len() <= MAX_RENDERED_BYTES + 256,
            "{}",
            rendered.len()
        );
        assert!(
            rendered.contains("output truncated"),
            "{}",
            &rendered[rendered.len() - 200..]
        );
    }

    #[test]
    fn render_contains_label_text() {
        let diags = Diagnostics(vec![
            Diagnostic::new(Span::new(4..9), "unknown thing", "not defined")
                .with_note("did you mean `known`?"),
        ]);
        let out = diags.render("test.rpol", "abc known", false);
        assert!(out.contains("unknown thing"), "{out}");
        assert!(out.contains("not defined"), "{out}");
        assert!(out.contains("did you mean `known`?"), "{out}");
        assert!(out.contains("test.rpol"), "{out}");
    }
}
