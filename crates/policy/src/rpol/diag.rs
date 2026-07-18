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

/// One compile error: a message, labeled source spans (the first is
/// primary), and free-form notes (used for did-you-mean suggestions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
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
        Self {
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

    /// Render every diagnostic against a multi-module compile
    /// (LAN-300): `sources[i]` is the `(display path, text)` of module
    /// `i`, matching each span's `file` index, so an error in an
    /// imported file renders an excerpt of — and names — that file.
    ///
    /// # Panics
    ///
    /// Never in practice: writing to an in-memory buffer is infallible.
    #[must_use]
    pub fn render_sources(&self, sources: &[(String, String)], color: bool) -> String {
        use ariadne::{Config, Label, Report, ReportKind};

        let name_of = |span: &Span| -> String {
            sources
                .get(span.file as usize)
                .or_else(|| sources.first())
                .map(|(name, _)| name.clone())
                .unwrap_or_default()
        };
        let mut out = Vec::new();
        for diag in &self.0 {
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
            report
                .finish()
                .write(ariadne::sources(sources.to_vec()), &mut out)
                .expect("writing a diagnostic to an in-memory buffer cannot fail");
        }
        String::from_utf8_lossy(&out).into_owned()
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
