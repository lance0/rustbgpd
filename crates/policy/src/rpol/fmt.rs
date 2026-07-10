//! The canonical `.rpol` formatter (`rbgp policy fmt`, LAN-323).
//!
//! One style, zero options (the gofmt philosophy). This is a
//! **concrete-syntax** formatter: the AST drops comments as lexer
//! trivia, so formatting re-lays-out the *token stream* — comments
//! included — and never adds, removes, or reorders a token
//! (semicolons stay exactly as written; they are optional in the
//! grammar). Whitespace and newlines carry no meaning in `.rpol`, so
//! any re-layout of the same token stream parses identically; the
//! formatter still proves it by re-lexing its own output and
//! comparing the full interleaved token-and-comment sequence before
//! returning ([`format_rpol`] fails closed on any mismatch).
//!
//! The canonical style (derived from `docs/rpol-language.md` and the
//! repo's `.rpol` receipts — documented in the "Formatting" section
//! of the language reference):
//!
//! - 4-space indent, one statement per line, `policy p {` brace
//!   placement, closing brace on its own line.
//! - A `term` / `if` / `else` body stays inline when it holds exactly
//!   one statement, contains no comments, and the line fits in 100
//!   columns; `policy`, `test`, `fn`, and `for` bodies always expand.
//! - Set bodies and test `route` / `peer` / `dataset` fixtures stay
//!   inline when they fit, else one member per line.
//! - Single spaces around operators; no space after a call name or
//!   inside parentheses/brackets; blank-line runs collapse to one;
//!   one blank line before every top-level `policy` / `fn` / `test`;
//!   no trailing whitespace; single trailing newline.
//!
//! Import/set/policy declaration order is never changed (import order
//! is semantic — resolution is depth-first in declaration order).

use std::fmt;

use super::diag::Diagnostics;
use super::lexer::{self, Tok};
use super::parser;

/// Maximum rendered line width considered when deciding whether a
/// block stays inline. Statements with no block to expand may exceed
/// it (the formatter never wraps expressions).
const MAX_WIDTH: usize = 100;
/// One indentation level.
const INDENT: &str = "    ";

/// Why a source could not be formatted.
#[derive(Debug)]
pub enum FmtError {
    /// The source has lex or parse errors — broken files are refused,
    /// never "formatted".
    Syntax(Diagnostics),
    /// An internal invariant failed (the output did not re-lex to the
    /// input's token-and-comment sequence). Nothing is returned in
    /// this case, so a formatter bug can never corrupt a policy file.
    Internal(String),
}

impl fmt::Display for FmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FmtError::Syntax(diags) => write!(
                f,
                "{} syntax error{} — fix them (see `rbgp policy check`) before formatting",
                diags.len(),
                if diags.len() == 1 { "" } else { "s" },
            ),
            FmtError::Internal(msg) => write!(f, "internal formatter error: {msg}"),
        }
    }
}

impl std::error::Error for FmtError {}

/// Format `.rpol` source into the canonical style.
///
/// Guarantees: the output re-lexes to the exact input sequence of
/// tokens (kind and text) and comments (order preserved, trailing
/// whitespace trimmed) — verified before returning — so
/// `parse(fmt(x))` is structurally identical to `parse(x)` and
/// compiles to identical IR. `format_rpol` is idempotent.
///
/// # Errors
///
/// [`FmtError::Syntax`] when the source has lex/parse diagnostics;
/// [`FmtError::Internal`] if the re-lex verification fails (formatter
/// bug — the input is left untouched).
pub fn format_rpol(source: &str) -> Result<String, FmtError> {
    let events = events(source).map_err(FmtError::Syntax)?;
    let (_, parse_diags) = parser::parse(source);
    if !parse_diags.is_empty() {
        return Err(FmtError::Syntax(Diagnostics(parse_diags)));
    }
    let tree = build_tree(&events)
        .map_err(|()| FmtError::Internal("unbalanced braces past the parse gate".into()))?;
    let mut lines = Vec::new();
    render_block(&tree, Ctx::Top, 0, &mut lines);
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    verify(&events, &out)?;
    Ok(out)
}

// ─── events: the interleaved token + comment stream ────────────────

/// One concrete-syntax event: a token or a comment, with the count of
/// newlines separating it from the previous event (0 = same line,
/// 1 = next line, ≥2 = at least one blank line between).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event<'a> {
    Tok { kind: Tok, text: &'a str, nl: u32 },
    Comment { text: &'a str, nl: u32 },
}

impl Event<'_> {
    /// Layout-independent identity: token kind + text, or the
    /// right-trimmed comment text. This is what verification compares.
    fn identity(&self) -> (Option<Tok>, &str) {
        match self {
            Event::Tok { kind, text, .. } => (Some(*kind), *text),
            Event::Comment { text, .. } => (None, text.trim_end()),
        }
    }
}

/// Lex `source` and recover the comments the lexer skips as trivia:
/// comments live in the gaps between token spans (a `#` inside a
/// string literal is inside a token span, never a gap).
fn events(source: &str) -> Result<Vec<Event<'_>>, Diagnostics> {
    let (tokens, diags) = lexer::lex(source, 0);
    if !diags.is_empty() {
        return Err(Diagnostics(diags));
    }
    let mut out = Vec::with_capacity(tokens.len());
    let mut pos = 0usize;
    let mut nl = 0u32;
    for token in &tokens {
        let range = token.span.range();
        scan_gap(&source[pos..range.start], &mut out, &mut nl);
        out.push(Event::Tok {
            kind: token.kind,
            text: &source[range.clone()],
            nl,
        });
        nl = 0;
        pos = range.end;
    }
    scan_gap(&source[pos..], &mut out, &mut nl);
    Ok(out)
}

/// Scan an inter-token gap for newlines and `#` comments.
fn scan_gap<'a>(gap: &'a str, out: &mut Vec<Event<'a>>, nl: &mut u32) {
    let bytes = gap.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                *nl += 1;
                i += 1;
            }
            b'#' => {
                let end = gap[i..].find('\n').map_or(gap.len(), |off| i + off);
                out.push(Event::Comment {
                    text: gap[i..end].trim_end(),
                    nl: *nl,
                });
                *nl = 0;
                i = end;
            }
            _ => i += 1,
        }
    }
}

// ─── tree: events grouped by braces ─────────────────────────────────

/// A concrete-syntax node. Only braces group (they are the only
/// layout-driving delimiters); parentheses and brackets stay flat.
#[derive(Debug)]
enum Node<'a> {
    Tok { kind: Tok, text: &'a str, nl: u32 },
    Comment { text: &'a str, nl: u32 },
    Group { nl: u32, children: Vec<Node<'a>> },
}

impl Node<'_> {
    fn nl(&self) -> u32 {
        match self {
            Node::Tok { nl, .. } | Node::Comment { nl, .. } | Node::Group { nl, .. } => *nl,
        }
    }
}

fn build_tree<'a>(events: &[Event<'a>]) -> Result<Vec<Node<'a>>, ()> {
    let mut stack: Vec<(u32, Vec<Node<'a>>)> = Vec::new();
    let mut current: Vec<Node<'a>> = Vec::new();
    for event in events {
        match *event {
            Event::Tok {
                kind: Tok::LBrace,
                nl,
                ..
            } => {
                stack.push((nl, std::mem::take(&mut current)));
            }
            Event::Tok {
                kind: Tok::RBrace, ..
            } => {
                let (nl, mut parent) = stack.pop().ok_or(())?;
                parent.push(Node::Group {
                    nl,
                    children: std::mem::take(&mut current),
                });
                current = parent;
            }
            Event::Tok { kind, text, nl } => current.push(Node::Tok { kind, text, nl }),
            Event::Comment { text, nl } => current.push(Node::Comment { text, nl }),
        }
    }
    if stack.is_empty() {
        Ok(current)
    } else {
        Err(())
    }
}

// ─── statement structure ────────────────────────────────────────────

/// What kind of block the renderer is laying out. Statement
/// boundaries and inline eligibility are context-dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// The file: imports, dataset declarations, sets, fns, policies,
    /// tests.
    Top,
    /// A `policy` body: `term` statements.
    Policy,
    /// A `test` body: `dataset` overrides, `route`/`peer` fixtures,
    /// `expect` lines.
    Test,
    /// A `term` / `if` / `else` / `for` / `fn` body: actions, `let`,
    /// `for`, nested `if`, a `fn` result expression.
    Body,
    /// A comma-separated member list (set bodies, test `dataset`
    /// overrides).
    CommaList,
    /// A semicolon-separated field list (test `route` / `peer`
    /// fixtures).
    FieldList,
}

/// The block context a brace group opens, plus whether the canonical
/// style ever renders it inline, keyed on the head token of the
/// statement that owns the group.
fn group_style(head_kind: Tok, head_text: &str, ctx: Ctx) -> (Ctx, bool) {
    match head_kind {
        Tok::PolicyKw => (Ctx::Policy, false),
        Tok::TestKw => (Ctx::Test, false),
        Tok::TermKw | Tok::IfKw => (Ctx::Body, true),
        Tok::PrefixSetKw | Tok::CommunitySetKw | Tok::AsnSetKw => (Ctx::CommaList, true),
        Tok::RouteKw | Tok::PeerKw if ctx == Ctx::Test => (Ctx::FieldList, true),
        Tok::Ident if head_text == "dataset" && ctx == Ctx::Test => (Ctx::CommaList, true),
        // `for` and `fn` bodies always expand (canon: the docs never
        // inline them); unknown heads expand defensively.
        _ => (Ctx::Body, false),
    }
}

/// One renderable unit of a block: a standalone comment or a
/// statement (a slice of the block's children).
enum Unit {
    Comment(usize),
    Stmt(std::ops::Range<usize>),
}

fn split_units(children: &[Node<'_>], ctx: Ctx) -> Vec<Unit> {
    let mut units = Vec::new();
    let mut i = 0;
    while i < children.len() {
        if matches!(children[i], Node::Comment { .. }) {
            units.push(Unit::Comment(i));
            i += 1;
            continue;
        }
        let end = stmt_end(children, i, ctx);
        units.push(Unit::Stmt(i..end));
        i = end;
    }
    units
}

/// First token (kind, text) of a node slice, skipping comments.
fn first_tok<'a>(nodes: &[Node<'a>]) -> Option<(Tok, &'a str)> {
    nodes.iter().find_map(|node| match node {
        Node::Tok { kind, text, .. } => Some((*kind, *text)),
        _ => None,
    })
}

/// Kind of the `n`-th token-or-group after index `i` (0 = the node at
/// `i` itself), skipping comments. Groups report as `LBrace`.
fn peek_kind(children: &[Node<'_>], i: usize, n: usize) -> Option<Tok> {
    children[i..]
        .iter()
        .filter_map(|node| match node {
            Node::Tok { kind, .. } => Some(*kind),
            Node::Group { .. } => Some(Tok::LBrace),
            Node::Comment { .. } => None,
        })
        .nth(n)
}

fn peek_is_ident(children: &[Node<'_>], i: usize, n: usize) -> bool {
    peek_kind(children, i, n) == Some(Tok::Ident)
}

/// Whether `prev` expects an operand after it — an `Ident` following
/// one of these continues an expression and never starts a statement
/// (guards the contextual `let`/`for`/`break`/`continue` heuristics).
fn expects_operand(prev: Tok) -> bool {
    matches!(
        prev,
        Tok::Plus
            | Tok::Minus
            | Tok::Star
            | Tok::Slash
            | Tok::Percent
            | Tok::EqEq
            | Tok::Eq
            | Tok::NotEq
            | Tok::GtEq
            | Tok::LtEq
            | Tok::AndAnd
            | Tok::OrOr
            | Tok::Bang
            | Tok::Comma
            | Tok::Dot
            | Tok::Colon
            | Tok::LParen
            | Tok::LBracket
            | Tok::InKw
            | Tok::HasKw
            | Tok::GeKw
            | Tok::LeKw
            | Tok::MatchesKw
            | Tok::ContainsKw
            | Tok::AsKw
            | Tok::WithKw
            | Tok::IfKw
            | Tok::SetKw
            | Tok::AddKw
            | Tok::RemoveKw
            | Tok::PrependKw
            | Tok::ExpectKw
            | Tok::Arrow
    )
}

/// Whether `kind` can begin a value-expression atom (the grammar's
/// `atom` / `field` heads).
fn is_atom_start(kind: Tok) -> bool {
    matches!(
        kind,
        Tok::Ident | Tok::Int | Tok::StdCommunityLit | Tok::RouteKw | Tok::PeerKw
    )
}

/// Whether `prev` can end a complete value expression. Two adjacent
/// atoms are never one expression, so inside an expression-shaped
/// statement (`let` initializer, `fn` result) an atom start after one
/// of these begins the next statement.
fn ends_expr(prev: Tok) -> bool {
    matches!(
        prev,
        Tok::Ident | Tok::Int | Tok::RParen | Tok::StdCommunityLit
    )
}

/// Whether the token at `i` starts a new statement in `ctx`. `prev`
/// is the last token consumed by the statement being scanned;
/// `expr_head` says that statement is expression-shaped (a `let` or a
/// bare value expression), where atom adjacency is a boundary.
fn is_starter(children: &[Node<'_>], i: usize, ctx: Ctx, prev: Tok, expr_head: bool) -> bool {
    let Node::Tok { kind, text, .. } = &children[i] else {
        return false;
    };
    match ctx {
        Ctx::Top => match kind {
            Tok::PolicyKw
            | Tok::TestKw
            | Tok::PrefixSetKw
            | Tok::CommunitySetKw
            | Tok::AsnSetKw => true,
            Tok::Ident => match *text {
                "import" => peek_kind(children, i, 1) == Some(Tok::Str),
                "fn" => {
                    peek_is_ident(children, i, 1) && peek_kind(children, i, 2) == Some(Tok::LParen)
                }
                "dataset" => matches!(
                    peek_kind(children, i, 1),
                    Some(Tok::PrefixSetKw | Tok::CommunitySetKw | Tok::AsnSetKw)
                ),
                _ => false,
            },
            _ => false,
        },
        Ctx::Policy => *kind == Tok::TermKw,
        Ctx::Test => match kind {
            Tok::RouteKw | Tok::PeerKw | Tok::ExpectKw => true,
            Tok::Ident => {
                *text == "dataset"
                    && peek_is_ident(children, i, 1)
                    && peek_kind(children, i, 2) == Some(Tok::LBrace)
            }
            _ => false,
        },
        Ctx::Body => match kind {
            Tok::IfKw
            | Tok::SetKw
            | Tok::AddKw
            | Tok::RemoveKw
            | Tok::PrependKw
            | Tok::AcceptKw
            | Tok::RejectKw => true,
            Tok::Ident
                if !expects_operand(prev)
                    && match *text {
                        "let" => {
                            peek_is_ident(children, i, 1)
                                && peek_kind(children, i, 2) == Some(Tok::Eq)
                        }
                        "for" => {
                            peek_is_ident(children, i, 1)
                                && peek_kind(children, i, 2) == Some(Tok::InKw)
                        }
                        "break" | "continue" => true,
                        _ => false,
                    } =>
            {
                true
            }
            k if expr_head && is_atom_start(*k) && ends_expr(prev) => true,
            _ => false,
        },
        Ctx::CommaList | Ctx::FieldList => false,
    }
}

/// End (exclusive) of the statement starting at `start`. Statements
/// end at their brace group (with `else` continuation for `if`), at a
/// consumed separator, before the next statement starter, before an
/// own-line comment, or at the end of the block.
fn stmt_end(children: &[Node<'_>], start: usize, ctx: Ctx) -> usize {
    let head = first_tok(&children[start..=start]);
    // Element lists: consume through the separator.
    if let Ctx::CommaList | Ctx::FieldList = ctx {
        let sep = if ctx == Ctx::CommaList {
            Tok::Comma
        } else {
            Tok::Semi
        };
        let mut i = start + 1;
        while i < children.len() {
            match &children[i] {
                Node::Comment { nl, .. } if *nl >= 1 => break,
                Node::Tok { kind, .. } if *kind == sep => return i + 1,
                _ => i += 1,
            }
        }
        return i;
    }
    // Top-level `dataset KIND NAME` — fixed arity, no braces; handled
    // explicitly so the KIND keyword is not mistaken for a set
    // definition starting.
    if ctx == Ctx::Top
        && let Some((Tok::Ident, "dataset")) = head
    {
        let mut i = start + 1;
        let mut toks = 0;
        while i < children.len() && toks < 2 {
            if matches!(children[i], Node::Tok { .. }) {
                toks += 1;
            }
            i += 1;
        }
        return i;
    }
    let head_kind = head.map_or(Tok::Ident, |(kind, _)| kind);
    // Expression-shaped statements (`let ...`, a `fn` body's result
    // expression) end at atom adjacency; `for` heads scan to their
    // group instead, and a `let` suppresses boundary checks until its
    // `=` is consumed (`let x =` is a declaration prefix, not atoms).
    let expr_head = ctx == Ctx::Body
        && is_atom_start(head_kind)
        && head.is_none_or(|(kind, text)| kind != Tok::Ident || text != "for");
    let mut in_let_prefix = matches!(head, Some((Tok::Ident, "let")));
    let mut prev = head_kind;
    let mut i = start + 1;
    while i < children.len() {
        match &children[i] {
            // An own-line comment is a statement boundary; a trailing
            // comment (same line) rides with the statement.
            Node::Comment { nl, .. } => {
                if *nl >= 1 {
                    break;
                }
                i += 1;
            }
            Node::Group { .. } => {
                i += 1;
                if head_kind == Tok::IfKw
                    && let Some(Node::Tok {
                        kind: Tok::ElseKw, ..
                    }) = children.get(i)
                {
                    i += 1;
                    while i < children.len() {
                        let done = matches!(children[i], Node::Group { .. });
                        i += 1;
                        if done {
                            break;
                        }
                    }
                }
                break;
            }
            Node::Tok { kind, .. } => {
                if *kind == Tok::Semi {
                    i += 1;
                    break;
                }
                if !in_let_prefix && is_starter(children, i, ctx, prev, expr_head) {
                    break;
                }
                if *kind == Tok::Eq {
                    in_let_prefix = false;
                }
                prev = *kind;
                i += 1;
            }
        }
    }
    i
}

// ─── rendering ──────────────────────────────────────────────────────

/// Whether a space separates two adjacent tokens.
fn needs_space(prev: Tok, next: Tok) -> bool {
    if matches!(
        next,
        Tok::Comma | Tok::Semi | Tok::Colon | Tok::Dot | Tok::RParen | Tok::RBracket
    ) {
        return false;
    }
    if matches!(prev, Tok::LParen | Tok::LBracket | Tok::Dot | Tok::Bang) {
        return false;
    }
    // Call syntax is tight: `min(`, `apply(`, `customer-in(200)`.
    if next == Tok::LParen && matches!(prev, Tok::Ident | Tok::ApplyKw) {
        return false;
    }
    true
}

fn push_tok(line: &mut String, prev: &mut Option<Tok>, kind: Tok, text: &str) {
    if let Some(p) = *prev
        && needs_space(p, kind)
    {
        line.push(' ');
    }
    line.push_str(text);
    *prev = Some(kind);
}

/// Render one statement on a single line, or `None` when the
/// canonical style forbids it (a comment anywhere inside, a
/// never-inline block, or a `term`/`if`/`else` body holding more than
/// one statement). Width is the caller's concern.
fn render_inline(nodes: &[Node<'_>], ctx: Ctx) -> Option<String> {
    let head = first_tok(nodes)?;
    let mut s = String::new();
    let mut prev: Option<Tok> = None;
    for node in nodes {
        match node {
            Node::Comment { .. } => return None,
            Node::Tok { kind, text, .. } => push_tok(&mut s, &mut prev, *kind, text),
            Node::Group { children, .. } => {
                let (gctx, inlinable) = group_style(head.0, head.1, ctx);
                if !inlinable {
                    return None;
                }
                push_tok(&mut s, &mut prev, Tok::LBrace, "{");
                if children.is_empty() {
                    push_tok(&mut s, &mut prev, Tok::RBrace, "}");
                    continue;
                }
                if gctx == Ctx::Body && split_units(children, gctx).len() != 1 {
                    return None;
                }
                let inner = render_inline(children, gctx)?;
                s.push(' ');
                s.push_str(&inner);
                s.push_str(" }");
                prev = Some(Tok::RBrace);
            }
        }
    }
    Some(s)
}

/// Render one statement in the expanded form: every brace group in it
/// becomes an indented block (inner statements re-attempt inlining
/// individually via [`render_block`]).
fn render_expanded(nodes: &[Node<'_>], ctx: Ctx, indent: usize, out: &mut Vec<String>) {
    let Some(head) = first_tok(nodes) else {
        return;
    };
    let base = INDENT.repeat(indent);
    let mut cur = base.clone();
    let mut prev: Option<Tok> = None;
    for node in nodes {
        match node {
            Node::Comment { text, nl } => {
                // A trailing comment ends its line (a `#` runs to end
                // of line); the statement continues indented one more
                // level. Mid-statement own-line comments keep their
                // own line. Both shapes are rare and stay verbatim.
                if *nl == 0 && !cur.trim().is_empty() {
                    cur.push(' ');
                    cur.push_str(text);
                    out.push(std::mem::take(&mut cur));
                } else {
                    if !cur.trim().is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                    out.push(format!("{base}{text}"));
                }
                cur = format!("{base}{INDENT}");
                prev = None;
            }
            Node::Tok { kind, text, .. } => push_tok(&mut cur, &mut prev, *kind, text),
            Node::Group { children, .. } => {
                let (gctx, _) = group_style(head.0, head.1, ctx);
                push_tok(&mut cur, &mut prev, Tok::LBrace, "{");
                if children.is_empty() {
                    push_tok(&mut cur, &mut prev, Tok::RBrace, "}");
                    continue;
                }
                out.push(std::mem::take(&mut cur));
                render_block(children, gctx, indent + 1, out);
                cur = format!("{base}}}");
                prev = Some(Tok::RBrace);
            }
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
}

/// Render a block's children: statements one per line (inline where
/// the style allows), standalone comments at the block indent,
/// trailing comments on their statement's line, blank runs collapsed
/// to one. At top level a blank line is forced before every
/// `policy` / `fn` / `test` (attached leading comments move with it).
fn render_block(children: &[Node<'_>], ctx: Ctx, indent: usize, out: &mut Vec<String>) {
    let units = split_units(children, ctx);
    let forced = forced_blanks(children, &units, ctx);
    let base = INDENT.repeat(indent);
    let mut first = true;
    for (idx, unit) in units.iter().enumerate() {
        match unit {
            Unit::Comment(i) => {
                let Node::Comment { text, nl } = &children[*i] else {
                    unreachable!("comment unit indexes a comment node");
                };
                if *nl == 0
                    && !first
                    && let Some(last) = out.last_mut()
                {
                    last.push(' ');
                    last.push_str(text);
                    continue;
                }
                if (*nl >= 2 || forced[idx]) && !first {
                    out.push(String::new());
                }
                out.push(format!("{base}{text}"));
            }
            Unit::Stmt(range) => {
                let nodes = &children[range.clone()];
                let nl = nodes.first().map_or(0, Node::nl);
                if (nl >= 2 || forced[idx]) && !first {
                    out.push(String::new());
                }
                let has_group = nodes.iter().any(|n| matches!(n, Node::Group { .. }));
                match render_inline(nodes, ctx) {
                    Some(s)
                        if !has_group || base.chars().count() + s.chars().count() <= MAX_WIDTH =>
                    {
                        out.push(format!("{base}{s}"));
                    }
                    _ => render_expanded(nodes, ctx, indent, out),
                }
            }
        }
        first = false;
    }
}

/// Top-level blank forcing: one blank line before every `policy`,
/// `fn`, and `test` item, placed before the comment block attached to
/// it (comments contiguous with the item, one newline apart).
fn forced_blanks(children: &[Node<'_>], units: &[Unit], ctx: Ctx) -> Vec<bool> {
    let mut forced = vec![false; units.len()];
    if ctx != Ctx::Top {
        return forced;
    }
    for (idx, unit) in units.iter().enumerate() {
        let Unit::Stmt(range) = unit else { continue };
        let big = matches!(
            first_tok(&children[range.clone()]),
            Some((Tok::PolicyKw | Tok::TestKw, _) | (Tok::Ident, "fn"))
        );
        if !big {
            continue;
        }
        let mut j = idx;
        while j > 0 && matches!(units[j - 1], Unit::Comment(_)) && unit_nl(children, &units[j]) == 1
        {
            j -= 1;
        }
        forced[j] = true;
    }
    forced
}

fn unit_nl(children: &[Node<'_>], unit: &Unit) -> u32 {
    match unit {
        Unit::Comment(i) => children[*i].nl(),
        Unit::Stmt(range) => children[range.clone()].first().map_or(0, Node::nl),
    }
}

// ─── verification ───────────────────────────────────────────────────

/// Prove the output carries the input's exact interleaved
/// token-and-comment sequence (the whole semantic content of the
/// file — layout is the only thing allowed to change).
fn verify(input: &[Event<'_>], output: &str) -> Result<(), FmtError> {
    let reparsed = events(output)
        .map_err(|d| FmtError::Internal(format!("output does not lex: {} errors", d.len())))?;
    if input.len() != reparsed.len() {
        return Err(FmtError::Internal(format!(
            "event count changed: {} -> {}",
            input.len(),
            reparsed.len()
        )));
    }
    for (a, b) in input.iter().zip(&reparsed) {
        if a.identity() != b.identity() {
            return Err(FmtError::Internal(format!(
                "event changed: {:?} -> {:?}",
                a.identity(),
                b.identity()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sets::SetStore;

    fn fmt(source: &str) -> String {
        format_rpol(source).expect("formats cleanly")
    }

    #[test]
    fn canonical_layout_from_messy_source() {
        let messy =
            "policy  customer-in( peer_lp :u32 ){term rpki-guard{if route.rpki==invalid{reject}}
            term customer-routes { if route.prefix in customers&&route.communities has 65000:100 {
            set local-pref peer_lp;add community 65001:999;accept } } }";
        assert_eq!(
            fmt(messy),
            "policy customer-in(peer_lp: u32) {\n\
             \x20   term rpki-guard { if route.rpki == invalid { reject } }\n\
             \x20   term customer-routes {\n\
             \x20       if route.prefix in customers && route.communities has 65000:100 {\n\
             \x20           set local-pref peer_lp;\n\
             \x20           add community 65001:999;\n\
             \x20           accept\n\
             \x20       }\n\
             \x20   }\n\
             }\n"
        );
    }

    #[test]
    fn single_statement_bodies_inline_and_multi_statement_bodies_expand() {
        assert_eq!(
            fmt("policy p { term rest { accept } }"),
            "policy p {\n    term rest { accept }\n}\n"
        );
        // Two statements in the term body: one per line.
        assert_eq!(
            fmt("policy p { term t { set med 5 accept } }"),
            "policy p {\n    term t {\n        set med 5\n        accept\n    }\n}\n"
        );
        // A `for` body never inlines, even when it would fit.
        assert_eq!(
            fmt(
                "policy p { term t { for asn in route.as-path { if asn in bogons { reject } } accept } }"
            ),
            "policy p {\n\
             \x20   term t {\n\
             \x20       for asn in route.as-path {\n\
             \x20           if asn in bogons { reject }\n\
             \x20       }\n\
             \x20       accept\n\
             \x20   }\n\
             }\n"
        );
    }

    #[test]
    fn sets_and_test_fixtures_inline_when_they_fit() {
        let src = "prefix-set customers{10.10.0.0/16 ge 24 le 26,192.168.1.0/24}
            test t{route{prefix 10.10.1.0/24;communities [65000:100,65000:666];med 300}
            expect customer-in(300)==accept with local-pref 300,med 0}";
        assert_eq!(
            fmt(src),
            "prefix-set customers { 10.10.0.0/16 ge 24 le 26, 192.168.1.0/24 }\n\
             \n\
             test t {\n\
             \x20   route { prefix 10.10.1.0/24; communities [65000:100, 65000:666]; med 300 }\n\
             \x20   expect customer-in(300) == accept with local-pref 300, med 0\n\
             }\n"
        );
    }

    #[test]
    fn oversized_set_expands_one_member_per_line() {
        let src = format!(
            "prefix-set big {{ {} }}",
            (0..6)
                .map(|i| format!("10.{i}.0.0/16 ge 24 le 28"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let out = fmt(&src);
        assert!(out.starts_with("prefix-set big {\n    10.0.0.0/16 ge 24 le 28,\n"));
        assert!(out.ends_with("    10.5.0.0/16 ge 24 le 28\n}\n"));
    }

    #[test]
    fn comments_survive_and_force_expansion() {
        let src = "policy p { term t { # why we reject\n if route.rpki == invalid { reject } } }";
        assert_eq!(
            fmt(src),
            "policy p {\n\
             \x20   term t {\n\
             \x20       # why we reject\n\
             \x20       if route.rpki == invalid { reject }\n\
             \x20   }\n\
             }\n"
        );
        // Trailing comments stay on their statement's line.
        let src = "policy p { term t {\n set med 5; # scrubbed\n accept } }";
        assert!(fmt(src).contains("        set med 5; # scrubbed\n"));
    }

    #[test]
    fn semicolons_are_preserved_verbatim() {
        // The formatter never adds or removes tokens: both spellings
        // keep their author's semicolons.
        let with_semis = fmt("policy p { term t { set med 5; accept } }");
        let without = fmt("policy p { term t { set med 5 accept } }");
        assert!(with_semis.contains("set med 5;\n"));
        assert!(without.contains("set med 5\n"));
    }

    #[test]
    fn blank_lines_collapse_and_policies_get_a_leading_blank() {
        let src = "prefix-set a { 10.0.0.0/8 }\nprefix-set b { 192.0.2.0/24 }\n\n\n\n# edge import\npolicy p { term t { accept } }";
        assert_eq!(
            fmt(src),
            "prefix-set a { 10.0.0.0/8 }\n\
             prefix-set b { 192.0.2.0/24 }\n\
             \n\
             # edge import\n\
             policy p {\n    term t { accept }\n}\n"
        );
        // The blank is forced even when the author left none, and the
        // attached comment moves with the policy.
        let src = "prefix-set a { 10.0.0.0/8 }\n# attached\npolicy p { term t { accept } }";
        assert!(fmt(src).contains("}\n\n# attached\npolicy p {"));
    }

    #[test]
    fn top_level_items_and_datasets_keep_declaration_order() {
        let src = "import \"lib/a.rpol\"\nimport \"lib/b.rpol\"\ndataset asn-set customers\ndataset prefix-set bogons\nasn-set partners { 64999 }";
        assert_eq!(
            fmt(src),
            "import \"lib/a.rpol\"\n\
             import \"lib/b.rpol\"\n\
             dataset asn-set customers\n\
             dataset prefix-set bogons\n\
             asn-set partners { 64999 }\n"
        );
    }

    #[test]
    fn let_for_fn_and_else_shapes_format() {
        let src =
            "fn penalty(len: u32, weight: u32) -> u32 { let base = len * weight min(base, 1000) }
            policy p { term t { let x = route.med+1
            if x >= 500 { reject } else { set med x } } }";
        assert_eq!(
            fmt(src),
            "fn penalty(len: u32, weight: u32) -> u32 {\n\
             \x20   let base = len * weight\n\
             \x20   min(base, 1000)\n\
             }\n\
             \n\
             policy p {\n\
             \x20   term t {\n\
             \x20       let x = route.med + 1\n\
             \x20       if x >= 500 { reject } else { set med x }\n\
             \x20   }\n\
             }\n"
        );
        // A multi-statement `else` body expands both branches.
        let src =
            "policy p { term t { if route.med >= 500 { reject } else { set med 5; accept } } }";
        assert_eq!(
            fmt(src),
            "policy p {\n\
             \x20   term t {\n\
             \x20       if route.med >= 500 {\n\
             \x20           reject\n\
             \x20       } else {\n\
             \x20           set med 5;\n\
             \x20           accept\n\
             \x20       }\n\
             \x20   }\n\
             }\n"
        );
    }

    #[test]
    fn syntax_errors_are_refused() {
        assert!(matches!(
            format_rpol("policy p { term t { @@ } }"),
            Err(FmtError::Syntax(_))
        ));
        assert!(matches!(
            format_rpol("policy p { term t {"),
            Err(FmtError::Syntax(_))
        ));
        // Empty input formats to empty output.
        assert_eq!(fmt(""), "");
    }

    /// The two hard guarantees, property-tested over every `.rpol`
    /// fixture in the repository plus the fuzz seed corpus:
    /// `fmt(fmt(x)) == fmt(x)`, and the formatted output compiles to
    /// IR identical to the original's (when the original compiles
    /// standalone). Token/comment-sequence preservation is verified
    /// inside `format_rpol` itself on every call.
    #[test]
    fn idempotence_and_compile_identity_over_repo_fixtures() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let dirs = [
            root.join("fuzz/seeds/rpol_compile"),
            root.join("../../tests/interop/configs"),
            root.join("../../examples"),
        ];
        let mut files = Vec::new();
        for dir in dirs {
            collect_rpol(&dir, &mut files);
        }
        assert!(
            files.len() >= 21,
            "expected the fixture corpus (fuzz seeds + interop configs + examples), found {}",
            files.len()
        );
        let mut formatted = 0usize;
        let mut ir_checked = 0usize;
        for path in &files {
            let source = std::fs::read_to_string(path).unwrap();
            let once = match format_rpol(&source) {
                Ok(out) => out,
                // Deliberately broken fixtures (parse-error seeds) are
                // refused, never mangled.
                Err(FmtError::Syntax(_)) => continue,
                Err(err) => panic!("{}: {err}", path.display()),
            };
            let twice = format_rpol(&once)
                .unwrap_or_else(|err| panic!("{}: reformat failed: {err}", path.display()));
            assert_eq!(once, twice, "{}: fmt is not idempotent", path.display());
            formatted += 1;
            // Compile identity where the file compiles standalone
            // (files using imports/datasets need the config loader).
            let mut store_a = SetStore::new();
            if let Ok(original) = super::super::compile_rpol(&source, &mut store_a) {
                let mut store_b = SetStore::new();
                let reformatted =
                    super::super::compile_rpol(&once, &mut store_b).unwrap_or_else(|d| {
                        panic!(
                            "{}: formatted output does not compile: {d:?}",
                            path.display()
                        )
                    });
                assert_eq!(
                    original,
                    reformatted,
                    "{}: formatting changed the compiled IR",
                    path.display()
                );
                ir_checked += 1;
            }
        }
        assert!(formatted >= 15, "only {formatted} fixtures formatted");
        assert!(ir_checked >= 8, "only {ir_checked} fixtures IR-compared");
        println!(
            "fixtures: {} total, {formatted} formatted+idempotent, {ir_checked} IR-identical",
            files.len()
        );
    }

    fn collect_rpol(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rpol(&path, out);
            } else if path.extension().is_some_and(|e| e == "rpol") {
                out.push(path);
            }
        }
    }
}
