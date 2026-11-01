//! The `.rpol` lexer (`logos`-generated), producing spanned tokens.
//!
//! Design notes (documented in `docs/reference/rpol-language.md`):
//!
//! - Structural words are reserved keywords; attribute/field names
//!   (`local-pref`, `communities`, …) and enum members (`valid`,
//!   `internal`, …) are *contextual* identifiers matched by the parser.
//! - Identifiers are kebab-case: `[A-Za-z_][A-Za-z0-9_]*(-[part])*`.
//!   Maximal munch is permanent (ADR-0103 Decision 2.1): `a-b` is one
//!   identifier, so binary `-` (LAN-299 arithmetic) requires
//!   whitespace — `route.med - 1` subtracts, `route.med-1` is an
//!   unknown-field error.
//! - Community, prefix, and IP literals are single tokens resolved by
//!   maximal munch: `10.0.0.0/8` is one prefix token, `65000:100` one
//!   standard-community token, `65000:1:2` one large-community token,
//!   `RT:65001:100` / `RO:...` extended-community tokens (`LC:` is an
//!   accepted large-community spelling for parity with the TOML
//!   frontend). IPv6 literals must use the compressed `::` form
//!   (all-numeric full-form IPv6 would be ambiguous with community
//!   literals).

use logos::Logos;

use super::diag::{Diagnostic, DiagnosticCode, Span};

/// One `.rpol` token kind. Text is recovered by slicing the source
/// with the token's span.
#[derive(Logos, Debug, Clone, Copy, PartialEq, Eq)]
#[logos(skip r"[ \t\r\n\f]+")]
#[logos(skip(r"#[^\n]*", allow_greedy = true))]
pub enum Tok {
    // ── literals (order/priority matters — see module docs) ────────
    /// `RT:65001:100`, `RO:192.0.2.1:5` — extended-community literal.
    #[regex(r"(RT|RO):([0-9]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+")]
    ExtCommunityLit,
    /// `65000:*:*` — exact global-admin large-community removal wildcard.
    #[regex(r"[0-9]+:\*:\*")]
    LargeCommunityWildcard,
    /// `*:*:*` — every large community (`remove large-community *:*:*`).
    #[token("*:*:*")]
    LargeCommunityAllWildcard,
    /// `65000:1:2` or `LC:65000:1:2` — large-community literal.
    #[regex(r"(LC:)?[0-9]+:[0-9]+:[0-9]+")]
    LargeCommunityLit,
    /// `65000:100` — standard-community literal.
    #[regex(r"[0-9]+:[0-9]+")]
    StdCommunityLit,
    /// `65000:*`, `*:666`, `65000:100..199`, `PRIVATE_AS:*`,
    /// `65000:1..9:*`, `RT:65000:*` — a community-set member pattern.
    /// Every field is a number, `*`, `a..b` or `PRIVATE_AS`. The lowest
    /// priority hands an all-number spelling, `65000:*:*` and `*:*:*` to
    /// the tokens above, so existing sources lex unchanged; every other
    /// match was a lex or parse error before (ADR-0103 Decision 2.3).
    /// `PRIVATE_AS` must end its field: `65000:PRIVATE_ASX` is a lex
    /// error, not a pattern followed by an identifier.
    #[regex(
        r"((LC:)?(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?):(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?):(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?)|(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?):(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?)|(RT|RO):(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(\*|PRIVATE_AS[A-Za-z0-9_]*(-[A-Za-z0-9_]+)*|[0-9]+(\.\.[0-9]+)?))",
        exact_private_as,
        priority = 1
    )]
    CommunityPattern,
    /// `10.0.0.0/8`, `2001:db8::/32` — prefix literal.
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+")]
    #[regex(r"[0-9A-Fa-f:]*::[0-9A-Fa-f:.]*/[0-9]+")]
    #[regex(r"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/[0-9]+")]
    PrefixLit,
    /// `192.0.2.1` — IPv4 address literal.
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")]
    Ipv4Lit,
    /// `2001:db8::1`, `::1` — IPv6 address literal (compressed form).
    #[regex(r"[0-9A-Fa-f:]*::[0-9A-Fa-f:.]*")]
    #[regex(r"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}")]
    Ipv6Lit,
    /// Unsigned integer literal.
    #[regex(r"[0-9]+")]
    Int,
    /// Double-quoted string (AS-path regexes, peer-group names).
    #[regex(r#""([^"\\]|\\.)*""#)]
    Str,

    // ── keywords ────────────────────────────────────────────────────
    /// `prefix-set`
    #[token("prefix-set")]
    PrefixSetKw,
    /// `community-set`
    #[token("community-set")]
    CommunitySetKw,
    /// `asn-set`
    #[token("asn-set")]
    AsnSetKw,
    /// `policy`
    #[token("policy")]
    PolicyKw,
    /// `term`
    #[token("term")]
    TermKw,
    /// `test`
    #[token("test")]
    TestKw,
    /// `if`
    #[token("if")]
    IfKw,
    /// `else`
    #[token("else")]
    ElseKw,
    /// `set`
    #[token("set")]
    SetKw,
    /// `add`
    #[token("add")]
    AddKw,
    /// `remove`
    #[token("remove")]
    RemoveKw,
    /// `prepend`
    #[token("prepend")]
    PrependKw,
    /// `accept`
    #[token("accept")]
    AcceptKw,
    /// `reject`
    #[token("reject")]
    RejectKw,
    /// `apply`
    #[token("apply")]
    ApplyKw,
    /// `in`
    #[token("in")]
    InKw,
    /// `has`
    #[token("has")]
    HasKw,
    /// `matches`
    #[token("matches")]
    MatchesKw,
    /// `contains`
    #[token("contains")]
    ContainsKw,
    /// `ge`
    #[token("ge")]
    GeKw,
    /// `le`
    #[token("le")]
    LeKw,
    /// `route`
    #[token("route")]
    RouteKw,
    /// `peer`
    #[token("peer")]
    PeerKw,
    /// `expect`
    #[token("expect")]
    ExpectKw,
    /// `with`
    #[token("with")]
    WithKw,
    /// `as`
    #[token("as")]
    AsKw,
    /// `self`
    #[token("self")]
    SelfKw,
    /// `u32`
    #[token("u32")]
    U32Kw,

    // ── identifiers ─────────────────────────────────────────────────
    /// Kebab-case identifier: set / policy / term / field / enum names.
    #[regex(r"[A-Za-z_][A-Za-z0-9_]*(-[A-Za-z0-9_]+)*")]
    Ident,

    // ── punctuation / operators ─────────────────────────────────────
    /// `{`
    #[token("{")]
    LBrace,
    /// `}`
    #[token("}")]
    RBrace,
    /// `(`
    #[token("(")]
    LParen,
    /// `)`
    #[token(")")]
    RParen,
    /// `[`
    #[token("[")]
    LBracket,
    /// `]`
    #[token("]")]
    RBracket,
    /// `,`
    #[token(",")]
    Comma,
    /// `;`
    #[token(";")]
    Semi,
    /// `.`
    #[token(".")]
    Dot,
    /// `:`
    #[token(":")]
    Colon,
    /// `==`
    #[token("==")]
    EqEq,
    /// `=` — `let` binding initializer (LAN-302). Un-lexable before
    /// bindings landed (`==` already lexed as one token, and logos
    /// prefers the longer match), so purely additive — ADR-0103
    /// Decision 2.3.
    #[token("=")]
    Eq,
    /// `!=`
    #[token("!=")]
    NotEq,
    /// `>=`
    #[token(">=")]
    GtEq,
    /// `<=`
    #[token("<=")]
    LtEq,
    /// `&&`
    #[token("&&")]
    AndAnd,
    /// `||`
    #[token("||")]
    OrOr,
    /// `!`
    #[token("!")]
    Bang,
    /// `+` (LAN-299 checked arithmetic; un-lexable before arithmetic
    /// landed, so purely additive — ADR-0103 Decision 2.3).
    #[token("+")]
    Plus,
    /// `-` as an operator token. Kebab-case maximal munch is permanent
    /// (ADR-0103 Decision 2.1): the identifier rule consumes `a-b` as
    /// one name, so subtraction requires whitespace (`a - b`);
    /// `route.med-1` is an unknown-field error, not `med - 1`.
    #[token("-")]
    Minus,
    /// `*`
    #[token("*")]
    Star,
    /// `/`
    #[token("/")]
    Slash,
    /// `%`
    #[token("%")]
    Percent,
    /// `->` — the function return-type arrow (LAN-304). Un-lexable
    /// before functions landed (`-` was a token but `>` alone was
    /// not, so any `->` was a lex error), and the kebab identifier
    /// rule cannot consume it (`>` is not an identifier character):
    /// purely additive — ADR-0103 Decision 2.3.
    #[token("->")]
    Arrow,
}

/// Accept a pattern token only when every `PRIVATE_AS…` field is exactly
/// `PRIVATE_AS`. The token regex extends that spelling over identifier
/// characters, so a longer name is one rejected token rather than a
/// pattern followed by an identifier.
fn exact_private_as(lex: &logos::Lexer<'_, Tok>) -> bool {
    lex.slice()
        .split(':')
        .all(|field| !field.starts_with("PRIVATE_AS") || field == "PRIVATE_AS")
}

impl Tok {
    /// Human-readable token description for error messages.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Tok::ExtCommunityLit => "extended-community literal",
            Tok::LargeCommunityWildcard => "large-community global-admin wildcard",
            Tok::LargeCommunityAllWildcard => "`*:*:*`",
            Tok::LargeCommunityLit => "large-community literal",
            Tok::StdCommunityLit => "community literal",
            Tok::CommunityPattern => "community pattern",
            Tok::PrefixLit => "prefix literal",
            Tok::Ipv4Lit | Tok::Ipv6Lit => "IP address literal",
            Tok::Int => "integer",
            Tok::Str => "string",
            Tok::PrefixSetKw => "`prefix-set`",
            Tok::CommunitySetKw => "`community-set`",
            Tok::AsnSetKw => "`asn-set`",
            Tok::PolicyKw => "`policy`",
            Tok::TermKw => "`term`",
            Tok::TestKw => "`test`",
            Tok::IfKw => "`if`",
            Tok::ElseKw => "`else`",
            Tok::SetKw => "`set`",
            Tok::AddKw => "`add`",
            Tok::RemoveKw => "`remove`",
            Tok::PrependKw => "`prepend`",
            Tok::AcceptKw => "`accept`",
            Tok::RejectKw => "`reject`",
            Tok::ApplyKw => "`apply`",
            Tok::InKw => "`in`",
            Tok::HasKw => "`has`",
            Tok::MatchesKw => "`matches`",
            Tok::ContainsKw => "`contains`",
            Tok::GeKw => "`ge`",
            Tok::LeKw => "`le`",
            Tok::RouteKw => "`route`",
            Tok::PeerKw => "`peer`",
            Tok::ExpectKw => "`expect`",
            Tok::WithKw => "`with`",
            Tok::AsKw => "`as`",
            Tok::SelfKw => "`self`",
            Tok::U32Kw => "`u32`",
            Tok::Ident => "identifier",
            Tok::LBrace => "`{`",
            Tok::RBrace => "`}`",
            Tok::LParen => "`(`",
            Tok::RParen => "`)`",
            Tok::LBracket => "`[`",
            Tok::RBracket => "`]`",
            Tok::Comma => "`,`",
            Tok::Semi => "`;`",
            Tok::Dot => "`.`",
            Tok::Colon => "`:`",
            Tok::EqEq => "`==`",
            Tok::Eq => "`=`",
            Tok::NotEq => "`!=`",
            Tok::GtEq => "`>=`",
            Tok::LtEq => "`<=`",
            Tok::AndAnd => "`&&`",
            Tok::OrOr => "`||`",
            Tok::Bang => "`!`",
            Tok::Plus => "`+`",
            Tok::Minus => "`-`",
            Tok::Star => "`*`",
            Tok::Slash => "`/`",
            Tok::Percent => "`%`",
            Tok::Arrow => "`->`",
        }
    }
}

/// A token with its source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// The token kind.
    pub kind: Tok,
    /// Its byte range in the source.
    pub span: Span,
}

/// Lex the entire source, attributing spans to module index `file`
/// (0 for a single-source compile). Unrecognized characters become
/// diagnostics (one per contiguous bad region) and lexing continues,
/// so the parser still sees — and can report on — the rest of the
/// file.
#[must_use]
pub fn lex(source: &str, file: u32) -> (Vec<Token>, Vec<Diagnostic>) {
    let mut tokens = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    for (result, range) in Tok::lexer(source).spanned() {
        let span = Span::in_file(range, file);
        let Ok(kind) = result else {
            // Coalesce adjacent error characters into one diagnostic.
            if let Some(last) = diagnostics.last_mut()
                && let Some((last_span, _)) = last.labels.first_mut()
                && last_span.end == span.start
            {
                last_span.end = span.end;
                continue;
            }
            diagnostics.push(Diagnostic::coded(
                DiagnosticCode::Lex,
                span,
                format!("unrecognized token `{}`", &source[span.range()]),
                "not a valid `.rpol` token",
            ));
            continue;
        };
        tokens.push(Token { kind, span });
    }
    (tokens, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<Tok> {
        let (tokens, diags) = lex(src, 0);
        assert!(diags.is_empty(), "unexpected lex errors: {diags:?}");
        tokens.into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn literals_use_maximal_munch() {
        assert_eq!(kinds("10.10.0.0/16"), vec![Tok::PrefixLit]);
        assert_eq!(kinds("10.10.0.1"), vec![Tok::Ipv4Lit]);
        assert_eq!(kinds("2001:db8::/32"), vec![Tok::PrefixLit]);
        assert_eq!(kinds("2001:db8::1"), vec![Tok::Ipv6Lit]);
        assert_eq!(kinds("65000:100"), vec![Tok::StdCommunityLit]);
        assert_eq!(kinds("65000:1:2"), vec![Tok::LargeCommunityLit]);
        assert_eq!(kinds("65000:*:*"), vec![Tok::LargeCommunityWildcard]);
        assert_eq!(kinds("*:*:*"), vec![Tok::LargeCommunityAllWildcard]);
        assert_eq!(kinds("* * *"), vec![Tok::Star, Tok::Star, Tok::Star]);
        assert_eq!(kinds("LC:65000:1:2"), vec![Tok::LargeCommunityLit]);
        assert_eq!(kinds("RT:65001:100"), vec![Tok::ExtCommunityLit]);
        assert_eq!(kinds("RO:192.0.2.1:5"), vec![Tok::ExtCommunityLit]);
        assert_eq!(kinds("42"), vec![Tok::Int]);
    }

    /// Community-set patterns are one token; the all-number spellings and
    /// the two existing large-community wildcards keep their tokens.
    #[test]
    fn community_patterns_lex_as_one_token_without_stealing_literals() {
        for pattern in [
            "65000:*",
            "*:666",
            "*:*",
            "65000:100..199",
            "100..199:5",
            "PRIVATE_AS:*",
            "65000:PRIVATE_AS",
            "65000:1:*",
            "65000:1..9:*",
            "*:1:*",
            "PRIVATE_AS:*:*",
            "LC:65000:*:*",
            "RT:65000:*",
            "RO:*:7",
            "RT:192.0.2.1:*",
            "RT:PRIVATE_AS:1..9",
            "65000:5..5",
        ] {
            assert_eq!(kinds(pattern), vec![Tok::CommunityPattern], "{pattern}");
        }
        assert_eq!(kinds("65000:100"), vec![Tok::StdCommunityLit]);
        assert_eq!(kinds("65000:1:2"), vec![Tok::LargeCommunityLit]);
        assert_eq!(kinds("RT:65000:1"), vec![Tok::ExtCommunityLit]);
        assert_eq!(kinds("65000:*:*"), vec![Tok::LargeCommunityWildcard]);
        assert_eq!(kinds("*:*:*"), vec![Tok::LargeCommunityAllWildcard]);
        assert_eq!(kinds("*"), vec![Tok::Star]);
        assert_eq!(kinds("PRIVATE_AS"), vec![Tok::Ident]);
        // `PRIVATE_AS` ends its field.
        for bad in [
            "65000:PRIVATE_ASX",
            "PRIVATE_AS_1:*",
            "65000:PRIVATE_AS-x",
            "RT:PRIVATE_ASN:1",
        ] {
            let (_, diags) = lex(bad, 0);
            assert_eq!(diags.len(), 1, "{bad} must be a lex error");
        }
        // Spaced forms stay separate tokens.
        assert_eq!(kinds("65000 : *"), vec![Tok::Int, Tok::Colon, Tok::Star]);
        assert_eq!(kinds("x: u32"), vec![Tok::Ident, Tok::Colon, Tok::U32Kw]);
        assert_eq!(kinds("med * 2"), vec![Tok::Ident, Tok::Star, Tok::Int]);
    }

    /// LAN-299 / ADR-0103 Decision 2.1: kebab-case maximal munch is
    /// permanent — `med-1` is one identifier; binary `-` needs
    /// whitespace. The other operators cannot collide with names.
    #[test]
    fn arithmetic_operators_vs_kebab_munch() {
        assert_eq!(
            kinds("med - 1"),
            vec![Tok::Ident, Tok::Minus, Tok::Int],
            "spaced minus is subtraction"
        );
        assert_eq!(kinds("med-1"), vec![Tok::Ident], "unspaced minus munches");
        assert_eq!(
            kinds("1 + 2 * 3 / 4 % 5"),
            vec![
                Tok::Int,
                Tok::Plus,
                Tok::Int,
                Tok::Star,
                Tok::Int,
                Tok::Slash,
                Tok::Int,
                Tok::Percent,
                Tok::Int
            ]
        );
        // Prefix literals own `/` inside maximal munch; arithmetic `/`
        // only appears where a prefix cannot lex.
        assert_eq!(kinds("10.0.0.0/8"), vec![Tok::PrefixLit]);
    }

    /// LAN-304: the return-type arrow lexes as one token and never
    /// collides with kebab identifiers or spaced subtraction.
    #[test]
    fn arrow_vs_minus_and_kebab_munch() {
        assert_eq!(kinds(") -> u32"), vec![Tok::RParen, Tok::Arrow, Tok::U32Kw]);
        assert_eq!(kinds("a - b"), vec![Tok::Ident, Tok::Minus, Tok::Ident]);
        // `>` is not an identifier character, so the munch stops at `a`.
        assert_eq!(kinds("a->b"), vec![Tok::Ident, Tok::Arrow, Tok::Ident]);
    }

    #[test]
    fn keywords_vs_kebab_identifiers() {
        assert_eq!(kinds("prefix-set"), vec![Tok::PrefixSetKw]);
        assert_eq!(kinds("prefix-sets"), vec![Tok::Ident]);
        assert_eq!(kinds("customer-in"), vec![Tok::Ident]);
        assert_eq!(kinds("local-pref"), vec![Tok::Ident]);
        assert_eq!(
            kinds("route.rpki == invalid"),
            vec![Tok::RouteKw, Tok::Dot, Tok::Ident, Tok::EqEq, Tok::Ident]
        );
    }

    #[test]
    fn comments_and_strings() {
        assert_eq!(
            kinds("accept # trailing comment\nreject"),
            vec![Tok::AcceptKw, Tok::RejectKw]
        );
        assert_eq!(kinds(r#""_65001_""#), vec![Tok::Str]);
    }

    #[test]
    fn unrecognized_tokens_are_reported_and_skipped() {
        let (tokens, diags) = lex("policy @@ demo", 0);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("unrecognized token"));
        assert_eq!(
            tokens.iter().map(|t| t.kind).collect::<Vec<_>>(),
            vec![Tok::PolicyKw, Tok::Ident]
        );
    }

    /// ADR-0103 Decision 2 rules 3 and 4: every `.rpol` source in the tree
    /// lexes to the token stream it had before the grammar slices that
    /// followed it. `lex_corpus.golden` holds one line per file: its path,
    /// token count and a digest of every token's kind and span (lex errors
    /// included). A new token that re-lexes an existing source changes
    /// that file's digest.
    ///
    /// After an intentional fixture edit, rewrite the golden with
    /// `RPOL_LEX_GOLDEN_BLESS=1 cargo test -p rustbgpd-policy --lib
    /// existing_rpol_sources_lex_unchanged` and review the diff: a changed
    /// line for a file you did not edit is a lexer regression.
    #[test]
    fn existing_rpol_sources_lex_unchanged() {
        use std::fmt::Write as _;
        use std::path::{Path, PathBuf};

        use sha2::{Digest, Sha256};

        fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if path.is_dir() {
                    if !name.starts_with('.') && name != "target" {
                        collect(&path, out);
                    }
                } else if name.ends_with(".rpol") {
                    out.push(path);
                }
            }
        }

        fn digest(source: &str) -> (usize, String) {
            let (tokens, diags) = lex(source, 0);
            let mut stream = String::new();
            for token in &tokens {
                let range = token.span.range();
                writeln!(stream, "{:?} {} {}", token.kind, range.start, range.end).unwrap();
            }
            for diag in &diags {
                let range = diag.labels[0].0.range();
                writeln!(stream, "lex-error {} {}", range.start, range.end).unwrap();
            }
            let hash = Sha256::digest(stream.as_bytes());
            let prefix = u64::from_be_bytes(hash[..8].try_into().unwrap());
            (tokens.len(), format!("{prefix:016x}"))
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let golden_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rpol/lex_corpus.golden");
        if std::env::var_os("RPOL_LEX_GOLDEN_BLESS").is_some() {
            let mut files = Vec::new();
            collect(&root, &mut files);
            let mut lines: Vec<String> = files
                .iter()
                .map(|path| {
                    let source = std::fs::read_to_string(path).unwrap();
                    let (count, hex) = digest(&source);
                    let rel = path
                        .strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    format!("{rel} {count} {hex}")
                })
                .collect();
            lines.sort();
            std::fs::write(&golden_path, lines.join("\n") + "\n").unwrap();
            return;
        }

        let golden = std::fs::read_to_string(&golden_path).unwrap();
        let mut checked = 0usize;
        let mut changed = Vec::new();
        for line in golden.lines() {
            let mut parts = line.rsplitn(3, ' ');
            let (hex, count, rel) = (
                parts.next().unwrap(),
                parts.next().unwrap(),
                parts.next().unwrap(),
            );
            let source = std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|err| panic!("{rel}: {err} (re-bless after removing a fixture)"));
            let (now_count, now_hex) = digest(&source);
            if now_count.to_string() != count || now_hex != hex {
                changed.push(format!("{rel}: {count} {hex} -> {now_count} {now_hex}"));
            }
            checked += 1;
        }
        assert!(checked >= 200, "only {checked} golden sources");
        assert!(
            changed.is_empty(),
            "sources lex differently:\n{}",
            changed.join("\n")
        );
    }
}
