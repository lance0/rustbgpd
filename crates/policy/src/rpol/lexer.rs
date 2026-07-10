//! The `.rpol` lexer (`logos`-generated), producing spanned tokens.
//!
//! Design notes (documented in `docs/rpol-language.md`):
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

use super::diag::{Diagnostic, Span};

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
    /// `65000:1:2` or `LC:65000:1:2` — large-community literal.
    #[regex(r"(LC:)?[0-9]+:[0-9]+:[0-9]+")]
    LargeCommunityLit,
    /// `65000:100` — standard-community literal.
    #[regex(r"[0-9]+:[0-9]+")]
    StdCommunityLit,
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
}

impl Tok {
    /// Human-readable token description for error messages.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Tok::ExtCommunityLit => "extended-community literal",
            Tok::LargeCommunityLit => "large-community literal",
            Tok::StdCommunityLit => "community literal",
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

/// Lex the entire source. Unrecognized characters become diagnostics
/// (one per contiguous bad region) and lexing continues, so the parser
/// still sees — and can report on — the rest of the file.
#[must_use]
pub fn lex(source: &str) -> (Vec<Token>, Vec<Diagnostic>) {
    let mut tokens = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    for (result, range) in Tok::lexer(source).spanned() {
        let span = Span::new(range);
        let Ok(kind) = result else {
            // Coalesce adjacent error characters into one diagnostic.
            if let Some(last) = diagnostics.last_mut()
                && let Some((last_span, _)) = last.labels.first_mut()
                && last_span.end == span.start
            {
                last_span.end = span.end;
                continue;
            }
            diagnostics.push(Diagnostic::new(
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
        let (tokens, diags) = lex(src);
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
        assert_eq!(kinds("LC:65000:1:2"), vec![Tok::LargeCommunityLit]);
        assert_eq!(kinds("RT:65001:100"), vec![Tok::ExtCommunityLit]);
        assert_eq!(kinds("RO:192.0.2.1:5"), vec![Tok::ExtCommunityLit]);
        assert_eq!(kinds("42"), vec![Tok::Int]);
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
        let (tokens, diags) = lex("policy @@ demo");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("unrecognized token"));
        assert_eq!(
            tokens.iter().map(|t| t.kind).collect::<Vec<_>>(),
            vec![Tok::PolicyKw, Tok::Ident]
        );
    }
}
