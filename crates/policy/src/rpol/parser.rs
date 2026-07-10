//! Handwritten recursive-descent parser for `.rpol`.
//!
//! Error recovery: a failed top-level item skips to the next
//! `prefix-set`/`community-set`/`policy`/`test` keyword at brace depth
//! zero; a failed statement inside a policy skips to the next `term`,
//! `;`, or closing brace. This is enough to report several independent
//! errors per file in one pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, LargeCommunity, Prefix};

use crate::engine::{CommunityMatch, parse_community_match};

use crate::ir::ArithOp;

use super::ast::{
    ActionStmt, AsnSetDef, CmpOp, CommunityKind, CommunityLit, CommunitySetDef, ExpectDef, Expr,
    FieldPath, FieldRoot, IfStmt, NextHopArg, PeerField, PolicyDef, PrefixEntryAst, PrefixSetDef,
    PrependAsArg, Rhs, RouteField, SourceFile, Stmt, TermDef, TestDef, U32Arg, ValueExprAst,
    WithAssertion,
};
use super::diag::{Diagnostic, Span, Spanned};
use super::lexer::{Tok, Token, lex};

/// Parse a source file, returning the AST and every diagnostic found
/// (lex + parse). The AST contains every item that parsed cleanly even
/// when diagnostics are present, so the typechecker can report further
/// errors in the same run.
#[must_use]
pub fn parse(source: &str) -> (SourceFile, Vec<Diagnostic>) {
    let (tokens, mut diags) = lex(source);
    let mut parser = Parser {
        src: source,
        tokens,
        pos: 0,
        diags: Vec::new(),
    };
    let file = parser.source_file();
    diags.append(&mut parser.diags);
    (file, diags)
}

struct Parser<'src> {
    src: &'src str,
    tokens: Vec<Token>,
    pos: usize,
    diags: Vec<Diagnostic>,
}

/// Parse-failure marker; the diagnostic is already recorded.
struct Fail;

type PResult<T> = Result<T, Fail>;

/// Maximum expression nesting depth (LAN-184). Parenthesized groups,
/// `!`, and each `&&`/`||` chain fold all count toward it: chained
/// binary ops fold into a left-leaning AST whose depth the recursive
/// passes downstream of the parser (typecheck, lowering, `Drop`)
/// consume, so the parser — the only producer of user-shaped `Expr`
/// trees — bounds them all here. Generous for any human-written
/// config, far below stack limits; rpol files arrive via SIGHUP
/// overlay at runtime, so an unbounded recursion is a
/// daemon-crash-by-config.
const MAX_EXPR_DEPTH: u32 = 128;

impl Parser<'_> {
    // ── token plumbing ──────────────────────────────────────────────

    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.pos).copied()
    }

    fn at(&self, kind: Tok) -> bool {
        self.peek().is_some_and(|t| t.kind == kind)
    }

    fn bump(&mut self) -> Option<Token> {
        let token = self.peek();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn eat(&mut self, kind: Tok) -> Option<Token> {
        if self.at(kind) { self.bump() } else { None }
    }

    fn text(&self, token: Token) -> &str {
        &self.src[token.span.range()]
    }

    fn eof_span(&self) -> Span {
        let end = self.src.len();
        Span::new(end..end)
    }

    fn here(&self) -> Span {
        self.peek().map_or_else(|| self.eof_span(), |t| t.span)
    }

    fn error_expected(&mut self, what: &str) -> Fail {
        let (span, found) = match self.peek() {
            Some(token) => (token.span, token.kind.describe().to_string()),
            None => (self.eof_span(), "end of file".to_string()),
        };
        self.diags.push(Diagnostic::new(
            span,
            format!("expected {what}, found {found}"),
            format!("expected {what} here"),
        ));
        Fail
    }

    fn expect(&mut self, kind: Tok, what: &str) -> PResult<Token> {
        if self.at(kind) {
            Ok(self.bump().expect("peeked"))
        } else {
            Err(self.error_expected(what))
        }
    }

    fn expect_ident(&mut self, what: &str) -> PResult<Spanned<String>> {
        let token = self.expect(Tok::Ident, what)?;
        Ok(Spanned::new(self.text(token).to_string(), token.span))
    }

    /// Skip tokens until one of `stops` at local brace depth zero (or
    /// EOF). A closing brace that would take the depth negative is
    /// consumed and resets to zero — it closed the enclosing block the
    /// error occurred in.
    fn recover_to(&mut self, stops: &[Tok]) {
        let mut depth: u32 = 0;
        while let Some(token) = self.peek() {
            if depth == 0 && stops.contains(&token.kind) {
                return;
            }
            self.pos += 1;
            match token.kind {
                Tok::LBrace => depth += 1,
                Tok::RBrace => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }

    // ── literal parsing ─────────────────────────────────────────────

    fn parse_u32_text(&mut self, text: &str, span: Span) -> PResult<u32> {
        text.parse::<u32>().map_err(|_| {
            self.diags.push(Diagnostic::new(
                span,
                format!("integer literal `{text}` does not fit in u32"),
                "out of range",
            ));
            Fail
        })
    }

    fn expect_u32(&mut self, what: &str) -> PResult<(u32, Span)> {
        let token = self.expect(Tok::Int, what)?;
        let text = self.text(token).to_string();
        Ok((self.parse_u32_text(&text, token.span)?, token.span))
    }

    /// `u32` argument position: integer literal or parameter name.
    fn u32_arg(&mut self, what: &str) -> PResult<U32Arg> {
        match self.peek().map(|t| t.kind) {
            Some(Tok::Int) => {
                let (value, span) = self.expect_u32(what)?;
                Ok(U32Arg::Lit(value, span))
            }
            Some(Tok::Ident) => Ok(U32Arg::Param(self.expect_ident(what)?)),
            _ => Err(self.error_expected(what)),
        }
    }

    fn parse_prefix_text(&mut self, text: &str, span: Span) -> PResult<Prefix> {
        let fail = |parser: &mut Self, detail: &str| {
            parser.diags.push(Diagnostic::new(
                span,
                format!("invalid prefix `{text}`: {detail}"),
                "invalid prefix",
            ));
            Fail
        };
        let Some((addr, len)) = text.split_once('/') else {
            return Err(fail(self, "missing `/length`"));
        };
        let Ok(len) = len.parse::<u8>() else {
            return Err(fail(self, "invalid prefix length"));
        };
        let prefix = if let Ok(v4) = addr.parse::<Ipv4Addr>() {
            if len > 32 {
                return Err(fail(self, "IPv4 prefix length exceeds 32"));
            }
            let canonical = Ipv4Prefix::new(v4, len);
            if canonical.addr != v4 {
                return Err(fail(
                    self,
                    &format!("host bits set beyond /{len} (did you mean {canonical}?)"),
                ));
            }
            Prefix::V4(canonical)
        } else if let Ok(v6) = addr.parse::<Ipv6Addr>() {
            if len > 128 {
                return Err(fail(self, "IPv6 prefix length exceeds 128"));
            }
            let canonical = Ipv6Prefix::new(v6, len);
            if canonical.addr != v6 {
                return Err(fail(
                    self,
                    &format!("host bits set beyond /{len} (did you mean {canonical}?)"),
                ));
            }
            Prefix::V6(canonical)
        } else {
            return Err(fail(self, "invalid address"));
        };
        Ok(prefix)
    }

    fn expect_prefix(&mut self) -> PResult<(Prefix, Span)> {
        let token = self.expect(Tok::PrefixLit, "a prefix (e.g. `10.0.0.0/8`)")?;
        let text = self.text(token).to_string();
        Ok((self.parse_prefix_text(&text, token.span)?, token.span))
    }

    fn expect_ip(&mut self, what: &str) -> PResult<(IpAddr, Span)> {
        let token = match self.peek().map(|t| t.kind) {
            Some(Tok::Ipv4Lit | Tok::Ipv6Lit) => self.bump().expect("peeked"),
            _ => return Err(self.error_expected(what)),
        };
        let text = self.text(token).to_string();
        let Ok(addr) = text.parse::<IpAddr>() else {
            self.diags.push(Diagnostic::new(
                token.span,
                format!("invalid IP address `{text}`"),
                "invalid address",
            ));
            return Err(Fail);
        };
        Ok((addr, token.span))
    }

    fn expect_str(&mut self, what: &str) -> PResult<Spanned<String>> {
        let token = self.expect(Tok::Str, what)?;
        let raw = self.text(token);
        // Strip quotes; unescape `\"` and `\\` (the only escapes).
        let inner = &raw[1..raw.len() - 1];
        let value = inner.replace("\\\"", "\"").replace("\\\\", "\\");
        Ok(Spanned::new(value, token.span))
    }

    /// A community literal of any kind, including well-known names
    /// (`NO_EXPORT`, `BLACKHOLE`, …).
    fn community_lit(&mut self) -> PResult<Spanned<CommunityLit>> {
        let Some(token) = self.peek() else {
            return Err(self.error_expected("a community literal"));
        };
        let text = self.text(token).to_string();
        let span = token.span;
        let lit = match token.kind {
            Tok::StdCommunityLit => {
                self.bump();
                let (asn, value) = text.split_once(':').expect("token shape");
                let asn: u32 = self.parse_u32_text(asn, span)?;
                let value: u32 = self.parse_u32_text(value, span)?;
                if asn > u32::from(u16::MAX) || value > u32::from(u16::MAX) {
                    self.diags.push(Diagnostic::new(
                        span,
                        format!("invalid standard community `{text}`: both parts must fit in u16"),
                        "part exceeds 65535",
                    ).with_note(
                        "for 4-byte ASNs use a large community (`asn:local1:local2`) or an extended community (`RT:asn:value`)",
                    ));
                    return Err(Fail);
                }
                CommunityLit::Standard((asn << 16) | value)
            }
            Tok::LargeCommunityLit => {
                self.bump();
                let body = text.strip_prefix("LC:").unwrap_or(&text);
                let mut parts = body.splitn(3, ':');
                let global_admin = self.parse_u32_text(parts.next().expect("token shape"), span)?;
                let local_data1 = self.parse_u32_text(parts.next().expect("token shape"), span)?;
                let local_data2 = self.parse_u32_text(parts.next().expect("token shape"), span)?;
                CommunityLit::Large(LargeCommunity {
                    global_admin,
                    local_data1,
                    local_data2,
                })
            }
            Tok::ExtCommunityLit => {
                self.bump();
                self.ext_community_lit(&text, span)?
            }
            Tok::Ident => {
                // Well-known community names (standard and extended)
                // share the TOML frontend's alias table via
                // `parse_community_match`.
                let well_known_shape = text.chars().all(|c| c.is_ascii_uppercase() || c == '_');
                match parse_community_match(&text) {
                    Ok(CommunityMatch::Standard { value }) if well_known_shape => {
                        self.bump();
                        CommunityLit::Standard(value)
                    }
                    Ok(CommunityMatch::ExactExt(raw)) if well_known_shape => {
                        self.bump();
                        CommunityLit::ExtRaw(raw)
                    }
                    _ => {
                        return Err(self.error_expected(
                            "a community literal (`65000:100`, `65000:1:2`, `RT:65001:100`, or a well-known name like `NO_EXPORT` or `OV_INVALID`)",
                        ));
                    }
                }
            }
            _ => {
                return Err(self.error_expected(
                    "a community literal (`65000:100`, `65000:1:2`, `RT:65001:100`, or a well-known name like `NO_EXPORT`)",
                ));
            }
        };
        Ok(Spanned::new(lit, span))
    }

    fn ext_community_lit(&mut self, text: &str, span: Span) -> PResult<CommunityLit> {
        let route_target = text.starts_with("RT:");
        let body = &text[3..];
        let (admin, local) = body.split_once(':').expect("token shape");
        let local = self.parse_u32_text(local, span)?;
        let (global, ipv4_admin) = if let Ok(v4) = admin.parse::<Ipv4Addr>() {
            (u32::from(v4), true)
        } else {
            (self.parse_u32_text(admin, span)?, false)
        };
        // RFC 4360 encodings: IPv4-admin and 4-octet-AS forms carry a
        // 2-octet local administrator.
        if (ipv4_admin || global > u32::from(u16::MAX)) && local > u32::from(u16::MAX) {
            self.diags.push(Diagnostic::new(
                span,
                format!(
                    "invalid extended community `{text}`: local administrator exceeds 65535 for {} global admin",
                    if ipv4_admin { "an IPv4" } else { "a 4-octet-AS" }
                ),
                "local admin out of range",
            ));
            return Err(Fail);
        }
        Ok(CommunityLit::Ext {
            route_target,
            global,
            local,
            ipv4_admin,
        })
    }

    // ── top level ───────────────────────────────────────────────────

    const TOP_LEVEL: &'static [Tok] = &[
        Tok::PrefixSetKw,
        Tok::CommunitySetKw,
        Tok::AsnSetKw,
        Tok::PolicyKw,
        Tok::TestKw,
    ];

    fn source_file(&mut self) -> SourceFile {
        let mut file = SourceFile::default();
        while let Some(token) = self.peek() {
            let result = match token.kind {
                Tok::PrefixSetKw => self.prefix_set_def().map(|def| file.prefix_sets.push(def)),
                Tok::CommunitySetKw => self
                    .community_set_def()
                    .map(|def| file.community_sets.push(def)),
                Tok::AsnSetKw => self.asn_set_def().map(|def| file.asn_sets.push(def)),
                Tok::PolicyKw => self.policy_def().map(|def| file.policies.push(def)),
                Tok::TestKw => self.test_def().map(|def| file.tests.push(def)),
                _ => Err(self.error_expected(
                    "a top-level item (`prefix-set`, `community-set`, `asn-set`, `policy`, or `test`)",
                )),
            };
            if result.is_err() {
                // Ensure progress even when the failing token IS a
                // top-level keyword (e.g. `policy` missing its name).
                if self.peek().map(|t| t.kind) == Some(token.kind) && self.here() == token.span {
                    self.pos += 1;
                }
                self.recover_to(Self::TOP_LEVEL);
            }
        }
        file
    }

    fn prefix_set_def(&mut self) -> PResult<PrefixSetDef> {
        self.expect(Tok::PrefixSetKw, "`prefix-set`")?;
        let name = self.expect_ident("a set name")?;
        self.expect(Tok::LBrace, "`{`")?;
        let mut entries = Vec::new();
        while !self.at(Tok::RBrace) {
            let (prefix, _) = self.expect_prefix()?;
            let mut ge = None;
            let mut le = None;
            if self.eat(Tok::GeKw).is_some() {
                let (value, value_span) = self.expect_u32("a prefix length after `ge`")?;
                ge = Some(self.prefix_len_bound(prefix, value, value_span)?);
            }
            if self.eat(Tok::LeKw).is_some() {
                let (value, value_span) = self.expect_u32("a prefix length after `le`")?;
                le = Some(self.prefix_len_bound(prefix, value, value_span)?);
            }
            entries.push(PrefixEntryAst { prefix, ge, le });
            if self.eat(Tok::Comma).is_none() {
                break;
            }
        }
        self.expect(Tok::RBrace, "`}` or `,` and another prefix")?;
        Ok(PrefixSetDef { name, entries })
    }

    fn prefix_len_bound(&mut self, prefix: Prefix, value: u32, span: Span) -> PResult<u8> {
        let max = match prefix {
            Prefix::V4(_) => 32u32,
            Prefix::V6(_) => 128,
        };
        if value > max {
            self.diags.push(Diagnostic::new(
                span,
                format!("prefix length bound {value} exceeds {max}"),
                "out of range",
            ));
            return Err(Fail);
        }
        Ok(u8::try_from(value).expect("bounded above"))
    }

    fn community_set_def(&mut self) -> PResult<CommunitySetDef> {
        self.expect(Tok::CommunitySetKw, "`community-set`")?;
        let name = self.expect_ident("a set name")?;
        self.expect(Tok::LBrace, "`{`")?;
        let mut entries = Vec::new();
        while !self.at(Tok::RBrace) {
            entries.push(self.community_lit()?);
            if self.eat(Tok::Comma).is_none() {
                break;
            }
        }
        self.expect(Tok::RBrace, "`}` or `,` and another community")?;
        Ok(CommunitySetDef { name, entries })
    }

    fn asn_set_def(&mut self) -> PResult<AsnSetDef> {
        self.expect(Tok::AsnSetKw, "`asn-set`")?;
        let name = self.expect_ident("a set name")?;
        self.expect(Tok::LBrace, "`{`")?;
        let mut entries = Vec::new();
        while !self.at(Tok::RBrace) {
            // `expect_u32` rejects out-of-range literals with an
            // "does not fit in u32" diagnostic — ASNs are u32, never
            // 16-bit-truncated.
            let (asn, span) = self.expect_u32("an ASN (a u32 integer)")?;
            entries.push(Spanned::new(asn, span));
            if self.eat(Tok::Comma).is_none() {
                break;
            }
        }
        self.expect(Tok::RBrace, "`}` or `,` and another ASN")?;
        Ok(AsnSetDef { name, entries })
    }

    // ── policies ────────────────────────────────────────────────────

    fn policy_def(&mut self) -> PResult<PolicyDef> {
        self.expect(Tok::PolicyKw, "`policy`")?;
        let name = self.expect_ident("a policy name")?;
        let mut params = Vec::new();
        if self.eat(Tok::LParen).is_some() {
            while !self.at(Tok::RParen) {
                let param = self.expect_ident("a parameter name")?;
                self.expect(Tok::Colon, "`:` and the parameter type")?;
                self.expect(Tok::U32Kw, "`u32` (the only parameter type in V1)")?;
                params.push(param);
                if self.eat(Tok::Comma).is_none() {
                    break;
                }
            }
            self.expect(Tok::RParen, "`)`")?;
        }
        self.expect(Tok::LBrace, "`{`")?;
        let mut terms = Vec::new();
        while !self.at(Tok::RBrace) {
            if let Ok(term) = self.term_def() {
                terms.push(term);
            } else {
                self.recover_to(&[Tok::TermKw, Tok::RBrace]);
                if self.peek().is_none() {
                    return Err(Fail);
                }
            }
        }
        self.expect(Tok::RBrace, "`}`")?;
        Ok(PolicyDef {
            name,
            params,
            terms,
        })
    }

    fn term_def(&mut self) -> PResult<TermDef> {
        self.expect(Tok::TermKw, "`term` (policy bodies are named terms)")?;
        let name = self.expect_ident("a term name")?;
        self.expect(Tok::LBrace, "`{`")?;
        let mut stmts = Vec::new();
        while !self.at(Tok::RBrace) {
            if let Ok(stmt) = self.stmt() {
                stmts.push(stmt);
            } else {
                self.recover_to(&[Tok::Semi, Tok::RBrace, Tok::TermKw]);
                if self.eat(Tok::Semi).is_none() {
                    break;
                }
            }
        }
        self.expect(Tok::RBrace, "`}`")?;
        Ok(TermDef { name, stmts })
    }

    fn stmt(&mut self) -> PResult<Stmt> {
        if self.at(Tok::IfKw) {
            return Ok(Stmt::If(self.if_stmt()?));
        }
        let action = self.action()?;
        self.eat(Tok::Semi);
        Ok(Stmt::Action(action))
    }

    fn if_stmt(&mut self) -> PResult<IfStmt> {
        let start = self.expect(Tok::IfKw, "`if`")?.span;
        let cond = self.expr(0)?;
        let span = start.to(cond.span());
        self.expect(Tok::LBrace, "`{`")?;
        let then_actions = self.action_list()?;
        self.expect(Tok::RBrace, "`}`")?;
        let else_actions = if self.eat(Tok::ElseKw).is_some() {
            self.expect(Tok::LBrace, "`{` (V1 has no `else if`)")?;
            let actions = self.action_list()?;
            self.expect(Tok::RBrace, "`}`")?;
            Some(actions)
        } else {
            None
        };
        Ok(IfStmt {
            cond,
            then_actions,
            else_actions,
            span,
        })
    }

    fn action_list(&mut self) -> PResult<Vec<ActionStmt>> {
        let mut actions = Vec::new();
        while !self.at(Tok::RBrace) {
            if self.at(Tok::IfKw) {
                self.diags.push(
                    Diagnostic::new(
                        self.here(),
                        "nested `if` is not supported in V1",
                        "`if` bodies contain only actions",
                    )
                    .with_note("split the condition with `&&`, or use another term"),
                );
                return Err(Fail);
            }
            actions.push(self.action()?);
            self.eat(Tok::Semi);
        }
        Ok(actions)
    }

    fn action(&mut self) -> PResult<ActionStmt> {
        let Some(token) = self.peek() else {
            return Err(self.error_expected("an action"));
        };
        match token.kind {
            Tok::AcceptKw => {
                self.bump();
                Ok(ActionStmt::Accept(token.span))
            }
            Tok::RejectKw => {
                self.bump();
                Ok(ActionStmt::Reject(token.span))
            }
            Tok::SetKw => {
                self.bump();
                let target = self.expect_ident("`local-pref`, `med`, or `next-hop`")?;
                match target.node.as_str() {
                    "local-pref" => {
                        let arg = self.value_expr(0)?;
                        let span = token.span.to(arg.span());
                        Ok(ActionStmt::SetLocalPref(arg, span))
                    }
                    "med" => {
                        let arg = self.value_expr(0)?;
                        let span = token.span.to(arg.span());
                        Ok(ActionStmt::SetMed(arg, span))
                    }
                    "next-hop" => {
                        let arg = if let Some(self_token) = self.eat(Tok::SelfKw) {
                            NextHopArg::Self_(self_token.span)
                        } else {
                            let (addr, span) = self.expect_ip("an IP address or `self`")?;
                            NextHopArg::Addr(addr, span)
                        };
                        let end = match &arg {
                            NextHopArg::Self_(span) | NextHopArg::Addr(_, span) => *span,
                        };
                        Ok(ActionStmt::SetNextHop(arg, token.span.to(end)))
                    }
                    other => {
                        self.diags.push(
                            Diagnostic::new(
                                target.span,
                                format!("unknown `set` target `{other}`"),
                                "not a settable attribute",
                            )
                            .with_note("settable attributes: local-pref, med, next-hop"),
                        );
                        Err(Fail)
                    }
                }
            }
            Tok::AddKw | Tok::RemoveKw => {
                let add = token.kind == Tok::AddKw;
                self.bump();
                let kind_ident =
                    self.expect_ident("`community`, `large-community`, or `ext-community`")?;
                let kind = match kind_ident.node.as_str() {
                    "community" => CommunityKind::Standard,
                    "large-community" => CommunityKind::Large,
                    "ext-community" => CommunityKind::Ext,
                    other => {
                        self.diags.push(Diagnostic::new(
                            kind_ident.span,
                            format!("unknown community kind `{other}`"),
                            "expected `community`, `large-community`, or `ext-community`",
                        ));
                        return Err(Fail);
                    }
                };
                let lit = self.community_lit()?;
                let span = token.span.to(lit.span);
                Ok(ActionStmt::Community {
                    add,
                    kind,
                    lit,
                    span,
                })
            }
            Tok::PrependKw => {
                self.bump();
                self.expect(
                    Tok::AsKw,
                    "`as` (`prepend as <asn|self|peer|origin> <count>`)",
                )?;
                // Computed operands (LAN-296): `self` / `peer` are
                // keyword tokens (previously parse errors here, so
                // purely additive); `origin` is a contextual
                // identifier that flows through the parameter path and
                // is disambiguated against the policy's declared
                // parameters (`PrependAsArg::operand`).
                let asn = if self.eat(Tok::SelfKw).is_some() {
                    PrependAsArg::SelfAs
                } else if self.eat(Tok::PeerKw).is_some() {
                    PrependAsArg::Peer
                } else {
                    PrependAsArg::Value(self.u32_arg("an ASN, `self`, `peer`, or `origin`")?)
                };
                let count = self.u32_arg("a prepend count")?;
                let span = token.span.to(count.span());
                Ok(ActionStmt::Prepend { asn, count, span })
            }
            _ => Err(self.error_expected(
                "an action (`accept`, `reject`, `set`, `add`, `remove`, or `prepend`)",
            )),
        }
    }

    // ── expressions ─────────────────────────────────────────────────

    /// Fail with a spanned diagnostic when `depth` exceeds
    /// [`MAX_EXPR_DEPTH`].
    fn check_expr_depth(&mut self, depth: u32) -> PResult<()> {
        if depth > MAX_EXPR_DEPTH {
            self.diags.push(
                Diagnostic::new(
                    self.here(),
                    format!("expression nesting exceeds {MAX_EXPR_DEPTH} levels"),
                    "too deeply nested",
                )
                .with_note("simplify the condition or split it across terms"),
            );
            return Err(Fail);
        }
        Ok(())
    }

    fn expr(&mut self, mut depth: u32) -> PResult<Expr> {
        let mut lhs = self.and_expr(depth)?;
        while self.eat(Tok::OrOr).is_some() {
            depth += 1;
            let rhs = self.and_expr(depth)?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn and_expr(&mut self, mut depth: u32) -> PResult<Expr> {
        let mut lhs = self.unary_expr(depth)?;
        while self.eat(Tok::AndAnd).is_some() {
            depth += 1;
            let rhs = self.unary_expr(depth)?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary_expr(&mut self, depth: u32) -> PResult<Expr> {
        self.check_expr_depth(depth)?;
        if let Some(bang) = self.eat(Tok::Bang) {
            let inner = self.unary_expr(depth + 1)?;
            let span = bang.span.to(inner.span());
            return Ok(Expr::Not(Box::new(inner), span));
        }
        if self.eat(Tok::LParen).is_some() {
            let inner = self.expr(depth + 1)?;
            self.expect(Tok::RParen, "`)`")?;
            return Ok(inner);
        }
        if self.at(Tok::ApplyKw) {
            return self.apply_expr();
        }
        if self.at(Tok::RouteKw) || self.at(Tok::PeerKw) {
            return self.predicate_expr();
        }
        Err(self.error_expected(
            "a condition (`route.<field> ...`, `peer.<field> ...`, `apply(...)`, `!`, or `(`)",
        ))
    }

    fn apply_expr(&mut self) -> PResult<Expr> {
        let start = self.expect(Tok::ApplyKw, "`apply`")?.span;
        self.expect(Tok::LParen, "`(`")?;
        let policy = self.expect_ident("a policy name")?;
        let mut args = Vec::new();
        if self.eat(Tok::LParen).is_some() {
            while !self.at(Tok::RParen) {
                args.push(self.u32_arg("a u32 argument")?);
                if self.eat(Tok::Comma).is_none() {
                    break;
                }
            }
            self.expect(Tok::RParen, "`)`")?;
        }
        let end = self.expect(Tok::RParen, "`)`")?.span;
        Ok(Expr::Apply {
            policy,
            args,
            span: start.to(end),
        })
    }

    // ── value expressions (LAN-299) ─────────────────────────────────

    /// The arithmetic operator at the cursor, if any.
    fn peek_arith(&self) -> Option<ArithOp> {
        match self.peek().map(|t| t.kind) {
            Some(Tok::Plus) => Some(ArithOp::Add),
            Some(Tok::Minus) => Some(ArithOp::Sub),
            Some(Tok::Star) => Some(ArithOp::Mul),
            Some(Tok::Slash) => Some(ArithOp::Div),
            Some(Tok::Percent) => Some(ArithOp::Rem),
            _ => None,
        }
    }

    /// `value_expr := value_mul (("+"|"-") value_mul)*` — checked u32
    /// arithmetic (LAN-299). `*`/`/`/`%` bind tighter than `+`/`-`;
    /// both bind tighter than comparisons. Chained operators count
    /// toward [`MAX_EXPR_DEPTH`] like `&&`/`||` chains do.
    fn value_expr(&mut self, mut depth: u32) -> PResult<ValueExprAst> {
        let mut lhs = self.value_mul(depth)?;
        while let Some(op @ (ArithOp::Add | ArithOp::Sub)) = self.peek_arith() {
            self.bump();
            depth += 1;
            self.check_expr_depth(depth)?;
            let rhs = self.value_mul(depth)?;
            let span = lhs.span().to(rhs.span());
            lhs = ValueExprAst::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    /// `value_mul := value_atom (("*"|"/"|"%") value_atom)*`.
    fn value_mul(&mut self, mut depth: u32) -> PResult<ValueExprAst> {
        let mut lhs = self.value_atom(depth)?;
        while let Some(op @ (ArithOp::Mul | ArithOp::Div | ArithOp::Rem)) = self.peek_arith() {
            self.bump();
            depth += 1;
            self.check_expr_depth(depth)?;
            let rhs = self.value_atom(depth)?;
            let span = lhs.span().to(rhs.span());
            lhs = ValueExprAst::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    /// One value operand: integer literal, parameter or builtin call
    /// (`min`/`max`/`clamp` — contextual: only an identifier followed
    /// by `(` is a call), `route.`/`peer.` field, or a parenthesized
    /// value expression.
    fn value_atom(&mut self, depth: u32) -> PResult<ValueExprAst> {
        self.check_expr_depth(depth)?;
        match self.peek().map(|t| t.kind) {
            Some(Tok::Int) => {
                let (value, span) = self.expect_u32("a u32 value")?;
                Ok(ValueExprAst::Lit(value, span))
            }
            Some(Tok::Ident) => {
                let name = self.expect_ident("a parameter or builtin")?;
                if self.at(Tok::LParen) {
                    self.value_call(name, depth)
                } else {
                    Ok(ValueExprAst::Ident(name))
                }
            }
            Some(Tok::RouteKw | Tok::PeerKw) => Ok(ValueExprAst::Field(self.field_path()?)),
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.value_expr(depth + 1)?;
                self.expect(Tok::RParen, "`)`")?;
                Ok(inner)
            }
            _ => Err(self.error_expected(
                "a u32 value (integer, parameter, `route.<field>`, `min(`/`max(`/`clamp(`, or `(`)",
            )),
        }
    }

    /// The argument list of a builtin call; the typechecker validates
    /// the name and arity.
    fn value_call(&mut self, name: Spanned<String>, depth: u32) -> PResult<ValueExprAst> {
        self.expect(Tok::LParen, "`(`")?;
        let mut args = Vec::new();
        while !self.at(Tok::RParen) {
            args.push(self.value_expr(depth + 1)?);
            if self.eat(Tok::Comma).is_none() {
                break;
            }
        }
        let end = self
            .expect(Tok::RParen, "`)` or `,` and another argument")?
            .span;
        let span = name.span.to(end);
        Ok(ValueExprAst::Call { name, args, span })
    }

    /// Continue a value expression whose first atom is already parsed
    /// (the comparison-RHS path: `rhs()` consumed an atom, then an
    /// arithmetic operator appeared). Finishes the `*`-level run the
    /// atom opens, then the `+`-level.
    fn value_expr_from_atom(&mut self, atom: ValueExprAst) -> PResult<ValueExprAst> {
        let mut lhs = atom;
        let mut depth = 0u32;
        while let Some(op @ (ArithOp::Mul | ArithOp::Div | ArithOp::Rem)) = self.peek_arith() {
            self.bump();
            depth += 1;
            self.check_expr_depth(depth)?;
            let rhs = self.value_atom(depth)?;
            let span = lhs.span().to(rhs.span());
            lhs = ValueExprAst::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        while let Some(op @ (ArithOp::Add | ArithOp::Sub)) = self.peek_arith() {
            self.bump();
            depth += 1;
            self.check_expr_depth(depth)?;
            let rhs = self.value_mul(depth)?;
            let span = lhs.span().to(rhs.span());
            lhs = ValueExprAst::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    /// Reinterpret an already-parsed comparison RHS as a value-expr
    /// atom (the arithmetic-continuation path). Non-u32-shaped
    /// operands get a spanned diagnostic.
    fn rhs_into_value_atom(&mut self, rhs: Rhs) -> PResult<ValueExprAst> {
        match rhs {
            Rhs::Int(value, span) => Ok(ValueExprAst::Lit(value, span)),
            Rhs::Ident(name) => {
                if self.at(Tok::LParen) {
                    self.value_call(name, 0)
                } else {
                    Ok(ValueExprAst::Ident(name))
                }
            }
            Rhs::Field(path) => Ok(ValueExprAst::Field(path)),
            other => {
                self.diags.push(Diagnostic::new(
                    other.span(),
                    format!(
                        "arithmetic requires u32 operands, found {}",
                        other.describe()
                    ),
                    "not a u32 operand",
                ));
                Err(Fail)
            }
        }
    }

    fn field_path(&mut self) -> PResult<FieldPath> {
        let root_token = self.bump().expect("caller checked route/peer");
        let root = if root_token.kind == Tok::RouteKw {
            FieldRoot::Route
        } else {
            FieldRoot::Peer
        };
        let mut segs = Vec::new();
        let mut span = root_token.span;
        while self.eat(Tok::Dot).is_some() {
            let seg = self.expect_ident("a field name")?;
            span = span.to(seg.span);
            segs.push(seg);
        }
        if segs.is_empty() {
            return Err(self.error_expected("`.` and a field name"));
        }
        Ok(FieldPath { root, segs, span })
    }

    fn predicate_expr(&mut self) -> PResult<Expr> {
        let field = self.field_path()?;
        // LAN-299: arithmetic after the field makes the whole
        // comparison a value comparison (`route.med + 50 >= p`).
        if self.peek_arith().is_some() {
            let lhs = self.value_expr_from_atom(ValueExprAst::Field(field))?;
            return self.value_cmp_tail(lhs);
        }
        let Some(op_token) = self.peek() else {
            return Err(self.error_expected(
                "an operator (`==`, `!=`, `>=`, `<=`, `in`, `has`, `matches`, or `contains`)",
            ));
        };
        match op_token.kind {
            Tok::EqEq | Tok::NotEq | Tok::GtEq | Tok::LtEq => {
                self.bump();
                let op = match op_token.kind {
                    Tok::EqEq => CmpOp::Eq,
                    Tok::NotEq => CmpOp::Ne,
                    Tok::GtEq => CmpOp::Ge,
                    _ => CmpOp::Le,
                };
                // LAN-299: `(` after a comparison operator can only
                // open a value expression (it was a parse error before
                // arithmetic landed), e.g. `route.med == (x + 2) * 3`.
                if self.at(Tok::LParen) {
                    let rhs = self.value_expr(0)?;
                    let span = field.span.to(rhs.span());
                    return Ok(Expr::ValueCmp {
                        lhs: ValueExprAst::Field(field),
                        op,
                        rhs,
                        span,
                    });
                }
                let rhs = self.rhs()?;
                // LAN-299: an arithmetic operator (or a builtin call's
                // `(`) after the RHS atom upgrades the comparison to a
                // value comparison; plain shapes keep the legacy
                // (never-match-on-absent) `Cmp` form.
                if self.peek_arith().is_some()
                    || (matches!(rhs, Rhs::Ident(_)) && self.at(Tok::LParen))
                {
                    let atom = self.rhs_into_value_atom(rhs)?;
                    let rhs = self.value_expr_from_atom(atom)?;
                    let span = field.span.to(rhs.span());
                    return Ok(Expr::ValueCmp {
                        lhs: ValueExprAst::Field(field),
                        op,
                        rhs,
                        span,
                    });
                }
                let span = field.span.to(rhs.span());
                Ok(Expr::Cmp {
                    field,
                    op,
                    rhs,
                    span,
                })
            }
            Tok::InKw => {
                self.bump();
                let set = self.expect_ident("a set name")?;
                Ok(Expr::In { field, set })
            }
            Tok::HasKw => {
                self.bump();
                let lit = self.community_lit()?;
                Ok(Expr::Has { field, lit })
            }
            Tok::MatchesKw => {
                self.bump();
                let pattern = self.expect_str("a regex string")?;
                Ok(Expr::Matches { field, pattern })
            }
            Tok::ContainsKw => {
                self.bump();
                let asn = self.u32_arg("an ASN")?;
                Ok(Expr::Contains { field, asn })
            }
            _ => Err(self.error_expected(
                "an operator (`==`, `!=`, `>=`, `<=`, `in`, `has`, `matches`, or `contains`)",
            )),
        }
    }

    /// The `<cmp-op> <value-expr>` tail of a value comparison whose
    /// left side is already parsed (LAN-299).
    fn value_cmp_tail(&mut self, lhs: ValueExprAst) -> PResult<Expr> {
        let op = match self.peek().map(|t| t.kind) {
            Some(Tok::EqEq) => CmpOp::Eq,
            Some(Tok::NotEq) => CmpOp::Ne,
            Some(Tok::GtEq) => CmpOp::Ge,
            Some(Tok::LtEq) => CmpOp::Le,
            _ => {
                return Err(
                    self.error_expected("a comparison operator (`==`, `!=`, `>=`, or `<=`)")
                );
            }
        };
        self.bump();
        let rhs = self.value_expr(0)?;
        let span = lhs.span().to(rhs.span());
        Ok(Expr::ValueCmp { lhs, op, rhs, span })
    }

    fn rhs(&mut self) -> PResult<Rhs> {
        let Some(token) = self.peek() else {
            return Err(self.error_expected("a comparison operand"));
        };
        match token.kind {
            Tok::Int => {
                let (value, span) = self.expect_u32("an integer")?;
                Ok(Rhs::Int(value, span))
            }
            Tok::Ident => Ok(Rhs::Ident(self.expect_ident("an operand")?)),
            Tok::Ipv4Lit | Tok::Ipv6Lit => {
                let (addr, span) = self.expect_ip("an IP address")?;
                Ok(Rhs::Ip(addr, span))
            }
            Tok::PrefixLit => {
                let (prefix, span) = self.expect_prefix()?;
                Ok(Rhs::Prefix(prefix, span))
            }
            Tok::Str => Ok(Rhs::Str(self.expect_str("a string")?)),
            Tok::StdCommunityLit | Tok::LargeCommunityLit | Tok::ExtCommunityLit => {
                Ok(Rhs::Community(self.community_lit()?))
            }
            // Field-vs-field comparison (`route.next-hop ==
            // peer.address`); the typechecker restricts which pairs
            // are legal.
            Tok::RouteKw | Tok::PeerKw => Ok(Rhs::Field(self.field_path()?)),
            _ => Err(self.error_expected(
                "a comparison operand (integer, identifier, IP, prefix, or string)",
            )),
        }
    }

    // ── tests ───────────────────────────────────────────────────────

    fn test_def(&mut self) -> PResult<TestDef> {
        self.expect(Tok::TestKw, "`test`")?;
        let name = self.expect_ident("a test name")?;
        self.expect(Tok::LBrace, "`{`")?;

        self.expect(Tok::RouteKw, "a `route { ... }` fixture")?;
        self.expect(Tok::LBrace, "`{`")?;
        let mut route = Vec::new();
        while !self.at(Tok::RBrace) {
            route.push(self.route_field()?);
            self.eat(Tok::Semi);
        }
        self.expect(Tok::RBrace, "`}`")?;

        let mut peer = Vec::new();
        if self.eat(Tok::PeerKw).is_some() {
            self.expect(Tok::LBrace, "`{`")?;
            while !self.at(Tok::RBrace) {
                peer.push(self.peer_field()?);
                self.eat(Tok::Semi);
            }
            self.expect(Tok::RBrace, "`}`")?;
        }

        let mut expects = Vec::new();
        while self.at(Tok::ExpectKw) {
            expects.push(self.expect_def()?);
        }
        if expects.is_empty() {
            self.diags.push(Diagnostic::new(
                self.here(),
                "test has no `expect`",
                "expected at least one `expect <policy> == accept|reject`",
            ));
            return Err(Fail);
        }
        self.expect(Tok::RBrace, "`}`")?;
        Ok(TestDef {
            name,
            route,
            peer,
            expects,
        })
    }

    fn route_field(&mut self) -> PResult<RouteField> {
        let field = self.expect_ident(
            "a route fixture field (`prefix`, `communities`, `as-path`, `rpki`, ...)",
        )?;
        match field.node.as_str() {
            "prefix" => {
                let (prefix, span) = self.expect_prefix()?;
                Ok(RouteField::Prefix(prefix, field.span.to(span)))
            }
            "communities" => {
                let (lits, span) = self.community_list()?;
                Ok(RouteField::Communities(lits, field.span.to(span)))
            }
            "large-communities" => {
                let (lits, span) = self.community_list()?;
                Ok(RouteField::LargeCommunities(lits, field.span.to(span)))
            }
            "ext-communities" => {
                let (lits, span) = self.community_list()?;
                Ok(RouteField::ExtCommunities(lits, field.span.to(span)))
            }
            "as-path" => Ok(RouteField::AsPath(
                self.expect_str("a space-separated ASN string (e.g. \"65001 65002\")")?,
            )),
            "next-hop" => {
                let (addr, span) = self.expect_ip("an IP address")?;
                Ok(RouteField::NextHop(addr, field.span.to(span)))
            }
            "local-pref" => {
                let (value, span) = self.expect_u32("a u32 value")?;
                Ok(RouteField::LocalPref(value, field.span.to(span)))
            }
            "med" => {
                let (value, span) = self.expect_u32("a u32 value")?;
                Ok(RouteField::Med(value, field.span.to(span)))
            }
            "rpki" => Ok(RouteField::Rpki(
                self.expect_ident("`valid`, `invalid`, or `not-found`")?,
            )),
            "aspa" => Ok(RouteField::Aspa(
                self.expect_ident("`valid`, `invalid`, or `unknown`")?,
            )),
            "route-type" => Ok(RouteField::RouteType(
                self.expect_ident("`local`, `internal`, or `external`")?,
            )),
            "evpn-route-type" => {
                let (value, span) = self.expect_u32("an EVPN route type (1-5)")?;
                Ok(RouteField::EvpnRouteType(value, field.span.to(span)))
            }
            "family" => Ok(RouteField::Family(
                self.expect_ident("a route family (`ipv4-unicast`, `evpn`, ...)")?,
            )),
            other => {
                let known = [
                    "prefix",
                    "communities",
                    "large-communities",
                    "ext-communities",
                    "as-path",
                    "next-hop",
                    "local-pref",
                    "med",
                    "rpki",
                    "aspa",
                    "route-type",
                    "evpn-route-type",
                    "family",
                ];
                let mut diag = Diagnostic::new(
                    field.span,
                    format!("unknown route fixture field `{other}`"),
                    "not a route fixture field",
                );
                if let Some(suggestion) = super::diag::closest(other, known) {
                    diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                }
                self.diags.push(diag);
                Err(Fail)
            }
        }
    }

    fn community_list(&mut self) -> PResult<(Vec<Spanned<CommunityLit>>, Span)> {
        let start = self.expect(Tok::LBracket, "`[`")?.span;
        let mut lits = Vec::new();
        while !self.at(Tok::RBracket) {
            lits.push(self.community_lit()?);
            if self.eat(Tok::Comma).is_none() {
                break;
            }
        }
        let end = self.expect(Tok::RBracket, "`]`")?.span;
        Ok((lits, start.to(end)))
    }

    fn peer_field(&mut self) -> PResult<PeerField> {
        let field =
            self.expect_ident("a peer fixture field (`address`, `asn`, `local-as`, `group`)")?;
        match field.node.as_str() {
            "address" => {
                let (addr, _) = self.expect_ip("an IP address")?;
                Ok(PeerField::Address(addr))
            }
            "asn" => {
                let (value, _) = self.expect_u32("an ASN")?;
                Ok(PeerField::Asn(value))
            }
            "local-as" => {
                let (value, _) = self.expect_u32("an ASN")?;
                Ok(PeerField::LocalAs(value))
            }
            "group" => Ok(PeerField::Group(self.expect_str("a group name string")?)),
            other => {
                let mut diag = Diagnostic::new(
                    field.span,
                    format!("unknown peer fixture field `{other}`"),
                    "not a peer fixture field",
                );
                if let Some(suggestion) =
                    super::diag::closest(other, ["address", "asn", "local-as", "group"])
                {
                    diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                }
                self.diags.push(diag);
                Err(Fail)
            }
        }
    }

    fn expect_def(&mut self) -> PResult<ExpectDef> {
        let start = self.expect(Tok::ExpectKw, "`expect`")?.span;
        let policy = self.expect_ident("a policy name")?;
        let mut args = Vec::new();
        if self.eat(Tok::LParen).is_some() {
            while !self.at(Tok::RParen) {
                let (value, span) = self.expect_u32("a u32 argument")?;
                args.push(Spanned::new(value, span));
                if self.eat(Tok::Comma).is_none() {
                    break;
                }
            }
            self.expect(Tok::RParen, "`)`")?;
        }
        self.expect(Tok::EqEq, "`==`")?;
        let accept = match self.peek().map(|t| t.kind) {
            Some(Tok::AcceptKw) => {
                self.bump();
                true
            }
            Some(Tok::RejectKw) => {
                self.bump();
                false
            }
            _ => return Err(self.error_expected("`accept` or `reject`")),
        };
        let mut with = Vec::new();
        let mut end = self.here();
        if self.eat(Tok::WithKw).is_some() {
            loop {
                with.push(self.with_assertion()?);
                if self.eat(Tok::Comma).is_none() {
                    break;
                }
            }
            end = self.here();
        }
        Ok(ExpectDef {
            policy,
            args,
            accept,
            with,
            span: start.to(end),
        })
    }

    fn with_assertion(&mut self) -> PResult<WithAssertion> {
        if self.eat(Tok::PrependKw).is_some() {
            self.expect(Tok::AsKw, "`as`")?;
            let (asn, _) = self.expect_u32("an ASN")?;
            let (count, _) = self.expect_u32("a prepend count")?;
            return Ok(WithAssertion::Prepend(asn, count));
        }
        let field =
            self.expect_ident("an assertion (`local-pref`, `med`, `next-hop`, `community`, ...)")?;
        match field.node.as_str() {
            "local-pref" => {
                let (value, _) = self.expect_u32("a u32 value")?;
                Ok(WithAssertion::LocalPref(value))
            }
            "med" => {
                let (value, _) = self.expect_u32("a u32 value")?;
                Ok(WithAssertion::Med(value))
            }
            "next-hop" => {
                if let Some(self_token) = self.eat(Tok::SelfKw) {
                    Ok(WithAssertion::NextHop(NextHopArg::Self_(self_token.span)))
                } else {
                    let (addr, span) = self.expect_ip("an IP address or `self`")?;
                    Ok(WithAssertion::NextHop(NextHopArg::Addr(addr, span)))
                }
            }
            "community" | "large-community" | "ext-community" => {
                Ok(WithAssertion::Community(self.community_lit()?))
            }
            other => {
                self.diags.push(
                    Diagnostic::new(
                        field.span,
                        format!("unknown `with` assertion `{other}`"),
                        "not an assertable attribute",
                    )
                    .with_note(
                        "assertable: local-pref, med, next-hop, community, large-community, ext-community, prepend",
                    ),
                );
                Err(Fail)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADR_EXAMPLE: &str = r"
prefix-set customers { 10.10.0.0/16 ge 24 le 28, 192.0.2.0/24 }
community-set tagged { 65000:100, 65000:200 }

policy customer-in(peer_lp: u32) {
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
    term customer-routes {
        if route.prefix in customers && route.communities has 65000:100 {
            set local-pref peer_lp;
            add community 65001:999;
            accept
        }
    }
    term bogon-guard { if apply(bogon-filter) { reject } }
}

policy bogon-filter {
    term bogons {
        if route.prefix == 0.0.0.0/8 { accept }
    }
    term not-a-bogon { reject }
}

test customer-in-accepts-tagged {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki valid }
    expect customer-in(200) == accept with local-pref 200
}
";

    #[test]
    fn parses_the_adr_example() {
        let (file, diags) = parse(ADR_EXAMPLE);
        assert!(diags.is_empty(), "{diags:#?}");
        assert_eq!(file.prefix_sets.len(), 1);
        assert_eq!(file.prefix_sets[0].entries.len(), 2);
        assert_eq!(file.prefix_sets[0].entries[0].ge, Some(24));
        assert_eq!(file.prefix_sets[0].entries[0].le, Some(28));
        assert_eq!(file.community_sets.len(), 1);
        assert_eq!(file.policies.len(), 2);
        assert_eq!(file.policies[0].params.len(), 1);
        assert_eq!(file.policies[0].terms.len(), 3);
        assert_eq!(file.tests.len(), 1);
        assert_eq!(file.tests[0].expects.len(), 1);
    }

    #[test]
    fn operator_precedence_not_binds_tighter_than_and_than_or() {
        let (file, diags) = parse(
            "policy p { term t { if !route.rpki == valid && route.med <= 5 || apply(q) { accept } } }",
        );
        // `!` applies to the comparison, not the whole conjunction:
        // ((!(rpki==valid)) && (med<=5)) || apply(q)
        assert!(diags.is_empty(), "{diags:#?}");
        let Stmt::If(if_stmt) = &file.policies[0].terms[0].stmts[0] else {
            panic!("expected if")
        };
        let Expr::Or(lhs, rhs) = &if_stmt.cond else {
            panic!("top must be Or, got {:?}", if_stmt.cond)
        };
        assert!(matches!(**rhs, Expr::Apply { .. }));
        let Expr::And(not_side, med_side) = &**lhs else {
            panic!("lhs must be And")
        };
        assert!(matches!(**not_side, Expr::Not(..)));
        assert!(matches!(**med_side, Expr::Cmp { .. }));
    }

    #[test]
    fn reports_multiple_errors_in_one_pass() {
        let src = "\
policy first { term t { if route.rpki = valid { reject } } }
policy second { term t { flarp } }
";
        let (file, diags) = parse(src);
        assert!(
            diags.len() >= 2,
            "want one error per broken policy, got {diags:#?}"
        );
        // Both policies attempted; neither silently swallowed the file.
        assert!(file.policies.len() <= 2);
    }

    #[test]
    fn rejects_host_bits_and_oversized_communities() {
        let (_, diags) = parse("prefix-set s { 10.0.0.1/24 }");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("host bits"), "{diags:#?}");

        let (_, diags) = parse("community-set c { 70000:1 }");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("fit in u16"), "{diags:#?}");
    }

    #[test]
    fn well_known_community_names_parse() {
        let (file, diags) = parse("community-set c { NO_EXPORT, BLACKHOLE }");
        assert!(diags.is_empty(), "{diags:#?}");
        assert_eq!(file.community_sets[0].entries.len(), 2);
        assert_eq!(
            file.community_sets[0].entries[0].node,
            CommunityLit::Standard(rustbgpd_wire::COMMUNITY_NO_EXPORT)
        );
    }

    #[test]
    fn parses_ext_and_large_community_forms() {
        let (file, diags) =
            parse("community-set c { RT:65001:100, RO:192.0.2.1:5, 65000:1:2, LC:65000:3:4 }");
        assert!(diags.is_empty(), "{diags:#?}");
        let entries = &file.community_sets[0].entries;
        assert!(matches!(
            entries[0].node,
            CommunityLit::Ext {
                route_target: true,
                global: 65001,
                local: 100,
                ipv4_admin: false,
            }
        ));
        assert!(matches!(
            entries[1].node,
            CommunityLit::Ext {
                route_target: false,
                ipv4_admin: true,
                ..
            }
        ));
        assert!(matches!(entries[2].node, CommunityLit::Large(_)));
        assert!(matches!(entries[3].node, CommunityLit::Large(_)));
    }

    #[test]
    fn else_branch_and_bare_actions_parse() {
        let src = "policy p { term t { set med 5; if route.med >= 10 { accept } else { add community 65000:1; reject } } }";
        let (file, diags) = parse(src);
        assert!(diags.is_empty(), "{diags:#?}");
        let term = &file.policies[0].terms[0];
        assert_eq!(term.stmts.len(), 2);
        let Stmt::If(if_stmt) = &term.stmts[1] else {
            panic!("expected if")
        };
        assert_eq!(if_stmt.else_actions.as_ref().map(Vec::len), Some(2));
    }
}
