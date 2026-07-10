//! The IR evaluator (ADR-0096) — the single evaluation engine behind
//! `evaluate_chain_with_attribution`.
//!
//! Semantics are decision-identical to the legacy statement walker
//! (pinned by the golden corpus in `engine/tests/ir_parity.rs`):
//! first-match-wins within a policy, `GoBGP` chain semantics across
//! policies (permits accumulate modifications and continue, a deny
//! terminates), RFC 4271 implicit `LOCAL_PREF`/`MED` defaults in
//! comparisons, and the same attribution rules.
//!
//! The no-match / no-modification path allocates nothing: guard
//! evaluation is all borrows, modifications are cloned only when a
//! matched permit term actually carries some, and the attribution name
//! is cloned only when the caller actually asked for attribution
//! (the `ATTR` const generic) — the plain [`CompiledChain::evaluate`]
//! path never touches it.

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::engine::{
    IMPLICIT_LOCAL_PREF, IMPLICIT_MED, PolicyAction, PolicyEvaluation, PolicyResult, PrependAs,
    RouteContext, RouteModifications,
};
use crate::ir::{
    ArithOp, Cmp, CompiledChain, CompiledPolicy, MatchExpr, TermAction, ValueCmpOp, ValueExpr,
    ValueField,
};
use crate::sets::prefix_entry_matches;

/// Why a route evaluation failed (LAN-299, the ADR-0103 Decision 4
/// rails). ANY of these resolves the route as a uniform **Deny**:
/// staged modifications are discarded, the chain's
/// [`PolicyHitCounters::eval_errors`] counter increments on the
/// counting paths, a rate-limited WARN names the failing policy/term,
/// and explain traces render the error in place of a verdict. Later
/// language slices (locals, loops, functions — ADR-0103) add kinds
/// here; the disposition never varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalErrorKind {
    /// `+` or `*` exceeded `u32::MAX`.
    Overflow,
    /// `-` went below zero (no signed types in the value model).
    Underflow,
    /// `/` with a zero divisor.
    DivideByZero,
    /// `%` with a zero divisor.
    RemainderByZero,
    /// `clamp(x, lo, hi)` evaluated with `lo > hi` (the statically
    /// known case is a compile error; this is the data-dependent one).
    ClampInverted,
    /// A `u32` field operand with no default was absent (origin AS on
    /// an empty/`AS_SET`-only path, unknown peer ASN).
    AbsentField(ValueField),
    /// A computed prepend operand (LAN-296) could not resolve —
    /// unknown context value, or zero (ASN 0 is prohibited on the
    /// wire, RFC 7607).
    AbsentPrependOperand(PrependAs),
    /// A `let`-binding slot was read with no frame written (LAN-302).
    /// Unreachable through the compiler — definite assignment and
    /// static slot allocation guarantee every `Local` read follows its
    /// `Bind` in walk order — so this is the fail-closed disposition
    /// of a compiler bug, mirroring how stale hit-counter shapes
    /// degrade instead of panicking on the production path.
    UnboundLocal,
}

impl EvalErrorKind {
    /// Stable short label (counter/log-friendly).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EvalErrorKind::Overflow => "overflow",
            EvalErrorKind::Underflow => "underflow",
            EvalErrorKind::DivideByZero => "divide-by-zero",
            EvalErrorKind::RemainderByZero => "remainder-by-zero",
            EvalErrorKind::ClampInverted => "clamp-inverted",
            EvalErrorKind::AbsentField(_) => "absent-operand",
            EvalErrorKind::AbsentPrependOperand(_) => "absent-prepend-operand",
            EvalErrorKind::UnboundLocal => "unbound-local",
        }
    }
}

impl fmt::Display for EvalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalErrorKind::Overflow => write!(f, "arithmetic overflow"),
            EvalErrorKind::Underflow => write!(f, "arithmetic underflow"),
            EvalErrorKind::DivideByZero => write!(f, "division by zero"),
            EvalErrorKind::RemainderByZero => write!(f, "remainder by zero"),
            EvalErrorKind::ClampInverted => write!(f, "clamp bounds inverted (lo > hi)"),
            EvalErrorKind::AbsentField(field) => {
                write!(f, "`{}` has no value for this route", field.as_str())
            }
            EvalErrorKind::AbsentPrependOperand(operand) => {
                write!(f, "prepend as {} unresolvable (", operand.as_str())?;
                match operand {
                    PrependAs::LocalAs => write!(f, "the chain carries no local ASN")?,
                    PrependAs::PeerAs => write!(f, "the peer ASN is unknown")?,
                    PrependAs::OriginAs => write!(f, "the route has no origin AS")?,
                }
                write!(f, ")")
            }
            EvalErrorKind::UnboundLocal => {
                write!(f, "internal error: unbound `let` slot (fail closed)")
            }
        }
    }
}

/// Size of the per-evaluation `let`-binding register file (LAN-302):
/// the language has exactly two nesting levels (a term body and one
/// `if`/`else` body), each capped at `MAX_LOCALS` = 64 bindings per
/// scope by the typechecker, so at most 2 × 64 slots are ever live.
/// Slots reset per source term and sibling scopes reuse, keeping the
/// frame this small forever (ADR-0103 Decision 3 caps the frame at
/// 1,024 slots; we need an eighth of that).
pub(crate) const LOCAL_FRAME_SLOTS: usize = 128;

/// The fixed-size evaluation frame `let` bindings live in: a stack
/// array, allocated (and zeroed) lazily only when a policy's walk
/// reaches its first [`TermAction::Bind`] — policies without bindings
/// never touch it, preserving the V1 hot-path cost exactly.
type LocalFrame = [u32; LOCAL_FRAME_SLOTS];

/// The frame as a read slice: empty when no binding has executed yet
/// (a `Local` read against it is the fail-closed
/// [`EvalErrorKind::UnboundLocal`] compiler-bug rail).
#[inline]
fn locals_slice(locals: Option<&LocalFrame>) -> &[u32] {
    locals.map_or(&[], |frame| &frame[..])
}

/// Evaluate a compiled value expression against a route context and
/// the current `let`-binding frame (`&[]` when the caller has none —
/// expressions without `Local` reads never index it). Pure and
/// allocation-free; every arithmetic step is checked (ADR-0103
/// Decision 2 — the SIGFPE class is unrepresentable). Recursion depth
/// is bounded by the frontend (`MAX_EXPR_DEPTH`).
pub(crate) fn eval_value(
    expr: &ValueExpr,
    ctx: &RouteContext<'_>,
    locals: &[u32],
) -> Result<u32, EvalErrorKind> {
    match expr {
        ValueExpr::Const(value) => Ok(*value),
        // One indexed load; the slot was written by this walk's Bind
        // term (definite assignment). `get` degrades a compiler bug to
        // a fail-closed eval error instead of a panic.
        ValueExpr::Local { slot, .. } => locals
            .get(*slot as usize)
            .copied()
            .ok_or(EvalErrorKind::UnboundLocal),
        ValueExpr::Field(field) => match field {
            ValueField::LocalPref => Ok(ctx.local_pref.unwrap_or(IMPLICIT_LOCAL_PREF)),
            ValueField::Med => Ok(ctx.med.unwrap_or(IMPLICIT_MED)),
            // Wire-bounded far below u32::MAX; saturate rather than
            // invent an error kind for an impossible input.
            ValueField::AsPathLen => Ok(u32::try_from(ctx.as_path_len).unwrap_or(u32::MAX)),
            ValueField::OriginAs => ctx
                .origin_asn
                .ok_or(EvalErrorKind::AbsentField(ValueField::OriginAs)),
            ValueField::PeerAsn => ctx
                .peer_asn
                .ok_or(EvalErrorKind::AbsentField(ValueField::PeerAsn)),
        },
        ValueExpr::Binary { op, lhs, rhs } => {
            let lhs = eval_value(lhs, ctx, locals)?;
            let rhs = eval_value(rhs, ctx, locals)?;
            checked_arith(*op, lhs, rhs)
        }
        ValueExpr::Min(a, b) => Ok(eval_value(a, ctx, locals)?.min(eval_value(b, ctx, locals)?)),
        ValueExpr::Max(a, b) => Ok(eval_value(a, ctx, locals)?.max(eval_value(b, ctx, locals)?)),
        ValueExpr::Clamp(x, lo, hi) => {
            let x = eval_value(x, ctx, locals)?;
            let lo = eval_value(lo, ctx, locals)?;
            let hi = eval_value(hi, ctx, locals)?;
            if lo > hi {
                return Err(EvalErrorKind::ClampInverted);
            }
            Ok(x.clamp(lo, hi))
        }
    }
}

/// One checked arithmetic step — the only place `u32` operators are
/// applied, shared by evaluation and compile-time constant folding so
/// the two can never disagree about what overflows.
pub(crate) fn checked_arith(op: ArithOp, lhs: u32, rhs: u32) -> Result<u32, EvalErrorKind> {
    match op {
        ArithOp::Add => lhs.checked_add(rhs).ok_or(EvalErrorKind::Overflow),
        ArithOp::Sub => lhs.checked_sub(rhs).ok_or(EvalErrorKind::Underflow),
        ArithOp::Mul => lhs.checked_mul(rhs).ok_or(EvalErrorKind::Overflow),
        ArithOp::Div => lhs.checked_div(rhs).ok_or(EvalErrorKind::DivideByZero),
        ArithOp::Rem => lhs.checked_rem(rhs).ok_or(EvalErrorKind::RemainderByZero),
    }
}

/// Rate-limited operator-visible WARN for evaluation errors: at most
/// one line per second process-wide (errors are per-route and can
/// arrive at line rate; the counters carry the volume). The clock read
/// is on the error path only — the ADR-0103 Decision 7 purity contract
/// exempts observability, and the hot path never reaches here.
fn warn_eval_error(policy: Option<&str>, term: Option<&str>, kind: EvalErrorKind) {
    static START: OnceLock<Instant> = OnceLock::new();
    static LAST_WARN: AtomicU64 = AtomicU64::new(0);
    let now = START.get_or_init(Instant::now).elapsed().as_secs() + 1;
    let last = LAST_WARN.load(Ordering::Relaxed);
    if now > last
        && LAST_WARN
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            policy = policy.unwrap_or("<inline>"),
            term = term.unwrap_or("<unnamed>"),
            reason = kind.label(),
            "policy evaluation error: {kind} — route denied (fail closed)"
        );
    }
}

/// Live per-term guard-hit counters for one chain (ADR-0096 Decision
/// 3.3, the IOS-XR `show pcl` idea): `hits[p][t]` counts how many
/// evaluated routes matched policy `p`'s term `t`'s guard, plus a
/// chain-level evaluation count as the denominator. Incremented with
/// relaxed atomics on the live evaluation path (one uncontended add per
/// matched term) and read by the policy-stats surface.
///
/// A counter set is shaped for — and only valid against — the
/// [`CompiledChain`] it was built from. It lives on the owning
/// `PolicyChain` instance, so replacing a chain resets the counts by
/// construction ("since chain install" semantics).
#[derive(Debug)]
pub struct PolicyHitCounters {
    policies: Vec<Vec<AtomicU64>>,
    evals: AtomicU64,
    eval_errors: AtomicU64,
}

impl PolicyHitCounters {
    /// Zeroed counters shaped like `chain` (one per term).
    #[must_use]
    pub fn for_chain(chain: &CompiledChain) -> Self {
        Self {
            policies: chain
                .policies
                .iter()
                .map(|policy| (0..policy.terms.len()).map(|_| AtomicU64::new(0)).collect())
                .collect(),
            evals: AtomicU64::new(0),
            eval_errors: AtomicU64::new(0),
        }
    }

    /// Routes evaluated through the chain since these counters were
    /// created (= since the chain instance was installed).
    #[must_use]
    pub fn evals(&self) -> u64 {
        self.evals.load(Ordering::Relaxed)
    }

    /// Routes denied by an evaluation error (LAN-299, ADR-0103
    /// Decision 4: checked-arithmetic failure or absent operand) since
    /// chain install. A nonzero value means some policy is erroring —
    /// the rate-limited WARN log and explain traces name where and
    /// why.
    #[must_use]
    pub fn eval_errors(&self) -> u64 {
        self.eval_errors.load(Ordering::Relaxed)
    }

    /// Snapshot of the per-term hit grid (`snapshot()[p][t]`).
    #[must_use]
    pub fn snapshot(&self) -> Vec<Vec<u64>> {
        self.policies
            .iter()
            .map(|terms| {
                terms
                    .iter()
                    .map(|hit| hit.load(Ordering::Relaxed))
                    .collect()
            })
            .collect()
    }
}

/// A policy's disposition of the route, borrowing the matched term's
/// modifications (cloned only if merged). `PermitOwned` carries
/// modifications accumulated from `Continue` terms merged with the
/// deciding term's own — only policies that actually hit a `Continue`
/// term (an `.rpol`-only construct) pay the clone. `Error` is the
/// LAN-299 evaluation-error rail: a guard or action-time value
/// expression failed; the caller denies the route, counts, and warns.
enum PolicyDecision<'a> {
    Permit(Option<&'a RouteModifications>),
    PermitOwned(RouteModifications),
    Deny,
    Error {
        kind: EvalErrorKind,
        term_index: usize,
    },
}

impl CompiledChain {
    /// Evaluate a route against this chain. Identical to
    /// [`evaluate_with_attribution`](Self::evaluate_with_attribution)
    /// without the attribution.
    #[must_use]
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> PolicyResult {
        self.evaluate_attributed::<false, false>(ctx, None).0
    }

    /// Evaluate a route against this chain with attribution to the
    /// terminal-decision policy — the IR backend of
    /// `PolicyChain::evaluate_with_attribution`, with identical
    /// semantics and results.
    #[must_use]
    pub fn evaluate_with_attribution(
        &self,
        ctx: &RouteContext<'_>,
    ) -> (PolicyResult, PolicyEvaluation) {
        self.evaluate_attributed::<false, true>(ctx, None)
    }

    /// Evaluate with live hit counting but without attribution — the
    /// non-attributed hot path (`PolicyChain::evaluate`). Skips the
    /// terminal policy-name clone that attribution pays per call.
    #[must_use]
    pub fn evaluate_counting(
        &self,
        ctx: &RouteContext<'_>,
        hits: &PolicyHitCounters,
    ) -> PolicyResult {
        hits.evals.fetch_add(1, Ordering::Relaxed);
        self.evaluate_attributed::<true, false>(ctx, Some(hits)).0
    }

    /// [`evaluate_with_attribution`](Self::evaluate_with_attribution)
    /// plus live hit counting: every matched guard bumps its term's
    /// counter (relaxed; `Continue` terms included, terms after the
    /// decider are never evaluated and never count) and the chain-level
    /// evaluation count increments once. `hits` is expected to have
    /// been built from this chain ([`PolicyHitCounters::for_chain`]); a
    /// set shorter than the chain (e.g. a stale hot-reload leftover)
    /// degrades to skipped increments rather than a panic.
    #[must_use]
    pub fn evaluate_with_attribution_counting(
        &self,
        ctx: &RouteContext<'_>,
        hits: &PolicyHitCounters,
    ) -> (PolicyResult, PolicyEvaluation) {
        hits.evals.fetch_add(1, Ordering::Relaxed);
        self.evaluate_attributed::<true, true>(ctx, Some(hits))
    }

    /// `COUNT` monomorphizes the walk: the non-counting instantiation
    /// compiles the counter plumbing away entirely, so the plain
    /// [`evaluate_with_attribution`](Self::evaluate_with_attribution)
    /// path costs exactly what it did before counters existed. `ATTR`
    /// does the same for attribution: the `false` instantiation never
    /// clones a policy name, so [`evaluate`](Self::evaluate) and
    /// [`evaluate_counting`](Self::evaluate_counting) allocate nothing
    /// for the discarded `PolicyEvaluation`.
    fn evaluate_attributed<const COUNT: bool, const ATTR: bool>(
        &self,
        ctx: &RouteContext<'_>,
        hits: Option<&PolicyHitCounters>,
    ) -> (PolicyResult, PolicyEvaluation) {
        let mut accumulated = RouteModifications::default();
        for (policy_index, policy) in self.policies.iter().enumerate() {
            let policy_hits = if COUNT {
                // Counters are shaped for — and live on — the chain they
                // were built from (they are replaced together), so a set
                // shorter than the chain is a construction impossibility.
                // `get` rather than `[]` keeps that invariant a
                // stat-undercount rather than a daemon panic if a future
                // refactor ever breaks it on this production path.
                hits.and_then(|h| h.policies.get(policy_index).map(Vec::as_slice))
            } else {
                None
            };
            match self.evaluate_policy::<COUNT>(policy, ctx, policy_hits) {
                PolicyDecision::Deny => {
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: if ATTR { policy.name.clone() } else { None },
                        },
                    );
                }
                // The LAN-299 eval-error rail (ADR-0103 Decision 4):
                // uniform Deny, staged modifications discarded (the
                // accumulator drops here), operator-visible counter +
                // rate-limited WARN naming the failing policy/term.
                PolicyDecision::Error { kind, term_index } => {
                    if COUNT && let Some(hits) = hits {
                        hits.eval_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    let term = policy
                        .terms
                        .get(term_index)
                        .and_then(|term| term.name.as_deref());
                    warn_eval_error(policy.name.as_deref(), term, kind);
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: if ATTR { policy.name.clone() } else { None },
                        },
                    );
                }
                PolicyDecision::Permit(Some(mods)) if !mods.is_empty() => {
                    accumulated.merge_from(mods.clone());
                }
                PolicyDecision::Permit(_) => {}
                PolicyDecision::PermitOwned(mods) => {
                    if !mods.is_empty() {
                        accumulated.merge_from(mods);
                    }
                }
            }
        }
        // All policies permitted (including an empty chain). Attribute
        // to the last policy in the chain since chain evaluation
        // completes only after every policy permits.
        let matched_policy = if ATTR {
            self.policies.last().and_then(|p| p.name.clone())
        } else {
            None
        };
        (
            PolicyResult {
                action: PolicyAction::Permit,
                modifications: accumulated,
            },
            PolicyEvaluation {
                action: PolicyAction::Permit,
                matched_policy,
            },
        )
    }

    /// A zeroed per-term hit-counter grid shaped like this chain, for
    /// [`evaluate_recording_hits`](Self::evaluate_recording_hits).
    #[must_use]
    pub fn zero_term_hits(&self) -> Vec<Vec<u64>> {
        self.policies
            .iter()
            .map(|policy| vec![0; policy.terms.len()])
            .collect()
    }

    /// Evaluate recording per-term guard hits — the `rbgp policy test`
    /// backend (ADR-0096 Decision 6). Decision semantics are identical
    /// to [`evaluate_with_attribution`](Self::evaluate_with_attribution)
    /// (same walk, same merge rules; an evaluation error denies the
    /// route, LAN-299 — dry runs move no live counters and log no
    /// WARN); additionally `hits[p][t]` is
    /// incremented whenever policy `p`'s term `t`'s guard matches
    /// during the walk (`Continue` terms included; terms after the
    /// deciding term are not evaluated, mirroring first-match-wins).
    ///
    /// # Panics
    ///
    /// If `hits` is not shaped like `policies` (one counter per term).
    #[must_use]
    pub fn evaluate_recording_hits(
        &self,
        ctx: &RouteContext<'_>,
        hits: &mut [Vec<u64>],
    ) -> PolicyResult {
        assert_eq!(hits.len(), self.policies.len(), "hits shaped like chain");
        let mut accumulated = RouteModifications::default();
        for (policy, policy_hits) in self.policies.iter().zip(hits.iter_mut()) {
            assert_eq!(policy_hits.len(), policy.terms.len());
            let mut continued: Option<RouteModifications> = None;
            // `Some(None)` = permit with no deciding-term mods;
            // `None` after the loop = fell through to default_action.
            let mut permit_mods: Option<Option<RouteModifications>> = None;
            let mut denied = false;
            // LAN-302: same lazy `let` frame as the live walk.
            let mut locals: Option<LocalFrame> = None;
            for (term, hit) in policy.terms.iter().zip(policy_hits.iter_mut()) {
                let mut err = None;
                let matched =
                    self.eval_expr(&term.guard, ctx, locals_slice(locals.as_ref()), &mut err);
                if err.is_some() {
                    // Guard evaluation error: fail closed (LAN-299).
                    denied = true;
                    break;
                }
                if matched {
                    *hit += 1;
                    match &term.action {
                        TermAction::Permit(mods) => {
                            match self.resolve_computed(mods, ctx, locals_slice(locals.as_ref())) {
                                Ok(resolved) => {
                                    permit_mods =
                                        Some(Some(resolved.unwrap_or_else(|| mods.clone())));
                                }
                                // Unresolvable computed operand: fail
                                // closed (same rule as the live walk).
                                Err(_) => denied = true,
                            }
                            break;
                        }
                        TermAction::Deny => {
                            denied = true;
                            break;
                        }
                        TermAction::Continue(mods) => {
                            if let Ok(resolved) =
                                self.resolve_computed(mods, ctx, locals_slice(locals.as_ref()))
                            {
                                continued
                                    .get_or_insert_with(RouteModifications::default)
                                    .merge_from(resolved.unwrap_or_else(|| mods.clone()));
                            } else {
                                denied = true;
                                break;
                            }
                        }
                        // LAN-302: eager `let`, identical to the live
                        // walk — initializer error fails closed.
                        TermAction::Bind { slot, expr, .. } => {
                            let Ok(value) = eval_value(expr, ctx, locals_slice(locals.as_ref()))
                            else {
                                denied = true;
                                break;
                            };
                            locals.get_or_insert([0; LOCAL_FRAME_SLOTS])[*slot as usize] = value;
                        }
                    }
                }
            }
            if permit_mods.is_none() && !denied {
                match policy.default_action {
                    PolicyAction::Permit => permit_mods = Some(None),
                    PolicyAction::Deny => denied = true,
                }
            }
            if denied {
                return PolicyResult::deny();
            }
            let mut merged = continued.unwrap_or_default();
            if let Some(Some(mods)) = permit_mods {
                merged.merge_from(mods);
            }
            if !merged.is_empty() {
                accumulated.merge_from(merged);
            }
        }
        PolicyResult {
            action: PolicyAction::Permit,
            modifications: accumulated,
        }
    }

    /// First-match-wins term walk; the policy's default action decides
    /// on fallthrough. [`TermAction::Continue`] terms are the one
    /// exception to first-match-wins: a matched Continue applies its
    /// modifications policy-locally and the walk keeps going; the
    /// eventual Permit merges them (the deciding term's own
    /// modifications winning scalar conflicts, mirroring chain-level
    /// merge), while a Deny — matched term or default — discards them.
    fn evaluate_policy<'a, const COUNT: bool>(
        &self,
        policy: &'a CompiledPolicy,
        ctx: &RouteContext<'_>,
        hits: Option<&[AtomicU64]>,
    ) -> PolicyDecision<'a> {
        let mut continued: Option<RouteModifications> = None;
        // LAN-302: the `let`-binding register file, materialized (one
        // stack zeroing, no heap) only when the walk reaches a Bind
        // term — binding-free policies never touch it.
        let mut locals: Option<LocalFrame> = None;
        for (term_index, term) in policy.terms.iter().enumerate() {
            let mut err = None;
            let matched = self.eval_expr(&term.guard, ctx, locals_slice(locals.as_ref()), &mut err);
            if let Some(kind) = err {
                // Guard evaluation error (LAN-299): terminal for the
                // route regardless of the guard's boolean outcome.
                return PolicyDecision::Error { kind, term_index };
            }
            if matched {
                if COUNT && let Some(hits) = hits {
                    // Same shape invariant as the per-policy slice: a
                    // term row shorter than the policy is impossible by
                    // construction, but `get` degrades to a skipped
                    // increment instead of a panic if it ever isn't.
                    if let Some(counter) = hits.get(term_index) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
                match &term.action {
                    TermAction::Permit(mods) => {
                        // LAN-296/LAN-299: fold computed operands
                        // (prepend, set values) into literal fields
                        // before the modifications leave the
                        // evaluator; an unresolvable operand fails the
                        // route closed on the eval-error rail.
                        let resolved =
                            match self.resolve_computed(mods, ctx, locals_slice(locals.as_ref())) {
                                Ok(resolved) => resolved,
                                Err(kind) => return PolicyDecision::Error { kind, term_index },
                            };
                        return match (continued, resolved) {
                            (Some(mut acc), resolved) => {
                                acc.merge_from(resolved.unwrap_or_else(|| mods.clone()));
                                PolicyDecision::PermitOwned(acc)
                            }
                            (None, Some(owned)) => PolicyDecision::PermitOwned(owned),
                            // The hot path: no Continue terms, nothing
                            // computed — borrow as before.
                            (None, None) => PolicyDecision::Permit(Some(mods)),
                        };
                    }
                    TermAction::Deny => return PolicyDecision::Deny,
                    TermAction::Continue(mods) => {
                        let resolved =
                            match self.resolve_computed(mods, ctx, locals_slice(locals.as_ref())) {
                                Ok(resolved) => resolved,
                                Err(kind) => return PolicyDecision::Error { kind, term_index },
                            };
                        continued
                            .get_or_insert_with(RouteModifications::default)
                            .merge_from(resolved.unwrap_or_else(|| mods.clone()));
                    }
                    // LAN-302: eager `let` — evaluate the initializer
                    // (against the frame as written so far; earlier
                    // bindings are readable), write the slot, keep
                    // walking. An initializer error is terminal on the
                    // uniform eval-error rail, used or not.
                    TermAction::Bind { slot, expr, .. } => {
                        match eval_value(expr, ctx, locals_slice(locals.as_ref())) {
                            Ok(value) => {
                                locals.get_or_insert([0; LOCAL_FRAME_SLOTS])[*slot as usize] =
                                    value;
                            }
                            Err(kind) => return PolicyDecision::Error { kind, term_index },
                        }
                    }
                }
            }
        }
        match (policy.default_action, continued) {
            (PolicyAction::Permit, Some(acc)) => PolicyDecision::PermitOwned(acc),
            (PolicyAction::Permit, None) => PolicyDecision::Permit(None),
            (PolicyAction::Deny, _) => PolicyDecision::Deny,
        }
    }

    /// Resolve a matched term's computed operands — the LAN-296
    /// prepend operand and the LAN-299 computed `set` values — against
    /// the evaluation context, at action-execution time.
    ///
    /// - `Ok(None)` — nothing computed (the hot path; no clone).
    /// - `Ok(Some(owned))` — a clone with every operand folded into
    ///   its literal field, so downstream consumers (merge, apply,
    ///   memoization, API surfaces) only ever see concrete values.
    /// - `Err(kind)` — an operand is unresolvable (absent context
    ///   value, checked-arithmetic failure): the caller fails the
    ///   route **closed** on the eval-error rail (uniform Deny +
    ///   counter + rate-limited WARN + explain error trace, ADR-0103
    ///   Decision 4). ASN 0 is never prepended (RFC 7607).
    pub(crate) fn resolve_computed(
        &self,
        mods: &RouteModifications,
        ctx: &RouteContext<'_>,
        locals: &[u32],
    ) -> Result<Option<RouteModifications>, EvalErrorKind> {
        if mods.as_path_prepend_computed.is_none()
            && mods.set_local_pref_computed.is_none()
            && mods.set_med_computed.is_none()
        {
            return Ok(None);
        }
        let mut resolved = mods.clone();
        if let Some((operand, count)) = mods.as_path_prepend_computed {
            let asn = operand
                .resolve(self.local_asn, ctx)
                .ok_or(EvalErrorKind::AbsentPrependOperand(operand))?;
            resolved.as_path_prepend = Some((asn, count));
            resolved.as_path_prepend_computed = None;
        }
        if let Some(expr) = &mods.set_local_pref_computed {
            resolved.set_local_pref = Some(eval_value(expr, ctx, locals)?);
            resolved.set_local_pref_computed = None;
        }
        if let Some(expr) = &mods.set_med_computed {
            resolved.set_med = Some(eval_value(expr, ctx, locals)?);
            resolved.set_med_computed = None;
        }
        Ok(Some(resolved))
    }

    /// Evaluate a single guard against this chain's set tables — the
    /// explain walk's window into the live matcher, so explain and
    /// evaluation cannot disagree about whether a guard fires (the
    /// same discipline as the legacy walk sharing
    /// `PolicyStatement::matches`). `Err` when the guard contains a
    /// value expression that failed to evaluate — the live walk denies
    /// the route there (LAN-299), and explain must render the same.
    /// `locals` is the caller's `let` frame (LAN-302): the explain
    /// trace walk re-derives bindings term by term and passes its own
    /// frame here, so guard evaluation stays shared.
    pub(crate) fn guard_matches(
        &self,
        expr: &MatchExpr,
        ctx: &RouteContext<'_>,
        locals: &[u32],
    ) -> Result<bool, EvalErrorKind> {
        let mut err = None;
        let matched = self.eval_expr(expr, ctx, locals, &mut err);
        match err {
            Some(kind) => Err(kind),
            None => Ok(matched),
        }
    }

    /// Evaluate one guard node. Pure and allocation-free; set/regex
    /// ids index this chain's tables directly (out-of-range ids are a
    /// compiler bug, not reachable from operator input). Evaluation is
    /// flat: rpol `apply` is inlined into the guard tree at lower time
    /// (never a runtime call into another policy), and the tree's depth
    /// is capped by the frontend (`MAX_EXPR_DEPTH` at parse,
    /// `MAX_APPLY_DEPTH`/`MAX_APPLY_EXPANSION` at typecheck — LAN-184 /
    /// LAN-290), so this recursion is statically bounded.
    ///
    /// `err` is the LAN-299 eval-error slot: a [`MatchExpr::ValueCmp`]
    /// whose value expression fails sets it (first error wins) and
    /// yields `false`; callers must treat a set slot as terminal for
    /// the route (uniform Deny) — the boolean is then meaningless.
    /// Short-circuited subtrees are never evaluated, so an error on a
    /// path the walk never reaches does not fire (lazy, like the
    /// arithmetic itself).
    fn eval_expr(
        &self,
        expr: &MatchExpr,
        ctx: &RouteContext<'_>,
        locals: &[u32],
        err: &mut Option<EvalErrorKind>,
    ) -> bool {
        match expr {
            MatchExpr::True => true,
            MatchExpr::And(children) => children
                .iter()
                .all(|child| self.eval_expr(child, ctx, locals, err)),
            MatchExpr::Or(children) => children
                .iter()
                .any(|child| self.eval_expr(child, ctx, locals, err)),
            MatchExpr::Not(inner) => !self.eval_expr(inner, ctx, locals, err),
            MatchExpr::ValueCmp(node) => {
                match (
                    eval_value(&node.lhs, ctx, locals),
                    eval_value(&node.rhs, ctx, locals),
                ) {
                    (Ok(lhs), Ok(rhs)) => match node.op {
                        ValueCmpOp::Eq => lhs == rhs,
                        ValueCmpOp::Ne => lhs != rhs,
                        ValueCmpOp::Ge => lhs >= rhs,
                        ValueCmpOp::Le => lhs <= rhs,
                    },
                    (Err(kind), _) | (_, Err(kind)) => {
                        err.get_or_insert(kind);
                        false
                    }
                }
            }
            MatchExpr::PrefixEq { prefix, ge, le } => ctx
                .prefix
                .is_some_and(|candidate| prefix_entry_matches(*prefix, *ge, *le, candidate)),
            // `!=` mirrors `==`: a prefixless route (BGP-LS / RTC NLRIs)
            // matches neither, so require the prefix present before
            // testing non-containment.
            MatchExpr::PrefixNe { prefix, ge, le } => ctx
                .prefix
                .is_some_and(|candidate| !prefix_entry_matches(*prefix, *ge, *le, candidate)),
            MatchExpr::PrefixInSet(id) => ctx
                .prefix
                .is_some_and(|candidate| self.prefix_sets[id.0 as usize].matches(candidate)),
            MatchExpr::CommunityContains(cm) => cm.matches_route_communities(ctx),
            MatchExpr::CommunityInSet(id) => self.community_sets[id.0 as usize].matches(ctx),
            MatchExpr::AsPathMatches(id) => {
                self.as_path_regexes[id.0 as usize].is_match(ctx.as_path_str)
            }
            MatchExpr::AsPathLen(cmp) => cmp_len(*cmp, ctx.as_path_len),
            MatchExpr::OriginAsEq(asn) => ctx.origin_asn == Some(*asn),
            // `!=` mirrors `==`: an absent origin (empty or AS_SET-only
            // path) matches neither, so require it present first.
            MatchExpr::OriginAsNe(asn) => ctx.origin_asn.is_some_and(|origin| origin != *asn),
            MatchExpr::OriginAsInSet(id) => ctx
                .origin_asn
                .is_some_and(|origin| self.asn_sets[id.0 as usize].contains(origin)),
            MatchExpr::PeerAsInSet(id) => ctx
                .peer_asn
                .is_some_and(|asn| self.asn_sets[id.0 as usize].contains(asn)),
            MatchExpr::LocalPref(cmp) => {
                cmp_value(*cmp, ctx.local_pref.unwrap_or(IMPLICIT_LOCAL_PREF))
            }
            MatchExpr::Med(cmp) => cmp_value(*cmp, ctx.med.unwrap_or(IMPLICIT_MED)),
            MatchExpr::NextHopEq(next_hop) => ctx.next_hop == Some(*next_hop),
            // `!=` mirrors `==`: an absent next-hop matches neither, so
            // require the attribute to be present before comparing.
            MatchExpr::NextHopNe(next_hop) => ctx.next_hop.is_some_and(|nh| nh != *next_hop),
            // Strict next-hop: both sides must be known; two unknowns
            // are not a match.
            MatchExpr::NextHopEqPeer => match (ctx.next_hop, ctx.peer_address) {
                (Some(next_hop), Some(peer)) => next_hop == peer,
                _ => false,
            },
            // Strict next-hop `!=`: like `==`, both sides must be known;
            // an absent next-hop or peer never matches.
            MatchExpr::NextHopNePeer => match (ctx.next_hop, ctx.peer_address) {
                (Some(next_hop), Some(peer)) => next_hop != peer,
                _ => false,
            },
            MatchExpr::NeighborIn(set) => {
                set.matches(ctx.peer_address, ctx.peer_asn, ctx.peer_group)
            }
            MatchExpr::RouteTypeIs(route_type) => ctx.route_type == Some(*route_type),
            // `!=` mirrors `==`: an absent route-type matches neither.
            MatchExpr::RouteTypeNe(route_type) => ctx.route_type.is_some_and(|t| t != *route_type),
            MatchExpr::EvpnRouteTypeIs(evpn_type) => ctx.evpn_route_type == Some(*evpn_type),
            // `!=` mirrors `==`: a non-EVPN route (absent
            // evpn-route-type) matches neither.
            MatchExpr::EvpnRouteTypeNe(evpn_type) => {
                ctx.evpn_route_type.is_some_and(|t| t != *evpn_type)
            }
            MatchExpr::FamilyIs(family) => ctx.family == Some(*family),
            // `!=` mirrors `==`: a context without typed family
            // knowledge matches neither.
            MatchExpr::FamilyNe(family) => ctx.family.is_some_and(|f| f != *family),
            MatchExpr::RpkiIs(state) => ctx.validation_state == *state,
            MatchExpr::AspaIs(state) => ctx.aspa_state == *state,
        }
    }
}

#[inline]
fn cmp_value(cmp: Cmp, value: u32) -> bool {
    match cmp {
        Cmp::Ge(bound) => value >= bound,
        Cmp::Le(bound) => value <= bound,
    }
}

/// `AS_PATH` length comparison — mirrors the legacy `v as usize`
/// widening against the context's `usize` count.
#[inline]
fn cmp_len(cmp: Cmp, len: usize) -> bool {
    match cmp {
        Cmp::Ge(bound) => len >= bound as usize,
        Cmp::Le(bound) => len <= bound as usize,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use rustbgpd_wire::{AspaValidation, Ipv4Prefix, Prefix, RpkiValidation};

    use crate::engine::{PolicyAction, RouteContext, RouteModifications};
    use crate::ir::{
        CompiledChain, CompiledPolicy, MatchExpr, PolicySource, SetId, Term, TermAction,
    };
    use crate::sets::{PrefixSet, PrefixSetEntry};

    fn ctx(prefix: Option<Prefix>) -> RouteContext<'static> {
        RouteContext {
            prefix,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path_len: 0,
            origin_asn: None,
            validation_state: RpkiValidation::NotFound,
            aspa_state: AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        }
    }

    fn single_term_chain(guard: MatchExpr, prefix_sets: Vec<Arc<PrefixSet>>) -> CompiledChain {
        CompiledChain {
            policies: vec![CompiledPolicy {
                name: None,
                terms: vec![Term {
                    name: None,
                    guard,
                    action: TermAction::Permit(RouteModifications::default()),
                }],
                default_action: PolicyAction::Deny,
                source: PolicySource::Toml,
            }],
            prefix_sets,
            ..CompiledChain::empty()
        }
    }

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            len,
        ))
    }

    /// Or / Not / True have no TOML frontend yet, so the golden corpus
    /// cannot reach them — pin their truth tables directly.
    #[test]
    fn or_not_true_semantics() {
        let route = ctx(Some(v4([10, 0, 0, 0], 24)));
        let hit = MatchExpr::PrefixEq {
            prefix: v4([10, 0, 0, 0], 24),
            ge: None,
            le: None,
        };
        let miss = MatchExpr::PrefixEq {
            prefix: v4([192, 0, 2, 0], 24),
            ge: None,
            le: None,
        };

        for (guard, expect) in [
            (MatchExpr::True, true),
            (MatchExpr::Or(vec![miss.clone(), hit.clone()]), true),
            (MatchExpr::Or(vec![miss.clone(), miss.clone()]), false),
            (MatchExpr::Or(vec![]), false),
            (MatchExpr::And(vec![]), true),
            (MatchExpr::Not(Box::new(miss.clone())), true),
            (MatchExpr::Not(Box::new(hit.clone())), false),
        ] {
            let chain = single_term_chain(guard.clone(), Vec::new());
            let (result, _) = chain.evaluate_with_attribution(&route);
            assert_eq!(
                result.action,
                if expect {
                    PolicyAction::Permit
                } else {
                    PolicyAction::Deny
                },
                "guard {guard:?}"
            );
        }
    }

    /// `evaluate_recording_hits` must be decision-identical to
    /// `evaluate_with_attribution` while counting matched guards —
    /// including Continue terms and terms skipped after the decider.
    #[test]
    fn recording_hits_matches_plain_evaluation_and_counts() {
        use crate::ir::CompiledPolicy;

        let hit = MatchExpr::PrefixEq {
            prefix: v4([10, 0, 0, 0], 8),
            ge: Some(8),
            le: Some(32),
        };
        let chain = CompiledChain {
            policies: vec![CompiledPolicy {
                name: Some("p".to_string()),
                terms: vec![
                    Term {
                        name: Some("tag".to_string()),
                        guard: hit.clone(),
                        action: TermAction::Continue(RouteModifications {
                            set_med: Some(5),
                            ..RouteModifications::default()
                        }),
                    },
                    Term {
                        name: Some("accept-10".to_string()),
                        guard: hit.clone(),
                        action: TermAction::Permit(RouteModifications {
                            set_local_pref: Some(200),
                            ..RouteModifications::default()
                        }),
                    },
                    Term {
                        name: Some("unreached".to_string()),
                        guard: MatchExpr::True,
                        action: TermAction::Deny,
                    },
                ],
                default_action: PolicyAction::Deny,
                source: PolicySource::Toml,
            }],
            ..CompiledChain::empty()
        };

        let mut hits = chain.zero_term_hits();
        assert_eq!(hits, vec![vec![0, 0, 0]]);
        for (route, expect_permit) in [
            (ctx(Some(v4([10, 1, 0, 0], 24))), true),
            (ctx(Some(v4([10, 2, 0, 0], 24))), true),
            (ctx(Some(v4([192, 0, 2, 0], 24))), false),
        ] {
            let recorded = chain.evaluate_recording_hits(&route, &mut hits);
            let (plain, _) = chain.evaluate_with_attribution(&route);
            assert_eq!(recorded, plain);
            assert_eq!(
                recorded.action,
                if expect_permit {
                    PolicyAction::Permit
                } else {
                    PolicyAction::Deny
                }
            );
            if expect_permit {
                // Continue mods merged under the deciding permit.
                assert_eq!(recorded.modifications.set_med, Some(5));
                assert_eq!(recorded.modifications.set_local_pref, Some(200));
            }
        }
        // Two 10/8 routes hit tag + accept-10; the miss hits only the
        // unconditional deny (terms after a decider are not evaluated).
        assert_eq!(hits, vec![vec![2, 2, 1]]);
    }

    #[test]
    fn prefix_in_set_respects_prefixless_routes() {
        let set = Arc::new(PrefixSet::new([PrefixSetEntry {
            prefix: v4([10, 0, 0, 0], 8),
            ge: Some(8),
            le: Some(32),
        }]));
        let chain = single_term_chain(MatchExpr::PrefixInSet(SetId(0)), vec![set]);

        let (result, _) = chain.evaluate_with_attribution(&ctx(Some(v4([10, 1, 2, 0], 24))));
        assert_eq!(result.action, PolicyAction::Permit);

        // A prefixless route (e.g. BGP-LS) never matches prefix nodes.
        let (result, _) = chain.evaluate_with_attribution(&ctx(None));
        assert_eq!(result.action, PolicyAction::Deny);
    }

    /// LAN-192: a counter set shorter than the chain (a stale hot-reload
    /// leftover) must degrade to skipped increments, not an index panic
    /// on the production evaluation path.
    #[test]
    fn stale_short_counter_set_does_not_panic() {
        use super::PolicyHitCounters;

        // Counters shaped for a 1-policy / 1-term chain…
        let small = single_term_chain(MatchExpr::True, Vec::new());
        let counters = PolicyHitCounters::for_chain(&small);

        // …applied to a larger chain: policy 0 visits two terms (the
        // second is out of the 1-term counter row) and policy 1 is out
        // of the 1-policy counter set entirely.
        let big = CompiledChain {
            policies: vec![
                CompiledPolicy {
                    name: Some("p0".to_string()),
                    terms: vec![
                        Term {
                            name: None,
                            guard: MatchExpr::True,
                            action: TermAction::Continue(RouteModifications::default()),
                        },
                        Term {
                            name: None,
                            guard: MatchExpr::True,
                            action: TermAction::Permit(RouteModifications::default()),
                        },
                    ],
                    default_action: PolicyAction::Deny,
                    source: PolicySource::Toml,
                },
                CompiledPolicy {
                    name: Some("p1".to_string()),
                    terms: vec![Term {
                        name: None,
                        guard: MatchExpr::True,
                        action: TermAction::Permit(RouteModifications::default()),
                    }],
                    default_action: PolicyAction::Deny,
                    source: PolicySource::Toml,
                },
            ],
            ..CompiledChain::empty()
        };

        let (result, _) = big.evaluate_with_attribution_counting(&ctx(None), &counters);
        assert_eq!(result.action, PolicyAction::Permit);
        // In-range term still counted; out-of-range slots skipped.
        assert_eq!(counters.snapshot(), vec![vec![1]]);
        assert_eq!(counters.evals(), 1);
    }
}
