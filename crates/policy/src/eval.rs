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

use std::sync::Arc;

use crate::datasets::{DatasetData, DatasetSnapshot, MAX_UNIT_DATASETS};
use crate::engine::{
    IMPLICIT_LOCAL_PREF, IMPLICIT_MED, PolicyAction, PolicyEvaluation, PolicyResult, PrependAs,
    RouteContext, RouteModifications,
};
use crate::ir::{
    ArithOp, Cmp, CompiledChain, CompiledPolicy, DatasetProbe, ForEachNode, LoopSource, MatchExpr,
    TermAction, ValueCmpOp, ValueExpr, ValueField,
};
use crate::sets::prefix_entry_matches;

/// The per-walk dataset pin frame (LAN-305, ADR-0103 Decision 8.5):
/// slot `i` holds the snapshot pinned for the chain's `DatasetId(i)`.
/// Built once at walk start by [`CompiledChain::pin_datasets`] and
/// read-only thereafter, so every probe in one walk — however many
/// guards reference the same dataset — sees exactly one generation,
/// even when a swap lands mid-walk. Chains without datasets pass the
/// shared empty frame; the fixed array is stack storage, sized by the
/// compile-time `MAX_UNIT_DATASETS` budget, so the pin allocates
/// nothing.
pub(crate) type PinnedDatasets = [Option<Arc<DatasetSnapshot>>; MAX_UNIT_DATASETS];

/// The dataset-free pin frame — what every chain compiled without
/// dataset references walks with, at zero per-route cost beyond one
/// branch.
pub(crate) static NO_DATASETS: PinnedDatasets = [const { None }; MAX_UNIT_DATASETS];

/// Worst-case per-route evaluation steps (ADR-0103 Decision 3,
/// `MAX_EVAL_COST`): the compile-time budget the typecheck cost DP
/// enforces per policy, and the runtime fuel every evaluation starts
/// with (LAN-303). Not operator-tunable.
pub(crate) const MAX_EVAL_COST: u64 = 1_000_000;

/// Hard per-loop iteration cap (ADR-0103 Decision 3,
/// `MAX_LOOP_ITERATIONS`): a loop whose source still has elements
/// after this many iterations fails the route closed
/// ([`EvalErrorKind::LoopLimitExceeded`]) — cap-then-**error**, never
/// silent truncation. Reachable only through pathological
/// data-dependent input (e.g. an extended-message route carrying tens
/// of thousands of communities); set sources larger than this are
/// rejected at compile time.
pub(crate) const MAX_LOOP_ITERATIONS: u32 = 4096;

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
    /// The per-evaluation instruction fuel ran out (LAN-303, ADR-0103
    /// Decision 3): the walk executed `MAX_EVAL_COST` (1,000,000)
    /// loop-iteration steps. The compile-time cost DP bounds each policy below the
    /// budget, so exhaustion indicates pathological data-dependent
    /// input compounding across a chain, or a compiler bug — both fail
    /// closed.
    FuelExhausted,
    /// One loop iterated past `MAX_LOOP_ITERATIONS` (4,096) with
    /// source elements remaining (LAN-303) — e.g. a peer-supplied route
    /// carrying more communities than the cap. Cap-then-error: the
    /// route is denied, never partially processed.
    LoopLimitExceeded,
    /// A `break`/`continue` term reached the policy-level walk
    /// (LAN-303). Unreachable through the compiler — the typechecker
    /// confines loop control to loop bodies — so this is the
    /// fail-closed disposition of a compiler bug, like
    /// [`UnboundLocal`](Self::UnboundLocal).
    StrayLoopControl,
    /// A dataset probe found no pinned snapshot in its slot, or a
    /// snapshot of the wrong kind (LAN-305). Unreachable through the
    /// compiler — lowering binds every referenced dataset or fails the
    /// compile, and kind agreement is a typecheck guarantee — so this
    /// is the fail-closed disposition of a compiler bug, like
    /// [`UnboundLocal`](Self::UnboundLocal).
    DatasetUnpinned,
}

/// One evaluation error with its blame context (LAN-301): the kind
/// plus the failing policy/term names, as the live walk resolved them.
/// Carried on [`PolicyEvaluation`](crate::engine::PolicyEvaluation)
/// (error path only — the hot path never builds one) and retained per
/// chain as [`PolicyHitCounters::last_error`] for the stats surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    /// Why the evaluation failed.
    pub kind: EvalErrorKind,
    /// Name of the failing policy (`None` = inline / anonymous).
    pub policy: Option<String>,
    /// Name of the failing term (`Bind` terms carry the qualified
    /// `term (let binding)` form); `None` for unnamed TOML statements.
    pub term: Option<String>,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} in policy {} term {}",
            self.kind.label(),
            self.policy.as_deref().unwrap_or("<inline>"),
            self.term.as_deref().unwrap_or("<unnamed>"),
        )
    }
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
            EvalErrorKind::FuelExhausted => "fuel-exhausted",
            EvalErrorKind::LoopLimitExceeded => "loop-limit-exceeded",
            EvalErrorKind::StrayLoopControl => "stray-loop-control",
            EvalErrorKind::DatasetUnpinned => "dataset-unpinned",
        }
    }

    /// Every stable label, for surfaces that validate operator-written
    /// kind names (the in-language `expect ... == error KIND` form).
    /// The kind set is closed by construction — extending the enum
    /// extends this list (the exhaustive `label` match enforces it).
    pub const LABELS: &'static [&'static str] = &[
        "overflow",
        "underflow",
        "divide-by-zero",
        "remainder-by-zero",
        "clamp-inverted",
        "absent-operand",
        "absent-prepend-operand",
        "unbound-local",
        "fuel-exhausted",
        "loop-limit-exceeded",
        "stray-loop-control",
        "dataset-unpinned",
    ];
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
            EvalErrorKind::FuelExhausted => {
                write!(
                    f,
                    "evaluation fuel exhausted ({MAX_EVAL_COST} iteration steps)"
                )
            }
            EvalErrorKind::LoopLimitExceeded => {
                write!(
                    f,
                    "loop exceeded {MAX_LOOP_ITERATIONS} iterations with elements remaining"
                )
            }
            EvalErrorKind::StrayLoopControl => {
                write!(
                    f,
                    "internal error: break/continue outside a loop (fail closed)"
                )
            }
            EvalErrorKind::DatasetUnpinned => {
                write!(
                    f,
                    "internal error: dataset snapshot unpinned or wrong kind (fail closed)"
                )
            }
        }
    }
}

/// Size of the per-evaluation `let`-binding register file (LAN-302 /
/// LAN-303): scopes are a term body, up to `MAX_LOOP_DEPTH` (4) nested
/// loop bodies, and one `if`/`else` body — each capped at `MAX_LOCALS`
/// = 64 bindings by the typechecker, which additionally rejects any
/// program whose live bindings along one path exceed this frame (the
/// slot is a `u8`, so 256 is the natural register-file size and stays
/// well under ADR-0103 Decision 3's 1,024-slot cap). Slots reset per
/// source term and sibling scopes reuse.
pub(crate) const LOCAL_FRAME_SLOTS: usize = 256;

/// The fixed-size evaluation frame `let` bindings live in: a stack
/// array, allocated (and zeroed) lazily only when a policy's walk
/// reaches its first [`TermAction::Bind`] — policies without bindings
/// never touch it, preserving the V1 hot-path cost exactly.
pub(crate) type LocalFrame = [u32; LOCAL_FRAME_SLOTS];

/// The frame as a read slice: empty when no binding has executed yet
/// (a `Local` read against it is the fail-closed
/// [`EvalErrorKind::UnboundLocal`] compiler-bug rail).
#[inline]
pub(crate) fn locals_slice(locals: Option<&LocalFrame>) -> &[u32] {
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
    /// Most recent evaluation error (LAN-301) — the "why" behind a
    /// nonzero `eval_errors`, surfaced by `rbgp policy stats`. Behind
    /// a `Mutex` because it carries names; written on the (cold,
    /// rate-bounded) error path only, never on the hot path.
    last_error: std::sync::Mutex<Option<EvalError>>,
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
            last_error: std::sync::Mutex::new(None),
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

    /// The most recent evaluation error, if any route has errored
    /// since chain install (LAN-301) — kind plus the failing
    /// policy/term, for the stats surface.
    #[must_use]
    pub fn last_error(&self) -> Option<EvalError> {
        self.last_error.lock().map_or(None, |guard| guard.clone())
    }

    /// Record one evaluation error: bump the counter and retain the
    /// error as [`last_error`](Self::last_error). Error path only.
    fn record_eval_error(&self, error: &EvalError) {
        self.eval_errors.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = Some(error.clone());
        }
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

/// The result of one loop evaluation (LAN-303): how many iterations
/// executed, whether (and where) a body verdict decided the policy.
/// The extra fields are cheap scalars carried for explain rendering
/// (loop summary + the deciding iteration — never per-iteration
/// output).
pub(crate) struct LoopOutcome {
    /// Iterations entered (each paid one fuel step).
    pub(crate) iterations: u32,
    /// 0-based iteration index of the deciding verdict, `None` when
    /// the loop ran to completion or exited via `break`.
    pub(crate) decided_at: Option<u32>,
    /// How the loop resolved.
    pub(crate) flow: LoopFlow,
}

/// How a loop resolved (LAN-303).
#[expect(
    clippy::large_enum_variant,
    reason = "transient per-decision return value, never stored or collected"
)]
pub(crate) enum LoopFlow {
    /// Ran out of elements or hit `break`: the enclosing walk
    /// continues after the loop.
    Completed,
    /// A body `accept` decided the policy, carrying the deciding
    /// term's resolved modifications (the caller merges accumulated
    /// `Continue` modifications under it, as with any permit).
    Permit(RouteModifications),
    /// A body `reject` decided the policy.
    Deny,
}

/// The element stream of one loop source (LAN-303). Attribute lists
/// and set snapshots iterate as slices; the typed `AS_PATH` flattens
/// through `AsPath::asns` (boxed — one allocation at loop entry, on
/// the loop path only; the loop-free hot path never constructs one).
enum ElementIter<'a> {
    Slice(std::slice::Iter<'a, u32>),
    Path(Box<dyn Iterator<Item = u32> + 'a>),
}

impl Iterator for ElementIter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        match self {
            ElementIter::Slice(iter) => iter.next().copied(),
            ElementIter::Path(iter) => iter.next(),
        }
    }
}

/// Execute a [`TermAction::CommunityVar`]: read the binding's value
/// from the frame and stage it as a standard-community add/remove in
/// the policy-local accumulator. A missing frame/slot is the
/// fail-closed compiler-bug rail, like every `Local` read.
pub(crate) fn exec_community_var(
    add: bool,
    slot: u8,
    locals: Option<&LocalFrame>,
    continued: &mut Option<RouteModifications>,
) -> Result<(), EvalErrorKind> {
    let value = locals_slice(locals)
        .get(usize::from(slot))
        .copied()
        .ok_or(EvalErrorKind::UnboundLocal)?;
    let mut mods = RouteModifications::default();
    if add {
        mods.communities_add.push(value);
    } else {
        mods.communities_remove.push(value);
    }
    continued
        .get_or_insert_with(RouteModifications::default)
        .merge_from(mods);
    Ok(())
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
        // The LAN-303 runtime fuel: one register write per evaluation.
        // Decremented ONLY at loop iteration steps (`eval_for_each`) —
        // straight-line code is pre-paid by the compile-time cost DP,
        // so a loop-free walk never touches it again and the V1 hot
        // path keeps its exact cost profile (ADR-0103 Decision 3).
        let mut fuel: u64 = MAX_EVAL_COST;
        self.evaluate_fueled::<COUNT, ATTR>(ctx, hits, &mut fuel)
    }

    /// [`evaluate_attributed`](Self::evaluate_attributed) against a
    /// caller-owned fuel counter, so tests can pin fuel accounting
    /// exactness (consumed == loop iterations) and exhaustion.
    #[cfg(test)]
    pub(crate) fn evaluate_measuring_fuel(&self, ctx: &RouteContext<'_>) -> (PolicyResult, u64) {
        let mut fuel: u64 = MAX_EVAL_COST;
        let (result, _) = self.evaluate_fueled::<false, false>(ctx, None, &mut fuel);
        (result, MAX_EVAL_COST - fuel)
    }

    /// Pin every referenced dataset's current snapshot — the per-walk
    /// pinning step (LAN-305, ADR-0103 Decision 8.5). One wait-free
    /// load per referenced dataset; the returned frame is stack
    /// storage. `None` when the chain references no datasets (the hot
    /// path: one branch, nothing built).
    pub(crate) fn pin_datasets(&self) -> Option<PinnedDatasets> {
        if self.datasets.is_empty() {
            return None;
        }
        let mut pinned: PinnedDatasets = [const { None }; MAX_UNIT_DATASETS];
        for (slot, binding) in pinned.iter_mut().zip(&self.datasets) {
            *slot = Some(binding.handle.pin());
        }
        Some(pinned)
    }

    fn evaluate_fueled<const COUNT: bool, const ATTR: bool>(
        &self,
        ctx: &RouteContext<'_>,
        hits: Option<&PolicyHitCounters>,
        fuel: &mut u64,
    ) -> (PolicyResult, PolicyEvaluation) {
        // LAN-305: pin dataset generations ONCE for the whole walk.
        let pinned_frame = self.pin_datasets();
        let pinned = pinned_frame.as_ref().unwrap_or(&NO_DATASETS);
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
            match self.evaluate_policy::<COUNT>(policy, ctx, policy_hits, fuel, pinned) {
                PolicyDecision::Deny => {
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: if ATTR { policy.name.clone() } else { None },
                            eval_error: None,
                        },
                    );
                }
                // The LAN-299 eval-error rail (ADR-0103 Decision 4):
                // uniform Deny, staged modifications discarded (the
                // accumulator drops here), operator-visible counter +
                // rate-limited WARN naming the failing policy/term.
                PolicyDecision::Error { kind, term_index } => {
                    // A failing Bind names its binding — for
                    // call-inlined binds (LAN-304) the qualified
                    // `fn.binding` name, so the WARN names both the
                    // function and the calling term. Error path only;
                    // the hot path never allocates here.
                    let term = policy.terms.get(term_index);
                    let term_label = term.map(|term| {
                        let name = term.name.as_deref().unwrap_or("<unnamed>");
                        match &term.action {
                            TermAction::Bind { name: bind, .. } => format!("{name} (let {bind})"),
                            _ => name.to_string(),
                        }
                    });
                    warn_eval_error(policy.name.as_deref(), term_label.as_deref(), kind);
                    let error = EvalError {
                        kind,
                        policy: policy.name.clone(),
                        term: term_label,
                    };
                    if COUNT && let Some(hits) = hits {
                        hits.record_eval_error(&error);
                    }
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: if ATTR { policy.name.clone() } else { None },
                            eval_error: Some(error),
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
                eval_error: None,
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
    #[expect(
        clippy::too_many_lines,
        reason = "one walk mirroring the live evaluator's term loop; splitting would decouple them"
    )]
    pub fn evaluate_recording_hits(
        &self,
        ctx: &RouteContext<'_>,
        hits: &mut [Vec<u64>],
    ) -> PolicyResult {
        assert_eq!(hits.len(), self.policies.len(), "hits shaped like chain");
        // LAN-303: dry runs are metered identically to the live walk.
        let mut fuel: u64 = MAX_EVAL_COST;
        // LAN-305: and pin dataset generations once, identically.
        let pinned_frame = self.pin_datasets();
        let pinned = pinned_frame.as_ref().unwrap_or(&NO_DATASETS);
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
                let matched = self.eval_expr(
                    &term.guard,
                    ctx,
                    locals_slice(locals.as_ref()),
                    pinned,
                    &mut err,
                );
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
                        // Deny denies; stray loop control (confined
                        // to loop bodies by the typechecker) fails
                        // closed like the live walk — same disposition.
                        TermAction::Deny | TermAction::Break | TermAction::ContinueLoop => {
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
                        // LAN-303: loops run identically to the live
                        // walk (same eval_for_each), errors fail
                        // closed. Body terms are outside the counter
                        // grid — the loop's own term counted above.
                        TermAction::ForEach(node) => {
                            let Ok(outcome) = self.eval_for_each(
                                node,
                                ctx,
                                &mut locals,
                                &mut continued,
                                &mut fuel,
                                pinned,
                            ) else {
                                denied = true;
                                break;
                            };
                            match outcome.flow {
                                LoopFlow::Completed => {}
                                LoopFlow::Permit(mods) => {
                                    permit_mods = Some(Some(mods));
                                    break;
                                }
                                LoopFlow::Deny => {
                                    denied = true;
                                    break;
                                }
                            }
                        }
                        TermAction::CommunityVar { add, slot, .. } => {
                            if exec_community_var(*add, *slot, locals.as_ref(), &mut continued)
                                .is_err()
                            {
                                denied = true;
                                break;
                            }
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
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per term action; splitting would scatter the walk semantics"
    )]
    fn evaluate_policy<'a, const COUNT: bool>(
        &self,
        policy: &'a CompiledPolicy,
        ctx: &RouteContext<'_>,
        hits: Option<&[AtomicU64]>,
        fuel: &mut u64,
        pinned: &PinnedDatasets,
    ) -> PolicyDecision<'a> {
        let mut continued: Option<RouteModifications> = None;
        // LAN-302: the `let`-binding register file, materialized (one
        // stack zeroing, no heap) only when the walk reaches a Bind
        // term — binding-free policies never touch it.
        let mut locals: Option<LocalFrame> = None;
        for (term_index, term) in policy.terms.iter().enumerate() {
            let mut err = None;
            let matched = self.eval_expr(
                &term.guard,
                ctx,
                locals_slice(locals.as_ref()),
                pinned,
                &mut err,
            );
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
                    // LAN-303: a bounded loop. A body verdict decides
                    // the policy; otherwise the walk continues after
                    // it. Any error (fuel, iteration cap, body
                    // evaluation) is terminal on the uniform rail,
                    // attributed to the loop's term.
                    TermAction::ForEach(node) => {
                        match self.eval_for_each(
                            node,
                            ctx,
                            &mut locals,
                            &mut continued,
                            fuel,
                            pinned,
                        ) {
                            Ok(outcome) => match outcome.flow {
                                LoopFlow::Completed => {}
                                LoopFlow::Permit(mods) => {
                                    return match continued {
                                        Some(mut acc) => {
                                            acc.merge_from(mods);
                                            PolicyDecision::PermitOwned(acc)
                                        }
                                        None => PolicyDecision::PermitOwned(mods),
                                    };
                                }
                                LoopFlow::Deny => return PolicyDecision::Deny,
                            },
                            Err((kind, _)) => return PolicyDecision::Error { kind, term_index },
                        }
                    }
                    // Loop control at policy level is confined to loop
                    // bodies by the typechecker; fail closed on the
                    // compiler-bug rail rather than misinterpret it.
                    TermAction::Break | TermAction::ContinueLoop => {
                        return PolicyDecision::Error {
                            kind: EvalErrorKind::StrayLoopControl,
                            term_index,
                        };
                    }
                    // LAN-303: stage the binding's value as a standard
                    // community add/remove; accumulates like Continue.
                    TermAction::CommunityVar { add, slot, .. } => {
                        if let Err(kind) =
                            exec_community_var(*add, *slot, locals.as_ref(), &mut continued)
                        {
                            return PolicyDecision::Error { kind, term_index };
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

    /// Evaluate one compiled `for` loop (LAN-303): bind each source
    /// element into the loop variable's frame slot and walk the body
    /// terms per iteration, with the enclosing policy's `continued`
    /// accumulator and `let` frame — a body verdict decides the whole
    /// policy, staged body modifications accumulate policy-locally,
    /// `break`/`continue` are loop-local control.
    ///
    /// Metering (ADR-0103 Decision 3): every iteration decrements
    /// `fuel` by exactly one (the back-edge charge — body straight-line
    /// cost is pre-paid by the compile-time DP) and counts against the
    /// hard per-loop cap [`MAX_LOOP_ITERATIONS`]; exhausting either
    /// fails closed. The iterated collection is the arrived route
    /// (staged modifications are never read back — Decision 2), so a
    /// body `add community` cannot extend its own iteration source.
    ///
    /// `Err` carries the iteration index at which evaluation failed,
    /// for explain rendering; the live walk uses only the kind.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per body term action; splitting would scatter the loop semantics"
    )]
    pub(crate) fn eval_for_each(
        &self,
        node: &ForEachNode,
        ctx: &RouteContext<'_>,
        locals: &mut Option<LocalFrame>,
        continued: &mut Option<RouteModifications>,
        fuel: &mut u64,
        pinned: &PinnedDatasets,
    ) -> Result<LoopOutcome, (EvalErrorKind, u32)> {
        let elements: ElementIter<'_> = match node.source {
            LoopSource::Communities => ElementIter::Slice(ctx.communities.iter()),
            LoopSource::AsPath => match ctx.as_path {
                // Wire order, prepend duplicates and AS_SET members
                // included (`AsPath::asns`); an absent path iterates
                // zero times, like an empty one.
                Some(path) => ElementIter::Path(Box::new(path.asns())),
                None => ElementIter::Slice([].iter()),
            },
            LoopSource::AsnSet(id) => {
                // Canonical (sorted, deduplicated) member order — the
                // interned representation — so iteration order is
                // deterministic across compiles and insertion orders.
                ElementIter::Slice(self.asn_sets[id.0 as usize].asns().iter())
            }
        };
        let mut iterations: u32 = 0;
        for element in elements {
            // Cap-then-error: the 4097th element is an evaluation
            // error, never a silent truncation (fail closed).
            if iterations == MAX_LOOP_ITERATIONS {
                return Err((EvalErrorKind::LoopLimitExceeded, iterations));
            }
            // The back-edge fuel charge: exactly one per iteration.
            *fuel = fuel
                .checked_sub(1)
                .ok_or((EvalErrorKind::FuelExhausted, iterations))?;
            iterations += 1;
            // The loop variable is a fresh immutable binding per
            // iteration (the LAN-302 slot model).
            locals.get_or_insert([0; LOCAL_FRAME_SLOTS])[usize::from(node.slot)] = element;
            let mut continue_iter = false;
            for term in &node.body {
                let mut err = None;
                let matched = self.eval_expr(
                    &term.guard,
                    ctx,
                    locals_slice(locals.as_ref()),
                    pinned,
                    &mut err,
                );
                if let Some(kind) = err {
                    return Err((kind, iterations - 1));
                }
                if !matched {
                    continue;
                }
                match &term.action {
                    TermAction::Permit(mods) => {
                        let resolved = self
                            .resolve_computed(mods, ctx, locals_slice(locals.as_ref()))
                            .map_err(|kind| (kind, iterations - 1))?;
                        return Ok(LoopOutcome {
                            iterations,
                            decided_at: Some(iterations - 1),
                            flow: LoopFlow::Permit(resolved.unwrap_or_else(|| mods.clone())),
                        });
                    }
                    TermAction::Deny => {
                        return Ok(LoopOutcome {
                            iterations,
                            decided_at: Some(iterations - 1),
                            flow: LoopFlow::Deny,
                        });
                    }
                    TermAction::Continue(mods) => {
                        let resolved = self
                            .resolve_computed(mods, ctx, locals_slice(locals.as_ref()))
                            .map_err(|kind| (kind, iterations - 1))?;
                        continued
                            .get_or_insert_with(RouteModifications::default)
                            .merge_from(resolved.unwrap_or_else(|| mods.clone()));
                    }
                    TermAction::Bind { slot, expr, .. } => {
                        let value = eval_value(expr, ctx, locals_slice(locals.as_ref()))
                            .map_err(|kind| (kind, iterations - 1))?;
                        locals.get_or_insert([0; LOCAL_FRAME_SLOTS])[usize::from(*slot)] = value;
                    }
                    TermAction::CommunityVar { add, slot, .. } => {
                        exec_community_var(*add, *slot, locals.as_ref(), continued)
                            .map_err(|kind| (kind, iterations - 1))?;
                    }
                    // `break` exits the innermost loop: the enclosing
                    // walk continues after it.
                    TermAction::Break => {
                        return Ok(LoopOutcome {
                            iterations,
                            decided_at: None,
                            flow: LoopFlow::Completed,
                        });
                    }
                    // `continue` skips the rest of this iteration.
                    TermAction::ContinueLoop => {
                        continue_iter = true;
                    }
                    // Nested loop: verdicts and errors propagate; a
                    // completed (or broken) inner loop resumes this
                    // body.
                    TermAction::ForEach(inner) => {
                        let outcome = self
                            .eval_for_each(inner, ctx, locals, continued, fuel, pinned)
                            .map_err(|(kind, _)| (kind, iterations - 1))?;
                        match outcome.flow {
                            LoopFlow::Completed => {}
                            flow @ (LoopFlow::Permit(_) | LoopFlow::Deny) => {
                                return Ok(LoopOutcome {
                                    iterations,
                                    decided_at: Some(iterations - 1),
                                    flow,
                                });
                            }
                        }
                    }
                }
                if continue_iter {
                    break;
                }
            }
        }
        Ok(LoopOutcome {
            iterations,
            decided_at: None,
            flow: LoopFlow::Completed,
        })
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
    /// frame here, so guard evaluation stays shared. `pinned` is the
    /// caller's dataset pin frame (LAN-305): explain pins once per
    /// trace walk — [`pin_datasets`](Self::pin_datasets) — so its
    /// probes see one generation, exactly like the live walk.
    pub(crate) fn guard_matches(
        &self,
        expr: &MatchExpr,
        ctx: &RouteContext<'_>,
        locals: &[u32],
        pinned: &PinnedDatasets,
    ) -> Result<bool, EvalErrorKind> {
        let mut err = None;
        let matched = self.eval_expr(expr, ctx, locals, pinned, &mut err);
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
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per MatchExpr node; splitting would scatter the evaluation table"
    )]
    fn eval_expr(
        &self,
        expr: &MatchExpr,
        ctx: &RouteContext<'_>,
        locals: &[u32],
        pinned: &PinnedDatasets,
        err: &mut Option<EvalErrorKind>,
    ) -> bool {
        match expr {
            MatchExpr::True => true,
            MatchExpr::And(children) => children
                .iter()
                .all(|child| self.eval_expr(child, ctx, locals, pinned, err)),
            MatchExpr::Or(children) => children
                .iter()
                .any(|child| self.eval_expr(child, ctx, locals, pinned, err)),
            MatchExpr::Not(inner) => !self.eval_expr(inner, ctx, locals, pinned, err),
            // LAN-305: probe the snapshot pinned at walk start — the
            // same indexed structures as the `*InSet` nodes, at the
            // same cost. An unpinned slot or kind mismatch is the
            // fail-closed compiler-bug rail.
            MatchExpr::InDataset { probe, id } => {
                let Some(snapshot) = pinned.get(id.0 as usize).and_then(Option::as_ref) else {
                    err.get_or_insert(EvalErrorKind::DatasetUnpinned);
                    return false;
                };
                match (probe, &snapshot.data) {
                    (DatasetProbe::Prefix, DatasetData::Prefix(set)) => {
                        ctx.prefix.is_some_and(|candidate| set.matches(candidate))
                    }
                    (DatasetProbe::OriginAs, DatasetData::Asn(set)) => {
                        ctx.origin_asn.is_some_and(|origin| set.contains(origin))
                    }
                    (DatasetProbe::PeerAs, DatasetData::Asn(set)) => {
                        ctx.peer_asn.is_some_and(|asn| set.contains(asn))
                    }
                    (DatasetProbe::Community, DatasetData::Community(set)) => set.matches(ctx),
                    (DatasetProbe::LocalAsn { slot, .. }, DatasetData::Asn(set)) => {
                        if let Some(value) = locals.get(usize::from(*slot)) {
                            set.contains(*value)
                        } else {
                            err.get_or_insert(EvalErrorKind::UnboundLocal);
                            false
                        }
                    }
                    (DatasetProbe::LocalCommunity { slot, .. }, DatasetData::Community(set)) => {
                        if let Some(value) = locals.get(usize::from(*slot)) {
                            set.contains_standard(*value)
                        } else {
                            err.get_or_insert(EvalErrorKind::UnboundLocal);
                            false
                        }
                    }
                    (DatasetProbe::ConstAsn(value), DatasetData::Asn(set)) => set.contains(*value),
                    (DatasetProbe::ConstCommunity(value), DatasetData::Community(set)) => {
                        set.contains_standard(*value)
                    }
                    // Kind mismatch: unreachable through the compiler
                    // (typecheck pins probe/kind agreement); fail
                    // closed rather than misread the data.
                    _ => {
                        err.get_or_insert(EvalErrorKind::DatasetUnpinned);
                        false
                    }
                }
            }
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
            // LAN-303: one frame load + one hash probe. A missing
            // frame is the fail-closed compiler-bug rail, like every
            // `Local` read.
            MatchExpr::LocalInAsnSet { slot, set, .. } => {
                if let Some(value) = locals.get(usize::from(*slot)) {
                    self.asn_sets[set.0 as usize].contains(*value)
                } else {
                    err.get_or_insert(EvalErrorKind::UnboundLocal);
                    false
                }
            }
            // LAN-303: probe the community set's standard partition by
            // raw u32 value (large/ext members are not u32-comparable
            // and never match a binding).
            MatchExpr::LocalInCommunitySet { slot, set, .. } => {
                if let Some(value) = locals.get(usize::from(*slot)) {
                    self.community_sets[set.0 as usize].contains_standard(*value)
                } else {
                    err.get_or_insert(EvalErrorKind::UnboundLocal);
                    false
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
            as_path: None,
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

    /// LAN-303: loop control reaching the policy-level walk is a
    /// compiler bug — it must fail closed on the eval-error rail, not
    /// be misread as a verdict or skipped.
    #[test]
    fn stray_loop_control_fails_closed() {
        for action in [TermAction::Break, TermAction::ContinueLoop] {
            let chain = CompiledChain {
                policies: vec![CompiledPolicy {
                    name: None,
                    terms: vec![
                        Term {
                            name: None,
                            guard: MatchExpr::True,
                            action: action.clone(),
                        },
                        Term {
                            name: None,
                            guard: MatchExpr::True,
                            action: TermAction::Permit(RouteModifications::default()),
                        },
                    ],
                    default_action: PolicyAction::Permit,
                    source: PolicySource::Rpol,
                }],
                ..CompiledChain::empty()
            };
            let (result, _) = chain.evaluate_with_attribution(&ctx(None));
            assert_eq!(result.action, PolicyAction::Deny, "{action:?}");
        }
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
