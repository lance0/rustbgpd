# ADR-0103: rpol execution model, purity contract, and evaluation budgets

**Status:** Accepted
**Date:** 2026-07-09

**Scope:** the gating decisions for every deep rpol extension — typed
arithmetic, lexical bindings and route-local mutation, bounded loops
and collection iteration, pure user functions, modules and imports, a
metered runtime, and external datasets with a possible
host-function/WASM escape hatch. None of those slices start until this
ADR's contracts are accepted; each slice cites the decision it
implements.

## Context

ADR-0096 shipped the `.rpol` language on a deliberately small core: a
typed, public, analyzable IR (`crates/policy/src/ir.rs`) evaluated by a
monomorphized tree-walk (`crates/policy/src/eval.rs`,
`evaluate_attributed::<COUNT, ATTR>`), with match *data* compiled out
into `Arc`-shared indexed sets (`crates/policy/src/sets.rs`). V1 has no
arithmetic, no locals, no loops, no functions, no modules — and four
consumers now depend on the IR being exactly what it is:

1. **The live-impact planner** diffs resolved `PolicyChain`s
   structurally (`compute_effective_neighbor_impact`,
   `src/config/mod.rs`); rpol members diff by compiled `CompiledChain`
   content — term names, guard trees, set tables, and set source-names
   all participate in equality (`crates/policy/src/ir.rs`).
2. **Explain** renders per-term traces from IR term names and shares
   guard evaluation with the live matcher
   (`CompiledChain::guard_matches`), so explain and evaluation cannot
   disagree.
3. **Per-term hit counters** (`PolicyHitCounters`) are shaped
   positionally from the chain — `hits[policy][term]` — and reset on
   chain replacement by construction.
4. **The `requires_*` hot-path gates** are structural IR analyses
   (AS-path string build, RPKI/ASPA refresh scoping, update-group
   peer-context disqualification).

Every planned extension threatens at least one of these consumers, and
several threaten the daemon itself. A prior hands-on evaluation of an
external policy runtime (recorded in ADR-0096) found exactly the
failure classes this ADR's contracts exist to exclude: compiled
division-by-zero delivering SIGFPE to the process, unbounded loops
hanging the evaluation thread with no fuel mechanism, and a private IR
that answered none of the four consumers above. Those are not
hypothetical threats — they killed the probe process. The budgets and
purity contract below are the measures that keep operator-authored
programs incapable of reproducing them in-process.

Existing bounds this ADR builds on (and must not contradict):

- `MAX_EXPR_DEPTH = 128` — parse-time expression nesting
  (`crates/policy/src/rpol/parser.rs`).
- `MAX_APPLY_DEPTH = 8` and `MAX_APPLY_EXPANSION = 100_000` — apply-DAG
  composition depth and inlined-node budget, enforced by a Kahn-ordered
  cost DP in `crates/policy/src/rpol/typeck.rs` *before lowering runs*;
  lowering and the evaluator are unguarded by design and rely on the
  typecheck invariant.
- Evaluation is already transactional per route: the evaluator returns
  `RouteModifications` as data; callers apply modifications only after
  a complete, successful walk. Nothing mid-walk mutates the route.

## Decision 1 — Extend the typed tree-walk IR; bytecode stays deferred

The execution model for arithmetic, bindings, loops, functions, and
modules is **the existing tree-walk over an extended typed IR**. A
compact bytecode runtime is not built now; it remains a deferred,
measured upgrade behind an explicit re-entry gate. This is a first-class outcome, not a
compromise: the benchmark below shows dispatch is not where policy
evaluation cost lives, and the tree-walk IR is the representation three
of the four consumers diff, render, and analyze directly.

### Benchmark receipt

Two spikes, same machine, one x86-64 core, release builds. Absolute
nanoseconds are machine-specific; the **ratios** are the durable
signal.

**Spike A — the shipped evaluator** (`cargo bench -p rustbgpd-policy
--bench policy_eval`, criterion means):

| Shape | ns/route |
|---|---|
| 1-statement chain | 28 |
| 32-statement walk-everything chain | 332 (~9.8 ns marginal/statement) |
| 32-statement chain, first-statement deny | 29 |
| AS-path regex evaluated / short-circuit skipped | 67 / 19 |
| Community scan evaluated / skipped | 23 / 19 |
| 1,000-prefix list as 1,000 IR terms | 2,488 |
| Same list as one indexed set probe | 19.5 |

**Spike B — fuel-metered stack machine**
(`docs/adr/0103-rpol-execution-model-spike/`; raw outputs of every run
and exact reproduction commands in its README): the same 15-term,
mixed match/no-match program — prefix-set probe, community scans,
scalar compares, checked arithmetic — lowered once to a guard tree and
once to a 50-op jump-threaded bytecode; 1M-route mixed stream;
best-of-5 timing, three process runs. Two hard assertions guard the
numbers: verdict tallies must be identical across all three
evaluators, and the fuel actually consumed must equal an independently
computed op-count oracle (24,557,144 ops for this workload) — the fuel
decrement is provably live, not optimized away.

| Evaluator | ns/route (best-of-5, per run) | vs tree-walk |
|---|---|---|
| Tree-walk (models the shipped IR) | 57–62 | 1.0× |
| Bytecode dispatch loop | 47–53 | 0.75–0.94× |
| Bytecode + per-instruction fuel decrement | 52–56 | 0.84–0.99× (+0–20% over bare bytecode) |

Two findings decide the question:

1. **Bytecode is a modest constant factor, not a step change.**
   0.75–0.94× across runs — at best ~25% on a deliberately
   dispatch-heavy synthetic, consistent with the 10–40% BIRD reported
   from linearization in the ADR-0096 survey. Evaluation cost lives in
   the match-data probes (set lookups, community scans, regex — Spike
   A's 128× set-index ratio), and no constant factor of that size
   justifies surrendering the analyzable tree that the four IR
   consumers diff, render, and analyze directly.
2. **Metering is affordable even at its worst case.** With the counter
   provably live, a decrement-and-branch on *every instruction* costs
   0–20% over bare bytecode run-to-run — and the fueled bytecode still
   evaluates at or below the tree-walk's cost (0.84–0.99×). The
   shipped design charges fuel only at loop back-edges and iteration
   steps (Decision 3), a strict subset of per-instruction metering, so
   this is an upper bound and V1-shaped programs pay zero. Metering
   therefore does not need bytecode to be cheap; **the fuel/step
   budget lands on the tree-walk**, and the metered-runtime slice is
   re-scoped accordingly (see the implementation plan).

**Bytecode re-entry gate:** build the compact bytecode tier only when a
profile of a real workload shows chain-walk dispatch (not set probes)
as a dominant manager-CPU term — the known candidate is the
fully-walked long-chain shape that regressed +27% in the IR cutover.
If the gate ever fires, bytecode is a **lowering below the IR**: the
typed IR remains the sole public surface for diffing, explain,
counters, and the `requires_*` analyses, and the bytecode program is a
derived, cache-like artifact regenerated from it. No consumer may ever
observe bytecode.

### Re-measurement addendum — 2026-07-10, post-metered-runtime slice

The Decision 1 benches re-run against the completed evaluator — every
program slice landed since the original receipt (arithmetic, bindings,
loops, functions, modules, datasets, fuel at back-edges, per-walk
dataset pinning). Same bench targets plus the bounded-loop shape and a
new fn-heavy arm (`cargo bench -p rustbgpd-policy --bench
policy_eval`). Conditions: 64-core x86-64 box, otherwise quiet (load
average < 2, no concurrent workspace builds), `--noplot`, three full
process runs, medians of criterion point estimates. Absolute
nanoseconds are not comparable to the Spike A table (different
machine); the ratios are the signal.

| Shape | ns/route (median of 3) |
|---|---|
| 1-statement chain | 39 |
| 32-statement walk-everything chain | 385 (~11.2 ns marginal/statement) |
| 32-statement chain, first-statement deny | 37 |
| AS-path regex evaluated / short-circuit skipped | 69 / 20 |
| Community scan evaluated / skipped | 29 / 20 |
| 1,000-prefix list as IR terms / as one indexed set probe | 4,409 / 28 (**156×**) |
| Constant actions / arithmetic actions | 44 / 80 |
| Community scrub: set probe / per-element fueled loop | 28 / 73 (~4.5 ns per element incl. fuel) |
| Damping via `fn` (3 call sites) / hand-inlined `let`s | 152 / 105 (~15 ns/call — argument-bind slot writes, no frames) |
| 50k-ASN set probe / dataset probe with per-walk pin | 20–25 / 28–34 |

**Gate verdict: the re-entry condition does not fire.** Chain-walk
dispatch is still a ~11 ns/statement marginal term, and match data
expressed the idiomatic way (indexed sets/datasets) still beats the
walked form by two orders of magnitude — the set-index ratio *grew*
(128× → 156×) as the walk gained the extended-IR machinery. Every
cost the new constructs added prices as expression evaluation
(checked-arithmetic ops, per-element fuel + slot writes, per-call
argument binds), not as dispatch — exactly the term bytecode cannot
help, per Spike B's 0.75–0.94×. No profile shows the fully-walked
long-chain shape dominating manager CPU. The compact bytecode tier
stays unbuilt; the gate stays open on the same trigger (a real-
workload profile with chain-walk dispatch as a dominant manager-CPU
term).

## Decision 2 — Value/type model and source-compatible grammar evolution

### Value model

- **`u32` remains the only arithmetic type.** Policy parameters are
  `u32` today, and every numeric attribute the language touches
  (`local-pref`, `med`, ASN, path length) is `u32`-shaped. Arithmetic
  (`+ - * / %`) is **checked**: overflow, underflow, and
  division/modulo by zero are *evaluation errors* (Decision 4), never
  traps — the SIGFPE class is unrepresentable. No floats, no signed
  integers, no bigints.
- First-class values (bindable by `let`): `u32`, `bool`,
  IP address, prefix, the three community kinds, the RPKI/ASPA/
  route-type enums, strings (literals only — no string operations),
  and **immutable collection views** (e.g. `route.communities`) which
  can be iterated and probed but not constructed, stored, or
  returned.
- **All values are immutable.** There is no assignment to a binding
  and no mutable collection. Route-local "mutation" is
  exactly today's model: `set`/`add`/`remove`/`prepend` **stage** into
  `RouteModifications`, which callers apply only after a successful
  complete walk. Reads during evaluation see the route as it arrived
  (staged writes are not read back); this keeps evaluation a pure
  function and keeps the transactional-per-route property for free.
  If read-back semantics are ever demanded, they are a separate ADR —
  they break memoization (`ExportMemo` memoizes on source-attr
  identity + modifications) and are excluded here.
- User functions are **pure, terminating, non-recursive**
  expressions over these values: no side effects, call graph is a DAG
  (the apply precedent), fully inlined at compile time. They are *not*
  total — checked arithmetic inside a function body can raise an
  evaluation error, which propagates per Decision 4.

### Grammar evolution rules (binding for every slice)

Existing `.rpol` programs must keep parsing and keep meaning the same
thing, forever. Concretely:

1. **Kebab-case maximal munch is permanent.** `a-b` is one identifier
   today because the language has no arithmetic; it stays one
   identifier. Subtraction **requires whitespace**: `a - b`. The lexer
   identifier rule does not change; `-` becomes a token only where the
   identifier munch cannot consume it. This is the price of arithmetic
   in a kebab-case language, and it is paid by the new feature, not by
   existing programs.
2. **No new reserved words.** Every new construct is introduced via
   contextual keywords in positions that are unoccupied in today's
   grammar: statement-initial `let` and `for` (statements today begin
   only with `if`/`set`/`add`/`remove`/`prepend`/`accept`/`reject`),
   top-level `fn` and `import` (top level today begins only with
   `prefix-set`/`community-set`/`policy`/`test`). A set named `let` or
   a policy named `fn` keeps working.
3. **New operator tokens must be un-lexable today.** `+ * / % < > =`
   appear in no currently-valid program (`>=`/`<=`/`==`/`!=` are
   already distinct tokens); adding them is purely additive. Any
   proposed token that could re-lex an existing literal form
   (community/prefix/IPv6 literals own `:`, `.`, `/` inside maximal
   munch) is rejected at design time.
4. **Compiled-form compatibility is a regression gate.** Each grammar
   slice carries a golden test: every `.rpol` fixture in the tree
   compiles to a `CompiledChain` equal to the pre-slice compilation.
   This is the same equality the live-impact planner uses, so the gate
   also proves reloads stay no-ops across an upgrade (Decision 5).

### IR stability

New IR nodes (arithmetic expressions, let-frames, loop nodes before
inlining) are **additive** variants on the existing public enums. No
existing variant changes shape or meaning; the four consumers' matches
stay exhaustive and get extended per-slice with the analyses each new
node requires (e.g. a loop over `route.communities` sets no
`requires_*` flag; a guard reading `peer.*` inside a function still
counts toward `requires_peer_context` after inlining).

## Decision 3 — Budgets

One principle: **every budget that can be enforced at compile time is
enforced at compile time**, by extending the existing Kahn-ordered cost
DP in `typeck.rs` — functions and loops join the apply DAG in the same
pass, so there is one place that answers "how big can this program get
and how long can it run". Runtime checks exist only where compile-time
bounds are data-dependent (collection iteration), and exceeding a
runtime budget is an evaluation error (Decision 4).

### Compile-time budgets

| Budget | Limit | Status |
|---|---|---|
| `.rpol` source size per file | 1 MiB | new (load-time reject) |
| Expression nesting (`MAX_EXPR_DEPTH`) | 128 | existing, parser |
| `apply` composition depth (`MAX_APPLY_DEPTH`) | 8 | existing, typeck |
| Function call-graph depth (`MAX_CALL_DEPTH`) | 8 | new — same DP, same rationale: inlining doubles per level |
| Module import depth (`MAX_MODULE_DEPTH`) | 8 | new — import graph is a DAG, cycles are compile errors |
| Inline expansion per policy (`MAX_APPLY_EXPANSION`) | 100,000 IR nodes | existing, extended: function inlining and unrolled/lowered loop bodies count against the same budget |
| Compiled chain total (`MAX_CHAIN_NODES`) | 1,000,000 IR nodes | new — sum across a chain's policies |
| Static loop iteration bound (`MAX_LOOP_ITERATIONS`) | 4,096 per loop | new — integer-range loops must have compile-time-known bounds; nesting multiplies in the cost DP |
| Locals per scope (`MAX_LOCALS`) | 64 | new |
| Worst-case evaluation cost (`MAX_EVAL_COST`) | 1,000,000 steps | new — the DP's per-route worst-case step count; programs whose bound exceeds it are rejected with a diagnostic naming the hot composition |

### Runtime budgets (per route evaluation)

| Budget | Limit | Mechanism |
|---|---|---|
| Instruction fuel | `MAX_EVAL_COST` (not operator-tunable) | Decremented at loop back-edges and collection-iteration steps only — straight-line guard code is pre-paid by the compile-time bound, so the V1 hot path (no loops) pays exactly zero, preserving today's cost. Exhaustion = evaluation error. Per ADR-0096: because the compile-time DP already bounds worst-case cost below `MAX_EVAL_COST` for static loops, runtime exhaustion is reachable only through data-dependent iteration and indicates either pathological input or a compiler bug — both fail closed. |
| Collection iteration | bounded by the collection (route attribute lists are wire-bounded; set snapshots are load-bounded) | counts against fuel per element |
| Value stack / locals frame | static slot count from compile time, ≤ 1,024 slots | preallocated per evaluation; no runtime growth |
| Evaluation scratch allocation | 64 KiB arena per route | Values built during evaluation (staged community lists, loop temporaries) draw from a per-evaluation scratch; exceeding = evaluation error. Guard-only paths allocate nothing, as today. |
| Call depth | none needed | functions are fully inlined; there are no runtime call frames (revisit only if the bytecode gate fires) |

## Decision 4 — Failure semantics: fail closed, transactionally

Any runtime evaluation error — checked-arithmetic error, fuel
exhaustion, scratch-arena exhaustion — resolves the route as **Deny**:

- **Import:** the route is rejected (not installed, treated as
  filtered).
- **Export:** the route is not advertised to that peer/group.
- **No partial modifications, ever.** This is already structural:
  modifications are staged data applied only after a complete
  successful walk. An error mid-walk discards the staged
  `RouteModifications`; the route and RIB are untouched.
- **Operator visibility:** a `bgp_policy_eval_errors_total{chain,
  reason}` counter increments; the explain surfaces render the error
  (term, source span, reason) in place of a verdict trace; a
  rate-limited log line names the policy and term. Silent fail-closed
  is not acceptable — an operator must be able to see *that* and *why*
  a policy is erroring from `rbgp` alone.

This **supersedes the ADR-0096 Decision 2 sketch** ("the route takes
the chain's default action"): a default-permit chain would fail *open*
on an arithmetic error, which is the wrong direction for a BGP daemon.
Deny is the uniform error disposition regardless of chain defaults.

`rbgp policy check` / in-language `test` blocks evaluate with the same
semantics, so an erroring policy is catchable in CI: a test whose
evaluation errors fails the test with the error rendered.

## Decision 5 — Structural diffing and live-impact planning survive lowering

The live-impact planner's diff primitive is `CompiledChain` equality;
these rules keep it meaningful as lowering gets more aggressive:

1. **Lowering is deterministic.** Identical source (and arguments)
   must produce structurally equal `CompiledChain`s: stable term
   ordering, stable And-child cost-sort, deterministic set/regex
   interning order, and — new with inlining and modules — deterministic
   function-inlining and module-resolution order. No iteration over
   unordered maps may influence emitted IR. (Violation cost: every
   SIGHUP reload of an unchanged file diffs as "moved" and triggers a
   spurious Route Refresh on every referencing peer.)
2. **Top-level term identity is preserved.** The existing multi-term
   split naming (`<term>.<n>`) is the pattern: lowering may split a
   source term into several IR terms with derived names, but the
   mapping is a pure function of the source. Function inlining
   follows the apply precedent: the inlined body becomes
   guard/action content *inside* the calling term — it never
   introduces, removes, or renames top-level terms.
3. **Data diffs as data.** External dataset snapshots, like
   set tables today, live outside the expression tree and diff
   independently: a dataset content change refreshes exactly the peers
   whose chains reference it, without the program diffing as changed.
   Module boundaries dissolve at compile time — the resolved
   chain is the identity; moving a definition between modules without
   changing the resolved content is a no-op diff (the same rule as
   `RpolPolicySet` excluding file paths from equality).
4. **Both sides of every diff come from the same resolver** — the
   existing `effective_policy_chains_for_neighbor` discipline extends
   to module resolution and dataset binding: the planner and the
   refresh path must share one resolution function.

## Decision 6 — Explain traces and per-term counters after lowering

Counters key positionally (`hits[policy][term]`); traces key on term
names. The contract:

1. **The term grid is a function of the source, not the optimizer.**
   Locals, arithmetic, and loops lower *within* a term; functions
   inline *within* the calling term. The set of IR terms — and hence
   the counter shape and the trace skeleton — changes only when the
   operator edits terms.
2. **Determinism of traces.** Explain shares guard evaluation with the
   live matcher (`guard_matches`) — that discipline extends to every
   new node: one evaluation function, explain walks it. Loop and
   function nodes render in traces as their source form (the guard
   pretty-printer renders `.rpol` syntax back, not lowered soup), with
   the source span carried through lowering.
3. **Known-and-accepted collapse:** `apply` already erases the applied
   policy's internal term identity (it inlines a decision predicate);
   inlined *functions* likewise contribute no term identity of their
   own. Per-function hit counting is explicitly out of scope — it
   would require runtime call frames, which Decision 3 declined.
4. **Evaluation errors are trace events** (Decision 4): the trace ends
   with the erroring term, its span, and the reason, so the explain
   trilogy renders budget failures exactly like verdicts.

## Decision 7 — Purity contract

Policy evaluation is a **pure function** of `(RouteContext, compiled
chain, pinned external snapshots)`. During evaluation there is no:

- clock, monotonic or wall (no time-of-day policies — model them as
  external data snapshots swapped by the operator/automation);
- randomness;
- network, filesystem, or subprocess access;
- blocking or lock acquisition (the relaxed-atomic hit counters are
  observability, not semantics, and are wait-free);
- cross-route mutable state: nothing written while evaluating route A
  is observable while evaluating route B (this is what makes
  `ExportMemo` memoization, per-thread evaluation under ADR-0100
  parallelism, and the differential update-group oracle sound);
- host-function registration mechanism of any kind (Decision 9): the
  purity contract is enforced by construction — the IR has no
  effectful node kinds, so there is nothing for an audit to miss.

The compile stage is permitted I/O only through the config loader
(reading `.rpol` files and dataset snapshots at load/reload), never
during evaluation.

## Decision 8 — Hot-reload atomicity and generations

The existing machinery is the model; new features extend it without
adding a second mechanism:

1. **Compile all-or-nothing** (existing): any diagnostic in any file
   of the candidate registry rejects the whole reload; the running
   generation is untouched. Modules compile as one unit — a
   broken import anywhere rejects the unit.
2. **Ack-gated snapshot absorption** (existing): the reload
   adopts the candidate `RpolPolicySet` into its working config only
   after the peer manager acks the sync; a rejected candidate is never
   visible to new sessions.
3. **Two-phase per-peer apply with rollback** (existing):
   resolve every affected peer's chains *before mutating anything*;
   on mid-fan-out failure, restore captured priors — no split-brain.
   Chain replacement is a whole-value swap in the session's
   single-task loop; in-flight evaluations hold the old
   `Arc<CompiledChain>` and complete on it. Counters reset with the
   chain by construction.
4. **Commit-confirmed / boot-revert** (existing, ADR-0076): policy
   rides the whole-config journal; no policy-specific revert path is
   added.
5. **New — dataset snapshot generations:** each external
   dataset is an immutable `Arc` snapshot with a monotonically
   increasing generation, swapped atomically in a registry. Rules:
   - **Per-walk pinning:** an evaluation resolves each referenced
     snapshot once, at walk start; one route never observes two
     generations of the same dataset. (Distribution passes may pin per
     pass for memoization coherence.)
   - **Programs validate against shape, not content:** compilation
     checks a dataset reference's declared type/schema; content swaps
     never require recompilation. A swap that changes shape is a
     config transaction, not a snapshot update, and follows rules 1–3.
   - **Diff behavior:** a snapshot content swap refreshes exactly the
     peers whose chains reference that dataset (the `requires_*`
     analysis pattern: `requires_dataset(id)`), mirroring today's
     RPKI/ASPA cache-update scoping.
   - **Failure:** a dataset that fails to load/parse keeps the prior
     snapshot and raises a counter + log; there is no "empty on error"
     — an empty snapshot is a semantic statement an operator must make
     explicitly.

## Decision 9 — External data yes, external code no

The escape-hatch question gets the maximum-skepticism treatment
it asks for. **The recommendation is: external data snapshots without
external code.** No WASM tier, no host-function registry, no in-process
plugin surface in the policy hot path.

The threat analysis (below) ranks it first for a reason: an external
code hook in per-route evaluation is the single largest blast-radius
item in the entire program. Concretely:

- **Crash/hang blast radius:** the policy evaluator runs inside the
  session and distribution paths of a BGP daemon holding real
  adjacencies. The prior external-runtime evaluation demonstrated the
  full class in-process: a trapping instruction (SIGFPE) kills the
  daemon and every session it holds; an unbounded loop wedges a
  session task through its hold timer. A WASM sandbox contains memory,
  but fuel does not meter host imports, trap handling adds a
  nondeterministic failure surface, and JIT/runtime bugs become
  daemon CVEs.
- **Cost:** marshalling a `RouteContext` across a WASM boundary was
  bounded at 0.5–5 µs/route in the ADR-0096 survey — 25–250× the
  entire current evaluation, before the callee does anything.
- **Purity is unauditable across a code boundary:** Decision 7 is
  enforceable because the IR has no effectful nodes. A host-function
  surface reintroduces every banned effect as "whatever the module
  does", and the four IR consumers (diff, explain, counters,
  `requires_*`) all go blind at the call boundary — an opaque call is
  exactly the private-IR failure that disqualified the external
  runtime.
- **What actually satisfies the demand:** every concrete "escape
  hatch" use case surveyed reduces to *data the daemon doesn't have*
  (bogon feeds, IX participant lists, geo/customer tags, origin-AS
  sets) joined against route attributes. That is Decision 8.5:
  typed, snapshot-swapped, generation-pinned datasets, probed by the
  same indexed-set machinery that already runs at 19.5 ns. External
  *computation* belongs outside the process, producing snapshots on
  its own clock (the RTR/cache pattern, already proven in-tree for
  RPKI/ASPA).

**Re-entry condition:** a demonstrated operator need that cannot be
expressed as a dataset join plus in-language logic, plus a design that
keeps the call out of the per-route path (e.g. an offline/async
enrichment producing a dataset). "We want Lua/WASM per route" is not,
by itself, a need.

## Threat and failure analysis

Ranked by blast radius × likelihood:

1. **External code in the hot path (the dataset hatch).** Daemon crash,
   session-task hang past hold timers, unauditable effects, JIT/runtime
   CVE surface, 25–250× marshalling floor. *Disposition: rejected
   (Decision 9); datasets-without-code instead.*
2. **Fail-open on evaluation error.** A default-permit chain taking
   its default on arithmetic error silently accepts routes the policy
   meant to filter. *Disposition: uniform Deny (Decision 4),
   superseding the ADR-0096 sketch; counter + explain + log make it
   observable.*
3. **Compile-time resource bombs through composition.** apply ×
   functions × loops × modules compound multiplicatively; each is
   individually bounded but their product is the real attack. One
   shared Kahn cost DP bounds depth, expansion, and worst-case steps
   *before lowering allocates anything* (Decision 3) — the apply
   precedent generalized, not duplicated.
4. **Runtime nontermination / overrun.** Data-dependent iteration
   escaping static bounds. *Disposition: fuel at back-edges, scratch
   arena cap, fail closed; straight-line code pre-paid at compile
   time so the hot path is unchanged.*
5. **Diff-identity destruction.** Nondeterministic lowering or
   optimizer-dependent term renaming makes every reload look like a
   policy change → fleet-wide Route Refresh churn on no-op SIGHUPs;
   or, inverted, over-normalization makes real changes diff as equal →
   stale policy on live sessions. *Disposition: Decision 5 determinism
   + term-identity rules, gated by the golden compiled-form corpus.*
6. **Torn external-data reads.** One route evaluated against two
   generations of a dataset (or program compiled against shape N,
   evaluated against N+1). *Disposition: per-walk snapshot pinning +
   shape-changes-are-transactions (Decision 8.5).*
7. **Grammar drift breaking fielded programs.** A new keyword or
   re-lexed literal silently changing an existing program's meaning.
   *Disposition: Decision 2 rules (no reserved words, maximal-munch
   permanence, un-lexable-today operators) + compiled-form golden
   gate.*

## Implementation plan (ordered)

Each slice is independently shippable, lands its own tests, and cites
the decision it implements. Order is chosen so every slice rides rails
the previous one built.

1. **Typed arithmetic.** `u32` checked ops; whitespace-
   disambiguated `-` (Decision 2.1); the evaluation-error rails
   everything else reuses: error node semantics, uniform Deny,
   `bgp_policy_eval_errors_total`, explain/trace error rendering
   (Decision 4). Smallest language change, largest contract
   installation.
2. **Lexical bindings and route-local mutation.** Statement-
   initial contextual `let`; static slot allocation (`MAX_LOCALS`,
   frame budget); immutable values; mutation stays staged
   `RouteModifications` (Decision 2, "no read-back").
3. **Bounded loops and collection iteration.** Static
   iteration bounds in the cost DP; first runtime fuel (back-edge
   decrements) and the scratch arena (Decision 3); collection views
   over route attributes.
4. **Pure user functions.** Top-level contextual `fn`; call
   DAG with `MAX_CALL_DEPTH` in the same DP as apply; full inlining
   preserving term identity (Decisions 5.2, 6.1); `requires_*`
   analyses across inlined bodies.
5. **Modules and imports.** Import DAG, one namespace after
   resolution, compile-as-one-unit reload semantics (Decision 8.1);
   resolved-content chain identity so refactors diff as no-ops
   (Decision 5.3). No IR change.
6. **Metered runtime, re-scoped.** The metering itself lands
   in slices 3–4 on the tree-walk; this slice completes the
   operator surface (error counters/labels finalized, explain error
   traces, `rbgp policy stats` exposure, soak/fuzz coverage of budget
   exhaustion) and **re-runs the Decision 1 benchmark against the
   then-current IR**. The compact bytecode interpreter is built only
   if the re-entry gate fires, and then strictly below the IR.
7. **External datasets.** Snapshot registry with generations,
   per-walk pinning, `requires_dataset` scoping, typed dataset kinds
   (prefix/ASN/community tags first); **no host-function/WASM tier**
   (Decision 9).

## Consequences

- Existing `.rpol` programs and TOML chains are untouched at every
  slice boundary; the compiled-form golden gate makes that a CI fact
  rather than an intention.
- The V1 hot path keeps its exact cost profile: no fuel, no arena, no
  frames on programs that don't use the new features — the
  monomorphization discipline (`COUNT`/`ATTR` const generics) extends
  to the new machinery.
- The four IR consumers (diff, explain, counters, `requires_*`) remain
  correct by contract, not by luck; every slice's review checklist
  includes Decisions 5 and 6 explicitly.
- Saying no to external code narrows external datasets to a data-plumbing
  feature with a well-worn in-tree pattern, and pushes exotic
  computation to where it can crash without taking sessions down.
- The bytecode question is settled by receipt, not taste, and stays
  re-openable by receipt: the gate names the profile signal that would
  reverse it.
