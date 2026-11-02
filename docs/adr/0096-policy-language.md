# ADR-0096: A typed, compiled policy language

- **Status:** Accepted (2026-07-02)
- **Date:** 2026-07-02
- **Relates to:** ADR-0073 (import-policy explain), ADR-0076 (config
  transactions / live-impact executor), the policy crate

## Context

Policy today is the GoBGP/OpenConfig model transliterated to TOML: ordered
statements of enumerated match fields ANDed together, first-match-wins
chains, a closed set of actions (`crates/policy/src/engine.rs`). It is
correct, explainable, transactional — and structurally capped. There are no
named sets (a 1,000-prefix customer list is 1,000 statements), no
parameters (per-peer variation = chain duplication), no composition
(policy-as-predicate), no computed decisions. Operators of the RR niche
this daemon targets live in policy all day; this surface is the daemon's
lowest ceiling relative to BIRD, Junos, and IOS-XR.

A field survey (BIRD filter language, FRR route-maps, Junos policy /
IOS-XR RPL, GoBGP, OpenBGPd), a code recon of our seams, and two
hands-on spikes (a roto adoption probe; a six-way evaluator benchmark)
inform this decision. Key inputs:

- **Every daemon in the reference class runs a compiled DSL + indexed
  match data.** BIRD linearizes filters to a stack machine and
  structurally diffs compiled programs on reconfigure; OpenBGPd's 2018
  rework (370k linear rules → <6k + shared indexed sets; >1h convergence
  → <2min) is the canonical lesson that **evaluation speed lives in the
  set-index layer, not the expression interpreter**. Nobody evaluates a
  general-purpose scripting VM per route.
- **Our differentiators require an analyzable representation.** Four
  existing consumers introspect policy structure statically:
  `requires_as_path_string()` (skips a per-route×peer string build),
  `requires_rpki/aspa_validation()` (scopes which peers refresh on a
  validation-cache update), the per-statement explain trace (ADR-0073),
  and the ADR-0076 live-impact planner (structural `PartialEq` diff of
  resolved chains). An opaque script answers none of these; a typed IR
  answers all of them.
- **Benchmark** (Threadripper 7970X, single core, 100k-route walk,
  realistic set-heavy policy; spike crate re-runnable):

  | Evaluator | ns/route | vs floor | allocs/route |
  |---|---|---|---|
  | Hand-rolled Rust (floor) | 13.8 | 1.0× | 0 |
  | **Typed-IR tree-walk (this ADR)** | **19.8** | **1.44×** | **0** |
  | mlua/Luau | 291 | 21× | 0 |
  | Rhai (pre-compiled AST) | 581 | 42× | 5 |
  | Today's chain (set expanded to 2,001 stmts) | 1,012 | 73× | 0 |
  | cel-rust v0.14 | 1,708 | 124× | 74 |

  The typed IR is effectively free — and **~51× cheaper than today's
  engine** for policies that need sets, because sets become shared
  indexed structures instead of statement chains.
- **roto (NLnet Labs) was evaluated hands-on and rejected for adoption**
  (RAID verdict): its compiler stages are private (no introspection,
  pre-1.0 API mid-restructure), and its safety model is wrong for an
  in-process per-route hook — unbounded loops/recursion with no fuel
  mechanism (a `while true {}` policy hangs the daemon), host panics
  abort the process, and compiled division-by-zero raises SIGFPE (it
  killed the probe process). Its *design* is excellent and is raided
  below. Its 56 ns/call confirms the performance class.

## Decision 1 — Build our own typed, compiled policy language

Working name **RPL** is taken (IOS-XR); the language is simply "the
rustbgpd policy language", files `*.rpol`. Pipeline:

```
lex (logos) → recursive-descent parse → typecheck (inference, friendly
diagnostics) → typed IR (PUBLIC, analyzable) → tree-walk evaluator (V1)
```

- Match **data** compiles out of the program into shared indexed
  structures: prefix sets as tries with ge/le ranges (reusing the
  `prefix-trie` dep), community/large/extended-community hash sets,
  AS-path matchers — built once at commit, deduped across policies and
  peers (the OpenBGPd lesson).
- Tree-walk first; a linearized bytecode VM is a *measured* upgrade path
  (BIRD gained 10-40% from linearization years after shipping; at
  19.8 ns/route we have 10-100× headroom before it matters).
- Parse/compile cost is irrelevant (sub-ms at commit time; roto measured
  0.3-0.9 ms/policy with a full Cranelift JIT — ours is cheaper).
  Diagnostic quality is everything: ariadne-style labeled errors.

## Decision 2 — Safety is total by construction

The language cannot express a non-terminating or daemon-killing program:

- **No unbounded loops, no recursion.** V1 has no loop construct at all
  (IOS-XR RPL proves BGP policy doesn't need one); policy calls form a
  DAG, checked at compile time.
- **Checked arithmetic.** Division/modulo by zero and overflow are
  *policy evaluation errors*, not traps: the route takes the chain's
  default action, a `bgp_policy_eval_errors_total` counter increments,
  and the error surfaces in explain. The daemon never crashes on
  operator input.
- **Step budget** as belt-and-suspenders: the evaluator counts IR steps
  against a compile-time-estimated bound (the K8s CEL cost-model idea);
  exceeding it is a bug in our compiler, not a tunable.
- Host functions exposed to the IR are panic-free by construction and
  reviewed as such (the roto SIGABRT lesson).

## Decision 3 — The IR is public and the introspection contract is preserved

The typed IR is a stable, documented crate surface (`rustbgpd-policy`),
because four consumers depend on analyzing it:

1. `requires_as_path_string()` etc. become IR analyses (does any node
   read `route.as_path_string` / RPKI / ASPA state?) — same hot-path
   gating, now over arbitrary policies.
2. The **ADR-0076 live-impact planner** diffs compiled IR structurally
   (BIRD's reconfigure model): only peers whose *compiled program or
   referenced set data* actually changed get planned/refreshed.
3. **Explain** renders from IR nodes: terms are named, every match node
   knows its source span, and per-term hit counters (the IOS-XR
   `show pcl` idea) come free from the evaluator.
4. `rbgp policy test` (Decision 6) executes the same IR read-only.

## Decision 4 — Language surface (V1)

Stolen deliberately: roto's `filtermap`/`Verdict` function shape +
in-language `test` blocks; Junos's named terms + policy-as-predicate +
chains; IOS-XR's parameters; BIRD's typed values + set literals with
ge/le; K8s's write-time cost estimate.

```rpol
prefix-set customers { 10.10.0.0/16 ge 24 le 28, 192.0.2.0/24 }

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
    # policy-as-predicate composition:
    term bogon-guard { if apply(bogon-filter) { reject } }
}

test customer-in-accepts-tagged {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki valid }
    expect customer-in(200) == accept with local-pref 200
}
```

First-class types: prefix, prefix-set (ge/le), community / large /
extended community with native literals (`65000:100`, RT/RO forms),
as-path with `contains` / `matches` (the existing Cisco-style regex
engine reused as the matcher), RPKI/ASPA states as enums, integers with
comparison ranges, peer context (address/ASN/group). No maps, no
user-defined types, no loops — V1 scope is RPL-sized on purpose.

## Decision 5 — One evaluator; TOML chains become a frontend

The existing TOML `PolicyStatement` chains **compile into the same IR**.
`evaluate_chain_with_attribution` — the single choke point every import
and export seam already calls — keeps its exact signature, backed by the
IR evaluator. Consequences:

- Zero seam churn across the 14 call sites; existing configs work
  unchanged forever (no migration cliff); decision-compatibility is
  pinned by golden tests (old engine vs IR on a corpus, byte-identical
  `PolicyResult`s) before the old evaluator is deleted.
- The ~51× set-policy win lands for *existing* TOML users the moment the
  IR ships, before the language does.
- `.rpol` policies are just a second frontend producing the same IR, so
  chains may mix named TOML policies and `.rpol` policies during
  migration.

## Decision 6 — `rbgp policy test`: the operator differentiator

No shipping daemon lets you test a **candidate** policy against the
**live RIB** of a running daemon with attribute-level diffs (Junos tests
verdicts only; XR profiles attached policies; Batfish is offline). We
ship, in one verb:

```
rbgp policy test my-policy.rpol --policy 'customer-in(200)' \
  --direction import --neighbor 10.0.0.1
  → accepted / rejected / modified counts
  → per-term hit counters
  → sample before/after attribute diffs (--show-changes N)
  → write-time cost estimate
```

Runs the compiled IR read-only over a RIB snapshot via the existing
query machinery — no session impact, `SensitiveRead` authz. In-language
`test` blocks run at compile/commit time (`rbgp policy check` runs them
standalone), so operators unit-test policies in CI before ever touching
the daemon.

## Decision 7 — Apply semantics ride ADR-0076, with an external-input fence

Compile at plan time (sub-ms; compile failure = plan failure, nothing
applied). The planner's impact set comes from IR structural diff
(Decision 3.2). Apply is the existing hot-swap + Route-Refresh path —
per-session atomic, commit-confirmed compatible, no FRR-style
reject-window. Set-data-only changes (a prefix added to a set) diff as
data, refreshing only peers whose policies reference that set.

Compatibility correction: native config apply/rollback and gNMI Set cannot
atomically stage or restore `.rpol` main/import files or policy-dataset
snapshots. While either the running or candidate config references those
inputs, the v1 planner rejects every executor family that would adopt the full
candidate snapshot. Operators deploy TOML and external inputs together and use
SIGHUP. True no-ops remain no-ops; pure `[[fib_tables]]` transactions with
unchanged external inputs remain committable because that targeted executor
does not adopt the full candidate config.

## Deferred (explicitly, with re-entry conditions)

- **Luau escape-hatch tier** for exotic logic — validated viable at
  291 ns/route with no GC outliers; add only on concrete operator demand,
  as a cold-path/marked-unsafe tier, never the core.
- **Bytecode VM** — gated on a measured need the tree-walk can't meet.
- Loops / maps / user types; external dataset joins (beyond the existing
  RPKI/ASPA inputs); wasm plugin tier (out of budget per-route: 0.5-5 µs
  marshalling-dominated).

## Staged PR plan

1. **IR + evaluator + indexed sets** behind the existing engine: TOML
   chains compile to IR, golden decision-compatibility corpus,
   `requires_*` reimplemented as IR analyses. Ships the 51× set win with
   zero behavior change. (The riskiest PR; everything after is surface.)
2. **Lexer/parser/typechecker + diagnostics** for `.rpol`, with the
   in-language `test` runner (`rbgp policy check`). Language exists,
   nothing consumes it yet.
3. **Config/API/CLI integration**: `.rpol` files referenced from TOML
   (`policy_file = ...`), named-policy registry, ADR-0076 planner on IR
   diff, gNMI paths, `rbgp policy test` (live-RIB dry run).
4. **Explain integration**: per-term traces + hit counters through
   ExplainImportPolicy/ExplainAdvertisedRoute; import decision cache
   unchanged (generation stamping already fits).
5. **M80 interop + docs**: policy parity lab vs FRR (M13/M34 patterns:
   same intent expressed in `.rpol` vs FRR route-maps, identical
   outcomes; policy-change-under-traffic via the refresh path), language
   reference doc, CONFIGURATION.md, migration guide, CHANGELOG.

## Receipts

- Field survey + per-candidate sources: session research record.
- roto probe + safety findings: scratchpad `roto-spike/` (SIGFPE,
  unbounded-loop hang, private IR — verified 0.11.0).
- Benchmark crate: scratchpad `policy-bench-spike/` (re-runnable,
  decision-tally-asserted across all six evaluators).

## Amendment (2026-07-02): implementation record — the arc shipped

The five staged PRs landed as four code slices plus the interop/docs
closer, one day, plan-to-main:

- **#654 — IR + indexed sets + IR-backed evaluator** (staged PR 1).
  TOML chains lazily compile to the public typed IR behind the
  unchanged `evaluate_chain_with_attribution` choke point; golden
  decision-parity corpus (~4,500 chain×route cases) pins the legacy
  walker and the IR path byte-identical; `requires_*` hot-path gates
  reimplemented as IR analyses. Measured headline: the set-heavy shape
  (1,000-prefix list) went ~3.8 µs → ~14 ns per route — **~270×**,
  above the ADR's projected 51×; realistic single/short-chain shapes
  20-50% faster; the one regression is the walk-every-statement long
  chain (+27%, the tree-walk And-indirection — the deferred
  linearized-bytecode pass remains the recovery path).
- **#655 — the `.rpol` frontend** (staged PR 2). Lexer (logos), parser,
  typechecker, ariadne diagnostics with multi-error recovery and
  did-you-mean, in-language `test` blocks through the real IR
  evaluator, `rbgp policy check` (exit 0/1/2). One surgical IR
  addition the ADR text didn't spell out: **`TermAction::Continue`**,
  the lowering target for modify-and-fallthrough terms (Junos-style
  modify-then-continue); the TOML frontend never emits it, so the
  parity corpus was unaffected.
- **#656 — daemon integration** (staged PR 3). `[policy] rpol_files`
  (compile-at-load, load-error diagnostics, one namespace with
  `[policy.definitions]`), call-form chain references monomorphized at
  load, SIGHUP hot-apply through `SyncRpolPolicies` with chain
  identity = compiled content (an unchanged file reloads as a no-op;
  a changed policy refreshes exactly the referencing peers),
  transactions fail closed on `.rpol` content (out-of-band files), and
  `rbgp policy test` / `TestPolicy` — the Decision 6 differentiator —
  evaluating candidate source read-only over a live RIB snapshot.
  The planned `--rib live` flag shipped as the default (and only)
  behavior; the write-time cost estimate from the Decision 6 sketch
  was dropped as speculative.
- **#658 — explain + live hit counters** (staged PR 4). Per-term
  statement traces in `ExplainImportPolicy` (guards pretty-printed
  back to `.rpol` syntax, sets by source name), `<chain-ref>:<term>`
  attribution in `ExplainAdvertisedRoute`, and Decision 3.3's live
  per-term counters via `GetPolicyStats` / `rbgp policy stats`
  (relaxed atomics; since-chain-install). A performance fix rode
  along: RIB distribution passes now take `PolicyChain::share()`
  handles instead of `Clone`, so evaluations land in the installed
  chain's counters and the IR compiles once per install instead of
  once per pass. **Follow-up on record:** import-side counters
  accumulate but have no read surface yet (`--direction import`
  returns `Unimplemented` saying so).
- **M80 — the parity receipt** (staged PR 5). 4-node containerlab:
  rustbgpd running `customer-in(peer_lp)` / `src-default` / `edge-out`
  from an `.rpol` file vs an FRR node running route-maps /
  prefix-lists / community-lists with the same intent, both fed one
  route matrix. 29/29: route-for-route import + export agreement
  (prefix-set ge/le boundary, community add/remove, LP set, as-path
  regex reject, modify-then-continue, the same parameterized policy
  instantiated twice), `policy check` exit 0, a `customer-in(500)`
  live-RIB dry run (counts + term hits + diffs), live stats, and an
  `.rpol` edit under traffic: no flap, Route Refresh observed on the
  wire at exactly the one peer whose resolved chain changed, LP
  re-imported. `tests/interop/m80-rpol-policy-parity-frr.clab.yml`.

Still deferred, unchanged from the Deferred section: Luau tier,
bytecode VM, loops/maps/user types, `as-path-set`, gNMI paths for
`.rpol` content (gNMI Set remains TOML-surface-only).

## Amendment (2026-11-01): callable policies — `apply p(args)` as a statement

Decision 4 made `apply` predicate-only: `apply(p)` asks whether `p` would
permit the route, and `p`'s actions do not run. This amendment adds the
IOS-XR RPL policy-library idiom alongside it. `apply p` and `apply p(args)`
in statement position run `p` in place, as RPL's `apply` pastes the child
policy into the parent. The predicate form keeps its meaning, and statement
position admitted no `apply` before, so no existing program changes
(ADR-0103 Decision 2, grammar rule 2). No breaking change makes this
design simpler or safer, so none is proposed.

This amendment depends on typed policy parameters, which add set,
community and address arguments to policy calls. Calls and their
examples below use those argument types; the implementation lands after
them.

### Semantics

1. **Paste-inline under the call-site guard.** A call runs `p`'s terms in
   order, under the path condition of the place it is written: the term,
   the enclosing `if` branches and the negations an `else if` chain
   carries. Arguments bind as in a chain reference, with typed
   parameters. A caller's own parameter passes through when its type
   matches.
2. **Modifications stage into the caller.** A callee `set`, `add`,
   `remove` or `prepend` joins the caller's staged modifications in
   execution order. The rules are those of successive statements in one
   policy: a later scalar write replaces an earlier one, and community
   additions and removals apply in order. They carry through to the
   policy's outcome: a later caller statement can override them, or the
   route can still be rejected. Conditions do not observe them, in the
   callee or in the caller's later statements and terms. Every condition
   reads the route as received, as before and as RPL conditions read the
   route's initial data.
3. **A callee `reject` denies the route.** A deny from any depth ends the
   evaluation, and staged modifications are discarded, as with a
   top-level `reject`.
4. **A callee `accept` returns to the caller.** It ends the callee: no
   later callee term runs, and its staged modifications are kept.
   Evaluation continues with the caller's next statement after the call,
   then the caller's later terms. An `accept` inside a callee therefore
   never ends the caller and never permits the route on its own; the
   caller's own verdict, or its `default-action`, decides.
5. **Fall-through runs the callee's `default-action`.** A callee that
   reaches its end without a verdict applies its declared default:
   - `accept`, or no declaration, returns, like an explicit `accept`;
   - `default-action reject` denies.

   A policy therefore means the same thing as a callee, as a chain
   member and under its own `expect` tests. RPL has no per-policy
   default, so an RPL child that falls through always returns; port such
   a child without `default-action reject`.
6. **`else if` first-match is unchanged.** The branch's guard alone
   decides which branch runs; the callee's outcome does not. A branch
   whose body calls a policy can fall through, because the callee may
   return, so later branches keep its negation. After a callee returns,
   evaluation continues after the whole `if` statement, never in a later
   branch of the same chain.

### Scope

- **Position.** A call is allowed wherever an action statement is
  allowed: in a term body, an `if` body or a `for` body. In a loop body
  the call runs once per iteration, and the loop's cost bound multiplies
  it.
- **Callee contents.** A callee may hold `let` bindings, `for` loops,
  function calls, `accept` inside its loops, and its own `apply`
  statements, because a statement call has a term walk to run them in.
- **Predicate targets.** A policy that contains an `apply` statement
  cannot be the target of `apply(p)`, the same rule as for `let`, `for`
  and function calls: the predicate has no term walk to run the callee
  in.
- **One composition graph.** Statement calls and predicate applies are
  edges of the same `apply` DAG. A cycle through any mix of the two is a
  compile error naming it, `MAX_APPLY_DEPTH` (8) counts both kinds of
  nesting, and the inlined terms count against `MAX_APPLY_EXPANSION` and
  `MAX_CHAIN_NODES`.

### Lowering

A call adds no IR node kind; the evaluator, the IR analyses and the
live-impact planner are unchanged. The return is a frame-slot flag, built
from the existing `Bind` term and a guard that reads a local.

- The callee lowers on its own, monomorphized with the call's arguments,
  to its IR term list. Its frame slots are offset above every caller slot
  live at the call site, and one more slot, the call's return flag, is
  reserved above them.
- The call emits, in order:
  - a `Bind` that clears the flag, guarded by the call-site path;
  - each callee term, guarded by the call-site path, then "flag is
    clear", then the term's own guard, as one flat conjunction in that
    order.
- A callee term that ends in `accept`, its `Permit(mods)`, becomes a
  `Bind` that sets the flag to that term's ordinal, then a `Continue(mods)`
  guarded by the path and "flag equals that ordinal". The modifications
  apply exactly when that term returned, and every later callee term sees
  the flag set and is skipped.
- Inside a callee loop body, `accept` sets the flag the same way and then
  breaks out of the loop. An enclosing callee loop gets a `Break` guarded
  by "flag is set" after each inner loop.
- `Deny` stays `Deny`. A fall-through `default-action reject` adds one
  final `Deny` guarded by the path and "flag is clear".
- **No callee guard is evaluated again after its own term.** Standalone
  lowering reuses frame slots across source terms and sibling scopes. A
  design that re-evaluated an earlier callee guard in later terms, for
  example by conjoining the negation of each earlier returning guard,
  would extend the lifetime of every binding that guard reads. A later
  binding could then overwrite one of them, flip the guard and suppress
  a required rejection.
  - A plain callee-to-caller slot remap is sound only because the flag
    removes those re-evaluations.
  - Any lowering that re-evaluates a callee guard across terms must
    allocate the slots it reads with their extended lifetime, live until
    the callee ends, and charge them to the caller's frame. A plain
    remap is insufficient there.
- Peer-context and other `requires_*` flags propagate with no extra
  rule, because the analyses read the inlined terms. A callee that reads
  `peer.*` makes every chain that calls it peer-context-dependent, which
  removes those peers from update-group sharing, as if the guard were
  written in the caller.
- Reload diffs the caller's compiled chain as before (ADR-0103
  Decision 5). Editing a callee therefore refreshes exactly the peers
  whose chains call it, and a callee's datasets are referenced by the
  caller's chain.

Two alternatives were rejected:
- **The negation encoding.** Each callee term would carry the negations
  of the earlier returning guards. It needs lifetime-extended slots for
  every binding those guards read. It re-evaluates every earlier
  returning guard, function calls included, in each later term, so its
  cost grows with the square of the returning terms. It also cannot
  express a return from inside a loop.
- **A runtime call node.** This is a `TermAction` that walks the callee
  as a sub-walk. It grows the public IR, the evaluator, explain and every
  IR analysis, and the flag already gives the same walk with existing
  nodes. It stays the upgrade path if a measured shape needs it.

### Frame budget

- At each call site, the caller's frame must hold every slot live there
  plus the callee's standalone frame high-water mark plus the return flag.
- Nested calls add their own frames and flags the same way.
- The existing per-term frame-slot check enforces this at the call site,
  under the same `LOCAL_FRAME_SLOTS` limit. The diagnostic names the call.

### Explain, stats and coverage

Inlined callee terms keep their identity under the call site. This
amends ADR-0103 Decision 6.3, which stays true for predicate `apply`.

- The caller term's IR terms are numbered `<term>.<n>` as today.
- An inlined term is named
  `<term>.<n>/<call>:<callee-term>`, for example
  `ours.3/tag-customer(65000:100):mark`:
  - `<call>` is the call as written, with canonical arguments;
  - `<callee-term>` is the callee's own IR term name.
  - Nested calls compose: `ours.3/a:x.2/b:y`.
- The flag's own terms are named after what they serve:
  - `<call>:enter` clears the flag;
  - `<callee-term>:return` applies a returning term's modifications;
  - `<call>:default` is a fall-through deny.
- The name is a pure function of the source, so counters keep their
  positional key and the term grid changes only when the operator edits
  a caller or a callee (ADR-0103 Decisions 5.2 and 6.1).
- `rbgp policy stats`, `rbgp policy test` term hits and the explain
  traces show these names. In-language test coverage credits a hit to
  the callee's source term.
- **Exception: a call inside a `for` body.** The call is inlined into the
  loop's body terms, which sit outside the policy's term and counter grid,
  and the loop evaluator reports neither body-term coverage nor
  per-body-term explain traces. A loop-contained call is therefore
  attributed at the loop level, like any other loop-body term today:
  counters, coverage and explain name the enclosing loop term, not the
  inlined callee terms. Per-term attribution inside loops remains a
  possible later extension, for loop bodies in general.

### Cost model

Every call is charged where it is written:

- **Charged at every call site.** An inlined callee is charged where it is
  written. Each callee IR term costs its own guard, plus the call-site path,
  plus the flag check. Each call adds its entry `Bind`, each returning term
  adds its flag `Bind` and `Continue`, and a default deny adds one term.
  Action value costs count toward `MAX_EVAL_COST`, and a call in a loop
  body is multiplied by the loop bound.
- **Charged per instantiation.** A parameterized callee is charged once
  for each instantiation, because each call site monomorphizes it.
- **No allocation per inlined term.** Each policy's inlinable cost is
  recorded once, in the existing Kahn-ordered DP, as saturating totals. A
  call site adds those totals with its path cost scaled by the term count.
  Nothing is allocated per inlined term: the per-term record is capped one
  past the budget, so the budget check still fires.
- **Never below the lowering.** A probe over the call shapes compares the
  charge with the lowered node count, and the boundary tests below pin it.

With the flag, a callee's cost is linear in its size at each call site.

### Tests the implementation must carry

- Semantics:
  - a callee `reject` denies, and its staged writes are discarded;
  - a callee `accept` returns, so later callee terms do not run and the
    caller's later statements and terms do;
  - fall-through returns, and fall-through with `default-action reject`
    denies;
  - staged writes reach the outcome, and a later caller write overrides
    them;
  - a condition after the call reads the original route.
- **Slot clobbering.** A returning callee term's guard reads a binding
  whose slot a later callee term reuses, and a later callee `reject` must
  still fire for a route that does not return.
  - Prove it red against a lowering that re-evaluates the earlier guard
    after the plain slot remap.
  - Cover the same shape across sibling `if` scopes inside one callee
    term.
- **Loops and branches.**
  - An `accept` inside a callee loop returns from the callee, including
    from a nested loop.
  - A call in a caller loop body runs once per iteration.
  - A call inside an `else if` branch never lets a later branch run after
    the callee returns.
- **Composition.**
  - Nested calls.
  - A cycle through statement calls, and one through a statement call
    and a predicate apply.
  - The depth cap.
  - A parameterized callee called with two argument lists.
  - A policy with an `apply` statement rejected as a predicate target.
- **Context, budgets and naming.**
  - A callee reading `peer.*` makes its caller's export chain ineligible
    for update-group sharing.
  - The frame budget at a call site, just under and just over.
  - The size budget for a deciding, a returning, a nested and a
    parameterized callee, just under and just over.
  - The agreement probe over the call shapes.
  - Explain, stats and test term-hit names for inlined terms and the
    flag terms.
  - A call inside a `for` body attributes its hits, coverage and explain
    trace to the enclosing loop term.
