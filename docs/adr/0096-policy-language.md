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
rbgp policy test my-policy.rpol --rib live --direction import --peer 10.0.0.1
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

## Decision 7 — Apply semantics ride ADR-0076 unchanged

Compile at plan time (sub-ms; compile failure = plan failure, nothing
applied). The planner's impact set comes from IR structural diff
(Decision 3.2). Apply is the existing hot-swap + Route-Refresh path —
per-session atomic, commit-confirmed compatible, no FRR-style
reject-window. Set-data-only changes (a prefix added to a set) diff as
data, refreshing only peers whose policies reference that set.

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
