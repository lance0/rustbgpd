# ADR-0103 benchmark spike — reproduction

The benchmark receipt in [ADR-0103](../0103-rpol-execution-model.md)
rests on two measurements. This directory banks everything needed to
reproduce and independently verify them.

## Spike A — the shipped evaluator

Spike A is the in-tree criterion bench, unmodified:

```
cargo bench -p rustbgpd-policy --bench policy_eval
```

Groups cited in the ADR: `policy_chain_eval` (1/8/32-statement chains
plus the `early_deny` short-circuit contrast), `policy_predicate_eval`
(regex/community/prefix evaluated-vs-skipped pairs), and `set_heavy`
(1,000-prefix list as `legacy_1000_stmts` / `ir_1000_terms` /
`ir_prefix_set`). To compare across refs:
`bench/compare-criterion.sh --package rustbgpd-policy --bench
policy_eval`.

## Spike B — this crate

A standalone, dependency-free crate (deliberately **not** a workspace
member — it has its own empty `[workspace]` table). One program shape
— 15 guarded terms: an indexed prefix-set probe, twelve community
scans, a three-leaf `And` with checked arithmetic in its action, a
scalar compare — evaluated three ways over the same deterministic
1M-route mixed match/no-match stream:

1. `tree-walk` — recursive enum-tree evaluation (models the shipped IR)
2. `bytecode` — the same chain lowered to a flat 50-op jump-threaded
   program
3. `bytecode+fuel` — identical, decrementing a fuel counter per
   instruction

### Verifiability guards (hard asserts — the run aborts if violated)

- **Parity:** verdict tallies must be identical across all three
  evaluators, every timed repetition.
- **Fuel liveness:** the fueled interpreter returns the ops it paid
  fuel for; the run asserts the workload total equals the output of
  `expected_ops()`, an independent op-count model that walks the
  *tree* program (mirroring the lowering contract: 2 ops per evaluated
  leaf, 1 per action, 1 for the default) and never touches the `Op`
  array or the interpreter. An optimized-away decrement cannot satisfy
  this. Expected total for this workload: **24,557,144 ops**.
- **Fail-closed:** fuel exhaustion on a starved budget must return the
  error path, asserted at the end of the run.
- `std::hint::black_box` barriers on the program, the set data, every
  route, every repetition's tally, and the consumed-fuel total.

### Reproduction

```
cd docs/adr/0103-rpol-execution-model-spike
cargo run --release
```

Recorded runs below: `rustc 1.97.0` / `cargo 1.97.0`, release profile
with `lto = true`, `codegen-units = 1` (default `opt-level = 3`), on
one otherwise-idle x86-64 core. Each process run prints 5 timed
repetitions per evaluator (after 2 warmups); three process runs were
recorded. Absolute nanoseconds are machine-specific — the ratios are
the signal.

### Raw output (all runs, unedited)

```
=== run 1 ===
program: 15 terms -> 50 bytecode ops; 1000000 routes
expected bytecode ops for workload: 24557144
         tree-walk: best  62.28 ns/route  samples [62.28, 64.52, 64.23, 66.39, 66.29]  (tally 214797158)
          bytecode: best  46.60 ns/route  samples [46.60, 46.63, 53.23, 57.67, 55.46]  (tally 214797158)
     bytecode+fuel: best  52.10 ns/route  samples [52.23, 52.25, 52.10, 55.70, 56.16]  (tally 214797158)
parity: verdict tallies identical across all evaluators: ok
fuel liveness: consumed == expected (24557144): ok

relative (best-of-5): bytecode = 0.75x tree-walk; fuel adds +11.8% over bytecode
fuel-exhaustion fail-closed: ok
=== run 2 ===
program: 15 terms -> 50 bytecode ops; 1000000 routes
expected bytecode ops for workload: 24557144
         tree-walk: best  56.85 ns/route  samples [56.85, 57.14, 56.88, 57.74, 63.56]  (tally 214797158)
          bytecode: best  46.72 ns/route  samples [46.72, 49.47, 53.21, 53.25, 53.89]  (tally 214797158)
     bytecode+fuel: best  56.03 ns/route  samples [56.38, 56.28, 56.94, 56.34, 56.03]  (tally 214797158)
parity: verdict tallies identical across all evaluators: ok
fuel liveness: consumed == expected (24557144): ok

relative (best-of-5): bytecode = 0.82x tree-walk; fuel adds +19.9% over bytecode
fuel-exhaustion fail-closed: ok
=== run 3 ===
program: 15 terms -> 50 bytecode ops; 1000000 routes
expected bytecode ops for workload: 24557144
         tree-walk: best  57.00 ns/route  samples [63.51, 63.35, 60.21, 57.00, 57.34]  (tally 214797158)
          bytecode: best  53.49 ns/route  samples [55.29, 53.49, 58.34, 57.43, 54.85]  (tally 214797158)
     bytecode+fuel: best  52.15 ns/route  samples [52.63, 56.25, 52.26, 52.15, 58.40]  (tally 214797158)
parity: verdict tallies identical across all evaluators: ok
fuel liveness: consumed == expected (24557144): ok

relative (best-of-5): bytecode = 0.94x tree-walk; fuel adds -2.5% over bytecode
fuel-exhaustion fail-closed: ok
```

### Note on an earlier, softer build of this spike

A pre-hardening build of this spike (no liveness oracle, fuel counter
not returned to the caller) reported the fueled variant *beating* the
unfueled one — the classic signature of the decrement being optimized
away or folded. The liveness assertion exists precisely to make that
failure mode impossible to misreport: with the counter provably live,
per-instruction fuel costs roughly 0–20% over bare bytecode dispatch
run-to-run, and fueled bytecode evaluates at 0.84–0.99× the tree-walk.
ADR-0103's receipt uses only the hardened numbers.
