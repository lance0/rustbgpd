# Lean daemon build-flavor measurement (July 2026)

This receipt tests whether rustbgpd should ship one additional lean daemon
flavor.
The sealed result is NO-GO for both individual candidates, so the combined
candidate was not eligible and rustbgpd continues to ship one daemon artifact.
This receipt does not ship the prototype features.

## Shapes

| Shape | Explicit rustbgpd features | Removed subtree |
|---|---|---|
| full | `jemalloc` on exact main | none |
| no-history | `jemalloc,linux-dataplane` on the prototype patch | SQLite-backed durable history; public API types retained |
| control-plane | `jemalloc,event-history` on the prototype patch | Linux writers/netlink; RR/route-server and EVPN reflection retained |

The combined shape is predeclared and implemented in the runner, but is built
and measured only if an individual candidate clears the ADR's value gate.

## Method

- Exact baseline: `86bff61fe5f3a033842335c72d54bb8fa1cac836`, the first
  main commit containing PR #1084.
- Rust/Cargo 1.95.0, `x86_64-unknown-linux-gnu`, release profile, explicit
  jemalloc, default linker, four jobs, and `CARGO_INCREMENTAL=0` for every
  shape.
- Identical selected-package invocation: `rustbgpd`, `rustbgpctl`, and
  `rs-config-render`. The full workspace is not a valid lean comparison under
  feature unification. A one-time full workspace-vs-selected binary A/A is
  retained separately; a same-target selected-then-workspace mismatch aborts
  the receipt, while separate-target LTO/hash variance is recorded only.
- Three clean builds per shape in Latin-square order. Each clean build uses a
  separate target directory. The evaluator automatically adds rounds four and
  five if clean ranges overlap or a result is near a threshold. "Near" is
  fixed before execution: two percentage points and 256 KiB for payload size,
  two percentage points and ten seconds for clean build, and one percentage
  point for the warm-regression ceiling.
- Three warm source-touch builds per shape, also balanced. Cargo JSON must
  identify the executable `rustbgpd` artifact with `fresh=false`; a no-op
  build is invalid.
- The size gate uses a normalized equivalent of the complete amd64 release
  payload: all three binaries, both licenses, schema, generated man pages, and
  generated shell completions. The full control comes from the workspace
  build used by the real release workflow; candidate payloads come from the
  selected-package builds. Stable order, epoch timestamps, numeric root
  ownership, fixed modes, and `gzip -9 -n` make the comparison reproducible.
  A conditional combined comparison packages both the winner and combined
  binaries from their paired marginal-build targets.
  The third clean run's Cargo timing HTML is retained as a deterministic gzip
  per shape; every timing HTML hash is in `timings.csv`.
- Dependency proofs use `cargo tree -p rustbgpd --target
  x86_64-unknown-linux-gnu -e normal,build,features`. `cargo deny` remains a
  workspace-wide advisory gate and is not variant-sensitive. No-history
  removes bundled SQLite's native build unit; control-plane removes the
  `rtnetlink` and netlink-protocol Rust compile units.
- The public receipt replaces source paths with `<WORKTREE>` and the Rust host
  triple line with `<BENCH_HOST>`; it contains no hostname, username, or home
  path.
- The runner records its own, the evaluator's, and the prototype patch's
  SHA-256 before work starts, checks them before and after builds and before
  sealing, and aborts if any changes. It refuses to delete or checksum an
  artifact outside the declared inventory.

The exact command is:

```bash
docs/perf/run-lean-daemon-build-flavors.sh all
```

## Correctness fences

The full graph must contain both subtrees. The no-history graph must omit
`rusqlite` and `libsqlite3-sys` while retaining every netlink root. The
control-plane graph must omit `rtnetlink`, `netlink-packet-route`,
`netlink-packet-core`, `netlink-packet-utils`, `netlink-proto`, and
`netlink-sys` while retaining both SQLite roots. The unmeasured combined graph
must omit both complete inventories.

Both candidates must accept the shipped route-server and EVPN RR examples,
an all-supported-families RR config, and controller injection. The no-history
candidate must retain FIB,
BLACKHOLE-install, EVPN VTEP/BUM, IRB, and
managed-netdev config while rejecting event history and gNMI ON_CHANGE backed
by history. The control-plane candidate must retain event history and gNMI
ON_CHANGE config while rejecting the Linux writer configurations. The full
control accepts both sets. If eligible, the combined candidate repeats the
RR/controller preservation checks and rejects both omitted capability sets.
These are `--check` smokes only; they do not prove
every production config ingress, and the ADR lists the additional work a
hypothetical implementation would require.

The runner's assertions were mutation-tested:

- each package-presence and package-absence assertion has a distinct mutation
  that emits only its expected RED sentinel;
- each accepted config is replaced with a config that its build must reject,
  and each expected rejection is replaced with an accepted RR config; and
- synthetic evaluator breaks independently prove both size conjuncts, both
  clean-build conjuncts, removed-unit evidence, the same-sign rule, warm
  ceiling, bounded-near extension trigger, and combined marginal gates.

See `assertion-mutations.txt` for executed exit statuses.

## Results

The runner completed three clean and three warm real-daemon builds per shape.
Neither clean range overlapped the full control and neither result was near a
threshold under the predeclared definition, so the automatic extension to
five repetitions did not trigger.

| Shape | Payload gzip bytes | Payload saving | Median clean | Clean saving | Median warm | Decision |
|---|---:|---:|---:|---:|---:|---|
| full | 18,009,952 | control | 312.13 s | control | 200.22 s | control |
| no-history | 16,895,780 | 1,114,172 B (6.19%) | 305.45 s | 6.68 s (2.14%) | 199.82 s (-0.20%) | NO-GO |
| control-plane | 16,335,689 | 1,674,263 B (9.30%) | 275.90 s | 36.23 s (11.61%) | 166.87 s (-16.66%) | NO-GO |

No-history missed both conjuncts of both value gates. Control-plane cleared
the 30-second clean-build conjunct, but missed its paired 15% requirement; it
also missed both the 10% and 2 MiB payload requirements. All three paired
clean deltas had the same favorable sign, and neither candidate violated the
5% warm-regression ceiling. Those safeguards do not substitute for the value
gate, so `individual_winner=none` and the combined shape was not built.

Correctness and receipt integrity also passed:

- the full, no-history, control-plane, and unmeasured combined dependency
  graphs matched their complete SQLite/netlink presence and absence
  inventories;
- 24 expected-accept and seven expected-reject config smokes passed against
  the exact measured binaries;
- protobuf plus both CLI help surfaces matched the full control;
- the same-target selected/workspace A/A daemon was byte-identical; and
- 80 assertion/evaluator mutations produced their expected RED receipts, all
  18 warm and clean daemon artifacts reported `fresh=false`, the declared
  artifact inventory matched exactly, and every entry in `SHA256SUMS`
  verified.

ADR-0115 therefore records the negative decision: retain the single full
daemon artifact and keep the prototype patch only as reproducible evidence.

## Artifact index

All files are under `docs/perf/artifacts/lean-daemon-build-flavors-2026-07/`:

- `prototype-features.patch` — non-production upper-bound prototype;
- `evaluate.py` — deterministic predeclared value-gate evaluator;
- `environment.txt` — scrubbed hardware, kernel, toolchain, target, profile,
  allocator, linker, and jobs;
- `dependency-graphs.txt.gz` and `config-smokes.txt` — capability proofs (the
  exact feature-expanded graphs are compressed to keep the review diff small);
- `timings.csv`, `warm-artifact-freshness.txt`, and one compressed Cargo
  timing report per measured shape;
- `release-payloads.csv` — normalized complete release-payload sizes/hashes;
- `full-workspace-vs-selected-aa.txt` — release-workflow contamination A/A;
- `public-contract-digests.txt` — protobuf and CLI-surface equality;
- `result-summary.txt` — deterministic evaluator inputs and decisions;
- `assertion-mutations.txt` — load-bearing assertion receipts;
- `receipt-inventory.txt` — concise asserted subtree and artifact inventory;
  and
- `SHA256SUMS` — sealed artifact hashes.
