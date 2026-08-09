# ADR-0115: Lean daemon build flavors

**Status:** Accepted (no additional flavor)
**Date:** 2026-07-22

## Context

The shipped `rustbgpd` daemon includes two substantial implementation
subtrees that a control-plane-only route server or route reflector may never
activate:

- durable event history, including `rusqlite` and bundled SQLite; and
- Linux FIB, BLACKHOLE, managed-netdev, and EVPN VTEP/IRB writers, including
  the netlink client stack.

Runtime opt-in already avoids their operational cost, but it does not remove
their code and dependencies from the release artifact. This ADR asks whether
one additional lean artifact would materially reduce artifact or build cost
without fragmenting configuration, packaging, release gates, or support.

This ADR is measurement-gated. The prototype does not authorize production
features, packages, workflows, or behavior. It preserves the public event
history API types while replacing storage with an unreachable facade, and it
preserves portable EVPN model, reflection, controller-feed, and in-memory
types while replacing Linux writers with unreachable facades. Candidate
`--check` paths explicitly reject omitted capabilities. This is an upper-bound
prototype: a production implementation would also need gates at normal
startup, `--diff` candidate load, reload and transaction ingress, generated
schema and documentation, and disabled API behavior.

Cargo features are additive. When several workspace packages are selected,
features for a shared dependency are unified; Cargo's resolver documentation
therefore recommends separate invocations when unification must be avoided.
The release workflow builds the entire workspace, which would contaminate a
lean measurement by re-enabling features from other members. Every measured
shape consequently uses the same explicit selected-package invocation for
`rustbgpd`, `rustbgpctl`, and `rs-config-render`. A one-time full-build A/A
compares the resulting daemon with the workspace-built daemon before the
candidate results are used. See the [Cargo resolver reference][cargo-resolver]
and [`cargo tree` feature inspection][cargo-features].

`rusqlite` documents that its `bundled` feature compiles the embedded SQLite
source with the `cc` crate. Removing `rusqlite` and `libsqlite3-sys` is
therefore a real dependency-graph reduction, but it is not automatically a
native-toolchain reduction: the full daemon's jemalloc and TLS dependencies
still have native build units. The control-plane prototype removes the
`rtnetlink` and netlink-protocol Rust compile units, but no native toolchain.
See the [rusqlite build notes][rusqlite-build].

## Predeclared value gate

Graph absence and fail-closed/preservation smokes are mandatory but do not by
themselves justify a new artifact. An individual candidate is a GO only if all
three clean-run deltas have the same sign and it meets either:

1. the deterministic, normalized gzip of the complete shipped release
   payload is at least 10% **and** 2 MiB smaller; or
2. median clean release build is at least 15% **and** 30 seconds faster, with
   an evidenced removed native or Rust compile unit.

Crate count or security-surface reduction alone is insufficient. The median
warm source-touch rebuild must not regress by more than 5%. A candidate near a
threshold, or whose ranges overlap the full build, receives two additional
repetitions. "Near" means within two percentage points and 256 KiB of the
size gate, within two percentage points and ten seconds of the clean-build
gate, or within one percentage point of the warm-regression ceiling. After
five repetitions the deterministic evaluator returns GO or NO-GO. A combined
candidate is measured only after an individual GO, against the individual
candidate furthest past either gate. "Furthest" scores each gate by its
limiting normalized conjunct (percent versus bytes, or percent versus seconds)
and takes the better gate. The combined candidate must add at least 5% and 1 MiB of
compressed reduction or 10% clean-build reduction while removing the second
complete subtree.

The exact runner, prototype patch, graphs, config smokes, timing rows, binary
hashes, Cargo timing artifacts, and checksums live in the
[lean daemon build-flavor receipt](../perf/lean-daemon-build-flavors-2026-07.md).

## Decision

Do not ship an additional lean daemon flavor. Both individual candidates are
NO-GO against the predeclared gate, so the combined candidate was not eligible
for measurement.

The no-history candidate reduced the normalized compressed release payload by
1,114,172 bytes (6.19%) and median clean build time by 6.68 seconds (2.14%).
It met neither size conjunct (10% and 2 MiB) nor either clean-build conjunct
(15% and 30 seconds).

The control-plane candidate reduced the normalized compressed release payload
by 1,674,263 bytes (9.30%) and median clean build time by 36.23 seconds
(11.61%). It met the 30-second clean-build conjunct, but not the required 15%;
it met neither size conjunct. Both candidates had positive clean-build savings
in every paired round and neither regressed the median warm rebuild, but those
properties are safeguards rather than independent reasons to ship a flavor.

The full sealed results, environment, dependency graphs, behavior smokes,
mutation receipts, and checksums are in the linked receipt.

## Consequences

- rustbgpd continues to ship one daemon artifact with durable history and the
  Linux dataplane compiled in and controlled at runtime.
- The prototype feature split is evidence only and does not enter production
  source, packaging, CI, or support policy.
- The project avoids duplicating release gates, documentation, configuration
  compatibility work, and operator choice for savings below the declared
  threshold.
- The dependency graphs confirm that SQLite and netlink are separable if
  future artifact growth or operator demand justifies repeating the
  measurement. A revisit must use a new predeclared gate and a fresh control;
  these July 2026 timings are not a standing authorization.

[cargo-resolver]: https://doc.rust-lang.org/cargo/reference/resolver.html#features
[cargo-features]: https://doc.rust-lang.org/cargo/reference/features.html#inspecting-resolved-features
[rusqlite-build]: https://docs.rs/rusqlite/0.40.1/rusqlite/index.html#notes-on-building-rusqlite-and-libsqlite3-sys
