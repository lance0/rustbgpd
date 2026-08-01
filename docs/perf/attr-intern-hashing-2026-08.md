# Attribute-intern hashing attribution (August 2026)

## Verdict

**Measured NO-GO.** The experiment does not authorize a fingerprint cache or
any other production optimization.

The rich/shared-`Arc` intern, insert, and bulk rows were stable, but the
required isolated hash-only row was not: its four same-SHA medians spanned
**19.71%**, over the predeclared **3%** isolated-control limit. Rich/shared
churn also spanned **5.04%**, over its 5% limit. Because every attribution
ratio uses the rejected hash row as its numerator, none is actionable. The raw
values remain in the artifact for audit, but are explicitly marked
`NOT_EVALUATED`.

This is a measurement receipt, not a performance claim. It changes no
production code and measures no production speedup.

## Question and decision rule

The roadmap asks whether repeatedly hashing an already-shared
`Arc<Vec<PathAttribute>>` is expensive enough to justify prototyping a stable
fingerprint with full-equality fallback. This experiment required all of the
following before a later prototype could be recommended:

1. the isolated rich/shared hash-only time is at least 20% of isolated intern
   time;
2. its conservative ceiling is at least 5% in Adj-RIB-In insertion, bulk
   initial load, and route churn;
3. each signal is more than twice its control noise; and
4. every input row is retained by the same-SHA controls: at most 3% range for
   isolated rows, at most 5% for end-to-end rows, and at most 5% coefficient
   of variation for either class.

Failure of any requirement is a NO-GO. There is no rounding exception.

## Harness

The benchmark-local additions to `crates/rib/benches/rib_ops.rs` cover this
matrix:

| Attribute shape | Allocation shape | 10k | 100k |
|---|---|---:|---:|
| Typical | one shared `Arc` | yes | yes |
| Typical | independently allocated, content-equal `Arc`s | yes | yes |
| Rich | one shared `Arc` | yes | no |
| Rich | independently allocated, content-equal `Arc`s | yes | no |
| Typical | many unique values | yes | no |

Every matrix row runs through isolated `attr_hash_only`, isolated
`attr_intern`, Adj-RIB-In insertion, bulk initial load, and route churn. Churn
starts with the stated route count and times announcements plus withdrawals
for 10% of it, matching the existing 10k-base/1k-churn shape.

The typical vector is the existing five-attribute benchmark vector: ORIGIN,
AS_PATH, NEXT_HOP, LOCAL_PREF, and MED. The rich vector adds 32 communities,
24 extended communities, 16 large communities, an originator ID, a 16-entry
cluster list, and OTC. The many-unique row varies MED without changing the
attribute roster.

### Prefix correction while preserving prefix length

The old generator repeated prefixes above 65,536. The corrected generator
preserves indices 0 through 65,535 exactly as the historical
`10.b1.b2.0/24` sequence. Each later 65,536-prefix block advances only the
first octet, preserving the historical `/24` prefix-length shape. A full
`HashSet` uniqueness assertion runs outside timed regions. The preflight pins
indices 0, 65,535, and 65,536 to `10.0.0.0/24`, `10.255.255.0/24`, and
`11.0.0.0/24`. Thus the 100k and existing 500k benches are unique without
converting unrelated historical `/24` rows to `/32`. It does not claim the
new later blocks have the same topology as the old duplicated fixtures.

### Attribution and structural assertions

A benchmark-local `CountingHasher` wraps the production `FxHasher` and feeds
the real `attrs.hash(&mut hasher)` implementation. Before Criterion measures
anything, the preflight asserts:

- nonzero hash writes and bytes;
- identical digest and work for shared versus independently allocated equal
  typical attributes;
- the same equality for rich attributes;
- equality between the counting digest and the actual timed helper's digest
  for both typical and rich attributes;
- distinct digests for two fixtures with distinct MED values;
- strictly more writes and bytes for rich than typical attributes;
- one input pointer for shared rows and one pointer per input for independent
  rows;
- one content value and one final intern-table entry for equal rows; and
- no content, pointer, or table-length collapse for the many-unique row.

The timed hash-only arm uses a plain production `FxHasher`; the counting
wrapper is assertion-only and therefore does not inflate the timed numerator.
That arm constructs one hasher per attribute vector and folds each digest with
its loop index so the compiler cannot discard the work. The fold makes the
result a conservative hash ceiling rather than a pure instruction-level hash
cost. The intern arm calls the real `AttrInternTable::intern`.

### Load-bearing red proofs

Two destructive mutations were applied independently. First, the timed
`hash_with_production_hasher` helper's `attrs.hash(&mut hasher)` call was
replaced with a non-hashing `black_box`. This command failed before emitting a
Criterion measurement:

```text
cargo bench -p rustbgpd-rib --bench rib_ops -- \
  'attr_hash_only/typical_shared_arc/10000' \
  --warm-up-time 0.1 --measurement-time 0.1 --sample-size 10 --noplot
```

The timed-helper failure was:

```text
counting and timed hash helpers must agree for typical attrs
left: 8849704318604773807
right: 0
```

Second, the generator was reverted to the old constant first octet, while
retaining the 100k input. The same command failed before sampling:

```text
benchmark prefixes must remain unique beyond 65,536
left: 65536
right: 100000
```

Restoring each guarded line made the preflight pass. These are the production
breaks that make the measurement gate red; behavioral interning assertions
alone would remain green after either attribution-fixture defect.

## Host and provenance

The retained controls ran on one physical CPU of this host:

- AMD Ryzen Threadripper 7970X, 32 cores / 64 threads, one NUMA node;
- 128 MiB L3, 32 MiB L2;
- Linux 6.17.0-35-generic, x86_64;
- CPU 15 via `taskset -c 15`;
- `amd-pstate-epp`, `performance` governor;
- rustc 1.97.0 (`2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`);
- cargo 1.97.0 (`c980f4866`); and
- Criterion 0.8.2.

Source and binary identity:

| Item | SHA-256 |
|---|---|
| Measurement base before the docs-only rebase | `8b5a28a6a9a713ae23a5b7b4c38fbee8f166cee2` |
| Settled base after the docs-only rebase | `b05c29fa17e41a60124d22780a0c53984d339466` |
| `Cargo.lock` | `d20b5fde3bf984ba4da5225f3a41a94b043672f2b6844d0777d3f8fe76593e18` |
| `rib_ops.rs` after the harness change | `14dc9042e8db8f54d2cb8c596e696fb7f4723e127bbd18feac56d3a6009bdd38` |
| `git diff -- crates/rib/benches/rib_ops.rs` | `81af68db313f5bf1b4c2c90083253ac9e8d9693894c2bef5c871ad67ffc9d0b6` |
| Release benchmark binary | `60e8d1e2ca14489b4ef049e6431151b03ffed73b0227ef2a3c533bb512a73b5e` |

The base update contained only `ROADMAP.md`, the ADR index, and ADR-0121. The
benchmark source hash, benchmark diff hash, and binary hash were
identical before and after that update. No measurement was rerun or re-labeled
across a code change.

## Commands and control order

The final controls used the restored timed hash helper and prefix-preserving
generator. The earlier `/32` experiment and both campaigns run before the
timed-helper/boundary attack-review fixes were discarded in full. None of
their rows appear in the checked-in CSV.

The exact final command template was:

```text
flock -n /tmp/rustbgpd-perf.lock taskset -c 15 \
  cargo bench -p rustbgpd-rib --bench rib_ops -- attr_ \
  --save-baseline <baseline> --warm-up-time 1 --measurement-time 2 \
  --sample-size 10 --noplot --quiet
```

The baselines were run counterbalanced on the same source and binary:

| Order | Baseline | Rich/shared hash estimate timestamp (local) |
|---:|---|---|
| 1 | `attrhash3_a1` | 2026-08-01 07:23:41 -0400 |
| 2 | `attrhash3_b1` | 2026-08-01 07:26:00 -0400 |
| 3 | `attrhash3_b2` | 2026-08-01 07:28:12 -0400 |
| 4 | `attrhash3_a2` | 2026-08-01 07:30:32 -0400 |

`A` and `B` are deliberately identical same-SHA controls, not candidate and
baseline implementations. For each row, the receipt uses Criterion's median
point estimate from each attempt, then computes the mean, sample standard
deviation, range divided by mean, and coefficient of variation across those
four medians.

## Result

The decision shape was rich attributes sharing one `Arc`, representing the RR
or route-server case that a pointer/fingerprint shortcut would target.

| Row | Mean of medians | Range | CV | Limit | Retained |
|---|---:|---:|---:|---:|---|
| Hash only | 0.882 ms | 19.71% | 9.83% | 3% | **No** |
| Intern | 0.912 ms | 0.11% | 0.05% | 3% | Yes |
| Adj-RIB-In insert | 1.192 ms | 0.26% | 0.11% | 5% | Yes |
| Bulk initial load | 2.218 ms | 0.79% | 0.35% | 5% | Yes |
| Route churn | 0.357 ms | 5.04% | 2.47% | 5% | **No** |

The four hash-only medians were 1.012, 0.839, 0.838, and 0.838 ms. The first
attempt is not removed as an outlier: the retention rule is intentionally
attempt-level and bounded, so the 19.71% span invalidates the row.

For completeness, dividing the discarded hash numerator by the stable rows
would produce diagnostic values of 96.7% of isolated intern, 74.0% of insert,
39.8% of bulk load, and 24.7% of churn after scaling hash work to the 1k churn
announcements. These are recorded as `NOT_EVALUATED`, not evidence. Quoting
them as a likely gain would confuse a ceiling with a measured optimization and
would ignore the failed control.

The 100k rows do not rescue the experiment. Typical/shared hash-only missed
the 3% isolated bound despite its intern row passing, while
typical/independently-equal missed multiple control bounds. The CSV retains
every attempt and marks each rejected summary explicitly.

## Artifact

[`artifacts/attr-intern-hashing-2026-08.csv`](artifacts/attr-intern-hashing-2026-08.csv)
contains:

- 140 raw attempt rows: four attempts for all 35 benchmark rows;
- Criterion's within-attempt standard deviation beside each raw median;
- 35 across-attempt summaries with range, CV, limit, and retention decision;
- four non-actionable diagnostic ratios with their required and two-noise
  thresholds; and
- the final `NO-GO` row.

No raw row was deleted because it was inconvenient. Superseded campaigns used
a different generator or preflight binary and are excluded as different
experiments, not filtered statistically.

## Why retain a NO-GO harness

The harness earns its maintenance cost in three bounded ways. It fixes the
pre-existing duplicate-prefix defect in the established 100k/500k RIB benches;
it leaves the exact matrix needed to repeat the roadmap question instead of
reconstructing a subtly different experiment; and its preflight makes hash,
pointer, content, table-length, and prefix-boundary drift fail before numbers
can publish. It is not on a per-commit CI path and adds no production code.

An earns-its-keep pass collapsed the repetitive case construction before the
final campaign. The three pipeline bodies remain explicit because they define
different timed boundaries; abstracting them after measurement would change
source and binary identity, invalidate all four controls, and make the receipt
harder to audit. Retaining the measured form is lower complexity than another
unmotivated rerun.

## Next step

Do not implement the fingerprint optimization from this receipt. If profiles
continue to identify attribute hashing, rerun the isolated rich/shared row
with a measurement method that can hold its same-SHA range below 3%—for
example, longer measurement windows and an explicitly recorded frequency
trace—then repeat the entire gate. A later prototype still requires a real
production A/B and full equality fallback. Only after the full measurement
matrix produces a GO should that prototype proceed to collision and memory
gates.
