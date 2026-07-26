# Revised UPDATE duplicate-table receipt — 2026-07

The revised UPDATE decoder used a fresh `HashSet<u8>` to remember attribute
type codes for each message. The type-code domain is exactly one octet, so the
candidate replaces it with a 256-entry stack-resident table. This removes one
heap request per decode without changing duplicate ordering or disposition.

## Pinned source and measured path

| Revision | Commit | Tree | Behavior |
|---|---|---|---|
| Baseline | `b874b847554a758563ce7f09e8d7b36a35d1ea8c` | `2f62167c8269a31d05f29e7335d18795c324d2fe` | Fresh duplicate `HashSet` per revised attribute decode |
| Candidate | `0bae2ba31ebb6d99bbbeb1cfb07fe98dcdd32eb6` | `152ecc5c08b70c620f3f5f4ec890393b6a216879` | Full-domain `[bool; 256]` duplicate table |

The timing fixture is one syntactically clean UPDATE with ORIGIN, AS_PATH,
NEXT_HOP, LOCAL_PREF, MED, COMMUNITIES, and one body NLRI, parsed through the
eBGP disposition branch. It enters the public `UpdateMessage::parse_revised`
production path and exercises the revised attribute decoder. Separately, the
allocation diagnostic calls the public
`decode_path_attributes_revised` attribute decoder 10,000 times on the same
53-byte, six-attribute section through a `System`-wrapped `GlobalAlloc`.

Environment: AMD Ryzen Threadripper 7970X 32-Cores, logical CPU 8 pinned,
`performance` governor, Linux 6.17.0-35-generic, rustc 1.97.0 / LLVM 22.1.6.
Each timing comparison uses six alternating pairs, Criterion's three-second
warmup, five-second measurement, and 100 samples.

## Allocation result

| Revision | Allocation requests | Requested bytes | Requests/call | Requested bytes/call |
|---|---:|---:|---:|---:|
| Baseline | 60,000 | 26,920,000 | 6 | 2,692 |
| Candidate | 50,000 | 26,440,000 | 5 | 2,644 |

The fixed table removes exactly one allocation request and 48 requested bytes
per public revised attribute-decoder call. Both baseline repeats are
byte-for-byte identical. The two candidate repeats and two final confirmation
repeats are byte-for-byte identical. The `attr_encode/rich/11` and
`validate_update` rows are exactly unchanged negative controls.

`requested_bytes` sums the layouts requested by successful `alloc`,
`alloc_zeroed`, and `realloc` calls. It is not RSS, retained or peak heap,
allocator overhead, or whole-daemon memory.

## Timing result and control bias

| Comparison | Base mean | Head mean | Raw mean delta | Stddev | Six-pair range | Last-pair 95% CI |
|---|---:|---:|---:|---:|---:|---:|
| Same revision | 293.6 ns | 272.6 ns | -7.09% | 2.82% | -11.15%..-3.88% | -5.21%..-4.32% |
| Baseline to candidate | 271.7 ns | 212.6 ns | -21.73% | 1.71% | -24.34%..-19.26% | -22.09%..-21.24% |

The same-revision run has a substantial systematic head-side bias: all six
attempts favor the checkout named “head.” Therefore **-21.73% is not a causal
speedup claim**, and the receipt does not subtract the two percentages to
manufacture a bias-corrected estimate.

The narrower result is still real and fixture-scoped. The target and control
ranges do not overlap. Even the least-negative target attempt (-19.26%) clears
the most-negative same-revision attempt (-11.15%) by 8.11 percentage points.
That establishes a speedup for this parser fixture without assigning a
corrected percentage to it.

## Correctness and red proof

The stack table spans all 256 possible `u8` type codes. A production regression
test sends duplicate unknown optional-transitive type 255 attributes and
requires the first value to survive while the later value receives RFC 7606
`AttributeDiscard`. Existing tests retain duplicate MP_UNREACH session-reset
behavior and ordinary duplicate handling. RFC 9774 prohibited AS-set segment
inspection remains before duplicate handling, so a malformed later duplicate
cannot be hidden by the discard.

Restoring only the fresh `HashSet` implementation makes the candidate
diagnostic fail:

```text
left:  (50000, 0, 10000, 60000, 26920000)
right: (40000, 0, 10000, 50000, 26440000)
```

That proof ties the measured allocation result to the production mechanism.
Shrinking the fixed table below the full octet domain makes the type-255
regression red.

## Limits and artifacts

This is a microbenchmark and allocation diagnostic for one clean UPDATE
fixture. It makes no daemon CPU, peer-fleet, full-table, convergence, network,
or RSS claim. Malformed and other attribute mixes may have different costs.

The complete compact evidence is under
[`artifacts/revised-update-duplicate-table-2026-07/`](artifacts/revised-update-duplicate-table-2026-07/).
It retains both summaries, all 24 deterministically compressed logs, all 24
unrounded median-estimate files required for exact recomputation, six
allocation diagnostics, sanitized metadata, the destructive proof,
reproduction commands, a machine-readable manifest, a verifier, and checksums.
