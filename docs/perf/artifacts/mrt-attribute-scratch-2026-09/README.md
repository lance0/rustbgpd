# MRT attribute-encoding scratch reuse (2026-09)

This receipt measures the snapshot encoder reusing one attribute-encoding
buffer per encode, instead of allocating a fresh `Vec` for every
non-`MP_REACH_NLRI` path attribute of every RIB entry. It is the shipped
follow-up to the 2026-07 scratch campaign
([`mrt-snapshot-allocation-2026-07`](../mrt-snapshot-allocation-2026-07/)).
That campaign measured the same idea behind a diagnostic counter threaded
through production signatures. This version carries no instrumentation.

- **Control:** `660a2388af25ea4122f7efcc4214f5807ef4a4aa` (main).
- **Candidate:** `573db05e055538067a0a0459a3989105a67ca188`, the same tree plus
  the encoder change.
- **Instrument:** the `snapshot_allocation` bench of `rustbgpd-mrt`, shapes
  `ixp-700` (400,400 paths from 700 sources) and `dual-full-feed` (800,800
  paths, 2 sources).

## Commands

```sh
# Built once per arm into separate target directories.
cargo build --locked --profile bench -p rustbgpd-mrt --bench snapshot_allocation
cargo build --locked --profile bench -p rustbgpd-mrt --bench snapshot_allocation \
  --features snapshot-allocation-diagnostics

# Allocation counts: one diagnostic run per arm and shape (fixed originated time).
snapshot_allocation diagnostic --candidate --shape <shape> --commit <sha> --output <file>

# Timing: 4 blocks in control/candidate/candidate/control order, both shapes,
# one pinned core. Each run takes 2 warmups and 7 samples.
taskset -c <core> snapshot_allocation timing --candidate --shape <shape> --commit <sha> --output <file>
```

`--candidate` selects the instrument's bounded top-level growth assertion,
which both arms satisfy. It does not name the arm under test. The arm is the
`arm` field added to each row of `timing.jsonl` and `diagnostic.jsonl`.

## Results

**Allocator activity** (`diagnostic.jsonl`, one run per arm and shape):

| Shape | Counter | Control | Candidate | Change |
| --- | --- | ---: | ---: | ---: |
| `ixp-700` | alloc calls | 4,804,807 | 2,402,408 | −50.000% |
| `ixp-700` | realloc calls | 1,201,240 | 800,841 | −33.332% |
| `ixp-700` | requested bytes | 265,107,946 | 237,480,375 | −10.421% |
| `ixp-700` | peak live requested bytes | 97,076,010 | 97,076,009 | −1 B |
| `dual-full-feed` | alloc calls | 9,609,606 | 4,804,807 | −50.000% |
| `dual-full-feed` | realloc calls | 2,402,442 | 1,601,643 | −33.333% |
| `dual-full-feed` | requested bytes | 445,825,888 | 390,570,717 | −12.394% |
| `dual-full-feed` | peak live requested bytes | 175,507,179 | 175,507,178 | −1 B |

**Output identity:** at fixed originated time, `raw_sha256` and
`semantic_sha256` are identical between arms for both shapes. In the timing
runs, originated time is live, so the raw hash varies per sample. The
semantic hash, output length and decoded entry count are identical across
all 112 timing samples of each shape.

**Elapsed time** (`timing.jsonl`, median of per-run medians, 8 runs per arm and
shape):

| Shape | Control | Candidate | Change | Per-block change |
| --- | ---: | ---: | ---: | --- |
| `ixp-700` | 140.0 ms | 122.0 ms | −12.86% | −12.6, −12.8, −12.9, −13.1 |
| `dual-full-feed` | 252.5 ms | 216.9 ms | −14.09% | −14.0, −14.1, −14.7, −13.6 |

The maximum within-run coefficient of variation is 1.59%.

These are encoder-only measurements of the snapshot builder. They make no
claim about daemon dump wall time, which also includes RIB collection and
file I/O.
